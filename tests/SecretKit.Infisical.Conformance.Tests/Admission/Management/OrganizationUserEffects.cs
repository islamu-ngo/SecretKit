using System.Security.Cryptography;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class OrganizationUserEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IOrganizationUserSource? source,
        CancellationToken token)
    {
        c.Probe.Contract(OrganizationUserContract.Owns(c.Definition.Key.Operation), NativeFailure.ContractMismatch);
        if (OrganizationUserContract.Gated(c.Variant)) { c.Probe.Effect(NativeObservation.Unavailable); return; }
        var input = OrganizationUserInput.FromScope(c.Input);
        if (input is null) { c.Probe.Effect(NativeObservation.Unavailable); return; }
        var authorities = new OrganizationUserAuthorities(c.Required("setupIdentityId"), c.Required("runtimeIdentityId"),
            c.Required("deniedIdentityId"), c.Required("administrativeIdentityId"), c.Required("observerIdentityId"));
        c.Probe.Contract(authorities.All.Distinct().Count() == 5, NativeFailure.MissingInput);
        // Controlled clocks/sources require explicit in-process injection. Private
        // operator JSON cannot promote a fixture to native-provider qualification.
        source ??= new InfisicalOrganizationUserSource(new(input.Observer), input.Observer.Identity);
        var root = new OrganizationUserRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.Environment.Origin.AbsoluteUri, c.OrganizationId, c.Definition.Key.Operation, c.Variant,
            c.Definition.Key.Case, c.Definition.Key.Scope, input.ProviderRevision, input.Deployment,
            input.Epoch, input.Observer.Identity, source.Kind, authorities);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await OrganizationUserTrial.OpenAsync(source, root, capability, input.TimeoutSeconds, owned =>
            c.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        OrganizationUserState[]? borrowed = null;
        OrganizationUserState[]? fullBaseline = null;
        await WitnessAsync(false, token);
        await trial.ArmAsync(token); // source is armed BEFORE the original 0..1 SDK invocation
        var intent = trial.Intent;
        var issued = trial.Issued;
        OrganizationUserReceipt receipt;
        if (intent.Method == "GET")
            receipt = await OriginalAsync(c, () => OrganizationMembershipOperations.ListOrganizationMemberships(c.OrganizationId),
                page => Page(page, fullBaseline!), token);
        else if (root.Operation == OrganizationUserContract.Batch)
            receipt = await OriginalAsync(c, () => MembershipMutationOperations.DeleteOrganizationMemberships(
                c.OrganizationId, intent.MembershipIds), page => page.IsComplete &&
                    page.Items.Count == intent.MembershipIds.Length &&
                    page.Items.Select(m => m.Id).Distinct().Count() == page.Items.Count &&
                    page.Items.All(m => Mutation(m, false)), token);
        else if (intent.Method == "DELETE")
            receipt = await OriginalAsync(c, () => OrganizationMembershipOperations.DeleteOrganizationMembership(
                c.OrganizationId, intent.MembershipIds.Single()), row => Mutation(row, false), token);
        else
            receipt = await OriginalAsync(c, () => OrganizationMembershipOperations.UpdateOrganizationMembership(
                c.OrganizationId, intent.MembershipIds.Single(), intent.Role, intent.Active),
                row => Mutation(row, true), token);
        // Never upgrade the actual receipt based on readback, status or source
        // settlement. Lost Applied and NonApplied both retain PossiblyDispatched.
        await trial.SettleAsync(receipt, token);
        await WitnessAsync(true, token);
        if (trial.Fence.Outcome == OrganizationUserOutcome.Partial)
        {
            // Correctly classified and cleaned, not a fabricated native-valid
            // partial-batch success or admission of the unrelated result.partial.
            c.Probe.Effect(NativeObservation.Unavailable);
            return;
        }
        c.Probe.Effect(NativeObservation.Matched);

        bool Mutation(OrganizationMembershipSummary row, bool patch)
        {
            var principal = issued.Principals.SingleOrDefault(p =>
                p.MembershipId == row.Id && p.Slot < OrganizationUserContract.Targets(root));
            if (principal is null) return false;
            var baseline = trial.Expected(false).Single(m => m.MembershipId == principal.MembershipId);
            return row.OrganizationId == c.OrganizationId && row.UserId == principal.UserId &&
                row.Status == baseline.Status &&
                row.Role == (patch ? intent.Role ?? baseline.Role : baseline.Role) &&
                row.IsActive == (patch ? intent.Active ?? baseline.Active : baseline.Active);
        }
        bool Page(ManagementPage<OrganizationMembershipSummary> page, OrganizationUserState[] expected) =>
            page.IsComplete && page.Items.Count == expected.Length &&
            page.Items.Select(m => m.Id).Distinct().Count() == expected.Length &&
            page.Items.All(m => m.User is not null && m.UserId == m.User.Id &&
                expected.Contains(new(m.UserId!, m.Id, m.User.Username, m.Role, m.IsActive == true, m.Status ?? "")) &&
                m.OrganizationId == c.OrganizationId && m.IsActive is not null);

        async ValueTask WitnessAsync(bool after, CancellationToken ct)
        {
            string phase = after ? "after" : "before";
            await trial.BeginAsync(phase, ct);
            var page = await c.NeedAsync(() => OrganizationMembershipOperations.ListOrganizationMemberships(c.OrganizationId),
                NativeIdentityRole.Observer, ct);
            var expected = trial.Expected(after);
            if (borrowed is null)
            {
                c.Probe.Contract(page.IsComplete && page.Items.All(m => m.User is not null && m.UserId == m.User.Id &&
                    m.IsActive is not null && m.Status is not null), NativeFailure.MissingPrerequisite);
                var ownedIds = trial.Issued.Principals.Select(p => p.MembershipId).ToHashSet(StringComparer.Ordinal);
                borrowed = page.Items.Where(m => !ownedIds.Contains(m.Id)).Select(m =>
                    new OrganizationUserState(m.UserId!, m.Id, m.User!.Username, m.Role, m.IsActive!.Value, m.Status!)).ToArray();
                fullBaseline = [.. expected, .. borrowed];
            }
            c.Probe.Contract(Page(page, [.. expected, .. borrowed]), NativeFailure.EffectMismatch);
            var access = new List<OrganizationUserAccess>();
            var credentials = trial.Issued.Principals;
            var wrong = credentials.Single(p => p.Slot == OrganizationUserContract.Targets(root));
            foreach (var principal in credentials.Where(p => p.Slot < OrganizationUserContract.Targets(root)).OrderBy(p => p.Slot))
            {
                bool allowed = trial.Allowed(principal.Slot, after);
                await User(principal, allowed);
                await User(wrong, false);
                await Role(NativeIdentityRole.Denied, root.Authorities.Denied, false);
                await User(principal, allowed);
                await Role(NativeIdentityRole.Observer, root.Authorities.Observer, true);
            }
            await trial.ObserveAsync(phase, access.ToArray(), ct);

            async ValueTask User(OrganizationUserPrincipal principal, bool allowed)
            {
                using var material = OrganizationUserContract.Material(principal.Credential);
                await Read(new Tokens(material), principal.UserId, principal.CredentialId, principal.CredentialHash, allowed);
            }
            async ValueTask Role(NativeIdentityRole role, string principalId, bool allowed)
            {
                var selected = await c.Environment.Tokens(role).GetTokenAsync(ct);
                c.Probe.Contract(selected.IsSuccess, NativeFailure.MissingInput);
                using var credential = selected.Value;
                char[] chars = credential.Material.ExportCharacters();
                byte[] bytes = Encoding.UTF8.GetBytes(chars);
                try { await Read(c.Environment.Tokens(role), principalId, null, OrganizationUserContract.Hash(bytes), allowed); }
                finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
            }
            async ValueTask Read(IInfisicalTokenSource tokens, string principalId, string? credentialId, string hash, bool allowed)
            {
                // New public SDK transport/client for EVERY read and recheck.
                // The selected consumer is the privately issued fresh user, not
                // any of the five preexisting host role credentials.
                using var transport = new ManagementTransport(c.Environment.Origin,
                    new() { AllowLoopbackDevelopmentHttp = c.Environment.AllowLoopbackDevelopmentHttp });
                var consumer = new ManagementClient(transport);
                var authority = new ManagementAuthority(consumer.Authority, tokens, c.OrganizationId);
                using var request = ScopedAccessOperations.GetGroup(c.OrganizationId, trial.Issued.CanaryId);
                var result = await consumer.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(c.OrganizationId, resourceId: trial.Issued.CanaryId)),
                    cancellationToken: ct);
                c.Probe.Contract(allowed ? result.IsSuccess && result.Value.Id == trial.Issued.CanaryId &&
                    result.Value.Name == trial.Issued.CanaryName && result.Value.OrganizationId == c.OrganizationId :
                    result.Status == SecretStatus.Denied, NativeFailure.EffectMismatch);
                access.Add(new("", principalId, credentialId, hash, trial.Issued.CanaryId, allowed));
            }
        }
    }

    private static async ValueTask<OrganizationUserReceipt> OriginalAsync<T>(ProjectFamilyContext c,
        Func<ManagementRequest<T>> factory, Func<T, bool> matches, CancellationToken token) where T : notnull
    {
        var client = c.Environment.CreateManagementClient();
        using var request = factory();
        using var intent = factory();
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        bool presend = c.Definition.Key.Case == "cancellation-boundary";
        bool lost = c.Definition.Key.Case == "lost-response-no-replay";
        var role = c.Definition.Key.Case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = presend ? new ProjectTokenBarrier(c.Environment.Tokens(role)) : null;
        var authority = new ManagementAuthority(client.Authority, barrier ?? c.Environment.Tokens(role),
            intent.Target.OrganizationId);
        using var boundary = lost ? new ProjectResponseBoundary(c.Environment.Origin, cancellation) : null;
        using var scope = boundary?.Enter();
        Task? entered = barrier?.Entered;
        Task<SecretOutcome<T>> execution = client.ExecuteAsync(request, authority,
            authority.IssueGrant(intent.OperationId, intent.Target), receipt, cancellation.Token).AsTask();
        SecretOutcome<T>? result = null;
        bool cancelled = false;
        try
        {
            if (entered is not null)
            {
                await entered.WaitAsync(token);
                cancellation.Cancel();
                barrier!.Release();
            }
            try { result = await execution; }
            catch (OperationCanceledException) when (!token.IsCancellationRequested && cancellation.IsCancellationRequested)
            { cancelled = true; }
            c.Probe.Contract(cancelled == (presend || lost) && (!lost || boundary!.Reached),
                NativeFailure.ContractMismatch);
            if (!cancelled)
                c.Probe.Contract(role == NativeIdentityRole.Denied ? result?.Status == SecretStatus.Denied :
                    result is { IsSuccess: true } success && matches(success.Value), NativeFailure.ContractMismatch);
            return new(receipt?.Evidence ?? DispatchEvidence.NotDispatched, result?.Status, cancelled);
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { result ??= await execution; }
            catch (OperationCanceledException) { }
            if (result is { IsSuccess: true } owned && owned.Value is IDisposable disposable) disposable.Dispose();
        }
    }
    private sealed class Tokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
        public override string ToString() => "[OrganizationUserTokens]";
    }
}
