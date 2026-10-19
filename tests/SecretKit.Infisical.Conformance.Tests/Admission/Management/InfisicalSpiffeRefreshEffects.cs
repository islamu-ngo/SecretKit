using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent-owned registration must select this handler and optional source before
// the original SDK dispatch. It is not a second admission registry.
internal static class InfisicalSpiffeRefreshEffects
{
    internal const string Operation = "i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle";

    internal static string? UnavailableReason(NativeCaseDefinition definition, SpiffeRefreshInput? input)
    {
        if (definition.Key.Operation != Operation || !InfisicalIdentityAuthenticationFamilies.Valid(definition))
            return "contract-mismatch";
        return input is null ? "issuer-key-rollover-event-observer-unavailable" : null;
    }

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token,
        IInfisicalSpiffeRefreshSource? selectedSource = null)
    {
        SpiffeRefreshInput? input = SpiffeRefreshInput.FromInputs(c.Environment);
        if (UnavailableReason(c.Definition, input) is not null)
        {
            c.Probe.Effect(NativeObservation.Unavailable);
            return;
        }
        input!.Validate(); // no remote resource or source ownership before validation
        if (selectedSource is null && input.Source != SpiffeRefreshSourceKind.NativeProvider)
            throw new NativeCaseFailureException("missing-input");
        IInfisicalSpiffeRefreshSource source = selectedSource ?? new InfisicalSpiffeRefreshSource(
            new(input.Observer), input.Observer.Identity, input.Source);
        await c.EnsureIdentityAsync(token);
        await c.EnsureConsumerAsync(token);
        var root = new SpiffeRefreshRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.OrganizationId, c.IdentityId, c.Definition.Key.Case, input.Deployment, input.Observer.Identity,
            input.Source, input.ProviderRevision, c.Definition.Key.Operation, c.Variant, c.Definition.Key.Scope);
        // A lost Open/Arm reply still has a root-keyed cleanup owner. The selected
        // service may only remove its exclusive trial resources, never borrowed grants.
        c.Core.Cleanup(async ct =>
        {
            SpiffeRefreshCleanup closed = await source.CloseAsync(root, ct);
            return closed.Root == root && closed.OriginalTerminal && closed.ExcludesLateWork && closed.OwnedAbsent &&
                closed.BorrowedPreserved && closed.CopiesDestroyed && closed.Registrations == 0 && closed.PendingWork == 0;
        });
        using var capability = SecretMaterial.FromText(input.Capability);
        SpiffeRefreshBinding binding = await source.OpenAsync(root, capability, token);
        InfisicalSpiffeRefreshSource.Require(binding.Root == root && binding.IndependentIssuer && binding.IndependentCache &&
            binding.BorrowedPreserved && !string.IsNullOrWhiteSpace(binding.Registration) &&
            new[] { binding.BaselineKey, binding.NewKey, binding.WrongKey }.Distinct().Count() == 3);
        using var ca = SecretMaterial.FromText(input.CaCertificate);
        using var distribution = SpiffeTrustBundleInput.HttpsWebBundle(input.BundleEndpoint, ca, 3600);
        using var configuration = new SpiffeAuthConfigurationInput(input.TrustDomain, input.SpiffeId,
            input.Audience, distribution, new(600, 1800, 2000));
        using SpiffeAuthConfiguration attached = await c.NeedAsync(
            () => ExternalIdentityAuthenticationOperations.AttachSpiffeAuth(c.OrganizationId, c.IdentityId, configuration),
            NativeIdentityRole.Setup, token);
        InfisicalSpiffeRefreshSource.Require(Matches(attached, c.IdentityId, input));
        await ProofsAsync(c, source, binding, null, input, false, token);
        SpiffeRefreshArm arm = await source.ArmAsync(binding, token);
        InfisicalSpiffeRefreshSource.Require(arm.Binding == binding && arm.ExclusiveIngress && arm.ClockHeld &&
            arm.BaselineCachePreserved && !string.IsNullOrWhiteSpace(arm.Window) &&
            !string.IsNullOrWhiteSpace(arm.BundleRevision));

        // Arm is established before this original request is constructed/sent.
        SpiffeRefreshReceipt receipt = await DispatchAsync(c, input, token);
        SpiffeRefreshSettlement settled = await source.SettleAsync(arm, receipt, token);
        bool applied = root.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        InfisicalSpiffeRefreshSource.Require(settled.Arm == arm && settled.Receipt == receipt &&
            settled.OriginalTerminal && settled.ExcludesLateWork && settled.NoReplay && settled.Complete &&
            settled.ForeignRequests == 0 && settled.PendingWork == 0 && settled.BorrowedPreserved &&
            settled.Requests == (root.Case == "cancellation-boundary" ? 0 : 1) &&
            settled.Fetches == (applied ? 1 : 0) && settled.CacheCommits == (applied ? 1 : 0) &&
            settled.OldKeyPresent && settled.NewKeyPresent == applied && !settled.WrongKeyPresent);
        // The chosen publisher supplies an overlap bundle. This is NOT a generic
        // promise of immediate old-key retirement, nor a metadata freshness oracle.
        await ProofsAsync(c, source, binding, arm, input, applied, token);
        using SpiffeAuthConfiguration readback = await c.NeedAsync(
            () => ExternalIdentityAuthenticationOperations.GetSpiffeAuth(c.OrganizationId, c.IdentityId),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(Matches(readback, c.IdentityId, input), NativeFailure.ContractMismatch);
        c.Probe.Effect(NativeObservation.Matched);
    }

    private static bool Matches(SpiffeAuthConfiguration config, string identity, SpiffeRefreshInput input) =>
        config.IdentityId == identity && config.TrustDomain == input.TrustDomain && config.AllowedSpiffeIds == input.SpiffeId &&
        config.AllowedAudiences == input.Audience && config.AccessTokenTTL == 600 && config.AccessTokenMaxTTL == 1800 &&
        config.AccessTokenNumUsesLimit == 2000 && config.TrustBundleDistribution.Profile == "https_web_bundle" &&
        config.TrustBundleDistribution.EndpointUrl == input.BundleEndpoint &&
        config.TrustBundleDistribution.CaCert?.Reveal() == input.CaCertificate &&
        config.TrustBundleDistribution.RefreshHintSeconds == 3600;

    private static async ValueTask ProofsAsync(IdentityAuthContext c, IInfisicalSpiffeRefreshSource source,
        SpiffeRefreshBinding binding, SpiffeRefreshArm? arm, SpiffeRefreshInput input, bool refreshed, CancellationToken token)
    {
        string phase = arm is null ? "before" : "after";
        foreach (string kind in new[] { "old", "new", "wrong-key", "wrong-domain", "wrong-audience" })
        {
            bool allowed = kind == "old" || refreshed && kind == "new";
            using var jwt = SecretMaterial.FromText(input.Jwt(kind));
            using var proof = InfisicalLoginProof.Spiffe(c.IdentityId, jwt);
            using var auth = new InfisicalProofAuthentication(c.Environment.Origin, c.Network);
            var receipt = auth.CreateReceipt();
            var result = await auth.LoginAsync(proof, receipt, token);
            using InfisicalProofLogin? login = result.IsSuccess ? result.Value : null;
            InfisicalSpiffeRefreshSource.Require(allowed ?
                result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied &&
                login!.ExpiresIn == 600 && login.AccessTokenMaxTTL == 1800 &&
                await c.UseTokenAsync(login.Token.Material, true, token) :
                result.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected);
            SpiffeRefreshProofFacts journal = await source.ProofAsync(binding, arm, phase, kind, jwt, token);
            InfisicalSpiffeRefreshSource.Require(journal.Registration == binding.Registration && journal.Arm == arm &&
                journal.Phase == phase && journal.Proof == kind && journal.Allowed == allowed &&
                journal.IssuedTokens == (allowed ? 1 : 0) && journal.Complete);
        }
    }

    private static async ValueTask<SpiffeRefreshReceipt> DispatchAsync(IdentityAuthContext c,
        SpiffeRefreshInput input, CancellationToken token)
    {
        var client = c.Environment.CreateManagementClient();
        using var request = ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle(c.OrganizationId, c.IdentityId);
        ManagementReceipt original = client.CreateReceipt(request);
        NativeIdentityRole role = c.Definition.Key.Case == "denied-authority" ?
            NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        ManagementAuthority authority = c.Environment.CreateManagementAuthority(client, role, c.OrganizationId);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        SecretStatus status = SecretStatus.Unknown;
        bool cancelled = false;
        if (c.Definition.Key.Case == "cancellation-boundary")
        {
            var barrier = new ProjectTokenBarrier(c.Environment.Tokens(role));
            authority = new(client.Authority, barrier, c.OrganizationId);
            Task entered = barrier.Entered;
            Task<SecretOutcome<SpiffeAuthConfiguration>> execution = client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), original, cancellation.Token).AsTask();
            try
            {
                await entered.WaitAsync(token);
                cancellation.Cancel();
                barrier.Release();
                try { await execution; }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { cancelled = true; }
            }
            finally
            {
                cancellation.Cancel();
                barrier.Release();
                try { await execution; } catch (OperationCanceledException) { }
            }
        }
        else if (c.Definition.Key.Case == "lost-response-no-replay")
        {
            using var boundary = new ProjectResponseBoundary(c.Environment.Origin, cancellation);
            using (boundary.Enter())
            {
                try
                {
                    var result = await client.ExecuteAsync(request, authority,
                        authority.IssueGrant(request.OperationId, request.Target), original, cancellation.Token);
                    if (result.IsSuccess) result.Value.Dispose();
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested) { cancelled = true; }
            }
            InfisicalSpiffeRefreshSource.Require(boundary.Reached);
        }
        else
        {
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), original, token);
            status = result.Status;
            try
            {
                InfisicalSpiffeRefreshSource.Require(role == NativeIdentityRole.Denied ?
                    status == SecretStatus.Denied : result.IsSuccess && Matches(result.Value, c.IdentityId, input));
            }
            finally { if (result.IsSuccess) result.Value.Dispose(); }
        }
        DispatchEvidence expected = c.Definition.Key.Case switch
        {
            "denied-authority" => DispatchEvidence.Rejected,
            "cancellation-boundary" => DispatchEvidence.NotDispatched,
            "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
            _ => DispatchEvidence.Applied
        };
        c.Probe.Contract(original.Evidence == expected &&
            cancelled == (c.Definition.Key.Case is "cancellation-boundary" or "lost-response-no-replay"),
            NativeFailure.ContractMismatch);
        return new(original.Evidence, status, cancelled);
    }
}
