using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalOrganizationUserCalibrationTests
{
    internal static NativeCaseDefinition Definition(string operation, string variant, string boundary) =>
        new(new("Infisical", operation, variant, "local", boundary),
            operation == OrganizationUserContract.Batch ? InfisicalProjectFamilies.Bindings[operation].Member :
                InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member);
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var inventory = JsonDocument.Parse(File.ReadAllText(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        foreach (var op in inventory.RootElement.GetProperty("operations").EnumerateArray())
        {
            string operation = op.GetProperty("id").GetString()!;
            if (!OrganizationUserContract.Owns(operation)) continue;
            foreach (var variant in op.GetProperty("variants").EnumerateArray())
                foreach (var boundary in op.GetProperty("requiredCases").EnumerateArray())
                    yield return (operation, variant.GetString()!, boundary.GetString()!);
        }
    }
    internal static OrganizationUserRoot Root(NativeEnvironment env, NativeCaseDefinition d,
        OrganizationUserSourceKind kind = OrganizationUserSourceKind.ControlledFixture) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), env.Origin.AbsoluteUri,
            InfisicalOrganizationUserFixture.Org, d.Key.Operation, d.Key.Variant, d.Key.Case, d.Key.Scope,
            "controlled-membership-v2", "controlled-deployment", "controlled-epoch",
            "controlled-organization-user-source", kind, InfisicalOrganizationUserFixture.Authorities);
    internal static OrganizationUserInput Input() => new(new(new("https://organization-source.invalid/"),
        "source-capability-token", "controlled-organization-user-source", 15),
        "private-user-issuer-capability", "controlled-deployment", "controlled-epoch", "controlled-membership-v2", 15);
    internal static object Families() => new Dictionary<string, object>
    {
        ["C08-IM-OrganizationMemberships"] = Scope(),
        ["C08-IM-MembershipMutations"] = Scope(),
        ["C08-IM-ManagementClient"] = Scope()
    };
    private static object Scope() => new
    {
        scopes = new
        {
            local = new
            {
                organizationId = InfisicalOrganizationUserFixture.Org,
                apiRevision = "AuthV1IdentitiesV1SecretsV4",
                setupIdentityId = InfisicalOrganizationUserFixture.Authorities.Setup,
                runtimeIdentityId = InfisicalOrganizationUserFixture.Authorities.Runtime,
                deniedIdentityId = InfisicalOrganizationUserFixture.Authorities.Denied,
                administrativeIdentityId = InfisicalOrganizationUserFixture.Authorities.Administrative,
                observerIdentityId = InfisicalOrganizationUserFixture.Authorities.Observer,
                observerUserId = InfisicalOrganizationUserFixture.BorrowedUser,
                observerUsername = "borrowed-user",
                organizationUser = Input()
            }
        }
    };

    [Test]
    public async Task RetainedInventoryHasTenVariantsFortyNineCasesAndTenMetadataGates()
    {
        var rows = Cases().ToArray();
        await Assert.That(rows.Length).IsEqualTo(49);
        await Assert.That(rows.Select(r => (r.Operation, r.Variant)).Distinct().Count()).IsEqualTo(10);
        await Assert.That(rows.Count(r => OrganizationUserContract.Gated(r.Variant))).IsEqualTo(10);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesSourceBeforeAnyEffects(string operation, string variant, string boundary)
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        if (OrganizationUserContract.Gated(variant))
        {
            await Assert.That(provider.Source.Opens).IsEqualTo(0);
            return;
        }
        using var env = provider.Environment(Families());
        await DirectAsync(provider, env, Definition(operation, variant, boundary));
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.Source.Fences.Single().RequestIds.Length)
            .IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(provider.Source.PrivateCopies.All(b => b.All(x => x == 0))).IsTrue();
    }

    [Test]
    [Arguments("lost-nonapplied")]
    [Arguments("lost-partial")]
    public async Task LostReplyPreservesActualReceiptAndIndependentlyClassifiesCommitSubset(string fault)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(Families());
        await DirectAsync(provider, env, Definition(OrganizationUserContract.Batch,
            "input.organizationId-membershipIds", "lost-response-no-replay"));
        var fence = provider.Source.Fences.Single();
        await Assert.That(fence.Receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(fence.Outcome).IsEqualTo(fault == "lost-partial" ?
            OrganizationUserOutcome.Partial : OrganizationUserOutcome.NonApplied);
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        // Classification is calibration, NOT a native-valid partial-batch trigger
        // or admission success. The effect must leave Partial explicitly gated.
    }

    internal static async Task DirectAsync(InfisicalOrganizationUserFixture provider, NativeEnvironment env,
        NativeCaseDefinition d)
    {
        var root = Root(env, d);
        OrganizationUserTrial? retained = null;
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        try
        {
            var trial = await OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(), root, capability,
                15, value => retained = value, CancellationToken.None);
            await WitnessAsync(env, root, trial, false);
            await trial.ArmAsync(CancellationToken.None);
            provider.Source.LoseResponse = d.Key.Case == "lost-response-no-replay";
            // Independent direct factories, not the effect dispatcher or its intent.
            var issued = trial.Issued;
            string[] ids = issued.Principals.Where(p => p.Slot < (d.Key.Operation == OrganizationUserContract.Batch ? 2 : 1))
                .OrderBy(p => p.Slot).Select(p => p.MembershipId).ToArray();
            OrganizationUserReceipt receipt;
            if (d.Key.Operation.EndsWith(".ListOrganizationMemberships", StringComparison.Ordinal))
                receipt = await ExecuteAsync(env, d, () => OrganizationMembershipOperations.ListOrganizationMemberships(root.OrganizationId),
                    page => page.IsComplete && page.Items.Count == issued.Principals.Length + 1);
            else if (d.Key.Operation == OrganizationUserContract.Batch)
                receipt = await ExecuteAsync(env, d, () => MembershipMutationOperations.DeleteOrganizationMemberships(root.OrganizationId, ids),
                    page => page.IsComplete && page.Items.Count == 2 &&
                        page.Items.Select(m => m.Id).Order().SequenceEqual(ids.Order()));
            else if (d.Key.Operation.EndsWith(".DeleteOrganizationMembership", StringComparison.Ordinal))
                receipt = await ExecuteAsync(env, d, () => OrganizationMembershipOperations.DeleteOrganizationMembership(root.OrganizationId, ids[0]),
                    row => row.Id == ids[0] && row.UserId == issued.Principals.Single(p => p.Slot == 0).UserId);
            else
            {
                string? role = d.Key.Variant is "role.value" or "isActive.omitted" ? issued.AllowedRole : null;
                bool? active = d.Key.Variant == "isActive.true" ? true :
                    d.Key.Variant is "role.omitted" or "isActive.false" ? false : null;
                receipt = await ExecuteAsync(env, d, () => OrganizationMembershipOperations.UpdateOrganizationMembership(
                    root.OrganizationId, ids[0], role, active), row => row.Id == ids[0] &&
                    row.UserId == issued.Principals.Single(p => p.Slot == 0).UserId &&
                    (role is null || row.Role == role) && (active is null || row.IsActive == active));
            }
            await trial.SettleAsync(receipt, CancellationToken.None);
            await WitnessAsync(env, root, trial, true);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
    }

    internal static async Task WitnessAsync(NativeEnvironment env, OrganizationUserRoot root,
        OrganizationUserTrial trial, bool after)
    {
        string phase = after ? "after" : "before";
        await trial.BeginAsync(phase, CancellationToken.None);
        var client = env.CreateManagementClient();
        using var list = OrganizationMembershipOperations.ListOrganizationMemberships(root.OrganizationId);
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Observer, root.OrganizationId);
        var result = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, list.Target));
        await Assert.That(result.IsSuccess && result.Value.IsComplete).IsTrue();
        var expected = trial.Expected(after);
        await Assert.That(result.Value.Items.Count).IsEqualTo(expected.Length + 1);
        await Assert.That(result.Value.Items.Select(m => m.Id).Distinct().Count()).IsEqualTo(result.Value.Items.Count);
        foreach (var item in expected)
            await Assert.That(result.Value.Items.Count(m => m.Id == item.MembershipId && m.UserId == item.UserId &&
                m.User?.Id == item.UserId && m.User.Username == item.Username && m.Role == item.Role &&
                m.IsActive == item.Active && m.Status == item.Status)).IsEqualTo(1);
        var accesses = new List<OrganizationUserAccess>();
        var issued = trial.Issued;
        var wrong = issued.Principals.Single(p => p.Slot == issued.Principals.Length - 1);
        foreach (var selected in issued.Principals.Where(p => p.Slot < issued.Principals.Length - 1).OrderBy(p => p.Slot))
        {
            bool allowed = trial.Allowed(selected.Slot, after);
            await UserRead(selected, allowed);
            await UserRead(wrong, false);
            await RoleRead(NativeIdentityRole.Denied, root.Authorities.Denied, false);
            await UserRead(selected, allowed); // fresh valid recheck after both negatives
            await RoleRead(NativeIdentityRole.Observer, root.Authorities.Observer, true);
        }
        await trial.ObserveAsync(phase, accesses.ToArray(), CancellationToken.None);

        async Task UserRead(OrganizationUserPrincipal principal, bool allowed)
        {
            using var material = OrganizationUserContract.Material(principal.Credential);
            await Read(new Tokens(material), principal.UserId, principal.CredentialId, principal.CredentialHash, allowed);
        }
        async Task RoleRead(NativeIdentityRole role, string id, bool allowed)
        {
            var credential = await env.Tokens(role).GetTokenAsync(CancellationToken.None);
            using var token = credential.Value;
            char[] chars = token.Material.ExportCharacters();
            byte[] bytes = Encoding.UTF8.GetBytes(chars);
            try { await Read(env.Tokens(role), id, null, Convert.ToHexString(SHA256.HashData(bytes)), allowed); }
            finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
        }
        async Task Read(IInfisicalTokenSource tokens, string user, string? credential, string hash, bool allowed)
        {
            using var transport = new ManagementTransport(env.Origin, new() { AllowLoopbackDevelopmentHttp = true });
            var fresh = new ManagementClient(transport);
            var auth = new ManagementAuthority(fresh.Authority, tokens, root.OrganizationId);
            using var request = ScopedAccessOperations.GetGroup(root.OrganizationId, issued.CanaryId);
            var read = await fresh.ExecuteAsync(request, auth, auth.IssueGrant(request.OperationId,
                new(root.OrganizationId, resourceId: issued.CanaryId)));
            await Assert.That(allowed ? read.IsSuccess && read.Value.Id == issued.CanaryId &&
                read.Value.Name == issued.CanaryName : read.Status == SecretStatus.Denied).IsTrue();
            accesses.Add(new("", user, credential, hash, issued.CanaryId, allowed));
        }
    }

    internal static async Task<OrganizationUserReceipt> ExecuteAsync<T>(NativeEnvironment env,
        NativeCaseDefinition d, Func<ManagementRequest<T>> factory, Func<T, bool> matches) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        using var intent = factory();
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        NativeIdentityRole role = d.Key.Case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = d.Key.Case == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
        var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), intent.Target.OrganizationId);
        using var lost = d.Key.Case == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
        using var scope = lost?.Enter();
        Task? entered = barrier?.Entered; // subscribed before original invocation
        Task<SecretOutcome<T>> execution = client.ExecuteAsync(request, authority,
            authority.IssueGrant(intent.OperationId, intent.Target), receipt, cancel.Token).AsTask();
        if (entered is not null)
        {
            await entered.WaitAsync(cancel.Token);
            cancel.Cancel(); barrier!.Release();
        }
        SecretOutcome<T>? outcome = null;
        bool cancelled = false;
        try { outcome = await execution; }
        catch (OperationCanceledException) when (cancel.IsCancellationRequested) { cancelled = true; }
        finally { barrier?.Release(); }
        bool interrupted = d.Key.Case is "cancellation-boundary" or "lost-response-no-replay";
        await Assert.That(cancelled).IsEqualTo(interrupted);
        if (lost is not null) await Assert.That(lost.Reached).IsTrue();
        if (!interrupted)
            await Assert.That(d.Key.Case == "denied-authority" ? outcome?.Status == SecretStatus.Denied :
                outcome is { IsSuccess: true } ok && matches(ok.Value)).IsTrue();
        return new(receipt?.Evidence ?? DispatchEvidence.NotDispatched, outcome?.Status, cancelled);
    }

    private sealed class Tokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
    }
}
