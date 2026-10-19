using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSpiffeRefreshCalibrationTests
{
    internal static readonly string[] Boundaries =
        ["selected-contract", "independent-effect", "denied-authority", "cancellation-boundary", "lost-response-no-replay"];
    public static IEnumerable<(string Boundary, string Mode)> Cases() =>
        Boundaries.SelectMany(b => new[] { "good", "ack-only", "wrong-cache" }.Select(m => (b, m)));

    // Deliberately calls SDK factories directly, never the refresh effects/trial.
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkCalibratesIndependentIssuerDistributionCacheAndTokenJournals(string boundary, string mode)
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture(mode);
        using NativeEnvironment env = Environment(fixture);
        var source = fixture.Source.Client();
        var root = Root(boundary);
        using var capability = SecretMaterial.FromText("exclusive-capability");
        using var borrowed = SecretMaterial.FromText("administrative");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var input = fixture.Input();
        try
        {
            var binding = await source.OpenAsync(root, capability, deadline.Token);
            await Assert.That(binding.Root == root && binding.IndependentCache && binding.IndependentIssuer).IsTrue();
            using SpiffeAuthConfiguration baseline = await GetAsync(env, deadline.Token);
            await Assert.That(baseline.TrustBundleDistribution.Profile).IsEqualTo("https_web_bundle");
            await Assert.That(fixture.Cache.Count).IsEqualTo(1);
            foreach (string proof in new[] { "old", "new", "wrong-key", "wrong-domain", "wrong-audience" })
                await CheckProofAsync(env, source, binding, null, input, "before", proof, proof == "old", deadline.Token);
            var arm = await source.ArmAsync(binding, deadline.Token);
            await Assert.That(arm.Binding == binding && arm.ClockHeld && arm.ExclusiveIngress &&
                arm.BaselineCachePreserved).IsTrue();
            await Assert.That(fixture.HasKey("new")).IsFalse();
            var client = env.CreateManagementClient();
            using var request = ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle(root.OrganizationId, root.IdentityId);
            ManagementReceipt receipt = client.CreateReceipt(request);
            var role = boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
            var authority = env.CreateManagementAuthority(client, role, root.OrganizationId);
            bool cancelled = false;
            SecretStatus status = SecretStatus.Unknown;
            using var cancel = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            if (boundary == "cancellation-boundary")
            {
                var barrier = new ProjectTokenBarrier(env.Tokens(role));
                authority = new(client.Authority, barrier, root.OrganizationId);
                Task entered = barrier.Entered;
                Task<SecretOutcome<SpiffeAuthConfiguration>> execution = client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), receipt, cancel.Token).AsTask();
                try
                {
                    await entered.WaitAsync(deadline.Token);
                    cancel.Cancel();
                    barrier.Release();
                    try { await execution; }
                    catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { cancelled = true; }
                }
                finally
                {
                    cancel.Cancel();
                    barrier.Release();
                    try { await execution; } catch (OperationCanceledException) { }
                }
            }
            else if (boundary == "lost-response-no-replay")
            {
                using var response = new ProjectResponseBoundary(env.Origin, cancel);
                using (response.Enter())
                {
                    try
                    {
                        var result = await client.ExecuteAsync(request, authority,
                            authority.IssueGrant(request.OperationId, request.Target), receipt, cancel.Token);
                        if (result.IsSuccess) result.Value.Dispose();
                    }
                    catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { cancelled = true; }
                }
                await Assert.That(response.Reached).IsTrue();
            }
            else
            {
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
                status = result.Status;
                if (result.IsSuccess) result.Value.Dispose();
            }
            var local = new SpiffeRefreshReceipt(receipt.Evidence, status, cancelled);
            var settled = await source.SettleAsync(arm, local, deadline.Token);
            bool apply = boundary is "selected-contract" or "independent-effect" or "lost-response-no-replay";
            await Assert.That(settled.Arm).IsEqualTo(arm);
            await Assert.That(settled.Receipt).IsEqualTo(local);
            await Assert.That(settled.Requests).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
            await Assert.That(settled.Fetches).IsEqualTo(apply && mode != "ack-only" ? 1 : 0);
            await Assert.That(settled.CacheCommits).IsEqualTo(apply && mode != "ack-only" ? 1 : 0);
            await Assert.That(settled.OriginalTerminal && settled.ExcludesLateWork && settled.NoReplay &&
                settled.Complete && settled.PendingWork == 0 && settled.ForeignRequests == 0).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(boundary switch
            {
                "denied-authority" => DispatchEvidence.Rejected,
                "cancellation-boundary" => DispatchEvidence.NotDispatched,
                "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
                _ => DispatchEvidence.Applied
            });
            await Assert.That(cancelled).IsEqualTo(boundary is "cancellation-boundary" or "lost-response-no-replay");
            foreach (string proof in new[] { "old", "new", "wrong-key", "wrong-domain", "wrong-audience" })
            {
                bool allowed = proof == "old" ? !(apply && mode == "wrong-cache") :
                    proof == "new" && apply && mode == "good";
                await CheckProofAsync(env, source, binding, arm, input, "after", proof, allowed, deadline.Token);
            }
            await Assert.That(settled.NewKeyPresent).IsEqualTo(apply && mode == "good");
            await Assert.That(settled.OldKeyPresent).IsEqualTo(!(apply && mode == "wrong-cache"));
            // Cached metadata is identical in all modes; only the actual fetch/keys/proofs distinguish them.
            using SpiffeAuthConfiguration observed = await GetAsync(env, deadline.Token);
            await Assert.That(observed.TrustBundleDistribution.CachedBundleLastRefreshedAt.Value)
                .IsEqualTo(baseline.TrustBundleDistribution.CachedBundleLastRefreshedAt.Value);
            await Assert.That(borrowed.Reveal()).IsEqualTo("administrative");
            Console.WriteLine($"SPIFFE calibration {boundary}/{mode}: requests={settled.Requests}, fetches={settled.Fetches}, commits={settled.CacheCommits}");
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, CancellationToken.None);
            await Assert.That(cleanup.Root == root && cleanup.OriginalTerminal && cleanup.ExcludesLateWork &&
                cleanup.OwnedAbsent && cleanup.BorrowedPreserved && cleanup.CopiesDestroyed &&
                cleanup.PendingWork == 0 && cleanup.Registrations == 0).IsTrue();
            await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        }
    }

    internal static async Task CheckProofAsync(NativeEnvironment env, IInfisicalSpiffeRefreshSource source,
        SpiffeRefreshBinding binding, SpiffeRefreshArm? arm, SpiffeRefreshInput input, string phase,
        string kind, bool allowed, CancellationToken token)
    {
        using var material = SecretMaterial.FromText(input.Jwt(kind));
        using var proof = InfisicalLoginProof.Spiffe(binding.Root.IdentityId, material);
        using var authentication = new InfisicalProofAuthentication(env.Origin,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var receipt = authentication.CreateReceipt();
        var result = await authentication.LoginAsync(proof, receipt, token);
        if (result.IsSuccess) result.Value.Dispose();
        await Assert.That(result.IsSuccess).IsEqualTo(allowed);
        await Assert.That(receipt.Evidence).IsEqualTo(allowed ? DispatchEvidence.Applied : DispatchEvidence.Rejected);
        var measured = await source.ProofAsync(binding, arm, phase, kind, material, token);
        await Assert.That(measured.Registration == binding.Registration && measured.Arm == arm &&
            measured.Phase == phase && measured.Proof == kind && measured.Allowed == allowed &&
            measured.IssuedTokens == (allowed ? 1 : 0) && measured.Complete).IsTrue();
    }
    internal static async Task<SpiffeAuthConfiguration> GetAsync(NativeEnvironment env, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        using var request = ExternalIdentityAuthenticationOperations.GetSpiffeAuth(
            InfisicalSpiffeRefreshFixture.Org, InfisicalSpiffeRefreshFixture.Identity);
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Observer, request.Target.OrganizationId);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), cancellationToken: token);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        return result.Value;
    }
    internal static SpiffeRefreshRoot Root(string boundary) => new(Guid.NewGuid().ToString("N"),
        Guid.NewGuid().ToString("N"), InfisicalSpiffeRefreshFixture.Org, InfisicalSpiffeRefreshFixture.Identity,
        boundary, "controlled-provider", "refresh-source", SpiffeRefreshSourceKind.ControlledFixture,
        "independent-local-functional-contract-1", "i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle",
        "input.organizationId-identityId", "local");
    internal static NativeEnvironment Environment(InfisicalSpiffeRefreshFixture fixture)
    {
        var json = new JsonObject
        {
            ["origin"] = fixture.Origin.AbsoluteUri,
            ["allowLoopbackDevelopmentHttp"] = true,
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject
            {
                ["ExternalIdentityAuthentication"] = new JsonObject
                {
                    ["apiRevision"] = "AuthV1IdentitiesV1SecretsV4",
                    ["spiffeRefresh"] = JsonSerializer.SerializeToNode(fixture.Input(), InfisicalSpiffeRefreshFixture.Json)
                },
                ["C08-IM-ExternalIdentityAuthentication"] = new JsonObject
                {
                    ["scopes"] = new JsonObject
                    {
                        ["local"] = InfisicalIdentityAuthenticationFamilyTests.Scope(false)
                    }
                }
            }
        };
        using var doc = JsonDocument.Parse(json.ToJsonString());
        return NativeEnvironment.Create(doc.RootElement);
    }
}
