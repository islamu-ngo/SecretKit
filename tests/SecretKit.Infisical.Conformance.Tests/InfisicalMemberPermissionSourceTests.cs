using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMemberPermissionSourceTests
{
    [Test]
    public async Task InvalidIssuanceReleasesReturnedPrivateMaterialDuringRecovery()
    {
        await using var provider = new InfisicalMemberPermissionFixture("credential-wrong-user");
        var root = provider.Root(MemberPermissionContract.Operations[2], MemberPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("member-capability");
        MemberPermissionTrial? retained = null;
        try
        {
            await Rejected(() => MemberPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability,
                t => retained = t, CancellationToken.None).AsTask());
            await Assert.That(retained!.Issued.Principals.Any(p => p.Credential.Any(b => b != 0))).IsTrue();
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(retained!.Issued.Principals.All(p => p.Credential.All(b => b == 0))).IsTrue();
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task InterruptedOpenRetainsRootRecoveryWithoutReturnedIdentifiers()
    {
        await using var provider = new InfisicalMemberPermissionFixture("interrupted-open");
        var source = provider.Source.CreateClient();
        var root = provider.Root(MemberPermissionContract.Operations[0], MemberPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("member-capability");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        MemberPermissionTrial? retained = null;
        Task entered = provider.OpenEntered.Task;
        var opening = MemberPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
        try
        {
            await entered.WaitAsync(cancellation.Token);
            cancellation.Cancel();
            bool cancelled = false;
            try { await opening; } catch (OperationCanceledException) { cancelled = true; }
            await Assert.That(cancelled).IsTrue();
        }
        finally
        {
            provider.OpenRelease.TrySetResult();
            try { await opening; } catch (OperationCanceledException) { }
            if (retained is not null) await retained.DisposeAsync();
        }
        await Rejected(() => source.StepAsync(root, MemberPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Assert.That(provider.Closes).IsEqualTo(1);
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ClosedRootAndChangedNonceCannotIssueOrReplayWork()
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        var source = provider.Source.CreateClient();
        var root = provider.Root(MemberPermissionContract.Operations[0], MemberPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("member-capability");
        await source.StepAsync(root, MemberPermissionStep.Reserve, capability, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "changed" }, MemberPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Rejected(() => source.StepAsync(root, MemberPermissionStep.Arm, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, MemberPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, MemberPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalMemberPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExplicitFactoryActorAndScopeProfilesCannotBeSubstituted(bool scope)
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        var root = provider.Root(MemberPermissionContract.Operations[0], MemberPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = MemberPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var capability = SecretMaterial.FromText("member-capability");
        await Rejected(() => MemberPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability,
            _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task ReusedJournalKeyIsNotAnIndependentAuthority()
    {
        await using var provider = new InfisicalMemberPermissionFixture();
        var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { MemberPermissionContract.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    [Test]
    public async Task CredentialWrapperIsSingleUseAndPreservesHostOwnership()
    {
        var host = new Tokens();
        using (var wrapper = new MemberPermissionTokens(host))
        {
            using var first = (await wrapper.GetTokenAsync(CancellationToken.None)).Value;
            await Rejected(() => wrapper.GetTokenAsync(CancellationToken.None).AsTask());
        }
        using var retained = (await host.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(host.Calls).IsEqualTo(2);
    }
    [Test]
    public async Task ConcurrentCredentialDispatchCannotAcquireTwice()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var wrapper = new MemberPermissionTokens(new HeldTokens(entered, release));
        Task signal = entered.Task;
        var execution = wrapper.GetTokenAsync(timeout.Token).AsTask();
        try { await signal.WaitAsync(timeout.Token); await Rejected(() => wrapper.GetTokenAsync(timeout.Token).AsTask()); }
        finally { release.TrySetResult(); }
        using var token = (await execution).Value;
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false;
        try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        internal int Calls;
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Calls++;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("host-token"))));
        }
    }
    private sealed class HeldTokens(TaskCompletionSource entered, TaskCompletionSource release) : IInfisicalTokenSource
    {
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            entered.TrySetResult(); await release.Task.WaitAsync(token);
            return SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("held-token")));
        }
    }
}
