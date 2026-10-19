using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicPermissionSourceTests
{
    [Test]
    public async Task OneWaySelectionNeverReturnsSetupAfterSealingOrRetriesMeasuredToken()
    {
        var setup = new Tokens("setup"); var runtime = new Tokens("runtime");
        using var source = new DynamicPermissionTokens(setup, runtime);
        using (var bootstrap = (await source.GetTokenAsync(CancellationToken.None)).Value)
            await Assert.That(bootstrap.Material.Reveal()).IsEqualTo("setup");
        source.Seal();
        using (var measured = (await source.GetTokenAsync(CancellationToken.None)).Value)
            await Assert.That(measured.Material.Reveal()).IsEqualTo("runtime");
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
        await Rejected(() => { source.Seal(); return Task.CompletedTask; });
        await Assert.That(setup.Calls).IsEqualTo(1);
        await Assert.That(runtime.Calls).IsEqualTo(1);
    }
    [Test]
    public async Task ConcurrentBootstrapCannotSealOrIssueAnotherCredential()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var setup = new HeldTokens(entered, release);
        var runtime = new Tokens("runtime");
        using var source = new DynamicPermissionTokens(setup, runtime);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task signal = entered.Task;
        var pending = source.GetTokenAsync(deadline.Token).AsTask();
        try
        {
            await signal.WaitAsync(deadline.Token);
            await Rejected(() => { source.Seal(); return Task.CompletedTask; });
            await Rejected(() => source.GetTokenAsync(deadline.Token).AsTask());
        }
        finally { release.TrySetResult(); }
        using var bootstrap = (await pending).Value;
        bootstrap.Dispose(); source.Seal();
        using var measured = (await source.GetTokenAsync(deadline.Token)).Value;
        await Assert.That(measured.Material.Reveal()).IsEqualTo("runtime");
        await Assert.That(runtime.Calls).IsEqualTo(1);
    }
    [Test]
    public async Task DeniedExercisingSourceDoesNotFallBackToSetup()
    {
        var setup = new Tokens("setup"); var denied = new Tokens("denied", SecretStatus.Denied);
        using var source = new DynamicPermissionTokens(setup, denied);
        using (var bootstrap = (await source.GetTokenAsync(CancellationToken.None)).Value) { }
        source.Seal();
        await Assert.That((await source.GetTokenAsync(CancellationToken.None)).Status).IsEqualTo(SecretStatus.Denied);
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
        await Assert.That(setup.Calls).IsEqualTo(1);
        await Assert.That(denied.Calls).IsEqualTo(1);
    }
    [Test]
    public async Task FailedBootstrapCannotBeSealedOrReused()
    {
        var setup = new Tokens("setup", SecretStatus.Denied); var runtime = new Tokens("runtime");
        using var source = new DynamicPermissionTokens(setup, runtime);
        await Assert.That((await source.GetTokenAsync(CancellationToken.None)).Status).IsEqualTo(SecretStatus.Denied);
        await Rejected(() => { source.Seal(); return Task.CompletedTask; });
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
        await Assert.That(runtime.Calls).IsEqualTo(0);
    }
    [Test]
    public async Task ReadAndCreateRequireSealingBeforeTheirOnlyMeasuredCredential()
    {
        var runtime = new Tokens("runtime");
        using var source = new DynamicPermissionTokens(null, runtime);
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
        source.Seal();
        using var measured = (await source.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(source.SetupHash).IsNull();
        await Assert.That(runtime.Calls).IsEqualTo(1);
        source.Dispose();
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
    }
    [Test]
    public async Task PrivateSourceRequiresOriginalRootAndClosedStepOrder()
    {
        await using var fixture = new InfisicalDynamicPermissionFixture();
        var source = fixture.Source.CreateClient();
        var root = fixture.Root(DynamicPermissionContract.Operations[0], DynamicPermissionAction.Lease, "independent-effect");
        using var capability = SecretMaterial.FromText("dynamic-capability");
        await source.StepAsync(root, DynamicPermissionStep.Reserve, capability, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "wrong" }, DynamicPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Rejected(() => source.StepAsync(root, DynamicPermissionStep.Arm, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, DynamicPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, DynamicPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalDynamicPermissionEffectTests.Clean(fixture);
    }
    private static async Task Rejected(Func<Task> action)
    {
        bool failed = false;
        try { await action(); } catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
    }
    private sealed class Tokens(string value, SecretStatus status = SecretStatus.Success) : IInfisicalTokenSource
    {
        internal int Calls;
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested(); Calls++;
            return ValueTask.FromResult(status == SecretStatus.Success ?
                SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(value))) :
                SecretOutcome<InfisicalAccessToken>.Failure(status));
        }
    }
    private sealed class HeldTokens(TaskCompletionSource entered, TaskCompletionSource release) : IInfisicalTokenSource
    {
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            entered.TrySetResult(); await release.Task.WaitAsync(token);
            return SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("setup")));
        }
    }
}
