using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalTagPermissionSourceTests
{
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task OnlySelectedTokenIsUsedAndDenialCannotRetry(int deny)
    {
        var selected = new Tokens("selected", deny == 0 ? SecretStatus.Success : SecretStatus.Denied);
        var source = new TagPermissionTokens(selected);
        var result = await source.GetTokenAsync(CancellationToken.None);
        if (result.IsSuccess) result.Value.Dispose();
        await Assert.That(result.Status).IsEqualTo(deny == 0 ? SecretStatus.Success : SecretStatus.Denied);
        await Rejected(() => source.GetTokenAsync(CancellationToken.None).AsTask());
        await Assert.That(selected.Calls).IsEqualTo(1);
    }
    [Test]
    public async Task ConcurrentDispatchCannotIssueAnotherCredential()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var source = new TagPermissionTokens(new HeldTokens(entered, release));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task signal = entered.Task;
        var pending = source.GetTokenAsync(deadline.Token).AsTask();
        try { await signal.WaitAsync(deadline.Token); await Rejected(() => source.GetTokenAsync(deadline.Token).AsTask()); }
        finally { release.TrySetResult(); }
        using var token = (await pending).Value;
    }
    [Test]
    public async Task PrivateSourceRequiresOriginalRootAndClosedStepOrder()
    {
        await using var fixture = new InfisicalTagPermissionFixture();
        var source = fixture.Source.CreateClient();
        var root = fixture.Root(TagPermissionContract.Operations[0], TagPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("tag-capability");
        await source.StepAsync(root, TagPermissionStep.Reserve, capability, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "wrong" }, TagPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Rejected(() => source.StepAsync(root, TagPermissionStep.Arm, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, TagPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, TagPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalTagPermissionEffectTests.Clean(fixture);
    }
    [Test]
    public async Task TagReferencesAndMutationAuthoritiesRetainSdkClientAffinity()
    {
        var firstTokens = new Tokens("first");
        var secondTokens = new Tokens("second");
        await using var first = new InfisicalClient(new("https://tag-affinity.invalid/"), firstTokens);
        await using var second = new InfisicalClient(new("https://tag-affinity.invalid/"), secondTokens);
        var target = new SecretReference(first.Authority, new InfisicalTagAddress(
            "30000000-0000-0000-0000-000000000001", "30000000-0000-0000-0000-000000000002"));
        var read = await second.GetTagAsync(target);
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Invalid);
        var authority = new InfisicalNativeAuthority(second.Authority, secondTokens,
            "30000000-0000-0000-0000-000000000001");
        var receipt = new MutationReceipt(target);
        var mutation = await first.UpdateTagAsync(target, "changed", "#A1B2C3", authority, receipt);
        await Assert.That(mutation.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(firstTokens.Calls).IsEqualTo(0);
        await Assert.That(secondTokens.Calls).IsEqualTo(0);
    }
    [Test]
    public async Task DisposingSdkClientLeavesSuppliedTokenSourceHostOwned()
    {
        var tokens = new Tokens("host-owned");
        var client = new InfisicalClient(new("https://tag-ownership.invalid/"), tokens);
        await client.DisposeAsync();
        await Assert.That(tokens.Disposed).IsFalse();
        using var material = (await tokens.GetTokenAsync(CancellationToken.None)).Value;
        await Assert.That(tokens.Calls).IsEqualTo(1);
        tokens.Dispose();
        await Assert.That(tokens.Disposed).IsTrue();
    }
    private static async Task Rejected(Func<Task> action)
    {
        bool failed = false;
        try { await action(); } catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
    }
    private sealed class Tokens(string value, SecretStatus status = SecretStatus.Success) : IInfisicalTokenSource, IDisposable
    {
        internal int Calls;
        internal bool Disposed;
        public void Dispose() => Disposed = true;
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
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
