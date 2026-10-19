using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalFolderPermissionSourceTests
{
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task OnlySelectedTokenIsUsedAndDenialCannotRetry(int deny)
    {
        var selected = new Tokens("selected", deny == 0 ? SecretStatus.Success : SecretStatus.Denied);
        var source = new FolderPermissionTokens(selected);
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
        var source = new FolderPermissionTokens(new HeldTokens(entered, release));
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
        await using var fixture = new InfisicalFolderPermissionFixture();
        var source = fixture.Source.CreateClient();
        var root = fixture.Root(FolderPermissionContract.Operations[0], FolderPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("folder-capability");
        await source.StepAsync(root, FolderPermissionStep.Reserve, capability, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "wrong" }, FolderPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Rejected(() => source.StepAsync(root, FolderPermissionStep.Arm, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, FolderPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, FolderPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalFolderPermissionEffectTests.Clean(fixture);
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
