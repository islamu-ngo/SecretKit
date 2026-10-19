using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalImportPermissionSourceTests
{
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task OnlySelectedTokenIsUsedAndDenialCannotRetry(int deny)
    {
        var selected = new Tokens("selected", deny == 0 ? SecretStatus.Success : SecretStatus.Denied);
        var source = new ImportPermissionTokens(selected);
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
        var source = new ImportPermissionTokens(new HeldTokens(entered, release));
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
        await using var fixture = new InfisicalImportPermissionFixture();
        var source = fixture.Source.CreateClient();
        var root = fixture.Root(ImportPermissionContract.Operations[0], ImportPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("import-capability");
        await source.StepAsync(root, ImportPermissionStep.Reserve, capability, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "wrong" }, ImportPermissionStep.Open, null, CancellationToken.None).AsTask());
        await Rejected(() => source.StepAsync(root, ImportPermissionStep.Arm, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, ImportPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, ImportPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalImportPermissionEffectTests.Clean(fixture);
    }
    private static async Task Rejected(Func<Task> action)
    {
        bool failed = false;
        try { await action(); } catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
    }
    [Test]
    public async Task ClosedOriginalRootFencesLateSdkWorkAndForeignAffinityNeverIssuesTokens()
    {
        await using var fixture = new InfisicalImportPermissionFixture();
        using var env = fixture.Environment();
        using var cap = SecretMaterial.FromText("import-capability");
        var root = fixture.Root(ImportPermissionContract.Operations[0], ImportPermissionAction.Create, "independent-effect");
        ImportPermissionTrial? retained = null;
        ImportPermissionRow row;
        try
        {
            var trial = await ImportPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, cap,
                t => retained = t, CancellationToken.None);
            row = trial.Issued.Rows.First(r => r.Action == ImportPermissionAction.Create);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        var selected = new Tokens("setup");
        await using var first = new InfisicalClient(fixture.Origin, selected,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        await using var second = new InfisicalClient(fixture.Origin, selected,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var target = new SecretReference(first.Authority, new InfisicalImportAddress(row.Project,
            row.Environment, row.Path, row.FolderId.ToString()));
        var foreign = await second.ListImportsAsync(target);
        await Assert.That(foreign.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(selected.Calls).IsEqualTo(0);
        var receipt = new MutationReceipt(target);
        var result = await first.CreateImportAsync(target, new("source-b", ImportPermissionContract.SourcePath(row, true), row.Project),
            false, new(first.Authority, selected, row.Project, row.Environment, row.Path), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        await Assert.That(selected.Calls).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(0);
        await InfisicalImportPermissionEffectTests.Clean(fixture);
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
