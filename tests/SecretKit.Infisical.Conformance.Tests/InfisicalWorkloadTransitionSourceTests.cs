using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalWorkloadTransitionSourceTests
{
    [Test]
    public async Task SourceCloseWaitsForCapturedResponseBuffersToBeReleased()
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var root = InfisicalWorkloadTransitionCalibrationTests.Root(env,
            InfisicalWorkloadTransitionEffectTests.UpdateKubernetes, "templateId.value", "independent-effect");
        var source = provider.Source.CreateClient();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var capability = SecretMaterial.FromText("workload-capability");
        await source.ReserveAsync(root, capability, deadline.Token);
        var issued = await source.OpenAsync(root, deadline.Token);
        await source.BeginAsync(root, "before", deadline.Token);
        provider.ResponseRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task written = provider.ResponseWritten.Task;
        try
        {
            var result = await env.Tokens(NativeIdentityRole.Observer).GetTokenAsync(deadline.Token);
            using var credential = result.Value;
            var read = WorkloadTransitionEffects.ReadAsync(env, credential.Material, issued.Target, true, deadline.Token).AsTask();
            await written.WaitAsync(deadline.Token);
            await read;
            var closing = source.CloseAsync(root, deadline.Token).AsTask();
            await Assert.That(closing.IsCompleted).IsFalse();
            provider.ResponseRelease.TrySetResult();
            await closing;
            await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
            await Assert.That(provider.Remaining).IsEqualTo(0);
        }
        finally { provider.ResponseRelease.TrySetResult(); }
    }

    [Test]
    public async Task OriginalRootCloseDrainsPreenrolledIssuerWithoutOpenReply()
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var root = InfisicalWorkloadTransitionCalibrationTests.Root(env,
            InfisicalWorkloadTransitionEffectTests.UpdateKubernetes, "templateId.value", "independent-effect");
        var source = provider.Source.CreateClient();
        using var capability = SecretMaterial.FromText("workload-capability");
        await source.ReserveAsync(root, capability, CancellationToken.None);
        provider.Source.PauseIssuer = true;
        Task entered = provider.Source.IssuerEntered.Task;
        Task<WorkloadTransitionIssuance> opening = source.OpenAsync(root, CancellationToken.None).AsTask();
        await entered.WaitAsync(TimeSpan.FromSeconds(15));
        var closed = await source.CloseAsync(root, CancellationToken.None);
        await FailsAsync(async () => { await opening; });
        provider.Source.IssuerRelease.TrySetResult();
        await Assert.That(closed.PendingWork).IsEqualTo(0);
        await Assert.That(closed.Remaining.Length).IsEqualTo(0);
        await Assert.That(closed.Enrolled.Count(r => r.Kind == "issuer-work")).IsEqualTo(1);
        await Assert.That(provider.Source.IssuerWork).Contains("terminal:" + root.Id);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
        await FailsAsync(() => source.OpenAsync(root, CancellationToken.None).AsTask());
        await Assert.That(provider.Copies.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task CollisionRecoveryCannotCloseAnotherOwnedRoot()
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var first = InfisicalWorkloadTransitionCalibrationTests.Root(env,
            InfisicalWorkloadTransitionEffectTests.UpdateKubernetes, "templateId.value", "independent-effect");
        var second = first with { Id = Guid.NewGuid().ToString("N"), Nonce = Guid.NewGuid().ToString("N") };
        var a = provider.Source.CreateClient(); var b = provider.Source.CreateClient();
        using var capability = SecretMaterial.FromText("workload-capability");
        await a.ReserveAsync(first, capability, CancellationToken.None);
        await a.OpenAsync(first, CancellationToken.None);
        int before = provider.Remaining;
        await FailsAsync(() => b.ReserveAsync(second, capability, CancellationToken.None).AsTask());
        var otherClose = await b.CloseAsync(second, CancellationToken.None);
        await Assert.That(otherClose.Enrolled.Length).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(before);
        await Assert.That(provider.Owns(first)).IsTrue();
        await a.CloseAsync(first, CancellationToken.None);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    public async Task ConsumedStagesAndTerminalIngressForbidReplayAndLateWork()
    {
        await using var provider = new InfisicalWorkloadTransitionFixture();
        using var env = provider.Environment(InfisicalWorkloadTransitionCalibrationTests.Families());
        var root = InfisicalWorkloadTransitionCalibrationTests.Root(env,
            InfisicalWorkloadTransitionEffectTests.UpdateKubernetes, "templateId.value", "independent-effect");
        var source = provider.Source.CreateClient();
        WorkloadTransitionTrial? retained = null;
        using var capability = SecretMaterial.FromText("workload-capability");
        try
        {
            var trial = await WorkloadTransitionTrial.OpenAsync(source, root, capability, 15,
                t => retained = t, CancellationToken.None);
            await WorkloadTransitionEffects.WitnessAsync(env, root, trial, false, CancellationToken.None);
            await trial.ArmAsync(CancellationToken.None);
            await FailsAsync(() => trial.ArmAsync(CancellationToken.None).AsTask());
            var receipt = await WorkloadTransitionEffects.DispatchAsync(env, root, trial.Issued, CancellationToken.None);
            await trial.SettleAsync(receipt, CancellationToken.None);
            await FailsAsync(() => source.SettleAsync(root, CancellationToken.None).AsTask());
            var client = env.CreateManagementClient();
            using var input = new KubernetesAuthConfigurationInput(templateId:
                WorkloadAuthNullableText.FromValue(trial.Issued.TemplateB));
            using var request = WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth(root.Organization,
                trial.Issued.Target.Identity, input);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Administrative, root.Organization);
            var second = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), client.CreateReceipt(request));
            if (second.IsSuccess) second.Value.Dispose();
            await Assert.That(second.IsSuccess).IsFalse();
            await Assert.That(provider.Originals).IsEqualTo(1);
            await Assert.That(provider.LateRejections).Contains("dispatch");
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await FailsAsync(() =>
        {
            lock (provider.Gate) provider.Enroll("identity", Guid.NewGuid().ToString());
            return Task.CompletedTask;
        });
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }

    [Test]
    public async Task MissingProfileAndUnqualifiedSemanticsRemainGated()
    {
        var d = InfisicalWorkloadTransitionCalibrationTests.Definition(
            InfisicalWorkloadTransitionEffectTests.UpdateKubernetes, "reviewerJwt.null", "selected-contract");
        await Assert.That(WorkloadTransitionContract.Gate(d, null)).IsNotNull();
        var input = InfisicalWorkloadTransitionCalibrationTests.Input();
        await Assert.That(WorkloadTransitionContract.Gate(d, input with
        { Profile = input.Profile with { ReviewerNullUsesClient = false } })).IsNotNull();
        var invalid = input.Profile with
        {
            Journals = input.Profile.Journals.Select(j => j with { Writer = "coordinator-only" }).ToArray()
        };
        await FailsAsync(() =>
        {
            WorkloadTransitionContract.Profile(invalid); return Task.CompletedTask;
        });
    }

    [Test]
    public async Task ProtectedMaterialFormattingDoesNotRevealOwnedCredentials()
    {
        var proof = new WorkloadTransitionProof("proof", "private-jwt", "public-key", "subject");
        await Assert.That(proof.ToString().Contains("private-jwt", StringComparison.Ordinal)).IsFalse();
        await Assert.That(InfisicalWorkloadTransitionCalibrationTests.Input().ToString()
            .Contains("workload-capability", StringComparison.Ordinal)).IsFalse();
    }
    private static async Task FailsAsync(Func<Task> action)
    {
        bool rejected = false;
        try { await action(); }
        catch (NativeCaseFailureException) { rejected = true; }
        catch (OperationCanceledException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
