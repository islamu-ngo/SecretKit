using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusSucceededDeleteVaultIndependentCaptureRetainsActualAppliedStartAndCachedTask()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out var proof)).IsTrue();
        await Assert.That(proof).IsNotNull();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding with { }, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Client.PrepareReceipt(f.Scope, ManagementMutation.DeleteVault), start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, Task.CompletedTask, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out var target)).IsTrue();
        await Assert.That(target).IsNotNull();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding with { }, out _)).IsFalse();
        await Assert.That(await f.Check(retained: t => check = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentCompletion(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var completed)).IsTrue();
        await Assert.That(completed).IsNotNull();
        var copied = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        copied.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(check, copied.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentCompletion(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, copied.Task, out _)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusSucceededDeleteVaultIndependentExplicitHookRejectsOtherCasesBeforeDispatch(string boundary)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: boundary,
            statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultIndependentRawInstrumentationCannotIssueProfileProof()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect");
        ConfigureSucceededDelete(f);
        Task? start = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("202")]
    [Arguments("204")]
    [Arguments("Succeeded")]
    [Arguments("Failed")]
    [Arguments("Canceled")]
    [Arguments("future-state")]
    [Arguments("target")]
    [Arguments("foreign-target")]
    [Arguments("lost")]
    [Arguments("empty")]
    public async Task StatusSucceededDeleteVaultIndependentCaptureCannotInferProfileFromRequestedLabel(string fault)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        switch (fault)
        {
            case "202": f.Backend.StartStatus = 202; break;
            case "204": f.Backend.StartStatus = 204; f.Backend.StartBody = ""; break;
            case "empty": f.Backend.StartBody = ""; break;
            case "target": f.Backend.Targets.Clear(); break;
            case "foreign-target":
                f.Backend.Targets.Clear();
                f.Backend.Targets.Add(("Azure-AsyncOperation", "https://foreign.invalid/status"));
                break;
            case "lost": f.Backend.LoseStart = true; break;
            default: f.Backend.StartBody = "{\"status\":\"" + fault + "\"}"; break;
        }
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding,
            f.Client, (VaultScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task StatusSucceededDeleteVaultIndependentCaptureRejectsPartialOrRetryFraming(string header)
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" : header == "Content-Encoding" ? "gzip" : "bytes 0-1/2"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        bool proof = f.Handle is not null && f.Source.TryGetStatusSucceededDeleteVaultIndependentStart(f.Window, f.Binding,
            f.Client, (VaultScope)f.Scope, f.Receipt, start!, f.Handle, out _);
        await Assert.That(proof).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultIndependentCaptureForeignHandleDoesNotAcquireCheckSlot()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        using var other = new Fixture("DeleteVault");
        ConfigureSucceededDelete(f);
        ConfigureCancellationDelete(other);
        await f.Start();
        await other.Start();
        Task? check = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector, other.Handle!,
            default, t => check = t)).Throws<InvalidOperationException>();
        await Assert.That(check is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultIndependentCaptureFailedRetentionCannotMintCompletion()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        Task? start = null, check = null;
        await f.Start(retained: t => start = t);
        await Assert.That(async () => await f.Check(retained: t =>
        {
            check = t;
            throw new InvalidOperationException("controlled-retention-failure");
        })).Throws<InvalidOperationException>();
        await Assert.That(f.Source.TryGetStatusSucceededDeleteVaultIndependentCompletion(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await Assert.That(async () => await f.Check()).Throws<InvalidOperationException>();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusSucceededDeleteVaultIndependentCaptureSealJoinsRealCredentialDespiteForgedDrain()
    {
        using var f = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true);
        ConfigureSucceededDelete(f);
        f.Credential.Block = true;
        using var stop = new CancellationTokenSource();
        var work = f.Start(stop.Token);
        Task? sealing = null;
        try
        {
            await f.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            sealing = f.Source.SealAsync(f.Window);
            stop.Cancel();
            await f.Credential.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Window.Start!.Drained.TrySetResult();
            f.Window.Start.SdkTask = Task.CompletedTask;
            await Assert.That(sealing.IsCompleted).IsFalse();
            await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        }
        finally { f.Credential.Release.TrySetResult(); }
        await Assert.That(async () => await work.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await sealing!.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("null-stream")]
    public async Task StatusSucceededDeleteVaultIndependentCaptureRejectsPhysicalByteIdenticalSubstitution(string change)
    {
        Fixture? fixture = null;
        PrivateDeleteSelectedSubstitution? tap = null;
        using (fixture = new Fixture("DeleteVault", "status.Succeeded", boundary: "independent-effect", statusSucceededDeleteVaultIndependent: true,
            decorate: inner => tap = new(inner, change, () => fixture!.Backend.StartBody)))
        {
            ConfigureSucceededDelete(fixture);
            Task? start = null;
            await fixture.Start(retained: t => start = t);
            bool proof = fixture.Handle is not null && fixture.Source.TryGetStatusSucceededDeleteVaultIndependentStart(
                fixture.Window, fixture.Binding, fixture.Client, (VaultScope)fixture.Scope, fixture.Receipt,
                start!, fixture.Handle, out _);
            await Assert.That(proof).IsFalse();
            await Assert.That(tap!.Changes).IsEqualTo(1);
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
            await fixture.Source.SealAsync(fixture.Window);
        }
    }

}
