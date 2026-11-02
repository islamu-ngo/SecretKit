using System.Text;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("selected-contract")]
    [Arguments("cancellation-boundary")]
    [Arguments("denied-authority")]
    public async Task StatusPrivateUpdateIndependentHookRejectsOtherCasesBeforeDispatch(string boundary)
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: boundary, statusPrivateUpdateIndependent: true);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentRawCaptureCannotIssueTypedStartProof()
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect");
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionUpdateIndependentStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentForeignHandleCannotClaimCachedCheck()
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true);
        using var other = new Fixture("UpdatePrivateConnection");
        await f.Start();
        await other.Start();
        Task? foreign = null;
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector,
            other.Handle!, default, t => foreign = t)).Throws<InvalidOperationException>();
        await Assert.That(foreign is null).IsTrue();
        await Assert.That(await f.Check()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCaptureRetainsActualCachedCheckAndAppliedReceipt()
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true);
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionUpdateIndependentStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsTrue();
        await Assert.That(await f.Check(retained: t => check = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionUpdateIndependentCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, check!, out var proof)).IsTrue();
        await Assert.That(f.Source.OwnsStatusPrivateConnectionUpdateIndependentCompletion(proof!, f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, check!)).IsTrue();
        var foreign = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        foreign.SetResult(SecretStatus.Success);
        await Assert.That(ReferenceEquals(check, foreign.Task)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionUpdateIndependentCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, foreign.Task, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusTarget(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Window.Start!.Owned.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("updating")]
    [Arguments("201")]
    [Arguments("202")]
    [Arguments("denied")]
    [Arguments("empty")]
    [Arguments("missing-endpoint")]
    [Arguments("lost")]
    public async Task StatusPrivateUpdateIndependentCaptureCannotReplaceOriginalWireProof(string fault)
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true);
        if (fault == "pending") f.Backend.StartBody = f.Backend.StartBody.Replace("Approved", "Pending", StringComparison.Ordinal);
        if (fault == "updating") f.Backend.StartBody = f.Backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        if (fault == "201") f.Backend.StartStatus = 201;
        if (fault == "202") f.Backend.StartStatus = 202;
        if (fault == "denied") f.Backend.StartStatus = 403;
        if (fault == "empty") f.Backend.StartBody = "";
        if (fault == "missing-endpoint")
        {
            var body = JsonNode.Parse(f.Backend.StartBody)!;
            body["properties"]!.AsObject().Remove("privateEndpoint");
            f.Backend.StartBody = body.ToJsonString();
        }
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusPrivateConnectionUpdateIndependentStart(f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Azure-AsyncOperation")]
    [Arguments("Operation-Location")]
    [Arguments("Retry-After")]
    [Arguments("Content-Encoding")]
    [Arguments("Content-Range")]
    public async Task StatusPrivateUpdateIndependentCaptureRejectsAsyncAndPartialHeaders(string header)
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true);
        f.Backend.ExtraHeaders.Add((header, header == "Retry-After" ? "1" :
            header == "Content-Encoding" ? "gzip" : header == "Content-Range" ? "bytes 0-0/1" :
                Origin + Connection + "?api-version=2026-02-01"));
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusPrivateConnectionUpdateIndependentStart(f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("null-stream")]
    public async Task StatusPrivateUpdateIndependentCaptureRejectsPhysicalParserSubstitution(string change)
    {
        PrivateCancellationSubstitution? substitution = null;
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true,
            decorate: inner => substitution = new(inner, change));
        substitution!.Bytes = Encoding.UTF8.GetBytes(f.Backend.StartBody);
        Task? start = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Handle is not null && f.Source.TryGetStatusPrivateConnectionUpdateIndependentStart(f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, out _)).IsFalse();
        await Assert.That(substitution.Replacements).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusPrivateUpdateIndependentCaptureSealIgnoresForgedDiagnosticDrain()
    {
        using var f = new Fixture("UpdatePrivateConnection", boundary: "independent-effect", statusPrivateUpdateIndependent: true);
        f.Credential.Block = true;
        using var cancellation = new CancellationTokenSource();
        Task? sealing = null;
        var work = f.Start(cancellation.Token);
        try
        {
            await f.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            sealing = f.Source.SealAsync(f.Window);
            cancellation.Cancel();
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

}
