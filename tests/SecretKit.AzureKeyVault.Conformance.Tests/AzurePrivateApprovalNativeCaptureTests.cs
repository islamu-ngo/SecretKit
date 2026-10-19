using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    private const string ApprovalEndpoint = "/subscriptions/" + Subscription +
        "/resourceGroups/capture-group/providers/Microsoft.Network/privateEndpoints/approval-endpoint";

    [Test]
    public async Task StrictOriginalApprovalResponseAndActualCachedStatusAreSeparatePrivateEvidence()
    {
        using var f = ApprovalFixture();
        Task? start = null, status = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(OwnsApproval(f, proof!, start!)).IsTrue();
        await Assert.That(OwnsApproval(f, proof!, Task.CompletedTask)).IsFalse();
        await Assert.That(proof!.EndpointId).IsEqualTo(ApprovalEndpoint);
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(await f.Check(retained: task => status = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(OwnsApproval(f, proof, start!, status!)).IsTrue();
        await Assert.That(OwnsApproval(f, new Capture.PrivateApprovalResponseProof(ApprovalEndpoint), start!, status!)).IsFalse();
        var substitutedStatus = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        substitutedStatus.SetResult(SecretStatus.Success);
        await Assert.That(OwnsApproval(f, proof, start!, substitutedStatus.Task)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.Source.OwnsNativeStatusCompletion(f.Window, f.Binding)).IsFalse();
        await Assert.That(f.Source.TryGetSynchronousDeleteProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(OwnsApproval(f, proof, start!, status!)).IsFalse();
    }

    [Test]
    [Arguments("pending")]
    [Arguments("updating")]
    [Arguments("non-network-endpoint")]
    [Arguments("missing-endpoint")]
    [Arguments("wrong-name")]
    [Arguments("wrong-type")]
    [Arguments("duplicate")]
    [Arguments("case-alias")]
    [Arguments("error-envelope")]
    [Arguments("next-link")]
    [Arguments("retry-after")]
    [Arguments("content-encoding")]
    public async Task IneligibleOriginalApprovalResponseNeverMintsPrivateProof(string fault)
    {
        using var f = ApprovalFixture();
        var body = JsonNode.Parse(f.Backend.StartBody)!;
        switch (fault)
        {
            case "pending": body["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending"; break;
            case "updating": body["properties"]!["provisioningState"] = "Updating"; break;
            case "non-network-endpoint": body["properties"]!["privateEndpoint"]!["id"] = Vault + "/private-test-endpoint"; break;
            case "missing-endpoint": body["properties"]!.AsObject().Remove("privateEndpoint"); break;
            case "wrong-name": body["name"] = "another-connection"; break;
            case "wrong-type": body["type"] = "Microsoft.KeyVault/vaults"; break;
            case "case-alias": body["Properties"] = body["properties"]!.DeepClone(); break;
            case "error-envelope": body["error"] = new JsonObject { ["code"] = "failed" }; break;
            case "next-link": body["nextLink"] = "https://foreign.invalid/next"; break;
            case "retry-after": f.Backend.ExtraHeaders.Add(("Retry-After", "1")); break;
            case "content-encoding": f.Backend.ExtraHeaders.Add(("Content-Encoding", "gzip")); break;
        }
        f.Backend.StartBody = body.ToJsonString();
        if (fault == "duplicate") f.Backend.StartBody = f.Backend.StartBody.Replace(
            "\"provisioningState\":\"Succeeded\"", "\"provisioningState\":\"Succeeded\",\"provisioningState\":\"Succeeded\"",
            StringComparison.Ordinal);
        await f.Start();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        if (f.Handle is not null) await f.Check();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task CachedSuccessForUpdatingBodyCannotBecomeProofThroughDiagnosticMutation()
    {
        using var f = ApprovalFixture();
        f.Backend.StartBody = f.Backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        Task? start = null, status = null;
        await Assert.That(await f.Start(retained: t => start = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Check(retained: t => status = t)).IsEqualTo(SecretStatus.Success);
        f.Window.Start!.WrapperState = NativeProvisioningState.Succeeded;
        f.Window.Start.Outcome = SecretStatus.Success;
        foreach (var attempt in f.Window.Start.Attempts)
        {
            attempt.State = Capture.WireState.Succeeded;
            attempt.Valid = attempt.ResponseObserved = attempt.TransportTerminated = true;
        }
        f.Window.Start.SdkTask = start;
        f.Window.Status!.SdkTask = status;
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task ApprovalProofRejectsCopiedBindingScopeReceiptClientAndForeignHandle()
    {
        using var f = ApprovalFixture();
        using var other = ApprovalFixture();
        Task? start = null;
        await f.Start(retained: t => start = t);
        await other.Start();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out var proof)).IsTrue();
        var scope = (PrivateConnectionScope)f.Scope;
        await Assert.That(f.Source.OwnsPrivateApprovalResponseProof(proof!, f.Window, f.Binding with { }, f.Client, scope,
            f.Receipt, f.Handle!, start!)).IsFalse();
        await Assert.That(f.Source.OwnsPrivateApprovalResponseProof(proof!, f.Window, f.Binding, f.Client,
            new(scope.Vault, scope.ConnectionName), f.Receipt, f.Handle!, start!)).IsFalse();
        var receipt = f.Client.PrepareReceipt(f.Scope, f.Binding.Operation);
        await Assert.That(f.Source.OwnsPrivateApprovalResponseProof(proof!, f.Window, f.Binding, f.Client, scope,
            receipt, f.Handle!, start!)).IsFalse();
        await Assert.That(f.Source.OwnsPrivateApprovalResponseProof(proof!, f.Window, f.Binding, other.Client, scope,
            f.Receipt, f.Handle!, start!)).IsFalse();
        await Assert.That(f.Source.OwnsPrivateApprovalResponseProof(proof!, f.Window, f.Binding, f.Client, scope,
            f.Receipt, other.Handle!, start!)).IsFalse();
        await Assert.That(other.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
        await other.Source.SealAsync(other.Window);
    }

    [Test]
    public async Task PrivateApprovalBeforeSendRunsAfterCredentialBeforeHostDispatch()
    {
        using var f = ApprovalFixture();
        bool called = false;
        Task? start = null;
        var result = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, f.Scope, f.Input, f.Receipt,
            retained: t => start = t, privateApprovalBeforeSend: () =>
            {
                if (f.Credential.Audiences.Count == 0 || f.Backend.Requests.Count != 0)
                    throw new InvalidOperationException("controlled-approval-order");
                called = true;
            });
        if (result.IsSuccess) f.Handle = result.Value;
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(called).IsTrue();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(OwnsApproval(f, proof!, start!)).IsTrue();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task ApprovalJournalHookCannotChangeTheAuthenticatedRequestBeforeDispatch()
    {
        ApprovalRequestTrace? trace = null;
        using var f = new Fixture("UpdatePrivateConnection", decorate: inner => trace = new(inner));
        f.Backend.StartBody = f.Backend.StartBody.Replace(Vault + "/private-test-endpoint", ApprovalEndpoint, StringComparison.Ordinal);
        var result = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, f.Scope, f.Input, f.Receipt,
            privateApprovalBeforeSend: () => trace!.Request!.Headers.SetValue("Authorization", "Bearer substituted-approval"));
        if (result.IsSuccess) f.Handle = result.Value;
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task ApprovalSealWaitsForTheActualIgnoredCancellationCredential()
    {
        using var f = ApprovalFixture();
        f.Credential.Block = true;
        using var cancellation = new CancellationTokenSource();
        var start = f.Start(cancellation.Token);
        Task<Capture.Capture>? seal = null;
        try
        {
            await f.Credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await f.Credential.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            seal = f.Source.SealAsync(f.Window);
            await Assert.That(start.IsCompleted || seal.IsCompleted).IsFalse();
            await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        }
        finally { f.Credential.Release.TrySetResult(); }
        await Assert.That(async () => await start.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await seal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("fields")]
    [Arguments("drained")]
    [Arguments("window")]
    public async Task ApprovalPrivateFinalizationCannotBeForgedWhileTheActualSdkStillBorrowsResponse(string mutation)
    {
        SynchronousDeleteSdkBarrier? sdk = null;
        using var f = new Fixture("UpdatePrivateConnection", decorate: inner => sdk = new(inner));
        f.Backend.StartBody = f.Backend.StartBody.Replace(Vault + "/private-test-endpoint", ApprovalEndpoint, StringComparison.Ordinal);
        sdk!.Block = true;
        var start = f.Start();
        Task<Capture.Capture>? seal = null;
        MemoryStream[] snapshots = [];
        byte[][] arrays = [];
        try
        {
            await sdk.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var diagnostic = f.Window.Start!;
            snapshots = diagnostic.Snapshots.OfType<MemoryStream>().ToArray();
            arrays = diagnostic.Owned.ToArray();
            await Assert.That(snapshots.Length > 0 && arrays.Any(b => b.Any(v => v != 0))).IsTrue();
            diagnostic.SdkTask = Task.CompletedTask;
            diagnostic.Outcome = SecretStatus.Success;
            diagnostic.WrapperState = NativeProvisioningState.Succeeded;
            diagnostic.Terminated = true;
            diagnostic.Snapshots.Clear();
            diagnostic.Owned.Clear();
            if (mutation == "drained") diagnostic.Drained.TrySetResult();
            if (mutation == "window") f.Window.Start = null;
            seal = f.Source.SealAsync(f.Window);
            await Assert.That(start.IsCompleted || seal.IsCompleted).IsFalse();
            await Assert.That(snapshots.All(s => s.CanRead)).IsTrue();
            await Assert.That(arrays.Any(b => b.Any(v => v != 0))).IsTrue();
            await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        }
        finally { sdk.Release.TrySetResult(); }
        await Assert.That(await start.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Success);
        await seal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(snapshots.All(s => !s.CanRead)).IsTrue();
        await Assert.That(arrays.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task ThrowingOriginalApprovalStartHookCannotDetachTheActualTaskOrMintProof()
    {
        using var f = ApprovalFixture();
        Task? original = null;
        await Assert.That(async () => await f.Start(retained: task =>
        {
            original = task;
            throw new InvalidOperationException("controlled-approval-start-hook");
        })).Throws<InvalidOperationException>();
        await Assert.That(original!.IsCompleted).IsTrue();
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task ThrowingApprovalJournalHookCannotReachHostOrMintProof()
    {
        using var f = ApprovalFixture();
        var result = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, f.Scope, f.Input, f.Receipt,
            privateApprovalBeforeSend: () => throw new InvalidOperationException("controlled-closed-journal"));
        await Assert.That(result.Status).IsNotEqualTo(SecretStatus.Success);
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task ThrowingOriginalStatusHookCannotMintApprovalCompletionOrDetachStatusTask()
    {
        using var f = ApprovalFixture();
        Task? start = null, status = null;
        await f.Start(retained: t => start = t);
        await Assert.That(f.Source.TryGetPrivateApprovalResponseProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(async () => await f.Check(retained: t =>
        {
            status = t;
            throw new InvalidOperationException("controlled-status-hook");
        })).Throws<InvalidOperationException>();
        await Assert.That(status!.IsCompleted).IsTrue();
        await Assert.That(OwnsApproval(f, proof!, start!, status)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    private static bool OwnsApproval(Fixture f, Capture.PrivateApprovalResponseProof proof, Task start, Task? status = null) =>
        status is null
            ? f.Source.OwnsPrivateApprovalResponseProof(proof, f.Window, f.Binding, f.Client,
                (PrivateConnectionScope)f.Scope, f.Receipt, f.Handle!, start)
            : f.Source.OwnsPrivateApprovalCompletion(proof, f.Window, f.Binding, f.Client,
                (PrivateConnectionScope)f.Scope, f.Receipt, f.Handle!, start, status);

    private sealed class ApprovalRequestTrace(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal Request? Request;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Request = message.Request;
            await inner.ProcessAsync(message);
        }
    }

    private static Fixture ApprovalFixture()
    {
        var f = new Fixture("UpdatePrivateConnection");
        f.Backend.StartBody = f.Backend.StartBody.Replace(Vault + "/private-test-endpoint", ApprovalEndpoint, StringComparison.Ordinal);
        return f;
    }
}
