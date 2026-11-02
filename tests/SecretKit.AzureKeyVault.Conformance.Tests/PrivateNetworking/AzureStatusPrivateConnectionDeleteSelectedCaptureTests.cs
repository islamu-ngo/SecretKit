using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusPrivateDeleteSelectedCaptureJoinsOneActualCheckAndPendingReceipt()
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteSelected: true);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        var initial = f.Handle!.State;
        await Assert.That(initial is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded).IsTrue();
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var original = f.Window.Start!;
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out var start)).IsTrue();
        await Assert.That(start!.Binding).IsSameReferenceAs(f.Binding);
        var inventedStart = new TaskCompletionSource();
        inventedStart.SetResult();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, inventedStart.Task, f.Handle, out _)).IsFalse();
        var copiedReceipt = f.Client.PrepareReceipt(f.Scope, ManagementMutation.DeletePrivateConnection);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, copiedReceipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        Task? actual = null;
        await Assert.That(await f.Check(retained: t => actual = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!, out var completion)).IsTrue();
        await Assert.That(f.Source.OwnsStatusPrivateConnectionDeleteSelectedCompletion(completion!, f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!)).IsTrue();
        using var other = new Fixture("DeletePrivateConnection", statusPrivateDeleteSelected: true);
        await Assert.That(other.Source.OwnsStatusPrivateConnectionDeleteSelectedCompletion(completion!, f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!)).IsFalse();
        var invented = new TaskCompletionSource<SecretStatus>();
        invented.SetResult(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, invented.Task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Single().Method).IsEqualTo("DELETE");
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("pending")]
    [Arguments("updating")]
    [Arguments("201")]
    [Arguments("202")]
    [Arguments("204")]
    [Arguments("403")]
    [Arguments("empty")]
    [Arguments("endpoint")]
    [Arguments("lost")]
    public async Task StatusPrivateDeleteSelectedCaptureRequiresOriginalFullResource200(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteSelected: true);
        if (fault == "pending") f.Backend.StartBody = f.Backend.StartBody.Replace("Disconnected", "Pending", StringComparison.Ordinal);
        if (fault == "updating") f.Backend.StartBody = f.Backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        if (fault is "201" or "202" or "204" or "403") f.Backend.StartStatus = int.Parse(fault);
        if (fault == "empty") f.Backend.StartBody = "";
        if (fault == "endpoint") f.Backend.StartBody = f.Backend.StartBody.Replace(
            "Microsoft.Network/privateEndpoints", "Microsoft.Network/foreignEndpoints", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStart = true;
        await f.Start();
        if (f.Handle is not null)
            await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(f.Window, f.Binding, f.Client,
                (PrivateConnectionScope)f.Scope, f.Receipt, f.Window.Start!.SdkTask!, f.Handle, out _)).IsFalse();
        else await Assert.That(f.Receipt.Evidence == DispatchEvidence.Applied).IsFalse();
    }

    [Test]
    [Arguments("relative")]
    [Arguments("foreign")]
    [Arguments("wrong-api")]
    [Arguments("sibling")]
    [Arguments("query")]
    [Arguments("continuation")]
    [Arguments("canonical-location")]
    [Arguments("operation-location")]
    [Arguments("retry-after")]
    [Arguments("encoding")]
    [Arguments("range")]
    public async Task StatusPrivateDeleteSelectedCaptureRetainsStrictRouteEvidence(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteSelected: true);
        string location = fault switch
        {
            "relative" => Connection,
            "foreign" => "https://foreign.example" + Connection + "?api-version=2026-02-01",
            "wrong-api" => "https://management.azure.com" + Connection + "?api-version=2025-01-01",
            "sibling" => "https://management.azure.com" + Connection + "-other?api-version=2026-02-01",
            "query" => "https://management.azure.com" + Connection + "?api-version=2026-02-01&extra=1",
            _ => "https://management.azure.com" + Connection + "?api-version=2026-02-01"
        };
        string header = fault switch
        {
            "continuation" => "Azure-AsyncOperation",
            "operation-location" => "Operation-Location",
            "retry-after" => "Retry-After",
            "encoding" => "Content-Encoding",
            "range" => "Content-Range",
            _ => "Location"
        };
        string value = fault switch
        {
            "retry-after" => "1",
            "encoding" => "gzip",
            "range" => "bytes 0-0/1",
            _ => location
        };
        f.Backend.ExtraHeaders.Add((header, value));
        await Assert.That(await f.Start() == SecretStatus.Success).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("null-stream")]
    public async Task StatusPrivateDeleteSelectedCaptureRejectsPhysicalParserReplacement(string change)
    {
        Fixture? fixture = null;
        PrivateDeleteSelectedSubstitution? tap = null;
        using (fixture = new Fixture("DeletePrivateConnection", decorate: inner =>
            tap = new(inner, change, () => fixture!.Backend.StartBody), statusPrivateDeleteSelected: true))
        {
            await fixture.Start();
            if (fixture.Handle is not null)
                await Assert.That(fixture.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(fixture.Window,
                    fixture.Binding, fixture.Client, (PrivateConnectionScope)fixture.Scope, fixture.Receipt,
                    fixture.Window.Start!.SdkTask!, fixture.Handle, out _)).IsFalse();
            await Assert.That(tap!.Changes).IsEqualTo(1);
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        }
    }

    private sealed class PrivateDeleteSelectedSubstitution(HttpPipelineTransport inner, string change,
        Func<string> originalBody) : HttpPipelineTransport
    {
        internal int Changes;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            Changes++;
            byte[] bytes = Encoding.UTF8.GetBytes(originalBody());
            if (change == "response")
                message.Response = new OwnedArmResponse(message.Response.Status, message.Response.ReasonPhrase,
                    message.Response.ClientRequestId, message.Response.Headers.ToArray(), new MemoryStream(bytes, false));
            else message.Response.ContentStream = change == "stream" ? new MemoryStream(bytes, false) : null;
        }
    }
}
