using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    public async Task StatusPrivateDeleteIndependentCaptureJoinsOneActualCheckAndPendingReceipt()
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "independent-effect");
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        var initial = f.Handle!.State;
        await Assert.That(initial is NativeProvisioningState.Pending or NativeProvisioningState.Succeeded).IsTrue();
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var original = f.Window.Start!;
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out var start)).IsTrue();
        await Assert.That(start!.Binding).IsSameReferenceAs(f.Binding);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(f.Window, f.Binding with { }, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        var inventedStart = new TaskCompletionSource();
        inventedStart.SetResult();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, inventedStart.Task, f.Handle, out _)).IsFalse();
        var copiedReceipt = f.Client.PrepareReceipt(f.Scope, ManagementMutation.DeletePrivateConnection);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, copiedReceipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteCancellationStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteSelectedStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, out _)).IsFalse();
        Task? actual = null;
        await Assert.That(await f.Check(retained: t => actual = t)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!, out var completion)).IsTrue();
        await Assert.That(f.Source.OwnsStatusPrivateConnectionDeleteIndependentCompletion(completion!, f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!)).IsTrue();
        using var other = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "independent-effect");
        await Assert.That(other.Source.OwnsStatusPrivateConnectionDeleteIndependentCompletion(completion!, f.Window,
            f.Binding, f.Client, (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, actual!)).IsFalse();
        var invented = new TaskCompletionSource<SecretStatus>();
        invented.SetResult(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentCompletion(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, original.SdkTask!, f.Handle, invented.Task, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Single().Method).IsEqualTo("DELETE");
        await Assert.That(f.Backend.RequestBytes.Length).IsEqualTo(0);
        await Assert.That(f.Window.Status!.Attempts.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StatusPrivateDeleteIndependentRawInstrumentationCannotIssueTypedStart()
    {
        using var body = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "independent-effect");
        using var raw = new Fixture("DeletePrivateConnection", boundary: "independent-effect");
        raw.Backend.StartStatus = 200;
        raw.Backend.StartBody = body.Backend.StartBody;
        await Assert.That(await raw.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(raw.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(raw.Window, raw.Binding,
            raw.Client, (PrivateConnectionScope)raw.Scope, raw.Receipt, raw.Window.Start!.SdkTask!, raw.Handle!, out _)).IsFalse();
        await raw.Source.SealAsync(raw.Window);
        await Assert.That(raw.Backend.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task StatusPrivateDeleteIndependentExplicitHookRejectsOtherCasesBeforeDispatch()
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "selected-contract");
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(0);
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
    public async Task StatusPrivateDeleteIndependentCaptureRequiresOriginalFullResource200(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "independent-effect");
        if (fault == "pending") f.Backend.StartBody = f.Backend.StartBody.Replace("Disconnected", "Pending", StringComparison.Ordinal);
        if (fault == "updating") f.Backend.StartBody = f.Backend.StartBody.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        if (fault is "201" or "202" or "204" or "403") f.Backend.StartStatus = int.Parse(fault);
        if (fault == "empty") f.Backend.StartBody = "";
        if (fault == "endpoint") f.Backend.StartBody = f.Backend.StartBody.Replace(
            "Microsoft.Network/privateEndpoints", "Microsoft.Network/foreignEndpoints", StringComparison.Ordinal);
        if (fault == "lost") f.Backend.LoseStart = true;
        await f.Start();
        if (f.Handle is not null)
            await Assert.That(f.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(f.Window, f.Binding, f.Client,
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
    public async Task StatusPrivateDeleteIndependentCaptureRetainsStrictRouteEvidence(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", statusPrivateDeleteIndependent: true, boundary: "independent-effect");
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
    public async Task StatusPrivateDeleteIndependentCaptureRejectsPhysicalParserReplacement(string change)
    {
        Fixture? fixture = null;
        PrivateDeleteSelectedSubstitution? tap = null;
        using (fixture = new Fixture("DeletePrivateConnection", decorate: inner =>
            tap = new(inner, change, () => fixture!.Backend.StartBody), statusPrivateDeleteIndependent: true, boundary: "independent-effect"))
        {
            await fixture.Start();
            if (fixture.Handle is not null)
                await Assert.That(fixture.Source.TryGetStatusPrivateConnectionDeleteIndependentStart(fixture.Window,
                    fixture.Binding, fixture.Client, (PrivateConnectionScope)fixture.Scope, fixture.Receipt,
                    fixture.Window.Start!.SdkTask!, fixture.Handle, out _)).IsFalse();
            await Assert.That(tap!.Changes).IsEqualTo(1);
            await Assert.That(fixture.Backend.Requests.Count).IsEqualTo(1);
        }
    }

}
