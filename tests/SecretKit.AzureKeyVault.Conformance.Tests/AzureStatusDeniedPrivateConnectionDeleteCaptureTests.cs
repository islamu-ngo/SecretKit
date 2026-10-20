using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments("200")]
    [Arguments("204")]
    [Arguments("body")]
    [Arguments("missing-target")]
    [Arguments("foreign-target")]
    [Arguments("third-target")]
    [Arguments("retry")]
    [Arguments("lost")]
    public async Task StatusDeniedPrivateConnectionDeleteRequiresExactEmpty202(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", boundary: "denied-authority",
            statusDeniedPrivateConnectionDelete: true);
        if (fault is "200" or "204") f.Backend.StartStatus = int.Parse(fault);
        if (fault == "body") f.Backend.StartBody = """{"status":"InProgress"}""";
        if (fault == "missing-target") f.Backend.Targets.Clear();
        if (fault == "foreign-target")
        {
            f.Backend.Targets.Clear();
            f.Backend.Targets.Add(("Location", "https://foreign.example/status"));
            f.Backend.Targets.Add(("Azure-AsyncOperation", "https://foreign.example/status"));
        }
        if (fault == "third-target") f.Backend.Targets.Add(("Operation-Location", StatusUrl));
        if (fault == "retry") f.Backend.ExtraHeaders.Add(("Retry-After", "1"));
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        try { await f.Start(retained: task => start = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusDeniedPrivateConnectionDeleteRawFactsCannotEnrollQualifiedProofs()
    {
        using var f = new Fixture("DeletePrivateConnection", boundary: "denied-authority");
        f.AsyncStart();
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        var started = await f.Source.StartAsync(f.Window, f.Binding.Selector, f.Client, f.Scope,
            f.Input, f.Receipt, retained: task => start = task);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding.Selector, started.Value!,
            default, task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, started.Value!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, started.Value!, check!, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    public async Task StatusDeniedPrivateConnectionDeleteBindsFirstActualScopeWithoutAllowingLaterSubstitution()
    {
        using var f = new Fixture("DeletePrivateConnection", boundary: "denied-authority", statusDeniedPrivateConnectionDelete: true);
        var planned = (PrivateConnectionScope)f.Scope;
        var actual = new PrivateConnectionScope(planned.Vault, planned.ConnectionName);
        var receipt = f.Client.PrepareReceipt(actual, ManagementMutation.DeletePrivateConnection);
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        var started = await f.Source.StartStatusDeniedPrivateConnectionDeleteAsync(f.Window, f.Binding.Selector, f.Client,
            actual, f.Input, receipt, default, task => start = task);
        await Assert.That(started.IsSuccess).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteStart(f.Window, f.Binding, f.Client,
            actual, receipt, start!, started.Value!, out _)).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteStart(f.Window, f.Binding, f.Client,
            planned, receipt, start!, started.Value!, out _)).IsFalse();
        await Assert.That(await f.Source.CheckStatusDeniedPrivateConnectionDeleteAsync(f.Window, f.Binding.Selector,
            started.Value!, default, task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            actual, receipt, start!, started.Value!, check!, out _)).IsTrue();
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            planned, receipt, start!, started.Value!, check!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(401, false)]
    [Arguments(403, false)]
    [Arguments(401, true)]
    [Arguments(403, true)]
    public async Task StatusDeniedPrivateConnectionDeleteOwnsActualStartAndDeniedTasks(int status, bool absentStream)
    {
        using var f = new Fixture("DeletePrivateConnection", boundary: "denied-authority", statusDeniedPrivateConnectionDelete: true);
        f.Backend.NullResponseStream = absentStream;
        f.Backend.StatusStatus = status;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteStart(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle!, out var issued)).IsTrue();
        await Assert.That(issued!.HttpStatus).IsEqualTo(202);
        await Assert.That(issued.ResponseBytes).IsEqualTo(0);
        await Assert.That(ReferenceEquals(issued.StartTask, start)).IsTrue();
        await Assert.That(ReferenceEquals(issued.Target.Binding, f.Binding)).IsTrue();
        await Assert.That(issued.Target.StartDispatch).IsEqualTo(issued.StartDispatch);
        f.Backend.NullResponseStream = false;
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out var proof)).IsTrue();
        await Assert.That(ReferenceEquals(proof!.Start, issued)).IsTrue();
        await Assert.That(proof.HttpStatus).IsEqualTo(status);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var forged = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        forged.SetResult(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, forged.Task, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding with { }, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle, check!, out _)).IsFalse();
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("missing-message")]
    [Arguments("duplicate")]
    [Arguments("state-only")]
    [Arguments("success")]
    [Arguments("lost")]
    public async Task StatusDeniedPrivateConnectionDeleteUnqualifiedWireCannotMintDenial(string fault)
    {
        using var f = new Fixture("DeletePrivateConnection", boundary: "denied-authority", statusDeniedPrivateConnectionDelete: true);
        Task? start = null, check = null;
        await f.Start(retained: task => start = task);
        f.Backend.StatusStatus = fault == "success" ? 200 : 403;
        f.Backend.StatusBody = fault switch
        {
            "empty" => "",
            "missing-message" => """{"error":{"code":"AuthorizationFailed"}}""",
            "duplicate" => """{"error":{"code":"AuthorizationFailed","message":"one","message":"two"}}""",
            "state-only" => """{"status":"Forbidden"}""",
            "success" => f.Backend.StartBody.Replace("Updating", "Succeeded", StringComparison.Ordinal),
            _ => "{"
        };
        if (fault == "lost") f.Backend.LoseStatus = true;
        try { await f.Check(retained: task => check = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedPrivateConnectionDeleteDenied(f.Window, f.Binding, f.Client,
            (PrivateConnectionScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }
}
