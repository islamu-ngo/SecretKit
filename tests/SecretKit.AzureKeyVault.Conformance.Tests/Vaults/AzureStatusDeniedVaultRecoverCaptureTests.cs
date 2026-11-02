using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureManagementOperationNativeCaptureTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatusDeniedVaultRecoverThrowingRetentionHookStillJoinsActualTask(bool status)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority", statusDeniedVaultRecover: true);
        if (status)
        {
            await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
            f.Backend.StatusStatus = 403;
            f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        }
        f.Backend.BlockBody = true;
        var invocation = status
            ? f.Check(retained: _ => throw new InvalidOperationException("private-host-hook"))
            : f.Start(retained: _ => throw new InvalidOperationException("private-host-hook"));
        try
        {
            await f.Backend.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var seal = f.Source.SealAsync(f.Window);
            await Assert.That(invocation.IsCompleted || seal.IsCompleted).IsFalse();
            f.Backend.ReleaseBody.TrySetResult();
            await Assert.That(async () => await invocation.WaitAsync(TimeSpan.FromSeconds(10)))
                .Throws<InvalidOperationException>();
            var capture = await seal.WaitAsync(TimeSpan.FromSeconds(10));
            var observed = status ? capture.Status! : capture.Start!;
            await Assert.That(observed.Terminated && observed.SdkTask!.IsCompleted).IsTrue();
            await Assert.That(observed.Owned.All(b => b.All(v => v == 0))).IsTrue();
        }
        finally
        {
            f.Backend.ReleaseBody.TrySetResult();
            try { await invocation.WaitAsync(TimeSpan.FromSeconds(10)); }
            catch (InvalidOperationException) { }
        }
    }

    [Test]
    public async Task StatusDeniedVaultRecoverGenericCaptureCannotGrantQualifiedMembership()
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority");
        string body = f.Backend.StartBody;
        f.AsyncStart();
        f.Backend.StartStatus = 201;
        f.Backend.StartBody = body.Replace("Succeeded", "Updating", StringComparison.Ordinal);
        f.Backend.StatusStatus = 403;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverDenied(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count).IsEqualTo(2);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments(401)]
    [Arguments(403)]
    public async Task StatusDeniedVaultRecoverOwnsOriginalStartAndDeniedTask(int denied)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority", statusDeniedVaultRecover: true);
        f.Backend.StatusStatus = denied;
        f.Backend.StatusBody = """{"error":{"code":"AuthorizationFailed","message":"controlled-denial"}}""";
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Handle!.State).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle, out var issued)).IsTrue();
        await Assert.That(await f.Check(retained: task => check = task)).IsEqualTo(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverDenied(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle, check!, out var proof)).IsTrue();
        await Assert.That(f.Handle.State).IsEqualTo(NativeProvisioningState.Failed);
        await Assert.That(f.Receipt.Evidence).IsEqualTo(DispatchEvidence.Pending);
        var fake = new TaskCompletionSource<SecretStatus>(TaskCreationOptions.RunContinuationsAsynchronously);
        fake.SetResult(SecretStatus.Denied);
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverDenied(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle, fake.Task, out _)).IsFalse();
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverDenied(f.Window, f.Binding with { }, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle, check!, out _)).IsFalse();
        await Assert.That(await f.Handle.CheckStatusAsync()).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(1);
        await Assert.That(f.Backend.Authorizations.Distinct().Count()).IsEqualTo(1);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("synchronous")]
    [Arguments("202")]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("invalid-mode")]
    [Arguments("missing-target")]
    [Arguments("contradictory-target")]
    [Arguments("foreign-target")]
    [Arguments("lost")]
    public async Task StatusDeniedVaultRecoverRequiresOriginalQualified201(string fault)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority", statusDeniedVaultRecover: true);
        if (fault == "synchronous") f.Backend.StartStatus = 200;
        if (fault == "202") f.Backend.StartStatus = 202;
        if (fault == "empty") f.Backend.StartBody = "";
        if (fault == "malformed") f.Backend.StartBody = "{";
        if (fault == "invalid-mode") f.Backend.StartBody =
            f.Backend.StartBody.Replace("\"createMode\":\"recover\"", "\"createMode\":\"invalid\"", StringComparison.Ordinal);
        if (fault == "missing-target") f.Backend.Targets.Clear();
        if (fault == "contradictory-target")
            f.Backend.Targets[1] = ("Azure-AsyncOperation", "https://foreign.example/status");
        if (fault == "foreign-target")
        {
            f.Backend.Targets.Clear();
            f.Backend.Targets.Add(("Azure-AsyncOperation", "https://foreign.example/status"));
        }
        if (fault == "lost") f.Backend.LoseStart = true;
        Task? start = null;
        try { await f.Start(retained: task => start = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverStart(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, out _)).IsFalse();
        await Assert.That(f.Backend.Requests.Count(r => r.Method == "GET")).IsEqualTo(0);
        await f.Source.SealAsync(f.Window);
    }

    [Test]
    [Arguments("empty")]
    [Arguments("malformed")]
    [Arguments("missing-message")]
    [Arguments("duplicate")]
    [Arguments("success")]
    [Arguments("lost")]
    public async Task StatusDeniedVaultRecoverUnqualifiedPollCannotMintDenial(string fault)
    {
        using var f = new Fixture("RecoverVault", boundary: "denied-authority", statusDeniedVaultRecover: true);
        Task? start = null, check = null;
        await Assert.That(await f.Start(retained: task => start = task)).IsEqualTo(SecretStatus.Success);
        f.Backend.StatusStatus = fault == "success" ? 200 : 403;
        f.Backend.StatusBody = fault switch
        {
            "empty" => "",
            "missing-message" => """{"error":{"code":"AuthorizationFailed"}}""",
            "duplicate" => """{"error":{"code":"AuthorizationFailed","code":"Forbidden","message":"denied"}}""",
            "success" => """{"status":"Succeeded"}""",
            _ => "{"
        };
        f.Backend.LoseStatus = fault == "lost";
        try { await f.Check(retained: task => check = task); }
        catch (InvalidOperationException) { }
        await Assert.That(f.Source.TryGetStatusDeniedVaultRecoverDenied(f.Window, f.Binding, f.Client,
            (VaultScope)f.Scope, f.Receipt, start!, f.Handle!, check!, out _)).IsFalse();
        await f.Source.SealAsync(f.Window);
    }
}
