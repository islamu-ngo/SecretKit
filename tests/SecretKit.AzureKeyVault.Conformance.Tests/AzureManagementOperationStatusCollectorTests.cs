using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationStatusCollector;
using Capture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationNativeCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureManagementOperationStatusCollectorTests
{
    private const string Origin = "https://management.azure.com";
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Tenant = "22222222-2222-2222-2222-222222222222";
    private const string OperationId = "33333333-3333-3333-3333-333333333333";
    private const string Assignment = "44444444-4444-4444-4444-444444444444";
    private const string Vault = "/subscriptions/" + Subscription +
        "/resourceGroups/status-group/providers/Microsoft.KeyVault/vaults/status-vault";
    private const string Connection = Vault + "/privateEndpointConnections/status-connection";
    private const string Notification = Vault + "/providers/Microsoft.EventGrid/eventSubscriptions/status-notification";
    private const string OperationPath = "/subscriptions/" + Subscription +
        "/providers/Microsoft.KeyVault/locations/eastus/operations/" + OperationId;
    private const string StatusUri = Origin + OperationPath + "?api-version=2026-02-01";
    private const string Protected = "private-status-material";
    private static readonly DateTimeOffset Now = new(2026, 10, 15, 0, 0, 0, TimeSpan.Zero);
    private static readonly C.Limits Limits = new(65536, 8192, 512, TimeSpan.FromSeconds(20));

    [Test]
    [Arguments("CreateOrUpdateVault", true)]
    [Arguments("RecoverVault", true)]
    [Arguments("DeleteVault", true)]
    [Arguments("PurgeDeletedVault", true)]
    [Arguments("UpdatePrivateConnection", true)]
    [Arguments("DeletePrivateConnection", true)]
    [Arguments("DeleteRoleAssignment", false)]
    [Arguments("CreateOrUpdateNotification", true)]
    [Arguments("UpdateNotification", true)]
    [Arguments("DeleteNotification", true)]
    public async Task ActualInstalledStartsKeepOperationAndRevisionWithoutInventingTargets(string operation, bool eligible)
    {
        using var f = new Fixture(operation);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        bool issued = f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out var target);
        await Assert.That(issued).IsEqualTo(eligible);
        if (!eligible)
        {
            await Assert.That(f.Binding.ApiRevision).IsEqualTo("2022-04-01");
            await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
            return;
        }
        var snapshot = target ?? throw new InvalidOperationException("test-no-actual-native-target");
        await f.Source.SealAsync(f.NativeWindow);
        var result = await f.Collector.CollectAsync(f.Collector.Arm(snapshot, f.Binding), f.Binding);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(result.Binding).IsEqualTo(f.Binding);
        await Assert.That(result.StartDispatch).IsEqualTo(f.NativeWindow.Start!.Attempts.Single().Dispatch);
        await Assert.That(result.TargetSha256).IsEqualTo(snapshot.TargetSha256);
        await Assert.That(result.StartResponseSha256).IsEqualTo(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(f.StartState.Body))));
        var request = f.Reader.Requests.Single();
        await Assert.That(request.Uri).IsEqualTo(snapshot.TargetUri.AbsoluteUri);
        await Assert.That(request.Method).IsEqualTo("GET");
        await Assert.That(request.Body).IsNull();
        await Assert.That(request.Authorization).IsEqualTo("Bearer independent-reader");
        await Assert.That(f.ReaderCredential.Scopes.Single()).IsEqualTo(Origin + "/.default");
        await Assert.That(f.SelectedCredential.Scopes.Single()).IsEqualTo(Origin + "/.default");
        await Assert.That(result.ApiRevision).IsEqualTo(f.Binding.ApiRevision);
        await Assert.That(result.Identity).IsEqualTo("host-reader");
        await Assert.That(result.ArmedAt).IsEqualTo(Now);
        await Assert.That(result.StartedAt).IsEqualTo(Now);
        await Assert.That(result.FinishedAt).IsEqualTo(Now);
        await Assert.That(f.Native.Requests.Count).IsEqualTo(1);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("InProgress", "Pending")]
    [Arguments("Running", "Pending")]
    [Arguments("Accepted", "Pending")]
    [Arguments("Succeeded", "Succeeded")]
    [Arguments("Failed", "Failed")]
    [Arguments("Canceled", "Canceled")]
    [Arguments("Cancelled", "Canceled")]
    [Arguments("Unknown", "Unknown")]
    [Arguments("unrecognized-native-state", "Unknown")]
    public async Task IndependentProviderStateNeverComesFromRequestedSucceededVariant(string state, string expected)
    {
        using var f = new Fixture(variant: "status.Succeeded");
        var target = await f.Target();
        f.ReadState.Body = JsonSerializer.Serialize(new { id = OperationPath, name = OperationId, status = state });
        var result = await f.Read(target);
        var native = Enum.Parse<NativeProvisioningState>(expected);
        await Assert.That(result.OperationState).IsEqualTo(native);
        await Assert.That(result.Status).IsEqualTo(native switch
        {
            NativeProvisioningState.Succeeded => SecretStatus.Success,
            NativeProvisioningState.Pending => SecretStatus.Pending,
            _ => SecretStatus.Unknown
        });
        await Assert.That(result.Terminal).IsEqualTo(native is NativeProvisioningState.Succeeded or
            NativeProvisioningState.Failed or NativeProvisioningState.Canceled);
        await Assert.That(f.NativeWindow.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        await Assert.That(f.NativeWindow.Status).IsNull();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("Updating", "Pending")]
    [Arguments("Succeeded", "Succeeded")]
    [Arguments("Failed", "Failed")]
    [Arguments("Canceled", "Canceled")]
    [Arguments("new-state", "Unknown")]
    public async Task SelectedResourceTargetReadsOnlyNativeProvisioningStatus(string state, string expected)
    {
        using var f = new Fixture("CreateOrUpdateNotification", "status.Succeeded");
        var target = await f.Target();
        f.ReadState.Body = NotificationBody(state);
        var result = await f.Read(target);
        await Assert.That(target.Kind).IsEqualTo(Capture.StatusTargetKind.SelectedResource);
        await Assert.That(result.OperationState).IsEqualTo(Enum.Parse<NativeProvisioningState>(expected));
        await Assert.That(f.Reader.Requests.Single().Uri).IsEqualTo(
            Origin + Notification + "?api-version=2025-02-15");
        await Assert.That(JsonSerializer.Serialize(result)).IsEqualTo("{}");
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("id")]
    [Arguments("name")]
    [Arguments("type")]
    [Arguments("topic")]
    [Arguments("missing-state")]
    [Arguments("conflicting-status")]
    public async Task SelectedResourceIdentityAndStateMustBeCompleteAndExact(string fault)
    {
        using var f = new Fixture("CreateOrUpdateNotification");
        var target = await f.Target();
        string body = NotificationBody("Succeeded");
        f.ReadState.Body = fault switch
        {
            "id" => body.Replace(Notification, Notification + "-foreign", StringComparison.Ordinal),
            "name" => body.Replace("\"name\":\"status-notification\"", "\"name\":\"foreign\"", StringComparison.Ordinal),
            "type" => body.Replace("Microsoft.EventGrid/eventSubscriptions", "Microsoft.KeyVault/vaults", StringComparison.Ordinal),
            "topic" => body.Replace("\"topic\":\"" + Vault + "\"", "\"topic\":\"/foreign\"", StringComparison.Ordinal),
            "missing-state" => body.Replace("\"provisioningState\":\"Succeeded\"", "\"unrelated\":\"Succeeded\"", StringComparison.Ordinal),
            _ => body.Insert(1, "\"status\":\"Succeeded\",")
        };
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task ExistingNotificationProvisioningCannotEstablishDeletionSettlement()
    {
        using var f = new Fixture("DeleteNotification");
        var target = await f.Target();
        f.ReadState.Body = NotificationBody("Succeeded");
        var result = await f.Read(target);
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(result.Status == SecretStatus.Success || result.Terminal).IsFalse();
    }

    [Test]
    public async Task RejectedSdkStartCannotBeQualifiedThroughMutableDiagnostics()
    {
        using var f = new Fixture("CreateOrUpdateVault");
        f.StartState.Status = 202;
        f.StartState.Body = "";
        await Assert.That(await f.Start() == SecretStatus.Success).IsFalse();
        var invocation = f.NativeWindow.Start ?? throw new InvalidOperationException("missing-native-invocation");
        invocation.Outcome = SecretStatus.Success;
        invocation.HasNativeHandle = true;
        await Assert.That(f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task CachedPrivateConnectionSuccessIsNotIndependentRemoteSettlement()
    {
        using var f = new Fixture("UpdatePrivateConnection");
        var target = await f.Target();
        await Assert.That(await f.Source.CheckStatusAsync(f.NativeWindow, f.Binding.Selector, f.Handle!)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Requests.Count).IsEqualTo(1);
        await Assert.That(f.NativeWindow.Status!.Attempts.Count).IsEqualTo(0);
        await Assert.That(f.NativeWindow.Start!.Attempts.Single().State).IsEqualTo(Capture.WireState.Pending);
        var result = await f.Read(target);
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(result.Terminal).IsFalse();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task CapturedOperationResultsTemplateIsReadWithoutFollowingAnotherCoordinate()
    {
        using var f = new Fixture();
        f.StartState.Headers.Clear();
        string uri = StatusUri.Replace("/operations/", "/operationResults/", StringComparison.Ordinal);
        f.StartState.Headers.Add(("Location", uri));
        var target = await f.Target();
        f.ReadState.Body = """{"status":"Succeeded"}""";
        var result = await f.Read(target);
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Reader.Requests.Single().Uri).IsEqualTo(uri);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("selector-scope")]
    [Arguments("selector-operation")]
    [Arguments("selector-variant")]
    [Arguments("selector-case")]
    [Arguments("lease")]
    [Arguments("resource")]
    [Arguments("operation")]
    [Arguments("location")]
    [Arguments("revision")]
    public async Task FullBindingSubstitutionCannotArmOrConsumeAnObserverWindow(string field)
    {
        using var f = new Fixture();
        var target = await f.Target();
        var b = field switch
        {
            "nonce" => f.Binding with { Selector = f.Binding.Selector with { Nonce = Guid.NewGuid() } },
            "selector-scope" => f.Binding with { Selector = f.Binding.Selector with { Scope = "foreign-native-case" } },
            "selector-operation" => f.Binding with { Selector = f.Binding.Selector with { Operation = "foreign-operation" } },
            "selector-variant" => f.Binding with { Selector = f.Binding.Selector with { Variant = "status.Failed" } },
            "selector-case" => f.Binding with { Selector = f.Binding.Selector with { Case = "foreign-case" } },
            "lease" => f.Binding with { LeaseId = Guid.NewGuid() },
            "resource" => f.Binding with { Resource = new DeletedVaultScope(new(Guid.Parse(Subscription)), "eastus", "foreign-vault") },
            "operation" => f.Binding with { Operation = ManagementMutation.DeleteVault },
            "location" => f.Binding with { Location = "westus" },
            _ => f.Binding with { ApiRevision = "2022-04-01" }
        };
        await Assert.That(() => f.Collector.Arm(target, b)).Throws<InvalidOperationException>();
        var window = f.Collector.Arm(target, f.Binding);
        await Assert.That(async () => await f.Collector.CollectAsync(window, b)).Throws<InvalidOperationException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
        await Assert.That((await f.Collector.CollectAsync(window, f.Binding)).OperationState)
            .IsEqualTo(NativeProvisioningState.Pending);
    }

    [Test]
    [Arguments("identical")]
    [Arguments("dispatch")]
    [Arguments("target-hash")]
    [Arguments("response-hash")]
    [Arguments("kind")]
    [Arguments("hostile-uri")]
    [Arguments("binding")]
    public async Task EvenIdenticalClonedTargetsCannotBorrowSourceProvenance(string field)
    {
        using var f = new Fixture();
        var target = await f.Target();
        var copy = new Capture.StatusTarget(
            field == "binding" ? f.Binding with { LeaseId = Guid.NewGuid() } : target.Binding,
            field == "dispatch" ? Guid.NewGuid() : target.StartDispatch,
            field == "kind" ? Capture.StatusTargetKind.SelectedResource : target.Kind,
            field == "hostile-uri" ? new Uri("https://foreign.invalid/" + Protected) : target.TargetUri,
            field == "target-hash" ? new string('0', 64) : target.TargetSha256,
            field == "response-hash" ? new string('0', 64) : target.StartResponseSha256);
        await Assert.That(() => f.Collector.Arm(copy, copy.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ForgedForeignAndReplayedWindowsNeverSendOrRearm()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        var forged = new C.Window(target, f.Binding, window.ArmedAt);
        await Assert.That(async () => await f.Collector.CollectAsync(forged, f.Binding)).Throws<InvalidOperationException>();
        var foreign = new C(f.Source, new("host-reader", f.ReaderCredential, f.Reader), Limits, f.Clock);
        await Assert.That(async () => await foreign.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(() => foreign.Arm(new(target.Binding, target.StartDispatch, target.Kind,
            target.TargetUri, target.TargetSha256, target.StartResponseSha256), f.Binding)).Throws<InvalidOperationException>();
        await f.Collector.CollectAsync(window, f.Binding);
        await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Collector.Arm(target, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task ForeignCaptureOwnerCannotAuthorizeAnOtherwiseRealTarget()
    {
        using var f = new Fixture();
        using var other = new Fixture();
        var target = await f.Target();
        await Assert.That(() => other.Collector.Arm(target, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(other.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task MutableCaptureFieldsCannotRedirectFrozenTargetAfterSeal()
    {
        using var f = new Fixture();
        var target = await f.Target();
        f.NativeWindow.Continuation = "https://foreign.invalid/" + Protected;
        f.NativeWindow.Start!.Attempts.Single().ResponseSha256 = new string('0', 64);
        await f.Source.SealAsync(f.NativeWindow);
        var result = await f.Read(target);
        await Assert.That(result.TargetSha256).IsEqualTo(target.TargetSha256);
        await Assert.That(result.StartResponseSha256).IsEqualTo(target.StartResponseSha256);
        await Assert.That(f.Reader.Requests.Single().Uri).IsEqualTo(StatusUri);
    }

    [Test]
    [Arguments("unstarted")]
    [Arguments("synchronous")]
    [Arguments("denied")]
    [Arguments("lost")]
    [Arguments("rejected-start")]
    [Arguments("no-target")]
    [Arguments("canceled")]
    public async Task MissingActualEligibleStartNeverCreatesObserverAuthority(string kind)
    {
        using var f = new Fixture(kind == "rejected-start" ? "CreateOrUpdateVault" : "PurgeDeletedVault");
        if (kind is "synchronous" or "no-target") f.StartState.Headers.Clear();
        if (kind == "synchronous") f.StartState.Status = 200;
        if (kind == "denied")
        {
            f.StartState.Status = 403;
            f.StartState.Body = ErrorBody();
        }
        if (kind == "lost") f.StartState.Lose = true;
        if (kind == "rejected-start") { f.StartState.Status = 202; f.StartState.Body = ""; }
        if (kind == "canceled")
        {
            using var canceled = new CancellationTokenSource();
            canceled.Cancel();
            await Assert.That(async () => await f.Start(canceled.Token)).Throws<OperationCanceledException>();
        }
        else if (kind != "unstarted") _ = await f.Start();
        await f.Source.SealAsync(f.NativeWindow);
        await Assert.That(f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out _)).IsFalse();
        await Assert.That(() => f.Collector.Arm(null!, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task StartSendReturningDoesNotIssueTargetBeforeWholeSdkTaskTerminates()
    {
        using var f = new Fixture();
        f.StartState.Barrier = "body";
        var task = f.Start();
        try
        {
            await f.Native.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out _)).IsFalse();
            await Assert.That(task.IsCompleted).IsFalse();
        }
        finally { f.Native.Release.TrySetResult(); await task; }
        await Assert.That(f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out _)).IsTrue();
    }

    [Test]
    [Arguments(202)]
    [Arguments(204)]
    [Arguments(301)]
    [Arguments(401)]
    [Arguments(403)]
    [Arguments(404)]
    [Arguments(429)]
    [Arguments(500)]
    public async Task AcceptanceAbsenceDenialRedirectAndErrorsCannotAssertSettlement(int status)
    {
        using var f = new Fixture();
        var target = await f.Target();
        f.ReadState.Status = status;
        f.ReadState.Body = status >= 400 ? ErrorBody() : """{"status":"Succeeded"}""";
        if (status == 301) f.ReadState.Headers.Add(("Location", "https://foreign.invalid/" + Protected));
        var result = await f.Read(target);
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.Terminal).IsFalse();
        await Assert.That(result.Status == SecretStatus.Success || result.Status == SecretStatus.Absent).IsFalse();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("duplicate")]
    [Arguments("case-duplicate")]
    [Arguments("invalid-json")]
    [Arguments("empty")]
    [Arguments("array")]
    [Arguments("missing-state")]
    [Arguments("null-state")]
    [Arguments("numeric-state")]
    [Arguments("foreign-id")]
    [Arguments("foreign-name")]
    [Arguments("next-link")]
    [Arguments("value")]
    [Arguments("partial")]
    [Arguments("error-in-success")]
    [Arguments("error-only")]
    [Arguments("noncanonical-error")]
    [Arguments("invalid-error")]
    [Arguments("conflicting-state")]
    [Arguments("case-conflicting-state")]
    public async Task AmbiguousPartialOrForeignStatusPayloadsRemainUnknown(string fault)
    {
        using var f = new Fixture();
        var target = await f.Target();
        f.ReadState.Body = fault switch
        {
            "duplicate" => """{"status":"Succeeded","status":"Failed"}""",
            "case-duplicate" => """{"status":"Succeeded","Status":"Failed"}""",
            "invalid-json" => """{"status":"Succeeded" """,
            "empty" => "",
            "array" => """[{"status":"Succeeded"}]""",
            "missing-state" => "{}",
            "null-state" => """{"status":null}""",
            "numeric-state" => """{"status":1}""",
            "foreign-id" => """{"id":"/foreign/operation","status":"Succeeded"}""",
            "foreign-name" => """{"name":"foreign-operation","status":"Succeeded"}""",
            "next-link" => """{"status":"Succeeded","nextLink":"https://foreign.invalid/private"}""",
            "value" => """{"status":"Succeeded","value":[]}""",
            "partial" => """{"status":"Succeeded","partial":true}""",
            "error-in-success" => """{"status":"Succeeded","error":{"code":"Partial","message":"private"}}""",
            "error-only" => ErrorBody(),
            "noncanonical-error" => """{"status":"Succeeded","Error":{"code":"Partial","message":"private"}}""",
            "invalid-error" => """{"status":"Failed","error":{"code":123}}""",
            "conflicting-state" => """{"status":"Succeeded","properties":{"provisioningState":"Failed"}}""",
            _ => """{"status":"Succeeded","properties":{"ProvisioningState":"Failed"}}"""
        };
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(result.Terminal).IsFalse();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("Failed")]
    [Arguments("Canceled")]
    public async Task ValidNativeTerminalFailureWithProviderErrorRetainsFailureNotSuccess(string state)
    {
        using var f = new Fixture();
        var target = await f.Target();
        f.ReadState.Body = JsonSerializer.Serialize(new
        {
            status = state,
            error = new { code = "NativeFailure", message = Protected, details = new[] { new { code = "Detail", message = Protected } } }
        });
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsTrue();
        await Assert.That(result.OperationState).IsEqualTo(Enum.Parse<NativeProvisioningState>(state));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(result.Terminal).IsTrue();
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("http")]
    [Arguments("host")]
    [Arguments("port")]
    [Arguments("userinfo")]
    [Arguments("fragment")]
    [Arguments("revision")]
    [Arguments("query")]
    [Arguments("subscription")]
    [Arguments("location")]
    [Arguments("operation")]
    public async Task HostileProviderStartCoordinatesNeverReachReader(string fault)
    {
        using var f = new Fixture();
        string uri = fault switch
        {
            "http" => StatusUri.Replace("https:", "http:", StringComparison.Ordinal),
            "host" => StatusUri.Replace("management.azure.com", "foreign.invalid", StringComparison.Ordinal),
            "port" => StatusUri.Replace("management.azure.com", "management.azure.com:444", StringComparison.Ordinal),
            "userinfo" => StatusUri.Replace("https://", "https://private@", StringComparison.Ordinal),
            "fragment" => StatusUri + "#private",
            "revision" => StatusUri.Replace("2026-02-01", "2022-04-01", StringComparison.Ordinal),
            "query" => StatusUri + "&private=material",
            "subscription" => StatusUri.Replace(Subscription, Tenant, StringComparison.Ordinal),
            "location" => StatusUri.Replace("eastus", "westus", StringComparison.Ordinal),
            _ => StatusUri.Replace(OperationId, "not-an-operation", StringComparison.Ordinal)
        };
        f.StartState.Headers.Clear();
        f.StartState.Headers.Add(("Location", uri));
        _ = await f.Start();
        await Assert.That(f.Source.TryGetStatusTarget(f.NativeWindow, f.Binding, out _)).IsFalse();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("response-bytes")]
    [Arguments("row-bytes")]
    [Arguments("rows")]
    [Arguments("depth")]
    [Arguments("header-length")]
    [Arguments("header-count")]
    [Arguments("header-total")]
    [Arguments("declared-overflow")]
    [Arguments("declared-negative")]
    [Arguments("declared-invalid")]
    [Arguments("declared-mismatch")]
    [Arguments("request-id-duplicate")]
    [Arguments("foreign-location")]
    [Arguments("partial-header")]
    [Arguments("content-type")]
    [Arguments("encoding")]
    public async Task BoundedResponseValidationClearsOwnedBuffersOnEveryRejectedShape(string fault)
    {
        using var f = new Fixture();
        var target = await f.Target();
        if (fault == "response-bytes") f.ReadState.Body = new string('x', 65537);
        if (fault == "row-bytes") f.ReadState.Body = JsonSerializer.Serialize(new { status = "Succeeded", extra = new string('x', 8192) });
        if (fault == "rows") f.ReadState.Body = """{"status":"Succeeded","items":[""" +
            string.Join(',', Enumerable.Repeat("0", 513)) + "]}";
        if (fault == "depth") f.ReadState.Body = new string('[', 18) + "0" + new string(']', 18);
        if (fault == "header-length") f.ReadState.Headers.Add(("x-private", new string('x', 4097)));
        if (fault == "header-count")
            f.ReadState.Headers.AddRange(Enumerable.Range(0, 33).Select(i => ("x-private-" + i, "v")));
        if (fault == "header-total")
            f.ReadState.Headers.AddRange(Enumerable.Range(0, 5).Select(i => ("x-private-" + i, new string('x', 4000))));
        if (fault == "declared-overflow") f.ReadState.DeclaredLength = "65537";
        if (fault == "declared-negative") f.ReadState.DeclaredLength = "-1";
        if (fault == "declared-invalid") f.ReadState.DeclaredLength = "invalid";
        if (fault == "declared-mismatch") f.ReadState.DeclaredLength = "1";
        if (fault == "request-id-duplicate") f.ReadState.Headers.Add(("x-ms-request-id", "foreign-id"));
        if (fault == "foreign-location") f.ReadState.Headers.Add(("Location", "https://foreign.invalid/" + Protected));
        if (fault == "partial-header") f.ReadState.Headers.Add(("Content-Range", "bytes 0-1/20"));
        if (fault == "content-type") f.ReadState.ContentType = "text/html";
        if (fault == "encoding") f.ReadState.Headers.Add(("Content-Encoding", "gzip"));
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("uri")]
    [Arguments("query")]
    [Arguments("method")]
    [Arguments("body")]
    [Arguments("headers")]
    [Arguments("host")]
    public async Task CredentialTimeRequestSubstitutionFailsBeforeBorrowedTransportSend(string fault)
    {
        using var f = new Fixture();
        var target = await f.Target();
        f.ReaderCredential.BeforeToken = () =>
        {
            var request = f.Reader.LastRequest!;
            if (fault == "method") request.Method = RequestMethod.Post;
            else if (fault == "body") request.Content = RequestContent.Create(Encoding.UTF8.GetBytes(Protected));
            else if (fault == "headers") request.Headers.SetValue("x-private", new string('x', 4097));
            else if (fault == "host") request.Headers.SetValue("Host", "foreign.invalid");
            else request.Uri.Reset(new Uri(fault == "query" ? StatusUri + "&private=material" : "https://foreign.invalid/private"));
        };
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("expired")]
    [Arguments("wall-expired")]
    [Arguments("wall-backward")]
    [Arguments("timestamp-backward")]
    public async Task ArmedMonotonicWindowRejectsExpiryAndClockRollbackBeforeSend(string fault)
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        if (fault == "expired") f.Clock.Advance(Limits.Timeout);
        if (fault == "wall-expired") f.Clock.WallTicks = Limits.Timeout.Ticks;
        if (fault == "wall-backward") f.Clock.WallTicks = -1;
        if (fault == "timestamp-backward") f.Clock.Ticks = -1;
        var result = await f.Collector.CollectAsync(window, f.Binding);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
        await Assert.That(f.ReaderCredential.Scopes.Count).IsEqualTo(0);
        await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task WallClockChangesDuringReadCannotProduceTimelySuccessfulEvidence(bool forward)
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.ReadState.Body = """{"status":"Succeeded"}""";
        f.ReadState.Barrier = "body";
        var invocation = f.Collector.CollectAsync(window, f.Binding).AsTask();
        try
        {
            await f.Reader.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Clock.WallTicks = forward ? Limits.Timeout.Ticks : -1;
            f.Reader.Release.TrySetResult();
            var result = await invocation.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(result.ResponseComplete).IsFalse();
            await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        }
        finally { f.Reader.Release.TrySetResult(); await invocation; }
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments("bytes")]
    [Arguments("row")]
    [Arguments("rows")]
    [Arguments("timeout")]
    [Arguments("label")]
    [Arguments("credential")]
    [Arguments("transport")]
    public async Task InvalidAuthorityOrLimitsFailWithSanitizedInputError(string fault)
    {
        using var f = new Fixture();
        var limits = fault switch
        {
            "bytes" => Limits with { MaximumResponseBytes = 1024 * 1024 + 1 },
            "row" => Limits with { MaximumRowBytes = 65537 },
            "rows" => Limits with { MaximumRows = 0 },
            "timeout" => Limits with { Timeout = TimeSpan.Zero },
            _ => Limits
        };
        var authority = new C.Authority(fault == "label" ? Protected + "\n" : "host-reader",
            fault == "credential" ? null! : f.ReaderCredential, fault == "transport" ? null! : f.Reader);
        await Assert.That(() => new C(f.Source, authority, limits, f.Clock)).Throws<ArgumentException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("send", false)]
    [Arguments("body", false)]
    [Arguments("credential", false)]
    [Arguments("send", true)]
    [Arguments("body", true)]
    [Arguments("credential", true)]
    public async Task CancellationAndDeadlineWaitForActualInvocationBeforeErasing(string barrier, bool deadline)
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.ReadState.Barrier = barrier;
        f.ReaderCredential.Block = barrier == "credential";
        using var cancellation = new CancellationTokenSource();
        var invocation = f.Collector.CollectAsync(window, f.Binding, cancellation.Token).AsTask();
        try
        {
            await (barrier == "credential" ? f.ReaderCredential.Entered.Task :
                barrier == "send" ? f.Reader.SendEntered.Task : f.Reader.BodyEntered.Task)
                .WaitAsync(TimeSpan.FromSeconds(10));
            if (deadline) f.Clock.Advance(Limits.Timeout);
            else cancellation.Cancel();
            await (barrier == "credential" ? f.ReaderCredential.CancellationObserved.Task : f.Reader.CancellationObserved.Task)
                .WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(invocation.IsCompleted).IsFalse();
            if (barrier == "body")
            {
                await Assert.That(f.Reader.SendReturned.Task.IsCompleted).IsTrue();
                await Assert.That(f.Reader.Buffers.Count > 0).IsTrue();
                await Assert.That(f.Reader.Buffers.Any(bytes => bytes.Any(b => b != 0))).IsTrue();
            }
            await Assert.That(f.Reader.Disposed || f.ReaderCredential.Disposed).IsFalse();
            f.Reader.Release.TrySetResult();
            f.ReaderCredential.Release.TrySetResult();
            if (deadline)
            {
                var result = await invocation.WaitAsync(TimeSpan.FromSeconds(10));
                await Assert.That(result.Failure).IsEqualTo(C.Failure.Deadline);
                await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
            }
            else
                await Assert.That(async () => await invocation.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
            await ClearedAndBorrowed(f);
            await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        }
        finally
        {
            f.Reader.Release.TrySetResult();
            f.ReaderCredential.Release.TrySetResult();
            try { await invocation; } catch (OperationCanceledException) { }
        }
    }

    [Test]
    public async Task ArmedElapsedTimeIsDeductedFromTheActualReadDeadline()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.Clock.Advance(Limits.Timeout / 2);
        f.ReadState.Barrier = "body";
        var invocation = f.Collector.CollectAsync(window, f.Binding).AsTask();
        try
        {
            await f.Reader.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Clock.Advance(Limits.Timeout / 2);
            await f.Reader.CancellationObserved.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(invocation.IsCompleted).IsFalse();
            f.Reader.Release.TrySetResult();
            await Assert.That((await invocation.WaitAsync(TimeSpan.FromSeconds(10))).Failure).IsEqualTo(C.Failure.Deadline);
        }
        finally { f.Reader.Release.TrySetResult(); await invocation; }
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task WallElapsedTimeBoundsTheRemainingReadDeadline()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.Clock.WallTicks = (Limits.Timeout / 2).Ticks;
        f.ReadState.Barrier = "body";
        var invocation = f.Collector.CollectAsync(window, f.Binding).AsTask();
        try
        {
            await f.Reader.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            f.Clock.Advance(Limits.Timeout / 2);
            await Assert.That(f.Reader.CancellationObserved.Task.IsCompleted).IsTrue();
            await Assert.That(invocation.IsCompleted).IsFalse();
            f.Reader.Release.TrySetResult();
            await Assert.That((await invocation).Failure).IsEqualTo(C.Failure.Deadline);
        }
        finally { f.Reader.Release.TrySetResult(); await invocation; }
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task PreCanceledInvocationConsumesItsWindowWithoutDispatch()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ConcurrentDuplicateCannotSendWhileOriginalInvocationIsStillRunning()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.ReadState.Barrier = "body";
        var first = f.Collector.CollectAsync(window, f.Binding).AsTask();
        try
        {
            await f.Reader.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(async () => await f.Collector.CollectAsync(window, f.Binding)).Throws<InvalidOperationException>();
            await Assert.That(f.Reader.Requests.Count).IsEqualTo(1);
        }
        finally { f.Reader.Release.TrySetResult(); await first; }
        await ClearedAndBorrowed(f);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeAndCredentialFailuresAreSanitizedWithoutFallbackOrRetry(bool credential)
    {
        using var f = new Fixture();
        var target = await f.Target();
        if (credential) f.ReaderCredential.Throw = true;
        else f.ReadState.Lose = true;
        var result = await f.Read(target);
        await Assert.That(result.ResponseComplete).IsFalse();
        await Assert.That(result.OperationState).IsEqualTo(NativeProvisioningState.Unknown);
        await Assert.That(f.ReaderCredential.Scopes.Count).IsEqualTo(1);
        await Assert.That(f.Reader.Requests.Count).IsEqualTo(credential ? 0 : 1);
        await Assert.That(result.ToString().Contains(Protected, StringComparison.Ordinal)).IsFalse();
        await ClearedAndBorrowed(f);
    }

    [Test]
    public async Task FormattingSerializationAndBoundaryFailuresExposeNoCoordinatesOrMaterial()
    {
        using var f = new Fixture();
        var target = await f.Target();
        var window = f.Collector.Arm(target, f.Binding);
        f.ReadState.Body = """{"status":"Failed","error":{"code":"Native","message":"private-status-material"}}""";
        var result = await f.Collector.CollectAsync(window, f.Binding);
        object[] values = [f.Collector, target, window, result, f.Binding, new C.Authority("private-status-material", f.ReaderCredential, f.Reader)];
        foreach (var value in values)
        {
            await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            await Assert.That(value.ToString()!.Contains(Protected, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(Subscription, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("https://", StringComparison.Ordinal)).IsFalse();
        }
        try
        {
            f.Collector.Arm(new(target.Binding, target.StartDispatch, target.Kind, new Uri("https://foreign.invalid/" + Protected),
                target.TargetSha256, target.StartResponseSha256), f.Binding);
            throw new InvalidOperationException("test-expected-boundary");
        }
        catch (InvalidOperationException exception)
        {
            await Assert.That(exception.Message).IsEqualTo("management-status-target");
            await Assert.That(exception.InnerException).IsNull();
        }
        await ClearedAndBorrowed(f);
    }

    private static async Task ClearedAndBorrowed(Fixture f)
    {
        await Assert.That(f.Reader.Buffers.All(bytes => bytes.All(b => b == 0))).IsTrue();
        await Assert.That(f.Reader.Disposed || f.ReaderCredential.Disposed).IsFalse();
    }

    private static string ErrorBody() => """{"error":{"code":"NativeFailure","message":"private-status-material"}}""";
    private static string NotificationBody(string state) => JsonSerializer.Serialize(new
    {
        id = Notification,
        name = "status-notification",
        type = "Microsoft.EventGrid/eventSubscriptions",
        properties = new
        {
            topic = Vault,
            provisioningState = state,
            destination = new { endpointType = "WebHook", properties = new { endpointUrl = "https://delivery.invalid/" + Protected } }
        }
    });

    private sealed class Fixture : IDisposable
    {
        internal readonly Credential SelectedCredential = new("selected-start"), ReaderCredential = new("independent-reader");
        internal readonly ResponseState StartState = new(), ReadState = new();
        internal readonly Backend Native, Reader;
        internal readonly Capture Source;
        internal readonly Capture.Binding Binding;
        internal readonly Capture.Window NativeWindow;
        internal readonly ManagementOperationEffects.Input Input;
        internal readonly VaultAdministration Client;
        internal readonly ManagementReceipt Receipt;
        internal ManagementOperation? Handle;
        internal readonly Clock Clock = new();
        internal readonly C Collector;

        internal Fixture(string operation = "PurgeDeletedVault", string? variant = null)
        {
            var mutation = Enum.Parse<ManagementMutation>(operation);
            var vault = new VaultScope(new(new(Guid.Parse(Subscription)), "status-group"), "status-vault");
            ManagementScope resource = mutation switch
            {
                ManagementMutation.PurgeDeletedVault => new DeletedVaultScope(vault.ResourceGroup.Subscription, "eastus", vault.VaultName),
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeletePrivateConnection => new PrivateConnectionScope(vault, "status-connection"),
                ManagementMutation.DeleteRoleAssignment => new RoleAssignmentScope(vault, Guid.Parse(Assignment)),
                ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification or
                    ManagementMutation.DeleteNotification => new NotificationScope(vault, "status-notification"),
                _ => vault
            };
            string revision = resource is NotificationScope ? "2025-02-15" : resource is RoleAssignmentScope ? "2022-04-01" : "2026-02-01";
            Binding = new(new(Guid.NewGuid(), "controlled-native-case", ManagementOperationEffects.Members[0].Operation,
                variant ?? "operation." + operation, "selected-contract"), Guid.NewGuid(), resource, mutation, "eastus", revision);
            Input = new(null!, null!, Guid.Parse(Subscription), "status-group", "eastus", Guid.Parse(Tenant),
                VaultSku.Standard, 7, mutation, "https://delivery.invalid/" + Protected, Guid.Parse(Assignment));
            StartState.Status = mutation switch
            {
                ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault or
                    ManagementMutation.CreateOrUpdateNotification or ManagementMutation.UpdateNotification => 201,
                ManagementMutation.UpdatePrivateConnection or ManagementMutation.DeleteVault => 200,
                ManagementMutation.DeleteRoleAssignment => 204,
                _ => 202
            };
            StartState.Body = resource is NotificationScope && mutation != ManagementMutation.DeleteNotification ? NotificationBody("Updating") :
                mutation == ManagementMutation.UpdatePrivateConnection ? JsonSerializer.Serialize(new
                {
                    id = Connection,
                    name = "status-connection",
                    type = "Microsoft.KeyVault/vaults/privateEndpointConnections",
                    properties = new
                    {
                        provisioningState = "Updating",
                        privateLinkServiceConnectionState = new { status = "Approved" },
                        privateEndpoint = new { id = Vault + "/private-endpoint" }
                    }
                }) :
                mutation is ManagementMutation.CreateOrUpdateVault or ManagementMutation.RecoverVault ? JsonSerializer.Serialize(new
                {
                    id = Vault,
                    name = "status-vault",
                    type = "Microsoft.KeyVault/vaults",
                    location = "eastus",
                    properties = new
                    {
                        tenantId = Tenant,
                        sku = new { family = "A", name = "standard" },
                        provisioningState = "Updating",
                        vaultUri = "https://status-vault.vault.azure.net/"
                    }
                }) : mutation == ManagementMutation.DeleteVault ? """{"status":"InProgress"}""" : "";
            if (resource is not RoleAssignmentScope)
            {
                string uri = resource is NotificationScope ? Origin + Notification + "?api-version=" + revision : StatusUri;
                StartState.Headers.Add(("Location", uri));
                if (resource is not NotificationScope) StartState.Headers.Add(("Azure-AsyncOperation", uri));
            }
            ReadState.Body = resource is NotificationScope ? NotificationBody(
                mutation == ManagementMutation.DeleteNotification ? "Deleting" : "Updating") : """{"status":"InProgress"}""";
            Native = new(StartState);
            Reader = new(ReadState);
            Source = new(Native);
            NativeWindow = Source.Arm(Binding);
            Client = new(SelectedCredential, Source.SelectedTransport);
            Receipt = Client.PrepareReceipt(resource, mutation);
            Collector = new(Source, new("host-reader", ReaderCredential, Reader), Limits, Clock);
        }
        internal async Task<SecretStatus> Start(CancellationToken token = default)
        {
            var result = await Source.StartAsync(NativeWindow, Binding.Selector, Client, Binding.Resource, Input, Receipt, token);
            if (result.IsSuccess) Handle = result.Value;
            return result.Status;
        }
        internal async Task<Capture.StatusTarget> Target()
        {
            await Assert.That(await Start()).IsEqualTo(SecretStatus.Success);
            if (!Source.TryGetStatusTarget(NativeWindow, Binding, out var target))
                throw new InvalidOperationException("test-no-actual-native-target");
            return target;
        }
        internal ValueTask<C.Measurement> Read(Capture.StatusTarget target) => Collector.CollectAsync(Collector.Arm(target, Binding), Binding);
        public void Dispose() { Native.Dispose(); Reader.Dispose(); SelectedCredential.Dispose(); ReaderCredential.Dispose(); }
    }

    private sealed class Credential(string value) : TokenCredential, IDisposable
    {
        internal readonly List<string> Scopes = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Action? BeforeToken;
        internal bool Throw, Disposed, Block;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("test-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Scopes.AddRange(requestContext.Scopes);
            using var registration = cancellationToken.Register(() => CancellationObserved.TrySetResult());
            Entered.TrySetResult();
            if (Block)
            {
                await Release.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            BeforeToken?.Invoke();
            if (Throw) throw new InvalidOperationException(Protected);
            return new AccessToken(value, DateTimeOffset.MaxValue);
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class ResponseState
    {
        internal int Status = 200;
        internal string Body = "";
        internal string? Barrier, DeclaredLength;
        internal string ContentType = "application/json";
        internal bool Lose;
        internal readonly List<(string Name, string Value)> Headers = [];
    }

    private sealed record RequestRow(string Method, string Uri, string? Authorization, string? Body);

    // Native start responses and independent reader state are separate backend
    // instances. Neither is a projection of a selected SecretKit success result.
    private sealed class Backend : HttpPipelineTransport, IDisposable
    {
        private readonly HttpClient http;
        private readonly HttpClientTransport transport;
        internal readonly List<RequestRow> Requests = [];
        internal readonly List<byte[]> Buffers = [];
        internal readonly TaskCompletionSource SendEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource SendReturned = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource BodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource CancellationObserved = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Request? LastRequest;
        internal bool Disposed;

        internal Backend(ResponseState state)
        {
            http = new(new Handler(async (request, token) =>
            {
                Requests.Add(new(request.Method.Method, request.RequestUri!.AbsoluteUri,
                    request.Headers.Authorization?.ToString(), request.Content is null ? null : await request.Content.ReadAsStringAsync(token)));
                using var registration = token.Register(() => CancellationObserved.TrySetResult());
                SendEntered.TrySetResult();
                if (state.Barrier == "send")
                {
                    await Release.Task.ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                }
                if (state.Lose) throw new HttpRequestException(Protected);
                var response = new HttpResponseMessage((HttpStatusCode)state.Status)
                {
                    Content = new StreamContent(new ReadStream(Encoding.UTF8.GetBytes(state.Body), this, state.Barrier == "body", token))
                };
                response.Content.Headers.ContentType = new(state.ContentType);
                if (state.DeclaredLength is not null)
                    response.Content.Headers.TryAddWithoutValidation("Content-Length", state.DeclaredLength);
                response.Headers.TryAddWithoutValidation("x-ms-request-id", "native-status-read");
                foreach (var (name, value) in state.Headers)
                    if (name.StartsWith("Content-", StringComparison.OrdinalIgnoreCase)) response.Content.Headers.TryAddWithoutValidation(name, value);
                    else response.Headers.TryAddWithoutValidation(name, value);
                return response;
            }));
            transport = new(http);
        }
        public override Request CreateRequest() => LastRequest = transport.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("test-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await transport.ProcessAsync(message).ConfigureAwait(false);
            SendReturned.TrySetResult();
        }
        public void Dispose() { Disposed = true; http.Dispose(); }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }

    private sealed class ReadStream(byte[] bytes, Backend backend, bool barrier, CancellationToken actualToken) : Stream
    {
        private readonly MemoryStream input = new(bytes, false);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => input.Length;
        public override long Position { get => input.Position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => input.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment) && segment.Array is { } storage)
                backend.Buffers.Add(storage);
            if (barrier)
            {
                buffer.Span.Fill(0x5a);
                using var actual = actualToken.Register(() => backend.CancellationObserved.TrySetResult());
                using var read = cancellationToken.Register(() => backend.CancellationObserved.TrySetResult());
                backend.BodyEntered.TrySetResult();
                await backend.Release.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
            }
            return await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) input.Dispose();
            base.Dispose(disposing);
        }
    }

    private sealed class Clock : TimeProvider
    {
        internal long Ticks, WallTicks;
        private readonly List<Hook> timers = [];
        public override DateTimeOffset GetUtcNow() => Now.AddTicks(WallTicks);
        public override long GetTimestamp() => Ticks;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Hook(this, callback, state) { Due = Ticks + dueTime.Ticks };
            timers.Add(timer);
            return timer;
        }
        internal void Advance(TimeSpan duration)
        {
            Ticks += duration.Ticks;
            WallTicks += duration.Ticks;
            foreach (var timer in timers.ToArray())
                if (timer.Due <= Ticks) { timer.Due = long.MaxValue; timer.Fire(); }
        }
        private sealed class Hook(Clock clock, TimerCallback callback, object? state) : ITimer
        {
            internal long Due;
            internal void Fire() => callback(state);
            public bool Change(TimeSpan dueTime, TimeSpan period) { Due = clock.Ticks + dueTime.Ticks; return true; }
            public void Dispose() => Due = long.MaxValue;
            public ValueTask DisposeAsync() { Dispose(); return ValueTask.CompletedTask; }
        }
    }
}
