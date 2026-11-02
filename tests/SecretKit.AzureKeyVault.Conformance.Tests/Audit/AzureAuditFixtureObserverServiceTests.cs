using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using TriggerKind = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.AuditDiagnosticsEffects.TriggerKind;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Reuse the existing independent ARM resource model, not a selected result stub.
public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task AuditSourceRoutesRunOverOwnedHttpsHost()
    {
        using RSA key = RSA.Create(2048);
        var certificateRequest = new CertificateRequest("CN=localhost", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        certificateRequest.CertificateExtensions.Add(names.Build());
        using var certificate = certificateRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
        AuditFixtureObserverService? service = null;
        await using var host = RoleFixtureObserverHost.Start(certificate, new(IPAddress.Loopback, 0),
            (request, token) => service!.DispatchAsync(request, token));
        await using var fixture = new AuditServiceFixture(serviceOrigin: host.Origin);
        service = fixture.Service;
        using var observer = new OwnedManagementObserver(
            new(host.Origin, "private-owner-capability", TimeSpan.FromSeconds(10)),
            new HttpClientHandler
            {
                UseProxy = false,
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, leaf, _, errors) => leaf is not null &&
                    (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
                    leaf.RawData.AsSpan().SequenceEqual(certificate.RawData)
            });
        var lease = await observer.PostAsync<AuditDiagnosticsEffects.Prepare, AuditDiagnosticsEffects.Lease>(
            "audit/prepare", new(fixture.Selector, Subscription, "fixture-group", "eastus", Tenant,
                AuditServiceFixture.WorkspaceId, TriggerKind.Set, 20), default);
        var subscription = await observer.SubscribeAsync("audit", lease.Facts, default);
        var observation = observer.PostAsync<ObserveLease, AuditDiagnosticsEffects.Measurement>("audit/observe",
            new(lease.Facts.LeaseId, fixture.Selector.Nonce, "subscribed-event", subscription.SubscriptionId), default).AsTask();
        await fixture.Set(lease);
        await observer.PostAsync<AuditDiagnosticsEffects.Trigger, AuditDiagnosticsEffects.TriggerReceipt>(
            "audit/trigger", new(lease.Facts.LeaseId, fixture.Selector.Nonce, lease.TriggerId, TriggerKind.Set, null), default);
        await Assert.That((await observation).Events.Single().TriggerId).IsEqualTo(lease.TriggerId);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "audit/release", fixture.Selector, default);
        RoleFixtureRelease.Validate(release, fixture.Selector, lease.Facts);
        await Assert.That(fixture.Wires[0].Settings).IsNull();
    }

    [Test]
    [Arguments("Get")]
    [Arguments("List")]
    [Arguments("Set")]
    [Arguments("Delete")]
    [Arguments("Recover")]
    [Arguments("Backup")]
    [Arguments("Restore")]
    [Arguments("Purge")]
    [Arguments("UpdateProperties")]
    public async Task AuditSourceRunsActualTypedOperationsAndIndependentQueries(string operation)
    {
        await using var fixture = new AuditServiceFixture();
        var kind = Enum.Parse<TriggerKind>(operation);
        var lease = await fixture.Prepare(kind);
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        var observation = fixture.Observer.PostAsync<ObserveLease, AuditDiagnosticsEffects.Measurement>(
            "audit/observe", new(lease.Facts.LeaseId, fixture.Selector.Nonce, "subscribed-event", subscription.SubscriptionId),
            default).AsTask();
        await Assert.That(observation.IsCompleted).IsFalse();
        if (kind == TriggerKind.Set) await fixture.Set(lease);
        await fixture.Trigger(lease, kind);
        var measured = await observation;
        await Assert.That(measured.TriggerStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(measured.Events.Length).IsEqualTo(1);
        await Assert.That(measured.Events[0].Operation).IsEqualTo(kind == TriggerKind.UpdateProperties
            ? AuditOperation.Unknown : Enum.Parse<AuditOperation>("Secret" + kind));
        await Assert.That(fixture.Wires[0].QueryCount).IsEqualTo(1);
        await Assert.That(fixture.Wires[0].Settings).IsNotNull();
        if (kind is TriggerKind.Delete or TriggerKind.Purge)
            await Assert.That(fixture.Natives[0].State.Secret).IsNull();
        else await Assert.That(fixture.Natives[0].State.Secret).IsNotNull();
        if (kind == TriggerKind.UpdateProperties)
            await Assert.That(fixture.Wires[0].ContentType).IsEqualTo("audit-fixture");
        if (kind == TriggerKind.Delete) await Assert.That(fixture.Wires[0].Deleted).IsTrue();
        if (kind is TriggerKind.Recover or TriggerKind.Restore or TriggerKind.Purge)
            await Assert.That(fixture.Wires[0].Deleted).IsFalse();
        var release = await fixture.Release(lease);
        RoleFixtureRelease.Validate(release, fixture.Selector, lease.Facts);
        await Assert.That(fixture.Natives[0].Read().Resources.Count(r => !r.Borrowed)).IsEqualTo(4);
        await Assert.That(fixture.DiagnosticJournals[0].Read("owner", fixture.Selector).Resources.Length).IsEqualTo(2);
        await Assert.That(fixture.Wires[0].Settings).IsNull();
        await Assert.That(fixture.Natives[0].State.VaultExists || fixture.Natives[0].State.DeletedVaultExists).IsFalse();
        await Assert.That(fixture.Wires.All(w => w.WorkspaceWrites == 0 && !w.Disposed && w.DiagnosticDeletedBeforeVault)).IsTrue();
        await Assert.That(fixture.Credentials.All(c => !c.Disposed)).IsTrue();
    }

    [Test]
    [Arguments("batch.multiple")]
    [Arguments("batch.mixed-resource-workspace")]
    public async Task AuditSourceUsesSeparateRootsAndExactUnionForTwoWindows(string variant)
    {
        await using var fixture = new AuditServiceFixture(variant);
        var lease = await fixture.Prepare(TriggerKind.Set);
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        await fixture.Set(lease);
        await fixture.Trigger(lease, TriggerKind.Set);
        var measured = await fixture.Observe(lease, subscription);
        await Assert.That(lease.Windows.Length).IsEqualTo(2);
        await Assert.That(measured.Events.Length).IsEqualTo(2);
        await Assert.That(fixture.Natives.Select(n => n.State.Secret)).IsEquivalentTo(new string?[] { "selected-audit-value", "selected-audit-value" });
        await Assert.That(lease.Facts.OwnedResourceIds.Length).IsEqualTo(10);
        if (variant == "batch.mixed-resource-workspace")
        {
            await Assert.That(lease.Windows[0].WorkspaceId).IsNull();
            await Assert.That(lease.Windows[1].WorkspaceId).IsEqualTo((Guid?)AuditServiceFixture.WorkspaceId);
        }
        var release = await fixture.Release(lease);
        RoleFixtureRelease.Validate(release, fixture.Selector, lease.Facts);
        await Assert.That(release.BorrowedResourceIds.Length).IsEqualTo(2);
        await Assert.That(fixture.Natives.All(n => n.Read().Released)).IsTrue();
    }

    [Test]
    [Arguments("malformed")]
    [Arguments("lost")]
    [Arguments("foreign")]
    public async Task AuditOriginalHandlerClosesEveryRootAfterUnusablePrepareReply(string fault)
    {
        await using var fixture = new AuditServiceFixture();
        var result = await fixture.RunOriginal(fault);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Natives.All(n => n.Read().Closing && n.Read().Released)).IsTrue();
        await Assert.That(fixture.DiagnosticJournals.All(j => j.Read("owner", fixture.Selector).Closing &&
            j.Read("owner", fixture.Selector).Released)).IsTrue();
        await Assert.That(fixture.Wires.All(w => w.Settings is null && w.WorkspaceWrites == 0)).IsTrue();
    }

    [Test]
    public async Task AuditOriginalHandlerUsesSourceOwnedOriginalSetAndStrictRelease()
    {
        await using var fixture = new AuditServiceFixture();
        var result = await fixture.RunOriginal();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Wires[0].Events.Any(e => e.Operation == "SecretSet")).IsTrue();
        await Assert.That(fixture.Natives.All(n => n.Read().Released)).IsTrue();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("challenge")]
    [Arguments("wrong-operation")]
    [Arguments("unknown")]
    [Arguments("versions")]
    [Arguments("partial")]
    [Arguments("response-is-client")]
    public async Task AuditSourceDoesNotCertifyUnjoinedOrIncompleteIngestion(string fault)
    {
        await using var fixture = new AuditServiceFixture();
        fixture.Wires[0].Fault = fault;
        var lease = await fixture.Prepare(TriggerKind.Set);
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        await fixture.Set(lease);
        await fixture.Trigger(lease, TriggerKind.Set);
        await Assert.That(async () => await fixture.Observe(lease, subscription)).Throws<NativeCaseFailureException>();
        await Assert.That(fixture.Wires[0].QueryCount).IsEqualTo(1);
        await fixture.Release(lease);
    }

    [Test]
    public async Task AuditSourcePreservesDuplicateNativeRowsWithoutRepeatingQuery()
    {
        await using var fixture = new AuditServiceFixture();
        fixture.Wires[0].Fault = "duplicate";
        var lease = await fixture.Prepare(TriggerKind.Set);
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        await fixture.Set(lease);
        await fixture.Trigger(lease, TriggerKind.Set);
        var measurement = await fixture.Observe(lease, subscription);
        await Assert.That(measurement.Events.Length).IsEqualTo(2);
        await Assert.That(measurement.Events[0]).IsEqualTo(measurement.Events[1]);
        await Assert.That(async () => await fixture.Observe(lease, subscription)).Throws<NativeCaseFailureException>();
        await fixture.Release(lease);
    }

    [Test]
    public async Task AuditSourcePreservesUnrelatedRowsWithoutClaimingTheirCausality()
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Set);
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        await fixture.Set(lease);
        var selected = fixture.Wires[0].Events.Single();
        fixture.Wires[0].Events.Add(new("SecretGet", Guid.NewGuid(), selected.Timestamp.AddTicks(1)));
        await fixture.Trigger(lease, TriggerKind.Set);
        var measured = await fixture.Observe(lease, subscription);
        await Assert.That(measured.Events.Length).IsEqualTo(2);
        await Assert.That(measured.Events.Single(e => e.Operation == AuditOperation.SecretSet).TriggerId)
            .IsEqualTo(lease.TriggerId);
        await Assert.That(measured.Events.Single(e => e.Operation == AuditOperation.SecretGet).TriggerId)
            .IsEqualTo(string.Empty);
        await Assert.That(fixture.Wires[0].QueryCount).IsEqualTo(1);
        await fixture.Release(lease);
    }

    [Test]
    public async Task AuditJoinRejectsAmbiguousActuallyCapturedAttempts()
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Get);
        using var http = new HttpClient(new AuditWireHandler(fixture.Wires[0], "runtime"));
        var capture = new AuditNativeTriggerCapture(new HttpClientTransport(http));
        var vault = new VaultScope(new(new(Subscription), "fixture-group"), lease.Windows[0].VaultName);
        var binding = new AuditNativeTriggerCapture.Binding(fixture.Selector, lease.Facts.LeaseId,
            vault, TriggerKind.Get, RoleFixtureProvisioner.Canary, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "2025-07-01");
        var window = capture.Arm(binding);
        var client = new AzureKeyVaultClient(new("https://" + vault.VaultName + ".vault.azure.net"),
            fixture.Credentials[0], capture.CreateTransport(window, fixture.Selector));
        var reference = new SecretReference(client.Authority,
            new AzureSecretAddress(RoleFixtureProvisioner.Canary, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
        var read = await client.ReadAsync(reference);
        await Assert.That(read.Status).IsEqualTo(SecretStatus.Success);
        using var value = read.Value;
        var actual = await capture.SealAsync(window);
        var row = fixture.Wires[0].Events.Single();
        var observed = new AuditIngestionCollector.Measurement
        {
            Binding = new(fixture.Selector, lease.Facts.LeaseId, vault, null, lease.Windows[0].Start, lease.Windows[0].End),
            Failure = AuditIngestionCollector.Failure.None,
            NativeQueryRequestId = "independent-query",
            Rows = [new(row.Timestamp, AuditOperation.SecretGet, AuditResultKind.Success, row.Operation, row.Correlation)]
        };
        await Assert.That(AuditFixtureObserverService.Join(observed, [actual], lease.TriggerId).Length).IsEqualTo(1);
        await Assert.That(() => AuditFixtureObserverService.Join(observed, [actual, actual], lease.TriggerId))
            .Throws<InvalidOperationException>();
        await fixture.Release(lease);
    }

    [Test]
    public async Task AuditFailedNativePreparationRetainsUnresolvedRootAndClosesUnusedRoots()
    {
        await using var fixture = new AuditServiceFixture();
        fixture.Wires[0].DiagnosticLost = true;
        await Assert.That(async () => await fixture.Prepare(TriggerKind.Set)).Throws<NativeCaseFailureException>();
        var release = await fixture.Release(null);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(fixture.Wires[0].Settings).IsNotNull();
        await Assert.That(fixture.Natives[0].State.VaultExists).IsTrue();
        await Assert.That(fixture.Natives[1].Read().Released).IsTrue();
        await Assert.That(fixture.DiagnosticJournals[1].Read("owner", fixture.Selector).Released).IsTrue();
    }

    [Test]
    public async Task AuditReleaseBeforePrepareSealsAllPreconfiguredRoots()
    {
        await using var fixture = new AuditServiceFixture();
        var release = await fixture.Release(null);
        RoleFixtureRelease.Validate(release, fixture.Selector, null);
        await Assert.That(fixture.Natives.All(n => n.Read().Closing)).IsTrue();
        await Assert.That(fixture.DiagnosticJournals.All(j => j.Read("owner", fixture.Selector).Closing)).IsTrue();
        await Assert.That(async () => await fixture.Prepare(TriggerKind.Set)).Throws<NativeCaseFailureException>();
        await Assert.That(fixture.Natives.Sum(n => n.WriteCount)).IsEqualTo(0);
    }

    [Test]
    public async Task AuditOwnerFullSelectorOriginAndOneUseRoutesAreEnforced()
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Set);
        using (var foreign = fixture.Request("audit/release", fixture.Selector with { Scope = "foreign" }))
        using (var denied = await fixture.Service.DispatchAsync(foreign, default))
            await Assert.That(denied.IsSuccessStatusCode).IsFalse();
        using (var foreign = fixture.Request("audit/release", fixture.Selector))
        {
            foreign.Headers.Authorization = new("Bearer", "foreign-owner");
            using var denied = await fixture.Service.DispatchAsync(foreign, default);
            await Assert.That(denied.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        }
        using (var foreign = fixture.Request("audit/release", fixture.Selector))
        {
            foreign.RequestUri = new("https://foreign.invalid/audit/release");
            using var denied = await fixture.Service.DispatchAsync(foreign, default);
            await Assert.That(denied.IsSuccessStatusCode).IsFalse();
        }
        await Assert.That(fixture.Natives[0].Read().Closing).IsFalse();
        using (var foreign = fixture.Request("audit/trigger", new AuditDiagnosticsEffects.Trigger(
            lease.Facts.LeaseId, Guid.NewGuid(), lease.TriggerId, TriggerKind.Set, "claimed-version")))
        using (var denied = await fixture.Service.DispatchAsync(foreign, default))
            await Assert.That(denied.IsSuccessStatusCode).IsFalse();
        await Assert.That(async () => await fixture.Prepare(TriggerKind.Set)).Throws<NativeCaseFailureException>();
        var subscription = await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        await Assert.That(async () => await fixture.Observer.SubscribeAsync("audit", lease.Facts, default))
            .Throws<NativeCaseFailureException>();
        await fixture.Set(lease);
        await fixture.Trigger(lease, TriggerKind.Set);
        await Assert.That(async () => await fixture.Trigger(lease, TriggerKind.Set)).Throws<NativeCaseFailureException>();
        await fixture.Observe(lease, subscription);
        await fixture.Release(lease);
        await Assert.That(async () => await fixture.Trigger(lease, TriggerKind.Set)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await fixture.Set(lease)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("{\"nonce\":\"00000000-0000-0000-0000-000000000000\"}")]
    [Arguments("{\"selection\":{},\"selection\":{}}")]
    [Arguments("{} {}")]
    public async Task AuditMalformedBodyCannotCreateNativeResources(string body)
    {
        await using var fixture = new AuditServiceFixture();
        using var request = fixture.Request("audit/prepare", new { });
        request.Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body));
        using var response = await fixture.Service.DispatchAsync(request, default);
        await Assert.That(response.IsSuccessStatusCode).IsFalse();
        await Assert.That(fixture.Natives.Sum(n => n.WriteCount)).IsEqualTo(0);
        await fixture.Release(null);
    }

    [Test]
    public async Task AuditServiceReplyCannotExceedConfiguredBodyBudget()
    {
        await using var fixture = new AuditServiceFixture(maximumBodyBytes: 1024);
        using var request = fixture.Request("audit/prepare", new AuditDiagnosticsEffects.Prepare(
            fixture.Selector, Subscription, "fixture-group", "eastus", Tenant,
            AuditServiceFixture.WorkspaceId, TriggerKind.Set, 20));
        using var response = await fixture.Service.DispatchAsync(request, default);
        await Assert.That((await response.Content.ReadAsByteArrayAsync()).Length <= 1024).IsTrue();
        await Assert.That(response.IsSuccessStatusCode).IsFalse();
        using var release = fixture.Request("audit/release", fixture.Selector);
        using var released = await fixture.Service.DispatchAsync(release, default);
        await Assert.That((await released.Content.ReadAsByteArrayAsync()).Length <= 1024).IsTrue();
        await Assert.That(fixture.Natives.All(n => n.Read().Released)).IsTrue();
        await Assert.That(fixture.Wires.All(w => w.Settings is null)).IsTrue();
    }

    [Test]
    public async Task AuditBodyBudgetAndUnknownRouteRejectBeforeNativeSetup()
    {
        await using var fixture = new AuditServiceFixture();
        using (var request = fixture.Request("audit/prepare", new { padding = new string('x', 65537) }))
        using (var response = await fixture.Service.DispatchAsync(request, default))
            await Assert.That(response.IsSuccessStatusCode).IsFalse();
        using (var request = fixture.Request("audit/command", new { url = "https://foreign.invalid/" }))
        using (var response = await fixture.Service.DispatchAsync(request, default))
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.NotFound);
        await Assert.That(fixture.Natives.Sum(n => n.WriteCount)).IsEqualTo(0);
        await fixture.Release(null);
    }

    [Test]
    public async Task AuditCleanupWaitsForActualSdkCredentialContinuation()
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Set);
        await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        var credential = fixture.Credentials[0];
        credential.Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        credential.Continue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task set = fixture.Set(lease);
        try
        {
            await Task.WhenAny(credential.Entered.Task, set).WaitAsync(TimeSpan.FromSeconds(10));
            if (set.IsCompleted) await set;
            await credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // The actual SDK task remains inside the borrowed credential
            // callback, which deliberately ignores cancellation until released.
            var pending = await fixture.Release(lease);
            await Assert.That(pending.ActiveDispatches > 0).IsTrue();
            await Assert.That(fixture.Natives[0].State.VaultExists).IsTrue();
            await Assert.That(fixture.Wires[0].Settings).IsNotNull();
            await Assert.That(set.IsCompleted).IsFalse();
            credential.Continue.TrySetResult();
            try { await set; }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
            var complete = await fixture.Release(lease);
            RoleFixtureRelease.Validate(complete, fixture.Selector, lease.Facts);
            await Assert.That(fixture.Wires[0].Events.Count).IsEqualTo(0);
        }
        finally
        {
            credential.Continue.TrySetResult();
            try { await set; }
            catch (Exception) { }
        }
    }

    [Test]
    public async Task AuditCleanupCannotSubstituteCapturedSendDrainForWholeSdkTask()
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Set);
        await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        var wire = fixture.Wires[0];
        wire.BodyEntered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        wire.BodyContinue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task set = fixture.Set(lease);
        try
        {
            await Task.WhenAny(wire.BodyEntered.Task, set).WaitAsync(TimeSpan.FromSeconds(10));
            if (set.IsCompleted) await set;
            await wire.BodyEntered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            // The native HTTP send and capture have returned; response reading
            // and the enclosing actual SDK invocation have not terminated.
            var pending = await fixture.Release(lease);
            await Assert.That(pending.ActiveDispatches > 0).IsTrue();
            await Assert.That(set.IsCompleted).IsFalse();
            await Assert.That(fixture.Natives[0].State.VaultExists && wire.Settings is not null).IsTrue();
            wire.BodyContinue.TrySetResult();
            try { await set; }
            catch (OperationCanceledException) { }
            catch (InvalidOperationException) { }
            var unresolved = await fixture.Release(lease);
            // Cancellation during response materialization does not establish
            // remote settlement from a successful header alone.
            await Assert.That(unresolved.ActiveDispatches > 0).IsTrue();
            await Assert.That(fixture.Natives[0].State.VaultExists).IsTrue();
        }
        finally
        {
            wire.BodyContinue.TrySetResult();
            try { await set; }
            catch (Exception) { }
        }
    }

    [Test]
    [Arguments("lost-native")]
    [Arguments("pending-native")]
    [Arguments("foreign-native")]
    public async Task AuditLostOrPendingActualNativeWriteNeverAcknowledgesRelease(string fault)
    {
        await using var fixture = new AuditServiceFixture();
        var lease = await fixture.Prepare(TriggerKind.Set);
        await fixture.Observer.SubscribeAsync("audit", lease.Facts, default);
        fixture.Wires[0].Fault = fault;
        try { await fixture.Set(lease); }
        catch (InvalidOperationException) { }
        var release = await fixture.Release(lease);
        await Assert.That(release.ActiveDispatches > 0).IsTrue();
        await Assert.That(fixture.Natives[0].State.Secret).IsEqualTo("selected-audit-value");
        await Assert.That(fixture.Wires[0].Settings).IsNotNull();
        await Assert.That(() => RoleFixtureRelease.Validate(release, fixture.Selector, lease.Facts))
            .Throws<NativeCaseFailureException>();
    }

    private sealed class AuditServiceFixture : IAsyncDisposable
    {
        internal static readonly Guid WorkspaceId = Guid.Parse("12345678-1234-1234-1234-123456789abc");
        internal static string WorkspacePath => GroupPath + "/providers/Microsoft.OperationalInsights/workspaces/audit";
        internal FixtureSelector Selector;
        internal readonly Fixture[] Natives;
        internal readonly RoleFixtureJournal[] DiagnosticJournals;
        internal readonly AuditWire[] Wires;
        internal readonly AuditCredential[] Credentials;
        internal readonly AuditFixtureObserverService Service;
        internal readonly OwnedManagementObserver Observer;
        private readonly SecretMaterial capability = SecretMaterial.FromText("private-owner-capability");
        private readonly List<HttpClient> clients = [];
        private readonly AuditClock clock = new();
        private readonly HttpPipelineTransport selectedMonitoring;

        internal AuditServiceFixture(string variant = "query.resource", Uri? serviceOrigin = null,
            int maximumBodyBytes = 65536)
        {
            bool batch = variant.StartsWith("batch.", StringComparison.Ordinal);
            Selector = new(Guid.NewGuid(), "owned-source", "a.management.AuditDiagnostics." +
                (batch ? "QueryBatchAsync" : "QueryAsync"), variant, "selected-contract");
            Natives = [new(true, Selector), new(true, Selector)];
            DiagnosticJournals = Natives.Select(n =>
            {
                string path = Path.Combine(n.DirectoryPath, "diagnostics");
                Directory.CreateDirectory(path);
                return new RoleFixtureJournal(path);
            }).ToArray();
            Wires = Natives.Select(n => new AuditWire(n, clock)).ToArray();
            Credentials = [new("runtime-audit", "https://vault.azure.net/.default"),
                new("runtime-audit", "https://vault.azure.net/.default")];
            var sources = new List<AuditFixtureObserverService.WindowSource>();
            for (int index = 0; index < Natives.Length; index++)
            {
                int i = index;
                HttpPipelineTransport Transport(string role)
                {
                    var client = new HttpClient(new AuditWireHandler(Wires[i], role));
                    clients.Add(client);
                    return new HttpClientTransport(client);
                }
                var diagnostics = new AuditDiagnosticSettings(DiagnosticJournals[i],
                    new(Subscription, "fixture-group", "eastus", Tenant, WorkspacePath, WorkspaceId, true),
                    new("diagnostic-setup", new Credential("diagnostic-setup-arm"), Transport("diagnostic-setup")),
                    new("diagnostic-read", new Credential("diagnostic-read-arm"), Transport("diagnostic-read")),
                    new(65536, TimeSpan.FromSeconds(10)), clock);
                var collector = new AuditIngestionCollector(new AuditCredential("independent-monitor",
                    "https://api.loganalytics.io//.default"), Transport("monitor"), new(20, 65536, TimeSpan.FromSeconds(10)), clock);
                sources.Add(new(Natives[i].Journal, Natives[i].Source, diagnostics, collector,
                    Credentials[i], Transport("runtime")));
            }
            var monitorHttp = new HttpClient(new AuditWireHandler(Wires[0], "monitor"));
            clients.Add(monitorHttp);
            selectedMonitoring = new HttpClientTransport(monitorHttp);
            Uri origin = serviceOrigin ?? new("https://fixture.invalid/");
            Service = new(origin, "owner", "audit-source", capability,
                new(Subscription, "fixture-group", "eastus", Tenant, PrincipalId, DefinitionId, true, true),
                WorkspaceId, sources.ToArray(), new(20, maximumBodyBytes, TimeSpan.FromSeconds(10)), clock);
            Observer = new(new(origin, "private-owner-capability", TimeSpan.FromSeconds(10)),
                new SourceForwarder(Service.DispatchAsync));
        }

        internal HttpRequestMessage Request<T>(string path, T value)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "https://fixture.invalid/" + path);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "private-owner-capability");
            request.Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(value, ManagementAdmission.Json));
            return request;
        }
        internal ValueTask<AuditDiagnosticsEffects.Lease> Prepare(TriggerKind kind)
        {
            if (kind != TriggerKind.Set)
            {
                Selector = Selector with { Variant = kind == TriggerKind.UpdateProperties ? "operation.Unknown" : "operation.Secret" + kind };
                foreach (var native in Natives) native.Selector = Selector;
            }
            return Observer.PostAsync<AuditDiagnosticsEffects.Prepare, AuditDiagnosticsEffects.Lease>("audit/prepare",
                new(Selector, Subscription, "fixture-group", "eastus", Tenant, WorkspaceId, kind, 20), default);
        }
        internal async Task Set(AuditDiagnosticsEffects.Lease lease)
        {
            var client = new AzureKeyVaultClient(new("https://" + lease.Windows[0].VaultName + ".vault.azure.net"),
                Credentials[0], Service.RuntimeTransport);
            var reference = new SecretReference(client.Authority, new AzureSecretAddress(lease.Windows[0].RuntimeSecretName));
            using var material = SecretMaterial.FromText("selected-audit-value");
            var result = await Service.RunSetAsync(Selector, client, new(reference, material), new(reference), default);
            if (result.Status != SecretStatus.Success) throw new InvalidOperationException("controlled-set-failed");
        }
        internal ValueTask<AuditDiagnosticsEffects.TriggerReceipt> Trigger(AuditDiagnosticsEffects.Lease lease, TriggerKind kind) =>
            Observer.PostAsync<AuditDiagnosticsEffects.Trigger, AuditDiagnosticsEffects.TriggerReceipt>("audit/trigger",
                new(lease.Facts.LeaseId, Selector.Nonce, lease.TriggerId, kind, null), default);
        internal ValueTask<AuditDiagnosticsEffects.Measurement> Observe(AuditDiagnosticsEffects.Lease lease, ObservationSubscription subscription) =>
            Observer.PostAsync<ObserveLease, AuditDiagnosticsEffects.Measurement>("audit/observe",
                new(lease.Facts.LeaseId, Selector.Nonce, "subscribed-event", subscription.SubscriptionId), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release(AuditDiagnosticsEffects.Lease? lease) =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("audit/release", Selector, default);

        internal async Task<NativeCaseResult> RunOriginal(string? fault = null)
        {
            using var settings = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://owned-vault.vault.azure.net",
                setup = ServiceCredential("setup-secret"),
                runtime = ServiceCredential("runtime-audit"),
                denied = ServiceCredential("denied-secret"),
                administrative = ServiceCredential("administrative-secret"),
                observer = ServiceCredential("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["AuditDiagnostics"] = new AuditDiagnosticsEffects.Input(
                        new(new("https://fixture.invalid/"), "private-owner-capability", TimeSpan.FromSeconds(10)),
                        new("selected-monitor", DateTimeOffset.MaxValue, "https://api.loganalytics.io//.default"),
                        new("denied-monitor", DateTimeOffset.MaxValue, "https://api.loganalytics.io//.default"),
                        Subscription, "fixture-group", "eastus", Tenant, WorkspaceId, TimeSpan.FromSeconds(10),
                        TimeSpan.FromSeconds(10), 20, "selected-audit-value")
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(settings.RootElement);
            var member = AuditDiagnosticsEffects.Members[0];
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, "query.resource",
                "owned-source", "selected-contract"), member.Member);
            var registry = new NativeCaseRegistry();
            AuditDiagnosticsEffects.Register(registry, environment, [definition], endpoint =>
                new(endpoint, new SourceForwarder(async (request, token) =>
                {
                    bool prepare = request.RequestUri!.AbsolutePath == "/audit/prepare";
                    if (prepare)
                    {
                        var input = JsonSerializer.Deserialize<AuditDiagnosticsEffects.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!;
                        Selector = input.Selection;
                        foreach (var native in Natives) native.Selector = Selector;
                    }
                    var response = await Service.DispatchAsync(request, token);
                    if (!prepare || fault is null) return response;
                    response.Dispose();
                    if (fault == "lost") throw new IOException("controlled-lost-reply");
                    return Json(200, fault == "malformed" ? "{" :
                        JsonSerializer.Serialize(new AuditDiagnosticsEffects.Lease(
                            new(Guid.NewGuid(), Guid.NewGuid(), "foreign", "https://management.azure.com",
                                "2026-02-01", DateTimeOffset.UtcNow, []), [], "foreign"), ManagementAdmission.Json));
                })), Service.RuntimeTransport, selectedMonitoring, Service);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        public async ValueTask DisposeAsync()
        {
            await Service.DisposeAsync();
            Observer.Dispose();
            capability.Dispose();
            foreach (var client in clients) client.Dispose();
            foreach (var native in Natives) native.Dispose();
        }
    }

    private sealed class AuditClock : TimeProvider
    {
        private readonly DateTimeOffset start = DateTimeOffset.UtcNow.AddSeconds(-10);
        private long ticks;
        public override DateTimeOffset GetUtcNow() => start.AddTicks(Interlocked.Increment(ref ticks));
    }
    private sealed class AuditCredential(string value, string audience) : TokenCredential, IDisposable
    {
        internal bool Disposed;
        internal TaskCompletionSource? Entered, Continue;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
            GetTokenAsync(context, token).AsTask().GetAwaiter().GetResult();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            if (Disposed || context.Scopes.Single() != audience) throw new InvalidOperationException("controlled-audience");
            Entered?.TrySetResult();
            if (Continue is not null) await Continue.Task;
            token.ThrowIfCancellationRequested();
            return new(value, DateTimeOffset.MaxValue);
        }
        public void Dispose() => Disposed = true;
    }
    private sealed record AuditWireEvent(string Operation, Guid Correlation, DateTimeOffset Timestamp);
    private sealed class AuditWire(Fixture native, AuditClock clock)
    {
        internal string? Settings, Fault, DeletedValue, ContentType;
        internal bool Deleted, Disposed, DiagnosticLost, DiagnosticDeletedBeforeVault = true;
        internal TaskCompletionSource? BodyEntered, BodyContinue;
        internal int WorkspaceWrites, QueryCount;
        internal Guid Challenge;
        internal readonly List<AuditWireEvent> Events = [];
        internal async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (role == "monitor")
            {
                if (request.Headers.Authorization?.Parameter == "denied-monitor")
                    return Json(403, """{"error":{"code":"Forbidden"}}""");
                if (request.Method != HttpMethod.Post || request.RequestUri.Host != "api.loganalytics.io" ||
                    request.Headers.Authorization?.Parameter is not ("independent-monitor" or "selected-monitor"))
                    throw new InvalidOperationException("controlled-query-authority");
                QueryCount++;
                using var input = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                string query = input.RootElement.GetProperty("query").GetString()!;
                bool independent = query.Contains("CorrelationId", StringComparison.Ordinal);
                int from = query.IndexOf("datetime(", StringComparison.Ordinal) + 9;
                DateTimeOffset start = DateTimeOffset.Parse(query[from..query.IndexOf(')', from)], CultureInfo.InvariantCulture);
                string[] names = ["TimeGenerated", "OperationName", "ResultType", "_ResourceId", "Category", "CorrelationId"];
                var rows = Events.Where(e => e.Timestamp >= start).Select(e =>
                {
                    string op = Fault switch
                    {
                        "unknown" => "UnrecognizedProviderOperation",
                        "versions" => "SecretListVersions",
                        "wrong-operation" => "SecretGet",
                        _ => e.Operation
                    };
                    object[] row = [e.Timestamp.ToString("O", CultureInfo.InvariantCulture), op, "Success",
                        native.State.VaultId!, "AuditEvent", Fault == "missing" ? "" :
                            (Fault == "challenge" ? Challenge : e.Correlation).ToString("D")];
                    return independent ? row : row.Take(5).ToArray();
                }).ToArray();
                if (Fault == "duplicate") rows = [.. rows, .. rows];
                return Json(200, JsonSerializer.Serialize(new
                {
                    tables = new[] { new { name = "PrimaryResult", columns = names.Take(independent ? 6 : 5)
                        .Select((name, i) => new { name, type = i == 0 ? "datetime" : "string" }).ToArray(), rows } },
                    error = Fault == "partial" ? new { code = "PartialError", message = "controlled-partial" } : null
                }, new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull }));
            }
            if (role.StartsWith("diagnostic", StringComparison.Ordinal))
            {
                if (request.Headers.Authorization?.Parameter != role + "-arm")
                    throw new InvalidOperationException("controlled-diagnostic-authority");
                if (role == "diagnostic-read" && request.Method != HttpMethod.Get)
                    throw new InvalidOperationException("controlled-read-only");
                if (path == AuditServiceFixture.WorkspacePath)
                {
                    if (request.Method != HttpMethod.Get) WorkspaceWrites++;
                    return Json(200, JsonSerializer.Serialize(new
                    {
                        id = path,
                        type = "Microsoft.OperationalInsights/workspaces",
                        properties = new { customerId = AuditServiceFixture.WorkspaceId, provisioningState = "Succeeded" }
                    }));
                }
                if (path.Contains("/diagnosticSettings/", StringComparison.Ordinal))
                {
                    if (request.Method == HttpMethod.Put)
                    {
                        using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                        Settings = JsonSerializer.Serialize(new { id = path, properties = body.RootElement.GetProperty("properties") });
                        if (DiagnosticLost) throw new IOException("controlled-diagnostic-loss");
                    }
                    if (request.Method == HttpMethod.Delete)
                    {
                        DiagnosticDeletedBeforeVault &= native.State.VaultExists;
                        Settings = null;
                        return Json(204, "");
                    }
                    return Settings is null ? Missing() : Json(200, Settings);
                }
                // Independent native ARM read, using the same simulated resource store.
                using var copy = new HttpRequestMessage(HttpMethod.Get, request.RequestUri);
                copy.Headers.Authorization = new("Bearer", "observe-arm");
                return await native.State.Respond(copy, "observe-arm", token);
            }
            Guid correlation = Guid.Parse(request.Headers.GetValues("x-ms-client-request-id").Single());
            if (request.Headers.Authorization is null)
            {
                Challenge = correlation;
                var challenge = Json(401, "{}");
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    $"Bearer authorization=\"https://login.microsoftonline.com/{Tenant:D}\", resource=\"https://vault.azure.net\"");
                return challenge;
            }
            if (request.Headers.Authorization.Parameter != "runtime-audit")
                return Json(403, """{"error":{"code":"Forbidden"}}""");
            if (request.Method != HttpMethod.Get && !path.EndsWith("/backup", StringComparison.Ordinal))
            {
                var row = native.Read().Resources.Single(r => r.Id == native.State.VaultId + "/secrets/canary");
                if (row.ActiveDispatch == Guid.Empty || !row.SelectedAttempted)
                    throw new InvalidOperationException("controlled-selected-journal");
            }
            string operation;
            HttpResponseMessage response;
            if (path == "/deletedsecrets/canary" && request.Method == HttpMethod.Get)
                return Deleted ? Json(200, Secret(deleted: true)) : Missing();
            if (request.Method == HttpMethod.Put)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                native.State.Secret = body.RootElement.GetProperty("value").GetString();
                operation = "SecretSet";
                response = Json(Fault == "pending-native" ? 202 : 200, Secret());
            }
            else if (path.EndsWith("/recover", StringComparison.Ordinal))
            {
                if (!Deleted) return Missing();
                native.State.Secret = DeletedValue;
                Deleted = false;
                operation = "SecretRecover";
                response = Json(200, Secret());
            }
            else if (path.EndsWith("/backup", StringComparison.Ordinal))
            {
                operation = "SecretBackup";
                response = Json(200, JsonSerializer.Serialize(new { value = Base64Url(Encoding.UTF8.GetBytes(native.State.Secret!)) }));
            }
            else if (path == "/secrets/restore")
            {
                if (Deleted || native.State.Secret is not null) throw new InvalidOperationException("controlled-restore-precondition");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                string value = body.RootElement.GetProperty("value").GetString()!.Replace('-', '+').Replace('_', '/');
                native.State.Secret = Encoding.UTF8.GetString(Convert.FromBase64String(value.PadRight((value.Length + 3) / 4 * 4, '=')));
                operation = "SecretRestore";
                response = Json(200, Secret());
            }
            else if (request.Method == HttpMethod.Delete)
            {
                bool purge = path.StartsWith("/deletedsecrets/", StringComparison.Ordinal);
                if (purge)
                {
                    if (!Deleted) return Missing();
                    Deleted = false;
                    DeletedValue = null;
                }
                else { DeletedValue = native.State.Secret; native.State.Secret = null; Deleted = true; }
                operation = purge ? "SecretPurge" : "SecretDelete";
                response = Json(purge ? 204 : 200, purge ? "" : Secret(deleted: true));
            }
            else if (request.Method == HttpMethod.Patch)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                ContentType = body.RootElement.GetProperty("contentType").GetString();
                operation = "SecretUpdate";
                response = Json(200, Secret());
            }
            else if (path == "/secrets/")
            {
                operation = "SecretList";
                using var secret = JsonDocument.Parse(Secret());
                response = Json(200, JsonSerializer.Serialize(new { value = new[] { secret.RootElement } }));
            }
            else
            {
                operation = "SecretGet";
                response = native.State.Secret is null ? Missing() : Json(200, Secret());
            }
            Events.Add(new(operation, correlation, clock.GetUtcNow()));
            if (Fault == "lost-native" && operation == "SecretSet") { response.Dispose(); throw new IOException("controlled-lost-native"); }
            response.Headers.Remove("x-ms-request-id");
            response.Headers.Add("x-ms-request-id", Fault == "response-is-client" ? correlation.ToString("D") : Guid.NewGuid().ToString("D"));
            if (operation == "SecretSet" && BodyEntered is not null && BodyContinue is not null)
            {
                byte[] body = await response.Content.ReadAsByteArrayAsync(token);
                response.Content.Dispose();
                response.Content = new StreamContent(new AuditBlockedBody(body, BodyEntered, BodyContinue));
            }
            return response;
        }
        private string Secret(bool deleted = false) => JsonSerializer.Serialize(new
        {
            id = $"https://{(Fault == "foreign-native" ? "foreign-vault" : native.State.VaultName)}.vault.azure.net/secrets/canary/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            value = deleted ? DeletedValue : native.State.Secret,
            contentType = ContentType,
            recoveryId = deleted ? $"https://{native.State.VaultName}.vault.azure.net/deletedsecrets/canary" : null,
            deletedDate = deleted ? 1700000000 : (int?)null,
            scheduledPurgeDate = deleted ? 1800000000 : (int?)null,
            attributes = new { enabled = true }
        });
        private static string Base64Url(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
    private sealed class AuditWireHandler(AuditWire state, string role) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            state.Send(request, role, token);
        protected override void Dispose(bool disposing) { state.Disposed = true; base.Dispose(disposing); }
    }
    private sealed class AuditBlockedBody(byte[] body, TaskCompletionSource entered, TaskCompletionSource resume) : MemoryStream(body)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
        {
            entered.TrySetResult();
            await resume.Task;
            token.ThrowIfCancellationRequested();
            return await base.ReadAsync(buffer, token);
        }
    }
}
