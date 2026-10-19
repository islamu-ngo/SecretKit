using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;
using RoleOp = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.RoleManagementOperationFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task OriginalRoleOperationServiceJoins204ProofWithIndependentAbsenceAndCleanup()
    {
        await using var f = new RoleOperationServiceFixture();
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.SelectedRequests.Single().Method).IsEqualTo(HttpMethod.Delete);
        await Assert.That(f.ResourceReads).IsEqualTo(2);
        await Assert.That(f.Native.Read().Resources.Count(r => !r.Borrowed)).IsEqualTo(4);
        await Assert.That(f.Native.Read().Resources.Count(r => r.Borrowed)).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
        await Assert.That(f.Native.State.BeforeSendPersisted).IsTrue();
        await Assert.That(f.Native.Backends.SelectMany(b => b.Requests)
            .Where(r => r.Path == DefinitionPath).All(r => r.Method == HttpMethod.Get)).IsTrue();
    }

    [Test]
    [Arguments(200)]
    [Arguments(202)]
    [Arguments(403)]
    public async Task OriginalRoleOperationServiceRejectsUnqualifiedNativeResponse(int status)
    {
        await using var f = new RoleOperationServiceFixture();
        f.Native.State.SelectedDeleteStatus = status;
        int setupWrites = 0;
        f.AfterPrepare = () => setupWrites = f.Native.WriteCount;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.WriteCount).IsEqualTo(setupWrites);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("nonempty")]
    [Arguments("continuation")]
    [Arguments("retry")]
    [Arguments("no-op")]
    [Arguments("read-denied")]
    [Arguments("read-malformed")]
    public async Task OriginalRoleOperationServiceCannotReplaceProofOrIndependentAbsence(string fault)
    {
        await using var f = new RoleOperationServiceFixture();
        f.Fault = fault;
        if (fault is "lost" or "no-op") f.Native.State.SelectedDeleteFault = fault;
        if (fault == "nonempty") f.Native.State.SelectedDeleteBody = """{"status":"Succeeded"}""";
        if (fault is "continuation" or "retry")
            f.Native.State.SelectedDeleteHeader = fault == "retry" ? "Retry-After" : "Location";
        int setupWrites = 0;
        f.AfterPrepare = () => setupWrites = f.Native.WriteCount;
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.WriteCount).IsEqualTo(setupWrites);
    }

    [Test]
    [Arguments("principal")]
    [Arguments("definition")]
    [Arguments("scope")]
    public async Task OriginalRoleOperationServiceRequiresMeasuredOwnedBaseline(string fault)
    {
        await using var f = new RoleOperationServiceFixture() { BaselineFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    public async Task OriginalRoleOperationServiceRejectsUnadmittedCaseBeforeDeclaration(string boundary)
    {
        await using var f = new RoleOperationServiceFixture(boundary);
        await Assert.That(async () => await f.Observer.PostAsync<Op.Prepare, Op.Lease>(
            "operation/prepare", f.PrepareRequest(), default)).Throws<NativeCaseFailureException>();
        await Assert.That(Directory.EnumerateFiles(f.Native.DirectoryPath).Any()).IsFalse();
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    public async Task OriginalRoleOperationPreparationReplyLossRetainsCleanupOwnership(string fault)
    {
        await using var f = new RoleOperationServiceFixture() { PrepareReplyFault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task OriginalRoleOperationLeaseCannotAdoptRequestedAssignment()
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(lease.RoleAssignmentId == f.RequestedAssignment).IsFalse();
        await Assert.That(f.Native.Read().Resources.Any(r => !r.Borrowed &&
            r.Id.EndsWith("/" + lease.RoleAssignmentId!.Value.ToString("D"), StringComparison.OrdinalIgnoreCase))).IsTrue();
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task OriginalRoleOperationCachedCompletionRequiresIndependentAbsence()
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(await started.Value!.CheckStatusAsync()).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        var measured = await f.Observe(lease);
        await Assert.That(measured.ResourceStatus).IsEqualTo(SecretStatus.Absent);
        await Assert.That(measured.OperationState).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(f.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        await Assert.That(await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default)).IsEqualTo(SecretStatus.Success);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalRoleOperationRestartCannotRebuildOriginalProof(bool complete)
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        if (complete) await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        await f.Source.DisposeAsync();
        await using var restarted = f.NewSource();
        using var observer = f.NewObserver(restarted);
        var release = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", f.Native.Selector, default);
        await Assert.That(f.Native.Read().Released).IsEqualTo(complete);
        await Assert.That(release.ActiveDispatches == 0).IsEqualTo(complete);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
    }

    [Test]
    public async Task OriginalRoleOperationHistoricalProofCannotReopenClosedRoot()
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await f.Observe(lease);
        await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
        await Assert.That(async () => await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalRoleOperationReappearingAssignmentBlocksReplayAndParentCleanup()
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        var assignment = f.Native.State.AssignmentPath;
        var started = await f.Start(lease);
        await f.Observe(lease);
        await f.Source.RunCheckStatusAsync(f.Native.Selector, started.Value!, default);
        f.Native.State.AssignmentPath = assignment;
        int writes = f.Native.WriteCount;
        var release = await f.Release();
        await Assert.That(release.RemainingResourceIds.Length > 0).IsTrue();
        await Assert.That(f.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(f.SelectedRequests.Count).IsEqualTo(1);
        await Assert.That(f.Native.State.VaultExists).IsTrue();
    }

    [Test]
    [Arguments("selected")]
    [Arguments("resource")]
    public async Task OriginalRoleOperationDisposalDrainsActualBorrowersBeforeHostCleanup(string barrier)
    {
        await using var f = new RoleOperationServiceFixture();
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (barrier == "selected")
        {
            f.Native.State.SelectedApplied = f.Entered;
            f.Native.State.SelectedTerminate = f.Resume;
            work = f.Start(lease);
        }
        else
        {
            await f.Start(lease);
            f.Barrier = barrier;
            work = f.Observe(lease).AsTask();
        }
        Task? disposal = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That((await f.Release()).ActiveDispatches > 0).IsTrue();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposal.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception exception) when (exception is OperationCanceledException or NativeCaseFailureException or InvalidOperationException) { }
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Native.Credentials.All(c => !c.Disposed)).IsTrue();
    }

    private sealed class RoleOperationServiceFixture : IAsyncDisposable
    {
        private static readonly Uri Origin = new("https://role-operation.fixture.invalid");
        private const string Capability = "controlled-role-operation-capability";
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly HttpClient resourceHttp, selectedHttp;
        private readonly HttpPipelineTransport resourceTransport, selectedTransport;
        private readonly Credential resourceCredential = new("observe-operation-arm");
        private readonly Backend selectedBackend;
        private readonly Op.Input input;
        internal readonly Fixture Native;
        private readonly bool statusRoleDeleteIndependent;
        private bool readArmed;
        internal readonly RoleOp Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly Guid RequestedAssignment = Guid.NewGuid();
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ObservationSubscription? Armed;
        internal string? Fault, BaselineFault, PrepareReplyFault, Barrier;
        internal System.Action? AfterPrepare;
        internal Action<JsonObject>? BaselineTransform;
        internal int ResourceReads;
        internal IReadOnlyList<(HttpMethod Method, string Path)> SelectedRequests => selectedBackend.Requests;

        internal RoleOperationServiceFixture(string boundary = "selected-contract", bool statusRoleDeleteIndependent = false)
        {
            this.statusRoleDeleteIndependent = statusRoleDeleteIndependent;
            resourceHttp = new(new RoleOperationHandler(Resource));
            resourceTransport = new HttpClientTransport(resourceHttp);
            Native = new(allowPurge: true, selector: new(Guid.NewGuid(), "controlled", Op.Members[0].Operation,
                "operation.DeleteRoleAssignment", boundary), observeArmTransport: statusRoleDeleteIndependent ? resourceTransport : null);
            selectedBackend = new("administrative-arm", Native.State);
            selectedHttp = new(selectedBackend);
            selectedTransport = new HttpClientTransport(selectedHttp);
            Source = NewSource();
            Observer = NewObserver(Source);
            input = new(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                new(ServiceArm("setup-arm"), ServiceArm("administrative-arm"), ServiceArm("denied-arm"), ServiceArm("observe-operation-arm")),
                Subscription, "fixture-group", "eastus", Tenant, VaultSku.Standard, 7,
                ManagementMutation.DeleteRoleAssignment, "https://unused.example/webhook", RequestedAssignment);
        }

        internal RoleOp NewSource(RoleFixtureProvisioner? provisioner = null, bool cleanupOnly = false) => statusRoleDeleteIndependent
            ? cleanupOnly
                ? RoleOp.ForStatusRoleDeleteIndependentCleanup(Origin, "owner", "role-operation-source", capability, Native.Source.Host,
                    provisioner ?? Native.Source, new(65536, 65536, TimeSpan.FromSeconds(20)))
                : RoleOp.ForStatusRoleDeleteIndependent(Origin, "owner", "role-operation-source", capability, Native.Source.Host,
                    provisioner ?? Native.Source, new("observe-arm", Native.Credentials[2], resourceTransport), selectedTransport,
                    new(65536, 65536, TimeSpan.FromSeconds(20)))
            : new(Origin, "owner", "role-operation-source", capability, Native.Source.Host,
                provisioner ?? Native.Source, new("operation-reader", resourceCredential, resourceTransport), selectedTransport,
                new(65536, 65536, TimeSpan.FromSeconds(20)));
        internal OwnedManagementObserver NewObserver(RoleOp source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new RoleOperationHandler((request, token) =>
            {
                if (request.RequestUri!.AbsolutePath == "/operation/arm") readArmed = true;
                return source.DispatchAsync(request, token);
            }));
        internal Op.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group", "eastus", Tenant,
            VaultSku.Standard, 7, ManagementMutation.DeleteRoleAssignment, input.WebhookUrl, RequestedAssignment);
        internal async Task<Op.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<Op.Prepare, Op.Lease>("operation/prepare", PrepareRequest(), default);
            Armed = await Observer.SubscribeAsync("operation", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, Op.Measurement>("operation/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", Armed.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<ManagementOperation>> Start(Op.Lease lease)
        {
            var client = new VaultAdministration(new Credential("administrative-arm"), Source.SelectedTransport);
            var scope = new RoleAssignmentScope(new VaultScope(new(new(Subscription), "fixture-group"), lease.VaultName),
                lease.RoleAssignmentId ?? throw new InvalidOperationException("missing-role-operation-target"));
            var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteRoleAssignment);
            return Source.RunStartAsync(Native.Selector, client, scope, ManagementMutation.DeleteRoleAssignment, input, receipt, default).AsTask();
        }
        internal ValueTask<Op.Measurement> Observe(Op.Lease lease) => Observer.PostAsync<ObserveLease, Op.Measurement>(
            "operation/observe", new(lease.Facts.LeaseId, lease.Facts.Nonce, "selected-state", Armed!.SubscriptionId), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release() => Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "operation/release", Native.Selector, default);

        private async Task<HttpResponseMessage> Resource(HttpRequestMessage request, CancellationToken token)
        {
            ResourceReads++;
            if (selectedBackend.Requests.Count > 0)
            {
                if (Barrier == "resource") { Entered.TrySetResult(); await Resume.Task; }
                if (Fault == "read-denied") return new(HttpStatusCode.Forbidden) { Content = new StringContent("{}") };
                if (Fault == "read-malformed") return new(HttpStatusCode.OK) { Content = new StringContent("{") };
            }
            var response = await Native.State.Respond(request, statusRoleDeleteIndependent ? "observe-arm" : "observe-operation-arm", token);
            if (selectedBackend.Requests.Count > 0 && Barrier == "resource-body")
            {
                byte[] bytes = await response.Content.ReadAsByteArrayAsync(token);
                response.Content.Dispose();
                response.Content = new StreamContent(new RoleCancellationBody(bytes, Entered, Resume));
                response.Content.Headers.ContentType = new("application/json");
            }
            if (selectedBackend.Requests.Count == 0 && (BaselineFault is not null || BaselineTransform is not null) &&
                (!statusRoleDeleteIndependent || readArmed && !Native.Read().Closing &&
                    request.RequestUri!.AbsolutePath.Contains("/roleAssignments/", StringComparison.Ordinal)))
            {
                var body = JsonNode.Parse(await response.Content.ReadAsByteArrayAsync(token))!.AsObject();
                if (BaselineFault == "principal") body["properties"]!["principalId"] = Guid.NewGuid().ToString("D");
                if (BaselineFault == "definition") body["properties"]!["roleDefinitionId"] = DefinitionPath + "-foreign";
                if (BaselineFault == "scope") body["properties"]!["scope"] = GroupPath;
                BaselineTransform?.Invoke(body);
                response.Content.Dispose();
                response.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            }
            return response;
        }

        internal async Task<NativeCaseResult> RunOriginal(Op.SelectedInvocation? selectedInvocation = null)
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"),
                runtime = Runtime("runtime-secret"),
                denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"),
                observer = Runtime("observer-secret"),
                families = new Dictionary<string, object> { ["ManagementOperation"] = input }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", Op.Members[0].Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), Op.Members[0].Member);
            var registry = new NativeCaseRegistry();
            Op.Register(registry, environment, [definition], endpoint => new(endpoint,
                new RoleOperationHandler(async (request, token) =>
                {
                    bool prepare = request.RequestUri!.AbsolutePath == "/operation/prepare";
                    if (request.RequestUri.AbsolutePath == "/operation/arm") readArmed = true;
                    if (prepare) Native.Selector = JsonSerializer.Deserialize<Op.Prepare>(
                        await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    var reply = await Source.DispatchAsync(request, token);
                    if (!prepare) return reply;
                    AfterPrepare?.Invoke();
                    if (PrepareReplyFault is null) return reply;
                    reply.Dispose();
                    if (PrepareReplyFault == "lost") throw new IOException("controlled-role-preparation-reply-loss");
                    return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{") };
                })), Source.SelectedTransport, selectedInvocation ?? Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        public async ValueTask DisposeAsync()
        {
            try { await Source.DisposeAsync(); }
            finally
            {
                Observer.Dispose();
                resourceHttp.Dispose();
                selectedHttp.Dispose();
                capability.Dispose();
                Native.Dispose();
            }
        }
    }

    private sealed class RoleOperationHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
