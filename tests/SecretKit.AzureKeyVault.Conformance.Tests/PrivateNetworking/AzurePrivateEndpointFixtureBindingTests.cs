using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using Provisioner = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    public async Task MatchingUnregisteredCandidatesCannotMintOrReplaceAnAtomicBinding()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        await using var source = wire.Service();
        var forged = new PrivateEndpointFixtureProvisioner.BindingCandidate(source, wire.ConnectionId);
        bool rejected = false;
        wire.BeforePut = () =>
        {
            try { f.Journal.BindGeneratedPrivateConnection(Owner, f.Selector, parent.LeaseId, forged); }
            catch (InvalidOperationException) { rejected = true; }
        };
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(rejected).IsTrue();
        await Assert.That(result.State.ToString()).IsEqualTo("Ready");
        await Assert.That(() => f.Journal.BindGeneratedPrivateConnection(Owner, f.Selector, parent.LeaseId, forged))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Read().PrivateEndpoint!.Connection?.Id).IsEqualTo(wire.ConnectionId);
    }

    [Test]
    public async Task RootClosedDuringSetupCredentialCannotReachEndpointPut()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        wire.BeforeSetupCredential = () => f.Source.CloseSelectedRoot(Owner, f.Selector);
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString() == "Ready").IsFalse();
        await Assert.That(wire.Requests.Any(r => r.Method == "PUT")).IsFalse();
        await Assert.That(f.Read().Closing).IsTrue();
        await Assert.That(f.Read().PrivateEndpoint!.Connection).IsNull();
    }

    [Test]
    public async Task VerifiedOriginalParentContinuationCanRegisterEndpointReadinessWithoutReplay()
    {
        using var f = EndpointParent();
        f.Wire.CreateFault = "async";
        var parent = EndpointParentPlan(f);
        await Assert.That((await f.Source.ProvisionAsync(parent)).State).IsEqualTo(Provisioner.State.Pending);
        await Assert.That(f.Source.OwnsPreparedPlan(parent)).IsFalse();
        await Assert.That((await f.Source.SettleAsync(parent)).State).IsEqualTo(Provisioner.State.Pending);
        f.Wire.NativeStatus = "Succeeded";
        await Assert.That((await f.Source.SettleAsync(parent)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Source.OwnsPreparedPlan(parent)).IsFalse();
        await Assert.That((await f.Source.ContinueAsync(parent)).State).IsEqualTo(Provisioner.State.Ready);
        await Assert.That(f.Source.OwnsPreparedPlan(parent)).IsTrue();
        using var wire = new EndpointBindingWire(f);
        await using var source = wire.Service();
        await Assert.That(source.PlanDeclaredEndpoint(parent)).IsNotNull();
        await Assert.That(wire.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Backends[0].Requests.Count(r => r.Method == HttpMethod.Put)).IsEqualTo(1);
    }

    [Test]
    public async Task BoundEndpointDependenciesFenceRestartedParentCleanup()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        await using var source = wire.Service();
        await Assert.That((await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent))).State.ToString()).IsEqualTo("Ready");
        await source.DisposeAsync();
        int before = f.Writes;
        await using var cleanup = f.Cleanup();
        var result = await cleanup.ReleaseAsync(Owner, f.Selector, purge: true);
        await Assert.That(result.State).IsNotEqualTo(Provisioner.State.Released);
        await Assert.That(f.Writes).IsEqualTo(before);
        await Assert.That(f.Read().PrivateEndpoint!.Connection?.Id).IsEqualTo(wire.ConnectionId);
        await Assert.That(f.Read().Released).IsFalse();
        await Assert.That(wire.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task GenericEndCannotSettleEndpointCreationBeforeAtomicBinding()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        bool rejected = false;
        wire.BeforePut = () =>
        {
            var root = f.Read();
            var row = root.Resources.Single(r => r.Id == wire.Binding.EndpointId);
            try { f.Journal.EndDispatch(Owner, f.Selector, row.Id, row.ActiveDispatch, true); }
            catch (InvalidOperationException) { rejected = true; }
        };
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(rejected).IsTrue();
        await Assert.That(result.State.ToString()).IsEqualTo("Ready");
    }

    [Test]
    public async Task GenericSettlementCannotClearAnUnboundTerminatedCreationFence()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { Fault = "ambiguous" };
        await using var source = wire.Service();
        await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        var row = f.Read().Resources.Single(r => r.Id == wire.Binding.EndpointId);
        await Assert.That(row.InvocationTerminated && row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Journal.SettleDispatch(Owner, f.Selector, row.Id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Read().Resources.Single(r => r.Id == row.Id).ActiveDispatch).IsEqualTo(row.ActiveDispatch);
    }

    [Test]
    public async Task RetainedBindingCanRecoverDurableContentionWithoutRecreatingOrRereading()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        FileStream? blocker = null;
        wire.AfterConcrete = () => blocker = new FileStream(f.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        await using var source = wire.Service();
        var plan = source.PlanDeclaredEndpoint(parent);
        try
        {
            await Assert.That(async () => await source.ProvisionAsync(plan)).Throws<InvalidOperationException>();
        }
        finally { blocker?.Dispose(); }
        await Assert.That(blocker is not null).IsTrue();
        int reads = wire.Requests.Count;
        var recovered = await source.CompleteBindingAsync(plan);
        await Assert.That(recovered.State.ToString()).IsEqualTo("Ready");
        await Assert.That(wire.Requests.Count).IsEqualTo(reads);
        await Assert.That(wire.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Read().PrivateEndpoint!.Connection?.Id).IsEqualTo(wire.ConnectionId);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EndpointCompositionDrainsUncooperativeCreationWithoutDiscardingItsDurableFence(bool dispose)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        wire.BeforePutAsync = async token =>
        {
            using var registration = token.Register(() => canceled.TrySetResult());
            entered.TrySetResult();
            await resume.Task;
        };
        await using var source = wire.Service();
        var plan = source.PlanDeclaredEndpoint(parent);
        using var cancellation = new CancellationTokenSource();
        var provision = source.ProvisionAsync(plan, cancellation.Token).AsTask();
        Task? close = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (dispose) close = source.DisposeAsync().AsTask();
            else cancellation.Cancel();
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(provision.IsCompleted || close?.IsCompleted == true).IsFalse();
            await Assert.That(f.Read().Resources.Single(r => r.Id == wire.Binding.EndpointId).ActiveDispatch != Guid.Empty).IsTrue();
        }
        finally { resume.TrySetResult(); }
        if (dispose)
        {
            await Assert.That((await provision.WaitAsync(TimeSpan.FromSeconds(10))).State.ToString() == "Ready").IsFalse();
            await close!.WaitAsync(TimeSpan.FromSeconds(10));
        }
        else await Assert.That(async () => await provision.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        var root = f.Read();
        await Assert.That(root.PrivateEndpoint!.Connection).IsNull();
        await Assert.That(root.Resources.Single(r => r.Id == wire.Binding.EndpointId).ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(root.Released).IsFalse();
    }

    [Test]
    public async Task OriginalOwnedEndpointCreationBindsProviderAssignedConnectionNotNetworkSideName()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await Assert.That((await f.Source.ProvisionAsync(parent)).State).IsEqualTo(Provisioner.State.Ready);
        using var wire = new EndpointBindingWire(f);
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString()).IsEqualTo("Ready");
        var root = f.Read();
        var endpoint = root.PrivateEndpoint ?? throw new InvalidOperationException("missing-endpoint-slot");
        await Assert.That(endpoint.Connection?.Id).IsEqualTo(wire.ConnectionId);
        await Assert.That(endpoint.Connection!.Id.EndsWith("/" + endpoint.Declaration.NetworkConnectionName, StringComparison.Ordinal)).IsFalse();
        await Assert.That(endpoint.Connection.CreateAttempted).IsTrue();
        await Assert.That(root.Resources.Single(r => r.Id == endpoint.Declaration.EndpointId).ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(root.Resources.Length).IsEqualTo(5);
        await Assert.That(wire.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(wire.Requests.Any(r => r.Method is "DELETE" or "PATCH")).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreexistingEndpointOrManagedNicCannotBeAdoptedByMatchingMetadata(bool nic)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { EndpointExists = !nic, NicExists = nic };
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString() == "Ready").IsFalse();
        await Assert.That(wire.Requests.Any(r => r.Method != "GET")).IsFalse();
        await Assert.That(f.Read().PrivateEndpoint!.Connection).IsNull();
    }

    [Test]
    [Arguments("ambiguous")]
    [Arguments("foreign-concrete-endpoint")]
    [Arguments("truncated")]
    public async Task UnqualifiedGeneratedChildDiscoveryCannotClearOriginalCreationFence(string fault)
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f) { Fault = fault };
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString() == "Ready").IsFalse();
        var root = f.Read();
        var slot = root.PrivateEndpoint ?? throw new InvalidOperationException("missing-endpoint-slot");
        await Assert.That(slot.Connection).IsNull();
        var endpoint = root.Resources.Single(r => r.Id == slot.Declaration.EndpointId);
        await Assert.That(endpoint.CreateAttempted).IsTrue();
        await Assert.That(endpoint.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(root.Released).IsFalse();
        await Assert.That(wire.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(wire.Requests.Any(r => r.Method == "DELETE")).IsFalse();
    }

    [Test]
    public async Task RootCloseBeforeEndpointAdmissionPreventsAnyNetworkMutation()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        wire.BeforeAdmission = () => f.Journal.Close(Owner, f.Selector);
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString() == "Ready").IsFalse();
        await Assert.That(wire.Requests.Any(r => r.Method != "GET")).IsFalse();
        await Assert.That(f.Read().Closing).IsTrue();
    }

    [Test]
    public async Task AlreadyAdmittedCreationCanBindCleanupCoordinatesAfterCloseButCannotBecomeReady()
    {
        using var f = EndpointParent();
        var parent = EndpointParentPlan(f);
        await f.Source.ProvisionAsync(parent);
        using var wire = new EndpointBindingWire(f);
        wire.BeforePut = () => f.Journal.Close(Owner, f.Selector);
        await using var source = wire.Service();
        var result = await source.ProvisionAsync(source.PlanDeclaredEndpoint(parent));
        await Assert.That(result.State.ToString() == "Ready").IsFalse();
        var root = f.Read();
        await Assert.That(root.Closing).IsTrue();
        await Assert.That(root.PrivateEndpoint!.Connection?.Id).IsEqualTo(wire.ConnectionId);
        await Assert.That(root.Resources.Single(r => r.Id == wire.Binding.EndpointId).ActiveDispatch).IsEqualTo(Guid.Empty);
        await Assert.That(wire.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
    }

    private static Fixture EndpointParent()
    {
        var f = new Fixture(allowPurge: true);
        f.Selector = f.Selector with
        {
            Operation = ManagementOperationEffects.Members[0].Operation,
            Variant = "operation.UpdatePrivateConnection"
        };
        return f;
    }

    private static Provisioner.Plan EndpointParentPlan(Fixture f) =>
        f.Plan(seedCanary: false, privateEndpoint: new(DeclaredSubnet));

    private sealed class EndpointBindingWire : IDisposable
    {
        private readonly Fixture parent;
        private readonly List<HttpClient> clients = [];
        internal readonly PrivateEndpointResourceCollector.Binding Binding;
        internal readonly List<(string Method, string Path)> Requests = [];
        internal bool EndpointExists, NicExists;
        internal bool AllowEndpointDelete, PreserveNicAfterDelete;
        internal bool? ConnectionPresent;
        internal string ConnectionState = "Pending";
        internal string ConnectionProvisioning = "Succeeded";
        internal string? Fault;
        internal Action? BeforeAdmission, BeforePut;
        internal Action? BeforeDelete;
        internal Action? BeforeSetupCredential;
        internal Action? AfterConcrete;
        internal Func<CancellationToken, Task>? BeforePutAsync;
        internal Func<CancellationToken, Task>? BeforeDeleteAsync;
        internal string ConnectionId => Binding.VaultId + "/privateEndpointConnections/provider-assigned-connection";
        internal EndpointBindingWire(Fixture parent)
        {
            this.parent = parent;
            var root = parent.Read();
            var d = root.PrivateEndpoint?.Declaration ?? throw new InvalidOperationException("missing-endpoint-declaration");
            Binding = new(parent.Selector, root.LeaseId, d.EndpointId, d.VaultId, d.BorrowedSubnetId, d.ExpectedNicId,
                d.NetworkConnectionName, parent.Source.Host.Location, d.OwnerTagName, d.OwnerTagValue);
        }

        internal PrivateEndpointFixtureProvisioner Service(Provisioner? parentSource = null) =>
            new(parentSource ?? parent.Source,
                new("endpoint-setup", new EndpointWireCredential { BeforeToken = BeforeSetupCredential }, Transport()),
                new("endpoint-reader", new EndpointWireCredential(), Transport()),
                new("connection-reader", new EndpointWireCredential(), Transport()),
                new(65536, 32768, 4096, 64, 16, TimeSpan.FromSeconds(20)),
                new(1, 4, 65536, 32768, TimeSpan.FromSeconds(20)));

        private HttpPipelineTransport Transport()
        {
            var client = new HttpClient(new EndpointWireHandler(Respond));
            clients.Add(client);
            return new HttpClientTransport(client);
        }

        internal async Task<HttpResponseMessage> Respond(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            string path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method.Method, path));
            if (request.Method == HttpMethod.Put && path == Binding.EndpointId)
            {
                if (BeforePutAsync is not null) await BeforePutAsync(token);
                BeforePut?.Invoke();
                EndpointExists = NicExists = true;
                return Reply(200, EndpointData());
            }
            if (request.Method == HttpMethod.Delete && path == Binding.EndpointId && AllowEndpointDelete)
            {
                if (BeforeDeleteAsync is not null) await BeforeDeleteAsync(token);
                BeforeDelete?.Invoke();
                EndpointExists = false;
                if (!PreserveNicAfterDelete) NicExists = false;
                if (Fault == "lost-delete") throw new IOException("controlled-lost-endpoint-delete");
                var response = new HttpResponseMessage(HttpStatusCode.NoContent) { Content = new ByteArrayContent([]) };
                response.Headers.Add("x-ms-request-id", "controlled-endpoint-delete");
                return response;
            }
            if (request.Method != HttpMethod.Get) throw new InvalidOperationException("unexpected-endpoint-mutation");
            if (path == Binding.EndpointId)
                return EndpointExists ? Reply(200, EndpointData()) : Reply(404, Error());
            if (path == Binding.NicId)
            {
                BeforeAdmission?.Invoke();
                return NicExists ? Reply(200, new JsonObject
                {
                    ["id"] = Binding.NicId,
                    ["name"] = Binding.NicId[(Binding.NicId.LastIndexOf('/') + 1)..],
                    ["type"] = "Microsoft.Network/networkInterfaces",
                    ["location"] = Binding.Location,
                    ["properties"] = new JsonObject { ["provisioningState"] = "Succeeded" }
                }) : Reply(404, Error());
            }
            if (path == Binding.VaultId + "/privateEndpointConnections")
            {
                var rows = new JsonArray();
                if (ConnectionPresent ?? EndpointExists) rows.Add(ConnectionData());
                if (Fault == "ambiguous")
                {
                    var second = ConnectionData();
                    second["id"] = ConnectionId + "-second";
                    second["name"] = "provider-assigned-connection-second";
                    rows.Add(second);
                }
                var body = new JsonObject { ["value"] = rows };
                if (Fault == "truncated")
                    body["nextLink"] = "https://management.azure.com" + path + "?api-version=2026-02-01&$skiptoken=next";
                return Reply(200, body);
            }
            if (path == ConnectionId)
            {
                var body = ConnectionData();
                if (Fault == "foreign-concrete-endpoint") body["properties"]!["privateEndpoint"]!["id"] = Binding.EndpointId + "-foreign";
                AfterConcrete?.Invoke();
                return (ConnectionPresent ?? EndpointExists) ? Reply(200, body) : Reply(404, Error());
            }
            throw new InvalidOperationException("unexpected-endpoint-read");
        }

        private JsonObject EndpointData() => new()
        {
            ["id"] = Binding.EndpointId,
            ["name"] = Binding.EndpointId[(Binding.EndpointId.LastIndexOf('/') + 1)..],
            ["type"] = "Microsoft.Network/privateEndpoints",
            ["location"] = Binding.Location,
            ["tags"] = new JsonObject { [Binding.OwnerTagName] = Binding.OwnerTagValue },
            ["properties"] = new JsonObject
            {
                ["provisioningState"] = "Succeeded",
                ["subnet"] = new JsonObject { ["id"] = Binding.SubnetId },
                ["networkInterfaces"] = new JsonArray(new JsonObject { ["id"] = Binding.NicId }),
                ["manualPrivateLinkServiceConnections"] = new JsonArray(new JsonObject
                {
                    ["name"] = Binding.ConnectionName,
                    ["properties"] = new JsonObject
                    {
                        ["privateLinkServiceId"] = Binding.VaultId,
                        ["groupIds"] = new JsonArray("vault"),
                        ["privateLinkServiceConnectionState"] = new JsonObject { ["status"] = "Pending" }
                    }
                })
            }
        };

        internal JsonObject ConnectionData() => new()
        {
            ["id"] = ConnectionId,
            ["name"] = "provider-assigned-connection",
            ["type"] = "Microsoft.KeyVault/vaults/privateEndpointConnections",
            ["location"] = Binding.Location,
            ["properties"] = new JsonObject
            {
                ["provisioningState"] = ConnectionProvisioning,
                ["privateEndpoint"] = new JsonObject { ["id"] = Binding.EndpointId },
                ["privateLinkServiceConnectionState"] = new JsonObject { ["status"] = ConnectionState }
            }
        };

        private static JsonObject Error() => new() { ["error"] = new JsonObject { ["code"] = "NotFound", ["message"] = "controlled" } };
        private static HttpResponseMessage Reply(int status, JsonObject body)
        {
            var reply = new HttpResponseMessage((HttpStatusCode)status)
            {
                Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json")
            };
            reply.Headers.Add("x-ms-request-id", "endpoint-binding-native");
            return reply;
        }
        public void Dispose() { foreach (var client in clients) client.Dispose(); }
    }

    private sealed class EndpointWireCredential : TokenCredential
    {
        internal Action? BeforeToken;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) =>
            throw new InvalidOperationException("controlled-async-only");
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            BeforeToken?.Invoke();
            return ValueTask.FromResult(new AccessToken("controlled-endpoint-binding", DateTimeOffset.MaxValue));
        }
    }

    private sealed class EndpointWireHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token);
    }
}
