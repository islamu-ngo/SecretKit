using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using U = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationFixtureObserverService;
using V = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    public static IEnumerable<(string Variant, string Boundary)> OriginalPrivateUpdateCases()
    {
        foreach (string variant in new[]
        { "state.Unknown.rejected", "state.Pending.rejected", "state.Approved", "state.Rejected", "state.Disconnected.rejected" })
            foreach (string boundary in new[]
            { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary", "lost-response-no-replay" })
                yield return (variant, boundary);
    }

    [Test]
    [MethodDataSource(nameof(OriginalPrivateUpdateCases))]
    public async Task OriginalPrivateUpdateRunsExactEnumAndIndependentEffects(string variant, string boundary)
    {
        await using var f = new OriginalPrivateUpdateFixture(variant, boundary);
        var result = await f.RunOriginal();
        bool invalid = variant.EndsWith(".rejected", StringComparison.Ordinal);
        bool uncertain = !invalid && boundary is "cancellation-boundary" or "lost-response-no-replay";
        bool denied = !invalid && boundary == "denied-authority";
        await Assert.That(result.Passed).IsEqualTo(!uncertain);
        if (uncertain) await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(f.SelectedPuts).IsEqualTo(invalid ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.SetupPuts).IsEqualTo(1);
        await Assert.That(f.CanarySets).IsEqualTo(1);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "PUT")).IsEqualTo(1);
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.ParentDeletes).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.ParentPurges).IsEqualTo(uncertain ? 0 : 1);
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(5);
        await Assert.That(f.Native.Read().Released).IsEqualTo(!uncertain);
        await Assert.That(f.Prejournaled && f.Native.Wire.Prejournaled).IsTrue();
        await Assert.That(f.Tap.Completions).IsEqualTo(invalid || denied || uncertain ? 0 : 1);
        await Assert.That(f.PrivateReads > 0 && f.PublicReads > 0).IsTrue();
        if (!uncertain)
            await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(invalid ? DispatchEvidence.NotDispatched :
                denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied);
        if (!invalid && !denied)
        {
            await Assert.That(f.SelectedBody!.Count).IsEqualTo(1);
            await Assert.That(f.SelectedBody["properties"]!["privateLinkServiceConnectionState"]!["status"]!.GetValue<string>())
                .IsEqualTo(f.Requested.ToString());
        }
        if (uncertain)
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
    }

    [Test]
    [Arguments("selected-malformed")]
    [Arguments("selected-updating")]
    [Arguments("selected-accepted")]
    [Arguments("selected-created")]
    [Arguments("selected-state")]
    [Arguments("selected-endpoint")]
    [Arguments("selected-continuation")]
    [Arguments("unchanged")]
    [Arguments("post-child-state")]
    [Arguments("post-child-endpoint")]
    [Arguments("post-endpoint-state")]
    [Arguments("post-endpoint-subnet")]
    [Arguments("post-parent-owner")]
    [Arguments("post-parent-configuration")]
    [Arguments("private-denied")]
    [Arguments("private-version")]
    [Arguments("private-digest")]
    [Arguments("public-denied")]
    [Arguments("public-version")]
    [Arguments("public-digest")]
    public async Task OriginalPrivateUpdateRejectsIncompleteNativeConjunction(string fault)
    {
        await using var f = new OriginalPrivateUpdateFixture();
        f.Fault = fault;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.FaultsReached > 0).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(0);
        await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("state.Approved")]
    [Arguments("state.Rejected")]
    public async Task OriginalPrivateUpdateCompletesActualCachedHandleWithoutSelectedGet(string variant)
    {
        await using var f = new OriginalPrivateUpdateFixture(variant);
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease);
        await Assert.That(started.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(started.Value!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await f.Post(lease);
        int reads = f.PrivateReads + f.PublicReads;
        await f.Post(lease);
        await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
        await Assert.That(await f.Source.CompleteUpdatePrivateConnectionAsync(f.Native.Selector, started.Value, default))
            .IsEqualTo(SecretStatus.Success);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SelectedCredentialCalls).IsEqualTo(1);
        await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("state.Unknown.rejected")]
    [Arguments("state.Pending.rejected")]
    [Arguments("state.Disconnected.rejected")]
    public async Task OriginalPrivateUpdateInvalidEnumNeverAcquiresSelectedCredential(string variant)
    {
        await using var f = new OriginalPrivateUpdateFixture(variant);
        var lease = await f.PrepareAndBaseline();
        var result = await f.Start(lease);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(f.Tap.Receipt!.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(f.SelectedCredentialCalls).IsEqualTo(0);
        await Assert.That(f.SelectedPuts + f.SelectedGets).IsEqualTo(0);
        await f.Post(lease);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments("selected-arm")]
    [Arguments("read-arm")]
    [Arguments("connection-reader-arm")]
    [Arguments("endpoint-reader-arm")]
    [Arguments("private-runtime-secret")]
    [Arguments("public-runtime-secret")]
    public async Task OriginalPrivateUpdateCloseDrainsActualBorrowerBeforeCleanup(string stage)
    {
        await using var f = new OriginalPrivateUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        Task work;
        if (stage == "selected-arm") { f.Barrier = stage; work = f.Start(lease); }
        else
        {
            await f.Start(lease);
            f.Barrier = stage;
            work = f.Post(lease).AsTask();
        }
        Task? disposing = null;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await f.Release();
            disposing = f.Source.DisposeAsync().AsTask();
            await Assert.That(work.IsCompleted || disposing.IsCompleted).IsFalse();
            await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        }
        finally { f.Resume.TrySetResult(); }
        try { await work.WaitAsync(TimeSpan.FromSeconds(10)); }
        catch (Exception ex) when (ex is OperationCanceledException or InvalidOperationException or NativeCaseFailureException) { }
        await disposing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Released).IsFalse();
    }

    [Test]
    public async Task OriginalPrivateUpdateRejectsCounterfeitAndGenericSettlement()
    {
        await using var f = new OriginalPrivateUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That(() => f.Native.Journal.BeginPrivateConnectionUpdateInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new U.PrivateConnectionUpdateAdmission(f.Source))).Throws<InvalidOperationException>();
        await f.Start(lease);
        string id = f.Endpoint!.ConnectionId;
        var slot = f.Native.Read().PrivateEndpoint!;
        var row = slot.Connection!;
        await Assert.That(row.ActiveDispatch != Guid.Empty).IsTrue();
        await Assert.That(() => f.Native.Journal.EndPrivateConnectionUpdateInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new U.PrivateConnectionUpdateTermination(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettlePrivateConnectionUpdateInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, new U.PrivateConnectionUpdateSettlement(f.Source, row.ActiveDispatch)))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndDispatch(Owner, f.Native.Selector, id, row.ActiveDispatch, nativeSettled: false))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.SettleDispatch(Owner, f.Native.Selector, id, row.ActiveDispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Native.Journal.EndPrivateConnectionApprovalInvocation(Owner, f.Native.Selector,
            lease.Facts.LeaseId, slot.Declaration, id, row.ActiveDispatch)).Throws<InvalidOperationException>();
        f.Native.Journal.Close(Owner, f.Native.Selector);
        await Assert.That(() => f.Native.Journal.RecordAbsence(Owner, f.Native.Selector, id)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch).IsEqualTo(row.ActiveDispatch);
        await Assert.That(f.Endpoint.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    [Arguments("unresolved")]
    [Arguments("updated")]
    [Arguments("denied")]
    [Arguments("invalid")]
    public async Task OriginalPrivateUpdateRestartCannotReconstructInvocationProof(string state)
    {
        await using var f = new OriginalPrivateUpdateFixture(state == "invalid" ? "state.Unknown.rejected" : "state.Approved",
            state == "denied" ? "denied-authority" : "selected-contract");
        var lease = await f.PrepareAndBaseline();
        var started = await f.Start(lease, denied: state == "denied");
        if (state != "unresolved")
        {
            await f.Post(lease);
            if (state == "updated")
                await f.Source.CompleteUpdatePrivateConnectionAsync(f.Native.Selector, started.Value!, default);
        }
        await f.RestartRelease();
        await Assert.That(f.Native.Read().Released).IsEqualTo(state != "unresolved");
        await Assert.That(f.SelectedPuts).IsEqualTo(state == "invalid" ? 0 : 1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(state == "unresolved" ? 0 : 1);
        await Assert.That(f.ParentDeletes).IsEqualTo(state == "unresolved" ? 0 : 1);
        await Assert.That(f.ParentPurges).IsEqualTo(state == "unresolved" ? 0 : 1);
    }

    [Test]
    [Arguments("retry")]
    [Arguments("close")]
    [Arguments("dispose")]
    public async Task OriginalPrivateUpdateRetriesOnlyDrainedPersistenceAcrossFileContention(string mode)
    {
        await using var f = new OriginalPrivateUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        f.LockOnFinalization = true;
        var started = await f.Start(lease);
        await f.Post(lease);
        await Assert.That(f.JournalLock).IsNull();
        Exception? failure = null;
        try { await f.Source.CompleteUpdatePrivateConnectionAsync(f.Native.Selector, started.Value!, default); }
        catch (Exception ex) { failure = ex; }
        try
        {
            await Assert.That(failure).IsNotNull();
            await Assert.That(f.JournalLock).IsNotNull();
        }
        finally { f.UnlockJournal(); }
        int reads = f.PrivateReads + f.PublicReads, requests = f.Endpoint!.Requests.Count;
        if (mode == "retry")
        {
            await Assert.That(await f.Source.CompleteUpdatePrivateConnectionAsync(f.Native.Selector, started.Value!, default))
                .IsEqualTo(SecretStatus.Success);
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
        }
        else
        {
            if (mode == "close") await f.Release();
            await f.Source.DisposeAsync();
            await Assert.That(f.Native.Read().Idle || f.Native.Read().Released).IsFalse();
            await Assert.That(f.Native.Read().PrivateEndpoint!.Connection!.ActiveDispatch != Guid.Empty).IsTrue();
            await Assert.That(f.Endpoint.Requests.Count).IsEqualTo(requests);
            await Assert.That(f.PrivateReads + f.PublicReads).IsEqualTo(reads);
            await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
        }
        await Assert.That(f.SelectedPuts).IsEqualTo(1);
        await Assert.That(f.SelectedGets).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPrivateUpdateRejectsIndependentSdkResponseReplacement(bool disposeOriginal)
    {
        await using var f = new OriginalPrivateUpdateFixture();
        f.ReplaceResponse = true;
        f.DisposeOriginal = disposeOriginal;
        var result = await f.RunOriginal();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(f.Replacements).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.Endpoint!.Requests.Count(r => r.Method == "DELETE") + f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    [Test]
    public async Task OriginalPrivateUpdateObservationDoesNotHoldParentLockAcrossSynchronousCredentials()
    {
        await using var f = new OriginalPrivateUpdateFixture();
        var lease = await f.PrepareAndBaseline();
        await f.Start(lease);
        Task? closing = null;
        bool credentialReturned = false;
        f.OnParentCredential = () =>
        {
            f.OnParentCredential = null;
            closing = Task.Run(() => f.Parent.CloseSelectedRoot(Owner, f.Native.Selector));
            closing.WaitAsync(TimeSpan.FromSeconds(10)).GetAwaiter().GetResult();
            credentialReturned = true;
        };
        await Assert.That(async () => await f.Post(lease)).Throws<NativeCaseFailureException>();
        await Assert.That(closing).IsNotNull();
        await closing!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(credentialReturned).IsTrue();
        await Assert.That(f.Native.Read().Closing).IsTrue();
        await Assert.That(f.Native.Read().Released).IsFalse();
        await Assert.That(f.ParentDeletes + f.ParentPurges).IsEqualTo(0);
    }

    private sealed class OriginalPrivateUpdateFixture : IAsyncDisposable
    {
        private const string Capability = "controlled-original-private-update";
        private static readonly Uri Origin = new("https://original-private-update.invalid/");
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly V.Configuration Baseline;
        internal readonly VaultFixtureProvisioner Parent;
        internal readonly U Source;
        internal readonly OwnedManagementObserver Observer;
        internal readonly UpdateTap Tap;
        internal readonly bool Delete;
        internal readonly PrivateConnectionState Requested;
        internal EndpointBindingWire? Endpoint;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly Dictionary<string, HttpPipelineTransport> transports = [];
        internal int SelectedPuts, SelectedGets, SetupPuts, CanarySets, ParentDeletes, ParentPurges;
        internal int SelectedDeletes;
        internal bool DeleteResourceBody;
        internal int PrivateReads, PublicReads, FaultsReached;
        internal int SelectedCredentialCalls;
        internal bool Prejournaled = true;
        internal string? Fault;
        internal string? Barrier;
        internal bool LockOnFinalization;
        internal FileStream? JournalLock;
        internal bool ReplaceResponse, DisposeOriginal;
        internal int Replacements;
        internal Action? OnParentCredential;
        internal Action? OnEndpointCredential;
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        internal JsonObject? SelectedBody;
        private ObservationSubscription? subscription;
        private static VaultFixtureProvisioner.HostScope Host => new(Subscription, "fixture-group", "eastus", Tenant, true, true);
        internal OriginalPrivateUpdateFixture(string variant = "state.Approved", string boundary = "selected-contract",
            bool delete = false, TimeProvider? time = null)
        {
            Delete = delete;
            Native.Selector = Native.Selector with
            {
                Operation = "a.management.VaultAdministration." + (delete ? "DeletePrivateConnectionAsync" : "UpdatePrivateConnectionAsync"),
                Variant = delete ? "input.scope" : variant, Case = boundary
            };
            Requested = variant switch
            {
                "state.Approved" => PrivateConnectionState.Approved,
                "state.Rejected" => PrivateConnectionState.Rejected,
                "state.Pending.rejected" => PrivateConnectionState.Pending,
                "state.Disconnected.rejected" => PrivateConnectionState.Disconnected,
                _ => PrivateConnectionState.Unknown
            };
            Baseline = Native.Baseline with { PublicNetworkAccess = true };
            var setup = new VaultFixtureProvisioner.Authority("update-setup", CredentialFor("setup-arm"), Transport("setup-arm"));
            var setupSecret = new VaultFixtureProvisioner.Authority("update-setup-secret", CredentialFor("setup-secret"), Transport("setup-secret"));
            var read = new VaultFixtureProvisioner.Authority("update-parent", CredentialFor("read-arm"), Transport("read-arm"));
            var readSecret = new VaultFixtureProvisioner.Authority("update-parent-secret", CredentialFor("read-secret"), Transport("read-secret"));
            var limits = new VaultFixtureProvisioner.Limits(65536, TimeSpan.FromSeconds(20));
            Parent = delete
                ? VaultFixtureProvisioner.ForPrivateConnectionDelete(Native.Journal, Host, Baseline, setup, setupSecret, read, readSecret, limits)
                : VaultFixtureProvisioner.ForPrivateConnectionUpdate(Native.Journal, Host, variant, Baseline, setup, setupSecret, read, readSecret, limits);
            Source = delete ? new(Origin, Owner, "original-private-delete-source", capability, Host,
                new U.PrivateConnectionDeleteSource(Parent,
                    EndpointSource(),
                    new("delete-private-runtime", CredentialFor("private-runtime-secret"), Transport("private-runtime-secret")),
                    new("delete-public-runtime", CredentialFor("public-runtime-secret"), Transport("public-runtime-secret")),
                    new(65536, 8192, 4096, 4, 16, TimeSpan.FromSeconds(20)), Transport("selected-arm")),
                new(65536, 65536, TimeSpan.FromSeconds(20)), time) :
                new(Origin, Owner, "original-private-update-source", capability, Host,
                new U.PrivateConnectionUpdateSource(Parent,
                    EndpointSource(),
                    new("update-private-runtime", CredentialFor("private-runtime-secret"), Transport("private-runtime-secret")),
                    new("update-public-runtime", CredentialFor("public-runtime-secret"), Transport("public-runtime-secret")),
                    new(65536, 8192, 4096, 4, 16, TimeSpan.FromSeconds(20)), Transport("selected-arm")),
                new(65536, 65536, TimeSpan.FromSeconds(20)), time);
            Observer = new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(Source.DispatchAsync));
            Tap = new(Source);
        }
        private UpdateCredential CredentialFor(string role) =>
            new(role, role == "read-arm" ? () => OnParentCredential?.Invoke() :
                role == "endpoint-setup-arm" ? () => OnEndpointCredential?.Invoke() : null);
        private U.PrivateConnectionSource EndpointSource() => new(DeclaredSubnet,
            new("update-endpoint-setup", CredentialFor("endpoint-setup-arm"), Transport("endpoint-setup-arm")),
            new("update-endpoint-reader", CredentialFor("endpoint-reader-arm"), Transport("endpoint-reader-arm")),
            new("update-child-reader", CredentialFor("connection-reader-arm"), Transport("connection-reader-arm")),
            new(65536, 8192, 4096, 32, 16, TimeSpan.FromSeconds(20)),
            new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)));
        private HttpPipelineTransport Transport(string role)
        {
            if (transports.TryGetValue(role, out var existing)) return existing;
            var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
            clients.Add(client);
            HttpPipelineTransport transport = new HttpClientTransport(client);
            if (role == "selected-arm") transport = new UpdateBackend(transport, this);
            transports.Add(role, transport);
            return transport;
        }
        internal async Task<V.Lease> PrepareAndBaseline()
        {
            var lease = await Observer.PostAsync<V.Prepare, V.Lease>("vault/prepare",
                new(Native.Selector, Subscription, "fixture-group", Baseline,
                    [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            await Observer.PostAsync<ObserveLease, V.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription.SubscriptionId), default);
            return lease;
        }
        internal Task<SecretOutcome<ManagementOperation>> Start(V.Lease lease, bool denied = false)
        {
            var client = new VaultAdministration(new UpdateCredential(denied ? "denied-arm" : "selected-arm", () => SelectedCredentialCalls++),
                new UpdateSdk(Source.SelectedTransport, this));
            var scope = new PrivateConnectionScope(new(new(new(Subscription), "fixture-group"), lease.VaultName),
                lease.PrivateConnectionName!);
            return Delete ? Tap.RunDeletePrivateConnectionAsync(Native.Selector, client, scope,
                client.PrepareReceipt(scope, ManagementMutation.DeletePrivateConnection), default).AsTask() :
                Tap.RunUpdatePrivateConnectionAsync(Native.Selector, client, scope, Requested,
                    client.PrepareReceipt(scope, ManagementMutation.UpdatePrivateConnection), default).AsTask();
        }
        internal ValueTask<V.Measurement> Post(V.Lease lease) => Observer.PostAsync<ObserveLease, V.Measurement>("vault/observe",
            new(lease.Facts.LeaseId, lease.Facts.Nonce, "post-operation", subscription!.SubscriptionId), default);
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal async Task RestartRelease()
        {
            await using var parent = VaultFixtureProvisioner.ForCleanup(new RoleFixtureJournal(
                Path.GetDirectoryName(Native.JournalPath) ?? throw new InvalidOperationException("journal-directory")),
                Host, new("update-cleanup-admin", CredentialFor("setup-arm"), Transport("setup-arm")),
                new("update-cleanup-reader", CredentialFor("read-arm"), Transport("read-arm")),
                new(65536, TimeSpan.FromSeconds(20)));
            await using var source = Delete
                ? U.ForPrivateConnectionDeleteCleanup(Origin, Owner, "delete-restart", capability,
                    Host, parent, EndpointSource(), new(65536, 65536, TimeSpan.FromSeconds(20)))
                : U.ForPrivateConnectionUpdateCleanup(Origin, Owner, "update-restart", capability,
                    Host, parent, EndpointSource(), new(65536, 65536, TimeSpan.FromSeconds(20)));
            using var observer = new OwnedManagementObserver(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                new VaultForwarder(source.DispatchAsync));
            await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        }
        internal async Task<NativeCaseResult> RunOriginal()
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            AudienceToken Arm(string role) => new(role, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"), runtime = Runtime("runtime-secret"), denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"), observer = Runtime("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["VaultAdministration"] = new V.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-arm"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", Baseline, [new(Tenant, Principal, [SecretPermission.Get], null)],
                        Guid.Empty, 2, 32, TimeSpan.FromSeconds(20))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var member = V.Members.Single(m => m.Operation == Native.Selector.Operation);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, Native.Selector.Variant,
                "controlled", Native.Selector.Case), member.Member);
            var registry = new NativeCaseRegistry();
            V.Register(registry, environment, [definition], endpoint => new(endpoint,
                new VaultForwarder(async (request, token) =>
                {
                    if (request.RequestUri!.AbsolutePath == "/vault/prepare")
                        Native.Selector = JsonSerializer.Deserialize<V.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    return await Source.DispatchAsync(request, token);
                })), selectedTransport: new UpdateSdk(Source.SelectedTransport, this),
                privateConnectionUpdateSelectedInvocation: Delete ? null : Tap,
                privateConnectionDeleteSelectedInvocation: Delete ? Tap : null);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private bool IsFault(string value)
        {
            if (Fault != value) return false;
            FaultsReached++;
            return true;
        }
        private async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            bool arm = request.RequestUri.Host == "management.azure.com";
            bool network = path.Contains("/providers/Microsoft.Network/", StringComparison.Ordinal);
            bool child = path.Contains("/privateEndpointConnections", StringComparison.Ordinal);
            string? bearer = request.Headers.Authorization?.Parameter;
            if (Barrier == role && bearer is not null)
            {
                Entered.TrySetResult();
                await Resume.Task;
            }
            if (arm && (request.RequestUri.Query != (network ? "?api-version=2026-01-01" : "?api-version=2026-02-01") ||
                (role == "selected-arm" ? bearer is not ("selected-arm" or "denied-arm") : bearer != role)))
                throw new InvalidOperationException("original-update-arm-boundary");
            if (network || child)
            {
                Endpoint ??= new(Native) { AllowEndpointDelete = true };
                if (role == "selected-arm")
                {
                    if (request.Method == HttpMethod.Get) { SelectedGets++; throw new InvalidOperationException("no-selected-update-get"); }
                    if (Delete)
                    {
                        if (request.Method != HttpMethod.Delete || path != Endpoint.ConnectionId)
                            throw new InvalidOperationException("original-delete-selected-route");
                        SelectedDeletes++;
                        Prejournaled &= Native.Read().PrivateEndpoint!.Connection is { ActiveDispatch: var active } &&
                            active != Guid.Empty;
                        if (request.Content is not null && (await request.Content.ReadAsByteArrayAsync(token)).Length != 0)
                            throw new InvalidOperationException("original-delete-request-body");
                        if (bearer == "denied-arm")
                        {
                            if (IsFault("denial-child-change")) Endpoint.ConnectionState = "Approved";
                            if (IsFault("denial-parent-change")) Native.Wire.Vault!["properties"]!["softDeleteRetentionInDays"] = 7;
                            return Reply(403, IsFault("denial-malformed") ? "{" : """{"error":{"code":"Forbidden"}}""");
                        }
                        Endpoint.ConnectionPresent = false;
                        Endpoint.ConnectionState = "Disconnected";
                        if (IsFault("post-delete-child-present") || Fault == "post-child-endpoint")
                            Endpoint.ConnectionPresent = true;
                        if (DeleteResourceBody)
                        {
                            var deleted = Endpoint.ConnectionData();
                            deleted.Remove("location");
                            if (IsFault("delete-missing-id")) deleted.Remove("id");
                            if (IsFault("delete-foreign-id")) deleted["id"] = Endpoint.ConnectionId + "-foreign";
                            if (IsFault("delete-foreign-name")) deleted["name"] = "foreign";
                            if (IsFault("delete-foreign-type")) deleted["type"] = "Microsoft.KeyVault/vaults";
                            if (IsFault("delete-foreign-endpoint")) deleted["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                            foreach (string state in new[] { "Pending", "Approved", "Rejected" })
                                if (IsFault("delete-state-" + state))
                                    deleted["properties"]!["privateLinkServiceConnectionState"]!["status"] = state;
                            if (IsFault("delete-updating")) deleted["properties"]!["provisioningState"] = "Updating";
                            if (IsFault("delete-next-link")) deleted["nextLink"] = "https://management.azure.com/foreign";
                            if (IsFault("delete-partial")) deleted["partial"] = true;
                            if (IsFault("delete-error")) deleted["error"] = new JsonObject { ["code"] = "Forbidden" };
                            if (IsFault("delete-collection")) deleted["value"] = new JsonArray();
                            string payload = IsFault("delete-malformed") ? "{" : deleted.ToJsonString();
                            if (IsFault("delete-duplicate")) payload = payload[..^1] + ",\"id\":" + JsonSerializer.Serialize(Endpoint.ConnectionId) + "}";
                            var deletedResponse = Reply(IsFault("delete-status204") ? 204 : 200, payload);
                            if (IsFault("delete-charset")) deletedResponse.Content!.Headers.ContentType!.CharSet = "iso-8859-1";
                            if (IsFault("delete-length")) deletedResponse.Content!.Headers.ContentLength = Encoding.UTF8.GetByteCount(payload) + 1;
                            if (IsFault("delete-continuation")) deletedResponse.Headers.Add("Azure-AsyncOperation", "https://management.azure.com/foreign?api-version=2026-02-01");
                            if (IsFault("delete-retry")) deletedResponse.Headers.Add("Retry-After", "0");
                            if (IsFault("delete-encoding")) deletedResponse.Content!.Headers.ContentEncoding.Add("gzip");
                            if (IsFault("delete-content-range")) deletedResponse.Content!.Headers.Add("Content-Range", "bytes 0-1/100");
                            return deletedResponse;
                        }
                        return new HttpResponseMessage(HttpStatusCode.NoContent)
                        {
                            Content = new ByteArrayContent([]),
                            Headers = { { "x-ms-request-id", "original-private-delete" } }
                        };
                    }
                    if (request.Method != HttpMethod.Put || path != Endpoint.ConnectionId)
                        throw new InvalidOperationException("original-update-selected-route");
                    SelectedPuts++;
                    Prejournaled &= Native.Read().PrivateEndpoint!.Connection is { ActiveDispatch: var dispatch } &&
                        dispatch != Guid.Empty;
                    if (bearer == "denied-arm") return Reply(403, """{"error":{"code":"Forbidden"}}""");
                    SelectedBody = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
                    if (!IsFault("unchanged")) Endpoint.ConnectionState = Requested.ToString();
                    var row = Endpoint.ConnectionData();
                    row.Remove("location");
                    if (IsFault("selected-updating")) row["properties"]!["provisioningState"] = "Updating";
                    if (IsFault("selected-state")) row["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    if (IsFault("selected-endpoint")) row["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                    var response = Reply(IsFault("selected-accepted") ? 202 : IsFault("selected-created") ? 201 : 200,
                        IsFault("selected-malformed") ? "{" : row.ToJsonString());
                    if (IsFault("selected-continuation"))
                        response.Headers.Add("Azure-AsyncOperation", "https://management.azure.com/foreign?api-version=2026-02-01");
                    return response;
                }
                if (Delete && SelectedDeletes > 0 && path == Endpoint.ConnectionId && request.Method == HttpMethod.Get)
                {
                    if (IsFault("post-delete-child204")) return new HttpResponseMessage(HttpStatusCode.NoContent);
                    if (IsFault("post-delete-child404-malformed")) return Reply(404, "{");
                    if (IsFault("post-delete-child404-forbidden")) return Reply(404, """{"error":{"code":"Forbidden"}}""");
                }
                var native = await Endpoint.Respond(request, token);
                if (native.StatusCode == HttpStatusCode.OK && request.Method == HttpMethod.Get && path == Endpoint.Binding.EndpointId)
                {
                    var row = JsonNode.Parse(await native.Content!.ReadAsByteArrayAsync(token))!;
                    row["properties"]!["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceConnectionState"]!["status"] =
                        SelectedPuts + SelectedDeletes > 0 ? Endpoint.ConnectionState : "Pending";
                    if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-endpoint-state"))
                        row["properties"]!["manualPrivateLinkServiceConnections"]![0]!["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-endpoint-subnet"))
                        row["properties"]!["subnet"]!["id"] = Endpoint.Binding.SubnetId + "-foreign";
                    native.Dispose();
                    return Reply(200, row.ToJsonString());
                }
                if (native.StatusCode == HttpStatusCode.OK && path == Endpoint.ConnectionId)
                {
                    var row = Endpoint.ConnectionData();
                    row.Remove("location");
                    if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-child-state"))
                        row["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-child-endpoint"))
                        row["properties"]!["privateEndpoint"]!["id"] = Endpoint.Binding.EndpointId + "-foreign";
                    native.Dispose();
                    return Reply(200, row.ToJsonString());
                }
                return native;
            }
            if (role is "private-runtime-secret" or "public-runtime-secret")
            {
                if (request.Headers.Authorization is null)
                {
                    var challenge = Reply(401, "{}");
                    challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                        $"Bearer authorization=\"https://login.microsoftonline.com/{Tenant:D}\", resource=\"https://vault.azure.net\"");
                    return challenge;
                }
                if (request.Method != HttpMethod.Get || bearer != role ||
                    request.RequestUri.Host != Native.Wire.VaultName + ".vault.azure.net" ||
                    path != "/secrets/canary/" + Version || request.RequestUri.Query != "?api-version=2025-07-01")
                    throw new InvalidOperationException("original-update-runtime-boundary");
                bool privateRead = role == "private-runtime-secret";
                if (privateRead) PrivateReads++; else PublicReads++;
                string lane = privateRead ? "private" : "public";
                bool after = SelectedPuts + SelectedDeletes > 0;
                if (privateRead && Endpoint?.ConnectionState != "Approved" && !(after && IsFault("private-success")) ||
                    after && IsFault(lane + "-denied"))
                    return Reply(403, """{"error":{"code":"Forbidden"}}""");
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = $"https://{Native.Wire.VaultName}.vault.azure.net/secrets/canary/{(after && IsFault(lane + "-version") ? new string('b', 32) : Version)}",
                    value = after && IsFault(lane + "-digest") ? "foreign-controlled-material" : Native.Wire.Secret,
                    attributes = new { enabled = true }
                }));
            }
            if (role == "setup-arm")
            {
                if (request.Method == HttpMethod.Put) SetupPuts++;
                if (request.Method == HttpMethod.Delete) ParentDeletes++;
                if (request.Method == HttpMethod.Post) ParentPurges++;
            }
            if (role == "setup-secret" && request.Method == HttpMethod.Put) CanarySets++;
            if (role == "read-secret" && SelectedDeletes > 0 && request.Method == HttpMethod.Get && bearer is not null &&
                Fault is "canary-digest" or "canary-version")
            {
                bool wrongVersion = IsFault("canary-version");
                bool wrongDigest = IsFault("canary-digest");
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = $"https://{Native.Wire.VaultName}.vault.azure.net/secrets/canary/{(wrongVersion ? new string('b', 32) : Version)}",
                    value = wrongDigest ? "foreign-controlled-material" : Native.Wire.Secret,
                    attributes = new { enabled = true }
                }));
            }
            if (arm && request.Method == HttpMethod.Get && path.Contains("/deletedVaults/", StringComparison.Ordinal) && Native.Wire.Deleted)
                return Reply(200, JsonSerializer.Serialize(new
                {
                    id = path, name = Native.Wire.VaultName, type = "Microsoft.KeyVault/locations/deletedVaults",
                    properties = new
                    {
                        vaultId = Native.Wire.VaultId, location = "eastus", tags = Native.Wire.Vault!["tags"],
                        purgeProtectionEnabled = Baseline.PurgeProtection,
                        deletionDate = "2026-10-16T00:00:00Z", scheduledPurgeDate = "2026-11-08T00:00:00Z"
                    }
                }));
            if (role == "read-arm" && request.Method == HttpMethod.Get && path == Native.Wire.VaultId && Native.Wire.Active)
            {
                var row = Native.Wire.Vault!.DeepClone();
                if (Endpoint?.EndpointExists == true)
                {
                    var connection = Endpoint.ConnectionData();
                    connection.Remove("location");
                    connection.Remove("name");
                    connection.Remove("type");
                    row["properties"]!["privateEndpointConnections"] =
                        Endpoint.ConnectionPresent ?? Endpoint.EndpointExists ? new JsonArray(connection) : new JsonArray();
                }
                if (SelectedDeletes > 0 && IsFault("post-delete-parent-child-present"))
                {
                    var retained = Endpoint!.ConnectionData();
                    retained.Remove("location");
                    retained.Remove("name");
                    retained.Remove("type");
                    retained["properties"]!["privateLinkServiceConnectionState"]!["status"] = "Pending";
                    row["properties"]!["privateEndpointConnections"] = new JsonArray(retained);
                }
                if (SelectedDeletes > 0 && Fault == "post-child-endpoint") row["properties"]!.AsObject().Remove("privateEndpointConnections");
                if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-parent-owner")) row["tags"]!["secretkit-fixture"] = "foreign";
                if (SelectedPuts + SelectedDeletes > 0 && IsFault("post-parent-configuration")) row["properties"]!["softDeleteRetentionInDays"] = 7;
                return Reply(200, row.ToJsonString());
            }
            return await Native.Wire.Respond(request, role, token);
        }
        private static HttpResponseMessage Reply(int status, string payload) => new((HttpStatusCode)status)
        {
            Content = new StringContent(payload, Encoding.UTF8, "application/json"),
            Headers = { { "x-ms-request-id", "original-private-update-" + Guid.NewGuid().ToString("N") } }
        };
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            UnlockJournal();
            try { await Source.DisposeAsync(); }
            finally
            {
                UnlockJournal();
                try { await Parent.DisposeAsync(); }
                finally
                {
                    Observer.Dispose();
                    Endpoint?.Dispose();
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    Native.Dispose();
                }
            }
        }
        internal void UnlockJournal() { JournalLock?.Dispose(); JournalLock = null; }
        private sealed class UpdateSdk(HttpPipelineTransport inner, OriginalPrivateUpdateFixture fixture) : HttpPipelineTransport
        {
            public override Request CreateRequest() => inner.CreateRequest();
            public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
            public override async ValueTask ProcessAsync(HttpMessage message)
            {
                await inner.ProcessAsync(message);
                if (!fixture.ReplaceResponse) return;
                fixture.Replacements++;
                var headers = message.Response.Headers.ToArray();
                int status = message.Response.Status;
                var row = fixture.Endpoint!.ConnectionData();
                row.Remove("location");
                if (fixture.DisposeOriginal) message.Response.Dispose();
                message.Response = new UpdateIndependentResponse(status, row.ToJsonString(), headers);
            }
        }
        private sealed class UpdateIndependentResponse(int status, string body, HttpHeader[] headers) : Response
        {
            public override int Status => status;
            public override string ReasonPhrase => "Controlled";
            public override string ClientRequestId { get; set; } = "independent";
            public override Stream? ContentStream { get; set; } = new MemoryStream(Encoding.UTF8.GetBytes(body));
            public override void Dispose() => ContentStream?.Dispose();
            protected override bool ContainsHeader(string name) => headers.Any(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value)
            {
                value = headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
                return value is not null;
            }
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values)
            {
                bool found = TryGetHeader(name, out var value);
                values = found ? [value!] : null;
                return found;
            }
        }
        private sealed class UpdateBackend(HttpPipelineTransport inner, OriginalPrivateUpdateFixture fixture) : HttpPipelineTransport
        {
            public override Request CreateRequest() => inner.CreateRequest();
            public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
            public override async ValueTask ProcessAsync(HttpMessage message)
            {
                await inner.ProcessAsync(message);
                if (message.Request.Method == (fixture.Delete ? RequestMethod.Delete : RequestMethod.Put) && fixture.LockOnFinalization)
                    message.Response = new UpdateFinalizeResponse(message.Response, fixture);
            }
        }
        private sealed class UpdateFinalizeResponse(Response original, OriginalPrivateUpdateFixture fixture) : Response
        {
            public override int Status => original.Status;
            public override string ReasonPhrase => original.ReasonPhrase;
            public override string ClientRequestId { get => original.ClientRequestId; set => original.ClientRequestId = value; }
            public override Stream? ContentStream { get => original.ContentStream; set => original.ContentStream = value; }
            public override void Dispose()
            {
                original.Dispose();
                if (!fixture.LockOnFinalization) return;
                fixture.LockOnFinalization = false;
                fixture.JournalLock = new FileStream(fixture.Native.JournalPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
            }
            protected override bool ContainsHeader(string name) => original.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => original.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                original.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                original.Headers.TryGetValues(name, out values);
        }
        private sealed class UpdateCredential(string role, Action? onToken = null) : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("async-only");
            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                string audience = role.EndsWith("-secret", StringComparison.Ordinal) ?
                    "https://vault.azure.net/.default" : "https://management.azure.com/.default";
                if (context.Scopes.Length != 1 || context.Scopes[0] != audience)
                    throw new InvalidOperationException("original-update-audience");
                onToken?.Invoke();
                return ValueTask.FromResult(new AccessToken(role, DateTimeOffset.MaxValue));
            }
        }
        internal sealed class UpdateTap(U source) : V.PrivateConnectionUpdateSelectedInvocation,
            V.PrivateConnectionDeleteSelectedInvocation
        {
            internal ManagementReceipt? Receipt;
            internal int Completions;
            internal SecretStatus? DeleteStart, DeleteCompletion;
            internal ManagementOperation? DeleteHandle;
            public ValueTask<SecretOutcome<ManagementOperation>> RunUpdatePrivateConnectionAsync(FixtureSelector selector,
                VaultAdministration client, PrivateConnectionScope scope, PrivateConnectionState state, ManagementReceipt receipt,
                CancellationToken cancellationToken)
            {
                Receipt = receipt;
                return source.RunUpdatePrivateConnectionAsync(selector, client, scope, state, receipt, cancellationToken);
            }
            public ValueTask<SecretStatus> CompleteUpdatePrivateConnectionAsync(FixtureSelector selector,
                ManagementOperation originalHandle, CancellationToken cancellationToken)
            {
                Completions++;
                return source.CompleteUpdatePrivateConnectionAsync(selector, originalHandle, cancellationToken);
            }
            public async ValueTask<SecretOutcome<ManagementOperation>> RunDeletePrivateConnectionAsync(FixtureSelector selector,
                VaultAdministration client, PrivateConnectionScope scope, ManagementReceipt receipt, CancellationToken cancellationToken)
            {
                Receipt = receipt;
                var result = await source.RunDeletePrivateConnectionAsync(selector, client, scope, receipt, cancellationToken);
                DeleteStart = result.Status;
                DeleteHandle = result.IsSuccess ? result.Value : null;
                return result;
            }
            public async ValueTask<SecretStatus> CompleteDeletePrivateConnectionAsync(FixtureSelector selector,
                ManagementOperation originalHandle, CancellationToken cancellationToken)
            {
                Completions++;
                var result = await source.CompleteDeletePrivateConnectionAsync(selector, originalHandle, cancellationToken);
                DeleteCompletion = result;
                return result;
            }
        }
    }
}
