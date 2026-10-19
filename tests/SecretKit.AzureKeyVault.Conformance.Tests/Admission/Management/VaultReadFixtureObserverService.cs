using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using E = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using Endpoint = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using N = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultNetworkReadCollector;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultFixtureProvisioner;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Local source composition, not live qualification. Only original vault read
// invocations are admitted; the host retains all clients and native authorities.
internal sealed class VaultReadFixtureObserverService : E.ReadSelectedInvocation, IAsyncDisposable
{
    internal sealed record Limits(int MaximumRequestBytes, int MaximumBodyBytes, TimeSpan Timeout);
    internal sealed record PrivateConnectionReadSource(
        [property: JsonIgnore] string BorrowedSubnetId,
        [property: JsonIgnore] R.Authority EndpointSetup,
        [property: JsonIgnore] R.Authority EndpointReader,
        [property: JsonIgnore] M.Authority VaultConnectionReader,
        [property: JsonIgnore] R.Limits ResourceLimits,
        [property: JsonIgnore] M.Limits InventoryLimits,
        [property: JsonIgnore] N.Authority PrivateRuntime,
        [property: JsonIgnore] N.Authority PublicRuntime,
        [property: JsonIgnore] N.Limits NetworkLimits)
    {
        public override string ToString() => "[PrivateConnectionReadSource]";
    }
    private static readonly JsonSerializerOptions Json = new(ManagementAdmission.Json)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    private readonly object gate = new();
    private readonly Uri origin;
    private readonly string owner, observerIdentity;
    private readonly SecretMaterial capability;
    private readonly P.HostScope host;
    private readonly P provisioner;
    private readonly E.Configuration baseline;
    private readonly M metadata;
    private readonly M.Limits collectorLimits;
    private readonly string metadataIdentity;
    private readonly HttpPipelineTransport selectedBackend;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly PrivateConnectionReadSource? privateConnectionSource;
    private readonly Dictionary<Guid, Session> sessions = [];
    private readonly AsyncLocal<SelectedCall?> selected = new();
    private readonly AsyncLocal<P.VaultReadLoan?> observation = new();
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = Signal();
    private TaskCompletionSource? disposal;
    private int active;
    private bool disposed;
    private RoleFixtureJournal Journal => provisioner.Journal;

    private sealed class Session(FixtureSelector selector)
    {
        internal readonly FixtureSelector Selector = selector;
        internal readonly CancellationTokenSource Stop = new();
        internal P.Plan? Plan;
        internal E.Lease? Lease;
        internal M.Binding? Binding;
        internal SelectedCall? Selected;
        internal E.DeletedVaultRow? DeletedBaseline;
        internal E.DeletedVaultRow? RawDeletedCollection;
        internal bool? NameBaseline;
        internal E.Configuration? NameConfiguration;
        internal VaultGroupRow? RawGroup, GroupBaseline;
        internal string? RawGroupRequestId;
        internal M.Window? GroupWindow;
        internal Request? GroupRequest;
        internal int GroupSends;
        internal PrivateEndpointFixtureProvisioner? Endpoints;
        internal PrivateEndpointFixtureProvisioner.Plan? EndpointPlan;
        internal P.PrivateConnectionReadAdmission? PrivateAdmission;
        internal string? ConnectionId;
        internal M.ConnectionRow? RawConnection, ConnectionBaseline;
        internal string? RawConnectionRequestId;
        internal E.Measurement? PrivateBaseline;
        internal M.Measurement? ConnectionBefore, ConnectionAfter;
        internal M.Binding? ChildBinding;
        internal M.PrivateLinkRow? RawLink, LinkBaseline;
        internal string? RawLinkRequestId;
        internal M.Measurement? LinkBefore, LinkAfter;
        internal Endpoint.Measurement? EndpointBefore, EndpointAfter;
        internal N.Measurement? NetworkBefore, NetworkAfter;
        internal readonly List<byte[]> ObservationBuffers = [];
        internal readonly List<IDisposable> ObservationStorage = [];
        internal Guid Subscription;
        internal DateTimeOffset ArmedAt, BaselineAt;
        internal bool Armed, BeforeClaimed, BaselineReady, AfterClaimed, Closed, Releasing;
        internal int Active;
        internal TaskCompletionSource Drained = Signal();
    }

    private sealed class SelectedCall(Session session, VaultAdministration client, ManagementScope scope,
        P.VaultReadLoan loan)
    {
        internal readonly Session Session = session;
        internal readonly VaultAdministration Client = client;
        internal readonly ManagementScope Scope = scope;
        internal readonly P.VaultReadLoan Loan = loan;
        internal Request? Request;
        internal Task<SecretOutcome<VaultObservation>>? OriginalTask;
        internal Task<SecretOutcome<DeletedVaultObservation>>? OriginalDeletedTask;
        internal Task<ManagementInventory<DeletedVaultObservation>>? OriginalDeletedVaultsTask;
        internal ManagementInventory<DeletedVaultObservation>? OriginalDeletedVaults;
        internal Task<SecretOutcome<VaultNameAvailability>>? OriginalNameTask;
        internal Task<SecretOutcome<PrivateConnectionObservation>>? OriginalConnectionTask;
        internal PrivateConnectionObservation? OriginalConnectionObservation;
        internal Task<ManagementInventory<PrivateConnectionObservation>>? OriginalConnectionsTask;
        internal ManagementInventory<PrivateConnectionObservation>? OriginalConnections;
        internal Task<ManagementInventory<PrivateLinkObservation>>? OriginalLinksTask;
        internal ManagementInventory<PrivateLinkObservation>? OriginalLinks;
        internal Task<ManagementInventory<VaultObservation>>? OriginalVaultsTask;
        internal ManagementInventory<VaultObservation>? OriginalVaults;
        internal VaultGroupRow? RawGroup;
        internal M.PrivateLinkRow? RawLink;
        internal CollectionLimits? OriginalCollectionLimits;
        internal M.ConnectionRow? RawConnection;
        internal VaultNameAvailability? OriginalNameObservation;
        internal string? VaultName;
        internal bool? RawNameAvailable;
        internal DeletedVaultObservation? OriginalDeletedObservation;
        internal E.DeletedVaultRow? RawDeleted;
        internal Task? SendTask;
        internal int Sends;
        internal bool Attempted, ValidReply, Terminated, Finalized;
        internal int? NativeStatus;
        internal string? NativeRequestId;
        internal readonly List<byte[]> Buffers = [];
        internal readonly List<IDisposable> Storage = [];
        internal void Clear()
        {
            bool failed = false;
            foreach (var item in Storage)
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            Storage.Clear();
            foreach (var bytes in Buffers) CryptographicOperations.ZeroMemory(bytes);
            Buffers.Clear();
            Require(!failed);
        }
        public override string ToString() => "[VaultOriginalRead]";
    }

    private sealed record VaultGroupRow(E.VaultRow Row, E.Configuration Configuration, string VaultUri,
        string? CreateMode)
    {
        public override string ToString() => "[VaultGroupRow]";
    }

    internal VaultReadFixtureObserverService(Uri origin, string owner, string observerIdentity,
        SecretMaterial capability, P.HostScope host, P provisioner, M.Authority observer,
        HttpPipelineTransport selectedBackend, M.Limits collectorLimits, Limits limits, TimeProvider? time = null,
        PrivateConnectionReadSource? privateConnectionSource = null)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } && Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            host is not null && host.ExclusiveFixtureNamespace && host.AllowPurge &&
            provisioner is not null && observer is not null && Text(observer.Label, 128) &&
            observer.Credential is not null && observer.Transport is not null && selectedBackend is not null &&
            limits is not null && limits.MaximumRequestBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        baseline = provisioner.VaultReadBaseline(host, observer, selectedBackend);
        Require(!baseline.PurgeProtection);
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.host = host;
        this.provisioner = provisioner;
        this.selectedBackend = selectedBackend;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
        this.privateConnectionSource = privateConnectionSource;
        this.collectorLimits = collectorLimits;
        metadataIdentity = observer.Label;
        metadata = new(observer with { Transport = new ObservationTransport(this, observer.Transport) },
            collectorLimits, this.time);
        SelectedTransport = new OriginalTransport(this);
    }

    internal HttpPipelineTransport SelectedTransport { get; }

    internal async Task<HttpResponseMessage> DispatchAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!Authenticate(request)) return Error(HttpStatusCode.Unauthorized);
        if (request.Method != HttpMethod.Post || request.RequestUri is not { IsAbsoluteUri: true } uri ||
            uri.Scheme != "https" || uri.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return Error(HttpStatusCode.BadRequest);
        lock (gate)
        {
            if (disposed) return Error(HttpStatusCode.ServiceUnavailable);
            active++;
        }
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, deadline.Token);
            using var body = await ReadBody(request, linked.Token).ConfigureAwait(false);
            return uri.AbsolutePath switch
            {
                "/vault/prepare" => await Prepare(body.RootElement.Deserialize<E.Prepare>(Json) ?? throw Failure(),
                    linked.Token).ConfigureAwait(false),
                "/vault/arm" => Arm(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure()),
                "/vault/observe" => await Observe(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure(),
                    linked.Token).ConfigureAwait(false),
                "/vault/release" => await Release(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(),
                    linked.Token).ConfigureAwait(false),
                _ => Error(HttpStatusCode.NotFound)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return Error(HttpStatusCode.ServiceUnavailable); }
        finally { EndRequest(); }
    }

    private async Task<HttpResponseMessage> Prepare(E.Prepare input, CancellationToken token)
    {
        ValidateSelector(input.Selection);
        if (IsPrivate(input.Selection))
        {
            Require(privateConnectionSource is not null && baseline.PublicNetworkAccess && !baseline.PurgeProtection);
            _ = provisioner.VaultReadBaseline(host, privateConnectionSource.VaultConnectionReader, selectedBackend);
            _ = new N(privateConnectionSource.PrivateRuntime, privateConnectionSource.PublicRuntime,
                privateConnectionSource.NetworkLimits, time);
        }
        var configuration = Snapshot(input.Configuration);
        Require(input.SubscriptionId == host.SubscriptionId && input.ResourceGroup == host.ResourceGroup &&
            E.SameConfiguration(configuration, baseline) && input.IntendedPolicies is { Length: >= 1 and <= 16 } &&
            input.IntendedPolicies.All(p => p is not null && p.Permissions is not null));
        foreach (var policy in input.IntendedPolicies) _ = policy.Build();
        Session session;
        lock (gate)
        {
            Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection);
            Enter(session);
            sessions.Add(input.Selection.Nonce, session);
        }
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            if (IsPrivate(session.Selector))
            {
                var source = privateConnectionSource!;
                session.Endpoints = new(provisioner, source.EndpointSetup, source.EndpointReader,
                    source.VaultConnectionReader, source.ResourceLimits, source.InventoryLimits, time);
            }
            lock (gate)
            {
                // Registration precedes setup, including a lost prepare response.
                Require(!disposed && !session.Closed);
                session.Plan = provisioner.PlanFixture(owner, session.Selector,
                    IsDeleted(session.Selector) ? P.Preparation.Deleted : P.Preparation.Active, [],
                    seedCanary: IsPrivate(session.Selector),
                    privateEndpoint: IsPrivate(session.Selector) ? new(privateConnectionSource!.BorrowedSubnetId) : null);
            }
            P.Result prepared;
            if (IsPrivate(session.Selector))
            {
                byte[] entropy = RandomNumberGenerator.GetBytes(32);
                try
                {
                    using var canary = SecretMaterial.FromText(Convert.ToHexString(entropy));
                    prepared = await provisioner.ProvisionAsync(session.Plan, canary, linked.Token).ConfigureAwait(false);
                }
                finally { CryptographicOperations.ZeroMemory(entropy); }
            }
            else prepared = await provisioner.ProvisionAsync(session.Plan, cancellationToken: linked.Token).ConfigureAwait(false);
            if (IsDeleted(session.Selector))
                Require(prepared.State == P.State.Ready && prepared.VaultPresent == false &&
                    prepared.DeletedVaultPresent == true && prepared.Configuration is null && prepared.DeletedVault is not null);
            else
                Require(prepared.State == P.State.Ready && prepared.VaultPresent == true &&
                    prepared.DeletedVaultPresent == false && prepared.Configuration is not null &&
                    E.SameConfiguration(prepared.Configuration, baseline));
            if (IsPrivate(session.Selector))
            {
                Require(prepared.CanaryPresent == true && prepared.CanarySha256 is not null &&
                    prepared.CanaryVersion is not null);
                session.EndpointPlan = session.Endpoints!.PlanDeclaredEndpoint(session.Plan);
                var endpoint = await session.Endpoints.ProvisionAsync(session.EndpointPlan, linked.Token).ConfigureAwait(false);
                Require(endpoint.State == PrivateEndpointFixtureProvisioner.State.Ready && endpoint.ConnectionId is not null &&
                    session.Endpoints.OwnsBoundPlan(session.EndpointPlan, session.Plan, endpoint.ConnectionId));
                session.ConnectionId = endpoint.ConnectionId;
                session.PrivateAdmission = provisioner.RegisterPrivateConnectionRead(session.Plan, session.Endpoints,
                    session.EndpointPlan, session.ConnectionId);
            }
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed && OwnsPrepared(session));
                var snapshot = Journal.Read(owner, session.Selector);
                Require(Root(snapshot, session));
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    M.ArmOrigin, M.Revision, time.GetUtcNow(), IsPrivate(session.Selector)
                        ? PrivateOwnedResources(snapshot) : snapshot.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, session.ConnectionId?.Split('/')[^1], P.Canary,
                    prepared.CanarySha256 ?? "", Snapshot(baseline),
                    IsPrivate(session.Selector) ? PrivateConnectionState.Pending : PrivateConnectionState.Unknown)
                {
                    BaselineVaultStatus = IsDeleted(session.Selector) ? SecretStatus.Absent : SecretStatus.Success,
                    BaselineDeletedVaultStatus = IsDeleted(session.Selector) ? SecretStatus.Success : SecretStatus.Absent,
                    BaselineConnectionStatus = IsPrivate(session.Selector) ? SecretStatus.Success : SecretStatus.Unknown
                };
                return Reply(session.Lease);
            }
        }
        finally { Leave(session); }
    }

    private HttpResponseMessage Arm(ObserveLease input)
    {
        lock (gate)
        {
            var session = Find(input.Nonce, input.LeaseId);
            Require(session.Active == 0 && !session.Armed && input.SubscriptionId is null &&
                input.Phase == "subscribe-before-trigger" && OwnsPrepared(session));
            session.Binding = new(session.Selector, session.Plan!.LeaseId,
                IsDeletedList(session.Selector) ? M.QueryKind.ListDeletedVaults :
                IsVaultSubscriptionList(session.Selector) ? M.QueryKind.ListVaultsSubscription :
                IsVaultGroupList(session.Selector) ? M.QueryKind.ListVaultsResourceGroup :
                IsPrivateLinkList(session.Selector) ? M.QueryKind.ListPrivateLinkResources :
                IsPrivateList(session.Selector) ? M.QueryKind.ListPrivateConnections :
                IsPrivate(session.Selector) ? M.QueryKind.GetPrivateConnection :
                IsName(session.Selector) ? M.QueryKind.CheckNameAvailability :
                    IsDeleted(session.Selector) ? M.QueryKind.GetDeletedVault : M.QueryKind.GetVault,
                IsDeletedList(session.Selector) ? M.ReadKind.ListDeletedVaults :
                IsVaultSubscriptionList(session.Selector) ? M.ReadKind.ListVaultsSubscription :
                IsVaultGroupList(session.Selector) ? M.ReadKind.ListVaultsGroup :
                IsPrivateLinkList(session.Selector) ? M.ReadKind.ListPrivateLinkResources :
                IsPrivateList(session.Selector) ? M.ReadKind.ListPrivateConnections :
                IsPrivate(session.Selector) ? M.ReadKind.GetPrivateConnection :
                IsName(session.Selector) ? M.ReadKind.CheckNameAvailability :
                    IsDeleted(session.Selector) ? M.ReadKind.GetDeletedVault : M.ReadKind.GetVault,
                host.SubscriptionId, host.ResourceGroup, host.Location, session.Plan.VaultName,
                session.ConnectionId?.Split('/')[^1]);
            if (IsPrivateLinkList(session.Selector))
                session.ChildBinding = session.Binding with
                {
                    Selector = session.Selector with
                    {
                        Operation = M.Operation(M.QueryKind.GetPrivateConnection),
                        Variant = "selector.exact"
                    },
                    Query = M.QueryKind.GetPrivateConnection,
                    Read = M.ReadKind.GetPrivateConnection
                };
            session.Subscription = Guid.NewGuid();
            session.ArmedAt = time.GetUtcNow();
            session.Armed = true;
            return Reply(new ObservationSubscription(session.Plan.LeaseId, session.Selector.Nonce,
                session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> Observe(ObserveLease input, CancellationToken token)
    {
        Session session;
        P.VaultReadLoan loan;
        M.Window window;
        bool before = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Active == 0 && session.Armed && input.SubscriptionId == session.Subscription);
            if (before) Require(!session.BeforeClaimed && session.Selected is null);
            else Require(input.Phase == "post-operation" && session.BaselineReady && !session.AfterClaimed &&
                session.Selected is { Terminated: true, Finalized: true, Attempted: true, Sends: 1, Request: not null });
            P.VaultReadLoan? admitted;
            Require(IsPrivate(session.Selector)
                ? provisioner.TryEnterPrivateConnectionRead(session.Plan!, session.PrivateAdmission!, out admitted)
                : IsVaultGroupList(session.Selector)
                ? provisioner.TryEnterVaultGroupListRead(session.Plan!, out admitted)
                : IsVaultSubscriptionList(session.Selector)
                ? provisioner.TryEnterVaultSubscriptionListRead(session.Plan!, out admitted)
                : IsName(session.Selector)
                ? provisioner.TryEnterVaultNameRead(session.Plan!, out admitted)
                : IsDeletedList(session.Selector)
                ? provisioner.TryEnterDeletedVaultListRead(session.Plan!, out admitted)
                : IsDeleted(session.Selector)
                ? provisioner.TryEnterDeletedVaultRead(session.Plan!, out admitted)
                : provisioner.TryEnterVaultRead(session.Plan!, out admitted));
            Require(admitted is not null);
            loan = admitted;
            Enter(session);
            if (before) session.BeforeClaimed = true;
            else session.AfterClaimed = true;
        }
        var previous = observation.Value;
        try
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
            observation.Value = loan;
            if (IsPrivate(session.Selector))
                return await ObservePrivateConnection(session, loan, before, linked.Token).ConfigureAwait(false);
            window = metadata.Arm(session.Binding!);
            if (IsVaultGroupList(session.Selector) || IsVaultSubscriptionList(session.Selector) ||
                IsDeletedList(session.Selector))
            {
                session.GroupWindow = window;
                session.GroupRequest = null;
                session.GroupSends = 0;
                session.RawGroup = null;
                session.RawDeletedCollection = null;
                session.RawGroupRequestId = null;
            }
            var measured = await metadata.CollectAsync(window, session.Binding!, linked.Token).ConfigureAwait(false);
            // The parent observation uses THIS loan, not ObserveAsync (which must
            // keep rejecting a busy plan). Both actual tasks remain inside it.
            var prepared = await provisioner.ObserveVaultReadAsync(loan, linked.Token).ConfigureAwait(false);
            if (IsVaultGroupList(session.Selector) || IsVaultSubscriptionList(session.Selector))
                return ObserveVaultGroup(session, loan, window, measured, prepared, before, linked.Token);
            if (IsName(session.Selector))
            {
                Require(measured.Binding == session.Binding && measured.WindowId == window.Id &&
                    measured.ArmedAt == window.ArmedAt && measured.ResponseComplete &&
                    measured.Status == SecretStatus.Success && measured.NativeRequestIds.Count == 1 &&
                    measured.NameAvailable == false && measured.Vaults.Count == 0 &&
                    measured.DeletedVaults.Count == 0 && measured.Connections.Count == 0 &&
                    measured.PrivateLinks.Count == 0 && measured.StartedAt >= window.ArmedAt &&
                    window.ArmedAt >= session.ArmedAt && measured.FinishedAt >= measured.StartedAt &&
                    prepared.State == P.State.Ready && prepared.VaultPresent == true &&
                    prepared.DeletedVaultPresent == false && prepared.Configuration is not null &&
                    prepared.DeletedVault is null && E.SameConfiguration(prepared.Configuration, baseline));
                var nameConfiguration = Snapshot(prepared.Configuration);
                lock (gate)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.CheckVaultRead(loan);
                    var observedAt = time.GetUtcNow();
                    Require(observedAt >= measured.FinishedAt && (before || observedAt >= session.BaselineAt));
                    if (before)
                    {
                        session.NameBaseline = measured.NameAvailable;
                        session.NameConfiguration = nameConfiguration;
                        session.BaselineAt = observedAt;
                        session.BaselineReady = true;
                    }
                    else
                    {
                        Require(measured.NameAvailable == session.NameBaseline &&
                            session.NameConfiguration is not null &&
                            E.SameConfiguration(nameConfiguration, session.NameConfiguration));
                        if (session.Selected!.RawNameAvailable is { } raw) Require(measured.NameAvailable == raw);
                        if (session.Selected.OriginalNameObservation is { } original)
                            Require(original.Available == measured.NameAvailable);
                    }
                    return Reply(new E.Measurement(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity,
                        observedAt, session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, nameConfiguration,
                        nameConfiguration.Policies, PrivateConnectionState.Unknown, SecretStatus.Unknown, [], null,
                        [], [], [], [], measured.NameAvailable));
                }
            }
            if (IsDeleted(session.Selector))
            {
                Require(measured.Binding == session.Binding && measured.WindowId == window.Id &&
                    measured.ArmedAt == window.ArmedAt && measured.ResponseComplete &&
                    measured.Status == SecretStatus.Success && measured.NativeRequestIds.Count == 1 &&
                    measured.DeletedVaults.Count == 1 && measured.Vaults.Count == 0 &&
                    measured.Connections.Count == 0 && measured.PrivateLinks.Count == 0 && measured.NameAvailable is null &&
                    measured.StartedAt >= window.ArmedAt && window.ArmedAt >= session.ArmedAt &&
                    measured.FinishedAt >= measured.StartedAt && prepared.State == P.State.Ready &&
                    prepared.VaultPresent == false && prepared.DeletedVaultPresent == true &&
                    prepared.Configuration is null && prepared.DeletedVault is not null);
                if (IsDeletedList(session.Selector))
                    Require(ReferenceEquals(measured.Binding, session.Binding) &&
                        measured.Identity == metadataIdentity && measured.ApiRevision == M.Revision &&
                        measured.Failure == M.Failure.None && measured.InventoryComplete &&
                        session.GroupRequest is not null && session.GroupSends == 1 &&
                        session.GroupWindow is not null && ReferenceEquals(session.GroupWindow, window) &&
                        measured.NativeRequestIds.Single() == session.RawGroupRequestId &&
                        session.RawDeletedCollection is not null);
                var nativeDeleted = measured.DeletedVaults[0];
                var row = new E.DeletedVaultRow(nativeDeleted.SubscriptionId, nativeDeleted.Location, nativeDeleted.Name,
                    nativeDeleted.DeletedOn, nativeDeleted.ScheduledPurgeOn, nativeDeleted.PurgeProtected);
                Require(row == prepared.DeletedVault && row.SubscriptionId == host.SubscriptionId &&
                    row.Location == host.Location && row.Name == session.Plan!.VaultName &&
                    row.DeletedOn is not null && row.ScheduledPurgeOn - row.DeletedOn == TimeSpan.FromDays(baseline.RetentionDays) &&
                    row.PurgeProtected == false);
                if (IsDeletedList(session.Selector)) Require(row == session.RawDeletedCollection);
                lock (gate)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    Require(!disposed && !session.Closed);
                    provisioner.CheckVaultRead(loan);
                    var observedAt = time.GetUtcNow();
                    Require(observedAt >= measured.FinishedAt && (before || observedAt >= session.BaselineAt));
                    if (before)
                    {
                        if (IsDeletedList(session.Selector)) Require(session.DeletedBaseline is null);
                        session.DeletedBaseline = row;
                        session.BaselineAt = observedAt;
                        session.BaselineReady = true;
                    }
                    else
                    {
                        Require(row == session.DeletedBaseline);
                        if (session.Selected!.RawDeleted is { } raw) Require(row == raw);
                        if (session.Selected.OriginalDeletedObservation is { } original)
                            Require(SameDeleted(original, row) &&
                                ReferenceEquals(original.Scope, session.Selected.Scope));
                        if (session.Selected.OriginalDeletedVaults is { Status: SecretStatus.Success } inventory)
                        {
                            Require(IsDeletedList(session.Selector) && inventory.Complete && inventory.Items.Count == 1 &&
                                session.Selected.Scope is SubscriptionScope);
                            MatchDeletedSubscriptionItem(inventory.Items.Single(),
                                (SubscriptionScope)session.Selected.Scope, row);
                        }
                    }
                    return Reply(new E.Measurement(session.Plan!.LeaseId, session.Selector.Nonce, observerIdentity,
                        observedAt, session.Plan.VaultId, SecretStatus.Absent, SecretStatus.Success, null, [],
                        PrivateConnectionState.Unknown, SecretStatus.Unknown, [], null, [], [row], [], [], null));
                }
            }
            Require(measured.Binding == session.Binding && measured.WindowId == window.Id &&
                measured.ResponseComplete && measured.Status == SecretStatus.Success &&
                measured.NativeRequestIds.Count == 1 && measured.Vaults.Count == 1 &&
                measured.StartedAt >= session.ArmedAt && measured.FinishedAt >= measured.StartedAt &&
                prepared.State == P.State.Ready && prepared.VaultPresent == true &&
                prepared.DeletedVaultPresent == false && prepared.Configuration is not null);
            var native = measured.Vaults[0];
            Require(native.Row.ResourceId.Equals(session.Plan!.VaultId, StringComparison.OrdinalIgnoreCase) &&
                native.Row.ProvisioningState == NativeProvisioningState.Succeeded && native.Configuration is not null);
            var configuration = Project(native.Configuration);
            Require(E.SameConfiguration(configuration, baseline) &&
                E.SameConfiguration(configuration, prepared.Configuration));
            lock (gate)
            {
                linked.Token.ThrowIfCancellationRequested();
                Require(!disposed && !session.Closed);
                provisioner.CheckVaultRead(loan);
                var observedAt = time.GetUtcNow();
                Require(observedAt >= measured.FinishedAt && (before || observedAt >= session.BaselineAt));
                if (before) { session.BaselineAt = observedAt; session.BaselineReady = true; }
                return Reply(new E.Measurement(session.Plan.LeaseId, session.Selector.Nonce, observerIdentity,
                    observedAt, session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, configuration,
                    configuration.Policies, PrivateConnectionState.Unknown, SecretStatus.Unknown, [], null,
                    [new(native.Row.ResourceId, native.Row.ProvisioningState, native.Row.Rbac,
                        native.Row.PurgeProtection, native.Row.RetentionDays)], [], [], [], null));
            }
        }
        finally
        {
            observation.Value = previous;
            // These snapshots outlive transport completion: the actual collector
            // SDK return and the parent witness both remain borrowers of the loan.
            bool disposalFailed = false;
            foreach (var item in session.ObservationStorage)
                try { item.Dispose(); }
                catch (Exception) { disposalFailed = true; }
            session.ObservationStorage.Clear();
            foreach (var bytes in session.ObservationBuffers) CryptographicOperations.ZeroMemory(bytes);
            session.ObservationBuffers.Clear();
            try { Require(!disposalFailed); }
            finally
            {
                try { provisioner.ExitVaultRead(loan); }
                finally { Leave(session); }
            }
        }
    }

    private HttpResponseMessage ObserveVaultGroup(Session session, P.VaultReadLoan loan, M.Window window,
        M.Measurement measured, P.Result prepared, bool before, CancellationToken token)
    {
        Require(ReferenceEquals(measured.Binding, session.Binding) &&
            measured.WindowId == window.Id && measured.ArmedAt == window.ArmedAt &&
            measured.Identity == metadataIdentity && measured.ApiRevision == M.Revision &&
            measured.Failure == M.Failure.None && measured.ResponseComplete && measured.InventoryComplete &&
            measured.Status == SecretStatus.Success && measured.NativeRequestIds.Count == 1 &&
            measured.NativeRequestIds.Single() == session.RawGroupRequestId &&
            session.GroupRequest is not null && session.GroupSends == 1 && session.RawGroup is not null &&
            measured.Vaults.Count == 1 && measured.DeletedVaults.Count == 0 &&
            measured.Connections.Count == 0 && measured.PrivateLinks.Count == 0 &&
            measured.NameAvailable is null && window.ArmedAt >= session.ArmedAt &&
            measured.StartedAt >= window.ArmedAt && measured.FinishedAt >= measured.StartedAt &&
            prepared.State == P.State.Ready && prepared.VaultPresent == true &&
            prepared.DeletedVaultPresent == false && prepared.DeletedVault is null &&
            prepared.Configuration is not null);
        var raw = session.RawGroup;
        var native = measured.Vaults.Single();
        Require(native.Row.ResourceId == session.Plan!.VaultId &&
            new E.VaultRow(native.Row.ResourceId, native.Row.ProvisioningState, native.Row.Rbac,
                native.Row.PurgeProtection, native.Row.RetentionDays) == raw.Row &&
            native.Configuration is not null);
        var configuration = Snapshot(Project(native.Configuration));
        Require(E.SameConfiguration(configuration, baseline) &&
            E.SameConfiguration(configuration, raw.Configuration) &&
            E.SameConfiguration(configuration, prepared.Configuration));
        lock (gate)
        {
            token.ThrowIfCancellationRequested();
            Require(!disposed && !session.Closed);
            provisioner.CheckVaultRead(loan);
            var observedAt = time.GetUtcNow();
            Require(observedAt >= measured.FinishedAt && (before || observedAt >= session.BaselineAt));
            if (before)
            {
                Require(session.GroupBaseline is null);
                session.GroupBaseline = raw with { Configuration = Snapshot(configuration) };
                session.BaselineAt = observedAt;
                session.BaselineReady = true;
            }
            else
            {
                Require(session.GroupBaseline is not null && SameGroup(raw, session.GroupBaseline));
                if (session.Selected!.RawGroup is { } selectedRaw) Require(SameGroup(raw, selectedRaw));
                if (session.Selected.OriginalVaults is { Status: SecretStatus.Success } inventory)
                {
                    Require(inventory.Complete && inventory.Items.Count == 1);
                    if (IsVaultSubscriptionList(session.Selector))
                    {
                        Require(session.Selected.Scope is SubscriptionScope);
                        MatchSubscriptionItem(inventory.Items.Single(), (SubscriptionScope)session.Selected.Scope, raw);
                    }
                    else
                    {
                        Require(session.Selected.Scope is ResourceGroupScope);
                        MatchGroupItem(inventory.Items.Single(), (ResourceGroupScope)session.Selected.Scope, raw);
                    }
                }
            }
            return Reply(new E.Measurement(session.Plan.LeaseId, session.Selector.Nonce, observerIdentity,
                observedAt, session.Plan.VaultId, SecretStatus.Success, SecretStatus.Absent, configuration,
                configuration.Policies, PrivateConnectionState.Unknown, SecretStatus.Unknown, [], null,
                [raw.Row], [], [], [], null));
        }
    }

    public async ValueTask<ManagementInventory<VaultObservation>> RunListVaultsResourceGroupAsync(
        FixtureSelector selector, VaultAdministration client, ResourceGroupScope originalScope,
        CollectionLimits originalLimits, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsVaultGroupList(selector) && client is not null && originalScope is not null &&
            originalLimits is not null && originalLimits.MaximumPages >= 1 && originalLimits.MaximumItems >= 1 &&
            originalScope.Subscription.SubscriptionId == host.SubscriptionId &&
            originalScope.ResourceGroup == host.ResourceGroup);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.GroupBaseline is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                session.Plan.VaultId == GroupListPath() + "/" + session.Plan.VaultName);
            Require(provisioner.TryEnterVaultGroupListRead(session.Plan, out var loan));
            call = new(session, client, originalScope, loan) { OriginalCollectionLimits = originalLimits };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalVaultsTask = call.Client.ListVaultsAsync(originalScope, originalLimits, linked.Token).AsTask();
            var result = await call.OriginalVaultsTask.ConfigureAwait(false);
            call.OriginalVaults = result;
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1 &&
                ReferenceEquals(call.Scope, originalScope) && ReferenceEquals(call.OriginalCollectionLimits, originalLimits));
            if (result.Status == SecretStatus.Success)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    result.Complete && result.Items.Count == 1 && call.RawGroup is not null &&
                    call.Session.GroupBaseline is not null && SameGroup(call.RawGroup, call.Session.GroupBaseline));
                MatchGroupItem(result.Items.Single(), originalScope, call.RawGroup);
            }
            else if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403 && !result.Complete && result.Items.Count == 0);
            else
                Require(selector.Case == "lost-response-no-replay" && result.Status == SecretStatus.Unknown &&
                    call.ValidReply && call.NativeStatus == 200 && !result.Complete && result.Items.Count == 0);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.OriginalVaultsTask is { IsCompleted: false })
                    try { await call.OriginalVaultsTask.ConfigureAwait(false); }
                    catch (Exception) { }
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        // Only after the actual foreign SDK task drains can a
                        // never-dispatched source admission remain available.
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<ManagementInventory<VaultObservation>> RunListVaultsSubscriptionAsync(
        FixtureSelector selector, VaultAdministration originalClient, SubscriptionScope originalSubscriptionScope,
        CollectionLimits originalLimits, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsVaultSubscriptionList(selector) && originalClient is not null && originalSubscriptionScope is not null &&
            originalLimits is not null && originalLimits.MaximumPages >= 1 && originalLimits.MaximumItems >= 1 &&
            originalSubscriptionScope.SubscriptionId == host.SubscriptionId);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.GroupBaseline is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                session.Plan.VaultId == GroupListPath() + "/" + session.Plan.VaultName);
            Require(provisioner.TryEnterVaultSubscriptionListRead(session.Plan, out var loan));
            call = new(session, originalClient, originalSubscriptionScope, loan) { OriginalCollectionLimits = originalLimits };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalVaultsTask = originalClient.ListVaultsAsync(originalSubscriptionScope, originalLimits, linked.Token).AsTask();
            var result = await call.OriginalVaultsTask.ConfigureAwait(false);
            call.OriginalVaults = result;
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1 &&
                ReferenceEquals(call.Client, originalClient) && ReferenceEquals(call.Scope, originalSubscriptionScope) &&
                ReferenceEquals(call.OriginalCollectionLimits, originalLimits));
            if (result.Status == SecretStatus.Success)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    result.Complete && result.Items.Count == 1 && call.RawGroup is not null &&
                    call.Session.GroupBaseline is not null && SameGroup(call.RawGroup, call.Session.GroupBaseline));
                MatchSubscriptionItem(result.Items.Single(), originalSubscriptionScope, call.RawGroup);
            }
            else if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403 && !result.Complete && result.Items.Count == 0);
            else
                Require(selector.Case == "lost-response-no-replay" && result.Status == SecretStatus.Unknown &&
                    call.ValidReply && call.NativeStatus == 200 && !result.Complete && result.Items.Count == 0);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.OriginalVaultsTask is { IsCompleted: false })
                    try { await call.OriginalVaultsTask.ConfigureAwait(false); }
                    catch (Exception) { }
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<ManagementInventory<DeletedVaultObservation>> RunListDeletedVaultsAsync(
        FixtureSelector selector, VaultAdministration originalClient, SubscriptionScope originalSubscriptionScope,
        CollectionLimits originalLimits, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsDeletedList(selector) && originalClient is not null && originalSubscriptionScope is not null &&
            originalLimits is not null && originalLimits.MaximumPages >= 1 && originalLimits.MaximumItems >= 1 &&
            originalSubscriptionScope.SubscriptionId == host.SubscriptionId);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.DeletedBaseline is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                session.Plan.VaultId == GroupListPath() + "/" + session.Plan.VaultName);
            Require(provisioner.TryEnterDeletedVaultListRead(session.Plan, out var loan));
            call = new(session, originalClient, originalSubscriptionScope, loan) { OriginalCollectionLimits = originalLimits };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalDeletedVaultsTask = originalClient.ListDeletedVaultsAsync(originalSubscriptionScope,
                originalLimits, linked.Token).AsTask();
            var result = await call.OriginalDeletedVaultsTask.ConfigureAwait(false);
            call.OriginalDeletedVaults = result;
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1 &&
                ReferenceEquals(call.Client, originalClient) && ReferenceEquals(call.Scope, originalSubscriptionScope) &&
                ReferenceEquals(call.OriginalCollectionLimits, originalLimits));
            if (result.Status == SecretStatus.Success)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    result.Complete && result.Items.Count == 1 && call.RawDeleted is not null &&
                    call.RawDeleted == call.Session.DeletedBaseline);
                MatchDeletedSubscriptionItem(result.Items.Single(), originalSubscriptionScope, call.RawDeleted);
            }
            else if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403 && !result.Complete && result.Items.Count == 0);
            else
                Require(selector.Case == "lost-response-no-replay" && result.Status == SecretStatus.Unknown &&
                    call.ValidReply && call.NativeStatus == 200 && !result.Complete && result.Items.Count == 0);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.OriginalDeletedVaultsTask is { IsCompleted: false })
                    try { await call.OriginalDeletedVaultsTask.ConfigureAwait(false); }
                    catch (Exception) { }
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    private void MatchDeletedSubscriptionItem(DeletedVaultObservation item, SubscriptionScope originalSubscription,
        E.DeletedVaultRow raw) =>
        Require(ReferenceEquals(item.Scope.Subscription, originalSubscription) &&
            originalSubscription.SubscriptionId == host.SubscriptionId && SameDeleted(item, raw));

    private string DeletedListPath() =>
        $"/subscriptions/{host.SubscriptionId:D}/providers/Microsoft.KeyVault/deletedVaults";

    private string SubscriptionListPath() =>
        $"/subscriptions/{host.SubscriptionId:D}/providers/Microsoft.KeyVault/vaults";

    private string GroupListPath() =>
        $"/subscriptions/{host.SubscriptionId:D}/resourceGroups/{host.ResourceGroup}/providers/Microsoft.KeyVault/vaults";

    private static bool SameGroup(VaultGroupRow left, VaultGroupRow right) =>
        left.Row == right.Row && left.VaultUri == right.VaultUri && left.CreateMode == right.CreateMode &&
        E.SameConfiguration(left.Configuration, right.Configuration);

    private static void MatchGroupItem(VaultObservation item, ResourceGroupScope originalGroup, VaultGroupRow raw) =>
        Require(ReferenceEquals(item.Scope.ResourceGroup, originalGroup) &&
            ReferenceEquals(item.Scope.ResourceGroup.Subscription, originalGroup.Subscription) &&
            item.Scope.ExportResourceId() == raw.Row.ResourceId &&
            item.Scope.VaultName == raw.Row.ResourceId.Split('/')[^1] &&
            item.ProvisioningState == raw.Row.ProvisioningState &&
            item.EnableRbacAuthorization == raw.Row.Rbac && item.EnablePurgeProtection == raw.Row.PurgeProtection &&
            item.RetentionDays == raw.Row.RetentionDays);

    private void MatchSubscriptionItem(VaultObservation item, SubscriptionScope originalSubscription, VaultGroupRow raw) =>
        Require(ReferenceEquals(item.Scope.ResourceGroup.Subscription, originalSubscription) &&
            originalSubscription.SubscriptionId == host.SubscriptionId &&
            item.Scope.ResourceGroup.ResourceGroup == host.ResourceGroup &&
            item.Scope.ExportResourceId() == raw.Row.ResourceId &&
            item.Scope.VaultName == raw.Row.ResourceId.Split('/')[^1] &&
            item.ProvisioningState == raw.Row.ProvisioningState &&
            item.EnableRbacAuthorization == raw.Row.Rbac && item.EnablePurgeProtection == raw.Row.PurgeProtection &&
            item.RetentionDays == raw.Row.RetentionDays);

    private async Task<HttpResponseMessage> ObservePrivateConnection(Session session, P.VaultReadLoan loan,
        bool before, CancellationToken token)
    {
        var source = privateConnectionSource!;
        var plan = session.Plan!;
        Require(session.ConnectionId is not null && session.Binding is not null && session.PrivateAdmission is not null);
        var prepared = await provisioner.ObserveVaultReadAsync(loan, token).ConfigureAwait(false);
        Require(prepared.State == P.State.Ready && prepared.VaultPresent == true && prepared.DeletedVaultPresent == false &&
            prepared.Configuration is not null && prepared.DeletedVault is null &&
            E.SameConfiguration(prepared.Configuration, baseline) &&
            prepared.CanaryPresent == true && prepared.CanarySha256 == plan.CanarySha256 &&
            prepared.CanaryVersion == plan.CanaryVersion && plan.CanaryVersion is not null && plan.CanarySha256 is not null);
        session.RawConnection = null;
        session.RawConnectionRequestId = null;
        var childBinding = IsPrivateLinkList(session.Selector) ? session.ChildBinding! : session.Binding;
        var child = new M(source.VaultConnectionReader with
        {
            Transport = new PrivateReadTransport(this, source.VaultConnectionReader.Transport,
                M.ArmOrigin + (IsPrivateList(session.Selector)
                    ? plan.VaultId + "/privateEndpointConnections" : session.ConnectionId) +
                    "?api-version=" + M.Revision, rawChild: true)
        }, source.InventoryLimits, time);
        var childWindow = child.Arm(childBinding);
        var measured = await child.CollectAsync(childWindow, childBinding, token).ConfigureAwait(false);
        Require(ReferenceEquals(measured.Binding, childBinding) && measured.WindowId == childWindow.Id &&
            measured.ArmedAt == childWindow.ArmedAt && measured.ResponseComplete &&
            measured.Identity == source.VaultConnectionReader.Label &&
            (!IsPrivateList(session.Selector) || measured.InventoryComplete) &&
            measured.Status == SecretStatus.Success && measured.NativeRequestIds.Count == 1 &&
            measured.NativeRequestIds.Single() == session.RawConnectionRequestId &&
            measured.Connections.Count == 1 && measured.Vaults.Count == 0 && measured.DeletedVaults.Count == 0 &&
            measured.PrivateLinks.Count == 0 && measured.NameAvailable is null &&
            childWindow.ArmedAt >= session.ArmedAt && measured.StartedAt >= childWindow.ArmedAt &&
            measured.FinishedAt >= measured.StartedAt);
        var row = measured.Connections.Single();
        Require(row == session.RawConnection && row.ResourceId == session.ConnectionId &&
            row.Name == session.Binding.ConnectionName && row.PrivateEndpointId == plan.PrivateEndpoint!.EndpointId &&
            row.State == PrivateConnectionState.Pending && row.ProvisioningState == NativeProvisioningState.Succeeded);

        M.Measurement? linkRead = null;
        M.PrivateLinkRow? linkRow = null;
        if (IsPrivateLinkList(session.Selector))
        {
            session.RawLink = null;
            session.RawLinkRequestId = null;
            var links = new M(source.VaultConnectionReader with
            {
                Transport = new PrivateReadTransport(this, source.VaultConnectionReader.Transport,
                    M.ArmOrigin + plan.VaultId + "/privateLinkResources?api-version=" + M.Revision, rawLink: true)
            }, source.InventoryLimits, time);
            var linkWindow = links.Arm(session.Binding);
            linkRead = await links.CollectAsync(linkWindow, session.Binding, token).ConfigureAwait(false);
            Require(ReferenceEquals(linkRead.Binding, session.Binding) &&
                !ReferenceEquals(linkRead.Binding, measured.Binding) &&
                linkRead.WindowId == linkWindow.Id && linkWindow.Id != childWindow.Id &&
                linkRead.ArmedAt == linkWindow.ArmedAt && linkWindow.ArmedAt >= measured.FinishedAt &&
                linkRead.StartedAt >= linkWindow.ArmedAt && linkRead.FinishedAt >= linkRead.StartedAt &&
                linkRead.ResponseComplete && linkRead.InventoryComplete &&
                linkRead.Identity == source.VaultConnectionReader.Label && linkRead.Status == SecretStatus.Success &&
                linkRead.NativeRequestIds.Count == 1 && linkRead.NativeRequestIds.Single() == session.RawLinkRequestId &&
                session.RawLinkRequestId != session.RawConnectionRequestId &&
                linkRead.PrivateLinks.Count == 1 && linkRead.Connections.Count == 0 &&
                linkRead.Vaults.Count == 0 && linkRead.DeletedVaults.Count == 0 && linkRead.NameAvailable is null &&
                session.RawLink is not null);
            linkRow = linkRead.PrivateLinks.Single();
            Require(SameLink(linkRow, session.RawLink));
        }

        var endpointBinding = provisioner.EndpointBinding(plan);
        var endpoint = new Endpoint(source.EndpointReader with
        {
            Transport = new PrivateReadTransport(this, source.EndpointReader.Transport,
                M.ArmOrigin + endpointBinding.EndpointId + "?api-version=" + Endpoint.Revision)
        }, source.ResourceLimits, time);
        var endpointWindow = endpoint.Arm(endpointBinding);
        var endpointRead = await endpoint.CollectAsync(endpointWindow, endpointBinding, token).ConfigureAwait(false);
        Require(ReferenceEquals(endpointRead.Binding, endpointBinding) && endpointRead.WindowId == endpointWindow.Id &&
            endpointRead.ArmedAt == endpointWindow.ArmedAt && endpointRead.Kind == Endpoint.ReadKind.Endpoint &&
            endpointRead.ResponseComplete && endpointRead.ResourceStatus == SecretStatus.Success &&
            endpointRead.HttpStatus == 200 && Text(endpointRead.NativeRequestId, 128) &&
            endpointRead.MatchesDeclaration && endpointRead.NativeState == "Succeeded" &&
            endpointRead.ManualConnectionState == "Pending" && endpointWindow.ArmedAt >= session.ArmedAt &&
            endpointRead.StartedAt >= endpointWindow.ArmedAt && endpointRead.FinishedAt >= endpointRead.StartedAt);

        string runtimeUri = "https://" + plan.VaultName + ".vault.azure.net/secrets/" + P.Canary + "/" +
            plan.CanaryVersion + "?api-version=" + N.Revision;
        var network = new N(source.PrivateRuntime with
        {
            Transport = new PrivateReadTransport(this, source.PrivateRuntime.Transport, runtimeUri)
        }, source.PublicRuntime with
        {
            Transport = new PrivateReadTransport(this, source.PublicRuntime.Transport, runtimeUri)
        }, source.NetworkLimits, time);
        var networkBinding = new N.Binding(session.Binding, P.Canary, plan.CanaryVersion, plan.CanarySha256, N.Revision);
        var networkWindow = network.Arm(networkBinding);
        var networkRead = await network.CollectAsync(networkWindow, networkBinding, token).ConfigureAwait(false);
        Require(ReferenceEquals(networkRead.Binding, networkBinding) && networkRead.WindowId == networkWindow.Id &&
            networkRead.ArmedAt == networkWindow.ArmedAt && networkWindow.ArmedAt >= session.ArmedAt &&
            networkRead.StartedAt >= networkWindow.ArmedAt && networkRead.FinishedAt >= networkRead.StartedAt &&
            networkRead.PrivateRead is { Status: SecretStatus.Denied, Failure: N.Failure.None, CanarySha256: null } &&
            networkRead.PublicRead is { Status: SecretStatus.Success, Failure: N.Failure.None } &&
            networkRead.PrivateRead.NativeRequestIds.Count == 1 && networkRead.PublicRead.NativeRequestIds.Count == 1 &&
            networkRead.PublicRead.CanarySha256 == plan.CanarySha256 &&
            networkRead.PrivateRead.Identity == source.PrivateRuntime.Label &&
            networkRead.PublicRead.Identity == source.PublicRuntime.Label &&
            !networkRead.PrincipalQualified && !networkRead.EgressQualified);
        lock (gate)
        {
            token.ThrowIfCancellationRequested();
            Require(!disposed && !session.Closed);
            provisioner.CheckVaultRead(loan);
            var observedAt = time.GetUtcNow();
            Require(observedAt >= measured.FinishedAt && observedAt >= endpointRead.FinishedAt &&
                (linkRead is null || observedAt >= linkRead.FinishedAt) &&
                observedAt >= networkRead.FinishedAt && (before || observedAt >= session.BaselineAt));
            var configuration = Snapshot(prepared.Configuration);
            var result = new E.Measurement(plan.LeaseId, session.Selector.Nonce, observerIdentity, observedAt,
                plan.VaultId, prepared.VaultPresent == true ? SecretStatus.Success : SecretStatus.Absent,
                prepared.DeletedVaultPresent == true ? SecretStatus.Success : SecretStatus.Absent, configuration,
                configuration.Policies, row.State, measured.Status, [],
                new(row.Name, networkRead.PrivateRead.Status, networkRead.PublicRead.Status,
                    networkRead.PrivateRead.NativeRequestIds.Single()), [], [],
                [new(row.Name, row.State, row.ProvisioningState)],
                linkRow is null ? [] : [new(linkRow.Name, linkRow.GroupId,
                    linkRow.RequiredMembers.ToArray(), linkRow.RequiredZoneNames.ToArray())], null);
            if (before)
            {
                Require(session.LinkBaseline is null);
                if (linkRow is not null)
                    session.LinkBaseline = linkRow with
                    {
                        RequiredMembers = linkRow.RequiredMembers.ToArray(),
                        RequiredZoneNames = linkRow.RequiredZoneNames.ToArray()
                    };
                session.ConnectionBefore = measured;
                session.LinkBefore = linkRead;
                session.EndpointBefore = endpointRead;
                session.NetworkBefore = networkRead;
                session.PrivateBaseline = result;
                session.ConnectionBaseline = row;
                session.BaselineAt = observedAt;
                session.BaselineReady = true;
            }
            else
            {
                Require(session.PrivateBaseline is { Configuration: not null } original &&
                    session.ConnectionBaseline == row && result.VaultStatus == original.VaultStatus &&
                    result.DeletedVaultStatus == original.DeletedVaultStatus &&
                    result.ConnectionStatus == original.ConnectionStatus && result.ConnectionState == original.ConnectionState &&
                    E.SameConfiguration(configuration, original.Configuration) &&
                    E.SamePolicies(result.Policies, original.Policies) &&
                    result.NetworkEffect!.PrivateReadStatus == original.NetworkEffect!.PrivateReadStatus &&
                    result.NetworkEffect.PublicReadStatus == original.NetworkEffect.PublicReadStatus);
                if (session.Selected!.RawConnection is { } raw) Require(raw == row);
                if (session.Selected.OriginalConnectionObservation is { } selectedResult)
                    Require(ReferenceEquals(selectedResult.Scope, session.Selected.Scope) &&
                        selectedResult.Scope.ConnectionName == row.Name && selectedResult.State == row.State &&
                        selectedResult.ProvisioningState == row.ProvisioningState);
                if (session.Selected.OriginalConnections is { Status: SecretStatus.Success } inventory)
                {
                    Require(IsPrivateList(session.Selector) && inventory.Complete && inventory.Items.Count == 1);
                    var item = inventory.Items.Single();
                    Require(ReferenceEquals(item.Scope.Vault, session.Selected.Scope) &&
                        item.Scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + item.Scope.ConnectionName ==
                            row.ResourceId && item.Scope.ConnectionName == row.Name &&
                        item.State == row.State && item.ProvisioningState == row.ProvisioningState);
                }
                if (IsPrivateLinkList(session.Selector))
                {
                    Require(linkRow is not null && session.LinkBaseline is not null &&
                        SameLink(linkRow, session.LinkBaseline));
                    if (session.Selected.RawLink is { } rawLink) Require(SameLink(linkRow, rawLink));
                    if (session.Selected.OriginalLinks is { Status: SecretStatus.Success } links)
                    {
                        Require(links.Complete && links.Items.Count == 1);
                        var item = links.Items.Single();
                        Require(item.Name == linkRow.Name && item.GroupId == linkRow.GroupId &&
                            item.RequiredMembers.SequenceEqual(linkRow.RequiredMembers) &&
                            item.RequiredZoneNames.SequenceEqual(linkRow.RequiredZoneNames));
                    }
                }
                session.ConnectionAfter = measured;
                session.LinkAfter = linkRead;
                session.EndpointAfter = endpointRead;
                session.NetworkAfter = networkRead;
            }
            return Reply(result);
        }
    }

    public async ValueTask<ManagementInventory<PrivateLinkObservation>> RunListPrivateLinkResourcesAsync(
        FixtureSelector selector, VaultAdministration client, VaultScope originalVaultScope,
        CollectionLimits originalLimits, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsPrivateLinkList(selector) && client is not null && originalVaultScope is not null &&
            originalLimits is not null && originalLimits.MaximumPages >= 1 && originalLimits.MaximumItems >= 1);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.PrivateBaseline is not null &&
                session.ConnectionBaseline is not null && session.LinkBaseline is not null &&
                session.PrivateAdmission is not null && !session.AfterClaimed && session.Selected is null &&
                session.Active == 0 && originalVaultScope.ExportResourceId() == session.Plan.VaultId);
            Require(provisioner.TryEnterPrivateConnectionRead(session.Plan, session.PrivateAdmission, out var loan));
            call = new(session, client, originalVaultScope, loan) { OriginalCollectionLimits = originalLimits };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalLinksTask = call.Client.ListPrivateLinkResourcesAsync(originalVaultScope,
                originalLimits, linked.Token).AsTask();
            var result = await call.OriginalLinksTask.ConfigureAwait(false);
            call.OriginalLinks = result;
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1 &&
                ReferenceEquals(call.Scope, originalVaultScope) &&
                ReferenceEquals(call.OriginalCollectionLimits, originalLimits));
            if (result.Status == SecretStatus.Success)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    result.Complete && result.Items.Count == 1 && call.RawLink is not null &&
                    call.Session.LinkBaseline is not null && SameLink(call.RawLink, call.Session.LinkBaseline));
                var item = result.Items.Single();
                Require(item.Name == call.RawLink.Name && item.GroupId == call.RawLink.GroupId &&
                    item.RequiredMembers.SequenceEqual(call.RawLink.RequiredMembers) &&
                    item.RequiredZoneNames.SequenceEqual(call.RawLink.RequiredZoneNames));
            }
            else if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403 && !result.Complete && result.Items.Count == 0);
            else
                Require(selector.Case == "lost-response-no-replay" && result.Status == SecretStatus.Unknown &&
                    call.ValidReply && call.NativeStatus == 200 && !result.Complete && result.Items.Count == 0);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<ManagementInventory<PrivateConnectionObservation>> RunListPrivateConnectionsAsync(
        FixtureSelector selector, VaultAdministration client, VaultScope originalScope,
        CollectionLimits originalLimits, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsPrivateList(selector) && client is not null && originalScope is not null &&
            originalLimits is not null && originalLimits.MaximumPages >= 1 && originalLimits.MaximumItems >= 1);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.PrivateBaseline is not null &&
                session.ConnectionBaseline is not null && session.PrivateAdmission is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                originalScope.ExportResourceId() == session.Plan.VaultId);
            Require(provisioner.TryEnterPrivateConnectionRead(session.Plan, session.PrivateAdmission, out var loan));
            call = new(session, client, originalScope, loan) { OriginalCollectionLimits = originalLimits };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalConnectionsTask = call.Client.ListPrivateConnectionsAsync(originalScope,
                originalLimits, linked.Token).AsTask();
            var result = await call.OriginalConnectionsTask.ConfigureAwait(false);
            call.OriginalConnections = result;
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1 &&
                ReferenceEquals(call.Scope, originalScope) && ReferenceEquals(call.OriginalCollectionLimits, originalLimits));
            if (result.Status == SecretStatus.Success)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    result.Complete && result.Items.Count == 1 && call.RawConnection is not null &&
                    call.RawConnection == call.Session.ConnectionBaseline);
                var item = result.Items.Single();
                Require(ReferenceEquals(item.Scope.Vault, originalScope) &&
                    item.Scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + item.Scope.ConnectionName ==
                        call.RawConnection.ResourceId &&
                    item.Scope.ConnectionName == call.RawConnection.Name &&
                    item.State == call.RawConnection.State &&
                    item.ProvisioningState == call.RawConnection.ProvisioningState);
            }
            else if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403 && !result.Complete && result.Items.Count == 0);
            else
                Require(selector.Case == "lost-response-no-replay" && result.Status == SecretStatus.Unknown &&
                    call.ValidReply && call.NativeStatus == 200 && !result.Complete && result.Items.Count == 0);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<SecretOutcome<PrivateConnectionObservation>> RunGetPrivateConnectionAsync(
        FixtureSelector selector, VaultAdministration client, PrivateConnectionScope scope,
        CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsPrivate(selector) && !IsPrivateList(selector) && !IsPrivateLinkList(selector) &&
            client is not null && scope is not null);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.PrivateBaseline is not null &&
                session.ConnectionBaseline is not null && session.PrivateAdmission is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                scope.Vault.ExportResourceId() == session.Plan.VaultId &&
                scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + scope.ConnectionName == session.ConnectionId);
            Require(provisioner.TryEnterPrivateConnectionRead(session.Plan, session.PrivateAdmission, out var loan));
            call = new(session, client, scope, loan);
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalConnectionTask = call.Client.GetPrivateConnectionAsync(scope, linked.Token).AsTask();
            var result = await call.OriginalConnectionTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1);
            if (result.IsSuccess)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && Text(call.NativeRequestId, 128) &&
                    ReferenceEquals(result.Value.Scope, scope) && call.RawConnection is not null &&
                    call.RawConnection == call.Session.ConnectionBaseline &&
                    result.Value.Scope.ConnectionName == call.RawConnection.Name &&
                    result.Value.State == call.RawConnection.State &&
                    result.Value.ProvisioningState == call.RawConnection.ProvisioningState);
                call.OriginalConnectionObservation = result.Value;
            }
            if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception) { }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                        // A client that never entered this original transport
                        // cannot consume its selected admission. Its actual SDK
                        // task has drained; no source GET is replayed here.
                        if (call.Request is null && !call.Attempted && call.Sends == 0)
                            lock (gate)
                                if (ReferenceEquals(call.Session.Selected, call)) call.Session.Selected = null;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<SecretOutcome<VaultObservation>> RunGetVaultAsync(FixtureSelector selector,
        VaultAdministration client, VaultScope scope, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(selector.Operation == M.Operation(M.QueryKind.GetVault) && selector.Variant == "selector.exact");
        Require(client is not null && scope is not null);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && !session.AfterClaimed &&
                session.Selected is null && session.Active == 0 &&
                scope.ExportResourceId() == session.Plan.VaultId);
            // Validate the scope before consuming admission. Capture the actual
            // client and scope objects; no reconstruction or SDK receipt exists.
            Require(provisioner.TryEnterVaultRead(session.Plan, out var loan));
            call = new(session, client, scope, loan);
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalTask = call.Client.GetVaultAsync((VaultScope)call.Scope, linked.Token).AsTask();
            var result = await call.OriginalTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1);
            if (result.IsSuccess)
                Require(call.ValidReply && call.NativeStatus == 200 && ReferenceEquals(result.Value.Scope, call.Scope));
            if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                // Also join the captured inner send if a host wrapper returns
                // early. Cancellation is never an acknowledgement of drainage.
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception)
                    {
                        // Drain only: the original SDK task owns outcome mapping.
                        // A transport exception is not replaced with a success.
                    }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<SecretOutcome<DeletedVaultObservation>> RunGetDeletedVaultAsync(FixtureSelector selector,
        VaultAdministration client, DeletedVaultScope scope, CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(selector.Operation == M.Operation(M.QueryKind.GetDeletedVault) &&
            selector.Variant == "selector.exact" && client is not null && scope is not null);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.DeletedBaseline is not null &&
                !session.AfterClaimed && session.Selected is null && session.Active == 0 &&
                $"/subscriptions/{scope.Subscription.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{scope.Location}/deletedVaults/{scope.VaultName}" ==
                    session.Plan.DeletedId);
            Require(provisioner.TryEnterDeletedVaultRead(session.Plan, out var loan));
            call = new(session, client, scope, loan);
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalDeletedTask = call.Client.GetDeletedVaultAsync(scope, linked.Token).AsTask();
            var result = await call.OriginalDeletedTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1);
            if (result.IsSuccess)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && ReferenceEquals(result.Value.Scope, scope) &&
                    call.RawDeleted is not null && call.RawDeleted == call.Session.DeletedBaseline &&
                    SameDeleted(result.Value, call.RawDeleted));
                call.OriginalDeletedObservation = result.Value;
            }
            if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception)
                    {
                        // Only the original SDK task maps the drained failure.
                    }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    public async ValueTask<SecretOutcome<VaultNameAvailability>> RunCheckNameAvailabilityAsync(FixtureSelector selector,
        VaultAdministration client, SubscriptionScope originalSubscription, string vaultName,
        CancellationToken cancellationToken)
    {
        ValidateSelector(selector);
        Require(IsName(selector) && client is not null && originalSubscription is not null);
        cancellationToken.ThrowIfCancellationRequested();
        SelectedCall call;
        lock (gate)
        {
            Require(sessions.TryGetValue(selector.Nonce, out var session) && !disposed && !session.Closed &&
                session.Selector == selector && session.Plan is not null && session.Lease is not null &&
                session.Armed && session.BaselineReady && session.NameBaseline == false &&
                session.NameConfiguration is not null && !session.AfterClaimed &&
                session.Selected is null && session.Active == 0 &&
                originalSubscription.SubscriptionId == host.SubscriptionId &&
                session.Plan.VaultId.StartsWith($"/subscriptions/{originalSubscription.SubscriptionId:D}/",
                    StringComparison.Ordinal) && vaultName == session.Plan.VaultName);
            Require(provisioner.TryEnterVaultNameRead(session.Plan, out var loan));
            call = new(session, client, originalSubscription, loan) { VaultName = vaultName };
            session.Selected = call;
            Enter(session);
            active++;
        }
        var previous = selected.Value;
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token,
                call.Session.Stop.Token, lifetime.Token);
            selected.Value = call;
            linked.Token.ThrowIfCancellationRequested();
            call.OriginalNameTask = call.Client.CheckNameAvailabilityAsync(originalSubscription, vaultName, linked.Token).AsTask();
            var result = await call.OriginalNameTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            Require(call.Request is not null && call.Attempted && call.Sends == 1);
            if (result.IsSuccess)
            {
                Require(call.ValidReply && call.NativeStatus == 200 && call.RawNameAvailable is not null &&
                    result.Value.Available == call.RawNameAvailable &&
                    result.Value.Available == call.Session.NameBaseline);
                call.OriginalNameObservation = result.Value;
            }
            if (result.Status == SecretStatus.Denied)
                Require(call.ValidReply && call.NativeStatus is 401 or 403);
            return result;
        }
        finally
        {
            selected.Value = previous;
            try
            {
                if (call.SendTask is { IsCompleted: false })
                    try { await call.SendTask.ConfigureAwait(false); }
                    catch (Exception)
                    {
                        // The actual SDK task, not drainage, supplies the outcome.
                    }
            }
            finally
            {
                call.Terminated = true;
                try { call.Clear(); }
                finally
                {
                    try
                    {
                        provisioner.ExitVaultRead(call.Loan);
                        call.Finalized = true;
                    }
                    finally { Leave(call.Session); EndRequest(); }
                }
            }
        }
    }

    private sealed class OriginalTransport(VaultReadFixtureObserverService service) : HttpPipelineTransport
    {
        private SelectedCall Current()
        {
            var call = service.selected.Value ?? throw Failure();
            Require(!service.disposed && !call.Session.Closed && !call.Terminated &&
                ReferenceEquals(call.Session.Selected, call));
            return call;
        }
        public override Request CreateRequest()
        {
            lock (service.gate)
            {
                var call = Current();
                Require(call.Request is null);
                service.provisioner.CheckVaultRead(call.Loan);
                return call.Request = service.selectedBackend.CreateRequest();
            }
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            lock (service.gate)
            {
                var call = Current();
                Require(ReferenceEquals(message.Request, call.Request) && ++call.Sends == 1);
                call.SendTask = service.Send(call, message);
                return new(call.SendTask);
            }
        }
        public override string ToString() => "[VaultOriginalReadTransport]";
    }

    private async Task Send(SelectedCall call, HttpMessage message)
    {
        bool name = IsName(call.Session.Selector);
        string id = IsDeletedList(call.Session.Selector) ? DeletedListPath() :
            IsVaultSubscriptionList(call.Session.Selector) ? SubscriptionListPath() :
            IsVaultGroupList(call.Session.Selector) ? GroupListPath() :
            IsPrivateLinkList(call.Session.Selector) ? call.Loan.Plan.VaultId + "/privateLinkResources" :
            IsPrivateList(call.Session.Selector) ? call.Loan.Plan.VaultId + "/privateEndpointConnections" :
            IsPrivate(call.Session.Selector) ? call.Session.ConnectionId! : name ? NamePath(call.Loan.Plan) :
            IsDeleted(call.Session.Selector) ? call.Loan.Plan.DeletedId : call.Loan.Plan.VaultId;
        ValidateRequest(message, id, name);
        var content = message.Request.Content;
        var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
        ReadOnlyMemory<byte> originalBody = default;
        if (name)
        {
            Require(call.Scope is SubscriptionScope subscription && subscription.SubscriptionId == host.SubscriptionId &&
                call.VaultName == call.Loan.Plan.VaultName);
            originalBody = await SnapshotNameRequest(message, call.Loan.Plan, call.Buffers).ConfigureAwait(false);
            Require(ReferenceEquals(content, message.Request.Content) &&
                headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            // Dispatch the validated bytes, not another serialization of a
            // potentially stateful original RequestContent.
            call.Storage.Add(content!);
            content = RequestContent.Create(new BinaryData(originalBody));
            call.Storage.Add(content);
            message.Request.Content = content;
        }
        try
        {
            Task send;
            lock (gate)
            {
                // Authentication has already completed in the original SDK. No
                // journal lock is held when the host's ProcessAsync is invoked.
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(!disposed && !call.Session.Closed && !call.Terminated &&
                    ReferenceEquals(message.Request, call.Request) &&
                    ReferenceEquals(content, message.Request.Content) &&
                    headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                ValidateRequest(message, id, name);
                provisioner.CheckVaultRead(call.Loan);
                message.BufferResponse = false;
                call.Attempted = true;
                send = selectedBackend.ProcessAsync(message).AsTask();
            }
            await send.ConfigureAwait(false);
        }
        finally { if (message.HasResponse) call.Storage.Add(message.Response); }
        ValidateRequest(message, id, name);
        if (name)
        {
            var currentBody = await SnapshotNameRequest(message, call.Loan.Plan, call.Buffers).ConfigureAwait(false);
            Require(originalBody.Span.SequenceEqual(currentBody.Span));
        }
        Require(ReferenceEquals(content, message.Request.Content) &&
            headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))) && message.HasResponse);
        if (IsVaultGroupList(call.Session.Selector) || IsVaultSubscriptionList(call.Session.Selector) ||
            IsDeletedList(call.Session.Selector))
            lock (gate)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(!disposed && !call.Session.Closed && !call.Terminated &&
                    ReferenceEquals(call.Session.Selected, call) && ReferenceEquals(call.Request, message.Request));
                provisioner.CheckVaultRead(call.Loan);
            }
        var response = message.Response;
        call.NativeStatus = response.Status;
        Require(response.Status is 200 or 401 or 403);
        long? declared = ValidateResponseHeaders(response);
        Require(response.Headers.TryGetValue("x-ms-request-id", out var nativeRequestId));
        call.NativeRequestId = nativeRequestId;
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        call.Buffers.Add(bytes);
        int count = 0;
        if (response.ContentStream is { } input)
        {
            call.Storage.Add(input);
            while (true)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                int read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumBodyBytes);
            }
        }
        Require(count > 0 && count <= limits.MaximumBodyBytes && (declared is null || declared == count));
        if (IsPrivateLinkList(call.Session.Selector))
            Require(count <= privateConnectionSource!.InventoryLimits.MaximumResponseBytes);
        if (IsVaultGroupList(call.Session.Selector) || IsVaultSubscriptionList(call.Session.Selector) ||
            IsDeletedList(call.Session.Selector))
            Require(count <= collectorLimits.MaximumResponseBytes);
        using (var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 }))
        {
            Unique(document.RootElement);
            if (response.Status == 200) ValidateSuccess(call, document.RootElement);
            else Require(document.RootElement.GetProperty("error").GetProperty("code").ValueKind == JsonValueKind.String);
        }
        message.CancellationToken.ThrowIfCancellationRequested();
        var buffered = new MemoryStream(bytes, 0, count, writable: false, publiclyVisible: true);
        call.Storage.Add(buffered);
        response.ContentStream = buffered;
        call.ValidReply = true;
        // The original ManagementBoundaryTransport remains outside this source:
        // only it injects its response-loss/cancellation event, without replay.
    }

    private sealed class PrivateReadTransport(VaultReadFixtureObserverService service, HttpPipelineTransport inner,
        string exactUri, bool rawChild = false, bool rawLink = false) : HttpPipelineTransport
    {
        private Request? request;
        private int sends;
        public override Request CreateRequest()
        {
            lock (service.gate)
            {
                var loan = service.observation.Value ?? throw Failure();
                Require(!service.disposed && loan.PrivateConnection is not null && request is null);
                service.provisioner.CheckVaultRead(loan);
                return request = inner.CreateRequest();
            }
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            var loan = service.observation.Value ?? throw Failure();
            Session session;
            Task actual;
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            lock (service.gate)
            {
                Require(service.sessions.TryGetValue(loan.Plan.Selector.Nonce, out session!) &&
                    ReferenceEquals(session.Plan, loan.Plan) && !service.disposed && !session.Closed &&
                    session.Active == 1 && loan.PrivateConnection is not null &&
                    ReferenceEquals(request, message.Request) && ++sends == 1);
                message.CancellationToken.ThrowIfCancellationRequested();
                ValidatePrivateRequest(message, exactUri);
                service.provisioner.CheckVaultRead(loan);
                message.BufferResponse = false;
                // The collectors authenticate before reaching this wrapper.
                // Retain and join the actual host task, not a cancelable waiter.
                actual = inner.ProcessAsync(message).AsTask();
            }
            try { await actual.ConfigureAwait(false); }
            finally
            {
                if ((rawChild || rawLink) && message.HasResponse) session.ObservationStorage.Add(message.Response);
            }
            ValidatePrivateRequest(message, exactUri);
            Require(ReferenceEquals(request, message.Request) &&
                headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            if (rawChild || rawLink)
                await service.CapturePrivateMetadata(session, message, rawLink).ConfigureAwait(false);
        }
        public override string ToString() => "[PrivateConnectionReadTransport]";
    }

    private static void ValidatePrivateRequest(HttpMessage message, string exactUri)
    {
        Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
            message.Request.Uri.ToUri().OriginalString == exactUri &&
            message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
            authorization.StartsWith("Bearer ", StringComparison.Ordinal) && Text(authorization[7..], 16384));
        var headers = message.Request.Headers.ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => Text(h.Name, 128) && Text(h.Value, 16384)) &&
            !message.Request.Headers.Contains("Content-Length") &&
            !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
        if (message.Request.Headers.TryGetValue("Host", out var host))
            Require(host == new Uri(exactUri).Host);
    }

    private async Task CapturePrivateMetadata(Session session, HttpMessage message, bool link)
    {
        Require(message.HasResponse && message.Response.Status == 200);
        var response = message.Response;
        long? declared = ValidateResponseHeaders(response);
        Require(response.Headers.TryGetValue("x-ms-request-id", out var requestId));
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        session.ObservationBuffers.Add(bytes);
        int count = 0;
        if (response.ContentStream is { } input)
        {
            session.ObservationStorage.Add(input);
            while (true)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                int read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumBodyBytes);
            }
        }
        Require(count > 0 && count <= limits.MaximumBodyBytes && (declared is null || declared == count));
        if (link) Require(count <= privateConnectionSource!.InventoryLimits.MaximumResponseBytes);
        using (var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 }))
        {
            if (link) session.RawLink = PrivateLinkCollection(session, document.RootElement);
            else session.RawConnection = IsPrivateList(session.Selector)
                ? PrivateCollection(session, document.RootElement) : PrivateChild(session, document.RootElement);
        }
        if (link) session.RawLinkRequestId = requestId;
        else session.RawConnectionRequestId = requestId;
        message.CancellationToken.ThrowIfCancellationRequested();
        var buffered = new MemoryStream(bytes, 0, count, writable: false, publiclyVisible: true);
        session.ObservationStorage.Add(buffered);
        // Exactly these validated bytes go to the original metadata collector
        // and its SDK parser. There is no replacement child reader.
        response.ContentStream = buffered;
    }

    private E.DeletedVaultRow DeletedVaultCollection(Session session, JsonElement root)
    {
        VaultGroupShape(root);
        Require(IsDeletedList(session.Selector) && root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().All(p => p.Name is "value" or "nextLink") &&
            (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
        var values = root.GetProperty("value");
        Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 1);
        var row = values[0];
        Require(row.ValueKind == JsonValueKind.Object &&
            Encoding.UTF8.GetByteCount(row.GetRawText()) <= collectorLimits.MaximumRowBytes &&
            row.EnumerateObject().Count() == 4 &&
            row.EnumerateObject().All(p => p.Name is "id" or "name" or "type" or "properties") &&
            row.GetProperty("id").GetString() == session.Plan!.DeletedId &&
            row.GetProperty("name").GetString() == session.Plan.VaultName &&
            row.GetProperty("type").GetString() == "Microsoft.KeyVault/locations/deletedVaults");
        var properties = row.GetProperty("properties");
        Require(properties.ValueKind == JsonValueKind.Object && properties.EnumerateObject().Count() == 6 &&
            properties.EnumerateObject().All(p => p.Name is "vaultId" or "location" or "tags" or
                "deletionDate" or "scheduledPurgeDate" or "purgeProtectionEnabled") &&
            properties.GetProperty("vaultId").GetString() == session.Plan.VaultId &&
            properties.GetProperty("location").GetString() == host.Location &&
            properties.GetProperty("purgeProtectionEnabled").ValueKind == JsonValueKind.False);
        var tags = properties.GetProperty("tags");
        Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().Count() == 1 &&
            tags.GetProperty("secretkit-fixture").GetString() == session.Selector.Nonce.ToString("N") &&
            properties.GetProperty("deletionDate").TryGetDateTimeOffset(out var deletedOn) &&
            properties.GetProperty("scheduledPurgeDate").TryGetDateTimeOffset(out var purgeOn) &&
            purgeOn - deletedOn == TimeSpan.FromDays(baseline.RetentionDays));
        // Identity and ownership come from the actual closed raw row. Only
        // fields present in the public SDK and collector are projected.
        string[] id = row.GetProperty("id").GetString()!.Split('/');
        var projected = new E.DeletedVaultRow(Guid.Parse(id[2]), properties.GetProperty("location").GetString()!,
            row.GetProperty("name").GetString()!, properties.GetProperty("deletionDate").GetDateTimeOffset(),
            properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset(),
            properties.GetProperty("purgeProtectionEnabled").GetBoolean());
        Require(session.DeletedBaseline is null || projected == session.DeletedBaseline);
        return projected;
    }

    private VaultGroupRow VaultGroupCollection(Session session, JsonElement root)
    {
        VaultGroupShape(root);
        Require((IsVaultGroupList(session.Selector) || IsVaultSubscriptionList(session.Selector)) &&
            root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().All(p => p.Name is "value" or "nextLink") &&
            (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
        var values = root.GetProperty("value");
        Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 1);
        // The entire selected collection must be this singleton. No ownership filter,
        // continuation permission, reconstructed JSON, or second send exists.
        var row = values[0];
        Require(row.ValueKind == JsonValueKind.Object &&
            Encoding.UTF8.GetByteCount(row.GetRawText()) <= collectorLimits.MaximumRowBytes &&
            row.EnumerateObject().All(p => p.Name is "id" or "name" or "type" or "location" or "tags" or "properties") &&
            row.GetProperty("id").GetString() == session.Plan!.VaultId &&
            row.GetProperty("name").GetString() == session.Plan.VaultName &&
            row.GetProperty("type").GetString() == "Microsoft.KeyVault/vaults" &&
            row.GetProperty("location").GetString() == host.Location);
        var tags = row.GetProperty("tags");
        Require(tags.ValueKind == JsonValueKind.Object && tags.EnumerateObject().Count() == 1 &&
            tags.GetProperty("secretkit-fixture").GetString() == session.Selector.Nonce.ToString("N"));
        var properties = row.GetProperty("properties");
        Require(properties.ValueKind == JsonValueKind.Object &&
            properties.EnumerateObject().All(p => p.Name is "tenantId" or "sku" or "vaultUri" or
                "provisioningState" or "enableSoftDelete" or "enableRbacAuthorization" or "enablePurgeProtection" or
                "softDeleteRetentionInDays" or "publicNetworkAccess" or "accessPolicies" or "createMode") &&
            properties.GetProperty("provisioningState").GetString() == "Succeeded" &&
            properties.GetProperty("tenantId").GetGuid() == host.TenantId &&
            properties.GetProperty("enableSoftDelete").ValueKind == JsonValueKind.True);
        string expectedUri = "https://" + session.Plan.VaultName + ".vault.azure.net";
        string? vaultUri = properties.GetProperty("vaultUri").GetString();
        Require(vaultUri == expectedUri || vaultUri == expectedUri + "/");
        string? createMode = null;
        if (properties.TryGetProperty("createMode", out var mode))
        {
            Require(mode.ValueKind == JsonValueKind.String && mode.GetString() == "default");
            createMode = mode.GetString();
        }
        var sku = properties.GetProperty("sku");
        Require(sku.ValueKind == JsonValueKind.Object && sku.EnumerateObject().Count() == 2 &&
            sku.EnumerateObject().All(p => p.Name is "family" or "name") &&
            sku.GetProperty("family").GetString() == "A" &&
            string.Equals(sku.GetProperty("name").GetString(), baseline.Sku.ToString(), StringComparison.OrdinalIgnoreCase));
        var policies = properties.GetProperty("accessPolicies");
        Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() <= 16);
        var projected = policies.EnumerateArray().Select(policy =>
        {
            Require(policy.ValueKind == JsonValueKind.Object &&
                policy.EnumerateObject().All(p => p.Name is "tenantId" or "objectId" or "applicationId" or "permissions"));
            var permissions = policy.GetProperty("permissions");
            Require(permissions.ValueKind == JsonValueKind.Object &&
                permissions.EnumerateObject().All(p => p.Name is "secrets" or "keys" or "certificates" or "storage"));
            foreach (string other in new[] { "keys", "certificates", "storage" })
                Require(!permissions.TryGetProperty(other, out var array) ||
                    array.ValueKind == JsonValueKind.Array && array.GetArrayLength() == 0);
            var secrets = permissions.GetProperty("secrets");
            Require(secrets.ValueKind == JsonValueKind.Array && secrets.GetArrayLength() <= 8);
            var selectedPermissions = secrets.EnumerateArray().Select(value =>
            {
                Require(value.ValueKind == JsonValueKind.String);
                Require(Enum.TryParse<SecretPermission>(value.GetString(), true, out var permission) &&
                    Enum.IsDefined(permission) &&
                    permission.ToString().Equals(value.GetString(), StringComparison.OrdinalIgnoreCase));
                return permission;
            }).ToArray();
            Require(selectedPermissions.Distinct().Count() == selectedPermissions.Length);
            return new E.Policy(policy.GetProperty("tenantId").GetGuid(), policy.GetProperty("objectId").GetGuid(),
                selectedPermissions, policy.TryGetProperty("applicationId", out var application) &&
                    application.ValueKind != JsonValueKind.Null ? application.GetGuid() : null);
        }).ToArray();
        var access = properties.GetProperty("publicNetworkAccess");
        Require(access.ValueKind == JsonValueKind.String && access.GetString() is "Enabled" or "Disabled");
        var configuration = Snapshot(new E.Configuration(row.GetProperty("location").GetString()!,
            properties.GetProperty("tenantId").GetGuid(), baseline.Sku,
            properties.GetProperty("enableRbacAuthorization").GetBoolean(),
            properties.GetProperty("enablePurgeProtection").GetBoolean(),
            properties.GetProperty("softDeleteRetentionInDays").GetInt32(),
            access.GetString() == "Enabled", projected));
        Require(E.SameConfiguration(configuration, baseline));
        return new(new(row.GetProperty("id").GetString()!, NativeProvisioningState.Succeeded,
            configuration.Rbac, configuration.PurgeProtection, configuration.RetentionDays),
            configuration, vaultUri!, createMode);
    }

    private static void VaultGroupShape(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in node.EnumerateObject())
            {
                Require(names.Count < 128 && names.Add(property.Name));
                VaultGroupShape(property.Value);
            }
        }
        else if (node.ValueKind == JsonValueKind.Array)
        {
            Require(node.GetArrayLength() <= 10000);
            foreach (var value in node.EnumerateArray()) VaultGroupShape(value);
        }
        else if (node.ValueKind == JsonValueKind.String) Require(node.GetString()!.Length <= 8192);
    }

    private M.PrivateLinkRow PrivateLinkCollection(Session session, JsonElement root)
    {
        var source = privateConnectionSource;
        Require(source is not null);
        Unique(root);
        Require(IsPrivateLinkList(session.Selector) && root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().All(p => p.Name is "value" or "nextLink") &&
            (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
        var values = root.GetProperty("value");
        Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 1);
        var row = values[0];
        Require(row.ValueKind == JsonValueKind.Object &&
            Encoding.UTF8.GetByteCount(row.GetRawText()) <= source.InventoryLimits.MaximumRowBytes &&
            row.EnumerateObject().All(p => p.Name is "id" or "name" or "type" or "properties") &&
            row.GetProperty("id").GetString() == session.Plan!.VaultId + "/privateLinkResources/vault" &&
            row.GetProperty("name").GetString() == "vault" &&
            row.GetProperty("type").GetString() == "Microsoft.KeyVault/vaults/privateLinkResources");
        var properties = row.GetProperty("properties");
        Require(properties.ValueKind == JsonValueKind.Object &&
            properties.EnumerateObject().All(p => p.Name is "groupId" or "requiredMembers" or "requiredZoneNames") &&
            properties.GetProperty("groupId").GetString() == "vault");
        return new(row.GetProperty("name").GetString()!, properties.GetProperty("groupId").GetString(),
            Strings("requiredMembers"), Strings("requiredZoneNames"));

        string[] Strings(string name)
        {
            var array = properties.GetProperty(name);
            Require(array.ValueKind == JsonValueKind.Array && array.GetArrayLength() <= 256);
            var strings = array.EnumerateArray().Select(value =>
            {
                Require(value.ValueKind == JsonValueKind.String && value.GetString()!.Length <= 8192);
                return value.GetString()!;
            }).ToArray();
            Require(strings.Distinct(StringComparer.OrdinalIgnoreCase).Count() == strings.Length);
            return strings;
        }
    }

    private static bool SameLink(M.PrivateLinkRow left, M.PrivateLinkRow right) =>
        left.Name == right.Name && left.GroupId == right.GroupId &&
        left.RequiredMembers.SequenceEqual(right.RequiredMembers) &&
        left.RequiredZoneNames.SequenceEqual(right.RequiredZoneNames);

    private static M.ConnectionRow PrivateCollection(Session session, JsonElement root)
    {
        Unique(root);
        Require(root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().All(p => p.Name is "value" or "nextLink") &&
            (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
        var values = root.GetProperty("value");
        Require(values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 1);
        // This source is a closed singleton profile. Reject all continuation
        // before either actual parser sees these same bytes or can send again.
        return PrivateChild(session, values[0]);
    }

    private static M.ConnectionRow PrivateChild(Session session, JsonElement root)
    {
        Unique(root);
        Require(root.ValueKind == JsonValueKind.Object &&
            root.EnumerateObject().All(p => p.Name is "id" or "name" or "type" or "properties" or "etag" or "systemData") &&
            root.GetProperty("id").GetString() == session.ConnectionId &&
            root.GetProperty("name").GetString() == session.ConnectionId!.Split('/')[^1] &&
            root.GetProperty("type").GetString() == "Microsoft.KeyVault/vaults/privateEndpointConnections");
        var properties = root.GetProperty("properties");
        Require(properties.ValueKind == JsonValueKind.Object &&
            properties.EnumerateObject().All(p => p.Name is "privateEndpoint" or "privateLinkServiceConnectionState" or "provisioningState") &&
            properties.GetProperty("provisioningState").GetString() == "Succeeded");
        var endpoint = properties.GetProperty("privateEndpoint");
        var state = properties.GetProperty("privateLinkServiceConnectionState");
        Require(endpoint.ValueKind == JsonValueKind.Object && endpoint.EnumerateObject().Count() == 1 &&
            endpoint.GetProperty("id").GetString() == session.Plan!.PrivateEndpoint!.EndpointId &&
            state.ValueKind == JsonValueKind.Object &&
            state.EnumerateObject().All(p => p.Name is "status" or "description" or "actionsRequired") &&
            state.GetProperty("status").GetString() == "Pending");
        foreach (string optional in new[] { "description", "actionsRequired" })
            if (state.TryGetProperty(optional, out var value))
                Require(value.ValueKind is JsonValueKind.String or JsonValueKind.Null);
        return new(root.GetProperty("name").GetString()!, PrivateConnectionState.Pending, NativeProvisioningState.Succeeded)
        {
            ResourceId = root.GetProperty("id").GetString(),
            PrivateEndpointId = endpoint.GetProperty("id").GetString()
        };
    }

    private sealed class ObservationTransport(VaultReadFixtureObserverService service, HttpPipelineTransport inner)
        : HttpPipelineTransport
    {
        public override Request CreateRequest()
        {
            lock (service.gate)
            {
                Require(!service.disposed && service.observation.Value is not null);
                service.provisioner.CheckVaultRead(service.observation.Value);
                if (IsVaultGroupList(service.observation.Value.Plan.Selector) ||
                    IsVaultSubscriptionList(service.observation.Value.Plan.Selector) ||
                    IsDeletedList(service.observation.Value.Plan.Selector))
                {
                    var loan = service.observation.Value;
                    Require(service.sessions.TryGetValue(loan.Plan.Selector.Nonce, out var session) &&
                        ReferenceEquals(session.Plan, loan.Plan) && !session.Closed && session.Active == 1 &&
                        session.GroupWindow is not null && ReferenceEquals(session.GroupWindow.Binding, session.Binding) &&
                        session.GroupRequest is null);
                    return session.GroupRequest = inner.CreateRequest();
                }
                return inner.CreateRequest();
            }
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            var loan = service.observation.Value ?? throw Failure();
            bool name = IsName(loan.Plan.Selector);
            bool group = IsVaultGroupList(loan.Plan.Selector) || IsVaultSubscriptionList(loan.Plan.Selector) ||
                IsDeletedList(loan.Plan.Selector);
            string id = IsDeletedList(loan.Plan.Selector) ? service.DeletedListPath() :
                IsVaultSubscriptionList(loan.Plan.Selector) ? service.SubscriptionListPath() :
                group ? service.GroupListPath() : name ? NamePath(loan.Plan) :
                IsDeleted(loan.Plan.Selector) ? loan.Plan.DeletedId : loan.Plan.VaultId;
            var content = message.Request.Content;
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            List<byte[]> buffers;
            List<IDisposable> storage;
            Session current;
            lock (service.gate)
            {
                Require(service.sessions.TryGetValue(loan.Plan.Selector.Nonce, out var session) &&
                    ReferenceEquals(session.Plan, loan.Plan) && session.Active == 1 &&
                    ReferenceEquals(service.observation.Value, loan));
                buffers = session.ObservationBuffers;
                storage = session.ObservationStorage;
                current = session;
                if (group)
                    Require(!session.Closed && ReferenceEquals(session.GroupRequest, message.Request) &&
                        session.GroupWindow is not null && ++session.GroupSends == 1);
            }
            ValidateRequest(message, id, name);
            ReadOnlyMemory<byte> originalBody = default;
            if (name)
            {
                originalBody = await service.SnapshotNameRequest(message, loan.Plan, buffers).ConfigureAwait(false);
                Require(ReferenceEquals(content, message.Request.Content) &&
                    headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                storage.Add(content!);
                content = RequestContent.Create(new BinaryData(originalBody));
                storage.Add(content);
                message.Request.Content = content;
            }
            Task send;
            lock (service.gate)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(!service.disposed && ReferenceEquals(service.observation.Value, loan) &&
                    (!group || !current.Closed && ReferenceEquals(current.GroupRequest, message.Request)) &&
                    ReferenceEquals(content, message.Request.Content) &&
                    headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                ValidateRequest(message, id, name);
                service.provisioner.CheckVaultRead(loan);
                if (group) message.BufferResponse = false;
                send = inner.ProcessAsync(message).AsTask();
            }
            try { await send.ConfigureAwait(false); }
            finally { if (group && message.HasResponse) storage.Add(message.Response); }
            ValidateRequest(message, id, name);
            if (name)
            {
                var currentBody = await service.SnapshotNameRequest(message, loan.Plan, buffers).ConfigureAwait(false);
                Require(originalBody.Span.SequenceEqual(currentBody.Span));
            }
            Require(ReferenceEquals(content, message.Request.Content) &&
                headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
            if (group)
            {
                lock (service.gate)
                {
                    message.CancellationToken.ThrowIfCancellationRequested();
                    Require(!service.disposed && !current.Closed &&
                        ReferenceEquals(current.GroupRequest, message.Request) &&
                        ReferenceEquals(service.observation.Value, loan));
                    service.provisioner.CheckVaultRead(loan);
                }
                await service.CaptureVaultGroup(current, message).ConfigureAwait(false);
            }
        }
    }

    private async Task CaptureVaultGroup(Session session, HttpMessage message)
    {
        Require(message.HasResponse && message.Response.Status == 200);
        var response = message.Response;
        long? declared = ValidateResponseHeaders(response);
        Require(response.Headers.TryGetValue("x-ms-request-id", out var requestId));
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        session.ObservationBuffers.Add(bytes);
        int count = 0;
        if (response.ContentStream is { } input)
        {
            session.ObservationStorage.Add(input);
            while (true)
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                int read = await input.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                count += read;
                Require(count <= limits.MaximumBodyBytes && count <= collectorLimits.MaximumResponseBytes);
            }
        }
        Require(count > 0 && count <= collectorLimits.MaximumResponseBytes && (declared is null || declared == count));
        using (var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 }))
        {
            if (IsDeletedList(session.Selector))
                session.RawDeletedCollection = DeletedVaultCollection(session, document.RootElement);
            else session.RawGroup = VaultGroupCollection(session, document.RootElement);
        }
        session.RawGroupRequestId = requestId;
        message.CancellationToken.ThrowIfCancellationRequested();
        var buffered = new MemoryStream(bytes, 0, count, writable: false, publiclyVisible: true);
        session.ObservationStorage.Add(buffered);
        response.ContentStream = buffered;
    }

    private static string NamePath(P.Plan plan) =>
        plan.VaultId[..plan.VaultId.IndexOf("/resourceGroups/", StringComparison.Ordinal)] +
        "/providers/Microsoft.KeyVault/checkNameAvailability";

    private async Task<ReadOnlyMemory<byte>> SnapshotNameRequest(HttpMessage message, P.Plan plan, List<byte[]> buffers)
    {
        Require(IsName(plan.Selector));
        ValidateRequest(message, NamePath(plan), name: true);
        var content = message.Request.Content!;
        byte[] bytes = new byte[limits.MaximumRequestBytes];
        buffers.Add(bytes);
        using var sink = new MemoryStream(bytes, 0, bytes.Length, writable: true, publiclyVisible: true);
        await content.WriteToAsync(sink, message.CancellationToken).ConfigureAwait(false);
        int count = checked((int)sink.Position);
        Require(count > 0 && count <= limits.MaximumRequestBytes &&
            ReferenceEquals(content, message.Request.Content));
        if (message.Request.Headers.TryGetValue("Content-Length", out var length))
            Require(int.TryParse(length, NumberStyles.None, CultureInfo.InvariantCulture, out int declared) &&
                declared == count);
        using var document = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 });
        var body = document.RootElement;
        Unique(body);
        Require(body.ValueKind == JsonValueKind.Object && body.EnumerateObject().Count() == 2 &&
            body.GetProperty("name").ValueKind == JsonValueKind.String &&
            body.GetProperty("name").GetString() == plan.VaultName &&
            body.GetProperty("type").ValueKind == JsonValueKind.String &&
            body.GetProperty("type").GetString() == "Microsoft.KeyVault/vaults");
        return bytes.AsMemory(0, count);
    }

    private static void ValidateRequest(HttpMessage message, string id, bool name = false)
    {
        Require(message.Request.Method == (name ? RequestMethod.Post : RequestMethod.Get) &&
            (name ? message.Request.Content is not null : message.Request.Content is null) &&
            message.Request.Uri.ToUri().OriginalString == M.ArmOrigin + id + "?api-version=" + M.Revision &&
            message.Request.Headers.TryGetValue("Authorization", out var authorization) &&
            authorization.StartsWith("Bearer ", StringComparison.Ordinal) && Text(authorization[7..], 16384));
        var headers = message.Request.Headers.ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => Text(h.Name, 128) && Text(h.Value, 16384)) &&
            !message.Request.Headers.Contains("Content-Encoding") && !message.Request.Headers.Contains("Transfer-Encoding") &&
            (name || !message.Request.Headers.Contains("Content-Length")));
        if (name)
            Require(message.Request.Headers.TryGetValue("Content-Type", out var type) &&
                type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
        if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
    }

    private long? ValidateResponseHeaders(Response response)
    {
        var headers = response.Headers.ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => Text(h.Name, 128) && Text(h.Value, 16384)) &&
            !new[] { "Location", "Operation-Location", "Azure-AsyncOperation", "Retry-After",
                "Content-Encoding", "Transfer-Encoding", "WWW-Authenticate" }.Any(n => response.Headers.TryGetValue(n, out _)) &&
            response.Headers.TryGetValue("x-ms-request-id", out var id) && Text(id, 128) &&
            response.Headers.TryGetValue("Content-Type", out var type) &&
            type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
        if (!response.Headers.TryGetValue("Content-Length", out var text)) return null;
        Require(long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
            length >= 0 && length <= limits.MaximumBodyBytes);
        return length;
    }

    private void ValidateSuccess(SelectedCall call, JsonElement root)
    {
        if (IsDeletedList(call.Session.Selector))
        {
            Require(call.Scope is SubscriptionScope && call.Session.DeletedBaseline is not null);
            call.RawDeleted = DeletedVaultCollection(call.Session, root);
            Require(call.RawDeleted == call.Session.DeletedBaseline);
            return;
        }
        if (IsVaultSubscriptionList(call.Session.Selector))
        {
            Require(call.Scope is SubscriptionScope && call.Session.GroupBaseline is not null);
            call.RawGroup = VaultGroupCollection(call.Session, root);
            Require(SameGroup(call.RawGroup, call.Session.GroupBaseline));
            return;
        }
        if (IsVaultGroupList(call.Session.Selector))
        {
            Require(call.Scope is ResourceGroupScope && call.Session.GroupBaseline is not null);
            call.RawGroup = VaultGroupCollection(call.Session, root);
            Require(SameGroup(call.RawGroup, call.Session.GroupBaseline));
            return;
        }
        if (IsPrivateLinkList(call.Session.Selector))
        {
            Require(call.Scope is VaultScope && call.Session.LinkBaseline is not null);
            call.RawLink = PrivateLinkCollection(call.Session, root);
            Require(SameLink(call.RawLink, call.Session.LinkBaseline));
            return;
        }
        if (IsPrivate(call.Session.Selector))
        {
            Require(IsPrivateList(call.Session.Selector) ? call.Scope is VaultScope : call.Scope is PrivateConnectionScope);
            call.RawConnection = IsPrivateList(call.Session.Selector)
                ? PrivateCollection(call.Session, root) : PrivateChild(call.Session, root);
            Require(call.RawConnection == call.Session.ConnectionBaseline);
            return;
        }
        if (IsName(call.Session.Selector))
        {
            Require(root.ValueKind == JsonValueKind.Object &&
                root.GetProperty("nameAvailable").ValueKind is JsonValueKind.True or JsonValueKind.False);
            call.RawNameAvailable = root.GetProperty("nameAvailable").GetBoolean();
            Require(call.RawNameAvailable == call.Session.NameBaseline);
            return;
        }
        if (IsDeleted(call.Session.Selector))
        {
            Require(call.Scope is DeletedVaultScope &&
                root.GetProperty("id").GetString() == call.Loan.Plan.DeletedId &&
                root.GetProperty("type").GetString() == "Microsoft.KeyVault/locations/deletedVaults" &&
                (!root.TryGetProperty("nextLink", out var deletedNext) || deletedNext.ValueKind == JsonValueKind.Null));
            if (root.TryGetProperty("name", out var deletedName))
                Require(deletedName.GetString() == call.Loan.Plan.VaultName);
            var deletedProperties = root.GetProperty("properties");
            Require(deletedProperties.GetProperty("vaultId").GetString() == call.Loan.Plan.VaultId &&
                deletedProperties.GetProperty("location").GetString() == host.Location &&
                deletedProperties.GetProperty("tags").GetProperty("secretkit-fixture").GetString() ==
                    call.Session.Selector.Nonce.ToString("N") &&
                deletedProperties.GetProperty("deletionDate").TryGetDateTimeOffset(out var deletedOn) &&
                deletedProperties.GetProperty("scheduledPurgeDate").TryGetDateTimeOffset(out var purgeOn) &&
                purgeOn - deletedOn == TimeSpan.FromDays(baseline.RetentionDays) &&
                deletedProperties.GetProperty("purgeProtectionEnabled").ValueKind == JsonValueKind.False);
            // Project only the actual validated response body. The scope fixes
            // its subscription/name; neither it nor setup supplies timestamps.
            string[] id = root.GetProperty("id").GetString()!.Split('/');
            call.RawDeleted = new(Guid.Parse(id[2]), deletedProperties.GetProperty("location").GetString()!,
                id[^1], deletedProperties.GetProperty("deletionDate").GetDateTimeOffset(),
                deletedProperties.GetProperty("scheduledPurgeDate").GetDateTimeOffset(),
                deletedProperties.GetProperty("purgeProtectionEnabled").GetBoolean());
            Require(call.RawDeleted == call.Session.DeletedBaseline);
            return;
        }
        Require(root.GetProperty("id").GetString()?.Equals(call.Loan.Plan.VaultId, StringComparison.OrdinalIgnoreCase) == true &&
            root.GetProperty("location").GetString() == host.Location &&
            root.GetProperty("tags").GetProperty("secretkit-fixture").GetString() == call.Session.Selector.Nonce.ToString("N") &&
            (!root.TryGetProperty("nextLink", out var next) || next.ValueKind == JsonValueKind.Null));
        if (root.TryGetProperty("name", out var name)) Require(name.GetString() == call.Loan.Plan.VaultName);
        if (root.TryGetProperty("type", out var type)) Require(type.GetString() == "Microsoft.KeyVault/vaults");
        var properties = root.GetProperty("properties");
        string expectedUri = "https://" + call.Loan.Plan.VaultName + ".vault.azure.net";
        string? vaultUri = properties.GetProperty("vaultUri").GetString();
        Require(properties.GetProperty("tenantId").GetGuid() == host.TenantId &&
            (vaultUri == expectedUri || vaultUri == expectedUri + "/") &&
            properties.GetProperty("provisioningState").GetString() == "Succeeded" &&
            properties.GetProperty("enableSoftDelete").GetBoolean() &&
            properties.GetProperty("sku").GetProperty("family").GetString() == "A" &&
            string.Equals(properties.GetProperty("sku").GetProperty("name").GetString(),
                baseline.Sku.ToString(), StringComparison.OrdinalIgnoreCase) &&
            properties.GetProperty("enableRbacAuthorization").GetBoolean() == baseline.Rbac &&
            properties.GetProperty("enablePurgeProtection").GetBoolean() == baseline.PurgeProtection &&
            properties.GetProperty("softDeleteRetentionInDays").GetInt32() == baseline.RetentionDays &&
            properties.GetProperty("publicNetworkAccess").GetString() == (baseline.PublicNetworkAccess ? "Enabled" : "Disabled"));
        var policies = properties.GetProperty("accessPolicies");
        Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() <= 16);
        var projected = policies.EnumerateArray().Select(p =>
        {
            var permissions = p.GetProperty("permissions");
            foreach (string other in new[] { "keys", "certificates", "storage" })
                Require(!permissions.TryGetProperty(other, out var values) ||
                    values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 0);
            var secrets = permissions.GetProperty("secrets");
            Require(secrets.ValueKind == JsonValueKind.Array && secrets.GetArrayLength() <= 8);
            var selectedPermissions = secrets.EnumerateArray().Select(v =>
            {
                Require(Enum.TryParse<SecretPermission>(v.GetString(), true, out var permission) &&
                    Enum.IsDefined(permission) && permission.ToString().Equals(v.GetString(), StringComparison.OrdinalIgnoreCase));
                return permission;
            }).ToArray();
            Require(selectedPermissions.Distinct().Count() == selectedPermissions.Length);
            return new E.Policy(p.GetProperty("tenantId").GetGuid(), p.GetProperty("objectId").GetGuid(),
                selectedPermissions, p.TryGetProperty("applicationId", out var application) &&
                    application.ValueKind != JsonValueKind.Null ? application.GetGuid() : null);
        }).ToArray();
        Require(E.SamePolicies(projected, baseline.Policies));
    }

    private async Task<HttpResponseMessage> Release(FixtureSelector selector, CancellationToken token)
    {
        ValidateSelector(selector);
        Session session;
        Task borrowers;
        bool closed = true;
        lock (gate)
        {
            Require(!disposed);
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(sessions.Count < 32);
                session = new(selector);
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Closed = true;
            // A pure root predicate runs under the journal lock. No host
            // callback, plan lock or readiness reconstruction occurs there.
            try { Close(session); }
            catch (Exception) { closed = false; }
            session.Releasing = true;
            borrowers = session.Active == 0 ? Task.CompletedTask : session.Drained.Task;
        }
        try
        {
            try { session.Stop.Cancel(); }
            catch (Exception) { closed = false; }
            await borrowers.ConfigureAwait(false);
            Require(closed);
            token.ThrowIfCancellationRequested();
            var snapshot = Journal.Read(owner, selector);
            if (snapshot.Idle)
            {
                if (IsPrivate(selector) && snapshot.Resources.Length != 0)
                {
                    Require(privateConnectionSource is not null);
                    var source = privateConnectionSource;
                    session.Endpoints ??= new(provisioner, source.EndpointSetup, source.EndpointReader,
                        source.VaultConnectionReader, source.ResourceLimits, source.InventoryLimits, time);
                    var parent = session.Plan ?? provisioner.OpenCleanupPlan(owner, selector);
                    var dependencies = await session.Endpoints.CleanupAsync(parent, token).ConfigureAwait(false);
                    snapshot = dependencies.Journal;
                    if (dependencies.State == PrivateEndpointFixtureProvisioner.CleanupState.DependenciesAbsent)
                        snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                            cancellationToken: token, privateEndpointCleanup: session.Endpoints).ConfigureAwait(false)).Journal;
                }
                else snapshot = (await provisioner.ReleaseAsync(owner, selector, purge: true,
                    cancellationToken: token, requireOriginalDeletedReadRoot: IsDeleted(selector)).ConfigureAwait(false)).Journal;
            }
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private RoleFixtureJournal.Snapshot Close(Session session) =>
        Journal.Close(owner, session.Selector, snapshot => Root(snapshot, session));

    private bool Root(RoleFixtureJournal.Snapshot snapshot, Session session)
    {
        if (IsPrivate(session.Selector)) return PrivateRoot(snapshot, session);
        if (snapshot.Owner != owner || snapshot.Selector != session.Selector || snapshot.PrivateEndpoint is not null)
            return false;
        if (snapshot.Resources.Length == 0) return session.Plan is null;
        if (snapshot.Resources.Length != 3 || snapshot.Resources.Any(r => r.Borrowed || r.SelectedAttempted) ||
            session.Plan is not null && snapshot.LeaseId != session.Plan.LeaseId) return false;
        string prefix = $"/subscriptions/{host.SubscriptionId:D}/resourceGroups/{host.ResourceGroup}/providers/Microsoft.KeyVault/vaults/";
        var vault = snapshot.Resources.SingleOrDefault(r => r.Id.StartsWith(prefix, StringComparison.Ordinal) &&
            r.Id[prefix.Length..] is { Length: 24 } name && name.StartsWith("skv", StringComparison.Ordinal) &&
            name[3..].All(char.IsAsciiHexDigit));
        if (vault is null || vault.CleanupOnly || session.Plan is not null && vault.Id != session.Plan.VaultId) return false;
        string deleted = $"/subscriptions/{host.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{host.Location}/deletedVaults/" +
            vault.Id[prefix.Length..];
        return snapshot.Resources.Count(r => r.Id == vault.Id + "/secrets/" + P.Canary && r.CleanupOnly &&
                !r.CreateAttempted && !r.DeleteAttempted && r.ActiveDispatch == Guid.Empty) == 1 &&
            snapshot.Resources.Count(r => r.Id == deleted && (IsDeleted(session.Selector)
                ? !r.CleanupOnly
                : r.CleanupOnly && !r.CreateAttempted)) == 1 &&
            (!IsDeleted(session.Selector) || !vault.DeleteAttempted);
    }

    private bool PrivateRoot(RoleFixtureJournal.Snapshot snapshot, Session session)
    {
        if (snapshot.Owner != owner || snapshot.Selector != session.Selector) return false;
        if (snapshot.Resources.Length == 0) return session.Plan is null && snapshot.PrivateEndpoint is null;
        if (snapshot.PrivateEndpoint is not { } slot || privateConnectionSource is null ||
            snapshot.Resources.Length != 5 || snapshot.Resources.Any(r => r.SelectedAttempted) ||
            slot.ApprovalSettledDispatch != Guid.Empty ||
            session.Plan is not null && (snapshot.LeaseId != session.Plan.LeaseId ||
                slot.Declaration != session.Plan.PrivateEndpoint ||
                session.Plan.Manifest.Any(m => snapshot.Resources.Count(r =>
                    r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) != 1)))
            return false;
        var d = slot.Declaration;
        string name = d.VaultId.Split('/')[^1];
        string group = $"/subscriptions/{host.SubscriptionId:D}/resourceGroups/{host.ResourceGroup}";
        string deleted = $"/subscriptions/{host.SubscriptionId:D}/providers/Microsoft.KeyVault/locations/{host.Location}/deletedVaults/{name}";
        if (name.Length != 24 || !name.StartsWith("skv", StringComparison.Ordinal) || !name[3..].All(char.IsAsciiHexDigit) ||
            d.VaultId != group + "/providers/Microsoft.KeyVault/vaults/" + name ||
            d.EndpointId != group + "/providers/Microsoft.Network/privateEndpoints/" + name + "-pe" ||
            d.ExpectedNicId != group + "/providers/Microsoft.Network/networkInterfaces/" + name + "-nic" ||
            d.NetworkConnectionName != name + "-link" || d.OwnerTagName != "secretkit-fixture" ||
            d.OwnerTagValue != session.Selector.Nonce.ToString("N") ||
            d.BorrowedSubnetId != privateConnectionSource.BorrowedSubnetId)
            return false;
        RoleFixtureJournal.Resource[] manifest =
        [
            new(d.VaultId, false), new(d.VaultId + "/secrets/" + P.Canary, false),
            new(deleted, false, CleanupOnly: true), new(d.EndpointId, false), new(d.BorrowedSubnetId, true)
        ];
        if (!manifest.All(m => snapshot.Resources.Count(r =>
            r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) ||
            snapshot.Resources.Single(r => r.Id == deleted).CreateAttempted ||
            snapshot.Resources.Single(r => r.Id == d.VaultId + "/secrets/" + P.Canary).DeleteAttempted ||
            snapshot.Resources.Any(r => r.Borrowed &&
                (r.CreateAttempted || r.DeleteAttempted || r.Absent || r.InvocationTerminated || r.ActiveDispatch != Guid.Empty)))
            return false;
        if (slot.Connection is { } child)
        {
            string prefix = d.VaultId + "/privateEndpointConnections/";
            if (!child.Id.StartsWith(prefix, StringComparison.Ordinal) ||
                !Text(child.Id[prefix.Length..], 128) || child.Id[prefix.Length..].Contains('/') ||
                child.Borrowed || child.CleanupOnly || !child.CreateAttempted || child.DeleteAttempted ||
                child.SelectedAttempted || session.ConnectionId is not null && session.ConnectionId != child.Id)
                return false;
        }
        return true;
    }

    private static string[] PrivateOwnedResources(RoleFixtureJournal.Snapshot snapshot)
    {
        var slot = snapshot.PrivateEndpoint!;
        return snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).Append(slot.Declaration.ExpectedNicId)
            .Concat(slot.Connection is null ? [] : new[] { slot.Connection.Id }).ToArray();
    }

    private static RoleFixtureRelease.Measurement ReleaseMeasurement(Session session, RoleFixtureJournal.Snapshot snapshot)
    {
        Require(snapshot.Closing && snapshot.Selector == session.Selector);
        if (IsPrivate(session.Selector) && snapshot.PrivateEndpoint is { } slot)
        {
            string[] resources = PrivateOwnedResources(snapshot);
            var provenAbsent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty)
                .Select(r => r.Id).ToList();
            if (snapshot.PrivateEndpointAbsent)
            {
                provenAbsent.Add(slot.Declaration.ExpectedNicId);
                if (slot.Connection is not null) provenAbsent.Add(slot.Connection.Id);
            }
            return new(session.Selector, true,
                session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty) +
                (slot.Connection is { ActiveDispatch: var dispatch } && dispatch != Guid.Empty ? 1 : 0),
                resources, snapshot.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(),
                provenAbsent.ToArray(), resources.Except(provenAbsent, StringComparer.OrdinalIgnoreCase).ToArray());
        }
        var owned = snapshot.Resources.Select(r => r.Id).ToArray();
        var absent = snapshot.Resources.Where(r => r.Absent && r.ActiveDispatch == Guid.Empty).Select(r => r.Id).ToArray();
        return new(session.Selector, true, session.Active + snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty),
            owned, [], absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private Session Find(Guid nonce, Guid lease)
    {
        Require(sessions.TryGetValue(nonce, out var session) && !disposed && !session.Closed &&
            session.Lease is not null && session.Plan is not null && session.Plan.LeaseId == lease);
        return session;
    }
    private static E.Configuration Snapshot(E.Configuration configuration)
    {
        Require(configuration is not null && configuration.Policies is { Length: <= 16 } &&
            configuration.Policies.All(p => p is not null && p.Permissions is { Length: <= 8 } &&
                p.Permissions.Distinct().Count() == p.Permissions.Length));
        var copy = configuration with
        {
            Policies = configuration.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray()
        };
        _ = copy.Build();
        Require(E.SamePolicies(copy.Policies, copy.Policies));
        return copy;
    }
    private static E.Configuration Project(M.ConfigurationMetadata c) => new(c.Location, c.TenantId, c.Sku,
        c.Rbac, c.PurgeProtection, c.RetentionDays, c.PublicNetworkAccess,
        c.Policies.Select(p => new E.Policy(p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
    private bool OwnsPrepared(Session session) => IsDeletedList(session.Selector)
        ? provisioner.OwnsPreparedDeletedVaultListReadPlan(session.Plan!)
        : IsDeleted(session.Selector)
        ? provisioner.OwnsPreparedDeletedVaultReadPlan(session.Plan!)
        : IsName(session.Selector) ? provisioner.OwnsPreparedVaultNameReadPlan(session.Plan!)
        : IsVaultGroupList(session.Selector) ? provisioner.OwnsPreparedVaultGroupListReadPlan(session.Plan!)
        : IsVaultSubscriptionList(session.Selector) ? provisioner.OwnsPreparedVaultSubscriptionListReadPlan(session.Plan!)
        : provisioner.OwnsPreparedPlan(session.Plan!);
    private static bool IsVaultGroupList(FixtureSelector selector) => P.VaultGroupListReadSelector(selector);
    private static bool IsVaultSubscriptionList(FixtureSelector selector) => P.VaultSubscriptionListReadSelector(selector);
    private static bool IsName(FixtureSelector selector) =>
        selector.Operation == M.Operation(M.QueryKind.CheckNameAvailability);
    private static bool IsDeleted(FixtureSelector selector) =>
        selector.Operation == M.Operation(M.QueryKind.GetDeletedVault) && selector.Variant == "selector.exact" ||
        IsDeletedList(selector);
    private static bool IsDeletedList(FixtureSelector selector) => P.DeletedVaultListReadSelector(selector);
    private static bool IsPrivate(FixtureSelector selector) => P.PrivateConnectionReadSelector(selector);
    private static bool IsPrivateList(FixtureSelector selector) =>
        selector.Operation == M.Operation(M.QueryKind.ListPrivateConnections) && selector.Variant == "collection.bounded";
    private static bool IsPrivateLinkList(FixtureSelector selector) =>
        selector.Operation == M.Operation(M.QueryKind.ListPrivateLinkResources) && selector.Variant == "collection.bounded";
    private static bool SameDeleted(DeletedVaultObservation observation, E.DeletedVaultRow row) =>
        observation.Scope.Subscription.SubscriptionId == row.SubscriptionId &&
        observation.Scope.Location == row.Location && observation.Scope.VaultName == row.Name &&
        observation.DeletedOn == row.DeletedOn && observation.ScheduledPurgeOn == row.ScheduledPurgeOn &&
        observation.PurgeProtected == row.PurgeProtected;
    private static void ValidateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)) &&
            (selector.Operation == M.Operation(M.QueryKind.GetVault) || IsDeleted(selector) || IsName(selector) ||
                IsPrivate(selector) || IsVaultGroupList(selector) || IsVaultSubscriptionList(selector)) &&
            (IsPrivate(selector) || IsVaultGroupList(selector) || IsVaultSubscriptionList(selector) || IsDeletedList(selector) ||
                selector.Variant == "selector.exact") &&
            selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary" or "lost-response-no-replay");
    private static bool Text([NotNullWhen(true)] string? value, int maximum) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= maximum && !value.Any(char.IsControl);
    private bool Authenticate(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not { Scheme: "Bearer", Parameter: { Length: > 0 and <= 8192 } supplied })
            return false;
        char[] expected = capability.ExportCharacters();
        byte[] left = Encoding.UTF8.GetBytes(expected), right = Encoding.UTF8.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(SHA256.HashData(left), SHA256.HashData(right)); }
        finally { Array.Clear(expected); CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
    }
    private async Task<JsonDocument> ReadBody(HttpRequestMessage request, CancellationToken token)
    {
        Require(request.Content?.Headers.ContentLength is >= 0 &&
            request.Content.Headers.ContentLength <= limits.MaximumRequestBytes &&
            request.Content.Headers.ContentType?.MediaType == "application/json" &&
            request.Content.Headers.ContentEncoding.Count == 0);
        byte[] bytes = new byte[limits.MaximumRequestBytes + 1];
        try
        {
            using var stream = await request.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            int length = 0, count;
            while (length < bytes.Length && (count = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false)) != 0)
                length += count;
            Require(length <= limits.MaximumRequestBytes && length == request.Content.Headers.ContentLength);
            var reader = new Utf8JsonReader(bytes.AsSpan(0, length), new JsonReaderOptions { MaxDepth = 32 });
            var document = JsonDocument.ParseValue(ref reader);
            try { Require(!reader.Read()); Unique(document.RootElement); return document; }
            catch { document.Dispose(); throw; }
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void Unique(JsonElement node)
    {
        if (node.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in node.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
        }
        else if (node.ValueKind == JsonValueKind.Array)
            foreach (var item in node.EnumerateArray()) Unique(item);
    }
    private HttpResponseMessage Reply<T>(T value)
    {
        byte[] bytes = new byte[limits.MaximumBodyBytes];
        try
        {
            using var stream = new MemoryStream(bytes, 0, bytes.Length, writable: true);
            JsonSerializer.Serialize(stream, value, ManagementAdmission.Json);
            var content = new ByteArrayContent(bytes.AsSpan(0, checked((int)stream.Position)).ToArray());
            content.Headers.ContentType = new("application/json");
            return new(HttpStatusCode.OK) { Content = content };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{\"error\":\"vault-read-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static void Enter(Session session)
    {
        if (session.Active++ == 0) session.Drained = Signal();
    }
    private void Leave(Session session)
    {
        lock (gate) if (--session.Active == 0) session.Drained.TrySetResult();
    }
    private void EndRequest()
    {
        lock (gate) if (--active == 0 && disposed) drained.TrySetResult();
    }
    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = Signal();
            if (active == 0) drained.TrySetResult();
        }
        _ = Drain(completion);
        return new(completion.Task);
    }
    private async Task Drain(TaskCompletionSource completion)
    {
        bool closed = true;
        try
        {
            Session[] owned;
            lock (gate)
            {
                owned = sessions.Values.ToArray();
                foreach (var session in owned)
                {
                    session.Closed = true;
                    try { Close(session); }
                    catch (Exception) { closed = false; }
                }
            }
            foreach (var session in owned)
                try { session.Stop.Cancel(); }
                catch (Exception) { closed = false; }
            try { lifetime.Cancel(); }
            catch (Exception) { closed = false; }
            await drained.Task.ConfigureAwait(false);
            foreach (var session in owned)
                if (session.Endpoints is not null)
                    try { await session.Endpoints.DisposeAsync().ConfigureAwait(false); }
                    catch (Exception) { closed = false; }
            foreach (var session in owned) session.Stop.Dispose();
            lifetime.Dispose();
            Require(closed);
            completion.TrySetResult();
        }
        catch (Exception) { completion.TrySetException(Failure()); }
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("vault-read-source-unavailable");
    public override string ToString() => "[VaultReadFixtureObserverService]";
}
