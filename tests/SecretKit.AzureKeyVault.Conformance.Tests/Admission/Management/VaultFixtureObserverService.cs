using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using E = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using M = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;
using T = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultPolicyPermissionTrial;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Local, authenticated source composition, not provider qualification. The host
// owns every borrowed authority, transport, provisioner, metadata source and
// capability. A session owns only its trial, windows and retained invocation.
internal sealed partial class VaultFixtureObserverService : E.SelectedInvocation, IAsyncDisposable
{
    internal sealed record PrincipalSource(
        [property: JsonIgnore] T.PrincipalClaim Principal,
        [property: JsonIgnore] T.Authority Intended)
    {
        public override string ToString() => "[VaultPrincipalSource]";
    }
    internal sealed record WindowSource(
        [property: JsonIgnore] RoleFixtureJournal Journal,
        [property: JsonIgnore] VaultFixtureProvisioner Provisioner,
        [property: JsonIgnore] M Metadata,
        [property: JsonIgnore] PrincipalSource[] Principals,
        [property: JsonIgnore] T.Authority TrialDenied,
        [property: JsonIgnore] T.Authority TrialObserver,
        [property: JsonIgnore] HttpPipelineTransport SelectedTransport)
    {
        public override string ToString() => "[VaultWindowSource]";
    }
    internal sealed record Limits(int MaximumBodyBytes, int MaximumReplyBytes, TimeSpan Timeout);
    private static readonly JsonSerializerOptions Json = new(ManagementAdmission.Json)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    private readonly object gate = new();
    private readonly Uri origin;
    private readonly string owner, observerIdentity;
    private readonly SecretMaterial capability;
    private readonly VaultFixtureProvisioner.HostScope scope;
    private readonly E.Configuration baseline;
    private readonly PrincipalSource[] principals;
    private readonly WindowSource source = null!;
    private readonly SettingsSource? settingsSource;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly Dictionary<Guid, Session> sessions = [];
    private readonly AsyncLocal<SelectedCall?> current = new();
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TaskCompletionSource? disposal;
    private bool disposed;
    private int active;

    private sealed class Session(FixtureSelector selector)
    {
        internal readonly FixtureSelector Selector = selector;
        internal readonly CancellationTokenSource Stop = new();
        internal VaultFixtureProvisioner.Plan? Plan;
        internal E.Lease? Lease;
        internal M.Binding? Binding;
        internal M.Window? BeforeActive, BeforeDeleted, AfterActive, AfterDeleted;
        internal readonly List<PermissionWindow> Trials = [];
        internal Task? TrialDisposal;
        internal SelectedCall? Selected;
        internal SettingsCall? SettingsSelected;
        internal VaultFixtureProvisioner.SettingsLoan? SettingsLoan;
        internal SettingsObservation? SettingsBefore;
        internal SettingsSettlement? SettingsCompletion;
        internal readonly TaskCompletionSource SettingsDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal Guid Subscription;
        internal DateTimeOffset ArmedAt, BaselineAt;
        internal bool Closed, ArmClaimed, Armed, BeforeClaimed, BaselineReady, AfterClaimed, Releasing;
        internal int Active;
    }

    private sealed class PermissionWindow(T source, T.PrincipalClaim principal)
    {
        internal readonly T Source = source;
        internal readonly T.PrincipalClaim Principal = principal;
        internal T.Window? Window;
    }

    internal VaultFixtureObserverService(Uri origin, string owner, string observerIdentity, SecretMaterial capability,
        VaultFixtureProvisioner.HostScope scope, E.Configuration baseline,
        WindowSource source, Limits limits, TimeProvider? time = null)
    {
        Require(origin is
        {
            IsAbsoluteUri: true, Scheme: "https", AbsolutePath: "/",
            UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0
        } &&
            Text(owner, 128) && Text(observerIdentity, 128) && capability is not null &&
            scope is not null && scope.ExclusiveFixtureNamespace && scope.AllowPurge &&
            scope.SubscriptionId != Guid.Empty && scope.TenantId != Guid.Empty &&
            Segment(scope.ResourceGroup, 90) && Segment(scope.Location, 50) &&
            source is not null && source.Journal is not null && source.Provisioner is not null &&
            source.Metadata is not null && source.SelectedTransport is not null &&
            source.Principals is { Length: 1 or 2 } &&
            source.Principals.All(p => p is not null && p.Principal is not null &&
                p.Principal.TenantId == scope.TenantId && p.Principal.PrincipalId != Guid.Empty &&
                p.Principal.ApplicationId != Guid.Empty && Authority(p.Intended)) &&
            Authority(source.TrialDenied) && Authority(source.TrialObserver) &&
            limits is not null && limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.MaximumReplyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        principals = source.Principals.Select(p => new PrincipalSource(p.Principal with { }, p.Intended)).ToArray();
        Require(principals.Select(p => p.Principal.PrincipalId).Distinct().Count() == principals.Length);
        T.Authority[] authorities = [.. principals.Select(p => p.Intended), source.TrialDenied, source.TrialObserver];
        Require(authorities.Select(a => a.Label).Distinct(StringComparer.Ordinal).Count() == authorities.Length &&
            authorities.Select(a => a.Credential).Distinct(ReferenceEqualityComparer.Instance).Count() == authorities.Length &&
            authorities.Select(a => a.Transport).Distinct(ReferenceEqualityComparer.Instance).Count() == authorities.Length &&
            authorities.All(a => !ReferenceEquals(a.Transport, source.SelectedTransport)));
        this.baseline = Snapshot(baseline);
        Require(this.baseline.TenantId == scope.TenantId && this.baseline.Location == scope.Location &&
            !this.baseline.Rbac && !this.baseline.PurgeProtection && this.baseline.Policies.Length < 16 &&
            this.baseline.Policies.Length + principals.Length <= 16 &&
            this.baseline.Policies.All(p => principals.All(s => p.PrincipalId != s.Principal.PrincipalId ||
                p.TenantId == s.Principal.TenantId && p.ApplicationId == s.Principal.ApplicationId)));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability;
        this.scope = scope;
        this.source = source;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
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
            if (settingsSource is not null)
                return uri.AbsolutePath switch
                {
                    "/vault/prepare" => await PrepareSettings(body.RootElement.Deserialize<E.Prepare>(Json) ?? throw Failure(),
                        linked.Token).ConfigureAwait(false),
                    "/vault/arm" => ArmSettings(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure()),
                    "/vault/observe" => await ObserveSettings(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure(),
                        linked.Token).ConfigureAwait(false),
                    "/vault/release" => await ReleaseSettings(body.RootElement.Deserialize<FixtureSelector>(Json) ?? throw Failure(),
                        linked.Token).ConfigureAwait(false),
                    _ => Error(HttpStatusCode.NotFound)
                };
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
        var configured = Snapshot(input.Configuration);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            E.SameConfiguration(configured, baseline) &&
            (input.Selection.Variant == "policies.multiple") == (principals.Length == 2) &&
            (principals.Length == 2 || input.ApplicationId == (principals[0].Principal.ApplicationId ?? Guid.Empty) &&
                (input.Selection.Variant == "applicationId.value") == principals[0].Principal.ApplicationId.HasValue) &&
            input.IntendedPolicies is not null && input.IntendedPolicies.Length == principals.Length &&
            principals.Select((p, i) => Matches(input.IntendedPolicies[i], p.Principal, input.Selection)).All(m => m) &&
            (input.Selection.Variant switch
            {
                "change.Remove" => principals.All(s => baseline.Policies.Any(p => Matches(p, s.Principal, input.Selection))),
                "change.Replace" => principals.All(s => baseline.Policies.Any(p => p.PrincipalId == s.Principal.PrincipalId &&
                    !Matches(p, s.Principal, input.Selection))),
                _ => baseline.Policies.All(p => principals.All(s => p.PrincipalId != s.Principal.PrincipalId))
            }));
        Session session;
        lock (gate)
        {
            Require(!disposed && sessions.Count < 32 && !sessions.ContainsKey(input.Selection.Nonce));
            // Registration precedes journal/preparation and survives a lost reply.
            session = new(input.Selection) { Active = 1 };
            sessions.Add(input.Selection.Nonce, session);
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
        var material = new List<SecretMaterial>();
        try
        {
            var children = new List<VaultFixtureProvisioner.PolicyChildSpecification>();
            foreach (string name in ChildNames(principals.Length))
            {
                var value = RandomMaterial();
                material.Add(value);
                var preparation = name.Contains("restore", StringComparison.Ordinal) ||
                    name.Contains("set", StringComparison.Ordinal) ? VaultFixtureProvisioner.Preparation.Absent :
                    name.Contains("recover", StringComparison.Ordinal) || name.Contains("purge", StringComparison.Ordinal)
                        ? VaultFixtureProvisioner.Preparation.Deleted : VaultFixtureProvisioner.Preparation.Active;
                children.Add(new(name, preparation, value, name.Contains("restore", StringComparison.Ordinal)));
            }
            lock (gate)
            {
                Require(!session.Closed && !disposed);
                session.Plan = source.Provisioner.PlanFixture(owner, session.Selector,
                    VaultFixtureProvisioner.Preparation.Active, [], true, children.ToArray());
                var journal = source.Journal.Read(owner, session.Selector);
                Require(journal.LeaseId == session.Plan.LeaseId && journal.Resources.Length == children.Count + 3 &&
                    journal.Resources.All(r => !r.Borrowed));
            }
            using var canary = RandomMaterial();
            var prepared = await source.Provisioner.ProvisionAsync(session.Plan, canary, linked.Token).ConfigureAwait(false);
            Require(prepared.State == VaultFixtureProvisioner.State.Ready &&
                prepared.Configuration is not null && E.SameConfiguration(prepared.Configuration, baseline) &&
                prepared.CanarySha256 is { Length: 64 } && prepared.CanaryVersion is not null &&
                session.Plan.PolicyChildren.Count == children.Count && session.Plan.PolicyChildren.All(c => c.Prepared));
            lock (gate)
            {
                Require(!session.Closed && !disposed);
                var journal = source.Journal.Read(owner, session.Selector);
                Require(!journal.Closing && journal.Resources.Length == children.Count + 3 &&
                    journal.Resources.All(r => r.ActiveDispatch == Guid.Empty));
                session.Lease = new(new(session.Selector.Nonce, session.Plan.LeaseId, observerIdentity,
                    M.ArmOrigin, M.Revision, time.GetUtcNow(), journal.Resources.Select(r => r.Id).ToArray()),
                    session.Plan.VaultName, null, VaultFixtureProvisioner.Canary, prepared.CanarySha256,
                    Snapshot(baseline), PrivateConnectionState.Unknown);
                return Reply(session.Lease);
            }
        }
        finally
        {
            foreach (var value in material) value.Dispose();
            Leave(session);
        }
    }

    private HttpResponseMessage Arm(ObserveLease input)
    {
        lock (gate)
        {
            var session = Find(input.Nonce, input.LeaseId);
            Require(!session.ArmClaimed && input.SubscriptionId is null && input.Phase == "subscribe-before-trigger");
            session.ArmClaimed = true;
            var plan = session.Plan!;
            var binding = new M.Binding(session.Selector, plan.LeaseId, M.QueryKind.ChangeAccessPolicies,
                M.ReadKind.GetVault, scope.SubscriptionId, scope.ResourceGroup, scope.Location, plan.VaultName, null);
            session.Binding = binding;
            session.BeforeActive = source.Metadata.Arm(binding);
            session.BeforeDeleted = source.Metadata.Arm(binding with { Read = M.ReadKind.GetDeletedVault });
            session.AfterActive = source.Metadata.Arm(binding);
            session.AfterDeleted = source.Metadata.Arm(binding with { Read = M.ReadKind.GetDeletedVault });
            for (int i = 0; i < principals.Length; i++)
            {
                Require(!disposed && !session.Closed);
                var selected = principals[i];
                var trial = new PermissionWindow(new(source.Journal, selected.Principal, selected.Intended, source.TrialDenied,
                    new(limits.MaximumReplyBytes, Math.Min(16384, limits.MaximumReplyBytes), limits.MaximumReplyBytes,
                        65536, 128, 32, limits.Timeout), time, source.TrialObserver), selected.Principal);
                session.Trials.Add(trial);
                var copies = new List<IDisposable>();
                try
                {
                    var fixtures = new List<T.PreparedFixture>();
                    foreach (var permission in Enum.GetValues<SecretPermission>())
                        foreach (bool denied in new[] { true, false })
                        {
                            string name = FixtureName(permission, denied, i, principals.Length);
                            var child = plan.PolicyChildren.Single(c => c.Name == name);
                            SecretMaterial? set = permission == SecretPermission.Set ? child.CopySet() : null;
                            AzureSecretBackup? backup = permission == SecretPermission.Restore ? child.CopyBackup() : null;
                            if (set is not null) copies.Add(set);
                            if (backup is not null) copies.Add(backup);
                            fixtures.Add(new(permission, denied, name, child.Version,
                                child.Desired switch
                                {
                                    VaultFixtureProvisioner.Preparation.Active => T.PreparedState.Active,
                                    VaultFixtureProvisioner.Preparation.Deleted => T.PreparedState.Deleted,
                                    VaultFixtureProvisioner.Preparation.Absent => T.PreparedState.Absent,
                                    _ => T.PreparedState.Unknown
                                }, child.Sha256, set, backup));
                        }
                    var names = fixtures.Select(f => f.Name).ToHashSet(StringComparer.Ordinal);
                    trial.Window = trial.Source.Arm(new(owner, binding, T.Revision, fixtures.ToArray(),
                        [VaultFixtureProvisioner.Canary, .. plan.PolicyChildren.Select(c => c.Name).Where(n => !names.Contains(n))]));
                }
                finally { foreach (var copy in copies) copy.Dispose(); }
            }
            session.Subscription = Guid.NewGuid();
            session.ArmedAt = time.GetUtcNow();
            Require(!disposed && !session.Closed);
            session.Armed = true;
            return Reply(new ObservationSubscription(plan.LeaseId, session.Selector.Nonce,
                session.Subscription, session.ArmedAt));
        }
    }

    private async Task<HttpResponseMessage> Observe(ObserveLease input, CancellationToken token)
    {
        Session session;
        bool before = input.Phase == "baseline-before-dispatch";
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && input.SubscriptionId == session.Subscription);
            if (before)
            {
                Require(!session.BeforeClaimed && session.Selected is null);
                session.BeforeClaimed = true;
            }
            else
            {
                Require(input.Phase == "post-operation" && session.BaselineReady && !session.AfterClaimed &&
                    session.Selected is { Terminated: true, ThroughSource: true, Finalized: true, Settled: true });
                session.AfterClaimed = true;
            }
            session.Active++;
        }
        // Selected caller cancellation does not poison this independent window.
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
        try
        {
            var binding = session.Binding!;
            var vault = await source.Metadata.CollectAsync(before ? session.BeforeActive! : session.AfterActive!,
                binding, linked.Token).ConfigureAwait(false);
            var deleted = await source.Metadata.CollectAsync(before ? session.BeforeDeleted! : session.AfterDeleted!,
                binding with { Read = M.ReadKind.GetDeletedVault }, linked.Token).ConfigureAwait(false);
            Require(vault.ResponseComplete && deleted.ResponseComplete &&
                vault.Status == SecretStatus.Success && deleted.Status == SecretStatus.Absent &&
                vault.Vaults.Count == 1 && deleted.DeletedVaults.Count == 0 &&
                vault.NativeRequestIds.Count == 1 && deleted.NativeRequestIds.Count == 1 &&
                vault.FinishedAt >= session.ArmedAt && deleted.FinishedAt >= vault.FinishedAt);
            var native = vault.Vaults[0];
            Require(native.Row.ResourceId.Equals(session.Plan!.VaultId, StringComparison.OrdinalIgnoreCase) &&
                native.Row.ProvisioningState == NativeProvisioningState.Succeeded && native.Configuration is not null);
            var configuration = Project(native.Configuration);
            E.PolicyEffect[] effects = [];
            if (before) Require(E.SameConfiguration(configuration, baseline));
            else
            {
                Require(vault.FinishedAt >= session.BaselineAt);
                var combined = new List<E.PolicyEffect>();
                foreach (var trial in session.Trials)
                {
                    var measured = await trial.Source.CollectAsync(trial.Window!, binding, linked.Token).ConfigureAwait(false);
                    combined.AddRange(E.ComposePolicyEffects(trial.Source, trial.Window!, binding, trial.Principal, measured));
                }
                effects = combined.ToArray();
                Require(effects.Length == principals.Length * 8 &&
                    effects.Select(e => (e.PrincipalId, e.Permission)).Distinct().Count() == effects.Length);
            }
            lock (gate)
            {
                Require(!session.Closed);
                var observedAt = time.GetUtcNow();
                Require(observedAt >= deleted.FinishedAt);
                if (before) { session.BaselineAt = observedAt; session.BaselineReady = true; }
                return Reply(new E.Measurement(session.Plan.LeaseId, session.Selector.Nonce, observerIdentity,
                    observedAt, session.Plan.VaultId, vault.Status, deleted.Status, configuration,
                    configuration.Policies, PrivateConnectionState.Unknown, SecretStatus.Absent, effects, null,
                    [new(native.Row.ResourceId, native.Row.ProvisioningState, native.Row.Rbac,
                        native.Row.PurgeProtection, native.Row.RetentionDays)], [], [], [], null));
            }
        }
        finally { Leave(session); }
    }

    private async Task<HttpResponseMessage> Release(FixtureSelector selector, CancellationToken token)
    {
        ValidateSelector(selector);
        Session session;
        RoleFixtureJournal.Snapshot snapshot;
        lock (gate)
        {
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                Require(sessions.Count < 32);
                // Restart release uses only the original journal coordinates.
                session = new(selector);
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector);
            session.Closed = true;
        }
        try
        {
            lock (gate) snapshot = source.Provisioner.CloseSelectedRoot(owner, selector);
        }
        finally { session.Stop.Cancel(); }
        lock (gate)
        {
            if (session.Active != 0 || session.Releasing)
                return Reply(ReleaseMeasurement(session, snapshot, session.Releasing ? 1 : 0));
            session.Releasing = true;
        }
        try
        {
            await DisposeTrial(session).ConfigureAwait(false);
            // A failed local append may be repeated after actual task drain;
            // no SDK mutation, polling or fabricated settlement is repeated.
            if (session.Selected is { Terminated: true, Finalized: false } call)
                FinalizeSelected(call);
            snapshot = source.Journal.Read(owner, selector);
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty))
                return Reply(ReleaseMeasurement(session, snapshot));
            snapshot = (await source.Provisioner.ReleaseAsync(owner, selector, true, token).ConfigureAwait(false)).Journal;
            return Reply(ReleaseMeasurement(session, snapshot));
        }
        finally { lock (gate) session.Releasing = false; }
    }

    private RoleFixtureRelease.Measurement ReleaseMeasurement(Session session, RoleFixtureJournal.Snapshot snapshot,
        int additional = 0)
    {
        Require(snapshot.Owner == owner && snapshot.Selector == session.Selector && snapshot.Closing);
        var owned = snapshot.Resources.Where(r => !r.Borrowed).Select(r => r.Id).ToArray();
        var absent = snapshot.Resources.Where(r => !r.Borrowed && r.Absent && r.ActiveDispatch == Guid.Empty)
            .Select(r => r.Id).ToArray();
        return new(session.Selector, true, session.Active + additional +
            snapshot.Resources.Count(r => r.ActiveDispatch != Guid.Empty), owned,
            snapshot.Resources.Where(r => r.Borrowed).Select(r => r.Id).ToArray(), absent,
            owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private Task DisposeTrial(Session session)
    {
        lock (gate) return session.TrialDisposal ??= DrainTrials(session.Trials.ToArray());
    }

    private static async Task DrainTrials(PermissionWindow[] trials)
    {
        bool failed = false;
        foreach (var trial in trials)
        {
            try { await trial.Source.DisposeAsync().ConfigureAwait(false); }
            catch (Exception) { failed = true; }
        }
        Require(!failed);
    }

    private Session Find(Guid nonce, Guid lease)
    {
        Require(sessions.TryGetValue(nonce, out var session) && !disposed && !session.Closed &&
            session.Lease is not null && session.Plan is not null && session.Plan.LeaseId == lease);
        return session;
    }
    private static string FixtureName(SecretPermission permission, bool denied, int index, int count) =>
        permission is SecretPermission.Get or SecretPermission.List or SecretPermission.Backup
            ? "policy-read" : "policy-" + (count == 1 ? "" : "p" + index + "-") +
                permission.ToString().ToLowerInvariant() + (denied ? "-denied" : "-intended");
    private static string[] ChildNames(int count) => Enumerable.Range(0, count)
        .SelectMany(i => Enum.GetValues<SecretPermission>().SelectMany(p =>
            new[] { FixtureName(p, true, i, count), FixtureName(p, false, i, count) }))
        .Distinct(StringComparer.Ordinal).ToArray();
    private static SecretMaterial RandomMaterial()
    {
        byte[] bytes = RandomNumberGenerator.GetBytes(32);
        try { return SecretMaterial.FromText(Convert.ToHexString(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static SecretPermission[] Permissions(FixtureSelector selector) => selector.Variant == "permissions.empty" ? [] :
        selector.Variant.StartsWith("permission.", StringComparison.Ordinal)
            ? [Enum.Parse<SecretPermission>(selector.Variant["permission.".Length..])]
            : Enum.GetValues<SecretPermission>();
    private static bool Matches(E.Policy? policy, T.PrincipalClaim principal, FixtureSelector selector) =>
        policy is not null && policy.TenantId == principal.TenantId &&
        policy.PrincipalId == principal.PrincipalId && policy.ApplicationId == principal.ApplicationId &&
        policy.Permissions is { Length: <= 8 } &&
        policy.Permissions.Distinct().Count() == policy.Permissions.Length &&
        policy.Permissions.Order().SequenceEqual(Permissions(selector).Order());
    private static E.Configuration Snapshot(E.Configuration configuration)
    {
        try
        {
            Require(configuration is not null && configuration.Policies is { Length: <= 16 } &&
                configuration.Policies.All(p => p is not null && p.Permissions is not null &&
                    p.Permissions.Length <= 8 && p.Permissions.Distinct().Count() == p.Permissions.Length));
            var snapshot = configuration with
            {
                Policies = configuration.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray()
            };
            _ = snapshot.Build();
            Require(E.SamePolicies(snapshot.Policies, snapshot.Policies));
            return snapshot;
        }
        catch (Exception) { throw Failure(); }
    }
    private static E.Configuration Project(M.ConfigurationMetadata c) => new(c.Location, c.TenantId, c.Sku,
        c.Rbac, c.PurgeProtection, c.RetentionDays, c.PublicNetworkAccess,
        c.Policies.Select(p => new E.Policy(p.TenantId, p.PrincipalId, p.Permissions.ToArray(), p.ApplicationId)).ToArray());
    private static void ValidateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }.All(v => Text(v, 512)) &&
            selector.Operation == M.Operation(M.QueryKind.ChangeAccessPolicies) &&
            (selector.Variant is "change.Add" or "change.Remove" or "change.Replace" or "permissions.empty" or
                "applicationId.omitted" or "applicationId.value" or "policies.multiple" ||
                selector.Variant.StartsWith("permission.", StringComparison.Ordinal) &&
                Enum.TryParse<SecretPermission>(selector.Variant["permission.".Length..], out var permission) &&
                Enum.IsDefined(permission) && permission.ToString() == selector.Variant["permission.".Length..]) &&
            selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
                "cancellation-boundary" or "lost-response-no-replay");
    private static bool Authority(T.Authority authority) => authority is not null && Text(authority.Label, 128) &&
        authority.Credential is not null && authority.Transport is not null;
    private static bool Segment(string? value, int maximum) => Text(value, maximum) && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
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
            request.Content.Headers.ContentLength <= limits.MaximumBodyBytes &&
            request.Content.Headers.ContentType?.MediaType == "application/json" &&
            request.Content.Headers.ContentEncoding.Count == 0);
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        try
        {
            using var stream = await request.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            int length = 0, count;
            while (length < bytes.Length && (count = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false)) != 0)
                length += count;
            Require(length <= limits.MaximumBodyBytes && length == request.Content.Headers.ContentLength);
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
    private HttpResponseMessage Reply<TValue>(TValue value)
    {
        byte[] bytes = new byte[limits.MaximumReplyBytes];
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
        Content = new StringContent("{\"error\":\"vault-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private void Leave(Session session)
    {
        lock (gate)
            if (--session.Active == 0 && session.Closed) session.SettingsDrained.TrySetResult();
    }
    private void EndRequest() { lock (gate) if (--active == 0 && disposed) drained.TrySetResult(); }
    public ValueTask DisposeAsync()
    {
        TaskCompletionSource completion;
        lock (gate)
        {
            if (disposal is not null) return new(disposal.Task);
            disposed = true;
            completion = disposal = new(TaskCreationOptions.RunContinuationsAsynchronously);
            if (active == 0) drained.TrySetResult();
        }
        _ = settingsSource is null ? Drain(completion) : DrainSettings(completion);
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
                    try { source.Provisioner.CloseSelectedRoot(owner, session.Selector); }
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
            {
                await DisposeTrial(session).ConfigureAwait(false);
                session.Selected?.Clear();
                session.Stop.Dispose();
            }
            lifetime.Dispose();
            Require(closed);
            completion.TrySetResult();
        }
        catch (Exception) { completion.TrySetException(Failure()); }
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("vault-source-unavailable");
    public override string ToString() => "[VaultFixtureObserverService]";
}
