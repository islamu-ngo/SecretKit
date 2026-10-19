using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using TriggerKind = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.AuditDiagnosticsEffects.TriggerKind;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Local source composition only. The host owns TLS, credentials, transports,
// namespace exclusivity and principal/egress qualification. This class owns
// admission, actual SDK tasks, capture windows and bounded response storage.
internal sealed class AuditFixtureObserverService : AuditDiagnosticsEffects.SelectedInvocation, IAsyncDisposable
{
    internal sealed record WindowSource([property: JsonIgnore] RoleFixtureJournal Journal,
        [property: JsonIgnore] RoleFixtureProvisioner Provisioner,
        [property: JsonIgnore] AuditDiagnosticSettings Diagnostics, [property: JsonIgnore] AuditIngestionCollector Collector,
        [property: JsonIgnore] TokenCredential RuntimeCredential, [property: JsonIgnore] HttpPipelineTransport RuntimeTransport)
    {
        public override string ToString() => "[AuditWindowSource]";
    }
    internal sealed record Limits(int MaximumRows, int MaximumBodyBytes, TimeSpan Timeout);
    private static readonly JsonSerializerOptions Json = new(ManagementAdmission.Json)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true
    };
    private readonly object gate = new();
    private readonly Uri origin;
    private readonly string owner, observerIdentity;
    private readonly SecretMaterial capability;
    private readonly RoleFixtureProvisioner.HostScope scope;
    private readonly Guid workspace;
    private readonly WindowSource[] sources;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly Dictionary<Guid, Session> sessions = [];
    private readonly AsyncLocal<NativeCall?> originalCall = new();
    private readonly CancellationTokenSource lifetime = new();
    private readonly TaskCompletionSource drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int active;
    private bool disposed;
    private Task? disposal;

    private sealed class Session(FixtureSelector selector, WindowSource[] sources)
    {
        internal readonly FixtureSelector Selector = selector;
        // Explicit service lease root, independent of every constituent journal.
        internal readonly Guid LeaseRoot = Guid.NewGuid();
        internal readonly string TriggerId = Guid.NewGuid().ToString("N");
        internal readonly Work[] Windows = sources.Select(s => new Work(s)).ToArray();
        internal readonly CancellationTokenSource Stop = new();
        internal readonly TaskCompletionSource Triggered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TriggerKind Kind;
        internal int Count, Active;
        internal bool Closed, Armed, Observed, TriggerClaimed, SetClaimed, SetSucceeded, Releasing;
        internal Guid Subscription;
        internal AuditDiagnosticsEffects.Lease? Lease;
    }
    private sealed class Work(WindowSource source)
    {
        internal readonly WindowSource Source = source;
        internal RoleFixtureProvisioner.Plan? Plan;
        internal AuditDiagnosticSettings.Plan? Diagnostics;
        internal VaultScope? Vault;
        internal AuditIngestionCollector.Window? Query;
        internal NativeCall? Primary;
        internal byte[]? Backup;
        internal readonly List<NativeCall> Calls = [];
        internal Guid Dispatch;
        internal bool FinalizationRetained, Settled;
        internal RoleFixtureJournal.Snapshot? BaseClosed, DiagnosticClosed;
    }
    private sealed class NativeCall(Session session, Work work, TriggerKind kind)
    {
        internal readonly Session Session = session;
        internal readonly Work Work = work;
        internal readonly TriggerKind Kind = kind;
        internal AuditNativeTriggerCapture Source = null!;
        internal AuditNativeTriggerCapture.Window Window = null!;
        internal AuditNativeTriggerCapture.Capture? Capture;
        internal Task<AuditNativeTriggerCapture.Capture>? Sealing;
        internal RoleFixtureProvisioner.BoundaryTransport Boundary = null!;
        internal InvocationTransport Transport = null!;
        internal NativeEvidence Evidence = null!;
        internal NativeEvidence? StatusEvidence;
        internal Task? SdkTask, StatusTask;
        internal Operation? Pending;
        internal bool Started, Terminated, Succeeded, Settled, StatusAttempted, Original, ThroughSource;
    }

    internal AuditFixtureObserverService(Uri origin, string owner, string observerIdentity, SecretMaterial capability,
        RoleFixtureProvisioner.HostScope scope, Guid workspace, WindowSource[] sources, Limits limits,
        TimeProvider? time = null)
    {
        Require(origin is
        {
            IsAbsoluteUri: true,
            Scheme: "https",
            AbsolutePath: "/",
            UserInfo.Length: 0,
            Query.Length: 0,
            Fragment.Length: 0
        } &&
            owner is { Length: > 0 and <= 128 } && observerIdentity is { Length: > 0 and <= 128 } &&
            capability is not null && scope is not null && scope.ExclusiveFixtureNamespace &&
            scope.IntendedRoleDefinitionId != Guid.Empty && scope.IntendedPrincipalId != Guid.Empty &&
            workspace != Guid.Empty && sources is { Length: 1 or 2 } &&
            sources.All(s => s is not null && s.Journal is not null && s.Provisioner is not null &&
                s.Diagnostics is not null && s.Collector is not null && s.RuntimeCredential is not null &&
                s.RuntimeTransport is not null) &&
            sources.Select(s => s.Journal).Distinct(ReferenceEqualityComparer.Instance).Count() == sources.Length &&
            sources.Select(s => s.Provisioner).Distinct(ReferenceEqualityComparer.Instance).Count() == sources.Length &&
            sources.Select(s => s.Diagnostics).Distinct(ReferenceEqualityComparer.Instance).Count() == sources.Length &&
            sources.Select(s => s.Collector).Distinct(ReferenceEqualityComparer.Instance).Count() == sources.Length &&
            limits is not null && limits.MaximumRows is >= 1 and <= 1000 &&
            limits.MaximumBodyBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.origin = origin;
        this.owner = owner;
        this.observerIdentity = observerIdentity;
        this.capability = capability!;
        this.scope = scope!;
        this.workspace = workspace;
        this.sources = sources!.ToArray();
        this.limits = limits!;
        this.time = time ?? TimeProvider.System;
        RuntimeTransport = new OriginalTransport(this);
    }

    internal HttpPipelineTransport RuntimeTransport { get; }

    internal async Task<HttpResponseMessage> DispatchAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (!Authenticate(request)) return Error(HttpStatusCode.Unauthorized);
        if (request.Method != HttpMethod.Post || request.RequestUri is not { IsAbsoluteUri: true } uri ||
            uri.Scheme != "https" || uri.GetLeftPart(UriPartial.Authority) != origin.GetLeftPart(UriPartial.Authority) ||
            uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0)
            return Error(HttpStatusCode.BadRequest);
        lock (gate) { if (disposed) return Error(HttpStatusCode.ServiceUnavailable); active++; }
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, lifetime.Token, deadline.Token);
        try
        {
            using var body = await ReadBody(request, linked.Token).ConfigureAwait(false);
            return uri.AbsolutePath switch
            {
                "/audit/prepare" => await Prepare(body.RootElement.Deserialize<AuditDiagnosticsEffects.Prepare>(Json)
                    ?? throw Failure(), linked.Token).ConfigureAwait(false),
                "/audit/arm" => Arm(body.RootElement.Deserialize<ObserveLease>(Json) ?? throw Failure()),
                "/audit/observe" => await Observe(body.RootElement.Deserialize<ObserveLease>(Json)
                    ?? throw Failure(), linked.Token).ConfigureAwait(false),
                "/audit/trigger" => await Trigger(body.RootElement.Deserialize<AuditDiagnosticsEffects.Trigger>(Json)
                    ?? throw Failure(), linked.Token).ConfigureAwait(false),
                "/audit/release" => await Release(body.RootElement.Deserialize<FixtureSelector>(Json)
                    ?? throw Failure(), linked.Token).ConfigureAwait(false),
                _ => Error(HttpStatusCode.NotFound)
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return Error(HttpStatusCode.ServiceUnavailable); }
        finally { EndRequest(); }
    }

    private async Task<HttpResponseMessage> Prepare(AuditDiagnosticsEffects.Prepare input, CancellationToken token)
    {
        ValidateSelector(input.Selection);
        Require(input.SubscriptionId == scope.SubscriptionId && input.ResourceGroup == scope.ResourceGroup &&
            input.Location == scope.Location && input.TenantId == scope.TenantId && input.WorkspaceId == workspace &&
            input.MaximumRows == limits.MaximumRows && input.TriggerOperation == ExpectedKind(input.Selection) &&
            (input.TriggerOperation is not (TriggerKind.Purge or TriggerKind.Restore) || scope.AllowPurge));
        Session session;
        lock (gate)
        {
            Require(!disposed && !sessions.ContainsKey(input.Selection.Nonce));
            session = new(input.Selection, sources) { Kind = input.TriggerOperation, Count = Count(input.Selection), Active = 1 };
            Require(session.Count <= sources.Length);
            sessions.Add(input.Selection.Nonce, session);
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
        try
        {
            // All coordinates are source-planned and journaled before any native
            // call. Unused configured roots are still closed during release.
            lock (gate)
            {
                Require(!session.Closed);
                foreach (var work in session.Windows.Take(session.Count))
                {
                    work.Plan = work.Source.Provisioner.PlanFixture(owner, session.Selector, new(null, null, []), true);
                    work.Vault = new(new(new(scope.SubscriptionId), scope.ResourceGroup), work.Plan.VaultName);
                    var own = work.Source.Journal.Read(owner, session.Selector);
                    Require(own.LeaseId == work.Plan.LeaseId && own.Resources.Count(r => !r.Borrowed) == 4);
                    work.Diagnostics = work.Source.Diagnostics.PlanFixture(owner, session.Selector, work.Plan.VaultId);
                }
            }
            foreach (var work in session.Windows.Take(session.Count))
            {
                byte[] entropy = RandomNumberGenerator.GetBytes(32);
                using var canary = SecretMaterial.FromText(Convert.ToHexString(entropy));
                CryptographicOperations.ZeroMemory(entropy);
                var provisioned = await work.Source.Provisioner.ProvisionAsync(work.Plan!, canary.Reveal(), linked.Token).ConfigureAwait(false);
                Require(provisioned.State == RoleFixtureProvisioner.State.Ready &&
                    provisioned.CanaryVersion is not null && provisioned.CanarySha256 is not null);
                var configured = await work.Source.Diagnostics.ProvisionAsync(work.Diagnostics!, linked.Token).ConfigureAwait(false);
                Require(configured.State == AuditDiagnosticSettings.State.Ready && configured.RoutingReady);
                lock (gate)
                {
                    Require(!session.Closed);
                    if (Mutates(session.Kind))
                        work.Dispatch = work.Source.Journal.BeginSelectedUpdate(owner, session.Selector, work.Plan!.SecretId);
                }
                // Lifecycle prerequisites precede the query interval. Their real
                // SDK tasks and receipts are retained under the same logical
                // canary dispatch, not reclassified as selected deletes.
                if (session.Kind == TriggerKind.Restore)
                {
                    var backup = NewCall(session, work, TriggerKind.Backup);
                    var response = await Invoke(backup, c => c.BackupSecretAsync(RoleFixtureProvisioner.Canary, linked.Token)).ConfigureAwait(false);
                    using (response.GetRawResponse()) work.Backup = response.Value;
                    Require(backup.Succeeded && work.Backup.Length is > 0 && work.Backup.Length <= limits.MaximumBodyBytes);
                }
                if (session.Kind is TriggerKind.Recover or TriggerKind.Purge or TriggerKind.Restore)
                {
                    var deletion = NewCall(session, work, TriggerKind.Delete);
                    var pending = await Invoke(deletion, c => c.StartDeleteSecretAsync(RoleFixtureProvisioner.Canary, linked.Token)).ConfigureAwait(false);
                    deletion.Pending = pending;
                    deletion.Settled = false;
                    ValidateSecret(deletion, pending.Value.Properties);
                    await Settle(deletion, linked.Token, closing: false).ConfigureAwait(false);
                    Require(deletion.Settled);
                }
                if (session.Kind == TriggerKind.Restore)
                {
                    Require(scope.AllowPurge);
                    var purge = NewCall(session, work, TriggerKind.Purge);
                    using var response = await Invoke(purge, c => c.PurgeDeletedSecretAsync(RoleFixtureProvisioner.Canary, linked.Token)).ConfigureAwait(false);
                    Require(purge.Succeeded && purge.Settled);
                }
            }
            lock (gate)
            {
                Require(!session.Closed);
                DateTimeOffset start = time.GetUtcNow();
                var windows = session.Windows.Take(session.Count).Select((work, index) =>
                    new AuditDiagnosticsEffects.Window(work.Plan!.VaultName, RoleFixtureProvisioner.Canary, start,
                        start + limits.Timeout, Workspace(session.Selector, index))).ToArray();
                string[] owned = session.Windows.Take(session.Count).SelectMany(work =>
                    work.Source.Journal.Read(owner, session.Selector).Resources.Where(r => !r.Borrowed).Select(r => r.Id)
                        .Append(work.Diagnostics!.SettingsId)).ToArray();
                Require(owned.Length <= 16 && owned.Distinct(StringComparer.OrdinalIgnoreCase).Count() == owned.Length);
                session.Lease = new(new(session.Selector.Nonce, session.LeaseRoot, observerIdentity,
                    "https://management.azure.com", "2026-02-01", start, owned), windows, session.TriggerId);
                return Reply(session.Lease);
            }
        }
        catch
        {
            Close(session);
            throw;
        }
        finally { Leave(session); }
    }

    private HttpResponseMessage Arm(ObserveLease input)
    {
        lock (gate)
        {
            var session = Find(input.Nonce, input.LeaseId);
            Require(!session.Armed && input.SubscriptionId is null && input.Phase == "subscribe-before-trigger");
            foreach (var work in session.Windows.Take(session.Count))
            {
                int index = Array.IndexOf(session.Windows, work);
                var window = session.Lease!.Windows[index];
                work.Query = work.Source.Collector.Arm(new(session.Selector, session.LeaseRoot, work.Vault!,
                    window.WorkspaceId, window.Start, window.End));
                work.Primary = NewCall(session, work, session.Kind);
            }
            session.Subscription = Guid.NewGuid();
            session.Armed = true;
            // This arms local source state, not a remote ingestion subscription.
            return Reply(new ObservationSubscription(session.LeaseRoot, session.Selector.Nonce,
                session.Subscription, time.GetUtcNow()));
        }
    }

    public async ValueTask<SecretOutcome<AzureSetSecretResult>> RunSetAsync(FixtureSelector selector,
        AzureKeyVaultClient client, AzureSetSecretRequest request, MutationReceipt receipt, CancellationToken cancellationToken)
    {
        Session session;
        lock (gate)
        {
            Require(!disposed);
            Require(sessions.TryGetValue(selector.Nonce, out session!));
            Require(session.Selector == selector && !session.Closed && session.Armed &&
                session.Kind == TriggerKind.Set && !session.SetClaimed);
            session.SetClaimed = true;
            session.Active++;
            active++;
        }
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token, session.Stop.Token);
        NativeCall original = session.Windows[0].Primary!;
        try
        {
            original.Original = true;
            originalCall.Value = original;
            SecretOutcome<AzureSetSecretResult> result;
            try
            {
                lock (gate)
                {
                    Require(!session.Closed && !original.Started);
                    original.Started = true;
                    // Retain the ACTUAL original SDK Task, not a send counter or
                    // a task completed by the selected caller's acknowledgement.
                    original.SdkTask = client.SetSecretAsync(request, receipt, linked.Token).AsTask();
                }
                result = await ((Task<SecretOutcome<AzureSetSecretResult>>)original.SdkTask!).ConfigureAwait(false);
                original.Succeeded = result.Status == SecretStatus.Success;
            }
            finally
            {
                originalCall.Value = null;
                await Finish(original).ConfigureAwait(false);
            }
            Require(original.Succeeded && original.ThroughSource);
            foreach (var work in session.Windows.Skip(1).Take(session.Count - 1))
            {
                var call = work.Primary!;
                var response = await Invoke(call, c => c.SetSecretAsync(
                    new KeyVaultSecret(RoleFixtureProvisioner.Canary, request.Material.Reveal()), linked.Token)).ConfigureAwait(false);
                using (response.GetRawResponse()) { Require(call.Succeeded); ValidateSecret(call, response.Value.Properties); }
            }
            lock (gate) { Require(!session.Closed); session.SetSucceeded = true; }
            return result;
        }
        finally { Leave(session); EndRequest(); }
    }

    private async Task<HttpResponseMessage> Trigger(AuditDiagnosticsEffects.Trigger input, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && !session.TriggerClaimed && input.TriggerId == session.TriggerId &&
                input.Operation == session.Kind && (session.Kind != TriggerKind.Set || session.SetSucceeded));
            session.TriggerClaimed = true;
            session.Active++;
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
        try
        {
            if (session.Kind != TriggerKind.Set)
                foreach (var work in session.Windows.Take(session.Count))
                    await TriggerNative(work.Primary!, linked.Token).ConfigureAwait(false);
            lock (gate)
            {
                Require(!session.Closed && session.Windows.Take(session.Count).All(w => w.Primary!.Succeeded));
                // Only actual source-owned SDK completion opens the observation
                // barrier. SelectedVersion is deliberately not authority.
                session.Triggered.TrySetResult();
                return Reply(new AuditDiagnosticsEffects.TriggerReceipt(session.LeaseRoot, input.Nonce, session.TriggerId));
            }
        }
        catch
        {
            session.Triggered.TrySetException(Failure());
            throw;
        }
        finally { Leave(session); }
    }

    private async Task TriggerNative(NativeCall call, CancellationToken token)
    {
        string name = RoleFixtureProvisioner.Canary;
        switch (call.Kind)
        {
            case TriggerKind.Get:
                var got = await Invoke(call, c => c.GetSecretAsync(name, call.Work.Plan!.CanaryVersion, token)).ConfigureAwait(false);
                using (got.GetRawResponse()) ValidateSecret(call, got.Value.Properties);
                break;
            case TriggerKind.List:
                await Invoke(call, async c =>
                {
                    await using var pages = c.GetPropertiesOfSecretsAsync(token).AsPages().GetAsyncEnumerator(token);
                    Require(await pages.MoveNextAsync().ConfigureAwait(false));
                    var page = pages.Current;
                    using (page.GetRawResponse())
                    {
                        Require(page.ContinuationToken is null && page.Values.Count <= limits.MaximumRows &&
                            page.Values.Any(p => p.Name == name));
                    }
                    return true;
                }).ConfigureAwait(false);
                break;
            case TriggerKind.Delete:
                var deleted = await Invoke(call, c => c.StartDeleteSecretAsync(name, token)).ConfigureAwait(false);
                call.Pending = deleted;
                call.Settled = false;
                ValidateSecret(call, deleted.Value.Properties);
                break;
            case TriggerKind.Recover:
                var recovered = await Invoke(call, c => c.StartRecoverDeletedSecretAsync(name, token)).ConfigureAwait(false);
                call.Pending = recovered;
                call.Settled = false;
                ValidateSecret(call, recovered.Value);
                break;
            case TriggerKind.Backup:
                var backup = await Invoke(call, c => c.BackupSecretAsync(name, token)).ConfigureAwait(false);
                using (backup.GetRawResponse()) CryptographicOperations.ZeroMemory(backup.Value);
                break;
            case TriggerKind.Restore:
                Require(call.Work.Backup is { Length: > 0 });
                var restored = await Invoke(call, c => c.RestoreSecretBackupAsync(call.Work.Backup!, token)).ConfigureAwait(false);
                using (restored.GetRawResponse()) ValidateSecret(call, restored.Value);
                CryptographicOperations.ZeroMemory(call.Work.Backup!);
                call.Work.Backup = null;
                break;
            case TriggerKind.Purge:
                Require(scope.AllowPurge);
                using (await Invoke(call, c => c.PurgeDeletedSecretAsync(name, token)).ConfigureAwait(false)) { }
                break;
            case TriggerKind.UpdateProperties:
                var properties = new SecretProperties(new Uri("https://" + call.Work.Plan!.VaultName +
                    ".vault.azure.net/secrets/" + name + "/" + call.Work.Plan.CanaryVersion))
                { ContentType = "audit-fixture" };
                var updated = await Invoke(call, c => c.UpdateSecretPropertiesAsync(properties, token)).ConfigureAwait(false);
                using (updated.GetRawResponse()) ValidateSecret(call, updated.Value);
                break;
            default: throw Failure();
        }
        Require(call.Succeeded);
    }

    private async Task<HttpResponseMessage> Observe(ObserveLease input, CancellationToken token)
    {
        Session session;
        lock (gate)
        {
            session = Find(input.Nonce, input.LeaseId);
            Require(session.Armed && !session.Observed && input.SubscriptionId == session.Subscription &&
                input.Phase == "subscribed-event");
            session.Observed = true;
            session.Active++;
        }
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Stop.Token);
        try
        {
            await session.Triggered.Task.WaitAsync(linked.Token).ConfigureAwait(false);
            var events = new List<AuditDiagnosticsEffects.MeasuredEvent>();
            foreach (var work in session.Windows.Take(session.Count))
            {
                // Exactly one bounded native query after the exact trigger event.
                // ResponseComplete is not a watermark or an absence assertion.
                var measured = await work.Source.Collector.CollectAsync(work.Query!, linked.Token).ConfigureAwait(false);
                Require(measured.ResponseComplete && measured.Rows.Count > 0 && work.Primary!.Capture is not null);
                events.AddRange(Join(measured, [work.Primary!.Capture!], session.TriggerId));
            }
            lock (gate) Require(!session.Closed);
            return Reply(new AuditDiagnosticsEffects.Measurement(session.LeaseRoot, session.Selector.Nonce,
                observerIdentity, time.GetUtcNow(), events.ToArray(), SecretStatus.Success));
        }
        finally { Leave(session); }
    }

    internal static AuditDiagnosticsEffects.MeasuredEvent[] Join(AuditIngestionCollector.Measurement measured,
        IReadOnlyList<AuditNativeTriggerCapture.Capture> captures, string trigger)
    {
        Require(measured.ResponseComplete && measured.Rows.Count > 0);
        var events = measured.Rows.Select(row =>
        {
            var matching = captures.Where(c => c.Binding.Selector == measured.Binding.Selector &&
                    c.Binding.LeaseId == measured.Binding.LeaseId &&
                    c.Binding.Vault.ExportResourceId().Equals(measured.Binding.Vault.ExportResourceId(), StringComparison.OrdinalIgnoreCase))
                .SelectMany(c => c.Attempts).Where(a => a.Authorized && a.TransportTerminated && a.ResponseObserved &&
                    a.ClientCorrelationId != Guid.Empty && row.CorrelationId == a.ClientCorrelationId &&
                    a.NativeResponseRequestId is { Length: > 0 } &&
                    (!Guid.TryParse(a.NativeResponseRequestId, out var responseId) || responseId != a.ClientCorrelationId) &&
                    row.NativeOperation == NativeName(a.Operation) &&
                    row.Operation == Project(a.Operation) &&
                    row.Result == AuditResultKind.Success && a.HttpStatus == (a.Operation == TriggerKind.Purge ? 204 : 200))
                .ToArray();
            Require(matching.Length <= 1);
            return new AuditDiagnosticsEffects.MeasuredEvent(measured.Binding.Vault.ExportResourceId(),
                measured.Binding.WorkspaceId, row.Timestamp, row.Operation, row.Result,
                matching.Length == 1 ? trigger : string.Empty);
        }).ToArray(); // Deliberately retain duplicate multiplicity.
        Require(events.Any(e => e.TriggerId == trigger));
        return events;
    }

    private async Task<HttpResponseMessage> Release(FixtureSelector selector, CancellationToken token)
    {
        ValidateSelector(selector);
        Session session;
        lock (gate)
        {
            if (!sessions.TryGetValue(selector.Nonce, out session!))
            {
                session = new(selector, sources);
                sessions.Add(selector.Nonce, session);
            }
            Require(session.Selector == selector && !session.Releasing);
            session.Releasing = true;
        }
        try
        {
            Require(Close(session));
            lock (gate)
                if (session.Active != 0 || session.Windows.SelectMany(w => w.Calls).Any(c => c.SdkTask is { IsCompleted: false }))
                    return Reply(ReleaseMeasurement(session));
            foreach (var work in session.Windows)
            {
                foreach (var call in work.Calls)
                    if (call.Pending is not null) await Settle(call, token, closing: true).ConfigureAwait(false);
                if (work.Dispatch == Guid.Empty) continue;
                if (!work.FinalizationRetained)
                {
                    Require(work.Calls.All(c => c.Terminated && (c.SdkTask is null || c.SdkTask.IsCompleted)));
                    work.Settled = work.Calls.All(c => c.Settled);
                    // Retain this actual completed evidence before the append.
                    // A failed journal write is retried, never the native call.
                    work.FinalizationRetained = true;
                }
                var row = work.Source.Journal.Read(owner, selector).Resources.Single(r => r.Id == work.Plan!.SecretId);
                if (row.ActiveDispatch == work.Dispatch)
                    work.Source.Journal.EndDispatch(owner, selector, row.Id, work.Dispatch, work.Settled);
            }
            foreach (var work in session.Windows)
                await work.Source.Provisioner.SettleAsync(owner, selector, token).ConfigureAwait(false);
            foreach (var work in session.Windows)
                if (work.DiagnosticClosed!.Resources.Length != 0)
                    await work.Source.Diagnostics.ObserveAsync(owner, selector, token).ConfigureAwait(false);
            Require(Close(session));
            // No root deletes while any constituent dispatch remains unsettled.
            if (session.Windows.Any(w => w.BaseClosed!.Resources.Concat(w.DiagnosticClosed!.Resources)
                    .Any(r => r.ActiveDispatch != Guid.Empty)))
                return Reply(ReleaseMeasurement(session));
            foreach (var work in session.Windows)
                work.DiagnosticClosed = (await work.Source.Diagnostics.ReleaseAsync(owner, selector, token).ConfigureAwait(false)).Journal
                    ?? throw Failure();
            if (session.Windows.Any(w => !w.DiagnosticClosed!.Released)) return Reply(ReleaseMeasurement(session));
            // Every diagnostic resource is independently absent before any vault
            // delete. Borrowed workspaces never enter either deletion path.
            foreach (var work in session.Windows)
                work.BaseClosed = (await work.Source.Provisioner.ReleaseAsync(owner, selector, scope.AllowPurge, token).ConfigureAwait(false)).Journal
                    ?? throw Failure();
            return Reply(ReleaseMeasurement(session));
        }
        finally
        {
            lock (gate)
            {
                session.Releasing = false;
                if (session.Active == 0)
                    foreach (var work in session.Windows)
                    {
                        if (work.Backup is { } backup) { CryptographicOperations.ZeroMemory(backup); work.Backup = null; }
                        foreach (var call in work.Calls)
                        {
                            // Completion evidence is retained separately; do not
                            // keep completed generic task results containing values.
                            if (call.Terminated && call.SdkTask is { IsCompleted: true }) call.SdkTask = null;
                            if (call.StatusTask is { IsCompleted: true }) call.StatusTask = null;
                            if (call.StatusAttempted) call.Pending = null;
                        }
                    }
            }
        }
    }

    private RoleFixtureRelease.Measurement ReleaseMeasurement(Session session)
    {
        lock (gate)
        {
            var snapshots = session.Windows.SelectMany(w => new[] { w.BaseClosed!, w.DiagnosticClosed! }).ToArray();
            Require(snapshots.All(s => s is not null && s.Owner == owner && s.Selector == session.Selector && s.Closing));
            var resources = snapshots.SelectMany(s => s.Resources).ToArray();
            string[] owned = resources.Where(r => !r.Borrowed).Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] borrowed = resources.Where(r => r.Borrowed).Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            string[] absent = resources.Where(r => !r.Borrowed).GroupBy(r => r.Id, StringComparer.OrdinalIgnoreCase)
                .Where(g => g.All(r => r.Absent && r.ActiveDispatch == Guid.Empty)).Select(g => g.Key).ToArray();
            Require(owned.Length <= 16 && borrowed.Length <= 16 && !owned.Intersect(borrowed, StringComparer.OrdinalIgnoreCase).Any());
            var result = new RoleFixtureRelease.Measurement(session.Selector, true,
                session.Active + resources.Count(r => r.ActiveDispatch != Guid.Empty),
                owned, borrowed, absent, owned.Except(absent, StringComparer.OrdinalIgnoreCase).ToArray());
            if (result.ActiveDispatches == 0 && result.RemainingResourceIds.Length == 0)
                RoleFixtureRelease.Validate(result, session.Selector, session.Lease?.Facts);
            return result;
        }
    }

    private bool Close(Session session)
    {
        bool closed = true;
        lock (gate)
        {
            session.Closed = true;
            // Attempt every root even if one journal is temporarily unavailable.
            foreach (var work in session.Windows)
            {
                foreach (var call in work.Calls)
                {
                    call.Sealing ??= call.Source.SealAsync(call.Window).AsTask();
                    if (!call.Started) { call.Terminated = true; call.Settled = true; }
                }
                try { work.BaseClosed = work.Source.Provisioner.CloseSelectedRoot(owner, session.Selector); }
                catch (Exception) { closed = false; }
                try { work.DiagnosticClosed = work.Source.Diagnostics.CloseSelectedRoot(owner, session.Selector); }
                catch (Exception) { closed = false; }
            }
        }
        session.Stop.Cancel();
        session.Triggered.TrySetCanceled(session.Stop.Token);
        return closed;
    }

    private NativeCall NewCall(Session session, Work work, TriggerKind kind)
    {
        lock (gate)
        {
            Require(!session.Closed && work.Plan is not null && work.Vault is not null);
            var call = new NativeCall(session, work, kind);
            call.Evidence = new NativeEvidence(work.Source.RuntimeTransport);
            call.Source = new(call.Evidence, limits.MaximumBodyBytes);
            call.Window = call.Source.Arm(new(session.Selector, session.LeaseRoot, work.Vault!, kind,
                kind == TriggerKind.List ? null : RoleFixtureProvisioner.Canary,
                kind is TriggerKind.Get or TriggerKind.UpdateProperties ? work.Plan!.CanaryVersion : null, "2025-07-01"));
            var (path, method) = Route(kind, work.Plan!.CanaryVersion);
            call.Boundary = new(call.Source.CreateTransport(call.Window, session.Selector),
                "https://" + work.Plan.VaultName + ".vault.azure.net", path, "2025-07-01", method,
                limits.MaximumBodyBytes, true);
            call.Transport = new(this, call, call.Boundary);
            work.Calls.Add(call);
            return call;
        }
    }

    private async Task<T> Invoke<T>(NativeCall call, Func<SecretClient, Task<T>> invoke)
    {
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
        {
            Transport = call.Transport,
            DisableChallengeResourceVerification = false
        };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var client = new SecretClient(new("https://" + call.Work.Plan!.VaultName + ".vault.azure.net"),
            call.Work.Source.RuntimeCredential, options);
        try
        {
            Task<T> task;
            lock (gate)
            {
                Require(!call.Session.Closed && !call.Started);
                call.Started = true;
                task = invoke(client);
                call.SdkTask = task;
            }
            T result = await task.ConfigureAwait(false);
            call.Succeeded = true;
            return result;
        }
        finally { await Finish(call).ConfigureAwait(false); }
    }

    private async Task Finish(NativeCall call)
    {
        Task<AuditNativeTriggerCapture.Capture> sealing;
        lock (gate) sealing = call.Sealing ??= call.Source.SealAsync(call.Window).AsTask();
        call.Capture = await sealing.ConfigureAwait(false);
        call.Terminated = true;
        call.Settled = (!call.Original || call.ThroughSource) && !call.Evidence.Async &&
            call.Capture.Attempts.All(a => a.ResponseObserved && a.TransportTerminated &&
                (a.HttpStatus is 400 or 401 or 403 or 404 or 409 or 412 ||
                    a.HttpStatus is 200 or 201 or 204 && call.Boundary.Valid && call.Succeeded));
        call.Succeeded &= call.Capture.Attempts.Count(a => a.Authorized && a.ResponseObserved &&
            a.HttpStatus == (call.Kind == TriggerKind.Purge ? 204 : 200)) == 1 && !call.Evidence.Async && call.Boundary.Valid;
        call.Boundary.Dispose();
    }

    private async Task Settle(NativeCall call, CancellationToken token, bool closing)
    {
        if (call.Pending is null || call.StatusAttempted || !call.Succeeded) return;
        Require(call.Terminated && (call.SdkTask is null || call.SdkTask.IsCompleted));
        call.StatusAttempted = true;
        string path = call.Kind == TriggerKind.Delete ? "/deletedsecrets/" + RoleFixtureProvisioner.Canary :
            "/secrets/" + RoleFixtureProvisioner.Canary;
        var evidence = new NativeEvidence(call.Work.Source.RuntimeTransport, freshCorrelation: true);
        using var boundary = new RoleFixtureProvisioner.BoundaryTransport(evidence,
            "https://" + call.Work.Plan!.VaultName + ".vault.azure.net", path, "2025-07-01", RequestMethod.Get,
            limits.MaximumBodyBytes, true);
        call.Transport.Status = boundary;
        call.Transport.AllowClosedStatus = closing;
        try
        {
            Task<Response> task = call.Pending.UpdateStatusAsync(token).AsTask();
            call.StatusTask = task;
            using var response = await task.ConfigureAwait(false);
            call.Settled = call.Pending.HasCompleted && boundary.Valid && boundary.Status == 200 && !evidence.Async &&
                evidence.StatusAttempts.All(a => a.Terminated && a.ResponseObserved) &&
                evidence.StatusAttempts.Count(a => a.Authorized && a.Status == 200) == 1;
            if (call.Settled)
            {
                switch (call.Pending)
                {
                    case DeleteSecretOperation deletion: ValidateSecret(call, deletion.Value.Properties); break;
                    case RecoverDeletedSecretOperation recovery: ValidateSecret(call, recovery.Value); break;
                    default: throw Failure();
                }
            }
        }
        catch (Exception)
        {
            token.ThrowIfCancellationRequested();
            call.Settled = false;
        }
        finally
        {
            call.Transport.Status = null;
            call.Transport.AllowClosedStatus = false;
            call.StatusEvidence = evidence;
        }
    }

    private sealed class NativeEvidence(HttpPipelineTransport inner, bool freshCorrelation = false) : HttpPipelineTransport
    {
        internal sealed record StatusAttempt([property: JsonIgnore] Guid ClientCorrelation,
            [property: JsonIgnore] string Path, string Method, bool Authorized,
            int? Status, [property: JsonIgnore] string? ResponseRequestId, bool ResponseObserved, bool Terminated)
        {
            public override string ToString() => "[AuditNativeStatusAttempt]";
        }
        internal readonly List<StatusAttempt> StatusAttempts = [];
        internal bool Async;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Guid correlation = freshCorrelation ? Guid.NewGuid() : Guid.Empty;
            if (freshCorrelation) message.Request.Headers.SetValue("x-ms-client-request-id", correlation.ToString("D"));
            bool observed = false;
            int? status = null;
            string? id = null;
            try
            {
                await inner.ProcessAsync(message).ConfigureAwait(false);
                observed = true;
                status = message.Response.Status;
                message.Response.Headers.TryGetValue("x-ms-request-id", out id);
                Async |= status == 202 || new[] { "Azure-AsyncOperation", "Operation-Location", "Location" }
                    .Any(h => message.Response.Headers.TryGetValue(h, out _));
            }
            finally
            {
                if (freshCorrelation) StatusAttempts.Add(new(correlation, message.Request.Uri.ToUri().AbsolutePath,
                    message.Request.Method.ToString(), message.Request.Headers.Contains("Authorization"), status, id, observed, true));
            }
        }
    }
    private sealed class InvocationTransport(AuditFixtureObserverService service, NativeCall call,
        HttpPipelineTransport primary) : HttpPipelineTransport
    {
        internal HttpPipelineTransport? Status;
        internal bool AllowClosedStatus;
        public override Request CreateRequest() => (Status ?? primary).CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            lock (service.gate)
            {
                Require(call.Started && (!call.Session.Closed || AllowClosedStatus && Status is not null) &&
                    (!call.Terminated || Status is not null));
                return (Status ?? primary).ProcessAsync(message);
            }
        }
    }
    private sealed class OriginalTransport(AuditFixtureObserverService service) : HttpPipelineTransport
    {
        private NativeCall Current
        {
            get
            {
                var call = service.originalCall.Value ?? throw Failure();
                lock (service.gate)
                {
                    Require(call.Original && call.Started && !call.Terminated && !call.Session.Closed);
                    call.ThroughSource = true;
                    return call;
                }
            }
        }
        public override Request CreateRequest() => Current.Transport.CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override ValueTask ProcessAsync(HttpMessage message) => Current.Transport.ProcessAsync(message);
        public override string ToString() => "[AuditOriginalRuntimeTransport]";
    }

    private Session Find(Guid nonce, Guid lease)
    {
        Require(sessions.TryGetValue(nonce, out var session) && !session.Closed &&
            session.Lease is not null && session.LeaseRoot == lease);
        return session!;
    }
    private static void ValidateSelector(FixtureSelector selector) =>
        Require(selector is not null && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }
                .All(s => s is { Length: > 0 and <= 1024 } && !s.Any(char.IsControl)) &&
            AuditDiagnosticsEffects.Members.Any(m => m.Operation == selector.Operation && m.Variants.Contains(selector.Variant)) &&
            selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or "cancellation-boundary");
    private static TriggerKind ExpectedKind(FixtureSelector selector) => selector.Variant switch
    {
        "operation.Unknown" => TriggerKind.UpdateProperties,
        "operation.SecretGet" => TriggerKind.Get,
        "operation.SecretList" => TriggerKind.List,
        "operation.SecretDelete" => TriggerKind.Delete,
        "operation.SecretRecover" => TriggerKind.Recover,
        "operation.SecretBackup" => TriggerKind.Backup,
        "operation.SecretRestore" => TriggerKind.Restore,
        "operation.SecretPurge" => TriggerKind.Purge,
        _ => TriggerKind.Set
    };
    private static int Count(FixtureSelector selector) => selector.Variant is "batch.multiple" or
        "batch.mixed-resource-workspace" or "batch.caller-cancellation-progress" ? 2 : 1;
    private Guid? Workspace(FixtureSelector selector, int index) => selector.Variant == "query.workspace" ||
        selector.Variant == "batch.mixed-resource-workspace" && index == 1 ? workspace : null;
    private static bool Mutates(TriggerKind kind) => kind is not (TriggerKind.Get or TriggerKind.List or TriggerKind.Backup);
    private static string NativeName(TriggerKind kind) => kind == TriggerKind.UpdateProperties ? "SecretUpdate" : "Secret" + kind;
    private static AuditOperation Project(TriggerKind kind) => kind == TriggerKind.UpdateProperties
        ? AuditOperation.Unknown : Enum.Parse<AuditOperation>("Secret" + kind);
    private static (string, RequestMethod) Route(TriggerKind kind, string? version) => kind switch
    {
        TriggerKind.Get => ("/secrets/canary/" + version, RequestMethod.Get),
        TriggerKind.List => ("/secrets/", RequestMethod.Get),
        TriggerKind.Set => ("/secrets/canary", RequestMethod.Put),
        TriggerKind.Delete => ("/secrets/canary", RequestMethod.Delete),
        TriggerKind.Recover => ("/deletedsecrets/canary/recover", RequestMethod.Post),
        TriggerKind.Backup => ("/secrets/canary/backup", RequestMethod.Post),
        TriggerKind.Restore => ("/secrets/restore", RequestMethod.Post),
        TriggerKind.Purge => ("/deletedsecrets/canary", RequestMethod.Delete),
        TriggerKind.UpdateProperties => ("/secrets/canary/" + version, RequestMethod.Patch),
        _ => throw Failure()
    };
    private static void ValidateSecret(NativeCall call, SecretProperties properties)
    {
        bool valid = properties.Name == RoleFixtureProvisioner.Canary &&
            properties.VaultUri == new Uri("https://" + call.Work.Plan!.VaultName + ".vault.azure.net") &&
            properties.Version is { Length: 32 } version && version.All(char.IsAsciiHexDigit) &&
            (call.Kind is not (TriggerKind.Get or TriggerKind.UpdateProperties) || version == call.Work.Plan.CanaryVersion);
        if (!valid) { call.Settled = false; call.Succeeded = false; throw Failure(); }
    }
    private bool Authenticate(HttpRequestMessage request)
    {
        if (request.Headers.Authorization is not { Scheme: "Bearer", Parameter: { Length: > 0 and <= 8192 } supplied }) return false;
        char[] expected = capability.ExportCharacters();
        byte[] left = Encoding.UTF8.GetBytes(expected), right = Encoding.UTF8.GetBytes(supplied);
        try { return CryptographicOperations.FixedTimeEquals(SHA256.HashData(left), SHA256.HashData(right)); }
        finally { Array.Clear(expected); CryptographicOperations.ZeroMemory(left); CryptographicOperations.ZeroMemory(right); }
    }
    private async Task<JsonDocument> ReadBody(HttpRequestMessage request, CancellationToken token)
    {
        Require(request.Content?.Headers.ContentLength is >= 0 && request.Content.Headers.ContentLength <= limits.MaximumBodyBytes);
        byte[] bytes = new byte[limits.MaximumBodyBytes + 1];
        try
        {
            using var stream = await request.Content!.ReadAsStreamAsync(token).ConfigureAwait(false);
            int length = 0, read;
            while (length < bytes.Length && (read = await stream.ReadAsync(bytes.AsMemory(length), token).ConfigureAwait(false)) != 0)
                length += read;
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
    private HttpResponseMessage Reply<T>(T value)
    {
        byte[] storage = new byte[limits.MaximumBodyBytes];
        try
        {
            using var output = new MemoryStream(storage, 0, storage.Length, writable: true);
            JsonSerializer.Serialize(output, value, ManagementAdmission.Json);
            return new(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(storage.AsSpan(0, checked((int)output.Position)).ToArray())
            };
        }
        finally { CryptographicOperations.ZeroMemory(storage); }
    }
    private static HttpResponseMessage Error(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{\"error\":\"audit-source-unavailable\"}", Encoding.UTF8, "application/json")
    };
    private void Leave(Session session)
    {
        lock (gate)
        {
            session.Active--;
            if (session.Closed && session.Active == 0)
                foreach (var work in session.Windows)
                    if (work.Backup is { } backup) { CryptographicOperations.ZeroMemory(backup); work.Backup = null; }
        }
    }
    private void EndRequest()
    {
        lock (gate) if (--active == 0 && disposed) drained.TrySetResult();
    }
    public ValueTask DisposeAsync()
    {
        lock (gate)
        {
            if (disposal is not null) return new(disposal);
            disposed = true;
            if (active == 0) drained.TrySetResult();
            disposal = Drain();
            return new(disposal);
        }
    }
    private async Task Drain()
    {
        bool closed = true;
        foreach (var session in sessions.Values.ToArray()) closed &= Close(session);
        lifetime.Cancel();
        await drained.Task.ConfigureAwait(false);
        foreach (var session in sessions.Values)
        {
            foreach (var work in session.Windows)
            {
                foreach (var call in work.Calls)
                {
                    await (call.Sealing ??= call.Source.SealAsync(call.Window).AsTask()).ConfigureAwait(false);
                    call.Boundary.Dispose();
                    call.SdkTask = null;
                    call.StatusTask = null;
                    call.Pending = null;
                }
                if (work.Backup is { } backup) CryptographicOperations.ZeroMemory(backup);
            }
            session.Stop.Dispose();
        }
        lifetime.Dispose();
        Require(closed);
    }
    private static void Require(bool value) { if (!value) throw Failure(); }
    private static InvalidOperationException Failure() => new("audit-source-unavailable");
    public override string ToString() => "[AuditFixtureObserverService]";
}
