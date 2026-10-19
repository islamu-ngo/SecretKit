using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Source-owned routing only. The service composes this with the base provisioner,
// closes both journals before deletion, and owns ingestion and trigger capture.
// An opaque host transport still needs separate no-redirect/egress qualification.
internal sealed class AuditDiagnosticSettings
{
    private const string Origin = "https://management.azure.com";
    private const string SettingsRevision = "2021-05-01-preview";
    private const string VaultRevision = "2026-02-01";
    // Microsoft Workspaces/Get REST contract, accessed 2026-10-15:
    // https://learn.microsoft.com/en-us/rest/api/loganalytics/workspaces/get?view=rest-loganalytics-2022-10-01
    // Fixed workspace GET returns Workspace; properties.customerId is read-only.
    private const string WorkspaceRevision = "2022-10-01";
    private const string Extension = "/providers/Microsoft.Insights/diagnosticSettings/";
    internal enum State { Ready, Incomplete, Pending, Denied, Uncertain, Closing, Released }
    internal sealed record HostScope(
        [property: JsonIgnore] Guid SubscriptionId,
        [property: JsonIgnore] string ResourceGroup,
        [property: JsonIgnore] string Location,
        [property: JsonIgnore] Guid TenantId,
        [property: JsonIgnore] string WorkspaceArmId,
        [property: JsonIgnore] Guid QueryWorkspaceId,
        bool ExclusiveFixtureNamespace)
    {
        public override string ToString() => "[AuditDiagnosticSettingsScope]";
    }
    internal sealed record Authority(
        [property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[AuditDiagnosticSettingsAuthority]";
    }
    internal sealed record Limits(int MaximumResponseBytes, TimeSpan Timeout);
    internal sealed class Receipt(bool delete)
    {
        internal bool Delete { get; } = delete;
        internal bool Attempted { get; set; }
        internal bool Terminated { get; set; }
        internal bool RemoteSettled { get; set; }
        internal int? HttpStatus { get; set; }
        internal Guid Dispatch { get; set; }
        public override string ToString() => "[AuditDiagnosticSettingsReceipt]";
    }
    internal sealed class Plan(object source, string owner, FixtureSelector selector, Guid leaseId, string vaultId)
    {
        internal object Source { get; } = source;
        internal string Owner { get; } = owner;
        internal FixtureSelector Selector { get; } = selector;
        internal Guid LeaseId { get; } = leaseId;
        internal string VaultId { get; } = vaultId;
        internal string SettingsId => VaultId + Extension + "sk-audit-" + Selector.Nonce.ToString("N");
        internal List<Receipt> History { get; } = [];
        internal IReadOnlyList<Receipt> Receipts { get { lock (History) return History.ToArray(); } }
        internal int Consumed;
        public override string ToString() => "[AuditDiagnosticSettingsPlan]";
    }
    internal sealed class Result
    {
        internal required State State { get; init; }
        internal bool RoutingReady { get; init; }
        internal RoleFixtureJournal.Snapshot? Journal { get; init; }
        internal IReadOnlyList<Receipt> Receipts { get; init; } = [];
        public override string ToString() => "[AuditDiagnosticSettingsResult]";
    }

    private readonly RoleFixtureJournal journal;
    private readonly HostScope host;
    private readonly Authority setup;
    private readonly Authority read;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object source = new();
    private readonly Dictionary<Guid, Plan> plans = [];
    private string GroupId => $"/subscriptions/{host.SubscriptionId:D}/resourceGroups/{host.ResourceGroup}";

    internal AuditDiagnosticSettings(RoleFixtureJournal journal, HostScope host, Authority setup, Authority read,
        Limits limits, TimeProvider? time = null)
    {
        Require(journal is not null && host is not null && host.SubscriptionId != Guid.Empty &&
            host.TenantId != Guid.Empty && host.QueryWorkspaceId != Guid.Empty && host.ExclusiveFixtureNamespace &&
            Segment(host.ResourceGroup, 90) && Segment(host.Location, 50) &&
            WorkspaceId(host.WorkspaceArmId) && setup is not null && read is not null &&
            setup.Credential is not null && read.Credential is not null &&
            setup.Transport is not null && read.Transport is not null &&
            !ReferenceEquals(setup.Credential, read.Credential) &&
            !ReferenceEquals(setup.Transport, read.Transport) &&
            setup.Label is { Length: > 0 and <= 128 } && read.Label is { Length: > 0 and <= 128 } &&
            setup.Label != read.Label && limits is not null &&
            limits.MaximumResponseBytes is >= 1024 and <= 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.journal = journal!;
        this.host = host!;
        this.setup = setup!;
        this.read = read!;
        this.limits = limits!;
        this.time = time ?? TimeProvider.System;
    }

    // Local object distinction prevents aliasing, not shared-principal cloud use.
    // The host supplies a separate trusted durable directory, never the base root.
    internal Plan PlanFixture(string owner, FixtureSelector selector, string exactVaultId)
    {
        ValidateVaultId(exactVaultId);
        var plan = new Plan(source, owner, selector, Guid.Empty, exactVaultId);
        var state = journal.Prepare(owner, selector,
            [new(plan.SettingsId, false), new(host.WorkspaceArmId, true)]);
        var retained = new Plan(source, owner, selector, state.LeaseId, exactVaultId);
        lock (plans) plans.Add(selector.Nonce, retained);
        return retained;
    }

    internal RoleFixtureJournal.Snapshot CloseSelectedRoot(string owner, FixtureSelector selector) =>
        journal.Close(owner, selector);

    internal async ValueTask<Result> ProvisionAsync(Plan plan, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(plan is not null && ReferenceEquals(plan.Source, source));
        Require(Interlocked.Exchange(ref plan!.Consumed, 1) == 0);
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            var state = ReadPlan(plan.Owner, plan.Selector);
            Require(!state.Closing && state.LeaseId == plan.LeaseId &&
                state.Resources.All(r => !r.CreateAttempted));
            await ValidateBorrowedWorkspace(linked.Token).ConfigureAwait(false);
            await ValidateOwnedVault(plan, linked.Token).ConfigureAwait(false);
            using (var existing = await Get(plan.SettingsId, SettingsRevision, linked.Token).ConfigureAwait(false))
                Require(existing is null);
            State outcome = await Mutate(plan, false, linked.Token).ConfigureAwait(false);
            if (outcome != State.Ready) return Finish(outcome, plan);
            // A selected PUT acknowledgement is never readback authority.
            return await ObserveCore(plan, linked.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(exception is ReadDeniedException ? State.Denied : State.Uncertain, plan);
        }
    }

    internal async ValueTask<Result> ObserveAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var plan = Reconstruct(ReadPlan(owner, selector));
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try { return await ObserveCore(plan, linked.Token).ConfigureAwait(false); }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(exception is ReadDeniedException ? State.Denied : State.Uncertain, plan);
        }
    }

    internal async ValueTask<Result> ReleaseAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = journal.Close(owner, selector);
        if (snapshot.Resources.Length == 0) return new() { State = State.Released, Journal = snapshot };
        var plan = Reconstruct(ReadPlan(owner, selector));
        RecoverFinalization(plan);
        snapshot = ReadPlan(owner, selector);
        // Termination is not settlement. Lost/202/crashed sends remain pending
        // across restart, even when a later GET reports absence.
        if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty)) return Finish(State.Pending, plan);
        using var deadline = new CancellationTokenSource(limits.Timeout, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            using (var settings = await Get(plan.SettingsId, SettingsRevision, linked.Token).ConfigureAwait(false))
            {
                if (settings is not null)
                {
                    journal.RecordPresence(owner, selector, plan.SettingsId);
                    Require(Same(Text(settings.RootElement, "id"), plan.SettingsId));
                    await ValidateOwnedVault(plan, linked.Token).ConfigureAwait(false);
                    var row = snapshot.Resources.Single(r => !r.Borrowed);
                    Require(row.CreateAttempted);
                    if (!row.DeleteAttempted)
                        await Mutate(plan, true, linked.Token).ConfigureAwait(false);
                }
            }
            snapshot = ReadPlan(owner, selector);
            if (snapshot.Resources.Any(r => r.ActiveDispatch != Guid.Empty)) return Finish(State.Pending, plan);
            using var after = await Get(plan.SettingsId, SettingsRevision, linked.Token).ConfigureAwait(false);
            if (after is null) journal.RecordAbsence(owner, selector, plan.SettingsId);
            else journal.RecordPresence(owner, selector, plan.SettingsId);
            return Finish(journal.Read(owner, selector).Released ? State.Released : State.Closing, plan);
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested) throw new OperationCanceledException(cancellationToken);
            return Finish(exception is ReadDeniedException ? State.Denied : State.Uncertain, plan);
        }
    }

    private async Task<Result> ObserveCore(Plan plan, CancellationToken token)
    {
        RecoverFinalization(plan);
        await ValidateBorrowedWorkspace(token).ConfigureAwait(false);
        await ValidateOwnedVault(plan, token).ConfigureAwait(false);
        using var settings = await Get(plan.SettingsId, SettingsRevision, token).ConfigureAwait(false);
        bool ready = settings is not null;
        if (settings is not null) ValidateSettings(plan, settings.RootElement);
        var state = ReadPlan(plan.Owner, plan.Selector);
        return Finish(state.Resources.Any(r => r.ActiveDispatch != Guid.Empty) ? State.Pending :
            state.Closing ? State.Closing : ready ? State.Ready : State.Incomplete, plan, ready);
    }

    private async Task ValidateBorrowedWorkspace(CancellationToken token)
    {
        using var workspace = await Get(host.WorkspaceArmId, WorkspaceRevision, token).ConfigureAwait(false);
        Require(workspace is not null);
        var root = workspace!.RootElement;
        Require(Same(Text(root, "id"), host.WorkspaceArmId) &&
            Same(Text(root, "type"), "Microsoft.OperationalInsights/workspaces"));
        var properties = root.GetProperty("properties");
        Require(Guid.TryParse(Text(properties, "customerId"), out var customer) && customer == host.QueryWorkspaceId &&
            Text(properties, "provisioningState") == "Succeeded");
    }

    private async Task ValidateOwnedVault(Plan plan, CancellationToken token)
    {
        using var vault = await Get(plan.VaultId, VaultRevision, token).ConfigureAwait(false);
        Require(vault is not null);
        var root = vault!.RootElement;
        Require(Same(Text(root, "id"), plan.VaultId) && Same(Text(root, "location"), host.Location) &&
            Same(Text(root, "type"), "Microsoft.KeyVault/vaults") &&
            Text(root.GetProperty("tags"), "secretkit-fixture") == plan.Selector.Nonce.ToString("N"));
        var properties = root.GetProperty("properties");
        Require(Guid.TryParse(Text(properties, "tenantId"), out var tenant) && tenant == host.TenantId &&
            Text(properties, "provisioningState") == "Succeeded");
    }

    private void ValidateSettings(Plan plan, JsonElement root)
    {
        Require(Same(Text(root, "id"), plan.SettingsId));
        var properties = root.GetProperty("properties");
        Require(Same(Text(properties, "workspaceId"), host.WorkspaceArmId) &&
            Empty(properties, "logAnalyticsDestinationType") &&
            Empty(properties, "storageAccountId") && Empty(properties, "eventHubAuthorizationRuleId") &&
            Empty(properties, "eventHubName") && Empty(properties, "marketplacePartnerId") &&
            Empty(properties, "serviceBusRuleId"));
        var logs = properties.GetProperty("logs");
        Require(logs.ValueKind == JsonValueKind.Array && logs.GetArrayLength() == 1);
        var audit = logs[0];
        Require(Text(audit, "category") == "AuditEvent" && Empty(audit, "categoryGroup") &&
            audit.GetProperty("enabled").ValueKind == JsonValueKind.True);
        if (properties.TryGetProperty("metrics", out var metrics) && metrics.ValueKind != JsonValueKind.Null)
            Require(metrics.ValueKind == JsonValueKind.Array && metrics.GetArrayLength() == 0);
    }

    private async Task<State> Mutate(Plan plan, bool delete, CancellationToken token)
    {
        var receipt = new Receipt(delete);
        lock (plan.History) plan.History.Add(receipt);
        using var boundary = Boundary(setup, plan.SettingsId, SettingsRevision,
            delete ? RequestMethod.Delete : RequestMethod.Put, () =>
            {
                receipt.Dispatch = journal.BeginDispatch(plan.Owner, plan.Selector, plan.SettingsId, delete);
                receipt.Attempted = true;
            });
        byte[]? body = delete ? null : JsonSerializer.SerializeToUtf8Bytes(new
        {
            properties = new
            {
                workspaceId = host.WorkspaceArmId,
                logs = new[] { new { category = "AuditEvent", enabled = true } },
                metrics = Array.Empty<object>(),
                logAnalyticsDestinationType = (string?)null
            }
        });
        try
        {
            return await Send(setup, boundary, plan.SettingsId, SettingsRevision,
                delete ? RequestMethod.Delete : RequestMethod.Put, body, token, response =>
            {
                Require(boundary.Valid);
                if (response.Status is 401 or 403)
                {
                    receipt.RemoteSettled = true;
                    return State.Denied;
                }
                if (response.Status == 202) return State.Pending;
                // Native synchronous DELETE is bodyless. Async operation headers
                // are not settlement evidence and are never followed.
                if (delete)
                {
                    Require(response.Status is 200 or 204);
                    Require(!AsyncHeaders(response));
                    receipt.RemoteSettled = true;
                    return State.Ready;
                }
                Require(response.Status == 200 && !AsyncHeaders(response));
                using var document = Parse(response);
                ValidateSettings(plan, document.RootElement);
                receipt.RemoteSettled = true;
                return State.Ready;
            }).ConfigureAwait(false);
        }
        catch
        {
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
            return State.Uncertain;
        }
        finally
        {
            if (body is not null) CryptographicOperations.ZeroMemory(body);
            receipt.HttpStatus = boundary.Status;
            receipt.Terminated = true;
            if (receipt.Attempted)
                journal.EndDispatch(plan.Owner, plan.Selector, plan.SettingsId, receipt.Dispatch, receipt.RemoteSettled);
        }
    }

    private async Task<JsonDocument?> Get(string id, string revision, CancellationToken token)
    {
        using var boundary = Boundary(read, id, revision, RequestMethod.Get);
        return await Send(read, boundary, id, revision, RequestMethod.Get, null, token, response =>
        {
            Require(boundary.Valid);
            if (response.Status is 401 or 403) throw new ReadDeniedException();
            if (response.Status == 404) return null;
            Require(response.Status == 200);
            return Parse(response);
        }).ConfigureAwait(false);
    }

    private RoleFixtureProvisioner.BoundaryTransport Boundary(Authority authority, string id, string revision,
        RequestMethod method, Action? beforeSend = null) =>
        new(authority.Transport, Origin, id, revision, method, limits.MaximumResponseBytes, false, beforeSend);

    private static async Task<T> Send<T>(Authority authority,
        RoleFixtureProvisioner.BoundaryTransport boundary, string id, string revision,
        RequestMethod method, byte[]? body, CancellationToken token, Func<Azure.Response, T> consume)
    {
        var options = new ArmClientOptions { Transport = boundary };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        var pipeline = HttpPipelineBuilder.Build(options);
        using var message = pipeline.CreateMessage();
        message.Request.Method = method;
        message.Request.Uri.Reset(new Uri(Origin + id + "?api-version=" + revision));
        var access = await authority.Credential.GetTokenAsync(new([Origin + "/.default"]), token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        Require(!string.IsNullOrWhiteSpace(access.Token) && access.ExpiresOn > DateTimeOffset.UtcNow);
        message.Request.Headers.SetValue("Authorization", "Bearer " + access.Token);
        if (body is not null)
        {
            message.Request.Headers.SetValue("Content-Type", "application/json");
            message.Request.Content = RequestContent.Create(body);
        }
        message.BufferResponse = false;
        await pipeline.SendAsync(message, token).ConfigureAwait(false);
        // Consume while the message owns its response. Parsed documents own
        // their storage; no disposed SDK response escapes this scope.
        return consume(message.Response);
    }

    private static JsonDocument Parse(Azure.Response response) =>
        JsonDocument.Parse(response.ContentStream ?? throw Failure(), new JsonDocumentOptions { MaxDepth = 32 });
    private static bool AsyncHeaders(Azure.Response response) =>
        new[] { "Azure-AsyncOperation", "Operation-Location", "Location" }
            .Any(header => response.Headers.TryGetValue(header, out _));

    private RoleFixtureJournal.Snapshot ReadPlan(string owner, FixtureSelector selector)
    {
        var snapshot = journal.Read(owner, selector);
        Require(snapshot.Resources.Length == 2 && snapshot.Resources.Count(r => r.Borrowed) == 1 &&
            snapshot.Resources.All(r => !r.CleanupOnly && !r.SelectedAttempted));
        var workspace = snapshot.Resources.Single(r => r.Borrowed);
        Require(Same(workspace.Id, host.WorkspaceArmId) && !workspace.CreateAttempted && !workspace.DeleteAttempted &&
            workspace.ActiveDispatch == Guid.Empty && !workspace.Absent);
        string settings = snapshot.Resources.Single(r => !r.Borrowed).Id;
        string suffix = Extension + "sk-audit-" + selector.Nonce.ToString("N");
        Require(settings.EndsWith(suffix, StringComparison.Ordinal));
        ValidateVaultId(settings[..^suffix.Length]);
        return snapshot;
    }

    private Plan Reconstruct(RoleFixtureJournal.Snapshot snapshot)
    {
        string settings = snapshot.Resources.Single(r => !r.Borrowed).Id;
        lock (plans)
        {
            if (plans.TryGetValue(snapshot.Selector.Nonce, out var retained))
            {
                Require(retained.Owner == snapshot.Owner && retained.Selector == snapshot.Selector &&
                    retained.LeaseId == snapshot.LeaseId && Same(retained.SettingsId, settings));
                return retained;
            }
        }
        return new(source, snapshot.Owner, snapshot.Selector, snapshot.LeaseId,
            settings[..settings.LastIndexOf(Extension, StringComparison.Ordinal)]);
    }
    private void RecoverFinalization(Plan plan)
    {
        // Only retained actual invocation completion can repair a failed local
        // append. Reopening the source loses that evidence and stays pending.
        foreach (var receipt in plan.Receipts)
        {
            if (!receipt.Attempted || !receipt.Terminated) continue;
            var row = ReadPlan(plan.Owner, plan.Selector).Resources.Single(r => !r.Borrowed);
            if (row.ActiveDispatch == receipt.Dispatch && (!row.InvocationTerminated || receipt.RemoteSettled))
                journal.EndDispatch(plan.Owner, plan.Selector, plan.SettingsId, receipt.Dispatch, receipt.RemoteSettled);
        }
    }
    private Result Finish(State state, Plan plan, bool ready = false) => new()
    {
        State = state,
        RoutingReady = ready,
        Journal = journal.Read(plan.Owner, plan.Selector),
        Receipts = plan.Receipts
    };
    private void ValidateVaultId(string id)
    {
        string prefix = GroupId + "/providers/Microsoft.KeyVault/vaults/";
        Require(id is { Length: <= 2048 } && id.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        string name = id[prefix.Length..];
        Require(name.Length is >= 3 and <= 24 && char.IsAsciiLetter(name[0]) &&
            char.IsAsciiLetterOrDigit(name[^1]) && name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') &&
            !name.Contains("--", StringComparison.Ordinal));
    }
    private static bool WorkspaceId(string? id)
    {
        if (id is not { Length: <= 2048 }) return false;
        string[] parts = id.Split('/');
        return parts.Length == 9 && parts[0] == "" && Same(parts[1], "subscriptions") &&
            Guid.TryParseExact(parts[2], "D", out var subscription) && subscription != Guid.Empty &&
            Same(parts[3], "resourceGroups") && Segment(parts[4], 90) && Same(parts[5], "providers") &&
            Same(parts[6], "Microsoft.OperationalInsights") && Same(parts[7], "workspaces") &&
            parts[8].Length is >= 4 and <= 63 &&
            char.IsAsciiLetterOrDigit(parts[8][0]) && char.IsAsciiLetterOrDigit(parts[8][^1]) &&
            parts[8].All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    }
    private static bool Segment(string? text, int maximum) => text is { Length: > 0 } &&
        text.Length <= maximum && text is not ("." or "..") &&
        text.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static string? Text(JsonElement node, string name) => node.GetProperty(name).GetString();
    private static bool Empty(JsonElement node, string name) =>
        !node.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null;
    private static bool Same(string? left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static void Require(bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("audit-diagnostic-settings-boundary");
    private sealed class ReadDeniedException : Exception;
    public override string ToString() => "[AuditDiagnosticSettings]";
}
