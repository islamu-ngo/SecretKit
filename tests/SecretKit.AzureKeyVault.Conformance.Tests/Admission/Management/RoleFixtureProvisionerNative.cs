using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.ResourceManager;
using Azure.ResourceManager.Authorization;
using Azure.ResourceManager.KeyVault;
using Azure.Security.KeyVault.Secrets;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal sealed partial class RoleFixtureProvisioner
{
    internal sealed record StatusRoleMetadata(string Id, string Name, string Type, string Scope,
        string RoleDefinitionId, Guid PrincipalId, string? PrincipalType, string? Description,
        string? Condition, string? ConditionVersion, DateTimeOffset? CreatedOn, DateTimeOffset? UpdatedOn,
        string? CreatedBy, string? UpdatedBy, string? DelegatedManagedIdentityResourceId)
    {
        public override string ToString() => "[StatusRoleMetadata]";
    }

    internal sealed class StatusRoleDeleteReadProof(Plan plan, object slot, Guid subscription, Guid selectedDispatch,
        Authority reader, DateTimeOffset armedAt, Task nativeTask, RequestFailedException? nativeError,
        int httpStatus, StatusRoleMetadata? metadata, string requestSha256, string responseSha256,
        string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal object Source => Plan.Source;
        internal object Slot { get; } = slot;
        internal string Owner => Plan.Owner;
        internal FixtureSelector Selector => Plan.Selector;
        internal Guid LeaseId => Plan.LeaseId;
        internal Guid Subscription { get; } = subscription;
        internal Guid SelectedDispatch { get; } = selectedDispatch;
        internal string ApiRevision => RoleRevision;
        internal string ResourceId => Plan.AssignmentId;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Authority Reader { get; } = reader;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal Task NativeTask { get; } = nativeTask;
        internal RequestFailedException? NativeError { get; } = nativeError;
        internal int HttpStatus { get; } = httpStatus;
        internal int NativeStatus => NativeError?.Status ?? 200;
        internal bool Present => Metadata is not null;
        internal StatusRoleMetadata? Metadata { get; } = metadata;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusRoleDeleteReadProof]";
    }

    internal sealed class StatusRoleDeleteIndependentReadProof(Plan plan, object slot, Guid subscription, Guid selectedDispatch,
        Authority reader, DateTimeOffset armedAt, Task nativeTask, RequestFailedException? nativeError,
        int httpStatus, StatusRoleMetadata? metadata, string requestSha256, string responseSha256,
        string nativeRequestId, DateTimeOffset startedAt, DateTimeOffset finishedAt)
    {
        internal Plan Plan { get; } = plan;
        internal object Source => Plan.Source;
        internal object Slot { get; } = slot;
        internal string Owner => Plan.Owner;
        internal FixtureSelector Selector => Plan.Selector;
        internal Guid LeaseId => Plan.LeaseId;
        internal Guid Subscription { get; } = subscription;
        internal Guid SelectedDispatch { get; } = selectedDispatch;
        internal string ApiRevision => RoleRevision;
        internal string ResourceId => Plan.AssignmentId;
        internal string Phase => SelectedDispatch == Guid.Empty ? "baseline-before-dispatch" : "selected-state";
        internal Authority Reader { get; } = reader;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal Task NativeTask { get; } = nativeTask;
        internal RequestFailedException? NativeError { get; } = nativeError;
        internal int HttpStatus { get; } = httpStatus;
        internal int NativeStatus => NativeError?.Status ?? 200;
        internal bool Present => Metadata is not null;
        internal StatusRoleMetadata? Metadata { get; } = metadata;
        internal string RequestSha256 { get; } = requestSha256;
        internal string ResponseSha256 { get; } = responseSha256;
        internal string NativeRequestId { get; } = nativeRequestId;
        internal DateTimeOffset StartedAt { get; } = startedAt;
        internal DateTimeOffset FinishedAt { get; } = finishedAt;
        public override string ToString() => "[StatusRoleDeleteIndependentReadProof]";
    }

    internal async ValueTask<StatusRoleDeleteReadProof> ObserveStatusRoleDeleteCancellationAsync(
        Plan originalPlan, Guid selectedDispatch, CancellationToken token)
    {
        StatusRoleReadSlots slots;
        lock (plans)
        {
            Require(statusRoleReads.TryGetValue(originalPlan, out slots!) && prepared.Contains(originalPlan));
            if (selectedDispatch == Guid.Empty)
            {
                Require(!slots.Baseline && !slots.After);
                slots.Baseline = true;
            }
            else
            {
                Require(slots.Baseline && !slots.After);
                slots.After = true;
            }
        }
        var state = ReadPlan(originalPlan.Owner, originalPlan.Selector);
        Require(!state.Closing && RoleFixtureJournal.StatusRoleDeleteRoot(state) &&
            state.LeaseId == originalPlan.LeaseId &&
            state.Resources.Single(r => r.Id == originalPlan.AssignmentId) is { } row &&
            (selectedDispatch == Guid.Empty ? !row.SelectedAttempted && row.ActiveDispatch == Guid.Empty :
                row.SelectedAttempted && row.ActiveDispatch == selectedDispatch && row.InvocationTerminated));
        DateTimeOffset started = time.GetUtcNow();
        Require(started >= slots.ArmedAt);
        var read = await ReadArm(originalPlan, slots.Reader, token).ConfigureAwait(false);
        Require(selectedDispatch == Guid.Empty ? read.Metadata is not null : read.Metadata is null);
        var finishedState = ReadPlan(originalPlan.Owner, originalPlan.Selector);
        Require(!finishedState.Closing && finishedState.LeaseId == originalPlan.LeaseId &&
            finishedState.Resources.Single(r => r.Id == originalPlan.AssignmentId) is { } finishedRow &&
            (selectedDispatch == Guid.Empty ? !finishedRow.SelectedAttempted && finishedRow.ActiveDispatch == Guid.Empty :
                finishedRow.SelectedAttempted && finishedRow.ActiveDispatch == selectedDispatch && finishedRow.InvocationTerminated));
        var proof = new StatusRoleDeleteReadProof(originalPlan, selectedDispatch == Guid.Empty ? slots.BaselineSlot : slots.AfterSlot,
            slots.Subscription, selectedDispatch, slots.Reader,
            slots.ArmedAt, read.Task, read.Error, read.Status, read.Metadata, read.RequestHash, read.ResponseHash,
            read.RequestId, started, time.GetUtcNow());
        Require(proof.FinishedAt >= started && !token.IsCancellationRequested);
        lock (plans) issuedStatusRoleReads.Add(proof);
        return proof;
    }

    internal async ValueTask<StatusRoleDeleteIndependentReadProof> ObserveStatusRoleDeleteIndependentAsync(
        Plan originalPlan, Guid selectedDispatch, CancellationToken token)
    {
        StatusRoleReadSlots slots = null!;
        lock (plans)
        {
            Require(independentPlans.Contains(originalPlan) && !originalPlan.IndependentRestored &&
                prepared.Contains(originalPlan) && independentReads.TryGetValue(originalPlan, out slots!));
            if (selectedDispatch == Guid.Empty)
            {
                Require(!slots.Baseline && !slots.After);
                slots.Baseline = true;
            }
            else
            {
                Require(slots.Baseline && !slots.After);
                slots.After = true;
            }
        }
        if (Interlocked.Exchange(ref originalPlan.Busy, 1) != 0) throw Failure();
        try
        {
            var state = FreezeIndependent(ReadPlan(originalPlan.Owner, originalPlan.Selector));
            Require(!state.Closing && RoleFixtureJournal.StatusRoleDeleteIndependentRoot(state) &&
                state.LeaseId == originalPlan.LeaseId &&
                state.Resources.Single(r => r.Id == originalPlan.AssignmentId) is { } row &&
                (selectedDispatch == Guid.Empty
                    ? RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(originalPlan.IndependentReady!, state) &&
                        !row.SelectedAttempted && row.ActiveDispatch == Guid.Empty
                    : row.SelectedAttempted && row.ActiveDispatch == selectedDispatch && row.InvocationTerminated));
            DateTimeOffset started = time.GetUtcNow();
            Require(started >= slots.ArmedAt);
            var read = await ReadArm(originalPlan, slots.Reader, token).ConfigureAwait(false);
            Require(selectedDispatch == Guid.Empty ? read.Metadata is not null : read.Metadata is null);
            Require(RoleFixtureJournal.SameStatusRoleDeleteIndependentSnapshot(state,
                ReadPlan(originalPlan.Owner, originalPlan.Selector)));
            var proof = new StatusRoleDeleteIndependentReadProof(originalPlan,
                selectedDispatch == Guid.Empty ? slots.BaselineSlot : slots.AfterSlot, slots.Subscription, selectedDispatch,
                slots.Reader, slots.ArmedAt, read.Task, read.Error, read.Status, read.Metadata, read.RequestHash,
                read.ResponseHash, read.RequestId, started, time.GetUtcNow());
            Require(!token.IsCancellationRequested && proof.FinishedAt >= started);
            lock (plans) issuedIndependentReads.Add(proof);
            return proof;
        }
        finally { Volatile.Write(ref originalPlan.Busy, 0); }
    }

    private sealed record StatusRoleRead(Task Task, RequestFailedException? Error, int Status,
        StatusRoleMetadata? Metadata, RoleAssignmentData? Data, string RequestHash, string ResponseHash, string RequestId);

    private async Task<StatusRoleRead> ReadArm(Plan plan, Authority reader, CancellationToken token)
    {
        using var transport = new BoundaryTransport(reader.Transport, ArmOrigin, plan.AssignmentId, RoleRevision,
            RequestMethod.Get, limits.MaximumResponseBytes, false, strictRole: true,
            rolePresence: () =>
            {
                if (journal.Read(plan.Owner, plan.Selector).Closing)
                    journal.RecordPresence(plan.Owner, plan.Selector, plan.AssignmentId);
            });
        Task<Response<RoleAssignmentResource>> task = Arm(reader, transport)
            .GetRoleAssignmentResource(new(plan.AssignmentId)).GetAsync(cancellationToken: token);
        StatusRoleMetadata? metadata = null;
        RoleAssignmentData? data = null;
        RequestFailedException? error = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            Require(transport.Status == 200 && raw.Status == 200 && transport.RoleBody is not null &&
                transport.RoleParser is { } parser && parser.Owns(raw));
            data = response.Value.Data;
            metadata = ParseStatusRole(transport.RoleBody!.Bytes, plan, data);
        }
        catch (RequestFailedException failure) when (failure.Status == 404 && failure.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && transport.Status == 404 && transport.RoleBody is not null);
            using var json = JsonDocument.Parse(transport.RoleBody!.Bytes);
            var root = json.RootElement;
            Require(OnlyRoleFields(root, "error") && root.TryGetProperty("error", out var detail) &&
                OnlyRoleFields(detail, "code", "message") &&
                detail.GetProperty("code").GetString() == "ResourceNotFound" &&
                (!detail.TryGetProperty("message", out var message) ||
                    message.ValueKind == JsonValueKind.String && message.GetString() is { Length: <= 4096 }));
            error = failure;
        }
        Require(transport.RoleParser is { Complete: true, Invalid: false } && transport.Valid &&
            transport.RoleIntegrity is not null && transport.RoleIntegrity() &&
            (metadata is null ? task.IsFaulted && error is not null : task.IsCompletedSuccessfully));
        string responseHash = transport.BodySha256!, requestHash = transport.RequestSha256!, requestId = transport.RequestId!;
        int status = transport.Status!.Value;
        transport.Dispose();
        return new(task, error, status, metadata, data, requestHash, responseHash, requestId);
    }

    private StatusRoleMetadata ParseStatusRole(ReadOnlyMemory<byte> bytes, Plan plan, RoleAssignmentData native)
    {
        using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = json.RootElement;
        Require(OnlyRoleFields(root, "id", "name", "type", "properties"));
        var properties = root.GetProperty("properties");
        Require(OnlyRoleFields(properties, "scope", "roleDefinitionId", "principalId", "principalType",
            "description", "condition", "conditionVersion", "createdOn", "updatedOn", "createdBy", "updatedBy",
            "delegatedManagedIdentityResourceId"));
        string Required(JsonElement node, string name) => Optional(node, name) ?? throw Failure();
        string? Optional(JsonElement node, string name)
        {
            if (!node.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
            Require(value.ValueKind == JsonValueKind.String && value.GetString() is { Length: <= 16384 });
            return value.GetString();
        }
        DateTimeOffset? Date(string name)
        {
            string? value = Optional(properties, name);
            if (value is null) return null;
            Require(properties.GetProperty(name).TryGetDateTimeOffset(out _));
            return properties.GetProperty(name).GetDateTimeOffset();
        }
        string? Audit(string name)
        {
            string? value = Optional(properties, name);
            Require(value is null || Guid.TryParse(value, out _));
            return value;
        }
        string? delegated = Optional(properties, "delegatedManagedIdentityResourceId");
        if (delegated is not null) Require(new ResourceIdentifier(delegated).ToString() == delegated);
        var observed = new StatusRoleMetadata(Required(root, "id"), Required(root, "name"), Required(root, "type"),
            Required(properties, "scope"), Required(properties, "roleDefinitionId"),
            Guid.Parse(Required(properties, "principalId")), Optional(properties, "principalType"),
            Optional(properties, "description"), Optional(properties, "condition"), Optional(properties, "conditionVersion"),
            Date("createdOn"), Date("updatedOn"), Audit("createdBy"), Audit("updatedBy"), delegated);
        var actual = new StatusRoleMetadata(native.Id.ToString(), native.Name, native.ResourceType.ToString(),
            native.Scope, native.RoleDefinitionId.ToString(), native.PrincipalId ?? Guid.Empty, native.PrincipalType?.ToString(),
            native.Description, native.Condition, native.ConditionVersion, native.CreatedOn, native.UpdatedOn,
            native.CreatedBy, native.UpdatedBy, native.DelegatedManagedIdentityResourceId?.ToString());
        Require(observed == actual && observed.Id == plan.AssignmentId &&
            observed.Name == plan.AssignmentId[(plan.AssignmentId.LastIndexOf('/') + 1)..] &&
            observed.Type == "Microsoft.Authorization/roleAssignments" && observed.Scope == plan.VaultId &&
            observed.RoleDefinitionId == DefinitionId && observed.PrincipalId == host.IntendedPrincipalId);
        return observed;
    }

    private static bool OnlyRoleFields(JsonElement node, params string[] names) =>
        node.ValueKind == JsonValueKind.Object &&
        node.EnumerateObject().All(p => names.Contains(p.Name, StringComparer.Ordinal)) &&
        node.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == node.EnumerateObject().Count();

    private sealed record IndependentOwnedRead(Task Task, RequestFailedException? Error, int Status,
        KeyVaultData? Vault, DeletedKeyVaultData? Deleted, string RequestHash, string ResponseHash, string RequestId)
    {
        internal bool Absent => Task.IsFaulted && Status == 404 &&
            Error is { Status: 404, ErrorCode: "ResourceNotFound" } && Vault is null && Deleted is null;
        public override string ToString() => "[IndependentOwnedRead]";
    }

    private async Task<IndependentOwnedRead> ReadIndependentOwned(Plan plan, bool deleted, CancellationToken token)
    {
        string id = deleted ? DeletedId(plan.VaultName) : plan.VaultId;
        using var transport = new BoundaryTransport(observeArm.Transport, ArmOrigin, id, VaultRevision,
            RequestMethod.Get, limits.MaximumResponseBytes, false, rolePresence: () =>
            {
                if (journal.Read(plan.Owner, plan.Selector).Closing)
                    journal.RecordPresence(plan.Owner, plan.Selector, id);
            }, strictOwnedRead: true);
        var client = Arm(observeArm, transport);
        Task<Response<KeyVaultResource>>? vaultTask = null;
        Task<Response<DeletedKeyVaultResource>>? deletedTask = null;
        if (deleted) deletedTask = client.GetDeletedKeyVaultResource(new(id)).GetAsync(token);
        else vaultTask = client.GetKeyVaultResource(new(id)).GetAsync(token);
        Task task = (Task?)vaultTask ?? deletedTask!;
        KeyVaultData? vault = null;
        DeletedKeyVaultData? marker = null;
        RequestFailedException? error = null;
        try
        {
            if (deleted)
            {
                var response = await deletedTask!.ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(raw.Status == 200 && transport.RoleParser is { } parser && parser.Owns(raw));
                marker = response.Value.Data;
                ValidateDeleted(plan, marker);
            }
            else
            {
                var response = await vaultTask!.ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(raw.Status == 200 && transport.RoleParser is { } parser && parser.Owns(raw));
                vault = response.Value.Data;
                ValidateVault(plan, vault);
            }
            Require(transport.Status == 200 && transport.RoleBody is not null);
            ValidateIndependentOwnedBody(plan, transport.RoleBody!.Bytes, vault, marker);
        }
        catch (RequestFailedException failure) when (failure.Status == 404 && failure.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && transport.Status == 404 && transport.RoleBody is not null);
            using var json = JsonDocument.Parse(transport.RoleBody!.Bytes);
            var root = json.RootElement;
            Require(OnlyRoleFields(root, "error") && root.TryGetProperty("error", out var detail) &&
                OnlyRoleFields(detail, "code", "message") && detail.GetProperty("code").GetString() == "ResourceNotFound" &&
                (!detail.TryGetProperty("message", out var message) ||
                    message.ValueKind == JsonValueKind.String && message.GetString() is { Length: <= 4096 }));
            error = failure;
        }
        Require(transport.Valid && transport.RoleParser is { Complete: true, Invalid: false } &&
            transport.RoleIntegrity is not null && transport.RoleIntegrity() &&
            (error is null ? task.IsCompletedSuccessfully : task.IsFaulted));
        var result = new IndependentOwnedRead(task, error, transport.Status!.Value, vault, marker,
            transport.RequestSha256!, transport.BodySha256!, transport.RequestId!);
        transport.Dispose();
        token.ThrowIfCancellationRequested();
        return result;
    }

    private void ValidateIndependentOwnedBody(Plan plan, ReadOnlyMemory<byte> bytes, KeyVaultData? vault,
        DeletedKeyVaultData? deleted)
    {
        using var json = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 8 });
        var root = json.RootElement;
        var properties = root.GetProperty("properties");
        bool marker = deleted is not null;
        Require(OnlyRoleFields(root, marker ? ["id", "name", "type", "properties"] :
            ["id", "name", "type", "location", "tags", "properties"]) &&
            root.GetProperty("id").GetString() == (marker ? DeletedId(plan.VaultName) : plan.VaultId) &&
            root.GetProperty("name").GetString() == plan.VaultName &&
            root.GetProperty("type").GetString() == (marker ? "Microsoft.KeyVault/deletedVaults" : "Microsoft.KeyVault/vaults"));
        var tags = marker ? properties.GetProperty("tags") : root.GetProperty("tags");
        Require(OnlyRoleFields(tags, OwnershipTag) && tags.GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N"));
        if (marker)
        {
            Require(OnlyRoleFields(properties, "vaultId", "location", "tags", "purgeProtectionEnabled",
                "deletionDate", "scheduledPurgeDate") &&
                properties.GetProperty("vaultId").GetString() == plan.VaultId &&
                properties.GetProperty("location").GetString() == host.Location &&
                properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted!.Properties.PurgeProtectionEnabled &&
                deleted.Properties.PurgeProtectionEnabled == false &&
                properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Properties.DeletedOn &&
                properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Properties.ScheduledPurgeOn);
        }
        else
        {
            var native = vault!.Properties;
            var sku = properties.GetProperty("sku");
            Require(root.GetProperty("location").GetString() == host.Location &&
                OnlyRoleFields(properties, "tenantId", "sku", "vaultUri", "provisioningState", "enableRbacAuthorization",
                    "enableSoftDelete", "enablePurgeProtection", "softDeleteRetentionInDays", "publicNetworkAccess",
                    "createMode", "accessPolicies") &&
                OnlyRoleFields(sku, "family", "name") && sku.GetProperty("family").GetString() == "A" &&
                native.Sku.Family.ToString() == "A" &&
                string.Equals(sku.GetProperty("name").GetString(), native.Sku.Name.ToString(), StringComparison.OrdinalIgnoreCase) &&
                string.Equals(native.Sku.Name.ToString(), "standard", StringComparison.OrdinalIgnoreCase) &&
                properties.GetProperty("tenantId").GetGuid() == host.TenantId &&
                properties.GetProperty("vaultUri").GetString() == SecretOrigin(plan).AbsoluteUri.TrimEnd('/') &&
                properties.GetProperty("provisioningState").GetString() == native.ProvisioningState?.ToString() &&
                properties.GetProperty("enableRbacAuthorization").GetBoolean() && native.EnableRbacAuthorization == true &&
                properties.GetProperty("enableSoftDelete").GetBoolean() && native.EnableSoftDelete == true &&
                !properties.GetProperty("enablePurgeProtection").GetBoolean() && native.EnablePurgeProtection == false);
            if (properties.TryGetProperty("softDeleteRetentionInDays", out var retention))
                Require(retention.GetInt32() == 7 && native.SoftDeleteRetentionInDays == 7);
            if (properties.TryGetProperty("publicNetworkAccess", out var access))
                Require(access.GetString() == "Enabled" && native.PublicNetworkAccess?.ToString() == "Enabled");
            if (properties.TryGetProperty("createMode", out var mode))
                Require(string.Equals(mode.GetString(), "default", StringComparison.OrdinalIgnoreCase) &&
                    string.Equals(native.CreateMode?.ToString(), "default", StringComparison.OrdinalIgnoreCase));
            if (properties.TryGetProperty("accessPolicies", out var policies))
                Require(policies.ValueKind == JsonValueKind.Array && policies.GetArrayLength() == 0 && native.AccessPolicies.Count == 0);
        }
    }

    private ArmClient Arm(Authority authority, BoundaryTransport transport)
    {
        var options = new ArmClientOptions
        {
            Environment = new(new Uri(ArmOrigin), ArmOrigin),
            Transport = transport
        };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", VaultRevision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", VaultRevision);
        options.SetApiVersion("Microsoft.Authorization/roleAssignments", RoleRevision);
        options.SetApiVersion("Microsoft.Authorization/roleDefinitions", RoleRevision);
        return new(new AudienceCredential(authority.Credential, ArmOrigin + "/.default"), null, options);
    }

    private static SecretClient Secret(Authority authority, Plan plan, BoundaryTransport transport)
    {
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = transport };
        Quiet(options);
        return new(SecretOrigin(plan), new AudienceCredential(authority.Credential, "https://vault.azure.net/.default"), options);
    }

    private static void Quiet(ClientOptions options)
    {
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
    }

    private sealed class AudienceCredential(TokenCredential inner, string audience) : TokenCredential
    {
        private void Check(TokenRequestContext context)
        {
            Require(context.Scopes.Length == 1 && context.Scopes[0] == audience);
        }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Check(requestContext);
            return inner.GetToken(requestContext, cancellationToken);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            Check(requestContext);
            return inner.GetTokenAsync(requestContext, cancellationToken);
        }
    }

    private async Task<T?> ReadArm<T>(string id, Func<ArmClient, CancellationToken, Task<Response<T>>> read,
        CancellationToken token) where T : class
    {
        using var transport = new BoundaryTransport(observeArm.Transport, ArmOrigin, id, Revision(id),
            RequestMethod.Get, limits.MaximumResponseBytes, false);
        try
        {
            Response<T> response = await read(Arm(observeArm, transport), token).ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            Require(transport.Valid && transport.Status == 200);
            return response.Value;
        }
        catch (RequestFailedException) when (transport.Valid && transport.Status == 404) { return null; }
    }

    private async Task<KeyVaultData?> ObserveVault(Plan plan, CancellationToken token) =>
        StatusRoleDeleteIndependentSelector(plan.Selector)
            ? (await ReadIndependentOwned(plan, false, token).ConfigureAwait(false)).Vault
            : (await ReadArm(plan.VaultId, (client, ct) => client.GetKeyVaultResource(new(plan.VaultId))
                .GetAsync(ct), token).ConfigureAwait(false))?.Data;

    private async Task<DeletedKeyVaultData?> ObserveDeleted(Plan plan, CancellationToken token) =>
        StatusRoleDeleteIndependentSelector(plan.Selector)
            ? (await ReadIndependentOwned(plan, true, token).ConfigureAwait(false)).Deleted
            : (await ReadArm(DeletedId(plan.VaultName), (client, ct) => client.GetDeletedKeyVaultResource(new(DeletedId(plan.VaultName)))
                .GetAsync(ct), token).ConfigureAwait(false))?.Data;

    private async Task<bool> DeletedExists(Plan plan, CancellationToken token) =>
        await ObserveDeleted(plan, token).ConfigureAwait(false) is not null;

    private async Task<RoleAssignmentData?> ObserveAssignment(string id, CancellationToken token)
    {
        Plan? rolePlan;
        lock (plans) rolePlan = plans.Values.SingleOrDefault(p => p.AssignmentId == id &&
            (StatusRoleDeleteCancellationSelector(p.Selector) || StatusRoleDeleteIndependentSelector(p.Selector)));
        if (rolePlan is not null)
            return (await ReadArm(rolePlan, observeArm, token).ConfigureAwait(false)).Data;
        return (await ReadArm(id, (client, ct) => client.GetRoleAssignmentResource(new(id))
            .GetAsync(cancellationToken: ct), token).ConfigureAwait(false))?.Data;
    }

    private string DeletedId(string vaultName) => SubscriptionId +
        "/providers/Microsoft.KeyVault/locations/" + host.Location + "/deletedVaults/" + vaultName;

    private void ValidateVault(Plan plan, KeyVaultData data) =>
        Require(Same(data.Id?.ToString(), plan.VaultId) && Same(data.Location.Name, host.Location) &&
            data.Properties is { } properties && properties.TenantId == host.TenantId &&
            properties.EnableRbacAuthorization == true && properties.VaultUri == SecretOrigin(plan) &&
            data.Tags.TryGetValue(OwnershipTag, out string? nonce) && nonce == plan.Selector.Nonce.ToString("N"));

    private void ValidateDeleted(Plan plan, DeletedKeyVaultData data) =>
        Require(Same(data.Id?.ToString(), DeletedId(plan.VaultName)) &&
            data.Properties is { } properties && Same(properties.VaultId, plan.VaultId) &&
            Same(properties.Location, host.Location) &&
            properties.Tags.TryGetValue(OwnershipTag, out string? nonce) && nonce == plan.Selector.Nonce.ToString("N"));

    private void ValidateAssignment(Plan plan, RoleAssignmentData data) =>
        Require(Same(data.Id?.ToString(), plan.AssignmentId) && Same(data.Scope, plan.VaultId) &&
            Same(data.RoleDefinitionId?.ToString(), DefinitionId) && data.PrincipalId == host.IntendedPrincipalId);

    private async Task BorrowedAsync(RoleFixtureJournal.Snapshot snapshot, List<BorrowedReadback> rows, CancellationToken token)
    {
        foreach (var resource in snapshot.Resources.Where(r => r.Borrowed))
        {
            using var transport = new BoundaryTransport(observeArm.Transport, ArmOrigin, resource.Id, RoleRevision,
                RequestMethod.Get, limits.MaximumResponseBytes, false);
            var client = Arm(observeArm, transport);
            if (resource.Id.Contains("/roleAssignments/", StringComparison.Ordinal))
            {
                var response = await client.GetRoleAssignmentResource(new(resource.Id))
                    .GetAsync(cancellationToken: token).ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                var data = response.Value.Data;
                string parent = resource.Id[..resource.Id.LastIndexOf("/providers/", StringComparison.Ordinal)];
                Require(Same(data.Id?.ToString(), resource.Id) && Same(data.Scope, parent) &&
                    data.PrincipalId is { } principal && principal != Guid.Empty && data.RoleDefinitionId is not null);
            }
            else
            {
                var response = await client.GetAuthorizationRoleDefinitionResource(new(resource.Id))
                    .GetAsync(token).ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(Same(response.Value.Data.Id?.ToString(), resource.Id));
            }
            Require(transport.Valid && transport.Status == 200 && transport.BodySha256 is not null);
            rows.Add(new(resource.Id, transport.BodySha256!));
        }
    }

    private async Task<Result> ObserveCore(Plan plan, IReadOnlyList<BorrowedReadback> borrowed, CancellationToken token)
    {
        var vault = await ObserveVault(plan, token).ConfigureAwait(false);
        bool ready = false;
        if (vault is not null)
        {
            ValidateVault(plan, vault);
            ready = Succeeded(vault);
        }
        var assignment = await ObserveAssignment(plan.AssignmentId, token).ConfigureAwait(false);
        if (assignment is not null) ValidateAssignment(plan, assignment);
        string? digest = null;
        string? version = null;
        if (ready)
        {
            using var transport = new BoundaryTransport(observeSecret.Transport, SecretOrigin(plan).AbsoluteUri.TrimEnd('/'),
                "/secrets/" + Canary + "/", SecretRevision, RequestMethod.Get, limits.MaximumResponseBytes, true);
            try
            {
                var response = await Secret(observeSecret, plan, transport).GetSecretAsync(Canary, cancellationToken: token).ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                Require(transport.Valid && transport.Status == 200 && response.Value.Name == Canary &&
                    response.Value.Properties.VaultUri == SecretOrigin(plan) &&
                    Version(response.Value.Properties.Version) &&
                    (plan.CanaryVersion is null || response.Value.Properties.Version == plan.CanaryVersion) &&
                    response.Value.Properties.Enabled != false && response.Value.Value is not null &&
                    (response.Value.Properties.NotBefore is null || response.Value.Properties.NotBefore <= time.GetUtcNow()) &&
                    (response.Value.Properties.ExpiresOn is null || response.Value.Properties.ExpiresOn > time.GetUtcNow()));
                digest = Hash(response.Value.Value!);
                version = response.Value.Properties.Version;
            }
            catch (RequestFailedException) when (transport.Valid && transport.Status == 404) { }
        }
        return new()
        {
            State = ready && digest is not null && assignment is not null ? State.Ready :
                vault is not null && !ready ? State.Pending : State.Incomplete,
            Journal = journal.Read(plan.Owner, plan.Selector),
            Borrowed = borrowed,
            Receipts = plan.Receipts,
            VaultReady = ready,
            AssignmentPresent = assignment is not null,
            CanaryPresent = ready ? digest is not null : null,
            CanarySha256 = digest,
            CanaryVersion = version
        };
    }

    private static bool Same(string? left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool Version(string? version) => version is { Length: 32 } && version.All(char.IsAsciiHexDigit);
    private static string Hash(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
