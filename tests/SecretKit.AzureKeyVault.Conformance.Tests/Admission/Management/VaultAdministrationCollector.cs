using System.ClientModel.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Host-composed metadata source only. Neither its identity label nor a successful
// ARM response establishes an actual principal, permission effect or network path.
internal sealed class VaultAdministrationCollector
{
    internal const string ArmOrigin = "https://management.azure.com";
    internal const string Revision = "2026-02-01";
    internal enum ReadKind
    {
        GetVault, GetDeletedVault, GetPrivateConnection, ListVaultsGroup, ListVaultsSubscription,
        ListDeletedVaults, ListPrivateConnections, ListPrivateLinkResources, CheckNameAvailability
    }
    internal enum QueryKind
    {
        ChangeAccessPolicies, CheckNameAvailability, CreateOrUpdateVault, DeletePrivateConnection, DeleteVault,
        GetDeletedVault, GetPrivateConnection, GetVault, ListDeletedVaults, ListPrivateConnections,
        ListPrivateLinkResources, ListVaultsResourceGroup, ListVaultsSubscription, PurgeDeletedVault,
        RecoverVault, UpdatePrivateConnection, UpdateSettings
    }
    internal enum Failure { None, Boundary, Budget, Denied, Unavailable, Deadline }
    internal sealed record Limits(int MaximumPages, int MaximumItems, int MaximumResponseBytes,
        int MaximumRowBytes, TimeSpan Timeout);
    internal sealed record Authority([property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential, [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[VaultMetadataAuthority]";
    }
    internal sealed record Binding(
        [property: JsonIgnore] FixtureSelector Selector, [property: JsonIgnore] Guid LeaseId,
        [property: JsonIgnore] QueryKind Query, [property: JsonIgnore] ReadKind Read,
        [property: JsonIgnore] Guid SubscriptionId, [property: JsonIgnore] string ResourceGroup,
        [property: JsonIgnore] string Location, [property: JsonIgnore] string VaultName,
        [property: JsonIgnore] string? ConnectionName)
    {
        public override string ToString() => "[VaultMetadataBinding]";
    }
    internal sealed class Window(object owner, Binding binding, DateTimeOffset armedAt, long timestamp)
    {
        internal object Owner { get; } = owner;
        internal Binding Binding { get; } = binding;
        internal DateTimeOffset ArmedAt { get; } = armedAt;
        internal long Timestamp { get; } = timestamp;
        internal Guid Id { get; } = Guid.NewGuid();
        internal int Consumed;
        public override string ToString() => "[VaultMetadataWindow]";
    }
    internal sealed class PolicyMetadata
    {
        internal required Guid TenantId { get; init; }
        internal required Guid PrincipalId { get; init; }
        internal required Guid? ApplicationId { get; init; }
        internal required IReadOnlyList<string> Secrets { get; init; }
        internal required IReadOnlyList<string> Keys { get; init; }
        internal required IReadOnlyList<string> Certificates { get; init; }
        internal required IReadOnlyList<string> Storage { get; init; }
        public override string ToString() => "[VaultPolicyMetadata]";
    }
    internal sealed record PolicyConfiguration([property: JsonIgnore] Guid TenantId,
        [property: JsonIgnore] Guid PrincipalId, [property: JsonIgnore] SecretPermission[] Permissions,
        [property: JsonIgnore] Guid? ApplicationId)
    {
        public override string ToString() => "[VaultPolicyConfigurationMetadata]";
    }
    internal sealed record ConfigurationMetadata([property: JsonIgnore] string Location,
        [property: JsonIgnore] Guid TenantId, [property: JsonIgnore] VaultSku Sku,
        [property: JsonIgnore] bool Rbac, [property: JsonIgnore] bool PurgeProtection,
        [property: JsonIgnore] int RetentionDays, [property: JsonIgnore] bool PublicNetworkAccess,
        [property: JsonIgnore] PolicyConfiguration[] Policies)
    {
        public override string ToString() => "[VaultConfigurationMetadata]";
    }
    internal sealed record VaultRow([property: JsonIgnore] string ResourceId,
        [property: JsonIgnore] NativeProvisioningState ProvisioningState, [property: JsonIgnore] bool? Rbac,
        [property: JsonIgnore] bool? PurgeProtection, [property: JsonIgnore] int? RetentionDays)
    {
        public override string ToString() => "[VaultRowMetadata]";
    }
    internal sealed record DeletedVaultRow([property: JsonIgnore] Guid SubscriptionId, [property: JsonIgnore] string Location,
        [property: JsonIgnore] string Name, [property: JsonIgnore] DateTimeOffset? DeletedOn,
        [property: JsonIgnore] DateTimeOffset? ScheduledPurgeOn, [property: JsonIgnore] bool? PurgeProtected)
    {
        public override string ToString() => "[DeletedVaultMetadata]";
    }
    internal sealed record ConnectionRow([property: JsonIgnore] string Name, [property: JsonIgnore] PrivateConnectionState State,
        [property: JsonIgnore] NativeProvisioningState ProvisioningState)
    {
        [JsonIgnore] internal string? ResourceId { get; init; }
        [JsonIgnore] internal string? PrivateEndpointId { get; init; }
        public override string ToString() => "[VaultConnectionMetadata]";
    }
    internal sealed record PrivateLinkRow([property: JsonIgnore] string Name, [property: JsonIgnore] string? GroupId,
        [property: JsonIgnore] string[] RequiredMembers, [property: JsonIgnore] string[] RequiredZoneNames)
    {
        public override string ToString() => "[VaultPrivateLinkMetadata]";
    }
    internal sealed class VaultMetadata
    {
        internal required VaultRow Row { get; init; }
        internal required string Location { get; init; }
        internal required Guid TenantId { get; init; }
        internal required string Sku { get; init; }
        internal required string SkuFamily { get; init; }
        internal required string? PublicNetworkAccess { get; init; }
        internal required string? NativeProvisioningState { get; init; }
        internal required bool? SoftDelete { get; init; }
        internal required IReadOnlyList<PolicyMetadata> Policies { get; init; }
        // Null means the native state cannot be represented losslessly by the
        // existing configuration DTO, not a guessed default configuration.
        internal ConfigurationMetadata? Configuration
        {
            get
            {
                if (SkuFamily != "A" || Sku.ToLowerInvariant() is not ("standard" or "premium") ||
                    SoftDelete != true ||
                    Row.Rbac is null || Row.PurgeProtection is null || Row.RetentionDays is not (>= 7 and <= 90) ||
                    PublicNetworkAccess is not ("Enabled" or "Disabled") || Policies.Count > 16)
                    return null;
                var policies = new List<PolicyConfiguration>();
                foreach (var p in Policies)
                {
                    if (p.TenantId != TenantId || p.Keys.Count != 0 || p.Certificates.Count != 0 || p.Storage.Count != 0)
                        return null;
                    var secrets = new List<SecretPermission>();
                    foreach (string text in p.Secrets)
                    {
                        if (!Enum.TryParse<SecretPermission>(text, true, out var value) || !Enum.IsDefined(value) ||
                            !value.ToString().Equals(text, StringComparison.OrdinalIgnoreCase)) return null;
                        secrets.Add(value);
                    }
                    policies.Add(new(p.TenantId, p.PrincipalId, secrets.ToArray(), p.ApplicationId));
                }
                return new(Location, TenantId, Sku.Equals("premium", StringComparison.OrdinalIgnoreCase) ? VaultSku.Premium : VaultSku.Standard,
                    Row.Rbac.Value, Row.PurgeProtection.Value, Row.RetentionDays.Value, PublicNetworkAccess == "Enabled", policies.ToArray());
            }
        }
        public override string ToString() => "[VaultMetadata]";
    }
    internal sealed class Measurement
    {
        internal required Binding Binding { get; init; }
        internal required Guid WindowId { get; init; }
        internal required DateTimeOffset ArmedAt { get; init; }
        internal required DateTimeOffset StartedAt { get; init; }
        internal required DateTimeOffset FinishedAt { get; init; }
        internal required string Identity { get; init; }
        internal string ApiRevision => Revision;
        internal required Failure Failure { get; init; }
        internal required SecretStatus Status { get; init; }
        internal required IReadOnlyList<string> NativeRequestIds { get; init; }
        internal required IReadOnlyList<VaultMetadata> Vaults { get; init; }
        internal required IReadOnlyList<DeletedVaultRow> DeletedVaults { get; init; }
        internal required IReadOnlyList<ConnectionRow> Connections { get; init; }
        internal required IReadOnlyList<PrivateLinkRow> PrivateLinks { get; init; }
        internal required bool? NameAvailable { get; init; }
        internal bool ResponseComplete => Failure == Failure.None;
        internal bool InventoryComplete => IsInventory(Binding.Read) && ResponseComplete && Status == SecretStatus.Success;
        internal bool? ResourceAbsent => IsConcrete(Binding.Read) && ResponseComplete
            ? Status == SecretStatus.Absent : null;
        public override string ToString() => "[VaultMetadataMeasurement]";
    }

    private readonly Authority authority;
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object owner = new();

    internal VaultAdministrationCollector(Authority authority, Limits limits, TimeProvider? time = null)
    {
        if (authority is null || authority.Credential is null || authority.Transport is null ||
            string.IsNullOrWhiteSpace(authority.Label) || authority.Label.Length > 128 ||
            limits is null || limits.MaximumPages is < 1 or > 100 || limits.MaximumItems is < 1 or > 10000 ||
            limits.MaximumResponseBytes is < 1024 or > 16 * 1024 * 1024 ||
            limits.MaximumRowBytes is < 256 or > 1024 * 1024 ||
            limits.Timeout <= TimeSpan.Zero || limits.Timeout > TimeSpan.FromMinutes(2))
            throw new ArgumentException("vault-metadata-input");
        this.authority = authority;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal Window Arm(Binding binding)
    {
        ValidateBinding(binding);
        return new(owner, binding, time.GetUtcNow(), time.GetTimestamp());
    }

    // Binding is compared before consuming the window. A real invocation consumes
    // it even if canceled or incomplete; there is no implicit replay or polling.
    internal async ValueTask<Measurement> CollectAsync(Window window, Binding binding, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (window is null || !ReferenceEquals(window.Owner, owner) || window.Binding != binding ||
            Interlocked.Exchange(ref window.Consumed, 1) != 0)
            throw new InvalidOperationException("vault-metadata-window");
        DateTimeOffset started = time.GetUtcNow();
        TimeSpan remaining = limits.Timeout - time.GetElapsedTime(window.Timestamp);
        var vaults = new List<VaultMetadata>();
        var deleted = new List<DeletedVaultRow>();
        var connections = new List<ConnectionRow>();
        var links = new List<PrivateLinkRow>();
        bool? available = null;
        if (remaining <= TimeSpan.Zero) return Finish(Failure.Deadline, SecretStatus.Unavailable, []);
        using var deadline = new CancellationTokenSource(remaining, time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        using var boundary = new BoundaryTransport(authority.Transport, binding, limits);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        foreach (string type in new[] { "Microsoft.KeyVault/vaults", "Microsoft.KeyVault/deletedVaults",
            "Microsoft.KeyVault/vaults/privateEndpointConnections", "Microsoft.KeyVault/vaults/privateLinkResources" })
            options.SetApiVersion(type, Revision);
        var client = new ArmClient(new AudienceCredential(authority.Credential), null, options);
        string path = Path(binding);
        try
        {
            switch (binding.Read)
            {
                case ReadKind.GetVault:
                    {
                        var r = await client.GetKeyVaultResource(new(path)).GetAsync(linked.Token).ConfigureAwait(false);
                        using var raw = r.GetRawResponse();
                        vaults.Add(Vault(r.Value.Data));
                        break;
                    }
                case ReadKind.GetDeletedVault:
                    {
                        var r = await client.GetDeletedKeyVaultResource(new(path)).GetAsync(linked.Token).ConfigureAwait(false);
                        using var raw = r.GetRawResponse();
                        deleted.Add(Deleted(r.Value.Data));
                        break;
                    }
                case ReadKind.GetPrivateConnection:
                    {
                        var r = await client.GetKeyVaultPrivateEndpointConnectionResource(new(path)).GetAsync(linked.Token).ConfigureAwait(false);
                        using var raw = r.GetRawResponse();
                        connections.Add(Connection(r.Value.Data));
                        break;
                    }
                case ReadKind.CheckNameAvailability:
                    {
                        var r = await client.GetSubscriptionResource(new(Subscription(binding)))
                            .CheckKeyVaultNameAvailabilityAsync(new KeyVaultNameAvailabilityContent(binding.VaultName), linked.Token).ConfigureAwait(false);
                        using var raw = r.GetRawResponse();
                        Require(r.Value.NameAvailable is not null);
                        available = r.Value.NameAvailable;
                        break;
                    }
                case ReadKind.ListVaultsGroup:
                    await Inventory<KeyVaultData, VaultMetadata>(Vault, vaults).ConfigureAwait(false);
                    break;
                case ReadKind.ListVaultsSubscription:
                    await Inventory<KeyVaultData, VaultMetadata>(Vault, vaults).ConfigureAwait(false);
                    break;
                case ReadKind.ListDeletedVaults:
                    await Inventory<DeletedKeyVaultData, DeletedVaultRow>(Deleted, deleted).ConfigureAwait(false);
                    break;
                case ReadKind.ListPrivateConnections:
                    await Inventory<KeyVaultPrivateEndpointConnectionData, ConnectionRow>(Connection, connections).ConfigureAwait(false);
                    break;
                case ReadKind.ListPrivateLinkResources:
                    await Inventory<KeyVaultPrivateLinkResourceData, PrivateLinkRow>(Link, links).ConfigureAwait(false);
                    break;
                default: throw new Boundary();
            }
            linked.Token.ThrowIfCancellationRequested();
            Require(boundary.Valid && boundary.Status == 200);
            return Finish(Failure.None, SecretStatus.Success, boundary.RequestIds);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (deadline.IsCancellationRequested) return Finish(Failure.Deadline, SecretStatus.Unavailable, boundary.RequestIds);
            if (exception is RequestFailedException && boundary.Valid && boundary.Status == 404 && IsConcrete(binding.Read))
                return Finish(Failure.None, SecretStatus.Absent, boundary.RequestIds);
            Failure failure = exception is Boundary b ? b.Reason :
                exception is RequestFailedException { InnerException: Boundary inner } ? inner.Reason :
                boundary.Status is 401 or 403 ? Failure.Denied :
                exception is RequestFailedException or HttpRequestException or IOException ? Failure.Unavailable : Failure.Boundary;
            return Finish(failure, failure == Failure.Denied ? SecretStatus.Denied : SecretStatus.Unavailable, boundary.RequestIds);
        }

        async Task Inventory<T, TRow>(Func<T, TRow> project, List<TRow> rows)
        {
            // Source-owned pagination: some installed SDK collection adapters
            // ignore nextLink. Parse each bounded row with the native SDK model,
            // but drive only the actual provider-authored continuation here.
            var pipeline = HttpPipelineBuilder.Build(options,
                new BearerTokenAuthenticationPolicy(new AudienceCredential(authority.Credential), ArmOrigin + "/.default"));
            string next = ArmOrigin + path + "?api-version=" + Revision;
            do
            {
                using var message = pipeline.CreateMessage();
                message.Request.Method = RequestMethod.Get;
                message.Request.Uri.Reset(new Uri(next));
                await pipeline.SendAsync(message, linked.Token).ConfigureAwait(false);
                if (message.Response.Status != 200) throw new RequestFailedException(message.Response);
                using var document = JsonDocument.Parse(message.Response.ContentStream!);
                var values = document.RootElement.GetProperty("value");
                foreach (var row in values.EnumerateArray())
                {
                    linked.Token.ThrowIfCancellationRequested();
                    byte[] bytes = Encoding.UTF8.GetBytes(row.GetRawText());
                    try { rows.Add(project(ModelReaderWriter.Read<T>(new BinaryData(bytes))!)); }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                }
                boundary.CheckPage(values.GetArrayLength());
                next = boundary.Next!;
            } while (next is not null);
            boundary.RequireComplete(rows.Count);
        }

        Measurement Finish(Failure failure, SecretStatus status, IReadOnlyList<string> requestIds) => new()
        {
            Binding = window.Binding,
            WindowId = window.Id,
            ArmedAt = window.ArmedAt,
            StartedAt = started,
            FinishedAt = time.GetUtcNow(),
            Identity = authority.Label,
            Failure = failure,
            Status = status,
            NativeRequestIds = Array.AsReadOnly(requestIds.ToArray()),
            Vaults = vaults.AsReadOnly(),
            DeletedVaults = deleted.AsReadOnly(),
            Connections = connections.AsReadOnly(),
            PrivateLinks = links.AsReadOnly(),
            NameAvailable = failure == Failure.None ? available : null
        };
    }

    private static VaultMetadata Vault(KeyVaultData data)
    {
        var p = data.Properties;
        return new()
        {
            Row = new(data.Id.ToString(), Provisioning(p.ProvisioningState?.ToString()), p.EnableRbacAuthorization,
                p.EnablePurgeProtection, p.SoftDeleteRetentionInDays),
            Location = data.Location.Name,
            TenantId = p.TenantId,
            Sku = p.Sku.Name.ToString(),
            SkuFamily = p.Sku.Family.ToString(),
            PublicNetworkAccess = p.PublicNetworkAccess,
            NativeProvisioningState = p.ProvisioningState?.ToString(),
            SoftDelete = p.EnableSoftDelete,
            Policies = Array.AsReadOnly(p.AccessPolicies.Select(a => new PolicyMetadata
            {
                TenantId = a.TenantId,
                PrincipalId = Guid.Parse(a.ObjectId),
                ApplicationId = a.ApplicationId,
                Secrets = Array.AsReadOnly(a.Permissions.Secrets.Select(v => v.ToString()).ToArray()),
                Keys = Array.AsReadOnly(a.Permissions.Keys.Select(v => v.ToString()).ToArray()),
                Certificates = Array.AsReadOnly(a.Permissions.Certificates.Select(v => v.ToString()).ToArray()),
                Storage = Array.AsReadOnly(a.Permissions.Storage.Select(v => v.ToString()).ToArray())
            }).ToArray())
        };
    }
    private static DeletedVaultRow Deleted(DeletedKeyVaultData data)
    {
        string[] parts = data.Id.ToString().Split('/');
        return new(Guid.Parse(parts[2]), parts[6], parts[8], data.Properties.DeletedOn,
            data.Properties.ScheduledPurgeOn, data.Properties.PurgeProtectionEnabled);
    }
    private static ConnectionRow Connection(KeyVaultPrivateEndpointConnectionData data) =>
        new(data.Name, Named<PrivateConnectionState>(data.ConnectionState?.Status?.ToString()),
            Provisioning(data.ProvisioningState?.ToString()))
        {
            ResourceId = data.Id.ToString(),
            PrivateEndpointId = data.PrivateEndpointId?.ToString()
        };
    private static PrivateLinkRow Link(KeyVaultPrivateLinkResourceData data) =>
        new(data.Name, data.GroupId, data.RequiredMembers.ToArray(), data.RequiredZoneNames.ToArray());
    private static T Named<T>(string? text) where T : struct, Enum =>
        Enum.TryParse<T>(text, true, out var value) && Enum.IsDefined(value) &&
        value.ToString().Equals(text, StringComparison.OrdinalIgnoreCase) ? value : default;
    private static NativeProvisioningState Provisioning(string? text) => text?.ToLowerInvariant() switch
    {
        "succeeded" => NativeProvisioningState.Succeeded,
        "failed" => NativeProvisioningState.Failed,
        "canceled" or "cancelled" => NativeProvisioningState.Canceled,
        "creating" or "updating" or "deleting" or "accepted" or "running" or "inprogress" => NativeProvisioningState.Pending,
        _ => NativeProvisioningState.Unknown
    };
    internal static string Operation(QueryKind query) => "a.management.VaultAdministration." + (query switch
    {
        QueryKind.ListVaultsResourceGroup => "ListVaultsAsync.ResourceGroup",
        QueryKind.ListVaultsSubscription => "ListVaultsAsync.Subscription",
        _ => query + "Async"
    });
    internal static ReadKind DefaultRead(QueryKind query) => query switch
    {
        QueryKind.CheckNameAvailability => ReadKind.CheckNameAvailability,
        QueryKind.GetDeletedVault or QueryKind.PurgeDeletedVault => ReadKind.GetDeletedVault,
        QueryKind.GetPrivateConnection or QueryKind.UpdatePrivateConnection or QueryKind.DeletePrivateConnection => ReadKind.GetPrivateConnection,
        QueryKind.ListVaultsResourceGroup => ReadKind.ListVaultsGroup,
        QueryKind.ListVaultsSubscription => ReadKind.ListVaultsSubscription,
        QueryKind.ListDeletedVaults => ReadKind.ListDeletedVaults,
        QueryKind.ListPrivateConnections => ReadKind.ListPrivateConnections,
        QueryKind.ListPrivateLinkResources => ReadKind.ListPrivateLinkResources,
        _ => ReadKind.GetVault
    };
    private static void ValidateBinding(Binding b)
    {
        if (b is null || b.Selector is null || b.LeaseId == Guid.Empty || b.Selector.Nonce == Guid.Empty ||
            b.SubscriptionId == Guid.Empty || !Enum.IsDefined(b.Query) || !Enum.IsDefined(b.Read) ||
            !Segment(b.ResourceGroup, 90) || !Segment(b.Location, 50) || !Segment(b.VaultName, 24) ||
            b.VaultName.Length < 3 || b.ConnectionName is not null && !Segment(b.ConnectionName, 256) ||
            new[] { b.Selector.Scope, b.Selector.Operation, b.Selector.Variant, b.Selector.Case }
                .Any(v => string.IsNullOrWhiteSpace(v) || v.Length > 512) ||
            b.Selector.Operation != Operation(b.Query) ||
            b.Read != DefaultRead(b.Query) && !(b.Query is QueryKind.DeleteVault or QueryKind.PurgeDeletedVault or QueryKind.RecoverVault or QueryKind.ChangeAccessPolicies &&
                b.Read is ReadKind.GetVault or ReadKind.GetDeletedVault) ||
            b.Read == ReadKind.GetPrivateConnection && b.ConnectionName is null)
            throw new ArgumentException("vault-metadata-binding");
        var member = VaultAdministrationEffects.Members.Single(m => m.Operation == Operation(b.Query));
        if (!member.Variants.Contains(b.Selector.Variant, StringComparer.Ordinal))
            throw new ArgumentException("vault-metadata-binding");
    }
    private static bool Segment(string? text, int maximum) => text is { Length: > 0 } && text.Length <= maximum &&
        text is not ("." or "..") && text.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool Same(string? a, string? b) => string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    private static bool IsConcrete(ReadKind read) => read is ReadKind.GetVault or ReadKind.GetDeletedVault or ReadKind.GetPrivateConnection;
    private static bool IsInventory(ReadKind read) => read is >= ReadKind.ListVaultsGroup and <= ReadKind.ListPrivateLinkResources;
    private static string Subscription(Binding b) => $"/subscriptions/{b.SubscriptionId:D}";
    private static string Group(Binding b) => Subscription(b) + "/resourceGroups/" + b.ResourceGroup;
    private static string VaultId(Binding b) => Group(b) + "/providers/Microsoft.KeyVault/vaults/" + b.VaultName;
    private static string Path(Binding b) => b.Read switch
    {
        ReadKind.GetVault => VaultId(b),
        ReadKind.GetDeletedVault => Subscription(b) + "/providers/Microsoft.KeyVault/locations/" + b.Location + "/deletedVaults/" + b.VaultName,
        ReadKind.GetPrivateConnection => VaultId(b) + "/privateEndpointConnections/" + b.ConnectionName,
        ReadKind.ListVaultsGroup => Group(b) + "/providers/Microsoft.KeyVault/vaults",
        ReadKind.ListVaultsSubscription => Subscription(b) + "/providers/Microsoft.KeyVault/vaults",
        ReadKind.ListDeletedVaults => Subscription(b) + "/providers/Microsoft.KeyVault/deletedVaults",
        ReadKind.ListPrivateConnections => VaultId(b) + "/privateEndpointConnections",
        ReadKind.ListPrivateLinkResources => VaultId(b) + "/privateLinkResources",
        ReadKind.CheckNameAvailability => Subscription(b) + "/providers/Microsoft.KeyVault/checkNameAvailability",
        _ => throw new Boundary()
    };

    private sealed class BoundaryTransport(HttpPipelineTransport inner, Binding binding, Limits limits) : HttpPipelineTransport, IDisposable
    {
        private readonly HashSet<string> visited = new(StringComparer.Ordinal);
        private readonly HashSet<string> identities = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> requestIds = [];
        private Response? response;
        private ZeroingStream? buffer;
        private string? next;
        private int pages, items, pageItems;
        private bool checkedPage = true;
        internal bool Valid { get; private set; }
        internal int Status { get; private set; }
        internal IReadOnlyList<string> RequestIds => requestIds;
        internal string? Next => next;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new Boundary();

        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            string actual = ValidateUri(message.Request.Uri.ToUri().OriginalString, pages == 0);
            Require(checkedPage);
            if (pages >= limits.MaximumPages || IsInventory(binding.Read) && items >= limits.MaximumItems) throw new Boundary(Failure.Budget);
            Require(pages == 0 || next is not null && actual == ValidateUri(next, false));
            Require(visited.Add(actual));
            await ValidateRequest(message).ConfigureAwait(false);
            // Only an actual native invocation replaces the previous response.
            // SDK lazy/cached data never resets a previously validated boundary.
            buffer?.Dispose();
            response?.Dispose();
            buffer = null;
            response = null;
            Valid = false;
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) response = message.Response; }
            Require(response is not null);
            Status = response.Status;
            message.CancellationToken.ThrowIfCancellationRequested();
            if (Status is >= 300 and < 400) throw new Boundary();
            long? length = null;
            if (response.Headers.TryGetValues("Content-Length", out var lengths))
            {
                string[] values = lengths.ToArray();
                if (values.Length != 1 || !long.TryParse(values[0], NumberStyles.None, CultureInfo.InvariantCulture, out long parsed) ||
                    parsed > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                length = parsed;
            }
            buffer = await Buffer(message).ConfigureAwait(false);
            if (length is { } expected) Require(expected == buffer.Length);
            using var document = JsonDocument.Parse(buffer.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
            JsonElement root = document.RootElement;
            Shape(root);
            Require(root.ValueKind == JsonValueKind.Object);
            Require(response.Headers.TryGetValues("x-ms-request-id", out var nativeIds));
            string[] ids = nativeIds.ToArray();
            Require(ids.Length == 1 && ids[0].Length is > 0 and <= 256 &&
                ids[0].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
            requestIds.Add(ids[0]);
            if (Status != 200)
            {
                Require(Status >= 400);
                message.CancellationToken.ThrowIfCancellationRequested();
                Valid = true;
                return;
            }
            Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("errors", out _));
            if (binding.Read == ReadKind.CheckNameAvailability)
            {
                Require(root.TryGetProperty("nameAvailable", out var available) && available.ValueKind is JsonValueKind.True or JsonValueKind.False);
                pageItems = 0;
                next = null;
            }
            else if (IsInventory(binding.Read))
            {
                JsonElement rows = ArrayValue(root, "value");
                pageItems = rows.GetArrayLength();
                if (pageItems > limits.MaximumItems - items) throw new Boundary(Failure.Budget);
                foreach (var row in rows.EnumerateArray()) ValidateRow(row);
                next = null;
                if (root.TryGetProperty("nextLink", out var link) && link.ValueKind != JsonValueKind.Null)
                {
                    Require(link.ValueKind == JsonValueKind.String);
                    next = link.GetString();
                    string key = ValidateUri(next!, false);
                    Require(!visited.Contains(key) && pageItems != 0);
                }
                checkedPage = false;
            }
            else
            {
                ValidateRow(root);
                pageItems = 1;
                next = null;
            }
            items += pageItems;
            pages++;
            message.CancellationToken.ThrowIfCancellationRequested();
            Valid = true;
        }

        internal void CheckPage(int count)
        {
            Require(Valid && !checkedPage && count == pageItems);
            checkedPage = true;
        }
        internal void RequireComplete(int count) => Require(Valid && checkedPage && pages > 0 && next is null && items == count);

        private async Task ValidateRequest(HttpMessage message)
        {
            bool name = binding.Read == ReadKind.CheckNameAvailability;
            Require(message.Request.Method == (name ? RequestMethod.Post : RequestMethod.Get));
            if (!name) { Require(message.Request.Content is null); return; }
            Require(message.Request.Content is not null);
            using var sink = new RequestBuffer();
            await message.Request.Content.WriteToAsync(sink, message.CancellationToken).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(sink.Written);
            Shape(doc.RootElement);
            Require(doc.RootElement.ValueKind == JsonValueKind.Object && doc.RootElement.EnumerateObject().Count() == 2 &&
                Text(doc.RootElement, "name") == binding.VaultName && Text(doc.RootElement, "type") == "Microsoft.KeyVault/vaults");
        }
        private string ValidateUri(string text, bool first)
        {
            Require(!string.IsNullOrEmpty(text) && text.Length <= 8192);
            Require(Uri.TryCreate(text, UriKind.Absolute, out var uri));
            Require(uri.Scheme == "https" && uri.IsDefaultPort && uri.UserInfo.Length == 0 && !text.Contains('#') &&
                Same(text.Split('?')[0], ArmOrigin + Path(binding)) && uri.Query.Length > 0);
            var query = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string part in uri.Query[1..].Split('&'))
            {
                string[] pair = part.Split('=', 2);
                Require(pair.Length == 2 && !BadEscape(pair[0]) && !BadEscape(pair[1]));
                string key = Uri.UnescapeDataString(pair[0]), value = Uri.UnescapeDataString(pair[1]);
                Require(key is "api-version" or "$skiptoken" && value.Length is > 0 and <= 4096 &&
                    !value.Any(char.IsControl) && query.TryAdd(key, value));
            }
            Require(query.TryGetValue("api-version", out var revision) && revision == Revision &&
                (first ? query.Count == 1 : IsInventory(binding.Read) && query.Count == 2 && query.ContainsKey("$skiptoken")));
            return string.Join("&", query.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p =>
                Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        }
        private static bool BadEscape(string text)
        {
            for (int i = 0; i < text.Length; i++)
                if (text[i] == '%' && (i + 2 >= text.Length || !char.IsAsciiHexDigit(text[i + 1]) || !char.IsAsciiHexDigit(text[i + 2])))
                    return true;
            return false;
        }
        private void ValidateRow(JsonElement row)
        {
            if (Encoding.UTF8.GetByteCount(row.GetRawText()) > limits.MaximumRowBytes) throw new Boundary(Failure.Budget);
            string id = Text(row, "id"), name = Text(row, "name");
            Require(id.Length <= 2048 && Segment(name, 256));
            Require(identities.Add(id));
            if (IsConcrete(binding.Read)) Require(Same(id, Path(binding)));
            JsonElement properties = Object(row, "properties");
            if (binding.Read is ReadKind.GetVault or ReadKind.ListVaultsGroup or ReadKind.ListVaultsSubscription)
            {
                Require(Same(Text(row, "type"), "Microsoft.KeyVault/vaults"));
                ValidateVaultId(id, name, binding.Read != ReadKind.ListVaultsSubscription);
                string location = Text(row, "location");
                Require(Segment(location, 50) && (binding.Read != ReadKind.GetVault || Same(location, binding.Location)));
                GuidValue(properties, "tenantId");
                var sku = Object(properties, "sku");
                _ = Text(sku, "name"); _ = Text(sku, "family");
                OptionalText(properties, "provisioningState"); OptionalText(properties, "publicNetworkAccess");
                OptionalBoolean(properties, "enableRbacAuthorization"); OptionalBoolean(properties, "enablePurgeProtection");
                OptionalBoolean(properties, "enableSoftDelete");
                if (properties.TryGetProperty("softDeleteRetentionInDays", out var retention) && retention.ValueKind != JsonValueKind.Null)
                    Require(retention.TryGetInt32(out _));
                JsonElement policies = ArrayValue(properties, "accessPolicies");
                if (policies.GetArrayLength() > 16) throw new Boundary(Failure.Budget);
                var keys = new HashSet<(Guid, Guid, Guid?)>();
                foreach (var policy in policies.EnumerateArray())
                {
                    Guid tenant = GuidValue(policy, "tenantId"), principal = GuidValue(policy, "objectId");
                    Guid? app = policy.TryGetProperty("applicationId", out var application) && application.ValueKind != JsonValueKind.Null
                        ? GuidValue(policy, "applicationId") : null;
                    Require(keys.Add((tenant, principal, app)));
                    var permissions = Object(policy, "permissions");
                    StringArray(permissions, "secrets");
                    foreach (string kind in new[] { "keys", "certificates", "storage" })
                        if (permissions.TryGetProperty(kind, out _)) StringArray(permissions, kind);
                }
            }
            else if (binding.Read is ReadKind.GetDeletedVault or ReadKind.ListDeletedVaults)
            {
                Require(Same(Text(row, "type"), "Microsoft.KeyVault/locations/deletedVaults"));
                string[] parts = id.Split('/');
                Require(parts.Length == 9 && parts[0].Length == 0 && Same(parts[1], "subscriptions") && Same(parts[2], binding.SubscriptionId.ToString("D")) &&
                    Same(parts[3], "providers") && Same(parts[4], "Microsoft.KeyVault") && Same(parts[5], "locations") &&
                    Segment(parts[6], 50) && Same(parts[7], "deletedVaults") && Same(parts[8], name) && Segment(name, 24));
                Require(Same(Text(properties, "location"), parts[6]));
                ValidateVaultId(Text(properties, "vaultId"), name, binding.Read == ReadKind.GetDeletedVault);
                OptionalDate(properties, "deletionDate"); OptionalDate(properties, "scheduledPurgeDate");
                OptionalBoolean(properties, "purgeProtectionEnabled");
            }
            else
            {
                string kind = binding.Read == ReadKind.ListPrivateLinkResources ? "privateLinkResources" : "privateEndpointConnections";
                Require(Same(Text(row, "type"), "Microsoft.KeyVault/vaults/" + kind));
                Require(Same(id, VaultId(binding) + "/" + kind + "/" + name));
                if (binding.Read == ReadKind.ListPrivateLinkResources)
                {
                    OptionalText(properties, "groupId");
                    StringArray(properties, "requiredMembers"); StringArray(properties, "requiredZoneNames");
                }
                else
                {
                    OptionalText(properties, "provisioningState");
                    if (properties.TryGetProperty("privateLinkServiceConnectionState", out var state) && state.ValueKind != JsonValueKind.Null)
                    {
                        Require(state.ValueKind == JsonValueKind.Object);
                        OptionalText(state, "status");
                    }
                }
            }
        }
        private void ValidateVaultId(string id, string name, bool group)
        {
            string[] p = id.Split('/');
            Require(p.Length == 9 && p[0].Length == 0 && Same(p[1], "subscriptions") &&
                Same(p[2], binding.SubscriptionId.ToString("D")) && Same(p[3], "resourceGroups") && Segment(p[4], 90) &&
                (!group || Same(p[4], binding.ResourceGroup)) && Same(p[5], "providers") &&
                Same(p[6], "Microsoft.KeyVault") && Same(p[7], "vaults") && Same(p[8], name) && Segment(p[8], 24));
        }
        private async ValueTask<ZeroingStream> Buffer(HttpMessage message)
        {
            Response current = response ?? throw new Boundary();
            byte[] bytes = new byte[limits.MaximumResponseBytes + 1];
            try
            {
                int count = 0;
                if (current.ContentStream is { } source)
                {
                    using (source)
                    {
                        int read;
                        do
                        {
                            read = await source.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false);
                            message.CancellationToken.ThrowIfCancellationRequested();
                            count += read;
                            if (count > limits.MaximumResponseBytes) throw new Boundary(Failure.Budget);
                        } while (read != 0);
                    }
                }
                var stream = new ZeroingStream(bytes, count);
                current.ContentStream = stream;
                return stream;
            }
            catch { CryptographicOperations.ZeroMemory(bytes); throw; }
        }
        public void Dispose()
        {
            buffer?.Dispose();
            response?.Dispose();
        }
    }

    private static JsonElement Object(JsonElement root, string field)
    {
        Require(root.ValueKind == JsonValueKind.Object);
        Require(root.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.Object);
        return value;
    }
    private static JsonElement ArrayValue(JsonElement root, string field)
    {
        Require(root.ValueKind == JsonValueKind.Object);
        Require(root.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.Array);
        return value;
    }
    private static string Text(JsonElement root, string field)
    {
        Require(root.ValueKind == JsonValueKind.Object);
        Require(root.TryGetProperty(field, out var value) && value.ValueKind == JsonValueKind.String);
        return value.GetString()!;
    }
    private static Guid GuidValue(JsonElement root, string field)
    {
        Require(Guid.TryParse(Text(root, field), out Guid id) && id != Guid.Empty);
        return id;
    }
    private static void OptionalText(JsonElement root, string field)
    {
        if (root.TryGetProperty(field, out var v)) Require(v.ValueKind is JsonValueKind.String or JsonValueKind.Null);
    }
    private static void OptionalBoolean(JsonElement root, string field)
    {
        if (root.TryGetProperty(field, out var v)) Require(v.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null);
    }
    private static void OptionalDate(JsonElement root, string field)
    {
        if (root.TryGetProperty(field, out var v) && v.ValueKind != JsonValueKind.Null)
            Require(v.ValueKind == JsonValueKind.String && v.TryGetDateTimeOffset(out _));
    }
    private static void StringArray(JsonElement root, string field)
    {
        JsonElement array = ArrayValue(root, field);
        Require(array.GetArrayLength() <= 256);
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var value in array.EnumerateArray())
            Require(value.ValueKind == JsonValueKind.String && values.Add(value.GetString()!));
    }
    // Structural, byte, row and array budgets are applied before native SDK model
    // materialization. Duplicate properties are rejected rather than last-wins.
    private static void Shape(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in element.EnumerateObject())
            {
                Require(names.Count < 128 && names.Add(p.Name));
                Shape(p.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            if (element.GetArrayLength() > 10000) throw new Boundary(Failure.Budget);
            foreach (var item in element.EnumerateArray()) Shape(item);
        }
        else if (element.ValueKind == JsonValueKind.String && element.GetString()!.Length > 8192)
            throw new Boundary(Failure.Budget);
    }
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new Boundary();
    }
    private sealed class Boundary(Failure reason = Failure.Boundary) : Exception("vault-metadata-boundary")
    {
        internal Failure Reason { get; } = reason;
    }
    private sealed class AudienceCredential(TokenCredential inner) : TokenCredential
    {
        private static void Check(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Require(context.Scopes.Length == 1 && context.Scopes[0] == ArmOrigin + "/.default");
        }
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Check(context, cancellationToken);
            return inner.GetToken(context, cancellationToken);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Check(context, cancellationToken);
            return inner.GetTokenAsync(context, cancellationToken);
        }
    }
    private sealed class ZeroingStream : MemoryStream
    {
        private readonly byte[] storage;
        private readonly int count;
        internal ZeroingStream(byte[] storage, int count) : base(storage, 0, count, false, true)
        {
            this.storage = storage;
            this.count = count;
        }
        internal ReadOnlyMemory<byte> Bytes => storage.AsMemory(0, count);
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(storage);
            base.Dispose(disposing);
        }
    }
    private sealed class RequestBuffer : Stream
    {
        private readonly byte[] storage = new byte[1024];
        private int written;
        internal ReadOnlyMemory<byte> Written => storage.AsMemory(0, written);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => written;
        public override long Position { get => written; set => throw new Boundary(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new Boundary();
        public override long Seek(long offset, SeekOrigin origin) => throw new Boundary();
        public override void SetLength(long value) => throw new Boundary();
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (buffer.Length > 1024 - written) throw new Boundary(Failure.Budget);
            buffer.CopyTo(storage.AsSpan(written));
            written += buffer.Length;
        }
        public override void WriteByte(byte value)
        {
            if (written == 1024) throw new Boundary(Failure.Budget);
            storage[written++] = value;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.AsSpan(offset, count));
            return Task.CompletedTask;
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(storage);
            base.Dispose(disposing);
        }
    }
}
