using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

public enum AuditEventClass { Management, Authentication, Authorization, DataAccess }

public sealed class AuditClassSetting
{
    public AuditClassSetting(AuditEventClass eventClass, bool isEnabled)
    {
        if (!Enum.IsDefined(eventClass)) throw new ArgumentException("Invalid audit class.");
        EventClass = eventClass;
        IsEnabled = isEnabled;
    }
    public AuditEventClass EventClass { get; }
    public bool IsEnabled { get; }
    public override string ToString() => "[AuditClassSetting]";
}

public sealed class AuditSettings
{
    internal AuditSettings(JsonElement root)
    {
        JsonElement value = ManagementJson.Object(root, "auditLogSettings");
        AuditClassSetting[] items = ManagementJson.Array(value, "eventClasses")
            .Select(item => new AuditClassSetting(GovernanceOperations.ParseClass(
                ManagementJson.Required(item, "eventClass")), ManagementJson.Boolean(item, "isEnabled"))).ToArray();
        if (items.Length > 4 || items.Select(item => item.EventClass).Distinct().Count() != items.Length)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        Classes = Array.AsReadOnly(items);
        UsesNewPrivilegeSystem = ManagementJson.Boolean(value, "shouldUseNewPrivilegeSystem");
    }
    [JsonIgnore] public IReadOnlyList<AuditClassSetting> Classes { get; }
    public bool UsesNewPrivilegeSystem { get; }
    public override string ToString() => "[AuditSettings]";
}

/// <summary>Known audit metadata only; arbitrary actor/event metadata is not exported.</summary>
public sealed class AuditEntry
{
    internal AuditEntry(JsonElement value, ManagementTarget scope)
    {
        ManagementJson.RequireEqual(value, "orgId", scope.OrganizationId);
        if (scope.ProjectId is not null) ManagementJson.RequireEqual(value, "projectId", scope.ProjectId);
        Id = ManagementJson.Required(value, "id");
        ProjectId = ManagementJson.Optional(value, "projectId");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        ActorType = ManagementJson.Required(ManagementJson.Object(value, "actor"), "type");
        JsonElement nativeEvent = ManagementJson.Object(value, "event");
        EventType = ManagementJson.Required(nativeEvent, "type");
        EventClass = GovernanceOperations.ParseClass(ManagementJson.Required(nativeEvent, "class"));
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string? ProjectId { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string ActorType { get; }
    [JsonIgnore] public string EventType { get; }
    public AuditEventClass EventClass { get; }
    public bool IncludesEventMetadata => false;
    public override string ToString() => "[AuditEntry]";
}

/// <summary>Stable response ordinal, including rows whose scope or contract failed validation.</summary>
public sealed class AuditRow
{
    internal AuditRow(int ordinal, SecretOutcome<AuditEntry> outcome)
    {
        Ordinal = ordinal;
        Outcome = outcome;
    }
    public int Ordinal { get; }
    public SecretOutcome<AuditEntry> Outcome { get; }
    public override string ToString() => "[AuditRow]";
}

public static class GovernanceOperations
{
    public static ManagementRequest<AuditSettings> GetOrganizationAuditSettings(string organizationId) =>
        AuditConfiguration(organizationId, null, null);

    public static ManagementRequest<AuditSettings> SetOrganizationAuditSettings(string organizationId,
        IReadOnlyList<AuditClassSetting> settings) => AuditConfiguration(organizationId, null, settings);

    public static ManagementRequest<AuditSettings> GetProjectAuditSettings(string organizationId, string projectId) =>
        AuditConfiguration(organizationId, projectId, null);

    public static ManagementRequest<AuditSettings> SetProjectAuditSettings(string organizationId, string projectId,
        IReadOnlyList<AuditClassSetting> settings) => AuditConfiguration(organizationId, projectId, settings);

    public static ManagementRequest<ManagementPage<AuditRow>> ReadAudit(string organizationId,
        DateTimeOffset from, DateTimeOffset until, string? projectId = null, int offset = 0, int limit = 100)
    {
        if (until <= from) throw new ArgumentException("An ordered audit time window is required.");
        var scope = new ManagementTarget(organizationId, projectId);
        string path = "/api/v1/organization/audit-logs?" + ManagementJson.Paging(offset, limit) +
            "&startDate=" + Uri.EscapeDataString(from.ToString("O", CultureInfo.InvariantCulture)) +
            "&endDate=" + Uri.EscapeDataString(until.ToString("O", CultureInfo.InvariantCulture)) +
            (projectId is null ? "" : "&projectId=" + ManagementJson.Escape(projectId));
        return new("infisical.get.v1.organization.audit.logs", HttpMethod.Get, path, scope, null, root =>
        {
            var rows = new List<AuditRow>();
            foreach (JsonElement value in ManagementJson.Array(root, "auditLogs"))
            {
                SecretOutcome<AuditEntry> outcome;
                try
                {
                    outcome = SecretOutcome<AuditEntry>.Success(new AuditEntry(value, scope));
                }
                catch (ManagementContractException error)
                {
                    outcome = SecretOutcome<AuditEntry>.Failure(error.Status);
                }
                rows.Add(new AuditRow(offset + rows.Count, outcome));
            }
            return ScopedAccessOperations.BoundedPage(rows.ToArray(), offset, limit);
        }, false);
    }

    private static ManagementRequest<AuditSettings> AuditConfiguration(string org, string? project,
        IReadOnlyList<AuditClassSetting>? settings)
    {
        AuditClassSetting[]? copy = settings?.Take(5).ToArray();
        if (copy is not null && (copy.Length is < 1 or > 4 || copy.Any(item => item is null) ||
            copy.Select(item => item.EventClass).Distinct().Count() != copy.Length))
        {
            throw new ArgumentException("One to four distinct audit class settings are required.");
        }
        string kind = project is null ? "organization" : "projects.by.projectId";
        string route = project is null ? "/api/v1/organization" : "/api/v1/projects/" + ManagementJson.Escape(project);
        return new($"infisical.{(copy is null ? "get" : "put")}.v1.{kind}.audit.log.settings",
            copy is null ? HttpMethod.Get : HttpMethod.Put, route + "/audit-log-settings", new(org, project),
            copy is null ? null : writer =>
            {
                writer.WriteStartObject();
                writer.WriteStartArray("eventClasses");
                foreach (AuditClassSetting item in copy)
                {
                    writer.WriteStartObject();
                    writer.WriteString("eventClass", ClassName(item.EventClass));
                    writer.WriteBoolean("isEnabled", item.IsEnabled);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.WriteEndObject();
            }, root => new(root), copy is not null);
    }

    internal static string ClassName(AuditEventClass value) => value switch
    {
        AuditEventClass.Management => "management",
        AuditEventClass.Authentication => "authentication",
        AuditEventClass.Authorization => "authorization",
        AuditEventClass.DataAccess => "data-access",
        _ => throw new ArgumentException("Invalid audit class.")
    };

    internal static AuditEventClass ParseClass(string value) => value switch
    {
        "management" => AuditEventClass.Management,
        "authentication" => AuditEventClass.Authentication,
        "authorization" => AuditEventClass.Authorization,
        "data-access" => AuditEventClass.DataAccess,
        _ => throw new ManagementContractException(SecretStatus.Unknown)
    };
}

/// <summary>Sharing metadata projection. Recipient policy is not inferred from this result.</summary>
public sealed class SharedSecretMetadata
{
    internal SharedSecretMetadata(JsonElement value, string organizationId, string? id = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Optional(value, "name");
        ExpiresAt = ManagementJson.Required(value, "expiresAt");
        AccessType = ManagementJson.Optional(value, "accessType");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string? Name { get; }
    [JsonIgnore] public string ExpiresAt { get; }
    [JsonIgnore] public string? AccessType { get; }
    public bool IncludesRecipientPolicy => false;
    public override string ToString() => "[SharedSecretMetadata]";
}

public sealed class CreatedShare : IDisposable
{
    internal CreatedShare(SharedSecretMetadata metadata, SecretMaterial link)
    {
        Metadata = metadata;
        Link = link;
    }
    [JsonIgnore] public SharedSecretMetadata Metadata { get; }
    [JsonIgnore] public SecretMaterial Link { get; }
    public void Dispose() => Link.Dispose();
    public override string ToString() => "[CreatedShare]";
}

public sealed class SharedValue : IDisposable
{
    internal SharedValue(SharedSecretMetadata metadata, SecretMaterial material)
    {
        Metadata = metadata;
        Material = material;
    }
    [JsonIgnore] public SharedSecretMetadata Metadata { get; }
    [JsonIgnore] public SecretMaterial Material { get; }
    public void Dispose() => Material.Dispose();
    public override string ToString() => "[SharedValue]";
}

public enum ShareAudience { Organization, Anyone }

public static class SharingOperations
{
    public static ManagementRequest<ManagementPage<SharedSecretMetadata>> ListShares(
        string organizationId, int offset = 0, int limit = 100)
    {
        if (offset > 100) throw new ArgumentException("The native sharing offset exceeds its published maximum.");
        return new("infisical.get.v1.shared.secrets", HttpMethod.Get,
            "/api/v1/shared-secrets?" + ManagementJson.Paging(offset, limit), new(organizationId), null,
            root => ScopedAccessOperations.CountedPage(root, "secrets",
                value => new SharedSecretMetadata(value, organizationId), offset, limit), false);
    }

    public static ManagementRequest<SharedSecretMetadata> GetShare(string organizationId, string shareId) =>
        new("infisical.get.v1.shared.secrets.by.id", HttpMethod.Get,
            "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId), new(organizationId, resourceId: shareId),
            null, root => new(root, organizationId, shareId), false);

    public static ManagementRequest<SharedSecretMetadata> DeleteShare(string organizationId, string shareId) =>
        new("infisical.delete.v1.shared.secrets.by.id", HttpMethod.Delete,
            "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId), new(organizationId, resourceId: shareId),
            null, root => new(root, organizationId, shareId));

    public static ManagementRequest<CreatedShare> CreateShare(string organizationId, string name,
        SecretMaterial material, int lifetimeMinutes, ShareAudience audience,
        int? maximumViews = null, SecretMaterial? password = null)
    {
        ManagementJson.Text(name, 50);
        ArgumentNullException.ThrowIfNull(material);
        if (!Enum.IsDefined(audience) || lifetimeMinutes is < 5 or > 43200 || maximumViews is < 1)
        {
            throw new ArgumentException("Invalid sharing bounds.");
        }
        char[] value = material.ExportCharacters();
        char[]? proof = password?.ExportCharacters();
        try
        {
            if (value.Length > 10000 || proof?.Length > 4096)
            {
                throw new ArgumentException("Sharing material exceeds its input budget.");
            }
            return new("infisical.post.v1.shared.secrets", HttpMethod.Post, "/api/v1/shared-secrets",
                new(organizationId, resourceId: name), writer =>
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", name);
                    writer.WriteString("secretValue", value.AsSpan());
                    if (proof is not null) writer.WriteString("password", proof.AsSpan());
                    writer.WriteString("expiresIn", lifetimeMinutes.ToString(CultureInfo.InvariantCulture) + "m");
                    writer.WriteString("accessType", audience == ShareAudience.Organization ? "organization" : "anyone");
                    if (maximumViews is { } count) writer.WriteNumber("maxViews", count);
                    writer.WriteEndObject();
                }, root =>
                {
                    var metadata = new SharedSecretMetadata(root, organizationId);
                    return new(metadata, SecretMaterial.FromText(ManagementJson.Required(root, "sharedSecretLink")));
                });
        }
        finally
        {
            Array.Clear(value);
            if (proof is not null) Array.Clear(proof);
        }
    }

    /// <summary>Access may consume a view; it is always a receipt-bearing effect, never a plain read.</summary>
    public static ManagementRequest<SharedValue> AccessShare(string organizationId, string shareId,
        SecretMaterial? password = null)
    {
        char[]? proof = password?.ExportCharacters();
        try
        {
            if (proof?.Length > 4096) throw new ArgumentException("Sharing proof exceeds its input budget.");
            return new("infisical.post.v1.shared.secrets.by.id.access", HttpMethod.Post,
                "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId) + "/access",
                new(organizationId, resourceId: shareId), writer =>
                {
                    writer.WriteStartObject();
                    if (proof is not null) writer.WriteString("password", proof.AsSpan());
                    writer.WriteEndObject();
                }, root =>
                {
                    var metadata = new SharedSecretMetadata(root, organizationId, shareId);
                    string value = ManagementJson.Optional(root, "secretValue") ??
                        throw new ManagementContractException(SecretStatus.Denied);
                    return new(metadata, SecretMaterial.FromText(value));
                });
        }
        finally
        {
            if (proof is not null) Array.Clear(proof);
        }
    }
}
