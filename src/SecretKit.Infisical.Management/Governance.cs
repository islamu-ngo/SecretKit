using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native audit event categories; writable settings admit only authentication and authorization.</summary>
public enum AuditEventClass { /** <summary>Administrative configuration events.</summary> */ Management, /** <summary>Identity authentication events.</summary> */ Authentication, /** <summary>Authorization decision events.</summary> */ Authorization, /** <summary>Secret or other protected data access events.</summary> */ DataAccess }

/// <summary>One explicit native audit-class switch, not evidence that events were captured.</summary>
public sealed class AuditClassSetting
{
    /// <summary>Captures a known audit category and its explicit enabled state.</summary>
    public AuditClassSetting(AuditEventClass eventClass, bool isEnabled)
    {
        if (!Enum.IsDefined(eventClass)) throw new ArgumentException("Invalid audit class.");
        EventClass = eventClass;
        IsEnabled = isEnabled;
    }
    /// <summary>Gets the selected native audit category.</summary>
    public AuditEventClass EventClass { get; }
    /// <summary>Gets the explicit enabled state, not provider logging proof.</summary>
    public bool IsEnabled { get; }
    /// <summary>Returns a marker without additional policy details.</summary>
    public override string ToString() => "[AuditClassSetting]";
}

/// <summary>Returned audit settings, not permission or event-delivery evidence.</summary>
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
    /// <summary>Gets bounded returned class settings; absent categories are not inferred.</summary>
    [JsonIgnore] public IReadOnlyList<AuditClassSetting> Classes { get; }
    /// <summary>Gets the provider-reported privilege-system flag.</summary>
    public bool UsesNewPrivilegeSystem { get; }
    /// <summary>Returns a marker without class settings.</summary>
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
        ExpiresAt = ProjectWire.StringField(value, "expiresAt", nullable: true);
        IpAddress = ProjectWire.StringField(value, "ipAddress", nullable: true);
        ProjectName = ProjectWire.StringField(value, "projectName", nullable: true);
        UpdatedAt = ProjectField<string>.Present(ManagementJson.Required(value, "updatedAt"));
        UserAgent = ProjectWire.StringField(value, "userAgent", nullable: true);
        UserAgentType = ProjectWire.StringField(value, "userAgentType", nullable: true);
    }
    /// <summary>Gets the returned audit-entry identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned project coordinate, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? ProjectId { get; }
    /// <summary>Gets the returned event creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the native actor discriminator without arbitrary actor metadata.</summary>
    [JsonIgnore] public string ActorType { get; }
    /// <summary>Gets the native event-type discriminator without arbitrary event metadata.</summary>
    [JsonIgnore] public string EventType { get; }
    /// <summary>Gets the returned known audit category.</summary>
    public AuditEventClass EventClass { get; }
    /// <summary>Gets expiry timestamp presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> ExpiresAt { get; }
    /// <summary>Gets protected IP-address presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> IpAddress { get; }
    /// <summary>Gets project-name presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> ProjectName { get; }
    /// <summary>Gets the required returned update timestamp with presence information.</summary>
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    /// <summary>Gets protected user-agent presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> UserAgent { get; }
    /// <summary>Gets native agent-type presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> UserAgentType { get; }
    /// <summary>Always false: arbitrary actor metadata is not exported.</summary>
    public bool IncludesActorMetadata => false;
    /// <summary>Always false: arbitrary event metadata is not exported.</summary>
    public bool IncludesEventMetadata => false;
    /// <summary>Returns a marker without audit contents or coordinates.</summary>
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
    /// <summary>Gets the response ordinal including the requested offset; failed rows retain their positions.</summary>
    public int Ordinal { get; }
    /// <summary>Gets this row's validated outcome without discarding neighboring rows.</summary>
    public SecretOutcome<AuditEntry> Outcome { get; }
    /// <summary>Returns a marker without audit row contents.</summary>
    public override string ToString() => "[AuditRow]";
}

/// <summary>Constructs disposable audit-setting and inventory requests under independently approved authority.</summary>
public static class GovernanceOperations
{
    /// <summary>Builds organization audit-setting inspection; inspection does not establish logging or rights.</summary>
    public static ManagementRequest<AuditSettings> GetOrganizationAuditSettings(string organizationId) =>
        AuditConfiguration(organizationId, null, null);

    /// <summary>Builds organization audit-setting update requiring authentication and authorization exactly once.</summary>
    public static ManagementRequest<AuditSettings> SetOrganizationAuditSettings(string organizationId,
        IReadOnlyList<AuditClassSetting> settings) =>
        AuditConfiguration(organizationId, null, settings ?? throw new ArgumentNullException(nameof(settings)));

    /// <summary>Builds project audit-setting inspection for the explicit project UUID.</summary>
    public static ManagementRequest<AuditSettings> GetProjectAuditSettings(string organizationId, string projectId) =>
        AuditConfiguration(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)), null);

    /// <summary>Builds project audit-setting update requiring both writable categories exactly once.</summary>
    public static ManagementRequest<AuditSettings> SetProjectAuditSettings(string organizationId, string projectId,
        IReadOnlyList<AuditClassSetting> settings) =>
        AuditConfiguration(organizationId, projectId ?? throw new ArgumentNullException(nameof(projectId)),
            settings ?? throw new ArgumentNullException(nameof(settings)));

    /// <summary>Builds independent approval intent for the complete category-switch body and exact scope.</summary>
    public static ManagementTarget AuditSettingsTarget(string organizationId,
        IReadOnlyList<AuditClassSetting> settings, string? projectId = null)
    {
        ArgumentNullException.ThrowIfNull(settings);
        using var request = AuditConfiguration(organizationId, projectId, settings);
        return request.Target;
    }

    /// <summary>Builds bounded audit inventory over an ordered time window; each row retains its validation outcome.</summary>
    public static ManagementRequest<ManagementPage<AuditRow>> ReadAudit(string organizationId,
        DateTimeOffset from, DateTimeOffset until, string? projectId = null, int offset = 0, int limit = 100,
        AuditSelectors? selectors = null)
    {
        string query = AuditQuery(from, until, projectId, offset, limit, selectors);
        var scope = AuditTarget(organizationId, projectId, query, selectors);
        string path = "/api/v1/organization/audit-logs?" + query;
        return new("infisical.get.v1.organization.audit.logs", HttpMethod.Get, path, scope, null, root =>
        {
            var rows = new List<AuditRow>();
            foreach (JsonElement value in ManagementJson.Array(root, "auditLogs"))
            {
                SecretOutcome<AuditEntry> outcome;
                try
                {
                    var entry = new AuditEntry(value, scope);
                    ManagementResponseContracts.ValidateAuditRow(value);
                    ManagementResponseUuids.ValidateAuditRow(value);
                    ManagementResponseDates.ValidateAuditRow(value);
                    outcome = SecretOutcome<AuditEntry>.Success(entry);
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

    /// <summary>Builds independent approval intent for exact time bounds, paging and selector shapes.</summary>
    public static ManagementTarget AuditReadTarget(string organizationId, DateTimeOffset from, DateTimeOffset until,
        string? projectId = null, int offset = 0, int limit = 100, AuditSelectors? selectors = null) =>
        AuditTarget(organizationId, projectId, AuditQuery(from, until, projectId, offset, limit, selectors), selectors);

    private static string AuditQuery(DateTimeOffset from, DateTimeOffset until, string? projectId,
        int offset, int limit, AuditSelectors? selectors)
    {
        if (until <= from) throw new ArgumentException("An ordered audit time window is required.");
        string query = ManagementJson.Paging(offset, limit) +
            "&startDate=" + Uri.EscapeDataString(from.ToString("O", CultureInfo.InvariantCulture)) +
            "&endDate=" + Uri.EscapeDataString(until.ToString("O", CultureInfo.InvariantCulture)) +
            (projectId is null ? "" : "&projectId=" + ManagementJson.Escape(projectId)) + selectors?.Query();
        if (query.Length > 60000) throw new ArgumentException("The audit query exceeds its local URI budget.");
        return query;
    }

    private static ManagementTarget AuditTarget(string organizationId, string? projectId, string query, AuditSelectors? selectors)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            query,
            classArray = selectors?.EventClass?.IsArray,
            typeArray = selectors?.EventType?.IsArray
        });
        try { return new(organizationId, projectId, secondaryId: Convert.ToHexString(SHA256.HashData(bytes))); }
        finally { Array.Clear(bytes); }
    }

    private static ManagementRequest<AuditSettings> AuditConfiguration(string org, string? project,
        IReadOnlyList<AuditClassSetting>? settings)
    {
        if (project is not null) ManagementJson.UuidInput(project);
        AuditClassSetting[]? copy = settings?.Take(3).ToArray();
        if (copy is not null && (copy.Length != 2 ||
            copy.Any(item => item is null || item.EventClass is not (AuditEventClass.Authentication or AuditEventClass.Authorization)) ||
            copy.Select(item => item.EventClass).Distinct().Count() != copy.Length))
        {
            throw new ArgumentException("Authentication and authorization audit settings are each required exactly once.", nameof(settings));
        }
        string kind = project is null ? "organization" : "projects.by.projectId";
        string route = project is null ? "/api/v1/organization" : "/api/v1/projects/" + ManagementJson.Escape(project);
        void Write(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteStartArray("eventClasses");
            foreach (AuditClassSetting item in copy!)
            {
                writer.WriteStartObject();
                writer.WriteString("eventClass", ClassName(item.EventClass));
                writer.WriteBoolean("isEnabled", item.IsEnabled);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteEndObject();
        }
        return new($"infisical.{(copy is null ? "get" : "put")}.v1.{kind}.audit.log.settings",
            copy is null ? HttpMethod.Get : HttpMethod.Put, route + "/audit-log-settings",
            copy is null ? new(org, project) : ProjectWire.Intent(org, project, null, Write),
            copy is null ? null : Write, root => new(root), copy is not null);
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
    internal SharedSecretMetadata(JsonElement value, string organizationId, string? id = null, bool inspection = false)
    {
        string? returnedOrganization = ManagementJson.Optional(value, "orgId");
        if (returnedOrganization is not null && returnedOrganization != organizationId)
            throw new ManagementContractException(SecretStatus.Invalid);
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        Id = ManagementJson.Required(value, "id");
        Name = ManagementJson.Optional(value, "name");
        ExpiresAt = ManagementJson.Required(value, "expiresAt");
        AccessType = ManagementJson.Optional(value, "accessType");
        OrganizationId = ProjectWire.StringField(value, "orgId", nullable: true);
        AllowExternalEmails = ProjectWire.BooleanField(value, "allowExternalEmails", nullable: true);
        CreatedAt = ProjectWire.StringField(value, "createdAt");
        UpdatedAt = ProjectWire.StringField(value, "updatedAt");
        if (!CreatedAt.IsPresent || !UpdatedAt.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
        ExpiresAfterViews = ProjectWire.NumberField(value, "expiresAfterViews", nullable: true);
        IdentityId = ProjectWire.StringField(value, "identityId", nullable: true);
        LastViewedAt = ProjectWire.StringField(value, "lastViewedAt", nullable: true);
        Type = ProjectWire.StringField(value, "type");
        UserId = ProjectWire.StringField(value, "userId", nullable: true);
        IsAuthorizedUser = ProjectWire.BooleanField(value, "isAuthorizedUser");
        IsPasswordProtected = ProjectWire.BooleanField(value, "isPasswordProtected");
        if (inspection && (!IsAuthorizedUser.IsPresent || !IsPasswordProtected.IsPresent))
            throw new ManagementContractException(SecretStatus.Unknown);
        OrganizationName = ProjectWire.StringField(value, "orgName");
    }
    /// <summary>Gets the returned share identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned share name, or null when not supplied.</summary>
    [JsonIgnore] public string? Name { get; }
    /// <summary>Gets the native returned expiration timestamp.</summary>
    [JsonIgnore] public string ExpiresAt { get; }
    /// <summary>Gets the returned audience label, or null when not supplied.</summary>
    [JsonIgnore] public string? AccessType { get; }
    /// <summary>Gets organization presence, retaining explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> OrganizationId { get; }
    /// <summary>Gets external-email policy-field presence, not full recipient policy.</summary>
    [JsonIgnore] public ProjectField<bool> AllowExternalEmails { get; }
    /// <summary>Gets required returned creation time with presence information.</summary>
    [JsonIgnore] public ProjectField<string> CreatedAt { get; }
    /// <summary>Gets required returned update time with presence information.</summary>
    [JsonIgnore] public ProjectField<string> UpdatedAt { get; }
    /// <summary>Gets view-expiration count presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<double> ExpiresAfterViews { get; }
    /// <summary>Gets creating-identity presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> IdentityId { get; }
    /// <summary>Gets last-view timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> LastViewedAt { get; }
    /// <summary>Gets returned native share-type presence.</summary>
    [JsonIgnore] public ProjectField<string> Type { get; }
    /// <summary>Gets creating-user presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> UserId { get; }
    /// <summary>Gets reported authorization-flag presence; not independently verified recipient policy.</summary>
    [JsonIgnore] public ProjectField<bool> IsAuthorizedUser { get; }
    /// <summary>Gets password-protection flag presence; not a password export.</summary>
    [JsonIgnore] public ProjectField<bool> IsPasswordProtected { get; }
    /// <summary>Gets organization-name presence without inferring an omitted name.</summary>
    [JsonIgnore] public ProjectField<string> OrganizationName { get; }
    /// <summary>Always false: full recipient policy is not projected.</summary>
    public bool IncludesRecipientPolicy => false;
    /// <summary>Returns a marker without share metadata.</summary>
    public override string ToString() => "[SharedSecretMetadata]";
}

/// <summary>Share creation result owning a protected link; dispose after use and protect deliberate plaintext exports.</summary>
public sealed class CreatedShare : IDisposable
{
    internal CreatedShare(SharedSecretMetadata metadata, SecretMaterial link)
    {
        Metadata = metadata;
        Link = link;
    }
    /// <summary>Gets returned share metadata without inferring recipient access.</summary>
    [JsonIgnore] public SharedSecretMetadata Metadata { get; }
    /// <summary>Gets the owned protected link; revealing creates an ordinary managed string.</summary>
    [JsonIgnore] public SecretMaterial Link { get; }
    /// <summary>Disposes owned link material without deleting the provider share.</summary>
    public void Dispose() => Link.Dispose();
    /// <summary>Returns a marker without the share link.</summary>
    public override string ToString() => "[CreatedShare]";
}

/// <summary>Share-access result owning returned secret material; access may already have consumed a view.</summary>
public sealed class SharedValue : IDisposable
{
    internal SharedValue(SharedSecretMetadata metadata, SecretMaterial material)
    {
        Metadata = metadata;
        Material = material;
    }
    /// <summary>Gets returned metadata associated with accessed material.</summary>
    [JsonIgnore] public SharedSecretMetadata Metadata { get; }
    /// <summary>Gets owned returned material; dispose the containing result after use.</summary>
    [JsonIgnore] public SecretMaterial Material { get; }
    /// <summary>Disposes owned value material without undoing view consumption or erasing exported strings.</summary>
    public void Dispose() => Material.Dispose();
    /// <summary>Returns a marker without the shared value.</summary>
    public override string ToString() => "[SharedValue]";
}

/// <summary>Explicit native audience choice for share creation.</summary>
public enum ShareAudience { /** <summary>Selects organization-scoped sharing.</summary> */ Organization, /** <summary>Selects the native anyone audience; recipient policy still belongs to the provider and host.</summary> */ Anyone }

/// <summary>Constructs disposable sharing requests; view-consuming access requires mutation receipts.</summary>
public static class SharingOperations
{
    /// <summary>Builds count-validated share inventory within the native offset limit.</summary>
    public static ManagementRequest<ManagementPage<SharedSecretMetadata>> ListShares(
        string organizationId, int offset = 0, int limit = 100)
    {
        if (offset > 100) throw new ArgumentException("The native sharing offset exceeds its published maximum.");
        string query = ManagementJson.Paging(offset, limit);
        return new("infisical.get.v1.shared.secrets", HttpMethod.Get,
            "/api/v1/shared-secrets?" + query,
            ProjectWire.Intent(organizationId, null, null, writer => writer.WriteStringValue(query)), null,
            root => ScopedAccessOperations.CountedPage(root, "secrets",
                value => new SharedSecretMetadata(value, organizationId), offset, limit), false);
    }

    /// <summary>Builds independent approval intent for the selected sharing inventory page.</summary>
    public static ManagementTarget ListSharesTarget(string organizationId, int offset = 0, int limit = 100)
    {
        using var request = ListShares(organizationId, offset, limit);
        return request.Target;
    }

    /// <summary>Builds share metadata inspection without retrieving the shared value.</summary>
    public static ManagementRequest<SharedSecretMetadata> GetShare(string organizationId, string shareId) =>
        new("infisical.get.v1.shared.secrets.by.id", HttpMethod.Get,
            "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId), new(organizationId, resourceId: shareId),
            null, root => new(root, organizationId, shareId, inspection: true), false);

    /// <summary>Builds deletion of the exact share; uncertain execution is retained in the caller receipt.</summary>
    public static ManagementRequest<SharedSecretMetadata> DeleteShare(string organizationId, string shareId) =>
        new("infisical.delete.v1.shared.secrets.by.id", HttpMethod.Delete,
            "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId), new(organizationId, resourceId: shareId),
            null, root => new(root, organizationId, shareId));

    /// <summary>Builds sharing with a 5-to-43200-minute lifetime; copies material into the owned request body and leaves originals caller-owned.</summary>
    public static ManagementRequest<CreatedShare> CreateShare(string organizationId, string name,
        SecretMaterial material, int lifetimeMinutes, ShareAudience audience,
        int? maximumViews = null, SecretMaterial? password = null,
        bool? allowExternalEmails = null, IReadOnlyList<string>? authorizedEmails = null)
    {
        ManagementJson.Text(name, 50);
        ArgumentNullException.ThrowIfNull(material);
        if (!Enum.IsDefined(audience) || lifetimeMinutes is < 5 or > 43200 || maximumViews is < 1)
        {
            throw new ArgumentException("Invalid sharing bounds.");
        }
        string[]? emails = authorizedEmails?.Take(101).ToArray();
        if (emails is not null && (emails.Length > 100 || emails.Any(email =>
            email is null || email.Length > 1024 || !System.Net.Mail.MailAddress.TryCreate(email, out var address) ||
            address.Address != email)))
            throw new ArgumentException("Invalid sharing email selectors.");
        char[] value = material.ExportCharacters();
        char[]? proof = null;
        try
        {
            proof = password?.ExportCharacters();
            if (value.Length > 10000 || proof?.Length > 4096)
            {
                throw new ArgumentException("Sharing material exceeds its input budget.");
            }
            void Write(Utf8JsonWriter writer)
            {
                writer.WriteStartObject();
                writer.WriteString("name", name);
                writer.WriteString("secretValue", value.AsSpan());
                if (proof is not null) writer.WriteString("password", proof.AsSpan());
                writer.WriteString("expiresIn", lifetimeMinutes.ToString(CultureInfo.InvariantCulture) + "m");
                writer.WriteString("accessType", audience == ShareAudience.Organization ? "organization" : "anyone");
                if (maximumViews is { } count) writer.WriteNumber("maxViews", count);
                if (allowExternalEmails is { } external) writer.WriteBoolean("allowExternalEmails", external);
                if (emails is not null)
                {
                    writer.WriteStartArray("authorizedEmails");
                    foreach (string email in emails) writer.WriteStringValue(email);
                    writer.WriteEndArray();
                }
                writer.WriteEndObject();
            }
            return new("infisical.post.v1.shared.secrets", HttpMethod.Post, "/api/v1/shared-secrets",
                ProjectWire.Intent(organizationId, null, name, Write), Write, root =>
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

    /// <summary>Independently select every sharing input for the host's exact grant.</summary>
    public static ManagementTarget CreateShareTarget(string organizationId, string name,
        SecretMaterial material, int lifetimeMinutes, ShareAudience audience,
        int? maximumViews = null, SecretMaterial? password = null,
        bool? allowExternalEmails = null, IReadOnlyList<string>? authorizedEmails = null)
    {
        using var request = CreateShare(organizationId, name, material, lifetimeMinutes, audience,
            maximumViews, password, allowExternalEmails, authorizedEmails);
        return request.Target;
    }

    /// <summary>Access may consume a view; it is always a receipt-bearing effect, never a plain read.</summary>
    public static ManagementRequest<SharedValue> AccessShare(string organizationId, string shareId,
        SecretMaterial? password = null)
    {
        char[]? proof = password?.ExportCharacters();
        try
        {
            if (proof?.Length > 4096) throw new ArgumentException("Sharing proof exceeds its input budget.");
            void Write(Utf8JsonWriter writer)
            {
                writer.WriteStartObject();
                if (proof is not null) writer.WriteString("password", proof.AsSpan());
                writer.WriteEndObject();
            }
            return new("infisical.post.v1.shared.secrets.by.id.access", HttpMethod.Post,
                "/api/v1/shared-secrets/" + ManagementJson.Escape(shareId) + "/access",
                ProjectWire.Intent(organizationId, null, shareId, Write), Write, root =>
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

    /// <summary>Builds independent approval intent for exact share access and optional password; construction does not consume a view.</summary>
    public static ManagementTarget AccessShareTarget(string organizationId, string shareId, SecretMaterial? password = null)
    {
        using var request = AccessShare(organizationId, shareId, password);
        return request.Target;
    }
}
