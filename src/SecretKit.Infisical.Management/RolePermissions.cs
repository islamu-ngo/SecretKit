using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

public enum OrganizationRoleSubject
{
    Workspace, Project, Role, SubOrganization, Member, Settings, IncidentContact, Sso, Scim,
    GithubOrgSync, GithubOrgSyncManual, Ldap, Groups, SecretScanning, Billing, Identity, Kms,
    AuditLogs, ProjectTemplates, AppConnections, OrganizationAdminConsole, SecretShare, Kmip,
    MachineIdentityAuthTemplate, Gateway, GatewayPool, Relay, KmipServer, EmailDomains,
    CertificateManager, HoneyTokens, OauthClients, SecretsManagementInsights
}

public enum OrganizationRoleAction
{
    Read, Create, Edit, Delete, RequestAccess, DirectAccess, LinkGroup, GrantPrivileges,
    BypassSsoEnforcement, AddIdentities, AddMembers, RemoveMembers, RemoveIdentities,
    ManageBilling, RevokeAuth, EditAuth, CreateToken, GetToken, DeleteToken, Connect,
    RotateCredentials, AccessAllProjects, ManageSettings, Proxy, ListTemplates, EditTemplates,
    CreateTemplates, DeleteTemplates, UnlinkTemplates, AttachTemplates, CreateGateways,
    ListGateways, EditGateways, DeleteGateways, AttachGateways, RevokeGatewayAccess,
    CreateGatewayPools, ListGatewayPools, EditGatewayPools, DeleteGatewayPools, AttachGatewayPools,
    CreateRelays, ListRelays, EditRelays, DeleteRelays, RevokeRelayAccess, CreateKmipServers,
    ListKmipServers, EditKmipServers, DeleteKmipServers, RevokeKmipServerAccess, VerifyDomain,
    ManageInstance, Setup, GenerateReport, DeleteReport, SearchAllSecretValues
}

/// <summary>Finite active subjects; deprecated SSH/MCP compatibility branches are not authorable.</summary>
public enum ProjectRoleSubject
{
    Secrets, SecretFolders, SecretImports, DynamicSecrets, Identity, PkiSubscribers,
    CertificateTemplates, SecretRotation, SecretSyncs, PkiSyncs, SecretEventSubscriptions,
    CertificateProfiles, CertificatePolicies, CertificateApplication, CertificateAuthorities,
    Certificates, SecretApproval, SecretRollback, Member, Groups, Role, Integrations, Webhooks,
    ServiceTokens, Settings, SecretValidationRules, Environments, Tags, AuditLogs, Insights,
    IpAllowlist, PkiAlerts, PkiCollections, CertificateInventoryViews, PkiDiscovery,
    PkiCertificateInstallations, CodeSigners, Workspace, Kms, Cmek, Kmip, Commits,
    SecretScanningDataSources, SecretScanningFindings, SecretScanningConfigs, AppConnections,
    HsmConnectors, HoneyTokens, ProxiedServices, AgentVaultAccessBundles, AgentVaultSessions,
    AgentVaultProxies, ApprovalRequests, ApprovalRequestGrants, SecretApprovalRequest, ProjectFolderGrant
}

public enum ProjectRoleAction
{
    Read, Create, Edit, Delete, DescribeSecret, ReadValue, ReadRootCredential, CreateRootCredential,
    EditRootCredential, DeleteRootCredential, Lease, GrantPrivileges, AssignRole,
    AssignAdditionalPrivileges, AssumePrivileges, RevokeAuth, EditAuth, CreateToken, GetToken,
    DeleteToken, IssueCert, ListCerts, ReadGeneratedCredentials, RotateSecrets, SyncSecrets,
    ImportSecrets, RemoveSecrets, SyncCertificates, ImportCertificates, RemoveCertificates,
    SetPostSyncCommand, SetHealthCheckCommand, SetTargetHost, SubscribeToCreationEvents,
    SubscribeToUpdateEvents, SubscribeToDeletionEvents, SubscribeToImportMutationEvents,
    RevealAcmeEabSecret, RotateAcmeEabSecret, ManageApplicationAttachments, List,
    IssueCaCertificate, SignIntermediate, ReadPrivateKey, Import, GenerateReport, DeleteReport,
    RunScan, Sign, Encrypt, Decrypt, Verify, GenerateMac, VerifyMac, Rotate, ExportPrivateKey,
    CreateClients, UpdateClients, DeleteClients, ReadClients, GenerateClientCertificates,
    PerformRollback, ReadDataSources, CreateDataSources, EditDataSources, DeleteDataSources,
    TriggerDataSourceScans, ReadDataSourceScans, ReadDataSourceResources, ReadFindings,
    UpdateFindings, ReadConfigs, UpdateConfigs, ReadAppConnections, CreateAppConnections,
    EditAppConnections, DeleteAppConnections, ConnectAppConnections, RotateCredentials,
    ReadHsmConnectors, CreateHsmConnectors, EditHsmConnectors, DeleteHsmConnectors,
    TestHsmConnectors, AttachHsmConnectors, ReadCredentials, Reset, Revoke, Proxy, ReportUsage,
    ManageMembers, IssueToken, ReadGrant, CreateGrant, RevokeGrant
}

public enum RoleConditionField
{
    ConnectionId, Environment, SecretPath, SecretName, EventType, IdentityId, AssignableRole,
    AssignableSubject, AssignableAction, Name, SubscriberName, Slug, CommonName, AltNames,
    SerialNumber, FriendlyName, Status, UserEmail, GroupName
}

/// <summary>Explicit literal or conjunctive comparison operators. No arbitrary predicate text.</summary>
public sealed class RoleStringClause
{
    private readonly string? _literal;
    private readonly string? _equal;
    private readonly string? _notEqual;
    private readonly string? _glob;
    private readonly string[]? _included;
    internal bool HasNotEqual => _notEqual is not null;
    internal bool HasGlob => _glob is not null;
    internal bool IsLiteral => _literal is not null;

    private RoleStringClause(string? literal, string? equal, string? notEqual, string? glob,
        IReadOnlyList<string>? included)
    {
        foreach (string? value in new[] { literal, equal, notEqual, glob })
            if (value is not null) RolePermissionWire.Text(value, 1024, literal == value);
        _literal = literal;
        _equal = equal;
        _notEqual = notEqual;
        _glob = glob;
        _included = included is null ? null : RolePermissionWire.CopyStrings(included);
    }

    public static RoleStringClause Literal(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value, null, null, null, null);
    }

    public static RoleStringClause Compare(string? equal = null, string? notEqual = null,
        IReadOnlyList<string>? included = null, string? glob = null) =>
        new(null, equal, notEqual, glob, included);

    internal void Write(Utf8JsonWriter writer)
    {
        if (_literal is not null) { writer.WriteStringValue(_literal); return; }
        writer.WriteStartObject();
        if (_equal is not null) writer.WriteString("$eq", _equal);
        if (_notEqual is not null) writer.WriteString("$ne", _notEqual);
        if (_included is not null) RolePermissionWire.Strings(writer, "$in", _included);
        if (_glob is not null) writer.WriteString("$glob", _glob);
        writer.WriteEndObject();
    }

    public override string ToString() => "[RoleStringClause]";
}

public sealed class RoleCondition
{
    public RoleCondition(RoleConditionField field, RoleStringClause clause)
    {
        if (!Enum.IsDefined(field)) throw new ArgumentOutOfRangeException(nameof(field));
        ArgumentNullException.ThrowIfNull(clause);
        Field = field;
        Clause = clause;
    }
    [JsonIgnore] public RoleConditionField Field { get; }
    [JsonIgnore] public RoleStringClause Clause { get; }
    public override string ToString() => "[RoleCondition]";
}

public sealed class RoleSecretTags
{
    private readonly string[]? _included;
    private readonly string[]? _all;
    public RoleSecretTags(IReadOnlyList<string>? included = null, IReadOnlyList<string>? all = null)
    {
        _included = included is null ? null : RolePermissionWire.CopyStrings(included);
        _all = all is null ? null : RolePermissionWire.CopyStrings(all);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("secretTags");
        if (_included is not null) RolePermissionWire.Strings(writer, "$in", _included);
        if (_all is not null) RolePermissionWire.Strings(writer, "$all", _all);
        writer.WriteEndObject();
    }
    public override string ToString() => "[RoleSecretTags]";
}

/// <summary>Conjunctive key/value comparisons on one metadata entry, not independent entries.</summary>
public sealed class RoleMetadataMatch
{
    private readonly RoleStringClause? _key;
    private readonly RoleStringClause? _value;
    internal bool HasNotEqual => (_key?.HasNotEqual ?? false) || (_value?.HasNotEqual ?? false);

    public RoleMetadataMatch(RoleStringClause? key = null, RoleStringClause? value = null)
    {
        foreach (RoleStringClause? clause in new[] { key, value })
            if (clause is not null && (clause.IsLiteral || clause.HasGlob))
                throw new ArgumentException("Metadata accepts comparison objects without glob predicates.");
        _key = key;
        _value = value;
    }

    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("metadata");
        writer.WriteStartObject("$elemMatch");
        if (_key is not null) { writer.WritePropertyName("key"); _key.Write(writer); }
        if (_value is not null) { writer.WritePropertyName("value"); _value.Write(writer); }
        writer.WriteEndObject();
        writer.WriteEndObject();
    }
    public override string ToString() => "[RoleMetadataMatch]";
}

/// <summary>One organization subject and its validated action selection; immutable owned input.</summary>
public sealed class OrganizationRolePermission
{
    private readonly string _subject;
    private readonly string[] _actions;
    private readonly bool _scalar;
    private readonly bool? _inverted;
    private readonly RoleCondition[]? _conditions;

    public OrganizationRolePermission(OrganizationRoleSubject subject, OrganizationRoleAction action,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null)
        : this(subject, [action], inverted, conditions) => _scalar = true;

    public OrganizationRolePermission(OrganizationRoleSubject subject, IReadOnlyList<OrganizationRoleAction> actions,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null)
    {
        _subject = RolePermissionWire.Name(subject);
        _actions = RolePermissionWire.Actions(actions, OrganizationActions(subject));
        if (inverted is not null && subject != OrganizationRoleSubject.AppConnections)
            throw new ArgumentException("Inversion is not supported for this subject.");
        _inverted = inverted;
        _conditions = RolePermissionWire.Conditions(conditions, subject == OrganizationRoleSubject.AppConnections
            ? [RoleConditionField.ConnectionId] : []);
    }

    private static string OrganizationActions(OrganizationRoleSubject subject) => subject switch
    {
        OrganizationRoleSubject.Workspace => "create",
        OrganizationRoleSubject.Project => "create request-access",
        OrganizationRoleSubject.SubOrganization => "create edit delete direct-access link-group",
        OrganizationRoleSubject.Member => "read create edit delete grant-privileges",
        OrganizationRoleSubject.Sso => "read create edit delete bypass-sso-enforcement",
        OrganizationRoleSubject.Groups => "read create edit delete grant-privileges add-identities add-members remove-members remove-identities",
        OrganizationRoleSubject.Billing => "read manage-billing",
        OrganizationRoleSubject.Identity => "read create edit delete grant-privileges revoke-auth edit-auth create-token get-token delete-token",
        OrganizationRoleSubject.AuditLogs => "read edit",
        OrganizationRoleSubject.AppConnections => "read create edit delete connect rotate-credentials",
        OrganizationRoleSubject.OrganizationAdminConsole => "access-all-projects",
        OrganizationRoleSubject.SecretShare => "manage-settings",
        OrganizationRoleSubject.Kmip => "proxy",
        OrganizationRoleSubject.MachineIdentityAuthTemplate => "list-templates edit-templates create-templates delete-templates unlink-templates attach-templates",
        OrganizationRoleSubject.Gateway => "create-gateways list-gateways edit-gateways delete-gateways attach-gateways revoke-gateway-access",
        OrganizationRoleSubject.GatewayPool => "create-gateway-pools list-gateway-pools edit-gateway-pools delete-gateway-pools attach-gateway-pools",
        OrganizationRoleSubject.Relay => "create-relays list-relays edit-relays delete-relays revoke-relay-access",
        OrganizationRoleSubject.KmipServer => "create-kmip-servers list-kmip-servers edit-kmip-servers delete-kmip-servers revoke-kmip-server-access",
        OrganizationRoleSubject.EmailDomains => "read create verify-domain delete",
        OrganizationRoleSubject.CertificateManager => "read manage-instance manage-settings",
        OrganizationRoleSubject.HoneyTokens => "setup",
        OrganizationRoleSubject.SecretsManagementInsights => "read generate-report delete-report search-all-secret-values",
        OrganizationRoleSubject.Role or OrganizationRoleSubject.Settings or OrganizationRoleSubject.IncidentContact or
        OrganizationRoleSubject.Scim or OrganizationRoleSubject.GithubOrgSync or OrganizationRoleSubject.GithubOrgSyncManual or
        OrganizationRoleSubject.Ldap or OrganizationRoleSubject.SecretScanning or OrganizationRoleSubject.Kms or
        OrganizationRoleSubject.ProjectTemplates or OrganizationRoleSubject.OauthClients => "read create edit delete",
        _ => throw new ArgumentOutOfRangeException(nameof(subject))
    };

    internal void Write(Utf8JsonWriter writer) =>
        RolePermissionWire.Write(writer, _subject, _actions, _scalar, _inverted, _conditions, null, null);
    public override string ToString() => "[OrganizationRolePermission]";
}

public sealed class ProjectRolePermission
{
    private readonly string _subject;
    private readonly string[] _actions;
    private readonly bool _scalar;
    private readonly bool? _inverted;
    private readonly RoleCondition[]? _conditions;
    private readonly RoleSecretTags? _tags;
    private readonly RoleMetadataMatch? _metadata;

    public ProjectRolePermission(ProjectRoleSubject subject, ProjectRoleAction action,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null, RoleSecretTags? secretTags = null,
        RoleMetadataMatch? metadata = null)
        : this(subject, [action], inverted, conditions, secretTags, metadata) => _scalar = true;

    public ProjectRolePermission(ProjectRoleSubject subject, IReadOnlyList<ProjectRoleAction> actions,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null, RoleSecretTags? secretTags = null,
        RoleMetadataMatch? metadata = null)
    {
        _subject = RolePermissionWire.Name(subject);
        _actions = RolePermissionWire.Actions(actions, ProjectActions(subject));
        RoleConditionField[] fields = Fields(subject);
        if (inverted is not null && fields.Length == 0 && subject is not
            (ProjectRoleSubject.AgentVaultAccessBundles or ProjectRoleSubject.AgentVaultSessions or ProjectRoleSubject.AgentVaultProxies))
            throw new ArgumentException("Inversion is not supported for this subject.");
        _inverted = inverted;
        _conditions = RolePermissionWire.Conditions(conditions, fields, subject);
        if (secretTags is not null && subject != ProjectRoleSubject.Secrets)
            throw new ArgumentException("Tag conditions are not supported for this subject.");
        _tags = secretTags;
        if (metadata is not null && (subject is not (ProjectRoleSubject.DynamicSecrets or ProjectRoleSubject.Certificates) ||
            subject == ProjectRoleSubject.Certificates && metadata.HasNotEqual))
            throw new ArgumentException("Metadata comparisons are not supported for this subject.");
        _metadata = metadata;
    }

    private static RoleConditionField[] Fields(ProjectRoleSubject subject) => subject switch
    {
        ProjectRoleSubject.Secrets => [RoleConditionField.Environment, RoleConditionField.SecretPath, RoleConditionField.SecretName, RoleConditionField.EventType],
        ProjectRoleSubject.SecretFolders or ProjectRoleSubject.SecretImports or ProjectRoleSubject.DynamicSecrets or
        ProjectRoleSubject.Commits or ProjectRoleSubject.HoneyTokens or ProjectRoleSubject.ProxiedServices or
        ProjectRoleSubject.ProjectFolderGrant => [RoleConditionField.Environment, RoleConditionField.SecretPath],
        ProjectRoleSubject.SecretRotation or ProjectRoleSubject.SecretSyncs or ProjectRoleSubject.SecretEventSubscriptions =>
            [RoleConditionField.Environment, RoleConditionField.SecretPath, RoleConditionField.ConnectionId],
        ProjectRoleSubject.Identity => [RoleConditionField.IdentityId, RoleConditionField.AssignableRole, RoleConditionField.AssignableSubject, RoleConditionField.AssignableAction],
        ProjectRoleSubject.Member => [RoleConditionField.UserEmail, RoleConditionField.AssignableRole, RoleConditionField.AssignableSubject, RoleConditionField.AssignableAction],
        ProjectRoleSubject.Groups => [RoleConditionField.GroupName, RoleConditionField.AssignableRole],
        ProjectRoleSubject.PkiSubscribers or ProjectRoleSubject.CertificateTemplates or
        ProjectRoleSubject.CertificatePolicies or ProjectRoleSubject.CertificateAuthorities => [RoleConditionField.Name],
        ProjectRoleSubject.PkiSyncs => [RoleConditionField.Name, RoleConditionField.SubscriberName],
        ProjectRoleSubject.CertificateProfiles => [RoleConditionField.Slug],
        ProjectRoleSubject.Certificates => [RoleConditionField.CommonName, RoleConditionField.AltNames, RoleConditionField.SerialNumber, RoleConditionField.FriendlyName, RoleConditionField.Status],
        ProjectRoleSubject.AppConnections => [RoleConditionField.ConnectionId],
        _ => []
    };

    private static string ProjectActions(ProjectRoleSubject subject) => subject switch
    {
        ProjectRoleSubject.Secrets => "read describeSecret readValue create edit delete",
        ProjectRoleSubject.DynamicSecrets => "read-root-credential create-root-credential edit-root-credential delete-root-credential lease",
        ProjectRoleSubject.Identity => "read create edit delete grant-privileges assign-role assign-additional-privileges assume-privileges revoke-auth edit-auth create-token get-token delete-token",
        ProjectRoleSubject.PkiSubscribers or ProjectRoleSubject.CertificateTemplates => "read create edit delete issue-cert list-certs",
        ProjectRoleSubject.SecretRotation => "read read-generated-credentials create edit delete rotate-secrets",
        ProjectRoleSubject.SecretSyncs => "read create edit delete sync-secrets import-secrets remove-secrets",
        ProjectRoleSubject.PkiSyncs => "read create edit delete sync-certificates import-certificates remove-certificates set-post-sync-command set-health-check-command set-target-host",
        ProjectRoleSubject.SecretEventSubscriptions => "subscribe-to-creation-events subscribe-to-update-events subscribe-to-deletion-events subscribe-to-import-mutation-events",
        ProjectRoleSubject.CertificateProfiles => "read create edit delete issue-cert reveal-acme-eab-secret rotate-acme-eab-secret manage-application-attachments",
        ProjectRoleSubject.CertificateApplication => "read list create",
        ProjectRoleSubject.CertificateAuthorities => "read create edit delete issue-ca-certificate sign-intermediate",
        ProjectRoleSubject.Certificates => "read create edit delete read-private-key import",
        ProjectRoleSubject.SecretRollback or ProjectRoleSubject.ApprovalRequests => "read create",
        ProjectRoleSubject.Member => "read create edit delete grant-privileges assign-role assign-additional-privileges assume-privileges",
        ProjectRoleSubject.Groups => "read create edit delete grant-privileges assign-role",
        ProjectRoleSubject.AuditLogs => "read edit",
        ProjectRoleSubject.Insights => "read generate-report delete-report",
        ProjectRoleSubject.PkiDiscovery => "read create edit delete run-scan",
        ProjectRoleSubject.PkiCertificateInstallations => "read edit delete",
        ProjectRoleSubject.CodeSigners => "read create edit delete sign",
        ProjectRoleSubject.Workspace => "edit delete",
        ProjectRoleSubject.Kms => "edit",
        ProjectRoleSubject.Cmek => "read create edit delete encrypt decrypt sign verify generate-mac verify-mac rotate export-private-key",
        ProjectRoleSubject.Kmip => "create-clients update-clients delete-clients read-clients generate-client-certificates",
        ProjectRoleSubject.Commits => "read perform-rollback",
        ProjectRoleSubject.SecretScanningDataSources => "read-data-sources create-data-sources edit-data-sources delete-data-sources trigger-data-source-scans read-data-source-scans read-data-source-resources",
        ProjectRoleSubject.SecretScanningFindings => "read-findings update-findings",
        ProjectRoleSubject.SecretScanningConfigs => "read-configs update-configs",
        ProjectRoleSubject.AppConnections => "read-app-connections create-app-connections edit-app-connections delete-app-connections connect-app-connections rotate-credentials",
        ProjectRoleSubject.HsmConnectors => "read-hsm-connectors create-hsm-connectors edit-hsm-connectors delete-hsm-connectors test-hsm-connectors attach-hsm-connectors",
        ProjectRoleSubject.HoneyTokens => "read read-credentials create edit reset revoke",
        ProjectRoleSubject.ProxiedServices => "read create edit delete proxy report-usage",
        ProjectRoleSubject.AgentVaultAccessBundles => "read create edit delete manage-members",
        ProjectRoleSubject.AgentVaultSessions => "read create revoke",
        ProjectRoleSubject.AgentVaultProxies => "read create edit delete issue-token revoke",
        ProjectRoleSubject.ApprovalRequestGrants => "read revoke",
        ProjectRoleSubject.SecretApprovalRequest => "read",
        ProjectRoleSubject.ProjectFolderGrant => "read-grant create-grant revoke-grant",
        ProjectRoleSubject.SecretFolders or ProjectRoleSubject.SecretImports or ProjectRoleSubject.CertificatePolicies or
        ProjectRoleSubject.SecretApproval or ProjectRoleSubject.Role or ProjectRoleSubject.Integrations or
        ProjectRoleSubject.Webhooks or ProjectRoleSubject.ServiceTokens or ProjectRoleSubject.Settings or
        ProjectRoleSubject.SecretValidationRules or ProjectRoleSubject.Environments or ProjectRoleSubject.Tags or
        ProjectRoleSubject.IpAllowlist or ProjectRoleSubject.PkiAlerts or ProjectRoleSubject.PkiCollections or
        ProjectRoleSubject.CertificateInventoryViews => "read create edit delete",
        _ => throw new ArgumentOutOfRangeException(nameof(subject))
    };

    internal void Write(Utf8JsonWriter writer) =>
        RolePermissionWire.Write(writer, _subject, _actions, _scalar, _inverted, _conditions, _tags, _metadata);
    public override string ToString() => "[ProjectRolePermission]";
}

internal static class RolePermissionWire
{
    internal static void Text(string value, int maximum, bool allowEmpty = false)
    {
        ArgumentNullException.ThrowIfNull(value);
        if ((!allowEmpty && value.Length == 0) || value.Length > maximum || value.Any(char.IsControl))
            throw new ArgumentException("Invalid protected role input.");
    }

    internal static string[] CopyStrings(IReadOnlyList<string> values)
    {
        string[] copy = values.Take(101).ToArray();
        if (copy.Length > 100) throw new ArgumentException("Invalid role condition budget.");
        foreach (string value in copy) Text(value, 1024);
        return copy;
    }

    internal static string Name<T>(T value) where T : struct, Enum
    {
        if (!Enum.IsDefined(value)) throw new ArgumentOutOfRangeException(nameof(value));
        string name = value.ToString();
        if (name is "DescribeSecret" or "ReadValue") return char.ToLowerInvariant(name[0]) + name[1..];
        var result = new StringBuilder();
        for (int i = 0; i < name.Length; i++)
        {
            if (i > 0 && char.IsUpper(name[i])) result.Append('-');
            result.Append(char.ToLowerInvariant(name[i]));
        }
        return result.ToString();
    }

    internal static string[] Actions<T>(IReadOnlyList<T> actions, string allowed) where T : struct, Enum
    {
        ArgumentNullException.ThrowIfNull(actions);
        T[] copy = actions.Take(101).ToArray();
        if (copy.Length is < 1 or > 100) throw new ArgumentException("Invalid role action budget.");
        string[] result = copy.Select(Name).ToArray();
        string[] permitted = allowed.Split(' ');
        if (result.Any(action => !permitted.Contains(action, StringComparer.Ordinal)))
            throw new ArgumentException("An action is outside its selected subject domain.");
        return result;
    }

    internal static RoleCondition[]? Conditions(IReadOnlyList<RoleCondition>? values, RoleConditionField[] allowed,
        ProjectRoleSubject? project = null)
    {
        if (values is null) return null;
        RoleCondition[] copy = values.Take(21).ToArray();
        if (allowed.Length == 0 || copy.Length > 20 ||
            copy.Any(value => value is null) || copy.Select(value => value.Field).Distinct().Count() != copy.Length)
            throw new ArgumentException("Invalid role condition selection.");
        foreach (RoleCondition value in copy)
        {
            if (!allowed.Contains(value.Field)) throw new ArgumentException("A condition is outside its selected subject domain.");
            bool glob = value.Field is not (RoleConditionField.ConnectionId or RoleConditionField.EventType or
                RoleConditionField.IdentityId or RoleConditionField.AssignableRole) &&
                !(project == ProjectRoleSubject.SecretFolders && value.Field == RoleConditionField.Environment);
            if (value.Clause.HasGlob && !glob || value.Clause.HasNotEqual && project == ProjectRoleSubject.PkiSubscribers)
                throw new ArgumentException("A comparison is not supported for this subject field.");
        }
        return copy;
    }

    internal static void Strings(Utf8JsonWriter writer, string field, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(field);
        foreach (string value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    internal static void Write(Utf8JsonWriter writer, string subject, string[] actions, bool scalar,
        bool? inverted, RoleCondition[]? conditions, RoleSecretTags? tags, RoleMetadataMatch? metadata)
    {
        writer.WriteStartObject();
        writer.WriteString("subject", subject);
        if (scalar) writer.WriteString("action", actions[0]);
        else Strings(writer, "action", actions);
        if (inverted is { } deny) writer.WriteBoolean("inverted", deny);
        if (conditions is not null || tags is not null || metadata is not null)
        {
            writer.WriteStartObject("conditions");
            foreach (RoleCondition condition in conditions ?? [])
            {
                string name = condition.Field.ToString();
                writer.WritePropertyName(char.ToLowerInvariant(name[0]) + name[1..]);
                condition.Clause.Write(writer);
            }
            tags?.Write(writer);
            metadata?.Write(writer);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }
}

/// <summary>Protected native scalar or array metadata, not an effective authorization decision.</summary>
public sealed class RolePermissionSelection
{
    internal RolePermissionSelection(JsonElement value)
    {
        IsScalar = value.ValueKind == JsonValueKind.String;
        string[] values = IsScalar ? [String(value)] :
            ManagementJson.Array(value).Select(item => String(item, allowEmpty: true)).ToArray();
        Values = Array.AsReadOnly(values);
    }

    private static string String(JsonElement value, bool allowEmpty = false)
    {
        if (value.ValueKind != JsonValueKind.String)
            throw new ManagementContractException(SecretKit.Core.SecretStatus.Unknown);
        string result = value.GetString()!;
        if (result.Length > 16384 || !allowEmpty && result.Length == 0)
            throw new ManagementContractException(SecretKit.Core.SecretStatus.Unknown);
        return result;
    }

    public bool IsScalar { get; }
    [JsonIgnore] public IReadOnlyList<string> Values { get; }
    public override string ToString() => "[RolePermissionSelection]";
}

/// <summary>Known permission metadata only. Returned condition values remain unestablished and unexported.</summary>
public sealed class RolePermissionSummary
{
    internal RolePermissionSummary(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty("action", out var action))
            throw new ManagementContractException(SecretKit.Core.SecretStatus.Unknown);
        Action = new(action);
        if (value.TryGetProperty("subject", out var subject)) Subject = new(subject);
        if (value.TryGetProperty("inverted", out _)) Inverted = ManagementJson.Boolean(value, "inverted");
        HasConditions = value.TryGetProperty("conditions", out _);
    }

    internal static IReadOnlyList<RolePermissionSummary>? Read(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new ManagementContractException(SecretKit.Core.SecretStatus.Unknown);
        if (!value.TryGetProperty("permissions", out var permissions)) return null;
        return Array.AsReadOnly(ManagementJson.Array(permissions)
            .Select(permission => new RolePermissionSummary(permission)).ToArray());
    }

    [JsonIgnore] public RolePermissionSelection Action { get; }
    [JsonIgnore] public RolePermissionSelection? Subject { get; }
    [JsonIgnore] public bool? Inverted { get; }
    public bool HasConditions { get; }
    public bool IncludesConditionValues => false;
    public override string ToString() => "[RolePermissionSummary]";
}
