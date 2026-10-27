using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>Closed native organization permission subjects; selecting one does not grant its capabilities.</summary>
public enum OrganizationRoleSubject
{
    /** <summary>Legacy workspace subject admitting project creation.</summary> */
    Workspace, /** <summary>Project provisioning and access-request administration.</summary> */ Project, /** <summary>Organization custom-role administration.</summary> */ Role, /** <summary>Child-organization administration and direct-access controls.</summary> */ SubOrganization, /** <summary>Organization member administration and privilege assignment.</summary> */ Member, /** <summary>Organization settings administration.</summary> */ Settings, /** <summary>Security incident contact administration.</summary> */ IncidentContact, /** <summary>Single sign-on configuration and enforcement controls.</summary> */ Sso, /** <summary>SCIM provisioning configuration.</summary> */ Scim,
    /** <summary>GitHub organization synchronization configuration.</summary> */
    GithubOrgSync, /** <summary>Manual GitHub organization synchronization configuration.</summary> */ GithubOrgSyncManual, /** <summary>LDAP directory configuration.</summary> */ Ldap, /** <summary>Organization group and group-member administration.</summary> */ Groups, /** <summary>Organization secret-scanning administration.</summary> */ SecretScanning, /** <summary>Billing inspection and billing-management authority.</summary> */ Billing, /** <summary>Machine-identity administration and authentication credential controls.</summary> */ Identity, /** <summary>Organization key-management administration.</summary> */ Kms,
    /** <summary>Audit log visibility and settings.</summary> */
    AuditLogs, /** <summary>Organization-owned project-template administration.</summary> */ ProjectTemplates, /** <summary>Native application-connection permissions; this SDK exposes no arbitrary connector runtime.</summary> */ AppConnections, /** <summary>Administrative access across organization projects.</summary> */ OrganizationAdminConsole, /** <summary>Organization secret-sharing settings.</summary> */ SecretShare, /** <summary>Organization KMIP proxy authority.</summary> */ Kmip,
    /** <summary>Machine-identity authentication template administration.</summary> */
    MachineIdentityAuthTemplate, /** <summary>Gateway creation, attachment and access revocation.</summary> */ Gateway, /** <summary>Gateway-pool administration and attachment.</summary> */ GatewayPool, /** <summary>Relay administration and access revocation.</summary> */ Relay, /** <summary>KMIP server administration and access revocation.</summary> */ KmipServer, /** <summary>Allowed email-domain registration and verification.</summary> */ EmailDomains,
    /** <summary>Certificate-manager instance and settings administration.</summary> */
    CertificateManager, /** <summary>Organization honey-token setup authority.</summary> */ HoneyTokens, /** <summary>OAuth client administration.</summary> */ OauthClients, /** <summary>Secrets-management insights, reports and value search.</summary> */ SecretsManagementInsights
}

/// <summary>Closed native organization actions; constructors validate applicability to the selected subject.</summary>
public enum OrganizationRoleAction
{
    /** <summary>Reads metadata for the selected organization subject.</summary> */
    Read, /** <summary>Creates a resource within the selected subject.</summary> */ Create, /** <summary>Changes configuration for an existing subject resource.</summary> */ Edit, /** <summary>Deletes an existing subject resource.</summary> */ Delete, /** <summary>Requests access to a project rather than granting direct access.</summary> */ RequestAccess, /** <summary>Selects direct child-organization access authority.</summary> */ DirectAccess, /** <summary>Links a group to a child organization.</summary> */ LinkGroup, /** <summary>Assigns privileges within the selected member, group or identity subject.</summary> */ GrantPrivileges,
    /** <summary>Bypasses native single sign-on enforcement.</summary> */
    BypassSsoEnforcement, /** <summary>Adds machine identities to groups.</summary> */ AddIdentities, /** <summary>Adds users to groups.</summary> */ AddMembers, /** <summary>Removes users from groups.</summary> */ RemoveMembers, /** <summary>Removes machine identities from groups.</summary> */ RemoveIdentities,
    /** <summary>Changes organization billing rather than merely reading billing details.</summary> */
    ManageBilling, /** <summary>Revokes machine-identity authentication configuration.</summary> */ RevokeAuth, /** <summary>Changes machine-identity authentication configuration.</summary> */ EditAuth, /** <summary>Issues machine-identity tokens.</summary> */ CreateToken, /** <summary>Retrieves machine-identity token data under native authority.</summary> */ GetToken, /** <summary>Deletes machine-identity tokens.</summary> */ DeleteToken, /** <summary>Uses a native application connection.</summary> */ Connect,
    /** <summary>Rotates native connection credentials.</summary> */
    RotateCredentials, /** <summary>Accesses projects through the administrative console.</summary> */ AccessAllProjects, /** <summary>Changes organization-level settings for the selected specialized subject.</summary> */ ManageSettings, /** <summary>Uses the native KMIP proxy.</summary> */ Proxy, /** <summary>Lists machine-identity authentication templates.</summary> */ ListTemplates, /** <summary>Changes machine-identity authentication templates.</summary> */ EditTemplates,
    /** <summary>Creates machine-identity authentication templates.</summary> */
    CreateTemplates, /** <summary>Deletes machine-identity authentication templates.</summary> */ DeleteTemplates, /** <summary>Unlinks identities from authentication templates.</summary> */ UnlinkTemplates, /** <summary>Attaches authentication templates to identities.</summary> */ AttachTemplates, /** <summary>Creates gateway configurations.</summary> */ CreateGateways,
    /** <summary>Lists gateway configurations.</summary> */
    ListGateways, /** <summary>Changes gateway configurations.</summary> */ EditGateways, /** <summary>Deletes gateway configurations.</summary> */ DeleteGateways, /** <summary>Attaches gateways to selected resources.</summary> */ AttachGateways, /** <summary>Revokes gateway access.</summary> */ RevokeGatewayAccess,
    /** <summary>Creates gateway pools.</summary> */
    CreateGatewayPools, /** <summary>Lists gateway pools.</summary> */ ListGatewayPools, /** <summary>Changes gateway pools.</summary> */ EditGatewayPools, /** <summary>Deletes gateway pools.</summary> */ DeleteGatewayPools, /** <summary>Attaches gateway pools to selected resources.</summary> */ AttachGatewayPools,
    /** <summary>Creates relay configurations.</summary> */
    CreateRelays, /** <summary>Lists relay configurations.</summary> */ ListRelays, /** <summary>Changes relay configurations.</summary> */ EditRelays, /** <summary>Deletes relay configurations.</summary> */ DeleteRelays, /** <summary>Revokes relay access.</summary> */ RevokeRelayAccess, /** <summary>Creates KMIP server configurations.</summary> */ CreateKmipServers,
    /** <summary>Lists KMIP server configurations.</summary> */
    ListKmipServers, /** <summary>Changes KMIP server configurations.</summary> */ EditKmipServers, /** <summary>Deletes KMIP server configurations.</summary> */ DeleteKmipServers, /** <summary>Revokes KMIP server access.</summary> */ RevokeKmipServerAccess, /** <summary>Verifies ownership of a registered email domain.</summary> */ VerifyDomain,
    /** <summary>Manages the certificate-manager instance.</summary> */
    ManageInstance, /** <summary>Initializes organization honey-token capability.</summary> */ Setup, /** <summary>Generates a secrets-management insights report.</summary> */ GenerateReport, /** <summary>Deletes a secrets-management insights report.</summary> */ DeleteReport, /** <summary>Searches secret values across the native insights scope.</summary> */ SearchAllSecretValues
}

/// <summary>Finite active subjects; deprecated SSH/MCP compatibility branches are not authorable.</summary>
public enum ProjectRoleSubject
{
    /** <summary>Secret metadata and value permissions, whose read actions are distinct.</summary> */
    Secrets, /** <summary>Secret folder administration.</summary> */ SecretFolders, /** <summary>Secret import configuration.</summary> */ SecretImports, /** <summary>Dynamic-secret root credentials and lease issuance.</summary> */ DynamicSecrets, /** <summary>Project machine-identity administration and delegated privileges.</summary> */ Identity, /** <summary>PKI subscriber configuration and certificate issuance.</summary> */ PkiSubscribers,
    /** <summary>Certificate-template configuration and issuance.</summary> */
    CertificateTemplates, /** <summary>Native secret-rotation configuration and generated credentials.</summary> */ SecretRotation, /** <summary>Native secret-sync configuration and transfer controls.</summary> */ SecretSyncs, /** <summary>PKI synchronization configuration and transfer controls.</summary> */ PkiSyncs, /** <summary>Subscriptions to native secret lifecycle events.</summary> */ SecretEventSubscriptions,
    /** <summary>Certificate profile configuration and ACME binding controls.</summary> */
    CertificateProfiles, /** <summary>Certificate policy configuration.</summary> */ CertificatePolicies, /** <summary>Certificate application registration and listing.</summary> */ CertificateApplication, /** <summary>Certificate-authority administration and intermediate signing.</summary> */ CertificateAuthorities,
    /** <summary>Certificate administration and private-key access.</summary> */
    Certificates, /** <summary>Secret approval policy administration.</summary> */ SecretApproval, /** <summary>Secret rollback request administration.</summary> */ SecretRollback, /** <summary>Project user membership and delegated privilege assignment.</summary> */ Member, /** <summary>Project group membership and role assignment.</summary> */ Groups, /** <summary>Project custom-role administration.</summary> */ Role, /** <summary>Retained native project integration configuration.</summary> */ Integrations, /** <summary>Project webhook configuration.</summary> */ Webhooks,
    /** <summary>Project service-token administration.</summary> */
    ServiceTokens, /** <summary>Project settings administration.</summary> */ Settings, /** <summary>Secret validation-rule configuration.</summary> */ SecretValidationRules, /** <summary>Project environment administration.</summary> */ Environments, /** <summary>Secret tag administration.</summary> */ Tags, /** <summary>Project audit-log inspection and settings.</summary> */ AuditLogs, /** <summary>Project insights and report administration.</summary> */ Insights,
    /** <summary>Project network allowlist administration.</summary> */
    IpAllowlist, /** <summary>PKI alert configuration.</summary> */ PkiAlerts, /** <summary>PKI collection administration.</summary> */ PkiCollections, /** <summary>Certificate inventory-view administration.</summary> */ CertificateInventoryViews, /** <summary>PKI discovery configuration and scans.</summary> */ PkiDiscovery,
    /** <summary>Discovered certificate-installation administration.</summary> */
    PkiCertificateInstallations, /** <summary>Code-signer configuration and signing authority.</summary> */ CodeSigners, /** <summary>Native workspace-level project modification and deletion.</summary> */ Workspace, /** <summary>Project KMS configuration changes.</summary> */ Kms, /** <summary>Customer-managed encryption key administration and cryptographic operations.</summary> */ Cmek, /** <summary>KMIP client configuration and client-certificate generation.</summary> */ Kmip, /** <summary>Secret commit inspection and rollback execution.</summary> */ Commits,
    /** <summary>Secret-scanning data sources, scans and resources.</summary> */
    SecretScanningDataSources, /** <summary>Secret-scanning finding inspection and updates.</summary> */ SecretScanningFindings, /** <summary>Secret-scanning configuration inspection and updates.</summary> */ SecretScanningConfigs, /** <summary>Native application-connection administration; not an SDK connector execution surface.</summary> */ AppConnections,
    /** <summary>Hardware security module connector administration.</summary> */
    HsmConnectors, /** <summary>Honey-token configuration, credential access and reset.</summary> */ HoneyTokens, /** <summary>Proxy service configuration, runtime proxy authority and usage reporting.</summary> */ ProxiedServices, /** <summary>Agent Vault access-bundle administration and membership.</summary> */ AgentVaultAccessBundles, /** <summary>Agent Vault session creation and revocation.</summary> */ AgentVaultSessions,
    /** <summary>Agent Vault proxy administration and token issuance.</summary> */
    AgentVaultProxies, /** <summary>Approval request creation and inspection.</summary> */ ApprovalRequests, /** <summary>Approval-request grant inspection and revocation.</summary> */ ApprovalRequestGrants, /** <summary>Secret approval-request inspection.</summary> */ SecretApprovalRequest, /** <summary>Explicit project-folder grant administration.</summary> */ ProjectFolderGrant
}

/// <summary>Closed native project actions; valid combinations depend on the selected subject.</summary>
public enum ProjectRoleAction
{
    /** <summary>Reads the selected subject under its native semantics.</summary> */
    Read, /** <summary>Creates a resource for the selected subject.</summary> */ Create, /** <summary>Changes an existing subject resource.</summary> */ Edit, /** <summary>Deletes an existing subject resource.</summary> */ Delete, /** <summary>Inspects secret metadata without selecting value-read authority.</summary> */ DescribeSecret, /** <summary>Reads secret values separately from metadata description.</summary> */ ReadValue, /** <summary>Reads dynamic-secret root credential configuration.</summary> */ ReadRootCredential, /** <summary>Creates dynamic-secret root credential configuration.</summary> */ CreateRootCredential,
    /** <summary>Changes dynamic-secret root credential configuration.</summary> */
    EditRootCredential, /** <summary>Deletes dynamic-secret root credential configuration.</summary> */ DeleteRootCredential, /** <summary>Issues a dynamic-secret lease.</summary> */ Lease, /** <summary>Delegates privileges to selected members, groups or identities.</summary> */ GrantPrivileges, /** <summary>Assigns a native project role to a principal.</summary> */ AssignRole,
    /** <summary>Assigns additional project privileges.</summary> */
    AssignAdditionalPrivileges, /** <summary>Assumes delegated native privileges.</summary> */ AssumePrivileges, /** <summary>Revokes machine-identity authentication.</summary> */ RevokeAuth, /** <summary>Changes machine-identity authentication.</summary> */ EditAuth, /** <summary>Issues machine-identity tokens.</summary> */ CreateToken, /** <summary>Retrieves machine-identity token data.</summary> */ GetToken,
    /** <summary>Deletes machine-identity tokens.</summary> */
    DeleteToken, /** <summary>Issues certificates through the selected PKI subject.</summary> */ IssueCert, /** <summary>Lists certificates through the selected PKI subject.</summary> */ ListCerts, /** <summary>Retrieves generated rotation credential material.</summary> */ ReadGeneratedCredentials, /** <summary>Triggers native secret rotation.</summary> */ RotateSecrets, /** <summary>Transfers secrets through a native synchronization configuration.</summary> */ SyncSecrets,
    /** <summary>Imports secrets through a native synchronization configuration.</summary> */
    ImportSecrets, /** <summary>Removes synchronized secrets through native authority.</summary> */ RemoveSecrets, /** <summary>Transfers certificates through PKI synchronization.</summary> */ SyncCertificates, /** <summary>Imports certificates through PKI synchronization.</summary> */ ImportCertificates, /** <summary>Removes synchronized certificates through native authority.</summary> */ RemoveCertificates,
    /** <summary>Configures a command to run after native certificate synchronization.</summary> */
    SetPostSyncCommand, /** <summary>Configures a native target health-check command.</summary> */ SetHealthCheckCommand, /** <summary>Configures a native synchronization target host.</summary> */ SetTargetHost, /** <summary>Subscribes to secret creation events.</summary> */ SubscribeToCreationEvents,
    /** <summary>Subscribes to secret update events.</summary> */
    SubscribeToUpdateEvents, /** <summary>Subscribes to secret deletion events.</summary> */ SubscribeToDeletionEvents, /** <summary>Subscribes to secret-import mutation events.</summary> */ SubscribeToImportMutationEvents,
    /** <summary>Reveals the ACME external-account-binding secret.</summary> */
    RevealAcmeEabSecret, /** <summary>Rotates the ACME external-account-binding secret.</summary> */ RotateAcmeEabSecret, /** <summary>Changes certificate profile application attachments.</summary> */ ManageApplicationAttachments, /** <summary>Lists certificate applications without selecting detail-read authority.</summary> */ List,
    /** <summary>Issues a certificate-authority certificate.</summary> */
    IssueCaCertificate, /** <summary>Signs an intermediate certificate authority.</summary> */ SignIntermediate, /** <summary>Retrieves certificate private-key material.</summary> */ ReadPrivateKey, /** <summary>Imports certificate material under native authority.</summary> */ Import, /** <summary>Generates a report for the selected insights subject.</summary> */ GenerateReport, /** <summary>Deletes a report for the selected insights subject.</summary> */ DeleteReport,
    /** <summary>Starts a PKI discovery scan.</summary> */
    RunScan, /** <summary>Performs a signature operation through the selected native subject.</summary> */ Sign, /** <summary>Encrypts using a customer-managed key.</summary> */ Encrypt, /** <summary>Decrypts using a customer-managed key.</summary> */ Decrypt, /** <summary>Verifies a signature using a customer-managed key.</summary> */ Verify, /** <summary>Generates a message authentication code.</summary> */ GenerateMac, /** <summary>Verifies a message authentication code.</summary> */ VerifyMac, /** <summary>Rotates a customer-managed encryption key.</summary> */ Rotate, /** <summary>Exports customer-managed private-key material.</summary> */ ExportPrivateKey,
    /** <summary>Creates KMIP clients.</summary> */
    CreateClients, /** <summary>Changes KMIP clients.</summary> */ UpdateClients, /** <summary>Deletes KMIP clients.</summary> */ DeleteClients, /** <summary>Reads KMIP client configuration.</summary> */ ReadClients, /** <summary>Generates certificates for KMIP clients.</summary> */ GenerateClientCertificates,
    /** <summary>Executes native rollback for a secret commit.</summary> */
    PerformRollback, /** <summary>Reads secret-scanning data sources.</summary> */ ReadDataSources, /** <summary>Creates secret-scanning data sources.</summary> */ CreateDataSources, /** <summary>Changes secret-scanning data sources.</summary> */ EditDataSources, /** <summary>Deletes secret-scanning data sources.</summary> */ DeleteDataSources,
    /** <summary>Starts secret-scanning data-source scans.</summary> */
    TriggerDataSourceScans, /** <summary>Reads secret-scanning scan metadata.</summary> */ ReadDataSourceScans, /** <summary>Reads resources discovered in secret-scanning data sources.</summary> */ ReadDataSourceResources, /** <summary>Reads secret-scanning findings.</summary> */ ReadFindings,
    /** <summary>Changes secret-scanning finding state.</summary> */
    UpdateFindings, /** <summary>Reads secret-scanning configuration.</summary> */ ReadConfigs, /** <summary>Changes secret-scanning configuration.</summary> */ UpdateConfigs, /** <summary>Reads native application-connection configuration.</summary> */ ReadAppConnections, /** <summary>Creates native application connections.</summary> */ CreateAppConnections,
    /** <summary>Changes native application connections.</summary> */
    EditAppConnections, /** <summary>Deletes native application connections.</summary> */ DeleteAppConnections, /** <summary>Uses native application connections.</summary> */ ConnectAppConnections, /** <summary>Rotates native application-connection credentials.</summary> */ RotateCredentials,
    /** <summary>Reads HSM connector configuration.</summary> */
    ReadHsmConnectors, /** <summary>Creates HSM connectors.</summary> */ CreateHsmConnectors, /** <summary>Changes HSM connectors.</summary> */ EditHsmConnectors, /** <summary>Deletes HSM connectors.</summary> */ DeleteHsmConnectors,
    /** <summary>Tests native HSM connector connectivity.</summary> */
    TestHsmConnectors, /** <summary>Attaches HSM connectors to selected resources.</summary> */ AttachHsmConnectors, /** <summary>Retrieves honey-token credential material.</summary> */ ReadCredentials, /** <summary>Resets a honey token.</summary> */ Reset, /** <summary>Revokes honey tokens, Agent Vault sessions or proxies under their subject-specific semantics.</summary> */ Revoke, /** <summary>Uses the configured native proxy service.</summary> */ Proxy, /** <summary>Reports native proxy-service usage.</summary> */ ReportUsage,
    /** <summary>Changes Agent Vault access-bundle membership.</summary> */
    ManageMembers, /** <summary>Issues an Agent Vault proxy token.</summary> */ IssueToken, /** <summary>Reads a project-folder grant.</summary> */ ReadGrant, /** <summary>Creates a project-folder grant.</summary> */ CreateGrant, /** <summary>Revokes a project-folder grant.</summary> */ RevokeGrant
}

/// <summary>Closed native condition keys; each subject restricts admitted keys and operators.</summary>
public enum RoleConditionField
{
    /** <summary>Matches a native application-connection identifier.</summary> */
    ConnectionId, /** <summary>Matches a native environment slug.</summary> */ Environment, /** <summary>Matches a protected secret folder path.</summary> */ SecretPath, /** <summary>Matches a protected secret key name.</summary> */ SecretName, /** <summary>Matches a native secret event discriminator.</summary> */ EventType, /** <summary>Matches a machine-identity identifier.</summary> */ IdentityId, /** <summary>Constrains which native role can be assigned.</summary> */ AssignableRole,
    /** <summary>Constrains which permission subject can be delegated.</summary> */
    AssignableSubject, /** <summary>Constrains which native action can be delegated.</summary> */ AssignableAction, /** <summary>Matches a named PKI resource.</summary> */ Name, /** <summary>Matches a PKI synchronization subscriber name.</summary> */ SubscriberName, /** <summary>Matches a certificate-profile slug.</summary> */ Slug, /** <summary>Matches a certificate common name.</summary> */ CommonName, /** <summary>Matches certificate alternative names.</summary> */ AltNames,
    /** <summary>Matches a certificate serial number.</summary> */
    SerialNumber, /** <summary>Matches a certificate friendly name.</summary> */ FriendlyName, /** <summary>Matches native certificate status.</summary> */ Status, /** <summary>Matches a project member email selector.</summary> */ UserEmail, /** <summary>Matches a project group name.</summary> */ GroupName
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

    /// <summary>Selects a literal string rather than an operator object; an empty literal is explicit.</summary>
    public static RoleStringClause Literal(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new(value, null, null, null, null);
    }

    /// <summary>Copies explicit comparison operands; subject validation later restricts unsupported operators.</summary>
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

    /// <summary>Returns a marker without condition operands.</summary>
    public override string ToString() => "[RoleStringClause]";
}

/// <summary>One typed native condition field and bounded string clause, not arbitrary policy JSON.</summary>
public sealed class RoleCondition
{
    /// <summary>Binds a known condition key to an explicit clause; applicability is checked by the permission constructor.</summary>
    public RoleCondition(RoleConditionField field, RoleStringClause clause)
    {
        if (!Enum.IsDefined(field)) throw new ArgumentOutOfRangeException(nameof(field));
        ArgumentNullException.ThrowIfNull(clause);
        Field = field;
        Clause = clause;
    }
    /// <summary>Gets the native condition key.</summary>
    [JsonIgnore] public RoleConditionField Field { get; }
    /// <summary>Gets the protected literal or comparison clause.</summary>
    [JsonIgnore] public RoleStringClause Clause { get; }
    /// <summary>Returns a marker without condition contents.</summary>
    public override string ToString() => "[RoleCondition]";
}

/// <summary>Native secret-tag predicates with independently optional inclusion and all-tag arrays.</summary>
public sealed class RoleSecretTags
{
    private readonly string[]? _included;
    private readonly string[]? _all;
    /// <summary>Copies bounded tag arrays; null omits each operator and an empty array remains explicit.</summary>
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
    /// <summary>Returns a marker without tag selectors.</summary>
    public override string ToString() => "[RoleSecretTags]";
}

/// <summary>Conjunctive key/value comparisons on one metadata entry, not independent entries.</summary>
public sealed class RoleMetadataMatch
{
    private readonly RoleStringClause? _key;
    private readonly RoleStringClause? _value;
    internal bool HasNotEqual => (_key?.HasNotEqual ?? false) || (_value?.HasNotEqual ?? false);

    /// <summary>Captures key/value comparisons on one metadata entry; literal and glob clauses are not admitted.</summary>
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
    /// <summary>Returns a marker without metadata operands.</summary>
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

    /// <summary>Captures a scalar native organization action with optional inversion and copied conditions.</summary>
    public OrganizationRolePermission(OrganizationRoleSubject subject, OrganizationRoleAction action,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null)
        : this(subject, [action], inverted, conditions) => _scalar = true;

    /// <summary>Copies validated organization actions; only application connections admit inversion and connection conditions.</summary>
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
    /// <summary>Returns a marker without permission conditions.</summary>
    public override string ToString() => "[OrganizationRolePermission]";
}

/// <summary>Immutable native project permission input; construction validates dialect, not effective provider authorization.</summary>
public sealed class ProjectRolePermission
{
    private readonly string _subject;
    private readonly string[] _actions;
    private readonly bool _scalar;
    private readonly bool? _inverted;
    private readonly RoleCondition[]? _conditions;
    private readonly RoleSecretTags? _tags;
    private readonly RoleMetadataMatch? _metadata;

    /// <summary>Captures a scalar action preserving its native shape and validating subject-specific constraints.</summary>
    public ProjectRolePermission(ProjectRoleSubject subject, ProjectRoleAction action,
        bool? inverted = null, IReadOnlyList<RoleCondition>? conditions = null, RoleSecretTags? secretTags = null,
        RoleMetadataMatch? metadata = null)
        : this(subject, [action], inverted, conditions, secretTags, metadata) => _scalar = true;

    /// <summary>Copies nonempty action selections and conditions; tags and metadata are admitted only for their native subjects.</summary>
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
    /// <summary>Returns a marker without project permission conditions.</summary>
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

    /// <summary>Gets whether the returned native selection was a scalar rather than an array.</summary>
    public bool IsScalar { get; }
    /// <summary>Gets returned scalar or array values; array shape and empty entries are preserved.</summary>
    [JsonIgnore] public IReadOnlyList<string> Values { get; }
    /// <summary>Returns a marker without permission selection values.</summary>
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

    /// <summary>Gets returned native action metadata without interpreting it as an access decision.</summary>
    [JsonIgnore] public RolePermissionSelection Action { get; }
    /// <summary>Gets returned subject metadata, or null when omitted.</summary>
    [JsonIgnore] public RolePermissionSelection? Subject { get; }
    /// <summary>Gets returned inversion, or null when absent rather than inferring false.</summary>
    [JsonIgnore] public bool? Inverted { get; }
    /// <summary>Gets whether a conditions node was returned; no condition values are interpreted.</summary>
    public bool HasConditions { get; }
    /// <summary>Always false: unconstrained returned condition values are deliberately not exported.</summary>
    public bool IncludesConditionValues => false;
    /// <summary>Returns a marker without permission metadata.</summary>
    public override string ToString() => "[RolePermissionSummary]";
}
