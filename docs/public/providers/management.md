# Provider administration and audit

> **Audience:** Administrators, .NET developers, and AI coding assistants
> **Status:** Retained implemented subsets; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; not a native qualification run
> **Source anchors:** [Infisical management](../../../src/SecretKit.Infisical.Management/), [Azure management](../../../src/SecretKit.AzureKeyVault.Management/), focused evidence below

Management packages are optional. They do not grant administration rights,
select an application's runtime identity, or prove that runtime reads work.
Select administrative and monitoring credentials explicitly; retain mutation
receipts before dispatch. Runtime lifecycle remains native:
[Infisical](infisical.md) and [Azure secret data plane](azure-key-vault.md).

## Infisical administration

All types in this section are in `SecretKit.Infisical.Management`.
`ManagementTransport(origin, maximumResponseBytes: 1024 * 1024, proxy: null,
allowLoopbackDevelopmentHttp: false)` owns a fixed-origin HTTP wrapper.
The host disposes the transport; `ManagementClient(transport, timeProvider: null)`
does not dispose it. HTTPS is required except explicit loopback development HTTP.
Body construction is bounded to 64 KiB; transport response budgets permit
1 KiB..16 MiB. Pass a cancellation deadline; there is no implicit HTTP timeout.

Named static factories construct disposable `ManagementRequest<T>` objects;
there is no public arbitrary HTTP/JSON executor.

1. Select `ManagementAuthority(client.Authority, administrativeTokens,
   organizationId, projectId: null)`. Null project means exact organization
   scope, not a wildcard for every project.
2. Construct the request through the appropriate factory below.
3. In trusted host code, call `authority.IssueGrant(request.OperationId,
   independentTarget)`. Build the target from independently approved inputs or
   that family's target helper, not by copying an untrusted request's `Target`.
4. For mutations, retain `client.CreateReceipt(request)` before awaiting.
5. Call `client.ExecuteAsync(request, authority, grant, receipt,
   cancellationToken)`; omit receipt for reads. Dispose the request and any
   disposable result.

Client, authority issuer, operation and exact target must match before token
acquisition. Grants assert local trusted intent, not provider membership or
effective permission. Some targets encode query/body choices as well as IDs;
use the factory's matching target helper instead of reducing them to a resource
ID. Implicit-scope server responses are not token-to-organization attestation.
For `ListOrganizationIdentityMemberships`, independently approve the organization,
offset, limit, search (including omission versus empty), order column and direction
through `OrganizationIdentityMembershipListTarget`. A coordinate-only grant or
any changed selector is rejected before token acquisition; this binds local intent,
not the remote token's principal or permissions.
Sources: [authorization](../../../src/SecretKit.Infisical.Management/ManagementAuthorization.cs),
[request ownership](../../../src/SecretKit.Infisical.Management/ManagementContracts.cs),
[executor](../../../src/SecretKit.Infisical.Management/ManagementClient.cs).

### Example: an explicitly authorized group creation

This integration function accepts already approved organization/name/slug and
the explicitly selected organization-scoped authority. The caller owns
`client`, `authority` and token source. It retains the receipt before invoking
this function so cancellation cannot hide dispatch evidence.

```csharp
using System.Threading;
using System.Threading.Tasks;
using SecretKit.Core;
using SecretKit.Infisical.Management;

static ValueTask<SecretOutcome<GroupMetadata>> ExecuteGroupCreationAsync(
    ManagementClient client, ManagementAuthority authority,
    ManagementRequest<GroupMetadata> request, ManagementReceipt receipt,
    string approvedOrganization, string approvedName, string approvedSlug,
    CancellationToken deadline)
{
    var target = ScopedAccessOperations.GroupCreationTarget(
        approvedOrganization, approvedName, approvedSlug);
    var grant = authority.IssueGrant(request.OperationId, target);
    return client.ExecuteAsync(request, authority, grant, receipt, deadline);
}
```

At the trusted call site, construct `request` with
`ScopedAccessOperations.CreateGroup(approvedOrganization, approvedName,
approvedSlug)` and `receipt` with `client.CreateReceipt(request)`; keep the
request alive until the await completes, then dispose it. Approved inputs must
come from host policy, not be echoed from an untrusted request.

### Retained factory owner map

Methods here construct requests; `ManagementClient.ExecuteAsync` sends them.
The linked source defines exact optional input and protected result variants.
This map includes retained families beyond the basic operation-coverage registry.

| Family | Factory owner / real methods | Constraints and meaning |
| --- | --- | --- |
| Projects, environments, tags, role inventory | [ProjectOperations](../../../src/SecretKit.Infisical.Management/Projects.cs): `ListProjects`, `GetProject`, `GetProjectBySlug`, `CreateProject`, `UpdateProject`, `DeleteProject`; environment create/get/by-slug/update/delete/restore; tag list/get/by-slug/create/update/delete; `ListProjectRoles` | Explicit organization/project/selector; typed project field variants, not arbitrary settings. Native environment/tag runtime counterparts also exist. |
| Project templates | [ProjectTemplateOperations](../../../src/SecretKit.Infisical.Management/ProjectTemplates.cs): `ListProjectTemplates`, `GetProjectTemplate`, `CreateProjectTemplate`, `UpdateProjectTemplate`, `DeleteProjectTemplate` | [Typed configuration](../../../src/SecretKit.Infisical.Management/ProjectTemplateVariants.cs) for roles, conditions, environments and principals; omission is not arbitrary JSON. |
| Identity CRUD and organization metadata | [IdentityOperations](../../../src/SecretKit.Infisical.Management/Identities.cs): organization/project identity list/get/create/update/delete; `GetSelectedIdentityOrganization` | Organization metadata does not bind a supplied bearer token to a principal. |
| Identity discovery | [IdentitySearchOperations](../../../src/SecretKit.Infisical.Management/IdentitySearch.cs): `SearchIdentities`, `CountIdentities` | Typed filters/order/scope; query choices participate in intent targets. |
| Identity templates | [IdentityTemplateOperations](../../../src/SecretKit.Infisical.Management/IdentityTemplates.cs): list/search/get/create/update/delete, usage get/delete; [variant factories](../../../src/SecretKit.Infisical.Management/IdentityTemplateVariants.cs): `CreateLdapIdentityTemplate`, `CreateKubernetesIdentityTemplate`, `UpdateIdentityTemplateConfiguration`, `DeleteIdentityTemplateUsages` | OIDC, LDAP and Kubernetes typed subsets; configuration is not a login proof or deployment witness. |
| Universal/Token Auth administration | [IdentityAuthenticationOperations](../../../src/SecretKit.Infisical.Management/IdentityAuthentication.cs): attach/update/get/delete auth configuration; Universal client-secret create/list/get/revoke and lockout clear; Token Auth `CreateToken`, `ListTokens`, `GetToken`, `RenameToken`, `RevokeToken` | Dispose returned credential creations. Configuration/metadata is separate from runtime login, lifetime evidence and fresh-read revocation checks. |
| Cloud authentication configuration | [CloudIdentityAuthenticationOperations](../../../src/SecretKit.Infisical.Management/CloudIdentityAuthentication.cs): `AttachAwsAuth`, `UpdateAwsAuth`, `GetAwsAuth`, `DeleteAwsAuth` and corresponding Azure/GCP/AliCloud methods | Host-selected configuration only; no cloud credential acquisition. |
| Workload authentication configuration | [WorkloadIdentityAuthenticationOperations](../../../src/SecretKit.Infisical.Management/WorkloadIdentityAuthentication.cs): attach/update/get/delete JWT, OIDC and Kubernetes auth | Typed settings; no token discovery, signing or inferred principal. |
| External authentication configuration | [ExternalIdentityAuthenticationOperations](../../../src/SecretKit.Infisical.Management/ExternalIdentityAuthentication.cs): attach/update/get/delete LDAP, OCI, SPIFFE and TLS-certificate auth; `ClearLdapAuthLockouts`, `RefreshSpiffeBundle` | Dispose protected input/results where declared; issuer and certificate acceptance require native evidence. |
| Groups, candidates, organization roles | [ScopedAccessOperations](../../../src/SecretKit.Infisical.Management/ScopedAccess.cs): group CRUD; group member/project/identity/user lists; add/remove identity/user; `AvailableGroups`, `AvailableIdentities`; organization role list/get/by-slug/delete | Explicit selectors and independent target helpers; visibility is not effective access. |
| Memberships and role assignment | [MembershipOperations](../../../src/SecretKit.Infisical.Management/Memberships.cs): project identity/group and organization group operations; [ProjectMembershipOperations](../../../src/SecretKit.Infisical.Management/ProjectMemberships.cs): list, role update, username inspect, candidate/identity membership lists | Preserve typed permanent/temporary role variants and exact principal selection. |
| Organization user/identity memberships | [OrganizationMembershipOperations](../../../src/SecretKit.Infisical.Management/OrganizationMemberships.cs): list/update/delete; [OrganizationIdentityMembershipOperations](../../../src/SecretKit.Infisical.Management/OrganizationIdentityMemberships.cs): `ListOrganizationIdentityMemberships` | Returned metadata is protected; organization and project scopes are distinct. |
| Bulk membership mutations | [MembershipMutationOperations](../../../src/SecretKit.Infisical.Management/MembershipMutations.cs): `InviteProjectMembers`, `RemoveProjectMembers`, `DeleteOrganizationMemberships` | Typed principal batches and intent targets, not a general bulk executor. |
| Role writes | [RoleChangeOperations](../../../src/SecretKit.Infisical.Management/RoleChanges.cs): organization/project create/update role | Typed [permission changes](../../../src/SecretKit.Infisical.Management/RolePermissions.cs), not a grant to the executing identity. |
| Project role reads/deletion | [ProjectOperations](../../../src/SecretKit.Infisical.Management/Projects.cs): `ListProjectRoles`, `GetProjectRole`, `GetProjectRoleBySlug`, `DeleteProjectRole` | Explicit project/role selector; distinct from organization role factories and role create/update. |
| Identity privileges | [IdentityPrivilegeOperations](../../../src/SecretKit.Infisical.Management/IdentityPrivileges.cs): project list/get/delete; [IdentityPrivilegeChangeOperations](../../../src/SecretKit.Infisical.Management/IdentityPrivilegeChanges.cs): project create/update/by-slug and permanent/temporary legacy writes; [LegacyIdentityPrivilegeOperations](../../../src/SecretKit.Infisical.Management/LegacyIdentityPrivileges.cs): legacy list/get/delete | Distinct native contracts and typed lifetimes; no compatibility facade. |
| Audit settings and audit rows | [GovernanceOperations](../../../src/SecretKit.Infisical.Management/Governance.cs): `GetOrganizationAuditSettings`, `SetOrganizationAuditSettings`, project equivalents, `ReadAudit` | Exact class settings, typed selectors, bounded window/page. Inspect each `AuditRow` outcome; GET settings alone is not evidence that operations were logged or an identity has effective rights. |
| Sharing | [SharingOperations](../../../src/SecretKit.Infisical.Management/Governance.cs): `ListShares`, `GetShare`, `CreateShare`, `DeleteShare`, `AccessShare` | Dispose created-share/material results. Access can have native effects and is not an ordinary Core read. |
| Project connection metadata | [ProjectConnectionOperations](../../../src/SecretKit.Infisical.Management/ProjectConnections.cs): `ListAuthorizations`, `ListIntegrations` | Retained metadata only; not the removed third-party connection/sync catalog or destination-access proof. |
| PostgreSQL rotation configuration | [PostgresSecretRotationOperations](../../../src/SecretKit.Infisical.Management/PostgresSecretRotations.cs): `List`, `Get`, `GetByName`, `Create`, `Update`, `Delete`, `Move`, `CheckCredentials`, `GetGeneratedCredentials`, `ListPostgresSubset`, `PostgresOptionsSubset` | Native `postgres-credentials` API; explicit existing connection, protected parameters and disposable generated results. |
| MySQL rotation configuration | [MySqlSecretRotationOperations](../../../src/SecretKit.Infisical.Management/MySqlSecretRotations.cs): corresponding CRUD/move/check/generated methods, `ListMySqlSubset`, `MySqlOptionsSubset` | Native MySQL API support, not MariaDB qualification or a shipped database driver. |
| SQL Server rotation configuration | [MsSqlSecretRotationOperations](../../../src/SecretKit.Infisical.Management/MsSqlSecretRotations.cs): corresponding CRUD/move/check/generated methods, `ListMsSqlSubset`, `MsSqlOptionsSubset` | Native `mssql-credentials` API; no ODBC/SQL client implementation. |
| Gateway administration | [GatewayAdministrationOperations](../../../src/SecretKit.Infisical.Management/GatewayAdministration.cs): `Create`, `Get`, `Update`, `GenerateEnrollmentToken` | Dispose enrollment tokens; metadata does not prove agent deployment or connectivity. |
| Proxied services | [ProxiedServiceAdministrationOperations](../../../src/SecretKit.Infisical.Management/ProxiedServiceAdministration.cs): `List`, `Create`, `Get`, `GetByName`, `Update`, `Delete` | Existing typed gateway/proxy subset, not arbitrary service execution. |

SQL credential checks are effectful requests requiring management receipts.
Their selected native empty 204 acknowledgement is supported; an empty response
does not authorize success for unrelated operations. Delete flags preserve
omitted/false/true distinctions. Configuration deletion or credential metadata
does not independently prove SQL revocation or consumer convergence. Trigger,
automatic enablement and progress remain on `InfisicalRotationClient`, with
different receipts.

### Results and evidence

`ManagementPage<T>` exposes `Items`, `IsComplete`, `NextOffset`; inspect them
instead of treating a bounded page as complete inventory. A mutation receipt
belongs to one immutable request and client. Pre-dispatch rejection/cancellation
leaves `NotDispatched`; uncertainty after dispatch remains `PossiblyDispatched`.
`Applied` means a validated native success projection, not downstream delivery.
There is no automatic replay or rollback.

Cancellation is rechecked after asynchronous completion and before failure
returns, including an unsuccessful token acquisition. A validated response keeps
its known receipt even when cancellation prevents returning the result; owned
material that cannot be returned is disposed. Cancellation does not undo a remote
effect.

Counted pages reject contradictions between the returned item count, selected
offset/limit and response total. An empty page at or beyond the total is complete;
a short page before the reported end is not consistent success. Counts describe
one response, not a stable snapshot across successive requests.

Start with [ManagementBoundaryTests](../../../tests/SecretKit.Infisical.Management.Tests/ManagementBoundaryTests.cs)
for exact grants, scope and retired-route rejection,
[PostgresSecretRotationTests](../../../tests/SecretKit.Infisical.Management.Tests/PostgresSecretRotationTests.cs)
for SQL configuration/check boundaries, and the
[family test directory](../../../tests/SecretKit.Infisical.Management.Tests/)
for auth, memberships, governance and gateway variants. Event-stream
payload/lifetime/resume contracts, omitted native variants, entitlements and
downstream effects remain gaps. Broad third-party app-connection/sync
administration is outside current scope.

## Azure administration

Types here belong to `SecretKit.AzureKeyVault.Management`, not the data-plane
namespace. Construct
`VaultAdministration(administrativeCredential, transport,
maximumResponseBytes: 1024 * 1024, timeout: null, timeProvider: null)`.
The credential and `HttpPipelineTransport` remain host-owned. The default
operation deadline is 30 seconds; explicit deadlines must be positive and at
most two minutes. Response budgets permit 1 KiB..16 MiB.

Typed scopes form explicit coordinates:
`SubscriptionScope(Guid)` -> `ResourceGroupScope(subscription, name)` ->
`VaultScope(group, name)`. Deleted vault, private connection, role assignment,
role definition and notification operations use their dedicated scopes.
`VaultScope.ExportResourceId()` is an explicit plaintext export.

| Family / source owner | `VaultAdministration` methods | Implemented boundary |
| --- | --- | --- |
| [Vault lifecycle](../../../src/SecretKit.AzureKeyVault.Management/VaultAdministration.cs) | `CreateOrUpdateVaultAsync`, `RecoverVaultAsync`, `UpdateSettingsAsync`, `GetVaultAsync`, `DeleteVaultAsync`, `GetDeletedVaultAsync`, `PurgeDeletedVaultAsync`, `ListVaultsAsync` (group/subscription), `ListDeletedVaultsAsync`, `CheckNameAvailabilityAsync` | Selected settings/SKU/tenant/network/retention; name check does not reserve. Updates do not expose all ARM fields or CAS. |
| Access policies, same owner | `ChangeAccessPoliciesAsync` | Add/replace/remove, at most 16 policies, eight secret permissions; explicit tenant/principal/application, no directory lookup. |
| Private connectivity metadata, same owner | `GetPrivateConnectionAsync`, `ListPrivateConnectionsAsync`, `UpdatePrivateConnectionAsync`, `DeletePrivateConnectionAsync`, `ListPrivateLinkResourcesAsync` | Approve/reject existing connection; no private-endpoint provisioning. |
| [RBAC](../../../src/SecretKit.AzureKeyVault.Management/RoleAdministration.cs) | `CreateRoleAssignmentAsync`, `GetRoleAssignmentAsync`, `DeleteRoleAssignmentAsync`, `ListRoleAssignmentsAsync`, `GetRoleDefinitionAsync`, `ListRoleDefinitionsAsync` | Vault-scoped writes, explicit same-subscription definition and principal; selected ancestor metadata is read-only. No custom-role writes or effective-permission proof. |
| [Notifications](../../../src/SecretKit.AzureKeyVault.Management/NotificationAdministration.cs) | `CreateOrUpdateNotificationAsync`, `UpdateNotificationAsync`, `DeleteNotificationAsync`, `GetNotificationAsync`, `ListNotificationsAsync`, `GetNotificationFullUrlAsync`, `GetNotificationDeliveryAttributesAsync` | Named vault-scoped Event Grid subscriptions; HTTPS webhook, three secret event kinds, at most ten static/dynamic delivery headers. No arbitrary destination catalog or delivery proof. |

Only public-cloud administration/monitoring endpoints are selected:
`management.azure.com` (Key Vault `2026-02-01`, Authorization `2022-04-01`,
Event Grid `2025-02-15`) and `api.loganalytics.io` (Logs v1).
This differs from runtime vault hostname acceptance. No arbitrary ARM resource
ID, endpoint, SDK model, JSON executor or directory administration is exposed.

Call `PrepareReceipt(scope, ManagementMutation.<operation>)` before each mutation.
Use that exact scope instance and client; Azure's management receipt is unrelated
to Infisical's same-named type. Dispatch evidence begins at the authenticated SDK
send boundary, not credential acquisition or unauthenticated challenge.
`ManagementOperation.CheckStatusAsync(cancellationToken)` performs an explicit
bounded SDK update; there is no background poller. Handles and receipts are
in-memory, not a restart journal. Status observations do not rewrite historical
start receipts or prove runtime delivery.

Notification create/update uses `WaitUntil.Started`: even a start response saying
`Succeeded` begins pending until an explicit status check. Delete 200/204 is
terminal; 202 remains pending. Status URLs must match the selected origin,
resource path and revision. Notification DELETE also accepts a bounded subset of
originally issued regional Event Grid `operationResults` and `operationStatus`
URLs at `2025-02-15`, in the selected subscription/resource group. Other status
URL forms remain unsupported. This exception does not broaden PUT/PATCH or
authorize arbitrary ARM requests; see
[controlled transport validation](../../../src/SecretKit.AzureKeyVault.Management/ControlledTransport.cs).
Update replaces the selected destination/event filter; advanced filters,
dead-letter/retry settings, managed identity and other destination kinds are not
exposed. Dispose `NotificationConfiguration`, `NotificationFullUrl` and each
returned delivery-attribute row; URLs/header fields are protected material.

Collections use `CollectionLimits(maximumPages: 4, maximumItems: 100,
timeout: null)` and expose `Items`, `Complete`, `Status`. Partial rows are not
complete success. If the SDK loses a native vault-list continuation, the adapter
returns incomplete `Unsupported` rather than inventing manual pagination.

Evidence: [ScopeAuthorityTests](../../../tests/SecretKit.AzureKeyVault.Management.Tests/ScopeAuthorityTests.cs),
[RoleAdministrationTests](../../../tests/SecretKit.AzureKeyVault.Management.Tests/RoleAdministrationTests.cs),
[NotificationAdministrationTests](../../../tests/SecretKit.AzureKeyVault.Management.Tests/NotificationAdministrationTests.cs).
Remote provisioning, inherited access effects, private connectivity and actual
notification delivery remain unverified.

## Azure audit

Construct `AuditDiagnostics(monitoringCredential, transport,
maximumResponseBytes: 1024 * 1024, timeProvider: null)` separately. An
administrative credential does not prove Log Analytics query rights or that a
vault emits audit records.

`QueryAsync(new AuditQuery(vault, start, end, maximumRows: 100, timeout: null,
workspaceId: null), cancellationToken)` executes one canonical POST for a fixed
`AzureDiagnostics`/`AuditEvent` query restricted to that vault. Supply a workspace
GUID for workspace querying; omit it for resource querying. Windows are
start-inclusive/end-exclusive, at most one day; rows are 1..1,000; query timeout
defaults to 30 seconds and permits 1 second..2 minutes.

Results expose a narrow timestamp/finite operation/finite result projection.
Inspect `Complete` and `Error` as well as `Status`; a partial error can retain
useful rows with success status but incomplete coverage. Returned vault/category
are checked. No raw KQL, arbitrary columns, cross-resource query or inferred
cursor is exposed.

`QueryBatchAsync(queries, progress, timeout, cancellationToken)` is local
sequential execution, not deprecated native `/$batch`. Supply 1..16 queries,
matching single-use `AuditBatchProgress(count)`, and a total timeout of
1 second..2 minutes. Progress retains completed indexes on caller cancellation;
unfinished indexes remain null.
SDK logging/tracing/retries are disabled; host instrumentation remains separate.
Diagnostic-settings CRUD and categories are excluded, not callable features.
Missing logs do not establish absence of an operation, and
`RuntimeDeliveryProven` remains false.

Source: [AuditDiagnostics](../../../src/SecretKit.AzureKeyVault.Management/AuditDiagnostics.cs).
Evidence: [AuditPartialResultTests](../../../tests/SecretKit.AzureKeyVault.Management.Tests/AuditPartialResultTests.cs).
See [operations](../operations-and-compatibility.md) and
[current support](../provider-support.md) for the remaining native/platform gates.
