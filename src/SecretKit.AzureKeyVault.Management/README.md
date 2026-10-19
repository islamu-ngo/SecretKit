# SecretKit.AzureKeyVault.Management

[Current support](../../docs/public/provider-support.md) distinguishes these
offline-tested subsets from unverified remote effects and release admission.

Optional, offline-tested administration and audit adapters. Depends inward on
Core plus the approved `Azure.ResourceManager.KeyVault` 1.4.0 and
`Azure.Monitor.Query` 1.7.1, `Azure.ResourceManager.Authorization` 1.1.7 and
`Azure.ResourceManager.EventGrid` 1.1.0. Root solution registration and isolated
installed-package integration are verified for this implemented subset.

## Authority and ownership

Construct `VaultAdministration` with an explicit administrative `TokenCredential`
and host-owned `HttpPipelineTransport`. Construct `AuditDiagnostics` separately
with an explicit monitoring credential and transport. Neither can read secret
content or infer an application's runtime identity. ARM results, access policies,
name availability and monitoring visibility never prove runtime delivery.

Only Azure public cloud is supported by this package: `management.azure.com`,
Key Vault ARM `2026-02-01`, scoped Authorization ARM `2022-04-01`; `api.loganalytics.io`, Logs v1 with the official
public-cloud audience. No caller-selectable endpoint, arbitrary resource ID,
directory client, raw SDK model, JSON body or KQL executor is exposed. Sovereign
clouds and live service behavior remain unverified.
The selected Logs SDK emits the public audience scope
`https://api.loganalytics.io//.default` (including its native double slash);
offline tests record this exact SDK behavior rather than assert live token acceptance.

SDK retry count is zero. SDK logging, content logging and distributed tracing
are disabled. The caller owns credential/transport instrumentation and must
configure its transport not to redirect or instrument sensitive payloads. The
adapter validates outer SDK requests, not internals of a host-supplied transport.
No host credential or transport is disposed. SDK wire serialization necessarily
creates plaintext request strings.

Scopes are constructed from typed subscription, group, vault, deleted-vault and
connection coordinates. Identifiers are ignored by default JSON serialization
and formatting. `VaultScope.ExportResourceId()` is an explicit plaintext export.
SDK exceptions, provider error bodies, diagnostics, destination URLs and arbitrary
audit columns are never returned. Collections and audit events are also excluded
from default serialization; explicitly inspected native projections are sensitive.

## Admitted-family inventory

`OperationSupport.Inventory` covers all **34** admitted management families.
Its status numbers describe successful native responses, not measured live
conformance. All rows keep permission checked and live verified false.

| Registry families | Implementation and accepted successful HTTP statuses |
| --- | --- |
| `vault.CreateOrUpdate`, `vault.Recover` | Official SDK `WaitUntil.Started`; 200/201. Explicit selected Standard/Premium SKU, tenant, location, RBAC, purge protection, retention, public network and secret-only policies. Recovery sends `createMode=recover`. No CAS or create-only promise. |
| `vault.Update` | SDK patch; 200/201. Only explicit RBAC, enable-purge-protection and public-network changes. Null means omitted. Other settings, tags, firewall/subnet rules and deployment flags are not exposed. |
| `vault.Get` | SDK selected-vault read; 200. Protected scope, finite provisioning state and selected settings, not a full raw metadata export. |
| `vault.Delete` | SDK start; 200/204. Not per-secret deletion. |
| `vault.GetDeleted` | SDK selected deleted-vault read; 200. Deletion, scheduled purge and purge-protection metadata. |
| `vault.PurgeDeleted` | SDK start; 200/202. Remote retention/purge protection remains authoritative. |
| `vault.ListByResourceGroup`, `vault.ListBySubscription`, `vault.ListDeleted` | Vault-specific SDK inventories; 200. Bounded pages/items/time, partial rows with explicit completeness and error status. Not generic resource lists. |
| `vault.CheckNameAvailability` | SDK canonical POST; 200. Does not reserve a name. |
| `accessPolicy.add`, `accessPolicy.replace`, `accessPolicy.remove` | SDK native policy operation; 200/201. Explicit tenant/principal/application and only the eight admitted secret permissions; at most 16 selected policies. No directory lookup or inferred principal. |
| `privateConnection.Get`, `privateConnection.List` | SDK selected-vault connection metadata; 200; single GET also accepts 204 as absent. |
| `privateConnection.Update` | SDK start; 200. Approve/reject an existing connection only; no private endpoint provisioning or arbitrary descriptive text. |
| `privateConnection.Delete` | SDK start; 200/202/204. |
| `privateLink.List` | SDK selected-vault private-link metadata; 200. No endpoint provisioning. |
| `roleAssignment.Create`, `.Get`, `.Delete`, `.List`; `roleDefinition.Get`, `.List` | Official Authorization SDK, bounded native subset at 2022-04-01. Assignment mutations require explicit vault/assignment coordinates; metadata reads also represent selected subscription/group ancestors. Definition reads require explicit subscription/definition coordinates. Create/update selects a principal and same-subscription definition, without CAS or effective-permission proof. Metadata, permissions and conditions are protected projections. Native `atScope()` lists include the selected vault, its group and its subscription; other coordinates are rejected. Inherited observations cannot obtain mutation receipts or change ancestor assignments. Create accepts 200/201, delete 200/204, reads 200. |
| `audit.QueryWorkspace`, `audit.QueryResource` | SDK canonical POST; 200, including explicit partial errors. Fixed AzureDiagnostics/AuditEvent query for exactly one validated vault. Narrow timestamp/finite operation/finite result projection; returned resource and category verified. |
| `notification.CreateOrUpdate`, `.Update`, `.Delete`, `.Get`, `.List`, `.GetFullUrl`, `.GetDeliveryAttributes` | Official `Azure.ResourceManager.EventGrid` 1.1.0 SDK, stable 2025-02-15. Only selected `VaultScope` and named `NotificationScope`; no subscription/group-wide discovery. Create/update accept 201; delete 200/202/204; reads 200. Full URL and delivery attributes use canonical POST reads. Handwritten inputs cover only HTTPS webhook destinations, the three Key Vault secret events, and at most ten static/dynamic headers. No complete destination/public-API coverage claim. |

Notification create/update use `WaitUntil.Started` and return the native SDK status
handle. A 201 with `provisioningState=Succeeded` still starts pending in this SDK;
only an explicit bounded `CheckStatusAsync` advances the handle. DELETE 200/204
are terminal native responses; 202 remains pending. Receipts retain historical
start evidence, not runtime delivery or effective-permission proof.
Notification status headers admit only the exact selected resource path, origin
and revision. Other Event Grid operation-status URL shapes remain unsupported,
retaining possible-dispatch uncertainty rather than following arbitrary ARM URLs.

`NotificationConfiguration` replaces destination and included-event filter on
update; it omits labels, expiry, retry/dead-letter settings, managed identity,
advanced filters, subject filters, batching, TLS/AAD settings and non-webhook
destinations. Native PATCH serializes its selected properties directly, whereas
PUT wraps them in `properties`. Metadata observations validate returned ID, name
and vault topic, and project finite provisioning/destination kinds only.
Full-URL and delivery-attribute POST responses contain no returned resource
coordinates: their independently controlled authenticated request binds them
to the selected subscription; no response coordinate is invented.

Endpoint URLs and static values/dynamic source fields are owned `SecretMaterial`
with `JsonIgnore` and safe formatting. Configuration copies caller attributes;
dispose configuration, `NotificationFullUrl`, and each returned delivery-attribute
row. Explicit `Reveal` creates ordinary plaintext strings; SDK URI/serialization
strings cannot be cleared by these owners. Page/item/deadline/byte budgets apply
to notification collections; unsupported mapping types fail closed.

The SDK resource-group list seam discarded the fixture's native `nextLink`.
The transport independently observes and validates continuation metadata. If a
wire continuation exists but the SDK exposes none, returned rows are explicitly
incomplete with `Status=Unsupported`; no manual raw request fills that gap.
Where the SDK supplies page metadata, page/item/time budgets apply normally.

Current named diagnostic settings CRUD and diagnostic categories are **excluded**
by the registry because their service revision is `2021-05-01-preview`; the stable
legacy service route has unestablished Key Vault applicability. None is callable.
Custom-role writes, directory/subscription administration, ARM secret resources,
keys/certificates/HSM, deprecated native query batch and GET query aliases remain
excluded. The local `QueryBatchAsync` is bounded canonical single-query execution,
not the excluded native `/$batch`.

## Receipts and bounded execution

Call `PrepareReceipt(scope, operation)` before a mutation. A receipt is bound to
the client, exact scope instance and native operation, and consumed once. Its
`BeginDispatch` runs at the controlled, authenticated SDK transport send boundary,
not client construction or credential acquisition. Unauthenticated challenges do
not advance evidence. Pre-send cancellation retains `NotDispatched`; a lost
committed response or post-send cancellation retains `PossiblyDispatched`.
No blind replay, retry, rollback or idempotency claim is made.

Each start/read has a bounded deadline and byte budget. Start operations return
an in-memory `ManagementOperation`; `CheckStatusAsync` performs one explicit SDK
update (at most two reads including a final resource fetch), never background
polling or `WaitUntil.Completed`. Only selected-resource final reads and
provider-authored Key Vault operations/operationResults URLs in the selected
subscription, public ARM origin and revision can be followed. Other status URL
shapes are specifically unsupported at this boundary, leaving uncertainty.
Status handles are not serializable URLs or durable rehydration tokens.
Receipts preserve historical start evidence; status checks do not rewrite them.

The pinned Authorization SDK dereferences an absent resource model on native
DELETE 204. A direct SDK fixture reproduces `NullReferenceException`. The adapter
recognizes that exact SDK failure only after its controlled transport observes
the validated terminal 204, then records completed local deletion evidence.
Other failures retain uncertainty; no retry or synthetic provider resource is used.
Optional assignment-create description, conditions, principal type and delegated
managed-identity settings are not yet exposed. Neither those missing inputs nor
the six callable methods establish complete public-API coverage or live access.

Audit queries have a maximum one-day window, 1..1000 rows, one page, 1..120-second
client/server deadline and bounded response bytes. A sentinel extra row marks
truncation. There is no native row cursor: callers explicitly select another
window; no snapshot, gap-free pagination or unique row ordering across requests
is claimed. Unknown operations/results become finite `Unknown` values, not
arbitrary strings. Partial errors retain valid rows but `Complete=false`, with
bounded error kinds rather than provider error text. Unexpected columns or
substituted coordinates discard the response.

Local batches accept 1..16 immutable query inputs and a total deadline, run
sequentially and keep stable input indexes in caller-held `AuditBatchProgress`.
Individual failures remain results and do not prevent later queries. Caller
cancellation propagates; already completed indexes remain available and unfinished
indexes remain null. No worker, sleep, hidden retry or native deprecated batch.

## Offline verification

Tests use actual official SDK clients over a custom HTTP transport with fixture
backend state, event barriers and nonproduction canaries. They do not establish
live credentials, permissions, propagation, entitlements, cloud compatibility
or distribution readiness.

Retained 2026-10-09 evidence: the official SDK baseline failed behaviorally on
a substituted vault response before adapter implementation. Generated locks
passed locked restore; the Release build and **52/52** focused tests passed.
Both owned directories passed scoped formatting verification and language-server
diagnostics reported zero findings. A native continuation discarded by the SDK
and the SDK's exact monitoring audience were measured, not inferred.
Subsequent integrated RBAC/notification verification passed all **79/79** tests.
The Release solution build, seven-package pack and isolated installed consumer
also passed. Parent review confirmed separate monitoring/administrative identities,
fixed resource queries, bounded partial results and retained batch cancellation
progress. These checks do not establish live permissions or delivery.

Run from the independent SecretKit root:

```sh
dotnet restore tests/SecretKit.AzureKeyVault.Management.Tests/SecretKit.AzureKeyVault.Management.Tests.csproj --locked-mode
dotnet build tests/SecretKit.AzureKeyVault.Management.Tests/SecretKit.AzureKeyVault.Management.Tests.csproj --configuration Release --no-restore
dotnet run --project tests/SecretKit.AzureKeyVault.Management.Tests/SecretKit.AzureKeyVault.Management.Tests.csproj --configuration Release --no-build -- --minimum-expected-tests 79
dotnet format tests/SecretKit.AzureKeyVault.Management.Tests/SecretKit.AzureKeyVault.Management.Tests.csproj --verify-no-changes --include src/SecretKit.AzureKeyVault.Management tests/SecretKit.AzureKeyVault.Management.Tests
dotnet pack src/SecretKit.AzureKeyVault.Management/SecretKit.AzureKeyVault.Management.csproj --configuration Release --no-build --no-restore --output src/SecretKit.AzureKeyVault.Management/artifacts/packages
```
