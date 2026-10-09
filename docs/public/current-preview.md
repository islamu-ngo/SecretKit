# Current local preview

This checkout implements a limited read, generation and selected-write subset. It is unpublished and does
not implement the complete admitted operation inventory.
The surrounding guides describe the larger design, not completed support.

The currently install-tested packages are `SecretKit.Core`, `SecretKit.Infisical`,
`SecretKit.AzureKeyVault`, optional `SecretKit.Extensions.Configuration` and
optional `SecretKit.Extensions.Hosting`, `SecretKit.Infisical.Management` and
`SecretKit.AzureKeyVault.Management`,
targeting .NET 10. Core has no package dependency. Providers depend inward on
Core. Microsoft.Extensions.Configuration belongs only to the optional export
package. Databases, ASP.NET and consumer application projects are not required.

## Read contract

Create a provider client with an explicitly selected origin and credential
source. Its `Authority` identifies that client instance. A `SecretReference`
combines that authority with a provider-owned address; a reference from another
client is rejected before credentials or transport are used.

`ISecretReader.ReadAsync` returns a bounded `SecretOutcome<SecretRead>`.
Only success exposes `Value`. Cancellation propagates. A successful read owns
independent disposable `SecretMaterial`; dispose the `SecretRead` after use.
`Reveal` deliberately creates an ordinary managed string which the SDK cannot
erase. Formatting and default JSON serialization do not reveal protected
material or coordinates.

Infisical uses the current v4 selected-name read and direct metadata-list
endpoints. Project, environment, folder, shared-secret type, imports, reference
expansion and version are explicit address/query choices. A returned key or
selected-version mismatch fails closed. Material requires explicit
`secretValueHidden: false`; withheld material is denied and missing/malformed
visibility evidence is unknown. No other authentication principal is selected.

The current Infisical client accepts a host-owned `IInfisicalTokenSource`.
The source returns independently owned token material and must honor
cancellation. This is not implementation of the thirteen native machine-auth
flows. The user selected handwritten typed HTTP contracts with Refit and
HttpClient. Internal Refit bindings construct native requests; the controlled
transport retains actual send cancellation, bounded raw responses and receipts.
No production, test or assessment project depends on the official Infisical SDK.
Public contracts are not generated from a vendor OpenAPI schema.

Azure uses the official `SecretClient` with explicit stable `2025-07-01`.
The host supplies `TokenCredential`; SecretKit does not choose a credential
chain. Returned vault/name/version coordinates must match the selected read.
Disabled, not-yet-valid and expired values do not become normal consumption
material. SDK retries, logging/content logging and distributed tracing are
disabled; challenge-resource verification remains enabled.

## Inventory and networking

`ISecretInventory.InspectAsync` returns metadata, not material or proof that an
application identity can read values. Collection start/end and completeness
are reported; paging is not a remote transaction or point-in-time snapshot.
Page, item and response-byte budgets apply. A truncated result is incomplete.

Azure inventory rejects foreign-origin rows and continuation links that change
the origin, inventory operation or selected API revision. Infisical's current
list is nonpaginated; its admitted item budget can produce incomplete metadata.

Response bodies are bounded. The default limit is 1 MiB. Infisical accepts
1 KiB through 16 MiB; Azure accepts 1 KiB through 16 MiB. Azure bounds raw streams
before SDK parsing, including responses without Content-Length. This does not
prevent the native SDK/parser from creating managed material strings.

HTTPS and standard certificate validation are defaults. Infisical development
HTTP requires explicit `AllowLoopbackDevelopmentHttp` and a loopback origin. Default
transports disable redirects and cookies. Azure accepts standard HTTPS vault
origins for public, US Government and China endpoint syntax; syntax admission
is not tested sovereign-cloud support.

Infisical owns its default transport and drains active reads on asynchronous
disposal. Supplied token sources and injected transports remain host-owned.
Azure supplied credentials/transports remain host-owned. Host HTTP,
credential and proxy instrumentation is outside SDK-owned diagnostic controls.

## Generations, changes and consumer workflows

The optional configuration package collects all required consumer-key selections
asynchronously, then publishes one local immutable generation. Acquired handles
retain old storage across replacement; every returned disposable read is a copy.
Failed or canceled collection does not publish a partial mixture. Versions and
collection windows are observations, not a remote snapshot guarantee.

`SecretConfigurationExport.CreateAcknowledgingManagedStrings` is explicit string
export with prevalidated case-insensitive destination-key collisions. Exported
values are ordinary strings; default configuration debug views and options remain
host-owned plaintext boundaries. The export's redacted summary contains no values.

Selected writes are Infisical shared-secret create/value update and Azure native
SetSecret. The caller holds a target-bound `MutationReceipt` before execution.
Cancel-before-send leaves it undispatched; cancellation after possible send
propagates while retaining uncertainty. Transport loss after a committed write is
unknown and is never automatically replayed. Azure mandatory create-only,
version-match and version-targeted Set are unsupported before mutation.

Infisical approval submission is distinct from applied material. An observed
approval identifier does not prove merge, downstream delivery or activation.
Unestablished approval/access-request/PIT/insight/webhook administration remains
static `ContractNotEstablished` evidence with permission not checked, not a stub
administrative module or private endpoint.

Standalone RuntimeConfiguration and ProviderAssessment samples demonstrate
selected-authority bootstrap, intended-identity assessment, fresh Check again,
logical multi-key generations and explicitly reviewed bounded changes. Reviewed
batches admit at most 128 items and 16 workers, preserve indexed outcomes and
caller-held receipts, and do not claim a transaction or rollback.

Consumer-owned activation examples apply non-sliding freshness deadlines,
prepare/validate before publishing a client generation, guard late disable and
retire clients after acquired/in-flight work releases. Replica acknowledgement is
local material-free evidence, not durable persistence or fleet convergence.
These examples perform no unsolicited business action or actual migration.

## Explicitly hosted native token maintenance

`InfisicalPeriodicTokenSession` accepts one supplied protected token and
independently verified lifetime evidence. It sends native token renewal with
single-flight ownership and a fixed trusted origin. Finite lifetime remains bound
to original issuance; periodic semantics are not inferred from zero maximum TTL.
Unknown lifetime, expiry, token loss or uncertain renewal requires explicitly
authorized recovery. There is no login loop or token persistence.

The optional hosting package starts only when the host calls StartAsync or
registers the service in a started host. It schedules renewal from the known
deadline, exposes material-free maintenance health and cancels/drains on Stop.
Its renewal retry budget is zero: this contract has no established safe replay.
The session/credential/transport remain host-owned. No general scheduler or
application readiness policy is introduced.

## Evidence boundary

The optional Infisical administration package currently exposes 84 typed
operation projections out of 122 admitted management operations, including
bounded group inventories and project-template metadata CRUD. Supported input
subsets are not complete native-operation coverage. The exact source-linked
[management inventory](../../src/SecretKit.Infisical.Management/operation-coverage.json)
retains optional configuration gaps and unestablished response contracts.

Offline transport tests exercise material ownership, cancellation, identity
separation, response budgets, status mapping and metadata boundaries. They do
not establish real provider permissions, server editions, paid features,
cloud behavior, runtime interoperability, Native AOT or trimming.

Local `0.1.0-preview.1` artifacts are a subset and working-tree build, not a
published release or complete provenance/API certification. Installation tests
restore the local packages into an isolated package cache and run an independent
consumer without project references. The [operation registries](../internal/providers/)
separate admitted contracts, partial implementation and unverified compatibility.
The completed release still requires native lifecycle/management/connector
coverage, live conformance, complete seven-package verification and protected
publisher evidence.
