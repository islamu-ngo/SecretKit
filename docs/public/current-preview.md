# Current local preview

**In development. Not ready for production. APIs may change without backward
compatibility.** The current local candidate is `0.1.0-local.20261024.1`.
The [local recipe](local-packages.md) prepares a relocatable repository feed,
without listed or unlisted publication. Offline installed-package evidence,
17-case deployment-functional acceptance and complete 21-case native
qualification remain separate. Functional acceptance cannot promote unproven
identity/policy/deployment bindings or grant public-release authority.
Run-specific evidence belongs to the exact frozen candidate's local records;
the commands and authored tests described here are not a claim of a native pass.

## Infisical-first local adoption direction

The [runtime adoption security contract](../internal/RUNTIME_ADOPTION_SECURITY.md)
defines requirements for installed console/worker/web apps, causal native
proof and setup cleanup. The three app entrypoints and controlled proof/lifetime
protocols have offline process/HTTP evidence; this does not qualify the final
local archives, a deployment, Windows, or full native cleanup. The
[adoption and recovery guide](demos-and-recovery.md) records the measured scope
and unqualified trim/AOT profiles. SecretKit is not ready for production.

Accepted on 2026-10-23: prioritize qualified local Infisical packages, with no
public NuGet publication or Event repository integration phase. Azure and
selected administration remain retained work. The [local package guide](local-packages.md)
describes existing evaluation commands; the
[engineering contract](../internal/INFISICAL_LOCAL_READINESS.md) identifies the
planned revision/provenance, authentication, consumer and qualification work.
The local profile tooling, qualified raw native read/revision API, explicit
token-bound handoff, host-owned read transport and generic consumer composition
are now implemented. The minimal installed fixture has separate Core+Infisical,
Configuration, Hosting and full modes. These remain offline implementation
claims; the exact local native profile is not live-qualified.

The dedicated [local native compatibility ledger](../internal/compatibility/infisical-local-profile.md)
retains missing provider authority and unestablished deployment/principal/policy
binding as open gates. Declared versions, actor IDs and policy digests do not
become independently observed native facts. S15 cannot pass from offline
protocol responses or a declaration-only native input.

The preceding readiness assessment on 2026-10-23 passed a Release solution build,
all 4,175 offline solution tests using freshly packed package originals, locked
restore, both offline samples and formatting. Its dependency vulnerability query
reported no vulnerable packages. Packages were evaluated on CachyOS Linux x64
with SDK `10.0.302`; the source was initially uncommitted and was committed as
`e635985239a3146228f1bb75d65a3f13c84a292c` during that assessment. Those
development artifacts are not a protected source-bound release candidate.
No checks were rerun for this documentation-only update. The native conformance
projects are separate from the ordinary solution's passing test count.

Common reads project an optional numeric version. The implemented
`ReadNativeAsync` additionally qualifies raw, non-imported reads with exact
returned coordinates, resource `id` and positive version. Its opaque revision
compares across clients but does not transfer client authority or describe
expanded/imported material. Offline protocol tests are not native deployment
qualification. A four-package local profile remains separate. A functioning
generic consumer is not proof of Event acceptance or complete Infisical support.

The [current provider support view](provider-support.md) records the 2026-10-12
offline foundation and its explicit live/platform limits. Dated narratives below
retain their original scope; they are not complete current admission.

Accepted scope correction (2026-10-11): the broad Infisical third-party
app-connection and secret-sync catalog has been removed from local source.
Core, Infisical/direct Azure runtime access, optional configuration/hosting,
selected administration, native SQL rotation configuration and runtime features,
and existing gateway/proxy administration remain. See the
[applied decision](connector-scope-decision.md). Local removal verification passed; historical evidence below remains separate.

This checkout implements a limited read, generation and selected-write subset. It is unpublished and does
not implement the complete admitted operation inventory.
The surrounding guides describe the larger design, not completed support.

An earlier development checkpoint on 2026-10-22 passed locked restore, Release
build, all 4,146 offline solution tests across twelve test projects, both offline
samples and solution formatting. Seven fresh `0.1.0-preview.1` package originals
were packed locally and consumed through the isolated package-only checks.
These results are from CachyOS Linux x64 with SDK `10.0.302`, not the required
Ubuntu/Windows same-run release matrix. They do not establish provider effects,
hosted candidate approval, publication readiness or general database support;
the [database credential boundary](database-credentials.md) remains unchanged.

On 2026-10-10, the owned pinned Infisical v0.166.3 sandbox passed an installed
package-only narrative with separate generated administrative, project-viewer
runtime and denied machine identities. It verified selected/versioned reads,
absence and denied writes/reads, cross-project isolation, metadata inventory,
required bootstrap and explicit export, a pinned configuration generation across
replacement, optional fresh recheck and admin-visible/runtime-denied assessment.
This is local conformance for that slice, not all admitted routes, editions or
external backends. Azure live testing remains deferred.

The historically install-tested packages before removal are `SecretKit.Core`, `SecretKit.Infisical`,
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
Duplicate JSON property names in these read, inventory and static-mutation
responses are rejected before projection, including escaped equivalent names.
An ambiguous response after mutation dispatch leaves the receipt uncertain;
the SDK does not replay the mutation.

The current Infisical client accepts a host-owned `IInfisicalTokenSource`.
The source returns independently owned token material and must honor
cancellation. This is not implementation of the thirteen native machine-auth
flows. The current native addition exposes an explicit Universal Auth login
exchange plus 18 Universal/Token Auth management routes, with copied protected
material and caller-held single-use receipts. It performs no automatic login,
principal discovery or mutation replay. Reported positive login expiry is not
capped by max-TTL or promoted into finite periodic policy evidence. Unspecified
trusted-IP response shapes and individual credential DELETE routes remain gaps.
The user selected handwritten typed HTTP contracts with Refit and
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

## Azure management notification DELETE

Azure management notification DELETE accepts a bounded subset of originally
issued Event Grid operation URLs at API version 2025-02-15: the documented
regional operationResults and operationStatus paths in the selected resource
group and subscription. The existing selected-resource Location remains
supported. This does not broaden notification PUT/PATCH or admit arbitrary ARM
status URLs. Native status or authorization denial is not resource-absence,
delivery-drain or cleanup-settlement proof. This local subset is not live
provider or principal qualification.

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

## Infisical identity operation scope

Identity updates require an explicit identity ID and, for project operations,
an explicit project ID. Missing coordinates are rejected before dispatch rather
than selecting an organization route or a create action. Independent update
approval-target helpers and project list/create targets enforce the same
required null-coordinate boundary.

Explicit create operations remain create operations; optional patch fields
still retain their documented omission behavior. These guards do not establish
remote membership, entitlements or administrative rights.

The identity-coordinate checkpoint passed 4,175 offline solution tests and the
separate controlled identity-family (19) and original permission-route (872)
tests. Fresh installed originals, samples, build and formatting also passed.
These results remain local development evidence, not native deployment or
release qualification.

## Infisical audit configuration

Organization and project audit-setting writes require exactly one
`Authentication` setting and one `Authorization` setting. Both boolean values
are explicit because the request replaces the mutable settings. Null, missing,
duplicate or permanent classes are rejected before transport; a null setter
input cannot become a read request.
Project audit getters and setters also reject a null project ID rather than
selecting the organization route.

`Management` and `DataAccess` remain valid audit read/filter classes, but are
always recorded and cannot be changed by these setters. Enabling authorization
logging still requires Infisical's new privilege system; the SDK neither enables
that system nor infers administrative permission.

Settings readback is configuration evidence, not proof of event production,
persistence, suppression or immediate policy enforcement. Published settings
changes may take up to ten minutes to propagate. Native audit conformance still
needs the selected deployment's independent event evidence; no live verification
or compatibility with the historical v0.166.3 sandbox follows from this local fix.

After these audit request and project-scope repairs, the local checkpoint passed
4,166 offline solution tests and 110 separate controlled governance tests, with
fresh seven-package originals, installed consumers, both samples and formatting.
These are development results on the same CachyOS host, not live audit-policy
or Ubuntu/Windows release qualification.

## Evidence boundary

The basic Infisical administration inventory records 121 callable typed
operation projections out of 122 research rows across five families, including
bounded group inventories, project-template metadata CRUD and organization-user
membership list/update/delete, identity-template subsets and organization identity
membership inventory and project user/identity membership inspection and role
updates, scoped identity search/count, membership invitation/bulk removal,
project connection metadata, legacy identity privilege inspection/deletion,
typed v1/v2 privilege authoring and bounded organization/project role authoring.
Supported input
subsets are not complete native-operation coverage. The exact source-linked
[management inventory](../../src/SecretKit.Infisical.Management/operation-coverage.json)
retains optional configuration gaps and unestablished response contracts. It
has no connector families and is not complete retained administration coverage:
native SQL rotation configuration, gateway/proxy and other retained native
subsets are not all counted in that denominator. Permission subjects named
`AppConnections` are access-policy values, not public catalog support.

Offline transport tests exercise material ownership, cancellation, identity
separation, response budgets, status mapping and metadata boundaries. They do
not establish real provider permissions, server editions, paid features,
cloud behavior, runtime interoperability, Native AOT or trimming.

Historical local `0.1.0-preview.1` artifacts are a pre-removal subset and
working-tree build, not a published release or post-removal certification. Installation tests
restore the local packages into an isolated package cache and run an independent
consumer without project references. The frozen Infisical inventory in the
[research registries](../internal/providers/) is `ContractResearchOnly`
evidence, not current admission or a promise to deliver every connector.
The accepted scope retains bounded native features rather than comprehensive
third-party integration administration. Historical verification recorded 15,870
offline solution passes; the 15,182 cases were in the whole management suite,
not solely connector tests. Ten owned live cases yielded nine passes and one
replication license rejection. Post-removal checks passed locked restore, the
full solution Release build, all 3,668 offline tests, formatting, seven local
packages and fresh installed consumers. The consumer asserted public connector
API absence. Exact-file C# diagnostics were clean; three retired-route guard
cases passed separately and are included in the full total. Independent
read-only review found no scoped regression.
Azure live and licensed/native effects remain gates; no publication or complete
coverage is claimed.
