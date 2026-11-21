# Core delivery scope and deferred orchestration

## Current priority: local Infisical adoption

The user's 2026-10-23 direction supersedes simultaneous two-provider completion
as the immediate delivery goal. Build and qualify reusable Infisical access
through local packages; public publication and changes to Event or Configurator
are outside this workstream. Preserve Azure, selected administration, unfinished
provider work and the existing public release protocol.

The [local readiness contract](INFISICAL_LOCAL_READINESS.md) owns current
behavioral gaps, package/evidence boundaries and implementation sequencing.
The [public local guide](../public/local-packages.md) owns adopter evaluation.
The removal decision and historical evidence below remain valid in their dated
scope; they are not a new local qualification result.

Decision: accepted user scope correction on 2026-10-11, applied to local source.
It supersedes both comprehensive R6 connector delivery and the intermediate
keep/preserve requests. The broad third-party Infisical app-connection and
secret-sync catalog is removed, not awaiting confirmation or a new archive.

The [public decision](../public/connector-scope-decision.md) explains the
boundary; [scope and orchestration](../public/scope-and-orchestration.md)
distinguishes secret access, optional administration and Configurator.

## Retained scope

The [package-only demo guide](../public/demos-and-recovery.md) owns practical
startup, activation, request lease, shutdown and recovery guidance, with bounded
measurement/compatibility evidence. Another backend follows the
[provider admission decision](PROVIDER_ADMISSION.md), not a catalog-completion
goal. Unavailable native qualification does not itself prohibit authorized
implementation, and authorized authoring does not establish native support.

- BCL-only Core with `ISecretReader`, `ISecretInventory`, references, owned
  material and explicit outcomes.
- Infisical and direct Azure runtime secret reads, writes, authentication and
  supported provider-native lifecycle.
- Independent optional configuration export and explicitly started hosting.
- Project/environment, identity/access and selected governance administration.
- Native SQL rotation configuration and runtime features, plus existing
  gateway and proxied-service administration.

An Infisical Azure connection is not the direct Azure provider. A role subject
named `AppConnections` is not a connector factory. Retained rotation configuration
can reference an existing connection without SDK connection provisioning.
The single direct PostgreSQL connection setup inside `RotationProgressTests`
is an owned test-only prerequisite, not public connector support.

## Applied removal and verified local evidence

The removal unit deleted 234 catalog C# units, 80 connector-only test files,
640 dispatcher cases, `connector-coverage.json`, and 16 partial archived
source/test files for Fireworks, Spacelift, Daytona and TeamCity sync.
No new archive, branch, repository or integration package was created.
Shared rotation parsing is detached from catalog helpers; delivered-connection
summary overloads and the standalone owned connection test are removed.
The local verification below applies to the reduced source.

Removal evidence: the reduced full solution Release build
completed with exit 0; exact-file LSP checks on all 16 changed C# files were
clean; the retired-route guard passed three cases. Source checks found no
catalog factories/types/routes, only retained `ProjectConnectionOperations`
and audit/role permission vocabulary.

The full offline matrix passed 3,668 cases with no failures. Locked restore,
Release build, formatting and local pack also passed. All seven packages were
installed into fresh consumer outputs/cache; the consumer ran successfully and
asserted that no public connection/sync catalog types remained. The three guard
cases are already included in the full total.

Independent read-only review found no scoped regression. Retained JSON
inventories parsed successfully. The optional Biome JSON language server was
unavailable; no dependency was installed for it. Exact C# diagnostics and the
actual compiler were clean. No new live-provider verification was claimed.

The basic `operation-coverage.json` stays at 122 research rows / 121 callable
projections across ScopedAccess, Projects, Identities, IdentityPrivileges and
Governance. It has no connector families and does not enumerate all retained
administration. Frozen `infisical-operations.json` is `ContractResearchOnly`
evidence, not current product admission or complete implemented coverage.

## Historical verification before removal

The 2026-10-11 checkout passed 15,870 offline solution tests, locked restore,
build, formatting, local packaging of seven packages and an isolated
package-only consumer. The separate 15,182-case management run covered the
whole management suite, not solely connector tests. Neither result verifies
the post-removal checkout.

Owned live identity, installed read/write/configuration/assessment workflows,
mutation uncertainty, ordinary imports, authentication, token policy and
bootstrap recovery had scoped positive evidence. Across eight native class
invocations, ten cases were attempted: nine passed and one replication case
was rejected (`Invalid` / `Rejected`) by the owned deployment's license gate.
That is not a whole-green native matrix.

Historical connector audits and counts describe the former scope only. The
Qovery fault-fixture and Vault action-effect evidence gaps were not closed by
passing counts; removed tests are not relabeled as verified native effects.

## Remaining gates

Azure live verification remains deferred without an account. Licensed replicated
imports and SQL acquisition/rotation remain entitlement gates. Native credential
effects, permissions, persistence, edition/version compatibility, unspecified
event/output schemas and platform/AOT/trimming support need scoped evidence.
Source removal does not revoke remote credentials or change server policy.
Private consumers outside the checkout are unknown.

No live-provider scenario, commit or publication was performed during this
removal. Local package evaluation does not authorize a public release.

## Later workflow: a selected Configurator deployment

Coolify is illustrative, not an approved working integration. Choose one actual
application, destination and delivery mechanism before orchestration. Runtime
secret fetching needs no external connector. Broader optional integration
administration could be legitimate, but it is excluded by this product decision.

Configurator owns destination configuration, deployment sequencing, grants,
operator review and recovery; destination clients remain separate. SecretKit
owns typed provider access and retained native administration. Each step needs
selected authority, observable state and a recovery decision. Reconcile lost
responses from actual provider evidence rather than replaying mutations.

Reconsider a specific integration only for a demonstrated consumer, established
contracts, maintenance ownership and effect-level verification. Do not turn the
historical provider catalog back into the backlog.

## Configurator provisioning consumer

Accepted 2026-11-14 in [ADR-006](adr/ADR-006-configurator-provisioning-and-credential-sources.md):
Configurator uses SecretKit, not vendor CLIs, for every secret-store operation
from its native clients. A vendor CLI may only be an explicit, host-selected
credential source. Azure operator sign-in uses the operator's own Entra client
ID. Infisical retains Universal Auth for the pilot. Machine OIDC Auth does not
establish human delegation. Delegated OAuth implementation remains deferred;
the 2026-11-15 correction in ADR-006 changes SecretKit guidance only.
Configurator's separate ADR has not been edited, and its browser client is
permanently excluded.

The items below distinguish implemented subsets from remaining proposed work.
They follow the order in which Configurator's first pilot would need them:
Infisical through SecretKit on Desktop and Terminal. None authorizes live
provider access, publication or a Configurator change.

| Item | Need | Current source position | Evidence required |
| --- | --- | --- | --- |
| Desktop platform qualification | Configurator Desktop ships on Linux, Windows and macOS | Evidence is Linux development only; JIT/net10.0 | Exact archives installed and executed on Windows and macOS for Core, Infisical and AzureKeyVault; no claim from Linux results |
| Multi-folder value-free Infisical inventory | Compare live key names across every folder a definition maps | `ISecretInventory` lists one folder (`recursive` is `false`); `ListFoldersAsync` can already enumerate folders recursively | Bounded composition with page/item/time budgets and explicit completeness; partial results stay partial, never "unchanged" |
| Interactive operator composition guide | Desktop/terminal hosts select credentials safely | `AzureKeyVaultClient` accepts any host `TokenCredential`; Universal Auth and OIDC/JWT proof exchanges exist | Documentation and a sample: Azure.Identity browser/device-code credentials with the operator's own client ID and protected persistent cache; explicit `AzureCliCredential`; Universal Auth with a host-held client secret |
| Write-conflict honesty for compare-then-apply | A value can change between inventory and write | Azure `SetSecret` has no create-only or version-match option; Infisical write preconditions not yet assessed | Document the race; expose version metadata for an immediate pre-write re-read; never present it as atomic |
| Operator discovery for pickers | Choose subscription/vault or project/environment/folder | `VaultAdministration.ListSubscriptionsAsync` enumerates validated Azure subscription metadata under the selected administrative identity with page/item/time budgets and explicit completeness, preserving provider order; vault listing then uses a selected subscription. Infisical `ListProjects`, project reads and folder listing exist in subsets | Offline transport tests cover Azure projection, malformed payloads and collection bounds; live subscription visibility and Infisical coverage under the selected identity's actual permissions remain unestablished |
| Infisical delegated OAuth (future) | Human-attributed access under the user's permissions | [OAuth applications](https://infisical.com/docs/documentation/platform/oauth-applications/overview) document human delegation; `InfisicalLoginProof.Oidc` is a separate machine-identity exchange | [Token exchange](https://infisical.com/docs/documentation/platform/oauth-applications/token-exchange) needs organization-owned confidential middleware, client-secret custody, active OIDC SSO and prior user sign-in; no refresh token or administration mutations. [Authorization code](https://infisical.com/docs/documentation/platform/oauth-applications/authorization-code) currently offers only `secrets:read`, with its own client-secret custody decision despite PKCE; never embed a confidential secret in a desktop binary |
| Third provider proposal (future) | Configurator's vision lists another self-hostable vault | No third provider admitted | A [provider admission](PROVIDER_ADMISSION.md) proposal with Configurator as the named consumer; OpenBao (MPL-2.0) fits ISLAMU's sovereignty goals better than source-available Vault, subject to that review |

Excluded by the same decision: CLI wrappers or process execution in any
package, a common Core writer before shared write semantics are demonstrated,
restoration of the connector/sync catalog, and trimming/AOT work for
Configurator's browser client.

## Strategic positioning and pre-1.0 unlocks

See [Positioning and strategy](POSITIONING_AND_STRATEGY.md) for the concrete
value-proposition analysis outside Event/Configurator (including why anti-lock-in
is not the moat, what differentiates SecretKit for Infisical and Azure Key
Vault consumers, verified preview blockers in memory/concurrency/error mapping,
and the pre-1.0 unlocks required before targeting closed-source external teams).
