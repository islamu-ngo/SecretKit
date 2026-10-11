# Core delivery scope and deferred orchestration

Decision: accepted user scope correction on 2026-10-11, applied to local source.
It supersedes both comprehensive R6 connector delivery and the intermediate
keep/preserve requests. The broad third-party Infisical app-connection and
secret-sync catalog is removed, not awaiting confirmation or a new archive.

The [public decision](../public/connector-scope-decision.md) explains the
boundary; [scope and orchestration](../public/scope-and-orchestration.md)
distinguishes secret access, optional administration and Configurator.

## Retained scope

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
