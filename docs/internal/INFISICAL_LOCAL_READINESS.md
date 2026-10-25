# Infisical-first local readiness contract

> Audience: SDK implementers, reviewers, and integration authors
> Status: Implemented offline boundaries; owned native qualification remains a separate gate
> Decision date: 2026-10-23
> Baseline: `e635985239a3146228f1bb75d65a3f13c84a292c`
> Source anchors: [architecture](SDK_ARCHITECTURE.md), [runtime contracts](RUNTIME_CONTRACTS.md), [delivery](DELIVERY_AND_MAINTENANCE.md), [public local guide](../public/local-packages.md)

## Decision and authority

The next runtime increment follows the
[runtime adoption security contract](RUNTIME_ADOPTION_SECURITY.md). Its three
installed apps and causal proof/cleanup are requirements, not current completed
native observations. Existing offline work below remains implemented.

The immediate outcome is qualified local Infisical packages for reusable .NET
application integration. This supersedes the earlier simultaneous two-provider
delivery priority for this workstream. It does not remove Azure, management,
typed native features, historical evidence, or unfinished provider work.

Event supplies functional requirements, not SDK models, source, tests, or a
compatibility target. This workstream changes SecretKit only. No phase edits
Event or Configurator, publishes packages, configures a NuGet owner, or changes
publication authority. Breaking API redesign is allowed during development;
compatibility aliases and obsolete-contract preservation are not requirements.

## Existing state versus required work

The native package now exposes qualified raw, non-imported reads and opaque
resource revisions. Common reads validate returned scope contradictions without
inventing native evidence. Token-bound lifetime handoff, caller-driven
authentication/recovery composition, required/optional sample workflows,
mutation-result preservation and validated host-owned read transport are
implemented with deterministic offline tests.

The source-owned four-package profile has separate local preparation/check
commands and a package-only consumer with independently optional extensions.
These are offline mechanisms, not certification of the declared deployment,
actor binding, private networking, approval policy or native longevity.
The table retains the delivery requirements; current native scope belongs in
the compatibility ledger and exact local reports, not inferred from this list.

| Concern | Existing evidence | Local-readiness requirement |
| --- | --- | --- |
| Reads | Authority-bound v4 reads; key, material-visibility and selected-version checks | Typed provider identity/revision evidence and validation of returned coordinates needed by exact-address consumption |
| Inventory | Direct-folder metadata with item/response limits | Keep metadata distinct from material acquisition; reject ambiguous or substituted provenance |
| Revision | Optional numeric observation version; provider secret ID is not projected by the common read | Stable value-free native resource identity plus positive version, without material hashes or fabricated observation-time revisions |
| Authentication | Explicit login, supplied token source, renewal session and opt-in hosted maintenance | Usable documented composition for startup, finite lifetime, single-flight work, explicit recovery and shutdown |
| Configuration | All-required collection, retained local generations and deliberate string export | Reusable required/optional composition examples, mapping/precedence checks and bounded caller-owned refresh |
| Mutations | Caller-held receipts; applied, pending and unknown are distinct | Installed-consumer proof that those distinctions survive host translation and cancellation |
| Transport | Trusted origin, bounded responses, no redirect/replay; reads rely on caller deadlines | Measured deadline/cancellation, private-CA/proxy and self-hosted network acceptance without TLS bypass or mandatory IPv4 |
| Packaging | Seven-pack family and package-only smoke witnesses exist | Independent four-package local profile, fresh-cache selection, exact source/archive records and useful consumer scenarios |
| Native evidence | Historical scoped Infisical sandbox narratives | Focused owned qualification of the exact local profile; missing authority remains an open qualification gate |
| Public release | Seven-package/two-provider `complete-live` verifier | Preserve unchanged authority; local evidence cannot create an approved public release |

These are integration requirements, not a statement that every existing generic
read is defective. Claims must follow source and tests, not the earlier report's
recommendations alone.

## Architectural ownership

| Owner | Responsibilities |
| --- | --- |
| Core | BCL-only portable reads/inventory, opaque disposable material, references, bounded outcomes and dispatch receipts |
| Infisical | Handwritten typed Refit/HttpClient contracts, native coordinates, resource identity/revision, authentication and native mutation semantics |
| Configuration | Caller-driven required selections, immutable local generations, explicit mappings and managed-string export |
| Hosting | Explicitly started token maintenance, material-free state and bounded shutdown |
| Nonpackable consumers/tests | Generic bootstrap, optional-capability, mutation-translation, separate-authority and activation examples |
| Application | Tenant hierarchy, bindings, domain validation, configuration meaning, Data Protection admission, live clients, readiness, persistence and convergence |

No shipped package introduces database drivers, ODBC, an Event dependency,
generic raw-request execution, or a general database compatibility matrix.
Credentials stay opaque in Core; Infisical native APIs stay typed. Optional
database verification remains nonpackable, and MySQL observations do not qualify
MariaDB.

## Behavioral acceptance

1. A read MUST bind the selected client, exact native coordinates and the
   documented returned identity/version evidence. Missing or contradictory
   evidence MUST NOT become a fully qualified native revision.
2. Native revision equality MUST distinguish the same resource/version from
   deletion and recreation. An observation timestamp, material hash, or new
   client instance MUST NOT substitute for provider identity.
3. Material visibility, absence, denial, invalid evidence, unavailable transport,
   throttling, cancellation and unknown outcomes MUST remain distinguishable
   under the supported contracts.
4. Metadata inventory MUST NOT read secret values, expand references, acquire
   leases, or establish delivery permission as an incidental effect.
5. Authentication MUST use explicitly selected credentials. Startup exchange,
   renewal and recovery are separate decisions; no automatic fallback principal,
   consumed-credential replay, hidden worker or implicit re-login is admitted.
6. Required collection MUST publish only a complete valid local generation.
   Optional capability failure MUST NOT publish a partial required generation
   or fail unrelated application startup.
7. Mutations MUST preserve caller-held receipt evidence across cancellation and
   response loss. Pending approval MUST NOT be reported as applied material or
   consumer activation.
8. Networking MUST preserve trusted origin, certificate validation, response and
   duration budgets, cancellation and resource ownership. No global networking
   change or unconditional IPv4 policy is introduced.
9. Local qualification MUST bind the declared package set, source snapshot,
   original archive digests, dependency closure, scenarios and observed platform.
   It MUST NOT grant publication or claim Event acceptance.

## Local qualification profile

The application profile contains `SecretKit.Core`,
`SecretKit.Infisical`, `SecretKit.Extensions.Configuration` and
`SecretKit.Extensions.Hosting`. Individual consumers select only needed
dependencies. Management and Azure are outside this profile, not deleted.

The profile claims selected shared-secret reads, metadata inventory, Universal
Auth startup and admitted token maintenance, selected shared-secret mutations,
generation/export and explicitly started hosting. It does not claim all native
methods merely because they share an assembly. Existing dynamic, rotation,
import, organization and management surfaces retain their actual evidence and
are not silently counted as locally qualified.

The dedicated source-owned profile names exact members and scenarios.
Existing complete-live admission requirements remain intact. A local
record has a distinct schema/kind and cannot be accepted by public candidate,
manifest, journal, approval or publish paths. A negative cross-mode test is a
required authority invariant.

Existing full-solution regression checks remain required for shared changes.
That is regression protection, not a demand for Azure or management completion.

## Acceptance evidence and operations

The first executable proof is a fresh package-only generic consumer, not an
Event migration. It must cover bootstrap-before-dependent-service construction,
separate runtime/denied identities, optional capabilities, revision drift,
generation ownership, explicit recovery, mutation uncertainty and safe output.
Application policies appear only as small nonpackable consumer examples.

Focused native checks use an already owned, explicitly selected Infisical
deployment, identities, allowed namespace and cleanup plan. No credentials,
backend provisioning, registry publication, browser session or deployment change
is inferred from this document. Missing inputs do not block independent
authoring or offline validation, but do block a live-qualified completion claim.

The dated 2026-10-23 readiness assessment observed 4,175 passing offline solution
tests, fresh local packaging, both offline samples, locked restore, formatting
and a dependency vulnerability query reporting no vulnerable packages. That
assessment is historical evidence for the assessed working tree, not a new
execution by this documentation task or a hosted release candidate. Native
conformance projects are separate from the ordinary solution.

## Documentation and implementation sequencing

Update current scope and evidence language before implementation planning.
Implementation then proceeds through profile isolation, native read/revision
contracts, authentication lifecycle, configuration and consumer workflows,
mutation/transport boundaries, installed-package qualification, and focused
native acceptance. Each increment owns tests and the corresponding public and
internal guidance. No tracked document depends on private active-task files.

## Local adoption delivery

Current candidate `0.1.0-local.20261024.1` remains development-only, not
production-ready, with breaking APIs permitted and no compatibility aliases.
The [chronological local recipe](../public/local-packages.md) is the command
owner for locked restore, same-Version conformance/solution builds, final
packing, four-original selection, source record and installed-consumer checks.
Complete tracked edits before freezing the record; subsequent source changes
require a new candidate and affected verification, not edited evidence.

`LocalInfisicalBundleTests` produces one relocatable handoff from unchanged
originals and exercises four independent consumer modes with its relative
configuration and empty caches. A retained output is explicitly selected;
ordinary CI uses a temporary output. This adds no packable bundler or Event code.

`LocalProfileFunctionalTests` separately evaluates the 17-case development
pilot after independently freezing expected identity before dispatch and after
cleanup. Exact per-case observed reasons, Applied create evidence, confirmed
owned-resource-cleanup and unavailable no-approval state are required.
Structural report validation and full 21-case qualification remain unchanged.
No arbitrary-token principal proof or public approval is inferred. Missing
deployment authority/inputs block the pilot, not independent offline authoring.
Both listed and unlisted publication remain outside this delivery.

