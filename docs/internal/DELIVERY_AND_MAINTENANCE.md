# SecretKit Delivery And Maintenance

> Audience: SDK maintainers, implementers, reviewers and release owners
> Status: Delivery requirements with an implemented public publisher and planned local profile
> Owner: SecretKit delivery maintainer
> Last Verified: 2026-10-09, bounded design evidence and local links only
> Source Anchors: [overview](README.md), [architecture](SDK_ARCHITECTURE.md), [runtime contracts](RUNTIME_CONTRACTS.md), [historical research](RESEARCH_EVIDENCE.md)

This proposal puts documentation and early adopting-consumer evidence before comprehensive feature expansion, with an honest declared-coverage release gate.

## Current delivery direction

The [runtime adoption security contract](RUNTIME_ADOPTION_SECURITY.md) adds
explicit installed-app and causal-evidence obligations. Keep partial setup
cleanup, unavailable cases and exact candidate bindings visible; no new support
claim follows until its corresponding checks are observed.

The accepted 2026-10-23 goal is
[Infisical-first local qualification](INFISICAL_LOCAL_READINESS.md). Documentation
is updated before the library implementation plan. The next implementation
must separate a four-package local application profile from the existing
seven-package/two-provider `complete-live` public publisher. It must preserve
unfinished provider work, source-owned admission inventories and public
approval authority.

Local qualification is complete only for named package bytes, native members,
scenarios, identities and platforms. It is not package-wide certification,
Event acceptance or publication approval. No public-publishing or application
repository implementation phase belongs to this workstream. The
[local profile ADR](adr/ADR-002-infisical-local-qualification.md) records this
decision; the sequence below is historical broader delivery context where it
requires both providers, both application workflows or public publication.

The [accepted 2026-10-11 decision](../public/connector-scope-decision.md)
supersedes comprehensive connector delivery: the third-party app-connection/
sync catalog is removed from local source. Selected administration, native SQL
rotation configuration/runtime features and existing gateway/proxy administration
remain. Local removal checks passed; live-provider and release gates remain separate. The earlier broad delivery plan is
historical where it conflicts with that boundary.

## Offline operator contract maintenance

The nonpackable Release tool compares selected implemented Infisical operator
wire facts with a maintainer-supplied local OpenAPI JSON document:

```sh
dotnet build tools/SecretKit.Release/SecretKit.Release.csproj -c Release --no-restore
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll operator-contract-check /absolute/path/to/openapi.json
```

Run from the SecretKit root. The command reads
[`infisical-operator-contracts.json`](infisical-operator-contracts.json), prints
the supplied document's SHA-256, closed findings and operation count, and exits
0 only when every selected comparison matches. Exit 1 means drift, invalid
input or an unestablished construct. It never opens a publication journal,
reads publishing credentials, fetches references, changes a manifest or calls
a provider. This command grants no release authority.

The hand-authored manifest follows actual request builders and response readers:
Universal Auth/token lifecycle, value-free inventory and import groups, qualified
secret reads, static create/update, bulk delete, folder list/get/create, import
configuration listing and project capitalization metadata. Its provenance and
exclusions are part of the review. Exact wire names are interoperability facts;
the vendor document, expressive schemas, implementation and examples are not
copied into the repository. The manifest is a narrow consumer projection,
not a replacement for admission inventories or a full API catalog.

Request `required` lists mean the SDK always sends those members. A newly
required member is incompatible when the selected request does not always
supply it. Response `required` lists mean the reader needs the member.
Request restrictions must accept the SDK's declared inputs; response schemas
must fit its declared accepted types, enums, nullability and bounds. Relevant
optional fields are checked too. Added unrelated operations and extra response
members do not fail; making a required response member optional does.
Path-template labels are mapped by position, while literal segments and
parameter locations must match. Path-level parameters are inherited and
operation-level parameters override them by location and name.

The admitted subset is OpenAPI 3.0.0 through 3.0.3, JSON request/response content,
scalar parameters, object properties, arrays, required members, primitive types,
nullability, primitive enums, selected formats and inclusive numeric/length/item
bounds. Formats are `uuid`, `date-time`, `date`, `password`, `int32`, `int64`,
`float` and `double`. Descriptions, defaults and examples are annotations, never
evidence of runtime behavior. `anyOf` and `oneOf` alternatives within the selected
scope are established before comparison, including alternatives a request does not select. Each
declared request alternative must fit an API alternative; every API response
alternative must fit a consumer alternative unless an audited scope exclusion
applies. `oneOf` requires provably disjoint
primitive types or disjoint enums; overlapping or unestablished alternatives
fail closed. Other compositions, conditional schemas, executable
patterns, schema-valued additional properties and other relevant unknown
constructs yield an explicit `unestablished-*` finding. Such a finding stops
that operation's remaining comparisons; other operations continue. The count
reports operations attempted, not all assertions proven.

Each input is limited to 32 MiB and JSON nesting to 64. Each document's resolver
allows at most 4,096 reference resolutions and 32 active references, rejecting
cycles and sibling definitions on `$ref`. Only same-document `#/...` JSON
pointers with `~0`/`~1` escaping are supported; percent-encoded fragments,
external URLs and other files fail closed. Expanded schema traversal is also
bounded to 64. Duplicate JSON members, duplicate parameter definitions and
ambiguous matching method/path definitions cannot silently select a winner.
Unselected response fields and unrelated operations are outside the check.

An operation may declare a `narrowings` array. Every entry requires `path`,
`sdkRule`, `openApiRule` and a nonempty `rationale`. Paths use comparison labels
such as `response.secret.version` and `response.secrets[].type`. Rules project
all compared primitive facts, or an object's type and required-member set.
Primitive unions may also be projected. Rules must match the resolved schemas
and establish a strict subset; stale, unmatched or widened rules are findings.
Object presence rules additionally require every selected member to exist.
These declarations cannot waive removed properties, unsupported schemas or
unrelated nested differences. Schema resolution uses the same local reference
resolver as ordinary comparison. Request restrictions are never waived.

An operation may also declare `excludedAlternatives`, with a comparison
`location`, discriminator property name and source-anchored `rationale`.
Each declaration must identify exactly one branch whose object properties
include that discriminator and whose `required` set lists it. The consumer
shape at that location must exist and must not declare the discriminator.
Stale declarations, ambiguous matches and consumer-declared discriminators are
findings. All union members must remain schema objects with safe local
references; only an audited excluded branch's internal type completeness is
outside scope. At least one branch must remain, and every retained branch is
established and compared normally. Exclusions never apply to requests.

For a future comparison, obtain the public specification through a separately
authorized process, retain its source identity/date/hash, and supply its local
path. Review each finding against the implementation and current public
interface facts. Update a manifest fact only after its owning wire behavior and
tests justify the change; never regenerate expectations from the supplied
document to turn drift green. Keep the specification outside this repository.
OAuth/prose-only contracts, approval follow-up, native effects, authorization,
server versions and platform qualification remain outside this evidence.

### Supplied snapshot observation, November 18, 2026

The read-only OpenAPI 3.0.3 snapshot at
`/tmp/sk-openapi/infisical-openapi.json` has SHA-256
`4ca14f6cae737de96b8009bb432ed06b5e2723bf598eedde5719a37701eedb79`.
It remains outside the repository. The actual command checked **13 operations**,
reported **0 findings** and exited **0** after the audited corrections below.
`Program.Main` accepts `operator-contract-check <specification>` and reads that
local input; it has no default specification and never fetches one.

| Selected operation | Audited resolution |
| --- | --- |
| Metadata inventory | Two `shared` string narrowings; imported optional `updatedAt`/`tags` omitted because undocumented, while documented direct metadata remains selected |
| Qualified secret read | `shared` string and positive Int32 revision narrowings |
| Static create and update | Approval alternatives explicitly excluded from applied-success scope; retained responses bind `shared` and positive Int32 narrowings |
| Bulk delete | Approval alternative explicitly excluded; retained rows bind selected `shared`/`personal` types and positive Int32 revisions |
| Project policy | Required `project` wrapper and selected `secret-manager` discriminator narrowings |
| Folder list | Its scalar `anyOf` parameter is established and accepts the selected wire type |

The three approval alternatives contain an internally untyped nullable field.
Their required `approval` discriminator is absent from the applied-success
consumer shape. Three source-anchored exclusions model the existing approval
scope boundary; they do not establish approval schemas or provider effects.
The newly reached success alternatives also omit optional `secretPath`.
`InfisicalStaticChanges.cs:168-169` and `NativeBulk.cs:424-425` check that member
only when present, so those undocumented optional projections were removed;
the documented qualified-read `secretPath` remains checked. Twelve narrowings
are bound to the exact remaining primitive and presence facts. No missing
property was admitted by a narrowing.

Linux x64 verification with SDK **10.0.404** passed both warning-as-error builds
and all **111 focused checker tests**, including **29 union/narrowing cases**,
**10 exclusion cases** and actual CLI synthetic exit-0/exit-1 observations.
Removing the consumer-discriminator guard made its exclusion regression fail;
the guard was restored byte for byte before the passing verification.
Scoped formatting passed. The earlier full Release.Tests run, before the added
exclusion cases, executed **874** tests: **870 passed**, **4 failed**, none
skipped. Those failures concerned provider source-digest checks and missing
archive/installed-candidate inputs, not the checker; no untouched-baseline
reproduction is claimed. These observations establish offline selected-contract
matching only, not native qualification, publication authority or a minimum
server version.

On the same **2026-11-16** baseline (SDK **10.0.404**, runtime **10.0.15**),
offline hardening updates adopted `.NET 10` `System.Threading.Lock`, `CA2007`
`ConfigureAwait(false)` across `src/`, shared pooled `ArrayPool<byte>` +
`CryptographicOperations.ZeroMemory` bounded HTTP JSON readers with
`AllowDuplicateProperties = false`, allocation-free `SearchValues<char>`
validation, unified `SqlRotation*` shared models with non-backtracking
`[GeneratedRegex]`, scoped `ControlledTransport` status checks, zero
`[RequiresUnreferencedCode]` or internal plaintext `.Reveal()` /
`.ExportCharacters()` exports across the five `<IsAotCompatible>true</IsAotCompatible>`
packages (`Core`, `Infisical`, `Infisical.Management`, `Configuration`,
`Hosting`), filtered SPDX 2.2 SBOM generation/validation (`Microsoft.Sbom.Targets`
**4.1.13**), and Tier 1 multi-agent adversarial review remediations. Live
provider qualification (`2.1–2.4`, `3.3–3.6`, `4.1–4.3`), `windows-2025` /
`macos-15` CI jobs (`5.2`), protected candidate promotion (`6.2`), and NuGet
publication remain open external gates.

## Admission Policy Is Not A Populated Registry

After building the affected provider projects in Release, refresh their owned
handwritten source inventory from the repository root:

```sh
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll admission-refresh-sources . docs/internal/releases/admission/infisical.json
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll admission-refresh-sources . docs/internal/releases/admission/azure-key-vault.json
```

The command compares the existing operation inventory with both provider
assemblies' compiled public remote members before writing. Missing or linked
sources and foreign inventory paths fail. It independently discovers handwritten
sources, excluding `bin` and `obj`, and updates only source paths and digests.
Operation identities, variants, required cases, prerequisites and exclusions
remain unchanged. A new remote member requires a separately reviewed admission
change; stale assemblies cannot establish coverage of an unbuilt source change.
Run the independent `AdmissionTests` after refresh. This operation establishes
local source consistency, without granting native qualification.

Admission requires a supported published public contract, compatible provenance, explicit authority/effects, testable semantics, a named maintenance owner and a current product use case. Private/undocumented contracts, adjacent products and unapproved previews remain excluded. The earlier public-API-complete first-release default is superseded by the accepted product scope, not a requirement to restore the catalog.

A populated per-operation registry would be a separate required artifact before credible estimates or completion claims. Neither this prose nor R4's cohort inventory is that registry. Each row would require:

| Required evidence | Proposed row meaning |
| --- | --- |
| Operation identity and owner | Stable independently designed identity; package/native module; accountable maintainer |
| Supported contract | Official functional source, access date, chosen API family/revision, replacement decision and supported deployment boundary |
| Permissions | Identity/credential source, resource/plane, scope and entitlement prerequisites; unknown explicitly retained |
| Effects | Read versus issuance/mutation/destruction, import/replication/approval effects, sensitivity, preconditions, concurrency and replay guarantees |
| Outcomes and observations | Applied/pending/rejected/unknown mapping, actual provider handles if available, supported reconciliation and completeness/collection limits |
| Evidence | Implementation status, deterministic test mapping, focused real-provider receipts, compatibility matrix and installed-package evidence |

Registry population must not turn documentation-page or method/path counts into implemented operation counts. The frozen `infisical-operations.json` is `ContractResearchOnly`, not current admission. The basic management inventory has 122 research rows / 121 callable projections in five families and no connector families; it does not enumerate all retained administration. Typed configuration and effect mapping remain required for retained native features; a catch-all JSON dictionary, raw request gateway or unavailable stub does not count as support.

An admission decision would not prove a deployed provider supports the operation. Permissions and editions would remain scoped observations, and live conformance would remain a separate gate. Unknown required semantics would fail closed, while the registry retained the reason and the evidence needed to resolve it.

## Coverage And Compatibility Boundaries

The retained Infisical boundary includes supported secret reads, inventory, lifecycle, organization/imports, machine authentication, dynamic credentials, scoped access/governance, native SQL rotation configuration and runtime features, and existing gateway/proxy administration. Infisical.Management keeps selected administrative dependencies out of ordinary runtime access. The broad third-party connection/sync catalog is excluded; broader optional integration administration could be legitimate under a future explicit product decision.

The proposed Azure boundary would include secret data-plane families and optional scoped vault, RBAC/access-policy, diagnostics and audit administration. Keys, certificates, Managed HSM, broad directory/subscription management and unrelated vendor products would remain outside scope. A secret data-plane client would not become a rotation automation platform.

Breadth would measure covered admitted operation families/variants; depth would measure each family's lifecycle, authorization, uncertainty, versioning and failure semantics. Neither would initially be verified. Provider version, edition, endpoint/region, API family, Azure cloud/audience, SDK version and principal scope would all require declared compatibility evidence.

The implementation would choose a supported protocol independently for each provider family. An older provider protocol could be legitimate if it remained supported and was explicitly admitted for a declared deployment. That would not be a SecretKit public API compatibility shim. No silent API downgrade, alternate endpoint, fallback identity or replacement of required semantics would occur when a deployment lacked support.

Missing UI-feature programmable contracts would remain future vendor gates, with no no-op module. This would not exclude effects already documented on admitted operations. In particular, import creation, requested replication and destination pending/applied/unknown states would require registry and result mappings even if approval administration itself remained gated.

## Proposed Dependency-Ordered Delivery

These are historical broader intended outcomes, not the current local-readiness
phase sequence or authorization to implement. Follow the
[current local contract](INFISICAL_LOCAL_READINESS.md) for the immediate goal.

| Sequence | Proposed result and exit evidence |
| --- | --- |
| Documentation foundation first | Canonical internal/public contracts, ADR, ownership and admission policy; populate the operation registry before estimates or completion claims; reconcile parent-owned plan/review/I-VSD mappings |
| Dual-provider minimal reads | Dependency-free Core plus both Infisical and Azure minimal readers/inventory; reference/material/outcome ownership; justified transport choice; explicit identity and version/collection evidence |
| Both workflows and installed-package pilot | Standalone Event-like runtime and Configurator-like inspection/review workflows consuming packed prerelease packages, not project references; focused real-provider risk evidence early |
| Safe writes, imports, snapshots and auth lifecycle | Native mutation/precondition contracts, pre-dispatch receipts, import approval effects, coherent acquired generations, explicit string export, optional host-started maintenance and recovery boundaries |
| Retained administration and native features | Selected project/identity/access administration, native SQL rotation configuration/runtime features and gateway/proxy administration; no broad third-party connection/sync catalog |
| Final declared coverage/provider/install/publish gate | Full declared operation and compatibility evidence, provider conformance, installed-package matrix, package provenance and protected publication readiness |

The early pilot would test whether the SDK is useful before the large administrative investment. Both workflows would be mandatory evidence, not an Event-only smoke sample followed by a Configurator example at the end. No Event or Configurator source, packages, migrations or documentation would change in these examples.

Focused real-provider risk tests would begin in that early pilot against existing authorized isolated sandboxes. Initial read/auth risks would include intended-identity access, self-hosted/FFI behavior relevant to transport selection, version selection, endpoint/challenge security and telemetry leakage. As mutations were added, focused risks would include committed/lost-response version creation, cancellation receipts, import pending/application distinctions and renewal using constrained bootstrap credentials. These would run when the corresponding behavior existed, not attempt to test unimplemented features or defer all remote evidence to publication.

Missing sandbox authority, credentials, edition entitlements or observable provider states would remain explicit open gates. The workstream would not create Docker environments, browsers, application orchestration, new vendor runtimes or provisioning platforms to hide that absence. Evidence could not be replaced by success from an unrelated administrator identity.

## Proportionate Verification

The user's verification override replaces a blanket prohibition on intermediate live tests and an exactly-one-build rule. Affected deterministic and focused real-provider checks would run when needed and repeat only after a change, failure or open risk justified them. Passing unchanged evidence would be retained. No broad intermediate sweep, unrelated suite, Docker, browser or new orchestration would be introduced.

Proposed checks would exercise observable invariants through actual adapter seams: independent material copies, retired-generation draining, coherent local multi-key reads, OCE with caller-held receipts, no mutation replay, bounded bulk partial outcomes, intended-identity separation and unsafe upstream diagnostics rejection. Fake time and subscribed event barriers would establish asynchronous state transitions before triggering them; fixed sleeps and source-text tests would not qualify.

Real-provider evidence would distinguish supported observations from inferred outcomes. A lost-response test would inspect resulting provider state where possible, not merely assert a mock call count. Import tests would examine destination approval/application evidence independently of import creation. Authentication tests would exercise maximum lifetime, consumed bootstrap and restart recovery boundaries.

The final gate would cover the full declared provider/operation/install matrix once the implementation was complete, with reruns only for changes, failures or unresolved risk. Actual commands, versions, environment scope, outcomes and unavailable checks would be recorded by the executor. No command in this proposal has been run as a product build or test.

## Value, Baseline And Conformance Kit

The proposed early value assessment would compare both installed-package workflows with direct supported provider usage for equivalent tasks. It would record dependency footprint, setup/credential steps, consumer code and duplicated safety logic, latency/request overhead, cancellation/uncertainty handling and operator comprehension of partial results. The direct-provider baseline would use independently authored functional scenarios, not imported vendor source. No unmeasured reduction or performance claim would be made.

A proposed conformance kit would provide reusable deterministic contract cases plus explicitly authorized remote scenarios keyed to registry rows. It would identify provider/API/edition/cloud combinations, permissions, sensitivity, receipt/outcome expectations and evidence limits. Adopters could reproduce a compatibility claim without assuming every provider deployment behaved identically. The kit would not embed credentials or turn provider integration into a new orchestration product.

Prerelease pilots could establish value before complete breadth. Their artifacts and claims would be labeled prerelease and incomplete, never marketed as the final complete release. Any full-release claim must satisfy the explicitly selected current scope and its declared depth/evidence, not every row of a historical research catalog.

## Dependency, Provenance And Licensing

### Connected dependency advisory gate

Root policy explicitly enables `NuGetAudit`, selects `NuGetAuditMode=all` and
`NuGetAuditLevel=low`, and names nuget.org under `NuGet.Config` `auditSources`.
Warnings remain errors. This is independent of intentional offline package
consistency restores: their existing `NuGetAudit=false` does not establish
connected advisory clearance.

From the repository root, use the fixed Release command with a fresh output
directory for each selected graph:

```sh
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit SecretKit.slnx artifacts/audit-source-main
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit SecretKit.Conformance.slnx artifacts/audit-source-conformance
```

Solution targets perform a connected locked restore with explicit audit settings,
then native resolved-package and vulnerable-package JSON reporting, both including
transitive packages. The pinned SDK is retained; no dependency is upgraded.
Installed audits select the actual isolated `project.assets.json`, not a
project's default `obj` directory. `dependency-audit-installed <assets> <fresh-output>`
retains the original project, intermediate path, package cache, mode and resolved
candidate version, then reports with `--no-restore`. It does not rewrite
installation evidence or restore from another feed/cache. Required assets and
enabled lockfiles must exist. Installation and connected source-restore results
remain separate gates.

The source callable contract is `DependencyAudit.RunAsync(source, target, output)`;
installed callers use `RunInstalledAsync(source, assets, output)`.
It returns zero only for the recorded selected graph after both native execution
and report policy pass. The parent verifier must require both source solutions
and every exact installed graph selected by its installation owners. One
successful target is not aggregate clearance. Preserve failure exits; never
translate an audit failure into package qualification success.

The complete local post-pack runner records every successful real consumer
restore under the selected observation directory's `graphs/`, with exclusive
creation and exact project/assets/lock hashes. Synthetic verifier fixtures are
not native graph records. Use an explicit fresh observation directory:

```sh
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack"
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll dependency-audit-installed-set "$PWD/artifacts/local-cohort" "$PWD/artifacts/verification/post-pack" "$PWD/artifacts/verification/advisories/installed"
```

Successful installation verifiers write separate exclusive graph and installation
receipts. After all post-pack lanes pass, the runner finalizes
`installed-graphs.json`, binding the complete receipt/graph set to cohort and
platform. Removing a graph, its receipt, or both cannot silently narrow selection.

The set command reopens all selected graph bytes and the complete hardening/
platform observations against the original cohort, audits every recorded graph,
and writes `installed-set.json` plus native reports. Source and installed audits
are mandatory executable steps in the producer graph; missing data or failure
blocks the owning job and candidate assembly.

Native CLI zero alone is insufficient. The validator checks native v1 report
shape, source identity, exact project coverage, framework/package/version binding
to the full resolved report, and known severity. Missing, malformed, duplicate,
unavailable, filtered or inconsistent evidence fails. Any reported advisory,
including low severity, blocks clearance. Native child failure, nonempty native
stderr and a changed source or graph also block clearance.

The initially empty
[`dependency-advisory-exceptions.json`](dependency-advisory-exceptions.json)
contains schema version 1 and an `exceptions` array. Each entry requires exact
`project`, `framework`, `package`, `version`, `advisory`, plus nonempty `owner`,
`rationale`, `evidence`, and an `expiresAt` timestamp strictly in the future and
ending in `Z`. Project paths resolve against the source root. Wildcards,
duplicates, expired, unowned, unused and mismatched entries fail. Package IDs
compare case-insensitively; versions and advisory URLs match exactly. One advisory
shared by another package or project receives no inherited acceptance.

These entries record reviewed risk only. Even a valid matching entry does not
clear a vulnerable report or a failed native child. No `NuGetAuditSuppress`,
`NoWarn`, warning demotion or suppression bridge is generated. A release waiver
would require a separate explicit policy decision.

Each output preserves native stdout/stderr and exits, selected arguments,
actual SDK, UTC observation time, audit-source identity, source-content snapshot,
registry digest, and before/after project/assets/lock digests. `audit.json`
records the decision. Outputs use exclusive creation and are never overwritten.
The observation applies only to those graph bytes and time. Auditing historical
installed graphs does not qualify later source changes or the final cohort;
the final installation owners must supply and audit their new exact graphs.

Core would remain dependency-free; optional package installation would avoid forcing unnecessary providers or administrative SDKs. Reuse would prefer suitable supported SDKs after exact direct/transitive version, license, notice, vulnerability and security-control review. Managed Infisical REST would need the coverage/FFI justification described in [architecture](SDK_ARCHITECTURE.md), not an assumption inherited from Event.

SecretKit's existing MIT licensing would remain the intended distribution basis. A copyright owner may license its own code under MIT or another license when it holds the relevant rights; contributor and third-party rights must still be reviewed. This is not a universal prohibition on reuse or dual licensing.

The source-free clean-room boundary is this project's chosen engineering policy. It does not assert that every similar SDK is legally required to use clean-room development. Event's AGPL label would not be blindly relabeled MIT, nor would an unsupported assertion of common ownership resolve all contributor/dependency rights.

Reuse or generation would require compatible approved source and rights review. Incompatible expressive schemas, vendor backend/SDK source, generated source summaries and implementation-derived structure would not enter this workstream. Public interoperability facts could inform intentionally designed contracts without copying schema organization, models, source, tests or prose. A public API specification being accessible would not establish permission to ingest its expressive contents.

The parent's warning that a Context7 Infisical query returned PKI and backend implementation snippets would be treated as inadmissible material, not sanitized by paraphrasing. This documentation uses bounded functional evidence only; it does not consume that output.

## Release And Maintenance Ownership

Before implementation estimates and release readiness, named people would be assigned these proposed responsibilities; role labels below are not completed appointments:

| Proposed owner | Accountability |
| --- | --- |
| Architecture/package maintainer | Core admission, package dependency/API boundaries, consumer value and compatibility policy |
| Provider maintainers | Per-family contract/version/edition/cloud evidence, typed variants, vendor-change monitoring and conformance |
| Security maintainer | Authority boundaries, leakage/receipt/retry reviews, vulnerability intake and incident/recovery guidance |
| Dependency/provenance maintainer | Resolved graph, notices, rights approvals, advisories and SDK upgrade evidence |
| Release maintainer | NuGet namespace/publisher rights, reproducible artifact claims, family manifest, protected CI/OIDC and install validation |
| Documentation maintainer | Internal/public contract parity and truthful support/unsupported states; coordinate parent-owned planning/review mappings |

Vendor changes would trigger scoped assessment of affected registry rows, compatibility and required tests. Silent downgrades or indefinite stale support claims would not be permitted. Security incidents would separate a package fix from authorization to change remote secrets or revoke provider credentials. Provider-side effects would not be undone by reverting code.

The proposed release would validate `net10.0` package applicability, API/dependency coherence, installability without Event/databases/ASP.NET and source/provenance metadata for all seven packages. Native AOT would remain an open unsupported claim until explicitly verified.

Protected NuGet trusted publishing would require verified namespace, repository, workflow, environment and owner rights. Fork/untrusted code would receive no publishing authority. Publication would require separate explicit authorization. A package family would not publish atomically: the immutable manifest would show completed/missing packages, and authorized resumption would publish only verified missing artifacts, not replace existing versions.

Deterministic assembly compilation would not by itself prove byte-identical `.nupkg` archives under .NET 10. Reproducibility claims would need actual unsigned-content/archive comparison and treatment of signing/provenance changes. Pre-v1 API redesign could remove bad contracts rather than ship speculative aliases; changes would still be documented for pilot adopters.

## Functional Sources And Current Limits

- [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing): identity-bound publishing proposal.
- [Package validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/package-validation/overview): package applicability/API consistency.
- [Deterministic packages](https://learn.microsoft.com/en-us/nuget/create-packages/deterministic-packages): do not import .NET 11 reproducibility defaults into unverified .NET 10 claims.
- [Infisical API overview](https://infisical.com/docs/api-reference/overview/introduction) and [authentication](https://infisical.com/docs/api-reference/overview/authentication): functional contract and auth-family boundaries.
- [Azure secret client](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.secretclient?view=azure-dotnet), [access planes](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide), [monitoring](https://learn.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault): data/management/audit distinctions.

These citations derive from R4's functional source register and the parent's explicit corrections. Live retrieval, refreshed compatibility, exact import-create source evidence, populated registry, named ownership, implementation, tests and publication remain outside this five-page task. Scoped local-link validation is the only completion evidence claimed here.
