# SecretKit SDK - Provider Responsibility Assessment

Last Updated: 2026-10-09 Europe/Brussels

## Review Metadata

- Mode: planning
- Subject: SecretKit unified .NET secret-management SDK
- Workstream: secretkit-sdk
- Report kind: implementation-planning assessment
- Report status: current
- Disposition: plan-aligned
- Evidence cutoff: 2026-10-08
- Reviewed input: SecretKit SDK evidence/design revision R5 and persistent documentation; final mapping audit passed
- Supersedes: none

## Executive Summary

SecretKit will let application developers use a small shared contract for ordinary secret access while retaining advanced provider capabilities through typed modules. Its first release is limited to complete secret-management coverage for Infisical and Azure Key Vault. Making capability limits visible protects operators from assuming that a successful inventory proves delivery, that an approved write has already taken effect, or that every provider offers conditional writes, leases and rotation.

The most consequential risks are disclosure through .NET object formatting and diagnostics, mixing credentials between provider instances, replaying uncertain mutations, and overstating feature/security coverage. The design must isolate identities and scopes, keep values out of ordinary output, distinguish side effects from reads, and report partial or uncertain outcomes accurately. Those obligations apply to other companies as well as ISLAMU consumers.

Event and Configurator remain evidence/requirements sources only. R5 adds early standalone samples and durable design documentation without implementing either consumer's activation, tenant policy or deployment. Actual migration/restart-policy removal still needs released SDK evidence and separate authorization.

R5 puts adoption and operational reliability ahead of inventory volume: documentation first, minimal dual-provider reads, both installed-consumer pilots, safe changes/generations/maintenance, then comprehensive depth. Focused authorized provider checks occur early; implemented coverage is distinct from verified compatibility and public adoption.

The user explicitly authorized official-source fallback after the MCP failure. The contract-boundary question then timed out, and the user directed completion on best judgment. R4 explicitly adopts the recommended public-API-complete first release with later supported vendor-contract admission. This is an agent default, not a user-confirmed feature selection. The current plan-aligned disposition reflects the aligned responsibility/mitigation design; it does not establish deployed security, stakeholder acceptance or certification.

## Scope

Provider-controlled SDK design, public capability claims, credential/value handling, endpoint trust, package distribution, documentation and extension governance. The first release includes admitted current public secret-management APIs and prerequisite administration. Product features without established supported programmable contracts are explicitly unavailable to the SDK and require later vendor-contract admission; they are not counted as first-release support. Adjacent products and additional providers remain excluded.

## Claim Boundary

This is I-VSD design reasoning about maintainer responsibility, not a religious-legal ruling, security certification, legal opinion, or guarantee of perfect secrecy. Owned buffer erasure cannot erase strings retained by a provider SDK or the .NET runtime. No test execution, real-provider audit, paid-feature entitlement validation, publishing-account ownership or stakeholder study is asserted.

## Findings

### IVSD-F001: Plaintext Must Not Escape Through Ordinary Developer Output

Applications entrust the SDK with credentials whose exposure can compromise other people's data and infrastructure. Event's existing public positional `SecretValue` record illustrates why reusing convenient value types without reviewing generated formatting is unsafe for a public library. Provider errors, structured logs, debugger displays, JSON serializers and tracing can expose values or sensitive coordinates even when application code never deliberately prints them.

**IVSD-M001** requires separate metadata and material, explicitly redacted formatting and serialization, explicit reveal/export operations, buffer disposal, and redaction tests through public seams. Logging must record bounded operation/outcome codes, not request/response bodies, secret names, paths, tokens or raw exceptions. This adds deliberate access steps but prevents accidental disclosure in routine support and automation. It does not promise zeroization of provider-created managed strings.

Provider SDK logging/content logging/distributed tracing must also be configured not to expose coordinates; redacting only SecretKit's own logger is insufficient. Host-enabled HTTP/credential instrumentation and explicit material reveal remain documented host responsibilities, not a process-wide secrecy guarantee.

IConfiguration integration deliberately exports plaintext strings. The host must opt in and own debugging, options serialization, logs and string lifetime; wrapper safety does not survive that export. Independent caller-owned material copies prevent one caller's disposal clearing another's data. A logical operation acquires one immutable local generation; remote versions/collection windows are evidence, not a manufactured transaction.

- Lifecycle / severity: open / critical design risk
- Claim type / validation: source-supported risk and proposed design mitigation; source traceability only
- Principles / domains: Amanah, La Darar, Tajassus / technical, operational, design
- Stakeholders / controlled decision: developers, operators and people whose data credentials protect / SDK material types and diagnostics defaults
- Evidence: L06, L08, W07-W08, W24
- Owner / next validation: core/provider/config maintainers; S02-S03/S13, tasks 1.3 and 3.1-3.2, native diagnostic tests
- Escalation: confidentiality failure blocks package release

### IVSD-F002: One Organization's Identity Must Not Authorize Another's Request

A reusable SDK will serve many vaults, projects, environments and companies in one process. A global token or cache entry keyed only by a secret name can cross those boundaries. Administrative discovery also cannot establish that a different runtime identity has access. Silent credential-chain or provider fallback can turn a denied request into an unintended successful read.

**IVSD-M002** requires explicitly constructed provider instances, identity-qualified tokens/cache keys, trusted endpoint binding, independent runtime-identity probes, and no automatic cross-provider or principal fallback. The remote provider remains the authorization authority; an SDK capability descriptor is not an authorization grant. The trade-off is explicit client construction instead of convenience defaults that conceal the active identity.

Periodic authentication adds a concrete recovery boundary: if a host misses renewal after consuming a one-use bootstrap credential, repeatedly attempting login cannot restore legitimate authority. The host must receive an explicit maintenance requirement and a recovery-required outcome. Do not market periodic tokens as eliminating every bootstrap/recovery duty or assume a fixed token lifetime from documentation examples.

- Lifecycle / severity: open / critical design risk
- Claim type / validation: source/documentation-supported design requirement; no concurrency proof yet
- Principles / domains: Amanah, Adl, La Darar / technical and operational
- Stakeholders / controlled decision: organizations and application owners / instance, endpoint, credential and cache isolation
- Evidence: L02-L03, L10-L11, W02, W10, W14-W15
- Owner / next validation: authentication/core maintainers; S04-S05/S15, tasks 1.4, 2.1-2.3, 5.3, 6.1-6.2
- Escalation: cross-identity access or endpoint credential leakage blocks release

### IVSD-F003: “Complete Support” Needs An Auditable Definition

A CRUD wrapper can be useful but would not fulfill the requested SDK. Conversely, a single universal interface can falsely imply that Azure offers Infisical imports, dynamic leases or approvals. Edition limits and runtime permissions further restrict what an installed adapter can do. Infisical's page counts include deprecated and adjacent material; counting pages would inflate coverage.

**IVSD-M003** requires a versioned operation inventory, typed native modules for unequal features, explicit support/entitlement/permission evidence, and an implementation/test mapping for every admitted stable operation. Unsupported features must be visible before side effects, and unknown permission must not be presented as permission denied or granted. Claims are bounded to the declared provider/API snapshot, not all future releases.

Complete official-source research identified product features whose supported public programmable contracts were not established in the checked reference/interface metadata. The explicit timeout default keeps those outside a public-API-complete first release and discloses ContractNotEstablished rather than pretend the provider lacks the product feature. One later-admission item requires a supported contract, provenance/edition/effect review and conformance. No stub module or complete-UI-product claim is allowed.

Admission policy/source cohort counts are not a populated registry. Each admitted operation needs an owner, supported contract, permission/effect and actual verification evidence before estimates/completion. Provider breadth/depth and tested server/edition/API/cloud/platform compatibility remain distinct. The direct-provider/config/Dapr/agent baseline and external adoption hypothesis require measurement, not novelty or superiority claims.

- Lifecycle / severity: accepted for planning, implementation pending / high design and claim risk
- Claim type / validation: proposed claim governance; provider index evidence is preliminary
- Principles / domains: Sidq, promise-keeping, avoiding deception and Gharar / strategic, governance, evaluation
- Stakeholders / controlled decision: adopting companies, maintainers and operators / coverage claims and extension contract
- Evidence: W01-W10, W19-W20, L01, L10
- Owner / next validation: provider/product maintainers; S01/S07/S17, tasks 1.2, 5.2, 6.3, 8.1-8.3, 9.1-9.2
- Escalation: supported contracts before future feature admission; unclassified/unimplemented admitted operations block release

### IVSD-F004: Uncertain Or Approved Writes Are Not Completed Writes

Operators need to know whether infrastructure was actually changed. A transport timeout after acceptance can leave the outcome unknown; automatically replaying a write can create another version, lease or credential. Approval workflows may return a pending change instead of applying it. Read-then-write checks cannot invent a provider transaction or compare-and-swap guarantee.

**IVSD-M004** requires distinct applied, pending approval, conflict, rejected and outcome-unknown results; provider-native preconditions where available; no unconditional replay of side-effecting requests; explicit destructive operations; and per-operation partial results. Reconciliation and approval UX remain consumer-owned. This avoids false success but requires callers to handle uncertainty and recovery deliberately.

An approved vote is not a merged/applied secret change; that state/exception contract is mandatory for future approval-feature admission, not claimed first-release Infisical implementation. Azure mutation pipelines must disable automatic SDK retries; exercise committed state plus lost response through the real adapter/SDK boundary rather than prove only that a mock was called once.

A caller-held receipt exists before dispatch. Cancellation remains cancellation, but a sent operation's receipt records known/unknown effect; a local ID is neither idempotency nor a remote query handle. Admitted import replication can create destination approval requests even without approval-administration support: resource creation, requested replication and pending/applied/unknown destination evidence are separate. Bounded bulk concurrency and per-item receipts avoid unsafe fan-out/replay.

- Lifecycle / severity: open / critical operational risk
- Claim type / validation: documentation-supported design mitigation; remote behavior not exercised
- Principles / domains: Amanah, La Darar, Sidq / technical, design and operational
- Stakeholders / controlled decision: deployment operators / mutation, retry and result contracts
- Evidence: L10, W04, W08-W09, W20, W24
- Owner / next validation: mutation maintainers; S03/S06-S07/S16, tasks 3.3-3.5, 5.2 and 7.2
- Escalation: unsafe replay or false atomicity blocks release

### IVSD-F005: Dynamic Acquisition And Rotation Need Explicit Lifetimes

Fetching dynamic credentials creates resources and obligations to renew or revoke them. Ordinary inventory must not acquire a lease. Static rotation can invalidate credentials immediately or overlap old/new values; local refresh does not establish application or fleet convergence.

**IVSD-M005** requires separate inspect/acquire/renew/revoke APIs, identity-bound lease handles, explicit expiry and uncertainty states, deterministic clock/event-based tests, and documented caller responsibility for delivery and lifecycle scheduling. Rotation administration reports provider progress only. A hidden scheduler or general cache must not renew, reuse or revoke credentials behind the caller's back.

The optional host-owned authentication helper is explicitly started, narrowly scoped and observable; Core still starts no worker. It renews during idle periods, cancels on shutdown and reports consumed-bootstrap restart recovery rather than persist plaintext tokens or choose another identity. Force-fresh Check again/Enable observes the actual selected path. Consumer revision/client/replica coordination remains outside SDK.

- Lifecycle / severity: open / high operational and security risk
- Claim type / validation: preliminary official documentation and proposed state contract
- Principles / domains: La Darar, Amanah, Ihsan / technical and operational
- Stakeholders / controlled decision: application and infrastructure owners / lease/rotation APIs and lifecycle defaults
- Evidence: L04, W03-W04
- Owner / next validation: lifecycle maintainers; S08-S09/S14-S15, tasks 4.1-4.5 and 7.2-7.3
- Escalation: inability to distinguish lease side effects or uncertain revocation blocks release

### IVSD-F006: Portability Must Respect Ownership And Provider Limits

SecretKit's existing license is MIT; Event's public licensing and contributor provenance are different. Relabeling Event source as MIT without rights review would burden downstream adopters. Provider backups can also be provider- or scope-bound rather than portable export formats. A public abstraction must not imply that provider snapshots restore across companies or clouds.

**IVSD-M006** preserves SecretKit's current license, independently authors the new SDK from permitted functional evidence, and requires file-level rights review before any future direct extraction. Dependencies retain their notices and terms. Export/backup APIs explicitly classify sensitive artifacts, scope restrictions and unsupported transformations; no automatic cross-provider migration or cryptographic-key regeneration is promised.

That clean-room policy is not a universal assertion that a copyright holder cannot license owned work differently. File-level contributor/third-party rights and project approval govern possible reuse. Compatible approved wire-model inputs may justify internal generation; no incompatible source/schema ingestion or blind relicensing is authorized. Public contracts are deliberately designed.

- Lifecycle / severity: open / high rights and portability risk
- Claim type / validation: observed repository license and proposed provenance controls; no legal determination
- Principles / domains: rights of people, promise-keeping, Sidq / governance and strategic
- Stakeholders / controlled decision: contributors and adopting companies / source provenance, licensing and portability claims
- Evidence: SecretKit LICENSE, L01-L03, L10, W07-W08; Event IP governance
- Owner / next validation: project steward/release maintainer; S10/S17, tasks 0.1, 1.1, 8.2, 9.3-9.5
- Escalation: uncertain source rights or incompatible dependency terms require steward/legal resolution before incorporation

### IVSD-F007: Publication Credentials And Artifact Claims Must Be Verifiable

A security SDK creates concentrated supply-chain trust. CI that exposes publishing credentials to pull requests, rebuilds different artifacts for publication, or leaves a half-published family unlabeled can undermine every adopting application. Deterministic assembly settings alone do not prove byte-identical package archives.

**IVSD-M007** requires locked dependencies, vulnerable-package/license review, package metadata and binary contract checks, protected OIDC publishing, staged exact-artifact promotion, checksums and honest partial-publication recovery. Maintainers must verify package namespace ownership and actual publisher identity. SecretKit's release process is new, so these are planned obligations rather than claims about existing automation.

- Lifecycle / severity: open / high supply-chain risk
- Claim type / validation: preliminary official publication documentation and proposed controls
- Principles / domains: Amanah, Ihsan, Sidq / governance, operational and evaluation
- Stakeholders / controlled decision: adopting companies / release identity, artifacts and notices
- Evidence: W11-W13; inspected empty SecretKit release surface
- Owner / next validation: release maintainer; S11/S16-S17, tasks 1.5, 2.4 and 9.1-9.6
- Escalation: publisher ownership, artifact provenance and authorization are publication gates

### IVSD-F008: A Library Workstream Must Not Change Its Consumers Prematurely

The user explicitly wants Event to keep working with its current secrets projects until SecretKit is released. Extracting files, changing references, maintaining source parity, or quietly adding Configurator provider behavior would violate that boundary and could disrupt unrelated active work.

**IVSD-M008** confines product implementation, tests, samples and documentation to SecretKit. Future-consumer samples model the required workflows without referencing or writing those repositories. Later migration is an actionable standalone backlog item with a release trigger, not a hidden mandatory phase here.

- Lifecycle / severity: accepted / high scope and reliability concern
- Claim type / validation: explicit user direction and inspected worktree states
- Principles / domains: Amanah, promise-keeping, La Darar / governance and operational
- Stakeholders / controlled decision: Event/Configurator maintainers / write paths and migration sequencing
- Evidence: user scope correction on 2026-10-08, L10-L13
- Owner / next validation: implementing agent; S12/S15, tasks 2.1-2.4, 4.4-4.5 and 9.5
- Escalation: any proposed consumer edit requires a separately authorized post-release workstream

## Recommendations

Use a small core, narrow capabilities and independently authored provider-native modules. Keep separate Azure data-plane and optional management-plane packages so ordinary applications do not inherit administrative dependencies. Prefer the official Azure SDK and an owned managed REST adapter for Infisical, pending research verification, rather than importing Event's two Infisical transports.

Reject the lowest-common-denominator design because it loses required features, and reject a universal security-platform interface because the user excluded adjacent products. Reject implicit identity/provider fallback, global secret caches, serialized plaintext results, fake conditional writes and source parity. A raw “execute arbitrary provider request” escape hatch is not complete typed support.

## Stakeholders

Application developers, operators, infrastructure/security teams, ISLAMU maintainers, other adopting companies, contributors, and people whose information is protected by the credentials. Provider vendors own service authorization, entitlements and remote behavior; consumers own application policy, approvals, delivery and scheduling; SecretKit maintainers own truthful mapping and secure SDK behavior.

## I-VSD Principles And Domains

Amanah applies to custody of credentials and administrative power. Sidq and promise-keeping apply to capability/release claims. La Darar applies to destructive automation and leakage. Rights of people apply to provenance and organizational isolation. Tajassus applies to minimal diagnostics. Ihsan applies to maintainable, tested contracts. All six review domains are relevant at the responsibility level. Payments, riba, content moderation, ranking and religious-content decisions are not part of this SDK.

## Validation Gaps

No runtime implementation, live paid-feature tests, stakeholder interviews, independent security assessment, incident data, or package publication evidence exists. The graph and requested research MCP servers are unavailable. The next validation is source revalidation and design mapping, followed by invariant-breaker tests and provider conformance during implementation.

## Escalation Needed

Official-source fallback and the explicit timeout admission default resolve planning intake. Supported vendor contracts are required before future gated-feature admission; license/name/publisher ownership must be resolved before incorporation/publication. There is no religious-legal question requiring a scholarly ruling in the current technical scope. Escalate if later governance/business terms introduce one.

## Evidence Reviewed

The persistent `docs/internal/RESEARCH_EVIDENCE.md`, `REVIEW_TRACEABILITY.md`, runtime/architecture/delivery guides and source-free active packet/inventory ground R5. Restored MCP results are distinguished from empty, irrelevant and 429-throttled responses; vendor implementation material is excluded. Primary published import/configuration/lifecycle facts and the user's CTO review ground the new contracts. No consumer/runtime operation was audited by implication.

## Missing Evidence

Supported contracts before future gated-feature admission, actual resolved transitive dependency/license approval, runtime security/concurrency/conformance results, NuGet account/prefix ownership and stakeholder/operational validation. Successful MCP results are unavailable and no longer required under fallback authorization. The timeout default must not be portrayed as affirmative stakeholder validation.

## Context Inventory

SecretKit is an empty MIT repository. Event has working source and existing tests, not a portable package boundary. Configurator has local configuration capabilities and a future provider-integration vision. Its provider connectors were not found in the bounded source inspection. No consumer changes are authorized.

## Common Overlooked Failures And Outcomes

Metadata listing that reveals names/tags; admin visibility confused with runtime access; stale tokens shared across identities; stale snapshots presented as live; recursive/import semantics changed by API version; acquisition during inspection; duplicate leases after timeout; approval requests reported as applied; expiry treated as server denial; fake Azure compare-and-swap; missing notices; partial NuGet publication; and later migrations started before the release trigger.

## Review Lifecycle

| Date | Previous status | New status | Trigger | Evidence |
| --- | --- | --- | --- | --- |
| 2026-10-08 | none | draft / changes-required | Repository research and user scope decisions; mandatory MCP research unavailable | Evidence/design R1 |
| 2026-10-08 | draft / changes-required | draft / changes-required | Auth lifetime/recovery, throttling, pagination and .NET 10 test-selection evidence strengthened; alternate requested-tool routes still unavailable | Evidence/design R2 |
| 2026-10-08 | draft / changes-required | draft / changes-required | Official-source fallback authorized; complete source boundaries, missing programmable contracts and native SDK controls identified; release-boundary choice pending | Evidence/design R3 |
| 2026-10-08 | draft / changes-required | current / plan-aligned | Question timed out; user directed completion on best judgment; explicit public-API-first default aligned with phases, claims and future admission | Evidence/design R4 |
| 2026-10-09 | current / plan-aligned R4 | current / plan-aligned R5 | CTO contract/value/runtime review incorporated; durable docs, seven packages, documentation-first/early evidence and final mapping audit | Evidence/design R5; documentation evidence only |

## Planning Handoff

- Workstream: secretkit-sdk
- Status: current / plan-aligned
- Reviewed input: SecretKit SDK plan/task/context and persistent documentation revision R5
- Findings and mitigations: IVSD-F001 through IVSD-F008 paired with IVSD-M001 through IVSD-M008
- Required plan mappings: Section 9 must retain every pair's scenarios and owning tasks
- Escalations required before: future vendor-contract feature admission; source incorporation for rights; implementation approval; release/publication for conformance and publisher controls
- Refresh triggers: provider/product scope, identity fallback, material/cache/telemetry policy, lease or retry semantics, licensing, release controls, consumer write scope, or mapped-task changes
