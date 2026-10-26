# SecretKit internal documentation

> **Audience:** SDK contributors, maintainers and evidence reviewers
> **Status:** Current contracts and implemented subsets; historical research is separate
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 (local source/documentation review only)
> **Source anchors:** [Contributor contract](../../AGENTS.md),
> [project map](../../PROJECTS.md), [current support](../public/provider-support.md)

SecretKit implements seven .NET 10 packages for common reads, typed Infisical/Azure
subsets and optional configuration/hosting. It is **in development, unpublished
and not ready for production**. The immediate workstream prioritizes Infisical
local evaluation without public publication or Event integration; retained
Azure/management work is not removed or relabeled.

## Read by task

Public task guides explain use; internal contracts govern design and evidence.
Start with [current preview](../public/current-preview.md) and
[provider support](../public/provider-support.md) before interpreting a design
requirement or historical registry as completed support.

| Public task | Guide |
| --- | --- |
| Install exact packages and perform a first read | [Getting started](../public/getting-started.md), [local packages](../public/local-packages.md) |
| Understand common ownership/outcomes | [Core API](../public/core-api.md) |
| Select native provider capabilities | [Provider index](../public/providers/README.md), [Infisical](../public/providers/infisical.md), [Azure](../public/providers/azure-key-vault.md), [management](../public/providers/management.md) |
| Compose required generations and explicit export | [Configuration/runtime](../public/configuration-and-runtime.md) |
| Compose authentication and token maintenance | [Authentication/hosting](../public/authentication-and-hosting.md) |
| Run examples or diagnose outcomes | [Demos/recovery](../public/demos-and-recovery.md), [troubleshooting](../public/troubleshooting.md) |
| Decide whether to adopt | [Adoption/value](../public/adoption-and-value.md) |

## Current contracts and decisions

For documentation changes, use the
[documentation architecture and maintenance guide](DOCUMENTATION_GUIDE.md).
It owns page routing, source anchors, example conventions, validation and the
remaining generated-API/IntelliSense documentation boundary.

These documents retain their existing authority. Requirements are not evidence
of implementation or permission, and a contract may describe more than the
implemented subset.

| Document | Responsibility |
| --- | --- |
| [SDK architecture](SDK_ARCHITECTURE.md) | Seven packages, inward dependencies, narrow BCL-only Core and application boundaries |
| [Runtime contracts](RUNTIME_CONTRACTS.md) | Material, generations, receipts, cancellation, transports, authentication and bounded bulk operations |
| [Core scope/roadmap](CORE_SCOPE_AND_ROADMAP.md) | Core-first scope and deferred orchestration |
| [Infisical local readiness](INFISICAL_LOCAL_READINESS.md), [ADR-002](adr/ADR-002-infisical-local-qualification.md) | Accepted 2026-10-23 local direction and four-package qualification boundaries |
| [Runtime adoption security](RUNTIME_ADOPTION_SECURITY.md), [ADR-003](adr/ADR-003-runtime-adoption-security-evidence.md) | Installed apps, causal actor/effect proof, lifetime, cleanup and evidence requirements |
| [Local profile](local/infisical-runtime.json) | Exact local version, package IDs, selected members and S01-S16 denominator |
| [Delivery/maintenance](DELIVERY_AND_MAINTENANCE.md), [publication protocol](releases/PUBLICATION_PROTOCOL.md) | Release evidence and publication authority, distinct from local evaluation |
| [Provider admission](PROVIDER_ADMISSION.md), [onboarding](PROVIDER_ONBOARDING.md) | Demand, ownership, native semantics and repeatable provider contribution evidence |
| [Accepted catalog removal](../public/connector-scope-decision.md) | 2026-10-11 removal of broad third-party connection/sync administration; native SQL rotation and gateway/proxy subsets retained |

The four-package local profile does not replace the seven-package public release
family or authorize publication. Runtime and administrative credentials remain
explicitly selected. Host-owned transports, application validation/activation,
readiness, persistence and recovery do not become SDK orchestration.
Breaking development changes are permitted without compatibility aliases.

## Evidence and qualification

| Evidence location | What it establishes and what it does not |
| --- | --- |
| [Local-profile ledger](compatibility/infisical-local-profile.md) | Harness admission, exact source/profile/archive binding, separate functional/full native denominators and unavailable binding proofs; not a blanket native pass |
| [Dynamic lifecycle evidence](compatibility/dynamic-lifecycle-evidence.md) | Profile/credential/lease observations and remaining downstream-effect gates |
| [Rotation progress evidence](compatibility/rotation-progress-evidence.md) | Rotation contracts and observed versus unverified effects |
| [Development checkpoints](compatibility/development-checkpoints.md) | Preserved earlier preview/support narratives, exact historical counts/dates and run qualifications; no checks rerun during this rewrite |
| [Infisical conformance](../../tests/SecretKit.Infisical.Conformance.Tests/), [Azure conformance](../../tests/SecretKit.AzureKeyVault.Conformance.Tests/) | Nonpackable native harnesses and controlled collector tests; presence is not execution or provider qualification |
| [Package witnesses](../../tests/SecretKit.Package.Tests/), [demo tests](../../tests/SecretKit.Demo.Tests/) | Installed original-package and process/HTTP test surfaces, not live provider certification |

Keep proposed behavior, source implementation, controlled offline runs and owned
native effects separate. Settings readback is not logging/delivery proof;
administrative visibility is not intended-identity consumption. Denied,
unavailable, uncertain and missing-entitlement cases cannot be promoted to pass.
Historical Linux results do not establish refreshed archives or the full
platform/release matrix. Current gaps belong with the exact native evidence.

## Historical design and research

- [ADR-001](adr/ADR-001-capability-aware-secret-sdk.md) retains the original
  decision, alternatives and revisit triggers.
- [Research evidence](RESEARCH_EVIDENCE.md) preserves R4/R5 source provenance and
  research limitations. R5 superseded the five-package/speculative-capability/
  late-pilot parts of R4; later accepted scope/local-readiness decisions govern
  current delivery.
- [Review traceability](REVIEW_TRACEABILITY.md) retains the 79 requested items and
  evidence ownership, not current admission.
- [Provider research registries](providers/) include the frozen Infisical
  `ContractResearchOnly` inventory. Research rows and route counts do not promise
  complete implementation or revive removed connector families.

Do not rewrite historical research into current support claims. Use the
source-linked public family map for implementation and the exact compatibility
record for observations. Official references in historical research supply
interface provenance, not copied implementation or deployment qualification.
