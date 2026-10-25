# SecretKit Internal Design

Current delivery priority: [core scope and deferred orchestration](CORE_SCOPE_AND_ROADMAP.md).

The accepted 2026-10-23 priority is
[Infisical-first local readiness](INFISICAL_LOCAL_READINESS.md), before public
publication and without an Event repository implementation phase. Retained
Azure/management work and its evidence are not removed or relabeled.

The [accepted 2026-10-11 scope decision](../public/connector-scope-decision.md)
has removed broad third-party app-connection/sync administration from local
source while retaining selected administration, native SQL rotation and
runtime features, and gateway/proxy administration. Local removal checks passed; live-provider and release gates remain separate. R4/R5 scope and research below are historical where superseded.

> Audience: SDK contributors and maintainers
> Status: Implemented SDK subsets; broader design and release evidence remain incomplete
> Owner: SecretKit maintainers
> Last Verified: 2026-10-12, local offline foundation; remote/release gates remain separate
> Source Anchors: [historical research](RESEARCH_EVIDENCE.md), [architecture](SDK_ARCHITECTURE.md), [runtime contracts](RUNTIME_CONTRACTS.md)

SecretKit implements a .NET SDK for Infisical and Azure Key Vault in documented
subsets. Start with [current support](../public/provider-support.md) for observed
behavior and limits, and [provider onboarding](PROVIDER_ONBOARDING.md) for the
repeatable contribution unit. Historical proposal sections below retain design
provenance rather than asserting that every feature is implemented or certified.

## Status And Authority

The architecture/runtime pages describe contracts and broader design; current
support records implemented and observed subsets. Neither grants remote authority
or establishes complete live compatibility. R4's bounded research and
[R5 research evidence](RESEARCH_EVIDENCE.md) are historical; the
[review traceability](REVIEW_TRACEABILITY.md) map is not current admission.
Official links preserve provenance, not remotely tested SDK behavior.

R5 supersedes the five-package/speculative-capability/late-pilot portions of R4.
Those historical planning claims do not establish the current local-readiness
implementation or approval. Tracked engineering contracts remain independent
of private task paths.

## Reading Map

The next increment is governed by the
[runtime adoption security contract](RUNTIME_ADOPTION_SECURITY.md) and
[ADR-003](adr/ADR-003-runtime-adoption-security-evidence.md). These distinguish
required new demos/proof producers from existing SDK implementation.

| Page | Design responsibility |
| --- | --- |
| [Infisical local readiness](INFISICAL_LOCAL_READINESS.md) | Current delivery direction, package profile, reusable behavior and acceptance boundaries |
| [SDK architecture](SDK_ARCHITECTURE.md) | Seven packages, dependency direction, narrow Core, native features, consumer boundaries |
| [Runtime contracts](RUNTIME_CONTRACTS.md) | Material ownership, generations, receipts, cancellation, authentication, transports, bulk operations |
| [Delivery and maintenance](DELIVERY_AND_MAINTENANCE.md) | Admission policy versus registry, early pilots, evidence gates, compatibility, release and ongoing ownership |
| [ADR-001](adr/ADR-001-capability-aware-secret-sdk.md) | Proposed decision, alternatives, consequences and revisit triggers |
| [Research evidence](RESEARCH_EVIDENCE.md) | Actual primary facts, MCP limitations and source boundary |
| [Review traceability](REVIEW_TRACEABILITY.md) | All 79 requested items and acceptance evidence ownership |

## Historical Design Scope

The package family would contain exactly `SecretKit.Core`, `SecretKit.Infisical`, `SecretKit.Infisical.Management`, `SecretKit.AzureKeyVault`, `SecretKit.AzureKeyVault.Management`, `SecretKit.Extensions.Configuration`, and `SecretKit.Extensions.Hosting`. There would be no umbrella package requiring every provider and no application/database dependency in Core.

Core would use only the BCL and contain proven common read, inventory, reference, material and outcome semantics. Provider-native modules would retain useful semantics that are not portable. They would not be second-class escape hatches. No speculative `ISecretApprovalClient`, common backup, lease, rotation, or recovery API would be reserved in Core. Native features could be admitted when their supported contracts and evidence justify them.

The earlier complete-admitted-API release goal is historical and superseded by the accepted two-provider/catalog-removal scope. The frozen Infisical inventory is `ContractResearchOnly`, not current product admission. Missing supported programmable contracts remain explicit gates, with no stubs; retained native feature depth still requires evidence.

Approval administration remaining outside an initial admission would not erase approval effects of admitted operations. Import-resource creation, replication requested, destination approval pending, destination applied and destination outcome unknown would be distinct observations. A returned import identifier would not certify destination material delivery.

## Trust And Consumer Boundaries

The proposed SDK would bind the caller's selected authority and preserve provider authorization. It would neither choose a fallback provider/identity nor decide application tenant authorization. A package split would organize dependencies, not enforce permission.

Event would continue to own desired and observed integration revisions, tenant boundaries, HAL action authorization, application validation, client handover, replica durable metadata and concurrent-disable rules. Configurator would own application definitions and operator review UX. SecretKit would provide fresh provider observations and scoped version/consistency evidence beneath those responsibilities. Early examples would be standalone SDK consumers inside SecretKit, not actual Event or Configurator migrations.

Disposable material would make access deliberate but would not promise elimination of all plaintext from a managed process. Independent caller-owned copies, immutable acquired generations and retirement rules are proposed in [runtime contracts](RUNTIME_CONTRACTS.md). Export to `IConfiguration` would intentionally create ordinary strings; debug views, options binding, logging and GC would then be separate exposure boundaries.

## Evidence And Open Gates

Provider breadth and depth, versions, editions, API families and cloud deployments would initially be unverified. Documentation page counts and observed method/path counts would not become completed operation counts. Required unknown semantics would fail closed; an unknown permission assessment would not become allowed. Remote observations would carry versions and collection windows rather than fabricated transactions.

Implementation readiness would require a populated operation registry with named owners, contracts, permissions, effects and evidence. Its policy alone would not support estimates or completion claims. Existing authorized isolated sandboxes would support focused early risk tests; missing authority or entitlement would remain an honest open gate, not cause new orchestration or a quiet downgrade.

This documentation task runs no build, tests, Docker, browser, provider mutation or publishing workflow. The proposed implementation verification sequence and limits are in [delivery and maintenance](DELIVERY_AND_MAINTENANCE.md).

## Functional Source Anchors

- [Infisical API overview](https://infisical.com/docs/api-reference/overview/introduction): independently versioned API families and endpoint selection.
- [Infisical references](https://infisical.com/docs/documentation/platform/secret-reference): provider-specific import and reference behavior.
- [Infisical approval workflows](https://infisical.com/docs/documentation/platform/secrets-mgmt/concepts/approval-workflows): approval and application are distinct.
- [Azure secret client](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/security.keyvault.secrets-readme?view=azure-dotnet): official client reuse and native secret lifecycle.
- [Azure access planes](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide): administrative and secret-data authority are distinct.

These are functional source citations, not permission to copy vendor source, expressive schemas or documentation prose.
