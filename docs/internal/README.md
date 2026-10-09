# SecretKit Internal Design

> Audience: SDK contributors and maintainers
> Status: Proposed / unimplemented
> Owner: SecretKit maintainers
> Last Verified: 2026-10-09, local design evidence and documentation links only
> Source Anchors: [R4 evidence](../../dev/active/secretkit-sdk/research-evidence.md), [R4 inventory](../../dev/active/secretkit-sdk/provider-operation-inventory.md), [architecture](SDK_ARCHITECTURE.md), [runtime contracts](RUNTIME_CONTRACTS.md)

SecretKit is proposed as a reusable .NET secret-management SDK for Infisical and Azure Key Vault, with a small portable read boundary and legitimate typed provider-native features.

## Status And Authority

These pages describe intended behavior, not shipped packages, working security controls, verified provider compatibility, or approval to implement. R4's bounded research supplies historical observations; [R5 research evidence](RESEARCH_EVIDENCE.md) records refreshed tools, primary facts and source limits, and [review traceability](REVIEW_TRACEABILITY.md) maps all 79 items. Neither is a populated implementation registry or live conformance result. Official links preserve provenance, not remotely tested SDK behavior.

R5 supersedes the five-package/speculative-capability/late-pilot portions of R4. The single active triad, public/internal guides, research/review map and I-VSD assessment share the revised design. This alignment is documentation evidence, not implementation approval.

## Reading Map

| Page | Design responsibility |
| --- | --- |
| [SDK architecture](SDK_ARCHITECTURE.md) | Seven packages, dependency direction, narrow Core, native features, consumer boundaries |
| [Runtime contracts](RUNTIME_CONTRACTS.md) | Material ownership, generations, receipts, cancellation, authentication, transports, bulk operations |
| [Delivery and maintenance](DELIVERY_AND_MAINTENANCE.md) | Admission policy versus registry, early pilots, evidence gates, compatibility, release and ongoing ownership |
| [ADR-001](adr/ADR-001-capability-aware-secret-sdk.md) | Proposed decision, alternatives, consequences and revisit triggers |
| [Research evidence](RESEARCH_EVIDENCE.md) | Actual primary facts, MCP limitations and source boundary |
| [Review traceability](REVIEW_TRACEABILITY.md) | All 79 requested items and acceptance evidence ownership |

## Proposed Scope

The package family would contain exactly `SecretKit.Core`, `SecretKit.Infisical`, `SecretKit.Infisical.Management`, `SecretKit.AzureKeyVault`, `SecretKit.AzureKeyVault.Management`, `SecretKit.Extensions.Configuration`, and `SecretKit.Extensions.Hosting`. There would be no umbrella package requiring every provider and no application/database dependency in Core.

Core would use only the BCL and contain proven common read, inventory, reference, material and outcome semantics. Provider-native modules would retain useful semantics that are not portable. They would not be second-class escape hatches. No speculative `ISecretApprovalClient`, common backup, lease, rotation, or recovery API would be reserved in Core. Native features could be admitted when their supported contracts and evidence justify them.

The selected release scope would be the complete declared set of admitted public secret-management operations, not every vendor product or UI feature. Missing supported programmable contracts would remain explicit future vendor gates, with no stubs. The public-API-first boundary originated as the planner's default after a question timed out, not an affirmative user decision that the long-term full-feature goal should shrink.

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
