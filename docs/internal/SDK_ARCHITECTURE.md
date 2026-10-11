# SecretKit SDK Architecture

> Audience: SDK implementers, reviewers and future consumer integrators
> Status: Proposed / unimplemented
> Owner: SecretKit architecture maintainer
> Last Verified: 2026-10-09, bounded design evidence and local links only
> Source Anchors: [internal overview](README.md), [historical research](RESEARCH_EVIDENCE.md), [runtime contracts](RUNTIME_CONTRACTS.md), [ADR-001](adr/ADR-001-capability-aware-secret-sdk.md)

This proposal separates a proven portable read contract from provider-native functionality, configuration export and optional host lifecycle.

Current scope follows the [accepted catalog-removal decision](../public/connector-scope-decision.md).
Broad third-party app-connection/sync administration is removed from local
source, not a future completeness requirement. Native SQL rotation configuration
and runtime features, selected administration and existing gateway/proxy
administration remain; local post-removal verification passed. Other proposed
behavior below is design, not post-removal verification.

## Seven Packages And Dependency Direction

| Proposed package | Responsibility | Proposed dependency boundary |
| --- | --- | --- |
| `SecretKit.Core` | Common reads and metadata inventory; authority-bound references, material and outcomes | BCL only; no external runtime dependencies |
| `SecretKit.Infisical` | Secret access, reference semantics and admitted native secret lifecycle/authentication features | Core; approved provider SDK or justified managed transport |
| `SecretKit.Infisical.Management` | Selected identity/project/access/governance administration, native SQL rotation configuration and existing gateway/proxy administration; no third-party connection/sync catalog | Core; Infisical adapter where needed; approved dependencies only |
| `SecretKit.AzureKeyVault` | Key Vault secret data plane and admitted native version/lifecycle features | Core; approved `Azure.Security.KeyVault.Secrets` and Azure.Core dependencies |
| `SecretKit.AzureKeyVault.Management` | Scoped vault administration, RBAC/access policies, diagnostics and authorized audit access | Core; approved Azure management/monitoring SDKs; data adapter only where needed |
| `SecretKit.Extensions.Configuration` | Explicit key mapping and string export through .NET configuration | Core; narrow Microsoft.Extensions.Configuration dependencies |
| `SecretKit.Extensions.Hosting` | Optional DI, explicitly started maintenance, health and lifecycle composition | Core; narrow Microsoft.Extensions.Hosting/DI/health dependencies |

Both extension packages would remain independently installable. Configuration export would not require a host, and host authentication maintenance would not require configuration export. No unconditional dependency between them would fuse these behaviors. Composition could use both in a sample or adopter application without adding an eighth facade package.

Core would not reference a provider SDK, Microsoft.Extensions, ASP.NET shared framework, Event, Configurator, database drivers, persistence layer or UI. All packages would initially target `net10.0`. Native AOT and trimming support would remain unverified, not advertised based on framework choice. Additional targets would require explicit demand and conformance, not speculative compatibility layers.

Separating management packages would keep administrative dependencies out of ordinary runtime readers. It would not confer, revoke or prove authorization: credentials and remote provider policy would still govern each operation. A runtime identity could be overprivileged despite its package selection, and a management identity might not be allowed to read material.

## Deliberately Small Core

The proposed common surface would cover only semantics demonstrated by both selected providers:

- Explicit reads through the selected provider instance and a typed reference, including a version selector only where its meaning is established.
- Metadata inventory distinguished from value retrieval and from a coherent remote snapshot.
- References preserving provider-owned address semantics and authority identity.
- Explicitly disposable material and material-free immutable observations.
- Bounded outcomes and capability evidence sufficient to avoid invented success, permissions or guarantees.

`ISecretReader`, `ISecretInventory`, `SecretReference`, `SecretMaterial` and `SecretOutcome<T>` are existing common APIs described in the [current preview](../public/current-preview.md). Core does not reserve future capabilities in anticipation of a common abstraction.

There would be no Core `ISecretApprovalClient` and no unproven common writer, backup, lease, rotation or recovery interface. Those effects and state machines differ enough to require native typed contracts until independent evidence establishes a genuinely substitutable shared contract. Adding an empty interface now would mislead adopters and constrain future design without proving portability.

A reference would bind an opaque provider-instance identity to an independently designed provider address and optional scoped version. Infisical project/environment/folder/key coordinates and Azure vault/name/version would not collapse into a lossy universal path. Address data would not select a new untrusted endpoint. Provider rules would own case comparison, valid identifiers and version interpretation. Formatting would redact sensitive coordinates even when metadata contains no value.

## Typed Native Features Are First-Class

The proposed provider packages would expose narrowly typed, independently designed native modules. An Azure backup artifact could remain an opaque, sensitive provider-bound artifact. Infisical dynamic issuance would retain definition, acquisition, renewal and revocation distinctions. Retained SQL rotation configuration stays typed; removing the third-party connection/sync catalog does not introduce an arbitrary JSON bag or raw-operation escape hatch.

Core would not absorb those models. Nor would public provider contracts simply expose vendor DTOs, exceptions, arbitrary HTTP requests or `ExecuteRaw`. Native operations would remain subject to the same ownership, receipt, cancellation and diagnostic contracts as portable reads.

The management split would be driven by resource function and dependency weight. Runtime token acquisition/renewal would remain an authentication concern in the Infisical adapter. Identity creation and credential issuance administration would belong in Infisical.Management. Lease material acquisition is not inventory. Existing gateway/proxy administration does not mean that the SDK deploys agents or operates backend transport. Role subjects named `AppConnections` remain policy values, not catalog APIs.

## Capability Evidence And Admission

Implementation support, supported programmable contract, deployed API/version, edition, identity permission and conformance evidence would be separate dimensions. Capability evidence would be scoped to the configured provider instance, identity and observation time; it could expire or be invalidated by credential/policy changes. An in-memory feature description would not grant permission.

Unknown required semantics would reject the operation before a mutation. Unknown permission could justify an explicit authorized provider probe if the admitted contract allowed it, but not a success claim. The result would distinguish unsupported, contract not established, entitlement unavailable, denied and not checked. Discovery would not acquire a dynamic credential, create an import or silently authenticate under another principal.

The [admission policy and populated registry](DELIVERY_AND_MAINTENANCE.md) are distinct concerns. Active coverage must map each retained operation to its package/native owner, contract, permissions, effects and evidence. The frozen Infisical registry is `ContractResearchOnly`; R4 counts are historical research, not current admission.

## SDK Reuse And Infisical Transport Decision

Official supported SDKs would be reused where their coverage, license, deployment behavior, cancellation, retries, diagnostics and ownership could satisfy these contracts. Azure's official secret SDK is the preferred candidate, not a completed dependency approval.

Managed Infisical REST would be selected only after a documented assessment of official SDK coverage and FFI/native deployment constraints. R4's observed Event self-hosted/native concerns would justify focused investigation, not prove that every current SDK deployment fails. The assessment would identify exact missing operations or unsupported deployment/control seams, test the relevant risk, and explain why configuration or wrapping could not solve it. It would also account for the cost of owning pagination, authentication, response limits and vendor changes.

The decision would avoid parallel SDK and REST stacks for the same operation merely to preserve Event behavior. If different admitted families needed different transports, their boundary and common security behavior would be explicit and verified. No dependency or generated client would be admitted without compatible approved provenance. No expressive vendor schema/source would be ingested as a design blueprint.

## Configuration Is An Export Boundary

SecretKit.Extensions.Configuration would propose asynchronous preparation followed by explicit string export. It would not perform remote I/O synchronously inside `IConfigurationProvider.Load`, block on async methods, or start background renewal as a side effect of configuration registration.

Key mapping would be explicit, collision-checked and compatible with provider naming rules. The adapter would not silently rewrite names to make a key appear valid. Configuration reload would publish a prepared complete mapping, while its string exposure and per-key coherence limits would remain documented in [runtime contracts](RUNTIME_CONTRACTS.md).

SecretKit.Extensions.Hosting would compose lifecycle only on explicit host opt-in. Optional authentication maintenance would require explicit host startup and would stop at shutdown. Snapshot refresh scheduling, application readiness and fleet reload policy would remain host responsibilities; neither extension would become a universal scheduler or durable reconciliation service.

## Consumer Workflows And Ownership

The proposed early examples would exercise both workflows using installed packages, with no repository references to Event or Configurator and no actual consumer migration:

1. An Event-like runtime would select an authority, read required settings, acquire one generation for a coherent operation, observe freshness/versions and explicitly hand a prepared client to application-owned code.
2. A Configurator-like workflow would inspect provider metadata/imports, read through the intended identity, report validation and delivery as different evidence, review intended changes and submit only supported typed operations with per-item receipts.

SecretKit would own fresh provider reads and scoped evidence of versions, namespace, collection window and consistency. It would not decide that a new remote version equals a successful Event integration revision.

Event would own desired/observed integration revisions, tenant authorization, HAL affordances backed by server authorization, semantic validation, client handover, durable replica metadata and concurrent-disable coordination. Its application would reject a prepared result if the integration was disabled or superseded before handover, and would decide when to retire application clients. SDK snapshots would not replace that state machine.

Configurator would own definitions, review UX, intended-identity selection, application acceptance and operator authorization. Administrative visibility would not be treated as proof that the consuming application's identity could read a value. SecretKit would not import Configurator scenario runners or expand its currently approved MVP.

## Functional Sources And Limits

- [Azure secret SDK](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/security.keyvault.secrets-readme?view=azure-dotnet) supports the reuse proposal; exact package/transitive approvals remain open.
- [Azure object types](https://learn.microsoft.com/en-us/azure/key-vault/general/about-keys-secrets-certificates) distinguishes secrets from excluded keys/certificates.
- [Infisical dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview) and [rotation](https://infisical.com/docs/documentation/platform/secret-rotation/overview) ground native side-effect distinctions.
- [Infisical API overview](https://infisical.com/docs/api-reference/overview/introduction) grounds per-family protocol selection, not a universal version floor.

These sources were cited through bounded R4 evidence, not newly tested. All package surfaces, examples and enforcement described here remain proposed.
