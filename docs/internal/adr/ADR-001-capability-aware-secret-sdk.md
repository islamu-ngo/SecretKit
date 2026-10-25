# ADR-001: Capability-Aware Secret SDK

Historical R5 proposal. Its comprehensive administration/connector delivery
and first-release scope are superseded by the
[accepted 2026-10-11 catalog-removal decision](../../public/connector-scope-decision.md).
Retained native secret features and selected administration remain in scope;
local post-removal verification passed. The proposal below is preserved as history,
not current catalog admission or an instruction to restore deleted APIs.

The later [ADR-002](ADR-002-infisical-local-qualification.md) prioritizes
Infisical-first local qualification without changing public publication
authority. That decision supersedes this historical proposal's simultaneous
provider and publishing sequence, not its still-applicable ownership boundaries.

> Audience: SDK maintainers and architecture/security reviewers
> Status: Proposed / unimplemented; not an accepted or executed decision
> Owner: SecretKit architecture maintainer
> Last Verified: 2026-10-09, bounded design evidence and local links only
> Source Anchors: [architecture](../SDK_ARCHITECTURE.md), [runtime contracts](../RUNTIME_CONTRACTS.md), [delivery](../DELIVERY_AND_MAINTENANCE.md), [historical research](../RESEARCH_EVIDENCE.md)

## Context

Event's secret access is coupled to application bindings, persistence/bootstrap and consumer lifecycle. Configurator's future workflow requires inspection, intended-identity delivery evidence, review and partial-effect reporting. Neither requirement is met by exporting Event's project or calling a CRUD facade complete secret management.

Infisical and Azure expose useful but different native lifecycle, version, approval, lease, recovery and administration semantics. Public functional documentation establishes some facts; it does not prove every version, edition, cloud or deployment. R4 supplied bounded evidence, not working code or live conformance.

The current request explicitly revises R4's broad speculative Core, five packages and late host/pilot sequence. The parent owns R5 planning/review/I-VSD and public docs; this ADR records the internal proposed decision without claiming those revisions or implementation are complete.

## Proposed Decision

Use exactly seven independently selectable packages: `SecretKit.Core`, `SecretKit.Infisical`, `SecretKit.Infisical.Management`, `SecretKit.AzureKeyVault`, `SecretKit.AzureKeyVault.Management`, `SecretKit.Extensions.Configuration`, and `SecretKit.Extensions.Hosting`.

Keep Core BCL-only and limited to proven common read/inventory/reference/material/outcome contracts. Remove speculative `ISecretApprovalClient` and unproven common backup, lease, rotation, recovery and write abstractions. Admit useful native typed features in provider packages with full effect and security contracts; native does not mean raw vendor DTOs or a weaker abstraction.

Separate configuration string export from host lifecycle. Use independent caller-owned disposable material copies and acquired immutable generations; retire internal generation storage only after active handles release it. Represent remote versions and collection/consistency evidence without pretending local snapshot publication is a remote transaction.

Establish a caller-held receipt before dispatch. Propagate OCE on cancellation and retain dispatched/known/unknown evidence without material. Local correlation IDs would not be remote idempotency keys/query handles. Supported reconciliation would be explicit, with no blind replay, fake CAS or cross-provider transaction.

Map admitted import creation, requested replication and destination approval-pending/applied/unknown effects even when approval administration is gated. Missing supported UI-feature contracts would remain future vendor admission without stubs.

Prefer suitable supported SDK reuse. Select managed Infisical REST only after concrete coverage/FFI and control-seam justification. Bind explicit caller authority and ownership; disable upstream Azure diagnostics, eliminate side-effect retries, retain challenge verification and document host instrumentation exposure. Optional renewal maintenance would be explicitly host-started, bounded, single-flight and nondurable across process restart.

Deliver documentation foundation first, then minimal reads from both providers, both standalone workflows and an installed-package pilot with early focused real-provider risks, followed by safe writes/imports/snapshot/auth lifecycle, comprehensive admitted administration/connectors and the final declared-coverage/provider/install/publish gate. Use proportionate affected checks rather than broad intermediate sweeps or an exactly-one-build constraint.

## Alternatives Considered

| Alternative | Strongest reason to choose it | Why the proposal does not choose it |
| --- | --- | --- |
| Package Event's current secret project | Existing consumers and tested application behaviors reduce initial extraction work | Would export application/database/framework coupling and rights questions; would confuse Event-owned integration state with SDK scope |
| CRUD-only universal SDK | Small learnable API and quick dual-provider demonstration | Cannot satisfy the admitted advanced coverage goal or truthful issuance/import/approval effects |
| Large common lifecycle interface | Uniform discoverability and fewer provider-specific calls | Shared names would conceal incompatible state machines and invent substitutability |
| Raw SDK exposure everywhere | Rapid access to upstream features and less transport ownership | Would leak vendor models, diagnostics/retry assumptions and unsupported common guarantees into callers |
| Managed REST for every provider immediately | Direct control over effects, transport and response limits | Would duplicate suitable SDK behavior without first proving coverage/FFI/control gaps |
| One provider package plus one hosting/config package | Fewer artifacts and simpler release administration | Would force administrative dependencies and couple string export to lifecycle; package simplicity would not improve authorization |
| Late examples and only final live evidence | Easier early offline progress | Would discover consumer/usability/FFI/permission failures after expensive feature expansion |

## Consequences

Adopters could install only the needed runtime, administration, export or host pieces. The price would be seven-package dependency/API/release coordination and a larger maintained native surface. Package boundaries would reduce dependency weight, not secure credentials by themselves.

The portable path would be smaller than the complete product surface. Providers would remain genuinely useful through native typed modules rather than losing features to a lowest common denominator. New common capabilities would need proof of shared semantics before entering Core.

Receipts and partial outcomes would require caller discipline, especially after OCE. Some outcomes would remain unknown because supported provider observations cannot prove a particular request's effect. Refusing automatic replay could inconvenience callers but would prevent hidden extra versions or credentials.

Material ownership would require acquisition and disposal ergonomics and concurrency tests. Exported strings, provider SDK strings, options/debug views, instrumentation and GC would remain leakage boundaries. A wrapper would not promise memory erasure or coherent `IConfiguration` multi-key reads.

Authentication maintenance would require explicit host lifecycle and recovery planning. A consumed bootstrap plus lost in-memory token after restart would require authorized recovery rather than persistence or fallback. Renewal could preserve authority only within actual provider constraints.

A policy and cohort inventory would not support completion estimates. A populated per-operation registry and declared compatibility/depth evidence would be work in their own right. Missing sandbox entitlement or provider contracts would remain visible gates. The public-API-first launch boundary would preserve the timeout-default history, not claim all vendor UI functionality.

Event would retain integration revision state, tenant/HAL authorization, validation, handover and durable replica/concurrent-disable behavior. Configurator would retain definitions and review UX. Standalone SDK pilots would test those seams without performing a consumer migration.

The proposed MIT/source-free provenance process would impose review cost without asserting a universal legal rule. Owners could license their own code subject to contributor/third-party rights, but no blind AGPL relicensing or incompatible expressive-source/schema ingestion would occur.

## Revisit Triggers

- Independent evidence establishes genuinely shared lifecycle semantics that could enter Core without loss or fabricated guarantees.
- A vendor publishes/authorizes missing approval, recovery or other programmable contracts, or changes admitted import effects.
- Official SDK coverage, FFI/deployment behavior or configurable retry/diagnostic controls change enough to alter the transport choice.
- A provider removes an admitted contract, changes edition/permission/cloud support, or requires a supported older protocol with explicit compatibility evidence.
- The installed-package pilots show unacceptable dependency cost, safety/usability overhead or no demonstrated value over direct-provider usage.
- A concrete adopter requirement establishes another target framework, trimming or Native AOT need; none is promised before verification.
- Ownership/provenance review, a dependency advisory or an upstream license change invalidates an admitted dependency.
- Evidence shows the package split cannot preserve independent configuration and host use, or that maintenance/coverage cannot be responsibly owned.

Revisiting would require a source-free functional assessment, updated registry/evidence, proportional affected checks and a reviewed decision. It would not authorize silent downgrade, speculative stubs, remote replay or consumer migration.

## Functional Sources And Decision Limits

[Infisical references](https://infisical.com/docs/documentation/platform/secret-reference), [approval workflows](https://infisical.com/docs/documentation/platform/secrets-mgmt/concepts/approval-workflows), [Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth), [Azure secret client](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/security.keyvault.secrets-readme?view=azure-dotnet) and [Azure Set Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret) ground the functional distinctions through inherited R4 evidence. The parent supplies refreshed source evidence, including import-create replication/approval facts.

No vendor backend/SDK source, expressive schema or generated source summary informs this decision record. No runtime, compatibility, license-certification, build, test or publication success is claimed. Acceptance and implementation remain future actions.
