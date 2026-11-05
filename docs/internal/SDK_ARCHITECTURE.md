# SecretKit SDK Architecture

> Audience: SDK implementers, reviewers and future consumer integrators
> Status: Implemented package boundaries with proposed local-readiness changes
> Owner: SecretKit architecture maintainer
> Scope Reviewed: 2026-10-23; current implementation evidence is in current-preview
> Source Anchors: [internal overview](README.md), [historical research](RESEARCH_EVIDENCE.md), [runtime contracts](RUNTIME_CONTRACTS.md), [ADR-001](adr/ADR-001-capability-aware-secret-sdk.md)

The implemented package boundaries separate portable reads from provider-native
functionality, configuration export and optional host lifecycle. Design ambitions
later in this document do not establish live provider qualification.

The [Infisical local readiness contract](INFISICAL_LOCAL_READINESS.md) now owns
immediate delivery requirements. Seven packages exist, but the planned local
application profile selects Core, Infisical and optional configuration/hosting.
Azure and management remain retained work. No Event-specific binding, bootstrap,
Data Protection admission or activation service belongs in shipped packages.
The [local profile decision](adr/ADR-002-infisical-local-qualification.md)
separates that goal from public publication.

Current scope follows the [accepted catalog-removal decision](../public/connector-scope-decision.md).
Broad third-party app-connection/sync administration is removed from local
source, not a future completeness requirement. Native SQL rotation configuration
and runtime features, selected administration and existing gateway/proxy
administration remain; local post-removal verification passed. Other proposed
behavior below is design, not post-removal verification.

## Seven Packages And Dependency Direction

The [runtime adoption contract](RUNTIME_ADOPTION_SECURITY.md) and
[ADR-003](adr/ADR-003-runtime-adoption-security-evidence.md) govern the next
installed console/worker/web consumers. They do not move application activation
or ASP.NET dependencies into shipped libraries.

| Package | Responsibility | Dependency boundary |
| --- | --- | --- |
| `SecretKit.Core` | Common reads and metadata inventory; authority-bound references, material and outcomes | BCL only; no external runtime dependencies |
| `SecretKit.Infisical` | Secret access, reference semantics and admitted native secret lifecycle/authentication features | Core; typed Refit/HttpClient transport |
| `SecretKit.Infisical.Management` | Selected identity/project/access/governance administration, native SQL rotation configuration and existing gateway/proxy administration; no third-party connection/sync catalog | Core; Infisical adapter where needed; approved dependencies only |
| `SecretKit.AzureKeyVault` | Key Vault secret data plane and admitted native version/lifecycle features | Core; approved `Azure.Security.KeyVault.Secrets` and Azure.Core dependencies |
| `SecretKit.AzureKeyVault.Management` | Scoped vault administration, RBAC/access policies, diagnostics and authorized audit access | Core; approved Azure management/monitoring SDKs |
| `SecretKit.Extensions.Configuration` | Explicit key mapping and string export through .NET configuration | Core; narrow Microsoft.Extensions.Configuration dependencies |
| `SecretKit.Extensions.Hosting` | Optional DI, explicitly started maintenance, health and lifecycle composition | Core and Infisical; narrow Microsoft.Extensions.Hosting/DI/health dependencies |

Both extension packages are independently installable. Configuration export does
not require a host, and hosting does not require Configuration. Applications can
compose both without an eighth facade package.

Core uses only the BCL. All packages target `net10.0` with the pinned SDK and C# 14.
Trim diagnostics do not certify trimming or Native AOT compatibility; both remain
unverified. Additional targets require explicit demand and conformance.

Management packages keep administrative dependencies out of ordinary runtime
readers. Package selection does not confer or prove authorization: credentials
and provider policy govern each operation. A runtime identity can be overprivileged,
and a management identity may lack permission to read material.

### Database credential boundary

The no-database-driver boundary applies to every shipped SecretKit package,
not only Core. Core reads and returns opaque secret material; it does not open
database connections. Typed Infisical credential-generation and rotation APIs
for PostgreSQL, MySQL and SQL Server remain provider API functionality without
database drivers.

Optional integration tests may use database clients or native tools to verify
returned credentials and downstream effects. Those dependencies stay in
nonpackable test projects/fixtures, never in shipped packages. The support
boundary is the Infisical API, not a general database-support matrix; MariaDB
needs separate verification. MSSQL/ODBC research concerned this peripheral test
infrastructure, and no ODBC helper was implemented or database dependency added
to shipped libraries. The [database credential guide](../public/database-credentials.md)
records the current boundary and research status.

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

Mutation evidence is read-only to callers. Each adapter owns a private
`MutationReceiptIssuer`, validates exact reference ownership and issues receipts
before dispatch. The issuer synchronizes transitions and rejects foreign
receipts. Management wrappers additionally preserve native request/grant scope.
Azure's consumed attempt reservation and Infisical's prepared pre-dispatch retry
policy are distinct from dispatch evidence. Unknown remote effects never permit
automatic replay; these local capabilities do not attest remote authorization.

Management factories bind typed request construction directly to the existing
Refit interfaces. Transport-owned generated clients construct one message without
sending; an independent method/origin/path/query guard checks it before credentials
are attached. Owned body buffers, response parsing and partial-result cleanup
remain at their existing boundaries. Unknown SQL password requirements, including
nested required fields, fail closed for all three SQL providers.

The proposed provider packages would expose narrowly typed, independently designed native modules. An Azure backup artifact could remain an opaque, sensitive provider-bound artifact. Infisical dynamic issuance would retain definition, acquisition, renewal and revocation distinctions. Retained SQL rotation configuration stays typed; removing the third-party connection/sync catalog does not introduce an arbitrary JSON bag or raw-operation escape hatch.

Core would not absorb those models. Nor would public provider contracts simply expose vendor DTOs, exceptions, arbitrary HTTP requests or `ExecuteRaw`. Native operations would remain subject to the same ownership, receipt, cancellation and diagnostic contracts as portable reads.

The management split would be driven by resource function and dependency weight. Runtime token acquisition/renewal would remain an authentication concern in the Infisical adapter. Identity creation and credential issuance administration would belong in Infisical.Management. Lease material acquisition is not inventory. Existing gateway/proxy administration does not mean that the SDK deploys agents or operates backend transport. Role subjects named `AppConnections` remain policy values, not catalog APIs.

## Capability Evidence And Admission

Implementation support, supported programmable contract, deployed API/version, edition, identity permission and conformance evidence would be separate dimensions. Capability evidence would be scoped to the configured provider instance, identity and observation time; it could expire or be invalidated by credential/policy changes. An in-memory feature description would not grant permission.

Unknown required semantics would reject the operation before a mutation. Unknown permission could justify an explicit authorized provider probe if the admitted contract allowed it, but not a success claim. The result would distinguish unsupported, contract not established, entitlement unavailable, denied and not checked. Discovery would not acquire a dynamic credential, create an import or silently authenticate under another principal.

The [admission policy and populated registry](DELIVERY_AND_MAINTENANCE.md) are distinct concerns. Active coverage must map each retained operation to its package/native owner, contract, permissions, effects and evidence. The frozen Infisical registry is `ContractResearchOnly`; R4 counts are historical research, not current admission.

## SDK Reuse And Infisical Transport Decision

Infisical uses independently handwritten typed Refit/HttpClient contracts.
Azure uses its selected official SDK dependencies. This workstream preserves
those existing transport choices rather than reopening SDK selection or adding
a second Infisical stack.

Native runtime callers select an explicit `InfisicalNativeOperation` carrying
Method, Kind, HardDelete, Recursive and optional LastSecretModified
(`DateTimeOffset?`). They no longer reconstruct routes or reparse query values
to infer the operation. Fixed wire interfaces still build requests, and the
runtime origin/method guard remains. Management retains its separate full
method/origin/path/query guard before credential acquisition; typed runtime
routing does not replace that independent destination check or expand the
compiled Management-to-Runtime seam.

`InfisicalTransportBinding` owns the internal fixed-origin, private-trust,
request-only builder and borrowed-resource policy shared by runtime and
management. The single shipped-package friendship from Infisical to
Infisical.Management intentionally permits that reuse without exposing a public
raw send surface. Test friendships are separate. CLR friendship exposes all
internals, so additional member usage requires review; it is not a member-level
security boundary. Public adapter tests cover TLS policy and host ownership.

`RuntimeManagementDependencyTests` enforces the reviewed Management-to-Runtime
seam using compiled ECMA-335 metadata. `ArchitectureBoundaryTests` applies that
same gate to the actual Management DLL inside the selected original package;
its existing assembly-dependency and friendship checks remain independent.
The focused scanner also checks the current Release Management output without
loading or executing either product assembly. Rebuild that output before using
the result as current-source evidence.

The allowlist names 15 Runtime types and 34 exact member signatures:

| Approved group | Types / members | Purpose |
| --- | --- | --- |
| Public token, network and rotation selection | 6 / 15 | `IInfisicalTokenSource.GetTokenAsync`; token material/expiry access; network construction, byte/time limits and the existing loopback/response-limit/proxy initialization; read-only native project/environment/folder and rotation ID/profile selectors. |
| Internal transport binding | 1 / 5 | `InfisicalTransportBinding` construction, `ValidateOrigin`, `Client`, `Requests` and `Dispose` preserve fixed-origin request construction and borrowed-resource ownership. |
| Internal budget | 2 / 2 | The `InfisicalOperation` type is present in the nullable budget selector; only `InfisicalOperationBudget.RunAsync<T>` and `RetryAfter` may be referenced. No other budget member is implicitly admitted. |
| Internal diagnostic capture/deferral/observation | 6 / 12 | `InfisicalDiagnostics.Capture`, `Complete` and `Defer`; interval start/duration/parent getters; completion status/reason/dispatch/termination getters; observation construction and its completion getter. Start and termination types carry only the closed capture/result contract. |

The diagnostic seam lets Management retain its own emitter while sharing the
existing budget's completion and release ordering. It does not admit the
Runtime diagnostic emitter, arbitrary lifecycle clients, setters on observation
state, or unrestricted access to all members of an approved type.

The canonical member signatures live in the test allowlist. They include
declaring assembly/type, member name, signature header (including static versus
instance), generic arity, required parameter count, parameter and return types,
and required/optional modifiers. Field references are scanned separately; no
Runtime field is approved. Nested and constructed-generic owners resolve to
their declaring assembly. Independently encoded in-memory PE images exercise
unknown types/methods/fields, a changed overload, nested/generic owners, an
approved diagnostic member and a same-named type from another assembly.
No source-text inventory or new production friendship implements this gate.

Checkpoint archives are historical evidence when their source predates a seam
change. Passing the current compiled-output gate does not qualify those archives,
and an older signature is not added as a compatibility exception. The final
fresh-cohort package lane must rerun the archive and friendship checks.

Historical Event self-hosted/FFI observations do not establish failure of every
vendor SDK deployment. Local readiness instead qualifies the existing managed
transport's current origin, cancellation, limits, ownership and diagnostics
controls against the selected deployment. Private CA/proxy and DNS behavior are
explicit test inputs, not reasons for TLS bypass or global networking changes.

The decision would avoid parallel SDK and REST stacks for the same operation merely to preserve Event behavior. If different admitted families needed different transports, their boundary and common security behavior would be explicit and verified. No dependency or generated client would be admitted without compatible approved provenance. No expressive vendor schema/source would be ingested as a design blueprint.

## Enterprise Hardening And Support Boundaries

[ADR-005](adr/ADR-005-enterprise-hardening-contracts.md) records strict,
operation-specific response acceptance, explicit identity replacement,
independent request/response byte limits and a cooperative end-to-end operation
budget. Accepted HTTP status alone does not establish valid material, identity
or applied effects; bounded additive authentication fields remain distinct from
malformed or contradictory known fields.

Hosting freezes the selected Infisical runtime at resolution. Identity
replacement requires explicit admission of a new runtime, fresh authority-bound
references, host-directed handover and retirement of accepted old work before
disposing owned resources. Options reload does not replace a principal. Hosting
depends on Core and Infisical independently of Configuration.

The current deployment posture is JIT on `net10.0`.
[Integration quality follow-ups](INTEGRATION_QUALITY_FOLLOW_UPS.md) retain the
named-consumer and qualification gates for sovereign management, trimming,
Native AOT and a second actual Hosting contract. Controlled test evidence does
not establish native qualification or production readiness.

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

These sources were cited through bounded R4 evidence, not newly tested here.
Existing surfaces and evidence are recorded in the
[current preview](../public/current-preview.md); future-tense requirements are
not an assertion that every existing package or example is unimplemented.
