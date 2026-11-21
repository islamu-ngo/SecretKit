# Adoption and value

> **Audience:** Application developers and technical evaluators
> **Status:** Implemented development subsets; value requires application evaluation
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-21 (source and documentation review; no build or tests run)
> **Source anchors:** [Project map](../../PROJECTS.md), [Core](../../src/SecretKit.Core/),
> [Configuration](../../src/SecretKit.Extensions.Configuration/README.md),
> [Hosting](../../src/SecretKit.Extensions.Hosting/README.md),
> [Positioning and strategy](../internal/POSITIONING_AND_STRATEGY.md)

SecretKit provides an implemented in-process boundary for selected Infisical and
Azure Key Vault operations. It makes authority selection, material ownership,
bounded outcomes and local generation replacement explicit. **In development,
not ready for production; unpublished, with breaking API changes permitted.**
The immediate adoption path is [exact local Infisical packages](local-packages.md),
not a commitment to simultaneous provider completion.

## What you can use now

| Need | Implemented utility | What the application still owns |
| --- | --- | --- |
| Read from explicitly selected providers | `ISecretReader`, authority-bound references and bounded outcomes through real Infisical/Azure adapters | Provider/address selection, identity provisioning, required-value policy and operation deadlines |
| Limit accidental material exposure | Independent disposable material, redacted formatting and controlled serialization | Explicit reveal/export, host instrumentation, process memory and ordinary managed strings |
| Prepare a coherent local required set | `SecretSnapshotLoader` publishes only complete valid collections; acquired handles retain their generation | Remote consistency expectations, freshness deadlines, semantic validation and optional-feature grouping |
| Export for string-based configuration consumers | Explicit mappings and acknowledged managed-string export with destination collision checks | Configuration precedence, options/debug exposure and client activation; separate indexer reads can cross reloads |
| Maintain an explicit Infisical token session | Original finite-lifetime ceilings, single-flight renewal and opt-in hosted maintenance | Verified lifetime/principal evidence, explicit startup and authorized replacement after uncertainty or token loss |
| Perform selected native operations | Typed native reads, mutations and separate management surfaces with caller-held receipts | Administrative authority, downstream effect verification, persistence and recovery decisions |

Start with [getting started](getting-started.md) and [Core API](core-api.md).
Use [provider support](provider-support.md) to select only the implemented native
families you need. Native addresses, permissions, revisions, imports, approvals,
leases and lifecycle effects retain their provider meaning; the common read
surface does not turn them into universal contracts.

## When the extra boundary earns its cost

SecretKit is **not** an anti-vendor-lock-in CRUD wrapper designed to make
Azure Key Vault and Infisical drop-in interchangeable:

- `SecretKit.Core` deliberately abstracts only reads (`ISecretReader`),
  value-free inventory (`ISecretInventory`), authority-bound references,
  bounded outcomes and pre-dispatch mutation receipts.
- Secret coordinates (`AzureSecretAddress` vs `InfisicalSecretAddress`), writes,
  dynamic credential leases, rotations, backups and authentication remain
  provider-native ([ADR-001](../internal/adr/ADR-001-capability-aware-secret-sdk.md)).
  `SecretKit.Extensions.Hosting` currently targets Infisical only.
- In real deployments, migrating secret managers is dominated by IAM/RBAC,
  infrastructure provisioning, key/folder topology changes and Keys/Certificates/HSM
  features (which SecretKit excludes) rather than swapping a read call.

Instead, SecretKit's concrete value depends on which problem you actually have:

| Buyer scenario | Fit today | Concrete value delivered | Honest caveats and alternatives |
| --- | --- | --- | --- |
| **Multi-backend self-hosted products or operator tools** (for example ISLAMU Event or Configurator) | **Strong** | One explicit ownership, generation-replacement, outcome and redaction model across operator-selected Infisical and Azure Key Vault backends without fragile CLI wrappers ([ADR-006](../internal/adr/ADR-006-configurator-provisioning-and-credential-sources.md)) | Unpublished preview; live provider qualification gates remain open |
| **Infisical `.NET 10` applications** | **Moderate-High** *(after preview fixes)* | Per-call `CancellationToken`, cooperative timeouts, private-CA/proxy `HttpMessageHandler` control, bounded payloads and typed dynamic/rotation/import/bulk/proof-auth coverage missing from `Infisical.Sdk` `3.0.4` ([SDK assessment](../internal/providers/infisical-sdk-assessment.md)) | Current preview still calls `.GetString()` before `SecretMaterial.FromText`; feature parity gaps can narrow if upstream updates its SDK |
| **Simple single-provider startup configuration or CRUD** (for example AKV-only web APIs) | **Poor** | Thin safety wrappers over `SecretClient` | Direct `Azure.Security.KeyVault.Secrets` + `AddAzureKeyVault` is simpler, Microsoft-backed and covers Keys/Certificates/HSMs |
| **High-assurance or live-rotating single-provider apps** (including closed-source AKV-only teams) | **Potentially Strong, Currently Blocked** | Coordinated multi-key validation and lease-drained client replacement (`SecretGenerationCoordinator<TClient>`) plus fail-closed guardrails (`SecretAuthority`, disabled write retries, consumption validity gating and redacted defaults) | See current blockers below before adopting for an AKV-only workload |

### What differentiates SecretKit even for single-provider apps

Microsoft's `Azure.Security.KeyVault.Secrets` and
`Azure.Extensions.AspNetCore.Configuration.Secrets` cover basic HTTP CRUD and
timer-based string reloads well, but leave two production gaps:

1. **Zero-downtime live secret rotation and client drain:** `AddAzureKeyVault`
   with `ReloadInterval` pushes plain strings into `IConfiguration` on a timer.
   Separate indexer lookups can mix old and new keys mid-reload, invalid rotated
   secrets are published without pre-cutover validation, and `IOptionsMonitor`
   does not wait for in-flight work using an old database or HTTP client to
   drain before disposal. `SecretSnapshotLoader` and
   `SecretGenerationCoordinator<TClient>` collect a complete valid generation,
   construct and validate the replacement client before cutover, enforce
   `FailClosed` or `BoundedLastKnown` policies, and retire old clients only
   after active `SecretGenerationLease<TClient>` handles finish.
2. **Fail-closed guardrails by construction:** Out of the box, official
   defaults invite `DefaultAzureCredential` probing traps, cross-vault reference
   mix-ups, silent duplicate secret versions from default write retries,
   consumption of expired or `NotBefore`-future secrets (`SecretClient` returns
   them unless callers inspect `SecretProperties`), accidental clearing-omission
   of empty tags (`EmptyTagsPolicy` in
   [AzureKeyVaultClient](../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs#L102-L130)),
   and accidental leakage through `ToString()` or JSON serialization. As shown
   empirically in
   [`DirectAzurePath`](../../tools/SecretKit.ConsumerBaseline/Workflows.cs#L90-L224),
   matching these guardrails directly over `SecretClient` requires ~135 lines of
   defensive boilerplate per workflow.

### Why AKV-only closed-source teams should wait today

For an Azure-Key-Vault-only closed-source application, current preview gaps
neutralize much of that advantage right now:

- **Heap strings remain on AKV and Infisical wire edges:** `SecretMaterial`
  currently stores an unpinned `char[]` and rents unpinned `ArrayPool` slices,
  while `AzureKeyVaultClient` wraps `SecretClient` (which requires `string` on
  `GetSecretAsync` and `SetSecretAsync`). See
  [Security and resource ownership](security-and-ownership.md#plaintext-is-an-explicit-boundary).
- **Asymmetric AOT and Hosting support:** `SecretKit.AzureKeyVault` and
  `SecretKit.AzureKeyVault.Management` do not set `<IsAotCompatible>true</IsAotCompatible>`,
  and `SecretKit.Extensions.Hosting` depends on `SecretKit.Infisical` directly.
- **Unresolved preview bugs and missing live Azure checks:** Open source-level
  defects (including `SecretGenerationCoordinator` revision/retirement races,
  `AzureKeyVaultClient` post-dispatch error masking, plaintext download in
  `CheckLifecycleStatusAsync`, and unverified live Azure execution) plus solo
  maintainer scope remain active pre-1.0 blockers documented in
  [Positioning and strategy](../internal/POSITIONING_AND_STRATEGY.md).

For a single provider with extensive native requirements, a direct vendor client
remains simpler today. SecretKit adds another dependency, narrower supported
subsets and an additional maintenance surface. Current evidence does not
establish comparative speed, cost, safety or engineering time savings.

| Approach | Fit to evaluate | Cost or boundary to inspect |
| --- | --- | --- |
| Direct provider client | A provider-specific application needing broad native functionality (or Keys/Certs/HSM) | Application-owned material, diagnostics, identity, validity gating, lifecycle and rotation-drain handling |
| String-valued configuration integration | Consumers already designed around startup configuration strings | Plaintext exposure, precedence, mid-reload tearing and options/client convergence |
| External agent, sidecar, environment or files | Deployment owns retrieval outside the application process | Delivery permissions, availability, refresh signals and stale-value policy |
| SecretKit in-process adapters | Multi-backend apps, Infisical `.NET 10` consumers, or apps requiring explicit ownership/generation contracts | Adapter maintenance, admitted subsets, preview bugs/heap-string boundaries and remaining live qualification |

These are architectural choices, not benchmark rankings or externally verified
recommendations. No vendor/adopter outreach or comparative runtime study was
performed for this documentation update.

## Working examples and evidence

The package-only [console](../../tests/PackageQualification/Infisical.ConsoleDemo/),
[worker](../../tests/PackageQualification/Infisical.WorkerDemo/) and
[web](../../tests/PackageQualification/Infisical.WebDemo/) apps demonstrate explicit reads/writes,
awaited admission, opt-in maintenance and request-pinned consumer generations.
The [demos and recovery guide](demos-and-recovery.md) explains their controls,
recovery ownership and fixed local-overhead workload. Controlled installed
process/HTTP tests are not live deployment qualification, production readiness
or proof of integration into another application.

The measured workload concerns synthetic in-process preparation/export and
generation lifetimes, not remote latency, integration hours or superiority over
alternatives. For a fair application evaluation, hold required keys, privileges,
failure cases and environments constant. Record setup/learning time separately
from steady-state work; count complexity moved into adapters as well as branches
removed from applications. Track support incidents and upgrade effort over a
stated observation period. Additional providers require demonstrated demand and
[admission](../internal/PROVIDER_ADMISSION.md), not automatic expansion.

## Application policy stays outside the SDK

Applications own tenant boundaries, secret meaning, required/optional decisions,
semantic validation, persistence, readiness and client handover. Reload signals,
native revision observations and successful writes do not perform activation or
prove replica convergence. Consumers own stale budgets and durable material-free
notifications/acknowledgements.

Event and Configurator integration are outside this library workstream; these
docs do not establish either application's acceptance or preserve their contracts
as compatibility shims. Configurator's 2026-11-14 decision to use SecretKit,
not vendor CLIs, for its native secret-store operations is recorded in
[ADR-006](../internal/adr/ADR-006-configurator-provisioning-and-credential-sources.md);
it adds proposed roadmap items, not implemented support. Development changes update real callers directly.
Core treats database credentials as opaque material; no database drivers ship.
The [removed connector catalog](connector-scope-decision.md) is not required for
ordinary reads or a reason to discard retained native rotation/gateway features.

## Adoption decision

Evaluate exact candidate originals with the
[local package recipe](local-packages.md), then follow
[configuration/runtime](configuration-and-runtime.md),
[authentication/hosting](authentication-and-hosting.md) and
[troubleshooting](troubleshooting.md) for the chosen composition.
Keep runtime and management identities explicit and least-privileged.

Use [current preview](current-preview.md) and
[operations/compatibility](operations-and-compatibility.md) before making support
claims. Historical observations and offline tests cannot qualify refreshed
archives, missing permissions/editions or unobserved effects. Azure live behavior,
full native binding evidence and untested platform/AOT/trim profiles remain gaps.
Local evaluation is not public-release or production authority.
