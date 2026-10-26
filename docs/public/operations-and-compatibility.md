# Operations and compatibility

> **Audience:** Operators, application developers, maintainers, and AI coding assistants
> **Status:** Current implemented operational reference; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; no new live qualification
> **Source anchors:** [project map](../../PROJECTS.md), [provider API owners](providers/README.md), [security policy](../../SECURITY.md)

SecretKit has seven separate package owners targeting `net10.0`. Package presence,
local installation, implementation and native qualification are different facts.
Use [current support](provider-support.md) and [current preview](current-preview.md)
for evidence scope; use the [provider guides](providers/README.md) to select actual
APIs. The four-package Infisical local evaluation profile does not require Azure
or management completion and grants no publication authority.

## Package and authority boundaries

| Package | Implemented responsibility | Operational consequence |
| --- | --- | --- |
| `SecretKit.Core` | BCL-only references, reads, inventory, outcomes, owned material | No vendor client, database driver, application readiness or scheduler. |
| `SecretKit.Infisical` | Common reads/inventory, selected shared writes, authentication and retained native lifecycle | Select runtime tokens explicitly; native administration can require a separate authority/client. [Guide](providers/infisical.md). |
| `SecretKit.AzureKeyVault` | Secret data plane, versions, metadata and lifecycle | Vault origin plus runtime `TokenCredential`; not ARM or monitoring authority. [Guide](providers/azure-key-vault.md). |
| `SecretKit.Infisical.Management` | Typed retained administration | Exact organization/project authority, independent intent grant and request-bound mutation receipt. [Guide](providers/management.md#infisical-administration). |
| `SecretKit.AzureKeyVault.Management` | Vault/access/role/private-connection/notification administration and separate audit queries | Explicit administration and monitoring credentials; public-cloud subsets. [Guide](providers/management.md#azure-administration). |
| `SecretKit.Extensions.Configuration` | Required collection, acquired local generations and deliberate string export | No remote snapshot, activation, automatic refresh or erasure of exported strings. [Guide](configuration-and-runtime.md). |
| `SecretKit.Extensions.Hosting` | Explicit Infisical authentication-maintenance lifecycle and material-free health | Construction/registration alone starts no worker; host owns startup, readiness and shutdown. [Guide](authentication-and-hosting.md). |

References belong to a selected client authority. Administrative visibility does
not establish intended-runtime delivery; ARM access does not imply secret-read
or audit-query access. Native backup, lease, approval and rotation semantics are
not flattened into a universal lifecycle interface.

The broad third-party connection/sync catalog is removed. Native SQL rotation
and existing gateway/proxy administration remain, without destination SDKs or
database drivers. See [scope decision](connector-scope-decision.md) and
[database credential boundary](database-credentials.md).

## Endpoints, trust and transport ownership

| Surface | Implemented transport boundary | What the host must supply |
| --- | --- | --- |
| Infisical common reads | Fixed HTTPS origin; explicit loopback HTTP opt-in; owned transport disables redirects, cookies and activity propagation | Bounded cancellation deadline and selected token source. With supplied `SocketsHttpHandler`, keep configuration stable and preserve validating TLS, no redirects/cookies/activity propagation. |
| Infisical dynamic/native rotation | Dedicated typed client; selected origin/scope/credentials | Secure supplied transport. Rotation's supplied `HttpClient` is host-owned; do not add redirects, cookies, retries or sensitive diagnostics. |
| Infisical management | `ManagementTransport` owns fixed-origin HTTP wrapper; no automatic retry or fallback | Dispose the transport after clients finish; pass cancellation deadlines and explicit grants/receipts. |
| Azure data plane | Official SDK, revision `2025-07-01`; trusted public/US government/China vault hostname forms; challenge-resource validation enabled | Selected credential and any injected transport; normal vault DNS for private endpoints. Accepted syntax does not qualify a cloud deployment. |
| Azure administration/audit | Fixed public-cloud ARM/Logs endpoints; SDK retries/logging/tracing disabled | Separate explicit administrative/monitoring credentials and secure host-owned transports. Sovereign management endpoints are not exposed. |

The Infisical read-client supplied-handler overload rejects custom certificate
validation callbacks and chain verification bypass flags. Use standard trust
stores or a validating custom-root chain policy, not an accept-all callback.
Proxy, DNS, credential telemetry and host transport instrumentation remain host
responsibilities. SDK validation of outer requests does not validate the internals
of arbitrary injected transports.

Source/evidence:
[Infisical client](../../src/SecretKit.Infisical/InfisicalClient.cs),
[transport ownership tests](../../tests/SecretKit.Infisical.Tests/InfisicalTransportOwnershipTests.cs),
[Azure client](../../src/SecretKit.AzureKeyVault/AzureKeyVaultClient.cs),
[Azure controlled transport](../../src/SecretKit.AzureKeyVault.Management/ControlledTransport.cs).
Deployment proxy/private-CA/DNS acceptance is separate from controlled tests.

## Deadlines, payloads and incomplete collections

Pass cancellation with an application-chosen deadline to provider operations.
Infisical common reads have no implicit timeout; cancellation covers credential
acquisition, send and response-body consumption. Azure management operations
default to 30 seconds and permit at most two minutes. Query-specific bounds are
documented in the [audit guide](providers/management.md#azure-audit).

Provider wire budgets generally permit 1 KiB..16 MiB, but input families have
additional limits: Infisical management bodies are 64 KiB, native bulk inputs
are capped at 128 rows, and Azure backup imports have a 16 MiB storage ceiling
plus the client's smaller wire budget including serialization overhead.
Do not treat one family's item limit as a global setting.

Check `IsComplete` on runtime/native inventories and Infisical management pages;
check `Complete` and `Status` on Azure management inventories. Audit queries also
carry `Error`, and Infisical audit pages contain row-level outcomes. Cancellation,
page/item limits, malformed scope, partial errors and SDK continuation loss must
not be promoted into complete evidence. Collection during concurrent writes is
not a transactional snapshot. No hidden worker fills missing pages.

## Mutation recovery

Retain the surface's receipt before awaiting dispatch:

| Surface | Receipt and effect model |
| --- | --- |
| Selected static Infisical/Azure writes and native `InfisicalClient` mutations | Core `MutationReceipt`, bound to the target reference. Approval acknowledgement is pending, not applied material. |
| Infisical dynamic definitions/leases | `InfisicalDynamicMutationReceipt`, bound to definition/lease and operation. Local disposal does not revoke remote credentials. |
| Infisical rotation execution | `InfisicalRotationReceipt`, exact reference/action; accepted trigger is pending and later status is not attributable completion. |
| Infisical management | `ManagementClient.CreateReceipt(request)`; exact immutable request/client plus independent grant. |
| Azure management | `VaultAdministration.PrepareReceipt(scope, operation)`; exact scope instance/client/native operation. |

These receipts are not interchangeable. Evidence can remain `NotDispatched`,
`PossiblyDispatched`, pending, applied or rejected according to the specific
surface; rotation has its own dispatch/effect enums. Cancellation after possible
dispatch is not proof of no effect. No automatic replay, rollback, idempotency key
or compare-and-swap guarantee is invented.

After an uncertain write, use an explicit appropriate read with the intended
identity and assess current state before deciding a new action. A read can
observe material/configuration but cannot uniquely attribute a concurrent write
or rewrite the original receipt. Azure lifecycle status checks require an
acknowledged start before absence can mean pending. Import configuration success
does not prove replication/approval application. Rotation acceptance/status does
not prove changed backend credentials, consumer activation or fleet convergence.

See [mutation tests](../../tests/SecretKit.Infisical.Tests/InfisicalMutationTests.cs),
[rotation tests](../../tests/SecretKit.Infisical.Tests/RotationOutcomeTests.cs),
[Azure lifecycle tests](../../tests/SecretKit.AzureKeyVault.Tests/NativeLifecycleTests.cs)
and [management grant tests](../../tests/SecretKit.Infisical.Management.Tests/ManagementBoundaryTests.cs).

## Authentication lifetime, restart and shutdown

The native `InfisicalPeriodicTokenSession` copies supplied material and retains
original lifetime bounds. The optional `InfisicalAuthenticationMaintenance`
helper runs only through explicit `StartAsync` or explicit hosted-service
participation. Renewal is single-flight; finite ceilings are not reset by renewal.
Unknown or inconsistent lifetime evidence, expired/lost material, rejected or
ambiguous renewal can require a newly authorized session.

No token-bearing checkpoint, fallback login, automatic credential creation or
retry loop recovers a consumed bootstrap credential. Stop maintenance and drain
accepted work under host policy, then dispose owned resources. Disposal is not
remote revocation. See [authentication and hosting](authentication-and-hosting.md),
[hosting owner](../../src/SecretKit.Extensions.Hosting/README.md) and
[recovery demonstrations](demos-and-recovery.md).

## Sensitive material and diagnostics

Dispose owned reads, credentials, login results, backups and protected native
results. Supplied clients, credentials and transports remain host-owned where
documented. SDK-owned protection excludes sensitive values and coordinates from
default formatting/serialization and bounded error surfaces; audit and management
metadata still require sensitive handling.

`Reveal`, explicit exports, SDK wire serialization and configuration export
produce ordinary managed strings or copies. Buffer disposal cannot erase those
strings, old options, downstream fields, logs, dumps or host traces.
`SecretSnapshotLoader` publishes complete local acquired generations; its
`Generation` is not a provider revision and `RemoteSnapshotGuaranteed` is false.
Configuration reload is not application activation. Review host debug views and
instrumentation before export. Sources:
[configuration ownership](../../src/SecretKit.Extensions.Configuration/README.md)
and [security policy](../../SECURITY.md).

## Compatibility and qualification

| Evidence | Establishes | Does not establish |
| --- | --- | --- |
| Source and controlled adapter tests | Implemented variants, ownership, bounded outcomes, receipt and transport behavior under exercised inputs | Live permissions, entitlement, provider effects or complete vendor coverage |
| Exact local packed-consumer evaluation | Selected artifacts install and exercise the observed consumer path | Public publication, production readiness or every retained API |
| Owned native observation | The named deployment/version, identity, operation and observed effect at that time | Other editions, clouds, issuers, regions, platforms or consumer convergence |
| Selected trim/AOT/demo attempt | Its recorded application/package path and outcome | Library-wide trim/AOT or platform certification |

Record provider version/deployment/edition, API family/revision, authentication,
permission model, region/cloud, operation variant, package/artifact identity,
OS/architecture and observation date for a compatibility claim. Unknown contracts,
missing entitlements and unobserved effects remain gaps, not successful gates.
The [support page](provider-support.md) and
[demo evidence](demos-and-recovery.md) retain scoped results; no new native,
Windows/macOS/ARM, trimming/AOT or publication qualification is asserted here.

Report vulnerabilities through [SECURITY.md](../../SECURITY.md). Release and
dependency provenance follow [contribution guidance](../../CONTRIBUTING.md) and
[third-party notices](../../THIRD-PARTY-NOTICES.md); a documentation change or
local package install does not authorize publishing.
