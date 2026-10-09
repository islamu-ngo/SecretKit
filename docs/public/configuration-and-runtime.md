# Configuration and runtime

> **Audience:** Application developers and operators
> **Status:** PROPOSED DESIGN
> **Owner:** SecretKit maintainers
> **Source facts checked:** 2026-10-09; no runtime verification
> **Source anchors:** Official references below

SecretKit proposes asynchronous selected-authority reads and protected local generations; the host would own startup, readiness, activation, and live-client replacement.

Nothing described here is implemented, published, or tested SecretKit behavior. Names describe intended contracts rather than a finalized callable API.

## Select one authority

The host would register installed adapters and select an immutable provider instance with a trusted endpoint, explicit identity, namespace boundary, and credential source. Selection would not install packages or discover arbitrary plugins. A provider reference would retain its instance identity and typed native address; a secret path would not be allowed to introduce another endpoint.

A required provider read would not silently fall back to an environment variable, a file, another identity, or another vendor. External environment/file delivery could be an explicitly selected consumer authority, but not a rescue path concealed behind a failed remote read. Application-specific tenant and binding policy would remain outside SecretKit.

Azure administration and secret delivery are distinct permission boundaries according to the [Azure access-plane documentation](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide). An administrative inspection would not prove that the intended runtime identity can retrieve material.

## Protected material and acquired generations

The protected read API would return typed, independent, disposable material copies. A cache hit would copy from owned storage, not hand a caller the cache's disposable object or shared writable buffer. Disposing or modifying one returned copy would not invalidate another caller or mutate the cached value. Explicit reveal or copy operations would make plaintext access deliberate; redacted formatting would be the default.

For a multi-key logical operation, such as constructing one database client from several settings, the caller would acquire one immutable generation handle and obtain every required value through that handle. Repeated reads against a mutable current-generation pointer could otherwise mix old and new values during refresh.

Publishing a replacement generation would not free storage still retained by readers. Internal generation handles would keep the retired generation's storage alive until all readers release it. Each material result would still be an independent disposable copy. The design would clear owned buffers when their ownership ends; it could not promise removal of all managed strings created by upstream transports or by callers.

A prepared generation would carry a local generation identifier, collection start/end times, freshness information, and per-key observed provider versions where available. It would distinguish unavailable version evidence rather than fabricate it from secret bytes. Immutability would describe the local collected set, not a remote transaction: provider values might change during the collection window. Related credentials could require provider-native version pinning or consumer coordination beyond a locally coherent generation.

Refresh would prepare and validate a candidate before replacing the current generation. An incomplete required-key set would not be published as a successful replacement. Cancellation and typed failures would remain observable. Existing readers could finish under the host's bounded stale policy; new consumers would not silently accept indefinite stale data.

## Plaintext configuration is a separate opt-in

`SecretKit.Extensions.Configuration` would expose prepared snapshots and an **explicit plaintext export opt-in** to `IConfiguration`. The protected material API would not implicitly stringify secrets into the configuration tree. Adopters using only protected reads would not need the export package.

The host would await remote preparation before attaching a snapshot. Synchronous configuration loading would perform no hidden network operation or sync-over-async wait. Explicit key mappings would be collision-checked; provider naming constraints would not be repaired by silently changing secret names.

Microsoft's [configuration documentation](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/?view=aspnetcore-10.0) describes ordered providers and last-provider precedence. For controlled secret keys, the host would either compose an authority-only view or ensure the selected snapshot takes precedence and reject conflicting overrides. A later environment, command-line, or JSON provider must not accidentally replace a controlled key. Ordinary non-secret configuration could retain a different host-selected precedence.

Export would create plaintext managed strings and broaden who can observe values. Configuration debugging and debug views, options binding, serializers, exception formatting, and logging could disclose them. Options instances and live clients could retain previous values beyond snapshot replacement. Disposing protected buffers would not clear exported immutable strings or all options copies; garbage collection is not a deterministic erasure guarantee. The host would decide whether that trade-off is acceptable, prohibit unsafe configuration dumps, and bound retained options/client lifetimes. Reload notifications would not prove clients rebound or replicas converged.

The configuration package would not start background workers, own readiness, or manage application lifecycle. Optional hosting integration would be a separate package.

## Bootstrap before database services

The proposed standalone database sample would:

1. Select the authority and intended identity from host-approved non-secret configuration and injected credential sources.
2. Await a complete required-key generation before registering or constructing database-dependent services.
3. Validate the application's consumption requirements without logging values.
4. Construct the database configuration/client from one acquired generation, using protected material or deliberately opted-in plaintext export.
5. Publish startup readiness only after the required preparation and bounded connectivity evidence succeed.

A required missing, denied, malformed, or unavailable setting would fail startup or keep readiness false. A previously prepared generation could be used only within an explicitly configured age and failure budget; never indefinitely or through an implicit alternate authority. The host would distinguish startup-required settings from later optional integrations.

A missing optional mail integration at startup would not fail the whole application. Its observed state would remain unavailable or disabled until configured and checked. Required database authority failure and optional integration absence are different policies, not one global all-secrets rule.

## Runtime setup and activation

An operator entering an existing provider reference and an operator provisioning a new provider resource would use separate flows.

**Provider-entry flow:** collect and validate a trusted provider/reference selection, save the intended configuration under consumer authorization, then force a fresh read using the intended runtime identity. An administrator's successful read, cached value, or entered credential alone would not satisfy delivery verification.

**Provisioning flow:** obtain separately authorized management identity and explicit approval for the selected native changes. Preserve existing values and provider prerequisites. Record effects, save the resulting intended reference, then perform the same fresh runtime-identity read. Provisioning would not automatically grant runtime permissions or enable the application integration.

Runtime **enable** and **check again** would force fresh reads rather than accept cached success. They would prepare a candidate generation and consumer client, validate required material, and perform a bounded connection check. Only a still-current enable intent with adequate readiness evidence could install the candidate. Check again would refresh evidence without silently enabling a disabled integration.

Checks would have explicit cancellation, timeout, network/endpoint boundaries, and safe result handling. A connection check would not place an order, write business data, send a normal notification, or acquire dynamic credentials as an unnoticed probe. A test email would be a separately explicit action with a selected recipient and disclosed external effect; successful credential retrieval would not imply successful mail delivery.

## Effects, revisions, and races

Native writes could finish synchronously, remain pending, partially apply, or leave effects unknown after a timeout. Resource creation would not mean downstream application is complete. In particular, the published [Infisical import-create contract](https://infisical.com/docs/api-reference/endpoints/secret-imports/create) describes replication that can create approval requests in the destination. An import resource could exist while destination application remains pending approval. That remains relevant even if approval-administration APIs are `ContractNotEstablished` for SecretKit.

A retry after an unknown effect would require reconciliation using supported native evidence and consumer policy, not blind replay. A failed candidate or failed runtime read would not trigger destructive provider rollback, deletion, revocation, or rotation. Any corrective native operation would be separately authorized and its consequences recorded.

The consumer would persist the desired revision independently from the observed configuration revision, active material generation, client generation, and readiness evidence. A provider save acknowledgement would not collapse those states into "enabled." Each replica would acquire and activate its own generation; the consumer would own acknowledgement, convergence deadlines, routing/readiness, durable retries, and failure recovery.

For a concurrent disable, candidate installation would compare against the current desired revision and enabled state. A late successful enable/check result could not overwrite a newer disable. Disposal of retired clients and draining in-flight operations would be host policy, not a provider operation.

Durable notifications would carry no secret values, tokens, plaintext configuration, or raw provider payloads. The consumer would own notification persistence, authorization, deduplication, and the safe revision identifiers used to prompt reconciliation. SecretKit would not supply a fleet coordinator, transactional outbox, tenant activation model, or application database.

## Authentication maintenance boundary

The optional hosting package could help a host schedule explicitly selected authentication maintenance, coordinate cancellation/shutdown, and expose safe maintenance status. It would not perform business-secret rotation or consumer activation. [Infisical Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth) documents periodic-token renewal and bootstrap credentials that can become unusable; the [operations page](operations-and-compatibility.md) describes the proposed recovery constraints.

Standalone samples would demonstrate these flows only inside SecretKit. Event and Configurator retain their meaning, activation, tenant, and persistence policies; no edits or migrations are included.

[Public design overview](README.md) | [Adoption and value](adoption-and-value.md) | [Operations and compatibility](operations-and-compatibility.md)
