# SecretKit Runtime Contracts

> Audience: SDK implementers, security reviewers and consumer integrators
> Status: Proposed / unimplemented
> Owner: SecretKit runtime and security maintainers
> Last Verified: 2026-10-09, bounded design evidence and local links only
> Source Anchors: [architecture](SDK_ARCHITECTURE.md), [delivery](DELIVERY_AND_MAINTENANCE.md), [R4 evidence](../../dev/active/secretkit-sdk/research-evidence.md)

This proposal defines observable ownership and failure behavior without claiming a remote transaction, replay guarantee or process-wide plaintext protection.

## Material Ownership And Disposal

Each successful material acquisition would return an independent caller-owned disposable copy. Two reads or two callers would never receive the same mutable/disposable material owner. Disposing one copy would clear its owned buffer and make further access fail; it would not invalidate another caller's copy or mutate cached storage. Explicit reveal/copy/export operations would delimit plaintext access. Generated record formatting, default serialization and exceptions would not expose material.

Material acquisition from a snapshot would occur through an acquired generation handle. That handle would pin internal immutable generation storage while acquisition was possible. Copies already returned would have independent lifetimes and would remain usable after the handle was released until their own disposal.

The proposed concurrency contract would linearize acquire versus retirement. Publication would atomically replace the current generation pointer only after all required entries were prepared. The old generation would become retired, prohibit new handle acquisition, and release its internal material storage only after every previously acquired handle released it. A handle release would be idempotent, with no counter underflow or double clearing. An acquisition racing with retirement would either acquire the old valid generation before retirement or acquire the new one, never obtain freed storage.

Snapshot disposal would retire its current generation and reject future acquisitions, not clear buffers under active readers. Disposing the snapshot would not dispose caller-owned clients, transports or material copies. Material reveal racing with its own disposal would either finish an explicitly synchronized copy or fail as disposed; it would never read an already cleared buffer. No borrowed mutable span would escape an owner lifetime.

Clearing SDK-owned buffers would be best effort within those buffers, not secure erasure of the process. Provider SDKs, parsers, HTTP handling and caller exports could create managed strings or other copies. GC, crash dumps and OS memory could retain them. There would be no promise that the wrapper's protection survives explicit export.

## Snapshots, Freshness And Coherence

A coherent local multi-key operation would acquire one immutable generation and obtain all required keys through it. Separate calls to the current snapshot could observe different generations. Refresh would collect and validate all required entries, then publish once; failure would leave the previous generation unpublished as new, with truthful failure/freshness status.

Local generation identity would mean local publication coherence, not remote atomicity. Each observation would retain provider instance and scoped identity evidence, actual remote version identifiers where supplied, collection start/end times, and the consistency evidence available from that provider operation. Per-item observations from different remote instants would remain visible even inside one locally immutable generation. Missing versions would remain unknown, not be synthesized from material hashes.

Paginated inventory would record the collection window, page/result completeness and applicable limits. Concurrent remote changes could make it inconsistent. Unpaginated lists would still require response/item budgets and would not imply a transaction. Required point-in-time semantics would fail closed if unproven. If a provider supplied a supported snapshot/version contract, it would remain native until shared semantics were demonstrated.

Optional caching would be disabled by default and scoped by provider instance, trusted endpoint policy, identity/credential generation, address, namespace, version, resolution mode and consumption-validity policy. Cached storage would own its copies; callers would obtain independent copies. Eviction and shutdown would retire generation storage using the same handle rules. Cache state would not leak across identities, and TTL would not exceed a known validity boundary. Dynamic leased credentials would not silently enter a generic cache.

Fresh reads would bypass the material cache when requested and report actual observed versions and timing. Failed/denied reads would not become successful stale reads. Any explicitly permitted stale-use policy would expose staleness and its deadline; required fresh semantics would reject it. Provider success retrieving an expired Azure secret would not by itself prove normal consumption validity.

## IConfiguration Is Explicit String Export

The configuration adapter would first prepare a complete asynchronous export, then publish the selected key mapping and signal reload. It would not hide remote I/O in synchronous configuration loading.

Export would deliberately create ordinary strings. `IConfiguration` indexer reads would be per-key and would not guarantee that a multi-key consumer saw one generation while reload occurred. A caller needing coherent multi-key behavior would use an acquired SDK generation or an application-owned immutable typed object built from one generation, not a series of indexer reads.

Debug views, enumeration, options binding, validation exceptions and logs could expose exported values. Old options instances and consumer fields could retain old strings after reload. Clearing internal SDK buffers or disposing the configuration adapter would not erase those strings or restore wrapper protection. The host would own restrictions on debug endpoints, option dumps, serializers, instrumentation, dumps and logs. The adapter would not claim that `IOptions` rebinding equals fleet convergence.

## Outcomes And Cancellation Receipts

Expected provider outcomes would use bounded material-free states rather than arbitrary provider exception text. Success, absence, denied, unavailable, invalid, throttled, conflict, pending and unknown would be distinguishable where supported. Programming misuse would remain an argument/disposal error. Provider payloads, raw responses, credentials, sensitive addresses and vendor inner exceptions would not enter ordinary diagnostics.

The caller would obtain a caller-held operation receipt before dispatch. This order is essential: cancellation after send could prevent a return value, so a receipt created only in a successful response could not preserve uncertainty. The receipt contract would describe dispatch/effect evidence only; it would not add a lifecycle-native feature to Core.

| Proposed receipt phase | Evidence and permissible interpretation |
| --- | --- |
| Established / not dispatched | Local intent registered; dispatch has not crossed the recorded transport boundary |
| Dispatched / outcome not known | Request handed to transport; remote acceptance or effect is not yet established |
| Known | Supported response or observation establishes the recorded bounded outcome, including pending/rejected/applied as applicable |
| Unknown after dispatch | Cancellation, transport loss or incomplete evidence leaves effect unresolved |

The transition to dispatched would be recorded before handing the request to a transport capable of sending it. This conservative boundary would not pretend the SDK can prove which bytes a server received. Not dispatched could be claimed only when the operation never crossed that boundary. Receipt updates would be concurrency-safe and monotonic in evidence: a known effect already recorded would not be rewritten as no effect when cancellation arrived. A later supported observation could refine unknown to known without erasing the dispatch history.

Cancellation would propagate `OperationCanceledException` (OCE), not become absence, an ordinary outcome or a successful receipt return. The caller would still retain the previously obtained receipt. Cancellation after dispatch would never mean no write, rollback, revoked issuance or untouched destination. The receipt would contain no material, credential, payload or sensitive path. Provider IDs retained for supported reconciliation would be controlled metadata, not automatic log fields.

A local correlation ID would not be a provider idempotency key or remote query handle. Only actual provider-issued handles and documented supported observations could enable reconciliation. A subsequent value/version read might not uniquely identify which concurrent caller wrote it; ambiguity would remain unknown. No blind replay, read-then-write CAS, invented idempotency or cross-provider transaction would be offered.

Azure Set Secret could create a new version on each accepted call. Side-effecting transport retries would therefore be zero. A lost response would preserve uncertainty and require an explicitly authorized subsequent action based on supported evidence, not automatic submission of the same request.

## Imports And Destination Approval Effects

The parent reports that the published Infisical import-create contract explicitly includes replication and approval effects. That functional fact must be mapped even when approval administration is outside admitted SDK scope; no backend/SDK source or source summary is needed to establish it.

The proposed native import result and receipt would distinguish:

1. Import resource created: the source/destination relationship exists as supported evidence shows.
2. Replication requested: delivery work was requested, not necessarily completed.
3. Destination approval pending: provider policy delays destination application.
4. Destination applied: supported destination evidence establishes application under the relevant scope/version.
5. Destination unknown: the response or available observation does not establish the destination outcome.

Import resource creation could coexist with pending or unknown destination state. A create response, requested replication or administrative source read would not prove intended-identity destination access. Approval, votes and merge/application would remain distinct even if no approval-policy/request/vote/merge module were shipped.

Missing approval-administration contracts would be vendor gates, not a reason to strip admitted import effects from the registry or pretend writes are immediate. No automatic bypass identity would be selected. An explicitly authorized native exception could be admitted only with its own supported contract and permissions.

## Client, Credential And Transport Ownership

Injected provider clients, `TokenCredential`, HTTP clients/handlers and other transports would be caller-owned unless an explicit ownership-transfer contract were selected. Registration or wrapping alone would not transfer ownership. SecretKit would dispose only resources it created or explicitly accepted by transfer, once and after in-flight use had drained according to the declared shutdown policy.

Immutable instance configuration would bind trusted endpoint/cloud, authority, credential generation and namespace. Supported reusable SDK clients would be shared only where their documented thread-safety contract permitted it. Mutable builders/options would not be shared as runtime state. Material ownership and credential ownership would remain separate.

Caller-supplied clients would have to demonstrate compatible security/retry configuration; otherwise the adapter would reject the required guarantee before dispatch. Merely wrapping an uncontrolled client would not establish diagnostic redaction or no-replay.

For Azure, the proposed pipelines would disable upstream SDK-owned logging, content logging and distributed tracing through supported diagnostics options. Side-effect retries would have `Retry.MaxRetries = 0`; separately configured read/status operations could use bounded retries after admission. A status query would not resubmit an LRO-start request. Challenge-resource verification would remain enabled; `DisableChallengeResourceVerification` would not be enabled.

Host-owned credential, HTTP and OpenTelemetry instrumentation would remain the host's responsibility. Disabling Azure diagnostics would not silence separately configured exporters or erase material the host already revealed.

Endpoints would use HTTPS and normal certificate validation. Approved secure proxies/private endpoints and custom CA trust could be configured explicitly without disabling validation. Any development HTTP exception would be explicit, local and excluded from production claims. Redirects, next links, challenge resources and proxy authentication would not send credentials outside the configured trusted origin/cloud policy. No automatic TLS bypass, fallback endpoint or IP-family workaround would be inferred from Event.

## Authentication And Optional Host Maintenance

The adapter would consume explicit credential/token/proof sources. Azure would accept caller-selected `TokenCredential`, not choose a hidden default credential chain. Infisical auth methods would be admitted individually; cloud proof creation and external federation would remain explicit host or approved integration responsibilities.

Normal token constraints would follow actual supported responses: expiry, maximum lifetime, use limits, periodic renewal and revocation are not interchangeable. Authentication could fail while configuration remained locally loaded; readiness would report this honestly without revealing the token.

An optional helper in SecretKit.Extensions.Hosting would maintain admitted renewals only after explicit host startup. Provider client construction, DI registration, configuration export and a first read would not silently launch it. Concurrent renewal demand would share one in-flight renewal per instance/credential generation. Cancellation by one waiter would not cancel maintenance required by other authorized waiters; host shutdown would own the maintenance cancellation scope.

The helper would use injected time, bounded renewal scheduling and retries supported by the operation's effect/idempotency evidence. No layered replay loop, fallback identity or unlimited re-login would occur. An uncertain renewal would preserve receipt evidence and apply only an admitted recovery policy. Status would distinguish not started, ready, renewal due/in flight, degraded, expired/revoked, recovery required and stopped without token contents.

Shutdown would stop scheduling, cancel/drain in-flight work within a documented bound, retain truthful outcome evidence and dispose only owned resources. Fake-time tests and event barriers would cover renewal timing, single-flight behavior, maximum lifetime, waiter cancellation and shutdown; fixed sleeps would not prove those contracts.

After process restart an in-memory token would be lost. A consumed single-use bootstrap credential could not be assumed to log in again. Explicit authorized recovery would be required; the SDK would neither loop against consumed credentials nor persist plaintext tokens to disk. Optional renewal would not imply durability or unlimited authority.

## Bulk Operations

Each native bulk family would declare maximum item count, response/material budget, bounded parallelism and queue capacity. Producers would observe backpressure rather than enqueue unlimited work. Results would retain caller input ordinals and expose deterministic input-order aggregation even if individual completion order differed. Resource-sensitive serial ordering would be preserved where the provider contract required it.

The caller would establish per-item receipts before each item's dispatch, including when a bulk request shared one transport envelope. Cancellation would stop admitting new work and propagate OCE while leaving receipts available. Never-dispatched items, sent unknown items, rejected/pending/applied items and known failures would remain distinguishable. Already-completed outcomes would not disappear when a different item failed.

Provider bulk atomicity would be reported only when supported evidence proved it. Separate HTTP calls would not constitute a transaction; mixed-provider batches would never promise one. Partial outcomes would retain actual versions and effect evidence. Automatic replay of the entire batch after a lost response would be prohibited.

## Functional Sources And Verification Limits

- [Azure Set Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret): version creation is not proof of CAS or idempotency.
- [Azure retry options](https://learn.microsoft.com/en-us/dotnet/api/azure.core.retryoptions.maxretries?view=azure-dotnet), [diagnostics options](https://learn.microsoft.com/en-us/dotnet/api/azure.core.diagnosticsoptions?view=azure-dotnet), [challenge verification](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.secretclientoptions.disablechallengeresourceverification?view=azure-dotnet): candidate public controls requiring adapter tests.
- [Infisical Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth): periodic renewal and bootstrap constraints.
- [Infisical pagination](https://infisical.com/docs/api-reference/overview/pagination), [rate limits](https://infisical.com/docs/api-reference/overview/rate-limits), [references](https://infisical.com/docs/documentation/platform/secret-reference): collection, retry-timing and resolution limits.
- [Infisical approval workflows](https://infisical.com/docs/documentation/platform/secrets-mgmt/concepts/approval-workflows): approval does not itself establish application.

Links and inherited public functional observations do not verify the proposed runtime. The parent owns refreshed source evidence, including the precise import-create citation. No provider calls, tests, source/schema ingestion or implementation occur in this document task.
