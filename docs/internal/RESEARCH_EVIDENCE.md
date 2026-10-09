# Research evidence and source boundary

> **Audience:** SecretKit maintainers and reviewers
> **Status:** PROPOSED DESIGN; source evidence is not runtime conformance
> **Owner:** SecretKit maintainers
> **Checked:** 2026-10-09
> **Revision:** R5

## What was actually researched

The requested Tavily MCP and Context7 MCP now respond. Tavily searches returned official Dapr/reference links; extraction of several primary URLs was rate-limited with HTTP 429. Context7 resolved `/dotnet/docs` and `/infisical/infisical`; the .NET hosted-service query supplied documentation facts, the broad configuration query returned no match, and the Infisical query returned irrelevant PKI/backend material. Empty/irrelevant/throttled results are not evidence for the requested behavior.

Vendor backend/source-derived material from that query was excluded from the design and handoff. The import conclusion comes from the public API reference, not backend implementation. No vendor source, schema expression, generated models, tests or snippets are incorporated here. Necessary public wire identifiers and independently described functional facts are permitted interoperability evidence, not a code-generation blueprint.

Native retrieval of primary pages completed gaps. This is not a claim that Tavily extraction succeeded or that Context7 verified all contracts. No SDK code, server operation, package install, live provider mutation or consumer deployment was executed in this documentation request.

## Primary functional facts

| Topic | Source | Evidence and design consequence |
| --- | --- | --- |
| Configuration values | [IConfiguration indexer](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.iconfiguration.item?view=net-10.0) | The host reads ordinary strings. Export from protected material is a deliberate plaintext boundary, not preservation of wrapper guarantees. |
| Debug views | [GetDebugView](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.configuration.configurationrootextensions.getdebugview?view=net-10.0-pp) | Value processing/filtering is available. Host debug dumps, options serialization, logs and GC string lifetime remain explicit responsibilities after export. |
| Provider precedence | [Configuration providers](https://learn.microsoft.com/en-us/dotnet/core/extensions/configuration-providers) | Later providers can override matching keys. Selected-authority SDK behavior alone cannot establish an application's complete bootstrap precedence. |
| Runtime options | [Options](https://learn.microsoft.com/en-us/dotnet/core/extensions/options) | Monitor/change notifications do not themselves fetch from a secret manager, rebuild arbitrary clients or coordinate workers. |
| Hosted lifecycle | [Hosted background tasks](https://learn.microsoft.com/en-us/dotnet/core/extensions/workers), Context7 official `.NET` documentation | Host start/stop/cancellation ownership supports a narrowly scoped optional maintenance service. Tests use fake time and exact events, not timing luck. |
| Periodic tokens | [Infisical Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth) | Renew before expiry, including idle periods. A lost process token and consumed/expired bootstrap credential require explicit recovery; a loop cannot manufacture authority. |
| Import effects | [Create secret import](https://infisical.com/docs/api-reference/endpoints/secret-imports/create) | Replication can create destination approval requests. Import-resource success, requested replication and destination application are not the same result. Approval administration exclusion does not remove this admitted-operation effect. |
| Runtime reads | [Retrieve secret](https://infisical.com/docs/api-reference/endpoints/secrets/read) | Retrieval is not confined to deployment. No-restart integration activation depends on application client/worker lifecycle and freshness, not the existence of a startup configuration provider. |
| Uncertain writes | [Azure Set Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/set-secret/set-secret?view=rest-keyvault-secrets-2025-07-01) | Setting an existing name creates a version. A local receipt/cancelled task does not prove no remote effect or make a mutation queryable/idempotent. |
| Cancellation | [OperationCanceledException](https://learn.microsoft.com/en-us/dotnet/api/system.operationcanceledexception?view=net-10.0) | Cancellation remains cancellation. The pre-created receipt is separate dispatch/outcome evidence; SDK behavior must not reinterpret it as rollback. |
| Cache freshness | [Sliding expiration](https://learn.microsoft.com/en-us/dotnet/api/microsoft.extensions.caching.memory.memorycacheentryoptions.slidingexpiration?view=net-10.0) | Inactivity-based expiry does not establish a maximum age under hot access. Activation/check-again needs explicit force-fresh semantics and normal caching needs a bounded absolute/freshness policy. |
| Azure configuration baseline | [Azure Key Vault configuration integration](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/extensions.aspnetcore.configuration.secrets-readme?view=azure-dotnet) | Direct existing providers are a legitimate baseline for basic startup settings; the proposed library must prove additional integration value. |
| Dapr | [Secrets API](https://docs.dapr.io/reference/api/secrets_api/), [retrieval workflow](https://docs.dapr.io/developing-applications/building-blocks/secrets/howto-secrets), [SDK usage](https://docs.dapr.io/developing-applications/sdks/dotnet/dotnet-secrets/dotnet-secrets-howto/) | Individual/bulk retrieval and the Dapr operational model are existing alternatives. The design does not assert novelty or superiority and does not clone their implementation. |
| External injection | [Vault Agent](https://developer.hashicorp.com/vault/docs/agent-and-proxy/agent) | Agent/file/environment approaches may make a direct provider SDK unnecessary. Choice depends on operator/deployment requirements. |
| Owned-code licensing | [GNU licensing FAQ](https://www.gnu.org/licenses/gpl-faq.en.html) | Copyright holders can offer different licenses when rights permit. Contributor/third-party material and project policy still require review; MIT reuse or schema generation is not authorized by assertion. |

## Proposed decisions versus provider guarantees

These are SecretKit design choices, not guarantees obtained from vendor documents:

- Acquired immutable local generations and independent caller-owned material copies.
- Before-dispatch receipts with cancellation plus separate dispatched/unknown evidence.
- Explicit plaintext configuration export and no promise of coherent multi-key indexer reads.
- Optional host-owned periodic-auth maintenance with recovery status.
- Bounded bulk concurrency, safe diagnostics and native capability segregation.
- Consumer-owned desired/observed revisions, late-disable guards, client-generation handover and material-free replica notifications.

Remote consistency requires an actual supported provider contract. Otherwise record versions and collection timing and call it a locally consistent assembled generation, not a transactional remote snapshot.

## Scope, admission and compatibility

R4 research counted 1,699 documentation pages and 2,381 public method/path facts. Those include adjacent and replaced APIs and are not implemented operation counts. The public-API-complete release target remains an explicitly labeled planner default after a prior unanswered question. Neither source cohorts nor admission policy is a populated operation registry.

Before estimate/completion claims, each admitted operation needs a supported wire contract, current-version decision, owner, permission/effect/sensitivity, tests and actual compatibility evidence. Provider breadth and feature depth are separate dimensions.

A compatibility matrix initially has no verified rows. Record tested Infisical release/edition, Azure API/cloud, runtime/platform, feature depth and evidence revision. Unknown required semantics fail closed; no silent downgrade. Supporting an older tested provider protocol is not a reason to preserve obsolete SecretKit API shapes.

## Repository and rights evidence

SecretKit starts as an independent MIT repository under `islamu-ngo/SecretKit`, with no product projects at the reviewed baseline. Event and Configurator are read-only requirements/evidence sources. Existing Event bindings/bootstrap/activation policy and Configurator definitions/review UX are not imported into SDK domain models.

The project chooses a clean-room/provenance policy to protect outbound licensing. That is not a universal legal assertion that owned code always needs rewriting. Review file-level owner/contributor/third-party rights before reuse; compatible model-generation inputs require their own approval. No code transfer, dependency addition or generator execution occurred here.

## Remaining evidence

No actual SDK, provider compatibility row, adoption timing, externally installed consumer, replica activation, Native AOT/trimming build, resolved transitive license graph, vulnerability result, sandbox entitlement or NuGet publication is verified. The phased ledger names those later gates and moves high-risk/provider/installed-consumer evidence earlier. No external maintainer was contacted.

Use this durable source anchor with [runtime contracts](RUNTIME_CONTRACTS.md), [delivery and maintenance](DELIVERY_AND_MAINTENANCE.md), [review traceability](REVIEW_TRACEABILITY.md) and the [decision record](adr/ADR-001-capability-aware-secret-sdk.md).
