# MQContract and SecretKit: provider architecture, engineering practices, and adoption strategy

**Research date:** 2026-10-11

**Purpose:** An extensive comparative engineering report, not an implementation plan or a product-readiness certification.

**MQContract examined:** `roger-castaldo/MQContract`, commit `fcd14d6103a743b4d0688a2633a1ffcf788c6261`.

**SecretKit examined:** commit `f7b1f7aec9f312fc2cbc54d1ea797d02824512ad`.

**Authority:** The current SecretKit contributor contract and accepted core-first scope govern recommendations. The request authorizes studying MQContract and producing this report; it does not change SecretKit's product scope.

Both working trees were clean at intake. MQContract's public `master` commit was independently checked through GitHub's API and matched the inspected clone. SecretKit references describe the local revision, which is the comparison baseline; they do not imply that every referenced artifact is publicly released.

## Contents

1. [Engineering judgment and the benefits worth pursuing](#1-engineering-judgment-and-the-benefits-worth-pursuing)
2. [Research method and strength of evidence](#2-research-method-and-strength-of-evidence)
3. [Where the analogy holds, and where it breaks](#3-where-the-analogy-holds-and-where-it-breaks)
4. [Repository structure and package boundaries](#4-repository-structure-and-package-boundaries)
5. [The common contract and extension mechanism](#5-the-common-contract-and-extension-mechanism)
6. [Execution paths through MQContract](#6-execution-paths-through-mqcontract)
7. [All twelve providers: capability and dependency matrix](#7-all-twelve-providers-capability-and-dependency-matrix)
8. [Provider case studies and semantic differences](#8-provider-case-studies-and-semantic-differences)
9. [Provider-onboarding conventions](#9-provider-onboarding-conventions)
10. [Capabilities, permission, and truthful support](#10-capabilities-permission-and-truthful-support)
11. [Middleware, serialization, and policy placement](#11-middleware-serialization-and-policy-placement)
12. [Resilience, mutation uncertainty, and recovery](#12-resilience-mutation-uncertainty-and-recovery)
13. [Ownership, concurrency, cancellation, and bounds](#13-ownership-concurrency-cancellation-and-bounds)
14. [Observability and protected diagnostics](#14-observability-and-protected-diagnostics)
15. [Source generation, reflection, and NativeAOT](#15-source-generation-reflection-and-nativeaot)
16. [Documentation and consumer experience](#16-documentation-and-consumer-experience)
17. [Testing and provider conformance](#17-testing-and-provider-conformance)
18. [GitHub workflows and CI](#18-github-workflows-and-ci)
19. [Packaging, dependency management, and releases](#19-packaging-dependency-management-and-releases)
20. [Benchmarks and performance evidence](#20-benchmarks-and-performance-evidence)
21. [SecretKit gap assessment](#21-secretkit-gap-assessment)
22. [A recommended target design for extensibility](#22-a-recommended-target-design-for-extensibility)
23. [Prioritized adoption roadmap and acceptance criteria](#23-prioritized-adoption-roadmap-and-acceptance-criteria)
24. [MIT reuse, attribution, and practical transfer](#24-mit-reuse-attribution-and-practical-transfer)
25. [Open questions, verification limits, and final recommendation](#25-open-questions-verification-limits-and-final-recommendation)
26. [Evidence register](#26-evidence-register)

## 1. Engineering judgment and the benefits worth pursuing

MQContract is a valuable reference for building a family of provider adapters around a stable consumer contract. It demonstrates the practical relationship among a common abstraction, separately installable connectors, provider-specific setup, repeated consumer examples, shared behavioral tests, and a CI inventory that knows about every connector. Its value is not merely that it supports many brokers. Its value is that the repository contains an identifiable procedure for making another broker participate in the same application-facing workflow. [M01], [M02], [M03], [M04]

SecretKit should adopt that repeatability. A new secret provider should be able to implement a small established contract, use a standard set of behavioral scenarios, supply native addressing and authentication, publish a precise support statement, and join predictable verification jobs. The maintainer should not have to invent the testing, documentation, packaging, and support-evidence process again for every provider.

However, MQContract is not uniformly more mature than SecretKit. SecretKit already has stronger explicit contracts in several areas that matter particularly for secrets: selected authority, references bound to one instance, owned disposable material, bounded outcomes, controlled diagnostic exposure, cancellation propagation, and pre-dispatch mutation receipts. Its central dependency policy, default non-packability, installed-package consumer checks, and protected publication design also improve on practices visible in MQContract. These are implemented or documented assets to preserve, not obstacles to remove. [S01], [S02], [S03], [S04], [S05], [S06], [S07]

The highest-return improvements are therefore:

1. **A shared provider contract test system.** The same invariant should be exercised through Infisical and Azure, and later through additional providers, without duplicating the definition of correct common behavior.
2. **A provider implementation and admission guide.** Establish exactly what another adapter must supply, what it may leave unsupported, how authority and ownership work, and which evidence is necessary.
3. **Complete clean-checkout verification CI.** SecretKit has publication machinery but no checked-in upstream `verify.yml` producer at this revision. Routine verification should work independently of publication. [S08], [S09]
4. **A current support/evidence index.** Users should be able to distinguish common support, native support, implemented subsets, offline tests, and scoped live evidence without reconstructing historical research.
5. **A shorter first-use path.** Show a small common consumer operation against each selected provider, with provider setup isolated and protected material handled correctly.
6. **Evidence-driven future expansion.** Add another provider only after the current contract and onboarding process are repeatable, and select it for actual adopter demand rather than to increase the provider count.

This is an extension strategy, not a recommendation to rewrite the SDK. MQContract shows how to multiply implementations around common seams. SecretKit must retain a narrower meaning of portability and a stricter account of authority and effects.

## 2. Research method and strength of evidence

### 2.1 Sources examined

The investigation used the local repositories as primary evidence. It inspected MQContract's root documentation and license; Abstractions, Core, Generators, and CQRS; every connector family; the samples and shared sample execution; test projects and common helpers; both checked-in GitHub workflows; shared build properties; and representative benchmark code.

For SecretKit, it inspected the contributor contracts, current-preview and scope documents, architecture/runtime/delivery documents, common contracts, provider construction and read paths, optional configuration and hosting boundaries, representative adapter tests, live-conformance documentation, installed-package tests, release protocol, release-tool provenance expectations, dependency configuration, and the solution inventory.

Three independent research lanes examined MQContract's core mechanisms, provider implementations, and engineering system. Their findings were reconciled with direct source inspection. Where two lanes disagreed or a claim depended on package behavior, the report did not simply choose the harsher interpretation.

The comparison uses these evidence levels:

| Evidence level | What it establishes | What it does not establish |
| --- | --- | --- |
| Source observation | An interface, dependency, implementation branch, configured workflow, or stated invariant exists at the revision | That the path passes, is exercised, or works in a particular deployment |
| Source deduction | A consequence follows from visible control flow or configuration | A reproduced runtime failure unless executed evidence exists |
| Inspected test | A scenario and assertions exist | That the test was discovered, passed, or covers all provider behavior |
| Repository-recorded historical result | The repository records a particular prior verification result | A fresh rerun during this study |
| Public service metadata | A package page or GitHub run reports a specific published state | Complete semantic compatibility or successful provider conformance |
| Recommendation | A proposed SecretKit improvement derived from the comparison | Existing implementation or authorization to implement |

This distinction is important because an SDK can have extensive tests and still lack a shared conformance definition, or have a successful scanner run while its provider matrix has not completed.

### 2.2 Upstream and publication checks

MQContract's inspected commit is the public `master` commit observed during the study. A public NuGet page confirms `MQContract.InMemory` version `4.0.0`, with .NET 8 and .NET 10 assets and a July 9, 2026 update. That establishes publication of this package, not verification of all twelve connectors. [E01], [E02]

The GitHub API returned one push-triggered `.NET-Test` run for the exact commit: run `29015187687`, created on July 9, 2026, completed with conclusion **cancelled**. It is not a passing full-test result. A separate scheduled CodeQL run, `38118962848`, completed successfully on October 11 at the same commit. Code scanning and provider conformance are different checks. The cause of the test cancellation was not established. [E03], [E04]

### 2.3 Navigation and limitations

Filesystem inventory and bounded source reads were used to establish repository structure. SecretKit language-server queries successfully mapped `ISecretReader` usage into both providers, the configuration package, samples, tests, and tooling. MQContract document-symbol requests timed out; source navigation was used instead. No graph installation, dependency installation, restore, SDK build, product test, broker launch, live secret-provider call, or publication occurred in this study.

Context7 did not contain a library entry for MQContract. Its absence was not treated as absence of documentation: local documentation, the public repository, package metadata, and workflow metadata supplied the relevant evidence.

A targeted framework check resolved one misleading test hypothesis. The shared tests use an interpolated assertion message containing a search for an error. At first sight that can look like unconditional evaluation on a successful result set. MSTest `4.2.3` has a condition-aware interpolated-string-handler overload for `Assert.IsTrue`, with interpolation enabled only for a failing condition. Consequently this report does **not** declare those expressions a demonstrated all-success defect. The pinned framework source matters more than an assumption about an older assertion API. [E05]

## 3. Where the analogy holds, and where it breaks

### 3.1 The shared architectural problem

Both libraries sit between application code and several external systems. Each must decide:

- Which operations genuinely belong in a common contract.
- Which coordinates, authentication mechanisms, and lifecycle features remain provider-native.
- How provider SDKs and transports enter the dependency graph.
- How errors and cancellation are represented.
- How reusable consumer code is demonstrated.
- How another provider is added and assessed.
- What a support claim means.

This is why studying MQContract is useful. It has already encountered the tension between a common API and heterogeneous underlying systems.

### 3.2 An identical method signature is not identical semantics

MQContract can expose one query method while implementing it through native NATS request/reply, session-backed Azure inboxes, Kafka pub/sub emulation, or Redis stream/reply-key polling. The entrypoint is common, but setup, resource requirements, delivery behavior, cleanup, and failure semantics differ. [M05], [M20], [M21], [M22], [M23]

SecretKit faces the same issue with reading, writing, versioning, inventory, leases, rotation, backup, recovery, and approval effects. A common `ReadAsync` can preserve a stable outcome and ownership contract while accepting provider-owned references. A universal writer or rotation interface would be more difficult: version creation, conditional mutation, credential issuance, and delayed effects are not interchangeable simply because each can be represented by a task.

The current SecretKit decision is appropriate: common reads and inventory are small; native lifecycle and management operations remain typed and provider-owned. It explicitly avoids speculative common backup, lease, rotation, or recovery interfaces. [S01], [S10], [S11]

### 3.3 Secrets require additional invariants

Messaging libraries routinely expose routing names, message identifiers, headers, exception details, and payload-oriented serializers. SecretKit deliberately treats material and coordinates as protected data and distinguishes explicit export from normal formatting and serialization.

Likewise, retrying a message transmission is often considered a normal resilience mechanism, subject to broker guarantees. Retrying a secret mutation after a lost response can create another version, issue another credential, repeat a destructive operation, or confuse an approval state. A local correlation ID does not prove provider idempotency.

These differences do not make a multi-provider secret SDK impractical. They mean its common contract must include safety and evidence semantics, not merely connectivity. A simpler SDK should reduce repetitive consumer work while retaining those guarantees.

### 3.4 Current scope and future extensibility

The accepted SecretKit scope remains completion of direct Infisical and Azure secret access plus selected native and administrative essentials. The removed Infisical third-party app-connection/sync catalog is not a missing collection of direct SecretKit providers. Reintroducing that catalog would not solve provider extensibility.

A direct SecretKit adapter connects the application to a secret manager. An Infisical connection/sync administration API configures Infisical's interaction with another destination. These are different product boundaries. Future support for more secret managers should add direct provider packages with their own contracts and evidence, not revive destination orchestration under another name. [S12], [S13]

## 4. Repository structure and package boundaries

### 4.1 MQContract's visible organization

The relevant structure is:

```text
MQContract/
  Abstractions/
    Attributes/
    Interfaces/
      Service/
      Consumers/
      Encoding/
      Encrypting/
      Conversion/
      Middleware/
    Messages/
  Core/
    Connections/
    Defaults/
    Factories/
    Helpers/
    Logging/
    Middleware/
    Subscriptions/
    MessageContext*.cs
  Connectors/
    ActiveMQ/
    AmazonSNQS/
    ApachePulsar/
    AzureServiceBus/
    GooglePubSub/
    HiveMQ/
    InMemory/
    Kafka/
    NATS/
    RabbitMQ/
    Redis/
    ZeroMQ/
    Shared/
  Generators/
  CQRS/
  Samples/
    Messages/
    <provider samples>/
  Testing/
    Core/
    CodeGenTesting/
    CQRSTesting/
    ConnectorTesting/
      Shared/
      <provider suites>/
  BenchMark/
  .github/workflows/
  Shared.props
```

The structure makes several responsibilities immediately visible. Contracts, execution machinery, connectors, code generation, higher-level CQRS, examples, tests, and performance experiments have separate owners. Most importantly, every connector is a separate project with its own SDK dependencies and an identifiable sample/test counterpart. [M03], [M04], [M06]

### 4.2 Dependency direction

The main runtime relationships can be understood as:

```text
Application
  -> MQContract Core implementation
  -> selected connector

Core implementation -> Abstractions
Selected connector  -> Abstractions + selected provider SDK
CQRS                 -> Abstractions
Generators           -> Roslyn, as compile-time tooling
```

Connectors generally reference Abstractions rather than Core. Shared implementation helpers are linked into connector projects as source. InMemory additionally links `Core/EnumerableExtensions.cs`; this is source reuse across folders, not a normal runtime project dependency. [M06], [M07]

There is an important qualification: MQContract's Abstractions package is not BCL-only. It references health-check abstractions and has a generator/analyzer relationship. Core references DI, logging, Polly, and Roslyn, and includes many optional runtime concerns in one implementation package. [M08], [M09]

This distinction prevents a misleading package-name comparison. MQContract **Core** is primarily its shared execution engine. SecretKit **Core** is primarily its common contracts and safety primitives. Renaming or splitting SecretKit merely to reproduce MQContract's vocabulary would not improve dependency direction.

### 4.3 SecretKit's current organization

SecretKit already has seven source packages under `src/`, with matching provider/feature test projects under `tests/`, separate samples and tools, public/internal documentation, a solution file, central package versions, and a repository-wide build policy. Its providers depend inward on Core; management dependencies are isolated; configuration export and hosting are independent optional layers. [S01], [S14], [S15]

The inspected source inventory contained 118 production C# files: 8 in Core, 29 in Infisical, 5 in Azure runtime, 61 in Infisical management, 10 in Azure management, 4 in Configuration, and 1 in Hosting. These are filesystem counts, not operation counts, complexity scores, or evidence that a package is complete.

The concentration in provider-native and administrative code suggests where maintenance attention is likely to be needed. It does not justify a global restructuring. Some native families have many types because the contracts preserve absent/null/false distinctions, scope, effects, and protected values.

### 4.4 What to adopt structurally

Adopt the **parallel provider unit**: implementation, public guide, common-contract scenarios, native-specific scenarios, provider fixture, and declared compatibility should form one coherent contribution.

Keep SecretKit's existing `src/`, `tests/`, `samples/`, `tools/`, and `docs/` organization. It already communicates project purpose well. There is no demonstrated benefit in changing it to `Connectors/`, renaming packages, introducing an umbrella package, or creating a shared execution engine that every operation must pass through.

Introduce deeper folders only where a concrete module has become difficult to navigate. A folder move is useful when it gives a native family an owner; it is not useful merely to create a tree resembling another repository.

## 5. The common contract and extension mechanism

### 5.1 The seam that makes MQContract extensible

`IMessageServiceConnection` defines a compact transport-facing surface: maximum message body size, publish, bulk publish, subscribe, and close. `ContractConnection.Instance` accepts an implementation directly. Core is not required to know a list of provider names before it can use another connector. [M02], [M03]

This is the most transferable architectural property. Provider support is supplied through an implementation of a public contract, rather than a giant central provider switch or reflection-based plugin requirement.

Application-facing typed messages are converted into a provider-neutral service envelope. Connectors translate that envelope into the relevant SDK's wire representation. For example, one connector maps the message type into native headers, another into Service Bus subject metadata, and another into a custom binary frame.

The common contract reduces the amount of broker-specific code in consumers, but it does not fully define broker semantics. Durability, consumer-group interpretation, startup readiness, and transport ownership are not uniformly established by the minimum interface.

### 5.2 Optional capability interfaces

MQContract uses additional interfaces for direct request/reply, inbox-based request/reply, query responders, and ping. Core selects an implementation path based on the supplied connector's interfaces.

This is better than forcing every connector to expose every transport primitive as a meaningless no-op. However, interface membership describes what an adapter can execute, not necessarily what the broker natively guarantees. Redis implements the direct-query interface while synthesizing the operation through streams and polling. [M05], [M23]

The lesson is to use small optional contracts while documenting their observable meaning. Interface segregation is not a substitute for a semantic specification.

### 5.3 SecretKit already has the essential seam

`ISecretReader` has an explicit `Authority` and one cancellation-aware `ReadAsync`. `ISecretInventory` is separate. Both runtime providers implement these contracts, and the configuration package consumes `ISecretReader` without referencing a particular provider. `SecretSelection` checks that the reference belongs to the selected reader. [S16], [S17], [S18]

Therefore SecretKit does not need a new universal facade before it can support another provider. Its common seam is already present. What is missing is a repeatable way to demonstrate that another implementation honors the seam.

The current authority-bound `SecretReference` intentionally carries a provider-owned address. This means a consumer can perform the same read workflow after selecting a provider, but cannot necessarily reuse an Azure address against Infisical. This is truthful portability: portable consumption behavior with native address construction.

### 5.4 What should remain outside the common seam

Keep provider-native credential issuance, rotation, approvals, imports, recovery, and opaque backup artifacts outside an unproven universal API. Do not make a provider implement an operation by changing its preconditions, choosing another identity, or silently moving to another provider.

For future providers that cannot support metadata inventory under the same meaning, implement the reader and declare inventory unavailable. Do not invent a list by reading values or treat inability to enumerate as inability to read a known reference.

## 6. Execution paths through MQContract

### 6.1 Publish

The ordinary single-service publish path is:

```text
Typed application value
  -> TransmissionMessage wrapper
  -> message metadata/factory resolution
  -> before-encode middleware
  -> selected encoder
  -> service envelope
  -> after-encode middleware
  -> selected resilience policy
  -> connector publication
  -> transmission outcome and diagnostics
```

The wrapper centralizes behavior that would otherwise be repeated across consumers. Encoding and middleware occur before transport retry; a retry resends the prepared envelope. The connector does not have to reproduce message-type discovery, typed conversion, or connection-level telemetry. [M10], [M11]

Mapped connections choose one matching transport. Multi-service connections can transmit through several matching transports and aggregate results. Routing uses the produced message's channel, type, and headers.

This is useful messaging composition. For SecretKit, the comparable reusable part is the consumer workflow around common reads, outcomes, observations, and material ownership. It does not imply that SecretKit needs cross-provider read fallback or fan-out mutations.

### 6.2 Query

Core chooses among three paths:

1. A connector-provided direct query operation.
2. A correlated connector inbox.
3. Core-created pub/sub request/reply.

The fallback path establishes the response listener before sending the request, which is sound ordering. Correlation headers and an explicit reply channel associate the response with the request. [M05], [M12]

But the paths are not identical. Inbox acknowledgement, timeout/cancellation handling, reply-group semantics, response publication, and cleanup differ. The pub/sub query responder does not pass the supplied group in the same way as the query-capable branch. An acknowledgement can precede response publication, so response loss does not imply request rollback.

A common query API is therefore a useful convenience over several mechanisms, not a transaction or exactly-once command protocol.

### 6.3 Subscription and processing

The receive path can filter headers before decoding, decode/convert the message, filter its typed value, apply post-decode middleware, invoke an application callback, and acknowledge according to the chosen path. Header filtering avoids unnecessary decoding. Typed conversion permits multiple message versions to be consumed behind an application-facing type.

Acknowledgement remains provider-sensitive. The common wrapper does not establish one dead-letter, redelivery, or persistence model for every connector. Some adapters await handlers and acknowledgements differently. [M11], [M13]

The SecretKit analogy is to validate returned coordinates, visibility, validity, and material ownership before publishing a successful read. Those checks belong at well-defined boundaries. A successful transport response is not yet proof that the selected secret was delivered correctly.

### 6.4 Routing and bulk lessons

The source contains several reminders that aggregation needs its own contract. Mapped/multi bulk routing uses the first message for route selection; registered maximum size is the minimum across connections; empty batches can reach `First()`; and shared envelopes/headers can be mutable. [M14]

For SecretKit, every bulk family should retain item identity, input order, independent receipts, bounded item/byte/worker counts, and partial outcomes. Do not generalize single-item behavior into bulk behavior merely by adding `Task.WhenAll`.

## 7. All twelve providers: capability and dependency matrix

The following is a source-derived matrix. Body sizes are **adapter declarations**, not independently verified service limits. Query classifications describe adapter strategy. All twelve implement the minimum publish/bulk/subscribe surface and a ping interface, but those signatures do not establish equivalent readiness or delivery guarantees.

| Provider | Query strategy | SDK declaration | Adapter body limit | Material differences |
| --- | --- | --- | --- | --- |
| ActiveMQ | Correlated inbox | Apache.NMS.AMQP `2.*` | 4 MiB | Topic/shared-consumer behavior; owned NMS connection/session; native reply destination |
| AmazonSNQS | Core pub/sub emulation | AWS SNS/SQS `4.*` | 256 KiB | SNS preferred, SQS fallback; SQS subscriptions; group argument not a shared broker group |
| ApachePulsar | Core pub/sub emulation | DotPulsar `[5.3.1,6.0.0)` | 5 MiB | Native subscription mode and starting position; producer/client ownership |
| AzureServiceBus | Session-addressed inbox | Azure.Messaging.ServiceBus `7.*` | 1 MiB | Fixed inbox topology; topic/subscription coordinates; native SDK batching |
| GooglePubSub | Core pub/sub emulation | Google.Cloud.PubSub.V1 `3.*` | 10 MiB | Project/topic/subscription coordinates; subscription provisioning can occur |
| HiveMQ | MQTT response-topic inbox | HiveMQtt `0.2*` | Configured maximum packet size | QoS/shared-subscription semantics; separate subscription clients |
| InMemory | Local inbox | No provider SDK | 4 MiB | Instance-local channels/groups; no broker durability or permission model |
| Kafka | Core pub/sub emulation | Confluent.Kafka and SchemaRegistry `2.*`; NJsonSchema range | Configured maximum, otherwise 1 MiB | Consumer offsets/groups; imposed producer tuning; schema middleware dependencies |
| NATS | Native request/reply | NATS.Net `2.8.1` | 1 MiB | Subject versus stream-name subscription; JetStream configuration remains native |
| RabbitMQ | Exchange/queue inbox | RabbitMQ.Client `7.*` | Factory inbound limit | Exchange type, bindings, queue groups, and reply topology matter |
| Redis | Connector-emulated direct-query interface | StackExchange.Redis `[2.13.17,3.0.0)` | 4 MiB | Redis Streams, not ordinary Pub/Sub; polling and reply keys |
| ZeroMQ | Custom-frame inbox | NetMQ `4.*` | 4 MiB | Explicit socket topology; local callbacks; no equivalent broker group semantics |

Provider implementations and manifests are linked individually in the evidence register. [M20]-[M31]

Most connectors implement bulk publication through the shared transmission worker, generally submitting individual SDK operations. Azure uses the SDK's batch object. A common `BulkPublishAsync` name therefore does not imply native batch atomicity, native batching efficiency, or equivalent partial-failure behavior.

Several SDK versions float within a major/minor pattern or range. Those declarations are not an exact resolved dependency graph. This report does not infer SDK-default retry behavior from a package name, except where the connector explicitly sets policy, as Kafka does.

The practical conclusion for SecretKit is that a provider matrix must describe **semantics and evidence**, not just checkmarks beside method names.

## 8. Provider case studies and semantic differences

### 8.1 NATS: native features need native coordinates

The NATS connector exposes its native connection and JetStream context and provides typed stream creation and consumer configuration. This is a useful example of retaining provider functionality outside the minimum common interface.

The sample publishes to a subject named `StoredArrivals` but maps subscription to a stream named `StoredArrivalsStream`. The distinction is essential. The connector checks stream names to decide whether to create a JetStream consumer or an ordinary subject subscription. A subject and a stream name are not interchangeable universal channels. [M20], [M32]

NATS also shows why construction and support claims need care. The constructor synchronously waits for connection setup. The documented default query timeout says 30 seconds, while the implementation initializes one minute. Ordinary publication calls the NATS publish API; it does not request a JetStream publish acknowledgement merely because the subject participates in a stream.

For SecretKit, preserve Infisical project/environment/folder/key semantics and Azure vault/name/version semantics. A common reference should not erase the coordinate differences, and a successful read should not be promoted into stronger consistency or delivery evidence than the actual operation establishes.

### 8.2 Azure Service Bus: an injected SDK does not settle ownership

The Azure Service Bus connector accepts a `ServiceBusClient`, exposes it, and disposes it on its own close path. The common wrapper also disposes injected service connections. This is convenient when the wrapper is the sole owner, but unsafe as a default rule for a host-shared SDK client. [M21], [M10]

Its RPC-like support requires a specific session-enabled inbox topic/subscription. Tests provision the inbox; a small sample does not make that infrastructure requirement disappear. Native bulk publication uses one sender selected from the first item and a real SDK batch, with admission failure when the batch cannot fit.

SecretKit should learn from the native-batch admission mechanism, but retain host ownership of supplied clients, credentials, and transports. It should also keep provisioning requirements explicit and separate from ordinary runtime access.

### 8.3 Kafka: transport tuning is application policy

The Kafka adapter sets all acknowledgements, idempotence, five retries, backoff, linger, batch size, compression, maximum in-flight operations, and timeouts. These are meaningful reliability/throughput choices, not merely mapping a neutral envelope into a Kafka DTO. Its delivery-callback path does not use the supplied cancellation token in the same way as its consumer receive path. [M22]

Kafka query behavior is Core emulation, but the connector recognizes the reply-group naming convention and changes consumer assignment behavior for it. This is a cross-layer convention that a provider author must know.

Its optional schema middleware also illustrates dependency cost: schema-registry and validation libraries are declared in the connector package even when the feature is not used.

For SecretKit, provider adapters should expose the required contract and make consequential policy choices explicit. Native retry behavior must be controlled where the SDK's mutation contract requires no replay. Optional expensive functionality should not unnecessarily expand the common dependency footprint.

### 8.4 InMemory: reusable demonstrations are useful, simulated guarantees are not

The in-memory adapter makes a quickstart possible without accounts or infrastructure. It demonstrates shared consumer code and instance-local group dispatch. That is a strong onboarding technique.

It does not establish broker persistence, acknowledgement/redelivery, permissions, recovery, or remote readiness. Its local grouping and channel behavior are implementation-specific. It also uses the same shared batch worker as several network connectors, so being in-memory does not remove lifecycle/concurrency concerns. [M24]

SecretKit already has offline demonstration readers in its samples. That is sufficient for demonstrating the consumer abstraction. A production in-memory secret provider is not necessary to reproduce MQContract's onboarding benefit, and should not become a hidden material cache or fallback.

A shared deterministic test fixture can supply controlled reads, denial, cancellation, and material without being marketed as a remote-provider substitute.

### 8.5 RabbitMQ: provider-native topology and effects need direct witnesses

RabbitMQ maps common channels to exchanges and groups to queues. The sample uses fanout exchanges; another exchange type would change routing behavior. The connector also creates an inbox exchange/reply queue and performs synchronous network initialization in its constructor. [M25]

A particularly concrete source counterexample is `QueueDeleteAsync`: the inspected implementation calls `QueueDeclareAsync`, despite its name and documentation describing deletion. This is an observed call-target mismatch, not a reproduced service result. It shows why method names and generated references cannot substitute for effect-level tests.

The SecretKit parallel is direct: a typed administration method must be checked against the actual request and supported effect. A create response, metadata flag, or method name cannot prove revocation, rotation completion, credential invalidation, or destination application.

### 8.6 Redis: a capability can be implemented rather than native

The Redis adapter uses Streams, consumer groups, and temporary reply keys. Its direct-query interface is synthesized through stream append and polling. A responder deletes the original stream entry and writes a reply key in separate operations. [M23]

This is legitimate adapter functionality if documented clearly. It is not equivalent to a broker's native request/reply guarantee or an atomic reply transaction.

SecretKit should label emulation and local composition honestly. Locally coherent generations are useful, but are not remote atomic snapshots. Read-then-write code is not compare-and-swap. A fresh observation is not necessarily attribution of a mutation to one caller.

### 8.7 Amazon and Google: happy-path fixtures can hide alternate-path problems

Amazon's direct SQS publication path writes a Base64 body, while its receive mapping expects an SNS JSON envelope containing `Message`. The connector tests wire SNS topics to SQS queues, so that fixture does not cover the direct-SQS encoding/decoding combination. The mismatch is visible in source; a separate runtime scenario would be needed to establish its observed failure. [M26]

Google's subscription lookup catches broadly and attempts creation. This can conflate missing resources with denied access or a transient lookup failure. [M27]

The transferable lesson is to test each admitted alternative, not merely the most convenient setup. For SecretKit, raw versus expanded references, imported versus local material, metadata-only visibility, disabled/expired values, and denied identities require separate scenarios. An administrative setup fixture must not accidentally validate runtime delivery under the wrong principal.

### 8.8 ZeroMQ: the sharpest boundary of interchangeability

ZeroMQ requires explicit socket binding/connection and custom framing. Subscription grouping is local callback registration; the connector does not honor every common group/error/cancellation input as a broker adapter would. A successful send means the frame submission did not throw, not that a recipient confirmed delivery. [M31]

This is not evidence that a common abstraction is useless. It is evidence that the abstraction must state exactly which outcomes are portable. The same principle applies to a secret backend that can read a known item but cannot enumerate, version, revoke, or enforce the semantics required by another provider.

## 9. Provider-onboarding conventions

### 9.1 MQContract's repeatable contribution unit

The visible pattern for another connector is:

1. Create a connector project importing shared build properties.
2. Reference Abstractions and the chosen provider SDK.
3. Implement the minimum service interface and selected capability interfaces.
4. Map envelopes, headers, subscriptions, outcomes, and lifetime behavior.
5. Reuse applicable shared implementation helpers.
6. Add a provider-specific sample that invokes the shared consumer demonstration.
7. Add a test project and provider fixture using the shared scenarios.
8. Add the projects to the solution and the test commands to CI.
9. Supply the API reference/package metadata.

There is no requirement to modify a central provider enum for the ordinary entrypoint. That is a real extensibility advantage. [M03], [M04], [M06], [M33]

However, this procedure does not itself prove substitutability. The provider author still has to settle native topology, ownership, readiness, cancellation, size accounting, acknowledgement, and recovery.

### 9.2 A SecretKit onboarding guide should go further

SecretKit needs a maintainer-facing guide answering:

- What is the minimum common read contract?
- What does a successful result own?
- How is a reference bound to an instance and provider-native address?
- Which identity supplies credentials, and who owns it?
- How are origin, redirects, continuation links, challenge resources, and response budgets controlled?
- Which expected failures become bounded outcomes?
- What cancellation behavior is required before credential acquisition, during transport, and after possible mutation dispatch?
- What does inventory mean, and how is incompleteness represented?
- Which native operations are admitted separately?
- How are SDK retries and diagnostics assessed?
- Which shared tests, native tests, and installed-consumer checks are necessary?
- Which live claims remain unavailable?
- Who maintains the provider after admission?

This should be a documented procedure first, not a generator that emits a nearly empty provider package. A skeleton without semantics and witnesses is not support.

### 9.3 Admission and implementation are different

A provider can be easy to add technically and still be a poor product choice. Before implementation, it needs a real use case, a supported contract, compatible dependencies, maintainable authentication/transport controls, and a viable evidence environment.

The current two-provider priority remains in force. A third adapter should test the quality of the extension process after that foundation is reliable. It should not become an excuse to defer Azure evidence or broaden native administration again.

## 10. Capabilities, permission, and truthful support

### 10.1 MQContract's capability model

The interface hierarchy is a useful execution-strategy model. Core can choose native request/reply, inbox, or emulation without a switch over connector names.

Its limitation is that interface presence and a shared method name can suggest more equivalence than exists. Native support, adapter emulation, required infrastructure, operational permissions, and tested deployment are different facts.

### 10.2 SecretKit's existing distinction

`SecretCapabilityEvidence` separates implementation availability, effect, permission evidence, and remote verification. Its current production use is a static description of unestablished Infisical contracts, with permission not checked and remote verification false. It is not an active, comprehensive provider capability discovery service. [S19]

This is a sound starting distinction, but the record itself has no authority, credential generation, deployment/API version, observation time, or expiry. It should therefore not be used as if it were a durable live permission certificate.

The report does not identify a current false permission claim in this usage. It identifies a future design constraint: if runtime-scoped capability assessment is added, its evidence needs scope and freshness, or it should remain a separate static support description.

### 10.3 Three different artifacts are useful

Recommended separation:

1. **Static support statement:** what the package implements, excludes, or leaves unestablished.
2. **Compatibility evidence:** the provider/API/edition/cloud/identity combination actually exercised at a particular revision.
3. **Runtime operation evidence:** what this selected authority observed now, including denied, absent, incomplete, pending, or unknown.

Do not merge these into one `SupportsFeature=true` flag. A feature can exist in the package but be unavailable in the deployment, disallowed for the identity, or unverified in the claimed environment.

### 10.4 Failure before side effects

Where a required semantic is unsupported, fail before dispatch. Azure Set Secret already rejects mandatory create-only, version-match, or version-targeted preconditions it cannot honor. That is preferable to simulating a precondition with an unsafe read-then-write sequence. [S20]

MQContract's emulation demonstrates how far a convenience API can go. SecretKit should deliberately stop where emulation would change authority, effect, or an essential guarantee.

## 11. Middleware, serialization, and policy placement

### 11.1 The useful separation

MQContract distinguishes before/after encode and decode, generic and type-specific middleware, encoders, converters, encryption, compression, metrics, and channel mapping. This is a clear illustration of separating cross-cutting mechanisms from provider mapping.

Built-in transform ordering is intentional: compression precedes encryption during encode, while decryption precedes decompression during decode. The inverse relationship matters. [M15], [M16]

SecretKit can benefit from equally explicit stage boundaries:

```text
Validate selected reference and admitted operation
  -> obtain explicitly selected credentials
  -> construct bounded native request
  -> record dispatch evidence where applicable
  -> perform controlled transport
  -> validate bounded response and returned coordinates
  -> create owned result/material
  -> publish material-free operation evidence
```

This describes an execution contract, not a proposed public middleware API.

### 11.2 Why not import a generic middleware engine

MQContract's middleware can see typed values, headers, and routing information. User middleware is stored in a `ConcurrentBag`, without a general registration-order contract. Context assignment uses `TryAdd` rather than ordinary replacement. Such flexibility can be appropriate for messaging customization, but is unsuitable for making SecretKit's authority checks, redaction, retry policy, or receipt recording optional/interchangeable middleware.

Security-critical stages should not be reorderable by ordinary extension registration. Optional diagnostics should receive a constrained material-free view, not a raw request, response, token, or secret.

### 11.3 Validation and transform limits

MQContract checks compression size before encryption, and encryption can expand the payload afterward. Decompression/decryption use growing streams without an explicit decoded-size budget in the inspected paths. These are source-observed boundaries, not measured memory incidents. [M16]

For SecretKit, maintain independent input, wire-response, parsed-item, material, and bulk bounds. Checking a header or compressed length does not prove that decoded content is bounded. Existing provider response controls are an asset to retain.

### 11.4 Version conversion is not lifecycle conversion

MQContract supports converters between message representations. That is useful for evolving wire contracts between teams. SecretKit may need explicit mapping of admitted API-version differences within a provider, preserving absence/null and native outcomes.

It should not use a conversion system to make an Azure backup, Infisical dynamic credential, and generic string appear to have one equivalent lifecycle. Data-shape conversion does not create equivalent authority or effect semantics.

## 12. Resilience, mutation uncertainty, and recovery

### 12.1 What MQContract actually retries

MQContract uses result-driven Polly policies. Nonfatal error results trigger retry/circuit logic; arbitrary thrown exceptions are not all covered by those result predicates. Policies can be selected by service, channel, message type, and default precedence. [M17]

The partial bulk retry logic retains successes and fatal-result items and retries remaining items. This is better than indiscriminately resending every item after any failure. It also depends on identifiers being unique and results being correctly associated with requests.

The mechanism is a transmission retry convenience. It does not prove that the server did not accept a request whose response was lost.

### 12.2 Queries can have side effects

The native-query resilience callback includes response decoding. A nonfatal decode result can therefore cause the original query to be executed again. CQRS commands with responses travel through query machinery, so a repeated request can be a repeated command, not another harmless read. [M05], [M17], [M18]

This is a central reason not to reuse the resilience model for SecretKit mutations. Secret operations include version creation, issuance, renewal, destruction, and delayed application. Their recovery rules must be based on actual effect evidence.

### 12.3 SecretKit's receipt model should remain

SecretKit gives the caller a target-bound receipt before dispatch. It records possible dispatch at a controlled send boundary and retains uncertainty when cancellation or transport loss prevents a supported outcome. The local identifier is not advertised as a provider idempotency key. [S04]

Azure disables SDK retries, diagnostics, and tracing through explicit supported options. Infisical uses controlled handwritten Refit/HTTP request construction and send paths rather than an uncontrolled parallel SDK stack. The official Azure client and managed Infisical transport are different implementation choices serving the same required invariants. [S20], [S21]

Do not replace this with a fatal/nonfatal exception flag. A failure can be retryable from an availability perspective while its effect remains unsafe to replay.

### 12.4 A useful future resilience policy

If bounded read retries are later justified, define them by operation semantics, cancellation budget, trusted endpoint, throttle evidence, and actual SDK configuration. Keep them distinct from mutation replay. A circuit breaker can reduce load without authorizing alternate identities or providers.

For uncertain mutations, support an explicitly selected native observation where it can establish something meaningful. Preserve ambiguity when a subsequent read cannot uniquely attribute a change to this caller. Do not fabricate rollback or cross-provider transactions.

## 13. Ownership, concurrency, cancellation, and bounds

### 13.1 Resource ownership

MQContract's wrappers generally dispose supplied underlying connections. The Azure connector disposes its injected client; CQRS disposes its supplied contracted connection. Close and dispose are separate paths. This makes the composition easy when ownership is exclusive, but ownership transfer is not explicit at the public seam. [M10], [M18], [M21]

SecretKit explicitly keeps supplied credentials/transports/clients host-owned and disposes only resources it owns. Its Infisical client manages a shutdown/drain path for active operations, while Azure stores host-supplied credentials and transports without transferring their lifetime. [S01], [S20], [S21]

A future provider guide should make owned versus borrowed resources a required table. Constructor convenience must not turn a shared host client into an unexpectedly disposable dependency.

### 13.2 The limits of a bounded queue

`BatchedMessageStream` uses a bounded channel of ten batches, which is a useful backpressure mechanism at one level. But a batch can contain arbitrarily many messages; result processing is launched in a detached task; and the reader does not await each batch's transmissions before admitting subsequent work. Disposal cancels/completes the reader side without an explicit join/drain/settlement contract for all accepted requests. [M34]

The structural risk is that queue capacity alone does not bound item count, retained bytes, or in-flight work. If transmission aggregation faults before setting the completion source, callers need an explicit exceptional settlement path. This study did not reproduce a hang or measure concurrency.

SecretKit should preserve separate limits for each relevant resource. Its reviewed sample batches document at most 128 items and 16 workers, retain input ordinals and receipts, and avoid transaction claims. Those are much more informative than the word "batch." [S02], [S22]

### 13.3 Cancellation must be one observable contract

MQContract passes cancellation to many transport operations, but not consistently through encoders, middleware, handlers, startup, or all provider callbacks. Some adapters convert cancellation into an error result; others propagate it. Constructor-started connection work has no caller cancellation parameter.

SecretKit's intended common contract propagates cancellation and retains caller-held mutation evidence. Keep that behavior consistent across providers. Tests should observe whether credentials were acquired, whether dispatch was crossed, what the receipt says, and whether accepted work settled.

Cancellation is not absence, denial, rollback, or proof that nothing reached the provider.

### 13.4 Concurrency and initialization

Several MQContract paths use check-then-create followed by `TryAdd`, including in-memory channels and inbox initialization. These source patterns require race-specific verification if their losing resource is not retained/disposed or a locally created value escapes despite losing insertion.

SecretKit should continue using deterministic event barriers and injected time for concurrent renewal, generation retirement, and shutdown. Shared test infrastructure should expose those events directly rather than wait for an assumed interval.

### 13.5 Protected material is a distinct ownership problem

`SecretMaterial` copies its input into owned character storage, synchronizes copying/reveal/disposal, clears its buffer, and redacts formatting. It does not promise to erase exported strings or every parser/SDK copy. [S03]

This is deliberately stronger and more precise than a neutral messaging byte envelope. Preserve independent copies for independent callers, and preserve acquired generation lifetimes. Simplifying the public path must not introduce shared disposable material or imply process-wide erasure.

## 14. Observability and protected diagnostics

### 14.1 What MQContract centralizes well

MQContract groups logger events by lifecycle, transport, publishing, consuming, and pipeline stages. It uses source-generated logging declarations and optional `ActivitySource` spans. Centralization makes behavior easier to inspect and avoids ad hoc logging in every consumer. [M35], [M36]

For SecretKit, a stable material-free diagnostic vocabulary would be useful: provider kind, operation kind, bounded status, duration, dispatch phase, incomplete inventory, or explicitly started maintenance state.

### 14.2 Data exposure and metric meaning

MQContract diagnostics include channels, message identifiers, connection identity, and raw exceptions. Its error model retains `Exception` and exposes `Exception.Message`; query errors can serialize exception text over the wire. Those are not appropriate defaults for SecretKit. [M37], [M38]

Its metric emission also occurs after encoding rather than after confirmed transport delivery. A label such as "sent" needs interpretation. Provider type/channel-specific instrument names can create dynamic cardinality. The inspected metrics worker is started through an untracked task and has no corresponding explicit shutdown path in that class. [M39]

For SecretKit, define every metric's meaning before instrumentation:

- Read attempted versus read successfully delivered.
- Inventory items observed versus complete inventory.
- Mutation dispatched versus acknowledged versus observed applied.
- Renewal attempted versus currently usable credential.
- Local generation published versus application client activated.

These pairs are not interchangeable.

### 14.3 Documentation versus trace implementation

`OpenTelemetry.md` describes standard `traceparent`, `tracestate`, and `baggage` propagation. The implementation uses private `_traceParentId` and `_traceParentSpanId` headers and reconstructs the parent from them. The report therefore treats the standard propagation statement as a documentation mismatch, not an implemented guarantee. [M36], [M40]

The practical lesson is to test the machine-consumed diagnostic contract. Do not validate observability by checking that an instrumentation class or README exists.

### 14.4 A SecretKit-compatible direction

Keep optional diagnostics outside BCL-only Core unless a genuine common contract requires a BCL primitive. Expose no protected coordinates, values, proof material, tokens, raw exception text, or arbitrary request/response bodies to ordinary diagnostic sinks.

Use listeners in tests to assert the absence of canary material and coordinates. Keep instrument names fixed and dimensions bounded. Diagnostics must not start a worker unless the optional host lifecycle explicitly owns it.

Host-owned HTTP/credential instrumentation remains a separate exposure boundary. Disabling SDK-owned diagnostics cannot erase values deliberately exported to configuration or logged by the host.

## 15. Source generation, reflection, and NativeAOT

### 15.1 The useful idea

MQContract's incremental generator emits typed context helpers for metadata, encoding, conversion, encryption, and query dispatch. Explicit compile-time registration can reduce runtime discovery and make supported types visible in source. Ambiguous discovered encoders/encryptors can produce compiler warnings rather than silently choosing one at generation time. [M41], [M42]

This is valuable where a library has many dynamically dispatched application message types.

### 15.2 What the implementation does not establish

The runtime still contains assembly scanning and reflective activation. The documentation says auto-discovery scans referenced assemblies, while helper syntax providers inspect class declarations from the current compilation. Generated typed dispatch also does not by itself make default JSON serialization reflection-free.

The inspected dynamic-code tests set an internal `DynamicCodeGate.TestOverride` to false. They are useful tests of selection logic, but not an actual NativeAOT-published consumer. [M43]

There is a particularly important fail-closed lesson: for an ungenerated message type when dynamic code is disabled, the inspected encryptor resolver returns null, and middleware can select a non-encrypting implementation. That is source-observed fallback behavior, not a newly reproduced deployment vulnerability. [M44]

Required protection should fail closed when the implementation cannot establish it. AOT restrictions must not silently change an encryption requirement.

### 15.3 SecretKit's decision

SecretKit forbids reflection plugin discovery, and its common readers do not require discovery of arbitrary application message classes. There is no demonstrated need to introduce a source-generator package merely to resemble MQContract.

If code generation later has a concrete purpose, keep it optional and independently assess its dependency, metadata, serialization, packaging, and diagnostic contracts. Handwritten protected Infisical contracts remain the selected transport strategy; this comparison is not authorization to replace them with vendor-schema generation.

NativeAOT/trimming support should be claimed only after publishing and running an installed-package consumer for the declared combination, not because a code path checks `RuntimeFeature.IsDynamicCodeSupported`.

## 16. Documentation and consumer experience

### 16.1 MQContract's first-use advantage

The root README provides a short in-memory story: install packages, declare a message, create a connector, subscribe, publish. The user sees the shared application-facing workflow before encountering every provider detail.

Provider samples then isolate setup and call the same `SampleExecution.ExecuteSample`. This demonstrates that the consumer workflow remains recognizable while setup changes. [M01], [M32], [M45]

SecretKit should reproduce that educational structure with its own semantics: a common read-and-dispose workflow, separate provider setup, then optional inventory/configuration/native lifecycle examples.

### 16.2 Generated reference is not semantic documentation

MQContract generates package Markdown from XML comments using Vsxmd. That can maintain an API index, but it also reproduces stale or inaccurate comments. The NATS timeout mismatch, absent KubeMQ/DotNetty paths, and Rabbit deletion call-target mismatch illustrate different ways documentation can diverge.

Generated API pages do not explain ownership transfer, emulator limitations, topology prerequisites, or native-versus-emulated guarantees by themselves. They should supplement a short manually owned semantic guide, not replace it.

### 16.3 SecretKit's current documentation friction

SecretKit's current-preview page carefully distinguishes implemented behavior and scoped evidence. Several internal design documents still carry `Proposed / unimplemented`, and the Infisical package README opens with an "uncommitted, offline implementation subset" description and historical admitted-route framing. Other documents state the accepted catalog removal and current local verification. [S02], [S10], [S11], [S23]

Those documents can be individually understandable as historical/design artifacts, but their simultaneous presentation makes it harder to answer: "What do I use now, and what is the actual contract?"

The recommendation is status reconciliation, not deleting history or weakening caveats. Keep one current entrypoint and explicitly mark which pages are proposals, historical research, or current package guides. Preserve version/date-specific evidence rather than presenting inherited prose as a fresh support claim.

### 16.4 Consumer quickstarts versus contributor quickstarts

SecretKit's root quickstart is primarily a clone/restore/build/offline-sample path. That is appropriate for an unpublished preview. It does not yet provide the same short, provider-by-provider installed-consumer experience as MQContract's published quickstart. [S24]

Before public release, provide small installed-package examples using actual supported setup. During local preview, label package source and preview status accurately. Show the bounded outcome check, explicit material lifetime, reference construction, and cancellation without printing secret material.

Keep extensive operator/runtime guidance in package/public docs. The marketing entrance should link to it rather than accumulate every operational detail.

## 17. Testing and provider conformance

### 17.1 The strongest engineering pattern to adopt

MQContract's connector suites invoke shared helpers for pub/sub, bulk pub/sub, query/response, and ping. A provider fixture supplies a connector, while the scenario defines the expected common behavior. This is the clearest example of making an abstraction's contract executable across implementations. [M46], [M47]

SecretKit has substantial provider-specific wire-seam tests, including independent material copies, authority isolation, status mapping, returned-coordinate validation, response budgets, cancellation, and explicit generation behavior. It also has installed-package and owned live Infisical scenarios. [S05], [S06], [S25], [S26]

The gap is not "SecretKit has no tests." It is that the common invariants are not organized as one reusable provider contract scenario system used by each adapter.

### 17.2 What MQContract's shared tests prove in principle

The shared pub/sub cases check delivered payloads, headers, count, and errors. Query cases check request/response content and headers. This is preferable to testing only that a mock SDK method was called.

The fixture/scenario separation reduces the cost of another connector and makes it easier to ask whether the new connector passes the same application-facing story.

That should be transferred as a test design principle, not by copying the helper implementations.

### 17.3 What should not be adopted

The helpers use fixed subscription waits, polling tasks with blocking delays, and cleanup paths that are not always protected by `finally`. The common container harness includes a 30-second disposal delay. Some fixture images use `latest`. Shared callback-written lists are also read by polling code. [M47], [M48]

These patterns can make readiness timing-dependent and failure cleanup hard to reason about. SecretKit's own contract explicitly requires event barriers and injected time. Its hosting tests already use those techniques to observe single-flight renewal, waiter cancellation, scheduling, and lifetime constraints. [S01], [S27]

Adopt the shared scenarios; retain SecretKit's stronger synchronization discipline.

### 17.4 Local brokers, emulators, and real cloud evidence

The connector suites use local brokers/containers, LocalStack for SNS/SQS, an Azure Service Bus emulator with SQL Server, and a Google Pub/Sub emulator. InMemory and ZeroMQ use local process/socket behavior.

These are useful integration environments. AWS/Azure/Google emulator results do not establish real IAM, cloud TLS/challenge behavior, service editions, regional limits, quotas, or production permissions.

SecretKit already distinguishes offline transport evidence, owned Infisical conformance, Azure live gates, and licensed feature gates. Do not collapse those categories to simplify a status badge. [S02], [S26]

### 17.5 Recommended common provider scenarios

The following scenario set should be defined once and run against every implementation of the relevant common contract:

| Scenario | Observable assertion |
| --- | --- |
| Successful read | Exact supplied fixture content is delivered without normalization; the result owns disposable material |
| Independent reads | Disposing one result does not invalidate another |
| Foreign authority | A reference from another instance is rejected before credential acquisition or transport |
| Absence | Absence is distinct from denial, unavailable transport, malformed response, and success |
| Protected diagnostics | Formatting, default serialization, errors, and diagnostic listeners do not disclose canaries |
| Pre-cancelled read | Cancellation propagates without credential acquisition or dispatch |
| In-flight cancellation | The actual transport observes cancellation; the caller does not receive absence or fabricated success |
| Returned-coordinate mismatch | The provider cannot substitute another name/version/origin for the selected reference |
| Oversized response | The result fails closed before successful material publication |
| Inventory isolation | Inventory contains metadata, not material or proof of read access |
| Inventory bounds | Collection window and incompleteness remain visible under truncation |
| Optional consumer workflow | The same common consumer function can use each admitted reader |

Not every scenario can use identical fixtures. The shared layer specifies the invariant; each adapter fixture supplies appropriate native responses, addresses, credentials, and exact barriers.

### 17.6 Keep native suites first-class

Common conformance must not become the whole test strategy. Azure lifecycle/backup/restore and Infisical imports/authentication/leases/rotation require native scenarios and independent effects.

For mutations, keep pre-dispatch receipts, committed/lost-response evidence, denial under the intended identity, and no replay. Where a paid feature cannot be exercised, leave the gate unverified or failed with its actual reason. Do not turn missing entitlement into a skipped green capability.

Initially, reusable fixtures/helpers can remain non-packable repository test infrastructure. A published test kit is a separate product decision with maintenance and security responsibilities.

## 18. GitHub workflows and CI

### 18.1 MQContract's main workflow

The checked-in `unittests.yml` runs on pushes and pull requests targeting `master`, with read-only repository contents permission. It installs .NET 8 and .NET 10, restores the solution, builds Core/CQRS/CodeGen and each connector test project, then runs the offline suites and both target frameworks for every connector. [M04]

The strength is visibility: every current connector has an explicit place in the workflow. A new provider does not silently remain outside CI.

Its limitations are also visible:

- One Ubuntu job runs the inventory sequentially.
- Earlier failure prevents later steps from executing.
- SDK channels and action tags are mutable rather than exact content pins.
- The builds use default configuration, not an explicit Release gate.
- No checked-in pack/install-consumer gate appears in this workflow.
- No explicit minimum discovered-test count appears.
- No provider/OS job matrix or independent per-provider completion record is defined.
- No formatting or complete release/provenance gate is demonstrated by these commands.

These are configuration observations. Repository-required status checks and branch protection were not established from filesystem evidence.

### 18.2 The reporting workflow

`unit-test-report.yml` uses `pull_request_target`, grants pull-request write permission, checks out without a PR-head ref, and runs only `Testing/Core`. It requests coverage and configures a reporter threshold of 90. [M49]

The default checkout in this event context is base-side; the resulting report should not be interpreted as verification of the contributed PR head. This report does not claim that the workflow executes arbitrary fork-head code with its write token. The actual visible problem is evidence binding: the reporting job is not explicitly reporting the full PR-head provider matrix.

The coverage threshold is configuration intent, not an observed measured percentage or proof that GitHub requires that result. The step is not marked `always()`, so preceding failures can prevent reporting.

A better pattern is to keep untrusted PR verification credential-free and associate reports with the exact tested run/artifacts. Any write-enabled reporting layer needs a narrow, explicit trust boundary.

### 18.3 Current public run evidence

The exact inspected head has a cancelled push test run, not a successful full matrix. A CodeQL run at the same head succeeded separately. Therefore the report does not use README badges or configured steps as proof that all connectors pass now. [E03], [E04]

The README's test badge also points to `unittests8x.yml`, while the checked-in workflow is `unittests.yml`. This is a documentation-maintenance issue, not evidence that testing infrastructure does not exist. [M01], [M04]

### 18.4 SecretKit's larger CI gap

At the inspected SecretKit revision, `.github/workflows/` contains `publish.yml`, but no `verify.yml`. The publisher's input and the release tool explicitly require a successful trusted run at `.github/workflows/verify.yml`.

The publication protocol already acknowledges the missing producer and the need to reconcile historical full-registry gates with the current reduced scope. This is unfinished infrastructure, not a newly discovered publication bypass. [S08], [S09], [S28]

MQContract's practical advantage is routine push/PR execution over its test inventory. SecretKit's practical advantage is stronger artifact and authority controls around publication. SecretKit should complete routine verification without downgrading publication protection.

### 18.5 Recommended clean-checkout verification order

The installed-package test reads local `.nupkg` files from `artifacts/packages`. The solution includes that suite. Consequently clean CI needs fresh packages before running package-install assertions, or it must split the package suite into an explicit later stage. Merely following a displayed test-then-pack list can rely on packages already present in a developer's workspace. [S05], [S14]

A proposed dependency order is:

```text
Locked restore
  -> Release build
  -> formatting and static boundary checks
  -> fresh local pack
  -> offline solution tests, including installed-package checks
  -> offline sample execution
  -> documentation/support consistency checks
  -> verification artifacts bound to the exact source
```

This is a recommendation, not a newly executed command sequence.

PR verification should have no publishing authority. A trusted protected-main producer can later produce the exact immutable package/evidence bundle required by the publisher. Live provider jobs should remain separately selected and explicitly authorized; absent cloud authority must not make the offline path unusable.

## 19. Packaging, dependency management, and releases

### 19.1 MQContract's useful conventions

`Shared.props` centralizes framework targets, package version, repository URL, license expression, symbols, documentation generation, and package README inclusion. Provider projects reference only their required SDKs plus the shared contract layer. This is a useful way to keep a family recognizable and separately installable. [M06], [M50]

The package family does not require every broker SDK to be installed by every consumer. That is directly applicable to future SecretKit providers.

### 19.2 Weaknesses not to copy

The inspected repository has no global SDK pin, central package-version file, or dependency lockfiles. Many provider dependencies float. Core has range-based dependencies. Test builds use `BlockMD=true`, disabling the normal Markdown-generation dependency path.

The Abstractions project includes an analyzer assembly from a hard-coded `Generators/bin/Debug/netstandard2.0` path. This deserves packed-artifact verification, especially when Release packaging is used; the report does not claim a package-content failure without building it. [M08]

All inspected test projects are explicitly non-packable. Samples and the benchmark project do not uniformly declare that boundary. A solution-wide pack without an explicit shipping allowlist could therefore select unintended projects. This is a pack-selection risk, not evidence that sample assemblies are embedded in Core.

The inspected tests consume project references rather than freshly packed packages. They do not establish clean consumer restore, analyzer placement, README assets, or final dependency closure.

### 19.3 SecretKit already does several things better

SecretKit centrally manages package versions, creates lockfiles, uses locked CI restore, treats warnings as errors, enables deterministic builds, defaults projects to non-packable, and includes third-party notices in packable projects. [S06], [S07]

Its package-install suite opens the package archives, verifies README/notices/license, checks dependency-free Core, restores into isolated outputs/cache, runs a package-only consumer, and rejects unwanted application-framework/database/official-Infisical-SDK dependencies. [S05]

Do not replace these checks with a solution build or a package-count badge.

### 19.4 Protected publication: preserve the design, complete the path

SecretKit's manual publication workflow uses SHA-pinned actions, disabled persisted checkout credentials, protected input bindings, immutable artifact identifiers, content hashes, a protected environment, publication-only OIDC permission, and checkpointed uncertainty. It avoids rebuilding packages after verification. [S08], [S09]

This is more rigorous publication machinery than anything demonstrated by MQContract's two checked-in test workflows.

But a well-designed publisher cannot compensate for an absent trusted verification producer or stale scope metadata. Complete the producer-to-publisher chain and reconcile the current admitted product scope before release. Do not restore deleted catalog APIs merely to satisfy a historical registry denominator.

The priorities are ordinary contributor verification first, exact-artifact evidence next, and actual publication only when its independent authority and remaining gates exist.

## 20. Benchmarks and performance evidence

### 20.1 What is valuable

MQContract has a dedicated BenchmarkDotNet project with memory diagnostics and baseline comparisons. It compares direct service-interface publication with typed wrapper publication, encoding choices, generated contexts, middleware, subscriptions, and CQRS.

A benchmark home is valuable because it makes performance claims testable and separates experiments from the runtime library. [M51]

### 20.2 What the current benchmarks mean

The publication baseline uses `FakePublishConnection`, which returns immediate success. It measures local wrapper/encoding overhead against a fake service seam, not real broker latency or throughput.

Some timed methods include context registration; middleware cases include construction/registration/disposal; the project targets .NET 8. The README image is not sufficient evidence of a current reproducible deployment result. No benchmark was run during this study. [M51], [M52]

Thus it would be incorrect to infer that SecretKit can achieve a particular speed improvement by adopting this architecture.

### 20.3 A SecretKit measurement plan

Useful measurements would include:

- Consumer setup complexity and duplicated safety code relative to direct provider use.
- Dependency footprint for a minimal reader versus administrative/native features.
- Local allocations for material copies and protected outcomes.
- Fresh-read overhead against the same controlled native transport.
- Inventory memory under byte/page/item bounds.
- Generation collection, publication, acquisition, and retirement.
- Authentication single-flight behavior under controlled concurrency.
- Installed-package startup/restore characteristics.

Separate local seam measurements from real provider latency and account for authentication, network, version, and edition. Preserve the same safety semantics in baseline and wrapper cases; an unsafe direct baseline is not a fair comparison.

A benchmark suite is lower priority than repeatable conformance and CI. It should follow an actual performance question rather than become another large subsystem to finish before a useful SDK.

## 21. SecretKit gap assessment

### 21.1 Findings ordered by practical impact

| Priority | Gap or issue | Evidence | Why it matters | Recommended response |
| --- | --- | --- | --- | --- |
| P0 | No checked-in routine verification producer; publisher expects `verify.yml` | Workflow inventory, publisher input, release-tool run-path validation, acknowledged protocol gap | The ordinary contributor and artifact-production path is incomplete | Implement credential-free PR checks and a trusted-main producer with explicit dependency order |
| P0 | Common provider invariants are not one reusable scenario system | Separate Azure/Infisical suites; existing common contracts | Every new adapter risks redefining or omitting common behavior | Extract reusable invariant scenarios while retaining real native seams |
| P1 | Support/evidence status is distributed across current preview, package docs, historical research, and proposed design docs | Current-preview, internal status headers, Infisical README, frozen registry context | Users and maintainers must reconstruct what is current | Establish one current support index with links to scoped evidence |
| P1 | Provider extension procedure is not yet a complete maintainer-facing admission/onboarding contract | Current project map and contributor rules versus MQContract's repeated provider unit | Adding another provider is technically possible but operationally bespoke | Write a guide and validate it with the existing two providers |
| P1 | Azure live and licensed/native effect gates remain open | Current-preview and conformance documentation | Offline success does not certify intended deployments | Close only in an owned/authorized environment; otherwise preserve explicit limits |
| P1 | Clean CI must order fresh pack before installed-package tests | PackageInstallTests plus solution membership | Stale/local artifacts can obscure clean-checkout behavior | Make package production and package-only execution explicit |
| P2 | Static capability descriptions are not scoped runtime permission evidence | Capability record and its current static production usage | Future expansion could overstate permission/freshness | Keep static support separate; add scoped evidence only for a real use case |
| P2 | First-use guidance favors contributors over installed consumers | Root clone/build quickstart and offline samples | Adoption still requires significant orientation | Add short provider setup plus common read examples at the appropriate preview/release stage |
| P2 | There is no demonstrated extensibility stress case beyond two providers | Current source package family | Hidden two-provider assumptions may remain | After current scope is solid, select one demand-driven third provider |
| P3 | Performance/AOT/platform claims need dedicated evidence | Current explicit open gates | Framework selection and source structure are not proof | Measure/publish specific consumers only when these claims are needed |

These priorities are engineering recommendations, not estimates, completed work, or permission to expand the product.

### 21.2 What is not a gap

The following choices should remain:

- BCL-only Core.
- Independently installable provider packages.
- Separation of management dependencies.
- Typed native lifecycle operations.
- Explicit identity selection and authority-bound references.
- Independent disposable material.
- Bounded expected outcomes instead of raw provider exceptions.
- Pre-dispatch receipts and no automatic mutation replay.
- Explicit configuration string export.
- Host-started maintenance rather than constructor-started workers.
- Honest distinction among proposed, implemented, offline-tested, and live-verified behavior.

These decisions may make a provider implementation more demanding, but they define the SDK's value. The goal is to make honoring them routine, not remove them to match the brevity of a messaging quickstart.

### 21.3 No global rewrite is justified

The comparison found substantial improvements to the engineering process and support presentation. It did not establish that SecretKit's package graph, common read seam, or ownership model is fundamentally wrong.

A rewrite would discard valuable contracts and consume effort before the missing shared tests/CI can protect it. The smallest high-value change is to make existing behavior consistently demonstrable and repeatable.

## 22. A recommended target design for extensibility

### 22.1 Preserve the existing package graph

Recommended dependency direction:

```text
Application-owned composition
  -> selected provider(s)
  -> optional configuration export
  -> optional explicitly started hosting

Selected runtime provider -> SecretKit.Core + admitted transport/SDK
Selected management      -> native administrative contracts/dependencies
Configuration export     -> SecretKit.Core + configuration abstractions
Hosting                  -> admitted explicit maintenance + host abstractions

SecretKit.Core            -> BCL only
```

A future provider should not require editing Core to add its name. Core remains about the contract, not the installed-provider catalog. An application can choose concrete adapters and bind consumer roles to readers explicitly.

Avoid reflection plugin discovery, implicit credential chains, a giant all-provider package, or a mutable global default provider.

### 22.2 Provider responsibilities

Every runtime provider should supply:

1. Explicit construction with a fixed admitted origin/cloud policy and selected credentials.
2. Provider-owned address/reference construction.
3. Common read implementation and inventory only where its semantics are supported.
4. Explicit owned/borrowed resource lifetimes.
5. Controlled request/response bounds and cancellation.
6. Bounded outcomes and protected observations.
7. A guide stating versions, deployment assumptions, known unsupported semantics, and native additions.
8. Shared contract-test participation.
9. Native wire/effect tests.
10. Installed-consumer and compatibility evidence appropriate to its support claim.

Administrative operations remain optional and native. A provider package must not acquire administrative authority as part of a read convenience.

### 22.3 Test infrastructure without new runtime machinery

Initially add a non-packable shared scenario/fixture layer inside `tests/`. It should reference the common contracts and define observable invariant cases. Provider fixtures remain responsible for native addresses, controlled credentials, bounded transport responses, and exact event barriers.

Run the scenarios through the actual adapter seam. Do not substitute a fake `ISecretReader` for every provider and then claim those tests validate provider behavior. A fake reader is appropriate for consumer-layer generation/export tests, not adapter conformance.

Keep provider-native scenarios beside their existing owners. Do not replace all native tests with a universal test base.

### 22.4 Support metadata should serve a real reader

Create a compact current index that can answer:

- Which package owns this operation?
- Which common/native contract applies?
- What is implemented?
- What is locally/offline exercised?
- What deployment/API/identity combination has live evidence?
- What remains unsupported, unestablished, or gated?

Prefer adapting existing documentation/evidence ownership over adding another overlapping registry. A machine-consumed schema is justified only when CI/release tooling has a concrete consumer and one authoritative source.

### 22.5 Ergonomics without concealed policy

Convenience can come from short explicit examples, typed setup options, clear named composition, and reusable consumer workflows. It does not require automatic fallback, synchronous remote initialization, hidden refresh, or arbitrary raw requests.

For instance, a consumer can accept an already selected reader and reference, check the bounded outcome, use the material deliberately, and dispose it. The provider-specific setup can be shown separately. That gives much of MQContract's educational benefit while retaining SecretKit's contract.

## 23. Prioritized adoption roadmap and acceptance criteria

This is a recommended sequence, not a task triad or authorization to implement.

### Stage A: Make the current foundation reproducible

**Goal:** A new contributor can verify the existing SDK from a clean checkout without secret-provider accounts.

**Work:**

- Add routine verification CI separate from publication.
- Establish fresh pack before package-install assertions.
- Run the current offline solution and sample baseline.
- Bind test summaries and artifacts to the exact commit.
- Preserve positive test-count expectations and dependency locks.
- Correct current support routing/status conflicts.

**Acceptance evidence:** A clean trusted/PR run completes the declared offline checks and package-only consumer path; it has no publication identity; the current support index points to the actual implementation/evidence boundaries.

**Trade-off:** This does not add another provider or close live Azure gates. It prevents future work from depending on an unreproducible contributor path.

### Stage B: Make common semantics executable across both providers

**Goal:** The portable contract is defined once and demonstrated through Infisical and Azure.

**Work:**

- Introduce reusable common scenario definitions.
- Connect both provider fixtures to them through native wire seams.
- Preserve provider-native tests.
- Cover authority, independent material, bounded outcomes, cancellation, coordinate validation, budgets, and inventory semantics.
- Use exact events/injected time, not readiness sleeps.

**Acceptance evidence:** The same scenario IDs run against both adapters; fixture behavior can cause a genuine adapter defect to fail; native differences remain visible; missing live evidence is not relabeled as common support.

**Trade-off:** Shared scenarios require careful fixture design. Over-abstraction would hide provider behavior; duplicating a small native setup is better than a misleading universal fixture.

### Stage C: Make provider contribution a documented procedure

**Goal:** Another maintainer can implement an adapter without redesigning the process.

**Work:**

- Write the provider admission/onboarding guide.
- Document owned/borrowed resources and credential/origin requirements.
- Define common versus native support and compatibility evidence.
- Create short provider setup plus common consumer examples.
- Identify provider maintenance ownership.

**Acceptance evidence:** A maintainer can use the guide to describe both current providers without undocumented exceptions. All checklist items correspond to actual contracts or tests; no empty provider skeleton is presented as support.

**Trade-off:** A reusable procedure is less visually impressive than a third provider, but it reduces the cost and risk of every later adapter.

### Stage D: Close the selected two-provider release boundary

**Goal:** Release readiness matches the reduced current product, not the historical connector catalog.

**Work:**

- Reconcile release scope metadata and gate definitions.
- Complete the trusted verification artifact producer.
- Establish Azure live evidence when an owned account/environment exists.
- Retain licensed/native effect gates that cannot be exercised.
- Review package dependency/provenance and installed-consumer matrix.

**Acceptance evidence:** The publisher can validate a real exact-artifact bundle for the selected scope, and every claimed compatibility/native effect has appropriate evidence. Missing authority or entitlement remains an explicit release decision rather than a fabricated green artifact.

**Trade-off:** A declared preview may remain useful before every native feature is live-proven. It must be labeled accordingly; a full-support claim cannot be manufactured by reducing test visibility.

### Stage E: Use one additional provider to test extensibility

**Goal:** Demonstrate that adding a provider does not require changing common consumers or weakening contracts.

**Work:**

- Select the provider for an adopter need and viable evidence environment.
- Implement only the admitted minimal/common slice first.
- Keep its addressing/authentication native.
- Run common scenarios and an installed consumer.
- Add native features only for a justified consumer workflow.

**Acceptance evidence:** The adapter joins the same verification and documentation process; Core does not acquire vendor dependencies or a provider switch; a common read consumer remains unchanged after explicit setup; unsupported semantics fail honestly.

**Trade-off:** Some providers may not support inventory or native lifecycle features. That is acceptable. The goal is a trustworthy provider, not an artificial all-features checkmark.

### Stage F: Invest in optional capabilities only when demanded

Potential later work includes bounded read resilience, material-free diagnostics, specific platform/AOT evidence, and benchmarks. Each needs a concrete question, bounded contract, and observable acceptance criterion.

Do not add a general scheduler, caching engine, distributed coordinator, code generator, universal writer, or provider discovery subsystem solely because MQContract has an analogous messaging feature.

### Priority/effort judgment

| Proposal | Expected benefit | Complexity/risk | Order |
| --- | --- | --- | --- |
| Routine verification CI | Immediate repeatability and regression visibility | Moderate integration work | First |
| Shared provider scenarios | Lower marginal provider cost and stronger portability evidence | Moderate design work | First |
| Status/support reconciliation | Faster and more accurate decisions | Low-to-moderate documentation/data ownership work | First |
| Provider onboarding guide | Repeatable future contributions | Low implementation risk | Next |
| Short provider consumer examples | Faster adoption | Low-to-moderate setup/provenance work | Next |
| Release producer/scope reconciliation | Complete exact-artifact release path | Significant cross-artifact coordination | Before release |
| Third provider | Tests real extensibility and adds useful coverage | Depends on selected backend and authority | After the foundation |
| Generic runtime engine/source generation | Unproven benefit for this SDK | High new abstraction/maintenance cost | Not recommended now |

No calendar or staffing estimate is justified by this study alone.

## 24. MIT reuse, attribution, and practical transfer

MQContract's license is MIT, copyright Roger Castaldo, and SecretKit is MIT, copyright ISLAMU. MIT permits use, copying, modification, merging, publication, distribution, sublicensing, and sale, subject to retaining the copyright and permission notice in copies or substantial portions. [M53], [S29], [E06]

Therefore the user's premise that MIT makes reuse possible is correct. The useful engineering distinction is **what should be reused**, not a blanket prohibition on learning from or using MIT software.

Practical categories:

| Category | Recommended handling |
| --- | --- |
| General engineering principles | Adopt freely through SecretKit's own contract: inward dependencies, optional capabilities, shared scenarios, explicit provider units |
| Functional public-interface facts | Use as evidence with revision/source attribution |
| A directly reused MIT implementation unit | Evaluate its actual applicability, preserve notices, record provenance, and test it under SecretKit's contract |
| Third-party SDK dependencies | Review their own direct/transitive terms and exact resolved versions; MQContract's MIT license does not relicense them |
| Generated documentation or third-party assets | Inspect their separate source/provenance and obligations before reuse |
| Distinctive implementation organization | Do not transplant by default; prefer the existing target-native structure unless a concrete improvement is demonstrated |

No MQContract implementation code, tests, documentation prose, or assets were copied into SecretKit by this report. The report records observed behavior and independently proposes SecretKit changes.

The current SecretKit contribution policy also calls for independently designed contracts and avoids importing vendor/sibling implementation. If direct source reuse is later selected, reconcile the chosen unit with that policy rather than assuming a license comparison silently changes the repository contract.

Most of the highest-value transfer here does not require copying code. The shared test **idea**, repeated provider contribution unit, and common-consumer demonstration are more useful than the particular timing helpers, batch worker, reflection discovery, or exception-bearing result classes.

## 25. Open questions, verification limits, and final recommendation

### 25.1 Remaining questions relevant to SecretKit

| Question | Established now | What would resolve it |
| --- | --- | --- |
| Can routine CI verify a clean checkout? | The producer workflow is absent; package tests require local packages | Implement/run the proposed offline dependency order on a clean runner |
| Do both adapters honor every common invariant? | Substantial individual tests and read implementations exist | Run one shared scenario system through both actual adapters |
| What is the release denominator after removal? | Current scope excludes the broad catalog; protocol acknowledges historical gate mismatch | Reconcile machine-consumed scope/registry/gate ownership |
| What Azure environments are supported live? | Current docs keep Azure live unverified | Owned-account tests for the specifically declared cloud/API/identity slice |
| Which licensed/native effects are verified? | Several gates remain explicit | An entitled owned environment and effect-level witnesses |
| Which third provider should come next? | No provider selected by this study | Actual adopter requirement, maintenance owner, and evidence environment |
| Should runtime capability evidence become scoped? | Current usage is static and deliberately not permission-checked | A concrete consumer requiring current permission/compatibility assessment |
| Is AOT/trimming/platform support worth pursuing now? | It remains unverified | A demanded platform and installed-package publish/run evidence |

### 25.2 Remaining MQContract validation leads

This study leaves runtime reproduction of several source risks unclaimed: detached batch fault/shutdown settlement, concurrent first-use initialization, acknowledgement/handler lifetime, malformed custom frames, real cloud permissions, native stream/schema paths, exact package asset layout, and actual AOT publishing.

These do not block the architectural conclusions. They limit how far the report can endorse the specific implementations as reusable runtime code.

In particular, the cancelled current-head test run is not evidence that any one source risk caused failure. Its cancellation reason was not established.

### 25.3 What was and was not verified

Verified in this study: repository identities/revisions; current upstream MQContract commit; source/configuration relationships and selected call paths; twelve connector families; both checked-in workflows; the public InMemory 4.0.0 package page; exact-head GitHub run conclusions; MIT notices; and the report's local documentation structure/references.

Not freshly executed: SDK restore/build/test/pack, benchmarks, broker/emulator scenarios, Azure live calls, Infisical live calls, native credential effects, publication, branch/environment protection checks, or package-content reproduction for MQContract. SecretKit's recorded prior results remain historical evidence at their stated scopes.

### 25.4 Final recommendation

Use MQContract to improve SecretKit's **repeatable provider engineering process**:

- Keep the existing common read and ownership architecture.
- Make its invariants executable across implementations.
- Make another provider a coherent implementation/test/sample/evidence unit.
- Complete ordinary verification CI and the trusted artifact producer.
- Give consumers one current support view and a short explicit setup path.
- Add breadth only after the existing two-provider foundation is reproducible.

Do not import MQContract's automatic reflection, hidden workers, implicit disposal transfer, raw exception model, broad retry behavior, or semantic emulation as defaults for secrets.

The most important outcome is that future provider support becomes cheaper to add **and harder to misrepresent**. More adapters should mean more implementations of a trustworthy contract, not more method signatures with increasingly different hidden behavior.

## 26. Evidence register

MQContract links are commit-pinned. SecretKit links are local repository references reviewed at `f7b1f7aec9f312fc2cbc54d1ea797d02824512ad`. Line ranges below identify the relevant inspected seam; recommendations are the author's analysis, not claims made by the referenced projects.

### 26.1 MQContract sources

| ID | Source and anchor | Main use |
| --- | --- | --- |
| M01 | [README][M01], getting started, samples, badges | Consumer story; stale paths/badge; benchmark framing |
| M02 | [IMessageServiceConnection][M02]:9-50 | Minimum provider seam |
| M03 | [ContractConnection][M03]:33-39 and factories | Provider injection without a central provider registry |
| M04 | [unittests.yml][M04]:3-110 | Main test triggers and full configured connector inventory |
| M05 | [AConnection][M05]:495-611 | Query dispatch strategies and fallback |
| M06 | [NATS.csproj][M06] | Representative provider project convention |
| M07 | [InMemory.csproj][M07]:12-17 | Linked shared implementation/source dependency |
| M08 | [Abstractions.csproj][M08]:11-20 | Health dependency and analyzer packaging path |
| M09 | [Core.csproj][M09]:14-27 | Core's runtime/build dependencies |
| M10 | [Connections/Connection.cs][M10]:21-36,51-124 | Ownership and ordinary publish/query paths |
| M11 | [AConnection][M11]:104-193,244-340 | Encode/decode/filter/transport stages |
| M12 | [QueryResponseHelper][M12]:8-77 | Private correlation and listener-before-send |
| M13 | [QueryResponseSubscription][M13]:23-132 | Query responder branch, groups, acknowledgement, errors |
| M14 | [MappedConnection][M14]:87-153; related [MultiServiceConnection][M54] and [ServiceConnectionList][M55] | Routing/aggregation caveats |
| M15 | [MiddlewareCollection][M15]:17-90 | Registration, caching, and user ordering |
| M16 | [CompressionMiddleware][M16]:13-38; [EncryptionMiddleware][M56]:24-52 | Transform order and size/protection boundaries |
| M17 | [ResiliencePolicy][M17]:21-48,156-220; [AConnection.Resilience][M57] | Result-driven policies and partial retry |
| M18 | [CqrsConnection][M18]:23-111,168-176 | Higher-level composition, commands, cancellation, ownership |
| M20 | [NATS Connection][M20]:16-169,178-245 | Native query; subject/stream behavior; startup/timeout |
| M21 | [AzureServiceBus Connection][M21]:17-98,114-185,220-227 | Injected ownership, batch and inbox |
| M22 | [Kafka Connection][M22]:28-96,125-185; [Kafka.csproj][M58] | Producer policy, cancellation, offsets, optional dependency cost |
| M23 | [Redis Connection][M23]:35-61,177-200; [query responder][M59] | Streams and emulated reply operation |
| M24 | [InMemory Connection][M24]; [MessageChannel][M60] and [MessageGroup][M61] | Local semantics and bounds |
| M25 | [RabbitMQ Connection][M25]:33-57,95-111,188-280 | Topology, construction, delete call-target mismatch |
| M26 | [AmazonSNQS Connection][M26] and [MessageMapper][M62]:48-74 | SNS/SQS mapping and alternate envelope path |
| M27 | [GooglePubSub Connection][M27]:41-55,128-174 | Client building and subscription creation |
| M28 | [ActiveMQ Connection][M28] and [project][M63] | NMS setup, inbox, dependency |
| M29 | [ApachePulsar Connection][M29] and [project][M64] | Native subscription/client policy and dependency |
| M30 | [HiveMQ Connection][M30] and [project][M65] | MQTT response-topic strategy and dependency |
| M31 | [ZeroMQ Connection][M31]:54-105,118-139,199-257 and [project][M66] | Explicit sockets and local callback semantics |
| M32 | [NATS sample][M32]:31-40 | Stream configuration and subject-to-stream mapping |
| M33 | [NATS connector test project][M33] | Test counterpart and linked helpers |
| M34 | [BatchedMessageStream][M34]:8-68 | Queue/worker/fault/shutdown contract |
| M35 | [Logs.Publishing][M35] | Central event declarations |
| M36 | [OpenTelemetryMiddleware][M36]:17-43,90-138 | Private propagation and diagnostic data |
| M37 | [ErrorMessage][M37]:10-44 | Exception-bearing outcomes and fatal classification |
| M38 | [ErrorServiceMessage][M38]:8-17 | Query exception text serialization |
| M39 | [MetricsMiddleware][M39]:23-46,76-79 | Worker lifetime and attempt-level metric meaning |
| M40 | [OpenTelemetry.md][M40] | Documented propagation versus implementation |
| M41 | [MessageContextGenerator][M41] and [Generators.csproj][M67] | Generated dispatch and default serialization |
| M42 | [SourceGenerator.md][M42]; [EncodersHelper][M68] | Discovery claims and actual syntax source |
| M43 | [DynamicCodeTests][M43]:17-21; [DynamicCodeGate][M69] | Simulated dynamic-code restriction, not actual AOT |
| M44 | [MessageContext.Encryptors][M44]:10-18 and [EncryptionMiddleware][M56]:24-29 | Required-protection fallback lesson |
| M45 | [SampleExecution][M45]:13-82 | Shared consumer story and demonstration policies |
| M46 | [InMemoryConnectorTests][M46]:9-34 | Shared scenario invocation pattern |
| M47 | [PubSubTestHelper][M47]:20-64 and [TestHelper][M70]:11-38 | Resulting-state assertions, waits, and cleanup |
| M48 | [AServiceHarness][M48]:9-23; [Amazon harness][M71], [Google harness][M72], [Azure harness][M73] | Containers/emulators and synchronization |
| M49 | [unit-test-report.yml][M49]:3-37 | Reporting trust context and coverage scope |
| M50 | [Shared.props][M50] | Build/package/documentation conventions |
| M51 | [Publishing benchmark][M51]:22-94 and [FakePublishConnection][M74] | Local seam baseline, not broker performance |
| M52 | [BenchMark.csproj][M52] and [PublishingWithMiddleware][M75] | Benchmark target and timed setup |
| M53 | [LICENSE][M53]:1-21 | MIT rights and notice condition |

### 26.2 SecretKit sources

| ID | Source and anchor | Main use |
| --- | --- | --- |
| S01 | [AGENTS.md][S01]:23-33,48-59 | Common boundaries, ownership, no hidden workers/replay, test discipline |
| S02 | [Current preview][S02] | Implemented subsets and live/evidence limits |
| S03 | [SecretMaterial][S03]:14-62 | Independent material ownership and explicit export |
| S04 | [MutationReceipt][S04]:19-75 | Pre-dispatch uncertainty and target binding |
| S05 | [PackageInstallTests][S05]:10-68 | Archive checks, fresh consumer, dependency boundaries |
| S06 | [Directory.Build.props][S06]:3-27 | Build/lock/warnings/pack/notices policy |
| S07 | [Directory.Packages.props][S07] | Central package versions |
| S08 | [publish.yml][S08]:4-25,58-185 and checkpoint steps | Exact-artifact publication controls and producer expectation |
| S09 | [PUBLICATION_PROTOCOL][S09]:5-20,31-79 | Acknowledged missing producer and historical gate reconciliation |
| S10 | [SDK_ARCHITECTURE][S10] | Common/native boundary; package graph; proposed status |
| S11 | [RUNTIME_CONTRACTS][S11] | Ownership, generations, cancellation, receipts, effects |
| S12 | [CORE_SCOPE_AND_ROADMAP][S12] | Accepted reduced scope and remaining gates |
| S13 | [Connector scope decision][S13] | Direct providers versus removed destination catalog |
| S14 | [SecretKit.slnx][S14] | Current project/solution membership |
| S15 | [PROJECTS.md][S15] | Package, test, sample, and tool owners |
| S16 | [ISecretReader][S16] and [SecretReference][S30] | Common seam and native authority-bound coordinates |
| S17 | [ISecretInventory][S17] | Metadata-only, bounded collection semantics |
| S18 | [SecretSelection][S18]:8-38 | Provider-independent composition with authority validation |
| S19 | [SecretCapabilityEvidence][S19] and [InfisicalContractAvailability][S31] | Static support dimensions and current use |
| S20 | [AzureKeyVaultClient][S20]:32-70,81-169 | SDK controls, native mutation/precondition and read path |
| S21 | [InfisicalClient][S21]:30-147,217-354,429-487 | Selected origin/credentials, managed transport, read and drain |
| S22 | [Reviewed changes scenario][S22] | Bounded consumer-owned batch semantics |
| S23 | [Infisical package README][S23] | Historical/current documentation friction and native guide |
| S24 | [README][S24]:143-179 | Contributor-oriented offline quickstart |
| S25 | [Azure tests][S25] and [Infisical read tests][S32] | Actual wire-seam common invariants |
| S26 | [Owned Infisical conformance guide][S26] | Separate identities, installed consumers, live/entitlement limits |
| S27 | [TokenMaintenanceTests][S27]:14-90 | Event barriers, injected time, single-flight and lifetime |
| S28 | [Release tool Program][S28]:99-111 | Exact required upstream workflow identity |
| S29 | [LICENSE][S29] | SecretKit MIT terms |

### 26.3 External verification sources

| ID | Source | Observation |
| --- | --- | --- |
| E01 | [GitHub commits/master API][E01] | Public head matches the local MQContract revision |
| E02 | [NuGet MQContract.InMemory 4.0.0][E02] | Published version, assets, and update date |
| E03 | [Exact-head push-run query][E03] and [run 29015187687][E07] | One matching push test run, conclusion cancelled |
| E04 | [CodeQL run 38118962848][E04] | Separate successful scheduled scanning run |
| E05 | [MSTest v4.2.3 Assert.IsTrue source][E05] | Condition-aware interpolation refutes an assumed all-success assertion defect |
| E06 | [Open Source Initiative MIT license][E06] | License notice condition and reuse rights |

External sources were accessed on 2026-10-11. Current service metadata can change; commit-pinned implementation citations preserve the source baseline.

[M01]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/README.md
[M02]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Abstractions/Interfaces/Service/IMessageServiceConnection.cs
[M03]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/ContractConnection.cs
[M04]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/.github/workflows/unittests.yml
[M05]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/AConnection.cs
[M06]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/NATS/NATS.csproj
[M07]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/InMemory/InMemory.csproj
[M08]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Abstractions/Abstractions.csproj
[M09]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Core.csproj
[M10]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/Connection.cs
[M11]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/AConnection.cs
[M12]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Subscriptions/QueryResponseHelper.cs
[M13]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Subscriptions/QueryResponseSubscription.cs
[M14]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/MappedConnection.cs
[M15]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Middleware/MiddlewareCollection.cs
[M16]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Middleware/CompressionMiddleware.cs
[M17]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/ResiliencePolicy.cs
[M18]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/CQRS/CqrsConnection.cs
[M20]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/NATS/Connection.cs
[M21]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/AzureServiceBus/Connection.cs
[M22]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/Kafka/Connection.cs
[M23]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/Redis/Connection.cs
[M24]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/InMemory/Connection.cs
[M25]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/RabbitMQ/Connection.cs
[M26]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/AmazonSNQS/Connection.cs
[M27]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/GooglePubSub/Connection.cs
[M28]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ActiveMQ/Connection.cs
[M29]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ApachePulsar/Connection.cs
[M30]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/HiveMQ/Connection.cs
[M31]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ZeroMQ/Connection.cs
[M32]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Samples/NATSSample/Program.cs
[M33]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/Nats/Nats.csproj
[M34]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/Shared/BatchedMessageStream.cs
[M35]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Logging/Logs.Publishing.cs
[M36]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Middleware/OpenTelemetryMiddleware.cs
[M37]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Abstractions/Messages/ErrorMessage.cs
[M38]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Messages/ErrorServiceMessage.cs
[M39]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Middleware/MetricsMiddleware.cs
[M40]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/OpenTelemetry.md
[M41]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Generators/MessageContextGenerator.cs
[M42]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/SourceGenerator.md
[M43]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/CodeGenTesting/DynamicCodeTests.cs
[M44]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/MessageContext.Encryptors.cs
[M45]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Samples/Messages/SampleExecution.cs
[M46]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/InMemory/InMemoryConnectorTests.cs
[M47]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/Shared/Helpers/PubSubTestHelper.cs
[M48]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/Shared/AServiceHarness.cs
[M49]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/.github/workflows/unit-test-report.yml
[M50]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Shared.props
[M51]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/BenchMark/PublishBenchmarks/Publishing.cs
[M52]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/BenchMark/BenchMark.csproj
[M53]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/LICENSE
[M54]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/MultiServiceConnection.cs
[M55]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/ServiceConnectionList.cs
[M56]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Middleware/EncryptionMiddleware.cs
[M57]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/Connections/AConnection.Resilience.cs
[M58]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/Kafka/Kafka.csproj
[M59]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/Redis/Subscriptions/QueryResponseSubscription.cs
[M60]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/InMemory/MessageChannel.cs
[M61]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/InMemory/MessageGroup.cs
[M62]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/AmazonSNQS/MessageMapper.cs
[M63]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ActiveMQ/ActiveMQ.csproj
[M64]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ApachePulsar/ApachePulsar.csproj
[M65]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/HiveMQ/HiveMQ.csproj
[M66]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Connectors/ZeroMQ/ZeroMQ.csproj
[M67]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Generators/Generators.csproj
[M68]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Generators/EncodersHelper.cs
[M69]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Core/DynamicCodeGate.cs
[M70]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/Shared/Helpers/TestHelper.cs
[M71]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/AmazonSQNS/AmazonSQNSTestHarness.cs
[M72]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/GooglePubSub/GooglePubSubTestHarness.cs
[M73]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/Testing/ConnectorTesting/AzureServiceBus/AzureServiceBusTestHarness.cs
[M74]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/BenchMark/PublishBenchmarks/FakePublishConnection.cs
[M75]: https://github.com/roger-castaldo/MQContract/blob/fcd14d6103a743b4d0688a2633a1ffcf788c6261/BenchMark/PublishBenchmarks/PublishingWithMiddleware.cs
[S01]: ../../../AGENTS.md
[S02]: ../../public/current-preview.md
[S03]: ../../../src/SecretKit.Core/SecretMaterial.cs
[S04]: ../../../src/SecretKit.Core/MutationReceipt.cs
[S05]: ../../../tests/SecretKit.Package.Tests/PackageInstallTests.cs
[S06]: ../../../Directory.Build.props
[S07]: ../../../Directory.Packages.props
[S08]: ../../../.github/workflows/publish.yml
[S09]: ../releases/PUBLICATION_PROTOCOL.md
[S10]: ../SDK_ARCHITECTURE.md
[S11]: ../RUNTIME_CONTRACTS.md
[S12]: ../CORE_SCOPE_AND_ROADMAP.md
[S13]: ../../public/connector-scope-decision.md
[S14]: ../../../SecretKit.slnx
[S15]: ../../../PROJECTS.md
[S16]: ../../../src/SecretKit.Core/ISecretReader.cs
[S17]: ../../../src/SecretKit.Core/ISecretInventory.cs
[S18]: ../../../src/SecretKit.Extensions.Configuration/SecretSelection.cs
[S19]: ../../../src/SecretKit.Core/SecretCapabilityEvidence.cs
[S20]: ../../../src/SecretKit.AzureKeyVault/AzureKeyVaultClient.cs
[S21]: ../../../src/SecretKit.Infisical/InfisicalClient.cs
[S22]: ../../../samples/ProviderAssessment/ReviewedChangesScenario.cs
[S23]: ../../../src/SecretKit.Infisical/README.md
[S24]: ../../../README.md
[S25]: ../../../tests/SecretKit.AzureKeyVault.Tests/AzureKeyVaultTests.cs
[S26]: ../../../tests/SecretKit.Infisical.Conformance.Tests/README.md
[S27]: ../../../tests/SecretKit.Hosting.Tests/TokenMaintenanceTests.cs
[S28]: ../../../tools/SecretKit.Release/Program.cs
[S29]: ../../../LICENSE
[S30]: ../../../src/SecretKit.Core/SecretReference.cs
[S31]: ../../../src/SecretKit.Infisical/InfisicalContractAvailability.cs
[S32]: ../../../tests/SecretKit.Infisical.Tests/InfisicalReadTests.cs
[E01]: https://api.github.com/repos/roger-castaldo/MQContract/commits/master
[E02]: https://www.nuget.org/packages/MQContract.InMemory/4.0.0
[E03]: https://api.github.com/repos/roger-castaldo/MQContract/actions/runs?head_sha=fcd14d6103a743b4d0688a2633a1ffcf788c6261&event=push&per_page=1
[E04]: https://github.com/roger-castaldo/MQContract/actions/runs/38118962848
[E05]: https://github.com/microsoft/testfx/blob/v4.2.3/src/TestFramework/TestFramework/Assertions/Assert.IsTrue.cs
[E06]: https://opensource.org/license/mit
[E07]: https://github.com/roger-castaldo/MQContract/actions/runs/29015187687
