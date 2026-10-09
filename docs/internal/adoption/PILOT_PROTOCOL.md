# Offline baseline and external-maintainer pilot protocol

Status: offline measurement only; Phase 2.4 live reads and Phase 9.2 external
adoption remain OPEN. No maintainer has been contacted by this work.

## Current experiment

The independently authored, nonpackable
[`SecretKit.ConsumerBaseline`](../../../tools/SecretKit.ConsumerBaseline/SecretKit.ConsumerBaseline.csproj)
executable compares two bounded consumer requirements:

- Bootstrap two required controlled keys before dependent construction; publish
  only on complete success, override their local defaults, preserve an unrelated
  default, and dispose independent material. The optional disabled integration
  requires no read. No database or business client is constructed.
- Assess one required key using the selected runtime identity, separately from
  a two-item administrative inventory. Absent and denied remain distinct;
  unavailable and unchecked are unverified; consumer-declared indirect delivery
  does not become ready. Each check is fresh; admin visibility is not delivery.

These requirements match the current samples' policy boundaries, not every
sample behavior. Read
[`BootstrapScenario`](../../../samples/RuntimeConfiguration/BootstrapScenario.cs),
[`AssessmentScenario`](../../../samples/ProviderAssessment/AssessmentScenario.cs),
and the
[`installed fixture`](../../../tests/fixtures/SecretKit.PackageConsumer/Program.cs).
This executable uses project references, not installed packages; it does not
replace the separately owned installed-workflow or live-read gates.

The SecretKit paths use actual Azure and Infisical `ISecretReader` /
`ISecretInventory` implementations. Bootstrap exercises `SecretSnapshotLoader`,
acquired material copies, and explicit configuration export. The direct path
calls the official Azure `SecretClient`, with an independently authored
application-owned collection and status normalization. It deliberately uses
Core's material/outcome vocabulary for comparable ownership, not a SecretKit
provider read. Its two-key dictionary is not an `IConfiguration` provider or
a reusable generation implementation. Timings include these different local
mechanisms; matching safe outputs do not establish equal functionality.

Azure paths share API 2025-07-01, the same generated credential, trusted HTTPS
fixture origin, challenge resource verification enabled, zero SDK retries, all
three SDK diagnostics flags disabled, and the same injected public
`HttpClientTransport`. The handler rejects other origins, methods and revisions.
No HTTP request can escape that handler. Responses are small, complete,
single-page fixtures. The SecretKit response-byte guard and full transport trust
checks are additional adapter work, not implemented anew in the direct consumer.
Failure semantics outside the recorded cells are unmeasured.

Infisical uses the actual public loopback-development HTTP path, an ephemeral
loopback-only TCP fixture, generated tokens and native v4 direct/raw selectors.
This is a fixture identity, not login, permission verification or cloud traffic.
The administrative client is a separate instance, but fixture inventories do
not implement real authorization. Consumer-declared indirect delivery does not
simulate provider reference/import expansion. No third-party source was read
or copied to author this executable; repository-native samples and documented
public interfaces supplied requirements. No new dependency was introduced:
Azure references use already admitted central versions and existing transitives.

Infisical.Sdk 3.0.4 is not a comparable timed lane. Its public read/login surfaces
lack per-request `CancellationToken` and public handler injection. Existing
[`historical assessment`](../providers/infisical-sdk-assessment.md)
recorded that a canceled `WaitAsync` wrapper left the vendor request active.
Its SDK-dependent executable/test were subsequently removed under the user's
explicit handwritten Refit/HttpClient decision. This recorded baseline predates
that transport migration and does not time its new graph. It did not invent an
authentication route. Infisical SDK parity and direct SDK timing remain UNKNOWN.

## Measurement rules and limits

[`pilot-evidence.json`](pilot-evidence.json) records native commands, exits,
source fingerprints, actual safe results, and Stopwatch ticks. Run from the
validated SecretKit repository:

```sh
dotnet build tools/SecretKit.ConsumerBaseline/SecretKit.ConsumerBaseline.csproj --configuration Release --verbosity quiet
dotnet run --project tools/SecretKit.ConsumerBaseline/SecretKit.ConsumerBaseline.csproj --configuration Release --no-build
```

Each path/workflow/scenario cell executes one separately recorded first
invocation, five discarded warmups and 30 serial measured operations. One
Stopwatch interval surrounds only the complete awaited workflow plus its safe
assertions; console serialization, setup and human coding time are outside it.
Do not compare cumulative runner duration as operation time. Raw ticks and
frequency permit independent statistics; nanoseconds = ticks * 1e9 / frequency.
Order is fixed: scenarios, then bootstrap/assessment, then SecretKit Azure,
direct Azure, SecretKit Infisical. There is no randomized order, confidence
interval, CPU isolation, GC isolation or outlier removal.

The first invocation in a cell is NOT an independent cold-process measurement:
only the process's very first operation can include untouched process-wide JIT;
later cells reuse clients and runtime state. Setup is a single mixed-path client
and fixture construction observation, not provider-specific setup or human
integration time. Warm means reused clients, handlers and process; bootstrap
still constructs a new local generation/export per operation. No material
cache or remote snapshot guarantee is asserted.

Fixture material and versions are generated in memory, never emitted. Fresh
checks rotate generated material and verify it without restart; they are
untimed correctness probes. Pre-dispatch cancellation is also an untimed probe.
The runner has a 60-second cancellation deadline, fixed iteration counts and a
4096-request loopback cap. Header count is bounded; the fixture does not accept
business requests. No remote service orchestration, credentials, secret values,
protected coordinates, payloads, tokens or provider exception text belong in
the JSON artifact.

Application-code counts are explicit source-scope counts, not product
complexity or a maintenance-cost estimate. Count nonblank, non-comment lines
including declarations and braces in the named regions. Count provider
decisions separately from provider-independent consumer policy. Report code
moved into adapters as existing, excluded code, never zero cost. The direct
lane is purposely one-provider-only; these counts cannot establish multi-provider
integration effort. Do not convert coding-agent elapsed minutes into engineering
hours.

## Pilot acceptance criteria, declared before any recruitment

Only an external maintainer who voluntarily opts into a separately authorized
pilot can provide external-adoption evidence. Agree their intended application,
required and optional keys, permitted sandbox scopes, identity source, exact
package/version, provider API/edition/cloud and observation period first. No
unsolicited outreach, posts, messages, publication or business actions are
authorized by this protocol.

Run both installed standalone workflows and a direct-provider baseline from the
same empty consumer requirement, with equal key sets, identity privileges and
failure scenarios. Preserve setup, failed attempts and unfamiliar-adapter
learning rather than preparing one lane in advance. Acceptance requires:

1. Intended runtime reads and separate admin inspection preserve absent,
   denied, unavailable, unknown validity and indirect/unverified distinctions.
   Required failures block activation; disabled optional integrations do not.
2. Controlled-key precedence has no merged-provider fallback. Acquired logical
   generations and independent ownership survive refresh/disposal; fresh
   checks see changed provider material without implying remote atomicity.
3. Cancellation reaches the actual transport, provider exceptions/material do
   not enter evidence, SDK diagnostics/trust/retry settings are recorded, and
   native import/version behavior is either verified or explicitly unknown.
4. Local installed-artifact commands and authorized live commands have exit,
   source/artifact fingerprint, test count where applicable, and observation
   evidence. Offline success cannot satisfy a live requirement.
5. The external maintainer performs the integration and reports acceptance,
   rejection or unresolved issues with permission to retain the material-free
   report. Internal reuse alone cannot satisfy this criterion.

## Human time, diagnosis and support collection

Use participant-recorded start/stop intervals with task categories and
interruptions, not agent timers. Measure from an empty sample through required
reads, bootstrap, failure handling and review. Keep deployment/identity setup,
implementation, learning, review and rework separately. Record participant
experience and which lane ran first. Until those intervals exist,
time-to-integrate is UNKNOWN.

Predeclare matched absent/denied/unavailable/invalid scenarios. For each, record
time to identify the cause, debugging actions, whether diagnosis was correct,
needed documentation/support and unresolved blockers. Retain failures;
do not equate status mapping or operation latency with diagnosis effort.
Diagnosis effort is UNKNOWN here.

Agree an observation period before measuring support burden: support cases,
maintenance hours, version upgrades, incidents and remaining failures. Capture
only category, anonymized participant ID with consent, duration and resolution;
no key names, identities, endpoints, payloads or logs containing material.
No such period or participant exists for this offline experiment.

## Candidate third-adapter research protocol

Research only; no provider addition is authorized. Before any measurement,
select a candidate based on consumer need and independent public contract
facts, record provenance/dependency rights and required native capabilities,
and define substitution criteria: selected authority, bounded material ownership,
version/validity evidence, safe outcomes, cancellation, diagnostics, trust,
inventory limits and imports/reference disclosure.

Estimate nothing from page counts. When a separate experiment is authorized,
record participant intervals for contract research, implementation, dependencies,
common-semantic proofs, native functionality, tests, docs and review. Count
changed paths and application branches, preserve rejected/unsupported contracts,
and record where semantic differences prevent substitution. No candidate was
implemented or timed here; third-adapter effort is UNKNOWN.

## Gates that remain open

Authorized live-provider compatibility and installed workflow validation,
human integration and diagnosis effort, support observation, third-adapter
effort, and external-maintainer adoption are outside this offline result.
Neither Phase 2.4 nor Phase 9.2 may be marked wholly complete from this artifact.
The result makes no superiority, production readiness or live-conformance claim.
