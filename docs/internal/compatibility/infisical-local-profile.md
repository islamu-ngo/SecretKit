# Infisical local-profile harness

## Evidence status

P7.1 admission and the runnable installed-consumer harness are authored.
No native/provider run was authorized or performed for this increment.
This page is a launch contract, not a successful compatibility report.
The profile is `infisical-runtime`, version `0.1.0-local.20261024.1`, with exactly
Core, Infisical, Configuration and Hosting. It has no public-release authority.

P1 adds a separate **owned causal issuance** host, not introspection of supplied
tokens. `LocalProfileConformanceTests` selects `RunCausalFromEnvironmentAsync`;
the development-functional pilot still selects `RunFromEnvironmentAsync`.
The latter retains all three unavailable supplied-token binding cases. Fresh
issuance never upgrades its actors, its policy digest or its report.

The causal host verifies the owned image/loopback ingress, creates fresh
organization identities with no-access organization roles, observes memberships,
empty additional-privilege inventories and Universal Auth configuration, creates
bootstrap credentials and retains the exact returned login tokens. Main runtime,
denied, writer and observer actors are generated independently. The host and child
both challenge the same runtime actor against an observer-confirmed populated
foreign project. A missing fixture, unknown response or another actor's denial
cannot satisfy that challenge. Create and update use different random material;
the observer must see replacement bytes and a changed native revision.

These are bounded claims about newly issued actors in a trusted, exclusively
controlled qualification run. They are not arbitrary-token principal proof,
remote attestation, release-to-image provenance or edition/entitlement proof.
Declared version/edition fields remain declarations.

The conformance host's Release build and 50 deterministic offline
`LocalProfileAdmissionTests` passed, exit 0. An authority-guard regression check
first produced a behavioral RED: 48 tests, 47 passed and one failed, exit 2.
Restoring the guard and completing the matrix produced 50/50 GREEN.
Final review added durable-create/cleanup regressions: the expanded admission
suite passed 58/58, including failed observer, interrupted execution,
unacknowledged effects and uncertain cleanup. No provider call was required.
These tests use synthetic, noninstalled archives for byte-binding checks.
The parent owns refreshed packaging and installed-mode evidence; neither
offline result establishes native support.

## Offline verification

Run exact offline classes from the SecretKit root; coordinate the shared build
outputs with other sessions:

```sh
dotnet restore tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --locked-mode
dotnet build tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --configuration Release --no-restore -p:Version=0.1.0-local.20261024.1
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalNativeProofTests/*' --minimum-expected-tests 32 --zero-tests-policy strict
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileAdmissionTests/*' --minimum-expected-tests 58 --zero-tests-policy strict
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileFunctionalAdmissionTests/*' --minimum-expected-tests 1 --zero-tests-policy strict
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileUpdateWitnessTests/*' --minimum-expected-tests 2 --zero-tests-policy strict
```

The matrix covers explicit authority/profile selection, distinct selected actor
inputs, owned selectors, origin restrictions, TLS-bypass rejection, duplicate
and unknown JSON, bounded input, Unix file protection, stale source/profile/
original/record bytes, complete report denominators and report redaction.
The live `LocalProfileConformanceTests` class is separately filterable. Missing
authority or inputs fails that class; it never skips or passes on absence.
Do not run the broad conformance suite to select offline tests.

`LocalNativeProofTests` uses the actual typed management/runtime HTTP parsers,
stateful loopback protocol effects, the shared child executor and serialized
producer/child envelopes and reports. Injected time advances only after a
bounded probe is armed. It checks causal substitution, original issue/expiry
scope, all six protocols, unchanged-value rejection, same-actor foreign access,
partial setup, interrupted execution, protected cleanup accounting and pending
approval uncertainty. This is controlled offline evidence, not an installed
native run. The initial P1 behavioral RED built successfully and failed all
three tests: missing supplements, missing producer cleanup, and a revision-only
update incorrectly accepted as replacement.

Independent review then reproduced two more producer defects through the same
HTTP/parser seam: an uncertain foreign membership lacked its project ancestor
fence, and Q06's definite rejected renewal remained uncertain. The compiling
34-case run failed exactly those two cases. Recording both membership parents
before dispatch and forwarding terminal renewal evidence made all 34 proof
cases and all 58 original admission cases pass. Scoped formatting also passed.
These remain offline source observations, not native effects.

## Freeze and installation

Before a separately authorized native run, finish all source and documentation
edits, build the candidate, and preserve exactly four original archives in an
otherwise empty originals directory. Create a distinct local record through
the release tool's `local-prepare` command, then use `local-check`. These commands
take source root, originals directory and record directory in that order.
The record remains `prepared-not-native-qualified`.

`LocalProfileConformance.Freeze` invokes `LocalQualification.Check`, reopening
the original archives and recomputing the source-content snapshot. It binds:

- Exact local version and profile SHA-256.
- Complete source-content SHA-256, including dirty/untracked source bytes.
- SHA-256 of the actual `local-qualification.json` record bytes.
- Exact four package identities and their original-archive SHA-256 values.

The host checks this binding before installation, before dispatch and after the
child exits. Changed source, profile, record or archive bytes invalidate the
observation; an old report must never be relabeled for refreshed archives.
This is consistency evidence, not a trusted build attestation.

Installation reuses `LocalPackageCandidate.Select`, `PrepareConsumer("full")`
and `VerifyRestored` in a unique empty cache. Restore/build credentials are not
injected. The minimal fixture references no management, Azure or database
package; setup stays in the existing nonpackable conformance host. The host
retains existing full-family release contracts.

## Live host environment

All paths below must be absolute. No credential belongs in these variables.

| Variable | Required value |
| --- | --- |
| `SECRETKIT_LOCAL_NATIVE_AUTHORITY` | `owned-local-native-execution`, only under actual execution authorization |
| `SECRETKIT_LOCAL_PROFILE` | `infisical-runtime` |
| `SECRETKIT_LOCAL_SOURCE` | Frozen SecretKit source root |
| `SECRETKIT_LOCAL_ORIGINALS` | Directory containing exactly the four originals |
| `SECRETKIT_LOCAL_RECORD` | Directory containing `local-qualification.json` |
| `SECRETKIT_LOCAL_NATIVE_INPUT` | Protected JSON envelope file |
| `SECRETKIT_LOCAL_NATIVE_REPORT` | New, unused report path with an existing parent directory |

The protected file is bounded to 131072 bytes; links are rejected. Unix input
permissions must contain only owner read/write bits, such as mode 0600 or 0400.
Windows ACL protection is not established by this Unix-mode check and remains
an additional qualification gate.

With separate authority and all required inputs, the live class entrypoint is:

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileConformanceTests/*' --minimum-expected-tests 1
```

This command is not part of offline verification. Even a future functional
observation run cannot pass full qualification while the binding cases below
remain unavailable.

The causal selection requires the verified owned IPv4 loopback sandbox and an
explicit setup authority allowed to create/revoke the run's actors, credentials,
memberships, project and fixtures. The selected primary project and owner folder
already belong to the authorized sandbox. The host generates new read/write keys
under the owner prefix, creates its read fixture and a separate foreign project,
and fixes selectedVersion=1. It does not overwrite a preowned read/write key.
Supplied runtime/denied/writer/observer tokens and optional authentication are
not promoted or used as causal actors; only the selected setup authority is
reused. The setup credential is not handed to the installed child.

### Separately scoped development-functional pilot

After actual authorization and protected input admission, select this class
instead of the full-qualification class:

```sh
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileFunctionalTests/*' --minimum-expected-tests 1 --zero-tests-policy strict
```

Required inputs include all five selected actors, an initially absent owned
write key, a preowned version-1 read key with selectedVersion=1 and recreation
permission, and finite Universal Auth with actual TTL at most 45 seconds,
positive maximum TTL, observeExpiry=true and distinct same-client recovery
material. Select approvalKey=null. Authoritative issuance/permission records
must be reviewed; actor strings, digests, organization-only metadata and decoded
tokens are not proof. Missing inputs fail; no skip or fallback principal exists.

The 17 required IDs are read, read-native, inspect, repeat-revision,
selected-revision, denied-read, runtime-write-denied, create, update-value,
recreation, universal-login, get-token, renew-token, expired-token,
explicit-recovery, network and cleanup. Ordinary cases require passed/observed;
network requires passed/selected-origin-system-trust-and-proxy; cleanup requires
passed/owned-resource-cleanup and the create effect must be Applied.
Pending approval remains unavailable/not-observed, and all three binding proofs
remain unavailable/authoritative-proof-unavailable. Contradictory effect/reason
evidence rejects even when 17 status strings say passed.

The live class independently freezes expected package/source/profile/record
identity before the existing host run and after cleanup. The predicate does no
I/O and grants no cleanup/publication authority. Both existing full-gate
assertions and the 21-entry report remain strict. Functional success does not
prove arbitrary-token identity, production readiness, approval semantics,
private CA/proxy/DNS support or complete native qualification.
Cleanup covers the acknowledged write resource only; the recreated read key
needs explicit operator follow-up. Failure or uncertainty blocks acceptance.

## Protected envelope schema

JSON uses camelCase. Every constructor field, including nullable fields, must
be present. Unknown fields, duplicate fields and malformed values are rejected
before dispatch. No secret values or actual sensitive coordinates belong in
checked-in input examples.

The root object is:

| Field | Contract |
| --- | --- |
| `schemaVersion` | Integer `1` |
| `kind` | `local-native-run` |
| `profileId` | `infisical-runtime` |
| `authority` | `owned-local-native-execution` |
| `binding` | The frozen binding below |
| `settings` | Protected selected deployment, actors and optional authentication |

`binding` contains `version`, `profileSha256`, `sourceSha256`, `recordSha256`
and `packages`. The version is the exact local version above. Each hash is
64 lowercase hexadecimal characters. `packages` is an exact four-element
array of `{ id, sha256 }` objects matching the original archives and the frozen
host record. Extra, duplicate, mixed-version and stale witnesses fail.

`settings` contains:

| Fields | Contract |
| --- | --- |
| `origin`, `allowLoopbackDevelopmentHttp` | Root HTTPS origin without userinfo/query/fragment; or explicitly enabled `http://127.0.0.1` at a nondefault port |
| `owner` | `secretkit-sdk-` followed by exactly eight hexadecimal characters |
| `organizationId`, `projectId` | Explicit GUID selections; not grants of ownership |
| `environment`, `folder` | Explicit environment; folder exactly `/` followed by `owner` |
| `readKey`, `writeKey`, `approvalKey` | Distinct owned names beginning `SDK_`, uppercased eight owner hex characters and `_`; `approvalKey` may be null |
| `selectedVersion` | Positive integer or null |
| `serverVersion`, `edition` | Host declarations; parseable numeric version and `oss`, `enterprise` or `cloud` |
| `recreate` | Explicit Boolean selecting destruction/recreation of the owned read key |
| `setup`, `runtime`, `denied`, `writer`, `observer` | Five distinct actor objects, each `{ id, token }`, with GUID ID and bounded token |
| `authentication` | Null, or the authentication object below |

Distinct actor IDs and token strings protect local selection against aliasing.
They do **not** establish authoritative token-to-principal binding. Likewise,
the environment's authority marker does not grant provider permissions.
For loopback, the host additionally reuses `OwnedSandbox.VerifyAsync` to check
the owned pod labels, pinned image digest and exact loopback ingress before
provider dispatch. HTTPS selections do not receive this pinned-sandbox proof.

`authentication` contains:

| Field | Contract |
| --- | --- |
| `actorId` | Must equal the selected runtime actor ID; still a host assertion |
| `clientId`, `clientSecret` | Explicit bounded Universal Auth bootstrap selection |
| `policyEvidenceSha256` | Host-supplied policy evidence digest, not proof by itself |
| `lifetime` | Explicit `finite` or `periodic`; never inferred from maximum TTL |
| `periodSeconds` | Null for finite; positive and at most 86400 for periodic |
| `recoveryClientSecret` | Null or independently supplied material different from the initial bootstrap secret |
| `observeExpiry` | Explicit Boolean selecting real issued-token expiry observation |

Login evidence is bound using the exact returned login's
`BindLifetimeEvidence`, preserving reported expiry and the conservative original
request time. A finite session additionally needs a positive reported maximum.
Periodic policy remains an unqualified host assertion even when explicitly
selected.

When expiry observation is selected, the actual issued token must report a TTL
of at most 45 seconds. The harness does not renew that token. It waits for a
conservative upper expiry bound, then requires actual provider denial and the
local session's recovery-required state. Only after that observation may it
attempt one explicit recovery login using the separate bootstrap material and
the same client ID. Renewal can then exercise the recovered token. No credential
callback, inferred principal, login retry or mutation replay is added.

## Installed child protocol

The host launches the installed fixture as:

```text
dotnet <installed-consumer.dll> native <absolute-unused-child-report-path>
```

`Program` passes only the arguments **after** `native` to
`NativeWorkflow.RunAsync(string[] args)`, returning `Task<int>`. That array must
contain exactly one report path. Protected input travels only through redirected
stdin: one compact JSON envelope followed by a newline. The host keeps stdin
open for the optional recreation control exchange.

If selected, recreation requires an initial qualified native revision at version
1. The child writes the fixed material-free line `LOCAL_RECREATE`. The host
uses only the explicitly selected setup actor and exact owned read key to
delete/recreate it, retaining mutation receipts. After confirmed application it
writes `continue` and a newline to stdin. The child then requires the same
numeric version but a different native resource revision. Other stdout lines
or repeated control requests are rejected; stderr is discarded.

The child writes a complete unavailable-denominator report before any credential
dispatch. Exit 2 means invalid launch arguments; exit 1 means admission failure,
incomplete execution, failed observations or any unavailable case. Exit 0 is
reserved for all child-owned cases and supplements passing; the original secret
cleanup and producer cleanup remain host observations. Supplied-token binding
guards prevent its full success. A report is not expected when admission fails.

### Causal issuance and lifetime control

The host-only `owned-causal-issuance-v1` extension travels over protected stdin,
never through an imported setup file. The host compares the entire produced
envelope before launch. Run nonce, frozen qualification-record hash, primary
namespace and foreign fixture are bound together; a trial additionally carries
that same run/record/namespace scope and its original request/completion bounds.
No token-derived public identifier is used.

The child requests each ordered trial with `LOCAL_TRIAL Qxx start`. The host
creates and observes an isolated actor/policy/bootstrap and performs its first
login just in time. Its bounded JSON response contains the actual issued token.
`second-bootstrap` is permitted once for Q04; `explicit-recovery` once for Q06.
Renewal has a pre-dispatch accounting exchange and an acknowledged-token exchange
under `LOCAL_RENEWED`; exact returned material remains protected IPC/memory.
No credential-bearing control line is a report, log or ordinary stdout sink.
The parent consumes it privately and does not render it. Unknown commands,
duplicate starts, unbound reports and unavailable trial evidence cannot pass.

| Supplement | Actual protocol |
| --- | --- |
| Q01 | Observed TTL=10/max=20/period=0; renew at original issue+5 and +12; after the conservative original maximum, require provider denial of the renewed credential and local recovery-required without another dispatch |
| Q02 | Observed TTL=10/configured max=20/period=60; renew, then renew/read beyond the original configured maximum while within the observed period; reported maximum zero alone is never periodic evidence |
| Q03 | Isolated unrenewed TTL=10 token; probe after response-completion+TTL+1 and require provider denial plus local recovery-required |
| Q04 | Bootstrap limit one: the host's acknowledged first login, then one explicit second exchange using the same bootstrap; require definite rejection |
| Q05 | Access-token limit one: exactly one permitted selected value read, then a second denied read, with no unrelated call or renewal using that actor |
| Q06 | Fresh local session without token remains recovery-required and performs no login; only an explicit independently authorized replacement bootstrap/login for the same actor restores read/renewal |

Q01-Q03 never recenter lifetime at handoff. Q06 tests missing-token state, not
process-memory erasure or crash recovery. Native time, actual request-use
consumption and revocation on the selected pin remain qualification gates.

### Whole-producer cleanup

The outer finalizer precedes the first setup mutation and covers partial setup,
failed launch, child/observer failure and cancellation. A separately bounded
cleanup drains the child first, revokes acknowledged credentials and tears down
only acknowledged run-owned fixtures, memberships, configurations, identities
and the foreign project, in dependency order. Original/renewed token material
is held separately from the resource ledger.

The owner-only `producer-ledger.jsonl` records run ownership, exact protected
cleanup coordinates, dependency handles and dispatch receipts, including
pre-dispatch uncertainty. It contains no credential bytes or fixture values.
Unknown acknowledgements block ancestor deletion and require operator
reconciliation; cleanup never guesses a handle, deletes broadly or replays a
mutation. Failed cleanup is retained rather than retried. Tokens are not
persisted for later recovery.

The original `cleanup` case still concerns only the acknowledged write key.
Required `producerCleanup` separately reports `complete`, `incomplete` or
`unavailable`, plus outstanding known and uncertain counts. Full causal success
requires complete cleanup with both counts zero, all 21 original cases and all
six ordered supplements passed. A passed secret cleanup cannot stand in for it.

## Report schema and native denominator

The material-free report has `schemaVersion: 1`,
`kind: local-native-observation-not-public-approval`, the exact `binding`,
`declaredServerVersion`, `apiVersion`, `declaredEdition`, `platform`, `createEffect`
and `cases`. `createEffect` retains the bounded receipt state independently of
the create scenario's observer outcome: `NotDispatched`, `PossiblyDispatched`,
`Applied`, `Pending`, `Rejected` or `Conflict`. The child persists this witness
before the independent read. The host recovers a validated bound child report
even after control-channel failure and attempts cleanup only for `Applied`,
with a separate bounded deadline. Cleanup uncertainty and failed observations
remain visible; neither is converted into mutation replay authority.
The two declared deployment fields are **not** observed server metadata.
Each case has fixed `id`, `status` (`passed`, `failed`, `unavailable`) and a
bounded fixed-vocabulary `reason`. Reports contain no actor IDs, tokens,
credentials, material, actual secret coordinates, response bodies or exception
text.

The current private report also requires `proofRun`, `supplementalCases`,
`producerCleanup`, `updateEffect`, `approvalEffect` and `executionCompleted`.
The six-member supplemental array is exactly Q01-Q06 in that order; missing,
duplicate, reordered or substituted members fail admission. Mutation effects
are persisted before independent observation. An incomplete child report with
NotDispatched cannot erase a later possibly dispatched mutation.
Supplied-token reports keep proofRun null, all three binding gates unavailable,
supplements unavailable and producer cleanup unavailable. Only the originating
fresh producer can admit its own causal report; its actual issuance and renewal/
exchange accounting must support any passed supplement.

The complete 21-case denominator is:

| Cases | Observation or limitation |
| --- | --- |
| `read`, `read-native`, `inspect` | Selected raw/no-import read and complete direct-folder inventory; native revision requires the adapter's returned ID/scope/positive-version contract |
| `repeat-revision`, `selected-revision` | Independent client's same revision and optional positive selected version |
| `denied-read`, `runtime-write-denied` | Selected denied actor cannot read; runtime update receives definite denial |
| `create`, `update-value` | Selected writer mutation confirmed applied, independent observer sees material; update must replace the created value with distinct material and change its revision |
| `pending-approval` | Optional preowned key retains the actual submission receipt; the case remains unavailable without supported independent approval/effect observation, even when acknowledgement reports pending |
| `recreation` | Optional host-driven version-1 delete/recreate distinguishes resource identity |
| `universal-login`, `get-token`, `renew-token` | Actual selected login, session-backed read and confirmed native renewal |
| `expired-token`, `explicit-recovery` | Actual short-lived issued-token expiry and explicitly supplied same-client recovery |
| `network` | Selected-origin read over the validated handler's default system trust/network settings only |
| `cleanup` | Host confirms removal of the newly created write key only |
| `deployment-binding`, `actor-binding`, `policy-binding` | Supplied-token mode: always unavailable. Causal mode: only scoped owned pin/issuance/native-challenge evidence for freshly generated actors; never arbitrary-token introspection or edition proof |

Report validation rejects missing/duplicate cases, substituted bindings, raw
diagnostics and invented supplied-token success for the three binding gates. Optional or
edition-limited cases remain in the denominator. No mock result substitutes for
a live observation.

## Remaining qualification gates

No live coverage is claimed. A future owned run must obtain actual execution
authority and protected inputs, freeze final archives/source/record bytes, and
capture genuine observations. It must additionally supply supported
authoritative deployment, token-to-principal and token-policy proof before
those binding cases can close. A policy digest or distinct strings cannot
close them. Newly generated causal actors are a separate observation mode, not
replacement evidence for those supplied tokens.

Pending approval remains a specific source-contract gate: the typed static
change surface reports submission, but this owned surface has no established
typed approval-request teardown operation. A pending submission therefore
retains reconciliation work and prevents complete producer cleanup. No close/
delete endpoint or broader cleanup authority is invented. Likewise, failure to
acknowledge revocation of an expired or renewed credential remains outstanding;
expiry is not silently reported as revocation.

Submission acknowledgement also cannot certify the individual approval case.
The current observation surface does not establish independent approval state,
so a successful submitted/pending receipt leaves `pending-approval` unavailable,
not passed. The receipt still reaches protected cleanup accounting. Controlled
regressions cover both an acknowledgement with no visible change and a provider
that applies the value while reporting pending; an independent reader confirms
the latter change, and neither response can manufacture a passing approval case.

On 2026-10-24, a bounded complete inspection of the official
[public OpenAPI contract](https://app.infisical.com/api/docs/json), version
`0.0.1`, covered 1,583 paths. Approval-related operation metadata and generic
request routes did not establish a secret-approval-request teardown interface;
the approval/request mutation routes found concerned certificate signing.
This is public-contract evidence, not proof that a private or differently
versioned deployment has no such API. A deployment-compatible supported contract
and owned acknowledgement/settlement are still required. Missing native inputs
alone are not an authoring blocker, and unsupported closure cannot be fabricated.

Custom DNS, private-CA and explicit proxy deployments, cancellation/shutdown
behavior under real networking, pending approval settlement, lost mutation
acknowledgements and complete owner-ID cleanup remain unqualified. The current
report exports bounded create/update/approval effects, not detailed dispatch receipts:
non-success mutations fail their case and are never retried. Unknown effects
are not cleanup authority.
In supplied-token mode the preowned read key remains changed after selected recreation; submitted
approvals and other preowned resources remain the external owner's
responsibility. The `cleanup` case must not be read as whole-sandbox cleanup.

The parent owns final integrated verification, refreshed installed-mode
evidence, public documentation and qualification status. No commit,
publication, provisioning or database dependency is authorized by this harness.

Credential-free PR CI separately restores/builds the conformance project and
runs only LocalProfileAdmissionTests, LocalNativeProofTests,
LocalProfileFunctionalAdmissionTests, LocalProfileUpdateWitnessTests,
InfisicalPeriodicRenewalGateTests and InfisicalRotationCancellationAdmissionTests.
Each class requires a positive test count. These guards preserve admission and
evidence rules without selecting native execution or changing the existing
17-case functional and 21-case native denominators.
