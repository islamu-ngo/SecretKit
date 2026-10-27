# Runtime adoption security and evidence contract

> Audience: SDK implementers, reviewers and application integrators
> Status: Implemented offline slices; final native/platform qualification remains incomplete
> Owner: SecretKit runtime/security maintainers
> Decision date: 2026-10-24
> Source anchors: [architecture](SDK_ARCHITECTURE.md), [runtime](RUNTIME_CONTRACTS.md), [ADR-003](adr/ADR-003-runtime-adoption-security-evidence.md)

SecretKit is **in development, not ready for production**. This contract defines
the Infisical runtime adoption boundaries without certifying a deployment.
Implementation and dated evidence remain described
in [current preview](../public/current-preview.md).

## Scope and ownership

Provide independent installed-package console, Generic Host worker and
ASP.NET Core applications. Core/Infisical are required; Configuration/Hosting
remain independently optional. Management and ASP.NET must not enter shipped
runtime dependencies. Applications own semantic validation, client activation,
request leases, readiness, persistence and recovery. No Event/Configurator
integration, new provider, database driver, universal writer, hidden material
cache, fallback identity or public publishing is included.

The current SDK already provides selected native reads/writes, qualified raw
revisions, explicit authentication and optional maintenance. Extend those
boundaries rather than recreate them. Development redesign updates real
callers/tests directly, without aliases or old-framework support.

## Observable acceptance

The following identifiers describe requirements, not completed observations.

| ID | Required behavior |
| --- | --- |
| S01 | Origins, authorities, references and identities are explicit; substitution fails before unauthorized use, with no broader principal fallback. |
| S02 | Applied, pending, denied, conflicting, cancelled and unknown writes retain native disposition and caller-held receipts; no replay or implied activation. |
| S03 | Raw resource identity and positive provider version distinguish update/recreation; timestamps/material hashes do not invent revisions. |
| S04 | Await required preparation before dependent construction; optional failure cannot invalidate unrelated required work. |
| S05 | Preserve original authentication lifetime and principal; expiry, uncertain renewal or consumed bootstrap requires explicit authorized recovery. |
| S06 | Reload/check notifications do not activate clients; revision, enabled-state and absolute-deadline fences reject late candidates. |
| S07 | Console performs selected installed-package reads/explicit writes, with bounded truthful exit outcomes and no material output. |
| S08 | Worker awaits admission before work, starts maintenance explicitly and drains before disposing app-owned resources. |
| S09 | One request pins one accepted generation; replaced/rejected clients retire exactly once after leases release, with awaited asynchronous completion. |
| S10 | Success/failure/startup/cancellation/shutdown do not emit credentials, material, protected coordinates or hostile provider prose to controlled sinks. |
| S11 | Safe-mode origin/TLS/redirect policy is enforced; explicit host-controlled transport retains host network policy. Both retain typed authority, body budgets, cancellation, ownership and truthful SDK handoff evidence; the SDK adds no replay. |
| S12 | Installed minimal/configuration/hosting/full graphs remain independent; web framework dependency is confined to its app. |
| S13 | Native actor/policy evidence requires owned causal issuance and native challenges, not labels, token hashes or JWT decoding. |
| S14 | Independent actors observe actual values/effects, approval state and lifetime limits; acknowledgements alone are insufficient. |
| S15 | Claims bind exact source/profile/original archives/run/platform and complete denominators; unavailable cases cannot become success. |
| S16 | Performance, retention and trimming/AOT results name their workload/environment and tested profile, not general compatibility. |
| S17 | A new provider requires demonstrated demand, official semantics, ownership, provenance and native environment; no placeholder implementation. |
| S18 | Breaking development changes update callers/tests/docs/admission together without weakening authority or retaining obsolete contracts. |

## Threat and trust boundaries

The worst credible break is credential disclosure through a reusable demo,
allowing external vault access. Before each app's implementation, compiling
process/host/HTTP tests must fail on synthetic credential canaries through
controlled output. Exercise logs/scopes, activities, metric tags, stdout/stderr,
HTTP errors and hostile response bodies. Omit protected data rather than depend
only on redaction. Revealed/exported managed strings remain host responsibility.

The trusted qualification host, its OS/runtime, selected provider and explicitly
authorized setup operator are roots, not independently attested facts.
Untrusted inputs/responses, concurrent callers, cross-scope references, forged
or stale evidence and substituted archives must fail closed. Process-memory
compromise is not an SDK protection claim.

Infisical networking is selected explicitly through NetworkOptions.Transport.
SafeDefault and SafeWithPrivateTrust retain normal issuer/hostname checks,
disable redirects/cookies/propagation, and omit ambient proxies. Explicit Proxy
selects safe routing; private roots are copied as public data and use the
handler's default no-revocation-lookup policy. HostControlled accepts a supplied
HttpClient or handler unchanged, including arbitrary HTTP(S), TLS, redirect,
retry and diagnostic policy. SDK-side typed authority/parsing/material/receipt
boundaries remain active, but no network guarantee is made inside that pipeline.
Borrowed resources are never disposed or reconfigured by the SDK.

Protected input must be bounded, reject duplicate/unknown fields and unsafe
file links, and never put credentials in command-line arguments or reports.
Native Windows credential-file claims additionally require observed ACL
protection. Default demo help does no I/O. Web binds loopback and exposes only
material-free work/liveness/readiness; no credential, mutation or admin routes.

## Causal proof, effect oracles and cleanup

Use an authorized owned deployment and fresh scoped actors. Observe native
configuration, issue credentials, and hand the exact tokens to the installed
child over protected IPC. Arbitrary supplied tokens remain unqualified.
Challenge the same allowed runtime actor in an independently populated foreign
scope; another denied actor does not prove that runtime actor's isolation.
Create/update use different material and independently verify replacement plus
revision; a revision-only change cannot satisfy the update oracle.

Before the first setup mutation, establish a protected per-run ledger for
acknowledged resource handles, ownership and receipts, without credential bytes.
The outer finalizer covers partial setup, launch/observer/child failure and
cancellation. Separately bounded, explicitly authorized cleanup drains trials,
revokes acknowledged credentials and tears down only acknowledged run-owned
resources in dependency order. Uncertain effects need operator reconciliation,
not delete-all, guessed handles, retries or broader principal selection.

Preserve the original ordered 21 native cases, including the existing secret
cleanup case. Require separate producer cleanup evidence; the secret case
cannot certify teardown of setup actors. Add exactly six ordered supplemental
trials: Q01 finite ceiling, Q02 periodic continuation, Q03 unrenewed expiry,
Q04 bootstrap-use limit, Q05 access-token-use limit, Q06 explicit recovery.
Q04/Q05 isolate first/second operations with a configured use limit of one;
do not infer consumption rules for arbitrary failed requests or renewal.

## Lifecycle, evidence and recovery

Async preparation precedes host start/HTTP serving. Generation publication is
application policy, not IConfiguration notification. Invoke and await user
disposal outside locks; retain exactly-once completion for active, superseded
and rejected clients. Cancellation/timeout never abandons cleanup or disposes
under a held request. Timeout is not successful drain.

Use deterministic event barriers/injected time before triggers, independent
oracles and real parser/process/HTTP seams. No sleeps, mock-call mirroring or
source-text assertions. Native lifetime may measure time itself with prearmed
bounded probes, never polling until success.

Freeze tracked source/docs/locks before final qualification; keep immutable
original archives and source-content records. Restore actual app projects
with exact versions, reviewed locks, source mapping and fresh caches, not SDK
ProjectReferences. Staging packages used to generate locks are not final proof.
Any changed bound input invalidates dependent evidence and requires a fresh
candidate. Offline success does not grant native or publication authority.

Local final execution uses source locks bound to its frozen original archives.
CI rebuilds carry their own commit metadata, so CI uses a separately validated
temporary input bundle. Its staged locks may differ from finalized source locks
only in SecretKit content hashes; versions, ranges, dependency edges, external
hashes and framework graphs stay fixed. Bind source/profile/qualification,
originals, app/source-lock inventory and workflow run/commit before locked app
execution. Invalid explicit bundle selection cannot fall back. Both platforms
must observe the same bundle; CI snapshots do not requalify historical archives.

Missing credentials/entitlements/platform executors block their qualification
claims, not independent authoring. Preserve partial results and full case
denominators. Reverting code cannot undo a remote write or consumed bootstrap.
No automatic login, replay, or operator cleanup is inferred from uncertainty.

## Current offline evidence and remaining gates

The installed console, started Generic Host and real loopback HTTP app have
controlled process evidence. Default activity tags, metric tags, Trace output,
stdout/stderr and HTTP errors are captured with synthetic canaries. The test-only
BCL observer is explicitly injected into test processes, not shipped or required
by an SDK or demo. Separate positive probes prevent empty capture from passing.
Native HTTP DiagnosticListener payloads are checked separately, including public
request members. Real TLS rejection, cross-origin redirect, body-budget and
exact-candidate rejection paths are exercised without credentials or bypasses.

Application retirement retains completion/failure for repeated lease disposal,
drains held work and invokes cleanup outside locks. Optional preparation has a
separate budget and cannot consume required startup's deadline. The producer
records all membership parents before dispatch; definite rejected renewal is
settled, while unknown effects remain uncertain. These are controlled local
observations, not native qualification or proof against a compromised process.

Native client/session/helper shutdown retains one original public outcome across
concurrent or reentrant stop/disposal. Notification, drain and owned cleanup
share one injected-time deadline. Callback faults are sanitized without losing
cleanup; timeout remains timeout after eventual completion. Late renewal cannot
publish. These are deterministic offline invariants, not forced termination of
arbitrary host callbacks or new deployment qualification.

Full native acceptance still requires all 21 original cases, six supplements
and complete producer cleanup. Pending approval exposes a concrete contract gap:
the current typed surface reports submission but does not establish owned request
teardown. A pending receipt therefore retains reconciliation and cannot produce
complete cleanup. Do not invent a close endpoint, infer closure from absence, or
reduce the denominator. Actual deployment authority, entitlements, Windows
execution and exact final archive-bound native effects remain separate gates.

The selected Linux trim/AOT publishes currently fail analysis; no suppressed
warning, compatibility flag or ordinary JIT success changes that assessment.
See [measured adoption and recovery](../public/demos-and-recovery.md) and the
[local evidence ledger](compatibility/infisical-local-profile.md).
