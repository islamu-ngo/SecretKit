# Package-only demos, measurements and recovery

**In development, not ready for production.** These are .NET 10 applications,
not deployment controllers or credential stores. Controlled local tests are
not native Infisical qualification. Start with [local package selection](local-packages.md);
select exact original archives and use source mapping and a fresh cache.

## Choose an application

| Application | Installed SecretKit packages | Application responsibility |
| --- | --- | --- |
| [Console](../../samples/Infisical.ConsoleDemo/README.md) | Core + Infisical | One selected read or deliberate create/update; retain mutation uncertainty |
| [Worker](../../samples/Infisical.WorkerDemo/README.md) | Core + Infisical + Hosting | Await preparation, explicitly start maintenance, stop/drain before disposal |
| [Loopback web API](../../samples/Infisical.WebDemo/README.md) | Core + Infisical + Configuration | Validate/activate clients, pin request leases, retire old clients after release |

The worker additionally uses Microsoft.Extensions.Hosting `10.0.12`. The web
application alone uses the ASP.NET Core shared framework. Neither expands the
SDK's dependencies. No demo references SDK source projects; the web links two
nonpackable application generation/lease sources.

Start reading each demo at `Program.cs`, then its named application class.
Console methods show each SDK operation; the worker separates host lifetime
from command processing; the web separates startup, endpoints and generation
ownership. Shared input models keep connection, mutation and session data
distinct. Each README gives the short reading order and commands.

Build the chosen app with its exact candidate version and matching generated
lock, as described in its README. No arguments or `--help` emits a material-free
help result without reading input or making provider calls. Help is a machine
event, not an interactive setup wizard.

## Protect and supply input

Use an application-owned protected stdin pipe. Do not use command-line
credentials, shell history, committed settings, terminal transcripts or
environment credential dumps. The demos have no credential-file switch or
HTTP credential-input endpoint. The host must also protect the pipe producer,
process memory, crash dumps and diagnostics.

Common input fields are `origin`, `project`, `environment`, `folder`, `key`,
and `token`. Use an explicitly selected least-privilege runtime token.
Use separately selected writer authority for an intentional console mutation;
that input also needs `value`. Duplicate/unknown fields and a `value` on a
read are rejected. The first input is bounded to 64 KiB, with additional
field/depth bounds.

The provider origin requires trusted HTTPS with no path, credentials, query or
fragment. `allowLoopbackDevelopmentHttp:true` explicitly permits loopback
development HTTP only; it is not a remote TLS bypass.

- **Console:** `read`, `create` or `update`; one JSON document followed by EOF.
  The app waits for EOF before parsing. There is no upsert or automatic login.
- **Worker:** `run` or `run --maintain`; one compact JSON frame ending in LF,
  then ASCII LF-terminated `work`, `renew` (maintenance mode only), or `stop`.
  Supply original issue time, expiry, lifetime classification and maximum TTL;
  periodic evidence also supplies its period. These are host assertions, not
  inferred from a token or proof of provider policy. See the worker README for
  exact fields. `token:null` represents lost credentials, not a login request.
- **Web:** `serve`; the first LF-terminated frame is common input. The second
  selects `downstream` (an HTTP origin with a literal loopback IP) and optional
  `optionalKey`. Then send LF-terminated `check`, `enable`, `disable` or `stop`.
  There is no public HTTP activation or administration route.

## Prepare, activate, lease and stop

The console disposes successful read material without printing it. Its `success`
means a selected read completed, not that another service accepted a credential.

The worker awaits its required read before constructing/starting the Generic
Host. `prepared` precedes `started`; neither DI registration nor a constructor
does provider I/O. `run --maintain` opts into the explicitly selected session's
maintenance. `renewal-awaiting` is a barrier, not a successful renewal;
`renewed` requires an acknowledgement. Wait for an operation outcome before
sending the next work item; the queue holds one waiting operation.

The web awaits required collection and client validation before binding.
Optional admission is a separately tracked task with its own 30-second budget;
it cannot hold the required listener startup hostage. Optional work returns
503 until its generation is usable.
Use the `listening` event's already-bound ephemeral IPv4 loopback address,
never port polling. `GET /health/live` observes serving; `GET /health/ready`
returns 200 only for a usable required generation, otherwise 503.
`POST /work` submits the fixed `{"operation":"reconcile"}` job to the selected
downstream's `/jobs`; `?optional=true` selects the separately prepared optional
client. Acceptance is not job completion. There is no secret-return route.

`check` collects and validates but does not activate or extend the old client's
absolute deadline. `enable` collects/validates a fresh candidate and publishes
only if it is still desired. `disable` fences late candidates and detaches
required work. Optional failure leaves unrelated required work available.
One request acquires one accepted generation lease; an old request keeps its
client across replacement, while later requests use the new accepted revision.
That revision is local, not a remote transaction or fleet convergence proof.
The example's last-known policy ends five minutes from collection start or at
an earlier observed expiry; successful notifications alone cannot reset it.

Console input/operation and worker lifecycle budgets are 30 seconds. Web startup,
collections and individual requests have 30-second budgets. Ctrl+C propagates
cancellation. Worker `stop` cancels/drains outstanding work; EOF drains accepted
work. Web `stop` or EOF stops intake and drains collections, requests and retired
clients. Host/retirement waits use separate five-second budgets. Timeout is
failure, never proof of drain: web retains and awaits owned cleanup even after
its bounded waiter expires, so a misbehaving dependency can delay exit.
Do not dispose a shared client under an outstanding request lease.

## Interpret outcomes and recover

| Observation | Operator/application action |
| --- | --- |
| `invalid` | Correct explicit input/mode; do not substitute an origin, principal or scope |
| `absent`, `denied`, `expired`, `unavailable` | Stop dependent work; inspect authorized provider/policy evidence and the selected input |
| `applied` | Mutation acknowledged; application validation/activation is still separate |
| `pending` (console exit 3) | Await separately authorized approval/effect observation; do not treat submission as activation |
| `unknown` or `PossiblyDispatched` receipt evidence | Preserve the receipt and reconcile under explicit authority; do not replay a mutation to discover its effect |
| `recovery-required` | Stop/drain; obtain an authorized replacement credential strategy and start a new selected lifecycle |
| `cancelled` (exit 5) | Stop dependent work; cancellation after dispatch does not undo a mutation or establish non-application |
| Shutdown/drain timeout | Record failure, retain cleanup ownership, and investigate outstanding work; do not report graceful stop |

Console exits are 0 success/help/applied, 2 invalid, 3 pending, 4 failure or
uncertainty, and 5 cancellation. Worker additionally has exit 6 for shutdown
timeout. Web HTTP work may return 503 unavailable, 502 downstream/unavailable,
or 504 for its operation deadline when the caller is still connected; unsupported
routes/methods return 404. Readiness and liveness have different meanings.

The SDK never repairs a selected principal, resurrects a lost token, infers a
periodic policy, persists a credential checkpoint, or replays an unknown write.
Readback can show resulting state without proving which concurrent writer
authored it. Unknown effects do not authorize broad cleanup. Applications own
durable recovery decisions, permissions, operator approval and replacement.

`Reveal`, configuration export and explicit downstream Bearer headers create
ordinary managed strings. SDK buffer disposal does not erase those strings,
JSON inputs, host logs, configuration debug views or downstream copies.
Review host-created plaintext and telemetry separately from SDK omission.

## Reproduce controlled measurements

The nonpackable [workload source](../../samples/Infisical.Demos/Measurements.cs)
is linked only into a generated standalone consumer by
[DemoQualityTests](../../tests/SecretKit.Demo.Tests/DemoQualityTests.cs).
It does not enter the minimal console, worker or web graph, install a benchmark
package, contact a provider, or reference SDK source. The isolated consumer
uses exact Core, Infisical and Configuration packages and links only the two
application-owned generation/lease sources. Infisical is present to retain the
existing configuration-profile archive/graph verification; this workload calls
the Core/Configuration APIs and sample lifecycle, not the native adapter.

From the checkout, after the Demo.Tests build lease is available:

```sh
export SECRETKIT_DEMO_CANDIDATE_DIRECTORY="$PWD/artifacts/runtime-adoption-hardening/console-red-originals"
export SECRETKIT_DEMO_CANDIDATE_VERSION=0.1.0-preview.1
dotnet build tests/SecretKit.Demo.Tests/SecretKit.Demo.Tests.csproj -c Release --no-restore
dotnet tests/SecretKit.Demo.Tests/bin/Release/net10.0/SecretKit.Demo.Tests.dll \
  --treenode-filter '/*/*/DemoQualityTests/*' \
  --minimum-expected-tests 3 --zero-tests-policy strict
```

This explicitly selects the pre-P7 four originals, not a final candidate.
Every invocation generates fresh source-mapped configuration, cache, outputs
and locks under `artifacts/runtime-adoption-hardening/quality/`. The generated
consumer lock is restored again with `--locked-mode` and archive/source/cache
bindings are checked. Records bind source SHA-256, all four original archive
SHA-256 values, package version, SDK, runtime, OS, RID, GC mode and workload.

The fixed workload uses eight synthetic 256-byte ASCII values, 16 warmups and
128 repetitions per row: prepare/collect; refresh plus explicit eight-key
string export; 256 acquire/execute/release operations per lease batch;
handover while holding an old lease; event-barrier collection cancellation;
and prepare/activate/shutdown. Shutdown timing includes setup, not just disposal.
Records retain every elapsed tick and process-wide allocated-byte delta.
Async scheduling, JIT/tiering, GC and other process activity affect numbers.
They are observations, never pass/fail thresholds, percentile promises,
retained-heap measurements or comparisons with another SDK.

The deterministic state witness holds the original client across 64 replacements:
two clients remain after each replacement, releasing that lease leaves one,
and shutdown waits for its final lease before all 65 created clients are
disposed exactly once. Temporary construction can have three live clients.
Cancellation is triggered only after the reader's entered event and preserves
the prior snapshot generation. These owned-resource states, not GC timing or
numerical performance limits, prove plateau/release.

All measured time is **controlled in-process local overhead**. There is no HTTP
transport, TLS, DNS, provider latency, downstream business latency or native
performance claim in those rows.

### Observed local workload, 2026-10-24

One integrated quality run used SDK `10.0.302`, `.NET 10.0.10`, CachyOS
(`Environment.OSVersion`: `Unix 7.2.6.1`), `linux-x64`, 16 logical processors
and workstation GC. Its record is locally retained at
`artifacts/runtime-adoption-hardening/quality/a48186fe28e74f6c8100cd05d90aaf54/measurements.json`.
The workload/warmup/repetition definition is above; the table shows arithmetic
means of the 128 samples, not a latency guarantee:

| Workload row | Mean elapsed, microseconds | Mean process allocated bytes |
| --- | --- | --- |
| Preparation/collection | 10.194 | 15,624 |
| Refresh/eight-key export | 16.018 | 22,944 |
| 256 request leases/executions/releases | 105.186 | 65,536 |
| Handover with old lease held | 18.616 | 21,312.25 |
| Event-triggered collection cancellation | 24.730 | 18,848 |
| Preparation/activation/shutdown | 27.899 | 25,632 |

The state witness observed two live clients after each of 64 replacements,
one after the original lease released, and zero after final shutdown release:
65 created, 65 disposed, zero duplicate disposals, peak three during construction.
The held lease stayed coherent, shutdown remained pending under its final lease,
and cancelled collection preserved the prior snapshot generation.

All four originals came from the explicitly selected
`artifacts/runtime-adoption-hardening/console-red-originals` feed, version
`0.1.0-preview.1`. SHA-256 bindings (Hosting is selected/recorded, not installed
in the configuration measurement consumer):

```text
SecretKit.Core                       f5f0a40743764e43883a47e77b2ad73e6f5fee9b3595ec6c3b582a56d9e05a4a
SecretKit.Infisical                   50055cbaba73dcad93bbf664ceededf83481c863298b849423330edaed917ca8
SecretKit.Extensions.Configuration    7b377195b178c2401bc83f924e22d8f08216f2839223767c80c6f190b48f4005
SecretKit.Extensions.Hosting          2157fcbda9cc25d1d5a9af42cf73d0b115465dfcd290f84b73e266d0e80d2f36
```

Executed nonpackable source SHA-256 bindings:

```text
samples/Infisical.Demos/Measurements.cs                         7717ace6b074d7804600e62ef66c53d4cb918932983977eeb77af2b54b880793
samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs  2ef39ba323b03e51dad0e94a35fbc76ea8dcd0fbad43483a36e213dbedbfc855
samples/RuntimeConfiguration/RuntimeGenerationLease.cs         eb77043115c34dee483e95cac73707103b016800f0c2805a12338a2e0d8359be
```

This binds the async lease source including retained disposal completion.
It is a reproducible pre-P7 observation, not a freeze: changed inputs need a new
record. Three integrated `DemoQualityTests` cases passed (one measured lifecycle
workload and two compatibility evidence-recording cases); that count does not
turn failed publishes into compatible applications.

## Selected trim and Native AOT scope

The quality fixture also copies the actual console app and its explicit linked
input/output sources into two isolated exact-package installations. It generates
a RID/tool-pack lock in each copy, then restores locked and attempts Release
publish for Linux x64, self-contained trimming and Native AOT separately.
It retains full command output and exit codes in `compatibility.json`, including
failed analysis. It does not set `IsTrimmable`/`IsAotCompatible`, change
warnings-as-errors, suppress warnings, or regenerate the repository app lock.

Only a successful publish is followed by running that executable's help and
actual selected read against a controlled loopback server. An analysis/publish
failure is **not qualified**, not a skipped success. The evidence does not
qualify the worker, web, all SDK paths, Windows, other RIDs or native deployment.
P7 final-package/platform checks and separate native gates remain required.

### Observed Linux analysis, 2026-10-24

The selected pre-P7 originals were version `0.1.0-preview.1`; SDK `10.0.302`,
runtime `.NET 10.0.10`, CachyOS, `linux-x64`. Both generated profile restores
and their locked rechecks succeeded. These are application analyses, not
library qualification:

| Profile | Actual publish properties | Outcome |
| --- | --- | --- |
| Trimmed console | `-c Release -r linux-x64 --self-contained true -p:PublishTrimmed=true` | Exit 1: IL2026 at shared `DemoOutput.cs:11` for reflection-based `JsonSerializer.Serialize<TValue>` |
| Native AOT console | `-c Release -r linux-x64 --self-contained true -p:PublishAot=true` | Exit 1: IL2026 and IL3050 at the same serialization call |

Warnings-as-errors remained enabled. IL2026 reports unreferenced-code risk;
IL3050 reports dynamic-code requirements. Neither publish produced an executable,
so trimmed/AOT help and controlled-read runs were **not run**, not passed.
This first analysis blocker is not an exhaustive inventory of dependency/AOT
issues. Shared demo output is outside this measurement change's ownership;
no warning was hidden and no production compatibility flag was added.

The exact generated commands use `dotnet restore <copied-project>
--force-evaluate --configfile <fresh-config>` with the selected RID/publish
property, then the same restore with `--locked-mode`, then `dotnet publish
<copied-project> --no-restore` with the table's properties and a fresh output.
All three commands carry exact candidate, fresh cache/intermediate/binary paths
and disabled fallback folders from the existing installation fixture. Complete
arguments, archive/source hashes and diagnostics are retained in each generated
`compatibility.json`; the profile-generated lock hash is separate from the
copied source-lock input hash. No default-cache package substitution is allowed.

The corresponding final local profile records are:

```text
artifacts/runtime-adoption-hardening/quality/trim-d280f3934d2348998c97b7179c5a998b/compatibility.json
artifacts/runtime-adoption-hardening/quality/aot-f46417c8ed3c47b4ba4489085f68c8bd/compatibility.json
```

Future provider work follows the [provider admission decision](../internal/PROVIDER_ADMISSION.md):
demonstrated demand, official semantics, ownership/provenance and a native plan.
Authorized implementation and unavailable native qualification remain distinct.
