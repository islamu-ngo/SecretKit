# Runtime hardening evidence profile

`runtime-hardening` names a separate scenario/report contract. Original archives
still select package profile `infisical-runtime`. The existing S01-S16 protocol,
17-case functional acceptance and 21-case native denominator are unchanged.
Neither source admission nor a controlled installed result qualifies a deployment.

## Controlled installed consumer

The package-only consumer accepts exactly `runtime-hardening offline`. It runs
both `SafeDefault` and explicit `HostControlled` against the existing controlled
loopback exchange fixture. HTTP is admitted only as loopback development traffic;
these observations do not prove TLS, private trust or proxy behavior.

Each stdout line is a JSON object, not a human log. Successful observations have
`record: "SCENARIO"`, `schemaVersion: 1`, `profile: "runtime-hardening"`, `mode`,
`transport`, `id`, `status: "passed"`, `reason: "controlled-observed"` and
`nativeQualified: false`. The last line has `record: "REPORT"`, the same schema,
profile and mode, `packageProfile: "infisical-runtime"`,
`kind: "controlled-installed-offline"`, both `transports`, and
`nativeQualified: false`. Exit 0 requires both complete applicable case sets.
Failure exits 1 with fixed diagnostics; a partial stream is not a passing report.
No material, token hashes, provider coordinates or exception payloads are emitted.
Credential-free CI explicitly selects `RuntimeHardeningAdmissionTests` in
addition to the six existing local/renewal/rotation guard classes; it never
selects the native execution producer.

| Case | Required observation | Installed modes |
| --- | --- | --- |
| RH01 | Fresh explicit Universal login receipt and exact issued token handoff into a session and raw read | All |
| RH02 | Complete required configuration generation and first export | configuration, full |
| RH03 | Replacement publication, pinned old handle and failed-refresh retention | configuration, full |
| RH04 | Denied read and contradictory cross-scope response rejection | All |
| RH05 | Renewal receipt applied and replacement token acquired | All |
| RH06 | Dropped renewal response, retained uncertainty, recovery-required state, then explicit fresh login/session/read | All |
| RH07 | Session/client shutdown and bounded public timeout while a token-source cancellation callback is held; explicit release drains the operation without late material | All |
| RH08 | Both transport selections; borrowed host handler remains usable after SDK teardown | All |
| RH09 | Explicit Hosting start and bounded stop, ending the selected session | hosting, full |

Configuration and Hosting APIs compile only when those optional packages are
installed. Minimal mode does not claim configuration generations or Hosting
scheduling. All modes perform actual provider-adapter wire exchanges.
The shutdown timeout is itself the behavior under test; other sequencing uses
prearmed completion signals, not sleeps or polling.

`LocalInfisicalInstallTests.RuntimeHardeningInstallsFreshSelectedOriginals`
requires `SECRETKIT_RUNTIME_HARDENING_ORIGINALS` and
`SECRETKIT_RUNTIME_HARDENING_VERSION`. There is no historical archive fallback.
It reuses `LocalPackageCandidate` for original hashes, source-mapped restore,
isolated caches and exact minimal/configuration/hosting/full package closures,
verifies XML from each original archive, checks the emitted case sets and saves
`artifacts/runtime-hardening/<run>/runtime-hardening.json`.
Those records contain selected original hashes and installed package IDs.
Do not run this test until the parent has produced fresh post-T18 packages.
PR CI creates its explicit four-archive selection by byte-comparing copies from
the current seven-package build before the package suite. The separate local
qualification stage explicitly selects its own newly packed local originals.
Neither stage falls back to an existing archive directory when inputs are absent.

The explicit compile owner is
`tests/fixtures/SecretKit.InfisicalConsumer/SecretKit.InfisicalConsumer.csproj`;
it includes `RuntimeHardeningWorkflow.cs`. `LocalQualification.CaptureSource`
automatically includes the new source bytes in its content snapshot. No demo
source inventory is expanded by this unit. A downstream copied-file inventory,
if present outside these owners, must add this literal workflow path before use;
it is not authority to edit an unowned inventory here.

## Native selection and execution

`RuntimeHardeningProfile.Admit` parses strict camel-case JSON with no unknown or
duplicate properties. Required constructor fields cannot be omitted. The selection
contains:

- `schemaVersion: 1`, `profile: "runtime-hardening"`,
  `packageProfile: "infisical-runtime"` and
  `authority: "selected-runtime-read-login-renew"`.
- `binding.archives`: the existing `LocalNativeBinding` from
  `LocalProfileConformance.Freeze`, including exact profile, source-content,
  qualification-record and four original archive SHA-256 digests and version.
  `binding.sourceRevision` is the 40-character lowercase revision recorded by
  the checked original family. `sdk` and `runtime` are exact .NET 10 versions;
  `platform` must be `linux-x64`. The dirty source content hash remains necessary:
  a matching Git revision alone cannot identify hardening changes.
- `provider`: explicit `deployment`, exact `version`, and `edition`
  (`oss`, `enterprise` or `cloud`). These are host-selected facts, not a server
  probe or a guess from an older qualification.
- `policy`: `lifetime` (`finite` or `periodic`), positive `ttlSeconds`,
  `maximumTtlSeconds`, nullable `periodSeconds`, `useLimit: 0`,
  `renewBeforeSeconds`, `requestTimeoutSeconds`, `evidence`
  (`declared` or `provider-observed`) and `evidenceSha256`. Finite policy requires
  no period and a maximum at least its TTL; periodic policy requires an exact
  positive period equal to TTL. Renewal margin must be inside the TTL and
  request timeout must be 1-60 seconds. The evidence digest is the deterministic
  policy projection below, never a token fingerprint or an arbitrary evidence label.
- `network`: fixed HTTPS `origin`, `mode` (`SafeDefault`,
  `SafeWithPrivateTrust` or `HostControlled`), `tls: "hostname-validity-chain"`,
  `proxy` (`none` or `explicit`), nullable `proxyEvidenceSha256`,
  `privateRootsSha256` and `hostPipelineSha256`. Explicit proxy requires its
  evidence digest; private trust requires its public-root-set digest;
  HostControlled requires its host pipeline digest. Contradictory mode-specific
  fields reject. This targeted native profile deliberately requires an explicitly
  selected validating host pipeline; the SDK's general HostControlled API can
  support weaker policies, and the SDK cannot enforce inside that pipeline.

### Protected execution input

The producer additionally admits a separate strict JSON input file. Its fields
are defined by `RuntimeHardeningInput`:

| Field | Required selection |
| --- | --- |
| `schemaVersion`, `profile` | `1`, `runtime-hardening` |
| `selectionSha256` | SHA-256 of the admitted selection serialized with `NativeWorkflow.JsonOptions`, in the record declaration order; binds all frozen archives, source/record, runtime, policy and network facts |
| `authority`, `readAuthority` | `selected-runtime-read-login-renew`, `owned-read-fixtures` |
| `bootstrap` | `identityId` UUID, explicit `clientId`, fresh `clientSecret` |
| `recoveryBootstrap` | Separately supplied `identityId`, `clientId`, `clientSecret`; identity/client must equal bootstrap, secret must differ |
| `allowedReads` | Two through eight distinct required coordinates, each with `projectId` UUID, `environment`, `folder`, `key` |
| `deniedRead` | A separately owned denied coordinate, different from every allowed coordinate |
| `crossScopeRead` | An owned denied coordinate whose project/environment/folder differs from every allowed scope; distinct from `deniedRead` |
| `acknowledgeManagedStringExport` | `true`; JSON parsing, authentication headers and Configuration export create ordinary managed strings |
| `acknowledgeResponseLoss` | `true`; authorizes discarding one actual successful renewal response, not replaying that mutation |
| `publicRootsDer` | Array of base64 public DER certificates for `SafeWithPrivateTrust`, otherwise empty; never private keys |
| `proxyUri` | Explicit public proxy URI when selected, otherwise null; no credentials, query or fragment |
| `responseLossPipelineSha256` | Digest of the concrete validating host pipeline described below, required for every selected transport mode |
| `deadlineSeconds` | 60-1800 seconds, at least twice TTL plus 60; includes producer installation/execution. TTL must exceed four request timeouts |

Environment/key/folder segments use ASCII letters, digits, underscore and hyphen.
Folders are `/` or slash-separated segments, without traversal or empty segments.
This fixture intentionally supports only unauthenticated explicit proxies.
Bootstrap strings cannot contain whitespace/control characters. There is no
setup/admin/supplied-token field, alternate identity or inferred recovery secret.
Both input files use the existing protected-file reader: absolute regular paths,
no links, at most 131072 bytes and owner-only Unix read/write permissions.

### Same-principal policy observation

The installed SDK performs a fresh Universal login with a caller-held receipt.
Only that newly issued token can authorize the bounded same-origin GET:

```text
/api/v1/auth/universal-auth/identities/{selected identityId}
```

The route and response members come from the target's
`IdentityAuthenticationOperations.GetUniversalAuth` and
`IdentityAuthenticationConfiguration`, not vendor implementation code.
The response must contain `identityUniversalAuth` with returned `identityId` and
`clientId` matching the bootstrap used for this login. `accessTokenTTL`,
`accessTokenMaxTTL`, `accessTokenNumUsesLimit`, and `accessTokenPeriod` must all
be present integral JSON numbers and equal the admitted policy. An omitted
period is not inferred as zero. A finite policy requires actual period zero;
a periodic policy requires its actual positive period. Login-reported TTL/maxTTL
must also agree. The same observation is repeated with the recovery login.

`policyObservationSha256` is lowercase SHA-256 of this UTF-8 projection, with
decimal invariant integers, LF separators, and a final LF:

```text
runtime-hardening-universal-policy-v1
{returned accessTokenTTL}
{returned accessTokenMaxTTL}
{returned accessTokenNumUsesLimit}
{returned accessTokenPeriod}
```

Identity/client correspondence is checked before projection; protected identifiers
are not written into reports. The host independently recomputes the projection
from reported numeric observations. The selected digest is compared, never copied
as observed proof. Missing observation rights, contradictory policy or unreadable
configuration leave qualification unavailable. No admin fallback, JWT decoding
or token introspection is attempted. `declared` policy cannot pass acceptance.
Provider deployment/version/edition remain explicitly host-selected metadata;
there is no invented server health/version introspection.

### Network configuration binding

Main login, reads, generation collection, renewal and recovery use the selected
SDK `SafeDefault`, `SafeWithPrivateTrust` or known `HostControlled` transport.
Safe transports use the SDK's implementation, including private trust selection.
No TLS callback bypass is installed. The separate fixed policy GET and
response-loss trial use a host-owned validating pipeline with the same explicit
proxy/public roots. No ambient proxy, proxy credentials, redirects, cookies,
activity-header propagation or application retry handler is enabled.
Connection lifetime is 120 seconds; connection/header deadlines use the admitted
request timeout. Body reads are bounded and caller-deadlined.

The public proxy digest is SHA-256 of UTF-8
`runtime-hardening-proxy-v1\n` + canonical `Uri.AbsoluteUri` + `\n`.
The public-root digest is SHA-256 of UTF-8 `runtime-hardening-roots-v1\n`,
followed by ordinal-sorted lowercase SHA-256 hashes of each exact DER certificate,
one per line with a final LF. Duplicate roots and non-certificate input reject.
Private roots replace system roots and retain normal chain/hostname/validity
validation with the handler's `NoCheck` revocation setting.

The concrete host-pipeline digest is lowercase SHA-256 over these UTF-8 lines,
each followed by LF:

1. `runtime-hardening-validating-pipeline-v1`
2. Canonical selected origin (`Uri.AbsoluteUri`).
3. Selected proxy digest, or `none`.
4. Selected private-root digest, or `system`.
5. Request timeout seconds, invariant decimal.
6. `no-redirects;no-cookies;no-ambient-proxy;no-propagation;no-retry;pool-120;chain-hostname-validity;revocation-nocheck;fixed-routes;drop-one-successful-renewal`
7. Selected bootstrap identity UUID.
8. For each allowed read in input order, then denied read, then cross-scope read:
   project UUID, environment, folder and key, each on its own line.

`responseLossPipelineSha256` must equal that computed digest. For HostControlled,
`network.hostPipelineSha256` must equal it too. Compute these first, then compute
the final selection digest. No credential, secret value or token hash enters
these projections. The pipeline only admits the fixed login/renewal routes,
the own-identity GET and the exact selected raw-read queries. This restriction
belongs to this host fixture, not to arbitrary SDK HostControlled transports.

### Producer invocation and evidence

After separate native authorization, select only this class from the SecretKit
root; this command is not part of offline CI:

```bash
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll \
  --treenode-filter '/*/*/RuntimeHardeningProfileTests/*' \
  --minimum-expected-tests 1 --zero-tests-policy strict
```

Required environment variables contain authority or paths only:

- `SECRETKIT_LOCAL_SOURCE`, `SECRETKIT_LOCAL_ORIGINALS`,
  `SECRETKIT_LOCAL_RECORD`: absolute paths to current source, the original
  four-package selection, and its checked qualification record directory.
- `SECRETKIT_RUNTIME_HARDENING_AUTHORITY=selected-runtime-read-login-renew`.
- `SECRETKIT_RUNTIME_HARDENING_SELECTION`: protected selection JSON path.
- `SECRETKIT_RUNTIME_HARDENING_INPUT`: protected execution input JSON path.
- `SECRETKIT_RUNTIME_HARDENING_REPORT`: a new absolute output path in an existing
  owned directory. An existing report is rejected, never imported as success.

`SelectedNativeExecutionProducesFreshBoundRuntimeObservations` freezes current
original archives, source content and record bytes; checks actual `dotnet --version`,
.NET 10 runtime and Linux x64; admits both files; creates a fresh run nonce; and
persists a complete unavailable RH01-RH09 report before installation or dispatch.
It calls `LocalProfileConformance.InstallAsync` to restore/build the actual
`full` package-only consumer using isolated caches and original-archive checks.
The child command is `dotnet <installed-consumer.dll> runtime-hardening native
<new-child-report-path>`. Minimal/configuration/hosting modes reject this native
route before reading stdin; their existing controlled routes remain available.

The producer sends one bounded JSON envelope over stdin, then closes it:
`schemaVersion`, `profile`, producer-generated `runId`, admitted `selection`,
and admitted `input`. No protected value enters process arguments, environment
or logs. The child's environment is cleared except PATH/HOME/DOTNET_ROOT, and
runtime diagnostics are disabled. The child re-admits the envelope, archive
family metadata and actual runtime before dispatch. The host rechecks source,
record and original hashes after execution, including failure paths.

The native sequence observes RH01 login/token/raw read; RH02 all-required
generation/export; RH03 a second actual collection and local replacement,
old pinned-handle usability and deliberately local failed-refresh retention;
RH04 actual denied and cross-scope reads; RH05 real renewal and usable renewed
token; RH06 a separate session copying only that real renewed token, loss of one
validated successful renewal response, recovery-required uncertainty, then
explicit separate fresh recovery login/read; RH09 explicit Hosting start/stop;
RH07 bounded shutdown with a held caller token-source callback and release/drain;
and RH08 host-owned pipeline usability after SDK teardown. Local replacement
does not require remote value changes. RH04 requires actual Denied outcomes;
absence, transport failure or fabricated scope mismatch is not native refusal.
Native renewal waits target the real session renewal deadline once, bounded by
the run deadline, without fixed sleeps or polling. RH07 uses prearmed signals.

Each successful case emits material-free JSON `SCENARIO` with the schema,
profile, `runId`, case ID, `status: passed`, and `reason: observed`.
The final `REPORT` has `schemaVersion: 1`, `record: REPORT`,
`profile: runtime-hardening`, `kind: native-observation-not-public-approval`,
`selectionSha256`, `runId`, `freshLoginRun`, `causalTokenHandoffRun`,
`policyObservationSha256`, numeric `observedPolicy`, `executionCompleted`,
and exactly RH01-RH09 in `cases`. It contains no origin, coordinates,
credentials or secret values. The report's two login fields must equal the
fresh producer run; completion is set only after execution and owned cleanup
return. All nine cases must pass, observed policy must match the selected
provider-observed policy, and the source freeze must remain unchanged.
The material-free `loginEvidence`, `renewalEvidence`, `lossEvidence` and
`recoveryLoginEvidence` fields retain fixed dispatch states even when the
corresponding operation fails. `responseLossObserved` and
`recoveryRequiredObserved` are persisted before recovery begins;
`recoveryReadObserved` records its actual usable read. A rejected recovery
therefore cannot erase the prior real renewal uncertainty or qualify RH06.

The child atomically replaces its report after each observation; the host
retains validated partial evidence even on launch, timeout or child failure.
Failed/unfinished runs cannot set successful completion. Stdout is a bounded
protocol and stderr is discarded by the parent; failures expose fixed markers,
never exception payloads. Reports are consistency evidence from this trusted
producer, not signatures or independent token/principal attestation.

Provisioning, remote secret writes, database operations, admin fallback,
credential revocation and publication are outside this workflow.

## Verification boundary

The independently runnable offline slice is `RuntimeHardeningAdmissionTests`.
Build only the conformance project with `--no-restore
-p:BuildProjectReferences=false`, then select that class with the TUnit tree-node
filter and strict positive test count. Do not run the broad conformance suite.
Compilation against parent-supplied fresh archives is a separate package API
check, not native execution. Final controlled/manual runs, fresh source/record
freeze, actual native authority and protected inputs, deployment/policy/network
observations, and independent final review remain external gates. Source admission
tests establish none of Windows, AOT, Event, production readiness or native parity.
