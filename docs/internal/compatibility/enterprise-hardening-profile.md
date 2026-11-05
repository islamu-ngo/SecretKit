# Enterprise hardening evidence profile

> **Audience:** Qualification maintainers, operators and evidence reviewers
> **Status:** Supplemental declaration, content checks and scoped Infisical owner admission; native qualification remains open
> **Owner:** SecretKit qualification maintainers
> **Last verified:** 2026-11-05, local contract/schema inspection; no provider execution
> **Source anchors:** [profile](enterprise-hardening-profile.json), [schema](enterprise-hardening-profile.schema.json), [ADR-005](../adr/ADR-005-enterprise-hardening-contracts.md)

`enterprise-hardening` is a separate supplemental evidence namespace. Its
`S01` is not local-profile `S01`. Always identify a case by profile plus scenario
ID. This declaration grants no runtime qualification, provider authority or
publication. It does not loosen any response validator or admit arbitrary JSON,
URLs, KQL or cloud profiles.

The existing local S01-S16 protocol, 17-case development-functional, 21-case
full-native, integration-quality and RH01-RH09 denominators remain unchanged.
No supplemental pass replaces a missing historical case. The profile is not a
new package selection: exact four-package local modes and the seven-package
family keep their existing ownership and artifact contracts.

## Scenario contract

The ordered `scenarioIds` are exactly S01-S28 from the approved enterprise
hardening behavioral contract. The table summarizes each requirement; none of
these rows is an execution result. Source/offline proof is required for each
implemented scenario. Installed, artifact, native and platform proof remains
separate and applies to the selected behavior and claim.

| ID | Required behavior / evidence focus |
| --- | --- |
| S01 | One management deadline across credentials, construction, send and body, without stage resets |
| S02 | Caller cancellation propagates; post-dispatch uncertainty and genuine known evidence survive late-result disposal without replay |
| S03 | Encoded execution overflow rejects before credentials/send; factory capacity stays separate |
| S04 | Rotation disposal closes new admission before credentials; previously admitted work may settle without a drain/reversal claim |
| S05 | Original Azure status failures cannot invent remote terminal states; unresolved operations permit later explicit checks |
| S06 | Native terminal evidence is independent of final-value validation; HasCompleted alone is insufficient; original handles and bounded observations remain |
| S07 | Coordinator applies selected collection controls through validation and collection; superseded candidates cannot activate |
| S08 | Hosting applies provider origin policy without credentials/network I/O; malformed/unsafe origins and incompatible proxies fail |
| S09 | Reload retains the existing principal; replacement is deliberate/keyed with retirement; validation is not permission proof |
| S10 | Azure common/native reads and inventory reject malformed/contradictory coordinates before publication |
| S11 | Equivalent Azure failures classify consistently, preserving mutation uncertainty above ordinary classification |
| S12 | Eligible 429/503 delta/date advice is clamped to 0..24 hours; malformed advice is omitted and never causes replay |
| S13 | Native numeric tokens remain exact; checked integral/decimal conversion rejects precision/range loss; per-field presence/null/sign rules remain |
| S14 | Completed trace interval uses captured start/end and caller parent, excluding observer callback time; completion-time export is explicit |
| S15 | Cancellation, shutdown, deadline and dependency termination remain distinct diagnostically without changing public cancellation/receipts |
| S16 | Throwing/reentrant listeners preserve results, ownership and ambient context; callbacks occur outside locks after ownership release; no arbitrary baggage or listener deadline promise |
| S17 | SDK diagnostics contain only documented closed categories/numeric measurements, without protected data or exception prose; host instrumentation remains separate |
| S18 | Source-only lanes require no candidate; post-pack first verifies complete artifacts; every solution host has an owner and positive discovery |
| S19 | Local selectors follow the local profile version; public candidate proposal stays separately bound |
| S20 | Missing/substituted archives, symbols, source/run/SDK or rebuild bindings fail; consumers cannot repack/rewrite producer records |
| S21 | Any required source/package/demo/platform/advisory failure blocks assembly/upload; formatting changes preserve workflow policy |
| S22 | Missing/unavailable/mismatched/expired/unowned advisory clearance fails; lock consistency is not clearance |
| S23 | Unadmitted closed native shapes retain rejection/uncertainty; profile metadata cannot broaden response acceptance |
| S24 | Source/offline/installed/native/platform/publication claims stay separately bound; historical denominators remain unchanged |
| S25 | Reuse accepted snapshot/client generations with coherent leases and explicit freshness/expiry, without per-operation provider reads or hidden cache |
| S26 | Inventory refresh changes only allowed source path/digest projections; missing/foreign/symlinked sources and altered members/denominators fail independent checks |
| S27 | Relative budgets follow monotonic elapsed time despite UTC jumps; expiry/date advice retain UTC semantics and caller cancellation precedence |
| S28 | Queued/late Azure status cancellation cannot return local success or reset another caller's state; genuine native evidence remains monotonic without new dispatch |

## Machine contract

The profile validates against the schema root. It is always
`kind: "supplemental-declaration"` and `nativeQualified: false`; it contains no
observations, credentials or fabricated current archive hashes. Gate entries
describe unmet prerequisites and revisit triggers, not successful checks.

The same schema's `#/$defs/observation` defines the proposed per-observation
envelope for executable admission. It requires `schemaVersion: 1`,
`profile: "enterprise-hardening"`, `kind`, nonempty unique `scenarioIds`,
`status` (`passed`, `failed`, `unavailable`), `nativeQualified` and `binding`.
Kinds and required additional bindings for passing observations are:

| Kind | Additional required binding fields | Scope |
| --- | --- | --- |
| `source-offline` | None beyond common fields | Deterministic source test/inspection evidence; no installed/native claim |
| `controlled-installed-offline` | `archives`, `cohortSha256`, `transportSha256` | Actual installed adapter/application execution under controlled transport |
| `artifact-integrity` | `archives`, `cohortSha256` | Original archives, symbols, independent rebuild and producer/consumer integrity |
| `native-observation` | `archives`, `cohortSha256`, `transportSha256`, `deploymentSha256`, `principalSha256`, `policySha256`, `effectSha256`, `authorizationSha256` | Authorized provider effects and original-operation evidence for named cases only |
| `platform-observation` | `archives`, `cohortSha256` | Actual selected OS/architecture/SDK/runtime job and installed results |
| `connected-advisory` | `graphSha256` | Actual connected native audit/report and exact disposition |
| `publication-authorization` | `archives`, `cohortSha256`, `authorizationSha256` | Separate actual publisher authority; not publication or native proof by itself |

Common binding fields are `profileSha256`, `sourceRevision`,
`sourceContentSha256`, `runId`, `sdk`, `runtime`, `platform`, `evidenceSha256`.
SHA-256 strings are lowercase 64-hex; revision is lowercase 40-hex. `runId`,
SDK/runtime/platform and package/version labels are bounded to 128 ASCII
letters/digits/dot/underscore/hyphen. Record exact executed SDK/runtime versions
and OS/architecture, not family labels such as `.NET 10` or `Linux`.
`archives` contains 1..7 entries of `packageId`, `version`, `sha256`.

Bindings identify exact original bytes. `profileSha256` hashes the raw tracked
profile bytes; `sourceContentSha256` uses the existing complete source-content
projection, not Git revision alone; `cohortSha256` identifies the immutable
producer record. `evidenceSha256` hashes the separate observed evidence artifact,
not its containing envelope. Native deployment/version/edition/cloud/endpoints,
identity role selection, effective policy observations, transport/TLS/proxy/
private-trust facts, effect witnesses and authority must be retained in their
separately admitted records; digests reference those records, never tokens,
credentials, secret values or their fingerprints. Public records contain no
protected coordinates. A digest asserts no truth by itself.

Every object is closed. Missing fields, wrong casing, unknown fields, duplicate
JSON properties and duplicate scenario/package identities must reject. JSON
Schema constrains shape; duplicate-property detection, unique package IDs,
safe regular-file resolution, byte/depth bounds and semantic joins belong to
the executable reader. Follow the existing 131072-byte/depth-16 native
admission convention; reject links, traversal and foreign roots. Resolve the
existing source/cohort projections rather than introducing a second hash recipe.

For non-native kinds and failed/unavailable observations, `nativeQualified`
must be false. A passing `native-observation` may request true only after the
executable verifier has independently validated every binding and actual effect.
Schema validity alone never makes that assertion admissible.
Failed/unavailable envelopes require the common bindings but may omit additional
bindings that were not obtained. Missing authority or effects must remain
missing, never filled with a synthetic digest to manufacture a passing shape.

## Executable admission handoff

The bounded Release reader validates declarations and independently selected
content bindings. Run its source-only content check with explicit inputs:

```sh
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll enterprise-hardening-check "$PWD" "/absolute/selection.json" "/absolute/observation.json"
```

Append the exact prepared cohort directory for installed/artifact selections.
Zero means `enterprise-content-consistent-not-qualified`; it grants no native,
platform or publication qualification. This reader cannot import native authority
from a report. An older runtime profile accepting its own report does not supply
the required enterprise principal/policy/effect custody.

The existing owned Infisical producer has a separate in-process admission path
for **enterprise S24 only**. It retains causal identity/configuration readback,
allowed and denied policy challenges, the installed child's applied effects,
the exact report and completed cleanup. Its private certificate belongs to that
owner and run; a reconstructed object or matching digest cannot replace it.
Actual sandbox inspection and the real installed producer's private enrollment
are additionally required for `native-owner-observation`. Controlled fixtures
return `controlled-owner-observation` and remain non-native.

The selected deployment is the existing pinned IPv4 loopback HTTP sandbox,
including its actual host-controlled transport and default proxy behavior.
It does not qualify HTTPS, private CAs, another deployment or other scenarios.
All historical case and trial denominators remain unchanged. The producer
rechecks source, original archives, complete cohort and profile bytes after
execution. See [owner admission](../../../tests/SecretKit.Infisical.Conformance.Tests/Hardening/EnterpriseHardeningNativeProof.cs)
and [producer](../../../tests/SecretKit.Infisical.Conformance.Tests/Qualification/LocalProfileConformance.cs).

After separately obtaining the existing owned-local native authority and
protected inputs, set `SECRETKIT_ENTERPRISE_HARDENING_COHORT` to the absolute
prepared cohort directory and select only
`/*/*/LocalProfileConformanceTests/InstalledOwnedLocalProfileHasEveryNativeObservation`.
That existing native parent retains its 21 cases, six supplemental trials and
cleanup requirements. Missing authority remains a failure; no native execution
is established by this documentation or by the controlled fixtures. The typed
owner result is not portable report authority.

Azure positive enterprise admission remains an implementation/design gap in
addition to missing G2 execution inputs. Existing original-operation registries
retain genuine handles, receipts and resource witnesses, but supplied credentials,
transport object identities and declared expiry do not establish authenticated
principal, effective policy, native network or installed-cohort provenance.
Those observations must be joined by a concrete authorized producer before
Azure native admission can succeed. Token inspection, declarations or another
wrapper around an existing settlement cannot supply that missing connection.

`installedModes` declares the four local modes and seven-package subset.
Complete post-pack execution requires all five exclusive reports, exact scenario
sets and successful subsets, current cohort digest, SDK/run/attempt, and the
actual executing runtime/platform. The separate platform record must match all
seven original archive hashes. These controlled results are not cross-platform
or native qualification. The executable owner must:

1. Verify exact profile/scenario/kind sets and required selected coverage.
   Source-only scenarios cannot replace installed execution. C24's appropriate
   four-mode and seven-package cases cover runtime changes; S18-S21/S24/S26 also
   require artifact/runner evidence. S22 requires connected advisory evidence.
2. Join profile/source/cohort/archive hashes, SDK/runtime/platform and run IDs
   against independently loaded expected originals. Reject old, swapped,
   missing, duplicate or fabricated records. Preserve producer bytes and separate
   host-local platform observations; a schema does not enforce immutability.
3. For each selected native case, verify fresh authorized deployment/version,
   selected runtime/admin/observer principals and observed policy, transport and
   independent effects. Declarations, token inspection and administration
   visibility are not same-principal or intended-delivery proof.
4. Preserve original operation handles, caller-held receipts and causal
   attribution for mutation/status trials. Generic Boolean evidence flags or a
   fresh operation cannot replace original terminal/resource/exclusion proof.
5. Report missing G1/G2 bindings as unavailable/unqualified, never native pass
   or a skipped successful gate. Keep native/provider/platform/publication
   claims separate. Each provider's existing native cases and selected hardening
   supplements remain required; no universal native pass over all 28 is inferred.

Existing conventions: [RuntimeHardeningProfile](../../../tests/SecretKit.Infisical.Conformance.Tests/Qualification/RuntimeHardeningProfile.cs)
(`Admit`, `Same`, `Accepts`, `ValidateProduced`) separates expected archive/source/
runtime bindings from causal login/policy/effect observations;
[its producer](../../../tests/SecretKit.Infisical.Conformance.Tests/Qualification/RuntimeHardeningProfileTests.cs)
freezes originals, retains an unavailable report before execution, and rechecks
binding after execution. These are reference seams, not an automatic mapping
from RH cases to this supplemental namespace.
[The runtime profile guide](runtime-hardening-profile.md) retains the existing
protected input and native selection rules.

The executable offline lane retains all existing guard selections and includes
`/*/*/EnterpriseHardeningAdmissionTests/*` with positive minimum 1 and strict
zero policy. Native producer tests must never be selected indiscriminately as
offline checks.

## External gates and recovery

The profile's G1-G5 entries retain the approved owners and triggers:

| Gate | Required action / consequence |
| --- | --- |
| G1 | Provider qualification maintainer/operator supplies authorized Infisical deployment/version, principal/policy and entitlement bindings through protected inputs; actual native effects remain required |
| G2 | Azure qualification owner supplies explicitly scoped subscription/vault/runtime/admin/observer sandbox authority; controlled tests do not qualify Azure effects |
| G3 | Release maintainer obtains actual required Ubuntu/Windows jobs against exact inputs; Linux workstation evidence cannot close this gate |
| G4 | Architecture maintainer revisits sovereign clouds, AOT or second hosting only on named consumer demand with accepted maintenance ownership; these are not unfinished implementations |
| G5 | Security/release maintainers obtain connected native audit/report success and exact current disposition; unavailable data fails clearance and an exception cannot waive native failure |

No supplied environment authority, native effects, CI results, advisory clearance
or publisher rights are asserted by this declaration. Missing authority leaves
native qualification open while offline authoring continues. On an inaccurate
claim, correct it while preserving dated evidence and its original inputs.
For uncertain mutations retain receipts and original-operation evidence; require
a new explicit authorized recovery decision instead of automatic replay.
See [support boundaries](../../public/provider-support.md),
[operations](../../public/operations-and-compatibility.md) and
[expansion follow-ups](../INTEGRATION_QUALITY_FOLLOW_UPS.md).
