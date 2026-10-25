# Evaluate Infisical through local packages

> **Audience:** .NET application developers and SDK maintainers
> **Status:** Offline local qualification commands implemented; installed/native qualification remains separate
> **Decision date:** 2026-10-23
> **Source anchors:** [current preview](current-preview.md), [scope](scope-and-orchestration.md), [local readiness contract](../internal/INFISICAL_LOCAL_READINESS.md)

**In development. Not ready for production. APIs may change without backward
compatibility.** Neither listed nor unlisted NuGet publication is part of this
workflow. Local installation, selected-deployment functional acceptance and full
native qualification are three different milestones.

SecretKit's immediate goal is reusable Infisical access through local NuGet
packages. Public NuGet publication is not required to evaluate the library or to
prepare an application integration. This goal does not claim that an Event
integration has been implemented or verified.

## Choose the boundary, not the entire repository

SecretKit is **in development, not ready for production**. The next
[runtime adoption increment](../internal/RUNTIME_ADOPTION_SECURITY.md) plans
independent installed console, worker and web applications with security and
recovery evidence. Those requirements do not imply the apps or native profile
are already qualified.

| Package | Application evaluation role |
| --- | --- |
| `SecretKit.Core` | Required common contracts and opaque owned secret material |
| `SecretKit.Infisical` | Required typed Infisical provider access |
| `SecretKit.Extensions.Configuration` | Optional prepared generations and explicit plaintext configuration export |
| `SecretKit.Extensions.Hosting` | Optional explicitly started authentication maintenance and health |

Azure and management packages remain separate existing work. Applications do not
need them for ordinary Infisical reads and selected value writes. No umbrella
package, database driver, UI, Event model, or Configurator runtime is required.
The four-package qualification profile does not mean every application
must install all four packages.

## Build and verify one immutable local candidate

Run from the SecretKit root with the SDK pinned in `global.json`. Use a fresh,
empty output directory for each candidate; do not mix package versions or
overwrite an earlier candidate. These commands build the current seven-package
solution because existing package witnesses still require that complete family.

Finish source, notices and documentation changes first. Run these commands
sequentially; the conformance project shares build outputs with the solution.
Every build uses the same candidate version, and the final solution build
precedes packing. Do not reuse an existing output for different bytes.

```bash
set -eu
version=0.1.0-local.20261024.1
candidate="$PWD/artifacts/local-infisical-adoption/candidate-1"
test ! -e "$candidate"
dotnet restore SecretKit.slnx --locked-mode
dotnet restore tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --locked-mode
dotnet build tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj --configuration Release --no-restore -p:Version="$version"
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileAdmissionTests/*' --minimum-expected-tests 58 --zero-tests-policy strict
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileFunctionalAdmissionTests/*' --minimum-expected-tests 1 --zero-tests-policy strict
dotnet tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll --treenode-filter '/*/*/LocalProfileUpdateWitnessTests/*' --minimum-expected-tests 2 --zero-tests-policy strict
dotnet build SecretKit.slnx --configuration Release --no-restore -p:Version="$version"
dotnet format SecretKit.slnx --verify-no-changes --no-restore --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --no-restore -p:Version="$version" --output "$candidate/packages"
mkdir -p "$candidate/originals" "$candidate/installations"
for id in SecretKit.Core SecretKit.Infisical SecretKit.Extensions.Configuration SecretKit.Extensions.Hosting; do
  cp "$candidate/packages/$id.$version.nupkg" "$candidate/originals/"
done
dotnet run --project tools/SecretKit.Release --configuration Release --no-build -- local-prepare "$PWD" "$candidate/originals" "$candidate/qualification"
SECRETKIT_CANDIDATE_DIRECTORY="$candidate/packages" \
SECRETKIT_CANDIDATE_VERSION="$version" \
SECRETKIT_LOCAL_CANDIDATE_DIRECTORY="$candidate/originals" \
SECRETKIT_LOCAL_CANDIDATE_VERSION="$version" \
SECRETKIT_LOCAL_QUALIFICATION_DIRECTORY="$candidate/qualification" \
SECRETKIT_LOCAL_INSTALL_REPORTS="$candidate/installations" \
SECRETKIT_LOCAL_HANDOFF_DIRECTORY="$candidate/handoff" \
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet run --project samples/RuntimeConfiguration --configuration Release --no-build
dotnet run --project samples/ProviderAssessment --configuration Release --no-build
dotnet run --project tools/SecretKit.Release --configuration Release --no-build -- local-check "$PWD" "$candidate/originals" "$candidate/qualification"
```

The full solution run includes the original four installed modes and the separate
portable-bundle test. Do not repeat the latter against the same retained output:
it deliberately rejects an existing destination. Dependency advisory review is
separate: `dotnet package list --project SecretKit.slnx --include-transitive --vulnerable --no-restore`.

Packing is local file creation, not publication. The package tests include
package-only consumers with fresh restore caches and original-archive hash
checks. They are not the application's acceptance suite. See
[package tests](../../tests/SecretKit.Package.Tests/) and the
[package consumer](../../tests/fixtures/SecretKit.PackageConsumer/).

In an independently owned consumer, configure a local folder feed and an exact
prerelease version using its own package-management conventions. Map
`SecretKit.*` to that feed and keep dependency sources explicit. Do not rely on
a previously populated global cache, floating versions, or SecretKit project
references as proof that the candidate packages install correctly.

## Freeze an offline local record

The nonpackable Release tool now has two independent commands. Neither reads
publisher/provider credentials, constructs a public release, opens a publication
journal, nor calls Infisical. The source-owned
[profile](../internal/local/infisical-runtime.json) fixes the four package IDs,
one exact version, eight runtime member signatures and S01-S16 as the required
scenario denominator. The native read is limited to `Raw IncludeImports=false`.
The scenario list declares required coverage; preparing a record does not mark
any scenario, installed consumer or native operation as passed.

Put only the four original unsigned `.nupkg` files in a dedicated directory.
Do not include symbol archives, Azure/management packages, nested directories,
or other files. Existing seven-package tests still use their own complete
candidate directory. The source-owned profile currently selects
`0.1.0-local.20261024.1`; this does not change the global/default version or public
candidate. Build that exact version and pack the four originals into a fresh,
previously absent directory separately from the default seven-pack originals:

```bash
local_version=0.1.0-local.20261024.1
dotnet build SecretKit.slnx --configuration Release --no-restore -p:Version="$local_version"
for package in SecretKit.Core SecretKit.Infisical SecretKit.Extensions.Configuration SecretKit.Extensions.Hosting; do
  dotnet pack "src/$package/$package.csproj" --configuration Release --no-build --no-restore \
    -p:Version="$local_version" -p:IncludeSymbols=false --output artifacts/infisical-originals
done
```

Do not mix these archives with an earlier version or default seven-package
candidate. The full solution build retains regression projects; the explicit
pack selection defines this independent four-package output. Then run:

```bash
dotnet build tools/SecretKit.Release/SecretKit.Release.csproj --configuration Release --no-restore
dotnet run --project tools/SecretKit.Release --configuration Release --no-build -- \
  local-prepare "$PWD" "$PWD/artifacts/infisical-originals" "$PWD/artifacts/infisical-record"
dotnet run --project tools/SecretKit.Release --configuration Release --no-build -- \
  local-check "$PWD" "$PWD/artifacts/infisical-originals" "$PWD/artifacts/infisical-record"
```

The three positional arguments are the source root, original archive directory,
and record directory. The output parent must already exist. Preparation requires
a previously absent record directory and writes only `local-qualification.json`;
it never overwrites earlier evidence. Success exits 0 and prints
`local-prepared-not-native-qualified` or
`local-content-consistent-not-native-qualified`. Invalid input exits 1 with a
bounded diagnostic, without paths or native response bodies.

Schema 1 / kind `local-qualification` binds the profile hash, version, original
archive hashes, nuspec source-commit label, exact source-content manifest and
observed runtime identifier, .NET version and operating-system description.
It accepts dirty source without a commit: HEAD is not used as source proof.
The source-content digest hashes the ordinal-path-sorted, camel-case indented
JSON array of `{file, sha256}` entries, including empty and untracked source
files. Paths are source-relative with `/` separators. Its explicit exclusions
are root `.git`, `artifacts`, `dev`, `.worktrees`, and every path segment named
`bin`, `obj` or `TestResults`. Do not place build inputs in those excluded locations. All other
files, including build configuration, lockfiles, profile, tests and docs, are
included. The record contains hashes and relative names, not file contents.

Both commands reject linked input directories/files, unsafe archive members,
unknown/duplicate JSON fields, altered member/scenario sets, mismatched versions,
bad hashes and wrong internal dependency closure. Checking reopens the original
archives and recomputes the complete source manifest; it does not trust an
unchanged record or a copied archive. Additions, deletions and mutations invalidate
the record. Package metadata and notices are inspected using the existing safe
archive/parser primitives.

This is offline consistency evidence, not a trusted build attestation: the
maintainer must produce the archives from the recorded source snapshot. Freeze
the source and original archives before installed/native qualification. Any
changed source/profile/archive hash invalidates exact-artifact native evidence;
repack and create a new record rather than editing old evidence. Installed
consumer scenarios and owned native evidence remain independent gates.

## Install only the selected profile

The nonpackable `SecretKit.InfisicalConsumer` fixture has four modes:
`minimal` (Core + Infisical), `configuration`, `hosting`, and `full`.
Each uses exact NuGet references, explicit compile inputs, an empty isolated
cache and local-feed source mapping. Archive digests and restored dependency
and framework references are checked before execution; Azure, management,
Event, database drivers and ASP.NET runtime dependencies are rejected.

After preparing the record above, run the installed cases against those
originals from the repository root:

```bash
SECRETKIT_LOCAL_CANDIDATE_DIRECTORY="$PWD/artifacts/infisical-originals" \
SECRETKIT_LOCAL_CANDIDATE_VERSION=0.1.0-local.20261024.1 \
SECRETKIT_LOCAL_QUALIFICATION_DIRECTORY="$PWD/artifacts/infisical-record" \
SECRETKIT_LOCAL_INSTALL_REPORTS="$PWD/artifacts/infisical-installations" \
dotnet tests/SecretKit.Package.Tests/bin/Release/net10.0/SecretKit.Package.Tests.dll \
  --treenode-filter '/*/*/LocalInfisicalInstallTests/*' \
  --minimum-expected-tests 25 --zero-tests-policy strict
```

Reports retain original/profile/source/record digests and the measured
installed scenario subsets. They explicitly leave native S15 unqualified.
The fixture runs real adapters against controlled loopback responses, not an
external deployment. `local-check` must still succeed for the same source and
originals after execution. Use a new report directory for every attempt.
The separate native protocol and its protected-input requirements are described
in [local native compatibility](../internal/compatibility/infisical-local-profile.md).

## Frozen app locks and CI verification inputs

Normal local final-candidate tests use the finalized source-owned
`samples/Infisical.{Console,Worker,Web}Demo/packages.lock.json` files unchanged.
Generate and review those locks from the selected staging originals before
freezing the local candidate. Final tests copy them into independent app
workspaces and restore with `--locked-mode`; they never regenerate source locks.

A later CI rebuild is a different artifact even when its package IDs and
versions match. The archives embed their Git commit and README/notices, so
historical local lock hashes cannot be substituted for rebuilt archive bytes.
The credential-free CI job therefore prepares a **temporary CI verification
bundle**, distinct from the immutable local candidate, before final app tests:

```bash
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll \
  local-demo-prepare . artifacts/local-originals artifacts/verification/local/qualification \
  artifacts/demo-inputs "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" 10.0.302
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll \
  local-demo-check . artifacts/demo-inputs \
  "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" 10.0.302
```

The fresh bundle contains exactly `originals/` (four byte-identical archives),
`qualification/local-qualification.json`, `locks/{console,worker,web}/packages.lock.json`
and `demo-inputs.json`. Preparation reuses `local-check`, checks the embedded
archive commits against the selected CI SHA, copies the actual apps and linked
sources, and generates locks only in temporary workspaces with isolated caches
and source-mapped NuGet configurations. Compared with finalized source locks,
only SecretKit package `contentHash` values may differ. Package IDs, versions,
request ranges, dependency edges, external hashes and framework graphs must
remain identical; a mismatch fails instead of rewriting the baseline.

The manifest binds schema/purpose, workflow run/attempt, selected SHA and SDK,
qualification digest, exact source-lock and staged-lock digests, and fixed app
source inventories. `local-demo-check` reopens the originals and checks the
current checkout/profile against the qualification record. It rejects missing,
extra, duplicate, linked, altered or substituted inputs.

Linux and Windows jobs download the same uploaded bundle without repacking.
Checkout sets `core.autocrlf=false` through the checkout step's process
environment only, preserving Linux-bound source bytes without changing global
Git settings. Select the bundle explicitly for final installed app tests:

```bash
SECRETKIT_DEMO_CANDIDATE_DIRECTORY="$PWD/artifacts/demo-inputs/originals" \
SECRETKIT_DEMO_CANDIDATE_VERSION=0.1.0-local.20261024.1 \
SECRETKIT_DEMO_STAGED_LOCK_DIRECTORY="$PWD/artifacts/demo-inputs" \
SECRETKIT_DEMO_SDK=10.0.302 \
dotnet tests/SecretKit.Demo.Tests/bin/Release/net10.0/SecretKit.Demo.Tests.dll \
  --minimum-expected-tests 65 --zero-tests-policy strict
```

The workflow SHA, run ID and attempt must also be present in `GITHUB_SHA`,
`GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`. An unset staged-lock selector uses
source locks; a set-but-invalid selector fails, with no fallback. Each actual
app workspace receives frozen selected lock bytes and verifies its original
and copied project/source/linked-source/lock inputs before restore and after
execution. Reports identify lock origin and digests, manifest/qualification,
originals, selected version, SDK, platform and outcome. Existing SDK profile
validators and the separate worker/web graph guards remain enforced.

This bundle supplies CI-only offline verification evidence. It does not
requalify the historical local candidate, establish an unobserved Windows or
native pass, or change the seven-package/two-provider public release approval
and publishing protocol.

## Portable repository feed

The retained `handoff/` contains `NuGet.Config`, `README.md`, `packages.sha256`
and `feed/` with exactly four unchanged `.nupkg` archives. Its local source is
relative to the configuration file; `SecretKit.*` maps only to that source.
External dependencies use the explicitly configured nuget.org source. This is
portable SecretKit distribution, not a fully offline mirror of all dependencies.

Copy the complete handoff into the consuming repository and include it in source
archives and container build contexts before restore. Use its configuration and
an empty isolated cache; do not substitute the maintainer's absolute-path test
configuration. Select exact bracketed versions, for example:

```xml
<PackageReference Include="SecretKit.Infisical" Version="[0.1.0-local.20261024.1]" />
```

The independently optional Configuration/Hosting packages use that same exact
version. Retain attribution, warning and hash records with the original bytes.
Replace version, archives and hash records together for a new candidate.
No developer home path, credential or publisher account is needed. Actual Event
placement, restore/container configuration and application acceptance remain a
separate downstream task.

## Application lifecycle

Inject the selected bootstrap credential, await complete required collection,
validate it, deliberately export only needed strings, and then construct
dependent consumers. Keep optional selections separate. Acquire one generation
per logical operation. Start optional maintenance explicitly; replacement,
bounded stop and disposal remain host-owned. Never repair a denied required read
with administrator credentials or interpret a reload as client activation.

## Application ownership

- The selected authority, credential injection, and provider permissions.
- Tenant or instance binding policy and permitted provider coordinates.
- Required versus optional settings, configuration names, and precedence.
- Cache freshness, reload scheduling, readiness, and activation of live clients.
- Database connections, Data Protection admission, and business validation.
- Desired/observed revisions, durable state, and replica convergence.

SecretKit supplies provider mechanisms and evidence beneath these policies. A
consumer can discard obsolete integration code during development; the SDK does
not preserve Event interfaces or introduce Event-specific aliases.

## Integration checks that matter

Evaluate selected reads, provider identity/revision evidence, exact coordinates,
material visibility, and cancellation before treating material as usable.
Inventory is metadata, not bulk plaintext retrieval. Raw reference syntax is
not application validation, and imports/reference expansion must be selected
deliberately.

Authentication needs an explicit startup, lifetime, and recovery policy. The
existing renewal session does not silently log in again or switch identities.
Bound read duration at the caller; host deadlines must not disappear when the
provider client is replaced.

Required selections can be collected into one local generation. Optional
features should use separate selections or capability assessment, so an absent
optional integration does not prevent unrelated startup. Configuration export
creates ordinary strings, and a reload notification is not client activation.

For writes, retain the pre-dispatch receipt. Applied, approval-pending, denied,
and unknown outcomes are different. Do not replay a possibly dispatched write
or interpret approval submission as an active credential.

## Evidence levels

| Evidence | What it establishes |
| --- | --- |
| Build and pack | Assemblies and local archives were produced |
| Offline adapter tests | Behavior against controlled protocol responses |
| Fresh installed consumer | Selected archive bytes restore and execute without project references |
| Owned live Infisical qualification | Only the named operations, identities, deployment, and version observed |
| Application acceptance | Only the application's tested integration and deployment |
| Public publication approval | A separate release decision; never implied by the rows above |

The repository-wide public publisher currently requires seven packages and both
providers under `complete-live`. That remains a separate, stricter protocol, not
the acceptance denominator for the new local goal. No public publishing phase
or Event repository work is part of this local-readiness workstream.

