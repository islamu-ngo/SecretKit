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

Use the separate [runtime-hardening profile](../internal/compatibility/runtime-hardening-profile.md)
to exercise newly built original archives in minimal, configuration, hosting and
full modes. Select the original directory and exact version explicitly; the new
workflow has no historical-cache fallback. Its `SCENARIO`/`REPORT` records use
profile `runtime-hardening`, while archive selection stays `infisical-runtime`.
Controlled loopback observations do not qualify a native issuer.

Native execution is a separate explicit selection. It requires current
deployment, lifetime and validating-network facts, protected authority and fresh
Universal login with a causal token handoff. Required policy that cannot be
observed remains unqualified; there is no administrative fallback or automatic
promotion of declared metadata into evidence.

SecretKit is **in development, not ready for production**. Independent installed
console, worker and web applications are implemented; use
[demos and recovery](demos-and-recovery.md) to choose one. The
[runtime adoption security contract](../internal/RUNTIME_ADOPTION_SECURITY.md)
defines their security and recovery evidence. App implementation does not
establish native deployment or final-archive qualification.

If you already have a prepared handoff, start at
[portable repository feed](#portable-repository-feed). The candidate-building
and evidence-freezing procedures below are for maintainers producing that
handoff. For a source-only first run, use [getting started](getting-started.md).

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

Run from the SecretKit root after finishing source and documentation changes.
The local profile owns the version; global.json owns SDK selection. Bootstrap
the tool without requiring any completed package or demo qualification:

```bash
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification ordinary
cohort="$PWD/artifacts/local-cohort-unique"
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification prepare-local "$cohort"
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification post-pack "$cohort"
```

Choose a previously absent absolute cohort directory with an existing parent.
Preparation retains both isolated build outputs and caches. It produces seven
original packages and their symbols, four byte-identical selected originals and
symbols, a second independently compiled family and selected subset, the local
qualification record, and frozen console/worker/web demo inputs. DLL, portable
PDB and document checksums must agree across builds; ZIP-byte equality is only
an observation. Existing directories are never replaced or merged. A failed
preparation remains available for diagnosis; use a new directory for another run.

`verification-cohort.json` binds every required archive, symbol and demo input.
`verification check "$cohort"` verifies the complete selection without running
tests. Missing, mixed, changed or linked artifacts fail before post-pack tests
start. Keep the distinct public-proposal package family and release authority
separate from this local cohort.

Post-pack runs the complete Package and Demo hosts and the Release archive and
installed-observation classes, with strict positive discovery and independent
failure aggregation. It derives all candidate, local,
integration-quality, symbol, rebuild, runtime-hardening and demo selectors from
the verified record. No ambient candidate or cache selects inputs. Every run
creates a new `artifacts/verification/observations/<id>/` directory and a separate
host-local qualification record. The producer's qualification is preserved;
platform observation files are published exclusively and cannot replace existing,
linked or producer-owned evidence. Independent Linux/Windows consumers download
the same cohort and never repack or regenerate source locks.

Build the separate conformance solution before the fixed safe offline lane:

```bash
dotnet restore SecretKit.Conformance.slnx --locked-mode
dotnet build SecretKit.Conformance.slnx --configuration Release --no-restore
dotnet tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll verification offline-conformance
```

This lane runs only the documented ProcessLifetimeTests, OwnedSandboxTests and
three Azure delivery/webhook selections with their existing floors. Whole live
conformance hosts remain separately authorized. Offline, installed, native and
publication evidence retain their existing distinct meanings and denominators.

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
`0.2.0-integration.3`; this does not change the global/default version or public
candidate. Build that exact version and pack the four originals into a fresh,
previously absent directory separately from the default seven-pack originals:

```bash
local_version=0.2.0-integration.3
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
SECRETKIT_LOCAL_CANDIDATE_VERSION=0.2.0-integration.3 \
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

The verified local cohort owns the demo version. Source-owned console, worker
and web locks constrain package identity, exact internal relationships and the
external dependency graph; their old SecretKit version never overrides a new
profile selection. Preparation generates staged locks in isolated app workspaces
against the exact originals. Only internal exact versions, internal dependency
versions and original content hashes may change. External package versions,
hashes, edges and framework graphs remain fixed. Source locks are not rewritten.

The cohort's `demos/` directory contains four unchanged originals, a copy of the
producer qualification, frozen per-app locks and `demo-inputs.json`. The manifest
binds the actual SDK, commit label, run/attempt, original and staged lock hashes,
and fixed source inventories. The post-pack verb verifies these bindings and
passes explicit `SECRETKIT_DEMO_CANDIDATE_DIRECTORY`,
`SECRETKIT_DEMO_CANDIDATE_VERSION`, `SECRETKIT_DEMO_STAGED_LOCK_DIRECTORY` and
`SECRETKIT_DEMO_SDK` selectors plus the bound run context to each demo process.
Local runs use run/attempt 1 unless an explicit CI context is present.

Every app copies selected locks unchanged and restores in locked mode with a
fresh cache. A supplied invalid lock selection fails without fallback. Checkout
uses `core.autocrlf=false` in independent CI consumers so source hashes remain
portable. The source version and producer evidence remain immutable while each
consumer writes its own host-local observations.

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
<PackageReference Include="SecretKit.Infisical" Version="[0.2.0-integration.3]" />
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

