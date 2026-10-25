# ADR-002: Separate Infisical local qualification from public publication

> Status: Accepted; offline P1 boundary implemented, installed/native qualification pending
> Date: 2026-10-23
> Decision owner: SecretKit maintainer
> Source baseline: `e635985239a3146228f1bb75d65a3f13c84a292c`
> Anchors: [local readiness](../INFISICAL_LOCAL_READINESS.md), [public protocol](../releases/PUBLICATION_PROTOCOL.md)

## Context

SecretKit has seven package projects and a public publisher requiring both
provider inventories and complete-live evidence. The next adoption goal needs
Infisical runtime mechanisms and optional configuration/hosting through local
archives. Coupling that goal to unrelated Azure and management completion
prevents useful early consumer evidence.

Event demonstrates requirements for stronger native revisions, exact-address
reads, lifetime handling, setup writes and bootstrap composition. Its tenant
models, persistence, configuration conventions and activation policy are not
portable SDK features. Development-mode breaking changes are permitted.

## Decision

1. Qualify a local application profile containing Core, Infisical, Configuration
   and Hosting; consumers may install a smaller dependency-closed subset.
2. Declare exact native members and consumer scenarios independently of the
   complete-live inventories. Package presence never qualifies every method.
3. Use a distinct typed local manifest/report binding source identity, original
   archive hashes, dependency closure, scenario results and observed platform.
   Public release parsing must reject it before approval or publication effects.
4. Keep the existing public publisher and broader admission inventory intact.
   Retain Azure/management and unfinished native work without making their
   completion part of the local goal.
5. Keep provider-specific identity/revision and authentication APIs native.
   Keep Core BCL-only and material opaque. Preserve application-owned policy.
6. Prove useful generic consumers inside SecretKit with installed packages,
   then qualify the named behavior against an explicitly authorized Infisical
   environment. No Event/Configurator edit or public publication is a phase.

## Alternatives considered

| Alternative | Reason not selected |
| --- | --- |
| Finish every public-release gate first | Delays the stated local Infisical outcome behind unrelated provider breadth |
| Loosen the public verifier to accept partial evidence | Confuses local experimentation with publication authority |
| Delete Azure, management or unfinished native work | Unnecessary scope expansion and loss of independent work |
| Recreate Event's provider/resolver interfaces in the SDK | Imports application policy and compatibility debt rather than reusable mechanisms |
| Add a new umbrella runtime package | Adds a facade without proving a missing portable responsibility |

## Implemented offline contract

`LocalQualification.ReadProfile(source)`, `Prepare(source, originals, output)`
and `Check(source, originals, directory)` in the nonpackable Release tool expose
separate `LocalProfile` / `LocalQualificationRecord` types. CLI commands
`local-prepare <source> <originals> <output>` and
`local-check <source> <originals> <record-directory>` use those APIs before any
public-release environment/approval handling. Success is exit 0; rejection is
exit 1. Neither route has a provider transport or journal dependency.

The source-owned `docs/internal/local/infisical-runtime.json` is schema 1 /
`local-profile`; records are schema 1 / `local-qualification` with status
`prepared-not-native-qualified`. Exact four-package membership, a single
version, eight runtime operation/member pairs (including the authored native
read), and S01-S16 are checked independently of public admission. Native reads
are qualified only for `Raw IncludeImports=false`. The record binds the profile
bytes rather than creating a second mutable coverage inventory. The profile
declares requirements; no scenario result is fabricated by preparing it.

The current local version is `0.1.0-local.20261024.1`. Build and pack with
`-p:Version=0.1.0-local.20261024.1`, separately selecting the four local originals
and excluding symbol archives from their directory. The global default version
and public candidate are unchanged. Isolated unit fixtures may use their own
exact version; CI/installed consumer wiring belongs to the independent local
candidate workflow, not a relaxation of the seven-pack publisher.

The implemented source route is `source-content-v1`, not clean-HEAD inference.
Every included file, including empty/untracked inputs, contributes a SHA-256
entry. The aggregate is SHA-256 over the path-sorted `FileDigest[]` serialized
with `Manifest.JsonOptions`; relative paths use `/`. Exclusions are root `.git`,
`artifacts`, `dev`, `.worktrees`, and all `bin`/`obj`/`TestResults` path segments. These are
metadata, private execution state and generated outputs, not permitted build
input locations. No ignore-aware Git enumeration can hide a dirty source file.
Checks compare the complete manifest and aggregate hash, not just HEAD or JSON
equality. Source links and linked ancestors are rejected before traversal.

Archives stay in the caller's original directory. Each check rereads original
bytes and validates hashes, unsigned safe ZIP structure, nuspec identity/version/
repository label, MIT license, README, source notices and internal dependency
closure. The original directory contains exactly the four selected `.nupkg`
files. Records are created in a new directory; output must be outside source or
under an explicit source-digest exclusion, preventing self-invalidating records.

The nuspec commit is a label observed in the archives, not proof that dirty
source equals that commit or that a trusted builder produced those archives.
The explicit content digest binds the dirty snapshot without requiring commits.
Producing artifacts from that snapshot remains the maintainer's build step.
Before P7, freeze that source/profile/archive tuple; any hash change invalidates
native exact-artifact evidence and requires new preparation/qualification.

The seven-package public manifest, approval, candidate and publication journal
protocol remains unchanged. Cross-mode tests reject local records through both
public verifiers and public manifests through the local parser.

## Consequences

The development-adoption increment keeps a distinct functional decision over
the same report, not another public manifest or attestation framework. It
requires all 17 selected cases with consistent effect/reason evidence; the
no-approval pilot retains pending-approval unavailable, and three binding cases
remain unavailable. The original full gate still requires 21 passes. Expected
artifact binding is frozen independently before the host run and after cleanup.

Repository delivery uses four byte-identical originals, relative feed
configuration, hashes, notices and a development/not-production warning.
Relocation tests use the bundled configuration and fresh caches, not the
existing absolute-feed fixture. Shared conformance/solution build outputs are
serialized and use one candidate Version. No compatibility layer, hosted feed,
publisher setup or downstream application migration is introduced.

There are two explicit evidence modes. Their shared validation should be reused
only where the contracts really match; no catch-all mode flag may bypass public
approval checks. Negative cross-mode tests are mandatory. Existing full-solution
regressions still protect retained code when common implementation changes.

The local profile is deliberately bounded. Broader public native APIs remain
documented according to their actual support state; a local pass cannot be
marketed as complete Infisical support. Generic sample policies demonstrate
composition but never become SDK readiness or fleet orchestration.

## Revisit triggers

Revisit for an explicitly authorized public release, a proven common revision
contract across providers, a new consumer responsibility, or evidence that the
local profile cannot be separated without weakening public authority. Missing
credentials or vendor entitlements change qualification status, not permission
to write independently testable library code.

