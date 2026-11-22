# November provider-engineering evidence

> **Audience:** Maintainers and qualification reviewers
> **Status:** Dated observations; native and publication gates remain open
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-22 reconciliation of retained artifacts and execution records; no new live run
> **Source anchors:** [public limits](../../public/qualification-limitations.md), [project parser](../../../src/SecretKit.Infisical.Management/Projects/Projects.cs), [absence witness](../../../tests/SecretKit.Infisical.Conformance.Tests/Admission/AbsenceWitness.cs), [live tooling](../LIVE_INFISICAL_PROVISIONING.md)

## Source and evidence boundaries

The November 21 source changes were committed in `04928a0..46dc645`, on top of
`e69a0d1`. They include project response safety, native fixture witnesses and
cleanup, sandbox admission, private environment exclusions, the nonpackable
LiveProvisioner and documentation. Earlier provenance/UTC fixes remain in
`751651f` and `3af5ee1`. The old query rename and missing-field relaxation were
reverted; they are not latest-provider compatibility fixes.

The development cohort `local-cohort-provider-engineering-1795293451` predates
those commits and binds the corresponding working source. Recorded ordinary
and offline-conformance selections passed 13 lanes each; post-pack passed
Package 128, Demo 67 and Release 75 cases. A later stable-HEAD cohort,
`live-provisioning-cohort-head-46dc645`, records source commit `46dc645` and the
same post-pack totals. These are separate cohorts, not interchangeable archives.

Earlier source changes during capture produced `cohort-source-changed`; a later
HEAD advancement during package preparation produced
`debug-sourcelink-repository`. Those failed attempts are not usable qualification
evidence. Stable-source/HEAD retries passed without relaxing validators.
Freeze source, docs, locks and HEAD before the next capture.

## Selected native packets on v0.167.12

These are measured child effects, not strict host passes or full permission
proof. Counts use the latest retained attempt for each selected packet.

| Packet | Selected cases | Observed | Remaining cases |
| --- | ---: | ---: | --- |
| Static read/inventory | 40 | 32 | 8 pinned imported-version failures |
| Create/update | 20 | 10 | 10 approval inputs/causality gaps |
| Folders | 100 | 90 | 5 partial-batch inputs, 3 move failures, 2 filter observations |
| Tags | 27 | 27 | Strict prerequisites still apply |
| Environments, final attempt | 63 | 63 | Strict prerequisites still apply |
| Projects, repaired attempt | 103 | 69 | 5 licensed templates, 5 KMS inputs, 20 non-secret witnesses, 4 explicit-denial mismatches |
| **Total** | **353** | **291** | **62** |

These packets cover 26 operations. The empty-input Infisical discovery run
enumerated 303 operations and 25,802 cases; it established no strict passes.
It must not be used as meaningful execution coverage of the other 277
operations. Historical pre-upgrade reports cannot qualify this deployment.
The SDK's full-family and Azure inventories have their own denominators.

Five project-template cleanup witnesses remain unconfirmed. Complete direct
Setup/Administrative inventories found no projects from the repaired run left
behind; this does not prove absence in the inaccessible template inventory.
The earlier failed management run's 24 owned projects were separately recovered.
Older unrelated resources were preserved.

## Defects repaired and limits retained

- Imported-source provenance and UTC folder watermarks were corrected.
- Project list responses now admit and require `totalCount`; contradictory
  counts fail closed and larger totals cannot certify inventory completeness.
- Blank native project IDs cannot become successful Applied acknowledgements.
  The receipt remains uncertain. This is a deterministic malformed-response
  regression, not malformed output observed from the native server.
- Cleanup uses the actual creator authority, explicit observer enrollment and
  exact concealed reads plus complete inventory omission. Organization-admin
  machine status alone did not establish global project visibility.
- Environment soft deletion is observed in deleted inventory; cleanup retains
  the owned ID and verifies final omission. Restore position is checked against
  independent readback rather than assumed unchanged.
- Project fixture tests passed 1,345 cases, Management 3,345, governance 113,
  workspace 1,577, authentication 123 and organization/import 79 in their
  recorded increments. These are not a new whole-repository test total.
- Explicit-version rejection, primary failure preservation, separate cleanup
  flags and unconfirmed principal/policy bindings remain intact.

## Later provisioning and narrative evidence

The provisioning workstream records completed local bootstrap, repeated
provisioning, native `IdentitySetupTests`, and installed narratives against
local and authorized remote deployments. Both narrative logs retain:

```text
INSTALLED_NATIVE_READ_WRITE_INVENTORY_AND_IDENTITIES_PASSED
INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED
```

The local and remote narrative log IDs are respectively
`8d028b9653374391901d37aa7b56e070` and
`8de5cfd974d34e7e88786250b598f646` under local `artifacts/live/`.
Their two markers were inspected during this reconciliation; no live command
was rerun. Broader build/test totals remain attributed to the provisioning
execution record, not independently rerun here.

Automation Universal Auth credentials now live in the private clone-root
`.env`, with ephemeral run settings under `artifacts/live/`. The old
`~/.local/state/secretkit-live/` directory was retired by the authorized
provisioning workstream after local/remote proofs. Do not resume obsolete scripts
or restore its bearer caches. Keep credentials and protected coordinates out of
tracked evidence and never read private configuration merely to review docs.

## Remaining admission owners

Principal/API-revision binding and G01 causal producers remain implementation
and evidence work. Licensed feature access, controlled KMS/non-secret resources,
issuers, real backend effects and independent observers require operator inputs.
Azure effects, hosted CI, downstream AOT/trimming and trusted release provenance
retain their separate owners. A missing license does not excuse or resolve
missing proof machinery; successful provisioning does not certify native policy.

The deployed v0.167.12 is a historical observation. Verify the then-current
upstream provider release before a future live run; latest-only support does
not mean preserving older-server behavior. No publication authority follows
from this ledger.
