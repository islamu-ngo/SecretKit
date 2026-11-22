# Qualification limits and release readiness

> **Audience:** Developers evaluating SecretKit, operators and maintainers
> **Status:** In development; not ready for production or publication sign-off
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-22 documentation reconciliation at `46dc645`; no new provider calls
> **Source anchors:** [support reference](provider-support.md), [dated evidence](../internal/compatibility/provider-engineering-2026-11.md), [provisioning guide](../internal/LIVE_INFISICAL_PROVISIONING.md)

SecretKit has implemented and tested subsets, but it does not yet have complete
native provider qualification. Successful builds, installed examples and live
effect observations answer different questions. None alone authorizes publication.

## Infisical deployment and license limits

The recorded November playground and local sandbox observations used Infisical
`v0.167.12`. This is a tested deployment version, not a claim that it is still the
newest upstream release. SecretKit's support policy is **latest provider release
only**, for Infisical and other secret managers. Consumers must keep their
providers current; no backward-compatibility shims are planned.

No Enterprise license was available for the recorded playground qualification.
The template endpoint returned a license-related HTTP 400. We therefore cannot
claim successful testing of that licensed feature. Other licensed capabilities,
approval causality and external backend effects retain their own unfulfilled
requirements. Health or a working login does not establish an edition,
subscription entitlement or permission. Do not classify every HTTP 400/403 as a
license problem.

The new provisioner has local and remote installed-narrative evidence. It does
not provision every issuer, KMS key, database, non-secret product, gateway or
independent observer needed by the native families. These are real missing
inputs, not successful tests or SDK defects by default.

## Remaining native proof gaps

| Area | Current limitation |
| --- | --- |
| Principal and policy binding | Supplied tokens stay opaque. Distinct credentials, declared identity IDs, JWT claims and successful reads do not prove that the exact bearer is the reviewed native principal or establish its complete effective policy. Missing bindings remain unqualified. |
| API revision and causal observers | Some isolated runs do not establish the required origin/API revision. Approval, audit, sharing, replication and downstream effects need the appropriate native contracts and independent observer producers. |
| Pinned imported reads | In the recorded deployment, an import requested at version 1 returned the latest version 2. The SDK rejects explicit-version substitution; these cases remain failed. |
| Folder operations | Move requests were refused and a modification-filter probe returned an empty list despite a newly created secret. Permission, entitlement and filter semantics were not fully established. These observations do not prove an SDK parser defect. |
| Project collection denial | The selected denied credential received HTTP 200 with an empty project list when roles were excluded, versus HTTP 403 when roles were requested. Four cases requiring explicit denial remain unqualified; the SDK does not invent denial from an empty successful result. |
| Project fixtures and cleanup | KMS inputs and controlled non-secret-product witnesses are missing. Five template cleanup witnesses remain unconfirmed because the licensed inventory is inaccessible. No remaining projects from the repaired management run were found in complete owner inventories; that is narrower than proving every resource cleaned. |
| Dynamic secrets and rotations | Typed definitions and acknowledgements do not prove real credential creation, database authentication, revocation or consumer convergence. SQL and other backend effects require their own controlled resources and observers. MySQL evidence does not qualify MariaDB. |
| Azure | Live data-plane, denied-status, Event Grid/sender, audit and management effects remain separate unclosed gates. Infisical results do not qualify Azure. |

A fixture-issued Token Auth principal-proof mode has been proposed, but is not
implemented qualification evidence. It would need exact issued-material binding,
independent metadata checks and owned issuance/revocation recovery. It would not,
by itself, qualify Universal Auth authentication or prove native policy/effects.
The existing provisioner continues to use Universal Auth.

## Evidence that is available

The [dated ledger](../internal/compatibility/provider-engineering-2026-11.md)
records the selected live packets and exact source/package boundaries.
They contain 291 observed child effects across 353 selected cases and 26
operations; strict host qualification remains unclosed. The separate
303-operation discovery baseline with empty family inputs is not evidence that
all those operations were meaningfully exercised.

Source/offline checks, installed package checks and local/remote narratives have
passed in their recorded increments. The later installed narrative has both
required result markers on local and remote deployments. Those narrow results
do not erase the native failures or qualify changed source and archives.

## Platform and release limits

Linux .NET 10 evidence does not establish the required hosted multi-OS release
matrix, macOS/ARM coverage, downstream NativeAOT or Azure trimming. Five packages
declare AOT compatibility; the Azure packages retain their documented limits.
See [provider support](provider-support.md).

The four-package local profile and seven-package release family remain distinct.
The local 17-case functional, 21-case native and supplemental hardening
denominators retain their meanings; the selected family counts above do not
replace them. Exact source, original archive hashes, candidate/tag provenance,
required CI and publisher authorization remain necessary.

## How to resume qualification

Follow the [provisioning guide](../internal/LIVE_INFISICAL_PROVISIONING.md).
Use explicitly selected authority and an owned sandbox, preserve real failures,
and provide the licensed features, backend/issuer inputs and independent
observers needed for the selected family. Resolve principal-proof and native
contract gaps before promoting observations to qualification.

Missing live inputs do not prevent offline implementation or deterministic
regression work. Keep untestable native cases open rather than adding fallbacks,
weakening assertions, replaying mutations or claiming qualification.
