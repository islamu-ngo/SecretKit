# Troubleshooting and recovery

> **Audience:** Application developers and operators
> **Status:** Diagnostic guide for implemented preview contracts
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against Core, provider and composition source
> **Source anchors:** [outcomes](../../src/SecretKit.Core/SecretOutcome.cs), [receipts](../../src/SecretKit.Core/MutationReceipt.cs), [demo recovery](demos-and-recovery.md)

Start with the operation's `Status`, whether a mutation may have been dispatched,
and which identity was selected. Do not log secret values or raw provider bodies
to diagnose a failure.

## Diagnose an outcome

| Observation | Check first | Safe next step |
| --- | --- | --- |
| `Invalid` before dispatch | Client/reference authority, address type, required coordinates and admitted input variant | Correct the selection; rebuild references for a replacement client |
| `Absent` | Exact selected name/version/scope and provider-native absence semantics | Verify through an authorized observer; do not substitute an identity |
| `Denied` | Runtime permissions and explicit material visibility | Obtain a deliberate policy decision; administrator inventory is not delivery proof |
| `Unavailable` | Origin, reachability, selected token source, transport and operation budget | Diagnose the selected dependency without printing credentials or response bodies |
| `Throttled` | Optional `RetryAfter` and operation effect | Let host policy decide a later attempt; timing does not authorize mutation replay |
| `Conflict` | Preconditions, concurrency and the native response contract | Re-observe and reconcile explicitly rather than silently upserting |
| `Pending` | Native approval/submission status | Await separately authorized effect observation; do not activate the candidate |
| `Unknown` | Incomplete, malformed, contradictory, ambiguous or lost evidence | Preserve uncertainty and receipt state; use an established native observation |
| `Unsupported` | Selected API/input variant, API version and package | Choose a documented variant; do not add an arbitrary HTTP fallback |
| `ContractNotEstablished` | Whether a callable supported contract exists at all | Treat it as a coverage gap, not a transient network error |
| `EntitlementUnavailable` | Selected provider edition, license and feature grant | Establish entitlement independently; code presence does not grant it |
| `RecoveryRequired` | Lost/expired token, uncertain renewal and lifetime evidence | Stop dependent work and start a newly authorized lifecycle |
| `Expired` | Credential/material expiry and original lifetime ceiling | Obtain authorized replacement; do not extend lifetime from a handoff timestamp |

See [Core reference](core-api.md#outcomes-and-exceptions) for the complete enum
contract. Provider methods use different subsets; this table does not invent a
cross-provider HTTP status mapping.

## Cancellation or a lost write response

Cancellation propagates. The caller must retain its `MutationReceipt` even if
the awaited operation throws.

- `NotDispatched` means the controlled send boundary was not entered.
- `PossiblyDispatched` means the provider may have acted; it does not mean failure
  or rollback.
- `Applied`, `Pending`, `Rejected` and `Conflict` record the native operation's
  established observation.

A receipt is single-use, target-bound and local. It is not a server query handle
or persisted journal. Do not reset it, reuse it for a different reference, or
retry an uncertain mutation to learn whether the first one worked. Readback can
show current state without attributing a change to this request.

For console/worker/web exit categories and drain failures, use
[demos and recovery](demos-and-recovery.md#interpret-outcomes-and-recover).

## Required configuration does not publish

`SecretSnapshotLoader.RefreshAsync` publishes only a complete valid candidate.
Every selection in a loader is required. A failed/cancelled collection retains
the previous generation; it does not partially update it.

1. Inspect the returned status and the loader's material-free `LastAttempt`.
2. Check the intended identity for each required selection.
3. Separate optional features into a different collection.
4. Confirm material validity/expiry at publication.
5. Keep readiness and allowed last-known staleness explicit in the application.

Cancelling a queued refresh does not cancel a different in-progress collection.
Loader disposal prevents new publication/acquisition but is not a substitute for
cancelling reader I/O.

## Values appear mixed after reload

Independent `IConfiguration` indexer reads can cross a reload. A reload signal
does not make several application reads atomic or replace an existing database
client.

Acquire one `SecretSnapshotHandle` for the logical operation, or prepare an
immutable application object from one handle and publish it explicitly.
Validate a new downstream client before activation and retain the old one until
its in-flight leases release.

Destination keys for explicit configuration export are case-insensitive:
`Connection:Key` and `connection:key` collide even though loader consumer keys use
ordinal comparison. Correct the mapping before export.

An export can build exactly one root. A rejected second Build leaves the first
root usable; a later sibling-source failure does not reopen that slot. Create a
new export rather than reusing or resetting an existing one.

If replacement reports that values were committed but notification failed, the
new dictionary is already visible. Callback diagnostics are sanitized; the
exception does not mean rollback. Inspect current state before another action.

## Authentication maintenance is not running

Constructing or registering a helper alone starts no worker. The host must
explicitly start `InfisicalAuthenticationMaintenance`, or register it as a hosted
service in a host that actually starts.

Use one helper per session lifecycle. Check health without exposing material.
Finite/periodic lifetime classification needs verified policy evidence; zero
maximum TTL is not proof of periodic semantics. After uncertainty, expiry or
process token loss, obtain an explicitly authorized replacement rather than
expecting automatic login, persistence or replay.

See [authentication and hosting](authentication-and-hosting.md).

## Shutdown times out or a cancellation callback fails

Admission stops before external callbacks run. Notification, drain and cleanup
use one original deadline; canceling one caller's wait does not cancel shared
cleanup. Timeout is not successful drain. Noncooperative host callbacks cannot
be killed, so owned cleanup remains pending until safe completion is possible.
Later cleanup does not change the original timeout; repeated stop/disposal
observes the same bounded outcome. Fixed callback-failure diagnostics contain
no callback prose or inner exception. Do not reset the budget or infer rollback.

Rotation token-acquisition transport/I/O failures also return bounded outcomes
without source exception text. Preserve a receipt that remains NotDispatched;
caller cancellation still propagates rather than becoming an ordinary failure.

## A native revision read fails while a common read works

`InfisicalClient.ReadNativeAsync` qualifies only raw, non-imported reads and
requires complete returned identity/version evidence. Expanded references or
imports can change material independently of a selected resource's version.
Use `Raw` with `IncludeImports=false` for qualified resource revisions. Missing
required native evidence remains unknown rather than borrowing request fields
or substituting `_id`.

Common reads can serve explicitly selected resolution/import modes without
claiming an opaque qualified revision. See [Infisical](providers/infisical.md).

## Local packages fail restore or qualification

- Check the exact profile version and original archive bytes, not just filenames.
- Keep `SecretKit.*` mapped to the intended local feed and use an isolated cache.
- Use matching finalized locks for the selected candidate; a CI rebuild is a
  different artifact even at the same version.
- Do not overwrite an old qualification record or reuse a destination that a
  command requires to be absent.
- Any source, profile or archive change invalidates an exact-source qualification
  record. Repack and create a new record.

Use [local packages](local-packages.md) for the owning procedure. Frozen-source
checks include documentation: updating these pages does not retroactively qualify
old artifacts. A provider-native test needs its own authorized deployment inputs;
ordinary solution test success does not supply them.

## Prepare a useful issue report

Include the source revision or exact package version, selected package/method,
OS/runtime, bounded status, cancellation stage and receipt evidence where
relevant. State whether the failure occurs offline, against installed archives,
or on a named sanitized provider/API/edition combination.

Provide a minimal reproduction with synthetic values. Remove tokens, values,
confidential coordinates, raw headers, provider bodies and protected input
files. Follow [CONTRIBUTING.md](../../CONTRIBUTING.md); suspected vulnerabilities
follow [SECURITY.md](../../SECURITY.md) instead.
