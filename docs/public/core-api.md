# Core API reference

> **Audience:** .NET application developers and adapter authors
> **Status:** Implemented `SecretKit.Core` contract
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-27 reader contract source review and ConfigurationTests; Core suite not rerun, no native qualification implied
> **Source anchors:** [Core source](../../src/SecretKit.Core/), [Core tests](../../tests/SecretKit.Core.Tests/)

`SecretKit.Core` defines common reads, metadata, material ownership and bounded
outcomes. It uses only the BCL. Authentication, remote coordinates, writes and
specialized lifecycle operations remain provider-native.

## Public type map

| Types | Contract and declaration |
| --- | --- |
| `ISecretReader` | Selected-authority asynchronous read; [declaration](../../src/SecretKit.Core/ISecretReader.cs) |
| `ISecretInventory`, `SecretInventory` | Bounded metadata collection; [declarations](../../src/SecretKit.Core/ISecretInventory.cs) |
| `SecretAuthority`, `SecretAddress`, `SecretReference`, `SecretInventoryScope` | Instance authority and provider-owned coordinates; [declarations](../../src/SecretKit.Core/SecretReference.cs) |
| `SecretOutcome<T>`, `SecretStatus` | Success-only value access and failure categories; [declarations](../../src/SecretKit.Core/SecretOutcome.cs) |
| `SecretMaterial` | Clearable owned characters and explicit exports; [declaration](../../src/SecretKit.Core/SecretMaterial.cs) |
| `SecretRead`, `SecretObservation`, `SecretValidity` | Owned read plus value-free observations; [declarations](../../src/SecretKit.Core/SecretObservation.cs) |
| `MutationReceipt`, `DispatchEvidence` | Caller-held mutation dispatch evidence; [declarations](../../src/SecretKit.Core/MutationReceipt.cs) |
| `SecretCapabilityEvidence`, `CapabilityAvailability`, `PermissionEvidence`, `SecretEffect` | Independent implementation, permission, effect and verification claims; [declarations](../../src/SecretKit.Core/SecretCapabilityEvidence.cs) |

## Read from one authority

The common read signature is:

```csharp
ValueTask<SecretOutcome<SecretRead>> ReadAsync(
    SecretReference reference,
    CancellationToken cancellationToken = default);
```

`ISecretReader.Authority` exposes an opaque `SecretAuthority`. Construct a
`SecretReference` with that instance and a provider-specific `SecretAddress`.
`reference.BelongsTo(authority)` uses object identity, not matching names,
credentials or endpoint text. Creating a reference grants no remote permission.
Built-in adapters reject foreign authority or address types before dispatch.

References do not choose a network endpoint. An Infisical address, for example,
selects project/environment/folder/key within the client's trusted origin.
A new client requires new references; a comparable native revision does not
transfer reference authority.

A successful `ReadAsync` result must retain the **exact requested reference
object** in `SecretRead.Observation.Reference`. Equal-looking coordinates or a
new reference with the same authority do not satisfy this contract.
`SecretSnapshotLoader` checks `ReferenceEquals` before copying material, disposes
mismatched results and returns `Invalid` without replacing the current generation.
Previously acquired generations and copies remain valid.

See [getting started](getting-started.md#5-make-a-selected-infisical-read) for a
complete read fragment and [provider guides](providers/README.md) for addresses.

## Outcomes and exceptions

`SecretOutcome<T>` requires non-null `T`. `IsSuccess` is true only for
`SecretStatus.Success`; only then is `Value` available. Accessing `Value` on a
failure throws `InvalidOperationException`. Failures do not contain provider
payloads or exceptions.

| `SecretStatus` | Meaning to preserve in consumer policy |
| --- | --- |
| `Success` | A value/result exists for this operation; downstream activation is separate |
| `Absent` | The selected resource was reported absent; not a synonym for denied |
| `Denied` | Access or material visibility was denied |
| `Unavailable` | The operation could not be completed through the selected dependency |
| `Invalid` | Input, selected scope or returned identity contradicts the operation contract |
| `Throttled` | Rate-limited; optional `RetryAfter` is advisory timing, not replay permission |
| `Conflict` | A provider conflict was observed; no automatic overwrite is implied |
| `Pending` | The operation awaits a native step such as approval; not applied material |
| `Unknown` | Available evidence does not establish a safe result or effect |
| `Unsupported` | The selected operation or variant is not supported |
| `ContractNotEstablished` | A supported programmable contract has not been established |
| `EntitlementUnavailable` | The required provider entitlement is unavailable |
| `RecoveryRequired` | The current lifecycle cannot continue without explicit recovery |
| `Expired` | Material or credential lifetime has ended |

These are contract categories, not a universal HTTP mapping. Not every adapter
or operation produces every status. Consult its native guide for response
mapping and supported variants.

`Success(value)` rejects null. `Failure(status, retryAfter)` rejects `Success`,
undefined enum values, negative timing, and retry timing on a status other than
`Throttled`. `RetryAfter` may be null.

Caller cancellation propagates as `OperationCanceledException`. Invalid
constructor arguments, disposed-object use and other programming errors can
still throw; a bounded outcome is not a blanket exception-suppression policy.
Handle cancellation at your application's lifecycle boundary, not by turning it
into `Absent`.

## Material and read ownership

`SecretRead` owns its `SecretMaterial`; disposing the read disposes that material.
The constructor takes ownership of the supplied material rather than copying it.
Built-in successful reads return independent owned material.

| `SecretMaterial` member | Ownership |
| --- | --- |
| `FromText(ReadOnlySpan<char>)` | Copies input into an owned character array; cannot erase the input |
| `Copy()` | Returns an independently owned material object; dispose it separately |
| `Reveal()` | Creates an ordinary managed plaintext string with an independent lifetime |
| `ExportCharacters()` | Returns an independent array; the caller must clear it |
| `Dispose()` | Clears owned character storage; safe to call more than once |

Copying, revealing or exporting after disposal throws `ObjectDisposedException`.
Copies already made survive original disposal. Do not treat the outcome as
disposable: dispose its successful read.

This standalone Core fragment demonstrates the array-export boundary with
synthetic, non-secret text:

```csharp
using SecretKit.Core;

using SecretMaterial material = SecretMaterial.FromText("documentation-example");
char[] characters = material.ExportCharacters();
try
{
    Console.WriteLine($"CHARACTER_COUNT_{characters.Length}");
}
finally
{
    Array.Clear(characters);
}
```

The example prints only a length. In an application, avoid logging lengths if
even that metadata is sensitive. Clearing this array or SDK storage does not
erase parser strings, exported strings, logs, dumps, or downstream copies.
See [security and ownership](security-and-ownership.md).

## Observations and inventory

`SecretObservation` holds a reference, optional provider version, observation
time, `SecretValidity`, and optional expiry. Validity is one of `Valid`,
`Disabled`, `NotYetValid`, `Expired`, or `Unknown`. A version string is not a
portable sequence number or cross-provider concurrency token.

`ISecretInventory.InspectAsync(scope, cancellationToken)` returns
`SecretOutcome<SecretInventory>`. A provider-specific `SecretInventoryScope`
binds selection to an authority.

`SecretInventory.Items` contains observations, never secret values.
`StartedAt`/`CompletedAt` record a collection window; `IsComplete` indicates
whether the bounded result is complete. `IsPointInTime` is always false.
Completeness within an admitted scope does not prove simultaneous remote state,
value-read permission, delivery, or application readiness.

Provider limits can truncate inventory; inspect `IsComplete` before treating it
as exhaustive. Use an actual selected read for runtime material access.

## Mutation receipts

Core defines no universal writer. Native mutation APIs use `MutationReceipt` to
keep dispatch evidence available even when a response is lost or cancellation
propagates. Create and retain a receipt **before** calling the operation.
Use its operation-specific factory where the provider supplies one.

| `DispatchEvidence` | What the caller knows |
| --- | --- |
| `NotDispatched` | The controlled send boundary has not been entered |
| `PossiblyDispatched` | A request may have reached the provider; effect is not settled |
| `Applied` | The operation's accepted response established its applied effect |
| `Pending` | A native pending result was observed |
| `Rejected` | The dispatched request was authoritatively rejected |
| `Conflict` | The dispatched request returned conflict evidence |

`MutationReceipt.IsFor(target)` matches the exact target object. It does not
match another reference merely because its coordinates are equal.
`LocalId` is a local correlation identifier, not a server idempotency key,
approval handle, durable journal or remote lookup token.

`BeginDispatch(target)` and `Record(evidence)` are adapter transition methods.
Application code must not call them to manufacture provider evidence.
Dispatch begins only once. No API resets an uncertain receipt for replay;
`Record` accepts only a terminal known observation from a possibly dispatched
state. Unsupported preconditions can fail before dispatch.

After transport loss or cancellation, inspect the retained receipt. A cancelled
task does not mean rollback. A fresh read may establish current state without
proving which writer caused it. Follow the native reconciliation procedure;
do not replay an uncertain mutation as a diagnostic.

## Capability evidence

`SecretCapabilityEvidence` separates:

- `Availability`: `Implemented`, `Unsupported`, or `ContractNotEstablished`.
- `Permission`: `NotChecked`, `Allowed`, or `Denied`.
- `Effect`: `ReadOnly`, `VersionCreating`, `CredentialIssuing`,
  `Administrative`, or `Destructive`.
- `RemotelyVerified`: false unless separately established.

Implementation is not permission, and permission is not remote conformance.
The record itself does not contact a provider or establish deployment facts.

## Behavioral evidence

The [Core tests](../../tests/SecretKit.Core.Tests/) cover independent copies,
redacted formatting/serialization, authority isolation and non-replayable
receipt transitions. The
[portable provider-contract tests](../../tests/SecretKit.ProviderContract.Tests/)
exercise common behavior through actual adapters with controlled responses.
Neither is a live-provider certification.
