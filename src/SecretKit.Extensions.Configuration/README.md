# SecretKit.Extensions.Configuration

For [Infisical-first local adoption](../../docs/public/local-packages.md), this
package is optional. Selections default to required; mark an explicitly optional
selection with `SecretPresencePolicy.Optional`. Application key naming, tenant bindings, cache/refresh
policy, Data Protection admission and activation remain outside the package.
Installed-consumer qualification does not add those policies to the runtime
library. The RuntimeConfiguration sample composes separate required and
optional groups; capability checks and explicit client activation remain
application-owned decisions.

See [current support](../../docs/public/provider-support.md) for package
boundaries and observed offline evidence.

This optional package references Core and Microsoft.Extensions.Configuration.
Core remains BCL-only. It installs no cache policy, TTL, worker or hosting lifecycle.
Supplied readers and transports remain caller-owned.

## Logical multi-key operations

Construct `SecretSnapshotLoader` with explicit `SecretSelection` entries: each
consumer key names its selected `ISecretReader` and authority-bound
`SecretReference`. Consumer keys use ordinal comparison. Selections are
unique and fixed for that loader. `RefreshAsync` collects asynchronously and
serializes concurrent collections. Only a complete valid candidate replaces the
current generation. Absent, denied, invalid, expired or unknown-validity material
cannot become a required generation. Validity deadlines are checked again at
publication. Subsequent freshness and activation decisions belong to the caller.
Only an optional selection's explicit Absent outcome is admitted. An absence-only
generation is valid and replaces stale presence; denial, expiry and other failures
still reject the entire candidate. Use separate loaders for optional capability
groups when one group's failure must not block another.
Successful reader observations must retain the exact requested `SecretReference`
instance. A different object, even with the same authority and address, is
rejected as Invalid before material is copied. Rejected reads are disposed and
previously acquired generations and copies remain valid.

`RefreshAsync` returns a bounded `SecretOutcome<long>`; `LastAttempt` retains only
timing, status, closed failure reason, retry timing and cancellation evidence. An unexpected reader
exception becomes Unavailable without its message or inner exception.
Cancellation propagates, clears candidate storage and preserves the prior
generation. Cancelling a queued collection does not cancel another collection.
Disposal prevents publication and future acquisition, but does not itself cancel
reader I/O: the caller supplies its cancellation policy.

Acquire once with `Acquire()` for each logical operation, then call
`handle.Read(consumerKey)` for every required value. Each returned `SecretRead`
owns an independent copy and must be disposed. Generation retirement waits for
all acquired handles; loader disposal cannot invalidate existing handles or
copies. Handle disposal is idempotent and prevents further reads from that handle.
Copies already returned survive until their own disposal.
`ReadOutcome(key)` returns either an owned successful read or explicit Absent for a
declared optional key. `Read(key)` throws for declared absence. Both reject unknown
keys and disposed handles. `Count` counts present values; `SelectionCount` also
counts absent selections.

`Generation` is a local publication number. Collection start/end times and each
read's actual `SecretObservation` retain version and provider evidence; unknown
versions stay unknown. `RemoteSnapshotGuaranteed` is always false. Local
immutability does not establish a remote transaction or simultaneous remote reads.

## Bounded collection

Pass `SecretCollectionOptions` as the loader's `options` argument to adjust limits.
Defaults are concurrency 1, 1000 selections, 16 MiB of candidate UTF-8 payload and
a one-minute collection timeout. Admitted ranges are concurrency 1-32, selections
1-10000, payload 1 KiB-64 MiB and positive timeout up to ten minutes.

Enumeration is bounded before retaining selections. A contiguous ordinal window
limits unresolved/staged work; a stalled earlier ordinal cannot grow an unbounded
queue of later results. Reduction, payload accounting and failure selection follow
input order, not completion order. A terminal failure stops new admission but does
not cancel earlier ordinals. All started reads settle and all delivered reads are
disposed, including late results rejected after cancellation or expiry.

The timeout starts after serialized admission and cancels only that collection's
reads. Caller cancellation propagates and takes precedence over the deadline;
deadline expiry returns Unavailable/DeadlineExceeded after started work settles.
An unrelated reader cancellation becomes Unavailable/TransportFailure. A reader
that ignores cancellation cannot be forcibly terminated; the collection remains
in flight until it returns. Disposal prevents publication but does not kill it.

The payload limit bounds encoded candidate values, not process heap usage. UTF-16
owners, previous pinned generations, returned copies, parser buffers and concurrent
reader deliveries require additional memory. Exact-reference, validity and expiry
checks run again before publication. No automatic refresh or retry is installed.

## One prepared owner

`PreparedSecretConfiguration.PrepareAsync(selections, ...)` returns an outcome
containing an owner of the loader and one pinned generation. Preparation performs
asynchronous reads but creates no ordinary plaintext strings. Use `Read` or
`ReadOutcome` to obtain independently owned material.

Call `prepared.ExportAcknowledgingManagedStrings(mappings)` only when plaintext
configuration is intended. All consumer keys and destination collisions are
validated before any reveal. The returned `IConfigurationRoot` is borrowed; the
prepared owner owns its root and export, permits one successful export and releases
both before its handle and loader. Failed mapping validation can be corrected
before export. Repeated disposal is harmless, borrowed readers remain host-owned
and previously returned material copies remain independently usable.

## Deliberate plaintext export

Call `SecretConfigurationExport.CreateAcknowledgingManagedStrings(handle, mappings)`
only when ordinary managed strings are intended. Each
`SecretConfigurationMapping` explicitly names its consumer key and destination
configuration key. The complete mapping is checked for ordinal case-insensitive
collisions before reading material. Add the returned source to a
`ConfigurationBuilder`; `Build` and synchronous `Load` do no reader I/O.
Declared absent selections produce explicit null entries so lower-priority
configuration cannot resurrect a value. Unknown selection keys are rejected before
revealing any mapped material.
Each export supports exactly one successful `Build`, including concurrent
builders. A second build throws `InvalidOperationException` without affecting
the winning root. The slot is consumed when the source returns its provider;
if a later sibling source fails, dispose the export rather than rebuilding it.

`ReplaceAcknowledgingManagedStrings(nextHandle)` prepares all mapped values,
atomically replaces the provider's string dictionary and signals reload.
Preparation failure leaves prior strings and the reload token unchanged.
Publication is committed before notification: a throwing reload callback leaves
the new values committed and causes a fixed `InvalidOperationException` without
callback text or an inner exception. There is no rollback.
Callbacks run outside source/provider gates and may reenter reads, replacement
or disposal. Concurrent notifications mean re-read current committed state, not
delivery of every intermediate generation. The provider
is read-only. Disposing either the source or configuration root clears its
dictionary references and prevents replacement or rebuild; an in-flight
replacement cannot resurrect a disposed provider.

Separate IConfiguration indexer reads can cross a reload and mix generations.
Use an acquired handle or construct a consumer-owned immutable typed object from
one handle when multi-key coherence is required. Reload does not mean consumer
activation, options convergence or fleet convergence.

`GetRedactedDebugView()` returns only a count and excludes keys and values.
Default formatting and System.Text.Json serialization of package objects exclude
material, keys, references and readers. Standard IConfiguration debug views,
enumeration, options binding, application serializers, logs, diagnostics and dumps
can disclose exported strings or coordinates. Those surfaces are host-owned.

SDK-owned character buffers are cleared on final release, not securely erased
process-wide. Exported strings, old options and consumer fields can remain alive
after replacement or disposal. This package never claims export erasure or that
wrapper protection survives the string boundary.
