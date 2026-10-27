# SecretKit.Extensions.Configuration

For [Infisical-first local adoption](../../docs/public/local-packages.md), this
package is optional. All selections in one loader are required; compose optional
features separately. Application key naming, tenant bindings, cache/refresh
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
`SecretReference`. Consumer keys use ordinal comparison. Selections are required,
unique and fixed for that loader. `RefreshAsync` collects asynchronously and
serializes concurrent collections. Only a complete valid candidate replaces the
current generation. Absent, denied, invalid, expired or unknown-validity material
cannot become a required generation. Validity deadlines are checked again at
publication. Subsequent freshness and activation decisions belong to the caller.

`RefreshAsync` returns a bounded `SecretOutcome<long>`; `LastAttempt` retains only
timing, status, retry timing and cancellation evidence. An unexpected reader
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

`Generation` is a local publication number. Collection start/end times and each
read's actual `SecretObservation` retain version and provider evidence; unknown
versions stay unknown. `RemoteSnapshotGuaranteed` is always false. Local
immutability does not establish a remote transaction or simultaneous remote reads.

## Deliberate plaintext export

Call `SecretConfigurationExport.CreateAcknowledgingManagedStrings(handle, mappings)`
only when ordinary managed strings are intended. Each
`SecretConfigurationMapping` explicitly names its consumer key and destination
configuration key. The complete mapping is checked for ordinal case-insensitive
collisions before reading material. Add the returned source to a
`ConfigurationBuilder`; `Build` and synchronous `Load` do no reader I/O.
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
