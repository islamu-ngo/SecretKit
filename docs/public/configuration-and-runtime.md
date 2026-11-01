# Configuration and runtime

> **Audience:** .NET application developers, operators and AI coding assistants
> **Status:** Implemented composition APIs; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-01 source review and 69 passing offline Configuration tests; no native qualification
> **Source anchors:** [Loader](../../src/SecretKit.Extensions.Configuration/SecretSnapshotLoader.cs), [selection](../../src/SecretKit.Extensions.Configuration/SecretSelection.cs), [handle](../../src/SecretKit.Extensions.Configuration/SecretSnapshotHandle.cs), [export](../../src/SecretKit.Extensions.Configuration/SecretConfigurationExport.cs)

Use `SecretKit.Extensions.Configuration` to collect required values asynchronously
and pin one local generation for a multi-key operation. Export to `IConfiguration`
only when ordinary plaintext strings are acceptable. The package does not choose
an identity, install refresh policy, start a worker or activate application clients.
Core/provider reads do not require this optional package.

The [prepared owner](../../src/SecretKit.Extensions.Configuration/PreparedSecretConfiguration.cs)
and [collection options](../../src/SecretKit.Extensions.Configuration/SecretCollectionOptions.cs)
compose the same loader/generation/export boundaries, not a second lifecycle.

## Select required groups explicitly

Each `SecretSelection(consumerKey, reader, reference, presencePolicy)` binds an application key to
one `ISecretReader` and a `SecretReference` belonging to that reader's authority.
An authority mismatch throws during selection construction. A loader requires
at least one selection, copies the selection list and rejects duplicate consumer
keys with **ordinal, case-sensitive** comparison. `Password` and `password` are
different consumer keys; reads through a handle require the exact spelling.

The default presence policy is `SecretPresencePolicy.Required`. Select
`SecretPresencePolicy.Optional` only when an explicit provider `Absent` result
is acceptable. Denied, invalid, expired and unavailable inputs still reject the
whole collection. An absence-only optional generation is complete and replaces
old presence. There is no fallback principal or local-default rescue path.

Keep independent optional feature groups in separate loaders when their failure
must not block startup-required settings. Optional absence and application
feature activation remain different decisions.

Use references and readers selected by trusted application configuration. An
administrative read does not prove delivery to the intended runtime identity.
The [provider guides](providers/infisical.md) describe native references;
[Azure Key Vault](providers/azure-key-vault.md) and
[management](providers/management.md) have distinct identity boundaries.

## Await collection before constructing dependent services

`RefreshAsync(CancellationToken)` defaults to serial reads and always serializes
concurrent collections on the same loader. It returns
`SecretOutcome<long>`: success contains the newly published local generation
number; failure preserves `Status`, `Reason` and optional `RetryAfter`.

Pass `SecretCollectionOptions` as the loader's optional third argument to choose
bounded concurrency (default 1, range 1-32), selection count (default 1000, range
1-10000), UTF-8 payload bytes (default 16 MiB, range 1 KiB-64 MiB), and collection
timeout (default one minute, positive and at most ten minutes). Timeout starts
after serialized admission, not while waiting behind another collection.

The contiguous ordinal window bounds unresolved/staged reads. Outcomes and
material accounting follow input order, not completion order. A terminal failure
stops admission, and already started work drains without canceling earlier
ordinals solely because a later read failed. One complete valid candidate is
published; local coherence is not remote transaction isolation. Payload limits
do not bound total heap use, upstream allocations or pinned older generations.

This fragment accepts an already selected reader and two authority-bound
references. It returns a caller-owned handle; disposing the temporary loader
does not invalidate that acquired generation.

```csharp
using SecretKit.Core;
using SecretKit.Extensions.Configuration;

static async Task<SecretSnapshotHandle> PrepareRequiredAsync(
    ISecretReader reader,
    SecretReference username,
    SecretReference password,
    CancellationToken cancellationToken)
{
    using var loader = new SecretSnapshotLoader(
    [
        new SecretSelection("username", reader, username),
        new SecretSelection("password", reader, password)
    ]);
    SecretOutcome<long> result = await loader.RefreshAsync(cancellationToken);
    if (!result.IsSuccess)
        throw new InvalidOperationException($"Required settings: {result.Status}.");
    return loader.Acquire();
}
```

Await this method before registering or starting services that need those values.
For example, within an async startup method with the inputs above:

```csharp
using SecretSnapshotHandle generation = await PrepareRequiredAsync(
    reader, username, password, cancellationToken);
using SecretRead user = generation.Read("username");
using SecretRead credential = generation.Read("password");
// Validate and construct the application dependency here, from this one handle.
// Reveal() is deliberate plaintext access, not required for protected copies.
```

Use a longer-lived loader when the application needs further refreshes. Call
`RefreshAsync` explicitly, inspect its outcome, then `Acquire()` the current
generation. Before the first successful collection, `Acquire()` throws
`InvalidOperationException`; a failed first attempt creates no usable generation.

### Failure and cancellation

Publication requires each present read to succeed with `SecretValidity.Valid`
and every absence to be explicitly optional. Unknown
or other non-valid validity becomes `Invalid`; expired validity becomes `Expired`.
The loader requires the returned observation to retain the exact requested
`SecretReference` object and rechecks all supplied expiry deadlines at collection
completion. A same-authority wrong object, reconstructed reference or foreign
reference is rejected as `Invalid` before copying material. Rejected reads and
partial candidates are disposed, never published; acquired old handles and copies
remain usable.

A failed refresh preserves the previous generation. An unexpected reader
exception becomes `Unavailable` without exposing its message or inner exception.
`LastAttempt` records bounded collection timing, status, retry timing and
cancellation evidence and `Reason`, not values, keys or provider exception text. `RetryAfter`
is evidence for host policy, not an automatic retry instruction.

Cancellation propagates as `OperationCanceledException`, disposes candidate
material and preserves the previous generation. Cancelling a queued collection
does not cancel the one already running; a cancellation before entering collection
does not create a new attempt record. Give remote reads a caller-controlled
deadline. Caller cancellation takes precedence over a collection deadline;
deadline failure is `Unavailable/DeadlineExceeded`. A reader ignoring cancellation
can delay safe drainage; the timeout does not forcibly terminate it. Unexpected
reader cancellation is a sanitized transport failure unless caller/deadline
cancellation is observable. Loader disposal prevents publication and future acquisition, but does
not itself cancel reader I/O or dispose supplied readers/transports.

## Pin one generation, then release each owner

`Acquire()` pins the current generation. `handle.Read(consumerKey)` returns a
`SecretRead` with an independent `SecretMaterial` copy and the actual
`SecretObservation`; dispose every returned read. A key not selected in that
generation throws `ArgumentException`.

`handle.ReadOutcome(consumerKey)` returns an independently owned successful read
or `Absent` for a declared optional absence. Dispose a successful result's value.
`Read` throws a fixed `InvalidOperationException` for absence. Unknown keys and
disposed handles remain misuse. `Count` counts present selections;
`SelectionCount` includes declared absent selections.

Replacing or disposing the loader releases its ownership of the old storage,
but handles keep it alive. Disposing a handle is idempotent and prevents further
reads through that handle; copies already returned remain valid until their own
disposal. Dispose handles promptly rather than retaining retired generations
indefinitely. SDK-owned character buffers clear on final release; this cannot
erase upstream parser strings or caller-created plaintext.

`Generation`, `CollectionStartedAt`, `CollectionCompletedAt`, `Count` and `SelectionCount` describe
the local collected set. Each read retains its observed provider version,
reference and validity metadata. Unknown provider versions remain unknown.
`RemoteSnapshotGuaranteed` is always `false`: serial reads may observe different
remote moments. A local generation is not a provider transaction, native resource
revision or proof that related credentials changed together.

Acquisition and handle reads do not perform fresh remote reads or revalidate age
and expiry. Retaining a previous generation is not permission to use stale
credentials indefinitely. The application must enforce its own age, expiry,
failure and readiness budgets, including during long-running operations.

## Opt into plaintext IConfiguration separately

For one-shot ownership, first await
`PreparedSecretConfiguration.PrepareAsync(selections, options: options,
cancellationToken: cancellationToken)`. On success, dispose the returned owner.
`Read` and `ReadOutcome` provide material-only acquisition. Only an explicit
`ExportAcknowledgingManagedStrings(mapping)` creates the single borrowed root;
the prepared owner disposes root/export before its pinned handle and loader.
Borrowed readers and caller-held read copies retain independent lifetimes.

`SecretConfigurationMapping(consumerKey, configurationKey)` names each exported
key explicitly. Destination keys use **ordinal, case-insensitive** collision
checks before any material is read. Mapping `username` to `Service:User` and
`password` to `service:user` therefore fails even though the consumer keys differ.
There is no automatic secret-name conversion.

Every mapped selection is validated before any material is revealed. A declared
absent optional selection exports an explicit null entry, masking lower-priority
configuration instead of resurrecting an old/default secret. Unselected keys
remain misuse; absence is not an implicit mapping wildcard.

When layering defaults, add the `SecretConfigurationExport` source directly after
the lower-priority providers. `AddConfiguration(preparedRoot)` chains through the
`IConfiguration` indexer and treats null as not found, so it cannot preserve that
explicit-null mask. A prepared root still retains null presence in its own
provider; use the direct export-source API when composing a fallback hierarchy.

Given an acquired `generation` containing the two keys above:

```csharp
using Microsoft.Extensions.Configuration;
using SecretKit.Extensions.Configuration;

using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(
    generation,
    [new("username", "Service:Username"), new("password", "Service:Password")]);
IConfigurationRoot authorityOnly = new ConfigurationBuilder().Add(export).Build();
using var configurationLifetime = (IDisposable)authorityOnly;
// Only explicitly mapped values are present; no environment/file fallback.
```

Preparation happens before attaching the source. `Build`, synchronous `Load`
and `IConfigurationRoot.Reload()` do not call the reader or refresh the loader.
The export owns strings, not the supplied handle; it neither retains nor disposes
that handle. The provider is read-only: setting configuration values throws
`NotSupportedException`.

An export is single-root: exactly one `Build` succeeds, including concurrent
builders. Later builds throw a fixed `InvalidOperationException` without
disposing or changing the winning provider. The slot is consumed when the source
returns its provider, even if a later sibling source fails to build the root.
Dispose the export after that failure; do not retry it in another builder.

For explicit replacement, keep the loader, export and root alive:

```csharp
SecretOutcome<long> refreshed = await loader.RefreshAsync(cancellationToken);
if (refreshed.IsSuccess)
{
    using SecretSnapshotHandle next = loader.Acquire();
    export.ReplaceAcknowledgingManagedStrings(next);
}
// On failure, apply the application's stale-use/readiness policy.
```

Replacement prepares every original mapping, atomically swaps the provider's
string dictionary and signals reload. Missing keys, a disposed handle or another
preparation failure leave previous strings and the reload token unchanged.
Once the dictionary is published, notification cannot roll it back. If a reload
callback throws, replacement throws a fixed `InvalidOperationException` stating
that values were committed but notification failed, with no callback payload or
inner exception. New strings remain committed, including those callbacks already
observed; escaped strings retain their independent lifetimes.
Callbacks execute outside source/provider gates and can reenter reads,
replacement or disposal. Concurrent notifications tell consumers to re-read
current committed state; they do not deliver every intermediate generation.
Separate indexer reads can cross a reload and mix generations. Use one handle
or construct a consumer-owned immutable settings object from one handle when
multi-key coherence matters.

The dedicated root above avoids competing sources. If using a shared root,
deliberately control source order: later providers can override earlier ones.
Do not let environment, command-line or JSON defaults silently replace
authority-controlled keys.

`GetRedactedDebugView()` exposes only a count. Standard configuration debug views,
enumeration, options binding, serializers, logs and dumps can disclose exported
values and coordinates. Disposal of the export or configuration root drops the
provider's dictionary references; it does not erase strings, old options or
consumer fields. Source/root disposal prevents replacement and rebuild, and a
replacement losing to disposal cannot resurrect values. Reload is not proof
that an options consumer or client switched credentials.

## Application activation is a separate step

A published generation is collected material, not an enabled integration.
The application validates its requirements, constructs a candidate dependency
from one handle, performs any authorized bounded connectivity check, then
installs it only if the enable intent is still current. A later disable must
win over an older successful check. Retire old clients after their in-flight
work drains; refresh alone does not replace them.

The executable [bootstrap scenario](../../samples/RuntimeConfiguration/BootstrapScenario.cs)
shows separate required and optional groups, an authority-only export and a
pinned handle across refresh. Its
[RuntimeIntegrationCoordinator](../../samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs)
and [generation lease](../../samples/RuntimeConfiguration/RuntimeGenerationLease.cs)
are **sample/application code, not shipped SDK APIs**. They demonstrate fresh
`CheckAgainAsync` without activation, explicit `EnableAsync`, revision-checked
handover, fail-closed or bounded-last-known policy and lease-based retirement.
They do not supply a durable tenant model, persistence or fleet coordination.

A provider write acknowledgement, a collected generation, an active application
client and readiness evidence are different states. Keep administrative
provisioning separately authorized; neither collection failure nor downstream
activation failure makes a confirmed provider mutation safe to replay or undo.

## Evidence and next steps

Mechanics above are grounded in the linked implementation and these inspectable
tests:

- [ConfigurationTests](../../tests/SecretKit.Configuration.Tests/ConfigurationTests.cs):
  `AcquiredGenerationAndCopiesSurviveReplacementAndOwnerDisposal`,
  `PartialCollectionNeverPublishesAndPreservesBoundedFailure`,
  `QueuedCollectionCancellationCannotReplaceInFlightGeneration`,
  `ValidityDeadlineReachedDuringCollectionFailsClosed`,
  `ExportRejectsCaseInsensitiveMappingCollisionsBeforeReveal`,
  `FailedExportReplacementKeepsPreviousStringsAndDoesNotSignalReload` and
  `SynchronousLoadCannotCollectAndDisposedConfigurationCannotBeRepublished`;
  these tests also cover concurrent/single-use builds, disposal/reload reentry,
  committed notification failures and exact returned-reference rejection.
- [BootstrapAuthorityTests](../../tests/SecretKit.Consumer.Tests/BootstrapAuthorityTests.cs):
  required failure prevents construction; independent optional failure leaves
  the required consumer usable.
- [ActivationRevisionTests](../../tests/SecretKit.Consumer.Tests/ActivationRevisionTests.cs):
  a check does not enable a disabled feature; disable during a read or validation
  prevents late activation.

ConfigurationTests passed locally on 2026-10-27. Other linked suites were not
rerun for this change. Offline contract evidence does not establish remote snapshot,
downstream connectivity, deployment or production qualification.
See [current preview](current-preview.md) for dated evidence and open gates.
Next, compose [authentication and hosting](authentication-and-hosting.md), or
follow the installed [worker](../../samples/Infisical.WorkerDemo/README.md) and
[web](../../samples/Infisical.WebDemo/README.md) examples.
