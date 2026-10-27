# Configuration and runtime

> **Audience:** .NET application developers, operators and AI coding assistants
> **Status:** Implemented composition APIs; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against source and tests; no checks rerun
> **Source anchors:** [Loader](../../src/SecretKit.Extensions.Configuration/SecretSnapshotLoader.cs), [selection](../../src/SecretKit.Extensions.Configuration/SecretSelection.cs), [handle](../../src/SecretKit.Extensions.Configuration/SecretSnapshotHandle.cs), [export](../../src/SecretKit.Extensions.Configuration/SecretConfigurationExport.cs)

Use `SecretKit.Extensions.Configuration` to collect required values asynchronously
and pin one local generation for a multi-key operation. Export to `IConfiguration`
only when ordinary plaintext strings are acceptable. The package does not choose
an identity, install refresh policy, start a worker or activate application clients.
Core/provider reads do not require this optional package.

## Select required groups explicitly

Each `SecretSelection(consumerKey, reader, reference)` binds an application key to
one `ISecretReader` and a `SecretReference` belonging to that reader's authority.
An authority mismatch throws during selection construction. A loader requires
at least one selection, copies the selection list and rejects duplicate consumer
keys with **ordinal, case-sensitive** comparison. `Password` and `password` are
different consumer keys; reads through a handle require the exact spelling.

Every selection in a loader is required. There is no optional flag, fallback
principal or local-default rescue path. Put startup-required settings in one
loader and each independent optional feature's required settings in another.
Failure of an optional group can leave that feature disabled without invalidating
the already prepared startup group. This is application policy, not a different
loader mode.

Use references and readers selected by trusted application configuration. An
administrative read does not prove delivery to the intended runtime identity.
The [provider guides](providers/infisical.md) describe native references;
[Azure Key Vault](providers/azure-key-vault.md) and
[management](providers/management.md) have distinct identity boundaries.

## Await collection before constructing dependent services

`RefreshAsync(CancellationToken)` performs the selected reads serially and
serializes concurrent collections on the same loader. It returns
`SecretOutcome<long>`: success contains the newly published local generation
number; failure contains `Status` and optional `RetryAfter`.

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

Publication requires every read to succeed with `SecretValidity.Valid`. Unknown
or other non-valid validity becomes `Invalid`; expired validity becomes `Expired`.
The loader checks returned authority and rechecks all supplied expiry deadlines
at collection completion. A partial candidate is disposed, never published.

A failed refresh preserves the previous generation. An unexpected reader
exception becomes `Unavailable` without exposing its message or inner exception.
`LastAttempt` records bounded collection timing, status, retry timing and
cancellation evidence, not values, keys or provider exception text. `RetryAfter`
is evidence for host policy, not an automatic retry instruction.

Cancellation propagates as `OperationCanceledException`, disposes candidate
material and preserves the previous generation. Cancelling a queued collection
does not cancel the one already running; a cancellation before entering collection
does not create a new attempt record. Give remote reads a caller-controlled
deadline. Loader disposal prevents publication and future acquisition, but does
not itself cancel reader I/O or dispose supplied readers/transports.

## Pin one generation, then release each owner

`Acquire()` pins the current generation. `handle.Read(consumerKey)` returns a
`SecretRead` with an independent `SecretMaterial` copy and the actual
`SecretObservation`; dispose every returned read. A key not selected in that
generation throws `ArgumentException`.

Replacing or disposing the loader releases its ownership of the old storage,
but handles keep it alive. Disposing a handle is idempotent and prevents further
reads through that handle; copies already returned remain valid until their own
disposal. Dispose handles promptly rather than retaining retired generations
indefinitely. SDK-owned character buffers clear on final release; this cannot
erase upstream parser strings or caller-created plaintext.

`Generation`, `CollectionStartedAt`, `CollectionCompletedAt` and `Count` describe
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

`SecretConfigurationMapping(consumerKey, configurationKey)` names each exported
key explicitly. Destination keys use **ordinal, case-insensitive** collision
checks before any material is read. Mapping `username` to `Service:User` and
`password` to `service:user` therefore fails even though the consumer keys differ.
There is no automatic secret-name conversion.

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
  `SynchronousLoadCannotCollectAndDisposedConfigurationCannotBeRepublished`.
- [BootstrapAuthorityTests](../../tests/SecretKit.Consumer.Tests/BootstrapAuthorityTests.cs):
  required failure prevents construction; independent optional failure leaves
  the required consumer usable.
- [ActivationRevisionTests](../../tests/SecretKit.Consumer.Tests/ActivationRevisionTests.cs):
  a check does not enable a disabled feature; disable during a read or validation
  prevents late activation.

These are implementation/offline contract evidence, not new test-run results or
remote snapshot, downstream connectivity, deployment or production qualification.
See [current preview](current-preview.md) for dated evidence and open gates.
Next, compose [authentication and hosting](authentication-and-hosting.md), or
follow the installed [worker](../../samples/Infisical.WorkerDemo/README.md) and
[web](../../samples/Infisical.WebDemo/README.md) examples.
