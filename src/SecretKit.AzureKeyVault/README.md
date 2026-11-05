# SecretKit.AzureKeyVault

Direct Azure Key Vault secret access for .NET 10. Start with an explicitly selected
`AzureKeyVaultClient`, bind references to its authority, and dispose each successful
`SecretRead`. Common reader helpers and `SecretMaterial.Use` / `UseUtf8` are available
through Core. This package does not depend on Infisical or require hosting integration.

See [current support](../../docs/public/provider-support.md) for current offline
evidence and the outstanding Azure live/platform gates.

This provider uses the official `SecretClient` (locked 4.11.2), selecting
2025-07-01 at a fixed trusted HTTPS vault origin. Credentials and injected
transports remain host-owned. SDK logging, tracing and retries are disabled;
challenge-resource verification and response stream bounds remain enabled.
Host-owned credential/transport instrumentation and buffering are outside this
boundary. Offline wire tests are not remote conformance or full SDK coverage.

## Public native API

`AzureKeyVaultClient` retains `ReadAsync`, `InspectAsync` and `SetSecretAsync`.
The native additions are:

- `GetSecretVersionAsync`: requires an exact version and retrieves native
  material plus validity metadata, even when disabled, not-yet-valid or expired
  if the service permits retrieval. Unlike consumption `ReadAsync`, it does not
  reject material solely on local validity. Dispose its `SecretRead`.
- `GetSecretVersionsAsync`: bounded version metadata, using
  `AzureInventoryScope` page/item limits and cancellation for the time budget.
- `UpdatePropertiesAsync`: `AzureUpdatePropertiesRequest` patches an exact
  version's enabled, not-before, expiry, content type and tags, without writing
  its value. Null attributes are omitted, not a request to clear them. Tags are
  copied at request construction. An empty tag map explicitly clears tags through
  a selected request policy that emits the empty object omitted by the SDK.
  No create-only or compare-and-swap
  condition is supported.
- `StartDeleteSecretAsync` and `StartRecoverDeletedSecretAsync`: all-version
  operations requiring an unversioned target and a caller-held `MutationReceipt`.
  An acknowledged, coordinate-validated start returns `AzureLifecycleResult`
  with `Pending` state and a protected local `AzureLifecycleOperation`.
  No availability check is made automatically.
- `CheckLifecycleStatusAsync`: one explicit service availability check on that
  operation. Native 404 after an acknowledged start means still `Pending`;
  matching deleted/recovered metadata is observed `Applied`. Denial, malformed
  coordinates or transport errors are outcomes, not invented pending states.
  Status does not update the start receipt: its `Pending` records the start
  acknowledgement, while the result records the subsequent observation.
- `GetDeletedSecretAsync` and `GetDeletedSecretsAsync`: protected metadata
  including deletion/scheduled-purge dates, never the vendor response's value.
- `PurgeDeletedSecretAsync`: requires a receipt and unversioned target.
  Native 204 is acknowledged `Applied`, not proof of immediate global
  disappearance. Azure enforces purge protection and retention.
- `BackupSecretAsync`: an unversioned, all-version opaque encrypted artifact
  returned as disposable `AzureSecretBackup`.
- `RestoreSecretBackupAsync`: `AzureRestoreSecretRequest` supplies the opaque
  backup and expected unversioned target with a receipt. The artifact, not the
  expected target, selects the service-side name. This is not a rename or a
  guarantee that an imported artifact belongs to the expected name; a foreign
  returned name produces `Unknown` after possible dispatch. Only restore trusted,
  correctly labelled artifacts. Native conflicts are not bypassed or replayed.

All references belong to this particular provider instance. Returned vault,
name, version, identifier paths and recovery coordinates are validated before
publishing native metadata/material. Inventories validate continuation origins,
paths and API revision and report incomplete page/item truncation. Collection
windows are not snapshots; concurrent writes, recovery and expiry can race.

## Receipts, cancellation and ownership

Call `client.CreateReceipt(target)` for the exact target reference before every
mutation. A receipt is consumed once, including when local validation or
cancellation prevents dispatch. It cannot be reused across native or selected
Set operations. Body-bearing mutations and authenticated bodyless mutations
mark `PossiblyDispatched` at the official SDK transport seam, before handing
the request to the injected transport. Unauthenticated Key Vault challenges
cannot apply a mutation. A post-dispatch challenge cannot replay it.

Cancellation propagates with bounded exception text, retaining the receipt.
A lost response remains `Unknown` with possible-dispatch evidence, even if the
service committed. There is no retry, rollback, hidden worker or durable
operation journal. After a lost delete response, an explicit deleted-object
query can observe the current object, but cannot uniquely attribute it to this
caller. Absence is not evidence of pending unless a start was acknowledged.
The same concurrency limitation applies to recovered-version observations.
Permission denials are outcomes for the attempted identity, not capabilities.

`AzureSecretBackup.FromBytes` copies caller bytes. `Copy` owns an independent
buffer; `Export` returns a caller-owned byte-array copy. Disposal zeros only
that owner's buffer and prevents future export/copy. Restore borrows the
caller-owned artifact, exports a temporary private copy, and clears that copy
after the SDK call. It neither disposes nor transfers the caller's artifact.
The backup API clears the returned SDK byte array after making its owned copy.
The SDK/JSON pipeline can create managed strings or other temporary buffers;
this does not promise process-wide erasure.

The configured `maximumResponseBytes` bounds each response body, including
unknown-length streams, and native mutation request bodies at the controlled
send boundary. Base64/JSON overhead counts toward request size. Backup imports
add an absolute 16 MiB storage bound; a provider's smaller configured wire
budget still applies. Page/item limits and cancellation are independent.
Names, versions, vault coordinates, tags and artifacts are excluded from
ordinary JSON/formatting/error outputs. Explicit property access and export
are deliberate disclosure; exports and host instrumentation are host-owned.

## Operation diagnostics

The BCL `ActivitySource` and `Meter` are named `SecretKit.AzureKeyVault`.
Completed spans use `azure.operation`; `azure.operations` counts operations and
`azure.duration` records seconds. Their only tags are `operation`, `outcome`,
`reason`, `dispatch` and `termination`, all drawn from closed SDK categories.
Operations are Read, Inventory, SetSecret, NativeRead, NativeInventory,
NativeMutation, LifecycleCheck and Backup.

Entry captures UTC, a monotonic timestamp and only caller trace/span IDs and
flags, without initializing instruments. Completion freezes elapsed time before
listeners run. Both span and histogram use a minimum of one TimeSpan tick
(100 ns) for zero/subtick intervals; operational cancellation is unchanged.
These completed spans are not parents of earlier HTTP work. Baggage, tracestate,
coordinates, identities, values, bodies and exception prose are not copied.

Failure of optional diagnostic clock capture/completion omits that record; it
cannot replace results, cancellation or cleanup. Operational clocks retain
their own failure semantics.

Termination is Completed (including unsuccessful ordinary results),
CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled or Faulted.
This package owns no shutdown/deadline token, so it does not infer those causes
from caller-supplied cancellation. Listeners run after operation cleanup; throwing
or reentrant callbacks cannot replace results or receipts. Reentrant emission
may be suppressed while the requested operation still executes. Ambient
`Activity.Current` is restored and metrics are attempted independently of
activity callbacks. Host instrumentation and host-added tags remain host-owned.

## Native restore scope and evidence

Azure backups cannot be decrypted outside Azure. Restore is restricted to
the same Azure subscription and geography/region boundary; Azure enforces the
actual permitted placement. The provider does not infer a subscription or
region from a vault hostname or parse opaque bytes to promise portability.
This is not a cross-subscription, cross-region, cross-provider or plaintext
export feature. Permissions, geography, limits, soft-delete and conflicts are
native service constraints.

Official contract sources inspected for public API facts:

- [SecretClient](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.secretclient?view=azure-dotnet)
- [Delete operation](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.deletesecretoperation?view=azure-dotnet)
- [Recovery operation](https://learn.microsoft.com/en-us/dotnet/api/azure.security.keyvault.secrets.recoverdeletedsecretoperation?view=azure-dotnet)
- [Backup restrictions](https://learn.microsoft.com/en-us/azure/key-vault/general/backup)

Provider credentials, live subscriptions/regions/clouds, native retention and
purge policy, real permission propagation and installed-package conformance
remain unverified. Root coverage registries and release claims are outside
this provider-local implementation scope.
