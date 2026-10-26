# Azure Key Vault secret data plane

> **Audience:** .NET developers and AI coding assistants using `SecretKit.AzureKeyVault`
> **Status:** Implemented/offline-tested subset; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; Azure live behavior unverified
> **Source anchors:** [client](../../../src/SecretKit.AzureKeyVault/AzureKeyVaultClient.cs), [native lifecycle](../../../src/SecretKit.AzureKeyVault/AzureNativeLifecycle.cs), [tests](../../../tests/SecretKit.AzureKeyVault.Tests/)

`AzureKeyVaultClient` owns secret **data-plane** reads, writes and lifecycle.
Vault provisioning, policies, role assignments and notification configuration
belong to [management](management.md#azure-administration). Audit queries use
[separate monitoring authority](management.md#azure-audit). None of these planes
proves another identity's runtime delivery.

## Construction and selection

Signature reference:

```csharp
AzureKeyVaultClient(Uri vaultUri, TokenCredential credential,
    HttpPipelineTransport? transport = null, TimeProvider? timeProvider = null,
    int maximumResponseBytes = 1024 * 1024)
```

The client uses the official Azure `SecretClient`, selecting service revision
`2025-07-01`. `vaultUri` must be a trusted HTTPS vault origin, default port,
without user information, path prefix, query or fragment. The runtime adapter
accepts public, US government and China vault hostname forms; that syntax
acceptance is not sovereign-cloud qualification. Private networking retains the
normal vault DNS name and TLS validation.

The supplied `TokenCredential` and optional transport stay host-owned.
SDK retries, logging, content logging and distributed tracing are disabled.
Challenge-resource verification remains enabled. The host must secure any
supplied transport and its instrumentation. Response bodies and native mutation
bodies are bounded by `maximumResponseBytes` (1 KiB..16 MiB).

`AzureSecretAddress(name, version: null)` selects latest material; a version
selects an exact native version. Names contain 1..127 ASCII letters, digits or
hyphens; versions contain exactly 32 hexadecimal characters. Bind addresses
with `new SecretReference(client.Authority, address)`; references cannot cross
client instances even when vault/name match.

## Common reads and version semantics

`ReadAsync(reference, cancellationToken)` is consumption: it checks validity
and rejects disabled, not-yet-valid or expired material. `InspectAsync(scope,
cancellationToken)` is value-free latest-version metadata inventory.
`AzureInventoryScope(client.Authority, maximumPages: 10, maximumItems: 1000)`
accepts 1..1,000 pages and 1..10,000 items. Use caller cancellation for the time
budget. Collections are not transactional snapshots.

`GetSecretVersionAsync` requires an exact version and may return disabled or
expired material with its validity metadata if Azure permits retrieval. It does
not bypass server authorization; it deliberately differs from consumption.
Dispose each successful `SecretRead`. Returned vault/name/version/identifier
coordinates and continuation origin/path/revision are validated before exposure.

## API owner map

Every method below is on `AzureKeyVaultClient`.

| Family | Methods and input | Semantics |
| --- | --- | --- |
| Common reads | `ReadAsync(SecretReference, ...)`, `InspectAsync(SecretInventoryScope, ...)` | Consumption validity checks; value-free bounded inventory. |
| Version-creating write | `SetSecretAsync(AzureSetSecretRequest, MutationReceipt, ...)` | Unversioned target; creates a new version and returns `AzureSetSecretResult.Reference` for the validated new version. |
| Native version reads | `GetSecretVersionAsync(target, ...)`, `GetSecretVersionsAsync(target, AzureInventoryScope, ...)` | Exact version for material retrieval; unversioned target for version metadata enumeration. |
| Metadata patch | `UpdatePropertiesAsync(AzureUpdatePropertiesRequest, MutationReceipt, ...)` | Exact version only; enabled/not-before/expiry/content type/tags, without changing the value. |
| All-version lifecycle | `StartDeleteSecretAsync(target, receipt, ...)`, `StartRecoverDeletedSecretAsync(target, receipt, ...)`, `CheckLifecycleStatusAsync(AzureLifecycleOperation, ...)` | Unversioned target; acknowledged start is pending; status check is explicit. |
| Deleted metadata | `GetDeletedSecretAsync(target, ...)`, `GetDeletedSecretsAsync(AzureInventoryScope, ...)` | Unversioned selection; no deleted value export. |
| Purge | `PurgeDeletedSecretAsync(target, receipt, ...)` | Unversioned; native acknowledgement, with Azure retention/purge protection authoritative. |
| Backup/restore | `BackupSecretAsync(target, ...)`, `RestoreSecretBackupAsync(AzureRestoreSecretRequest, receipt, ...)` | Unversioned all-version opaque artifact; restore requires expected target and receipt. |

Sources: [write request/result](../../../src/SecretKit.AzureKeyVault/AzureSetSecret.cs),
[address/scope](../../../src/SecretKit.AzureKeyVault/AzureSecretAddress.cs),
[native inputs/results](../../../src/SecretKit.AzureKeyVault/AzureNativeModels.cs).

### Make one selected write

This integration function declares all inputs and gives the caller its receipt
before asynchronous work begins. It does not obtain credentials or perform
retries. The caller owns the supplied client and material.

```csharp
using System.Threading;
using System.Threading.Tasks;
using SecretKit.Core;
using SecretKit.AzureKeyVault;

static ValueTask<SecretOutcome<AzureSetSecretResult>> SetAsync(
    AzureKeyVaultClient client, string name, SecretMaterial material,
    out MutationReceipt receipt, CancellationToken deadline)
{
    var target = new SecretReference(client.Authority,
        new AzureSecretAddress(name));
    receipt = new MutationReceipt(target);
    var request = new AzureSetSecretRequest(target, material);
    return client.SetSecretAsync(request, receipt, deadline);
}
```

Retain the `out` receipt even if awaiting the returned operation throws
cancellation. Check the outcome before accessing `Value`.
`AzureSetSecretPrecondition.CreateOnly` and `MatchVersion` are unsupported:
SetSecret is not CAS and a preceding read cannot supply that guarantee.

### Metadata omission and empty tags

`AzureUpdatePropertiesRequest(target, enabled: null, notBefore: null,
expiresOn: null, contentType: null, tags: null, precondition: None)` copies tags
at construction. Null fields are omitted, not cleared. An **empty dictionary**
explicitly clears tags; a selected request policy emits `{}` because the pinned
SDK otherwise omits it. Metadata input has a 64 KiB local envelope budget and at
most 128 tags. This is current source behavior even where an older source README
describes empty tags as unsupported.

Evidence:
[NativeLifecycleTests](../../../tests/SecretKit.AzureKeyVault.Tests/NativeLifecycleTests.cs),
especially `EmptyTagsAreExplicitlyClearedWithoutWritingMaterial` and
`EmptyTagClearDenialAndLostResponseCannotReplay`. These are controlled
observations, not live tag-clearing certification.

## Lifecycle, receipts and uncertainty

Create a fresh `MutationReceipt` bound to the exact target before each mutation.
Azure consumes receipts once, including local validation/cancellation failures.
Authenticated dispatch records `PossiblyDispatched`; unauthenticated Key Vault
challenges do not establish mutation dispatch. Cancellation propagates while
receipt evidence survives. A lost committed response is not automatically
replayed or attributed through a later read.

Delete/recover starts return `AzureLifecycleResult` with `Pending` and an
in-memory operation handle. `CheckLifecycleStatusAsync` performs one explicit
availability check: native 404 after an acknowledged start remains pending;
matching deleted/recovered metadata is observed applied. Denial, malformed
coordinates and transport errors remain outcomes. The original receipt records
the start acknowledgement, not the later status. After a lost start response,
absence alone is not proof of pending; a later object observation cannot uniquely
attribute a concurrent operation to this caller.

Purge acknowledgement is not immediate global disappearance. SecretKit does not
weaken Azure retention, purge protection, conflicts or server permissions.
There is no hidden poller, durable operation journal or rollback.

## Backup ownership and restore limitations

Dispose `AzureSecretBackup`. `FromBytes` copies input; `Copy` creates an
independent owner; `Export` creates a caller-owned byte-array copy. Imports have
an absolute 16 MiB storage bound and still obey the client's smaller wire budget,
including Base64/JSON overhead.

`AzureRestoreSecretRequest` borrows the artifact; it does not dispose or transfer
the caller's backup. The opaque artifact, **not the expected target**, chooses
the service-side name. A foreign returned name is `Unknown` after possible
dispatch, not a safe rename. Restore only trusted, correctly labelled artifacts.
Azure enforces allowed subscription/geography placement; SecretKit does not
infer region/subscription from a hostname or promise cross-region/provider
portability.

Disposal clears owned buffers, not every SDK/parser string, exported copy or
host log. Coordinates, tags and artifacts are sensitive even when no secret
value is present. See [operations](../operations-and-compatibility.md).

## Evidence and gaps

[AzureSetSecretTests](../../../tests/SecretKit.AzureKeyVault.Tests/AzureSetSecretTests.cs)
and [NativeLifecycleTests](../../../tests/SecretKit.AzureKeyVault.Tests/NativeLifecycleTests.cs)
exercise actual SDK transport boundaries, scope validation, independent metadata
readback, lifecycle status, cancellation, lost responses and no replay.
Remote permissions, propagation, regions/clouds, retention behavior and backup
placement still require owned native qualification. Keys, certificates and HSM
operations are outside this secret data-plane surface. Consult
[current support](../provider-support.md) before making deployment claims.
