# Azure Key Vault secret data plane

> **Audience:** .NET developers and AI coding assistants using `SecretKit.AzureKeyVault`
> **Status:** Implemented/offline-tested subset; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-11-21, source inspection of `AzureKeyVaultClient` and `AzureNativeLifecycle`; Azure live behavior unverified
> **Source anchors:** [client](../../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs), [native lifecycle](../../../src/SecretKit.AzureKeyVault/Lifecycle/AzureNativeLifecycle.cs), [tests](../../../tests/SecretKit.AzureKeyVault.Tests/)

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
    int maximumResponseBytes = 1024 * 1024, TimeSpan? operationTimeout = null)
```

The client reuses one official Azure `SecretClient` with the pinned SDK's default
service version. Continuations must match the initial SDK request's revision.
`vaultUri` must be a trusted HTTPS vault origin, default port,
without user information, path prefix, query or fragment. The runtime adapter
accepts public, US government and China vault hostname forms; that syntax
acceptance is not sovereign-cloud qualification. Private networking retains the
normal vault DNS name and TLS validation.

Accepted suffixes are `.vault.azure.net`, `.vault.usgovcloudapi.net` and
`.vault.azure.cn`. The data-plane SDK retains challenge-resource verification;
it does not reuse the ARM or Logs audience. Management and monitoring have their
own explicit [cloud selections](management.md#arm-and-audit-cloud-selection).
Current deployment posture is JIT/net10.0, with no sovereign, trimming or Native
AOT qualification implied by hostname acceptance.

The supplied `TokenCredential` and optional transport stay host-owned.
SDK retries, logging, content logging and distributed tracing are disabled.
Challenge-resource verification remains enabled. The host must secure any
supplied transport and its instrumentation. Response bodies and native mutation
bodies are bounded by `maximumResponseBytes` (1 KiB..16 MiB).
The optional `operationTimeout` bounds one public operation cooperatively,
including credential acquisition. Caller cancellation still propagates.
Hostname, coordinate and material bounds are SecretKit admission policies;
they do not describe every input the provider might accept.

`AzureSecretAddress(name, version: null)` selects latest material; a version
selects an exact native version. Names contain 1..127 ASCII letters, digits or
hyphens; versions contain exactly 32 hexadecimal characters. Bind addresses
with `new SecretReference(client.Authority, address)`; references cannot cross
client instances even when vault/name match.

## Select a credential

SecretKit references Azure.Core's `TokenCredential`, not Azure.Identity. The
host chooses one credential type, installs its package and owns its
configuration, cache and disposal. SecretKit does not test these credential
types, and live Azure sign-in behavior is unverified here.

Select one credential explicitly. A discovery chain such as
`DefaultAzureCredential` picks an identity from the environment, which conflicts
with SecretKit's rule that authority is selected, never inferred.

For interactive operator tools, such as ISLAMU Configurator's desktop and
terminal clients ([ADR-006](../../internal/adr/ADR-006-configurator-provisioning-and-credential-sources.md)):

- **Browser or device-code sign-in:** `InteractiveBrowserCredential` or
  `DeviceCodeCredential` with the operator organization's **own** Entra
  public-client ID and tenant. Without a client ID, Azure.Identity uses a
  development application that Microsoft does not recommend for production.
  A persisted token cache refuses unprotected storage unless
  `UnsafeAllowUnencryptedStorage` is set; keep that protection.
- **Existing Azure CLI login:** `AzureCliCredential`, chosen explicitly by the
  operator. It runs `az account get-access-token` in a subprocess and returns
  only an access token. This helps in tenants that block consent to new
  applications, because the Azure CLI is a pre-approved Microsoft application.
  The CLI never handles secret values in this composition, and SecretKit itself
  never launches it.

Workloads keep using their deployment's managed identity or workload credential,
selected the same explicit way.

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

Sources: [write request/result](../../../src/SecretKit.AzureKeyVault/Secrets/AzureSetSecret.cs),
[address/scope](../../../src/SecretKit.AzureKeyVault/Secrets/AzureSecretAddress.cs),
[native inputs/results](../../../src/SecretKit.AzureKeyVault/Lifecycle/AzureNativeModels.cs).

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
    receipt = client.CreateReceipt(target);
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
most 128 tags.

Evidence:
[NativeLifecycleTests](../../../tests/SecretKit.AzureKeyVault.Tests/NativeLifecycleTests.cs),
especially `EmptyTagsAreExplicitlyClearedWithoutWritingMaterial` and
`EmptyTagClearDenialAndLostResponseCannotReplay`, plus
`EmptyTagClearCancellationKeepsTheObservedUncertainEffect`. The
[selected policy](../../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs)
emits the empty object; `SdkOmitsEmptyTagsEvenAfterExplicitClear` characterizes
the pinned SDK's omission. These are controlled
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

## Comparison with direct `SecretClient`

| Concern | Direct `Azure.Security.KeyVault.Secrets.SecretClient` | `SecretKit.AzureKeyVault` (`AzureKeyVaultClient`) |
| --- | --- | --- |
| Identity default | Commonly paired with `DefaultAzureCredential` probing chains | Explicit `TokenCredential` only; no credential probing |
| Scope isolation | Caller owns vault/name checks | `SecretAuthority` (`ReferenceEquals`) prevents cross-client reference mix-ups |
| SDK retries & diagnostics | Enabled by default (retries can duplicate `SetSecret` versions) | `Retry.MaxRetries = 0` and SDK logging/tracing disabled; `MutationReceipt` tracks uncertain dispatches |
| Consumption validity | Returns expired and `NotBefore`-future secrets unless checked manually | `ReadAsync` rejects disabled, not-yet-valid and expired secrets |
| Empty tag clearing | Pinned `SecretClient` `4.11.2` omits `{}` for empty tag maps | `EmptyTagsPolicy` emits `"tags": {}` to clear tags |
| Generation rotation | `AddAzureKeyVault` uses timer string reloads into `IConfiguration` | Composes with `SecretSnapshotLoader` and `SecretGenerationCoordinator<TClient>` |
| Keys, certificates, HSM | Supported via sibling `Azure.Security.KeyVault.*` packages | Out of scope (secret values and metadata only) |

## Known preview limitations and gaps

Inspect these source-level boundaries before adopting `SecretKit.AzureKeyVault`
in an Azure-only codebase:

- **No zero-string or NativeAOT edge yet:** Because `AzureKeyVaultClient` wraps
  `SecretClient`, reads materialize `KeyVaultSecret.Value` as a `string` before
  `SecretMaterial.FromText` ([AzureKeyVaultClient.cs](../../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs#L316))
  and writes call `Reveal()` ([line 215](../../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs#L215)).
  Neither Azure package sets `<IsAotCompatible>true</IsAotCompatible>`.
- **No Hosting package integration:** `SecretKit.Extensions.Hosting` depends on
  `SecretKit.Infisical` and does not currently register or refresh Azure Key
  Vault runtimes.
- **Uncertain mutation outcomes:** Actual service responses with status
  `400`, `403`, `404` or `409` establish rejection or conflict. A transport
  exception, post-dispatch `401`, `429` or server failure remains uncertain
  and never authorizes replay.
- **Lifecycle observation authority:** Delete and recovery checks use bounded
  metadata inventories, without fetching secret values. Denial remains denial;
  incomplete enumeration remains unknown. The observer needs the corresponding
  metadata-list permissions even when value reads are permitted.
- **Unverified live Azure behavior:** No live Azure Key Vault data-plane,
  lifecycle, or management suite has executed against an Azure tenant.
