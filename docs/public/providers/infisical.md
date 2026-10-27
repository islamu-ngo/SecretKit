# Infisical runtime and native APIs

> **Audience:** .NET developers and AI coding assistants using `SecretKit.Infisical`
> **Status:** Implemented subsets; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; not a new live run
> **Source anchors:** [client](../../../src/SecretKit.Infisical/InfisicalClient.cs), [addresses](../../../src/SecretKit.Infisical/InfisicalSecretAddress.cs), [tests](../../../tests/SecretKit.Infisical.Tests/)

Use `InfisicalClient` for common secret reads, direct-folder inventory, selected
shared-secret writes and the native organization/import operations below. Use
the separate dynamic and rotation clients for their native lifecycle contracts.
Administration factories live in [the management package](management.md).

## Construct a client and bind an address

The read-client constructor is:

```csharp
InfisicalClient(Uri origin, IInfisicalTokenSource tokens,
    InfisicalNetworkOptions? network = null, TimeProvider? timeProvider = null)
```

This is a signature reference, not a standalone statement. The fixed origin
has no credentials, path prefix, query or fragment. Safe mode requires HTTPS or
explicit `AllowLoopbackDevelopmentHttp`. Select an arbitrary host pipeline with
`network.Transport = InfisicalTransportOptions.HostControlled(clientOrHandler)`;
it also admits HTTP and retains the host's TLS/routing/retry/diagnostic policy.
Omission selects `SafeDefault`. The host owns the token source and any supplied
client/handler; SDK disposal does not dispose or reconfigure them.

`InfisicalSecretAddress(projectId, environment, folder, key, version: null,
resolution: InfisicalResolution.Raw, includeImports: false)` selects a shared
secret. Folder paths must be absolute without `.`/`..` segments; a supplied
version must be positive. Bind it with
`new SecretReference(client.Authority, address)`. The authority is local
client ownership, not proof of server permission.

This integration function declares every input. The caller supplies an already
selected token source and consumes/disposes a successful result; it never logs
material:

```csharp
using System;
using System.Threading;
using System.Threading.Tasks;
using SecretKit.Core;
using SecretKit.Infisical;

static async ValueTask<SecretOutcome<InfisicalSecretRead>> ReadRawAsync(
    Uri trustedOrigin, IInfisicalTokenSource runtimeTokens,
    string projectId, string environment, string folder, string key,
    CancellationToken deadline)
{
    await using var client = new InfisicalClient(trustedOrigin, runtimeTokens);
    var target = new SecretReference(client.Authority,
        new InfisicalSecretAddress(projectId, environment, folder, key));
    return await client.ReadNativeAsync(target, deadline);
}
```

A returned material owner outlives client disposal. Check `IsSuccess` before
accessing `Value`; dispose `Value` when successful. Provider failures are bounded
`SecretOutcome<T>` values; cancellation propagates as cancellation.

## Raw revision versus resolved material

`ReadNativeAsync(reference, cancellationToken)` returns disposable
`InfisicalSecretRead` containing `Material`, `Observation` and an opaque
`InfisicalSecretRevision`. It qualifies only **Raw, non-imported** reads.
Expanded references or `IncludeImports=true` return `Invalid` on this API.
Use common `ReadAsync` when deliberately requesting provider-resolved material;
its observed numeric version is not a revision of all resolved dependencies.

Qualified responses must return matching `workspace`, `environment`,
`secretPath`, `type`, `secretKey`, resource `id`, positive integral `version`
and explicit material visibility. Missing/malformed required evidence is
`Unknown`, contradictory coordinates are `Invalid`, and hidden material is
`Denied`. There is no `_id` fallback or substitution of request coordinates.

Revision equality includes trusted origin, project/environment/folder namespace,
resource ID and version. It survives client replacement but distinguishes
deletion/recreation even when both objects have version 1. It does not make
client-bound references interchangeable, provide CAS, or describe import/reference
dependency changes. Source:
[revision](../../../src/SecretKit.Infisical/InfisicalSecretRevision.cs);
evidence: [InfisicalRevisionTests](../../../tests/SecretKit.Infisical.Tests/InfisicalRevisionTests.cs).

`InspectAsync(new InfisicalInventoryScope(client.Authority, projectId,
environment, folder, maximumItems: 1000), cancellationToken)` returns value-free
direct-folder metadata, without recursion, expansion or lease acquisition.
The scope accepts 1..10,000 items; completeness is an observation, not a snapshot.
Foreign scope and duplicate returned names are rejected.

## Selected shared-secret mutations

`CreateAsync(target, material, receipt, cancellationToken)` and
`UpdateValueAsync(target, material, receipt, cancellationToken)` require an
unversioned Raw address with imports disabled. They use the client's selected
token source; they do not require the separate native administration authority.
Input material remains caller-owned and is copied before token/network awaits.

Create a `MutationReceipt(target)` **before** calling. Retain it even if the call
throws cancellation. A valid applied response returns
`InfisicalStaticChange.Disposition = Applied`; an approval response returns
`SubmittedForApproval`, no applied version, and receipt evidence `Pending`.
The latter is not delivery. A lost response after possible dispatch is `Unknown`
with `PossiblyDispatched`; never blindly retry it. No compare-and-swap or
application activation is performed. See
[implementation](../../../src/SecretKit.Infisical/InfisicalStaticChanges.cs) and
[mutation tests](../../../tests/SecretKit.Infisical.Tests/InfisicalMutationTests.cs).

## Native API owner map

All methods in the first five rows are on `InfisicalClient`. Native addresses
derive from `InfisicalNativeAddress` and are bound through `SecretReference`.
Their mutations require a target-bound `MutationReceipt` plus
`InfisicalNativeAuthority(client.Authority, administrativeTokens, projectId,
environment: null, folder: null)`. This explicitly selects administrative
credentials and optional narrower scope; it never silently uses runtime tokens.
Folder restriction requires an environment.

| Family / source owner | Actual methods | Address and important constraints |
| --- | --- | --- |
| [Environments](../../../src/SecretKit.Infisical/Organization.cs) | `GetEnvironmentAsync`, `CreateEnvironmentAsync`, `UpdateEnvironmentAsync`, `DeleteEnvironmentAsync`, `RestoreEnvironmentAsync` | `InfisicalEnvironmentAddress(projectId, selector, selection)`, ID or slug; creation requires slug selection. Hard delete is explicit. |
| [Tags and folders](../../../src/SecretKit.Infisical/Organization.cs) | `ListTagsAsync`, `GetTagAsync`, `CreateTagAsync`, `UpdateTagAsync`, `DeleteTagAsync`; `ListFoldersAsync`, `GetFolderAsync`, `CreateFolderAsync`, `UpdateFolderAsync`, `DeleteFolderAsync`, `UpdateFoldersAsync`, `MoveFolderAsync` | `InfisicalTagAddress`; `InfisicalFolderAddress(projectId, environment, environmentId, parentPath, id, name)` requires known environment ID. Get/update require folder ID; create requires name. Moves must be covered at both scopes; batches share one project/environment/parent. |
| [Imports](../../../src/SecretKit.Infisical/Imports.cs) | `ListImportsAsync`, `GetImportAsync`, `CreateImportAsync`, `UpdateImportAsync`, `DeleteImportAsync`, `ReadImportedSecretsAsync` | `InfisicalImportAddress(projectId, environment, folder, folderId, importId)` requires known destination folder ID. `InfisicalImportSource` selects environment/path and optional source project. Dispose imported material results. |
| [Bulk secrets](../../../src/SecretKit.Infisical/NativeBulk.cs) | `CreateSecretsAsync`, `UpdateSecretsAsync`, `DeleteSecretsAsync` | `InfisicalBulkAddress` plus `InfisicalBulkSecret` rows. At most 128 inputs, no duplicate correlation. Create/update are shared-secret subsets; delete also supports personal. `Ignore`, `Upsert`, `FailOnNotFound` are update modes, not atomic preconditions. |
| [Validation](../../../src/SecretKit.Infisical/ValidationPolicies.cs) | `ListValidationRulesAsync`, `GetValidationRuleAsync`, `CreateValidationRuleAsync`, `UpdateValidationRuleAsync`, `DeleteValidationRuleAsync` | `InfisicalValidationAddress` selects static, dynamic or rotation policy. `InfisicalValidationInput` preserves omission versus supported explicit clears; regexes execute at the provider, not locally. |
| [Dynamic definitions and leases](../../../src/SecretKit.Infisical/InfisicalDynamicClient.cs) | `Definition`, `ListDefinitionsAsync`, `InspectDefinitionAsync`, `CreateDefinitionAsync`, `UpdateDefinitionPolicyAsync`, `UpdateDefinitionAsync`, `DeleteDefinitionAsync`; `ListLeasesAsync`, `InspectLeaseAsync`, `AcquireDatabaseAsync`, `RenewAsync`, `RenewLeaseAsync`, `RevokeAsync`, `RevokeLeaseAsync` | Separate `InfisicalDynamicClient`; typed profile/definition/lease targets and `InfisicalDynamicMutationReceipt`, not Core mutation receipts. |
| [Rotation execution](../../../src/SecretKit.Infisical/InfisicalRotationClient.cs) | `ListAsync`, `GetAsync`, `RotateSecretsAsync`, `SetAutomaticRotationAsync` | Separate `InfisicalRotationClient`; `InfisicalRotationScope`/`InfisicalRotationAddress` and `InfisicalRotationReceipt`. Configuration CRUD belongs to management. |
| [Authentication](../../../src/SecretKit.Infisical/InfisicalUniversalAuthentication.cs) and [proof exchanges](../../../src/SecretKit.Infisical/InfisicalProofAuthentication.cs) | `InfisicalUniversalAuthentication.LoginAsync`; `InfisicalProofAuthentication.LoginAsync`, `CreateRevocationReceipt`, `RevokeTokenAsync`; `InfisicalPeriodicTokenSession.GetTokenAsync`, `RenewAsync`, `StopAsync` | Host-supplied credentials/proofs; no issuer discovery or fallback identity. See [authentication guide](../authentication-and-hosting.md) for construction, receipts and lifetime evidence. |

Native lists carry `IsComplete`; typical organization/import/validation lists
accept 1..1,000 retained items. Imported group boundaries and order are preserved;
`Items` concatenates them without selecting a winner. Bulk observations retain
per-input evidence. Without known destination folder identity, an approval
cannot safely be correlated; cross-folder per-row path overrides are unsupported.
There is no cross-row transaction or rollback.

### Imports do not prove replication or delivery

`ObserveImportEffectsAsync(importReference, intendedClient,
destinationReference, cancellationToken)` makes a fresh import observation and
a fresh read as the explicitly supplied intended client. Administrative visibility
and intended delivery retain independent statuses.
`InfisicalImportEffectObservation.Destination` remains `Unknown`: replication
success metadata does not establish a destination approval/merge contract.
Provider-side expansion, import precedence and grants remain server-owned;
SecretKit does not recursively resolve references or emulate permissions.
See [effect implementation](../../../src/SecretKit.Infisical/ImportEffectObservation.cs)
and [ImportEffectTests](../../../tests/SecretKit.Infisical.Tests/ImportEffectTests.cs).

### Dynamic definitions are broader than credential acquisition

Construct `InfisicalDynamicClient(origin, tokens, scope, network: null,
timeProvider: null, maximumItems: 128)`. Its
`InfisicalDynamicScope(projectSlug, environmentSlug, path, folderId)` uses slugs
and a known folder GUID, not the static read's project-ID address.
Targets come from `client.Definition(name)`. Network selection uses the same
safe or explicit host-controlled contract as reads and authentication.

Typed [definition profiles](../../../src/SecretKit.Infisical/NativeDynamicProfiles.cs)
and [profile options](../../../src/SecretKit.Infisical/NativeDynamicProfileOptions.cs)
cover the `InfisicalDynamicProvider` choices, including SQL, cloud, directory,
messaging and other native profiles. This is input-schema support, not permission
or downstream qualification for every profile. `AcquireDatabaseAsync` accepts
only `SqlDatabase` and the exact `DB_USERNAME`/`DB_PASSWORD` result shape; other
provider result contracts return `ContractNotEstablished`.

Dispose `InfisicalDatabaseLease` and each `CopyCredentials()` result. Renewal uses
returned expiry, not an invented extension. Expiry/explicit revocation prevents
further credential consumption through governed copies; disposal alone releases
local material and does not revoke remotely. Retain `lease.Reference` if explicit
`RevokeLeaseAsync` cleanup is needed after disposal. A deletion acknowledgement has
`ExternalRevocationVerified=false`; it does not prove database sessions or
fixed-expiry external credentials are unusable.
Evidence: [LeaseLifecycleTests](../../../tests/SecretKit.Infisical.Tests/LeaseLifecycleTests.cs),
[DynamicDefinitionTests](../../../tests/SecretKit.Infisical.Tests/DynamicDefinitionTests.cs).

### Rotation trigger acceptance is not completion

Construct `InfisicalRotationClient(trustedOrigin, authority, administration,
network: null)` with a matching `InfisicalNativeAuthority`. It defaults to safe
networking; `network.MaximumResponseBytes` selects the byte budget and
`network.Transport` selects any explicit host-controlled pipeline. Construction
performs no I/O. Dispose the rotation client to release its SDK-owned resources.
`InfisicalRotationAddress` selects project, environment, path, native profile
and rotation UUID. The profile enum routes existing operations; it does not
provide configuration schemas for every profile.

Create `InfisicalRotationReceipt(target, action)` before a trigger/enablement
mutation. Trigger acknowledgement is `AcceptedPending`; automatic-rotation
setting acknowledgement is `AutomaticRotationSettingApplied`. Later `GetAsync`
is a fresh observation, not reconciliation of that trigger. Open native status
strings, job IDs and timestamps are not completion attribution.
`RequireCompareAndSwap` and `RequireIdempotency` preconditions are unsupported.
`ConsumerDeliveryVerified` and `FleetConvergenceVerified` remain false.
Evidence: [RotationOutcomeTests](../../../tests/SecretKit.Infisical.Tests/RotationOutcomeTests.cs).

## Transport and remaining gaps

All native entrypoints default to `SafeDefault`: normal HTTPS validation,
no redirects/cookies/propagation, no ambient proxy or SDK replay. Select private
issuers with `SafeWithPrivateTrust(roots)` and an explicit proxy with
`network.Proxy`. Private trust copies public certificate data and retains
hostname/chain checks with the normal handler no-revocation-lookup default.
`HostControlled(clientOrHandler)` is deliberately arbitrary networking, not an
SDK-enforced TLS or no-retry guarantee. Keep host configuration stable; do not
combine it with SDK proxy settings. `MaximumResponseBytes` permits 1 KiB..16 MiB; caller
cancellation supplies the operation deadline through token acquisition, send and
body reading. There is no implicit read timeout/retry. Host DNS, proxy and
instrumentation remain host responsibilities.

[Contract availability](../../../src/SecretKit.Infisical/InfisicalContractAvailability.cs)
explicitly reports approval administration, access requests, point-in-time
recovery, insights and webhook administration as `ContractNotEstablished`.
Other gaps include complete non-SQL credential result schemas, import-specific
approval/application evidence, and unobserved issuer, edition and native effect
combinations. These are not claims that the vendor lacks those features.
See [support](../provider-support.md), [database boundary](../database-credentials.md)
and [operations](../operations-and-compatibility.md).
