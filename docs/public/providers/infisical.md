# Infisical runtime and native APIs

> **Audience:** .NET developers and AI coding assistants using `SecretKit.Infisical`
> **Status:** Implemented subsets; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; not a new live run
> **SQL lifecycle update:** 2026-11-06, source and controlled offline verification; no new native qualification
> **Source anchors:** [client](../../../src/SecretKit.Infisical/Secrets/InfisicalClient.cs), [addresses](../../../src/SecretKit.Infisical/Secrets/InfisicalSecretAddress.cs), [tests](../../../tests/SecretKit.Infisical.Tests/)

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
[revision](../../../src/SecretKit.Infisical/Secrets/InfisicalSecretRevision.cs);
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

Call `client.CreateReceipt(target)` **before** dispatch. Retain it even if the call
throws cancellation. A valid applied response returns
`InfisicalStaticChange.Disposition = Applied`; an approval response returns
`SubmittedForApproval`, no applied version, and receipt evidence `Pending`.
The latter is not delivery. A lost response after possible dispatch is `Unknown`
with `PossiblyDispatched`; never blindly retry it. No compare-and-swap or
application activation is performed. See
[implementation](../../../src/SecretKit.Infisical/Secrets/InfisicalStaticChanges.cs) and
[mutation tests](../../../tests/SecretKit.Infisical.Tests/InfisicalMutationTests.cs).

Applied static responses require returned key, workspace, environment and a
positive integral version. Missing or malformed required evidence is Unknown;
contradictory keys/scope and nonpositive versions are Invalid. Returned
`secretPath` and `type`, when present, must match; omission stays unobserved and
is not filled from the request. A provider may have acted even when its response
is rejected, so the receipt remains PossiblyDispatched rather than Applied.

Bulk create/update/delete take a caller-held `InfisicalBulkReceipt`, not the
static operation's Core receipt. Construct it with the exact client, target,
ordered inputs, operation and update mode before awaiting. Inspect immutable
`receipt.Items` snapshots after a failed outcome or cancellation; supported
earlier rows remain known even if a later row is rejected. Included items start
PossiblyDispatched at envelope handoff, not Applied. Approval is Pending and
empty items cannot establish AllApplied. Receipts contain no values/value hashes
and cannot be reused after admission. See
[bulk evidence](../../internal/NATIVE_VALIDATION_BULK.md).

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
| [Environments](../../../src/SecretKit.Infisical/Organization/Organization.cs) | `GetEnvironmentAsync`, `CreateEnvironmentAsync`, `UpdateEnvironmentAsync`, `DeleteEnvironmentAsync`, `RestoreEnvironmentAsync` | `InfisicalEnvironmentAddress(projectId, selector, selection)`, ID or slug; creation requires slug selection. Hard delete is explicit. |
| [Tags and folders](../../../src/SecretKit.Infisical/Organization/Organization.cs) | `ListTagsAsync`, `GetTagAsync`, `CreateTagAsync`, `UpdateTagAsync`, `DeleteTagAsync`; `ListFoldersAsync`, `GetFolderAsync`, `CreateFolderAsync`, `UpdateFolderAsync`, `DeleteFolderAsync`, `UpdateFoldersAsync`, `MoveFolderAsync` | `InfisicalTagAddress`; `InfisicalFolderAddress(projectId, environment, environmentId, parentPath, id, name)` requires known environment ID. Get/update require folder ID; create requires name. Moves must be covered at both scopes; batches share one project/environment/parent. |
| [Imports](../../../src/SecretKit.Infisical/Imports/Imports.cs) | `ListImportsAsync`, `GetImportAsync`, `CreateImportAsync`, `UpdateImportAsync`, `DeleteImportAsync`, `ReadImportedSecretsAsync` | `InfisicalImportAddress(projectId, environment, folder, folderId, importId)` requires known destination folder ID. `InfisicalImportSource` selects environment/path and optional source project. Dispose imported material results. |
| [Bulk secrets](../../../src/SecretKit.Infisical/Secrets/NativeBulk.cs) | `CreateSecretsAsync`, `UpdateSecretsAsync`, `DeleteSecretsAsync` | `InfisicalBulkAddress` plus `InfisicalBulkSecret` rows. At most 128 inputs, no duplicate correlation. Create/update are shared-secret subsets; delete also supports personal. `Ignore`, `Upsert`, `FailOnNotFound` are update modes, not atomic preconditions. |
| [Validation](../../../src/SecretKit.Infisical/Organization/ValidationPolicies.cs) | `ListValidationRulesAsync`, `GetValidationRuleAsync`, `CreateValidationRuleAsync`, `UpdateValidationRuleAsync`, `DeleteValidationRuleAsync` | `InfisicalValidationAddress` selects static, dynamic or rotation policy. `InfisicalValidationInput` preserves omission versus supported explicit clears; regexes execute at the provider, not locally. |
| [Dynamic definitions and leases](../../../src/SecretKit.Infisical/Dynamic/InfisicalDynamicClient.cs) | `Definition`, `ListDefinitionsAsync`, `InspectDefinitionAsync`, `CreateDefinitionAsync`, `UpdateDefinitionPolicyAsync`, `UpdateDefinitionAsync`, `DeleteDefinitionAsync`; `ListLeasesAsync`, `InspectLeaseAsync`, `AcquireDatabaseAsync`, `RenewAsync`, `RenewLeaseAsync`, `RevokeAsync`, `RevokeLeaseAsync` | Separate `InfisicalDynamicClient`; typed profile/definition/lease targets and `InfisicalDynamicMutationReceipt`, not Core mutation receipts. |
| [Rotation execution](../../../src/SecretKit.Infisical/Rotation/InfisicalRotationClient.cs) | `ListAsync`, `GetAsync`, `RotateSecretsAsync`, `SetAutomaticRotationAsync` | Separate `InfisicalRotationClient`; `InfisicalRotationScope`/`InfisicalRotationAddress` and `InfisicalRotationReceipt`. Configuration CRUD belongs to management. |
| [Authentication](../../../src/SecretKit.Infisical/Authentication/InfisicalUniversalAuthentication.cs) and [proof exchanges](../../../src/SecretKit.Infisical/Authentication/InfisicalProofAuthentication.cs) | `InfisicalUniversalAuthentication.LoginAsync`; `InfisicalProofAuthentication.LoginAsync`, `CreateRevocationReceipt`, `RevokeTokenAsync`; `InfisicalPeriodicTokenSession.GetTokenAsync`, `RenewAsync`, `StopAsync` | Host-supplied credentials/proofs; no issuer discovery or fallback identity. See [authentication guide](../authentication-and-hosting.md) for construction, receipts and lifetime evidence. |

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
See [effect implementation](../../../src/SecretKit.Infisical/Imports/ImportEffectObservation.cs)
and [ImportEffectTests](../../../tests/SecretKit.Infisical.Tests/ImportEffectTests.cs).

### Dynamic definitions are broader than credential acquisition

Construct `InfisicalDynamicClient(origin, tokens, scope, network: null,
timeProvider: null, maximumItems: 128)`. Its
`InfisicalDynamicScope(projectSlug, environmentSlug, path, folderId)` uses slugs
and a known folder GUID, not the static read's project-ID address.
Targets come from `client.Definition(name)`. Network selection uses the same
safe or explicit host-controlled contract as reads and authentication.

`maximumItems` limits definition and lease list cardinality, not the fields or
nested inputs of one definition. Responses independently allow at most 1024
properties per object or elements per nested array, depth 32, property names of
1024 characters and string values of 65536 characters; duplicate properties are
rejected. `network.MaximumResponseBytes` bounds responses independently of
`network.MaximumRequestBytes`, which bounds encoded request bodies.
Typed create/update profiles retain their own input validation.

Typed [definition profiles](../../../src/SecretKit.Infisical/Dynamic/Profiles/)
and [profile options](../../../src/SecretKit.Infisical/Dynamic/Profiles/NativeDynamicProfileOptions.cs)
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
Within one client, acquired, listed and inspected references for the same
definition/lease UUID pair share lifecycle state. A revoke through any alias
blocks exports from every governed copy. Renewal uses the canonical observed
creation/version/expiry baseline; stale aliases cannot roll it back. Metadata
reads do not extend the usable deadline or clear uncertainty or revocation.
Clients and different definitions retain independent authority.

Receipts still bind to the exact reference object: construct a renewal or revoke
receipt with the alias passed to that operation. Sharing lifecycle does not make
another alias's receipt valid. Disposing a lease wrapper clears its own buffers;
independent copies remain usable while the shared lifecycle permits. The retained
reference can renew metadata or request cleanup after wrapper disposal; renewing
the disposed wrapper itself returns `Invalid`.

Definition deletion and rename exclude active child operations through response
publication. Contention returns `Conflict` before acquiring credentials. A
validated deletion blocks all child exports locally; ambiguous deletion or
rename blocks exports, acquisition, renewal and name-addressed mutations.
Fresh explicit UUID-addressed lease cleanup remains possible without clearing
parent uncertainty. After a validated rename, old name-addressed handles return
`Invalid` before credentials, even if another definition reuses that name.
These controls coordinate this client's live objects; they do not synchronize
other clients, processes or external provider actors.
Evidence: [LeaseLifecycleTests](../../../tests/SecretKit.Infisical.Tests/LeaseLifecycleTests.cs),
[LeaseAliasLifecycleTests](../../../tests/SecretKit.Infisical.Tests/LeaseAliasLifecycleTests.cs),
[DefinitionLifecycleTests](../../../tests/SecretKit.Infisical.Tests/DefinitionLifecycleTests.cs),
[DynamicDefinitionTests](../../../tests/SecretKit.Infisical.Tests/DynamicDefinitionTests.cs).

### Rotation trigger acceptance is not completion

Construct `InfisicalRotationClient(trustedOrigin, authority, administration,
network: null)` with a matching `InfisicalNativeAuthority`. It defaults to safe
networking; `network.MaximumResponseBytes` selects the byte budget and
`network.Transport` selects any explicit host-controlled pipeline. Construction
performs no I/O. `Dispose()` closes admission immediately and schedules eventual
owned cleanup without blocking on host callbacks. Prefer `await DisposeAsync()`
to await drain within `network.ShutdownTimeout` (positive, at most one minute).
New uncancelled calls throw `ObjectDisposedException` before credentials;
already-cancelled callers retain cancellation precedence. An earlier call that
loses dispatch reservation returns `Invalid` with an undispatched receipt.
Reserved requests may settle under their original caller/deadline budget.
A shutdown timeout throws `TimeoutException` and leaves cleanup pending until
operations and callbacks actually return. Repeated disposal shares the original
bounded result. Borrowed clients, handlers and token sources remain host-owned;
neither disposal path undoes provider effects.
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

Dynamic and rotation requests are built without bearer parameters and checked
against independent method, fixed origin, escaped path and exact scalar query
intent before token acquisition. Duplicate decoded query keys, traversal,
fragments and userinfo fail as `Invalid` with owned request/content disposal.
Query ordering may vary; encoded coordinates must match the selected intent.
The host still owns any instrumentation inside an explicitly supplied pipeline.

Response acceptance is operation-specific. Required fields, types, scope and
structural bounds remain enforced; authentication admits bounded additive
fields but rejects duplicate members and malformed known fields. Rejection after
dispatch does not prove that a mutation had no effect. See
[authentication envelope tests](../../../tests/SecretKit.Infisical.Tests/AuthenticationEnvelopeTests.cs)
and [revision tests](../../../tests/SecretKit.Infisical.Tests/InfisicalRevisionTests.cs).
Hosting freezes the selected runtime at resolution. Options reload cannot
replace its identity; admit a new runtime deliberately, use fresh authority-bound
references and retire old work under host policy. See
[the identity contract](../../internal/adr/ADR-005-enterprise-hardening-contracts.md#identity-and-composition).

All native entrypoints default to `SafeDefault`: normal HTTPS validation,
no redirects/cookies/propagation, no ambient proxy or SDK replay. Select private
issuers with `SafeWithPrivateTrust(roots)` and an explicit proxy with
`network.Proxy`. Private trust copies public certificate data and retains
hostname/chain checks with the normal handler no-revocation-lookup default.
`HostControlled(clientOrHandler)` is deliberately arbitrary networking, not an
SDK-enforced TLS or no-retry guarantee. Keep host configuration stable; do not
combine it with SDK proxy settings. `MaximumRequestBytes` and
`MaximumResponseBytes` independently permit 1 KiB..16 MiB. `OperationTimeout`
defaults to 30 seconds and accepts a positive duration up to one minute.
One cooperative budget covers credentials, request construction, send, body
reading and publication, using monotonic elapsed time. Caller cancellation takes
precedence. Arbitrary host callbacks must cooperate; the SDK retains cleanup
ownership until they settle. A deadline never authorizes replay or proves a
mutation did not happen. Host DNS, proxy and instrumentation remain host
responsibilities.

Source: [network options](../../../src/SecretKit.Infisical/Transport/InfisicalNetworkOptions.cs).
Authored [operation budget tests](../../../tests/SecretKit.Infisical.Tests/OperationBudgetTests.cs)
cover independent limits, streaming deadlines, late credentials and publication
without erasing known receipts. These tests were inspected, not rerun here.

[Contract availability](../../../src/SecretKit.Infisical/Internal/InfisicalContractAvailability.cs)
explicitly reports approval administration, access requests, point-in-time
recovery, insights and webhook administration as `ContractNotEstablished`.
Other gaps include complete non-SQL credential result schemas, import-specific
approval/application evidence, and unobserved issuer, edition and native effect
combinations. These are not claims that the vendor lacks those features.
See [support](../provider-support.md), [database boundary](../database-credentials.md)
and [operations](../operations-and-compatibility.md).
