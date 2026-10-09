# Native Infisical organization and import preview

This is an uncommitted, offline implementation subset, not full Infisical support
or remote conformance. Handwritten internal Refit 16.3.0 interfaces build native
requests with explicit cancellation. The existing `InfisicalClient` managed
transport controls the actual send, dispatch receipt and bounded response parser.
Refit does not deserialize responses or construct error-body exceptions on this
request-builder path; request-content and method-argument capture are disabled.
Common reads, selected shared-secret writes and the host-owned token session keep
their existing behavior.

## Authority and ownership

Bind every native address to the client's `SecretAuthority` through a
`SecretReference`. Native mutations also require an independently supplied
`InfisicalNativeAuthority` and a new, target-bound `MutationReceipt`. The authority
selects host-owned administrative credentials and a project, optionally restricted
to one environment and folder. It does not grant server permissions. Native writes
never substitute the client's runtime token source. Reads use that explicitly
selected client identity; use a separate client for administrative inspection.

IDs, names, paths, constraint expressions, values and approval handles have
redacted formatting and controlled serialization. Reveal material deliberately
and dispose results from `ReadImportedSecretsAsync`. Its `Groups` retain returned
group boundaries/order; `Items` concatenates them without choosing a winner.
Input material is copied before token/network awaits and remains caller-owned.
JSON/parser/plaintext managed strings can survive until GC; buffer disposal cannot
erase them or host-owned diagnostics.

Request and response byte budgets both use `MaximumResponseBytes` (1 KiB to
16 MiB). Lists accept 1 to 1,000 retained items and report truncation through
`IsComplete`. Imported groups are additionally capped at 1,000. Folder/secret
bulk inputs are capped at 128 with duplicate-correlation rejection. Lists are not
transactional snapshots. Mutations are never retried or replayed; cancellation
propagates, and the caller retains dispatch evidence when the response is lost.
Malformed, ambiguous, oversized or mismatched responses cannot mark receipts
applied. Batch subsets leave missing rows uncertain, not failed or rolled back.

## Exact operation status

The admitted registry is
[`docs/internal/providers/infisical-operations.json`](../../docs/internal/providers/infisical-operations.json),
observed 2026-10-09, method/path snapshot
`ae441902d9e0c8a32c4032ea0ef71422cd4aa681ced65dc9ee62c511018b8183`.
The table exhaustively maps the 44 Phase 5 routes, not all 1,566 admitted routes.
Every row below is implemented as a typed, bounded native subset with offline
wire-seam tests; **none is live verified or claimed fully supported**.
Project/identity/role/grant administration belongs to separate management work.

| Method | Admitted route | Native method |
| --- | --- | --- |
| POST | `/api/v1/projects/{projectId}/environments` | `CreateEnvironmentAsync` |
| GET | `/api/v1/projects/{projectId}/environments/{envId}` | `GetEnvironmentAsync`, ID selector |
| DELETE | `/api/v1/projects/{projectId}/environments/{id}` | `DeleteEnvironmentAsync`, explicit hard-delete flag |
| PATCH | `/api/v1/projects/{projectId}/environments/{id}` | `UpdateEnvironmentAsync` |
| POST | `/api/v1/projects/{projectId}/environments/{id}/restore` | `RestoreEnvironmentAsync` |
| GET | `/api/v1/projects/{projectId}/environments/slug/{envSlug}` | `GetEnvironmentAsync`, slug selector |
| GET | `/api/v1/projects/{projectId}/tags` | `ListTagsAsync` |
| POST | `/api/v1/projects/{projectId}/tags` | `CreateTagAsync` |
| DELETE | `/api/v1/projects/{projectId}/tags/{tagId}` | `DeleteTagAsync` |
| GET | `/api/v1/projects/{projectId}/tags/{tagId}` | `GetTagAsync`, ID selector |
| PATCH | `/api/v1/projects/{projectId}/tags/{tagId}` | `UpdateTagAsync` |
| GET | `/api/v1/projects/{projectId}/tags/slug/{tagSlug}` | `GetTagAsync`, slug selector |
| GET | `/api/v2/folders` | `ListFoldersAsync` |
| POST | `/api/v2/folders` | `CreateFolderAsync` |
| PATCH | `/api/v2/folders/{folderId}` | `UpdateFolderAsync` |
| DELETE | `/api/v2/folders/{folderIdOrName}` | `DeleteFolderAsync`, ID or name, explicit force-delete flag |
| GET | `/api/v2/folders/{id}` | `GetFolderAsync` |
| PATCH | `/api/v2/folders/batch` | `UpdateFoldersAsync` |
| POST | `/api/v2/folders/move` | `MoveFolderAsync` |
| GET | `/api/v2/secret-imports` | `ListImportsAsync` |
| POST | `/api/v2/secret-imports` | `CreateImportAsync` |
| DELETE | `/api/v2/secret-imports/{secretImportId}` | `DeleteImportAsync` |
| GET | `/api/v2/secret-imports/{secretImportId}` | `GetImportAsync` |
| PATCH | `/api/v2/secret-imports/{secretImportId}` | `UpdateImportAsync` |
| GET | `/api/v2/secret-imports/secrets` | `ReadImportedSecretsAsync` |
| DELETE | `/api/v4/secrets/batch` | `DeleteSecretsAsync` |
| PATCH | `/api/v4/secrets/batch` | `UpdateSecretsAsync` |
| POST | `/api/v4/secrets/batch` | `CreateSecretsAsync` |
| GET | `/api/v1/secret-validation-rules` | `ListValidationRulesAsync`, all kinds |
| GET | `/api/v1/secret-validation-rules/static-secrets` | `ListValidationRulesAsync`, static kind |
| POST | `/api/v1/secret-validation-rules/static-secrets` | `CreateValidationRuleAsync`, static kind |
| DELETE | `/api/v1/secret-validation-rules/static-secrets/{ruleId}` | `DeleteValidationRuleAsync`, static kind |
| GET | `/api/v1/secret-validation-rules/static-secrets/{ruleId}` | `GetValidationRuleAsync`, static kind |
| PATCH | `/api/v1/secret-validation-rules/static-secrets/{ruleId}` | `UpdateValidationRuleAsync`, static kind |
| GET | `/api/v1/secret-validation-rules/dynamic-secrets` | `ListValidationRulesAsync`, dynamic kind |
| POST | `/api/v1/secret-validation-rules/dynamic-secrets` | `CreateValidationRuleAsync`, dynamic kind |
| DELETE | `/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}` | `DeleteValidationRuleAsync`, dynamic kind |
| GET | `/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}` | `GetValidationRuleAsync`, dynamic kind |
| PATCH | `/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}` | `UpdateValidationRuleAsync`, dynamic kind |
| GET | `/api/v1/secret-validation-rules/secret-rotations` | `ListValidationRulesAsync`, rotation kind |
| POST | `/api/v1/secret-validation-rules/secret-rotations` | `CreateValidationRuleAsync`, rotation kind |
| DELETE | `/api/v1/secret-validation-rules/secret-rotations/{ruleId}` | `DeleteValidationRuleAsync`, rotation kind |
| GET | `/api/v1/secret-validation-rules/secret-rotations/{ruleId}` | `GetValidationRuleAsync`, rotation kind |
| PATCH | `/api/v1/secret-validation-rules/secret-rotations/{ruleId}` | `UpdateValidationRuleAsync`, rotation kind |

Folder addresses require the known environment ID, allowing responses with only
`envId` to be checked without inventing environment lookup. Folder batches use one
project/environment/parent scope; multi-environment batching is not exposed.
Moves require the explicit authority to cover both source and destination scopes.
Import addresses require the known destination folder ID. Create responses do not
echo a cross-project source ID; it remains unobserved unless returned by a later
documented observation. Name comparisons are ordinal; no case normalization is
invented.

Bulk addresses additionally accept a known destination folder ID; without it an
approval response cannot be safely correlated and remains unknown.
Secret creation/update bulk operations expose shared secrets; native deletion
also accepts the published personal type. Update modes are `Ignore`, `Upsert` and
`FailOnNotFound`, not atomic preconditions. Per-row path overrides outside the
selected folder are unavailable (`Unsupported`) because responses do not expose
row paths for safe correlation. No cross-folder transaction or rollback is
inferred. Optional published metadata maps contain strings only, not arbitrary
JSON. Approval conflict payloads and untyped response alternatives are not
exported or treated as applied results.

Validation policies preserve absent versus explicit-null patch fields. Static key
and value constraints remain distinct from dynamic/rotation password constraints
and their published provider choices. Constraint regexes are sent to the provider,
not run locally. The registry's unspecified aggregate item node was resolved using
the official documentation's static/dynamic/rotation `type` alternatives; no raw
JSON result or executable endpoint gateway is exposed.

## Import effects and fresh delivery

An applied import receipt proves **configuration mutation**, not replication or
downstream application. `InfisicalImport` separately reports `IsReplication`,
`ReplicationReportedSuccessful`, protected uninterpreted `ReplicationStatus` and
`LastReplicated`. `InfisicalBulkObservation` separately reports actual selected
destination rows applied, pending approval or uncertain. These observations are
not automatically correlated to an import or promoted into downstream completeness.

`ObserveImportEffectsAsync` performs a new import observation and a new read using
the explicitly supplied intended `InfisicalClient` and matching destination
reference. Inspection visibility and delivery have independent statuses.
Administrative success cannot replace an intended identity's denial or absence.
An intended successful read proves only that selected value/version was returned,
not that every import, replica, application or policy has converged.

The published v2 import response does not establish a destination approval handle
or a status-string vocabulary. `InfisicalImportEffectObservation.Destination`
therefore remains `Unknown`, including when `isReplicationSuccess=true`; it never
guesses pending/applied from status prose. Pending/applied destination observations
are exposed where the native bulk response actually supplies approval or matching
secret rows. Import-specific approval merge/application evidence is unavailable
until an admitted observable contract and live destination-policy checks exist.

References are resolved by the provider's v4 API only, through the existing
explicit `InfisicalResolution`/`IncludeImports` selection. Local secrets override
imports; duplicate imported names use the provider's bottom-most-import rule.
Relative reference resolution and cross-project sharing/grants stay server-owned.
SecretKit does not recursively fetch source references, locally emulate grants,
or infer a deployment's resolution policy.

## Evidence and external gates

`OrganizationTests`, `ImportEffectTests` and `ReferenceBoundaryTests` use the actual
managed HTTP seam with stateful fixtures, generated nonproduction material and
bounded event barriers. They cover current routes, response scope checks, applied
and conflict receipts, partial batches, approval responses, cancellation before
and after dispatch, lost responses without replay, budgets, serialization and fresh
intended denial despite administrative success. They are not a provider emulator
conformance claim.

Verified offline on 2026-10-09: locked restore and the Release native test-project
build exited 0. Exact TUnit class filters with positive minimum counts passed
`OrganizationTests` 8/8, `ImportEffectTests` 17/17 and `ReferenceBoundaryTests` 8/8
(33/33 total). Scoped source/test whitespace verification exited 0.
The complete concurrent native suite ran 128 tests: 111 passed and 17 sibling
rotation tests failed (`Trigger has no published body` and dependent event
timeouts). Those failures were left to their owner; the full suite is not claimed
green. The handwritten Refit declarations match all 44 admitted Phase 5 method/path
pairs with no missing or additional routes.

No live provider origin, disposable project/environment coordinates, intended/admin
credentials or edition entitlements were supplied. Exact permissions, cross-project
toggle/grants, deployment floor, blind-index uniqueness availability, provider regex
semantics, destination approval and replication completion remain external gates.
No live mutation, dependency, generated client, publication or commit is included.

Official factual sources consulted in addition to the independently authored registry:

- [Import creation/replication and approval behavior](https://infisical.com/docs/api-reference/endpoints/secret-imports/create)
- [Import response fields](https://infisical.com/docs/api-reference/endpoints/secret-imports/list)
- [Reference/import precedence and sharing](https://infisical.com/docs/documentation/platform/secret-reference)
- [Aggregate validation alternatives](https://infisical.com/docs/api-reference/endpoints/secret-validation-rules/list)
- [Folder creation fields](https://infisical.com/docs/api-reference/endpoints/folders/create)
- [Folder identity observation](https://infisical.com/docs/api-reference/endpoints/folders/get-by-id)

Refit request construction follows its
[documented typed request-builder contract](https://reactiveui.github.io/refit/#obtaining-the-built-request-without-sending).
The parent owns the central version/package reference, lock restore, provenance and
original common-read/session transport migration. Native transport seams are
`NativeWire.cs`, `NativeWireBindings.cs` and the optional native-request/private
parser hooks in `InfisicalClient.cs`; the public modules keep their protected
inputs and response observations.

Only public interface facts were used; implementation and tests were independently
authored. No Infisical vendor source or implementation structure was reused.
