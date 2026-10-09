# SecretKit.Infisical.Management

An optional, unpublished administrative package. It currently exposes **84 typed
operation projections out of 122 admitted management operations**. It is not
complete Infisical administration support. The exact, source-linked
[operation inventory](operation-coverage.json) distinguishes 37 established
operations not implemented in this increment and one event-subscription response
contract gap. There are no callable unsupported-operation stubs.

| Registry family | Admitted | Callable typed projections |
| --- | ---: | ---: |
| ScopedAccess | 30 | 24 |
| Projects | 43 | 32 |
| Identities | 26 | 15 |
| IdentityPrivileges | 12 | 3 |
| Governance | 11 | 10 |

The inventory retains all 19 metadata-only operation markers from the actual
registry. Published field facts and successful offline tests are not deployment,
edition, entitlement, permission, or live conformance evidence.

## Authorization contract

`ManagementAuthority` selects one client instance, host-owned token source, and
exact organization/project scope. A null project is organization scope, not a
wildcard. `IssueGrant(operationId, independentTarget)` is a **host assertion of
intent**, not proof of provider membership, effective permission, or capability.
Keep the issuer in trusted host code. An in-process library is not a sandbox for
hostile code that can construct its own authorities.

The host must independently determine that the selected principal and identifiers
correspond to its intended provider organization/project. Do not issue a grant
by blindly copying an untrusted request's target. Provider authorization is still
enforced by Infisical. In particular, group operations and several organization
operations omit an organization coordinate on the wire. A returned organization
check cannot undo a wrong-target mutation.

Execution checks the grant's issuing authority by reference, the selected client
identity, exact operation ID, and all four target coordinates with ordinal string
comparison **before token acquisition or remote I/O**. A grant for one principal,
operation, project, group, secondary identity, or soft-delete disposition cannot
authorize another. The operation ID maps to one fixed Refit endpoint/method;
the generated request is checked against the immutable intended endpoint before
token acquisition. Protected target properties are excluded from default JSON
serialization and formatting.

Example shape, with all identifiers and credentials supplied by trusted host code:

```csharp
using var transport = new ManagementTransport(trustedOrigin);
var client = new ManagementClient(transport);
var admin = new ManagementAuthority(client.Authority, selectedAdminTokens, selectedOrganization);
using var request = ScopedAccessOperations.DeleteGroup(selectedOrganization, requestedGroup);
ManagementGrant grant = admin.IssueGrant(request.OperationId,
    new ManagementTarget(selectedOrganization, resourceId: independentlyAuthorizedGroup));
ManagementReceipt receipt = client.CreateReceipt(request);
SecretOutcome<GroupMetadata> result = await client.ExecuteAsync(
    request, admin, grant, receipt, cancellationToken);
```

The host retains the receipt even if cancellation throws. Its local identifier is
not a provider idempotency key. Grants are reusable host intent, not single-use
bearer credentials; receipts are single-dispatch evidence.

## Refit and ownership

`ManagementApis.cs` contains seven handwritten internal Refit interfaces with fixed
native routes and `CancellationToken`. They return `Task<HttpRequestMessage>`,
the Refit request-builder contract supported by the selected **Refit 16.3.0**.
There is no generated vendor schema client, arbitrary public HTTP executor,
official Infisical SDK, or HttpClientFactory dependency.

`ManagementRequestBuilder` binds a typed operation to one interface method. Refit
performs request construction, path escaping, query construction, and body
attachment. It never receives the response or credentials. Relative generated
URIs are resolved against the fixed origin and their method, origin, path, and
decoded query pairs are checked before acquiring a token.

The host owns `ManagementTransport`, which creates a controlled `HttpClient` with
normal TLS validation, redirects/cookies disabled, no application retries, and
no automatic activity-header propagation. Explicit loopback HTTP is a development
option only. The management client never disposes its injected transport or token
source. The host must dispose transport after its active operations finish.

After request construction and token selection, `ManagementClient` injects the
bearer header, records the receipt at the last controlled dispatch boundary, and
uses `ResponseHeadersRead`. Refit automatic deserialization and error-body
capture are bypassed. `ExceptionFactory` is additionally configured to return no
exception using the selected version's `ValueTask<Exception?>` contract. Provider
exception text and error bodies are never included in public outcomes.

Input JSON is created eagerly from typed factory arguments in a fixed 64 KiB
buffer. Requests own the copied body and are disposable; copies used by in-flight
calls are independent. Responses are streamed into at most the configured budget
plus one overflow-detection byte (default 1 MiB, configurable 1 KiB to 16 MiB).
JSON depth is 64, duplicate property names are rejected, and collection parsers
reject more than 1,000 items. Request pages are bounded to 100 items; there is no
automatic paging. Full pages without a native total remain incomplete and carry
an explicit next offset. Sharing has the provider's additional offset maximum of
100; a larger native total is not a claim that the SDK can traverse beyond it.

Owned response material and share links use `SecretMaterial`. Disposal clears
owned buffers, not exported strings, HTTP/framework copies, or process memory.
Default formatting/serialization does not reveal material or coordinates.
Host instrumentation and the host's own explicit exports remain host concerns.

## Effects, validation, and projections

Project group-role update uses canonical PATCH with a copied, typed role list.
Its native response is `roles`, not a `groupMembership` envelope. The caller
supplies an independently selected expected membership ID, which is also bound
into the host grant. Each returned `projectMembershipId` must match it before
assignment metadata is published. This is neither an effective-permission probe
nor proof that the selected administrative identity belongs to the project.

Group inventories expose bounded native pages, search, name ordering and typed
member/project filters. `ListGroupProjects` requires an explicit selection:
assigned, unassigned or every project in the group's organization. The selection
is bound into the host grant, so an assigned-project grant cannot authorize the
organization-wide query. These responses do not return an organization ID;
the host's independently selected principal and group remain the scope authority.

Project-template list/get/create/update/delete use the native template envelopes
and validate returned organization IDs and selected template IDs. Creation binds
the intended name/type into the host grant; collection grants bind the selected
type. The typed input subset is name, type and description, with empty-description
clearing on PATCH. Results retain protected metadata, not configuration or
effective permissions. Optional roles/permissions, environments, users, groups,
identities and project-managed identities are not exposed. A missing returned
type remains unknown rather than being inferred from the request.

- `ManagementReceipt` is bound to one immutable request object and client.
  Reuse is rejected; there is no automatic replay, rollback, or transaction.
- Before dispatch, cancellation leaves `NotDispatched`. After dispatch, loss,
  cancellation, malformed/oversized responses, or wrong returned scopes preserve
  `PossiblyDispatched`. `202`, denial, and conflict remain distinct.
- `Applied` means the selected operation returned a valid native success
  projection. It does not imply secret consumption, runtime delivery, eventual
  convergence, or capability of another principal.
- Where a response supplies scope/identity coordinates, they are validated.
  Implicit-scope responses such as audit settings cannot attest their organization;
  their host grant and selected principal remain the precondition.
- Audit rows retain response ordinals including the requested offset. Wrong or
  absent organization/project scope becomes a per-row failure without returning
  that row's payload. An outer successful page may contain failed rows; inspect
  every `AuditRow.Outcome`. Pagination completeness is separate from row success.
- Shared-secret access consumes a view and therefore requires a receipt.
  Missing material does not become an empty successful value.
- Role, privilege, identity, membership, project and sharing results deliberately
  project known metadata. They do not export arbitrary permission conditions,
  actor/event metadata, recipient policy, deleted-environment actor payloads,
  project integration metadata, or effective access decisions.
- Optional native inputs not exposed include project `secretDetectionIgnoreValues`,
  sharing email recipient/external-email options, and some list search/filter/order
  variants. They remain explicit contract coverage gaps, not silently forwarded
  dictionaries. Organization/project role creation and permission mutation are
  not exposed.

## Provenance and open gates

The implementation is independently authored from the repository's functional
field-fact registry observed 2026-10-09. The inventory records exact method/path
and official source URLs for every admitted operation. No vendor implementation,
expressive schema, or generated vendor model was copied.

Additional official facts checked:

- [Shared-secret creation](https://infisical.com/docs/api-reference/endpoints/shared-secrets/create):
  native duration notation; five-minute minimum and thirty-day maximum. The typed
  factory emits integer minutes and requires an explicit audience.
- [Project events](https://infisical.com/docs/api-reference/endpoints/events/project-events):
  published input exists, but response framing/completion/resume semantics remain
  undescribed. No event stream client is exposed.
- [Refit public documentation](https://reactiveui.github.io/refit/):
  typed request builders, body handling, cancellation, and response ownership.
  Actual 16.3.0 compilation and wire tests govern version-specific behavior.

Refit 16.3.0 is centrally selected and provenance-reviewed by the integration
lead. The restore-generated runtime graph includes ReactiveUI.Primitives,
ReactiveUI.Primitives.Core and ReactiveUI.Disposables 8.2.0; root notices and
whole-repository dependency evidence remain lead-owned. The package adds no
other runtime package dependency. Tests reuse the repository's TUnit 1.73.19.

Still open: the 45 exact established operations in the inventory, event-stream
contract facts, omitted input/result variants, exact native permission keys,
deployment/version/edition conformance, sandbox identities, AOT/trimming,
platform/cloud matrix, and publication. No live credentials or remote mutations
were used. Solution inclusion, root documentation/notices, and registry status
integration are lead-owned.
