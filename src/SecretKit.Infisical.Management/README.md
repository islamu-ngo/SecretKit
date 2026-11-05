# SecretKit.Infisical.Management

Choose this optional package only for administrative workflows. For application
secret reads, scoped reads, prepared static writes, and authentication, start with
`SecretKit.Infisical`. Administrative visibility does not establish runtime access;
select a dedicated authorized identity for each responsibility.

[Current support](../../docs/public/provider-support.md) records the latest
offline foundation; historical counts below retain their original boundaries.

Optional, unpublished Infisical administration for selected secret-management
workflows. The broad third-party app-connection and secret-sync catalog has
been removed under the [accepted scope decision](../../docs/public/connector-scope-decision.md).
Ordinary application reads do not require this package or an external connector.
The SDK calls Infisical, not destination service SDKs.

## Retained support

Supported subsets include project/environment setup, identity and authentication
configuration, memberships, roles/privileges, scoped access and selected
governance. Native SQL rotation configuration and existing gateway/proxied-service
administration remain. Runtime reads, writes, dynamic credentials and rotation
observation/triggers stay in `SecretKit.Infisical`; direct Azure access stays in
`SecretKit.AzureKeyVault`.

Rotation configuration may reference an existing connection; it does not provide
the removed connection catalog. Permission subjects such as `AppConnections`
remain legitimate role-policy values, not connector operations. Project
authorization/integration metadata does not prove destination access or sync.

The source-linked [basic operation inventory](operation-coverage.json) has
**122 research rows and 121 callable typed projections in five families**:

| Basic registry family | Research rows | Callable typed projections |
| --- | ---: | ---: |
| ScopedAccess | 30 | 30 |
| Projects | 43 | 43 |
| Identities | 26 | 26 |
| IdentityPrivileges | 12 | 12 |
| Governance | 11 | 10 |

This inventory has no connector families and is not the complete retained
administration inventory. It does not count every native SQL rotation, gateway
or authentication-configuration route. Supported input/output subsets and the
event-subscription contract gap remain explicit; there are no callable
unsupported-operation stubs. The separate frozen
[Infisical research registry](../../docs/internal/providers/infisical-operations.json)
is `ContractResearchOnly`, not current admission or implementation coverage.

## Authority, receipts and ownership

`ManagementAuthority` selects one client, host-owned token source and exact
organization/project scope. A null project is organization scope, not a wildcard.
`IssueGrant(operationId, independentTarget)` asserts trusted host intent, not
provider membership or effective permission. Construct the target independently
from approved inputs, not by copying an untrusted request's target.

Execution checks the issuing authority, client, operation and exact target
before token acquisition or remote I/O. Infisical still enforces permissions;
implicit-scope responses cannot attest that the principal belongs to the
intended organization. A package boundary is not an authorization boundary.

Mutations require a caller-held `ManagementReceipt` bound to the immutable
request and client. Pre-dispatch cancellation leaves `NotDispatched`; loss or
cancellation after possible dispatch retains `PossiblyDispatched`. Reuse is
rejected. There is no automatic replay, rollback or transaction. `Applied`
means a valid native success projection, not runtime delivery, credential
effects or permission for another principal.

`ManagementTransport(origin, network)` uses the same explicit
`InfisicalNetworkOptions.Transport` selection as native runtime clients.
Omission is SDK-safe (normal TLS, no redirects/cookies/ambient proxy); explicit
`HostControlled(client)` or `HostControlled(handler)` retains the host's complete
network policy, including deliberate relaxations. Private issuer trust and
explicit proxies belong to safe mode. See
[transport ownership](../../docs/public/security-and-ownership.md#transport-and-cancellation).
Dispose `ManagementTransport` after accepted execution finishes; borrowed clients
and handlers remain usable and their configuration is unchanged.

`OperationTimeout` selects one cooperative credential-to-publication budget,
measured with monotonic elapsed time. Caller cancellation still takes precedence.
The SDK waits for owned work to settle and disposes late unpublished material;
it cannot forcibly stop a host callback that ignores cancellation. A deadline
does not establish that a mutation failed or was never dispatched.
`MaximumRequestBytes` rejects oversized encoded bodies before credential
acquisition, independently of `MaximumResponseBytes`. Both execution limits admit
1 KiB through 16 MiB. Request factories have a separate 64 KiB serialization
capacity; raising the execution limit does not increase that capacity.
Eligible 429/503 responses retain valid delta or HTTP-date `Retry-After` advice,
clamped between zero and 24 hours. Token-source failure reasons and advice also
survive execution. Advice is scheduling metadata: consumed mutation receipts
remain consumed and the SDK never resends the operation.

The host owns the token source. Internal handwritten
Refit bindings construct fixed requests; the controlled client owns dispatch,
cancellation and bounded raw response parsing. There is no arbitrary HTTP/JSON
executor, vendor-generated schema client, fallback principal or hidden cache.
Copied sensitive inputs/results are disposable and excluded from ordinary
formatting/serialization. Explicit strings and host instrumentation remain
separate plaintext boundaries.

## Completed operation diagnostics

Opt-in BCL listeners observe ActivitySource and Meter
`SecretKit.Infisical.Management`, activity `infisical.management.operation`,
counter `infisical.management.operations` and histogram
`infisical.management.duration` (seconds). Tags are limited to the admitted
operation category, outcome, reason, dispatch and termination. They contain no
request target, token, payload or operation-instance identifier.

Start and opaque parent trace/span IDs/flags are captured before execution;
baggage and tracestate are not copied. The completed interval ends after owned
cleanup and before any listener, including deferred nested runtime observations.
Span and histogram share monotonic elapsed time with a 100 ns minimum for
zero/subtick work. Termination distinguishes completed, caller/shutdown/dependency
cancellation, deadline and fault. It does not grant receipt replay authority.
Earlier HTTP spans cannot become children of a completion span.

Failure of optional diagnostic clock capture/completion omits that record; it
cannot replace results, cancellation or cleanup. Operational clocks retain
their own failure semantics.

Throwing and reentrant callbacks preserve results, receipts and ambient activity.
No exporter or worker is installed. Arbitrary host callbacks cannot be forcibly
stopped; host-authored activity fields and independent networking instrumentation
remain outside the SDK-authored field guarantee.

## Protected returned fields

Authentication response numbers use `ManagementNumber` or nullable
`ManagementNumber?`. `Export()` deliberately returns the exact detached JSON
number token. `GetInt64` and `GetDecimal`, and their Try counterparts, reject
fractional, range, precision or nonzero-underflow loss rather than rounding.
Failed conversion leaves the raw token available for explicit export. The
default value is uninitialized, ordinary formatting is redacted and JSON
serialization emits `{}`. Missing, null, required and sign rules remain specific
to each response field; request-side numeric inputs and bounds are unchanged.

Authentication results preserve unconstrained returned trusted-IP, bound-claim,
OIDC claim-mapping and LDAP allowed-field JSON through `ProjectField<JsonElement>`.
Check `IsPresent` and `IsNull` before explicitly accessing `Value`. These detached
snapshots survive response disposal; they do not infer an input schema,
effective IP policy or issuer acceptance.

Role, privilege and template permission summaries preserve returned conditions
through `ProjectField<PermissionConditionSnapshot>`. `Export()` deliberately
returns ordinary, unredacted JSON. Neither snapshot access nor
`IncludesConditionValues` evaluates a permission or establishes enforcement.
Snapshots and exports use managed storage without secure-erasure guarantees.

TLS-certificate results own returned encrypted-CA JSON as
`ProjectField<SecretMaterial>`. Dispose the result after use. Revealing this
field exports JSON ciphertext, not a decoded CA or certificate fingerprint;
explicit exports outlive SDK disposal. Default result serialization and
formatting omit protected values.

## Evidence and open gates

Historical pre-removal verification recorded 15,182 passing cases in the whole
management suite and 15,870 in the offline solution. Those are not connector-only
counts or post-removal results. The reduced solution passed locked restore,
Release build, all 3,668 offline tests, formatting and packaging. A fresh
installed-package consumer passed and asserted that public connector/sync types
are absent. Clean exact-file C# diagnostics and three retired-route guards
supplement that evidence; the guards are included in the full total.
Independent read-only review found no scoped regression.

The owned rotation fixture's direct Infisical PostgreSQL connection provisioning
is a test-only prerequisite, not public connector support. Historical native
rotation creation was rejected by the owned edition's license gate. SQL effects,
PATCH persistence, backend credential changes and consumer convergence remain
unverified. Gateway metadata does not prove agent/proxy deployment.

Offline transport evidence does not establish native permissions, edition or
entitlement, deployment/version compatibility, Azure live support, AOT/trimming
or production readiness. Event-stream payload/lifetime/resume contracts and
omitted native input/result variants remain gaps. No live-provider call, commit or publication was performed during removal.

See the [current preview](../../docs/public/current-preview.md),
[core scope and evidence](../../docs/internal/CORE_SCOPE_AND_ROADMAP.md) and
[owned conformance guidance](../../tests/SecretKit.Infisical.Conformance.Tests/README.md).
