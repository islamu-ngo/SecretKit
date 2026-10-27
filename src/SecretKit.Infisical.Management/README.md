# SecretKit.Infisical.Management

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

The host owns the token source. Internal handwritten
Refit bindings construct fixed requests; the controlled client owns dispatch,
cancellation and bounded raw response parsing. There is no arbitrary HTTP/JSON
executor, vendor-generated schema client, fallback principal or hidden cache.
Copied sensitive inputs/results are disposable and excluded from ordinary
formatting/serialization. Explicit strings and host instrumentation remain
separate plaintext boundaries.

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
