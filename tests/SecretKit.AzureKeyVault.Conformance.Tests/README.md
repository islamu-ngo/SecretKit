# Azure native conformance components

This nonpackable host contains controlled calibration tests and independently
bound native-family execution. Passing controlled tests does not qualify an
Azure deployment. The source-linked installed consumer reuses the Admission
components against selected original SecretKit packages.

Positive [enterprise-profile admission](../../docs/internal/compatibility/enterprise-hardening-profile.md)
is not implemented for Azure. Original-operation certificates establish their
registered operation and resource custody; supplied tokens, credential/transport
object identities and declared expiry do not establish native principal,
effective policy, network or installed-cohort provenance. A concrete producer
must join those facts to the same original invocation before positive admission.
Missing G2 execution authority is a separate gate. Existing operation evidence
and cleanup rules remain applicable.

The [conformance solution](../../SecretKit.Conformance.slnx) builds both provider
test hosts and their source dependencies. Installed-package consumers and
candidate-dependent demos remain a separate stage requiring exact prepared
packages. Build the solution, then run an explicit documented offline filter
or a separately authorized live parent; do not blanket-run its tests.

Controlled tests are grouped into [vaults](Vaults/), [roles](Roles/),
[private networking](PrivateNetworking/), [notifications](Notifications/),
[audit](Audit/), and shared [management behavior](Management/).
[Infrastructure](Infrastructure/) and [contracts](Contracts/) cover host inputs
and provider-family boundaries. Existing [Admission](Admission/) source links
and [Hosting](Hosting/) ownership stay separate. Namespaces and test filters
remain unchanged.

## Notification delivery authentication

`Admission/Management/NotificationDeliveryAuthentication.cs` validates an
explicitly selected Entra access-token profile with IdentityModel. Supply the
exact issuer, tenant, audience, application, service-principal object, subject,
required role, token version, RSA public signing keys, freshness limits and
clock. Keys are copied; token headers cannot select a discovery endpoint.
Replacing keys requires a new policy.

Supported profiles are signed RS256, app-only v1 or v2 access tokens with
`idtyp=app`, the selected actor and role, and bounded issued/not-before/expiry
times. The host must establish that its enrolled sender actually issues that
profile. Unknown profiles are rejected, not reinterpreted as authenticated
provider identity. Supplying selectors and keys does not prove enrollment,
exclusive subscription writers or the authority that configured delivery.

Pass the policy explicitly to `NotificationWebhookDeliveryCollector`. Invalid
or ambiguous authorization and excessive headers return 401 before the body is
read. Without a policy, capability-path collection remains only candidate
evidence; it is not a provider-authenticated endpoint.

The collector still cannot establish native event emission, exact wrong-event
exclusion or remote retry-queue closure. Neither successful JWT validation nor
local receiver shutdown changes those evidence flags.

## Owned HTTPS receiver

`Hosting/NotificationWebhookHost.cs` supplies a Kestrel adapter around one
collector window. It binds before returning, supports port 0 without reserving
and releasing a port, and refuses requests before `Arm`. It preserves actual
HTTPS authority, path, query and headers; forwarded headers cannot select the
callback authority. A public authority must be configured explicitly.

The host owns the server and collector. It borrows the original capture,
journal, trust policy and supplied certificate. `CloseAsync` closes request
admission and returns local observations; `StopAsync` and disposal join the
shared teardown, clear owned collector data and stop the listener. Canceling a
stop waiter does not abandon cleanup. Caller-owned objects remain usable.
Shutdown is cooperative I/O cleanup, not a promise to kill arbitrary callbacks.

The host forwards the actual subscription-validation response, including its
required `validationResponse` field, without following a validation URL.
A successful handshake does not establish delivery or provider identity.
This is an implemented receiver component, not a deployed or causally complete
native observer service.

Kestrel requires the ASP.NET shared framework in this native host only.
The hosting file deliberately sits outside the source-linked `Admission`
directory: neither shipped SDK packages nor the installed package consumer
acquire that shared-framework requirement.

IdentityModel and its required closure are fixture dependencies only; see
the repository [dependency provenance](../../THIRD-PARTY-NOTICES.md).
No shipped SecretKit package gains them.

## Focused offline checks

From the independent SecretKit repository root:

```sh
dotnet restore tests/SecretKit.AzureKeyVault.Conformance.Tests/SecretKit.AzureKeyVault.Conformance.Tests.csproj --locked-mode
dotnet build tests/SecretKit.AzureKeyVault.Conformance.Tests/SecretKit.AzureKeyVault.Conformance.Tests.csproj --configuration Release --no-restore
dotnet tests/SecretKit.AzureKeyVault.Conformance.Tests/bin/Release/net10.0/SecretKit.AzureKeyVault.Conformance.Tests.dll --treenode-filter '/*/*/AzureVaultFixtureProvisionerTests/*Delivery*' --minimum-expected-tests 1 --zero-tests-policy strict
dotnet tests/SecretKit.AzureKeyVault.Conformance.Tests/bin/Release/net10.0/SecretKit.AzureKeyVault.Conformance.Tests.dll --treenode-filter '/*/*/AzureVaultFixtureProvisionerTests/Webhook*' --minimum-expected-tests 1 --zero-tests-policy strict
dotnet tests/SecretKit.AzureKeyVault.Conformance.Tests/bin/Release/net10.0/SecretKit.AzureKeyVault.Conformance.Tests.dll --treenode-filter '/*/*/AzureVaultFixtureProvisionerTests/HostedWebhook*' --minimum-expected-tests 1 --zero-tests-policy strict
```

These tests sign real test tokens and validate actual bytes with an injected
clock. They do not obtain native credentials, contact Azure, discover keys or
claim native enrollment.
