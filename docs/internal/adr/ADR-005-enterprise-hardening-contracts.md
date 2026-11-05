# ADR-005: Enterprise hardening and support boundaries

Status: Accepted for the implemented development preview; not production or
native qualification. Source and authored tests inspected 2026-11-05; no tests
were executed for this documentation change.

## Decision

Retain seven packages, BCL-only Core, typed provider-native operations and
explicit host authority. Configuration and Hosting remain independently
optional. Development breaks require updating current callers, without aliases
or compatibility shims.

Response acceptance is operation-specific: HTTP success alone does not establish
valid material, coordinates, lifetime or applied effects. Required fields,
types, scope contradictions and structural/byte bounds remain enforced.
Authentication envelopes admit bounded additive fields but reject duplicate
members and malformed known fields; strict acceptance does not mean a universal
unknown-field ban. Rejected mutation responses preserve dispatch uncertainty.

Evidence: [authentication envelopes](../../../tests/SecretKit.Infisical.Tests/AuthenticationEnvelopeTests.cs)
(`AdditivePolicyRetainsKnownTypesLifetimeAndStructuralBounds`,
`RenewalAcceptsAdditionsButNeverDuplicateUnknownMembers`) and
[revision tests](../../../tests/SecretKit.Infisical.Tests/InfisicalRevisionTests.cs)
(`MissingEvidenceCannotProduceQualifiedMaterial`,
`ContradictoryReturnedCoordinatesAreInvalid`). Native raw revisions require
returned identity and positive version; ordinary resolved reads do not acquire
that stronger revision contract.

## Identity and composition

Hosting freezes the runtime selection when resolved. Options reload never
replaces a principal. Deliberately create and admit a replacement runtime with
explicit origin, identity and lifetime policy; bind fresh references to its
authority, direct new work to it, and retire accepted old work under the host's
lifetime policy before disposing owned resources. Revision equality across
clients does not transfer reference authority or remote permission.

[Registration source](../../../src/SecretKit.Extensions.Hosting/Registration/InfisicalServiceCollectionExtensions.cs)
owns `AddSecretKitInfisical` and `AddKeyedSecretKitInfisical`.
[Registration tests](../../../tests/SecretKit.Hosting.Tests/HostingRegistrationTests.cs)
cover conflicting borrowed owners and disposal ownership; they do not establish
an automatic identity migration protocol.
[Revision tests](../../../tests/SecretKit.Infisical.Tests/InfisicalRevisionTests.cs)
cover replacement versus resource recreation.

The actual [Hosting project](../../../src/SecretKit.Extensions.Hosting/SecretKit.Extensions.Hosting.csproj)
references Core and Infisical, plus Hosting/DI/HealthChecks abstractions. It does
not reference Configuration and is not a provider-neutral hosting contract.

## Budgets and mutation uncertainty

[InfisicalNetworkOptions](../../../src/SecretKit.Infisical/Transport/InfisicalNetworkOptions.cs)
selects independent request and response limits, each defaulting to 1 MiB and
accepting 1 KiB..16 MiB. The operation deadline defaults to 30 seconds, positive
and at most one minute. One monotonic cooperative budget spans credentials,
serialization, dispatch, response and publication. Arbitrary host callbacks
must cooperate; timeout is not proof of cleanup completion or no remote effect.

[ManagementClient](../../../src/SecretKit.Infisical.Management/Transport/ManagementClient.cs)
uses the same execution selections through
`ManagementTransport(Uri origin, InfisicalNetworkOptions? network = null)`.
The request factory's 64 KiB construction ceiling remains separate from the
selected execution request limit. A larger response limit cannot enlarge it.

[OperationBudgetTests](../../../tests/SecretKit.Infisical.Tests/OperationBudgetTests.cs)
cover `LargerRequestBudgetDoesNotDependOnSmallerResponseBudget`,
`RequestAndResponseLimitsAreIndependentAndOversizeNeverDispatches`,
`LateCredentialIsDisposedWithoutDispatchAndCallerCancellationWins` and
`LateLoginRejectsPublicationButRetainsActualAppliedReceipt`.

Azure metadata null tags omit the patch; an empty dictionary emits an explicit
empty object to clear tags. The selected
[client policy](../../../src/SecretKit.AzureKeyVault/Secrets/AzureKeyVaultClient.cs)
compensates for pinned SDK omission.
[NativeLifecycleTests](../../../tests/SecretKit.AzureKeyVault.Tests/NativeLifecycleTests.cs)
cover independent readback, unchanged material, denial, lost response and
cancellation. These controlled effects are not live Azure certification.

## Current support and expansion

The [provider support reference](../../public/provider-support.md) and
[management guide](../../public/providers/management.md#public-cloud-selection)
record the exact implemented endpoint, audience and API selections. Runtime
acceptance of sovereign vault hostname syntax does not qualify sovereign
management or monitoring.

The [build inputs](../../../Directory.Build.props) target `net10.0`. Current
deployment posture is JIT; trimming and Native AOT remain unqualified.
Sovereign management requires a named supported consumer with its exact cloud,
endpoint/audience/revision and authorized qualification environment. AOT requires
a named consumer deployment requirement and exact-archive analyzer/installed
execution proof. A second hosting contract requires a second actual provider
consumer and two implemented lifecycle contracts before proposing extraction.
No speculative cloud plug-in, extra TFM or empty hosting abstraction follows.

See [follow-ups](../INTEGRATION_QUALITY_FOLLOW_UPS.md) for owners and gates.
Existing S01-S16, 17-case functional, 21-case native and integration-quality
denominators remain unchanged. Offline observations cannot supply deployment,
principal, policy, entitlement, network, platform or publication authority.
