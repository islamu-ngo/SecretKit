# Historical Infisical SDK assessment

Assessment date: 2026-10-09. Candidate: Infisical.Sdk 3.0.4 from nuget.org.
Retired execution artifact: the user subsequently selected handwritten typed
HTTP with Refit and HttpClient and no official Infisical SDK dependencies,
including assessment tools and tests. The SDK-dependent projects were removed;
commands below record historical executions and are not current runnable checks.
The observed cancellation/coverage facts remain historical evidence, not a
claim about repository maintenance or the reason to reintroduce that dependency.

## Observed facts

- Package metadata identifies the official Infisical repository and revision
  4941b90f752744c34eb7aeb4e5234182e6fd2ab8.
- The package license is MIT, with a note preserving separately licensed
  embedded SDK terms. The archive contains managed assemblies and no native
  runtime assets. The compiled public surface loaded on linux-x64/net10.0.
- The current package does not justify an FFI/native-deployment objection.
  Historical concerns about another SDK cannot be applied to this package.
- Its declared dependencies include Polly.Extensions.Http and System.Text.Json.
  A dependency alone does not establish which operations are retried.
- The compiled public secret client exposes create, get, list, update and delete.
  Authentication exposes Universal and LDAP login. That is less than the admitted
  administration, connector and thirteen-family authentication scope.
- Those secret/login methods, and the public ApiClient methods, accept no
  CancellationToken. The settings builder exposes host selection only; no public
  handler injection, per-operation retry or diagnostic-control settings appeared.
- ApiClient exposes GetClient, returning a HttpClient. A public mutable client
  is not evidence that its handler/retry/redirect policy can be replaced safely.

These are interoperability facts from published documentation and reflection over
exported members, not observations of implementation source or private IL.

## Actual behavioral evidence

The SDK loaded and completed a read on linux-x64/net10.0. A deterministic local
wire test held the response behind an event, cancelled the wrapper's wait, and
then released the response. The wrapper threw OCE while the vendor task remained
active and subsequently returned the generated value. The test passed (one test,
exit 0). This directly disproves the assumption that WaitAsync makes the vendor
operation cancellable.

Command, Cwd SecretKit:
`dotnet run --project tests/SecretKit.VendorAssessment.Tests/SecretKit.VendorAssessment.Tests.csproj --configuration Release --no-build -- --minimum-expected-tests 1`.

The compiled public settings/client surface supplies no individual cancellation
or injectable handler seam. A wrapper cannot add a CancellationToken to the
underlying request. Cancelling all pending operations or allocating a new vendor
transport for each operation would violate the concurrent caller-isolation and
reusable transport contracts. Forking/private reflection is not supported SDK
reuse. This is a control-seam decision, not a native-deployment failure.

For the admitted additional authentication, organization, administration and
connector families, the official typed SDK surface is also incomplete. Those
gaps are documented separately from the runtime cancellation limitation. Azure
continues to reuse its official libraries and pipeline controls.

## Wrapper alternatives to verify

Cancelling Task.WaitAsync can stop the caller's wait without cancelling the SDK
operation. The deterministic public-SDK test in
tests/SecretKit.VendorAssessment.Tests exercises that difference through a local
wire fixture, with event barriers and generated nonproduction material.

HttpClient.CancelPendingRequests would act on all requests sharing that client,
not on one caller's request. Recreating a vendor client for every operation would
abandon the intended reuse/lifecycle boundary. Private reflection or editing
vendor source is not a supported wrapper configuration.

No absence of a documented setting is treated as an incident or proof of a
particular retry/logging implementation. Mutation replay, redirected credential
handling and response-budget control still require concrete evidence before
admitting that SDK for those guarantees.

## Historical decision rule (superseded)

Before the later explicit user decision, SDK reuse was conditional on coverage
and controls. Current Infisical code instead uses handwritten protected public
contracts and internal typed Refit bindings, with adapter-owned dispatch,
budgets, cancellation and receipt semantics. Azure continues using its official
SDKs. No vendor DTO or provider exception becomes a public SecretKit contract.

## Sources and reproducible evidence

- https://infisical.com/docs/sdks/languages/csharp, retrieved through Tavily MCP.
- https://api.nuget.org/v3-flatcontainer/infisical.sdk/3.0.4/infisical.sdk.nuspec
- The package LICENSE and asset list, downloaded into ignored artifacts/.
- tools/SecretKit.VendorAssessment, compiled public-member assessment.
- Context7 library /thomhurst/tunit supplied test-platform facts. No external
  example implementation was copied.

No live Infisical identity, edition, server or operation has been tested.
