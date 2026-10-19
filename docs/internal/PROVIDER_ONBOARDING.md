# Provider contribution contract

Apply this contract to a named consumer and supported provider slice. It does not
authorize another provider, a new dependency, or a remote environment. Start with
[current support](../public/provider-support.md), [the project map](../../PROJECTS.md)
and [runtime contracts](RUNTIME_CONTRACTS.md).

## Define the native responsibility

Name the owning package, exact public operation/member and native variants,
endpoint/API revision, response/input subset, intended identity, independent
effect witness and deployment/edition limits before implementation. Document
intentional unsupported contracts. Do not choose admission from passing tests.
Runtime credentials, administrative credentials and observers are selected
separately; a package split grants no permission.

Keep Core BCL-only. Use its existing read/inventory seams only for common
semantics. Keep native mutations, leases, approval, backup, recovery and
administration typed in their provider package. Do not add a universal SDK engine,
reflection discovery, arbitrary requests, a published test kit or placeholder
operation. New dependencies require provenance/license and notices review.

## Apply setup and ownership to both providers

| Concern | Infisical | Azure Key Vault |
| --- | --- | --- |
| Origin | Explicit fixed HTTPS origin; development HTTP is explicit and loopback-only | Explicit trusted HTTPS vault origin; management has its own fixed public-cloud endpoints |
| Identity | Host-selected `IInfisicalTokenSource`; native administration has separately selected authority | Host-selected `TokenCredential`; administration and monitoring select their own identity |
| Coordinates | Explicit project/environment/folder/key/version/reference-resolution/import choices | Explicit vault/name/version; native resource and administrative coordinates remain typed |
| Client lifetime | Asynchronously dispose/drain `InfisicalClient`; token sources remain host-owned | The adapter has no invented disposal contract; supplied credentials/transports remain host-owned |
| Test seam | Narrow internal friend for the native handler, owned by the shared test fixture | Existing public pipeline transport; fixture disposes only resources it created |
| Native support | Handwritten typed Refit/HttpClient contracts, no official Infisical SDK | Official Azure SDK, fixed revisions, no automatic retry or diagnostics |

For both, propagate cancellation and bound responses, pages, items and collection
windows. A supplied transport's instrumentation is the host's plaintext boundary.
Never infer a fallback principal. Every successful read owns independent material.
Receipts exist before dispatch, remain single-use and retain lost-response
uncertainty; no timeout authorizes mutation replay.

## Common consumer

The host constructs the actual provider and an authority-bound reference. This
fresh access check reports only the bounded status and disposes successful material:

```csharp
using SecretKit.Core;

static async ValueTask<SecretStatus> CheckAccessAsync(
    ISecretReader reader, SecretReference reference, CancellationToken cancellationToken)
{
    SecretOutcome<SecretRead> outcome =
        await reader.ReadAsync(reference, cancellationToken).ConfigureAwait(false);
    if (!outcome.IsSuccess)
        return outcome.Status;

    using SecretRead read = outcome.Value;
    return SecretStatus.Success;
}
```

Do not print material, references, native payloads or credential exceptions.
`Reveal` and configuration export are deliberate managed-string boundaries,
not defaults. A metadata inventory is not a value-access check. For generation
ownership and intended-identity assessment, use the executable offline
[RuntimeConfiguration](../../samples/RuntimeConfiguration/) and
[ProviderAssessment](../../samples/ProviderAssessment/) examples.
Registering a provider starts no maintenance. Hosting requires explicit startup
and shutdown with verified lifetime evidence.

## Verification unit

1. Register a non-packable native test project with centrally pinned dependencies;
   regenerate its lock through native restore.
2. Supply independent native responses and actual adapter/transport fixtures.
   Apply the [shared scenarios](../../tests/SecretKit.ProviderContract.Tests/)
   to both providers: authority, exact material, ownership, bounded outcomes,
   cancellation, coordinates, budgets, metadata-only inventory and cleanup.
3. For the worst isolation break, use identical coordinates with distinct
   credentials/material and subscribed concurrent barriers. Foreign work must
   fail before credential/send. Characterize compliant behavior and prove the
   oracle detects a narrowly owned mutation before changing a handler.
4. Retain provider-specific effects and stronger native tests. Subscribe before
   triggering asynchronous work and use bounded event/time oracles, never sleeps.
5. Build before fresh pack. The installed consumer must have no project reference,
   use an empty private cache, bind the selected version/source and verify each
   original restored archive hash. Both existing installed-consumer callers share
   [PackageCandidate](../../tests/fixtures/PackageCandidate.cs).
6. Run relevant native tests and the repository checks in
   [AGENTS.md](../../AGENTS.md); retain positive discovery and failures. Execute
   both offline examples when their guidance changes.

Only an owned, separately authorized live environment establishes remote
conformance. Name setup/runtime/observer ownership, entitled deployment, sandbox
namespace, bounded cleanup, operation/variant and independent native/backend
effect. An issued token, created resource or acknowledged request does not prove
delivery, revocation or usable downstream credentials. Missing rights, inputs,
entitlement or effects fail the candidate gate; do not skip them into a pass.

Keep reports material-free and source/version/inventory/scope-bound. Current
support, offline observations, scoped live observations and qualifying release
evidence must remain distinct. Historical registries and synthetic release test
bundles do not qualify. Each native feature keeps an explicit maintainer and
evidence refresh boundary; release approval remains independent.
