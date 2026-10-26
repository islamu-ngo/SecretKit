# Adoption and value

> **Audience:** Application developers and technical evaluators
> **Status:** Implemented development subsets; value requires application evaluation
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 (local source/documentation review only)
> **Source anchors:** [Project map](../../PROJECTS.md), [Core](../../src/SecretKit.Core/),
> [Configuration](../../src/SecretKit.Extensions.Configuration/README.md),
> [Hosting](../../src/SecretKit.Extensions.Hosting/README.md)

SecretKit provides an implemented in-process boundary for selected Infisical and
Azure Key Vault operations. It makes authority selection, material ownership,
bounded outcomes and local generation replacement explicit. **In development,
not ready for production; unpublished, with breaking API changes permitted.**
The immediate adoption path is [exact local Infisical packages](local-packages.md),
not a commitment to simultaneous provider completion.

## What you can use now

| Need | Implemented utility | What the application still owns |
| --- | --- | --- |
| Read from explicitly selected providers | `ISecretReader`, authority-bound references and bounded outcomes through real Infisical/Azure adapters | Provider/address selection, identity provisioning, required-value policy and operation deadlines |
| Limit accidental material exposure | Independent disposable material, redacted formatting and controlled serialization | Explicit reveal/export, host instrumentation, process memory and ordinary managed strings |
| Prepare a coherent local required set | `SecretSnapshotLoader` publishes only complete valid collections; acquired handles retain their generation | Remote consistency expectations, freshness deadlines, semantic validation and optional-feature grouping |
| Export for string-based configuration consumers | Explicit mappings and acknowledged managed-string export with destination collision checks | Configuration precedence, options/debug exposure and client activation; separate indexer reads can cross reloads |
| Maintain an explicit Infisical token session | Original finite-lifetime ceilings, single-flight renewal and opt-in hosted maintenance | Verified lifetime/principal evidence, explicit startup and authorized replacement after uncertainty or token loss |
| Perform selected native operations | Typed native reads, mutations and separate management surfaces with caller-held receipts | Administrative authority, downstream effect verification, persistence and recovery decisions |

Start with [getting started](getting-started.md) and [Core API](core-api.md).
Use [provider support](provider-support.md) to select only the implemented native
families you need. Native addresses, permissions, revisions, imports, approvals,
leases and lifecycle effects retain their provider meaning; the common read
surface does not turn them into universal contracts.

## When the extra boundary earns its cost

SecretKit can help when several consumers need the same explicit ownership and
failure-handling rules, or an application supports operator-selected providers.
The application can consume common read outcomes while keeping provider-native
features typed and separately reviewed. Install only needed packages: management
is not a runtime prerequisite, and Configuration/Hosting are independent options.

For a single provider with extensive native requirements, a direct vendor client
may be simpler. SecretKit adds another dependency, narrower supported subsets
and an additional maintenance surface. It does not eliminate deployment setup,
grant permissions, create remote atomic reads or activate an integration.
Current evidence does not establish comparative speed, cost, safety or engineering
time savings.

| Approach | Fit to evaluate | Cost or boundary to inspect |
| --- | --- | --- |
| Direct provider client | A provider-specific application needing broad native functionality | Application-owned material, diagnostics, identity and lifecycle handling |
| String-valued configuration integration | Consumers already designed around configuration strings | Plaintext exposure, precedence, refresh and options/client convergence |
| External agent, sidecar, environment or files | Deployment owns retrieval outside the application process | Delivery permissions, availability, refresh signals and stale-value policy |
| SecretKit in-process adapters | Shared ownership/outcome contracts plus selected native capabilities | Adapter maintenance, admitted subsets, explicit generation ownership and remaining live qualification |

These are architectural choices, not benchmark rankings or externally verified
recommendations. No vendor/adopter outreach or comparative test was performed
for this documentation update.

## Working examples and evidence

The package-only [console](../../samples/Infisical.ConsoleDemo/),
[worker](../../samples/Infisical.WorkerDemo/) and
[web](../../samples/Infisical.WebDemo/) apps demonstrate explicit reads/writes,
awaited admission, opt-in maintenance and request-pinned consumer generations.
The [demos and recovery guide](demos-and-recovery.md) explains their controls,
recovery ownership and fixed local-overhead workload. Controlled installed
process/HTTP tests are not live deployment qualification, production readiness
or proof of integration into another application.

The measured workload concerns synthetic in-process preparation/export and
generation lifetimes, not remote latency, integration hours or superiority over
alternatives. For a fair application evaluation, hold required keys, privileges,
failure cases and environments constant. Record setup/learning time separately
from steady-state work; count complexity moved into adapters as well as branches
removed from applications. Track support incidents and upgrade effort over a
stated observation period. Additional providers require demonstrated demand and
[admission](../internal/PROVIDER_ADMISSION.md), not automatic expansion.

## Application policy stays outside the SDK

Applications own tenant boundaries, secret meaning, required/optional decisions,
semantic validation, persistence, readiness and client handover. Reload signals,
native revision observations and successful writes do not perform activation or
prove replica convergence. Consumers own stale budgets and durable material-free
notifications/acknowledgements.

Event and Configurator integration are outside this library workstream; these
docs do not establish either application's acceptance or preserve their contracts
as compatibility shims. Development changes update real callers directly.
Core treats database credentials as opaque material; no database drivers ship.
The [removed connector catalog](connector-scope-decision.md) is not required for
ordinary reads or a reason to discard retained native rotation/gateway features.

## Adoption decision

Evaluate exact candidate originals with the
[local package recipe](local-packages.md), then follow
[configuration/runtime](configuration-and-runtime.md),
[authentication/hosting](authentication-and-hosting.md) and
[troubleshooting](troubleshooting.md) for the chosen composition.
Keep runtime and management identities explicit and least-privileged.

Use [current preview](current-preview.md) and
[operations/compatibility](operations-and-compatibility.md) before making support
claims. Historical observations and offline tests cannot qualify refreshed
archives, missing permissions/editions or unobserved effects. Azure live behavior,
full native binding evidence and untested platform/AOT/trim profiles remain gaps.
Local evaluation is not public-release or production authority.
