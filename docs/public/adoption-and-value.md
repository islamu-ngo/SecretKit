# Adoption and value

> **Audience:** Prospective adopters and technical evaluators
> **Status:** PROPOSED DESIGN
> **Owner:** SecretKit maintainers
> **Source facts checked:** 2026-10-09; no comparative benchmark
> **Source anchors:** Official references below

SecretKit proposes a reusable in-process boundary for operator-selectable provider access; its value must be measured rather than assumed.

The [accepted scope decision](connector-scope-decision.md) removes the broad
Infisical third-party app-connection/sync catalog while retaining optional
selected administration and native secret features. Ordinary application reads
use `ISecretReader` and `ISecretInventory` through Infisical or direct Azure
access, without an external connector. Broader integration administration can
be legitimate, but is outside the current product choice. Local removal checks passed; the evaluation below is not comparative or live evidence.

No SecretKit package, integration, publication, or provider conformance test is claimed here. The choices below are design alternatives, not superiority claims or recommendations obtained through outreach.

## When the abstraction might help

An application supporting several operator-selected providers could keep its consumption path stable while an installed adapter translates provider addresses, authentication, reads, versions, and outcomes. Explicit material ownership and bounded diagnostic behavior could also give multiple consumers a consistent review boundary.

That boundary would not erase provider differences. Azure vault addresses, Infisical project/environment/folder addresses, import rules, permissions, and mutation effects would retain their native meaning. The small common read surface would coexist with typed provider-native operations. Provider selection would use a host-owned allowlist of installed registrations, never arbitrary configuration-driven plugin installation.

For an application committed to one provider, the direct SDK may be the simpler choice. SecretKit would add another dependency and a contract maintenance obligation. A common facade would not create atomic remote reads, instant rotation propagation, universal administrative permissions, or features absent from the admitted provider contracts.

## Alternatives and their costs

| Approach | Useful fit | Trade-off to evaluate |
| --- | --- | --- |
| Direct vendor SDK | One provider or extensive native functionality | Application owns provider branching, credential lifecycle, diagnostics, and material handling |
| Vendor .NET configuration provider | Consumers already require string-valued configuration | Convenient configuration binding; plaintext exposure, precedence, and refresh behavior need review |
| Dapr sidecar retrieval | A deployment already standardizes Dapr and its secret-store components | Provider selection moves partly into sidecar/component configuration; app-to-sidecar availability and operational ownership remain |
| External agent, environment injection, or files | Deployment owns retrieval and delivers values outside the process | Application can avoid provider SDKs; file/environment exposure, refresh signaling, permissions, and stale-value handling move to deployment and consumer policy |
| Proposed SecretKit in-process adapters | Multiple operator-selected providers with an explicit application boundary | Adapter maintenance, dependency review, native feature divergence, and local generation ownership remain |

Microsoft documents an [Azure Key Vault configuration provider](https://learn.microsoft.com/en-us/aspnet/core/security/key-vault-configuration?view=aspnetcore-10.0). Dapr documents a [secrets building block](https://docs.dapr.io/developing-applications/building-blocks/secrets/secrets-overview/) for retrieval from configured stores; that architecture does not require a SecretKit adapter. Infisical documents an [external agent](https://infisical.com/docs/integrations/platforms/infisical-agent). These facts identify alternatives, not evidence that one is faster, safer, or cheaper.

## Proposed evaluation

Use equivalent standalone sample requirements, identity privileges, required-key sets, failure cases, and provider environments. Record setup separately from steady-state operation, and include unfamiliar-adapter learning time rather than comparing a mature SDK integration with a prepared SecretKit demo.

| Measure | What to record |
| --- | --- |
| Integration time | Engineering hours from empty sample to required reads, bootstrap, safe failure handling, and review; distinguish deployment setup and implementation |
| Provider branches | Application-owned provider-specific branches and duplicated lifecycle logic; also count complexity moved into adapters |
| Support burden | Support cases, maintenance hours, upgrade effort, incident diagnosis, and unresolved failures over a stated observation period |
| Third-provider effort | Time and changes needed to admit a third provider, prove common semantics, add native capabilities, tests, documentation, and dependency approval |

The third-provider evaluation would be a research exercise, not a commitment to support another vendor. Define acceptance criteria before measuring, preserve failed cases, and publish limitations with any later results. No comparative measurements have been performed for this proposal. No vendor or adopter outreach is part of this documentation work.

## Mechanisms and application policy

SecretKit would know how to address and read a provider under a supplied identity, return independent owned material, describe observed versions and outcomes, and prepare a local immutable generation. It would not decide what a database password or mail credential means to a business workflow.

Event would continue to own its secret definitions, tenant hierarchy, binding resolution, authorization, required-setting policy, and integration activation. Configurator would continue to own requirement definitions, operator review, destination acceptance, configuration persistence, and reconciliation. Neither application would gain an implemented SecretKit integration from these docs.

Consumers would also own desired and observed revisions, durable notifications without secret values, replica acknowledgements, stale budgets, and replacement of live clients. Selecting a provider package would neither activate an integration nor transfer tenant policy into the SDK.

## Adoption constraints

Install only the required approved packages; the seven-package proposal does not imply an umbrella dependency or automatic administrative registration. Use separate least-privilege runtime and management identities. Decide whether consumers need owned material or deliberately exported `IConfiguration` strings before selecting the optional configuration package.

Start with standalone samples and inspect the [runtime design](configuration-and-runtime.md) and [compatibility gates](operations-and-compatibility.md). Actual Event or Configurator migration would require a separate authorized workstream after a suitable SecretKit release.

[Public design overview](README.md)
