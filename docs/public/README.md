# SecretKit public design

> **Audience:** Prospective .NET adopters and maintainers
> **Status:** PROPOSED DESIGN
> **Owner:** SecretKit maintainers
> **Source facts checked:** 2026-10-09; documentation evidence only
> **Source anchors:** Official references in the linked pages

SecretKit is a proposed in-process .NET library family for applications whose operators select among explicitly installed secret-provider adapters.

These pages describe intended behavior. The [current local preview](current-preview.md) records implemented read, selected-write and native subsets and their limits; it is not a published or completed release. The [accepted scope decision](connector-scope-decision.md) removes broad third-party app-connection/sync administration from local source. Local post-removal verification passed; broader design is not completed support.

## Read the design

- [Current scope and future orchestration](scope-and-orchestration.md): core two-provider delivery, optional administration and Configurator setup.
- [Adoption and value](adoption-and-value.md): where an in-process abstraction might help, alternatives, consumer ownership, and measurements needed to establish value.
- [Configuration and runtime](configuration-and-runtime.md): selected authority, explicit plaintext export, generation ownership, bootstrap, optional integrations, and activation.
- [Operations and compatibility](operations-and-compatibility.md): seven proposed packages, native capabilities, compatibility evidence, authentication maintenance, security, and release policy.

## Intended boundary

The first provider candidates are Infisical and Azure Key Vault secrets. SecretKit would supply provider access mechanisms, bounded outcomes, and material ownership. The consuming application would retain the meaning of each setting, tenant policy, authority selection, activation, persistence, client replacement, and replica convergence.

Operator selection would choose an adapter already installed and registered by the host. A configuration value would not download a package, discover an arbitrary assembly, install a plugin, or grant provider permissions.

Standalone samples are proposed to illustrate database bootstrap and optional integration setup. They would live in SecretKit without dependencies on Event or Configurator. These docs authorize no edits to those applications and describe no completed extraction, migration, or source-parity arrangement.

## Seven-package proposal

| Proposed package | Intended responsibility |
| --- | --- |
| `SecretKit.Core` | Minimal proven common read contracts, references, outcomes, and owned material; no provider or host dependency |
| `SecretKit.Infisical` | Runtime authentication and basic secret data-plane access |
| `SecretKit.Infisical.Management` | Selected project/identity/access administration, native SQL rotation configuration and existing gateway/proxy administration; no third-party connection/sync catalog |
| `SecretKit.AzureKeyVault` | Secret data-plane operations |
| `SecretKit.AzureKeyVault.Management` | ARM administration and separately authorized audit integration |
| `SecretKit.Extensions.Configuration` | Prepared snapshots and explicit plaintext export, without host lifecycle |
| `SecretKit.Extensions.Hosting` | Optional authentication-maintenance and health integration |

The package split is not permission to use administrative authority, a dependency approval, or a claim of feature availability. Specialized recovery, backup, lease, and rotation semantics would remain provider-native until a shared contract is proven. No speculative common approval interface is proposed.

`net10.0` is the proposed starting target. OS, architecture, Native AOT, and trimming support would be claimed only after verification of the relevant package and dependency combination.

## Release meaning

The earlier planner-selected **public-API-complete first release** default is
historical. The user's 2026-10-11 direction supersedes it for current delivery:
finish the Infisical/Azure Key Vault core SDK first, with bounded support and
explicit verification gates. The subsequent accepted removal excludes the
third-party catalog rather than deferring comprehensive connector delivery.
Frozen Infisical research is `ContractResearchOnly`, not current admission.
Neither historical counts nor design breadth authorize publication.
See [current scope and future orchestration](scope-and-orchestration.md).

Product features without an established supported programmable contract would be reported as `ContractNotEstablished`. That status distinguishes missing SDK contract evidence from absence of the vendor feature. It would not ship a placeholder module or count as working support. Imports and other admitted operations can still encounter provider approval rules or downstream effects even when approval-administration endpoints are not admitted.

The [operations page](operations-and-compatibility.md) explains the proposed coverage and evidence gates. All provider version, edition, API, cloud, platform, and conformance combinations are initially unverified for SecretKit.
