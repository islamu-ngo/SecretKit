# SecretKit public design

> **Audience:** Prospective .NET adopters and maintainers
> **Status:** PROPOSED DESIGN
> **Owner:** SecretKit maintainers
> **Source facts checked:** 2026-10-09; documentation evidence only
> **Source anchors:** Official references in the linked pages

SecretKit is a proposed in-process .NET library family for applications whose operators select among explicitly installed secret-provider adapters.

These pages describe intended behavior. The [current local preview](current-preview.md) records the implemented read-only subset and its limits; it is not a published or completed release. The broader package names, lifecycle contracts and release boundaries below remain design rather than verified support.

## Read the design

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
| `SecretKit.Infisical.Management` | Explicit administrative and connector operations |
| `SecretKit.AzureKeyVault` | Secret data-plane operations |
| `SecretKit.AzureKeyVault.Management` | ARM administration and separately authorized audit integration |
| `SecretKit.Extensions.Configuration` | Prepared snapshots and explicit plaintext export, without host lifecycle |
| `SecretKit.Extensions.Hosting` | Optional authentication-maintenance and health integration |

The package split is not permission to use administrative authority, a dependency approval, or a claim of feature availability. Specialized recovery, backup, lease, and rotation semantics would remain provider-native until a shared contract is proven. No speculative common approval interface is proposed.

`net10.0` is the proposed starting target. OS, architecture, Native AOT, and trimming support would be claimed only after verification of the relevant package and dependency combination.

## Release meaning

The planning default after an unanswered question timed out is a **public-API-complete first release**: complete the admitted supported public secret-management operations at a declared interface snapshot, then satisfy the release gates. This is a planner-selected default, not a user-confirmed choice, a promise to wrap every vendor product, or approval to implement or publish.

Product features without an established supported programmable contract would be reported as `ContractNotEstablished`. That status distinguishes missing SDK contract evidence from absence of the vendor feature. It would not ship a placeholder module or count as working support. Imports and other admitted operations can still encounter provider approval rules or downstream effects even when approval-administration endpoints are not admitted.

The [operations page](operations-and-compatibility.md) explains the proposed coverage and evidence gates. All provider version, edition, API, cloud, platform, and conformance combinations are initially unverified for SecretKit.
