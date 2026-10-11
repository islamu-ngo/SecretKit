# Secret access, Infisical administration and deployment orchestration

## Current priority: Infisical and Azure Key Vault

The current delivery priority is a usable, verified SecretKit SDK for
Infisical and Azure Key Vault. Applications select their provider and identity
explicitly, then use the relevant secret-access and lifecycle contracts.

```text
ISLAMU application -> SecretKit -> Infisical or Azure Key Vault -> secret
```

Reading or writing a secret does not require an integration with LiteLLM,
Qovery, Hasura Cloud, Coolify or another deployment destination. Azure's
implementation and offline tests are present; live Azure verification remains
deferred without an Azure account. Final packaging and installed-consumer
verification must be reported separately from source and offline test results.

The 2026-10-11 scope correction makes comprehensive Infisical connector
coverage a future deliverable, not a prerequisite for this two-provider SDK.
Already integrated administrative APIs are retained. Unfinished connector
work is not a shipped support claim.

## Optional capability: administering Infisical integrations

LiteLLM is an AI model API gateway, Qovery is an application deployment
platform, and Hasura Cloud hosts GraphQL APIs over databases. In this work they
are destinations or systems that Infisical can connect to, not additional
SecretKit secret-storage providers.

The connector work implements typed calls to Infisical's administrative API:

```text
ISLAMU Configurator -> SecretKit -> Infisical administration API
                                      -> connection or sync configuration
```

It can create, inspect, update or delete an app connection; supply the
credentials Infisical needs; configure a supported secret sync; and request
supported sync or rotation actions. The implementation uses Infisical's frozen
public-interface facts and repository-native patterns. It is not research into
those services' implementations for inspiration, and it does not implement
their SDKs.

An app connection records connection configuration and credentials. It is
not automatically secret delivery. A separate sync configuration selects
source secrets and destination settings where that API exists. A successful
request or returned metadata is not proof of completed delivery, working
credentials or persisted configuration.

## Future capability: seamless Configurator setup

The desired Coolify-style experience is a possible orchestration workflow:

1. A user selects an application and deployment destination in ISLAMU Configurator.
2. Configurator creates the required Infisical project, environments and access.
3. It configures the supported secret-delivery mechanism.
4. It configures the deployment destination to consume those secrets.
5. It deploys the application and verifies secret delivery and access.

That could replace several manual setup steps with one guided workflow.
SecretKit supplies secret-provider contracts and selected administrative
building blocks. Configurator owns the orchestration and needs the relevant
destination APIs or deployment configuration as well.

No working Coolify integration or end-to-end deployment workflow is claimed
here. First establish whether the destination uses native synchronization,
runtime secret fetching or another delivery mechanism. A connection record
alone must never be treated as seamless setup.

## Why the connector work became so broad

The earlier R6 plan admitted every known Infisical connector. That expanded
the administrative surface far beyond the original two-provider workflows.
The revised direction separates three outcomes:

| Outcome | Connector requirement |
|---|---|
| Read/write secrets through Infisical or Azure Key Vault | No external destination connector required |
| Automate one selected deployment workflow | Only that workflow's integrations are needed |
| Offer comprehensive Infisical administration | Broad connector coverage is relevant |

Finish the core SDK first. Select and verify one concrete Configurator
workflow next, then add integrations that workflow actually needs. Broad
administration can be pursued separately when it has an explicit consumer.

Offline connector tests establish controlled SDK behavior, not native
permissions, edition support, destination convergence or an end-to-end
"configure everything and deploy" experience.

The core verification run passed 15,870 offline tests and fresh isolated
package installation. Owned Infisical read/write workflows and ordinary imports
passed live checks. Replicated imports require an entitlement absent from the
owned deployment and remain an explicit verification gate, alongside licensed
SQL acquisition/rotation, unspecified event/output contracts and deferred Azure
live testing. Passing core tests does not erase those limitations.
