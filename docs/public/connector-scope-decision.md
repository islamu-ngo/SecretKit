# SecretKit scope: secret access without a third-party connector catalog

Date: 2026-10-11.
Status: accepted product decision, applied to the local source surface.
Local removal verification passed: locked restore, Release build, 3,668 offline
tests, formatting, seven packages and fresh installed consumers. The installed
consumer checks that connector types are absent. This is not a public release
or complete live-provider certification.

The later [Infisical-first local adoption direction](scope-and-orchestration.md#immediate-delivery-priority)
changes delivery priority, not this accepted catalog-removal boundary or the
dated evidence below.

## Accepted decision

**SecretKit gets and manages secrets through Infisical and Azure Key Vault.
The broad Infisical third-party app-connection and secret-sync administration
catalog has been removed from the SDK.**

The latest user decision supersedes both "stop expanding but retain the
implemented catalog" and the subsequent request to preserve it separately.
Connector-only source, tests, dispatch bindings and partial archived units were
deleted; no replacement archive, branch, repository or integration package is
part of this decision. Historical research and measured evidence are still
history, not current support.

Optional integration administration can be a legitimate SDK responsibility.
It is excluded here by the current product choice, not because all
administration is inherently unrelated to secrets.

## An ordinary application needs no external connector

An application given an Infisical identity reads a stored database password:

```text
Application -> SecretKit -> Infisical -> database password
Application -> database client -> database
```

Alternatively, it reads directly from Azure Key Vault:

```text
Application -> SecretKit -> Azure Key Vault -> database password
```

`ISecretReader` returns owned secret material. `ISecretInventory` returns
metadata, not proof that the selected application identity can read values.
The database client uses the password; SecretKit does not become that client.
Applications still need credentials, permissions and explicit configuration.
There is no new feature or hidden material cache in this scope change.

Neither path requires an Infisical connection to 1Password, LiteLLM, Qovery,
Hasura or a deployment destination. The direct SecretKit Azure Key Vault
provider is not an Infisical Azure Key Vault app connection and remains intact.

## A connection is not synchronization or proven effects

An Infisical app connection configures how **Infisical** authenticates to
another system. The removed SDK factories called Infisical's HTTP API, not
each destination's service SDK. They were not extra SecretKit secret providers.

These responsibilities are distinct:

| Term | Meaning |
| --- | --- |
| Application provider credential | Lets the application ask Infisical or Azure Key Vault for secrets |
| Stored application secret | The value the application consumes |
| External connection credential | Lets Infisical authenticate to another system |
| Secret sync | Separately configured source/destination delivery under the selected feature's contract |
| Dynamic credentials | Provider-native issuance of temporary credentials |
| Rotation | Provider-native credential changes with their own configuration and effects |

A connection record alone does not select secrets, configure a destination,
deploy an application or prove working credentials. Returned metadata and a
successful request are not evidence of downstream delivery, rotation completion
or consumer convergence. No 1Password sync direction or working Coolify
integration is claimed.

## Retained and removed responsibilities

| Responsibility | Current product choice |
| --- | --- |
| Core read/inventory contracts, references, owned material and outcomes | Retained, BCL-only |
| Infisical and direct Azure authentication, reads, writes and supported native lifecycle | Retained within documented subsets |
| Optional configuration export and explicitly started hosting support | Retained |
| Project, environment, identity, access and selected governance administration | Retained, optional and explicitly authorized |
| Native SQL rotation configuration and runtime rotation/dynamic-secret features | Retained within documented subsets; licensed/native effects remain gates |
| Existing gateway and proxied-service administration | Retained; not proof of agent deployment or backend effects |
| Broad third-party app-connection and secret-sync catalog | Removed from the SDK |
| Deployment sequencing, destination configuration and recovery | Future Configurator responsibility |

Classification follows responsibility, not a keyword. Role permission subjects
named `AppConnections` describe access policy; they are not catalog factories.
Project integration metadata is not a public third-party connector catalog.
Native SQL rotation configuration can reference an existing connection without
exposing SDK connection provisioning.

The owned `RotationProgressTests` fixture provisions one PostgreSQL connection
directly through Infisical as a test-only prerequisite. It is not public SDK
connector support. The standalone connection test and its command were removed.

## Why this boundary

The earlier broad API plan turned Infisical's catalog into the product backlog.
Its historical design inventory included 69 connection variants and 49 sync
destinations, alongside 30 rotation and 28 dynamic-definition profiles. Those
planning categories were not complete support counts.

Keeping every implemented connector while stopping expansion still left a
large service-specific maintenance and support surface. Removing the catalog
lets current work focus on usable two-provider secret access, honest errors,
material ownership and verification. This is a product/maintenance judgment,
not a measured forecast of future cost savings.

Removing local APIs does not delete remote Infisical connections, revoke their
credentials, change server permissions or undo provider effects. Operators can
use Infisical's supported administration tools for existing integrations.
Private consumers outside this checkout are unknown; the preview permits
breaking development changes, but no consumer migration is claimed.

## Configurator and reconsideration

A future Configurator workflow can provision access and deploy an application
that reads its secrets at runtime; it need not push secrets through a connector.
If a particular workflow instead needs destination delivery, choose its actual
supported mechanism, authority, observable effects and recovery policy.
Configurator owns orchestration and separate destination clients.

Reconsider only a named integration with a demonstrated consumer, an established
contract, a maintainer and effect-level verification. That requires a new scope
decision, not automatic restoration of the whole catalog.

## Evidence limits

Before removal, the 2026-10-11 milestone recorded 15,870 passing offline solution
tests and seven local packages with installed-consumer evidence. The 15,182-case
run was the **whole Infisical management suite**, not solely connector tests.
These results describe the earlier checkout and do not validate the removal.

Owned live Infisical verification attempted ten cases: nine passed and one was
rejected at the replication license gate. Azure live verification and licensed
SQL acquisition/rotation and other unproven native effects remain explicit gates.
Post-removal verification passed locked restore, the full solution Release
build, all 3,668 offline tests, formatting and local packaging of seven packages.
The installed-package test uses fresh package/obj/bin directories and passes
its real consumer, including the connector API-absence assertion. The three
retired-route guard cases also passed separately; they are included in the full
count, not added to it. Exact-file LSP diagnostics were clean on all 16 changed
C# files. The retained JSON inventories parsed successfully.

Independent read-only review found no scoped regression in the deletion, parser
move or owned fixture boundaries. Its limits remain explicit: this is not a
whole-SDK or live-provider certification. No live scenario, Azure call, external
destination operation, commit or publication was performed during removal.

The basic management inventory still contains 122 research rows and 121 callable
typed projections across five families, with no connector families. It is not
complete Infisical administration. The frozen `infisical-operations.json` is
`ContractResearchOnly` evidence, not current product admission.

## Repository anchors

- [Package map](../../PROJECTS.md) and [contributor boundaries](../../CONTRIBUTING.md).
- [Retained management support and authority](../../src/SecretKit.Infisical.Management/README.md).
- [Current preview](current-preview.md) and [scope and orchestration](scope-and-orchestration.md).
- [Core scope, historical evidence and remaining gates](../internal/CORE_SCOPE_AND_ROADMAP.md).
- [Owned conformance fixture](../../tests/SecretKit.Infisical.Conformance.Tests/README.md).
