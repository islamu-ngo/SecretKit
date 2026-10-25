# Secret access, optional administration and deployment orchestration

## Immediate delivery priority

Accepted direction, 2026-10-23: make Infisical access useful to .NET applications
through qualified local packages before public NuGet publication. Event is a
requirements reference, not a repository edited by this workstream or a source
of SDK-specific models. Breaking redesign is permitted during development.

Azure and optional administration remain in the repository. Their completion,
all Infisical native families, and Configurator orchestration are not local
adoption prerequisites. Existing tests and unfinished work remain preserved.
The [local evaluation guide](local-packages.md) distinguishes existing commands
from the planned profile; the [engineering contract](../internal/INFISICAL_LOCAL_READINESS.md)
defines acceptance without claiming those changes are already implemented.

The [accepted catalog-removal decision](connector-scope-decision.md) defines the
current boundary. Broad Infisical third-party app-connection and secret-sync
administration has been removed from local source, not retained for a later
catalog release. Local removal checks passed; live-provider and release gates remain separate.

## Application secret access

Applications explicitly select Infisical or the direct Azure Key Vault provider
and an identity:

```text
Application -> SecretKit -> Infisical or Azure Key Vault -> secret
```

Common access uses `ISecretReader` and `ISecretInventory`. Supported writes and
lifecycle retain provider-native semantics. No external connection is needed to
read or write stored application secrets; no destination service SDK, hidden
cache or deployment worker is introduced. Direct Azure access is separate from
an Infisical Azure connection.

Applications own credential injection, access policy, validation, activation,
persistence and readiness. Optional configuration export and explicitly started
hosting support remain independently selectable.

Database credentials remain opaque material at the Core boundary. Infisical's
typed credential-generation and rotation APIs are legitimate provider features,
not database-client implementations. No shipped SecretKit package carries a
database driver. Optional tests may use separate database tools to verify
returned credentials; they do not create a general database-support matrix or
imply MariaDB compatibility from MySQL API support. See the
[database credential boundary](database-credentials.md).

## Optional administration

Project/environment setup, identity/access administration, native SQL rotation
configuration and existing gateway/proxy administration remain supported in
documented subsets. They require explicitly selected administrative authority,
not a discovered fallback identity. Permission subjects named `AppConnections`
remain access-policy semantics, not catalog APIs.

Broader integration administration can legitimately belong in an optional SDK.
The current SecretKit product choice excludes the third-party connection/sync
catalog; vendor API availability alone is not a reason to maintain it.
The removed factories called Infisical's administrative API, not the services'
SDKs or additional SecretKit providers.

An app connection configures how Infisical authenticates to another system.
A sync separately selects source secrets and destination settings. Neither
connection creation nor returned job metadata proves delivery, working
credentials, rotation effects or application convergence. No 1Password sync
direction is assumed.

## Future Configurator workflow

Configurator could guide project/access setup and deployment. An application
that fetches secrets at runtime need not use destination synchronization.
If a chosen workflow instead needs pushed secrets, select a supported delivery
mechanism and verify its effects independently.

Configurator owns destination clients/configuration, deployment sequencing,
operator review and recovery. SecretKit supplies retained provider operations,
not cross-system atomicity. Lost mutation responses retain caller-held receipts;
they do not authorize automatic replay.

No working Coolify integration or end-to-end deployment workflow is claimed.
Reconsider a specific integration only for a named consumer, established
contracts, accepted maintenance ownership and effect-level verification. That
requires a new scope decision, not restoration of the entire catalog.

## Historical evidence and current gates

The pre-removal milestone recorded 15,870 passing offline solution tests and
fresh local package installation. The 15,182-case count was the whole management
suite, not solely connector tests. Owned Infisical verification attempted ten
cases: nine passed and one replication case was rejected by the deployment's
license restriction.

These historical results do not validate the smaller post-removal product.
The reduced source passed locked restore, Release build, all 3,668 offline
tests, formatting and packaging. Fresh installed consumers passed, including
the public connector API-absence assertion. Exact C# diagnostics were clean;
three retired-route guards passed and are included in the full count.
Independent read-only review found no scoped regression.
Azure live testing, licensed SQL acquisition/rotation, unspecified contracts
and unproven native effects remain gates. See
[current preview](current-preview.md) and
[core scope and roadmap](../internal/CORE_SCOPE_AND_ROADMAP.md).
