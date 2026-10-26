# Current provider support

> **Audience:** Developers selecting packages and reviewers assessing support
> **Status:** Implemented subsets with offline evidence; incomplete live qualification
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 (local source/documentation review only)
> **Source anchors:** [Projects](../../PROJECTS.md), [package inputs](../../Directory.Build.props),
> [local profile](../internal/local/infisical-runtime.json), source/test links below

**In development. Not ready for production. Unpublished.** All packages target
.NET 10. Read [current preview](current-preview.md) for candidate/version authority
and [provider guides](providers/README.md) for usage. Tables below describe
implemented subsets, not complete vendor APIs or permissions granted to a caller.
Tests linked here are authored evidence surfaces, not a claim they were rerun.

## Seven packages, separately selected

| Package | Implemented responsibility | Source, usage and offline evidence |
| --- | --- | --- |
| `SecretKit.Core` | BCL-only authority-bound references, reads, metadata inventory, outcomes, disposable material and mutation receipts | [Source](../../src/SecretKit.Core/), [Core API](core-api.md), [tests](../../tests/SecretKit.Core.Tests/) |
| `SecretKit.Infisical` | Runtime reads/writes and typed native authentication, organization/import, dynamic and rotation subsets | [Native source guide](../../src/SecretKit.Infisical/README.md), [usage](providers/infisical.md), [tests](../../tests/SecretKit.Infisical.Tests/) |
| `SecretKit.AzureKeyVault` | Secret data plane and native lifecycle | [Native source guide](../../src/SecretKit.AzureKeyVault/README.md), [usage](providers/azure-key-vault.md), [tests](../../tests/SecretKit.AzureKeyVault.Tests/) |
| `SecretKit.Infisical.Management` | Selected identity, authentication, project, access, governance, SQL rotation and gateway/proxy administration | [Source guide](../../src/SecretKit.Infisical.Management/README.md), [usage](providers/management.md), [tests](../../tests/SecretKit.Infisical.Management.Tests/) |
| `SecretKit.AzureKeyVault.Management` | Vault, access, role, private-connection, notification and audit subsets | [Source guide](../../src/SecretKit.AzureKeyVault.Management/README.md), [usage](providers/management.md), [tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/) |
| `SecretKit.Extensions.Configuration` | All-required collection, acquired immutable local generations, explicit string export | [Source guide](../../src/SecretKit.Extensions.Configuration/README.md), [usage](configuration-and-runtime.md), [tests](../../tests/SecretKit.Configuration.Tests/) |
| `SecretKit.Extensions.Hosting` | Explicit Infisical token maintenance, material-free health and bounded stop/drain | [Source guide](../../src/SecretKit.Extensions.Hosting/README.md), [usage](authentication-and-hosting.md), [tests](../../tests/SecretKit.Hosting.Tests/) |

There is no umbrella dependency. Runtime reads do not require management.
Configuration and Hosting are independently optional; Hosting depends on
Infisical, not Configuration. The immediate local profile selects four packages,
not a replacement seven-package release policy.

## Infisical retained native families

All rows have controlled offline test coverage; live evidence is narrower and
deployment-specific. Follow the linked source guide for exact input/result variants.

| Family | Exact source and tests | Qualification boundary |
| --- | --- | --- |
| Common reads, direct-folder inventory, selected create/value update | [Client](../../src/SecretKit.Infisical/InfisicalClient.cs), [read tests](../../tests/SecretKit.Infisical.Tests/InfisicalReadTests.cs), [mutation tests](../../tests/SecretKit.Infisical.Tests/InfisicalMutationTests.cs) | Explicit visibility/scope/version checks; inventory is not material delivery. Historical owned read/write narratives do not cover every route. |
| Qualified raw resource revisions and host-owned networking | [Revision](../../src/SecretKit.Infisical/InfisicalSecretRevision.cs), [revision tests](../../tests/SecretKit.Infisical.Tests/InfisicalRevisionTests.cs), [transport tests](../../tests/SecretKit.Infisical.Tests/InfisicalTransportOwnershipTests.cs) | Only Raw with imports disabled; returned resource identity and positive version required. Equality does not transfer client authority. Private-network/deployment qualification remains separate. |
| Universal and proof login exchanges | [Universal](../../src/SecretKit.Infisical/InfisicalUniversalAuthentication.cs), [proofs](../../src/SecretKit.Infisical/InfisicalProofAuthentication.cs), [Universal tests](../../tests/SecretKit.Infisical.Tests/UniversalAuthenticationTests.cs), [proof tests](../../tests/SecretKit.Infisical.Tests/ProofAuthenticationTests.cs) | AliCloud, AWS, Azure, GCP, JWT, Kubernetes, LDAP, OCI, OIDC, SPIFFE and TLS-certificate proofs are host-supplied. No issuer acquisition/signing, fallback identity or full issuer/mTLS qualification. |
| Token lifetime, renewal and revocation | [Session](../../src/SecretKit.Infisical/InfisicalPeriodicTokenSession.cs), [revocation](../../src/SecretKit.Infisical/InfisicalTokenRevocation.cs), [revocation tests](../../tests/SecretKit.Infisical.Tests/TokenRevocationTests.cs), [Hosting tests](../../tests/SecretKit.Hosting.Tests/) | Original finite ceilings and explicit recovery survive handoff. Historical v0.166.3 observations are scoped; no arbitrary-token principal proof, longevity promise or automatic replay. |
| Environments, tags, folders, bounded bulk secrets and validation rules | [Organization](../../src/SecretKit.Infisical/Organization.cs), [bulk](../../src/SecretKit.Infisical/NativeBulk.cs), [validation](../../src/SecretKit.Infisical/ValidationPolicies.cs), [tests](../../tests/SecretKit.Infisical.Tests/OrganizationTests.cs) | Native authority and receipts required for writes; batches are not transactions. Permissions, regex semantics and unsupported variants remain native gates. |
| Imports, reference resolution and fresh intended-identity delivery | [Imports](../../src/SecretKit.Infisical/Imports.cs), [effects](../../src/SecretKit.Infisical/ImportEffectObservation.cs), [effect tests](../../tests/SecretKit.Infisical.Tests/ImportEffectTests.cs), [reference tests](../../tests/SecretKit.Infisical.Tests/ReferenceBoundaryTests.cs) | Configuration success is not replication or destination approval/application; intended-identity denial is not replaced by admin visibility. |
| Dynamic definitions, credential acquisition and lease lifecycle | [Dynamic client](../../src/SecretKit.Infisical/InfisicalDynamicClient.cs), [profiles](../../src/SecretKit.Infisical/NativeDynamicProfiles.cs), [definition tests](../../tests/SecretKit.Infisical.Tests/DynamicDefinitionTests.cs), [lease tests](../../tests/SecretKit.Infisical.Tests/LeaseLifecycleTests.cs) | 28 definition-input profiles do not mean 28 qualified credential backends. Complete non-SQL/Kubernetes result schemas and downstream revocation effects remain gaps; see [dynamic evidence](../internal/compatibility/dynamic-lifecycle-evidence.md). |
| Rotation reads, triggers and result observations | [Rotation](../../src/SecretKit.Infisical/InfisicalRotationClient.cs), [tests](../../tests/SecretKit.Infisical.Tests/RotationOutcomeTests.cs), [evidence](../internal/compatibility/rotation-progress-evidence.md) | Native acknowledgements are not independent SQL credential changes or consumer convergence. Historical license rejection remains a failed gate. |

Approval administration, access requests, point-in-time recovery, insights and
webhook administration remain
[`ContractNotEstablished`](../../src/SecretKit.Infisical/InfisicalContractAvailability.cs),
with permission not checked. They are static capability evidence, not callable
administrative stubs. Approval effects on an implemented mutation still remain
distinct from applied material.

## Retained administration

| Family | Source and evidence | Limits |
| --- | --- | --- |
| Infisical projects, scoped access, identities, memberships, roles/privileges and governance | [Management source](../../src/SecretKit.Infisical.Management/), [basic operation inventory](../../src/SecretKit.Infisical.Management/operation-coverage.json), [tests](../../tests/SecretKit.Infisical.Management.Tests/) | 122 research rows / 121 callable projections across five basic families, not all retained administration. Explicit identity/project coordinates and audit replacement rules apply. Audit settings readback is not event-production proof. |
| Infisical authentication configuration and credential administration | [Source guide](../../src/SecretKit.Infisical.Management/README.md), [identity auth tests](../../tests/SecretKit.Infisical.Management.Tests/IdentityAuthenticationTests.cs), [cloud auth tests](../../tests/SecretKit.Infisical.Management.Tests/CloudIdentityAuthenticationTests.cs) | Universal/Token and named external strategy subsets do not establish all authentication row variants, issuers, trusted-IP response shapes or credential DELETE contracts. |
| Infisical SQL rotation configuration and gateway/proxied services | [Source guide](../../src/SecretKit.Infisical.Management/README.md), [rotation tests](../../tests/SecretKit.Infisical.Management.Tests/PostgresSecretRotationTests.cs), [gateway tests](../../tests/SecretKit.Infisical.Management.Tests/GatewayAdministrationTests.cs), [proxy tests](../../tests/SecretKit.Infisical.Management.Tests/ProxiedServiceAdministrationTests.cs) | Existing connection references are not the removed connector catalog. Metadata does not deploy an agent/proxy or prove SQL effects. |
| Azure vault/access-policy/private-connection/private-link administration | [Vault source](../../src/SecretKit.AzureKeyVault.Management/VaultAdministration.cs), [tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/) | Public-cloud endpoint subset; no private endpoint provisioning, directory lookup or effective-permission proof. |
| Azure role assignment and role definition inspection | [Roles](../../src/SecretKit.AzureKeyVault.Management/RoleAdministration.cs), [support inventory](../../src/SecretKit.AzureKeyVault.Management/OperationSupport.cs), [tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/) | Typed vault scope and bounded ancestor observations; no custom-role authoring or ancestor mutation from an inherited observation. |
| Azure notifications and audit queries | [Notifications](../../src/SecretKit.AzureKeyVault.Management/NotificationAdministration.cs), [audit](../../src/SecretKit.AzureKeyVault.Management/AuditDiagnostics.cs), [tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/) | Selected HTTPS webhook/Event Grid and fixed Logs query subsets. Status/configuration is not delivery, audit ingestion or cleanup settlement. Diagnostic-settings CRUD is excluded. |

Azure management's [34-family inventory](../../src/SecretKit.AzureKeyVault.Management/OperationSupport.cs)
keeps `PermissionChecked` and `LiveVerified` false. The existence of nonpackable
conformance collectors does not change those flags or qualify a deployment.

## Azure secret data plane

[AzureKeyVaultClient](../../src/SecretKit.AzureKeyVault/AzureKeyVaultClient.cs)
selects stable `2025-07-01` and a host-supplied `TokenCredential`. Its
[native guide](../../src/SecretKit.AzureKeyVault/README.md) and
[tests](../../tests/SecretKit.AzureKeyVault.Tests/) cover common reads/inventory,
SetSecret, exact-version material/metadata, properties, delete/recover with explicit
status checks, deleted-secret metadata, purge, backup and restore.

Consumption rejects disabled/not-yet-valid/expired material; native exact-version
inspection has a different validity contract. Empty tag dictionaries explicitly
clear tags; null omits them (see the dated controlled readback evidence in the
[checkpoint ledger](../internal/compatibility/development-checkpoints.md)).
SetSecret has no mandatory create-only, version-match or version-targeted support.
Lifecycle acknowledgement does not prove immediate disappearance or readiness.
Azure live data-plane, lifecycle and administration remain unverified. Public,
US Government and China runtime origin syntax is not sovereign-cloud conformance;
management is public-cloud only.

## How to interpret evidence

The [shared provider suite](../../tests/SecretKit.ProviderContract.Tests/) uses
actual adapters with controlled responses for authority isolation, ownership,
bounded failures, cancellation and metadata. [Package witnesses](../../tests/SecretKit.Package.Tests/)
exercise exact original archives and isolated consumers. [Demo tests](../../tests/SecretKit.Demo.Tests/)
exercise installed process/HTTP behavior. None substitutes for native effects.

Use the [local-profile ledger](../internal/compatibility/infisical-local-profile.md)
for the distinct 17-case functional and 21-case full native reports and unavailable
binding proofs. Exact source/profile/archive/run bindings matter; an earlier
successful report cannot qualify changed bytes. Historical counts/dates remain
in [development checkpoints](../internal/compatibility/development-checkpoints.md).
No tests were rerun for this page.

Complete permissions, editions, external issuers, SQL backends, replication,
gateway/proxy deployment and Azure effects remain qualification gaps. Hosted CI
execution, the Ubuntu/Windows release matrix, macOS/ARM, trimming and NativeAOT
are not established by Linux offline evidence.

Database APIs mean typed Infisical credential-generation/rotation support, not
database connectivity in shipped libraries. No database drivers or ODBC helper
ship; MySQL does not qualify MariaDB. See [database credentials](database-credentials.md).
The broad third-party connection/sync catalog is [removed](connector-scope-decision.md).
Frozen [Infisical research](../internal/providers/infisical-operations.json)
remains `ContractResearchOnly`, not current admission or a delivery promise.
