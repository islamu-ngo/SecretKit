# Provider guide

> **Audience:** .NET application developers, administrators, and AI coding assistants
> **Status:** Implemented development-preview subsets; in development, not ready for production
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25, source inspection at `e6fe6b864420d9c8035395fa6c70a9c4ab1e67dd`; no new provider qualification
> **Source anchors:** [project map](../../../PROJECTS.md), [Core](../../../src/SecretKit.Core/), provider owners below

Choose the package by the operation and identity you need. Installation does not
grant provider permissions. These guides describe actual public APIs, not the
provider's entire product catalog.

| Task | Package and entry point | Guide |
| --- | --- | --- |
| Read an Infisical shared secret; inspect direct-folder metadata; perform selected writes | `SecretKit.Infisical`: `InfisicalClient` | [Infisical](infisical.md) |
| Manage Infisical native folders, tags, environments, imports, validation, dynamic definitions/leases or rotation execution | `SecretKit.Infisical`: native `InfisicalClient` methods, `InfisicalDynamicClient`, `InfisicalRotationClient` | [Native owner map](infisical.md#native-api-owner-map) |
| Read/write Azure Key Vault secrets, inspect versions, delete/recover, purge or back up/restore | `SecretKit.AzureKeyVault`: `AzureKeyVaultClient` | [Azure data plane](azure-key-vault.md) |
| Administer Infisical projects, identities, access, selected governance, SQL rotation configuration or gateways/proxies | `SecretKit.Infisical.Management`: operation factories and `ManagementClient` | [Management](management.md#infisical-administration) |
| Administer Azure vaults, access policies, role assignments, private connections or notifications | `SecretKit.AzureKeyVault.Management`: `VaultAdministration` | [Azure administration](management.md#azure-administration) |
| Query selected Azure secret audit events | `SecretKit.AzureKeyVault.Management`: separately constructed `AuditDiagnostics` | [Azure audit](management.md#azure-audit) |

`ISecretReader.ReadAsync` and `ISecretInventory.InspectAsync` are the shared
read/metadata boundaries. References contain provider-native addresses and belong
to a particular `SecretAuthority`; equal coordinates do not make references from
different clients interchangeable. Native operations retain their own request,
receipt, lifecycle and result types. See the [Core API](../core-api.md).

## Read evidence correctly

- **Implemented:** a source owner below executes the selected operation.
- **Offline evidence:** tests exercise that adapter over controlled transports.
  They do not establish a real identity's permission or downstream effects.
- **Native qualification:** requires an exact provider deployment, identity,
  entitlement, operation and independent effect observation. Consult
  [current support](../provider-support.md) and [current preview](../current-preview.md)
  for the scope of recorded evidence.

Mutation acknowledgement, configuration persistence, fresh intended-identity
delivery and consumer activation are separate observations. Do not turn a
successful management read into runtime permission evidence, a pending approval
into applied material, or a rotation status into fleet convergence.

## Boundaries to preserve in application code

Select credentials explicitly. Runtime and administration can require separate
clients, and Azure monitoring has its own credential. Keep caller-held receipts
before dispatch; a lost response can leave a write uncertain. There is no
automatic mutation replay, fallback identity, transaction, rollback or hidden
worker. Dispose owned material and native results that contain it. Explicit
`Reveal`/export operations create ordinary plaintext that disposal cannot erase.

Broad third-party app-connection/sync administration is removed; native SQL
rotation and existing gateway/proxy administration remain. No database driver
ships in the secrets libraries. See [scope decision](../connector-scope-decision.md)
and [database credentials](../database-credentials.md).

Start with [getting started](../getting-started.md), then the relevant provider
guide. Use [operations and compatibility](../operations-and-compatibility.md)
for deadlines, transports, uncertainty and deployment evidence.

## Source and test entry points

| Owner | Source | Controlled evidence |
| --- | --- | --- |
| Infisical runtime/native | [source](../../../src/SecretKit.Infisical/) | [tests](../../../tests/SecretKit.Infisical.Tests/) |
| Azure secret data plane | [source](../../../src/SecretKit.AzureKeyVault/) | [tests](../../../tests/SecretKit.AzureKeyVault.Tests/) |
| Infisical management | [source](../../../src/SecretKit.Infisical.Management/) | [tests](../../../tests/SecretKit.Infisical.Management.Tests/) |
| Azure management/audit | [source](../../../src/SecretKit.AzureKeyVault.Management/) | [tests](../../../tests/SecretKit.AzureKeyVault.Management.Tests/) |
| Shared provider invariants | [Core contracts](../../../src/SecretKit.Core/) | [actual-adapter contract suite](../../../tests/SecretKit.ProviderContract.Tests/) |
