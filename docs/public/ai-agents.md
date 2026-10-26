# Reading map for AI coding agents

> **Audience:** AI agents and developers supervising AI-assisted integration
> **Status:** Source-navigation guide, not a replacement for repository instructions
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against package, sample and test paths
> **Source anchors:** [AGENTS.md](../../AGENTS.md), [PROJECTS.md](../../PROJECTS.md), [Core reference](core-api.md)

Use this map to retrieve a small, relevant source slice before proposing code.
The task guides serve humans and agents alike. For changes inside SecretKit,
read [AGENTS.md](../../AGENTS.md) and [CONTRIBUTING.md](../../CONTRIBUTING.md)
first, then any path-scoped instructions.

## Establish context

1. Read [current preview](current-preview.md) for implementation and evidence
   boundaries. Do not treat historical research as supported API inventory.
2. Choose the package through [provider support](provider-support.md).
3. Read the task guide and exact public declarations linked below.
4. Inspect neighboring tests for contracts, including negative behavior.
5. Report which checks actually ran and which provider/platform facts remain
   unverified.

All packages target .NET 10. Core is BCL-only. APIs are in development; do not
invent compatibility aliases, deprecated wrappers or migration guarantees.

## Retrieve by task

| Task | Start with | Source and verification slice |
| --- | --- | --- |
| Common read/material ownership | [Core API](core-api.md) | [Core](../../src/SecretKit.Core/), [Core tests](../../tests/SecretKit.Core.Tests/), [portable contracts](../../tests/SecretKit.ProviderContract.Tests/) |
| Infisical selected/native read | [Infisical](providers/infisical.md) | [client](../../src/SecretKit.Infisical/InfisicalClient.cs), [addresses](../../src/SecretKit.Infisical/InfisicalSecretAddress.cs), [tests](../../tests/SecretKit.Infisical.Tests/) |
| Infisical authentication/renewal | [Authentication and hosting](authentication-and-hosting.md) | [token contract](../../src/SecretKit.Infisical/InfisicalAuthentication.cs), [session](../../src/SecretKit.Infisical/InfisicalPeriodicTokenSession.cs), [maintenance](../../src/SecretKit.Extensions.Hosting/InfisicalAuthenticationMaintenance.cs), [hosting tests](../../tests/SecretKit.Hosting.Tests/) |
| Infisical native features/admin | [Provider map](providers/README.md), [management](providers/management.md) | [runtime package](../../src/SecretKit.Infisical/), [management package](../../src/SecretKit.Infisical.Management/), [coverage inventory](../../src/SecretKit.Infisical.Management/operation-coverage.json) |
| Direct Azure read/lifecycle | [Azure Key Vault](providers/azure-key-vault.md) | [runtime package](../../src/SecretKit.AzureKeyVault/), [runtime tests](../../tests/SecretKit.AzureKeyVault.Tests/) |
| Azure management/audit | [Management](providers/management.md) | [management package](../../src/SecretKit.AzureKeyVault.Management/), [management tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/) |
| Multi-key collection/export | [Configuration and runtime](configuration-and-runtime.md) | [configuration package](../../src/SecretKit.Extensions.Configuration/), [configuration tests](../../tests/SecretKit.Configuration.Tests/) |
| Application activation/leases | [Demos](demos-and-recovery.md) | [offline sample](../../samples/RuntimeConfiguration/), [web sample](../../samples/Infisical.WebDemo/), [consumer tests](../../tests/SecretKit.Consumer.Tests/) |
| Local archives/profile/locks | [Local packages](local-packages.md) | [profile](../internal/local/infisical-runtime.json), [release tool](../../tools/SecretKit.Release/), [package tests](../../tests/SecretKit.Package.Tests/) |
| Broader engineering decisions | [Internal hub](../internal/README.md) | [architecture](../internal/SDK_ARCHITECTURE.md), [runtime contracts](../internal/RUNTIME_CONTRACTS.md), [ADRs](../internal/adr/) |

## Preserve these distinctions

| Do not equate | Why |
| --- | --- |
| Same endpoint/name and same authority | References are bound to an exact client authority instance |
| Metadata visibility and material read | Inventory is value-free and may use a different identity |
| Numeric version and qualified resolved revision | Expansion/imports can change delivered material independently |
| Success and application readiness | A read does not validate or activate a downstream client |
| Local generation and remote snapshot | Multi-key collection is not a provider transaction |
| Pending and applied | Native approval/submission does not establish application |
| Cancellation and not dispatched | A request may already have reached the provider |
| Implementation and permission/conformance | Capability, authority, entitlement and remote effects are separate |
| Provider database API and shipped database driver | Database clients belong to applications or nonpackable test tools |
| Historical registry and current admission | Removed connector families are not promised future work |

## Produce usable examples and changes

Use declared inputs and exact current signatures. Label integration fragments
and omit real credentials. Do not invent extension methods such as automatic
provider registration or configuration loading: follow actual declarations.
Keep asynchronous provider I/O out of synchronous configuration `Load` and
constructors. Acquire one handle per logical operation and dispose every
successful read.

Never fix a denial by selecting another principal, infer token identity from
unverified metadata, or add retry/relogin loops around uncertain mutations.
No database drivers, application contracts, arbitrary HTTP gateway or hidden
workers belong in the shipped library.

Documentation-only changes use link, formatting and command/path checks.
Behavior changes follow the repository's deterministic test and verification
contract. Live calls, publication and Git writes need their actual authorization;
a guide or test fixture supplies none.

## Accuracy and evidence

Use source and tests for SecretKit behavior. Use official, version-relevant
documentation for external API facts. Keep an evidence note with the
path/symbol or source URL, date/revision and the specific claim. Do not report
an unrun command as passed, or an offline fixture as a native deployment.

The [documentation maintenance guide](../internal/DOCUMENTATION_GUIDE.md)
describes page ownership, references, research provenance and remaining
documentation-tooling limits.
