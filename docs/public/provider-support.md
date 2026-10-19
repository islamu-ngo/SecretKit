# Current provider support

Status: implemented/offline scope, reviewed 2026-10-12 against baseline
`f7b1f7aec9f312fc2cbc54d1ea797d02824512ad` and the uncommitted
provider-engineering changes. Packages target .NET 10. This is not release
admission, a compatibility certification, or a claim of complete vendor coverage.

## Selecting a package

| Package | Implemented responsibility | Evidence and limits |
| --- | --- | --- |
| Core | Authority-bound references, common reads and metadata inventory, bounded outcomes, independently owned disposable material | [Core tests](../../tests/SecretKit.Core.Tests/). BCL only; native operations are not universal Core contracts. |
| Infisical | Common reads/inventory, selected shared-secret mutations, native authentication, imports, dynamic definitions/leases and rotation operations in documented subsets | [Native guide](../../src/SecretKit.Infisical/README.md), [offline tests](../../tests/SecretKit.Infisical.Tests/), [owned conformance harness](../../tests/SecretKit.Infisical.Conformance.Tests/). The harness is separate from routine CI. |
| Azure Key Vault | Common reads/inventory, SetSecret and native version, metadata, deleted-secret, backup/restore and lifecycle operations | [Native guide](../../src/SecretKit.AzureKeyVault/README.md), [offline tests](../../tests/SecretKit.AzureKeyVault.Tests/). Azure live coverage remains unverified. |
| Infisical Management | Explicitly authorized administration: identities/authentication, projects, access, governance, native SQL rotation and retained gateway/proxy subsets | [Native guide](../../src/SecretKit.Infisical.Management/README.md), [offline tests](../../tests/SecretKit.Infisical.Management.Tests/). Basic projection counts are not the complete retained-operation denominator. |
| Azure Key Vault Management | Explicit vault/access/role/private-connection administration, notification configuration and separately selected audit access | [Native guide](../../src/SecretKit.AzureKeyVault.Management/README.md), [offline tests](../../tests/SecretKit.AzureKeyVault.Management.Tests/). Public-cloud endpoint subsets only; configuration does not prove notification delivery or effective permission. |
| Configuration | Required collection, acquired local generations and deliberate managed-string export | [Guide](../../src/SecretKit.Extensions.Configuration/README.md), [tests](../../tests/SecretKit.Configuration.Tests/). No remote snapshot, activation or erasure of exported strings. |
| Hosting | Explicitly started Infisical token maintenance and material-free health | [Guide](../../src/SecretKit.Extensions.Hosting/README.md), [tests](../../tests/SecretKit.Hosting.Tests/). No constructor-started worker, automatic principal selection or mutation replay. |

The removed third-party connection/sync catalog is outside this product. Native
SQL rotation and existing gateway/proxy administration remain; see the
[accepted scope decision](connector-scope-decision.md).

## What the current evidence establishes

The [shared provider suite](../../tests/SecretKit.ProviderContract.Tests/) runs
22 scenarios through actual Infisical and Azure adapters with controlled native
responses, not substitute common readers. It exercises same-coordinate isolated
authorities and distinct credentials, concurrent reads, exact material, independent
disposal, bounded failures, cancellation, malformed/substituted/oversized responses,
metadata-only bounded inventory and native resource ownership. Both provider cases
are individually discovered. Temporarily removing the two real read authority
guards made both isolation cases fail; restoring them made the suite pass.

On 2026-10-12, fresh locked restore, Release build and pack passed; all 3,722 offline
tests, both offline samples and repository formatting passed. The seven-package
family installed from fresh caches for `0.1.0-preview.1` and `0.1.0-preview.2`;
original restored archive hashes matched each selected family. See the
[package witnesses](../../tests/SecretKit.Package.Tests/) and
[package-only consumer](../../tests/fixtures/SecretKit.PackageConsumer/).
These are Linux x64 development results, not the selected Linux/Windows
same-run release matrix.

The later corrected local matrix passed 3,959 tests across twelve native hosts,
including 301 release-boundary cases, on fresh restored/built/packed originals.
Both offline samples and solution formatting passed. The exit run exposed a
pre-existing shared SDK challenge-cache dependency in two security tests; unique
first-challenge origins now preserve their original zero-token/wire assertions
and normal concurrency. These remain Linux development observations.

Exact-version Azure metadata updates now send an explicit empty tag object when
an empty dictionary is supplied; null tags remain omitted. The pinned SDK omits
empty tags by itself, so this path uses a selected request policy while preserving
the existing authority, receipt, transport and no-retry controls. The native
Azure suite passed 141 cases, including controlled independent metadata readback,
unchanged material, denial, cancellation and lost-response/no-replay witnesses.
This establishes local behavior, not remote tag-clearing certification.

The [routine workflow](../../.github/workflows/verify.yml) is credential-free and
preserves positive per-host discovery and failures. Its diagnostic artifacts are
explicitly `offline-verification`, never release bundles. Its hosted execution
has not been observed.

## Live scope and unverified combinations

The [current preview](current-preview.md) records the earlier owned Infisical
v0.166.3 installed narrative with separate setup/runtime/denied identities.
Those dated observations cover only their named operations and deployment.
They do not establish all authentication issuers, editions, native profiles,
SQL backends, import replication, gateway/proxy effects or complete administration.
An entitlement denial remains a failed gate, not a supported feature.

Azure remote data-plane, lifecycle, administration, notification delivery and
audit behavior require their own owned environment, intended identity and
independent effect witnesses. Sovereign-cloud endpoint syntax in the runtime
adapter is not sovereign-cloud conformance. macOS, ARM, other runtime versions,
NativeAOT and trimming are unverified.

Current admission now records every retained member and variant separately from
qualifying complete-live release evidence. Contract gaps and unobserved native
effects still block release. This page describes implementation and offline
scope only. Frozen
[Infisical research](../internal/providers/infisical-operations.json) is historical
`ContractResearchOnly` evidence, not current admission. Package presence, a
successful response, inventory visibility and an issued mutation receipt each
establish less than an independently observed downstream effect.
