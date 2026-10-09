# Dependency provenance

SecretKit is independently authored under the repository MIT license. No vendor,
Event or Configurator implementation source or expressive schema is incorporated.
Public protocol identifiers are retained only where interoperability requires them.

Direct packages are distributed through nuget.org; the candidate package metadata
checked on 2026-10-09 declares MIT for TUnit 1.73.19, Azure.Security.KeyVault.Secrets
4.11.2, Azure.Core 1.63.0 and Microsoft.Extensions packages 10.0.12.
Their copyrights and licenses remain with their respective contributors.

Core has no external dependency. Azure packages are optional provider dependencies;
Microsoft.Extensions packages are optional composition dependencies. TUnit is
test-only and is not distributed as a runtime dependency.

Restore-generated lockfiles will identify exact direct/transitive versions and
content hashes. Resolved dependency notices and vulnerability evidence are a
required gate before distribution, not proved by this direct-metadata record.
No copied third-party source is included in these packages.

Infisical access uses independently handwritten typed native HTTP contracts and
Refit 16.3.0. No production, test or assessment project depends on the official
Infisical .NET SDK. The prior SDK-dependent assessment projects were retired.
Refit's official NuGet nuspec was inspected on 2026-10-09: MIT, source repository
https://github.com/reactiveui/refit at commit
053873c309b518d21aa128c246ff8c8b2e38bed4. Refit generates HTTP bindings for the
handwritten interfaces, not public models from a vendor OpenAPI schema.
Core retains no Refit dependency. Exact restored runtime/analyzer transitives
and package content hashes belong to their generated locks and release gate.

Optional Azure administration uses Azure.ResourceManager.KeyVault 1.4.0 and
Azure.Monitor.Query 1.7.1. Their NuGet nuspec metadata was inspected on 2026-10-09:
both declare MIT and the Azure SDK repository. Recorded source commits are
75a7ef8ab6eae983be2334991e4584a4f5f91d71 and
36824c3ca78ab202640254522dd2bf309a18ac2e respectively. These dependencies belong
only to the management package, not Core, common reads or application bootstrap.
Their transitive graph and distribution evidence remain part of the release gate.

Remaining admitted Azure RBAC and notification families select optional
Azure.ResourceManager.Authorization 1.1.7 and Azure.ResourceManager.EventGrid
1.1.0. Their official NuGet nuspecs declare MIT and Azure SDK source commits
f1ce8e8a389e35c76d1c108ec29b06e58ad7960c and
707f264e1c541be0f5af8d9215f00ed5eabb5173, inspected on 2026-10-09. They remain
management-only dependencies; selection does not establish callable family
coverage, permission or live conformance.
