# Operations and compatibility

> **Audience:** Operators, maintainers, and package reviewers
> **Status:** PROPOSED DESIGN
> **Owner:** SecretKit maintainers
> **Source facts checked:** 2026-10-09; provider conformance unverified
> **Source anchors:** Primary published documentation linked below

SecretKit proposes explicit capability admission and evidence-based support claims across seven separately installable packages.

This page defines intended operational and release policy. It does not describe implemented, published, or tested SDK behavior. Official vendor documentation establishes vendor facts, not SecretKit conformance.

Current product scope is the [accepted catalog-removal decision](connector-scope-decision.md).
Broad third-party app-connection/sync administration has been removed from local
source; retained native SQL rotation configuration/runtime features and existing
gateway/proxy administration are not removed. Local removal checks passed; live-provider and release gates remain separate.
Historical release goals below do not override that scope.

## Package responsibilities

| Proposed package | Intended boundary |
| --- | --- |
| `SecretKit.Core` | BCL-only, minimal proven read contracts, typed references, bounded outcomes, independent owned material, and acquired immutable generations; no vendor SDK, host framework, database, or application policy |
| `SecretKit.Infisical` | Runtime identity/authentication and basic secret data-plane operations, with explicit native address and reference semantics |
| `SecretKit.Infisical.Management` | Separately authorized selected project/identity/access administration, native SQL rotation configuration and existing gateway/proxy administration; no broad third-party connection/sync catalog |
| `SecretKit.AzureKeyVault` | Secret data plane, including admitted native versions and lifecycle operations |
| `SecretKit.AzureKeyVault.Management` | Optional ARM vault/access administration and separately authorized audit/monitoring integration |
| `SecretKit.Extensions.Configuration` | Prepared snapshots, explicit mappings, and opt-in plaintext `IConfiguration` export; no host lifecycle |
| `SecretKit.Extensions.Hosting` | Optional authentication-maintenance scheduling integration and safe health/status; host retains lifecycle policy |

There would be no umbrella package installing every provider. The host would explicitly register installed adapters and management capabilities. Configuration could select among those registrations but could not install arbitrary plugins. Installing a management package would not grant administrative authority or authorize provisioning.

Specialized recovery, backup, lease acquisition/renewal/revocation, and rotation would remain typed provider-native features until actual shared semantics were established. The data-plane versus management split would follow the native operation's authority and effect, not move all lifecycle operations into one universal interface. A metadata read would not silently acquire a lease or trigger rotation. No speculative core approval interface would be retained.

Azure's [secret client documentation](https://learn.microsoft.com/en-us/dotnet/api/overview/azure/security.keyvault.secrets-readme?view=azure-dotnet) describes secret lifecycle operations. [Azure monitoring](https://learn.microsoft.com/en-us/azure/key-vault/general/monitor-key-vault) and [diagnostic settings](https://learn.microsoft.com/en-us/azure/azure-monitor/data-collection/diagnostic-settings) involve additional monitoring authority; an ARM credential alone would not prove audit-query access. Infisical documents [dynamic secrets](https://infisical.com/docs/documentation/platform/dynamic-secrets/overview) and [rotation](https://infisical.com/docs/documentation/platform/secret-rotation/overview) with native effects that should not be flattened into ordinary reads.

## Admission and first-release boundary

The earlier public-API-complete first-release default is historical and superseded by the accepted two-provider/catalog-removal decision. Current admission follows demonstrated product use, not Infisical's complete API catalog. The frozen `infisical-operations.json` is `ContractResearchOnly`; basic management coverage is 122 research rows / 121 callable projections across five nonconnector families, not complete administration or live conformance.

Breadth means covering admitted operation families and variants. Depth means proving semantics, identity/permission boundaries, uncertainty, cancellation, lifecycle, and operational failure behavior for each claimed combination. A large endpoint list demonstrates neither depth nor conformance. Adjacent keys, certificates, PKI, KMS, PAM, and SSH products would remain outside the selected secret-management scope.

An admission record would identify the official functional source, supported operation/version, deployment/edition requirements, authority, effect class, concurrency strength, retry safety, dependency provenance, implementation owner, and conformance evidence. API families would version independently; the largest version number elsewhere in the product would not choose an operation's API.

Unestablished supported programmable contracts would be labeled `ContractNotEstablished`, not "vendor feature absent" or "implemented but unavailable." In the R4 evidence, approval administration, access-request administration, point-in-time recovery, insights, and webhook administration had unestablished contracts. They would require fresh supported contract evidence before admission, not private backend source, speculative interfaces, or stub support.

Admission would still account for approval and downstream effects on supported operations. The [Infisical create-import API](https://infisical.com/docs/api-reference/endpoints/secret-imports/create) describes replication potentially creating destination approval requests. Import creation is not proof of destination application. [Approval workflows](https://infisical.com/docs/documentation/platform/secrets-mgmt/concepts/approval-workflows) distinguish approval from merge. The absence of approval-administration support would not remove those native states or justify reporting them as successful application.

## Compatibility evidence

The support registry would keep these dimensions separate:

| Dimension | Intended meaning | Current SecretKit evidence |
| --- | --- | --- |
| Implemented | The admitted operation has a real SDK implementation, not a placeholder | Not established by these design docs |
| Verified | Conformance evidence exists for an exact environment and operation | No provider conformance run claimed |
| Unknown | A contract, environment, entitlement, or behavior lacks evidence | All initial support combinations unverified |
| Available to this identity | A scoped runtime observation establishes permission/entitlement at a stated time | Cannot be inferred from package installation or product availability |

A future matrix would record provider release/version, cloud or self-hosted deployment, edition, API version by family, authentication method, permission model, region/sovereign cloud, operation, selected dependencies, OS/architecture, and evidence date. This design page establishes no verified combination. Scoped historical evidence is in the [current preview](current-preview.md); it does not verify the removal. A passing read in one vault would not establish all Azure clouds or management/audit operations; one Infisical edition would not establish other native features or entitlements.

`net10.0` is proposed, not a shipped compatibility guarantee. Native AOT, trimming, OS/architecture portability, and other framework targets would be advertised only after packed-consumer verification of that exact package and dependency path. Assembly compilation alone would not establish platform support.

## Endpoints, proxy, CA, and bounded operations

The operator would select a trusted endpoint/cloud and explicit identity through host policy. Proxy configuration and private CA trust would use approved transport/OS mechanisms. Certificate and hostname verification, Azure challenge-resource validation, and trusted origin restrictions would remain enabled. There would be no TLS bypass, accept-all certificate callback, automatic endpoint guessing, or bearer-token forwarding to an untrusted redirect or pagination origin.

An explicitly authorized isolated local HTTP development endpoint would not become a production TLS exception. Provider addresses would not override trusted transport settings. Samples would use injected credential sources and no embedded passwords or tokens.

Bulk and inventory operations would have explicit maximum item count, page count, payload/memory budget, concurrency, duration, and cancellation limits. Provider page sizes and partial outcomes would be preserved. Collection while remote state changes would not be described as a transaction or stable inventory snapshot. One bulk response could contain mixed outcomes; transport success would not imply every item applied.

Retries would be bounded and justified by the operation's proven safety and native preconditions. Provider SDK retries would need review rather than stacking independent retry loops. A timeout after mutation could mean an unknown effect; reconcile before replay. No invented compare-and-swap guarantee would be derived from a preceding read. [Infisical rate-limit documentation](https://infisical.com/docs/api-reference/overview/rate-limits) supplies provider facts, not a universal quota or guaranteed retry header.

Diagnostics would expose bounded operation family, outcome, latency, freshness, and safe correlation data. Values, credentials, tokens, connection strings, sensitive addresses, principal/project identifiers, raw errors, provider payloads, and audit content would not become routine logs, traces, or metric labels. SDK-owned upstream logging/tracing would need explicit controls; host instrumentation and opted-in plaintext exports remain adoption boundaries. Administrative/audit results would retain sensitive handling even when they contain no secret value.

## Optional authentication maintenance

For an explicitly selected renewable authentication flow, the optional hosting integration could schedule maintenance before provider-reported expiry and coordinate single-flight renewal. The host would own the schedule, time budget, shutdown cancellation, service registration, and whether maintenance status affects readiness. The package would not launch an implicit universal scheduler, rotate business secrets, or reconcile fleet activation.

Safe status would distinguish healthy, maintenance due, failed renewal, expired/revoked authority, and recovery required without exposing tokens. Actual deadlines and credential constraints would come from supported responses, not copied documentation defaults. Per-request refresh alone would not keep an idle periodic-token host alive.

[Infisical Universal Auth](https://infisical.com/docs/documentation/platform/identities/universal-auth) documents renewal before periodic-token expiry and bootstrap client secrets whose use or lifetime can be exhausted. A process restart can lose its in-memory renewable token even when renewal had previously succeeded. If the bootstrap credential is consumed or expired, repeated login cannot recreate authority. Recovery would require an explicitly supplied renewable identity strategy or operator-provisioned replacement credential through an approved secret source. No automatic credential creation, secret-bearing disk checkpoint, infinite retry, or concealed fallback is proposed.

Shutdown would stop new maintenance work, cancel or boundedly finish outstanding work under host policy, and release owned resources. It would not revoke remote credentials as an implicit disposal effect. Required-secret readiness and optional-integration status would remain separate consumer policies described in the [runtime page](configuration-and-runtime.md).

## Proposed maintainer, security, dependency, and release policy

Maintainers would own a declared supported release/API matrix, coverage inventory, changelog, deprecation decisions, vulnerability triage, and compatibility evidence. A verified matrix row would record reproducible checks and scope, not only a documentation citation. Changes to a public contract would require explicit release notes and review of affected package consumers.

Security reporting would need a private maintainer-owned channel and response policy before publication. No response SLA or reporting address is established by these docs. Reports and reproduction material would exclude production secrets; incident handling would distinguish SDK defects, unsafe host instrumentation, and provider behavior without dismissing any boundary.

Each direct and resolved transitive dependency would require license/provenance, notices, vulnerability, version, and distribution review. The seven-package proposal is not approval to add any dependency. Core would remain minimal; Azure provider SDK candidates and optional Microsoft.Extensions dependencies would need a reviewed resolved graph. Public documentation supplies functional facts, not permission to copy vendor code or schemas.

Release gates would include public contract review, deterministic invariant tests, exact provider conformance for every claimed operation/environment, package/API/dependency checks, safe diagnostic verification, standalone packed-consumer samples, and namespace/publisher ownership. Missing entitlement or sandbox evidence would remain a release blocker for the corresponding claim, not be relabeled verified. Samples would not reference or migrate Event or Configurator.

Publication would use an authorized protected identity and exact verified immutable artifacts, with dependency/notices and provenance records. [NuGet trusted publishing](https://learn.microsoft.com/en-us/nuget/nuget-org/trusted-publishing) documents an OIDC-based publishing mechanism; its existence does not establish SecretKit ownership or configuration. A seven-package family publication could partially complete and would need a manifest and explicit incomplete status until all intended packages were available.

Published versions would not be overwritten. Corrective releases or authorized unlisting would be separate actions; reverting source would not undo remote provider mutations. [.NET package validation](https://learn.microsoft.com/en-us/dotnet/fundamentals/package-validation/overview) could contribute API/applicability evidence, but would not replace remote conformance or security review. Publication and all of these SDK checks remain unperformed in this documentation task.

[Public design overview](README.md) | [Adoption and value](adoption-and-value.md) | [Configuration and runtime](configuration-and-runtime.md)
