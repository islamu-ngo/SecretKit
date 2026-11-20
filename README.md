<a name="readme-top"></a>

<div align="center">

<img src="assets/images/adopters/ISLAMU/islamu-logo-text-only-v2.png" alt="ISLAMU logo" width="200" />

# ISLAMU SecretKit

**Secrets your .NET application holds on purpose — never by accident.**

.NET 10 libraries for explicit, disposable secret access through Infisical and Azure Key Vault.

**No ambient credentials · No hidden cache · No mutation replay**

> 🚧 **Development preview — not ready for production, not publicly published, and APIs may break.** Local tests and packages do not establish live provider conformance. Read the [current preview](docs/public/current-preview.md) before adopting an operation.

[![Credential-free verification][ci-shield]][ci-link]
[![License][license-shield]][license-link]
[![.NET 10][dotnet-shield]][dotnet-link]
[![Packages][packages-shield]](#packages)
[![Status][status-shield]](#about-secretkit)
[![Last commit][commit-shield]][commit-link]
[![Discord][discord-shield]][discord-link]

[**Quick Start**](#quick-start) · [**Packages**](#packages) · [**Architecture**](#architecture) · [**Provider Support**](#provider-support) · [**Security**](#security-and-ownership) · [**Documentation**](#documentation-public-guides-vs-internal-contracts) · [**Contributing**](#contributing) · [**License**](#license-and-provenance)

</div>

## About SecretKit

Most .NET secret access returns a `string` that a DI container copies, a log line formats, an exception retains, and process memory keeps with no owner. The failure is rarely a broken provider call; it is ambient authority and unowned material.

SecretKit takes a narrower position:

- **Authority is an instance, not a name.** A `SecretReference` belongs to one client instance by object identity. Matching coordinates do not transfer authority; a replacement client needs new references.
- **Material has an owner.** Successful reads return independently disposable buffers. `Use` / `UseUtf8` lend a temporary snapshot to a callback and clear it when the callback ends; `Reveal` and configuration export deliberately step outside that protection into ordinary managed strings.
- **Outcomes are closed and material-free.** Absence, denial, expiry, cancellation and unavailability stay distinct. `TryGetSecretAsync` returns `null` only for explicit absence; everything else remains a failure.
- **Native semantics survive.** Supported writes, revisions, rotation and administration stay typed and provider-native rather than flattened into a lowest-common-denominator abstraction.
- **Nothing is inferred.** No fallback principal, discovery of administrative identities, material cache, background worker, vendor CLI launch or automatic replay of an uncertain mutation.

### The trust chain

```text
host-selected credential ─▶ selected provider client ─▶ provider response
                                                     ─▶ owned SecretRead
                                                     ─▶ application use (callback or explicit export)
                                                     ─▶ optional plaintext boundary
```

The application chooses origin, identity, allowed coordinates and tenant binding. The provider enforces remote permission. SecretKit checks the admitted response and scope of the operation you selected — it does not infer your authorization policy, activate your services or converge your deployment.

SecretKit is deliberately **not** a vault, a process-isolation boundary, a deployment orchestrator or a forensic-erasure guarantee. It is the narrow, explicit seam between an authorized .NET application and a secret store.

---

## ✨ Highlights

- **⏱ A real first run in 30 seconds:** QuickStart uses synthetic in-memory material — no account, no network, no provider writes.
- **🔒 Values that do not leak by accident:** Protected values and coordinates stay out of default formatting, serialization, exceptions and SDK diagnostics.
- **🧾 Failure that stays diagnosable:** Closed status and failure reasons distinguish absence from denial, expiry and unavailability without copying provider payloads.
- **🔌 Composition you opt into:** Registration performs no network I/O; startup admission, health checks, keyed isolation and configuration export are explicit choices.
- **🧩 No umbrella dependency:** Runtime reads need `SecretKit.Infisical` plus Core. Management, configuration and hosting are separate selections.
- **📚 Runnable examples over prose:** Seven onboarding samples plus package-only console, worker and web harnesses for the installed-package path.
- **🧭 A stated boundary per operation:** Identity, scope, networking, material lifetime, export, mutations and health each have explicit library behavior and host responsibility.
- **🛡 Fail-closed writes:** Supported mutations retain caller-held pre-dispatch receipts; an uncertain response is never silently retried.
- **🔍 Evidence kept separate from claims:** Source, offline, installed-archive, native, platform and publication evidence levels are never conflated.
- **📉 Honest support statements:** Inventory is not delivery, approval is not application, configuration is not replication, and a native acknowledgement is not a downstream effect.
- **🕌 Values examined in the open:** Provider responsibility assessments under Islamic Value-Sensitive Design live in the repository, including risks that block a release.
- **📜 A repository contract, not folklore:** [`AGENTS.md`](AGENTS.md) owns invariants and verification; [`PROJECTS.md`](PROJECTS.md) maps each package to its owner and test suite.
- **🎯 Source navigation by task:** The [AI agent reading map](docs/public/ai-agents.md) points at exact declarations and test slices.
- **🧪 Deterministic tests only:** TUnit with `Microsoft.Testing.Platform`, exact event barriers and injected time — never sleeps, mock-call mirroring or timing polls.
- **🧱 Greenfield freedom, stated plainly:** Breaking changes are permitted during development; no compatibility aliases or migration guarantees are invented.

---

## 🧭 Architecture

Core defines the shared vocabulary. Providers depend inward on Core and preserve native behavior. Composition is optional and never implied by a package reference: dependency direction is always provider → Core, never the reverse. Package ownership is listed in [Packages](#packages).

The `i-vsd` reading of this design, including why one organization's identity must never authorize another's request, is recorded in [`islamic-value-sensitive-design/`](islamic-value-sensitive-design/workstreams/i-vsd-secretkit-sdk.md).

---

## 📦 Packages

Seven packages, separately selected. There is no umbrella dependency, and a package reference grants no provider authority.

| Package | Use it for | Depends on |
| --- | --- | --- |
| [SecretKit.Core](src/SecretKit.Core/README.md) | BCL-only reads, outcomes, material ownership and mutation evidence | — |
| [SecretKit.Infisical](src/SecretKit.Infisical/README.md) | Infisical runtime reads, authentication and supported native lifecycle operations | Core |
| [SecretKit.Extensions.Hosting](src/SecretKit.Extensions.Hosting/README.md) | Options, keyed DI, explicit startup admission and health integration | Core, Infisical |
| [SecretKit.Extensions.Configuration](src/SecretKit.Extensions.Configuration/README.md) | Local generations, leased client activation and deliberate configuration export | Core |
| [SecretKit.AzureKeyVault](src/SecretKit.AzureKeyVault/README.md) | Direct Azure Key Vault secret data-plane access | Core |
| [SecretKit.Infisical.Management](src/SecretKit.Infisical.Management/README.md) | Separately authorized Infisical administration | Infisical |
| [SecretKit.AzureKeyVault.Management](src/SecretKit.AzureKeyVault.Management/README.md) | Separately authorized Azure administration and audit access | Core |

Ordinary Infisical reads need `SecretKit.Infisical` and its Core dependency. Configuration and hosting are independent optional packages; hosting depends on Infisical, not on configuration. Runtime reads never require a management package, and management never substitutes for runtime delivery. Test doubles live in the nonpackable [testing fixture](tests/fixtures/SecretKit.Testing/); they do not add an eighth published package.

- **Target framework:** `net10.0` for every package, test, sample and tool.
- **SDK pin:** `10.0.404` in [`global.json`](global.json), with `latestPatch` roll-forward.
- **Version:** `0.1.0-preview.1` default in [`Directory.Build.props`](Directory.Build.props); the local profile selects a separate `0.2.0-integration.3` four-package cohort.
- **Trimming / AOT:** Core, Infisical, Infisical.Management, Configuration and Hosting set `IsAotCompatible`; both Azure packages remain non-AOT due to their SDK dependencies.
- **SBOM:** Every Release `.nupkg` embeds a filtered SPDX 2.2 manifest (`Microsoft.Sbom.Targets 4.1.13`).
- **Publication:** No public NuGet release exists; local packages are the supported evaluation path.

A version string, a successful pack or a relocatable feed does not establish an installed or native-qualified candidate. See [local packages](docs/public/local-packages.md) for the exact source, profile, record-bytes and archive-hash binding.

---

## Quick Start

The [QuickStart sample](samples/QuickStart/Program.cs) uses synthetic in-memory material. It requires no account and performs no provider writes. To use a real provider, follow [local package installation](docs/public/local-packages.md) and supply your own authorized identity and trusted origin.

### Make a scoped read

Given an authenticated `InfisicalClient client` and host-selected `string` coordinates, a scoped read needs only:

```csharp
using SecretKit.Infisical;

var scope = client.CreateScope(projectId, environment, folder);
using var read = await scope.GetSecretAsync(key, cancellationToken);
int characterCount = read.Material.Use(static characters => characters.Length);
```

Replace the callback with the operation that needs the material. `Use` and `UseUtf8` borrow a temporary span only for the callback and clear its buffer when the callback finishes. Dispose the read. `Reveal()` and configuration exports create ordinary plaintext strings whose lifetime is outside that protection.

`TryGetSecretAsync` returns `null` only for an explicit absence. Access denial, expiry and unavailable providers remain failures; they are not missing secrets. For explicit branching, `ReadAsync` returns `SecretOutcome<SecretRead>` with `TryGetValue`, `Match`, and `GetValueOrThrow` helpers.

The full first-use walkthrough — checkout preparation, the offline configuration example, identity separation and a complete read fragment with linked deadline — is [getting started](docs/public/getting-started.md).

### Register with a host

Integration fragment: `runtimeOptions` is an `InfisicalRuntimeOptions` containing explicit origin, identity, project and verified lifetime policy. `loadBootstrapMaterialAsync` is a host-provided `Func<CancellationToken, ValueTask<SecretMaterial>>` returning fresh owned material. `services` is your `IServiceCollection`; coordinates come from your host configuration.

```csharp
using Microsoft.Extensions.DependencyInjection;

services.AddSecretKitInfisical(options =>
{
    options.Runtime = runtimeOptions;
    options.ClientSecret = loadBootstrapMaterialAsync;
})
.WithDefaultScope(projectId, environment, folder)
.WithStartupAdmission()
.WithHealthChecks();
```

Startup admission authenticates during host startup and rejects failed admission. Omit it to defer authentication until explicit admission or reader use; registration itself performs no network I/O. Keyed registrations use `AddKeyedSecretKitInfisical(serviceKey, configure)` to keep runtime sessions and scopes separate. Neither path discovers an administrator or silently retries a consumed bootstrap attempt. See [authentication and hosting](docs/public/authentication-and-hosting.md).

### Replace configuration deliberately

Integration fragment: `selections` is an application-created collection of `SecretSelection` entries, and `mappings` contains explicit `SecretConfigurationMapping` entries. Both select known keys; `cancellationToken` comes from the host.

```csharp
using Microsoft.Extensions.Configuration;
using SecretKit.Extensions.Configuration;

using var loader = new SecretSnapshotLoader(selections);
(await loader.RefreshAsync(cancellationToken)).GetValueOrThrow();
using var first = loader.Acquire();
using var export = SecretConfigurationExport.Create(first, mappings);
IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
using IDisposable configurationLifetime = (IDisposable)configuration;
(await loader.RefreshAsync(cancellationToken)).GetValueOrThrow();
using var next = loader.Acquire();
export.Replace(next);
```

Replacement publishes one complete local dictionary and signals reload. Separate indexer reads can cross generations; use one snapshot handle for coherent multi-key work. Exported strings cannot be erased by disposing the SDK.

For a client that must be validated before activation, use `SecretGenerationCoordinator<TClient>`. The application supplies its validator, stale policy and age bound. `EnableAsync` collects and validates; `Acquire` returns a lease that keeps the client alive through `ExecuteAsync`. Retirement waits for leases. Client activation and configuration export remain separate operations, not a joint transaction.

### Runnable examples

| Sample | Demonstrates |
| --- | --- |
| [QuickStart](samples/QuickStart/) | Scoped reads and callback material access |
| [AspNetCore](samples/AspNetCore/) | Hosting registration and startup admission |
| [Worker](samples/Worker/) | Explicit worker composition |
| [ConfigurationReload](samples/ConfigurationReload/) | Generations and configuration replacement |
| [RuntimeConfiguration](samples/RuntimeConfiguration/) | Detailed consumer policy and ownership scenarios |
| [ProviderAssessment](samples/ProviderAssessment/) | Runtime authority versus administrative visibility |
| [Infisical.OperatorWorkflow](samples/Infisical.OperatorWorkflow/) | Universal Auth, value-free review, receipt-preserving bulk apply and explicit sign-out |

Package installation and recovery harnesses live under [tests/PackageQualification](tests/PackageQualification/) — a console reader/writer, a Generic Host worker and a loopback-only web host — separate from onboarding. Their controlled process and HTTP observations are not native qualification. See [demos and recovery](docs/public/demos-and-recovery.md).

---

## 🧩 Provider Support

Implemented subsets are real but incomplete: every row below has controlled offline coverage, live evidence is narrower, and no row grants a caller permission. Authoritative tables, exact source links and per-family limits: [provider support](docs/public/provider-support.md).

### Infisical runtime and native families

Common reads and selected writes, qualified raw revisions, Universal and proof authentication, token lifetime, organization surface, imports and references, dynamic secrets, SQL rotation. Approval administration, access requests, point-in-time recovery, insights and webhook administration remain `ContractNotEstablished` with permission unchecked — static capability evidence, not callable administrative stubs.

### Separately authorized administration

Infisical projects, access, identities, roles and governance; authentication configuration; SQL rotation and gateways; Azure vault, access, networking, roles, notifications and audit. Azure management's 35-family inventory keeps `PermissionChecked` and `LiveVerified` false. Existing connection references are not the removed third-party connector catalog.

### Azure Key Vault data plane

`AzureKeyVaultClient` selects the stable `2025-07-01` API version and a host-supplied `TokenCredential`. It covers common reads and inventory, `SetSecret`, exact-version material and metadata, properties, delete/recover with explicit status checks, deleted-secret metadata, purge, backup and restore.

Consumption rejects disabled, not-yet-valid and expired material; native exact-version inspection follows a different validity contract. Empty tag dictionaries explicitly clear tags while null omits them. `SetSecret` has no mandatory create-only, version-match or version-targeted support, and a lifecycle acknowledgement does not prove immediate disappearance or readiness. Public, US Government and China origin syntax is not sovereign-cloud conformance; management is public-cloud only. Azure live data-plane, lifecycle and administration remain unverified.

### Database credentials are not database clients

Database APIs mean typed Infisical credential generation and rotation support. No shipped package contains a database driver or ODBC helper, and MySQL support does not qualify MariaDB. Core keeps returned material opaque. See [database credentials](docs/public/database-credentials.md).

### Read evidence correctly

| Level | What it establishes | What it never establishes |
| --- | --- | --- |
| **Source and offline** | Implementation scope and controlled behavior through public seams | Installed archives, native provider effects or platform support |
| **Installed archive** | Exact package originals install and run in an isolated consumer | Remote conformance or entitlements |
| **Native** | Observed behavior against an authorized provider deployment | Complete editions, permissions or another tenant's policy |
| **Platform / publication** | A specific OS, architecture or authority to publish | Anything about an untested matrix or a future release |

The Infisical local ledger separates offline proof protocols, the 17-case development-functional acceptance set and the 21-case full native qualification. Historical counts and dates stay in the [development checkpoints](docs/internal/compatibility/development-checkpoints.md) rather than being presented as a current passing total. Complete permissions, editions, external issuers, SQL backends, replication, gateway deployment, Azure effects, hosted multi-OS execution, trimming and NativeAOT remain separate gates.

The broad third-party connection and sync catalog is [removed](docs/public/connector-scope-decision.md); native SQL rotation and existing gateway/proxy administration remain. Frozen Infisical research stays `ContractResearchOnly` and is not current admission.

---

## 🔐 Security and Ownership

| Boundary | Library behavior | Host responsibility |
| --- | --- | --- |
| Identity | Uses only explicitly supplied credentials and token sources | Inject least-privilege runtime identities; select administration separately |
| Scope | Binds references to client instances and checks returned coordinates | Authorize tenant-to-project, vault, environment and path mappings |
| Networking | Safe mode preserves TLS and restricts SDK networking; host-controlled mode borrows the chosen pipeline | Choose the mode and own DNS, proxy, trust policy, instrumentation and reachability |
| Secret lifetime | Owns disposable character buffers and independent read copies | Dispose reads and manage any copies consumers make |
| Configuration | Exports strings explicitly and publishes local generations | Precedence, debug views, options serialization, reload scheduling and activation |
| Mutations | Preserves caller-held dispatch evidence without automatic replay | Authorization, durable reconciliation, approvals and cleanup |
| Application health | Exposes bounded operation and maintenance evidence | Readiness, freshness, downstream verification and replica policy |

- Credentials, origin and authority are explicit host choices. Installing a package grants no access.
- SecretKit never launches vendor CLIs or other processes. A host may still pick a CLI-backed credential such as `AzureCliCredential`; SecretKit only sees the resulting `TokenCredential` ([ADR-006](docs/internal/adr/ADR-006-configurator-provisioning-and-credential-sources.md)).
- Dispose owned reads and material. Callback spans cannot outlive their callback.
- Diagnostic classifications exclude secret values, credentials and protected coordinates; host instrumentation and exported strings remain host responsibilities.
- Cancellation propagates. Mutation receipts retain dispatch evidence; uncertain writes must not be replayed automatically.
- A local generation is not a remote multi-key transaction, fleet convergence or proof of downstream readiness.
- Offline success is not live provider, entitlement, platform or production qualification.

Review host diagnostics, configuration debug views, exception sinks and downstream clients before exporting plaintext. Default-surface capture does not authorize recording complete requests, authorization headers, exported values or process memory. The nonpackable demo diagnostic observer is a test fixture, not a production redaction component. The tested surfaces and unqualified combinations are recorded in the [runtime adoption security contract](docs/internal/RUNTIME_ADOPTION_SECURITY.md); the full reasoning is in [security and resource ownership](docs/public/security-and-ownership.md).

---

## 🧪 Verification

Run from the SecretKit repository root with the SDK pinned in [`global.json`](global.json). Restore and rebuild first when inputs changed.

```bash
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet format SecretKit.slnx --verify-no-changes --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --output artifacts/packages
```

These commands build local artifacts; they do not publish a release.

- **Test stack:** TUnit with `Microsoft.Testing.Platform` — not the VSTest runner — under a positive minimum test count.
- **Async tests:** Exact event barriers and injected time; never sleeps or timing-dependent polling.
- **Assertions:** Behavior through the public adapter/transport seam and resulting state, never mock call counts.
- **Focused loops:** Per-project build and test via [PROJECTS.md](PROJECTS.md); they never replace the full SDK exit checks.
- **Documentation changes:** Relative-link, formatting and path/command validation instead of product builds.
- **CI:** [Credential-free SDK verification][ci-link] runs the format and verification lanes on `ubuntu-24.04`, `windows-2025` and `macos-15` runners.

Skipping a test never manufactures a passing support claim. Missing identities, entitlements, cloud coverage and publisher rights are recorded as open gates, not assumed away. Live verification requires an environment you own or are explicitly authorized to use, with separately selected identities.

Release-tool lanes go further than the solution build: `verification ordinary`, `verification prepare-local`, `verification post-pack` and `verification offline-conformance` own fixed cohort-derived selectors and positive discovery floors. Their exact ownership and archive handling are described in [local packages](docs/public/local-packages.md).

---

## 📚 Documentation: Public Guides vs. Internal Contracts

Public pages state implemented behavior for adopters. Internal pages carry architecture, decision records and qualification evidence. When they disagree, the internal contract owns the truth and the public page is repaired.

### Public guides

| Task | Start with |
| --- | --- |
| **Install and first run** | [Getting started](docs/public/getting-started.md), [local packages](docs/public/local-packages.md) |
| **Read values and own them** | [Core API](docs/public/core-api.md), [Infisical](docs/public/providers/infisical.md), [Azure Key Vault](docs/public/providers/azure-key-vault.md) |
| **Collect settings and replace generations** | [Configuration and runtime](docs/public/configuration-and-runtime.md) |
| **Compose login, renewal and shutdown** | [Authentication and hosting](docs/public/authentication-and-hosting.md) |
| **Administer separately** | [Management](docs/public/providers/management.md) |
| **Operate and diagnose** | [Operations and compatibility](docs/public/operations-and-compatibility.md), [troubleshooting](docs/public/troubleshooting.md), [demos and recovery](docs/public/demos-and-recovery.md) |
| **Build operator tooling** | [Interactive hosts](docs/public/interactive-hosts.md) |
| **Check a claim** | [Current preview](docs/public/current-preview.md), [provider support](docs/public/provider-support.md), [scope and orchestration](docs/public/scope-and-orchestration.md) |
| **Justify adoption** | [Adoption and value](docs/public/adoption-and-value.md), [connector scope decision](docs/public/connector-scope-decision.md) |
| **Work with an AI agent** | [Reading map for AI coding agents](docs/public/ai-agents.md) |

### Internal contracts

Architecture, runtime contracts, ADRs, readiness, qualification evidence, delivery and security surfaces live under [docs/internal/](docs/internal/README.md). Start with [docs/README.md](docs/README.md) and [docs/internal/README.md](docs/internal/README.md).

## 🤝 Contributing

The immediate priority is [Infisical-first local readiness](docs/internal/INFISICAL_LOCAL_READINESS.md); Azure and selected administration remain retained work.

**Before you invest in a change:**

1. Read the [current preview](docs/public/current-preview.md) and [scope](docs/public/scope-and-orchestration.md) — planned native operations are not all implemented or live-verified.
2. Check the [accepted catalog-removal decision](docs/public/connector-scope-decision.md); third-party connection and sync administration is outside current product scope.
3. Use [issues][issues-link] for ordinary bugs and proposals; discuss package, API, dependency and broad refactor changes first.
4. Report vulnerabilities privately through [SECURITY.md](SECURITY.md), including fixes discovered in forks.
5. Find your change's owner and tests in [PROJECTS.md](PROJECTS.md), then the invariants in [AGENTS.md](AGENTS.md).

**Non-Technical:**
- 🐛 [Report bugs][issues-link]
- 💡 [Suggest features][issues-link]
- 📖 [Improve public documentation](docs/README.md)
- 📣 Spread the word in your community

**Technical:**
- 💻 Fix bugs & implement features
- 🧪 Add deterministic tests through the affected public seam
- 📊 Measure and document provider support honestly
- 🎨 Improve samples and operator tooling

Keep Core BCL-only, keep provider-native features typed, and preserve explicit identity selection, material ownership, cancellation, bounded responses and mutation uncertainty. Label proposed behavior, implemented subsets, offline evidence and live conformance separately — and never put real credentials, values, sensitive coordinates or personal data in examples, fixtures, logs or attachments.

Pull requests describe the problem, resulting behavior, affected packages and actual verification, including omissions and remaining provider or platform gates. Follow the [pull request template](.github/PULL_REQUEST_TEMPLATE.md) and disclose AI assistance. Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## 🛡️ Security Disclosure

Report vulnerabilities privately to [security@openislamu.org](mailto:security@openislamu.org). Do not open a public issue or pull request containing an undisclosed vulnerability, and coordinate security fixes from forks through the same channel.

Include the affected package and version or commit; the .NET SDK, OS and provider version where relevant; a minimal reproduction using synthetic material and sanitized coordinates; expected and observed behavior with impact; and whether the evidence comes from a controlled transport or an authorized live provider. Never send real tokens, credentials, secret values, confidential coordinates or personal data.

Maintainers assess the report and coordinate disclosure and a fix where applicable. No response-time SLA or bounty is promised, and this unpublished preview has no stable-release support window or security certification. Test only environments you own or have explicit permission to assess. Full policy: [SECURITY.md](SECURITY.md).

---

## Community

Join the ISLAMU community on [Discord][discord-link] and our [GitHub Discussions][github-discussions-link]. We follow a [Code of Conduct][code-of-conduct] in all our community channels.

Ask in [issues][issues-link] with the package, version, sanitized failure category and a minimal reproduction. Concrete failures are how the support statements stay honest.

> Give us a Star ⭐️

---

## Contributors

### Core Maintainer

| Amir Akrari |
| :---: |
| <img src="https://github.com/amirakrari.png" width="200px" alt="Amir Akrari" /> |
| <a href="https://github.com/amirakrari"><img src="https://api.iconify.design/devicon:github.svg" width="25px"></a> <a href="https://bsky.app/profile/amirakrari.bsky.social"><img src="https://api.iconify.design/simple-icons:bluesky.svg" width="25px"></a> |

I am deeply grateful to all our amazing contributors.

---

## 💖 Sponsors

Support ISLAMU SecretKit's ongoing development, infrastructure, and open-source mission by becoming a financial sponsor.

- **Monthly Support:** [👉 Support Monthly via Stripe][stripe-monthly-link]
- **One-Time Contribution:** [👉 Donate Once via Stripe][stripe-oneoff-link]

> 💼 To discuss corporate sponsorship, custom invoicing, or enterprise partnerships, email us at [contact@openislamu.org][contact-email].

---

## 🤝 In-Kind Supporters

Special thanks to the organizations providing free tooling, infrastructure, and licenses to support ISLAMU's open-source development:

| Organization | Contribution & Usage |
| :---: | --- |
| [**GitBook**](https://www.gitbook.com) | Generously provides their Community Plan to host and power our public documentation. |
| [**Sonar Gitar**](https://gitar.ai) | Generously provides their Gitar Open Source Program to empower our development with AI code review. |

> If your organization would like to support ISLAMU SecretKit with in-kind tooling, infrastructure, or software licenses, please reach out to us at [contact@openislamu.org][contact-email].

---

## 🧰 Public-Repository Tools

We appreciate these generally available public-repository tools. They are not project-specific sponsorships.

- [CodeRabbit](https://www.coderabbit.ai/): AI code reviews for pull requests.
- [Codecov](https://about.codecov.io/): Test coverage reporting.
- [Socket.dev](https://socket.dev/): Dependency security analysis.
- [Imgbot](https://imgbot.net/): Automated image optimization.
- [Coverity](https://scan.coverity.com/): Static analysis code scanning you can trust.
- [SonarQube Cloud](https://www.sonarsource.com/products/sonarqube/cloud/): Code quality and security analysis.

---

## ISLAMU Solutions

SecretKit is part of the [ISLAMU][islamu-org-link] open-source ecosystem, alongside **ISLAMU Event** (self-hostable event discovery and management) and **ISLAMU Configurator** (offline-first software configuration assistant). Event and Configurator are requirements references for this SDK — never imported implementation, and never an implied activation, tenant policy or deployment integration.

- [ISLAMU Event][event-repo-link]: Event Platform & Management System.
- [ISLAMU Configurator][configurator-repo-link]: Universal, Offline-first Software Configuration Assistant.
- [I-VSD][ivsd-repo-link]: Islamic Value Sensitive Design: A Framework for Provider-Mediated Software Solutions
- [SecretKit][secretkit-repo-link]: Unified secret management SDK for .NET

---

## 🙏 Acknowledgements

- [.NET](https://dotnet.microsoft.com) and the `Microsoft.Extensions.*` packages: runtime, configuration, hosting and health abstractions.
- [Azure SDK for .NET](https://github.com/Azure/azure-sdk-for-net): Key Vault data-plane and resource-management clients.
- [Infisical](https://infisical.com): the secret-management platform whose public API facts this SDK implements against.
- [Refit](https://github.com/reactiveui/refit): typed HTTP clients in the Infisical packages.
- [TUnit](https://tunit.dev): the test framework behind every offline suite.
- [GitHub Actions](https://github.com/features/actions) and [Shields.io](https://shields.io): verification and documentation presentation.

---

## 🌱 Sustainability

ISLAMU is built by one person — **Amir Akrari** — entirely on personal free time and personal funds. **ISLAMU (ASBL en formation)** (a non-profit association in formation in Belgium) is being established as the operational and legal steward of all ISLAMU open-source projects. Sustainability is built on fundraising and grants, ranked sponsorship tiers, official partnerships and fleet tooling, and professional consulting — never on a hosted SaaS competing with partners.

If you are a company or institution that wants to support this work, reach out at [contact@openislamu.org][contact-email] or start a conversation in our [Discord][discord-link].

---

## 📞 Contact

For any question or problem reporting, please consider opening a [new issue][issues-link] or send an email to [contact@openislamu.org][contact-email] or create a new post in our [Discord Server][discord-link].

## Privacy Policy

You can find details [here][privacy-policy-link].

---

## 📄 License and Provenance

Released under the [MIT License](LICENSE):

> Copyright (c) 2026 ISLAMU

Dependencies and generated artifacts retain their own terms; resolved versions, licenses and provenance records live in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). The ISLAMU logo files under `assets/images/adopters/ISLAMU/` carry their own [license](assets/images/adopters/ISLAMU/LICENSE.md): CC BY 4.0, with no trademark rights in the ISLAMU name or logos granted. Contributions must be original material licensable under MIT — SecretKit does not import Event's AGPL license or Configurator's implementation, does not copy vendor code, tests or expressive schemas, and designs from supported public-interface facts with repository-native structure.

---

## 🏗️ Technology Stack

| Layer | Technology |
| --- | --- |
| Runtime | .NET 10, SDK 10.0.404 |
| Architecture | BCL-only core; provider packages depend inward on Core |
| HTTP | Refit typed HTTP clients |
| Azure | Azure SDK for .NET (Key Vault data plane and resource management) |
| Configuration | Microsoft.Extensions.Configuration |
| Hosting | Microsoft.Extensions.Hosting and health abstractions |
| Serialization | System.Text.Json (strict UTF-8 ownership) |
| Tests | TUnit with Microsoft.Testing.Platform |
| SBOM | Microsoft.Sbom.Targets 4.1.13 (SPDX 2.2) |
| Packaging | .nupkg with embedded README and THIRD-PARTY-NOTICES |

---

<div align="right">

[![][back-to-top]][back-to-top-link]

</div>

<!-- LINK GROUP -->

[back-to-top]: https://img.shields.io/badge/-BACK_TO_TOP-151515?style=flat-square
[back-to-top-link]: #readme-top

[ci-link]: https://github.com/islamu-ngo/SecretKit/actions/workflows/verify.yml
[ci-shield]: https://img.shields.io/github/actions/workflow/status/islamu-ngo/SecretKit/verify.yml?branch=main&logo=github&style=flat-square
[license-link]: LICENSE
[license-shield]: https://img.shields.io/github/license/islamu-ngo/SecretKit?color=1BC47D&style=flat-square
[dotnet-link]: https://dotnet.microsoft.com
[dotnet-shield]: https://img.shields.io/badge/.NET-10.0-512BD4?style=flat-square&logo=dotnet&logoColor=white
[packages-shield]: https://img.shields.io/badge/packages-7-0EA5E9?style=flat-square
[status-shield]: https://img.shields.io/badge/status-development_preview-F59E0B?style=flat-square
[commit-link]: https://github.com/islamu-ngo/SecretKit/commits/main
[commit-shield]: https://img.shields.io/github/last-commit/islamu-ngo/SecretKit?style=flat-square
[discord-link]: https://discord.gg/wrkY824Yv5
[discord-shield]: https://img.shields.io/discord/1357505436479131668?color=%237289da&label=Discord&logo=discord&logoColor=%237289da&style=flat-square
[issues-link]: https://github.com/islamu-ngo/SecretKit/issues/new/choose
[github-discussions-link]: https://github.com/islamu-ngo/SecretKit/discussions
[code-of-conduct]: CODE_OF_CONDUCT.md
[contact-email]: mailto:contact@openislamu.org
[privacy-policy-link]: https://openislamu.org/privacy
[islamu-org-link]: https://github.com/islamu-ngo
[event-repo-link]: https://github.com/islamu-ngo/Event
[configurator-repo-link]: https://github.com/islamu-ngo/Configurator
[ivsd-repo-link]: https://github.com/islamu-ngo/Islamic-Value-Sensitive-Design
[secretkit-repo-link]: https://github.com/islamu-ngo/SecretKit
[stripe-monthly-link]: https://donate.stripe.com/bJeeVeesc9kIdpCbMPaR201
[stripe-oneoff-link]: https://donate.stripe.com/14A6oIesc0Oc2KYg35aR200
