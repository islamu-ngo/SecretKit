<a name="readme-top"></a>

<div align="center">

<img src="https://raw.githubusercontent.com/islamu-ngo/Event/develop/assets/images/adopters/ISLAMU/islamu-logo-text-only-v2.png" alt="ISLAMU logo" width="200" />

# ISLAMU SecretKit

Open-source .NET secret-management libraries for Infisical and Azure Key Vault.

One small common read contract, typed provider-native operations, and explicit application-owned authority.

> 🚧 **Active Pre-Release Development:** SecretKit is an unpublished development preview. Local packages and selected provider checks exist; they do not establish complete API coverage, production readiness, or a public NuGet release. Start with the [current preview](docs/public/current-preview.md).

[![GitHub License][github-license-shield]][license-link]
[![GitHub Repo Stars][github-stars-shield]][github-stars-link]
[![GitHub Last Commit][github-last-commit-shield]][github-repo-link]
[![Contributors][github-contributors-shield]][github-contributors-link]
[![Discord][discord-shield]][discord-link]
[![Documentation][docs-shield]][docs-link]
[![Donate via Stripe][stripe-shield]][stripe-monthly-link]

[**Documentation**][docs-link] · [**Current Preview**](docs/public/current-preview.md) · [**Quickstart**](#quick-start-for-developers--contributors) · [**Developer Guide**](PROJECTS.md) · [**Sponsor**](#-sponsors)

</div>

## About ISLAMU SecretKit

SecretKit is an in-process **.NET 10 SDK** for applications that explicitly select Infisical or Azure Key Vault. Common reads and metadata inventory stay small; provider-specific writes, authentication, lifecycle, and administration retain their native semantics.

The consuming application owns credential injection, permissions, configuration meaning, client activation, and persistence. Installing a package does not grant provider access. SecretKit has no dependency on Event or Configurator applications.

The current priority is the two-provider SDK. Broader administration and guided Configurator deployment are separate outcomes; see [scope and future orchestration](docs/public/scope-and-orchestration.md).

## ✨ Who It Serves

### Application Developers

- **🔑 Explicit Provider Selection:** Read through a selected client and authority-bound reference, without an implicit fallback identity.
- **🧩 Small Common Contracts:** Use `ISecretReader` and `ISecretInventory` while preserving provider-owned coordinates and version semantics.
- **🔒 Owned Secret Material:** Dispose successful reads after use; deliberate string export remains a separate plaintext boundary.
- **📦 Optional Composition:** Add configuration snapshots or hosting integration only when the application needs them.

### Operators & Integration Authors

- **🛡️ Separate Identities:** Assess access through the intended runtime identity rather than treating administrator visibility as delivery.
- **📜 Typed Native Operations:** Use supported provider-specific operations without a raw-request escape hatch or invented cross-provider guarantees.
- **🔍 Bounded Evidence:** Distinguish absence, denial, unknown outcomes, incomplete inventories, and unverified compatibility.
- **🧪 Offline Examples:** Explore required bootstrap, generation replacement, and fresh access assessment without a provider account.

### Platform Owners & Self-Hosters

- **🆓 MIT-Licensed SDK:** First-party libraries use MIT; dependencies retain their own licenses and notices.
- **🏗️ Independent Libraries:** Core uses the BCL only. No database, UI, or ASP.NET shared framework is required.
- **📚 Two Documentation Tracks:** Public guides explain adoption; internal specifications record design and verification boundaries.
- **🧭 Host-Owned Policy:** Keep tenant isolation, readiness, reload scheduling, and fleet convergence in the application that owns them.

---

## 🚀 Integration & Package Options

SecretKit runs inside your application. Choose the packages that match its responsibilities:

| Package | Responsibility | Package Guide |
| --- | --- | --- |
| `SecretKit.Core` | Common reads, metadata inventory, outcomes, references, and disposable material | [Core Contracts](src/SecretKit.Core/) |
| `SecretKit.Infisical` | Infisical runtime access and supported native lifecycle/authentication operations | [Infisical](src/SecretKit.Infisical/README.md) |
| `SecretKit.AzureKeyVault` | Azure Key Vault secret data-plane access | [Azure Key Vault](src/SecretKit.AzureKeyVault/README.md) |
| `SecretKit.Infisical.Management` | Optional, explicitly authorized Infisical administration | [Infisical Administration](src/SecretKit.Infisical.Management/README.md) |
| `SecretKit.AzureKeyVault.Management` | Optional Azure administration and separately authorized audit access | [Azure Administration](src/SecretKit.AzureKeyVault.Management/README.md) |
| `SecretKit.Extensions.Configuration` | Prepared generations and deliberate plaintext configuration export | [Configuration](src/SecretKit.Extensions.Configuration/README.md) |
| `SecretKit.Extensions.Hosting` | Explicitly started authentication maintenance and health integration | [Hosting](src/SecretKit.Extensions.Hosting/README.md) |

These packages are present in the checkout, with bounded implemented subsets. Package existence is not complete native-operation support. Local installation evidence, offline tests, and live provider conformance have different scopes; consult the [current preview](docs/public/current-preview.md) before selecting an operation.

## 🎨 Application-Owned Configuration

Your application selects its provider, origin, credentials, and key mapping. Optional snapshots publish a complete local generation; they do not promise a remote transaction or activate your application clients for you.

Configurator may eventually orchestrate setup using these building blocks. No working end-to-end deployment workflow is claimed. See [configuration and runtime](docs/public/configuration-and-runtime.md) and [scope and orchestration](docs/public/scope-and-orchestration.md).

---

## 🛡️ Security & Trust Boundaries

- **Selected Authority:** References belong to a specific client; credentials and remote provider policy remain the authority for access.
- **Material Ownership:** Successful reads own disposable material. `Reveal` and configuration export create ordinary managed strings that SDK disposal cannot erase.
- **Controlled Networking:** SDK-owned transports bound responses and use documented origin, redirect, retry, and diagnostic controls. Host-supplied instrumentation remains the host's responsibility.
- **Mutation Uncertainty:** Supported mutations retain caller-held receipts. A lost response can leave an unknown outcome; the SDK does not silently replay the write.
- **Honest Support Claims:** Offline tests cannot prove provider permissions, editions, cloud compatibility, or destination delivery.

See [SECURITY.md](SECURITY.md), [runtime contracts](docs/internal/RUNTIME_CONTRACTS.md), and the [current preview](docs/public/current-preview.md) for exact boundaries. No security certification or compliance accreditation is claimed.

## FAQ

### Is SecretKit ready for production or available on NuGet?

This checkout is an unpublished preview. You can build local packages and evaluate supported slices, but no public package availability or production support policy is established. Azure live verification, broader provider coverage, and publication gates remain explicit limits in the [current preview](docs/public/current-preview.md).

### Does SecretKit replace my secret provider?

SecretKit is a client library. Infisical or Azure Key Vault stores and governs the secrets. Your application supplies credentials and chooses the identity; SecretKit does not provision a provider or discover an administrative principal automatically.

### Does disposing a read remove every copy of its secret?

Dispose each successful `SecretRead` to release its owned material. Strings created by `Reveal`, exported configuration values, logs, and downstream library copies are outside that buffer's lifetime. Review the application's plaintext boundaries and instrumentation.

### Does metadata visibility prove that an application can use a secret?

Metadata inventory and value access are separate operations. An administrator seeing a secret does not prove runtime access, freshness, downstream delivery, or application activation. The [ProviderAssessment sample](samples/ProviderAssessment/Program.cs) demonstrates that distinction with controlled offline identities.

### Are writes and configuration refreshes transactional?

Supported writes retain provider-native semantics and uncertainty. A complete local configuration generation avoids publishing a partial mixture, but it is not a multi-key remote snapshot, transaction, or rollback. Applications own validation and activation.

### Do I need deployment connectors to read secrets?

Ordinary Infisical or direct Azure Key Vault access does not require a connection to a deployment destination. The broad Infisical third-party connection/sync catalog has been removed from local source; selected optional administration and native secret features remain. Local post-removal verification passed. See the [accepted scope decision](docs/public/connector-scope-decision.md).

---

## Roadmap

The [repository scope](docs/public/scope-and-orchestration.md) describes the current two-provider priority and future orchestration. The wider ISLAMU [roadmap][roadmap-link] provides ecosystem context. Propose SecretKit changes through [issues][github-issues-link]; a roadmap entry is not an implemented support claim.

## 🤝 Contributing

You can help by reporting reproducible bugs, improving adopter guides, testing supported provider combinations with owned identities, or contributing focused SDK changes. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request and follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Quick Start (For Developers & Contributors)

Install **.NET SDK 10.0.302**, as pinned in [global.json](global.json), then use an independent checkout:

```bash
git clone https://github.com/islamu-ngo/SecretKit.git
cd SecretKit
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet run --project samples/RuntimeConfiguration --configuration Release --no-build
dotnet run --project samples/ProviderAssessment --configuration Release --no-build
```

Both samples run **offline demonstrations**, without real provider credentials, database connections, or remote mutations. They illustrate SDK ownership and consumer policy; they do not establish live provider conformance.

For verification and local packages:

```bash
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet format SecretKit.slnx --verify-no-changes --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --output artifacts/packages
```

Packing creates local evaluation artifacts and does not publish them. The [project guide](PROJECTS.md) maps owners and focused commands; the [agent contract](AGENTS.md) records invariants and verification expectations.

### Contributor Onboarding Path

1. Read [CONTRIBUTING.md](CONTRIBUTING.md) and run the offline quickstart.
2. Use [PROJECTS.md](PROJECTS.md) to locate the package and tests for your change.
3. Check the [current preview](docs/public/current-preview.md), [architecture](docs/internal/SDK_ARCHITECTURE.md), and [runtime contracts](docs/internal/RUNTIME_CONTRACTS.md).
4. For AI-assisted work, follow [AGENTS.md](AGENTS.md) and review every proposed change.

### ✍️ Contributor Licensing

Contribute material you have the right to license under the repository's [MIT license][license-link]. Preserve provenance and dependency notices. SecretKit has its own contribution contract; Event's AGPL and CLA workflows do not apply automatically. Vendor or sibling-project implementation source must not be copied into these libraries.

---

## 📚 Documentation: Public Guides vs. Internal Specifications

The [documentation hub][docs-link] routes readers to the correct track. Design documents explain intent; the current-preview page identifies implemented behavior and remaining verification gates.

### 🌐 Public Adopter Guides

| Guide | Reader Question |
| --- | --- |
| [Current Preview](docs/public/current-preview.md) | What is implemented and what remains unverified? |
| [Adoption and Value](docs/public/adoption-and-value.md) | Where might this SDK help my application? |
| [Configuration and Runtime](docs/public/configuration-and-runtime.md) | Who owns secrets, generations, and activation? |
| [Operations and Compatibility](docs/public/operations-and-compatibility.md) | How are native support and compatibility bounded? |
| [Scope and Orchestration](docs/public/scope-and-orchestration.md) | How do core access, administration, and deployment differ? |

### 🛠️ Internal Engineering Specifications

| Engineering Concern | Repository Document |
| --- | --- |
| Project ownership and local commands | [PROJECTS.md](PROJECTS.md) |
| Contributor and agent invariants | [AGENTS.md](AGENTS.md) |
| Package boundaries | [SDK_ARCHITECTURE.md](docs/internal/SDK_ARCHITECTURE.md) |
| Ownership, cancellation, outcomes, and receipts | [RUNTIME_CONTRACTS.md](docs/internal/RUNTIME_CONTRACTS.md) |
| Admission, maintenance, and publication gates | [DELIVERY_AND_MAINTENANCE.md](docs/internal/DELIVERY_AND_MAINTENANCE.md) |
| Engineering evidence and provider registries | [Internal Documentation](docs/internal/README.md) |

## 🏗️ Technology Stack

| Layer | Technology |
| --- | --- |
| Runtime | .NET 10 / C# 14; SDK pinned in `global.json` |
| Core | BCL-only contracts |
| Infisical transport | Handwritten typed contracts, Refit, and controlled HttpClient transport |
| Azure access | Official Azure SDK with explicit credentials |
| Optional composition | Microsoft.Extensions.Configuration and hosting abstractions |
| Tests | TUnit / Microsoft.Testing.Platform |
| Dependency management | Central versions and generated package lockfiles |

## Community

Meet the wider ISLAMU community on [Discord][discord-link]. Use [SecretKit issues][github-issues-link] for reproducible SDK bugs and proposals. All participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## 🛡️ Security Disclosure

Report vulnerabilities privately to [contact@openislamu.org][contact-email], including security fixes discovered in forks. Keep credentials, secret values, and confidential provider coordinates out of reports and public pull requests. Read [SECURITY.md](SECURITY.md) for disclosure guidance.

## Contributors

### Core Maintainer

| Amir Akrari |
| :---: |
| <img src="https://github.com/amirakrari.png" width="200" alt="Amir Akrari" /> |
| [GitHub](https://github.com/amirakrari) · [Bluesky](https://bsky.app/profile/amirakrari.bsky.social) |

Thank you to everyone who contributes code, documentation, testing, and review.

[![Contributors Image][contributors-image]][github-contributors-link]

## 💖 Sponsors

Support the ISLAMU open-source work behind SecretKit:

- [Monthly support via Stripe][stripe-monthly-link]
- [One-time contribution][stripe-oneoff-link]
- For organizational support, contact [contact@openislamu.org][contact-email].

## 🤝 In-Kind Supporters

Provider test environments, infrastructure, and review time can help establish verified support. Discuss an offer privately with [the maintainers][contact-email] before sharing credentials or granting access.

## ISLAMU Solutions

- [ISLAMU Event](https://github.com/islamu-ngo/Event): event platform and management system.
- [ISLAMU Configurator](https://github.com/islamu-ngo/Configurator): offline configuration preparation utility.
- [I-VSD](https://github.com/islamu-ngo/Islamic-Value-Sensitive-Design): Islamic Value Sensitive Design framework.

## 🙏 Acknowledgement

SecretKit builds on .NET, Refit, the Azure SDK, Microsoft.Extensions, and TUnit. Infisical and Azure Key Vault provide the native services these adapters address. Exact direct versions live in [Directory.Packages.props](Directory.Packages.props); attribution and distribution boundaries live in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## 🌱 Sustainability

SecretKit is part of the ISLAMU open-source ecosystem. Sponsorship, contributions, and practical verification help maintain the SDK and its provider contracts. Contact [the maintainers][contact-email] to discuss support or integration needs.

## 📞 Contact

For ordinary SDK questions and problems, open a [repository issue][github-issues-link] or join [Discord][discord-link]. For private matters, email [contact@openislamu.org][contact-email].

## 📄 License & Ecosystem Architecture

SecretKit's first-party libraries are licensed under [MIT][license-link]. Third-party dependencies keep their own terms. Event is a separately governed application; its licensing does not change SecretKit's license or create a runtime dependency.

Core remains independent of provider SDKs and host frameworks. Provider adapters depend inward on Core; configuration export, hosting, and management remain optional packages. Publication requires its own provenance, verification, publisher rights, and authorization; a local package build does not satisfy those gates.

<div align="right">

[Back to top](#readme-top)

</div>

[license-link]: LICENSE
[docs-link]: docs/README.md
[contact-email]: mailto:contact@openislamu.org
[github-repo-link]: https://github.com/islamu-ngo/SecretKit
[github-issues-link]: https://github.com/islamu-ngo/SecretKit/issues/new/choose
[github-stars-link]: https://github.com/islamu-ngo/SecretKit/stargazers
[github-contributors-link]: https://github.com/islamu-ngo/SecretKit/graphs/contributors
[github-license-shield]: https://img.shields.io/github/license/islamu-ngo/SecretKit?color=594ae2&logo=github&style=flat-square
[github-stars-shield]: https://img.shields.io/github/stars/islamu-ngo/SecretKit?color=594ae2&style=flat-square&logo=github
[github-last-commit-shield]: https://img.shields.io/github/last-commit/islamu-ngo/SecretKit?color=594ae2&style=flat-square&logo=github
[github-contributors-shield]: https://img.shields.io/github/contributors/islamu-ngo/SecretKit?color=594ae2&style=flat-square&logo=github
[contributors-image]: https://contrib.rocks/image?repo=islamu-ngo/SecretKit
[discord-shield]: https://img.shields.io/discord/1357505436479131668?color=%237289da&label=Discord&logo=discord&logoColor=%237289da&style=flat-square
[discord-link]: https://discord.gg/wrkY824Yv5
[docs-shield]: https://img.shields.io/badge/Docs-Markdown-3884FF?style=flat-square&logo=markdown&logoColor=white
[stripe-shield]: https://img.shields.io/badge/Donate-Stripe-635BFF?style=flat-square&logo=stripe&logoColor=white
[stripe-monthly-link]: https://donate.stripe.com/bJeeVeesc9kIdpCbMPaR201
[stripe-oneoff-link]: https://donate.stripe.com/14A6oIesc0Oc2KYg35aR200
[roadmap-link]: https://sites.plane.so/views/b8b7d9fced694f5a9d9a546e9d40d988
