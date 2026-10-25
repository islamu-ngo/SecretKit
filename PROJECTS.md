# SecretKit project guide

Use this map to locate a change's owner before editing. Package presence does not establish complete API or provider support; check the [current preview](docs/public/current-preview.md) first.

## Five-minute mental model

Core defines common reads, inventory, references, outcomes, and disposable material. Provider packages depend inward on Core and preserve native semantics. Management packages separate administrative dependencies from ordinary runtime access. Configuration export and hosting are independent optional composition layers.

The immediate 2026-10-23 priority is
[Infisical-first local-package readiness](docs/internal/INFISICAL_LOCAL_READINESS.md).
The planned four-package local profile is separate from the existing
seven-package public release family. Azure and management completion are not
prerequisites for that local goal; their existing regression protection remains.
No Event or Configurator repository implementation belongs in this workstream.

All projects target `net10.0`; tests, samples, and tools are non-packable. The frozen Infisical registry is `ContractResearchOnly` evidence, not current admission. The basic management inventory has 122 research rows / 121 callable projections in five families, no connector families, and does not enumerate all retained administration.

The [accepted scope decision](docs/public/connector-scope-decision.md) removes the broad third-party connection/sync catalog, retaining project/identity/access administration, native SQL rotation configuration and runtime features, and existing gateway/proxy administration. Ordinary provider reads need no external connector. Local post-removal verification passed; live-provider gates remain separate.

The application supplies identities and owns validation, activation, persistence, and readiness. SecretKit does not grant permissions, choose fallback principals, or orchestrate deployments. See [architecture](docs/internal/SDK_ARCHITECTURE.md) and [runtime contracts](docs/internal/RUNTIME_CONTRACTS.md).

## Package and test owners

| Owner | Source | Main Test Suite |
| --- | --- | --- |
| Common contracts and material | [SecretKit.Core](src/SecretKit.Core/) | [Core tests](tests/SecretKit.Core.Tests/) |
| Infisical runtime and native lifecycle | [SecretKit.Infisical](src/SecretKit.Infisical/) | [Infisical tests](tests/SecretKit.Infisical.Tests/) |
| Azure secret data plane | [SecretKit.AzureKeyVault](src/SecretKit.AzureKeyVault/) | [Azure tests](tests/SecretKit.AzureKeyVault.Tests/) |
| Infisical administration | [SecretKit.Infisical.Management](src/SecretKit.Infisical.Management/) | [Infisical management tests](tests/SecretKit.Infisical.Management.Tests/) |
| Azure administration and audit | [SecretKit.AzureKeyVault.Management](src/SecretKit.AzureKeyVault.Management/) | [Azure management tests](tests/SecretKit.AzureKeyVault.Management.Tests/) |
| Prepared generations and export | [SecretKit.Extensions.Configuration](src/SecretKit.Extensions.Configuration/) | [Configuration tests](tests/SecretKit.Configuration.Tests/) |
| Explicit hosted maintenance | [SecretKit.Extensions.Hosting](src/SecretKit.Extensions.Hosting/) | [Hosting tests](tests/SecretKit.Hosting.Tests/) |

Cross-cutting verification lives in [tests](tests/), including architecture, consumer, assessment, package, and release suites. The [internal hub](docs/internal/README.md) routes provider registries and compatibility evidence.

The [shared provider suite](tests/SecretKit.ProviderContract.Tests/) exercises
common invariants through actual Infisical and Azure adapters. It does not replace
native effect tests. Follow [provider onboarding](docs/internal/PROVIDER_ONBOARDING.md)
and [current support](docs/public/provider-support.md) before extending a provider.

## Samples and tools

- [Infisical.ConsoleDemo](samples/Infisical.ConsoleDemo/): package-only console
  read/explicit-write consumer; pack/select a candidate before restoring it.
  It is deliberately outside the pre-pack solution build. Its process tests
  require explicit demo candidate directory/version inputs; offline outcomes
  do not establish live conformance.

- [Infisical.WorkerDemo](samples/Infisical.WorkerDemo/): independent package-only
  Generic Host worker with awaited required admission, explicitly selected
  session, opt-in scheduled maintenance and bounded work/renew/stop controls.
  App-only Hosting 10.0.12 does not change SDK profile graphs. Actual installed
  host/renewal/drain tests live in `SecretKit.Demo.Tests/WorkerDemoTests.cs`;
  injected-time lifecycle tests remain in `SecretKit.Hosting.Tests`.

- [Infisical.WebDemo](samples/Infisical.WebDemo/): loopback-only installed-package
  Kestrel API with awaited required admission, separate liveness/readiness,
  explicit stdin activation controls and request-pinned downstream job clients.
  ASP.NET is confined to this nonpackable app. Actual HTTP handover, denial,
  optional-failure and disclosure tests live in `SecretKit.Demo.Tests/WebDemoTests.cs`;
  these controlled process observations are not native qualification.

- [RuntimeConfiguration](samples/RuntimeConfiguration/): offline required bootstrap and generation ownership.
- [Controlled measurements](samples/Infisical.Demos/Measurements.cs): nonpackable fixed local workload, linked only into the isolated exact-package consumer generated by `SecretKit.Demo.Tests/DemoQualityTests.cs`; [records and recovery guide](docs/public/demos-and-recovery.md).
- [ProviderAssessment](samples/ProviderAssessment/): offline administrator visibility versus intended-identity delivery.
- [ConsumerBaseline](tools/SecretKit.ConsumerBaseline/): consumer comparison tooling, not application runtime.
- [Release](tools/SecretKit.Release/): release verification and publication tooling with separate authority gates.

Do not treat a tool or sample as a remote execution grant. Publication and live-provider checks require their actual authorization.

## Commands

Run from the SecretKit root with the SDK in [global.json](global.json). The complete SDK handoff commands are in [AGENTS.md](AGENTS.md); the onboarding sequence is in [CONTRIBUTING.md](CONTRIBUTING.md).

For a focused inner loop after locked restore:

```bash
dotnet build tests/SecretKit.Core.Tests/SecretKit.Core.Tests.csproj --configuration Release --no-restore
dotnet test --project tests/SecretKit.Core.Tests/SecretKit.Core.Tests.csproj --configuration Release --no-build
```

Replace the project with the affected suite. Tests use TUnit and Microsoft.Testing.Platform, not the VSTest runner. Focused checks do not replace the repository's required SDK exit checks.

Documentation changes use relative-link, formatting, and path/command validation. No product build is needed when product behavior is unchanged.
