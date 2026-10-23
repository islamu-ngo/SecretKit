# SecretKit documentation

Choose the track for your task. SecretKit is an unpublished .NET SDK preview; proposed design, implemented behavior, and live verification are separate claims.

## Using and evaluating the SDK

- [Repository overview](../README.md): packages, quickstart, trust boundaries, and community.
- [Current preview](public/current-preview.md): implemented subsets and verification limits.
- [Current provider support](public/provider-support.md): package scope, executable offline evidence and unverified combinations.
- [Database credential boundary](public/database-credentials.md): opaque secret material, typed Infisical APIs and separate optional database verification.
- [Public design hub](public/README.md): adoption, configuration, compatibility, and intended behavior.
- [Scope and future orchestration](public/scope-and-orchestration.md): retained two-provider access, optional administration and future Configurator responsibility.
- [Connector scope decision](public/connector-scope-decision.md): accepted/applied catalog removal, retained support and local verification.
- [Package guides](../src/): package-specific entry points and responsibilities.

## Contributing and reviewing

- [Contribution guide](../CONTRIBUTING.md): local workflow and pull request evidence.
- [Project map](../PROJECTS.md): source owners, tests, samples, and tools.
- [Agent contract](../AGENTS.md): SDK invariants and verification baseline.
- [Internal documentation hub](internal/README.md): architecture, runtime contracts, provider inventories, and evidence.
- [Provider onboarding](internal/PROVIDER_ONBOARDING.md): setup, ownership and evidence requirements for both current providers.
- [Dependency provenance](../THIRD-PARTY-NOTICES.md): notices and distribution gates.

## Private reports and community conduct

- [Security policy](../SECURITY.md): private vulnerability disclosure and SDK boundaries.
- [Code of conduct](../CODE_OF_CONDUCT.md): participation and private conduct reporting.

When documentation and observed behavior differ, report the affected package, commit, and a sanitized reproduction. Do not turn a design proposal or offline test result into a live support claim.
