# Contributing to ISLAMU SecretKit

Help improve the two-provider SDK with focused changes, reproducible evidence, and clear support boundaries. Participation follows [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Before you start

- Read the [current preview](docs/public/current-preview.md) and [scope](docs/public/scope-and-orchestration.md). Planned native operations are not all implemented or live-verified.
- Use [issues](https://github.com/islamu-ngo/SecretKit/issues/new/choose) for ordinary bugs and proposals. Discuss package/API changes, new dependencies, and broad refactors before investing in them.
- Report security vulnerabilities privately through [SECURITY.md](SECURITY.md), including fixes discovered in forks.
- Check [PROJECTS.md](PROJECTS.md) for the owner and tests of your change, then [AGENTS.md](AGENTS.md) for the invariants.

## Local development

Install the SDK pinned in [global.json](global.json). Run commands from the SecretKit checkout:

```bash
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet run --project samples/RuntimeConfiguration --configuration Release --no-build
dotnet run --project samples/ProviderAssessment --configuration Release --no-build
```

The samples are offline demonstrations. They do not require provider accounts or prove live provider compatibility.

## Make a focused change

Keep Core BCL-only and provider-native features typed. Preserve explicit identity selection, material ownership, cancellation, bounded responses, and mutation uncertainty. Do not introduce hidden workers, principal fallback, mutation replay, or plaintext logging.

For behavioral changes, add a deterministic test through the affected public seam. Use event barriers and injected time for asynchronous behavior. Do not mirror mock calls or use sleeps. Documentation-only changes need link, formatting, and command/path checks rather than SDK test sweeps.

Keep public usage guidance and internal contracts consistent. Label proposed behavior, implemented subsets, offline evidence, and live conformance separately. Never include real credentials, values, sensitive coordinates, or personal data in examples, fixtures, logs, or attachments.

## Verification and pull requests

For SDK changes, run the checks in [AGENTS.md](AGENTS.md):

```bash
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet format SecretKit.slnx --verify-no-changes --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --output artifacts/packages
```

Restore and rebuild first when inputs changed. Use [PROJECTS.md](PROJECTS.md) for focused inner-loop tests; the full repository checks remain the SDK handoff baseline. Regenerate dependency locks through package tooling and review the resolved graph and notices.

Open a pull request describing the problem, resulting behavior, affected packages, and actual verification. Include omissions and remaining provider/platform gates. Follow the [pull request template](.github/PULL_REQUEST_TEMPLATE.md). Disclose AI assistance and understand every submitted change. Do not submit unrelated formatting or cleanup.

Live verification requires an owned or explicitly authorized environment and separately selected identities. Offline success does not authorize remote writes or establish entitlements. Packing is local evaluation; release publication has separate approval and verification gates.

## Licensing and provenance

Submit original material you can license under [MIT](LICENSE), and retain attribution and third-party notices. SecretKit does not import Event's AGPL license, CLA automation, or Configurator's implementation. Do not copy vendor code, tests, or expressive schemas; use supported public-interface facts with repository-native design.

Dependency and generated-artifact changes must preserve their owning tool, generated locks, and [provenance records](THIRD-PARTY-NOTICES.md). See [delivery and maintenance](docs/internal/DELIVERY_AND_MAINTENANCE.md) for admission and distribution gates.
