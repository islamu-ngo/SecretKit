# SecretKit contributor contract

SecretKit is a greenfield MIT .NET 10 SDK. Breaking changes during development
are permitted; do not add compatibility aliases. Independently design code from
public interface facts. Do not copy source from Event, Configurator or vendors.

## Start here

- [CONTRIBUTING.md](CONTRIBUTING.md) owns contributor workflow and PR evidence.
- [PROJECTS.md](PROJECTS.md) maps packages, tests, samples, and focused commands.
- [docs/README.md](docs/README.md) routes public and internal documentation.
- [Current preview](docs/public/current-preview.md) records implemented support;
  [scope](docs/public/scope-and-orchestration.md) records the core-first priority.
- [SECURITY.md](SECURITY.md) owns private vulnerability reporting;
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) owns community participation.

Read applicable path-scoped instructions before editing. Keep changes focused
on the named task and preserve existing work. No external cockpit is required
to understand or follow this repository contract.

## Boundaries

- Core uses the BCL only. Providers depend inward on Core.
- Provider-native lifecycle and management operations remain typed and native.
- Configuration export and hosting are independent optional packages.
- No database, ASP.NET shared framework, UI, reflection plugin discovery or
  arbitrary request execution belongs in these libraries.
- Runtime and administrative identities are explicitly selected, never inferred.
- Clients and transports supplied by a host stay host-owned.
- No hidden workers, fallback principals, material cache or mutation replay.
- Keep protected values and coordinates out of formatting, serialization,
  exceptions and diagnostics. Explicit exports create ordinary plaintext strings.
- Cancellation propagates. Mutations retain caller-held pre-dispatch receipts.

## Verification

Run from this repository. Use locked restore after dependency changes have
produced reviewed lockfiles. Do not hand-edit generated lockfiles.

```sh
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet format SecretKit.slnx --verify-no-changes --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --output artifacts/packages
```

Tests use TUnit/Microsoft.Testing.Platform with a positive minimum test count.
Use exact event barriers and injected time for asynchronous tests, never sleeps
or timing-dependent polling. Test the public adapter/transport seam and resulting
state, not mock call counts. Offline tests do not establish remote conformance.
Record missing identities, entitlements, cloud/platform coverage and publisher
rights as open gates. Do not skip tests to manufacture a passing support claim.

## Ownership

Documentation-only changes use link, formatting, and command/path checks rather
than product builds. Public guidance and internal contracts must distinguish
proposed behavior, implemented subsets, offline evidence, and live conformance.
For SDK behavior changes, the verification baseline above remains required.

Private execution notes remain locally excluded in dev/active/secretkit-sdk.
Preserve unrelated changes. No commit, push, publication or remote mutation
without its actual authorization. SDK construction grants no provider authority.
