# ISLAMU SecretKit

.NET 10 libraries for explicit, disposable secret access through Infisical and Azure Key Vault.

**Development preview: not ready for production, not publicly published, and APIs may break.**
Local tests and packages do not establish live provider conformance. See the
[current preview](docs/public/current-preview.md) before adopting an operation.

## Try it in 30 seconds

With the SDK pinned in [global.json](global.json), run the offline quickstart from
this checkout:

```bash
dotnet run --project samples/QuickStart --configuration Release
```

The [QuickStart sample](samples/QuickStart/Program.cs) uses synthetic in-memory
material. It requires no account and performs no provider writes. To use a real
provider, follow [local package installation](docs/public/local-packages.md) and
supply your own authorized identity and trusted origin.

Given an authenticated `InfisicalClient client` and host-selected `string`
coordinates, a scoped read needs only:

```csharp
using SecretKit.Infisical;

var scope = client.CreateScope(projectId, environment, folder);
using var read = await scope.GetSecretAsync(key, cancellationToken);
int characterCount = read.Material.Use(static characters => characters.Length);
```

Replace the callback with the operation that needs the material. `Use` and
`UseUtf8` borrow a temporary span only for the callback and clear its buffer
when the callback finishes. Dispose the read. `Reveal()` and configuration
exports create ordinary plaintext strings whose lifetime is outside that protection.

`TryGetSecretAsync` returns `null` only for an explicit absence. Access denial,
expiry and unavailable providers remain failures; they are not missing secrets.
For explicit branching, `ReadAsync` returns `SecretOutcome<SecretRead>` with
`TryGetValue`, `Match`, and `GetValueOrThrow` helpers.

## Choose packages

| Package | Use it for |
| --- | --- |
| [SecretKit.Core](src/SecretKit.Core/README.md) | BCL-only reads, outcomes, material ownership and mutation evidence |
| [SecretKit.Infisical](src/SecretKit.Infisical/README.md) | Infisical runtime reads, authentication and supported native lifecycle operations |
| [SecretKit.Extensions.Hosting](src/SecretKit.Extensions.Hosting/README.md) | Options, keyed DI, explicit startup admission and health integration |
| [SecretKit.Extensions.Configuration](src/SecretKit.Extensions.Configuration/README.md) | Local generations, leased client activation and deliberate configuration export |
| [SecretKit.AzureKeyVault](src/SecretKit.AzureKeyVault/README.md) | Direct Azure Key Vault secret data-plane access |
| [SecretKit.Infisical.Management](src/SecretKit.Infisical.Management/README.md) | Separately authorized Infisical administration |
| [SecretKit.AzureKeyVault.Management](src/SecretKit.AzureKeyVault.Management/README.md) | Separately authorized Azure administration and audit access |

Ordinary Infisical reads need `SecretKit.Infisical` and its Core dependency.
Configuration and hosting are independent optional packages. Test doubles live
in the nonpackable [testing fixture](tests/fixtures/SecretKit.Testing/); they do
not add an eighth published package.

## Register with a host

Integration fragment: `runtimeOptions` is an `InfisicalRuntimeOptions` containing
explicit origin, identity, project and verified lifetime policy.
`loadBootstrapMaterialAsync` is a host-provided
`Func<CancellationToken, ValueTask<SecretMaterial>>` returning fresh owned material.
`services` is your `IServiceCollection`; coordinates come from your host configuration.

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

Startup admission authenticates during host startup and rejects failed admission.
Omit it to defer authentication until explicit admission or reader use; registration
itself performs no network I/O. Keyed registrations use
`AddKeyedSecretKitInfisical(serviceKey, configure)` to keep runtime sessions and
scopes separate. Neither path discovers an administrator or silently retries a
consumed bootstrap attempt. See [authentication and hosting](docs/public/authentication-and-hosting.md).

## Replace configuration deliberately

Integration fragment: `selections` is an application-created collection of
`SecretSelection` entries, and `mappings` contains explicit
`SecretConfigurationMapping` entries. Both select known keys; `cancellationToken`
comes from the host.

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

Replacement publishes one complete local dictionary and signals reload. Separate indexer reads can cross
generations; use one snapshot handle for coherent multi-key work. Exported strings
cannot be erased by disposing the SDK.

For a client that must be validated before activation, use
`SecretGenerationCoordinator<TClient>`. The application supplies its validator,
stale policy and age bound. `EnableAsync` collects and validates; `Acquire`
returns a lease that keeps the client alive through `ExecuteAsync`. Retirement
waits for leases. Client activation and configuration export remain separate
operations, not a joint transaction.

## Runnable examples

| Sample | Demonstrates |
| --- | --- |
| [QuickStart](samples/QuickStart/) | Scoped reads and callback material access |
| [AspNetCore](samples/AspNetCore/) | Hosting registration and startup admission |
| [Worker](samples/Worker/) | Explicit worker composition |
| [ConfigurationReload](samples/ConfigurationReload/) | Generations and configuration replacement |
| [RuntimeConfiguration](samples/RuntimeConfiguration/) | Detailed consumer policy and ownership scenarios |
| [ProviderAssessment](samples/ProviderAssessment/) | Runtime authority versus administrative visibility |

Package installation and recovery harnesses live under
[tests/PackageQualification](tests/PackageQualification/), separate from onboarding.

## Security and support boundaries

- Credentials, origin and authority are explicit host choices. Installing a package grants no access.
- Dispose owned reads and material. Callback spans cannot outlive their callback.
- Diagnostic classifications exclude secret values, credentials and protected coordinates; host instrumentation and exported strings remain host responsibilities.
- Cancellation propagates. Mutation receipts retain dispatch evidence; uncertain writes must not be replayed automatically.
- A local generation is not a remote multi-key transaction, fleet convergence or proof of downstream readiness.
- Offline success is not live provider, entitlement, platform or production qualification.

Read the [documentation hub](docs/README.md),
[security and ownership guide](docs/public/security-and-ownership.md), and
[provider support](docs/public/provider-support.md). Report vulnerabilities privately
through [SECURITY.md](SECURITY.md).

## Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md), [PROJECTS.md](PROJECTS.md) and
[AGENTS.md](AGENTS.md). The repository uses MIT; dependencies retain their own
[notices](THIRD-PARTY-NOTICES.md). Participation follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

```bash
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
dotnet test --solution SecretKit.slnx --configuration Release --no-build
dotnet format SecretKit.slnx --verify-no-changes --verbosity quiet
dotnet pack SecretKit.slnx --configuration Release --no-build --output artifacts/packages
```

These commands build local artifacts; they do not publish a release.
