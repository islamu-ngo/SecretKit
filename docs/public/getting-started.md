# Get started with SecretKit

> **Audience:** .NET developers trying SecretKit for the first time
> **Status:** Tutorial using existing offline samples, followed by an integration fragment
> **Owner:** SecretKit maintainers
> **Last verified:** 2026-10-25 against sample and API source; commands not rerun for this documentation change
> **Source anchors:** [SDK pin](../../global.json), [offline sample](../../samples/RuntimeConfiguration/Program.cs), [Infisical client](../../src/SecretKit.Infisical/InfisicalClient.cs)

Run an offline example to learn the ownership model, then select a provider for
your application. **In development. Not ready for production.**

## 1. Prepare a checkout

Use a SecretKit checkout and the .NET SDK selected by
[`global.json`](../../global.json): `10.0.302`, with `latestPatch` roll-forward.
Run the following commands from the SecretKit repository root:

```sh
dotnet --version
dotnet restore SecretKit.slnx --locked-mode
dotnet build SecretKit.slnx --configuration Release --no-restore
```

Restore needs access to the configured dependency sources unless the required
packages are already available. These commands build source projects; they do
not prove that separately packed archives install correctly.

## 2. Run the offline configuration example

```sh
dotnet run --project samples/RuntimeConfiguration --configuration Release --no-build
```

The example uses synthetic material and controlled authentication responses. It
does not contact Infisical, Azure, or a database. Its output includes:

```text
AUTHENTICATION_EXPLICIT_RENEWAL_RECOVERY_REPLACEMENT
BOOTSTRAP_PREPARED_OPTIONAL_INTEGRATION_DISABLED
LOGICAL_GENERATION_1_NEXT_2_REMOTE_SNAPSHOT_False
```

A separate composition line includes an elapsed-time measurement; its numerical
value is not an acceptance threshold.

Read [`Program.cs`](../../samples/RuntimeConfiguration/Program.cs). It prepares
required values before dependent services, acquires generation 1, refreshes the
loader, and shows that the old handle still reads generation 1 while a new handle
reads generation 2. Both returned reads are independently disposable.
`RemoteSnapshotGuaranteed` is false: local coherence is not a remote transaction.

## 3. Observe identity separation

```sh
dotnet run --project samples/ProviderAssessment --configuration Release --no-build
```

The sample first reports administrator-visible metadata with an unavailable
intended runtime value. After a controlled change, "Check again" makes a fresh
runtime observation. It does not activate an integration.

Read the [assessment entry point](../../samples/ProviderAssessment/Program.cs).
An administrator's inventory and an application's read use separate identities.
Inventory success does not prove that a consumer can read or use a value.

## 4. Install a provider in your application

For Infisical, select `SecretKit.Infisical` and its `SecretKit.Core` dependency.
Configuration and hosting are optional. For direct Azure access, select
`SecretKit.AzureKeyVault` instead; Infisical is not required.

Follow [local packages](local-packages.md) for exact versions, original archives,
feed configuration and isolated installation. There is no public NuGet release
to assume. The larger candidate-freezing procedure is for maintainers; an adopter
with a prepared portable feed starts at
[portable repository feed](local-packages.md#portable-repository-feed).

## 5. Make a selected Infisical read

This is an **integration fragment**, not a standalone application or token
bootstrap. It assumes your host has already supplied:

| Input | Type and responsibility |
| --- | --- |
| `origin` | `Uri`: trusted provider HTTPS origin, not an API path |
| `tokens` | `IInfisicalTokenSource`: explicitly selected host-owned identity |
| `projectId`, `environment`, `folder`, `secretKey` | `string`: authorized provider coordinates; folder is absolute |
| `cancellationToken` | `CancellationToken`: host shutdown/request cancellation |

```csharp
using SecretKit.Core;
using SecretKit.Infisical;

using var deadline =
    CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
deadline.CancelAfter(TimeSpan.FromSeconds(10));

await using var client = new InfisicalClient(origin, tokens);
var reference = new SecretReference(
    client.Authority,
    new InfisicalSecretAddress(projectId, environment, folder, secretKey));

SecretOutcome<SecretRead> outcome =
    await client.ReadAsync(reference, deadline.Token);

Console.WriteLine($"READ_{outcome.Status}");
if (outcome.IsSuccess)
{
    using SecretRead read = outcome.Value;
    // Use read.Material inside this scope. Do not log or serialize its value.
    Console.WriteLine($"VALIDITY_{read.Observation.Validity}");
}
```

Only success permits `outcome.Value`. Cancellation throws rather than returning
a synthetic success or absence. A reference belongs to this client instance;
rebuild it for a replacement client even when its textual coordinates match.
The fragment reports status/validity only and deliberately performs no downstream
business action.

For actual use, supply material to your application's selected consumer within
its owned lifetime. `Reveal()` creates an ordinary plaintext string; disposal
cannot erase that string. See [Core contracts](core-api.md) before choosing that
boundary.

For a long-lived application, reuse the selected client for its lifecycle rather
than constructing one per request. Supply a deadline for every operation and
stop accepting work before disposing it. See
[authentication and hosting](authentication-and-hosting.md) for token sources,
explicit login, renewal and recovery.

## Next steps

- [Infisical](providers/infisical.md): raw revisions, selected writes, inventory
  and native lifecycle operations.
- [Azure Key Vault](providers/azure-key-vault.md): explicit credentials and
  provider-native secret lifecycle.
- [Configuration and runtime](configuration-and-runtime.md): collect all required
  settings, export deliberately, and activate application clients.
- [Troubleshooting](troubleshooting.md): interpret denied, unknown and
  recovery-required outcomes.
