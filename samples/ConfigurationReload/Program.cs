using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Infisical;
using SecretKit.Testing;

using var reader = new InMemoryInfisicalSecretReader();
var address = new InfisicalSecretAddress("demo-project", "development", "/", "DemoKey");
using var initial = SecretMaterial.FromText("offline-generation-one");
reader.Set(address, initial);
var required = new Dictionary<string, SecretReference> { ["credential"] = new(reader.Authority, address) };

await using var clients = new SecretGenerationCoordinator<DemoClient>(reader, required,
    static (snapshot, _) =>
    {
        using SecretRead read = snapshot.Read("credential");
        return ValueTask.FromResult(SecretOutcome<DemoClient>.Success(new(read.Material.Copy())));
    }, SecretGenerationStalePolicy.FailClosed, TimeSpan.FromMinutes(5), TimeProvider.System);
if (!(await clients.EnableAsync()).Active) throw new InvalidOperationException("Initial activation failed.");
await using var previous = clients.Acquire() ?? throw new InvalidOperationException("No active generation.");
using var replacement = SecretMaterial.FromText("offline-generation-two");
reader.Set(address, replacement);
if (!(await clients.EnableAsync()).Active) throw new InvalidOperationException("Replacement failed.");
await using var current = clients.Acquire() ?? throw new InvalidOperationException("No replacement generation.");
if (!await previous.ExecuteAsync(static (client, _) => ValueTask.FromResult(client.Matches("offline-generation-one"))) ||
    !await current.ExecuteAsync(static (client, _) => ValueTask.FromResult(client.Matches("offline-generation-two"))))
    throw new InvalidOperationException("Generation isolation failed.");

// Configuration export is a separate opt-in ordinary-string boundary, not client activation.
using var loader = new SecretSnapshotLoader(required.Select(pair => new SecretSelection(pair.Key, reader, pair.Value)));
if (!(await loader.RefreshAsync()).IsSuccess) throw new InvalidOperationException("Collection failed.");
using var first = loader.Acquire();
using var export = SecretConfigurationExport.Create(first, [new("credential", "Demo:Credential")]);
IConfigurationRoot configuration = new ConfigurationBuilder().Add(export).Build();
using IDisposable configurationLifetime = (IDisposable)configuration;
reader.Set(address, initial);
if (!(await loader.RefreshAsync()).IsSuccess) throw new InvalidOperationException("Refresh failed.");
using var next = loader.Acquire();
export.Replace(next);
if (configuration["Demo:Credential"] != "offline-generation-one")
    throw new InvalidOperationException("Configuration replacement failed.");
Console.WriteLine("Old and new client leases remained isolated; configuration was explicitly replaced.");

sealed class DemoClient(SecretMaterial material) : IAsyncDisposable
{
    public bool Matches(string expected) => material.Use(expected, static (value, target) => value.SequenceEqual(target));
    public ValueTask DisposeAsync() { material.Dispose(); return ValueTask.CompletedTask; }
}
