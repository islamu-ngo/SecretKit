using System.Text.Json;
using SecretKit.Core;
using SecretKit.Testing;

namespace SecretKit.Core.Tests;

public sealed class TestingFakesTests
{
    [Test]
    public async Task CoreFixtureGraphDoesNotPullProviderDependencies()
    {
        string assets = Path.GetFullPath("../../../obj/project.assets.json", AppContext.BaseDirectory);
        using JsonDocument graph = JsonDocument.Parse(await File.ReadAllTextAsync(assets));
        string[] libraries = graph.RootElement.GetProperty("libraries").EnumerateObject()
            .Select(library => library.Name).ToArray();
        await Assert.That(libraries.Any(name => name.StartsWith("SecretKit.Infisical/", StringComparison.Ordinal) ||
            name.StartsWith("Refit/", StringComparison.Ordinal))).IsFalse();
    }

    [Test]
    public async Task ReadsAreIndependentAndForeignAuthoritiesCannotRead()
    {
        using var reader = new InMemorySecretReader();
        var address = new Address();
        using var material = SecretMaterial.FromText("fixture-value");
        reader.Set(address, material);
        var reference = new SecretReference(reader.Authority, address);
        using SecretRead first = (await reader.ReadAsync(reference)).Value;
        reader.Remove(address);
        await Assert.That(first.Material.Reveal()).IsEqualTo("fixture-value");
        await Assert.That(ReferenceEquals(first.Observation.Reference, reference)).IsTrue();
        await Assert.That((await reader.ReadAsync(reference)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That((await reader.ReadAsync(new SecretReference(new SecretAuthority(), address))).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ConcurrentReplacementsNeverReturnDisposedOrPartialMaterial()
    {
        using var reader = new InMemorySecretReader();
        var address = new Address();
        var reference = new SecretReference(reader.Authority, address);
        using var material = SecretMaterial.FromText("complete-fixture-value");
        reader.Set(address, material);
        await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(async () =>
        {
            reader.Set(address, material);
            using SecretRead read = (await reader.ReadAsync(reference)).Value;
            await Assert.That(read.Material.Reveal()).IsEqualTo("complete-fixture-value");
        })));
    }

    [Test]
    public async Task FailureInjectionCancellationAndDisposalRemainDistinct()
    {
        using var reader = new InMemorySecretReader();
        var reference = new SecretReference(reader.Authority, new Address());
        foreach (SecretStatus status in new[] { SecretStatus.Absent, SecretStatus.Denied, SecretStatus.Unavailable })
        {
            reader.Failure = status;
            await Assert.That((await reader.ReadAsync(reference)).Status).IsEqualTo(status);
        }
        await Assert.That(async () => await reader.ReadAsync(reference, new CancellationToken(true)))
            .Throws<OperationCanceledException>();
        reader.Dispose();
        await Assert.That(async () => await reader.ReadAsync(reference)).Throws<ObjectDisposedException>();
    }

    private sealed class Address : SecretAddress;
}
