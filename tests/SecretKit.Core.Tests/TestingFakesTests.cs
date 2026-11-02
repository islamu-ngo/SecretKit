using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Testing;

namespace SecretKit.Core.Tests;

public sealed class TestingFakesTests
{
    [Test]
    public async Task ReadsAreIndependentAndForeignAuthoritiesCannotRead()
    {
        using var reader = new InMemoryInfisicalSecretReader();
        var address = new InfisicalSecretAddress("test-project", "test-env", "/", "test-key");
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
        using var reader = new InMemoryInfisicalSecretReader();
        var address = new InfisicalSecretAddress("test-project", "test-env", "/", "test-key");
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
    public async Task InventoryIsScopedBoundedAndContainsNoOwnedMaterial()
    {
        using var reader = new InMemoryInfisicalSecretReader();
        using var material = SecretMaterial.FromText("fixture-value");
        reader.Set(new InfisicalSecretAddress("test-project", "test-env", "/", "first"), material);
        reader.Set(new InfisicalSecretAddress("test-project", "test-env", "/", "second"), material);
        reader.Set(new InfisicalSecretAddress("other-project", "test-env", "/", "third"), material);
        var scope = new InfisicalInventoryScope(reader.Authority, "test-project", "test-env", "/", 1);
        SecretInventory inventory = (await reader.InspectAsync(scope)).Value;
        await Assert.That(inventory.Items.Count).IsEqualTo(1);
        await Assert.That(inventory.IsComplete).IsFalse();
        await Assert.That(inventory.Items[0].Reference.BelongsTo(reader.Authority)).IsTrue();
        await Assert.That((await reader.CreateScope("other-project", "test-env").InspectAsync("first")).Status)
            .IsEqualTo(SecretStatus.Absent);
        reader.Dispose();
        await Assert.That(async () => await reader.ReadAsync(inventory.Items[0].Reference))
            .Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task FailureInjectionAndCancellationPreserveTheirDistinction()
    {
        using var reader = new InMemoryInfisicalSecretReader();
        var reference = new SecretReference(reader.Authority,
            new InfisicalSecretAddress("test-project", "test-env", "/", "test-key"));
        foreach (SecretStatus status in new[] { SecretStatus.Absent, SecretStatus.Denied, SecretStatus.Unavailable })
        {
            reader.Failure = status;
            await Assert.That((await reader.ReadAsync(reference)).Status).IsEqualTo(status);
        }
        await Assert.That(async () => await reader.ReadAsync(reference, new CancellationToken(true)))
            .Throws<OperationCanceledException>();
    }

    [Test]
    public async Task TokenRotationCopiesAndExpiryUsesInjectedTime()
    {
        var clock = new FixtureClock();
        using var source = new TestTokenSource(clock);
        using var first = SecretMaterial.FromText("fixture-token-one");
        using var second = SecretMaterial.FromText("fixture-token-two");
        source.Rotate(first, clock.GetUtcNow().AddMinutes(1));
        using InfisicalAccessToken old = (await source.GetTokenAsync(default)).Value;
        source.Rotate(second, clock.GetUtcNow().AddMinutes(2));
        using InfisicalAccessToken current = (await source.GetTokenAsync(default)).Value;
        await Assert.That(old.Material.Reveal()).IsEqualTo("fixture-token-one");
        await Assert.That(current.Material.Reveal()).IsEqualTo("fixture-token-two");
        clock.Now = clock.Now.AddMinutes(2);
        await Assert.That((await source.GetTokenAsync(default)).Status).IsEqualTo(SecretStatus.Expired);
        source.Dispose();
        await Assert.That(async () => await source.GetTokenAsync(default)).Throws<ObjectDisposedException>();
    }

    private sealed class FixtureClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }
}
