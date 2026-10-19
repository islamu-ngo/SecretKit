using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.ProviderContract.Tests;

public sealed class PortableInventoryTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InventoryIsBoundedMetadataNotMaterialOrPointInTime(bool azure)
    {
        await using IProviderFixture fixture = PortableReadTests.Create(azure);
        fixture.Wire.Respond = (_, _) => Task.FromResult(fixture.InventoryResponse("inventory-material-canary"));
        SecretInventory inventory = (await fixture.Inventory.InspectAsync(fixture.Scope(1))).Value;
        await Assert.That(inventory.Items.Count).IsEqualTo(1);
        await Assert.That(inventory.IsComplete).IsFalse();
        await Assert.That(inventory.IsPointInTime).IsFalse();
        await Assert.That(inventory.CompletedAt >= inventory.StartedAt).IsTrue();
        await Assert.That(JsonSerializer.Serialize(inventory).Contains("inventory-material-canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(inventory.ToString().Contains("inventory-material-canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ForeignInventoryAuthorityNeverAcquiresOrSends(bool azure)
    {
        await using IProviderFixture first = PortableReadTests.Create(azure);
        await using IProviderFixture second = PortableReadTests.Create(azure);
        first.RejectUse = true;
        SecretOutcome<SecretInventory> result = await first.Inventory.InspectAsync(second.Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task OwnedInfisicalShutdownDrainsAcceptedWork()
    {
        var fixture = new InfisicalFixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Wire.Respond = async (_, token) =>
        {
            entered.TrySetResult();
            return await response.Task.WaitAsync(token);
        };
        Task<SecretOutcome<SecretRead>> pending = fixture.Reader.ReadAsync(fixture.Reference).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await fixture.DisposeAsync();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)))
            .Throws<OperationCanceledException>();
        await Assert.That(fixture.Wire.Disposed).IsTrue();
    }

    [Test]
    public async Task AzureAdapterDoesNotDisposeBorrowedTransportAfterReads()
    {
        await using var fixture = new AzureFixture();
        fixture.Wire.Respond = (_, _) => Task.FromResult(fixture.ReadResponse("synthetic-material"));
        using SecretRead read = (await fixture.Reader.ReadAsync(fixture.Reference)).Value;
        read.Dispose();
        await Assert.That(fixture.Wire.Disposed).IsFalse();
        using SecretRead next = (await fixture.Reader.ReadAsync(fixture.Reference)).Value;
        await Assert.That(next.Material.Reveal()).IsEqualTo("synthetic-material");
    }
}
