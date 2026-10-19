using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.ProviderContract.Tests;

internal interface IProviderFixture : IAsyncDisposable
{
    ISecretReader Reader { get; }
    ISecretInventory Inventory { get; }
    SecretReference Reference { get; }
    SecretInventoryScope Scope(int maximumItems = 1000);
    FixtureHandler Wire { get; }
    bool RejectUse { get; set; }
    HttpResponseMessage ReadResponse(string material, bool wrongCoordinates = false);
    HttpResponseMessage InventoryResponse(string canary);
}

public sealed class PortableReadTests
{
    internal static IProviderFixture Create(bool azure) => azure ? new AzureFixture() : new InfisicalFixture();

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task SameCoordinatesNeverCrossAuthorityEvenDuringConcurrentReads(bool azure)
    {
        await using IProviderFixture first = Create(azure);
        await using IProviderFixture second = Create(azure);
        first.RejectUse = second.RejectUse = true;
        SecretOutcome<SecretRead> foreignFirst = await first.Reader.ReadAsync(second.Reference);
        SecretOutcome<SecretRead> foreignSecond = await second.Reader.ReadAsync(first.Reference);
        await Assert.That(foreignFirst.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(foreignSecond.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => foreignFirst.Value).Throws<InvalidOperationException>();
        await Assert.That(() => foreignSecond.Value).Throws<InvalidOperationException>();
        first.RejectUse = second.RejectUse = false;

        var firstEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var secondEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        first.Wire.Respond = async (_, token) =>
        {
            firstEntered.TrySetResult();
            await release.Task.WaitAsync(token);
            return first.ReadResponse("first-material");
        };
        second.Wire.Respond = async (_, token) =>
        {
            secondEntered.TrySetResult();
            await release.Task.WaitAsync(token);
            return second.ReadResponse("second-material");
        };
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<SecretOutcome<SecretRead>> firstPending = first.Reader.ReadAsync(first.Reference, deadline.Token).AsTask();
        Task<SecretOutcome<SecretRead>> secondPending = second.Reader.ReadAsync(second.Reference, deadline.Token).AsTask();
        await Task.WhenAll(firstEntered.Task, secondEntered.Task).WaitAsync(deadline.Token);
        first.RejectUse = second.RejectUse = true;
        await Assert.That((await first.Reader.ReadAsync(second.Reference, deadline.Token)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await second.Reader.ReadAsync(first.Reference, deadline.Token)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        first.RejectUse = second.RejectUse = false;
        release.SetResult();
        SecretOutcome<SecretRead>[] results = await Task.WhenAll(firstPending, secondPending);
        using SecretRead firstRead = results[0].Value;
        using SecretRead secondRead = results[1].Value;
        await Assert.That(firstRead.Material.Reveal()).IsEqualTo("first-material");
        await Assert.That(secondRead.Material.Reveal()).IsEqualTo("second-material");
        firstRead.Dispose();
        await Assert.That(secondRead.Material.Reveal()).IsEqualTo("second-material");
        await Assert.That(JsonSerializer.Serialize(results).Contains("material", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(first.Reference).Contains("name-canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false, "")]
    [Arguments(true, "")]
    [Arguments(false, " \r\n\n ")]
    [Arguments(true, " \r\n\n ")]
    public async Task SuccessfulMaterialIsExactAndIndependentlyOwned(bool azure, string material)
    {
        await using IProviderFixture fixture = Create(azure);
        fixture.Wire.Respond = (_, _) => Task.FromResult(fixture.ReadResponse(material));
        using SecretRead first = (await fixture.Reader.ReadAsync(fixture.Reference)).Value;
        using SecretRead second = (await fixture.Reader.ReadAsync(fixture.Reference)).Value;
        await Assert.That(first.Material.Reveal()).IsEqualTo(material);
        first.Dispose();
        await Assert.That(second.Material.Reveal()).IsEqualTo(material);
    }

    [Test]
    [Arguments(false, 404, SecretStatus.Absent)]
    [Arguments(true, 404, SecretStatus.Absent)]
    [Arguments(false, 403, SecretStatus.Denied)]
    [Arguments(true, 403, SecretStatus.Denied)]
    [Arguments(false, 503, SecretStatus.Unavailable)]
    [Arguments(true, 503, SecretStatus.Unavailable)]
    public async Task NativeFailuresExposeNoMaterial(bool azure, int status, SecretStatus expected)
    {
        await using IProviderFixture fixture = Create(azure);
        fixture.Wire.Respond = (_, _) => Task.FromResult(FixtureHandler.Json("{}", status));
        SecretOutcome<SecretRead> result = await fixture.Reader.ReadAsync(fixture.Reference);
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CoordinateSubstitutionAndBudgetOverflowFailClosed(bool azure)
    {
        await using IProviderFixture fixture = Create(azure);
        fixture.Wire.Respond = (_, _) => Task.FromResult(fixture.ReadResponse("material", true));
        await Assert.That((await fixture.Reader.ReadAsync(fixture.Reference)).Status).IsEqualTo(SecretStatus.Invalid);
        fixture.Wire.Respond = (_, _) => Task.FromResult(fixture.ReadResponse(new string('x', 2048)));
        SecretOutcome<SecretRead> oversized = await fixture.Reader.ReadAsync(fixture.Reference);
        await Assert.That(oversized.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(() => oversized.Value).Throws<InvalidOperationException>();
        fixture.Wire.Respond = (_, _) => Task.FromResult(FixtureHandler.Json("{"));
        SecretOutcome<SecretRead> malformed = await fixture.Reader.ReadAsync(fixture.Reference);
        await Assert.That(malformed.IsSuccess).IsFalse();
        await Assert.That(() => malformed.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationPropagatesBeforeAndDuringNativeSend(bool azure)
    {
        await using IProviderFixture fixture = Create(azure);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        fixture.RejectUse = true;
        await Assert.That(async () => await fixture.Reader.ReadAsync(fixture.Reference, cancellation.Token))
            .Throws<OperationCanceledException>();
        fixture.RejectUse = false;
        using var inFlight = new CancellationTokenSource();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var response = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Wire.Respond = async (_, token) =>
        {
            entered.TrySetResult();
            return await response.Task.WaitAsync(token);
        };
        Task<SecretOutcome<SecretRead>> pending = fixture.Reader.ReadAsync(fixture.Reference, inFlight.Token).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        inFlight.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(5)))
            .Throws<OperationCanceledException>();
    }
}
