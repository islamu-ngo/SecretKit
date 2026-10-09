using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Consumer.Tests;

public sealed class BootstrapAuthorityTests
{
    [Test]
    [Arguments(SecretStatus.Absent)]
    [Arguments(SecretStatus.Denied)]
    [Arguments(SecretStatus.Unavailable)]
    public async Task RequiredFailureNeverConstructsDatabaseOrFallsBack(SecretStatus failure)
    {
        var reader = new Reader((reference, _) =>
            ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(failure)));
        SecretOutcome<BootstrapCandidate> result = await BootstrapScenario.PrepareAsync(reader, Bindings(reader));

        await Assert.That(result.Status).IsEqualTo(failure);
        await Assert.That(() => result.Value).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DatabaseConstructionWaitsForAllRequiredReads()
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var reader = new Reader(async (reference, token) =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(token);
            return Success(reference, Material());
        });
        bool databaseConstructed = false;
        async Task Start()
        {
            SecretOutcome<BootstrapCandidate> prepared = await BootstrapScenario.PrepareAsync(reader, Bindings(reader));
            using BootstrapCandidate candidate = prepared.Value;
            using SecretRead first = candidate.Read("Database:Username");
            using SecretRead second = candidate.Read("Database:Password");
            databaseConstructed = first.Material.Reveal().Length > 0 && second.Material.Reveal().Length > 0;
        }

        Task startup = Start();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(databaseConstructed).IsFalse();
        release.SetResult();
        await startup;
        await Assert.That(databaseConstructed).IsTrue();
    }

    [Test]
    public async Task PartialFailureClearsEarlierCandidateMaterial()
    {
        SecretMaterial material = SecretMaterial.FromText(Material());
        var first = new Address();
        var reader = new Reader((reference, _) => ValueTask.FromResult(ReferenceEquals(reference.Address, first)
            ? SecretOutcome<SecretRead>.Success(new SecretRead(material,
                new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)))
            : SecretOutcome<SecretRead>.Failure(SecretStatus.Denied)));
        var bindings = new Dictionary<string, SecretReference>
        {
            ["Database:Username"] = new(reader.Authority, first),
            ["Database:Password"] = new(reader.Authority, new Address())
        };

        SecretOutcome<BootstrapCandidate> result = await BootstrapScenario.PrepareAsync(reader, bindings);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task ForeignReferenceRejectsWholeMappingBeforeIo()
    {
        var reader = new Reader((_, _) => throw new InvalidOperationException("Foreign bootstrap dispatched."));
        var mappings = new Dictionary<string, SecretReference>
        {
            ["Database:Username"] = new(reader.Authority, new Address()),
            ["Database:Password"] = new(new SecretAuthority(), new Address())
        };

        SecretOutcome<BootstrapCandidate> result = await BootstrapScenario.PrepareAsync(reader, mappings);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CompleteControlledValuesOverrideLocalDefaultsAndCopiesRemainIndependent()
    {
        string value = Material();
        var reader = new Reader((reference, _) => ValueTask.FromResult(Success(reference, value)));
        using BootstrapCandidate candidate = (await BootstrapScenario.PrepareAsync(reader, Bindings(reader))).Value;
        IReadOnlyDictionary<string, string> exported = candidate.ExportOver(new Dictionary<string, string>
        {
            ["Database:Username"] = Material(),
            ["Application:Mode"] = "offline"
        });
        using SecretRead first = candidate.Read("Database:Username");
        using SecretRead second = candidate.Read("Database:Username");
        first.Dispose();

        await Assert.That(second.Material.Reveal()).IsEqualTo(value);
        await Assert.That(exported["Database:Username"]).IsEqualTo(value);
        await Assert.That(exported["Application:Mode"]).IsEqualTo("offline");
        await Assert.That(JsonSerializer.Serialize(candidate).Contains(value, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task CancelledPreparationClearsEarlierMaterialAndPropagates()
    {
        using var cancellation = new CancellationTokenSource();
        SecretMaterial material = SecretMaterial.FromText(Material());
        var first = new Address();
        var reader = new Reader((reference, token) =>
        {
            if (ReferenceEquals(reference.Address, first))
            {
                cancellation.Cancel();
                return ValueTask.FromResult(SecretOutcome<SecretRead>.Success(new SecretRead(material,
                    new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid))));
            }

            token.ThrowIfCancellationRequested();
            throw new InvalidOperationException("Cancelled bootstrap dispatched.");
        });
        var bindings = new Dictionary<string, SecretReference>
        {
            ["Database:Username"] = new(reader.Authority, first),
            ["Database:Password"] = new(reader.Authority, new Address())
        };

        await Assert.That(async () => await BootstrapScenario.PrepareAsync(reader, bindings, cancellation.Token))
            .Throws<OperationCanceledException>();
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
    }

    private static Dictionary<string, SecretReference> Bindings(Reader reader) => new()
    {
        ["Database:Username"] = new(reader.Authority, new Address()),
        ["Database:Password"] = new(reader.Authority, new Address())
    };

    private static string Material() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
    private static SecretOutcome<SecretRead> Success(SecretReference reference, string value) =>
        SecretOutcome<SecretRead>.Success(new SecretRead(SecretMaterial.FromText(value),
            new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)));
    private sealed class Address : SecretAddress;
    private sealed class Reader(Func<SecretReference, CancellationToken, ValueTask<SecretOutcome<SecretRead>>> read) : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default) =>
            read(reference, cancellationToken);
    }
}
