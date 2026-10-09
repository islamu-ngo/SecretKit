using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class AuthorityIsolationTests
{
    [Test]
    public async Task DistinctAuthoritiesCannotMatchBySecretName()
    {
        var first = new SecretAuthority();
        var second = new SecretAuthority();
        var reference = new SecretReference(first, new TestAddress());

        bool matches = reference.BelongsTo(second);

        await Assert.That(matches).IsFalse();
        await Assert.That(reference.BelongsTo(first)).IsTrue();
    }

    [Test]
    public async Task ReferenceSerializationDoesNotTraverseProviderCoordinates()
    {
        var reference = new SecretReference(new SecretAuthority(), new TestAddress());

        string json = JsonSerializer.Serialize(reference);

        await Assert.That(json.Contains("coordinate-canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task FailureCannotCarrySuccessfulMaterial()
    {
        SecretOutcome<SecretMaterial> outcome = SecretOutcome<SecretMaterial>.Failure(SecretStatus.Denied);

        await Assert.That(() => outcome.Value).Throws<InvalidOperationException>();
        await Assert.That(() => SecretOutcome<SecretMaterial>.Failure(SecretStatus.Success))
            .Throws<ArgumentException>();
    }

    private sealed class TestAddress : SecretAddress
    {
        public string Coordinate => "coordinate-canary";
    }
}
