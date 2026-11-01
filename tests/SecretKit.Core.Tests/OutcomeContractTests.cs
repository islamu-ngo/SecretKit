using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class OutcomeContractTests
{
    [Test]
    public async Task DefinedReasonsSurviveWithoutCreatingSuccessfulValues()
    {
        foreach (SecretFailureReason reason in Enum.GetValues<SecretFailureReason>())
        {
            var failure = SecretOutcome<SecretMaterial>.Failure(SecretStatus.Invalid, reason: reason);
            await Assert.That(failure.Reason).IsEqualTo(reason);
            await Assert.That(failure.IsSuccess).IsFalse();
            await Assert.That(() => failure.Value).Throws<InvalidOperationException>();
        }
    }

    [Test]
    public async Task UnknownEnumsAndInvalidTimingAreRejected()
    {
        await Assert.That(() => SecretOutcome<string>.Failure(SecretStatus.Invalid,
            reason: (SecretFailureReason)int.MaxValue)).Throws<ArgumentException>();
        await Assert.That(() => SecretOutcome<string>.Failure((SecretStatus)int.MaxValue)).Throws<ArgumentException>();
        await Assert.That(() => SecretOutcome<string>.Failure(SecretStatus.Success)).Throws<ArgumentException>();
        await Assert.That(() => SecretOutcome<string>.Failure(SecretStatus.Denied, TimeSpan.Zero)).Throws<ArgumentException>();
        await Assert.That(() => SecretOutcome<string>.Failure(SecretStatus.Unavailable, TimeSpan.FromTicks(-1))).Throws<ArgumentException>();
    }

    [Test]
    public async Task AdviceIsAllowedForThrottledAndUnavailableOnly()
    {
        foreach (SecretStatus status in new[] { SecretStatus.Throttled, SecretStatus.Unavailable })
        {
            var failure = SecretOutcome<string>.Failure(status, TimeSpan.FromSeconds(3),
                SecretFailureReason.TransportFailure);
            await Assert.That(failure.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(3));
            await Assert.That(failure.Reason).IsEqualTo(SecretFailureReason.TransportFailure);
        }
    }

    [Test]
    public async Task SuccessRetainsOwnedValueWithoutFailureDetailOrDisclosure()
    {
        const string canary = "outcome-credential-canary";
        using SecretMaterial value = SecretMaterial.FromText(canary);
        var success = SecretOutcome<SecretMaterial>.Success(value);
        await Assert.That(ReferenceEquals(success.Value, value)).IsTrue();
        await Assert.That(success.Reason).IsEqualTo(SecretFailureReason.None);
        await Assert.That(success.RetryAfter is null).IsTrue();
        await Assert.That(JsonSerializer.Serialize(success).Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(success.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(new { ExplicitDisclosure = value.Reveal() })
            .Contains(canary, StringComparison.Ordinal)).IsTrue();
        await Assert.That(() => SecretOutcome<string>.Success(null!)).Throws<ArgumentNullException>();
        await Assert.That(value.Reveal()).IsEqualTo(canary);
    }
}
