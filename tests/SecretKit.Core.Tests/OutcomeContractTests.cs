using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class OutcomeContractTests
{
    [Test]
    public async Task ProtectedCorrelationSurvivesConversionWithoutImplicitDisclosure()
    {
        const string canary = "private-request.canary_123";
        var correlation = new SecretCorrelationId(canary);
        var original = SecretOutcome<string>.Failure(SecretStatus.Throttled, TimeSpan.FromSeconds(42),
            SecretFailureReason.ValidationFailed, correlation);

        var converted = original.ConvertFailure<SecretRead>();

        await Assert.That(converted.Status).IsEqualTo(SecretStatus.Throttled);
        await Assert.That(converted.Reason).IsEqualTo(original.Reason);
        await Assert.That(converted.RetryAfter).IsEqualTo(TimeSpan.FromSeconds(42));
        await Assert.That(ReferenceEquals(converted.CorrelationId, correlation)).IsTrue();
        await Assert.That(converted.CorrelationId!.Reveal()).IsEqualTo(canary);
        string implicitOutput = $"{original}{converted}{correlation}" +
            JsonSerializer.Serialize(new { original, converted, correlation });
        await Assert.That(implicitOutput.Contains(canary, StringComparison.Ordinal)).IsFalse();
        try { converted.GetValueOrThrow(); }
        catch (SecretUnavailableException error)
        {
            await Assert.That(error.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
            await Assert.That(error.InnerException).IsNull();
        }
    }

    [Test]
    public async Task FailureConversionRejectsSuccessWithoutDisposingItsValue()
    {
        using var material = SecretMaterial.FromText("still-owned");
        var success = SecretOutcome<SecretMaterial>.Success(material);
        await Assert.That(() => success.ConvertFailure<string>()).Throws<InvalidOperationException>();
        await Assert.That(material.Reveal()).IsEqualTo("still-owned");
        await Assert.That(success.CorrelationId).IsNull();
    }

    [Test]
    [Arguments("")]
    [Arguments("coordinate/secret")]
    [Arguments("a\nb")]
    [Arguments("caf\u00e9")]
    public async Task InvalidCorrelationNeverLeaksThroughArgumentErrors(string value)
    {
        await Assert.That(() => new SecretCorrelationId(value)).Throws<ArgumentException>();
        await Assert.That(() => new SecretCorrelationId(new string('a', 129))).Throws<ArgumentException>();
        await Assert.That(new SecretCorrelationId(new string('a', 128)).Reveal().Length).IsEqualTo(128);
        await Assert.That(SecretCorrelationId.TryCreate(null, out _)).IsFalse();
        await Assert.That(SecretCorrelationId.TryCreate(value, out _)).IsFalse();
        await Assert.That(SecretCorrelationId.TryCreate(new string('a', 129), out _)).IsFalse();
        await Assert.That(SecretCorrelationId.TryCreate("req-AZ_09.canary", out SecretCorrelationId? valid)).IsTrue();
        await Assert.That(valid?.Reveal()).IsEqualTo("req-AZ_09.canary");
    }

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
