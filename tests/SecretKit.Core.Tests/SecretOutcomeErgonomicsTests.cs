using SecretKit.Core;

namespace SecretKit.Core.Tests;

public sealed class SecretOutcomeErgonomicsTests
{
    [Test]
    public async Task SuccessfulProjectionsRetainTheSameOwnedValue()
    {
        using SecretMaterial material = SecretMaterial.FromText("value-canary");
        var outcome = SecretOutcome<SecretMaterial>.Success(material);
        await Assert.That(outcome.TryGetValue(out var value)).IsTrue();
        await Assert.That(ReferenceEquals(value, material)).IsTrue();
        await Assert.That(ReferenceEquals(outcome.GetValueOrThrow(), material)).IsTrue();
        await Assert.That(outcome.Match(value => ReferenceEquals(value, material), (_, _, _) => false)).IsTrue();
    }

    [Test]
    public async Task FailureProjectionsPreserveEveryBoundedStatusAndAdvice()
    {
        foreach (SecretStatus status in Enum.GetValues<SecretStatus>().Where(status => status != SecretStatus.Success))
        {
            TimeSpan? advice = status is SecretStatus.Unavailable or SecretStatus.Throttled ? TimeSpan.FromSeconds(3) : null;
            var outcome = SecretOutcome<string>.Failure(status, advice, SecretFailureReason.TransportFailure);
            await Assert.That(outcome.TryGetValue(out var value)).IsFalse();
            await Assert.That(value is null).IsTrue();
            await Assert.That(outcome.Match(_ => false, (actual, reason, retryAfter) =>
                actual == status && reason == SecretFailureReason.TransportFailure && retryAfter == advice)).IsTrue();
            SecretUnavailableException? error = null;
            try { outcome.GetValueOrThrow(); }
            catch (SecretUnavailableException caught) { error = caught; }
            await Assert.That(error?.Status).IsEqualTo(status);
            await Assert.That(error?.FailureReason).IsEqualTo(SecretFailureReason.TransportFailure);
            await Assert.That(error?.RetryAfter).IsEqualTo(advice);
            await Assert.That(error?.InnerException is null).IsTrue();
        }
    }

    [Test]
    public async Task ReaderProjectionDistinguishesAbsenceFromFailureAndDoesNotLeakCoordinates()
    {
        var reader = new TestReader();
        var reference = new SecretReference(reader.Authority, new CanaryAddress());
        using SecretRead read = await reader.GetSecretAsync(reference);
        await Assert.That(ReferenceEquals(read.Observation.Reference, reference)).IsTrue();
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        reader.Status = SecretStatus.Absent;
        await Assert.That(await reader.TryGetSecretAsync(reference) is null).IsTrue();
        foreach (SecretStatus status in new[] { SecretStatus.Absent, SecretStatus.Denied, SecretStatus.Unavailable })
        {
            reader.Status = status;
            SecretUnavailableException? error = null;
            try { using var ignored = await reader.GetSecretAsync(reference); }
            catch (SecretUnavailableException caught) { error = caught; }
            await Assert.That(error?.Status).IsEqualTo(status);
            foreach (string canary in new[] { "canary-project-id", "canary-env", "canary-key", "material-canary" })
                await Assert.That(error!.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
            if (status != SecretStatus.Absent)
                await Assert.That(async () => await reader.TryGetSecretAsync(reference)).Throws<SecretUnavailableException>();
        }
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.That(async () => await reader.GetSecretAsync(reference, cancelled.Token)).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task ClassificationDoesNotTreatDenialAsPermissionToRefreshOrReplay()
    {
        await Assert.That(SecretStatus.Success.IsSuccess()).IsTrue();
        await Assert.That(SecretStatus.Unavailable.IsTransientFailure()).IsTrue();
        await Assert.That(SecretStatus.Throttled.IsTransientFailure()).IsTrue();
        await Assert.That(SecretStatus.Denied.IsTransientFailure()).IsFalse();
        await Assert.That(SecretStatus.Expired.RequiresReauthentication()).IsTrue();
        await Assert.That(SecretStatus.Denied.RequiresReauthentication()).IsFalse();
        await Assert.That(() => new SecretUnavailableException(SecretStatus.Success)).Throws<ArgumentException>();
        await Assert.That(() => new SecretUnavailableException((SecretStatus)int.MaxValue)).Throws<ArgumentException>();
        await Assert.That(() => new SecretUnavailableException(SecretStatus.Denied, (SecretFailureReason)int.MaxValue)).Throws<ArgumentException>();
    }

    private sealed class CanaryAddress : SecretAddress
    {
        public string Project => "canary-project-id";
        public string Environment => "canary-env";
        public string Key => "canary-key";
    }

    private sealed class TestReader : ISecretReader
    {
        public SecretAuthority Authority { get; } = new();
        public SecretStatus Status { get; set; } = SecretStatus.Success;
        public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(Status == SecretStatus.Success
                ? SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText("material-canary"),
                    new(reference, null, DateTimeOffset.UnixEpoch, SecretValidity.Valid)))
                : SecretOutcome<SecretRead>.Failure(Status));
        }
    }
}
