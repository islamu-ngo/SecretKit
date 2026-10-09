using SecretKit.Core;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Consumer.Tests;

public sealed class StalePolicyTests
{
    [Test]
    public async Task FailClosedRetiresClientAfterRefreshFailure()
    {
        var fixture = new RuntimeFixture { Value = "test-known" };
        using var coordinator = fixture.Create();
        await coordinator.EnableAsync();
        fixture.Failure = SecretStatus.Denied;
        RuntimeActivationObservation denied = await coordinator.CheckAgainAsync();
        await Assert.That(denied.LastStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(denied.Active).IsFalse();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task BoundedStaleDeadlineDoesNotSlideOnAcquisitionOrFailedRefresh()
    {
        var fixture = new RuntimeFixture { Value = "test-known" };
        using var coordinator = fixture.Create(RuntimeStalePolicy.BoundedLastKnown);
        RuntimeActivationObservation initial = await coordinator.EnableAsync();
        fixture.Time.Now += TimeSpan.FromMinutes(4);
        fixture.Failure = SecretStatus.Unavailable;
        RuntimeActivationObservation stale = await coordinator.CheckAgainAsync();
        await Assert.That(stale.Freshness).IsEqualTo(RuntimeFreshness.Stale);
        await Assert.That(stale.UsableUntil).IsEqualTo(initial.UsableUntil);
        using RuntimeGenerationLease pinned = coordinator.Acquire()!;
        await Assert.That(await pinned.ExecuteAsync()).IsEqualTo("test-known");
        fixture.Time.Now += TimeSpan.FromMinutes(1);
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(coordinator.Observe().Freshness).IsEqualTo(RuntimeFreshness.DeadlineElapsed);
        await Assert.That(async () => await pinned.ExecuteAsync()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task KnownExpiryOverridesMaximumStaleAndPinnedLease()
    {
        var fixture = new RuntimeFixture { Value = "test-expiring" };
        fixture.Expiry = fixture.Time.Now + TimeSpan.FromSeconds(30);
        using var coordinator = fixture.Create(RuntimeStalePolicy.BoundedLastKnown);
        RuntimeActivationObservation initial = await coordinator.EnableAsync();
        await Assert.That(initial.UsableUntil).IsEqualTo(fixture.Expiry);
        using RuntimeGenerationLease lease = coordinator.Acquire()!;
        fixture.Time.Now = fixture.Expiry.Value;
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(async () => await lease.ExecuteAsync()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task CandidateExpiringDuringValidationIsNeverActivated()
    {
        var fixture = new RuntimeFixture { Value = "test-expiring" };
        fixture.Expiry = fixture.Time.Now + TimeSpan.FromSeconds(30);
        fixture.BeforeValidation = _ =>
        {
            fixture.Time.Now = fixture.Expiry.Value;
            return Task.CompletedTask;
        };
        using var coordinator = fixture.Create();
        RuntimeActivationObservation expired = await coordinator.EnableAsync();
        await Assert.That(expired.LastStatus).IsEqualTo(SecretStatus.Expired);
        await Assert.That(coordinator.Acquire()).IsNull();
        await Assert.That(fixture.Clients.Single().Disposed).IsTrue();
    }

    [Test]
    public async Task FreshSuccessReplacesStaleClientAndDeadline()
    {
        var fixture = new RuntimeFixture { Value = "test-first" };
        using var coordinator = fixture.Create(RuntimeStalePolicy.BoundedLastKnown);
        RuntimeActivationObservation first = await coordinator.EnableAsync();
        fixture.Time.Now += TimeSpan.FromMinutes(4);
        fixture.Failure = SecretStatus.Unknown;
        await coordinator.CheckAgainAsync();
        fixture.Failure = null;
        fixture.Value = "test-fresh";
        RuntimeActivationObservation fresh = await coordinator.CheckAgainAsync();
        await Assert.That(fresh.Freshness).IsEqualTo(RuntimeFreshness.Fresh);
        await Assert.That(fresh.UsableUntil > first.UsableUntil).IsTrue();
        await Assert.That(fixture.Clients.First().Disposed).IsTrue();
        using RuntimeGenerationLease lease = coordinator.Acquire()!;
        await Assert.That(await lease.ExecuteAsync()).IsEqualTo("test-fresh");
    }
}
