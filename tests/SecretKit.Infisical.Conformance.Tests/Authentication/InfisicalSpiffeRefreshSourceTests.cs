using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSpiffeRefreshSourceTests
{
    [Test]
    [Arguments("open")]
    [Arguments("arm")]
    public async Task LostSourceReplyStillClosesRootWithoutReplay(string route)
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture();
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        var source = fixture.Source.Client();
        var root = InfisicalSpiffeRefreshCalibrationTests.Root("independent-effect");
        using var capability = SecretMaterial.FromText("exclusive-capability");
        fixture.Source.LostReply = route;
        bool unavailable = false;
        try
        {
            var binding = await source.OpenAsync(root, capability, CancellationToken.None);
            using var baseline = await InfisicalSpiffeRefreshCalibrationTests.GetAsync(env, CancellationToken.None);
            await source.ArmAsync(binding, CancellationToken.None);
        }
        catch (SecretKit.TestFixtures.NativeCaseFailureException e)
        { unavailable = e.Message == "observer-unavailable"; }
        finally
        {
            var cleanup = await source.CloseAsync(root, CancellationToken.None);
            await Assert.That(cleanup.OwnedAbsent && cleanup.CopiesDestroyed && cleanup.ExcludesLateWork).IsTrue();
        }
        await Assert.That(unavailable).IsTrue();
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Requests.Count).IsEqualTo(0);
        await Assert.That(capability.Reveal()).IsEqualTo("exclusive-capability");
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task FenceRejectsLateSameIdentityIngressAndCannotHideItInCleanup()
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture();
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        var source = fixture.Source.Client();
        var root = InfisicalSpiffeRefreshCalibrationTests.Root("independent-effect");
        using var capability = SecretMaterial.FromText("exclusive-capability");
        try
        {
            var binding = await source.OpenAsync(root, capability, CancellationToken.None);
            using var baseline = await InfisicalSpiffeRefreshCalibrationTests.GetAsync(env, CancellationToken.None);
            var arm = await source.ArmAsync(binding, CancellationToken.None);
            var before = await source.SettleAsync(arm,
                new(DispatchEvidence.NotDispatched, SecretStatus.Unknown, true), CancellationToken.None);
            await Assert.That(before.Requests).IsEqualTo(0);
            var client = env.CreateManagementClient();
            using var late = ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle(root.OrganizationId, root.IdentityId);
            var receipt = client.CreateReceipt(late);
            var authority = env.CreateManagementAuthority(client, SecretKit.TestFixtures.NativeIdentityRole.Administrative,
                root.OrganizationId);
            var result = await client.ExecuteAsync(late, authority, authority.IssueGrant(late.OperationId, late.Target), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
            await Assert.That(fixture.Requests.Count).IsEqualTo(0);
            await Assert.That(fixture.Cache.Count).IsEqualTo(1);
            await Assert.That(fixture.ForeignRequests).IsEqualTo(1);
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, CancellationToken.None);
            await Assert.That(cleanup.ExcludesLateWork).IsFalse();
            await Assert.That(cleanup.OwnedAbsent && cleanup.CopiesDestroyed && cleanup.OriginalTerminal).IsTrue();
        }
    }

    [Test]
    public async Task ClosedOptionalInputDoesNotInventStaticOrHttpRefresh()
    {
        await using var fixture = new InfisicalSpiffeRefreshFixture();
        using var env = InfisicalSpiffeRefreshCalibrationTests.Environment(fixture);
        var input = SpiffeRefreshInput.FromInputs(env);
        await Assert.That(input is not null).IsTrue();
        bool rejected = false;
        try { (input! with { BundleEndpoint = "http://publisher.invalid/bundle" }).Validate(); }
        catch (SecretKit.TestFixtures.NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await Assert.That(fixture.Source.Opens).IsEqualTo(0);
        await Assert.That(fixture.Bundles.Count).IsEqualTo(0);
    }
}
