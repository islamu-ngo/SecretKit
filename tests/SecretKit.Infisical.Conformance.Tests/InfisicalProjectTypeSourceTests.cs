using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalProjectTypeSourceTests
{
    [Test]
    [Arguments("lost-reserve", 0)]
    [Arguments("partial-open", 1)]
    [Arguments("lost-open", 24)]
    public async Task OriginalRootRetainsCompensationBeforeAnyReply(string fault, int issuedCount)
    {
        await using var provider = new InfisicalProjectTypeFixture(fault);
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var root = InfisicalProjectTypeCalibrationTests.Root(env, "type.Kms", "selected-contract");
        ProjectTypeTrial? retained = null;
        bool rejected = false;
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        try
        {
            await ProjectTypeTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                t => retained = t, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { rejected = true; }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(rejected && retained is not null).IsTrue();
        await Assert.That(provider.IssuanceJournal.Count).IsEqualTo(issuedCount);
        await Assert.That(provider.CleanupJournal.Count).IsEqualTo(issuedCount);
        await Assert.That(provider.Source.Cleanups.Single().Root).IsEqualTo(root);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.Registrations).IsEqualTo(0);
    }

    [Test]
    public async Task CloseFencesAndDrainsAnAlreadyEnrolledIssuerBeforeItCanCreate()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var root = InfisicalProjectTypeCalibrationTests.Root(env, "type.Pam", "selected-contract");
        ProjectTypeTrial? retained = null;
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        provider.Source.PauseIssuer = true;
        Task entered = provider.Source.IssuerEntered.Task;
        var opening = ProjectTypeTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
            t => retained = t, CancellationToken.None).AsTask();
        await entered.WaitAsync(TimeSpan.FromSeconds(15));
        await Assert.That(retained is not null).IsTrue();
        await retained!.DisposeAsync();
        bool rejected = false;
        try { await opening; }
        catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await Assert.That(provider.Source.IssuerWorkJournal.Select(w => w.State)
            .SequenceEqual(new[] { "enrolled", "aborted" })).IsTrue();
        await Assert.That(provider.IssuanceJournal.Count).IsEqualTo(0);
        await Assert.That(provider.Source.Cleanups.Single().PendingIssuers).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        // Late independent issuance hits the original creation tombstone.
        bool lateRejected = false;
        try { lock (provider.Gate) provider.Issue(root); }
        catch (NativeCaseFailureException) { lateRejected = true; }
        await Assert.That(lateRejected).IsTrue();
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    public async Task SourceConsumesStagesAndRejectsReplayedOpenWithoutDuplicateCreation()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var root = InfisicalProjectTypeCalibrationTests.Root(env, "type.AgentVault", "selected-contract");
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        await provider.Source.ReserveAsync(root, capability, CancellationToken.None);
        await provider.Source.OpenAsync(root, CancellationToken.None);
        bool rejected = false;
        try { await provider.Source.OpenAsync(root, CancellationToken.None); }
        catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await provider.Source.CloseAsync(root, CancellationToken.None);
        await Assert.That(provider.IssuanceJournal.Count).IsEqualTo(24);
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }

    [Test]
    public async Task ConflictingRootAndNonceCannotBorrowCleanupAuthority()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var owner = InfisicalProjectTypeCalibrationTests.Root(env, "type.Kms", "selected-contract");
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        await provider.Source.ReserveAsync(owner, capability, CancellationToken.None);
        var issued = await provider.Source.OpenAsync(owner, CancellationToken.None);
        var attacker = owner with { Nonce = Guid.NewGuid().ToString("N") };
        bool rejected = false;
        try { await provider.Source.CloseAsync(attacker, CancellationToken.None); }
        catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
        await Assert.That(provider.Remaining).IsEqualTo(24);
        await Assert.That(provider.Inventory(owner).Length).IsEqualTo(issued.Inventory.Length);
        await provider.Source.CloseAsync(owner, CancellationToken.None);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    public async Task CollidingNonceReserveDoesNotEnrollOrDeleteAnotherRootsProjects()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var owner = InfisicalProjectTypeCalibrationTests.Root(env, "type.Kms", "selected-contract");
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        await provider.Source.ReserveAsync(owner, capability, CancellationToken.None);
        await provider.Source.OpenAsync(owner, CancellationToken.None);
        var collision = owner with { Id = Guid.NewGuid().ToString("N") };
        ProjectTypeTrial? retained = null;
        bool rejected = false;
        try
        {
            await ProjectTypeTrial.OpenAsync(provider.Source.CreateClient(), collision, capability, 15,
                t => retained = t, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { rejected = true; }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(rejected).IsTrue();
        await Assert.That(provider.Remaining).IsEqualTo(24);
        await Assert.That(provider.CleanupJournal.Count).IsEqualTo(0);
        await provider.Source.CloseAsync(owner, CancellationToken.None);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    public async Task ClosedOriginalIngressRejectsAnActualLateNativeGet()
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        await InfisicalProjectTypeCalibrationTests.DirectAsync(provider, env, "type.Kms", "selected-contract");
        using var transport = new ManagementTransport(env.Origin, allowLoopbackDevelopmentHttp: true);
        var client = new ManagementClient(transport);
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Administrative, InfisicalProjectTypeFixture.Org);
        using var request = ProjectOperations.ListProjects(InfisicalProjectTypeFixture.Org, ProjectType.Kms, false);
        var late = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target));
        await Assert.That(late.IsSuccess).IsFalse();
        await Assert.That(provider.LateRejections.Count).IsEqualTo(1);
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    [Arguments("source")]
    [Arguments("roles")]
    [Arguments("query")]
    [Arguments("lost")]
    public async Task InvalidHostJoinsAreRejectedBeforeReservation(string fault)
    {
        await using var provider = new InfisicalProjectTypeFixture();
        using var env = provider.Environment(InfisicalProjectTypeCalibrationTests.Families());
        var root = InfisicalProjectTypeCalibrationTests.Root(env, "type.Kms", "selected-contract");
        root = fault switch
        {
            "source" => root with { Source = ProjectTypeSourceKind.NativeProvider },
            "roles" => root with { Authorities = root.Authorities with { Denied = root.Authorities.Observer } },
            "query" => root with { Query = new(null, null) },
            _ => root with { Case = "lost-response-no-replay" }
        };
        using var capability = SecretMaterial.FromText("private-project-type-capability");
        bool retained = false, rejected = false;
        try
        {
            await ProjectTypeTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                _ => retained = true, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected && !retained).IsTrue();
        await Assert.That(provider.Source.Opens).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }
}
