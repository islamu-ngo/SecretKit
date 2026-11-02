using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalOrganizationUserSourceTests
{
    private static NativeCaseDefinition Definition => InfisicalOrganizationUserCalibrationTests.Definition(
        OrganizationUserContract.Prefix + "UpdateOrganizationMembership", "role.value", "independent-effect");

    [Test]
    [Arguments("lost-reserve", 0)]
    [Arguments("lost-open-1", 1)]
    [Arguments("lost-open-2", 2)]
    [Arguments("lost-open-3", 3)]
    [Arguments("lost-open-4", 4)]
    [Arguments("lost-open-5", 5)]
    [Arguments("lost-open-6", 6)]
    [Arguments("lost-open-7", 7)]
    [Arguments("lost-open-8", 8)]
    [Arguments("lost-open-9", 9)]
    [Arguments("lost-open-10", 10)]
    [Arguments("lost-open-11", 11)]
    [Arguments("lost-open-12", 12)]
    [Arguments("lost-open", 9)]
    public async Task OriginalRootRecoversEveryPartialIssuanceWithoutReturnedIds(string fault, int resources)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var definition = resources > 9 ? InfisicalOrganizationUserCalibrationTests.Definition(
            OrganizationUserContract.Batch, "input.organizationId-membershipIds", "independent-effect") : Definition;
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, definition);
        OrganizationUserTrial? retained = null;
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        NativeCaseFailureException? failure = null;
        try
        {
            await OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                trial => retained = trial, CancellationToken.None);
        }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure?.Message).IsEqualTo("observer-unavailable");
        await Assert.That(retained is not null).IsTrue();
        await retained!.DisposeAsync();
        var cleanup = provider.Source.Cleanups.Single();
        await Assert.That(cleanup.Issued.Length).IsEqualTo(resources);
        await Assert.That(cleanup.Remaining.Length).IsEqualTo(0);
        await Assert.That(provider.CleanupJournal.Count).IsEqualTo(resources);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
        await Assert.That(provider.Source.PrivateCopies.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task CloseFencesIssuerContinuationBeforeItCanCreateAnything()
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        provider.Source.PauseIssuer = true;
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        OrganizationUserTrial? retained = null;
        Task entered = provider.Source.IssuerEntered.Task;
        Task<OrganizationUserTrial> open = OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(),
            root, capability, 15, t => retained = t, CancellationToken.None).AsTask();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            await entered.WaitAsync(deadline.Token);
            await retained!.DisposeAsync();
        }
        finally { provider.Source.IssuerRelease.TrySetResult(); }
        NativeCaseFailureException? failure = null;
        try { await open; }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure is not null).IsTrue();
        await Assert.That(provider.Source.IssuerAborts).IsEqualTo(1);
        await Assert.That(provider.Source.IssuerWorkJournal.Last().State).IsEqualTo("aborted");
        await Assert.That(provider.Source.Cleanups.Single().CreationFence).IsTrue();
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.UserIssuerJournal.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CollisionNeverGrantsCleanupAuthorityOverBorrowedState()
    {
        await using var provider = new InfisicalOrganizationUserFixture("collision");
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        OrganizationUserTrial? retained = null;
        try
        {
            await OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(), root, capability, 15,
                t => retained = t, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { }
        await retained!.DisposeAsync();
        await Assert.That(provider.Source.Opens).IsEqualTo(0);
        await Assert.That(provider.CleanupJournal.Count).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    [Arguments("wrong-epoch")]
    [Arguments("wrong-deployment")]
    [Arguments("wrong-clock")]
    [Arguments("stale-sequence")]
    [Arguments("regressed-time")]
    [Arguments("duplicate-event")]
    [Arguments("non-utc")]
    [Arguments("wrong-registration")]
    [Arguments("wrong-root")]
    [Arguments("credential-wrong-user")]
    [Arguments("credential-unbound")]
    [Arguments("membership-wrong-user")]
    [Arguments("inventory-missing")]
    [Arguments("unqualified-issuance")]
    public async Task IssuanceCannotSubstituteIdentityClockOrOwnership(string fault)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        NativeCaseFailureException? failure = null;
        try { await InfisicalOrganizationUserCalibrationTests.DirectAsync(provider, env, Definition); }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure?.Message).IsEqualTo("observer-unavailable");
        await Assert.That(provider.RequestJournal.Count).IsEqualTo(0);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
    }

    [Test]
    [Arguments("unheld-window", "observer-unavailable")]
    [Arguments("access-wrong-principal", "effect-mismatch")]
    [Arguments("access-wrong-credential", "effect-mismatch")]
    [Arguments("access-replayed", "effect-mismatch")]
    [Arguments("incomplete-inventory", "observer-unavailable")]
    [Arguments("metadata-echo", "observer-unavailable")]
    [Arguments("unqualified-access", "observer-unavailable")]
    [Arguments("credential-reissued", "observer-unavailable")]
    [Arguments("unexclusive-ingress", "observer-unavailable")]
    [Arguments("nonterminal", "observer-unavailable")]
    [Arguments("late-work", "observer-unavailable")]
    [Arguments("replayed-original", "observer-unavailable")]
    [Arguments("wrong-original-actor", "observer-unavailable")]
    [Arguments("extra-original", "observer-unavailable")]
    [Arguments("lost-settle", "observer-unavailable")]
    [Arguments("storage-wrong-role", "effect-mismatch")]
    public async Task JournalsRejectUnboundIncompleteReplayedAndNonterminalFacts(string fault, string reason)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        NativeCaseFailureException? failure = null;
        try { await InfisicalOrganizationUserCalibrationTests.DirectAsync(provider, env, Definition); }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure?.Message).IsEqualTo(reason);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }

    [Test]
    [Arguments("cleanup-residual")]
    [Arguments("cleanup-creation-fence")]
    [Arguments("cleanup-dispatch-fence")]
    [Arguments("cleanup-terminal")]
    [Arguments("cleanup-inventory")]
    [Arguments("cleanup-pending-issuer")]
    [Arguments("cleanup-pending-dispatch")]
    [Arguments("cleanup-registration")]
    [Arguments("cleanup-copies")]
    [Arguments("cleanup-epoch")]
    [Arguments("cleanup-root")]
    public async Task CleanupRequiresFullAbsenceAndBothTerminalFences(string fault)
    {
        await using var provider = new InfisicalOrganizationUserFixture(fault);
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        NativeCaseFailureException? failure = null;
        try { await InfisicalOrganizationUserCalibrationTests.DirectAsync(provider, env, Definition); }
        catch (NativeCaseFailureException error) { failure = error; }
        await Assert.That(failure?.Message).IsEqualTo("cleanup-incomplete");
        await Assert.That(provider.Source.Observations).IsEqualTo(2);
        await Assert.That(provider.Source.Closes).IsEqualTo(1);
    }

    [Test]
    public async Task SourceAndClientBothConsumeStagesEvenWhenAReplyIsLost()
    {
        await using var provider = new InfisicalOrganizationUserFixture("lost-open");
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        var client = provider.Source.CreateClient();
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        await client.ReserveAsync(root, capability, CancellationToken.None);
        int failures = 0;
        try { await client.OpenAsync(root, CancellationToken.None); }
        catch (NativeCaseFailureException) { failures++; }
        try { await client.OpenAsync(root, CancellationToken.None); }
        catch (NativeCaseFailureException) { failures++; }
        try { await provider.Source.OpenAsync(root, CancellationToken.None); }
        catch (NativeCaseFailureException) { failures++; }
        await client.CloseAsync(root, CancellationToken.None);
        try { await client.OpenAsync(root, CancellationToken.None); }
        catch (NativeCaseFailureException) { failures++; }
        await Assert.That(failures).IsEqualTo(4);
        await Assert.That(provider.Source.Opens).IsEqualTo(1);
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }

    [Test]
    public async Task DisposedIssuanceAndTransportCopiesAreActuallyCleared()
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        var buffers = new List<byte[]>();
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        var trial = await OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(size =>
        {
            byte[] buffer = new byte[size]; buffers.Add(buffer); return buffer;
        }), root, capability, 15, _ => { }, CancellationToken.None);
        var issuedBytes = trial.Issued.Principals.Select(p => p.Credential).ToArray();
        await Assert.That(issuedBytes.All(b => b.Any(v => v != 0))).IsTrue();
        await trial.DisposeAsync();
        await Assert.That(issuedBytes.Concat(buffers).Concat(provider.Source.PrivateCopies)
            .All(b => b.All(v => v == 0))).IsTrue();
        // Ordinary input/JSON/header strings, framework and socket copies are
        // intentionally outside this buffer-lifetime claim.
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ActualSecondDispatchIsRejectedAndCannotHideFromTheRequestFence(bool afterFence)
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        OrganizationUserTrial? retained = null;
        try
        {
            var trial = await OrganizationUserTrial.OpenAsync(provider.Source.CreateClient(), root, capability,
                15, t => retained = t, CancellationToken.None);
            await InfisicalOrganizationUserCalibrationTests.WitnessAsync(env, root, trial, false);
            await trial.ArmAsync(CancellationToken.None);
            var intent = trial.Intent;
            var first = await InfisicalOrganizationUserCalibrationTests.ExecuteAsync(env, Definition,
                () => OrganizationMembershipOperations.UpdateOrganizationMembership(root.OrganizationId,
                    intent.MembershipIds[0], intent.Role, intent.Active), _ => true);
            if (afterFence) await trial.SettleAsync(first, CancellationToken.None);
            var client = env.CreateManagementClient();
            using var request = OrganizationMembershipOperations.UpdateOrganizationMembership(root.OrganizationId,
                intent.MembershipIds[0], intent.Role, intent.Active);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Administrative, root.OrganizationId);
            var receipt = client.CreateReceipt(request);
            var second = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), receipt);
            await Assert.That(second.IsSuccess).IsFalse();
            await Assert.That(receipt.Evidence == DispatchEvidence.Applied).IsFalse();
            await Assert.That(provider.MembershipJournal.Count).IsEqualTo(1);
            if (afterFence)
            {
                await Assert.That(provider.RequestJournal.Count).IsEqualTo(1);
                await Assert.That(provider.LateRejections.Count).IsEqualTo(1);
            }
            else
            {
                NativeCaseFailureException? failure = null;
                try { await trial.SettleAsync(first, CancellationToken.None); }
                catch (NativeCaseFailureException error) { failure = error; }
                await Assert.That(failure?.Message).IsEqualTo("observer-unavailable");
                await Assert.That(provider.Source.Fences.Single().NoReplay).IsFalse();
                await Assert.That(provider.RequestJournal.Count).IsEqualTo(2);
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }

    [Test]
    public async Task AForeignNonceCannotReleaseAnotherRootsIssuedResources()
    {
        await using var provider = new InfisicalOrganizationUserFixture();
        using var env = provider.Environment(InfisicalOrganizationUserCalibrationTests.Families());
        var root = InfisicalOrganizationUserCalibrationTests.Root(env, Definition);
        using var capability = SecretMaterial.FromText("private-user-issuer-capability");
        var client = provider.Source.CreateClient();
        var trial = await OrganizationUserTrial.OpenAsync(client, root, capability, 15, _ => { }, CancellationToken.None);
        try
        {
            int before = provider.Remaining, failures = 0;
            try { await client.CloseAsync(root with { Nonce = "foreign" }, CancellationToken.None); }
            catch (NativeCaseFailureException) { failures++; }
            try { await provider.Source.CloseAsync(root with { Nonce = "foreign" }, CancellationToken.None); }
            catch (NativeCaseFailureException) { failures++; }
            await Assert.That(failures).IsEqualTo(2);
            await Assert.That(provider.Remaining).IsEqualTo(before);
            await Assert.That(provider.CleanupJournal.Count).IsEqualTo(0);
        }
        finally { await trial.DisposeAsync(); }
        await Assert.That(provider.Remaining).IsEqualTo(0);
    }
}
