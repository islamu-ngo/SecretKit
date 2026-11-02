using System.Collections.Immutable;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuditPermissionSourceTests
{
    [Test]
    public async Task SealedCensusDoesNotInventNativeAuditSortOrder()
    {
        await using var provider = new InfisicalAuditPermissionFixture("reverse-page-order");
        var result = await InfisicalAuditPermissionEffectTests.RunAsync(provider, AuditPermissionContract.Operations[0],
            "permission.AuditLogs.read", "independent-effect");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    public async Task PublicationFenceRejectsLateSdkSeedDispatch()
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        string operation = AuditPermissionContract.Operations[0];
        using var environment = provider.Environment(operation, AuditPermissionAction.Read);
        var root = provider.Root(operation, AuditPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("audit-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var source = provider.Source.CreateClient();
        AuditPermissionTrial? retained = null;
        try
        {
            var trial = await AuditPermissionTrial.OpenAsync(source, root, capability, t => retained = t, deadline.Token);
            await AuditPermissionEffects.WitnessAsync(environment, root, trial, false, deadline.Token);
            int generated = provider.Generated, historical = provider.HistoricalRows;
            var client = environment.CreateManagementClient();
            var future = trial.Plan.WindowSeeds(true, AuditPermissionOutcome.NonApplied)[0];
            using var request = RoleChangeOperations.CreateProjectRole(root.Organization, trial.Issued.Id(future.Project),
                new(future.Name, future.Slug, new("closed-seed"), []));
            var receipt = client.CreateReceipt(request);
            var authority = environment.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, request.Target.ProjectId);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, deadline.Token);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
            await Assert.That(provider.Generated).IsEqualTo(generated);
            await Assert.That(provider.HistoricalRows).IsEqualTo(historical);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    public async Task PublisherRequiresDistinctHostPinnedAuthority()
    {
        await using var provider = new InfisicalAuditPermissionFixture();
        var root = provider.Root(AuditPermissionContract.Operations[0], AuditPermissionAction.Read, "independent-effect");
        var publisher = root.Profile.Pins.Single(p => p.Journal == AuditPermissionJournal.Publisher);
        var storage = root.Profile.Pins.Single(p => p.Journal == AuditPermissionJournal.Storage);
        var collapsed = root.Profile with { Pins = root.Profile.Pins.Select(p => p == publisher ? p with { Spki = storage.Spki } : p).ToImmutableArray() };
        await Assert.That(() => AuditPermissionVerifier.Validate(collapsed)).Throws<NativeCaseFailureException>();
        await Assert.That(() => AuditPermissionVerifier.Validate(root.Profile with { Pins = root.Profile.Pins.Remove(publisher) })).Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task FailedOpenAllowsOnlyOriginalRootRecovery()
    {
        await using var provider = new InfisicalAuditPermissionFixture("lost-open");
        var root = provider.Root(AuditPermissionContract.Operations[0], AuditPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("audit-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var source = provider.Source.CreateClient();
        AuditPermissionTrial? retained = null;
        await Assert.That(async () => await AuditPermissionTrial.OpenAsync(source, root, capability, t => retained = t, deadline.Token)).Throws<NativeCaseFailureException>();
        await Assert.That(retained is not null).IsTrue();
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(async () => await source.StepAsync(root with { Nonce = Guid.NewGuid().ToString("N") }, AuditPermissionStep.Close, null, deadline.Token)).Throws<NativeCaseFailureException>();
        await Assert.That(async () => await source.StepAsync(root, AuditPermissionStep.Open, null, deadline.Token)).Throws<NativeCaseFailureException>();
        await retained!.DisposeAsync();
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    public async Task RootCloseDrainsAdmittedIssuerWithoutReturnedIds()
    {
        await using var provider = new InfisicalAuditPermissionFixture("delayed-issuer");
        var root = provider.Root(AuditPermissionContract.Operations[0], AuditPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("audit-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        AuditPermissionTrial? retained = null;
        Task entered = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Assert.That(async () => await AuditPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token)).Throws<NativeCaseFailureException>();
        await entered.WaitAsync(deadline.Token);
        var close = retained!.DisposeAsync().AsTask();
        await closing.WaitAsync(deadline.Token);
        await Assert.That(close.IsCompleted).IsFalse();
        provider.IssuerRelease.TrySetResult();
        await close.WaitAsync(deadline.Token);
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    public async Task RootCloseDrainsAdmittedPublicationBeforeSealingHistoricalResidue()
    {
        await using var provider = new InfisicalAuditPermissionFixture("delayed-publisher");
        var operation = AuditPermissionContract.Operations[0];
        using var environment = provider.Environment(operation, AuditPermissionAction.Read);
        var root = provider.Root(operation, AuditPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("audit-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        AuditPermissionTrial? retained = null;
        try
        {
            var trial = await AuditPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await trial.BeginSeedsAsync(false, deadline.Token);
            Task entered = provider.PublisherEntered.Task, closing = provider.CloseEntered.Task;
            _ = await AuditPermissionClient.SeedAsync(environment, root, trial.Issued, trial.Plan.WindowSeeds(false, trial.Outcome)[0], deadline.Token);
            await entered.WaitAsync(deadline.Token);
            var close = trial.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token);
            await Assert.That(close.IsCompleted).IsFalse();
            await Assert.That(provider.PendingPublication).IsEqualTo(1);
            provider.PublisherRelease.TrySetResult();
            await close.WaitAsync(deadline.Token);
            await Assert.That(provider.HistoricalRows).IsEqualTo(1);
        }
        finally { provider.PublisherRelease.TrySetResult(); if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }

    [Test]
    public async Task ReadAuditRetainsPartialInvalidOutcomesRatherThanDroppingRows()
    {
        await using var provider = new InfisicalAuditPermissionFixture("partial-invalid-page");
        string operation = AuditPermissionContract.Operations[0];
        using var environment = provider.Environment(operation, AuditPermissionAction.Read);
        var root = provider.Root(operation, AuditPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("audit-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        AuditPermissionTrial? retained = null;
        try
        {
            var trial = await AuditPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token);
            await AuditPermissionEffects.WitnessAsync(environment, root, trial, false, deadline.Token);
            await trial.ArmAsync(deadline.Token);
            await trial.SettleAsync(await AuditPermissionEffects.DispatchAsync(environment, root, trial.Plan, trial.Issued, deadline.Token), deadline.Token);
            await trial.BeginSeedsAsync(true, deadline.Token);
            var receipts = new List<AuditPermissionSeedReceipt>();
            foreach (var seed in trial.Plan.WindowSeeds(true, trial.Outcome))
                receipts.Add(await AuditPermissionClient.SeedAsync(environment, root, trial.Issued, seed, deadline.Token));
            await trial.PublishedAsync(true, receipts.ToArray(), deadline.Token);
            await trial.BeginAsync(true, deadline.Token);
            var client = environment.CreateManagementClient();
            using var request = GovernanceOperations.ReadAudit(root.Organization, root.From, root.Until,
                trial.Issued.Id(AuditPermissionPlan.Project), 0, 2, new(actor: root.Authorities.Setup, actorType: "identity",
                    eventClass: AuditEventFilter.Classes([AuditEventClass.Management]), eventType: AuditEventFilter.Types(["create-project-role"])));
            var authority = environment.CreateManagementAuthority(client, NativeIdentityRole.Runtime, root.Organization, request.Target.ProjectId);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), cancellationToken: deadline.Token);
            await Assert.That(result.IsSuccess).IsTrue();
            await Assert.That(result.Value.Items.Count).IsEqualTo(2);
            await Assert.That(result.Value.Items[0].Outcome.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(result.Value.Items[1].Outcome.IsSuccess).IsTrue();
            await Assert.That(result.Value.IsComplete).IsFalse();
            await Assert.That(result.Value.NextOffset).IsEqualTo(2);
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalAuditPermissionEffectTests.Clean(provider);
    }
}
