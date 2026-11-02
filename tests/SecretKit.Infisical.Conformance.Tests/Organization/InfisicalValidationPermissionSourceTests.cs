using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalValidationPermissionSourceTests
{
    [Test]
    public async Task EnforcementProbesReuseActorAndObserverConnections()
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        string operation = ValidationPermissionContract.Operations[0];
        using var env = provider.Environment(operation, ValidationPermissionAction.Read);
        var root = provider.Root(operation, ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        ValidationPermissionTrial? retained = null;
        try
        {
            var trial = await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
            await trial.BeginAsync(false, deadline.Token);
            var attempts = await ValidationPermissionClient.WritesAsync(env, root, trial.Issued, trial.Rows(false)[0], false, deadline.Token);
            await Assert.That(attempts.Length).IsEqualTo(8);
            // Real accepted sockets, not mock calls: seven writer probes, one
            // policy-actor probe and eight readbacks must share their clients.
            await Assert.That(provider.ConnectionCount <= 5).IsTrue();
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ReserveHasOnlyLogicalIntentsAndNoCanonicalIds()
    {
        await using var provider = new InfisicalValidationPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("validation-capability");
        var reserved = await source.StepAsync(root, ValidationPermissionStep.Reserve, capability, CancellationToken.None);
        await Assert.That(provider.Generated).IsEqualTo(0);
        await Assert.That(reserved.Issuer.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Storage.Payload.Content.Bindings.Length).IsEqualTo(0);
        await Assert.That(reserved.Owner.Payload.Content.Intents.Any(i => i.Kind == "validation-rule")).IsTrue();
        var opened = await source.StepAsync(root, ValidationPermissionStep.Open, null, CancellationToken.None);
        try
        {
            await Assert.That(provider.Generated > 0).IsTrue();
            await Assert.That(ValidationPermissionContract.Hash(reserved.Owner.Payload.Content.Intents)).IsEqualTo(ValidationPermissionContract.Hash(opened.Owner.Payload.Content.Intents));
            await Assert.That(opened.Storage.Payload.Content.Bindings.All(b => Guid.TryParse(b.CanonicalId, out _))).IsTrue();
            await Assert.That(opened.Storage.Payload.Content.Bindings.Select(b => b.CanonicalId).Distinct().Count()).IsEqualTo(provider.Generated);
        }
        finally
        {
            await source.StepAsync(root, ValidationPermissionStep.Close, null, CancellationToken.None);
            foreach (var actor in opened.Owner.Payload.Content.Actors) actor.Erase();
        }
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments("lost-open")]
    [Arguments("partial-open")]
    public async Task RootAloneRecoversUnreturnedCanonicalBindings(string fault)
    {
        await using var provider = new InfisicalValidationPermissionFixture(fault);
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("validation-capability"); ValidationPermissionTrial? retained = null;
        await Rejected(() => ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        await Assert.That(provider.Generated > 0).IsTrue();
        await Assert.That(provider.Remaining > 0).IsTrue();
        await retained!.DisposeAsync(); await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task LostOpenCleanupFencesAndDrainsPreviouslyAdmittedIssuer()
    {
        await using var provider = new InfisicalValidationPermissionFixture("delayed-issuer");
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("validation-capability"); using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        ValidationPermissionTrial? retained = null; Task admitted = provider.IssuerEntered.Task, closing = provider.CloseEntered.Task;
        await Rejected(() => ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, deadline.Token).AsTask());
        await admitted.WaitAsync(deadline.Token); int before = provider.Generated;
        var cleanup = retained!.DisposeAsync().AsTask();
        try
        {
            await closing.WaitAsync(deadline.Token); await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally { provider.IssuerRelease.TrySetResult(); await cleanup.WaitAsync(deadline.Token); }
        await Assert.That(provider.Generated).IsEqualTo(before + 1); await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CancellationDuringOpenReleasesAllOwnedMaterialAndRootRegistration()
    {
        await using var provider = new InfisicalValidationPermissionFixture("interrupted-open"); var source = provider.Source.CreateClient();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("validation-capability"); using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        ValidationPermissionTrial? retained = null; Task entered = provider.OpenEntered.Task;
        var open = ValidationPermissionTrial.OpenAsync(source, root, capability, t => retained = t, cancellation.Token).AsTask();
        try
        {
            await entered.WaitAsync(cancellation.Token); cancellation.Cancel(); bool cancelled = false;
            try { await open; } catch (OperationCanceledException) { cancelled = true; }
            await Assert.That(cancelled).IsTrue();
        }
        finally
        {
            provider.OpenRelease.TrySetResult(); try { await open; } catch (OperationCanceledException) { }
            if (retained is not null) await retained.DisposeAsync();
        }
        await Rejected(() => source.StepAsync(root, ValidationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RejectedIssuedMaterialIsErasedEvenAfterSignatureFailure()
    {
        await using var provider = new InfisicalValidationPermissionFixture("forged-journal");
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var capability = SecretMaterial.FromText("validation-capability"); ValidationPermissionTrial? retained = null;
        await Rejected(() => ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, capability, t => retained = t, CancellationToken.None).AsTask());
        var actors = retained!.Issued.Actors;
        await Assert.That(actors.Any(a => a.Credential.Any(v => v != 0))).IsTrue();
        await retained.DisposeAsync(); await Assert.That(actors.All(a => a.Credential.All(v => v == 0))).IsTrue();
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task ChangedRootOrClosedSessionCannotIssueMoreWork()
    {
        await using var provider = new InfisicalValidationPermissionFixture(); var source = provider.Source.CreateClient();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        await source.StepAsync(root, ValidationPermissionStep.Reserve, cap, CancellationToken.None);
        await Rejected(() => source.StepAsync(root with { Nonce = "different" }, ValidationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await source.StepAsync(root, ValidationPermissionStep.Close, null, CancellationToken.None);
        await Rejected(() => source.StepAsync(root, ValidationPermissionStep.Open, null, CancellationToken.None).AsTask());
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task FactoryScopeAndActorKindAreExplicit(bool scope)
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        root = scope ? root with { ScopeProfile = ValidationPermissionScope.Organization } : root with { ActorKind = MemberPermissionActorKind.User };
        using var cap = SecretMaterial.FromText("validation-capability");
        await Rejected(() => ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, _ => throw new InvalidOperationException(), CancellationToken.None).AsTask());
        await Assert.That(provider.Opens).IsEqualTo(0);
    }
    [Test]
    public async Task DisposedFixtureReleasesClearedOwnedCapturesButPreservesBorrowedMaterial()
    {
        var provider = new InfisicalValidationPermissionFixture();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        ValidationPermissionTrial? retained = null;
        await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, CancellationToken.None);
        await retained!.DisposeAsync();
        var buffers = provider.Copies.Concat(provider.BackendBuffers).ToArray();
        await provider.DisposeAsync();
        await Assert.That(buffers.All(b => b.All(v => v == 0))).IsTrue();
        await Assert.That(provider.Copies.IsEmpty && !provider.BackendBuffers.Any()).IsTrue();
        await Assert.That(provider.BorrowedPreserved).IsTrue();
    }
    [Test]
    public async Task CloseCancelsUnadmittedTransportWithoutInventingAnEnforcementAttempt()
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        var root = provider.Root(ValidationPermissionContract.Operations[0], ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        ValidationPermissionTrial? retained = null;
        await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        // An accepted connection is not an authenticated request. No raw HTTP or
        // provider operation is sent; Close must drain this transport separately.
        Task accepted = provider.TransportAccepted.Task;
        using var socket = new System.Net.Sockets.TcpClient();
        await socket.ConnectAsync(provider.Origin.Host, provider.Origin.Port, deadline.Token);
        await accepted.WaitAsync(deadline.Token);
        await retained!.DisposeAsync().AsTask().WaitAsync(deadline.Token);
        await Assert.That(provider.ClosedPacket!.Enforcement.Payload.Content.Decisions.Length).IsEqualTo(0);
        await Assert.That(provider.ClosedPacket.Backend.Payload.Content.Changes.Length).IsEqualTo(0);
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UncertainStaticWriteIsReconciledWithoutReceiptReplay(bool beforeDispatch)
    {
        await using var provider = new InfisicalValidationPermissionFixture();
        string operation = ValidationPermissionContract.Operations[0];
        using var env = provider.Environment(operation, ValidationPermissionAction.Read);
        var root = provider.Root(operation, ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        ValidationPermissionTrial? retained = null;
        var trial = await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        var row = trial.Rows(false)[0]; var p = ValidationPermissionPlan.Probes(row, false)[0];
        using var tokens = new MemberPermissionTokens(trial.Issued.Actors[3].Credential);
        var barrier = beforeDispatch ? new ProjectTokenBarrier(tokens) : null;
        await using var client = new InfisicalClient(env.Origin, barrier ?? (IInfisicalTokenSource)tokens, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var target = new SecretReference(client.Authority, new InfisicalSecretAddress(trial.Issued.Id(row.Project), p.Environment, p.Path, p.Name));
        var receipt = new MutationReceipt(target); using var value = SecretMaterial.FromText(p.Value);
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
        using var loss = beforeDispatch ? null : new ProjectResponseBoundary(env.Origin, cancellation);
        bool cancelled = false;
        try
        {
            using (loss?.Enter())
            {
                Task? entered = barrier?.Entered;
                var write = client.CreateAsync(target, value, receipt, cancellation.Token).AsTask();
                if (entered is not null) { await entered.WaitAsync(deadline.Token); cancellation.Cancel(); barrier!.Release(); }
                try { await write; } catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !deadline.IsCancellationRequested) { cancelled = true; }
            }
            await Assert.That(cancelled && (beforeDispatch || loss!.Reached)).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(beforeDispatch ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
            if (!beforeDispatch)
            {
                var replay = await client.CreateAsync(target, value, receipt, deadline.Token);
                await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            }
        }
        finally { cancellation.Cancel(); barrier?.Release(); await retained!.DisposeAsync(); }
        var closed = provider.ClosedPacket!;
        await Assert.That(closed.Enforcement.Payload.Content.Decisions.Length).IsEqualTo(beforeDispatch ? 0 : 1);
        await Assert.That(closed.Backend.Payload.Content.Changes.Length).IsEqualTo(beforeDispatch ? 0 : 1);
        if (!beforeDispatch)
        {
            var commit = closed.Backend.Payload.Content.Changes.Single();
            await Assert.That(commit.After!.ValueHash).IsEqualTo(ValidationPermissionContract.Hash(p.Value));
            await Assert.That(commit.Before is null && commit.After.Version == 1 && commit.Commit.Length > 0).IsTrue();
        }
        await Assert.That(receipt.Evidence).IsEqualTo(beforeDispatch ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task CloseDrainsAdmittedDispatchEnforcementAndBackendBeforeDeletingOwnedState()
    {
        await using var provider = new InfisicalValidationPermissionFixture("delayed-dispatch");
        string operation = ValidationPermissionContract.Operations[0];
        using var env = provider.Environment(operation, ValidationPermissionAction.Read);
        var root = provider.Root(operation, ValidationPermissionAction.Read, "independent-effect");
        using var cap = SecretMaterial.FromText("validation-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        ValidationPermissionTrial? retained = null;
        var trial = await ValidationPermissionTrial.OpenAsync(provider.Source.CreateClient(), root, cap, t => retained = t, deadline.Token);
        await trial.BeginAsync(false, deadline.Token);
        var row = trial.Rows(false)[0]; var p = ValidationPermissionPlan.Probes(row, false)[0];
        using var tokens = new MemberPermissionTokens(trial.Issued.Actors[3].Credential);
        await using var client = new InfisicalClient(env.Origin, tokens, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        var target = new SecretReference(client.Authority, new InfisicalSecretAddress(trial.Issued.Id(row.Project), p.Environment, p.Path, p.Name));
        var receipt = new MutationReceipt(target); using var value = SecretMaterial.FromText(p.Value);
        Task entered = provider.PipelineEntered.Task, closing = provider.CloseEntered.Task;
        var write = client.CreateAsync(target, value, receipt, deadline.Token).AsTask();
        Task? cleanup = null;
        try
        {
            await entered.WaitAsync(deadline.Token);
            cleanup = retained!.DisposeAsync().AsTask();
            await closing.WaitAsync(deadline.Token);
            await Assert.That(cleanup.IsCompleted).IsFalse();
        }
        finally
        {
            provider.PipelineRelease.TrySetResult();
            var result = await write.WaitAsync(deadline.Token);
            await Assert.That(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied).IsTrue();
            await (cleanup ?? retained!.DisposeAsync().AsTask()).WaitAsync(deadline.Token);
        }
        await InfisicalValidationPermissionEffectTests.Clean(provider);
    }
    [Test]
    public async Task RepeatedKeyDoesNotEstablishIndependentJournals()
    {
        await using var provider = new InfisicalValidationPermissionFixture(); var pins = provider.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        await Rejected(() => { ValidationPermissionVerifier.Validate(provider.Profile with { Pins = pins }); return Task.CompletedTask; });
    }
    [Test]
    public async Task RoleConditionDelegationIsNotInventedForUnconditionalCrud()
    {
        bool rejected = false;
        try { _ = new ProjectRolePermission(ProjectRoleSubject.SecretValidationRules, ProjectRoleAction.Read, conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("no-access"))]); }
        catch (ArgumentException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
    internal static async Task Rejected(Func<Task> action)
    {
        bool rejected = false; try { await action(); } catch (NativeCaseFailureException) { rejected = true; }
        await Assert.That(rejected).IsTrue();
    }
}
