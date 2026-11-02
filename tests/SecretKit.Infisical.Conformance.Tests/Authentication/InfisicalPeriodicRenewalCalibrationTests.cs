using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPeriodicRenewalCalibrationTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary, string Mode)> Cases() =>
        InfisicalPeriodicRenewalTests.OriginalCases().SelectMany(c =>
            new[] { "good", "same-credential" }.Select(mode => (c.Method, c.Variant, c.Boundary, mode)));

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IndependentQualifierDetectsForeignSameCredentialRequestAndLateIngress(bool afterFence)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture();
        var source = fixture.Source.Client();
        var input = fixture.Input();
        var row = InfisicalPeriodicRenewalTests.Row("RenewAsync", "lifetime.Finite", "independent-effect");
        var root = new PeriodicRenewalRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, row.Key.Operation, row.Key.Variant, row.Key.Case, "v0.166.3",
            input.Deployment, input.SourceIdentity, input.Epoch, input.Source, input.IdentityId,
            input.TokenRow, true, PeriodicRenewalBoundary.None);
        using var borrowed = SecretMaterial.FromText("runtime");
        using var capability = SecretMaterial.FromText(input.Capability);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var binding = await source.OpenAsync(root, borrowed, capability, deadline.Token);
            var arm = await source.ArmAsync(binding, deadline.Token);
            await using var original = Session();
            await Assert.That(await original.RenewAsync(deadline.Token)).IsEqualTo(SecretStatus.Success);
            await original.StopAsync();
            var receipt = new PeriodicRenewalReceipt(original.LastRenewal!.Evidence, SecretStatus.Success);
            if (afterFence) await source.SettleAsync(arm, receipt, deadline.Token);
            await using var foreign = Session();
            await Assert.That(await foreign.RenewAsync(deadline.Token)).IsEqualTo(SecretStatus.Denied);
            await foreign.StopAsync();
            if (!afterFence)
            {
                var settlement = await source.SettleAsync(arm, receipt, deadline.Token);
                await Assert.That(settlement.ForeignRequests).IsEqualTo(1);
            }
            await Assert.That(fixture.ForeignRequests).IsEqualTo(1);
            await Assert.That(fixture.Requests.Count).IsEqualTo(1);
            await Assert.That(fixture.Commits.Count).IsEqualTo(1);
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, deadline.Token);
            // A foreign attempt is not hidden by a complete/empty snapshot.
            await Assert.That(cleanup.ExcludesLateWork).IsFalse();
            await Assert.That(cleanup.OriginalTerminal && cleanup.OwnedCapturedResourcesAbsent &&
                cleanup.BorrowedIdentityAndGrants && cleanup.QualifiedLifetimePreserved).IsTrue();
        }

        InfisicalPeriodicTokenSession Session() => new(fixture.Origin, borrowed, fixture.SessionInput().Evidence,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(15), new() { AllowLoopbackDevelopmentHttp = true }, fixture.Clock);
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task ConcretePrivateClientCalibratesAgainstPublicSdkWithoutTrialOrEffects(
        string method, string variant, string boundary, string mode)
    {
        await using var fixture = new InfisicalPeriodicRenewalFixture(variant, mode);
        var row = InfisicalPeriodicRenewalTests.Row(method, variant, boundary);
        var input = fixture.Input(boundary == "denied-authority");
        var sessionInput = fixture.SessionInput();
        bool renew = method == "RenewAsync";
        bool recovery = variant is "lifetime.Unknown.recovery-required" or "session.recovery-required";
        bool expired = variant == "session.expired";
        bool dispatch = renew && !recovery && !expired;
        bool interrupted = dispatch && boundary is "cancellation-boundary" or "lost-response-no-replay";
        var source = fixture.Source.Client();
        var root = new PeriodicRenewalRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, row.Key.Operation, variant, boundary, "v0.166.3", input.Deployment,
            input.SourceIdentity, input.Epoch, input.Source, input.IdentityId, input.TokenRow, dispatch,
            !interrupted ? PeriodicRenewalBoundary.None : boundary == "cancellation-boundary" ?
                PeriodicRenewalBoundary.RequestCaptured : PeriodicRenewalBoundary.ResponseWithheld);
        using var borrowed = SecretMaterial.FromText(boundary == "denied-authority" ? "denied" : "runtime");
        using var capability = SecretMaterial.FromText(input.Capability);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        PeriodicRenewalCleanup? cleanup = null;
        // Root and cleanup owner precede Open, without using the production trial.
        try
        {
            var binding = await source.OpenAsync(root, borrowed, capability, deadline.Token);
            await Assert.That(binding.Lifetime).IsEqualTo(fixture.Baseline);
            await Assert.That(binding.ExactCredentialRowJoin && binding.IndependentJournal).IsTrue();
            await using var session = new InfisicalPeriodicTokenSession(fixture.Origin,
                sessionInput.TokenLost ? null : borrowed, sessionInput.Evidence, TimeSpan.FromSeconds(10),
                TimeSpan.FromSeconds(15), new() { AllowLoopbackDevelopmentHttp = true }, fixture.Clock);
            if (expired)
            {
                var expiry = await source.ExpireAsync(binding, deadline.Token);
                await Assert.That(expiry.NaturalExpiry && expiry.InjectedClock).IsTrue();
                await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.Expired);
            }
            var arm = await source.ArmAsync(binding, deadline.Token);
            InfisicalAccessToken? actual = null;
            SecretStatus status = SecretStatus.Unknown;
            try
            {
                if (interrupted)
                {
                    Task<PeriodicRenewalArrival> arrival = source.AwaitBoundaryAsync(arm, deadline.Token).AsTask();
                    using var waiter = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
                    Task<SecretStatus> execution = session.RenewAsync(waiter.Token).AsTask();
                    var signal = await arrival;
                    await Assert.That(signal.RequestId).IsEqualTo(fixture.Requests.Single().RequestId);
                    await Assert.That(signal.CredentialHandle).IsEqualTo(binding.CredentialHandle);
                    waiter.Cancel();
                    await session.StopAsync();
                    try { status = await execution; }
                    catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { }
                }
                else if (renew)
                {
                    status = await session.RenewAsync(deadline.Token);
                    if (status == SecretStatus.Success) actual = (await session.GetTokenAsync(deadline.Token)).Value;
                }
                else if (boundary == "cancellation-boundary")
                {
                    using var cancelled = new CancellationTokenSource();
                    cancelled.Cancel();
                    bool observed = false;
                    try { actual = (await session.GetTokenAsync(cancelled.Token)).Value; }
                    catch (OperationCanceledException) { observed = true; }
                    await Assert.That(observed).IsTrue();
                }
                else
                {
                    var result = await session.GetTokenAsync(deadline.Token);
                    status = result.Status;
                    if (result.IsSuccess) actual = result.Value;
                }
                await session.StopAsync();
                var original = session.LastRenewal;
                var receipt = new PeriodicRenewalReceipt(original?.Evidence, status);
                var settled = await source.SettleAsync(arm, receipt, deadline.Token);
                bool committed = dispatch && boundary is not ("denied-authority" or "cancellation-boundary");
                await Assert.That(fixture.Requests.Count).IsEqualTo(dispatch ? 1 : 0);
                await Assert.That(fixture.Commits.Count).IsEqualTo(committed ? 1 : 0);
                await Assert.That(settled.OriginalRequests).IsEqualTo(fixture.Requests.Count);
                await Assert.That(settled.OriginalCommits).IsEqualTo(fixture.Commits.Count);
                await Assert.That(settled.Outcome).IsEqualTo(committed ?
                    PeriodicRenewalOutcome.Applied : PeriodicRenewalOutcome.NonApplied);
                await Assert.That(settled.OriginalTerminal && settled.ExcludesLateWork &&
                    settled.CompleteInventory && settled.NoReplay && settled.ForeignRequests == 0).IsTrue();
                await Assert.That(settled.Stamp.Root).IsEqualTo(root);
                if (dispatch)
                {
                    var request = fixture.Requests.Single();
                    await Assert.That(request.Window == arm.Window && request.Nonce == root.Nonce &&
                        request.Row == input.TokenRow && request.Identity == input.IdentityId &&
                        request.CredentialHandle == binding.CredentialHandle).IsTrue();
                    await Assert.That(fixture.Terminals.Single()).IsEqualTo(request.RequestId);
                }
                else await Assert.That(original).IsNull();
                if (committed)
                {
                    var commit = fixture.Commits.Single();
                    await Assert.That(commit.After > commit.Before).IsTrue();
                    await Assert.That(settled.CapturedLifetime!.ExpiresAt).IsEqualTo(commit.After);
                    await Assert.That(settled.CapturedTokenRow).IsEqualTo(commit.CapturedRow);
                    await Assert.That(fixture.CapturedResources).IsEqualTo(mode == "same-credential" ? 0 : 1);
                }
                if (actual is not null)
                {
                    var delivery = await source.InspectDeliveryAsync(arm, actual.Material, deadline.Token);
                    await Assert.That(delivery.ExactSuppliedCredential).IsTrue();
                    await Assert.That(delivery.TokenRow).IsEqualTo(committed && mode != "same-credential" ?
                        "replacement-row" : input.TokenRow);
                    await Assert.That(actual.ExpiresAt).IsEqualTo(delivery.Lifetime.ExpiresAt);
                    using var wrong = SecretMaterial.FromText("wrong-independent");
                    await Assert.That(await Read(actual.Material, "allowed")).IsEqualTo(
                        boundary == "denied-authority" ? SecretStatus.Denied : SecretStatus.Success);
                    await Assert.That(await Read(wrong, "allowed")).IsEqualTo(SecretStatus.Denied);
                    await Assert.That(await Read(actual.Material, "forbidden")).IsEqualTo(SecretStatus.Denied);
                    await Assert.That(await Read(actual.Material, "allowed")).IsEqualTo(
                        boundary == "denied-authority" ? SecretStatus.Denied : SecretStatus.Success);
                    using var denied = SecretMaterial.FromText("denied");
                    using var observer = SecretMaterial.FromText("observer");
                    await Assert.That(await Read(denied, "allowed")).IsEqualTo(SecretStatus.Denied);
                    await Assert.That(await Read(observer, "allowed")).IsEqualTo(SecretStatus.Success);
                }
                else await Assert.That(fixture.Source.Deliveries).IsEqualTo(0);
                cleanup = await source.CloseAsync(root, deadline.Token);
                await Assert.That(ReferenceEquals(original, session.LastRenewal) &&
                    receipt.Evidence == session.LastRenewal?.Evidence).IsTrue();
            }
            finally { actual?.Dispose(); }
        }
        finally
        {
            cleanup ??= await source.CloseAsync(root, CancellationToken.None);
        }
        await Assert.That(cleanup.OriginalTerminal && cleanup.ExcludesLateWork &&
            cleanup.BorrowedIdentityAndGrants && cleanup.QualifiedLifetimePreserved &&
            cleanup.OwnedCapturedResourcesAbsent && cleanup.PrivateCopiesDestroyed).IsTrue();
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.CapturedResources + fixture.Source.Registrations + fixture.PendingWork).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();

        async Task<SecretStatus> Read(SecretMaterial material, string key)
        {
            // Fresh public consumer, independent of the effect implementation.
            using var tokens = new CalibrationTokens(material);
            await using var client = new InfisicalClient(fixture.Origin, tokens,
                new() { AllowLoopbackDevelopmentHttp = true });
            var result = await client.ReadAsync(new(client.Authority,
                new InfisicalSecretAddress("project", "env", "/borrowed", key)), deadline.Token);
            if (result.IsSuccess)
            {
                using var value = result.Value;
                await Assert.That(value.Material.Reveal()).IsEqualTo("canary-value");
            }
            return result.Status;
        }
    }

    private sealed class CalibrationTokens(SecretMaterial material) : IInfisicalTokenSource, IDisposable
    {
        private readonly SecretMaterial copy = material.Copy();
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(copy.Copy())));
        }
        public void Dispose() => copy.Dispose();
    }
}
