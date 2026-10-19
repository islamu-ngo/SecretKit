using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationMutationTests
{
    public static IEnumerable<(string Method, string Variant, string Boundary)> OriginalCases() =>
        InfisicalLifecycleFamilies.Catalog.Where(a => a.Operation is RotationMutationEffects.Prefix + "RotateSecretsAsync" or
            RotationMutationEffects.Prefix + "SetAutomaticRotationAsync")
            .SelectMany(a => a.Variants.SelectMany(v => a.Cases.Select(c =>
                (a.Operation[RotationMutationEffects.Prefix.Length..], v, c))));

    public static IEnumerable<(InfisicalRotationProfile Profile, string Method, bool Enabled)> SourceCases() =>
        Enum.GetValues<InfisicalRotationProfile>().SelectMany(p => new[]
        {
            (p, "RotateSecretsAsync", false), (p, "SetAutomaticRotationAsync", true), (p, "SetAutomaticRotationAsync", false)
        });

    internal static InfisicalRotationProfile Profile(string variant) => variant.StartsWith("profile.", StringComparison.Ordinal) ?
        Enum.Parse<InfisicalRotationProfile>(variant[8..]) : InfisicalRotationProfile.PostgresCredentials;

    internal static NativeCaseDefinition Row(string method, string variant, string boundary)
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a => a.Operation == RotationMutationEffects.Prefix + method);
        return new(new("Infisical", admission.Operation, variant, "controlled-mutation", boundary), admission.Member);
    }

    internal static NativeEnvironment Environment(NativeCaseDefinition row, RotationMutationInput input)
    {
        var m = input.Material;
        var legacy = new InfisicalRotationClientEffects.RotationInput(
            new(m.ProjectId, "project", m.Environment, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "/borrowed"),
            "organization", m.Profile, "dddddddd-dddd-dddd-dddd-dddddddddddd",
            new(m.Profile, "backend.invalid", 5432, "database", "account"), "account-a", "account-b",
            null, 1, input.Enabled, m.MaximumItems, m.AllowedActions, m.DeniedActions);
        var node = JsonSerializer.SerializeToNode(legacy, InfisicalRotationMutationFixture.Json)!.AsObject();
        node[RotationMutationEffects.Selection] = JsonSerializer.SerializeToNode(input, InfisicalRotationMutationFixture.Json);
        var families = new JsonObject
        {
            [InfisicalRotationClientEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    [row.Key.Scope] = new JsonObject
                    {
                        [row.Key.Operation] = new JsonObject
                        { [row.Key.Variant] = new JsonObject { [row.Key.Case] = node } }
                    }
                }
            }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = "https://mutation.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, InfisicalRotationMutationFixture.Json));
    }

    internal static async Task<NativeCaseResult> Run(InfisicalRotationMutationFixture fixture,
        NativeCaseDefinition row, RotationMutationInput? input = null, IInfisicalRotationMutationSource? source = null)
    {
        using var environment = Environment(row, input ?? fixture.Input());
        var registry = new NativeCaseRegistry();
        RotationMutationEffects.Register(registry, environment, [row], source ?? fixture.Source.Client(),
            fixture.Transport, role => fixture.Consumer(environment, role));
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
    }

    [Test]
    public async Task OriginalMutationDenominatorsAndPinnedProfilesStayWhole()
    {
        await Assert.That(OriginalCases().Count()).IsEqualTo(340);
        await Assert.That(OriginalCases().Count(c => c.Method == "RotateSecretsAsync")).IsEqualTo(165);
        await Assert.That(OriginalCases().Count(c => c.Method == "SetAutomaticRotationAsync")).IsEqualTo(175);
        await Assert.That(Enum.GetValues<InfisicalRotationProfile>().Count(p => RotationMaterialProfile.For(p).Pinned)).IsEqualTo(30);
    }

    [Test]
    [MethodDataSource(nameof(SourceCases))]
    public async Task ConcreteSourceCalibratesWithPublicSdkWithoutHostTrialOrEffectHandler(
        InfisicalRotationProfile profile, string method, bool enabled)
    {
        await using var fixture = new InfisicalRotationMutationFixture(profile);
        var input = fixture.Input(enabled);
        var row = Row(method, "profile." + profile, "independent-effect");
        using var environment = Environment(row, input);
        var m = input.Material;
        var action = method == "RotateSecretsAsync" ? InfisicalRotationAction.RotateSecrets :
            enabled ? InfisicalRotationAction.EnableAutomaticRotation : InfisicalRotationAction.DisableAutomaticRotation;
        var root = new RotationMutationRoot(new(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, "v0.166.3", m.DeploymentId, m.SourceIdentity, m.ClockEpoch, m.Source,
            m.ProjectId, m.Environment, m.Folder, m.RotationId, m.Profile, m.Kind, m.Generation),
            Guid.NewGuid().ToString("N"), action, InfisicalRotationPrecondition.None);
        var source = fixture.Source.Client();
        using var baseline = new RotationMaterialPacket(profile, m.Kind, m.Generation, m.Fields);
        using var capability = SecretMaterial.FromText(m.SetupCapability);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        // The local root and cleanup owner precede Open.
        try
        {
            var binding = await source.OpenAsync(root, baseline, capability, deadline.Token);
            await Assert.That(binding.OwnedSetup && binding.SetupSettled && binding.ExactMaterialKnown &&
                binding.IndependentJournals && binding.CompleteBackendInventory).IsTrue();
            var arm = await source.ArmAsync(binding, deadline.Token);
            using var http = new HttpClient(fixture.Transport, disposeHandler: false);
            var authority = new SecretAuthority();
            var client = new InfisicalRotationClient(environment.Origin, http, authority,
                new(authority, environment.Tokens(NativeIdentityRole.Runtime), m.ProjectId));
            var target = new SecretReference(authority, new InfisicalRotationAddress(m.ProjectId,
                m.Environment, m.Folder, profile, m.RotationId));
            var receipt = new InfisicalRotationReceipt(target, action);
            var result = method == "RotateSecretsAsync" ?
                await client.RotateSecretsAsync(target, receipt, cancellationToken: deadline.Token) :
                await client.SetAutomaticRotationAsync(target, enabled, receipt, cancellationToken: deadline.Token);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            var original = RotationMutationReceipt.Capture(root, receipt, result.Status);
            var settlement = await source.SettleAsync(arm, original, deadline.Token);
            await Assert.That(settlement.Stamp.Root == root && settlement.Arm.Stamp.Root == root && settlement.Receipt == original &&
                settlement.OriginalTerminal && settlement.ExcludesLateWork && settlement.CompleteDeliveryInventory).IsTrue();
            await Assert.That(settlement.OriginalRequests).IsEqualTo(1);
            await Assert.That(settlement.OriginalCommits).IsEqualTo(1);
            await Assert.That(fixture.RequestJournal.Count).IsEqualTo(1);
            bool changed = method == "RotateSecretsAsync" || enabled;
            await Assert.That(fixture.BackendJournal.Count).IsEqualTo(changed ? 1 : 0);
            await Assert.That(fixture.MappingJournal.Count).IsEqualTo(changed ? 2 : 1);
            await Assert.That(settlement.Generation).IsEqualTo(changed ? 8 : 7);
            if (method == "SetAutomaticRotationAsync")
            {
                await Assert.That(fixture.ConfigurationJournal.Single().Enabled).IsEqualTo(enabled);
                await Assert.That(fixture.SchedulerJournal.Count).IsEqualTo(1);
                await Assert.That(settlement.InjectedClock && settlement.QualifiedOpportunity &&
                    settlement.QueueTerminalBeforeOpportunity).IsTrue();
                await Assert.That(fixture.SchedulerJournal.Single().After != fixture.SchedulerJournal.Single().Before)
                    .IsEqualTo(enabled);
            }
            if (changed)
            {
                await Assert.That(settlement.PreviousActiveAccepted).IsEqualTo(fixture.NativeOverlap);
                await Assert.That(settlement.OverwrittenRetired && settlement.IdentityRetirementQualified).IsTrue();
            }
            var finalInput = m with { Generation = settlement.Generation, Fields = settlement.Fields };
            await using var consumer = fixture.Consumer(environment, NativeIdentityRole.Runtime);
            using var actual = await RotationMaterialPacket.ReadAsync(consumer, finalInput, false, deadline.Token);
            using var wrong = actual.Wrong();
            var auth = await source.AuthenticateAsync(arm, actual, wrong, deadline.Token);
            await Assert.That(auth.ExactSuppliedMaterial && auth.CoherentGeneration && auth.FreshSessions &&
                auth.IndependentBackend).IsTrue();
            await Assert.That(auth.Valid).IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(auth.Wrong).IsEqualTo(BackendAuthentication.Rejected);
            await Assert.That(auth.Recheck).IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(auth.AllowedActions.SequenceEqual(m.AllowedActions) &&
                auth.DeniedActions.SequenceEqual(m.DeniedActions)).IsTrue();
            await Assert.That(RotationMutationReceipt.Capture(root, receipt, result.Status)).IsEqualTo(original);
            var replay = method == "RotateSecretsAsync" ?
                await client.RotateSecretsAsync(target, receipt, cancellationToken: deadline.Token) :
                await client.SetAutomaticRotationAsync(target, enabled, receipt, cancellationToken: deadline.Token);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(fixture.RequestJournal.Count).IsEqualTo(1);
            await Assert.That(RotationMutationReceipt.Capture(root, receipt, result.Status)).IsEqualTo(original);
        }
        finally
        {
            var cleanup = await source.CloseAsync(root, deadline.Token);
            await Assert.That(cleanup.Root == root && cleanup.OriginalTerminal && cleanup.ExcludesLateWork &&
                cleanup.CompleteInventory && cleanup.CapturedSetsRetired && cleanup.OwnedIdentitiesAbsent &&
                cleanup.OwnedResourcesAbsent && cleanup.NativeSetupAbsent && cleanup.MappedSecretsAbsent &&
                cleanup.BorrowedPreserved && cleanup.PrivateDestroyed).IsTrue();
        }
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(OriginalCases))]
    public async Task IndependentEffectCalibrationCoversEveryOriginalMutationRow(string method, string variant, string boundary)
    {
        await using var fixture = new InfisicalRotationMutationFixture(Profile(variant));
        var result = await Run(fixture, Row(method, variant, boundary));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        bool precondition = RotationMutationEffects.Precondition(variant) != InfisicalRotationPrecondition.None;
        await Assert.That(fixture.RequestJournal.Count).IsEqualTo(precondition ? 0 : 1);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Arms).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Source.OriginalRoot == fixture.Source.ClosedRoot).IsTrue();
        await Assert.That(fixture.ReadJournal.Count).IsEqualTo(fixture.NativeFields.Length * 2);
        await Assert.That(fixture.AuthenticationJournal.Select(a => a.Accepted).ToArray())
            .IsEquivalentTo(new[] { true, false, true, true, false });
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.BorrowedPreserved && fixture.PrivateDestroyed).IsTrue();
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("RotateSecretsAsync", "no-backend-change", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "unrelated-event", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "retained-overwritten", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "wrong-material", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "mixed-generation", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "wrong-accepted", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "valid-outage", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "overbroad-grants", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "denied-material-accepted", "effect-mismatch")]
    [Arguments("RotateSecretsAsync", "echo-source", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "replay", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "late-work", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "pending-delivery", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "pending-work", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "incomplete-inventory", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "borrowed-damage", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "incomplete-cleanup", "cleanup-incomplete")]
    [Arguments("RotateSecretsAsync", "lost-open", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "lost-arm", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "lost-settle", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "lost-authenticate", "observer-unavailable")]
    [Arguments("RotateSecretsAsync", "lost-close", "cleanup-incomplete")]
    [Arguments("SetAutomaticRotationAsync", "ignored-setting", "effect-mismatch")]
    [Arguments("SetAutomaticRotationAsync", "partial-setting", "effect-mismatch")]
    [Arguments("SetAutomaticRotationAsync", "no-backend-change", "effect-mismatch")]
    [Arguments("SetAutomaticRotationAsync", "no-opportunity", "effect-mismatch")]
    [Arguments("SetAutomaticRotationAsync", "native-clock", "effect-mismatch")]
    public async Task IndependentJournalsRejectConcreteFaults(string method, string mode, string code)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.PostgresCredentials, mode);
        var result = await Run(fixture, Row(method, method == "RotateSecretsAsync" ?
            "precondition.None" : "enabled.true", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(code);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Source.OriginalRoot == fixture.Source.ClosedRoot).IsTrue();
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
        if (mode != "incomplete-cleanup") await Assert.That(fixture.Residual).IsEqualTo(0);
        else await Assert.That(fixture.Residual).IsGreaterThan(0);
    }

    [Test]
    [Arguments("unknown-nonapplied", 0)]
    [Arguments("unknown-partial", 2)]
    [Arguments("deferred-original", 1)]
    public async Task UnknownReceiptRemainsUnknownAcrossOriginalTerminalOutcomes(string mode, int outcome)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.CloudflareApiToken, mode);
        var result = await Run(fixture, Row("RotateSecretsAsync", "precondition.None", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var settlement = fixture.Source.Settlement!;
        await Assert.That(settlement.Outcome).IsEqualTo((RotationMutationOutcome)outcome);
        await Assert.That(settlement.Receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(settlement.Receipt.Effect).IsEqualTo(InfisicalRotationEffect.Unknown);
        await Assert.That(settlement.OriginalRequests).IsEqualTo(1);
        await Assert.That(settlement.OriginalTerminal && settlement.ExcludesLateWork).IsTrue();
        await Assert.That(fixture.RequestJournal.Count).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    public async Task DisabledSettingDoesNotDrainPreviouslyQueuedWork()
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.RedisCredentials, "queued-after-disable");
        var result = await Run(fixture, Row("SetAutomaticRotationAsync", "enabled.false", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var settlement = fixture.Source.Settlement!;
        await Assert.That(settlement.Enabled).IsFalse();
        await Assert.That(settlement.QueuedBackendDeliveries).IsEqualTo(1);
        await Assert.That(settlement.OriginalBackendDeliveries).IsEqualTo(0);
        await Assert.That(settlement.Generation).IsEqualTo(8);
        await Assert.That(settlement.OpportunityBaselineGeneration).IsEqualTo(8);
        await Assert.That(fixture.SchedulerJournal.Single().Before).IsEqualTo(fixture.SchedulerJournal.Single().After);
        await Assert.That(settlement.QueueTerminalBeforeOpportunity && settlement.QualifiedOpportunity).IsTrue();
    }

    [Test]
    [Arguments("ignored-setting")]
    [Arguments("partial-setting")]
    [Arguments("no-opportunity")]
    public async Task DisabledSettingAloneCannotQualifyScheduledAbsence(string mode)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.Auth0ClientSecret, mode);
        var result = await Run(fixture, Row("SetAutomaticRotationAsync", "enabled.false", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    public async Task PartialOriginalDeliveryCannotCreditAnUnrelatedAttempt()
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.AwsIamUserSecret, "unknown-partial");
        fixture.Source.Change = (route, node) => { if (route == "settle") node["eventAttemptId"] = "unrelated-attempt"; };
        var result = await Run(fixture, Row("RotateSecretsAsync", "precondition.None", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(fixture.RequestJournal.Count).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [Arguments("originalRequests", 0, "observer-unavailable")]
    [Arguments("originalCommits", 0, "effect-mismatch")]
    [Arguments("emptyPartial", 0, "effect-mismatch")]
    public async Task UnknownCannotConcealContradictoryOriginalCounts(string fault, int value, string code)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.DatabricksServicePrincipalSecret);
        fixture.Source.Change = (route, node) =>
        {
            if (route != "settle") return;
            if (fault == "emptyPartial")
            {
                node["outcome"] = (int)RotationMutationOutcome.Partial;
                node["originalCommits"] = 0;
                node["originalBackendDeliveries"] = 0;
            }
            else node[fault] = value;
        };
        var result = await Run(fixture, Row("RotateSecretsAsync", "precondition.None", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(code);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    public async Task UnknownNonAppliedOriginalSeparatelyAccountsForPreexistingQueuedChange()
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.RedisCredentials, "unknown-nonapplied-queued");
        var result = await Run(fixture, Row("SetAutomaticRotationAsync", "enabled.false", "lost-response-no-replay"));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var settlement = fixture.Source.Settlement!;
        await Assert.That(settlement.Outcome).IsEqualTo(RotationMutationOutcome.NonApplied);
        await Assert.That(settlement.OriginalCommits).IsEqualTo(0);
        await Assert.That(settlement.OriginalBackendDeliveries).IsEqualTo(0);
        await Assert.That(settlement.QueuedBackendDeliveries).IsEqualTo(1);
        await Assert.That(settlement.Enabled).IsTrue();
        await Assert.That(settlement.Generation).IsEqualTo(8);
        await Assert.That(fixture.SchedulerJournal.Count).IsEqualTo(0);
        await Assert.That(settlement.Receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    public async Task CompleteGcpKeyCannotSilentlyChangeTheSelectedTargetEmail()
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.GcpServiceAccountKey, "changed-target");
        var result = await Run(fixture, Row("RotateSecretsAsync", "profile.GcpServiceAccountKey", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(fixture.NativeFields).IsEquivalentTo(new[] { "serviceAccountKey" });
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [Arguments("observed")]
    [Arguments("lost")]
    [Arguments("canceled")]
    public async Task ExactCallerHeldReceiptCannotRedispatchAfterItsOriginalBoundary(string boundary)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.OpenaiServiceAccount, "deferred-original");
        var input = fixture.Input();
        var m = input.Material;
        var row = Row("RotateSecretsAsync", "precondition.None", "independent-effect");
        using var environment = Environment(row, input);
        var root = new RotationMutationRoot(new(Guid.NewGuid().ToString("D"), Guid.NewGuid().ToString("N"),
            row.Key.Identity, "v0.166.3", m.DeploymentId, m.SourceIdentity, m.ClockEpoch, m.Source,
            m.ProjectId, m.Environment, m.Folder, m.RotationId, m.Profile, m.Kind, m.Generation),
            Guid.NewGuid().ToString("N"), InfisicalRotationAction.RotateSecrets, InfisicalRotationPrecondition.None);
        var source = fixture.Source.Client();
        using var packet = new RotationMaterialPacket(m.Profile, m.Kind, m.Generation, m.Fields);
        using var capability = SecretMaterial.FromText(m.SetupCapability);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            var binding = await source.OpenAsync(root, packet, capability, deadline.Token);
            var arm = await source.ArmAsync(binding, deadline.Token);
            using var transport = new RotationMutationEffects.BoundaryTransport(boundary == "canceled", boundary == "lost", fixture.Transport);
            using var http = new HttpClient(transport);
            var authority = new SecretAuthority();
            var client = new InfisicalRotationClient(environment.Origin, http, authority,
                new(authority, environment.Tokens(NativeIdentityRole.Runtime), m.ProjectId));
            var target = new SecretReference(authority, new InfisicalRotationAddress(m.ProjectId, m.Environment, m.Folder, m.Profile, m.RotationId));
            var receipt = new InfisicalRotationReceipt(target, root.Action);
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token);
            Task? cancel = boundary == "canceled" ? transport.Reached.Task.ContinueWith(_ => cancellation.Cancel(),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
            SecretStatus status = SecretStatus.Unknown;
            try { status = (await client.RotateSecretsAsync(target, receipt, cancellationToken: cancellation.Token)).Status; }
            catch (OperationCanceledException) when (boundary == "canceled" && transport.Reached.Task.IsCompletedSuccessfully) { }
            if (cancel is not null) await cancel.WaitAsync(deadline.Token);
            var original = RotationMutationReceipt.Capture(root, receipt, status);
            var settlement = await source.SettleAsync(arm, original, deadline.Token);
            await Assert.That(settlement.Outcome).IsEqualTo(RotationMutationOutcome.Applied);
            await Assert.That(settlement.OriginalBackendDeliveries).IsEqualTo(1);
            await Assert.That(receipt.Dispatch).IsEqualTo(boundary == "observed" ?
                InfisicalRotationDispatch.ResponseObserved : InfisicalRotationDispatch.ResponseUnknown);
            var replay = await client.RotateSecretsAsync(target, receipt, cancellationToken: deadline.Token);
            await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(fixture.RequestJournal.Count).IsEqualTo(1);
            await Assert.That(RotationMutationReceipt.Capture(root, receipt, status)).IsEqualTo(original);
            await source.CloseAsync(root, deadline.Token);
            await Assert.That(RotationMutationReceipt.Capture(root, receipt, status)).IsEqualTo(original);
        }
        finally
        {
            if (fixture.Source.Closes == 0) await source.CloseAsync(root, deadline.Token);
        }
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("lost-response-no-replay")]
    [Arguments("cancellation-boundary")]
    public async Task DeferredOriginalBackendWorkSettlesWithoutRedispatch(string boundary)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.GcpServiceAccountKey, "deferred-original");
        var result = await Run(fixture, Row("RotateSecretsAsync", "profile.GcpServiceAccountKey", boundary));
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(fixture.Source.Settlement!.OriginalRequests).IsEqualTo(1);
        await Assert.That(fixture.Source.Settlement.OriginalBackendDeliveries).IsEqualTo(1);
        await Assert.That(fixture.Source.Settlement.PendingDeliveries).IsEqualTo(0);
        await Assert.That(fixture.BackendJournal.Single().Attempt).IsEqualTo(fixture.Source.OriginalRoot!.AttemptId);
        await Assert.That(fixture.TerminalJournal.Single()).IsEqualTo(fixture.Source.OriginalRoot.AttemptId);
    }

    [Test]
    [Arguments("open", "root")]
    [Arguments("arm", "nonce")]
    [Arguments("settle", "source")]
    [Arguments("settle", "epoch")]
    [Arguments("settle", "version")]
    [Arguments("settle", "kind")]
    [Arguments("settle", "identity")]
    [Arguments("settle", "attempt")]
    [Arguments("authenticate", "sequence")]
    [Arguments("authenticate", "event")]
    public async Task HostRejectsStaleOrCrossAttemptEvidence(string stage, string fault)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.LdapPassword);
        fixture.Source.Change = (route, node) =>
        {
            if (route != stage) return;
            var stamp = node["stamp"]!.AsObject();
            var root = stamp["root"]!.AsObject();
            var material = root["material"]!.AsObject();
            switch (fault)
            {
                case "root": material["id"] = "unrelated-root"; break;
                case "nonce": material["nonce"] = "unrelated-nonce"; break;
                case "source": material["sourceIdentity"] = "wrong-source"; break;
                case "epoch": material["clockEpoch"] = "stale-epoch"; break;
                case "version": material["providerVersion"] = "wrong-version"; break;
                case "kind": material["kind"] = (int)RotationMaterialKind.Token; break;
                case "identity": material["caseIdentity"] = "unrelated-case"; break;
                case "attempt": root["attemptId"] = "unrelated-attempt"; break;
                case "sequence": stamp["sequence"] = 0; break;
                case "event": stamp["eventId"] = "mutation-event-1"; break;
            }
        };
        var result = await Run(fixture, Row("RotateSecretsAsync", "profile.LdapPassword", "independent-effect"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.Source.Closes).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsEqualTo(0);
    }

    [Test]
    [Arguments("open", "ownedSetup")]
    [Arguments("open", "independentJournals")]
    [Arguments("arm", "captureArmed")]
    [Arguments("settle", "originalTerminal")]
    [Arguments("settle", "completeDeliveryInventory")]
    [Arguments("settle", "excludesLateWork")]
    [Arguments("settle", "configurationMatchesOutcome")]
    [Arguments("settle", "completeCredentialHistory")]
    [Arguments("authenticate", "coherentGeneration")]
    [Arguments("close", "capturedSetsRetired")]
    [Arguments("close", "completeInventory")]
    public async Task RequiredEvidenceCannotBeOmittedFromConcreteChannel(string stage, string field)
    {
        await using var fixture = new InfisicalRotationMutationFixture(InfisicalRotationProfile.SnowflakeUserKeyPair);
        fixture.Source.Change = (route, node) => { if (route == stage) node.Remove(field); };
        var result = await Run(fixture, Row("RotateSecretsAsync", "precondition.None", "selected-contract"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(stage == "close" ? "cleanup-incomplete" : "observer-unavailable");
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Source.Buffers.All(b => b.All(v => v == 0))).IsTrue();
    }
}
