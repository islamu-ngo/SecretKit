using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalGatewayPatchEffectTests
{
    internal static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    private static readonly string[] Boundaries =
    ["selected-contract", "independent-effect", "denied-authority", "cancellation-boundary", "lost-response-no-replay"];
    public static IEnumerable<(string Variant, string Boundary)> Cases() =>
        InfisicalGovernanceFamilies.Bindings[GatewayPatchEffects.Operation].Variants
            .SelectMany(v => Boundaries.Select(b => (v, b)));

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task IndependentCalibrationUsesSdkStorageAuthenticationAndOriginalFences(string variant, string boundary)
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture();
        var result = await Calibrate(fixture, variant, boundary);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Source.Observations).IsEqualTo(variant == "response.auth.Identity" ? 1 : 2);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed && fixture.BorrowedPreserved).IsTrue();
        var fence = fixture.Source.Fences[^1];
        await Assert.That(fence.OriginalAttemptSettled && fence.ExcludesLateApplication &&
            fence.ValidationActionsTerminal && fence.NoReplay).IsTrue();
        await Assert.That(fence.MatchedRequests).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await Assert.That(fence.AuthenticationApplied).IsEqualTo(
            boundary is not ("denied-authority" or "cancellation-boundary") && !GatewayPatchEffects.RetainsAuthentication(variant));
        await Assert.That(fence.NameApplied).IsEqualTo(
            boundary is not ("denied-authority" or "cancellation-boundary") && GatewayPatchEffects.Renames(variant));
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalGatewayUpdateMustOpenIndependentSourceAndObserveEffect(string variant, string boundary)
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture();
        using var environment = fixture.Environment(variant);
        var definition = Definition(variant, boundary);
        var registry = new NativeCaseRegistry();
        InfisicalGovernanceFamilies.Register(registry, environment, [definition], new() { Gateway = fixture });
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];
        // Keep this positive assertion Red until the parent routes the original
        // member. Unavailable never counts as a passing persistence witness.
        await Assert.That(fixture.Source.Opens).IsEqualTo(1).Because("source-not-opened:" + result.ReasonCode);
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.Source.PrivateCopiesDestroyed && fixture.BorrowedPreserved).IsTrue();
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ignored-auth")]
    [Arguments("ignored-name")]
    [Arguments("retained-optionals")]
    [Arguments("wrong-runtime")]
    [Arguments("denied-accepted")]
    [Arguments("noncommitted")]
    [Arguments("replay")]
    [Arguments("late")]
    [Arguments("foreign-source")]
    [Arguments("borrowed-damage")]
    [Arguments("cleanup-pending")]
    [Arguments("lost-open")]
    public async Task CalibrationRejectsConcreteStorageRuntimeAndCleanupFaults(string fault)
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture(fault);
        var result = await Calibrate(fixture, "patch.persistence-unestablished", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "effect-mismatch" or "observer-unavailable" or "cleanup-incomplete").IsTrue();
        // Unqualified terminality is quarantined, not repaired by forced delete.
        await Assert.That(fixture.ResidualCount).IsEqualTo(fault is "late" or "replay" ? 1 : 0);
        if (fault is "late" or "replay") await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsEqualTo(fault is not ("late" or "replay"));
    }

    [Test]
    [Arguments("source-root")]
    [Arguments("arm-attempt")]
    [Arguments("fence-arm")]
    [Arguments("observation-binding")]
    [Arguments("cleanup-root")]
    public async Task DirectInjectedEvidenceIsValidatedByHost(string fault)
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture();
        var result = await Calibrate(fixture, "patch.persistence-unestablished", "independent-effect",
            new Tampered(fixture.Source.CreateObserver(), fault));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "observer-unavailable" or "cleanup-incomplete").IsTrue();
        await Assert.That(fixture.ResidualCount).IsEqualTo(fault == "fence-arm" ? 1 : 0);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
    }

    [Test]
    public async Task LostResponseSeparatelyFencesAuthenticationWithoutRename()
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture("auth-only");
        var result = await Calibrate(fixture, "patch.persistence-unestablished", "lost-response-no-replay");
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        var fence = fixture.Source.Fences[^1];
        await Assert.That(fence.Disposition).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(fence.AuthenticationApplied).IsTrue();
        await Assert.That(fence.NameApplied).IsFalse();
        await Assert.That(fence.MatchedRequests).IsEqualTo(1);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ChangedDestinationDropsReviewerOrRejectsForeignReviewer(bool foreignReviewer)
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture();
        var baseline = InfisicalGatewayPatchEffectFixture.Baseline("name.omitted");
        var selected = InfisicalGatewayPatchEffectFixture.Selected("name.omitted") with
        {
            KubernetesHost = "https://cluster-two.invalid",
            CaCertificate = "CA-two",
            TokenReviewerJwt = foreignReviewer ? "reviewer-one" : null
        };
        using var environment = fixture.Environment("name.omitted", baseline, selected);
        var root = Root("name.omitted");
        var observer = fixture.Source.CreateObserver();
        var buffers = new List<byte[]>();
        observer = fixture.Source.CreateObserver(size => { var buffer = new byte[size]; buffers.Add(buffer); return buffer; });
        GatewayPatchTrial? retained = null;
        string? id = null;
        try
        {
            var trial = await GatewayPatchTrial.OpenAsync(observer, root, baseline, selected, 15, value => retained = value, CancellationToken.None);
            using var original = baseline.Create();
            await trial.ArmAsync("Create", "seed", "selected-contract", null, CancellationToken.None);
            using var create = GatewayAdministrationOperations.Create(root.OrganizationId, new(root.OriginalName, original));
            var receipt = fixture.Client.CreateReceipt(create);
            trial.Dispatching();
            var created = await Execute(fixture.Client, environment, create, receipt);
            await Assert.That(created.IsSuccess).IsTrue();
            id = created.Value.Id;
            await trial.CompleteAsync(receipt.Evidence, CancellationToken.None);
            await trial.ObserveAsync(CancellationToken.None);
            using var changed = selected.Create();
            await trial.ArmAsync("Update", "name.omitted", "selected-contract", id, CancellationToken.None);
            using var patch = GatewayAdministrationOperations.Update(root.OrganizationId, id, new(authentication: changed));
            var patchReceipt = fixture.Client.CreateReceipt(patch);
            trial.Dispatching();
            var updated = await Execute(fixture.Client, environment, patch, patchReceipt);
            await Assert.That(updated.IsSuccess).IsEqualTo(!foreignReviewer);
            await Assert.That(patchReceipt.Evidence).IsEqualTo(foreignReviewer ? DispatchEvidence.Rejected : DispatchEvidence.Applied);
            await trial.CompleteAsync(patchReceipt.Evidence, CancellationToken.None);
            await trial.ObserveAsync(CancellationToken.None);
            var actual = fixture.Storage(id)!["authMethod"]!["config"]!.AsObject();
            await Assert.That(InfisicalGatewayPatchEffectFixture.Text(actual, "tokenReviewerJwt"))
                .IsEqualTo(foreignReviewer ? "reviewer-one" : null);
        }
        finally
        {
            await fixture.RemoveOwnedAsync(root.OrganizationId, root.OriginalName, environment.Tokens(NativeIdentityRole.Setup), CancellationToken.None);
            if (retained is not null) await retained.DisposeAsync();
        }
        await Assert.That(buffers.Count > 0 && buffers.All(b => b.All(value => value == 0))).IsTrue();
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
    }

    [Test]
    public async Task PrivateProfileEncodingRejectsInvalidSecondInputAndDisposedCopies()
    {
        var baseline = InfisicalGatewayPatchEffectFixture.Baseline("name.omitted");
        var selected = baseline with { KubernetesHost = "" };
        await Assert.That(() => new GatewayPatchPrivateProfiles(baseline, selected)).Throws<ArgumentException>();
        using var profiles = new GatewayPatchPrivateProfiles(baseline, baseline with { AllowedAudience = "" });
        profiles.Dispose();
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);
        await Assert.That(() => profiles.Write(writer)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task PrivateProfileEncodingErasesFirstBufferWhenSecondEncodingFails()
    {
        var baseline = InfisicalGatewayPatchEffectFixture.Baseline("name.omitted");
        byte[] first = [1, 2, 3, 4];
        int encodings = 0;
        await Assert.That(() => new GatewayPatchPrivateProfiles(baseline, baseline with { AllowedAudience = "" },
            _ => ++encodings == 1 ? first : throw new NativeCaseFailureException("observer-unavailable")))
            .Throws<NativeCaseFailureException>();
        await Assert.That(first.All(value => value == 0)).IsTrue();
    }

    [Test]
    public async Task IndependentSourceCanServeDistinctOriginalRootsWithoutBorrowingEarlierEvidence()
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture();
        var source = fixture.Source.CreateObserver();
        var first = await Calibrate(fixture, "Aws.allowedAccountIds.omitted", "independent-effect", source);
        var second = await Calibrate(fixture, "Kubernetes.tokenReviewerJwt.omitted", "independent-effect", source);
        await Assert.That(first.Passed && second.Passed).IsTrue().Because(first.ReasonCode + "/" + second.ReasonCode);
        await Assert.That(fixture.Source.Opens).IsEqualTo(2);
        await Assert.That(fixture.Source.Fences.Select(f => f.Arm.AttemptId).Distinct().Count()).IsEqualTo(4);
        await Assert.That(fixture.Source.Fences.Select(f => f.Arm.Binding.Attempt.RootNonce).Distinct().Count()).IsEqualTo(2);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task LostOpenRecoversTheSourceOwnedResponseOnlyIdentityBaseline()
    {
        await using var fixture = new InfisicalGatewayPatchEffectFixture("lost-open");
        var result = await Calibrate(fixture, "response.auth.Identity", "independent-effect");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
    }

    internal static NativeCaseDefinition Definition(string v, string b) => new(
        new("Infisical", GatewayPatchEffects.Operation, v, "local", b),
        InfisicalGovernanceFamilies.Bindings[GatewayPatchEffects.Operation].Member);
    private static GatewayPatchRootAttempt Root(string variant) => new(Guid.NewGuid().ToString("D"),
        GatewayPatchEffects.Operation + "/" + variant + "/selected-contract", "v0.166.3",
        "controlled-gateway", "controlled-fixture", Guid.NewGuid().ToString("D"),
        InfisicalGatewayPatchEffectFixture.Organization, "sk" + Guid.NewGuid().ToString("N"),
        "sk" + Guid.NewGuid().ToString("N"), GatewayPatchSource.ControlledFixture);
    private static async ValueTask<SecretOutcome<GatewaySummary>> Execute(ManagementClient client, NativeEnvironment env,
        ManagementRequest<GatewaySummary> request, ManagementReceipt receipt)
    {
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Administrative, request.Target.OrganizationId);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt);
    }
    private static async Task<NativeCaseResult> Calibrate(InfisicalGatewayPatchEffectFixture fixture,
        string variant, string boundary, IGatewayPatchObserver? source = null)
    {
        using var environment = fixture.Environment(variant);
        var d = Definition(variant, boundary);
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            var context = new ProjectFamilyContext(environment, "GatewayAdministration", d, probe);
            try { await GatewayPatchEffects.ExecuteAsync(context, fixture, source ?? fixture, token); }
            finally { await context.CleanupAsync(); }
        }));
        return (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None))[0];
    }
    private sealed class Tampered(IGatewayPatchObserver inner, string fault) : IGatewayPatchObserver
    {
        public async ValueTask<GatewayPatchBinding> OpenAsync(GatewayPatchRootAttempt root,
            GatewayPatchAuthenticationInput baseline, GatewayPatchAuthenticationInput selected, CancellationToken token)
        {
            var result = await inner.OpenAsync(root, baseline, selected, token);
            return fault == "source-root" ? result with { Attempt = root with { RootNonce = "foreign" } } : result;
        }
        public async ValueTask<GatewayPatchArm> ArmAsync(GatewayPatchBinding binding, string attempt, string operation,
            string variant, string boundary, string? id, CancellationToken token)
        {
            var result = await inner.ArmAsync(binding, attempt, operation, variant, boundary, id, token);
            return fault == "arm-attempt" ? result with { AttemptId = "foreign" } : result;
        }
        public async ValueTask<GatewayPatchFence> CompleteAsync(GatewayPatchArm arm, DispatchEvidence receipt, CancellationToken token)
        {
            var result = await inner.CompleteAsync(arm, receipt, token);
            return fault == "fence-arm" ? result with { Arm = arm with { AttemptId = "foreign" } } : result;
        }
        public async ValueTask<GatewayPatchObservation> ObserveAsync(GatewayPatchBinding binding, GatewayPatchFence fence,
            CancellationToken token)
        {
            var result = await inner.ObserveAsync(binding, fence, token);
            return fault == "observation-binding" ? result with { Binding = binding with { ClockEpoch = "foreign" } } : result;
        }
        public async ValueTask<GatewayPatchCleanup> CloseAsync(GatewayPatchRootAttempt root, CancellationToken token)
        {
            var result = await inner.CloseAsync(root, token);
            return fault == "cleanup-root" ? result with { Attempt = root with { RootNonce = "foreign" } } : result;
        }
    }
}
