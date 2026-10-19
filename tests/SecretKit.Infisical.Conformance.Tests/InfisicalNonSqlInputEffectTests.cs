using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalNonSqlInputEffectTests
{
    internal static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly string[] Methods =
    [
        "CreateDefinitionAsync", "UpdateDefinitionAsync", "UpdateDefinitionPolicyAsync",
        "InspectDefinitionAsync", "ListDefinitionsAsync", "DeleteDefinitionAsync"
    ];
    private static readonly InfisicalDynamicProvider[] Providers = Enum.GetValues<InfisicalDynamicProvider>()
        .Where(p => p != InfisicalDynamicProvider.SqlDatabase).ToArray();
    private static readonly string[] TailscaleAlternatives =
    [
        "Tailscale.auth_keys.oauth", "Tailscale.federated_keys.api_key", "Tailscale.federated_keys.oauth",
        "Tailscale.oauth_keys.api_key", "Tailscale.oauth_keys.oauth"
    ];

    public static IEnumerable<(InfisicalDynamicProvider Provider, string Method, string Variant,
        string Boundary, string? Alternative)> ProtectedCases()
    {
        foreach (string method in Methods)
        {
            var admission = Admission(method);
            foreach (string variant in admission.Variants)
                foreach (var selection in Selections(variant))
                    foreach (string boundary in admission.Cases)
                        yield return (selection.Provider, method, variant, boundary, selection.Alternative);
        }
    }

    private static IEnumerable<(InfisicalDynamicProvider Provider, string? Alternative)> Selections(string variant)
    {
        if (variant.StartsWith("profile.", StringComparison.Ordinal))
        {
            if (Enum.TryParse<InfisicalDynamicProvider>(variant[8..], out var provider) &&
                provider != InfisicalDynamicProvider.SqlDatabase) yield return (provider, null);
            yield break;
        }
        if (InfisicalDynamicAlternativeProfileInputs.TryProvider(variant, out var alternate))
        { yield return (alternate, variant); yield break; }
        if (InfisicalDynamicNestedProfileOptions.Supports(variant))
        {
            if (variant.StartsWith("NativeGatewayOptions.", StringComparison.Ordinal))
            {
                foreach (var provider in new[] { InfisicalDynamicProvider.Clickhouse, InfisicalDynamicProvider.Vertica,
                    InfisicalDynamicProvider.AzureSqlDatabase, InfisicalDynamicProvider.Milvus,
                    InfisicalDynamicProvider.Kubernetes, InfisicalDynamicProvider.IbmApiConnect })
                    yield return (provider, null);
                yield return (InfisicalDynamicProvider.Kubernetes, "Kubernetes.static-account");
            }
            else if (variant.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal))
            {
                string[] parts = variant.Split('.');
                foreach (string alternative in TailscaleAlternatives)
                    if (parts[1] switch
                    {
                        "audience" => parts[2] == "omitted" || alternative.StartsWith("Tailscale.federated_keys.", StringComparison.Ordinal),
                        "reusable" or "preauthorized" => parts[2] == "omitted" || alternative == "Tailscale.auth_keys.oauth",
                        _ => true
                    }) yield return (InfisicalDynamicProvider.Tailscale, alternative);
            }
            else yield return (InfisicalDynamicNestedProfileOptionTests.Provider(variant), null);
            yield break;
        }
        if (InfisicalDynamicProfileVariants.TryProvider(variant, out var selected))
        {
            if (selected != InfisicalDynamicProvider.SqlDatabase) yield return (selected, null);
            yield break;
        }
        if (variant.StartsWith("AwsIam.", StringComparison.Ordinal))
        { yield return (InfisicalDynamicProvider.AwsIam, null); yield break; }
        if (variant.StartsWith("gatewayId.", StringComparison.Ordinal) ||
            variant.StartsWith("gatewayPoolId.", StringComparison.Ordinal))
        {
            foreach (var provider in new[] { InfisicalDynamicProvider.Clickhouse, InfisicalDynamicProvider.Vertica,
                InfisicalDynamicProvider.AzureSqlDatabase, InfisicalDynamicProvider.Milvus,
                InfisicalDynamicProvider.Kubernetes, InfisicalDynamicProvider.IbmApiConnect })
                yield return (provider, null);
            yield break;
        }
        if (variant is "passwordRequirements.omitted" or "passwordRequirements.value")
        {
            foreach (var provider in new[] { InfisicalDynamicProvider.Clickhouse, InfisicalDynamicProvider.Vertica,
                InfisicalDynamicProvider.AzureSqlDatabase, InfisicalDynamicProvider.Couchbase })
                yield return (provider, null);
            yield break;
        }
        if (variant is "selector.exact" or "collection.bounded" or "inputs.omitted" or "inputs.same-provider" or
            "defaultTtl.omitted" or "defaultTtl.value" or "maximumTtl.omitted" or "maximumTtl.null" or
            "maximumTtl.value" or "newName.omitted" or "newName.value" or "options.omitted" or "options.value" or
            "usernameTemplate.omitted" or "usernameTemplate.value" or "usernameTemplate.null" or
            "metadata.omitted" or "metadata.empty" or "metadata.value" or
            "forceRecordRemoval.false" or "forceRecordRemoval.true")
            foreach (var provider in Providers) yield return (provider, null);
    }

    public static IEnumerable<(InfisicalDynamicProvider Provider, string Variant, string? Alternative)> CalibrationCases() =>
        ProtectedCases().Where(c => c.Method is "CreateDefinitionAsync" or "UpdateDefinitionAsync")
            .Select(c => (c.Provider, c.Variant, c.Alternative)).Distinct();

    [Test]
    [MethodDataSource(nameof(ProtectedCases))]
    public async Task CalibratedIndependentNonSqlInputEvidenceMustPass(InfisicalDynamicProvider provider,
        string method, string variant, string boundary, string? alternative)
    {
        // Given a private closed selection and an independently provisioned service.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, variant, alternativeVariant: alternative);
        // When the actual admitted public client operation runs.
        var result = await RunAsync(fixture, method, variant, boundary);
        // Then metadata-only dispatch is insufficient: the intended Red stays asserted.
        await Assert.That(fixture.ResidualCount).IsEqualTo(0).Because(result.ReasonCode);
        await Assert.That(fixture.BorrowedRootIntact).IsTrue();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(fixture.Source.Observations).IsEqualTo(2);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
    }

    [Test]
    [MethodDataSource(nameof(CalibrationCases))]
    public async Task CalibrationUsesActualPublicHandlesReceiptsAndCommittedStorage(
        InfisicalDynamicProvider provider, string variant, string? alternative)
    {
        // Given a source independently calibrated against the public SDK surface.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, variant, alternativeVariant: alternative);
        // When baseline/selected typed factories actually save and update.
        await CalibrateAsync(fixture);
        // Then all definitions, source registrations and upstream artifacts are gone.
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Observations).IsEqualTo(2);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "ignored-admin", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "ignored-protected-field", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "ignored-transport", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "retained-wrong-authority", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "uncommitted-save", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Clickhouse, "replay", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Totp, "ignored-local", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Ssh, "ignored-local", "effect-mismatch")]
    [Arguments(InfisicalDynamicProvider.Github, "uncommitted-orphan-material", "cleanup-incomplete")]
    [Arguments(InfisicalDynamicProvider.Kubernetes, "uncommitted-orphan-resource", "cleanup-incomplete")]
    public async Task CalibrationRejectsActualFaultsDespiteSuccessfulSdkMetadata(
        InfisicalDynamicProvider provider, string mode, string code)
    {
        // Given an independently controlled faulty native save, before handler integration.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, "profile." + provider, mode);
        string? observed = null;
        // When real public SDK receipts/metadata are reconciled with the source.
        try { await CalibrateAsync(fixture); }
        catch (NativeCaseFailureException error) { observed = error.Message; }
        // Then even successful metadata cannot certify the concrete fault.
        await Assert.That(observed).IsEqualTo(code);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
        await Assert.That(fixture.Validations.Count).IsGreaterThan(0);
        await Assert.That(fixture.DefinitionCount).IsEqualTo(0);
        await Assert.That(fixture.Source.PrivateCopiesDestroyed).IsTrue();
        if (mode.Contains("orphan", StringComparison.Ordinal))
            await Assert.That(fixture.ActiveMaterials + fixture.ActiveResources).IsGreaterThan(0);
        else await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task CalibrationCancellationHasZeroRequestsPossibleDispatchAndOneTerminalFence()
    {
        // Given capture armed before the actual public transport cancellation event.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(InfisicalDynamicProvider.Clickhouse, "profile.Clickhouse");
        // When cancellation occurs after receipt Begin but before the native wire.
        await CalibrateAsync(fixture, cancelBoundary: true);
        // Then independent storage remains baseline and all ownership is closed.
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
        await Assert.That(fixture.Source.Observations).IsEqualTo(2);
        await Assert.That(fixture.Source.Registrations).IsEqualTo(0);
    }

    [Test]
    public async Task CalibrationRejectedAdministrativeCredentialHasTruthfulNegativeApplyFence()
    {
        // Given source capture and an owned folder before the public save attempt.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(InfisicalDynamicProvider.Clickhouse, "profile.Clickhouse");
        using var environment = Environment(fixture, new());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var token = deadline.Token;
        await using var native = environment.CreateClient(NativeIdentityRole.Setup);
        string name = "rejected-" + Guid.NewGuid().ToString("N");
        var folderTarget = new SecretReference(native.Authority, new InfisicalFolderAddress(
            InfisicalNonSqlInputEffectFixture.ProjectId, "env", InfisicalNonSqlInputEffectFixture.EnvironmentId, "/borrowed", name: name));
        var authority = new InfisicalNativeAuthority(native.Authority, environment.Tokens(NativeIdentityRole.Setup),
            InfisicalNonSqlInputEffectFixture.ProjectId);
        var source = fixture.Source.CreateObserver();
        var input = fixture.PrivateInput();
        using var profiles = new NonSqlInputPrivateProfiles(fixture.Provider, input.NonSqlInputWitness!,
            fixture.Selected, null, null, "CreateDefinitionAsync", fixture.Variant, input);
        var root = new NonSqlInputRootAttempt(Guid.NewGuid().ToString(), "rejected-calibration", "v0.166.3",
            "controlled-nonsql", "controlled-fixture", Guid.NewGuid().ToString(), fixture.Provider,
            NonSqlValidationKind.AdministrativeConnection, InfisicalNonSqlInputEffectFixture.ProjectId,
            "env", "/borrowed/" + name, NonSqlInputSource.ControlledFixture);
        var binding = await source.OpenAsync(root, profiles, token);
        var folder = await native.CreateFolderAsync(folderTarget, authority, new(folderTarget), cancellationToken: token);
        await Assert.That(folder.IsSuccess).IsTrue();
        await using var client = new InfisicalDynamicClient(fixture.Origin, environment.Tokens(NativeIdentityRole.Setup),
            new("project-slug", "env", "/borrowed/" + name, Guid.Parse(folder.Value.Id)),
            new() { AllowLoopbackDevelopmentHttp = true });
        var target = client.Definition(name);
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        var arm = await source.ArmAsync(new(binding, Guid.NewGuid().ToString(), name, null,
            "CreateDefinitionAsync", fixture.Variant, "independent-effect", NonSqlInputConfiguration.Selected), token);
        var bad = fixture.Selected! with { Clickhouse = fixture.Selected.Clickhouse! with { Password = "wrong-admin" } };
        using var profile = InfisicalDynamicProfileInputs.Create(fixture.Provider, bad);
        try
        {
            // When actual backend administrative authentication rejects the save.
            var created = await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(60)),
                new(TimeSpan.FromSeconds(300)), receipt, token);
            // Then independent state, not a submitted-body echo, proves no commit.
            await Assert.That(created.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
            var fence = await source.CompleteAsync(arm, receipt.Evidence, token);
            await Assert.That(fence.MatchedRequests).IsEqualTo(1);
            await Assert.That(fence.MatchedCommits).IsEqualTo(0);
            await Assert.That(!fence.Applied && fence.DefinitionAbsent && fence.OriginalAttemptSettled &&
                fence.ExcludesLateCommit && fence.NoReplay).IsTrue();
            await Assert.That((await client.InspectDefinitionAsync(target, token)).Status).IsEqualTo(SecretStatus.Absent);
            await Assert.That(async () => await source.ObserveAsync(binding, null, NonSqlInputConfiguration.Absent, token))
                .Throws<NativeCaseFailureException>();
        }
        finally
        {
            await Assert.That((await native.DeleteFolderAsync(folderTarget, authority, new(folderTarget),
                cancellationToken: token)).IsSuccess).IsTrue();
            await source.CloseAsync(root, token);
        }
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task MatrixRetainsEveryNonSqlAdmissionKeyAndAllSixOperations()
    {
        // Given the owning admission catalog, not a sampled hard-coded subset.
        var cases = ProtectedCases().ToArray();
        // When the controlled matrix is enumerated.
        var covered = cases.Select(c => (c.Method, c.Variant, c.Boundary)).ToHashSet();
        // Then every retained selection keeps its original key/case pairing.
        await Assert.That(cases.Select(c => c.Provider).Distinct().Count()).IsEqualTo(27);
        await Assert.That(cases.Select(c => c.Method).Distinct().Count()).IsEqualTo(6);
        foreach (string method in Methods)
            foreach (string variant in Admission(method).Variants.Where(v => Selections(v).Any()))
                foreach (string boundary in Admission(method).Cases)
                    await Assert.That(covered.Contains((method, variant, boundary))).IsTrue();
        foreach (string variant in new[] { "AwsIam.access-key.IamUser", "AwsIam.access-key.Temporary",
            "AwsIam.assume-role.IamUser", "AwsIam.assume-role.Temporary", "AwsIam.irsa.IamUser", "AwsIam.irsa.Temporary",
            "Totp.manual.Sha1", "Totp.manual.Sha256", "Totp.manual.Sha512", "Ldap.static-account",
            "Kubernetes.static-account", "ElasticSearch.api-key", "Tailscale.auth_keys.api_key",
            "Tailscale.auth_keys.oauth", "Tailscale.federated_keys.api_key", "Tailscale.federated_keys.oauth",
            "Tailscale.oauth_keys.api_key", "Tailscale.oauth_keys.oauth", "RabbitMq.tags.empty", "Atlas.scopes.empty",
            "Oauth2.extraParams.empty", "NativeGatewayOptions.clearGatewayId.true", "NativeGatewayOptions.clearGatewayPoolId.true" })
            await Assert.That(cases.Any(c => c.Variant == variant)).IsTrue();
    }

    [Test]
    [Arguments("ignored-protected-field", "effect-mismatch")]
    [Arguments("uncommitted-save", "effect-mismatch")]
    [Arguments("ignored-admin", "effect-mismatch")]
    [Arguments("ignored-options", "effect-mismatch")]
    [Arguments("ignored-transport", "effect-mismatch")]
    [Arguments("retained-wrong-authority", "effect-mismatch")]
    [Arguments("foreign-source", "observer-unavailable")]
    [Arguments("foreign-profile", "observer-unavailable")]
    [Arguments("foreign-provider", "observer-unavailable")]
    [Arguments("foreign-epoch", "observer-unavailable")]
    [Arguments("foreign-attempt", "observer-unavailable")]
    [Arguments("foreign-epoch-after-open", "observer-unavailable")]
    [Arguments("late-commit", "cleanup-incomplete")]
    [Arguments("replay", "effect-mismatch")]
    [Arguments("borrowed-state-damage", "cleanup-incomplete")]
    public async Task FaultyIndependentSourceCannotBeCertified(string mode, string code)
    {
        // Given a faulty service/source that can still return successful metadata.
        string variant = mode == "ignored-options" ? "metadata.value" : "profile.Clickhouse";
        await using var fixture = new InfisicalNonSqlInputEffectFixture(InfisicalDynamicProvider.Clickhouse, variant, mode);
        // When the admitted update attempts independent verification.
        var result = await RunAsync(fixture, "UpdateDefinitionAsync", variant, "independent-effect");
        // Then the exact defect code, not a weakened unavailable expectation, is required.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(code);
        await Assert.That(fixture.Source.Opens).IsEqualTo(1);
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Totp)]
    [Arguments(InfisicalDynamicProvider.Ssh)]
    public async Task IgnoredLocalTransformationCannotBecomeAdministrativeSuccess(InfisicalDynamicProvider provider)
    {
        // Given local-only validation with its transformation disabled.
        string variant = "profile." + provider;
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, variant, "ignored-local");
        // When the actual public definition operation runs.
        var result = await RunAsync(fixture, "UpdateDefinitionAsync", variant, "independent-effect");
        // Then remote administrative evidence cannot substitute for local lineage.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Github, "orphan-material")]
    [Arguments(InfisicalDynamicProvider.Kubernetes, "orphan-resource")]
    [Arguments(InfisicalDynamicProvider.Github, "pending-admin")]
    public async Task CleanupRejectsOriginalSaveArtifactsAfterDefinitionRemoval(
        InfisicalDynamicProvider provider, string mode)
    {
        // Given a save-time artifact independent of the definition inventory.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, "profile." + provider, mode);
        // When definitions are removed but the original artifact remains.
        var result = await RunAsync(fixture, "CreateDefinitionAsync", "profile." + provider, "independent-effect");
        // Then source cleanup must report incomplete, without forced disposal.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("NativeGatewayOptions.gatewayId.value", InfisicalDynamicProvider.Redis)]
    [Arguments("NativeTailscaleOptions.audience.value", InfisicalDynamicProvider.Tailscale)]
    [Arguments("NativeAwsIamOptions.sessionPolicyArns.value", InfisicalDynamicProvider.AwsIam)]
    public async Task InvalidPrivateSelectionRemainsMissingInput(string variant, InfisicalDynamicProvider provider)
    {
        // Given a mismatched closed private selection, retained in admission.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(provider, "profile." + provider);
        var input = fixture.Input();
        input["optionProvider"] = provider.ToString();
        // When selection is attempted before any owned folder or source root.
        var result = await RunAsync(fixture, "CreateDefinitionAsync", variant, "selected-contract", input);
        // Then it stays missing input and has zero native/source side effects.
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(fixture.Requests.Count).IsEqualTo(0);
        await Assert.That(fixture.Source.Opens).IsEqualTo(0);
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    [Test]
    public async Task MissingWitnessNeverCertifiesMetadata()
    {
        // Given no independently configured source witness.
        await using var fixture = new InfisicalNonSqlInputEffectFixture(InfisicalDynamicProvider.Clickhouse, "profile.Clickhouse");
        // When the public create definition operation returns valid metadata.
        var result = await RunAsync(fixture, "CreateDefinitionAsync", "profile.Clickhouse",
            "independent-effect", fixture.Input(witness: false));
        // Then metadata-only success remains unavailable.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.ResidualCount).IsEqualTo(0);
    }

    private static LifecycleAdmission Admission(string method) =>
        InfisicalLifecycleFamilies.Catalog.Single(a => a.Operation == "i.runtime.InfisicalDynamicClient." + method);

    private static async Task<NativeCaseResult> RunAsync(InfisicalNonSqlInputEffectFixture fixture,
        string method, string variant, string boundary, JsonObject? input = null)
    {
        var admission = Admission(method);
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, variant, "offline", boundary), admission.Member);
        var families = new JsonObject
        {
            [InfisicalDynamicClientEffects.Family] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    ["offline"] = new JsonObject
                    {
                        [admission.Operation] = new JsonObject
                        {
                            [variant] = new JsonObject { [boundary] = input ?? fixture.Input() }
                        }
                    }
                }
            }
        };
        using var environment = Environment(fixture, families);
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, environment, [row], nonSqlInputs: fixture.Source.CreateObserver());
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
    }

    private static NativeEnvironment Environment(InfisicalNonSqlInputEffectFixture fixture, JsonObject families) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = fixture.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, Options));

    private static async Task CalibrateAsync(InfisicalNonSqlInputEffectFixture fixture, bool cancelBoundary = false)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var token = deadline.Token;
        using var environment = Environment(fixture, new());
        await using var native = environment.CreateClient(NativeIdentityRole.Setup);
        string name = "calibration-" + Guid.NewGuid().ToString("N");
        var folderTarget = new SecretReference(native.Authority, new InfisicalFolderAddress(
            InfisicalNonSqlInputEffectFixture.ProjectId, "env", InfisicalNonSqlInputEffectFixture.EnvironmentId, "/borrowed", name: name));
        var source = fixture.Source.CreateObserver();
        var root = new NonSqlInputRootAttempt(Guid.NewGuid().ToString(), "calibration", "v0.166.3",
            "controlled-nonsql", "controlled-fixture", Guid.NewGuid().ToString(), fixture.Provider,
            NonSqlInputPrivateProfiles.Kind(fixture.Provider), InfisicalNonSqlInputEffectFixture.ProjectId,
            "env", "/borrowed/" + name, NonSqlInputSource.ControlledFixture);
        var privateInput = fixture.PrivateInput();
        var selection = fixture.Selection();
        using var profiles = new NonSqlInputPrivateProfiles(fixture.Provider, privateInput.NonSqlInputWitness!,
            selection.Profile, selection.Alternative, fixture.AlternativeVariant, "UpdateDefinitionAsync", fixture.Variant, privateInput);
        var binding = await source.OpenAsync(root, profiles, token);
        var folder = await native.CreateFolderAsync(folderTarget, new InfisicalNativeAuthority(native.Authority,
            environment.Tokens(NativeIdentityRole.Setup), InfisicalNonSqlInputEffectFixture.ProjectId),
            new(folderTarget), cancellationToken: token);
        await Assert.That(folder.IsSuccess).IsTrue();
        var scope = new InfisicalDynamicScope("project-slug", "env", "/borrowed/" + name, Guid.Parse(folder.Value.Id));
        using var transport = new LifecycleTransport(cancelBoundary ? "cancellation-boundary" : "selected-contract");
        await using var client = new InfisicalDynamicClient(fixture.Origin, environment.Tokens(NativeIdentityRole.Setup),
            scope, new() { AllowLoopbackDevelopmentHttp = true }, transport: transport);
        try
        {
            var target = client.Definition(name);
            var createReceipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
            var seedArm = await source.ArmAsync(new(binding, Guid.NewGuid().ToString(), name, null,
                "CreateDefinitionAsync", "seed", "selected-contract", NonSqlInputConfiguration.Baseline), token);
            using var baseline = fixture.Create(false);
            var created = await client.CreateDefinitionAsync(target, baseline, new(TimeSpan.FromSeconds(60)),
                new(TimeSpan.FromSeconds(300)), createReceipt, token);
            await Assert.That(created.IsSuccess).IsTrue();
            await Assert.That(createReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            var seedFence = await source.CompleteAsync(seedArm, createReceipt.Evidence, token);
            await Assert.That(seedFence.DefinitionId).IsEqualTo(created.Value.Id);
            await source.ObserveAsync(binding, created.Value.Id, NonSqlInputConfiguration.Baseline, token);
            var changedArm = await source.ArmAsync(new(binding, Guid.NewGuid().ToString(), name, created.Value.Id,
                "UpdateDefinitionAsync", fixture.Variant, "independent-effect",
                cancelBoundary || fixture.Variant == "inputs.omitted" ? NonSqlInputConfiguration.Baseline : NonSqlInputConfiguration.Selected), token);
            using var selected = fixture.Create(true);
            var updateReceipt = new InfisicalDynamicMutationReceipt(created.Value.Target, InfisicalDynamicOperation.UpdateDefinition);
            var options = fixture.Variant == "options.omitted" ? null : new NativeDynamicDefinitionOptions(
                fixture.Variant == "usernameTemplate.value" ? "owned-selected" : null,
                fixture.Variant == "metadata.omitted" ? null : fixture.Variant == "metadata.value" ?
                    [new("marker", "selected")] : []);
            if (cancelBoundary)
            {
                using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
                Task boundary = transport.Reached.Task;
                var cancelling = boundary.ContinueWith(_ => cancellation.Cancel(), CancellationToken.None,
                    TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
                transport.Arm();
                await Assert.That(async () => await client.UpdateDefinitionAsync(created.Value,
                    new(inputs: selected), updateReceipt, cancellation.Token)).Throws<OperationCanceledException>();
                await cancelling.WaitAsync(token);
                await Assert.That(updateReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
                var cancelledFence = await source.CompleteAsync(changedArm, updateReceipt.Evidence, token);
                await Assert.That(cancelledFence.MatchedRequests).IsEqualTo(0);
                await Assert.That(cancelledFence.MatchedCommits).IsEqualTo(0);
                await Assert.That(cancelledFence.OriginalAttemptSettled && cancelledFence.ExcludesLateCommit &&
                    cancelledFence.NoReplay && !cancelledFence.Applied).IsTrue();
                await source.ObserveAsync(binding, created.Value.Id, NonSqlInputConfiguration.Baseline, token);
                await Assert.That(async () => await source.CompleteAsync(changedArm, updateReceipt.Evidence, token))
                    .Throws<NativeCaseFailureException>();
                transport.Disarm();
                return;
            }
            var updated = await client.UpdateDefinitionAsync(created.Value, new(
                inputs: fixture.Variant == "inputs.omitted" ? null : selected, options: options,
                clearUsernameTemplate: fixture.Variant == "usernameTemplate.null"), updateReceipt, token);
            await Assert.That(updated.IsSuccess).IsTrue();
            await Assert.That(updated.Value.Id).IsEqualTo(created.Value.Id);
            await Assert.That(updateReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await source.CompleteAsync(changedArm, updateReceipt.Evidence, token);
            await source.ObserveAsync(binding, updated.Value.Id,
                fixture.Variant == "inputs.omitted" ? NonSqlInputConfiguration.Baseline : NonSqlInputConfiguration.Selected, token);
            var inspected = await client.InspectDefinitionAsync(target, token);
            var listed = await client.ListDefinitionsAsync(token);
            await Assert.That(inspected.IsSuccess && listed.IsSuccess && listed.Value.IsComplete &&
                listed.Value.Items.Count == 1 && listed.Value.Items[0].Id == updated.Value.Id).IsTrue();
            // A foreign client's public handle cannot be borrowed for mutation.
            await using var foreign = new InfisicalDynamicClient(fixture.Origin, environment.Tokens(NativeIdentityRole.Setup),
                scope, new() { AllowLoopbackDevelopmentHttp = true });
            var foreignReceipt = new InfisicalDynamicMutationReceipt(foreign.Definition(name), InfisicalDynamicOperation.DeleteDefinition);
            var rejected = await foreign.DeleteDefinitionAsync(updated.Value, foreignReceipt, cancellationToken: token);
            await Assert.That(rejected.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(foreignReceipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        finally
        {
            // Reconcile through original public handles, without force-record cleanup.
            var inventory = await client.ListDefinitionsAsync(token);
            await Assert.That(inventory.IsSuccess && inventory.Value.IsComplete).IsTrue();
            foreach (var definition in inventory.Value.Items)
            {
                var deletion = await client.DeleteDefinitionAsync(definition,
                    new(definition.Target, InfisicalDynamicOperation.DeleteDefinition), cancellationToken: token);
                await Assert.That(deletion.IsSuccess && !deletion.Value.ExternalRevocationVerified).IsTrue();
                await Assert.That((await client.InspectDefinitionAsync(definition.Target, token)).Status).IsEqualTo(SecretStatus.Absent);
            }
            await Assert.That((await native.DeleteFolderAsync(folderTarget,
                new InfisicalNativeAuthority(native.Authority, environment.Tokens(NativeIdentityRole.Setup),
                    InfisicalNonSqlInputEffectFixture.ProjectId),
                new(folderTarget), cancellationToken: token)).IsSuccess).IsTrue();
            var closed = await source.CloseAsync(root, token);
            await Assert.That(closed.OwnedUpstreamMaterialDisposed && closed.OwnedUpstreamResourcesAbsent &&
                closed.OriginalAttemptsSettled && closed.PendingDeliveries == 0 && closed.RemainingRegistrations == 0).IsTrue();
        }
    }
}
