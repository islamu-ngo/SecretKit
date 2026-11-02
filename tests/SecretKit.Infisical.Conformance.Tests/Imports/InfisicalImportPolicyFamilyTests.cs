using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalImportPolicyFamilyTests
{
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string ReplacementEnvironmentId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private static readonly string[] OrganizationMethods = ["CreateEnvironmentAsync", "CreateFolderAsync",
        "CreateTagAsync", "DeleteEnvironmentAsync", "DeleteFolderAsync", "DeleteTagAsync",
        "GetEnvironmentAsync", "GetFolderAsync", "GetTagAsync", "ListFoldersAsync", "ListTagsAsync",
        "MoveFolderAsync", "RestoreEnvironmentAsync", "UpdateEnvironmentAsync", "UpdateFolderAsync",
        "UpdateFoldersAsync", "UpdateTagAsync"];
    private static readonly string[] ImportMethods = ["CreateImportAsync", "DeleteImportAsync",
        "GetImportAsync", "ListImportsAsync", "ReadImportedSecretsAsync", "UpdateImportAsync"];
    private static readonly string[] PolicyMethods = ["CreateValidationRuleAsync", "DeleteValidationRuleAsync",
        "GetValidationRuleAsync", "ListValidationRulesAsync", "UpdateValidationRuleAsync"];

    [Test]
    public async Task EveryCurrentMemberVariantAndCaseRemainsRegistered()
    {
        NativeCaseDefinition[] all = await DefinitionsAsync();
        await Assert.That(all.Length).IsEqualTo(622);
        await Assert.That(all.Select(d => d.Member).Distinct().Count()).IsEqualTo(29);
        foreach ((string[] methods, int variants, int cases) in new[]
        {
            (OrganizationMethods, 40, 190), (ImportMethods, 25, 111), (PolicyMethods, 62, 301),
            (new[] { "ObserveImportEffectsAsync" }, 5, 20)
        })
        {
            var rows = all.Where(d => methods.Any(m => d.Key.Operation == "i.runtime.InfisicalClient." + m)).ToArray();
            await Assert.That(rows.Length).IsEqualTo(cases);
            await Assert.That(rows.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(variants);
        }
        using NativeEnvironment env = Environment(new("http://127.0.0.1:1"), new JsonObject());
        var registry = new NativeCaseRegistry();
        InfisicalImportPolicyFamilies.Register(registry, env, all);
        var results = await NativeCaseRunner.RunAsync(registry, all, CancellationToken.None);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task InvalidAdmissionFailsBeforeAnyProviderCall(string invalid)
    {
        NativeCaseDefinition original = (await DefinitionsAsync()).First();
        var d = invalid switch
        {
            "member" => original with { Member = original.Member + ".wrong" },
            "variant" => original with { Key = original.Key with { Variant = "invented" } },
            _ => original with { Key = original.Key with { Case = "invented" } }
        };
        await using var backend = new Backend();
        using NativeEnvironment env = Environment(backend.Origin, new JsonObject());
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("contract-mismatch");
        await Assert.That(backend.RequestCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateEnvironmentAsync")]
    [Arguments("CreateFolderAsync")]
    [Arguments("CreateTagAsync")]
    [Arguments("DeleteEnvironmentAsync")]
    [Arguments("DeleteFolderAsync")]
    [Arguments("DeleteTagAsync")]
    [Arguments("GetEnvironmentAsync")]
    [Arguments("GetFolderAsync")]
    [Arguments("GetTagAsync")]
    [Arguments("ListFoldersAsync")]
    [Arguments("ListTagsAsync")]
    [Arguments("MoveFolderAsync")]
    [Arguments("RestoreEnvironmentAsync")]
    [Arguments("UpdateEnvironmentAsync")]
    [Arguments("UpdateFolderAsync")]
    [Arguments("UpdateFoldersAsync")]
    [Arguments("UpdateTagAsync")]
    public async Task OrganizationUsesPublicSdkAndIndependentOwnedState(string method)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync(method, "independent-effect");
        var input = OrganizationInput(true);
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Organization", d, input));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
        await Assert.That(backend.Roles.Contains("observer")).IsTrue();
        await Assert.That(backend.Roles.Contains("runtime")).IsTrue();
    }

    [Test]
    [Arguments("ListFoldersAsync", false)]
    [Arguments("ListFoldersAsync", true)]
    [Arguments("ListTagsAsync", false)]
    [Arguments("ListTagsAsync", true)]
    public async Task OrganizationInventoryRejectsDuplicatesAndIncompletePages(string method, bool bounded)
    {
        await using var backend = new Backend { DuplicateOrganizationInventory = true };
        var d = await DefinitionAsync(method, "independent-effect");
        var input = OrganizationInput(true) with { MaximumItems = bounded ? 1 : 1000 };
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Organization", d, input));
        var result = await RunAsync(env, d);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    public async Task EveryOrganizationVariantAndCaseUsesItsTypedBranch()
    {
        var rows = (await DefinitionsAsync()).Where(d =>
            OrganizationMethods.Any(m => d.Key.Operation == "i.runtime.InfisicalClient." + m));
        foreach (var d in rows)
        {
            bool denied = d.Key.Case == "denied-authority";
            bool cancelled = d.Key.Case == "cancellation-boundary";
            bool lost = d.Key.Case == "lost-response-no-replay";
            bool mutation = d.Key.Operation.Contains(".Create", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Update", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Delete", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Move", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Restore", StringComparison.Ordinal);
            bool applied = !denied && (!cancelled || !mutation);
            string v = d.Key.Variant;
            var input = OrganizationInput(applied) with
            {
                Description = v == "description.value" ? "changed" : null,
                ClearDescription = v is "description.null" or "clearDescription.true",
                Position = v == "position.value" ? 2 : null,
                Name = v == "name.value" ? "changed" : null,
                RenameSlug = v == "slug.value",
                HardDelete = v == "hardDelete.true",
                ForceDelete = v == "forceDelete.true",
                Recursive = v == "recursive.true",
                LastSecretModified = v == "lastSecretModified.value" ? DateTimeOffset.UnixEpoch : null,
                PartialBatch = v == "result.partial",
                BatchApplied = v == "result.partial" ? [applied, false] : null
            };
            await using var backend = new Backend { LoseResponse = lost, PartialBatch = input.PartialBatch };
            using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Organization", d, input));
            var result = await RunAsync(env, d);
            await Assert.That(result.ReasonCode).IsEqualTo("observed").Because(d.Key.Operation + "/" + v + "/" + d.Key.Case);
            await Assert.That(backend.ResourceCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("CreateImportAsync")]
    [Arguments("DeleteImportAsync")]
    [Arguments("GetImportAsync")]
    [Arguments("ListImportsAsync")]
    [Arguments("ReadImportedSecretsAsync")]
    [Arguments("UpdateImportAsync")]
    public async Task ImportsRequireActualSourceAndIntendedDelivery(string method)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync(method, "independent-effect");
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, ImportInput(true)));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("groups", false)]
    [Arguments("groups", true)]
    [Arguments("items", false)]
    [Arguments("items", true)]
    public async Task ImportedInventoryCannotReplaceMissingCoordinatesWithDuplicates(string kind, bool observerOnly)
    {
        await using var backend = new Backend { DuplicateImported = kind, DuplicateObserverOnly = observerOnly };
        var d = await DefinitionAsync("ReadImportedSecretsAsync", "independent-effect", "group-order.preserved");
        var input = ImportInput(true) with
        {
            TwoGroups = true,
            Source = Fixture(new StaticSeed("TARGET", "source-value"), new StaticSeed("SECOND", "second-source")),
            Replacement = Fixture(new StaticSeed("TARGET", "replacement-value"), new StaticSeed("SECOND", "second-replacement"))
        };
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, input));
        var result = await RunAsync(env, d);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    public async Task UnexpectedSuccessfulImportedReadErasesMaterialBeforeDenialAssertion()
    {
        await using var backend = new Backend();
        using NativeEnvironment env = Environment(backend.Origin, new JsonObject());
        var probe = new NativeCaseProbe();
        await using var fixture = new ImportsEffects.OwnedImports(env, ImportInput(false), probe, "local");
        await fixture.InitializeAsync(true, CancellationToken.None);
        var result = await fixture.Destination.Runtime.ReadImportedSecretsAsync(
            fixture.Target(fixture.Destination.Runtime));
        await Assert.That(result.IsSuccess).IsTrue();
        using var owned = result.Value;
        SecretMaterial held = owned.Items.Single().Material;
        await Assert.That(held.Reveal()).IsEqualTo("source-value");
        await Assert.That(() => InfisicalImportPolicyFamilies.Result(
            new StaticDispatch<InfisicalImportedSecrets>(result, false), null,
            SecretStatus.Denied, default, probe)).Throws<NativeCaseFailureException>();
        await Assert.That(() => held.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("sourceEnvironment.value")]
    [Arguments("sourcePath.omitted")]
    public async Task EnvironmentOnlyUpdatesPreservePathPositionAndOwnedDelivery(string variant)
    {
        foreach (string caseName in new[] { "selected-contract", "independent-effect", "denied-authority",
            "cancellation-boundary", "lost-response-no-replay" })
        {
            bool applied = caseName is not ("denied-authority" or "cancellation-boundary");
            await using var backend = new Backend
            {
                LoseResponse = caseName == "lost-response-no-replay",
                SelectedPath = "/api/v2/secret-imports"
            };
            var d = await DefinitionAsync("UpdateImportAsync", caseName, variant);
            var input = ImportInput(applied) with
            {
                SupplySourceEnvironment = true,
                SupplySourcePath = false,
                Replacement = Fixture(new StaticSeed("TARGET", "replacement-value")) with
                { Environment = "replacement-env", EnvironmentId = ReplacementEnvironmentId }
            };
            using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, input));
            var result = await RunAsync(env, d);
            await Assert.That(result.ReasonCode).IsEqualTo("observed").Because(caseName + "/" + result.ReasonCode);
            await Assert.That(backend.ResourceCount).IsEqualTo(0);
            await Assert.That(backend.SecretCount).IsEqualTo(0);
            await Assert.That(backend.RuntimeMutations).IsEqualTo(applied ? 1 : 0);
        }
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task EnvironmentOnlyUpdateRejectsIgnoredSelectionAndOldDelivery(bool ignoredUpdate)
    {
        await using var backend = new Backend
        {
            IgnoreImportEnvironmentChange = ignoredUpdate,
            DeliverFromOldEnvironment = !ignoredUpdate
        };
        var d = await DefinitionAsync("UpdateImportAsync", "independent-effect", "sourceEnvironment.value");
        var input = ImportInput(true) with
        {
            SupplySourceEnvironment = true,
            SupplySourcePath = false,
            Replacement = Fixture(new StaticSeed("TARGET", "replacement-value")) with
            { Environment = "replacement-env", EnvironmentId = ReplacementEnvironmentId }
        };
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, input));
        var result = await RunAsync(env, d);
        await Assert.That(result.ReasonCode).IsEqualTo(ignoredUpdate ? "contract-mismatch" : "effect-mismatch").Because(result.ReasonCode);
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
        await Assert.That(backend.SecretCount).IsEqualTo(0);
    }

    [Test]
    public async Task EveryImportVariantAndCaseRetainsDeliveryAndReplicationBoundaries()
    {
        var rows = (await DefinitionsAsync()).Where(d =>
            ImportMethods.Any(m => d.Key.Operation == "i.runtime.InfisicalClient." + m));
        foreach (var d in rows)
        {
            bool denied = d.Key.Case == "denied-authority";
            bool cancelled = d.Key.Case == "cancellation-boundary";
            bool mutation = d.Key.Operation.Contains(".Create", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Update", StringComparison.Ordinal) ||
                d.Key.Operation.Contains(".Delete", StringComparison.Ordinal);
            bool applied = !denied && (!cancelled || !mutation);
            string v = d.Key.Variant;
            var input = ImportInput(applied) with
            {
                Replication = v == "replication.true",
                ExplicitSourceProject = v == "source.selected-other-project",
                SupplySourceEnvironment = v == "sourceEnvironment.value",
                SupplySourcePath = v == "sourcePath.value",
                Position = v == "position.value" ? 2 : null,
                TwoGroups = v == "group-order.preserved",
                MaximumItems = v == "collection.item-budget" ? 1 : 1000,
                Source = Fixture(new StaticSeed("TARGET", "source-value"), new StaticSeed("SECOND", "second-source")),
                Replacement = Fixture(new StaticSeed("TARGET", "replacement-value"), new StaticSeed("SECOND", "second-replacement")) with
                {
                    Environment = v == "sourceEnvironment.value" ? "replacement-env" : "env",
                    EnvironmentId = v == "sourceEnvironment.value" ? ReplacementEnvironmentId : EnvironmentId
                }
            };
            if (input.ExplicitSourceProject)
                input = input with
                {
                    Source = input.Source with { ProjectId = "other" },
                    Replacement = input.Replacement with { ProjectId = "other" }
                };
            await using var backend = new Backend { LoseResponse = d.Key.Case == "lost-response-no-replay" };
            using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, input));
            var result = await RunAsync(env, d);
            await Assert.That(result.ReasonCode).IsEqualTo(input.Replication ? "observer-unavailable" : "observed")
                .Because(d.Key.Operation + "/" + v + "/" + d.Key.Case);
            await Assert.That(backend.ResourceCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("CreateValidationRuleAsync")]
    [Arguments("DeleteValidationRuleAsync")]
    [Arguments("GetValidationRuleAsync")]
    [Arguments("ListValidationRulesAsync")]
    [Arguments("UpdateValidationRuleAsync")]
    public async Task ValidationRequiresAllowedAndViolatingOperations(string method)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync(method, "independent-effect");
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-ValidationPolicies", d, PolicyInput(method)));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("description.null")]
    [Arguments("environment.null")]
    [Arguments("keyConstraints.null")]
    [Arguments("valueConstraints.null")]
    [Arguments("isActive.false")]
    public async Task ValidationClearsAndDisableProveTheChangedEnforcement(string variant)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync("UpdateValidationRuleAsync", "independent-effect", variant);
        var input = PolicyInput("UpdateValidationRuleAsync");
        var change = input.Change with
        {
            Description = null,
            ClearDescription = variant == "description.null",
            SupplyEnvironment = variant != "environment.null",
            ClearEnvironment = variant == "environment.null",
            KeyConstraints = null,
            ClearKeyConstraints = variant == "keyConstraints.null",
            ValueConstraints = variant == "valueConstraints.null" ? null : input.Change.ValueConstraints,
            ClearValueConstraints = variant == "valueConstraints.null",
            IsActive = variant != "isActive.false"
        };
        if (variant is "valueConstraints.null" or "isActive.false")
            input = input with { After = input.After.Select(t => t with { ExpectedStatus = SecretStatus.Success }).ToArray() };
        using NativeEnvironment env = Environment(backend.Origin,
            Family("C08-IR-ValidationPolicies", d, input with { Change = change }));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    public async Task NonStaticPolicyKindsFailClosedWithoutOwnedBackendInputs()
    {
        foreach (string method in PolicyMethods)
            foreach (var kind in new[] { InfisicalValidationKind.DynamicSecrets, InfisicalValidationKind.SecretRotations })
            {
                var d = await DefinitionAsync(method, "independent-effect", "kind." + kind);
                var rule = Rule("^good") with
                {
                    ValueConstraints = null,
                    PasswordConstraints = new(null, 2048, "^good", null, null, null, null),
                    Providers = [kind == InfisicalValidationKind.DynamicSecrets ?
                    InfisicalValidationProvider.SqlDatabase : InfisicalValidationProvider.PostgresCredentials]
                };
                var input = PolicyInput(method) with { Kind = kind, Seed = rule, Change = rule };
                await using var backend = new Backend();
                using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-ValidationPolicies", d, input));
                await Assert.That((await RunAsync(env, d)).ReasonCode)
                    .IsEqualTo("missing-input");
                await Assert.That(backend.Roles.Count).IsEqualTo(0);
                await Assert.That(backend.ResourceCount).IsEqualTo(0);
            }
    }

    [Test]
    [Arguments("CreateFolderAsync", "C08-IR-Organization")]
    [Arguments("CreateImportAsync", "C08-IR-Imports")]
    [Arguments("CreateValidationRuleAsync", "C08-IR-ValidationPolicies")]
    public async Task DeniedAuthorityCannotMutateOwnedState(string method, string family)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync(method, "denied-authority");
        JsonNode input = family == "C08-IR-Organization" ? Node(OrganizationInput(false)) :
            family == "C08-IR-Imports" ? Node(ImportInput(false)) : Node(PolicyInput(method, applied: false));
        using NativeEnvironment env = Environment(backend.Origin, Family(family, d, input));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.RuntimeMutations).IsEqualTo(method.Contains("Validation", StringComparison.Ordinal) ? 6 : 0);
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateFolderAsync", "C08-IR-Organization", false)]
    [Arguments("CreateFolderAsync", "C08-IR-Organization", true)]
    [Arguments("CreateImportAsync", "C08-IR-Imports", false)]
    [Arguments("CreateImportAsync", "C08-IR-Imports", true)]
    [Arguments("CreateValidationRuleAsync", "C08-IR-ValidationPolicies", false)]
    [Arguments("CreateValidationRuleAsync", "C08-IR-ValidationPolicies", true)]
    public async Task ExactEventBarriersRetainReceiptsAndNeverReplay(string method, string family, bool lost)
    {
        await using var backend = new Backend
        {
            LoseResponse = lost,
            SelectedPath = method.Contains("Folder", StringComparison.Ordinal) ? "/api/v2/folders" :
                method.Contains("Import", StringComparison.Ordinal) ? "/api/v2/secret-imports" :
                "/api/v1/secret-validation-rules/static-secrets"
        };
        var d = await DefinitionAsync(method, lost ? "lost-response-no-replay" : "cancellation-boundary");
        JsonNode input = family == "C08-IR-Organization" ? Node(OrganizationInput(lost)) :
            family == "C08-IR-Imports" ? Node(ImportInput(lost)) : Node(PolicyInput(method, applied: lost));
        using NativeEnvironment env = Environment(backend.Origin, Family(family, d, input));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("observed");
        await Assert.That(backend.SelectedMutations).IsEqualTo(lost ? 1 : 0);
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("import-material")]
    [Arguments("validation-metadata")]
    [Arguments("cleanup")]
    public async Task AcknowledgementsAndMetadataCannotReplaceEffects(string failure)
    {
        await using var backend = new Backend
        {
            WrongImportedValue = failure == "import-material",
            IgnoreValidation = failure == "validation-metadata",
            DenyCleanup = failure == "cleanup"
        };
        string method = failure == "validation-metadata" ? "CreateValidationRuleAsync" : "CreateImportAsync";
        var d = await DefinitionAsync(method, "independent-effect");
        JsonNode input = failure == "validation-metadata" ? Node(PolicyInput(method)) : Node(ImportInput(true));
        using NativeEnvironment env = Environment(backend.Origin,
            Family(failure == "validation-metadata" ? "C08-IR-ValidationPolicies" : "C08-IR-Imports", d, input));
        var result = await RunAsync(env, d);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(failure == "cleanup" ? "cleanup-incomplete" :
            failure == "validation-metadata" ? "contract-mismatch" : "effect-mismatch");
    }

    [Test]
    [Arguments("selector.exact")]
    [Arguments("import-visible.delivery-success")]
    [Arguments("import-visible.delivery-denied")]
    [Arguments("import-absent")]
    [Arguments("destination-state.Unknown")]
    public async Task DestinationContractGapStaysUnavailableAfterActualSdkObservation(string variant)
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync("ObserveImportEffectsAsync", "independent-effect", variant);
        var input = new ImportEffectObservationEffects.EffectInput(ImportInput(true),
            variant == "import-absent", variant == "import-visible.delivery-denied");
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-ImportEffectObservation", d, input));
        var result = await RunAsync(env, d);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(backend.ResourceCount).IsEqualTo(0);
    }

    [Test]
    public async Task EntitlementIsRequiredBeforeAnyValidationWrite()
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync("CreateValidationRuleAsync", "selected-contract");
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-ValidationPolicies",
            d, PolicyInput("CreateValidationRuleAsync") with { Entitled = false }));
        await Assert.That((await RunAsync(env, d)).ReasonCode).IsEqualTo("missing-prerequisite");
        await Assert.That(backend.RequestCount).IsEqualTo(0);
    }

    [Test]
    public async Task CredentialSelectionDoesNotCertifyPrincipalSeparation()
    {
        await using var backend = new Backend();
        var d = await DefinitionAsync("CreateImportAsync", "independent-effect");
        using NativeEnvironment env = Environment(backend.Origin, Family("C08-IR-Imports", d, ImportInput(true)));
        await Assert.That((await RunAsync(env, d)).Passed).IsTrue();
        var identities = env.PrerequisiteResults([
            new("Infisical", "local", "selected-runtime-identity"),
            new("Infisical", "local", "separate-observer-identity")]);
        await Assert.That(identities.All(i => !i.Confirmed)).IsTrue();
    }

    private static StaticFixtureInput Fixture(params StaticSeed[] seeds) =>
        new("project", "env", EnvironmentId, "/owned", seeds, StaticApiRevision.SecretsV4FoldersV2);
    private static OrganizationEffects.OrganizationInput OrganizationInput(bool applied) =>
        new(Fixture(), null, false, null, null, false, false, false, false, null, 1000, applied, false);
    private static ImportsEffects.ImportInput ImportInput(bool applied) =>
        new(Fixture(), Fixture(new StaticSeed("TARGET", "source-value")), Fixture(new StaticSeed("TARGET", "replacement-value")),
            false, false, false, false, null, 1000, applied, false);
    private static ValidationPoliciesEffects.PolicyInput PolicyInput(string method, bool applied = true)
    {
        var seed = Rule("^good");
        var change = method == "UpdateValidationRuleAsync" ? Rule("^new") : seed;
        bool create = method == "CreateValidationRuleAsync";
        bool absent = create && !applied || method == "DeleteValidationRuleAsync" && applied;
        string allowed = method == "UpdateValidationRuleAsync" && applied ? "new-value" : "good-value";
        ValidationPoliciesEffects.Trial[] before = create ? [] :
            [new("BEFORE_OK", "baseline", "good-value", false, SecretStatus.Success),
                new("BEFORE_BAD", "baseline", "bad", false, SecretStatus.Invalid)];
        return new(Fixture(), InfisicalValidationKind.StaticSecrets, seed, change, before,
            [new("AFTER_OK", "baseline", allowed, false, SecretStatus.Success),
                new("AFTER_BAD", "baseline", "bad", false, absent ? SecretStatus.Success : SecretStatus.Invalid)],
            1000, false, applied, true);
    }
    private static ValidationPoliciesEffects.RuleInput Rule(string regex) =>
        new(null, null, true, null, new(null, null, regex, null, null, null, null), null, null,
            true, true, false, false, false, false);
    private static JsonNode Node<T>(T input) => JsonSerializer.SerializeToNode(input,
        new JsonSerializerOptions(InfisicalStaticFamilies.Options) { IgnoreReadOnlyProperties = false })!;
    private static JsonObject Family<T>(string name, NativeCaseDefinition d, T input) =>
        new()
        {
            [name] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    [d.Key.Scope] = new JsonObject
                    {
                        [d.Key.Operation] = new JsonObject { [d.Key.Variant] = new JsonObject { [d.Key.Case] = Node(input) } }
                    }
                }
            }
        };
    private static NativeEnvironment Environment(Uri origin, JsonObject families) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }));
    private static async Task<NativeCaseResult> RunAsync(NativeEnvironment env, NativeCaseDefinition d)
    {
        var registry = new NativeCaseRegistry();
        InfisicalImportPolicyFamilies.Register(registry, env, [d]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return (await NativeCaseRunner.RunAsync(registry, [d], deadline.Token)).Single();
    }
    private static async Task<NativeCaseDefinition> DefinitionAsync(string method, string @case, string? variant = null) =>
        (await DefinitionsAsync()).First(d => d.Key.Operation == "i.runtime.InfisicalClient." + method &&
            d.Key.Case == @case && (variant is null || d.Key.Variant == variant));
    private static async Task<NativeCaseDefinition[]> DefinitionsAsync()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        string[] methods = [.. OrganizationMethods, .. ImportMethods, .. PolicyMethods, "ObserveImportEffectsAsync"];
        return inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => methods.Any(m => o.GetProperty("id").GetString() == "i.runtime.InfisicalClient." + m))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
    }

    // This stateful loopback server is offline characterization only. All requests
    // come through the real public SDK with separately selected role credentials.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, JsonObject> folders = [];
        private readonly Dictionary<string, JsonObject> environments = [];
        private readonly Dictionary<string, JsonObject> tags = [];
        private readonly Dictionary<string, JsonObject> imports = [];
        private readonly Dictionary<string, JsonObject> rules = [];
        private readonly Dictionary<(string Project, string Environment, string Folder, string Key), (string Value, int Version)> secrets = [];
        private readonly Task accept;
        private int requestCount, runtimeMutations, selectedMutations;
        internal int RequestCount => requestCount;
        internal int RuntimeMutations => runtimeMutations;
        internal int SelectedMutations => selectedMutations;
        internal int SecretCount { get { lock (folders) return secrets.Count; } }
        internal HashSet<string> Roles { get; } = [];
        internal int ResourceCount
        {
            get
            {
                lock (folders) return folders.Count + environments.Count +
            tags.Count + imports.Count + rules.Count;
            }
        }
        internal bool LoseResponse { get; init; }
        internal string? SelectedPath { get; init; }
        internal bool WrongImportedValue { get; init; }
        internal bool IgnoreImportEnvironmentChange { get; init; }
        internal bool DeliverFromOldEnvironment { get; init; }
        internal string? DuplicateImported { get; init; }
        internal bool DuplicateObserverOnly { get; init; }
        internal bool DuplicateOrganizationInventory { get; init; }
        internal bool IgnoreValidation { get; init; }
        internal bool DenyCleanup { get; init; }
        internal bool PartialBatch { get; init; }
        internal Uri Origin { get; }

        internal Backend()
        {
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }
        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                try
                {
                    NetworkStream stream = socket.GetStream();
                    var header = new List<byte>();
                    byte[] one = new byte[1];
                    while (header.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        header.Add(one[0]);
                        if (header.Count >= 4 && header.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                    string[] first = lines[0].Split(' ');
                    string role = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                        .Split(' ').Last();
                    int length = int.Parse(lines.FirstOrDefault(l =>
                        l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("fixture-input");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    JsonObject input = JsonNode.Parse(length == 0 ? "{}"u8.ToArray() : body)!.AsObject();
                    var uri = new Uri(Origin, first[1]);
                    (int Code, JsonObject Body) response;
                    lock (folders)
                    {
                        requestCount++;
                        Roles.Add(role);
                        response = Handle(first[0], uri, role, input);
                        if (DuplicateOrganizationInventory && role == "runtime" && first[0] == "GET")
                            foreach (string key in new[] { "folders", "tags" })
                                if (response.Body[key] is JsonArray { Count: > 0 } items)
                                    items.Add(items[0]!.DeepClone());
                    }
                    byte[] output = JsonSerializer.SerializeToUtf8Bytes(response.Body);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Code} Fixture\r\n" +
                        $"Content-Type: application/json\r\nContent-Length: {output.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                    if (LoseResponse && role == "runtime" && (SelectedPath is null || uri.AbsolutePath == SelectedPath ||
                        uri.AbsolutePath.StartsWith(SelectedPath + "/", StringComparison.Ordinal)) &&
                        first[0] != "GET")
                    {
                        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                        await release.Task.WaitAsync(shutdown.Token);
                    }
                    await stream.WriteAsync(output, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }
        private (int, JsonObject) Handle(string method, Uri uri, string role, JsonObject b)
        {
            string path = uri.AbsolutePath;
            if (role == "denied") return (403, new());
            if (DenyCleanup && role == "administrative" && method == "DELETE") return (403, new());
            if (role == "runtime" && method != "GET")
            {
                runtimeMutations++;
                if (path == SelectedPath) selectedMutations++;
            }
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal)) return Folder(method, uri, b);
            if (path.Contains("/environments", StringComparison.Ordinal))
                return EnvironmentState(method, path, b, uri.Query.Contains("hardDelete=true", StringComparison.Ordinal));
            if (path.Contains("/tags", StringComparison.Ordinal)) return TagState(method, path, b);
            if (path.StartsWith("/api/v2/secret-imports", StringComparison.Ordinal)) return ImportState(method, uri, b, role);
            if (path.StartsWith("/api/v1/secret-validation-rules", StringComparison.Ordinal)) return RuleState(method, uri, b);
            if (path.StartsWith("/api/v4/secrets", StringComparison.Ordinal)) return SecretState(method, uri, b);
            return (404, new());
        }
        private static JsonObject Stamp() => new()
        {
            ["id"] = Guid.NewGuid().ToString(),
            ["createdAt"] = "2026-10-12T00:00:00Z",
            ["updatedAt"] = "2026-10-12T00:00:00Z"
        };
        private static string Text(JsonObject b, string key) => b[key]!.GetValue<string>();
        private static JsonObject Response(string key, JsonNode value) => new() { [key] = value.DeepClone() };
        private static JsonObject List(string key, IEnumerable<JsonObject> values) =>
            new() { [key] = new JsonArray(values.Select(v => v.DeepClone()).ToArray()) };
        private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&')
            .Select(v => v.Split('=', 2)).Where(v => v.Length == 2 && v[0] == key)
            .Select(v => Uri.UnescapeDataString(v[1])).Single();

        private (int, JsonObject) Folder(string method, Uri uri, JsonObject b)
        {
            string path = uri.AbsolutePath;
            if (method == "POST" && !path.EndsWith("/move", StringComparison.Ordinal))
            {
                JsonObject f = Stamp();
                f["name"] = Text(b, "name"); f["path"] = Text(b, "path") + "/" + Text(b, "name");
                f["envId"] = Text(b, "environment") == "env" ? EnvironmentId : ReplacementEnvironmentId;
                f["projectId"] = Text(b, "projectId");
                f["environment"] = new JsonObject { ["envSlug"] = Text(b, "environment") };
                f["description"] = b["description"]?.DeepClone();
                folders.Add(Text(f, "id"), f);
                return (200, Response("folder", f));
            }
            if (path.EndsWith("/batch", StringComparison.Ordinal))
            {
                var results = new List<JsonObject>();
                foreach (JsonObject change in b["folders"]!.AsArray().Cast<JsonObject>())
                {
                    if (PartialBatch && results.Count == 1) break;
                    JsonObject f = folders[Text(change, "id")];
                    f["name"] = change["name"]!.DeepClone();
                    f["path"] = Text(change, "path") + "/" + Text(change, "name");
                    if (change.ContainsKey("description")) f["description"] = change["description"]?.DeepClone();
                    results.Add(f);
                }
                return (200, List("folders", results));
            }
            if (path.EndsWith("/move", StringComparison.Ordinal))
            {
                JsonObject f = folders[Text(b, "folderId")];
                string oldPath = Text(f, "path");
                f["path"] = Text(b, "destinationPath") + "/" + Text(f, "name");
                return (200, new()
                {
                    ["folderId"] = Text(f, "id"),
                    ["sourceEnvironment"] = "env",
                    ["sourcePath"] = oldPath,
                    ["destinationEnvironment"] = Text(b, "destinationEnvironment"),
                    ["destinationPath"] = Text(b, "destinationPath")
                });
            }
            if (path == "/api/v2/folders")
            {
                string parent = Query(uri, "path");
                bool recursive = uri.Query.Contains("recursive=true", StringComparison.Ordinal);
                return (200, List("folders", folders.Values.Where(f =>
                    Text(f, "projectId") == Query(uri, "projectId") &&
                    Text(f["environment"]!.AsObject(), "envSlug") == Query(uri, "environment")).Where(f => recursive ?
                    Text(f, "path").StartsWith(parent + "/", StringComparison.Ordinal) :
                    Text(f, "path")[..Text(f, "path").LastIndexOf('/')] == parent)));
            }
            string selector = path.Split('/').Last();
            JsonObject? found = folders.Values.Where(f => method == "GET" ? Text(f, "id") == selector :
                Text(f, "id") == selector ||
                Text(f["environment"]!.AsObject(), "envSlug") == Text(b, "environment")).SingleOrDefault(f => Text(f, "id") == selector ||
                Text(f, "name") == selector && (method == "GET" ||
                    Text(f, "path") == Text(b, "path") + "/" + selector));
            if (found is null) return (404, new());
            if (method == "PATCH")
            {
                found["name"] = b["name"]!.DeepClone();
                found["path"] = Text(b, "path") + "/" + Text(b, "name");
                if (b.ContainsKey("description")) found["description"] = b["description"]?.DeepClone();
            }
            JsonObject result = Response("folder", found);
            if (method == "DELETE")
            {
                string ownedPath = Text(found, "path");
                string environment = Text(found["environment"]!.AsObject(), "envSlug");
                string project = Text(found, "projectId");
                foreach (var f in folders.Values.Where(f => Text(f, "projectId") == project &&
                    Text(f["environment"]!.AsObject(), "envSlug") == environment &&
                    (Text(f, "path") == ownedPath ||
                    Text(f, "path").StartsWith(ownedPath + "/", StringComparison.Ordinal))).ToArray())
                    folders.Remove(Text(f, "id"));
                foreach (var key in secrets.Keys.Where(k => k.Project == project && k.Environment == environment &&
                    (k.Folder == ownedPath || k.Folder.StartsWith(ownedPath + "/", StringComparison.Ordinal))).ToArray()) secrets.Remove(key);
                foreach (var item in imports.Values.Where(item => Text(item, "secretPath") == ownedPath).ToArray())
                    imports.Remove(Text(item, "id"));
            }
            return (200, result);
        }
        private (int, JsonObject) EnvironmentState(string method, string path, JsonObject b, bool hardDelete)
        {
            bool restore = path.EndsWith("/restore", StringComparison.Ordinal);
            string selector = path.Split('/')[restore ? ^2 : ^1];
            if (method == "POST" && !restore)
            {
                JsonObject e = Stamp();
                e["projectId"] = "project"; e["name"] = b["name"]!.DeepClone();
                e["slug"] = b["slug"]!.DeepClone(); e["position"] = b["position"]?.DeepClone() ?? JsonValue.Create(1);
                environments.Add(Text(e, "id"), e);
                return (200, Response("environment", e));
            }
            JsonObject? found = environments.Values.SingleOrDefault(e => Text(e, "id") == selector || Text(e, "slug") == selector);
            if (found is null) return (404, new());
            foreach (string field in new[] { "name", "slug", "position" })
                if (b.ContainsKey(field)) found[field] = b[field]!.DeepClone();
            if (restore) found["softDeletedAt"] = null;
            JsonObject result;
            if (method == "DELETE")
            {
                found["softDeletedAt"] = "2026-10-12T00:00:00Z";
                result = Response("environment", found);
                if (hardDelete) environments.Remove(Text(found, "id"));
            }
            else result = Response("environment", found);
            return (200, result);
        }
        private (int, JsonObject) TagState(string method, string path, JsonObject b)
        {
            if (method == "GET" && path.EndsWith("/tags", StringComparison.Ordinal)) return (200, List("tags", tags.Values));
            if (method == "POST")
            {
                JsonObject tag = Stamp(); tag["projectId"] = "project"; tag["slug"] = b["slug"]!.DeepClone();
                tag["color"] = b["color"]!.DeepClone(); tags.Add(Text(tag, "id"), tag);
                return (200, Response("tag", tag));
            }
            string selector = path.Split('/').Last();
            JsonObject? found = tags.Values.SingleOrDefault(t => Text(t, "id") == selector || Text(t, "slug") == selector);
            if (found is null) return (404, new());
            if (method == "PATCH") { found["slug"] = b["slug"]!.DeepClone(); found["color"] = b["color"]!.DeepClone(); }
            var result = Response("tag", found);
            if (method == "DELETE") tags.Remove(Text(found, "id"));
            return (200, result);
        }
        private (int, JsonObject) ImportState(string method, Uri uri, JsonObject b, string role)
        {
            string path = uri.AbsolutePath;
            if (path.EndsWith("/secrets", StringComparison.Ordinal))
            {
                string destination = Query(uri, "path");
                var groups = new List<JsonObject>();
                foreach (JsonObject import in imports.Values.Where(i => Text(i, "secretPath") == destination))
                {
                    string source = Text(import, "importPath");
                    string environment = Text(import["importEnv"]!.AsObject(), "slug");
                    string project = Text(import["importEnv"]!.AsObject(), "projectId");
                    string folderId = Text(folders.Values.Single(f => Text(f, "path") == source &&
                        Text(f, "projectId") == project &&
                        Text(f["environment"]!.AsObject(), "envSlug") == environment), "id");
                    JsonObject[] values = secrets.Where(s => s.Key.Project == project &&
                        s.Key.Environment == environment && s.Key.Folder == source).Select(s =>
                        Secret(s.Key.Key, WrongImportedValue ? "wrong" : s.Value.Value, s.Value.Version, project, environment)).ToArray();
                    groups.Add(new()
                    {
                        ["environment"] = environment,
                        ["secretPath"] = source,
                        ["folderId"] = folderId,
                        ["secrets"] = new JsonArray(values.Select(v => (JsonNode)v).ToArray())
                    });
                }
                if (!DuplicateObserverOnly || role == "observer")
                {
                    if (DuplicateImported == "groups" && groups.Count > 1)
                        groups[1] = groups[0].DeepClone().AsObject();
                    if (DuplicateImported == "items")
                        foreach (var group in groups)
                        {
                            var items = group["secrets"]!.AsArray();
                            if (items.Count > 1) items[1] = items[0]!.DeepClone();
                        }
                }
                return (200, List("secrets", groups));
            }
            if (method == "GET" && path == "/api/v2/secret-imports")
                return (200, List("secretImports", imports.Values.Where(i => Text(i, "secretPath") == Query(uri, "path"))));
            if (method == "POST")
            {
                JsonObject item = Stamp();
                string destination = Text(b, "path");
                item["folderId"] = Text(folders.Values.Single(f => Text(f, "path") == destination), "id");
                item["projectId"] = "project"; item["secretPath"] = destination;
                item["environment"] = new JsonObject { ["slug"] = "env" };
                JsonObject source = b["import"]!.AsObject();
                item["importPath"] = source["path"]!.DeepClone();
                item["importEnv"] = new JsonObject
                {
                    ["id"] = EnvironmentId,
                    ["name"] = "Env",
                    ["slug"] = Text(source, "environment"),
                    ["projectId"] = source["sourceProjectId"]?.DeepClone() ?? JsonValue.Create("project")
                };
                item["position"] = imports.Count + 1; item["isReplication"] = b["isReplication"]!.DeepClone();
                imports.Add(Text(item, "id"), item);
                return (200, Response("secretImport", item));
            }
            string id = path.Split('/').Last();
            if (!imports.TryGetValue(id, out JsonObject? found)) return (404, new());
            if (method == "PATCH")
            {
                JsonObject change = b["import"]!.AsObject();
                if (change.ContainsKey("path")) found["importPath"] = change["path"]!.DeepClone();
                if (change.ContainsKey("environment") && !(IgnoreImportEnvironmentChange && role == "runtime"))
                    found["importEnv"]!["slug"] = change["environment"]!.DeepClone();
                if (change.ContainsKey("position")) found["position"] = change["position"]!.DeepClone();
            }
            var result = Response("secretImport", found);
            if (method == "DELETE") imports.Remove(id);
            return (200, result);
        }
        private (int, JsonObject) RuleState(string method, Uri uri, JsonObject b)
        {
            string path = uri.AbsolutePath;
            if (method == "GET" && uri.Query.Length != 0) return (200, List("secretValidationRules", rules.Values));
            if (method == "POST")
            {
                JsonObject rule = Stamp();
                rule["type"] = path.Split('/').Last(); rule["projectId"] = "project";
                foreach (var field in b) rule[field.Key] = field.Value?.DeepClone();
                rule["environment"] = b["environment"] is null ? null :
                    new JsonObject { ["id"] = EnvironmentId, ["name"] = "Env", ["slug"] = Text(b, "environment") };
                rules.Add(Text(rule, "id"), rule);
                return (200, Response("secretValidationRule", rule));
            }
            string id = path.Split('/').Last();
            if (!rules.TryGetValue(id, out JsonObject? found)) return (404, new());
            if (method == "PATCH")
                foreach (var field in b)
                {
                    if (field.Key == "environment") found[field.Key] = field.Value is null ? null :
                        new JsonObject { ["id"] = EnvironmentId, ["name"] = "Env", ["slug"] = field.Value.DeepClone() };
                    else if (field.Value is null && field.Key.EndsWith("Constraints", StringComparison.Ordinal)) found.Remove(field.Key);
                    else found[field.Key] = field.Value?.DeepClone();
                }
            var result = Response("secretValidationRule", found);
            if (method == "DELETE") rules.Remove(id);
            return (200, result);
        }
        private static JsonObject Secret(string key, string value, int version, string project = "project", string environment = "env") => new()
        {
            ["secretKey"] = key,
            ["secretValue"] = value,
            ["secretValueHidden"] = false,
            ["workspace"] = project,
            ["environment"] = environment,
            ["type"] = "shared",
            ["version"] = version
        };
        private (int, JsonObject) SecretState(string method, Uri uri, JsonObject b)
        {
            string key = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
            if (method == "GET")
            {
                string folder = Query(uri, "secretPath");
                string project = Query(uri, "projectId"), environment = Query(uri, "environment");
                if (secrets.TryGetValue((project, environment, folder, key), out var value))
                    return (200, Response("secret", Secret(key, value.Value, value.Version, project, environment)));
                foreach (JsonObject import in imports.Values.Where(i => Text(i, "secretPath") == folder))
                    if (secrets.TryGetValue((Text(import["importEnv"]!.AsObject(), "projectId"),
                        DeliverFromOldEnvironment ? "env" : Text(import["importEnv"]!.AsObject(), "slug"),
                        Text(import, "importPath"), key), out value))
                        return (200, Response("secret", Secret(key, WrongImportedValue ? "wrong" : value.Value, value.Version, project, environment)));
                return (404, new());
            }
            string selectedFolder = Text(b, "secretPath");
            if (uri.AbsolutePath.EndsWith("/batch", StringComparison.Ordinal))
            {
                foreach (JsonObject item in b["secrets"]!.AsArray().Cast<JsonObject>())
                    secrets.Remove((Text(b, "projectId"), Text(b, "environment"), selectedFolder, Text(item, "secretKey")));
                return (200, List("secrets", b["secrets"]!.AsArray().Cast<JsonObject>().Select(item =>
                    new JsonObject
                    {
                        ["secretKey"] = Text(item, "secretKey"),
                        ["workspace"] = Text(b, "projectId"),
                        ["environment"] = Text(b, "environment"),
                        ["version"] = 1,
                        ["type"] = "shared"
                    })));
            }
            string material = Text(b, "secretValue");
            if (!IgnoreValidation)
                foreach (JsonObject rule in rules.Values.Where(r => Text(r, "secretPath") == selectedFolder &&
                    r["isActive"]?.GetValue<bool>() != false))
                {
                    string? regex = rule["valueConstraints"]?["regexPattern"]?.GetValue<string>();
                    if (regex is not null && !Regex.IsMatch(material, regex)) return (400, new());
                }
            var coordinate = (Text(b, "projectId"), Text(b, "environment"), selectedFolder, key);
            int version = secrets.TryGetValue(coordinate, out var old) ? old.Version + 1 : 1;
            secrets[coordinate] = (material, version);
            return (200, Response("secret", Secret(key, material, version, Text(b, "projectId"), Text(b, "environment"))));
        }
        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
