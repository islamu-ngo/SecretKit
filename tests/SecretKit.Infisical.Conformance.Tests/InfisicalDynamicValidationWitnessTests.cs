using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicValidationWitnessTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string Password32 = "aaaaaaaaAAAAAAAA11111111!!!!!!!!";
    // Active validation rules impose length, not the definition's category counts.
    private const string Policy24 = "abcdefghijklmnopqr_-.~!1";
    private const string Policy32 = "abcdefghijklmnopqrstuvwxyz_-.~!1";
    private static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments("CreateValidationRuleAsync", "kind.DynamicSecrets", "independent-effect", "active")]
    [Arguments("CreateValidationRuleAsync", "DynamicSecrets.SqlDatabase", "selected-contract", "active")]
    [Arguments("CreateValidationRuleAsync", "isActive.false", "independent-effect", "inactive")]
    [Arguments("CreateValidationRuleAsync", "kind.DynamicSecrets", "denied-authority", "active")]
    [Arguments("CreateValidationRuleAsync", "kind.DynamicSecrets", "cancellation-boundary", "active")]
    [Arguments("CreateValidationRuleAsync", "kind.DynamicSecrets", "lost-response-no-replay", "active")]
    [Arguments("UpdateValidationRuleAsync", "DynamicSecrets.SqlDatabase", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.DynamicSecrets", "denied-authority", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.DynamicSecrets", "cancellation-boundary", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.DynamicSecrets", "lost-response-no-replay", "active")]
    [Arguments("UpdateValidationRuleAsync", "isActive.true", "independent-effect", "activate")]
    [Arguments("UpdateValidationRuleAsync", "isActive.false", "independent-effect", "deactivate")]
    [Arguments("DeleteValidationRuleAsync", "kind.DynamicSecrets", "independent-effect", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.DynamicSecrets", "denied-authority", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.DynamicSecrets", "cancellation-boundary", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.DynamicSecrets", "lost-response-no-replay", "active")]
    [Arguments("GetValidationRuleAsync", "kind.DynamicSecrets", "independent-effect", "active")]
    [Arguments("GetValidationRuleAsync", "kind.DynamicSecrets", "denied-authority", "active")]
    [Arguments("ListValidationRulesAsync", "kind.DynamicSecrets", "independent-effect", "active")]
    [Arguments("ListValidationRulesAsync", "kind.DynamicSecrets", "denied-authority", "active")]
    public async Task RuleMutationMeasuresBothActualCredentialsWithoutChangingDefinition(
        string method, string variant, string boundary, string transition)
    {
        // Given independently stored rules, provider records, roles and issuance.
        await using var wire = new ValidationWire();
        bool applied = boundary is not "denied-authority" and not "cancellation-boundary";
        var input = Input(method, applied, transition);
        // When the registered family executes actual native CRUD and typed SQL acquisition.
        var result = await RunAsync(wire, method, variant, boundary, input);
        // Then both issued pairs, wrong-password controls and cleanup are independently witnessed.
        bool mutation = method is "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" or "DeleteValidationRuleAsync";
        await Assert.That(wire.RuntimeMutations).IsEqualTo(mutation && applied ? 1 : 0);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(wire.Issued.Count).IsEqualTo(2);
        await Assert.That(wire.Issued.Select(i => i.DefinitionId).Distinct().Count()).IsEqualTo(1);
        await Assert.That(wire.Issued.Select(i => i.User).Distinct().Count()).IsEqualTo(2);
        await Assert.That(wire.DefinitionUpdates).IsEqualTo(0);
        await Assert.That(wire.DefinitionCreates).IsEqualTo(1);
        await Assert.That(wire.ProjectInventoryBeforeOwnership).IsTrue();
        await Assert.That(wire.ProjectInventoriesOnly).IsTrue();
        await Assert.That(wire.AdminAcquisitionsOnly).IsTrue();
        await Assert.That(wire.NonforceRevocationsOnly).IsTrue();
        await Assert.That(wire.Issued[0].Password.Reveal().Length).IsEqualTo(
            method == "CreateValidationRuleAsync" || transition == "activate" ? 32 : 24);
        int after = method switch
        {
            "CreateValidationRuleAsync" => applied && transition != "inactive" ? 24 : 32,
            "UpdateValidationRuleAsync" => transition == "activate" ? 24 :
                transition == "deactivate" || applied ? 32 : 24,
            "DeleteValidationRuleAsync" => applied ? 32 : 24,
            _ => 24
        };
        await Assert.That(wire.Issued[1].Password.Reveal().Length).IsEqualTo(after);
        await Assert.That(wire.BaselineAcceptedWithFreshCredential).IsTrue();
        await Assert.That(wire.Issued.All(i => wire.Accepted.Contains(i.Id) &&
            wire.WrongPasswordRejected.Contains(i.Id) && wire.AcceptedAgain.Contains(i.Id) &&
            wire.RejectedAfterCleanup.Contains(i.Id))).IsTrue();
        await Assert.That(wire.FinalInventoryCoversEveryIssuedName).IsTrue();
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ignored-rule", "effect-mismatch")]
    [Arguments("wrong-length", "effect-mismatch")]
    [Arguments("wrong-alphabet", "effect-mismatch")]
    [Arguments("wrong-credentials", "effect-mismatch")]
    [Arguments("reject-auth", "effect-mismatch")]
    [Arguments("password-ignored", "effect-mismatch")]
    [Arguments("unavailable", "observer-unavailable")]
    [Arguments("wrong-coordinate", "effect-mismatch")]
    [Arguments("wrong-actions", "effect-mismatch")]
    [Arguments("wrong-expiry", "effect-mismatch")]
    [Arguments("premature-revoke", "effect-mismatch")]
    [Arguments("retain-baseline", "cleanup-incomplete")]
    [Arguments("retain-fresh", "cleanup-incomplete")]
    [Arguments("retain-lease", "cleanup-incomplete")]
    [Arguments("retain-definition", "cleanup-incomplete")]
    [Arguments("retain-rule", "cleanup-incomplete")]
    [Arguments("cleanup-ack", "cleanup-incomplete")]
    [Arguments("lost-issuance", "cleanup-incomplete")]
    public async Task MetadataCannotCertifyIssuanceAuthenticationOrAbsence(string mode, string reason)
    {
        // Given a metadata-correct rule and an independently injected downstream fault.
        await using var wire = new ValidationWire(mode);
        // When a single active rule changes from 24 to 32.
        var result = await RunAsync(wire, "UpdateValidationRuleAsync");
        // Then the actual fault, not a provider acknowledgement, determines the result.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.Issued.Count).IsGreaterThan(0);
        if (mode is "retain-baseline" or "retain-fresh" or "cleanup-ack")
            await Assert.That(wire.RoleCount).IsGreaterThan(0);
        else
            await Assert.That(wire.RoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("other-active", "missing-prerequisite")]
    [Arguments("other-inactive", "missing-prerequisite")]
    [Arguments("incomplete-project", "observer-unavailable")]
    [Arguments("unbound-project", "observer-unavailable")]
    [Arguments("missing-backend", "observer-unavailable")]
    [Arguments("missing-trial", "missing-input")]
    [Arguments("missing-project-slug", "missing-input")]
    [Arguments("bad-ttl", "missing-input")]
    [Arguments("unsupported-profile", "observer-unavailable")]
    [Arguments("unsupported-constraint", "observer-unavailable")]
    [Arguments("unsupported-provider", "observer-unavailable")]
    [Arguments("unscoped-rule", "observer-unavailable")]
    public async Task AdmissionRequiresExclusiveCompleteProjectAndSupportedInputs(string mode, string reason)
    {
        // Given a prerequisite or input that cannot establish the narrow owned witness.
        await using var wire = new ValidationWire(mode);
        var input = Input("CreateValidationRuleAsync");
        switch (mode)
        {
            case "missing-trial": input["dynamicTrial"] = null; break;
            case "missing-project-slug": input["dynamicTrial"]!.AsObject().Remove("projectSlug"); break;
            case "bad-ttl": input["dynamicTrial"]!["maximumSeconds"] = 30; break;
            case "unsupported-profile": input["dynamicTrial"]!["profile"]!["engine"] = "Mysql"; break;
            case "unsupported-constraint": input["change"]!["passwordConstraints"]!["regexPattern"] = "^safe"; break;
            case "unsupported-provider": input["change"]!["providers"] = new JsonArray("Milvus"); break;
            case "unscoped-rule": input["change"]!["supplyEnvironment"] = false; break;
        }
        // When admission precedes any ownership or provider mutation.
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: input,
            supplyBackend: mode != "missing-backend");
        // Then unrelated rules are never adopted or removed.
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(0);
        await Assert.That(wire.UnrelatedRuleCount).IsEqualTo(mode.StartsWith("other-", StringComparison.Ordinal) ? 1 : 0);
    }

    [Test]
    public async Task FixtureRuleStorageControlsPasswordsAndRecordDeletionCannotEraseRoles()
    {
        // Given the strict backend used by the public SDK witnesses.
        await using var wire = new ValidationWire();
        // When its independent rule store is replaced and provider records disappear.
        // Then immutable issuance still authenticates until strict lease revocation.
        await wire.VerifyStorageAsync();
    }

    [Test]
    [Arguments("UpdateValidationRuleAsync", "regex", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "prefix", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "suffix", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "combined", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "no-regex", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "bare24", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "bare32", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "prefix-only", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "suffix-only", "independent-effect", "active")]
    [Arguments("CreateValidationRuleAsync", "combined", "independent-effect", "active")]
    [Arguments("CreateValidationRuleAsync", "combined", "independent-effect", "inactive")]
    [Arguments("DeleteValidationRuleAsync", "combined", "independent-effect", "active")]
    [Arguments("GetValidationRuleAsync", "combined", "independent-effect", "active")]
    [Arguments("ListValidationRulesAsync", "combined", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "combined", "independent-effect", "activate")]
    [Arguments("UpdateValidationRuleAsync", "combined", "independent-effect", "deactivate")]
    [Arguments("CreateValidationRuleAsync", "combined", "denied-authority", "active")]
    [Arguments("CreateValidationRuleAsync", "combined", "cancellation-boundary", "active")]
    [Arguments("CreateValidationRuleAsync", "combined", "lost-response-no-replay", "active")]
    [Arguments("UpdateValidationRuleAsync", "regex", "denied-authority", "active")]
    [Arguments("UpdateValidationRuleAsync", "prefix", "cancellation-boundary", "active")]
    [Arguments("UpdateValidationRuleAsync", "suffix", "lost-response-no-replay", "active")]
    [Arguments("DeleteValidationRuleAsync", "combined", "denied-authority", "active")]
    [Arguments("DeleteValidationRuleAsync", "combined", "cancellation-boundary", "active")]
    [Arguments("DeleteValidationRuleAsync", "combined", "lost-response-no-replay", "active")]
    [Arguments("GetValidationRuleAsync", "combined", "denied-authority", "active")]
    [Arguments("ListValidationRulesAsync", "combined", "denied-authority", "active")]
    public async Task RuleRegexAndAffixTransitionsMeasureActualCredentials(
        string method, string shape, string boundary, string transition)
    {
        await using var wire = new ValidationWire();
        bool applied = boundary is not "denied-authority" and not "cancellation-boundary";
        var input = ShapeInput(method, shape, applied, transition);
        var result = await RunAsync(wire, method, input: input, boundary: boundary);
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        bool mutation = method is "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" or "DeleteValidationRuleAsync";
        await Assert.That(wire.RuntimeMutations).IsEqualTo(mutation && applied ? 1 : 0);
        await Assert.That(wire.Issued.Count).IsEqualTo(2);
        string seed = shape == "no-regex" ? "A_" + Policy24[..20] + "_A" : "A_" + new string('A', 24) + "_A";
        if (shape is "bare24" or "bare32") seed = new string('A', 24);
        if (shape == "prefix-only") seed = "A_" + new string('A', 24);
        if (shape == "suffix-only") seed = new string('A', 24) + "_A";
        string changed = shape switch
        {
            "regex" => "A_" + new string('a', 24) + "_A",
            "bare24" or "bare32" => new string('a', 24),
            "prefix-only" => "B_" + new string('A', 24),
            "suffix-only" => new string('A', 24) + "_B",
            "prefix" => "B_" + new string('A', 24) + "_A",
            "suffix" => "A_" + new string('A', 24) + "_B",
            "no-regex" => "B_" + Policy32[..28] + "_B",
            _ => seed
        };
        string before = method == "CreateValidationRuleAsync" || transition == "activate" ? Password32 : seed;
        string after = method switch
        {
            "CreateValidationRuleAsync" => applied && transition != "inactive" ? changed : Password32,
            "UpdateValidationRuleAsync" => transition == "activate" ? changed :
                transition == "deactivate" ? applied ? Password32 : seed : applied ? changed : seed,
            "DeleteValidationRuleAsync" => applied ? Password32 : seed,
            _ => seed
        };
        await Assert.That(wire.Issued[0].Password.Reveal() == before).IsTrue();
        await Assert.That(wire.Issued[1].Password.Reveal() == after).IsTrue();
        await Assert.That(wire.DefinitionCreates).IsEqualTo(1);
        await Assert.That(wire.DefinitionUpdates).IsEqualTo(0);
        await Assert.That(wire.Issued.Select(i => i.DefinitionId).Distinct().Count()).IsEqualTo(1);
        await Assert.That(wire.Issued.Select(i => i.User).Distinct().Count()).IsEqualTo(2);
        await Assert.That(wire.BaselineAcceptedWithFreshCredential).IsTrue();
        await Assert.That(wire.Issued.All(i => wire.Accepted.Contains(i.Id) &&
            wire.WrongPasswordRejected.Contains(i.Id) && wire.AcceptedAgain.Contains(i.Id) &&
            wire.RejectedAfterCleanup.Contains(i.Id))).IsTrue();
        await Assert.That(wire.ProjectInventoryBeforeOwnership && wire.ProjectInventoriesOnly &&
            wire.AdminAcquisitionsOnly && wire.NonforceRevocationsOnly &&
            wire.FinalInventoryCoversEveryIssuedName).IsTrue();
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ignored-regex")]
    [Arguments("wrong-case")]
    [Arguments("missing-prefix")]
    [Arguments("swapped-prefix")]
    [Arguments("missing-suffix")]
    [Arguments("swapped-suffix")]
    [Arguments("bounds-override-regex")]
    public async Task RegexAndAffixGenerationFaultsCannotCertifyMetadata(string mode)
    {
        await using var wire = new ValidationWire(mode);
        var result = await RunAsync(wire, "UpdateValidationRuleAsync",
            input: ShapeInput("UpdateValidationRuleAsync", "regex"));
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.Issued.Count).IsEqualTo(2);
        await Assert.That(wire.DefinitionUpdates).IsEqualTo(0);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
        await Assert.That(wire.FinalInventoryCoversEveryIssuedName).IsTrue();
    }

    [Test]
    [Arguments("regexPattern", "^safe")]
    [Arguments("regexPattern", "^[A-Z]{32}$")]
    [Arguments("regexPattern", "[A-Z]{24}")]
    [Arguments("requiredPrefix", "C_")]
    [Arguments("requiredPrefix", "")]
    [Arguments("requiredSuffix", "_C")]
    [Arguments("requiredSuffix", "")]
    [Arguments("uniqueAcrossLastVersions", "1")]
    [Arguments("uniqueWithinScope", "true")]
    [Arguments("clearEnvironment", "true")]
    [Arguments("clearKeyConstraints", "true")]
    [Arguments("clearValueConstraints", "true")]
    public async Task ArbitraryShapesReuseAndClearsRemainUnavailableBeforeOwnership(string field, string value)
    {
        await using var wire = new ValidationWire();
        var input = Input("CreateValidationRuleAsync");
        var change = input["change"]!.AsObject();
        if (field.StartsWith("clear", StringComparison.Ordinal)) change[field] = true;
        else change["passwordConstraints"]![field] = field == "uniqueAcrossLastVersions" ? JsonValue.Create(1) :
            field == "uniqueWithinScope" ? JsonValue.Create(true) : JsonValue.Create(value);
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: input);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.Issued.Count).IsEqualTo(0);
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
    }

    [Test]
    public async Task SafeStarInActiveRuleCredentialIsObserved()
    {
        await using var wire = new ValidationWire("safe-star");
        var result = await RunAsync(wire, "UpdateValidationRuleAsync");
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(wire.Issued[1].Password.Reveal().Contains('*')).IsTrue();
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.RoleCount).IsEqualTo(0);
    }

    private static JsonObject ShapeInput(string method, string shape, bool applied = true, string transition = "active")
    {
        var input = Input(method, applied, transition);
        foreach (string slot in new[] { "seed", "change" })
        {
            bool changed = slot == "change";
            var constraints = input[slot]!["passwordConstraints"]!;
            constraints["minimumLength"] = shape == "bare24" ? 24 : shape == "no-regex" ? changed ? 32 : 24 : 32;
            constraints["maximumLength"] = shape == "bare24" ? 24 : shape == "no-regex" ? changed ? 32 : 24 : 32;
            constraints["regexPattern"] = shape == "no-regex" ? null :
                changed && shape is "regex" or "bare24" or "bare32" ? "^[a-z]{24}$" : "^[A-Z]{24}$";
            constraints["requiredPrefix"] = shape is "bare24" or "bare32" or "suffix-only" ? null :
                changed && shape is "prefix" or "prefix-only" or "no-regex" ? "B_" : "A_";
            constraints["requiredSuffix"] = shape is "bare24" or "bare32" or "prefix-only" ? null :
                changed && shape is "suffix" or "suffix-only" or "no-regex" ? "_B" : "_A";
        }
        return input;
    }

    private static JsonObject Input(string method, bool applied = true, string transition = "active")
    {
        ValidationPoliciesEffects.RuleInput Rule(int length, bool active) => new(null, null, active,
            null, null, new(length, length, null, null, null, null, null),
            [InfisicalValidationProvider.SqlDatabase], true, true, false, false, false, false);
        var seed = Rule(24, transition != "activate");
        var change = method == "UpdateValidationRuleAsync" && transition == "active" ? Rule(32, true) :
            Rule(24, transition is not "inactive" and not "deactivate");
        return JsonSerializer.SerializeToNode(new ValidationPoliciesEffects.PolicyInput(
            new("project", "env", EnvironmentId, "/owned", [], StaticApiRevision.SecretsV4FoldersV2),
            InfisicalValidationKind.DynamicSecrets, seed, change,
            [], [],
            1000, false, applied, true,
            new(new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database", "admin", "private-password",
                "create-role", "revoke-role", "renew-role", null, false, null, null,
                new(32, 8, 8, 8, 8, "!")), 60, 300, ["select"], ["write"], "project-slug")), Options)!.AsObject();
    }

    private static async Task<NativeCaseResult> RunAsync(ValidationWire wire, string method,
        string variant = "kind.DynamicSecrets", string boundary = "independent-effect",
        JsonObject? input = null, bool supplyBackend = true)
    {
        bool read = method is "GetValidationRuleAsync" or "ListValidationRulesAsync";
        string operation = "i.runtime.InfisicalClient." + method;
        string member = method switch
        {
            "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalValidationInput,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            "DeleteValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            "GetValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            "ListValidationRulesAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,System.Int32,System.Boolean,System.Threading.CancellationToken)",
            _ => throw new ArgumentOutOfRangeException(nameof(method))
        };
        var row = new NativeCaseDefinition(new("Infisical", operation, variant, "offline", boundary), member);
        var families = new JsonObject
        {
            ["C08-IR-ValidationPolicies"] = new JsonObject
            {
                ["scopes"] = new JsonObject
                {
                    ["offline"] = new JsonObject
                    {
                        [operation] = new JsonObject
                        {
                            [variant] = new JsonObject
                            {
                                [boundary] = input ?? Input(method,
                                    boundary != "denied-authority" && (read || boundary != "cancellation-boundary"))
                            }
                        }
                    }
                }
            }
        };
        using var env = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = wire.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, Options));
        var registry = new NativeCaseRegistry();
        ValidationPoliciesEffects.Register(registry, env, [row], supplyBackend ? wire : null);
        return (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
    }

    // Native records, retained SQL roles, and immutable issued credentials have
    // distinct stores. A rule update replaces its constraint object; issuance
    // consults that stored rule, never the selected operation or its acknowledgement.
    private sealed class ValidationWire : IAsyncDisposable, IInfisicalDynamicBackendObserver,
        IInfisicalDynamicUsernameObserver
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<string, JsonObject> rules = [];
        private readonly Dictionary<string, Definition> definitions = [];
        private readonly Dictionary<Guid, Issuance> leases = [];
        private readonly Dictionary<string, Issuance> roles = [];
        private readonly string mode;
        private readonly Task accept;
        private const string UnrelatedId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
        internal Uri Origin { get; }
        internal List<Issuance> Issued { get; } = [];
        internal HashSet<Guid> Accepted { get; } = [];
        internal HashSet<Guid> WrongPasswordRejected { get; } = [];
        internal HashSet<Guid> AcceptedAgain { get; } = [];
        internal HashSet<Guid> RejectedAfterCleanup { get; } = [];
        internal int ProviderMutations { get; private set; }
        internal int RuntimeMutations { get; private set; }
        internal int DefinitionCreates { get; private set; }
        internal int DefinitionUpdates { get; private set; }
        internal bool ProjectInventoryBeforeOwnership { get; private set; }
        internal bool ProjectInventoriesOnly { get; private set; } = true;
        internal bool AdminAcquisitionsOnly { get; private set; } = true;
        internal bool NonforceRevocationsOnly { get; private set; } = true;
        internal bool BaselineAcceptedWithFreshCredential { get; private set; }
        internal bool FinalInventoryCoversEveryIssuedName { get; private set; }
        internal int UnrelatedRuleCount => rules.ContainsKey(UnrelatedId) ? 1 : 0;
        internal int RecordCount { get { lock (folders) return folders.Count + rules.Count + definitions.Count + leases.Count; } }
        internal int RoleCount { get { lock (folders) return roles.Count; } }

        internal ValidationWire(string mode = "good")
        {
            this.mode = mode;
            if (mode.StartsWith("other-", StringComparison.Ordinal))
                rules[UnrelatedId] = ExternalRule(UnrelatedId, "project", mode == "other-active");
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
                    var stream = socket.GetStream();
                    var headers = new List<byte>();
                    byte[] one = new byte[1];
                    while (headers.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        headers.Add(one[0]);
                        if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string principal = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                        .Split(' ').Last() ?? "";
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                        .Split(':')[1] ?? "0");
                    if (length is < 0 or > 1048576) throw new InvalidOperationException("offline-budget");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    var json = JsonNode.Parse(length == 0 ? "{}"u8.ToArray() : body)!.AsObject();
                    (int Status, object Payload) result;
                    lock (folders) result = Handle(request[0], new(Origin, request[1]), principal, json);
                    byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                        shutdown.Token);
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private static string Text(JsonObject body, string field) => body[field]?.GetValue<string>() ?? "";
        private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&')
            .Where(p => p.StartsWith(key + "=", StringComparison.Ordinal))
            .Select(p => Uri.UnescapeDataString(p[(key.Length + 1)..])).SingleOrDefault() ?? "";
        private static object Response(string key, JsonObject value) => new JsonObject { [key] = value.DeepClone() };

        private (int, object) Handle(string method, Uri uri, string principal, JsonObject body)
        {
            string path = uri.AbsolutePath;
            if (principal == "denied") return (403, new { });
            if (method is "POST" or "PATCH" or "DELETE") ProviderMutations++;
            if (path.StartsWith("/api/v1/secret-validation-rules", StringComparison.Ordinal))
                return RuleState(method, uri, principal, body);
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString("D");
                    folders[id] = (Text(body, "name"), Text(body, "path").TrimEnd('/') + "/" + Text(body, "name"));
                    return (200, new { folder = Folder(id) });
                }
                if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
                string selector = Uri.UnescapeDataString(path.Split('/').Last());
                string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
                if (found is null) return (404, new { });
                object folder = Folder(found);
                if (method == "DELETE") folders.Remove(found);
                return (200, new { folder });
            }
            if (!path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal)) return (404, new { });
            if (path == "/api/v1/dynamic-secrets")
            {
                if (method == "GET") return (200, new { dynamicSecrets = definitions.Values.Select(DefinitionJson).ToArray() });
                DefinitionCreates++;
                var definition = new Definition(Guid.NewGuid(), Text(body, "name"),
                    folders.Single(f => f.Value.Path == Text(body, "path")).Key,
                    Text(body, "defaultTTL"), Text(body, "maxTTL"), Text(body, "path"));
                definitions.Add(definition.Name, definition);
                return (200, new { dynamicSecret = DefinitionJson(definition) });
            }
            if (path == "/api/v1/dynamic-secrets/leases")
            {
                AdminAcquisitionsOnly &= principal == "administrative";
                var definition = definitions[Text(body, "dynamicSecretName")];
                var rule = rules.Values.SingleOrDefault(r => Text(r, "projectId") == "project" &&
                    r["environment"]?["slug"]?.GetValue<string>() == "env" &&
                    Text(r, "secretPath") == definition.Path && r["isActive"]?.GetValue<bool>() == true);
                int? length = rule?["passwordConstraints"]?["minLength"]?.GetValue<int>();
                string password = mode == "ignored-rule" ? Password32 : length switch
                {
                    24 => Policy24,
                    32 => Policy32,
                    _ => Password32
                };
                if (rule is not null && mode != "ignored-rule")
                {
                    var constraints = rule["passwordConstraints"]!.AsObject();
                    string regex = Text(constraints, "regexPattern");
                    string prefix = Text(constraints, "requiredPrefix");
                    string suffix = Text(constraints, "requiredSuffix");
                    // Pinned provider generation facts: regex makes the middle; affixes wrap it.
                    // Without regex, the final length includes both affixes.
                    string middle = regex switch
                    {
                        "^[A-Z]{24}$" => new string('A', 24),
                        "^[a-z]{24}$" => new string('a', 24),
                        "" => password[..(password.Length - prefix.Length - suffix.Length)],
                        _ => throw new InvalidOperationException("unsupported-fixture-regex")
                    };
                    if (Issued.Count > 0)
                    {
                        if (mode == "ignored-regex") middle = Policy24;
                        if (mode == "wrong-case") middle = new string(regex == "^[a-z]{24}$" ? 'A' : 'a', 24);
                        if (mode == "missing-prefix") prefix = "";
                        if (mode == "swapped-prefix") prefix = prefix == "A_" ? "B_" : "A_";
                        if (mode == "missing-suffix") suffix = "";
                        if (mode == "swapped-suffix") suffix = suffix == "_A" ? "_B" : "_A";
                        if (mode == "bounds-override-regex") middle = new string('a', length!.Value - prefix.Length - suffix.Length);
                    }
                    password = prefix + middle + suffix;
                }
                if (Issued.Count > 0)
                {
                    if (mode == "wrong-length") password = "abcdefghijklmnopqrstuvw";
                    if (mode == "wrong-alphabet") password = password[..^1] + "?";
                    if (mode == "safe-star") password = password[..^1] + "*";
                }
                var issuance = new Issuance(Guid.NewGuid(), definition.Id,
                    "sk_generated_" + Guid.NewGuid().ToString("N"), SecretMaterial.FromText(password));
                if (!roles.TryAdd(issuance.User, issuance)) throw new InvalidOperationException("duplicate-role");
                leases.Add(issuance.Id, issuance);
                Issued.Add(issuance);
                if (mode == "lost-issuance")
                    return (200, new { dynamicSecret = DefinitionJson(definition), lease = LeaseJson(issuance), data = new { } });
                return (200, new
                {
                    dynamicSecret = DefinitionJson(definition),
                    lease = LeaseJson(issuance),
                    data = new
                    {
                        DB_USERNAME = issuance.User,
                        DB_PASSWORD = mode == "wrong-credentials" && Issued.Count > 1 ? Password32 : issuance.Password.Reveal()
                    }
                });
            }
            string[] segments = path.Split('/');
            if (segments[4] == "leases")
            {
                Guid id = Guid.Parse(segments[5]);
                if (!leases.TryGetValue(id, out var lease)) return (404, new { });
                if (method == "DELETE")
                {
                    bool forced = body["isForced"]?.GetValue<bool>() == true;
                    NonforceRevocationsOnly &= !forced;
                    if (mode != "retain-lease") leases.Remove(id);
                    bool baseline = Issued[0] == lease;
                    if (!forced && !(mode == "retain-baseline" && baseline || mode == "retain-fresh" && !baseline || mode == "cleanup-ack"))
                        roles.Remove(lease.User);
                }
                return (200, new { lease = LeaseJson(lease) });
            }
            string name = Uri.UnescapeDataString(segments[4]);
            if (!definitions.TryGetValue(name, out var foundDefinition)) return (404, new { });
            if (segments.Length > 5)
                return (200, new { leases = leases.Values.Where(l => l.DefinitionId == foundDefinition.Id).Select(LeaseJson).ToArray() });
            if (method == "PATCH") DefinitionUpdates++;
            // Definition removal deliberately does not touch the backend role store.
            if (method == "DELETE" && mode != "retain-definition") definitions.Remove(name);
            return (200, new { dynamicSecret = DefinitionJson(foundDefinition) });
        }

        private (int, object) RuleState(string method, Uri uri, string principal, JsonObject body)
        {
            string collection = "/api/v1/secret-validation-rules/dynamic-secrets";
            if (method == "GET" && uri.AbsolutePath == collection)
            {
                bool bound = Query(uri, "projectId") == "project" &&
                    Query(uri, "environment") == "" && Query(uri, "secretPath") == "";
                ProjectInventoriesOnly &= bound;
                if (ProviderMutations == 0 && bound) ProjectInventoryBeforeOwnership = true;
                if (mode == "unbound-project") return (200, new
                {
                    secretValidationRules = new[] { ExternalRule(UnrelatedId, "other", false) }
                });
                if (mode == "incomplete-project") return (200, new
                {
                    secretValidationRules = Enumerable.Range(1, 1001).Select(n =>
                        ExternalRule(new Guid(n, 0, 0, new byte[8]).ToString("D"), "project", false)).ToArray()
                });
                return (200, new JsonObject
                {
                    ["secretValidationRules"] = new JsonArray(rules.Values.Select(r => r.DeepClone()).ToArray())
                });
            }
            if (principal == "runtime" && method is "POST" or "PATCH" or "DELETE")
            {
                RuntimeMutations++;
                if (mode == "premature-revoke" && Issued.Count > 0) roles.Remove(Issued[0].User);
            }
            if (method == "POST")
            {
                string id = Guid.NewGuid().ToString("D");
                var rule = new JsonObject
                {
                    ["id"] = id,
                    ["type"] = "dynamic-secrets",
                    ["projectId"] = "project",
                    ["createdAt"] = Epoch,
                    ["updatedAt"] = Epoch
                };
                ReplaceRule(rule, body);
                rules.Add(id, rule);
                return (200, Response("secretValidationRule", rule));
            }
            string selector = uri.AbsolutePath.Split('/').Last();
            if (!rules.TryGetValue(selector, out var found)) return (404, new { });
            if (method == "PATCH") ReplaceRule(found, body);
            var result = Response("secretValidationRule", found);
            if (method == "DELETE" && !(mode == "retain-rule" && principal == "administrative")) rules.Remove(selector);
            return (200, result);
        }

        private static void ReplaceRule(JsonObject rule, JsonObject body)
        {
            foreach (var field in body)
                rule[field.Key] = field.Key == "environment" && field.Value is not null ?
                    new JsonObject { ["id"] = EnvironmentId, ["name"] = "Env", ["slug"] = field.Value.DeepClone() } :
                    field.Value?.DeepClone();
        }

        private static JsonObject ExternalRule(string id, string project, bool active) => new()
        {
            ["id"] = id,
            ["name"] = "external-" + id,
            ["type"] = "dynamic-secrets",
            ["projectId"] = project,
            ["isActive"] = active,
            ["environment"] = new JsonObject { ["id"] = EnvironmentId, ["name"] = "Other", ["slug"] = "elsewhere" },
            ["secretPath"] = "/elsewhere",
            ["providers"] = new JsonArray("sql-database"),
            ["passwordConstraints"] = new JsonObject { ["minLength"] = 24, ["maxLength"] = 24 },
            ["createdAt"] = Epoch,
            ["updatedAt"] = Epoch
        };

        private object Folder(string id) => new
        {
            id,
            envId = EnvironmentId,
            name = folders[id].Name,
            path = folders[id].Path,
            projectId = "project",
            environment = new { envSlug = "env" },
            createdAt = Epoch,
            updatedAt = Epoch
        };
        private static object DefinitionJson(Definition definition) => new
        {
            id = definition.Id,
            name = definition.Name,
            folderId = definition.FolderId,
            type = "sql-database",
            defaultTTL = definition.DefaultTtl,
            maxTTL = definition.MaximumTtl,
            version = 1,
            createdAt = Epoch,
            updatedAt = Epoch,
            status = (string?)null
        };
        private static object LeaseJson(Issuance issuance) => new
        {
            id = issuance.Id,
            dynamicSecretId = issuance.DefinitionId,
            createdAt = Epoch.AddSeconds(1),
            expireAt = Epoch.AddSeconds(121),
            updatedAt = Epoch.AddSeconds(1),
            version = 1,
            externalEntityId = issuance.User,
            status = (string?)null
        };

        public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
            SecretMaterial username, SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                var issued = Issued.SingleOrDefault(i => i.Id == coordinate.LeaseId &&
                    i.DefinitionId == coordinate.DefinitionId && i.User == username.Reveal());
                bool bound = coordinate.Engine == NativeSqlEngine.Postgres && coordinate.Host == "backend.invalid" &&
                    coordinate.Port == 5432 && coordinate.Database == "database";
                bool present = issued is not null && roles.TryGetValue(issued.User, out var role) && role == issued;
                bool pair = issued is not null && password.Reveal() == issued.Password.Reveal();
                bool accepted = bound && present && (pair || mode == "password-ignored") &&
                    !(mode == "reject-auth" && Issued.Count > 1);
                if (issued is not null)
                {
                    if (accepted && pair)
                    {
                        Accepted.Add(issued.Id);
                        if (WrongPasswordRejected.Contains(issued.Id)) AcceptedAgain.Add(issued.Id);
                        if (issued == Issued[0] && Issued.Count > 1)
                            BaselineAcceptedWithFreshCredential = true;
                    }
                    else if (!accepted && !pair && present) WrongPasswordRejected.Add(issued.Id);
                    else if (!accepted && pair && !present) RejectedAfterCleanup.Add(issued.Id);
                }
                return ValueTask.FromResult(new DynamicBackendFacts(
                    mode == "wrong-coordinate" && present ? coordinate with { Database = "other" } : coordinate,
                    mode == "unavailable" && present ? BackendAuthentication.Unavailable :
                        accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                    accepted ? mode == "wrong-actions" ? ["insert"] : ["select"] : [],
                    accepted ? ["write"] : [], accepted ? Epoch.AddSeconds(mode == "wrong-expiry" ? 122 : 121) : null));
            }
        }

        public ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
            IReadOnlyList<string> usernames, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                bool bound = coordinate == new DynamicUsernameCoordinate(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database");
                bool issuedOnly = usernames.All(n => Issued.Any(i => i.User == n));
                string[] existing = usernames.Where(roles.ContainsKey).ToArray();
                if (bound && issuedOnly && Issued.Count > 0 && existing.Length == 0 &&
                    Issued.All(i => usernames.Contains(i.User)))
                    FinalInventoryCoversEveryIssuedName = true;
                return ValueTask.FromResult(new DynamicUsernameFacts(coordinate, usernames.ToArray(), existing, bound && issuedOnly));
            }
        }

        internal async Task VerifyStorageAsync()
        {
            folders["folder"] = ("fixture", "/owned/fixture");
            var definition = new Definition(Guid.NewGuid(), "fixture", "folder", "60s", "300s", "/owned/fixture");
            definitions.Add(definition.Name, definition);
            var uri = new Uri(Origin, "/api/v1/dynamic-secrets/leases");
            var body = new JsonObject { ["dynamicSecretName"] = "fixture" };
            Handle("POST", uri, "administrative", body);
            var rule = new JsonObject
            {
                ["projectId"] = "project",
                ["environment"] = new JsonObject { ["slug"] = "env" },
                ["secretPath"] = definition.Path,
                ["isActive"] = true,
                ["passwordConstraints"] = new JsonObject { ["minLength"] = 24, ["maxLength"] = 24, ["regexPattern"] = "obsolete" }
            };
            rules["fixture"] = rule;
            ReplaceRule(rule, new() { ["passwordConstraints"] = new JsonObject { ["minLength"] = 24, ["maxLength"] = 24 } });
            await Assert.That(rule["passwordConstraints"]!["regexPattern"] is null).IsTrue();
            Handle("POST", uri, "administrative", body);
            await Assert.That(Issued[0].Password.Reveal() == Password32 && Issued[1].Password.Reveal() == Policy24).IsTrue();
            await Assert.That(Issued[0].User == Issued[1].User).IsFalse();
            foreach (var shape in new (int Length, string? Regex, string? Prefix, string? Suffix, string Expected)[]
            {
                (32, "^[A-Z]{24}$", "A_", "_A", "A_" + new string('A', 24) + "_A"),
                (32, "^[a-z]{24}$", "A_", "_A", "A_" + new string('a', 24) + "_A"),
                (32, "^[a-z]{24}$", "B_", "_A", "B_" + new string('a', 24) + "_A"),
                (32, "^[a-z]{24}$", "B_", "_B", "B_" + new string('a', 24) + "_B"),
                (24, null, "A_", "_A", "A_" + Policy24[..20] + "_A"),
                (24, "^[A-Z]{24}$", null, null, new string('A', 24))
            })
            {
                ReplaceRule(rule, new()
                {
                    ["passwordConstraints"] = new JsonObject
                    {
                        ["minLength"] = shape.Length,
                        ["maxLength"] = shape.Length,
                        ["regexPattern"] = shape.Regex,
                        ["requiredPrefix"] = shape.Prefix,
                        ["requiredSuffix"] = shape.Suffix
                    }
                });
                Handle("POST", uri, "administrative", body);
                await Assert.That(Issued[^1].Password.Reveal() == shape.Expected).IsTrue();
            }
            await Assert.That(Issued.Select(i => i.User).Distinct().Count()).IsEqualTo(Issued.Count);
            Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/fixture"), "administrative", new());
            foreach (var issuance in Issued)
            {
                var coordinate = new DynamicBackendCoordinate(NativeSqlEngine.Postgres, "backend.invalid", 5432,
                    "database", definition.Id, issuance.Id);
                using var user = SecretMaterial.FromText(issuance.User);
                using var wrong = SecretMaterial.FromText("deliberately-wrong");
                await Assert.That((await MeasureAsync(coordinate, user, issuance.Password, CancellationToken.None)).Authentication)
                    .IsEqualTo(BackendAuthentication.Accepted);
                await Assert.That((await MeasureAsync(coordinate, user, wrong, CancellationToken.None)).Authentication)
                    .IsEqualTo(BackendAuthentication.Rejected);
                await Assert.That((await MeasureAsync(coordinate, user, issuance.Password, CancellationToken.None)).Authentication)
                    .IsEqualTo(BackendAuthentication.Accepted);
                Handle("DELETE", new(Origin, "/api/v1/dynamic-secrets/leases/" + issuance.Id), "administrative", new());
                await Assert.That((await MeasureAsync(coordinate, user, issuance.Password, CancellationToken.None)).Authentication)
                    .IsEqualTo(BackendAuthentication.Rejected);
            }
            var inventory = await InspectUsernamesAsync(new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database"),
                Issued.Select(i => i.User).ToArray(), CancellationToken.None);
            await Assert.That(inventory.IsComplete).IsTrue();
            await Assert.That(inventory.ExistingUsernames.Length).IsEqualTo(0);
            Handle("DELETE", new(Origin, "/api/v1/secret-validation-rules/dynamic-secrets/fixture"), "administrative", new());
            Handle("DELETE", new(Origin, "/api/v2/folders/folder"), "administrative", new());
            await Assert.That(RecordCount).IsEqualTo(0);
            await Assert.That(RoleCount).IsEqualTo(0);
        }

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            foreach (var issuance in Issued) issuance.Password.Dispose();
            shutdown.Dispose();
        }

        private sealed record Definition(Guid Id, string Name, string FolderId, string DefaultTtl,
            string MaximumTtl, string Path);
        internal sealed record Issuance(Guid Id, Guid DefinitionId, string User, SecretMaterial Password)
        {
            public override string ToString() => "[Issuance]";
        }
    }
}
