using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ValidationPoliciesEffects
{
    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IInfisicalDynamicBackendObserver? backend = null,
        IInfisicalRotationValidationAccountFactory? rotationFactory = null,
        IInfisicalRotationCredentialObserver? rotationBackend = null, HttpMessageHandler? offlineRotationTransport = null)
    {
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.CreateValidationRuleAsync",
            "SecretKit.Infisical.InfisicalClient.CreateValidationRuleAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalValidationInput,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["kind.StaticSecrets", "kind.DynamicSecrets", "kind.SecretRotations", "StaticSecrets.keyConstraints", "StaticSecrets.valueConstraints", "StaticSecrets.uniqueAcrossLastVersions", "StaticSecrets.uniqueWithinScope", "DynamicSecrets.SqlDatabase", "DynamicSecrets.Milvus", "SecretRotations.PostgresCredentials", "SecretRotations.MysqlCredentials", "SecretRotations.MssqlCredentials", "SecretRotations.OracleCredentials", "SecretRotations.UnixLinuxLocalAccount", "SecretRotations.LdapPassword", "description.omitted", "description.value", "isActive.omitted", "isActive.false", "isActive.true", "environment.omitted", "environment.value", "secretPath.value"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t, backend, rotationFactory, rotationBackend, offlineRotationTransport));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.DeleteValidationRuleAsync",
            "SecretKit.Infisical.InfisicalClient.DeleteValidationRuleAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["kind.StaticSecrets", "kind.DynamicSecrets", "kind.SecretRotations"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t, backend, rotationFactory, rotationBackend, offlineRotationTransport));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.GetValidationRuleAsync",
            "SecretKit.Infisical.InfisicalClient.GetValidationRuleAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            ["selector.exact", "kind.StaticSecrets", "kind.DynamicSecrets", "kind.SecretRotations"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t, backend, rotationFactory, rotationBackend, offlineRotationTransport));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.ListValidationRulesAsync",
            "SecretKit.Infisical.InfisicalClient.ListValidationRulesAsync(SecretKit.Core.SecretReference,System.Int32,System.Boolean,System.Threading.CancellationToken)",
            ["allKinds.false", "allKinds.true", "kind.StaticSecrets", "kind.DynamicSecrets", "kind.SecretRotations"], false,
            (d, p, t) => ExecuteAsync(env, d, p, t, backend, rotationFactory, rotationBackend, offlineRotationTransport));
        InfisicalImportPolicyFamilies.Add(registry, env, expected, "i.runtime.InfisicalClient.UpdateValidationRuleAsync",
            "SecretKit.Infisical.InfisicalClient.UpdateValidationRuleAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalValidationInput,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            ["kind.StaticSecrets", "kind.DynamicSecrets", "kind.SecretRotations", "StaticSecrets.keyConstraints", "StaticSecrets.valueConstraints", "StaticSecrets.uniqueAcrossLastVersions", "StaticSecrets.uniqueWithinScope", "DynamicSecrets.SqlDatabase", "DynamicSecrets.Milvus", "SecretRotations.PostgresCredentials", "SecretRotations.MysqlCredentials", "SecretRotations.MssqlCredentials", "SecretRotations.OracleCredentials", "SecretRotations.UnixLinuxLocalAccount", "SecretRotations.LdapPassword", "description.omitted", "description.value", "isActive.omitted", "isActive.false", "isActive.true", "environment.omitted", "environment.value", "secretPath.value", "description.null", "environment.null", "keyConstraints.null", "valueConstraints.null"], true,
            (d, p, t) => ExecuteAsync(env, d, p, t, backend, rotationFactory, rotationBackend, offlineRotationTransport));
    }
    internal sealed record Constraints(int? MinimumLength, int? MaximumLength, string? RegexPattern,
        string? RequiredPrefix, string? RequiredSuffix, int? UniqueAcrossLastVersions, bool? UniqueWithinScope)
    {
        internal InfisicalTextConstraints Build() => new(MinimumLength, MaximumLength, RegexPattern,
            RequiredPrefix, RequiredSuffix, UniqueAcrossLastVersions, UniqueWithinScope);
        public override string ToString() => "[Constraints]";
    }
    internal static bool SupportedPasswordConstraints(Constraints? constraints) =>
        constraints is
        {
            MinimumLength: 24 or 32, RegexPattern: null or "^[A-Z]{24}$" or "^[a-z]{24}$",
            RequiredPrefix: null or "A_" or "B_", RequiredSuffix: null or "_A" or "_B",
            UniqueAcrossLastVersions: null, UniqueWithinScope: null
        } && constraints.MaximumLength == constraints.MinimumLength;

    internal static bool GeneratedPasswordMatches(string password, Constraints? constraints)
    {
        if (constraints is null)
            return password.Length == 32 && password.Count(c => c is >= 'a' and <= 'z') == 8 &&
                password.Count(c => c is >= 'A' and <= 'Z') == 8 &&
                password.Count(c => c is >= '0' and <= '9') == 8 && password.Count(c => c == '!') == 8;
        string prefix = constraints.RequiredPrefix ?? "";
        string suffix = constraints.RequiredSuffix ?? "";
        // Pinned generation applies regex to the middle, then wraps literal affixes.
        // Only the two closed patterns admitted above are interpreted here.
        int middleLength = constraints.RegexPattern is null ?
            constraints.MinimumLength!.Value - prefix.Length - suffix.Length : 24;
        if (password.Length != prefix.Length + middleLength + suffix.Length ||
            !password.StartsWith(prefix, StringComparison.Ordinal) || !password.EndsWith(suffix, StringComparison.Ordinal))
            return false;
        var middle = password.AsSpan(prefix.Length, middleLength);
        return constraints.RegexPattern switch
        {
            null => !middle.ContainsAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~!*"),
            "^[A-Z]{24}$" => !middle.ContainsAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
            "^[a-z]{24}$" => !middle.ContainsAnyExcept("abcdefghijklmnopqrstuvwxyz"),
            _ => false
        };
    }
    internal sealed record RuleInput(string? Name, string? Description, bool? IsActive,
        Constraints? KeyConstraints, Constraints? ValueConstraints, Constraints? PasswordConstraints,
        InfisicalValidationProvider[]? Providers, bool SupplyEnvironment, bool SupplySecretPath,
        bool ClearDescription, bool ClearEnvironment, bool ClearKeyConstraints, bool ClearValueConstraints)
    {
        internal InfisicalValidationInput Build(string ownedName, StaticOwnedFixture f, bool create) =>
            new(create ? ownedName : Name, Description, IsActive, KeyConstraints?.Build(), ValueConstraints?.Build(),
                PasswordConstraints?.Build(), Providers, SupplyEnvironment ? f.Input.Environment : null,
                SupplySecretPath ? f.Folder : null, ClearDescription, ClearEnvironment, ClearKeyConstraints, ClearValueConstraints);
        public override string ToString() => "[RuleInput]";
    }
    internal sealed record Trial(string Key, string BaselineValue, string Value, bool Update, SecretStatus ExpectedStatus)
    {
        public override string ToString() => "[Trial]";
    }
    internal sealed record PolicyInput(StaticFixtureInput Fixture, InfisicalValidationKind Kind,
        RuleInput Seed, RuleInput Change, Trial[] Before, Trial[] After, int MaximumItems,
        bool AllKinds, bool ExpectedApplied, bool Entitled, DynamicValidationInput? DynamicTrial = null,
        RotationValidationInput? RotationTrial = null)
    {
        public override string ToString() => "[PolicyInput]";
    }

    internal sealed record DynamicValidationInput(DynamicSqlInput Profile, int DefaultSeconds,
        int MaximumSeconds, string[] AllowedActions, string[] DeniedActions, string? ProjectSlug = null)
    {
        public override string ToString() => "[DynamicValidationInput]";
    }

    internal sealed record RotationValidationInput(string OrganizationId, string ConnectionId,
        string Host, int Port, string Database, int RotationInterval, string[] AllowedActions, string[] DeniedActions,
        InfisicalRotationProfile Profile = InfisicalRotationProfile.PostgresCredentials)
    {
        public override string ToString() => "[RotationValidationInput]";
    }

    private static void CheckVariant(PolicyInput i, NativeCaseDefinition d, NativeCaseProbe p, bool create)
    {
        string v = d.Key.Variant;
        if (i.Fixture is null || i.Fixture.Seeds is null || i.Seed is null ||
            i.Change is null || i.Before is null || i.After is null)
            throw new NativeCaseFailureException("missing-input");
        RuleInput input = create || d.Key.Operation.EndsWith(".UpdateValidationRuleAsync", StringComparison.Ordinal) ?
            i.Change : i.Seed;
        p.Contract(i.Entitled, NativeFailure.MissingPrerequisite);
        p.Contract(i.MaximumItems is >= 1 and <= 1000 && i.Before is { Length: <= 32 } &&
            i.After is { Length: <= 32 } &&
            (i.Kind != InfisicalValidationKind.StaticSecrets || i.After.Length > 0) && Enum.IsDefined(i.Kind) &&
            i.Before.All(t => t is not null) && i.After.All(t => t is not null) &&
            (!InfisicalImportPolicyFamilies.Denied(d) || !i.ExpectedApplied) &&
            (InfisicalImportPolicyFamilies.Interrupted(d) || InfisicalImportPolicyFamilies.Denied(d) || i.ExpectedApplied),
            NativeFailure.MissingInput);
        foreach (InfisicalValidationKind kind in Enum.GetValues<InfisicalValidationKind>())
            p.Contract(v != "kind." + kind || i.Kind == kind, NativeFailure.MissingInput);
        p.Contract(!v.StartsWith("StaticSecrets.", StringComparison.Ordinal) || i.Kind == InfisicalValidationKind.StaticSecrets,
            NativeFailure.MissingInput);
        p.Contract(v != "StaticSecrets.keyConstraints" || input.KeyConstraints is not null, NativeFailure.MissingInput);
        p.Contract(v != "StaticSecrets.valueConstraints" || input.ValueConstraints is not null, NativeFailure.MissingInput);
        p.Contract(v != "StaticSecrets.uniqueAcrossLastVersions" || input.ValueConstraints?.UniqueAcrossLastVersions is not null,
            NativeFailure.MissingInput);
        p.Contract(v != "StaticSecrets.uniqueWithinScope" || input.ValueConstraints?.UniqueWithinScope is not null,
            NativeFailure.MissingInput);
        foreach (InfisicalValidationProvider provider in Enum.GetValues<InfisicalValidationProvider>())
        {
            p.Contract(v != "DynamicSecrets." + provider || i.Kind == InfisicalValidationKind.DynamicSecrets &&
                input.Providers?.Contains(provider) == true, NativeFailure.MissingInput);
            p.Contract(v != "SecretRotations." + provider || i.Kind == InfisicalValidationKind.SecretRotations &&
                input.Providers?.Contains(provider) == true, NativeFailure.MissingInput);
        }
        foreach ((string field, bool supplied) in new[] { ("description", input.Description is not null),
            ("isActive", input.IsActive is not null), ("environment", input.SupplyEnvironment),
            ("secretPath", input.SupplySecretPath) })
        {
            p.Contract(v != field + ".omitted" || !supplied, NativeFailure.MissingInput);
            p.Contract(v != field + ".value" || supplied, NativeFailure.MissingInput);
        }
        p.Contract(v != "isActive.false" || input.IsActive == false, NativeFailure.MissingInput);
        p.Contract(v != "isActive.true" || input.IsActive == true, NativeFailure.MissingInput);
        p.Contract(v != "allKinds.false" || !i.AllKinds, NativeFailure.MissingInput);
        p.Contract(v != "allKinds.true" || i.AllKinds, NativeFailure.MissingInput);
        p.Contract(v != "description.null" || input.ClearDescription, NativeFailure.MissingInput);
        p.Contract(v != "environment.null" || input.ClearEnvironment, NativeFailure.MissingInput);
        p.Contract(v != "keyConstraints.null" || input.ClearKeyConstraints, NativeFailure.MissingInput);
        p.Contract(v != "valueConstraints.null" || input.ClearValueConstraints, NativeFailure.MissingInput);
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition d,
        NativeCaseProbe p, CancellationToken token, IInfisicalDynamicBackendObserver? backend,
        IInfisicalRotationValidationAccountFactory? rotationFactory, IInfisicalRotationCredentialObserver? rotationBackend,
        HttpMessageHandler? offlineRotationTransport)
    {
        PolicyInput i = InfisicalStaticFamilies.Input<PolicyInput>(env, "C08-IR-ValidationPolicies", d);
        bool create = d.Key.Operation.EndsWith(".CreateValidationRuleAsync", StringComparison.Ordinal);
        bool update = d.Key.Operation.EndsWith(".UpdateValidationRuleAsync", StringComparison.Ordinal);
        bool delete = d.Key.Operation.EndsWith(".DeleteValidationRuleAsync", StringComparison.Ordinal);
        bool list = d.Key.Operation.EndsWith(".ListValidationRulesAsync", StringComparison.Ordinal);
        if (i.Kind == InfisicalValidationKind.DynamicSecrets)
        {
            backend ??= InfisicalLifecycleObservers.FromInputs(env, "C08-IR-ValidationPolicies");
            await OwnedDynamicValidation.AdmitAsync(env, i, d, p, backend, token);
        }
        if (i.Kind == InfisicalValidationKind.SecretRotations)
        {
            rotationFactory ??= InfisicalRotationValidationAccounts.FromInputs(env);
            rotationBackend ??= InfisicalLifecycleObservers.FromInputs(env, "C08-IR-ValidationPolicies");
            await OwnedRotationValidation.AdmitAsync(env, i, d, p, rotationFactory, rotationBackend,
                offlineRotationTransport, token);
        }
        CheckVariant(i, d, p, create);
        await using var f = new StaticOwnedFixture(env, i.Fixture, p, d.Key.Scope);
        await f.InitializeAsync(token);
        await using var dynamic = i.Kind == InfisicalValidationKind.DynamicSecrets ?
            new OwnedDynamicValidation(env, i.DynamicTrial!, f, p, backend!) : null;
        await using var rotation = i.Kind == InfisicalValidationKind.SecretRotations ?
            new OwnedRotationValidation(env, i.RotationTrial!, f, p, rotationFactory!, rotationBackend!,
                offlineRotationTransport) : null;
        string name = "sk-" + Guid.NewGuid().ToString("N");
        string? id = null;
        SecretReference Target(InfisicalClient c, bool collection = false, bool newRule = false) =>
            new(c.Authority, new InfisicalValidationAddress(i.Fixture.ProjectId, i.Kind,
                collection || newRule ? null : id, collection ? null :
                    i.Seed.SupplyEnvironment ? i.Fixture.Environment : null, collection ? null : f.Folder));
        InfisicalNativeAuthority Authority(InfisicalClient c, NativeIdentityRole role) =>
            new(c.Authority, env.Tokens(role), i.Fixture.ProjectId);
        string kindPath = i.Kind switch
        {
            InfisicalValidationKind.StaticSecrets => "static-secrets",
            InfisicalValidationKind.DynamicSecrets => "dynamic-secrets",
            InfisicalValidationKind.SecretRotations => "secret-rotations",
            _ => throw new NativeCaseFailureException("missing-input")
        };
        try
        {
            if (i.Kind == InfisicalValidationKind.StaticSecrets)
                await BaselineAsync(f, i.Before.Concat(i.After).ToArray(), p, token);
            if (!create)
            {
                var seed = Target(f.Setup, newRule: true);
                var r = new MutationReceipt(seed);
                var seeded = await f.Setup.CreateValidationRuleAsync(seed, i.Seed.Build(name, f, true),
                    Authority(f.Setup, NativeIdentityRole.Setup), r, token);
                p.Contract(seeded.IsSuccess && r.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
                id = seeded.Value.Id;
                var initial = await f.Observer.GetValidationRuleAsync(Target(f.Observer), token);
                p.Contract(initial.IsSuccess && Matches(initial.Value, i.Seed, name, f, null),
                    NativeFailure.ObserverUnavailable);
                if (i.Kind == InfisicalValidationKind.StaticSecrets)
                {
                    p.Contract(i.Before.Any(t => t.ExpectedStatus == SecretStatus.Success) &&
                        i.Before.Any(t => t.ExpectedStatus is SecretStatus.Invalid or SecretStatus.Conflict),
                        NativeFailure.MissingInput);
                    await TrialsAsync(f, i.Before, p, token);
                }
            }
            if (dynamic is not null || rotation is not null)
            {
                var baselineRules = await f.Observer.ListValidationRulesAsync(Target(f.Observer, collection: true),
                    cancellationToken: token);
                p.Contract(baselineRules.IsSuccess && baselineRules.Value.IsComplete &&
                    baselineRules.Value.Items.Count == (create ? 0 : 1) &&
                    (create || baselineRules.Value.Items[0].Id == id &&
                        Matches(baselineRules.Value.Items[0], i.Seed, name, f, null)),
                    NativeFailure.ObserverUnavailable);
                Constraints? baselineConstraints = !create && i.Seed.IsActive == true ?
                    i.Seed.PasswordConstraints : null;
                if (dynamic is not null)
                {
                    await dynamic.InitializeAsync(token);
                    await dynamic.TrialAsync(baselineConstraints, token);
                }
                else
                {
                    await rotation!.InitializeAsync(token);
                    await rotation.TrialAsync(baselineConstraints, token);
                }
            }
            bool denied = InfisicalImportPolicyFamilies.Denied(d);
            InfisicalClient c = denied ? f.Denied : f.Runtime;
            var target = Target(c, collection: list, newRule: create);
            // Creation scope belongs to the selected input, not the seed branch.
            if (create) target = new(c.Authority, new InfisicalValidationAddress(i.Fixture.ProjectId, i.Kind,
                environment: i.Change.SupplyEnvironment ? i.Fixture.Environment : null, secretPath: f.Folder));
            var receipt = new MutationReceipt(target);
            var authority = Authority(c, denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime);
            string path = "/api/v1/secret-validation-rules" + (list && i.AllKinds ? "" : "/" + kindPath) +
                (list || create ? "" : "/" + id);
            if (list)
            {
                var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path, "GET",
                    ct => c.ListValidationRulesAsync(target, i.MaximumItems, i.AllKinds, ct), token);
                InfisicalImportPolicyFamilies.Result(dispatch, null, denied ? SecretStatus.Denied : SecretStatus.Success, default, p);
                if (dispatch.Outcome is { IsSuccess: true } result)
                    p.Contract(result.Value.Items.Any(rule => rule.Id == id && Matches(rule, i.Seed, name, f, null)),
                        NativeFailure.ObserverUnavailable);
            }
            else
            {
                var dispatch = await InfisicalImportPolicyFamilies.DispatchAsync(env, d, p, path,
                    create ? "POST" : update ? "PATCH" : delete ? "DELETE" : "GET",
                    ct => create ? c.CreateValidationRuleAsync(target, i.Change.Build(name, f, true), authority, receipt, ct) :
                        update ? c.UpdateValidationRuleAsync(target, i.Change.Build(name, f, false), authority, receipt, ct) :
                        delete ? c.DeleteValidationRuleAsync(target, authority, receipt, ct) : c.GetValidationRuleAsync(target, ct), token);
                InfisicalImportPolicyFamilies.Result(dispatch, create || update || delete ? receipt : null,
                    denied ? SecretStatus.Denied : SecretStatus.Success,
                    InfisicalImportPolicyFamilies.Interrupted(d) ? DispatchEvidence.PossiblyDispatched :
                        denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied, p);
                if (create && dispatch.Outcome is { IsSuccess: true } result) id = result.Value.Id;
                if (!create && !update && !delete && dispatch.Outcome is { IsSuccess: true } read)
                    p.Contract(Matches(read.Value, i.Seed, name, f, null), NativeFailure.ContractMismatch);
            }
            var observed = await f.Observer.ListValidationRulesAsync(Target(f.Observer, collection: true),
                cancellationToken: token);
            p.Contract(observed.IsSuccess && observed.Value.IsComplete, NativeFailure.ObserverUnavailable);
            var selected = observed.Value.Items.SingleOrDefault(rule => id is null ? rule.Name == name : rule.Id == id);
            bool absent = create && !i.ExpectedApplied || delete && i.ExpectedApplied;
            p.Contract(absent ? selected is null : selected is not null &&
                Matches(selected, create ? i.Change : update && i.ExpectedApplied ? i.Change : i.Seed,
                    name, f, update && i.ExpectedApplied ? i.Seed : null), NativeFailure.EffectMismatch);
            if (dynamic is not null || rotation is not null)
            {
                p.Contract(observed.Value.Items.Count == (absent ? 0 : 1), NativeFailure.ObserverUnavailable);
                RuleInput effectiveRule = create ? i.Change : update && i.ExpectedApplied ? i.Change : i.Seed;
                Constraints? effectiveConstraints = !absent && effectiveRule.IsActive == true ?
                    effectiveRule.PasswordConstraints : null;
                if (dynamic is not null)
                {
                    await dynamic.TrialAsync(effectiveConstraints, token);
                    await dynamic.VerifyBaselineAsync(token);
                }
                else
                {
                    await rotation!.TrialAsync(effectiveConstraints, token);
                    await rotation.VerifyBaselineAsync(token);
                }
                env.ConfirmPrerequisite(d.Key.Scope, "validation-feature-entitlement", NativeObservation.Matched);
                env.ConfirmPrerequisite(d.Key.Scope, "validation-backend-observer", NativeObservation.Matched);
                p.Effect(NativeObservation.Matched);
                return;
            }
            if (i.Kind != InfisicalValidationKind.StaticSecrets)
            {
                // A password constraint requires the selected dynamic/rotation backend.
                // No material acquisition shape or backend witness is supplied by this family.
                p.Effect(NativeObservation.Unavailable);
            }
            RuleInput effective = create ? i.Change : update && i.ExpectedApplied ? i.Change : i.Seed;
            bool hasKey = !effective.ClearKeyConstraints && (effective.KeyConstraints is not null ||
                update && i.ExpectedApplied && i.Seed.KeyConstraints is not null);
            bool hasValue = !effective.ClearValueConstraints && (effective.ValueConstraints is not null ||
                update && i.ExpectedApplied && i.Seed.ValueConstraints is not null);
            if (!absent && selected!.IsActive is null) p.Effect(NativeObservation.Unavailable);
            bool active = !absent && (hasKey || hasValue) && selected!.IsActive == true;
            if (active)
                p.Contract(i.After.Any(t => t.ExpectedStatus == SecretStatus.Success) &&
                    i.After.Any(t => t.ExpectedStatus is SecretStatus.Invalid or SecretStatus.Conflict),
                    NativeFailure.MissingInput);
            else p.Contract(i.After.All(t => t.ExpectedStatus == SecretStatus.Success), NativeFailure.MissingInput);
            await TrialsAsync(f, i.After, p, token);
            env.ConfirmPrerequisite(d.Key.Scope, "validation-feature-entitlement", NativeObservation.Matched);
            env.ConfirmPrerequisite(d.Key.Scope, "validation-backend-observer", NativeObservation.Matched);
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            try
            {
                var found = await f.Observer.ListValidationRulesAsync(Target(f.Observer, collection: true),
                    cancellationToken: cleanup.Token);
                p.Contract(found.IsSuccess && found.Value.IsComplete, NativeFailure.CleanupIncomplete);
                foreach (var rule in found.Value.Items.Where(r => id is null ? r.Name == name : r.Id == id))
                {
                    var owned = new SecretReference(f.Administrative.Authority, new InfisicalValidationAddress(
                        i.Fixture.ProjectId, i.Kind, rule.Id, rule.Environment, rule.SecretPath));
                    var removed = await f.Administrative.DeleteValidationRuleAsync(owned,
                        Authority(f.Administrative, NativeIdentityRole.Administrative), new(owned), cleanup.Token);
                    var gone = await f.Observer.GetValidationRuleAsync(new(f.Observer.Authority, owned.Address), cleanup.Token);
                    p.Contract((removed.IsSuccess || removed.Status == SecretStatus.Absent) &&
                        gone.Status == SecretStatus.Absent, NativeFailure.CleanupIncomplete);
                }
                if (dynamic is not null || rotation is not null)
                {
                    var remaining = await f.Observer.ListValidationRulesAsync(Target(f.Observer, collection: true),
                        cancellationToken: cleanup.Token);
                    p.Contract(remaining.IsSuccess && remaining.Value.IsComplete && remaining.Value.Items.Count == 0,
                        NativeFailure.CleanupIncomplete);
                }
            }
            catch (Exception)
            {
                env.ConfirmPrerequisite(d.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
                p.Contract(false, NativeFailure.CleanupIncomplete);
            }
        }
    }

    private static async ValueTask BaselineAsync(StaticOwnedFixture f, Trial[] trials,
        NativeCaseProbe p, CancellationToken token)
    {
        p.Contract(trials.Select(t => t.Key).Distinct(StringComparer.Ordinal).Count() == trials.Length,
            NativeFailure.MissingInput);
        foreach (Trial trial in trials)
        {
            p.Contract(!string.IsNullOrWhiteSpace(trial.Key) &&
                trial.ExpectedStatus is SecretStatus.Success or SecretStatus.Invalid or SecretStatus.Conflict &&
                !f.Input.Seeds.Any(seed => seed.Key == trial.Key), NativeFailure.MissingInput);
            var target = f.Secret(f.Runtime, trial.Key);
            var r = new MutationReceipt(target);
            using var material = SecretMaterial.FromText(trial.BaselineValue);
            var created = await f.Runtime.CreateAsync(target, material, r, token);
            p.Contract(created.IsSuccess && created.Value.Disposition == InfisicalChangeDisposition.Applied &&
                r.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
            await f.ObserveAsync([new(trial.Key, SecretStatus.Success, trial.BaselineValue, null)], token, recordEffect: false);
            if (!trial.Update)
            {
                var bulk = new SecretReference(f.Runtime.Authority, new InfisicalBulkAddress(f.Input.ProjectId,
                    f.Input.Environment, f.Folder, f.FolderId));
                InfisicalBulkSecret[] items = [new(trial.Key)];
                var receipt = new InfisicalBulkReceipt(f.Runtime, bulk, items, InfisicalBulkOperation.Delete);
                var deleted = await f.Runtime.DeleteSecretsAsync(bulk, items,
                    f.Authority(f.Runtime, NativeIdentityRole.Runtime), receipt, token);
                p.Contract(deleted.IsSuccess && deleted.Value.AllApplied, NativeFailure.MissingPrerequisite);
                await f.ObserveAsync([new(trial.Key, SecretStatus.Absent, null, null)], token, recordEffect: false);
            }
        }
    }

    private static async ValueTask TrialsAsync(StaticOwnedFixture f, Trial[] trials,
        NativeCaseProbe p, CancellationToken token)
    {
        foreach (Trial trial in trials)
        {
            var target = f.Secret(f.Runtime, trial.Key);
            var receipt = new MutationReceipt(target);
            using var material = SecretMaterial.FromText(trial.Value);
            var attempted = trial.Update ? await f.Runtime.UpdateValueAsync(target, material, receipt, token) :
                await f.Runtime.CreateAsync(target, material, receipt, token);
            p.Contract(attempted.Status == trial.ExpectedStatus && receipt.Evidence ==
                (trial.ExpectedStatus == SecretStatus.Success ? DispatchEvidence.Applied :
                    trial.ExpectedStatus == SecretStatus.Conflict ? DispatchEvidence.Conflict : DispatchEvidence.Rejected),
                NativeFailure.ContractMismatch);
            bool applied = trial.ExpectedStatus == SecretStatus.Success;
            await f.ObserveAsync([new(trial.Key, applied || trial.Update ? SecretStatus.Success : SecretStatus.Absent,
                applied ? trial.Value : trial.Update ? trial.BaselineValue : null, null)], token);
        }
    }

    private static bool Matches(InfisicalValidationRule r, RuleInput changed, string name,
        StaticOwnedFixture f, RuleInput? seed)
    {
        return r.ProjectId == f.Input.ProjectId && r.SecretPath == f.Folder &&
            r.Name == (seed is null ? name : changed.Name ?? name) &&
            r.Description == (changed.ClearDescription ? null : changed.Description ?? seed?.Description) &&
            r.Environment == (changed.ClearEnvironment ? null : changed.SupplyEnvironment ||
                seed?.SupplyEnvironment == true ? f.Input.Environment : null) &&
            (changed.IsActive is null && seed?.IsActive is null || r.IsActive == (changed.IsActive ?? seed?.IsActive)) &&
            ConstraintsMatch(r.KeyConstraints, changed.ClearKeyConstraints ? null : changed.KeyConstraints ?? seed?.KeyConstraints) &&
            ConstraintsMatch(r.ValueConstraints, changed.ClearValueConstraints ? null : changed.ValueConstraints ?? seed?.ValueConstraints) &&
            ConstraintsMatch(r.PasswordConstraints, changed.PasswordConstraints ?? seed?.PasswordConstraints) &&
            ((changed.Providers ?? seed?.Providers) is not { } providers ? r.Providers is null :
                r.Providers is not null && r.Providers.SequenceEqual(providers));
    }
    private static bool ConstraintsMatch(InfisicalTextConstraints? actual, Constraints? expected) =>
        expected is null ? actual is null : actual is not null &&
        actual.MinimumLength == expected.MinimumLength && actual.MaximumLength == expected.MaximumLength &&
        actual.RegexPattern == expected.RegexPattern && actual.RequiredPrefix == expected.RequiredPrefix &&
        actual.RequiredSuffix == expected.RequiredSuffix && actual.UniqueAcrossLastVersions == expected.UniqueAcrossLastVersions &&
        actual.UniqueWithinScope == expected.UniqueWithinScope;
}
