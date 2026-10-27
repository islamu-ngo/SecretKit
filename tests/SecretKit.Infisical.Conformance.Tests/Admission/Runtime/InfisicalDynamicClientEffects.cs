using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalDynamicClientEffects
{
    internal const string Family = "C08-IR-InfisicalDynamicClient";
    private const string Prefix = "i.runtime.InfisicalDynamicClient.";

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected, IInfisicalDynamicBackendObserver? backend = null,
        IInfisicalSqlInputObserver? sqlInputs = null, IInfisicalNonSqlInputObserver? nonSqlInputs = null)
    {
        foreach (var definition in expected.Where(d => d.Key.Provider == "Infisical" &&
            d.Key.Operation.StartsWith(Prefix, StringComparison.Ordinal)))
            registry.Add(new(definition, (probe, token) => InfisicalLifecycleFamilies.BoundedAsync(probe, token,
                bounded => ExecuteAsync(env, definition, probe, backend, sqlInputs, nonSqlInputs, bounded),
                () =>
                {
                    InfisicalLifecycleFamilies.Admission(definition, probe);
                    var input = InfisicalLifecycleFamilies.Input<DynamicInput>(env, Family, definition);
                    return input.SqlInputWitness?.CaseTimeoutSeconds ??
                        input.NonSqlInputWitness?.CaseTimeoutSeconds ?? 40;
                })));
    }

    // Unimplemented host configuration branches stay in the denominator. They are not
    // interpreted as SQL or guessed from opaque provider material.
    internal static bool ExecutableVariant(string variant) => variant is
        "profile.SqlDatabase" or "selector.exact" or "collection.bounded" or
        "ttl.omitted" or "ttl.value" or "forceRecordRemoval.false" or "forceRecordRemoval.true" or
        "options.omitted" or "options.value" or "maximumTtl.omitted" or "maximumTtl.null" or "maximumTtl.value" or
        "usernameTemplate.omitted" or "usernameTemplate.value" or "usernameTemplate.null" or
        "metadata.omitted" or "metadata.empty" or "metadata.value" or
        "gatewayId.omitted" or "gatewayId.value" or "gatewayId.null" or
        "gatewayPoolId.omitted" or "gatewayPoolId.value" or "gatewayPoolId.null" or
        "sql.sslEnabled.omitted" or "sql.sslEnabled.false" or "sql.sslEnabled.true" or
        "sql.ca.omitted" or "sql.ca.value" or "sql.renewStatement.omitted" or "sql.renewStatement.value" or
        "passwordRequirements.omitted" or "passwordRequirements.value" or
        "defaultTtl.omitted" or "defaultTtl.value" or "newName.omitted" or "newName.value" or
        "inputs.omitted" or "inputs.same-provider" or
        "AwsIam.access-key.IamUser" or "AwsIam.access-key.Temporary" or
        "AwsIam.assume-role.IamUser" or "AwsIam.assume-role.Temporary" or
        "AwsIam.irsa.IamUser" or "AwsIam.irsa.Temporary" ||
        InfisicalDynamicAlternativeProfileInputs.TryProvider(variant, out _) ||
        InfisicalDynamicProfileVariants.TryProvider(variant, out _) ||
        InfisicalDynamicNestedProfileOptions.Supports(variant) ||
        variant.StartsWith("profile.", StringComparison.Ordinal) &&
        Enum.TryParse<InfisicalDynamicProvider>(variant["profile.".Length..], out var provider) &&
        Enum.IsDefined(provider) && variant == "profile." + provider ||
        variant.StartsWith("SqlDatabase.engine.", StringComparison.Ordinal) &&
        Enum.TryParse<NativeSqlEngine>(variant["SqlDatabase.engine.".Length..], out var engine) && Enum.IsDefined(engine) ||
        NormalizeSqlVariant(variant) != variant && ExecutableVariant(NormalizeSqlVariant(variant));

    internal static string NormalizeSqlVariant(string variant)
    {
        const string prefix = "NativeSqlDefinitionProfile.";
        if (!variant.StartsWith(prefix, StringComparison.Ordinal)) return variant;
        string field = variant[prefix.Length..];
        return field switch
        {
            "renewalStatement.omitted" => "sql.renewStatement.omitted",
            "renewalStatement.value" => "sql.renewStatement.value",
            "ca.omitted" => "sql.ca.omitted",
            "ca.value" => "sql.ca.value",
            "sslEnabled.omitted" => "sql.sslEnabled.omitted",
            "sslEnabled.false" => "sql.sslEnabled.false",
            "sslEnabled.true" => "sql.sslEnabled.true",
            "gatewayId.omitted" => "gatewayId.omitted",
            "gatewayId.value" => "gatewayId.value",
            "gatewayPoolId.omitted" => "gatewayPoolId.omitted",
            "gatewayPoolId.value" => "gatewayPoolId.value",
            "passwordRequirements.omitted" => "passwordRequirements.omitted",
            "passwordRequirements.value" => "passwordRequirements.value",
            "clearGatewayId.false" => "gatewayId.omitted",
            "clearGatewayId.true" => "gatewayId.null",
            "clearGatewayPoolId.false" => "gatewayPoolId.omitted",
            "clearGatewayPoolId.true" => "gatewayPoolId.null",
            _ => variant
        };
    }

    private static async ValueTask ExecuteAsync(NativeEnvironment env, NativeCaseDefinition row,
        NativeCaseProbe probe, IInfisicalDynamicBackendObserver? backend,
        IInfisicalSqlInputObserver? sqlInputs, IInfisicalNonSqlInputObserver? nonSqlInputs, CancellationToken token)
    {
        InfisicalLifecycleFamilies.Admission(row, probe);
        DynamicInput input = InfisicalLifecycleFamilies.Input<DynamicInput>(env, Family, row);
        backend ??= InfisicalLifecycleObservers.FromInputs(env, Family);
        if (!ExecutableVariant(row.Key.Variant))
            probe.Contract(false, NativeFailure.MissingPrerequisite);
        string variant = NormalizeSqlVariant(row.Key.Variant);
        string method = row.Key.Operation[Prefix.Length..];
        bool alternative = InfisicalDynamicAlternativeProfileInputs.TryProvider(variant, out var alternativeProvider);
        bool optionVariant = InfisicalDynamicProfileVariants.TryProvider(variant, out var optionProvider);
        bool nestedVariant = InfisicalDynamicNestedProfileOptions.Supports(variant);
        string alternativeFactory = variant;
        InfisicalDynamicProvider provider = alternative ? alternativeProvider :
            optionVariant ? optionProvider :
            variant.StartsWith("profile.", StringComparison.Ordinal) ?
            Enum.Parse<InfisicalDynamicProvider>(variant["profile.".Length..]) :
            variant.StartsWith("AwsIam.", StringComparison.Ordinal) ? InfisicalDynamicProvider.AwsIam :
            InfisicalDynamicProvider.SqlDatabase;
        if (provider == InfisicalDynamicProvider.SqlDatabase && input.NonSqlInputWitness is not null &&
            input.NonSqlProfile is { } closedProfile && !nestedVariant)
        {
            probe.Contract(variant is "selector.exact" or "collection.bounded" or
                "inputs.omitted" or "inputs.same-provider" or "defaultTtl.omitted" or "defaultTtl.value" or
                "maximumTtl.omitted" or "maximumTtl.null" or "maximumTtl.value" or
                "newName.omitted" or "newName.value" or "options.omitted" or "options.value" or
                "usernameTemplate.omitted" or "usernameTemplate.value" or "usernameTemplate.null" or
                "metadata.omitted" or "metadata.empty" or "metadata.value" or
                "forceRecordRemoval.false" or "forceRecordRemoval.true" or
                "gatewayId.omitted" or "gatewayId.value" or "gatewayId.null" or
                "gatewayPoolId.omitted" or "gatewayPoolId.value" or "gatewayPoolId.null" or
                "passwordRequirements.omitted" or "passwordRequirements.value", NativeFailure.MissingInput);
            provider = NonSqlInputPrivateProfiles.ProviderOf(closedProfile);
        }
        if (input.SqlInputWitness is not null && provider == InfisicalDynamicProvider.SqlDatabase &&
            method is "CreateDefinitionAsync" or "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync")
        {
            await SqlInputEffects.ExecuteAsync(env, row, probe, input, backend, sqlInputs, token);
            return;
        }
        if (nestedVariant)
        {
            probe.Contract(input.OptionProvider is { } supplied && Enum.IsDefined(supplied), NativeFailure.MissingInput);
            provider = input.OptionProvider.GetValueOrDefault();
            probe.Contract(provider != InfisicalDynamicProvider.SqlDatabase, NativeFailure.MissingPrerequisite);
            if (input.AlternativeVariant is { } factory)
            {
                probe.Contract(InfisicalDynamicAlternativeProfileInputs.TryProvider(factory, out var selectedProvider) &&
                    selectedProvider == provider, NativeFailure.MissingInput);
                alternative = true;
                alternativeFactory = factory;
            }
        }
        else probe.Contract(input.OptionProvider is null && input.AlternativeVariant is null, NativeFailure.MissingInput);
        DynamicSqlInput? sql = input.Profile;
        InfisicalDynamicProfileInput? selectedProfile = input.NonSqlProfile;
        InfisicalDynamicAlternativeProfileInput? selectedAlternative = input.AlternativeProfile;
        if (provider != InfisicalDynamicProvider.SqlDatabase)
        {
            probe.Contract(alternative ?
                input.AlternativeProfile is not null && input.NonSqlProfile is null :
                input.NonSqlProfile is not null && input.AlternativeProfile is null, NativeFailure.MissingInput);
            if (!nestedVariant && variant.StartsWith("AwsIam.", StringComparison.Ordinal))
            {
                var aws = input.NonSqlProfile?.AwsIam;
                string? authentication = aws?.Authentication switch
                {
                    DynamicAwsAuthentication.AccessKey => "access-key",
                    DynamicAwsAuthentication.AssumeRole => "assume-role",
                    DynamicAwsAuthentication.Irsa => "irsa",
                    _ => null
                };
                probe.Contract(aws is not null && authentication is not null &&
                    variant == "AwsIam." + authentication + "." + aws.CredentialKind, NativeFailure.MissingInput);
            }
            // The public material acquisition contract is SQL-only. Do not invent
            // issued non-SQL material or an externally prepared owned lease.
            probe.Contract(method is "CreateDefinitionAsync" or "UpdateDefinitionAsync" or
                "UpdateDefinitionPolicyAsync" or "InspectDefinitionAsync" or
                "ListDefinitionsAsync" or "DeleteDefinitionAsync", NativeFailure.MissingPrerequisite);
        }
        bool denied = row.Key.Case == "denied-authority";
        bool cancel = row.Key.Case == "cancellation-boundary";
        bool lost = row.Key.Case == "lost-response-no-replay";
        bool force = variant == "forceRecordRemoval.true";
        probe.Contract(input.DefaultSeconds > 0 && input.MaximumSeconds > input.DefaultSeconds,
            NativeFailure.MissingInput);
        if (provider == InfisicalDynamicProvider.SqlDatabase)
        {
            ArgumentNullException.ThrowIfNull(sql);
            probe.Contract(Enum.IsDefined(sql.Engine) &&
                (variant.StartsWith("SqlDatabase.engine.", StringComparison.Ordinal) ?
                    variant == "SqlDatabase.engine." + sql.Engine : true) &&
                input.TtlSeconds > 0 && input.Metadata is not null && input.AllowedActions is { Length: > 0 } &&
                input.DeniedActions is { Length: > 0 } &&
                (variant != "sql.ca.value" || sql.Ca is { Length: > 0 }) &&
                (variant != "sql.renewStatement.value" || sql.RenewalStatement is { Length: > 0 }) &&
                (variant != "gatewayId.value" || sql.GatewayId is { Length: > 0 }) &&
                (variant != "gatewayPoolId.value" || sql.GatewayPoolId is { Length: > 0 }) &&
                (variant != "usernameTemplate.value" || input.UsernameTemplate is { Length: > 0 }) &&
                (variant != "passwordRequirements.value" || sql.PasswordRequirements is not null) &&
                (variant != "metadata.value" || input.Metadata is { Length: > 0 }), NativeFailure.MissingInput);
        }
        if (optionVariant || nestedVariant)
        {
            try
            {
                if (nestedVariant && alternative)
                    selectedAlternative = InfisicalDynamicNestedProfileOptions.SelectAlternative(variant, alternativeFactory,
                        selectedAlternative ?? throw new ArgumentException("Missing alternative profile."));
                else if (nestedVariant)
                    selectedProfile = InfisicalDynamicNestedProfileOptions.Select(variant, provider,
                        selectedProfile ?? throw new ArgumentException("Missing typed profile."));
                else
                    selectedProfile = InfisicalDynamicProfileVariants.Select(variant,
                        selectedProfile ?? throw new ArgumentException("Missing typed profile."));
            }
            catch (ArgumentException)
            {
                // Invalid private selection is missing input, never a dispatched
                // provider failure. Validate it before owning a folder or definition.
                probe.Contract(false, NativeFailure.MissingInput);
                throw;
            }
        }
        if (provider != InfisicalDynamicProvider.SqlDatabase && input.NonSqlInputWitness is not null)
        {
            await NonSqlInputEffects.ExecuteAsync(env, row, probe, input, provider, selectedProfile,
                selectedAlternative, alternativeFactory, nonSqlInputs, token);
            return;
        }
        bool passwordWitness = variant == "passwordRequirements.value" &&
            method is "CreateDefinitionAsync" or "UpdateDefinitionAsync" &&
            sql?.Engine == NativeSqlEngine.Postgres && ClosedPasswordPolicy(sql.PasswordRequirements);
        if (variant == "passwordRequirements.value" && method == "UpdateDefinitionAsync")
            probe.Contract(ClosedPasswordPolicy(sql!.BaselinePasswordRequirements) &&
                sql.BaselinePasswordRequirements!.Length != sql.PasswordRequirements!.Length,
                NativeFailure.MissingInput);
        if (passwordWitness)
        {
            if (backend is null) probe.Effect(NativeObservation.Unavailable);
            await RequireDefinitionPasswordPolicyAsync(env, input.Sandbox.ProjectId, probe, token);
        }
        bool usernameWitness = variant == "usernameTemplate.value" &&
            method is "CreateDefinitionAsync" or "UpdateDefinitionAsync";
        IInfisicalDynamicUsernameObserver? usernameObserver = backend as IInfisicalDynamicUsernameObserver;
        DynamicUsernameCoordinate? usernameCoordinate = null;
        string[] plannedUsernames = [];
        if (usernameWitness)
        {
            if (sql?.Engine != NativeSqlEngine.Postgres || !LiteralUsername(input.UsernameTemplate))
                probe.Effect(NativeObservation.Unavailable);
            if (method == "UpdateDefinitionAsync")
                probe.Contract(LiteralUsername(input.BaselineUsernameTemplate) &&
                    input.BaselineUsernameTemplate != input.UsernameTemplate &&
                    input.BaselineUsernameTemplate![..^1] == input.UsernameTemplate![..^1], NativeFailure.MissingInput);
            usernameCoordinate = new(sql!.Engine, sql.Host, sql.Port, sql.Database);
            string stem = input.UsernameTemplate![..^1];
            plannedUsernames = [stem + "a", stem + "b"];
            if (usernameObserver is null) probe.Effect(NativeObservation.Unavailable);
            var inventory = await UsernameInventoryAsync(usernameObserver!, usernameCoordinate, plannedUsernames, token);
            probe.Contract(inventory.ExistingUsernames.Length == 0, NativeFailure.MissingPrerequisite);
        }

        InfisicalDynamicProfile CreateProfile(string sqlVariant) => alternative ?
            InfisicalDynamicAlternativeProfileInputs.Create(alternativeFactory,
                selectedAlternative ?? throw new ArgumentException("Missing alternative profile.")) :
            provider == InfisicalDynamicProvider.SqlDatabase ?
            Profile(sql ?? throw new ArgumentException("Missing SQL profile."), sqlVariant) :
            InfisicalDynamicProfileInputs.Create(provider,
                selectedProfile ?? throw new ArgumentException("Missing typed profile."));
        using InfisicalDynamicProfile seedProfile = passwordWitness && method == "UpdateDefinitionAsync" ?
            Profile(sql! with { PasswordRequirements = sql.BaselinePasswordRequirements }, variant) :
            CreateProfile("seed");

        await using var folder = new LifecycleOwnedFolder(env, input.Sandbox, probe, row.Key.Scope);
        await folder.InitializeAsync(token);
        var scope = new InfisicalDynamicScope(input.Sandbox.ProjectSlug, input.Sandbox.Environment,
            folder.Path, folder.FolderId);
        using var transport = new LifecycleTransport(row.Key.Case);
        var selected = new LifecycleSelectedTokens(env, NativeIdentityRole.Setup);
        await using var client = new InfisicalDynamicClient(env.Origin, selected, scope,
            new()
            {
                AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp,
                Transport = InfisicalTransportOptions.HostControlled(transport)
            });
        await using var observer = new InfisicalDynamicClient(env.Origin, env.Tokens(NativeIdentityRole.Observer),
            scope, new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        string name = "definition-" + Guid.NewGuid().ToString("N");
        // Both names are caller-owned before dispatch, including an uncertain response.
        string? renamedName = method == "UpdateDefinitionAsync" && variant == "newName.value" ?
            "definition-" + Guid.NewGuid().ToString("N") : null;
        InfisicalDynamicTarget target = client.Definition(name);
        InfisicalDynamicDefinition? definition = null;
        InfisicalDatabaseLease? lease = null;
        InfisicalDynamicMutationReceipt? receipt = null;
        string? username = null, password = null;
        InfisicalLeaseObservation? independentLease = null;
        var passwordCredentials = new List<(DynamicBackendCoordinate Coordinate, SecretMaterial User, SecretMaterial Secret,
            DateTimeOffset ExpiresAt)>();
        bool attemptedDefinition = false;
        bool cleanupComplete = true;

        async ValueTask VerifyPasswordLeaseAsync(DynamicPasswordInput? policy, string? expectedUsername = null)
        {
            var coordinate = new DynamicBackendCoordinate(sql!.Engine, sql.Host,
                sql.Port, sql.Database, definition!.Id, lease!.Reference.Id);
            var captured = (Coordinate: coordinate, User: SecretMaterial.FromText(username!),
                Secret: SecretMaterial.FromText(password!), ExpiresAt: lease.Observation.ExpiresAt);
            bool fresh = passwordCredentials.All(previous => previous.Coordinate.LeaseId != coordinate.LeaseId);
            // Capture before any assertion can fail, and retain both trials until
            // reconciliation has independently rejected every issued credential.
            passwordCredentials.Add(captured);
            probe.Contract(fresh, NativeFailure.EffectMismatch);
            probe.Contract(policy is not null ? PasswordMatches(password!, policy) :
                username == expectedUsername, NativeFailure.EffectMismatch);
            var current = await observer.InspectDefinitionAsync(observer.Definition(name), token);
            probe.Contract(current.IsSuccess, NativeFailure.ObserverUnavailable);
            probe.Contract(current.Value.Id == definition.Id &&
                current.Value.Provider == InfisicalDynamicProvider.SqlDatabase, NativeFailure.EffectMismatch);
            var observed = await observer.ListLeasesAsync(current.Value, token);
            probe.Contract(observed.IsSuccess && observed.Value.IsComplete, NativeFailure.ObserverUnavailable);
            independentLease = observed.Value.Items.SingleOrDefault(item => item.Reference.Id == lease.Reference.Id);
            probe.Contract(independentLease is not null, NativeFailure.ObserverUnavailable);
            probe.Contract(independentLease!.CreatedAt == lease.Observation.CreatedAt &&
                independentLease.ExpiresAt == lease.Observation.ExpiresAt &&
                independentLease.Version == lease.Observation.Version, NativeFailure.EffectMismatch);
            if (backend is null) probe.Effect(NativeObservation.Unavailable);
            var facts = await backend!.MeasureAsync(coordinate, captured.User, captured.Secret, token);
            if (facts.Authentication == BackendAuthentication.Unavailable)
                probe.Effect(NativeObservation.Unavailable);
            probe.Contract(facts.Coordinate == coordinate && facts.Authentication == BackendAuthentication.Accepted &&
                facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
                facts.DeniedActions.SequenceEqual(input.DeniedActions) &&
                facts.ExpiresAt == independentLease.ExpiresAt, NativeFailure.EffectMismatch);
        }

        try
        {
            if (method != "CreateDefinitionAsync")
            {
                attemptedDefinition = true;
                var seeded = await client.CreateDefinitionAsync(target, seedProfile,
                    new(TimeSpan.FromSeconds(input.DefaultSeconds)),
                    new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                    new(target, InfisicalDynamicOperation.CreateDefinition), token,
                    usernameWitness ? new(input.BaselineUsernameTemplate) : null);
                probe.Contract(seeded.IsSuccess, NativeFailure.MissingPrerequisite);
                definition = seeded.Value;
            }
            bool needsLease = provider == InfisicalDynamicProvider.SqlDatabase &&
                ((passwordWitness || usernameWitness) && method == "UpdateDefinitionAsync" ||
                renamedName is not null || method is "InspectLeaseAsync" or "ListLeasesAsync" or "RenewAsync" or
                "RenewLeaseAsync" or "RevokeAsync" or "RevokeLeaseAsync" or "DeleteDefinitionAsync");
            if (needsLease)
            {
                var issued = await client.AcquireDatabaseAsync(definition!,
                    new(target, InfisicalDynamicOperation.Acquire), cancellationToken: token);
                probe.Contract(issued.IsSuccess, NativeFailure.MissingPrerequisite);
                lease = issued.Value;
                var copied = lease.CopyCredentials();
                probe.Contract(copied.IsSuccess, NativeFailure.MissingPrerequisite);
                using var credentials = copied.Value;
                username = credentials.RevealUsername();
                password = credentials.RevealPassword();
                if (passwordWitness)
                    await VerifyPasswordLeaseAsync(sql!.BaselinePasswordRequirements!);
                if (usernameWitness)
                    await VerifyPasswordLeaseAsync(null, input.BaselineUsernameTemplate);
            }
            selected.Role = denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime;
            InfisicalLeaseObservation? priorLease = lease?.Observation;
            if (lease is not null)
            {
                var observedDefinition = await observer.InspectDefinitionAsync(observer.Definition(name), token);
                probe.Contract(observedDefinition.IsSuccess, NativeFailure.ObserverUnavailable);
                var observations = await observer.ListLeasesAsync(observedDefinition.Value, token);
                probe.Contract(observations.IsSuccess && observations.Value.IsComplete, NativeFailure.ObserverUnavailable);
                var baseline = observations.Value.Items.SingleOrDefault(l => l.Reference.Id == lease.Reference.Id);
                probe.Contract(baseline is not null, NativeFailure.ObserverUnavailable);
                probe.Contract(baseline!.CreatedAt == priorLease!.CreatedAt &&
                    baseline.ExpiresAt == priorLease.ExpiresAt && baseline.Version == priorLease.Version,
                    NativeFailure.EffectMismatch);
                priorLease = baseline;
            }
            InfisicalLeaseObservation? returnedRenewal = null;
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            // Subscribe before Arm and the SDK call. This is an exact transport event.
            Task boundary = transport.Reached.Task;
            Task? cancellationTask = cancel ? boundary.ContinueWith(_ => cancellation.Cancel(),
                CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default) : null;
            transport.Arm();
            using InfisicalDynamicProfile profile = CreateProfile(variant);
            InfisicalLeaseDuration? ttl = variant == "ttl.omitted" ? null : new(TimeSpan.FromSeconds(input.TtlSeconds));
            SecretStatus status = SecretStatus.Unknown;
            try
            {
                switch (method)
                {
                    case "CreateDefinitionAsync":
                        attemptedDefinition = true;
                        receipt = new(target, InfisicalDynamicOperation.CreateDefinition);
                        var created = await client.CreateDefinitionAsync(target, profile,
                            new(TimeSpan.FromSeconds(input.DefaultSeconds)),
                            variant == "maximumTtl.omitted" ? null :
                                new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                            receipt, cancellation.Token, Options(input, variant));
                        status = created.Status;
                        if (created.IsSuccess) definition = created.Value;
                        break;
                    case "UpdateDefinitionAsync":
                    case "UpdateDefinitionPolicyAsync":
                        receipt = new(target, InfisicalDynamicOperation.UpdateDefinition);
                        var updated = method == "UpdateDefinitionPolicyAsync" ?
                            await client.UpdateDefinitionPolicyAsync(definition!,
                                new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                                variant == "maximumTtl.null" ? null : new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                                receipt, cancellation.Token) :
                            await client.UpdateDefinitionAsync(definition!, new(
                                variant == "defaultTtl.omitted" ? null : new(TimeSpan.FromSeconds(input.DefaultSeconds + 1)),
                                variant is "maximumTtl.omitted" or "maximumTtl.null" ? null :
                                    new(TimeSpan.FromSeconds(input.MaximumSeconds)),
                                clearMaximumTtl: variant == "maximumTtl.null",
                                inputs: variant == "inputs.omitted" ? null : profile,
                                newName: renamedName,
                                options: Options(input, variant),
                                clearUsernameTemplate: variant == "usernameTemplate.null"), receipt, cancellation.Token);
                        status = updated.Status;
                        if (updated.IsSuccess) definition = updated.Value;
                        break;
                    case "InspectDefinitionAsync":
                        var inspected = await client.InspectDefinitionAsync(target, cancellation.Token);
                        status = inspected.Status;
                        if (inspected.IsSuccess) probe.Contract(inspected.Value.Id == definition!.Id,
                            NativeFailure.ContractMismatch);
                        break;
                    case "ListDefinitionsAsync":
                        var definitions = await client.ListDefinitionsAsync(cancellation.Token);
                        status = definitions.Status;
                        if (definitions.IsSuccess) probe.Contract(definitions.Value.IsComplete &&
                            definitions.Value.Items.Count == 1 && definitions.Value.Items[0].Id == definition!.Id,
                            NativeFailure.ContractMismatch);
                        break;
                    case "AcquireDatabaseAsync":
                        receipt = new(target, InfisicalDynamicOperation.Acquire);
                        var acquired = await client.AcquireDatabaseAsync(definition!, receipt, ttl, cancellation.Token);
                        status = acquired.Status;
                        if (acquired.IsSuccess)
                        {
                            lease = acquired.Value;
                            using var credentials = lease.CopyCredentials().Value;
                            username = credentials.RevealUsername();
                            password = credentials.RevealPassword();
                        }
                        break;
                    case "InspectLeaseAsync":
                        var inspectedLease = await client.InspectLeaseAsync(lease!.Reference, cancellation.Token);
                        status = inspectedLease.Status;
                        if (inspectedLease.IsSuccess) probe.Contract(inspectedLease.Value.Reference.Id ==
                            lease.Reference.Id, NativeFailure.ContractMismatch);
                        break;
                    case "ListLeasesAsync":
                        var leases = await client.ListLeasesAsync(definition!, cancellation.Token);
                        status = leases.Status;
                        if (leases.IsSuccess) probe.Contract(leases.Value.IsComplete && leases.Value.Items.Count == 1 &&
                            leases.Value.Items[0].Reference.Id == lease!.Reference.Id, NativeFailure.ContractMismatch);
                        break;
                    case "RenewAsync":
                    case "RenewLeaseAsync":
                        receipt = new(lease!.Reference, InfisicalDynamicOperation.Renew);
                        var renewed = method == "RenewAsync" ?
                            await client.RenewAsync(lease, receipt, ttl, cancellation.Token) :
                            await client.RenewLeaseAsync(lease.Observation, receipt, ttl, cancellation.Token);
                        status = renewed.Status;
                        if (renewed.IsSuccess) returnedRenewal = renewed.Value;
                        if (renewed.IsSuccess) probe.Contract(renewed.Value.Reference.Id == lease.Reference.Id &&
                            renewed.Value.CreatedAt == priorLease!.CreatedAt &&
                            renewed.Value.Version >= priorLease.Version, NativeFailure.ContractMismatch);
                        break;
                    case "RevokeAsync":
                    case "RevokeLeaseAsync":
                        receipt = new(lease!.Reference, InfisicalDynamicOperation.Revoke);
                        var revoked = method == "RevokeAsync" ?
                            await client.RevokeAsync(lease, receipt, force, cancellation.Token) :
                            await client.RevokeLeaseAsync(lease.Reference, receipt, force, cancellation.Token);
                        status = revoked.Status;
                        if (revoked.IsSuccess) probe.Contract(revoked.Value.ForcedRecordRemoval == force &&
                            !revoked.Value.ExternalRevocationVerified, NativeFailure.ContractMismatch);
                        break;
                    case "DeleteDefinitionAsync":
                        receipt = new(target, InfisicalDynamicOperation.DeleteDefinition);
                        var deleted = await client.DeleteDefinitionAsync(definition!, receipt, force, cancellation.Token);
                        status = deleted.Status;
                        if (deleted.IsSuccess) probe.Contract(deleted.Value.ForcedRecordRemoval == force &&
                            !deleted.Value.ExternalRevocationVerified, NativeFailure.ContractMismatch);
                        break;
                    default:
                        probe.Contract(false, NativeFailure.ContractMismatch);
                        break;
                }
            }
            catch (OperationCanceledException) when (cancel && boundary.IsCompletedSuccessfully && !token.IsCancellationRequested)
            {
                status = SecretStatus.Unknown;
            }
            if (cancellationTask is not null) await cancellationTask.WaitAsync(token);
            probe.Contract(status == (cancel || lost ? SecretStatus.Unknown :
                denied ? SecretStatus.Denied : SecretStatus.Success), NativeFailure.ContractMismatch);
            if (cancel || lost) probe.Contract(boundary.IsCompletedSuccessfully, NativeFailure.ContractMismatch);
            if (receipt is not null)
                probe.Contract(receipt.Evidence == (cancel || lost ? DispatchEvidence.PossiblyDispatched :
                    denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied), NativeFailure.ContractMismatch);
            transport.Disarm();

            // An independently selected principal fetches the effect, not the operation's echo.
            string currentName = renamedName is not null && !denied && !cancel ? renamedName : name;
            var independentlyObserved = await observer.InspectDefinitionAsync(observer.Definition(currentName), token);
            if (renamedName is not null)
            {
                string absentName = currentName == name ? renamedName : name;
                var absent = await observer.InspectDefinitionAsync(observer.Definition(absentName), token);
                probe.Contract(absent.Status == SecretStatus.Absent, NativeFailure.EffectMismatch);
            }
            bool removed = method == "DeleteDefinitionAsync" && !denied && !cancel;
            bool notCreated = method == "CreateDefinitionAsync" && (denied || cancel);
            probe.Contract(removed || notCreated ? independentlyObserved.Status == SecretStatus.Absent :
                independentlyObserved.IsSuccess, NativeFailure.ObserverUnavailable);
            if (!removed && independentlyObserved.IsSuccess)
            {
                probe.Contract(independentlyObserved.Value.Provider == provider &&
                    (definition is null || independentlyObserved.Value.Id == definition.Id), NativeFailure.EffectMismatch);
                int expectedDefault = (method is "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync") &&
                    !denied && !cancel && variant != "defaultTtl.omitted" ? input.DefaultSeconds + 1 : input.DefaultSeconds;
                int? expectedMaximum = !denied && !cancel &&
                    (method == "CreateDefinitionAsync" && variant == "maximumTtl.omitted" ||
                        method is "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync" && variant == "maximumTtl.null") ?
                    null : input.MaximumSeconds;
                probe.Contract(independentlyObserved.Value.DefaultTtl.Duration == TimeSpan.FromSeconds(expectedDefault) &&
                    independentlyObserved.Value.MaximumTtl?.Duration == (expectedMaximum is { } seconds ?
                        TimeSpan.FromSeconds(seconds) : (TimeSpan?)null), NativeFailure.EffectMismatch);
                var observedLeases = await observer.ListLeasesAsync(independentlyObserved.Value, token);
                probe.Contract(observedLeases.IsSuccess && observedLeases.Value.IsComplete, NativeFailure.ObserverUnavailable);
                independentLease = lease is null ? null : observedLeases.Value.Items.SingleOrDefault(l =>
                    l.Reference.Id == lease.Reference.Id);
                if (method is "RenewAsync" or "RenewLeaseAsync" or "InspectLeaseAsync" or "ListLeasesAsync" &&
                    independentLease is not null)
                    probe.Contract(independentLease.CreatedAt == priorLease!.CreatedAt &&
                        independentLease.Version >= priorLease.Version, NativeFailure.EffectMismatch);
                if (method is "RenewAsync" or "RenewLeaseAsync")
                {
                    probe.Contract(independentLease is not null, NativeFailure.ObserverUnavailable);
                    if (!denied && !cancel)
                    {
                        // Unchanged expiry cannot distinguish a renewal from a no-op or a
                        // native lifetime ceiling. Continued authentication is not a witness.
                        probe.Contract(independentLease!.ExpiresAt > priorLease!.ExpiresAt,
                            NativeFailure.ObserverUnavailable);
                        if (returnedRenewal is not null)
                            probe.Contract(returnedRenewal.ExpiresAt == independentLease.ExpiresAt &&
                                returnedRenewal.Version == independentLease.Version, NativeFailure.EffectMismatch);
                    }
                    else probe.Contract(independentLease!.ExpiresAt == priorLease!.ExpiresAt,
                        NativeFailure.EffectMismatch);
                }
                if (method is "RevokeAsync" or "RevokeLeaseAsync")
                    probe.Contract(observedLeases.Value.Items.Any(l => l.Reference.Id == lease!.Reference.Id) ==
                        (denied || cancel), NativeFailure.EffectMismatch);
            }
            if (provider != InfisicalDynamicProvider.SqlDatabase)
            {
                // Typed dispatch and independent definition metadata are not proof
                // of protected input persistence or non-SQL credential/backend effects.
                probe.Effect(NativeObservation.Unavailable);
                return;
            }
            ArgumentNullException.ThrowIfNull(sql);
            if ((passwordWitness || usernameWitness) && notCreated)
            {
                // Denied/cancelled creation has no owned definition from which to issue
                // credentials. Independent absence is the negative effect, not policy proof.
                probe.Effect(NativeObservation.Matched);
                return;
            }
            if (((method is "CreateDefinitionAsync" or "UpdateDefinitionAsync" or "UpdateDefinitionPolicyAsync") &&
                !denied && !cancel || method is "InspectDefinitionAsync" or "ListDefinitionsAsync") &&
                independentlyObserved.IsSuccess || (passwordWitness || usernameWitness) && method == "UpdateDefinitionAsync")
            {
                selected.Role = NativeIdentityRole.Setup;
                if (passwordWitness)
                    await RequireDefinitionPasswordPolicyAsync(env, input.Sandbox.ProjectId, probe, token);
                if (usernameWitness && method == "UpdateDefinitionAsync")
                {
                    var captured = passwordCredentials[0];
                    var baselineFacts = await backend!.MeasureAsync(captured.Coordinate, captured.User,
                        captured.Secret, token);
                    if (baselineFacts.Authentication == BackendAuthentication.Unavailable)
                        probe.Effect(NativeObservation.Unavailable);
                    probe.Contract(baselineFacts.Coordinate == captured.Coordinate &&
                        baselineFacts.Authentication == BackendAuthentication.Accepted &&
                        baselineFacts.AllowedActions.SequenceEqual(input.AllowedActions) &&
                        baselineFacts.DeniedActions.SequenceEqual(input.DeniedActions) &&
                        baselineFacts.ExpiresAt == captured.ExpiresAt, NativeFailure.EffectMismatch);
                    if (denied || cancel)
                    {
                        // A literal role cannot be created twice. Verify the retained
                        // baseline before revocation, then prove absence before reissue.
                        selected.Role = NativeIdentityRole.Administrative;
                        var revoked = await client.RevokeAsync(lease!,
                            new(lease!.Reference, InfisicalDynamicOperation.Revoke), cancellationToken: token);
                        probe.Contract(revoked.IsSuccess, NativeFailure.CleanupIncomplete);
                        var rejected = await backend.MeasureAsync(captured.Coordinate, captured.User,
                            captured.Secret, token);
                        probe.Contract(rejected.Coordinate == captured.Coordinate &&
                            rejected.Authentication == BackendAuthentication.Rejected, NativeFailure.CleanupIncomplete);
                        var absence = await UsernameInventoryAsync(usernameObserver!, usernameCoordinate!,
                            plannedUsernames, token);
                        probe.Contract(absence.ExistingUsernames.Length == 0, NativeFailure.CleanupIncomplete);
                        selected.Role = NativeIdentityRole.Setup;
                    }
                }
                var current = await client.InspectDefinitionAsync(client.Definition(currentName), token);
                probe.Contract(current.IsSuccess, NativeFailure.MissingPrerequisite);
                definition = current.Value;
                var issued = await client.AcquireDatabaseAsync(definition,
                    new(definition.Target, InfisicalDynamicOperation.Acquire), cancellationToken: token);
                probe.Contract(issued.IsSuccess, usernameWitness ? NativeFailure.EffectMismatch : NativeFailure.MissingPrerequisite);
                lease?.Dispose();
                lease = issued.Value;
                independentLease = null;
                var copied = lease.CopyCredentials();
                probe.Contract(copied.IsSuccess, NativeFailure.MissingPrerequisite);
                using var credentials = copied.Value;
                username = credentials.RevealUsername();
                password = credentials.RevealPassword();
                if (passwordWitness)
                {
                    await VerifyPasswordLeaseAsync(method == "UpdateDefinitionAsync" && (denied || cancel) ?
                        sql.BaselinePasswordRequirements! : sql.PasswordRequirements!);
                    probe.Effect(NativeObservation.Matched);
                    return;
                }
                if (usernameWitness)
                {
                    await VerifyPasswordLeaseAsync(null, method == "UpdateDefinitionAsync" && (denied || cancel) ?
                        input.BaselineUsernameTemplate : input.UsernameTemplate);
                    if (method == "UpdateDefinitionAsync" && !denied && !cancel)
                    {
                        var captured = passwordCredentials[0];
                        var retained = await backend!.MeasureAsync(captured.Coordinate, captured.User,
                            captured.Secret, token);
                        if (retained.Authentication == BackendAuthentication.Unavailable)
                            probe.Effect(NativeObservation.Unavailable);
                        probe.Contract(retained.Coordinate == captured.Coordinate &&
                            retained.Authentication == BackendAuthentication.Accepted &&
                            retained.AllowedActions.SequenceEqual(input.AllowedActions) &&
                            retained.DeniedActions.SequenceEqual(input.DeniedActions) &&
                            retained.ExpiresAt == captured.ExpiresAt, NativeFailure.EffectMismatch);
                    }
                    probe.Effect(NativeObservation.Matched);
                    return;
                }
            }
            if (backend is null || username is null || password is null)
                probe.Effect(NativeObservation.Unavailable);
            using var user = SecretMaterial.FromText(username!);
            using var secret = SecretMaterial.FromText(password!);
            var coordinate = new DynamicBackendCoordinate(sql.Engine, sql.Host,
                sql.Port, sql.Database, definition!.Id, lease!.Reference.Id);
            if (variant is "sql.ca.value" or "sql.sslEnabled.true" or "sql.sslEnabled.false" or
                "gatewayId.value" or "gatewayId.null" or "gatewayPoolId.value" or "gatewayPoolId.null" or
                "usernameTemplate.value" or "usernameTemplate.null" or "metadata.value" or "metadata.empty" or "options.value" or
                "passwordRequirements.value" ||
                row.Key.Variant.StartsWith("NativeSqlDefinitionProfile.", StringComparison.Ordinal))
                // The current typed oracle measures permissions/authentication/expiry, not TLS routing,
                // naming or metadata persistence. The SDK case ran; those facts remain unavailable.
                probe.Effect(NativeObservation.Unavailable);
            DynamicBackendFacts facts = await backend!.MeasureAsync(coordinate, user, secret, token);
            if (facts.Authentication == BackendAuthentication.Unavailable)
                probe.Effect(NativeObservation.Unavailable);
            bool revokedEffect = (method is "RevokeAsync" or "RevokeLeaseAsync" or "DeleteDefinitionAsync") && !denied && !cancel;
            bool expectedRejection = revokedEffect && !force;
            probe.Effect(facts.Coordinate == coordinate &&
                facts.Authentication == (expectedRejection ? BackendAuthentication.Rejected : BackendAuthentication.Accepted) &&
                (expectedRejection || facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
                    facts.DeniedActions.SequenceEqual(input.DeniedActions) &&
                    facts.ExpiresAt == (independentLease ?? lease.Observation).ExpiresAt) ?
                NativeObservation.Matched : NativeObservation.Mismatched);
        }
        finally
        {
            // Reconcile owned provider records once; never replay the original uncertain mutation.
            // A failed cleanup stays failed; never escalate to forced record removal.
            try
            {
                selected.Role = NativeIdentityRole.Administrative;
                transport.Disarm();
                using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                if (attemptedDefinition)
                {
                    foreach (string ownedName in renamedName is null ? new[] { name } : new[] { name, renamedName })
                    {
                        var current = await client.InspectDefinitionAsync(client.Definition(ownedName), cleanup.Token);
                        if (current.IsSuccess)
                        {
                            var leases = await client.ListLeasesAsync(current.Value, cleanup.Token);
                            cleanupComplete &= leases.IsSuccess && leases.Value.IsComplete;
                            if (leases.IsSuccess)
                                foreach (var orphan in leases.Value.Items)
                                {
                                    var removed = await client.RevokeLeaseAsync(orphan.Reference,
                                        new(orphan.Reference, InfisicalDynamicOperation.Revoke),
                                        cancellationToken: cleanup.Token);
                                    cleanupComplete &= removed.IsSuccess;
                                }
                            var removedDefinition = await client.DeleteDefinitionAsync(current.Value,
                                new(current.Value.Target, InfisicalDynamicOperation.DeleteDefinition),
                                cancellationToken: cleanup.Token);
                            cleanupComplete &= removedDefinition.IsSuccess;
                        }
                        else cleanupComplete &= current.Status == SecretStatus.Absent;
                        var absence = await observer.InspectDefinitionAsync(observer.Definition(ownedName), cleanup.Token);
                        cleanupComplete &= absence.Status == SecretStatus.Absent;
                    }
                    if (!passwordWitness && !usernameWitness && backend is not null && username is not null && password is not null &&
                        definition is not null && lease is not null)
                    {
                        ArgumentNullException.ThrowIfNull(sql);
                        using var user = SecretMaterial.FromText(username);
                        using var secret = SecretMaterial.FromText(password);
                        var coordinate = new DynamicBackendCoordinate(sql.Engine, sql.Host,
                            sql.Port, sql.Database, definition.Id, lease.Reference.Id);
                        var state = await backend.MeasureAsync(coordinate, user, secret, cleanup.Token);
                        cleanupComplete &= state.Coordinate == coordinate &&
                            state.Authentication == BackendAuthentication.Rejected;
                    }
                }
            }
            catch (Exception) { cleanupComplete = false; }
            using var passwordCleanup = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            foreach (var captured in passwordCredentials)
            {
                try
                {
                    if (backend is null) cleanupComplete = false;
                    else
                    {
                        var state = await backend.MeasureAsync(captured.Coordinate, captured.User, captured.Secret,
                            passwordCleanup.Token);
                        cleanupComplete &= state.Coordinate == captured.Coordinate &&
                            state.Authentication == BackendAuthentication.Rejected;
                    }
                }
                catch (Exception) { cleanupComplete = false; }
                finally
                {
                    captured.User.Dispose();
                    captured.Secret.Dispose();
                }
            }
            if (usernameWitness)
            {
                try
                {
                    var absence = await UsernameInventoryAsync(usernameObserver!, usernameCoordinate!,
                        plannedUsernames, passwordCleanup.Token);
                    cleanupComplete &= absence.ExistingUsernames.Length == 0;
                }
                catch (Exception) { cleanupComplete = false; }
            }
            lease?.Dispose();
            if (!cleanupComplete) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }

    private static bool LiteralUsername(string? name) =>
        name is { Length: 23 } && name.StartsWith("sk_u_", StringComparison.Ordinal) &&
        name[21] == '_' && name[22] is 'a' or 'b' &&
        name.AsSpan(5, 16).ContainsAnyExcept("0123456789abcdef") == false;

    private static async ValueTask<DynamicUsernameFacts> UsernameInventoryAsync(
        IInfisicalDynamicUsernameObserver observer, DynamicUsernameCoordinate coordinate,
        string[] usernames, CancellationToken token)
    {
        var facts = await observer.InspectUsernamesAsync(coordinate, usernames, token);
        if (facts is null || facts.Coordinate != coordinate || !facts.IsComplete ||
            facts.RequestedUsernames is null || !facts.RequestedUsernames.SequenceEqual(usernames) ||
            facts.ExistingUsernames is null ||
            facts.ExistingUsernames.Distinct(StringComparer.Ordinal).Count() != facts.ExistingUsernames.Length ||
            facts.ExistingUsernames.Any(name => !usernames.Contains(name, StringComparer.Ordinal)))
            throw new NativeCaseFailureException("observer-unavailable");
        return facts;
    }

    private static bool ClosedPasswordPolicy(DynamicPasswordInput? policy) =>
        policy is
    {
        Length: 24, Lowercase: 6, Uppercase: 6, Digits: 6, Symbols: 6,
        AllowedSymbols: "!"
    } or
    {
        Length: 32, Lowercase: 8, Uppercase: 8, Digits: 8, Symbols: 8,
        AllowedSymbols: "!"
    };

    private static bool PasswordMatches(string password, DynamicPasswordInput policy)
    {
        if (password.Length != policy.Length) return false;
        int lowercase = 0, uppercase = 0, digits = 0, symbols = 0;
        foreach (char character in password)
        {
            switch (character)
            {
                case >= 'a' and <= 'z': lowercase++; break;
                case >= 'A' and <= 'Z': uppercase++; break;
                case >= '0' and <= '9': digits++; break;
                case '!': symbols++; break;
                default: return false;
            }
        }
        return lowercase == policy.Lowercase && uppercase == policy.Uppercase &&
            digits == policy.Digits && symbols == policy.Symbols;
    }

    private static async ValueTask RequireDefinitionPasswordPolicyAsync(NativeEnvironment env,
        string projectId, NativeCaseProbe probe, CancellationToken token)
    {
        // Dynamic validation rules can replace definition requirements. Do not guess
        // scope matching: only a complete inventory with every rule explicitly inactive
        // (including an empty inventory) excludes that competing explanation.
        await using var observer = env.CreateObserverClient();
        var rules = await observer.ListValidationRulesAsync(new(observer.Authority,
            new InfisicalValidationAddress(projectId, InfisicalValidationKind.DynamicSecrets)),
            cancellationToken: token);
        probe.Contract(rules.IsSuccess && rules.Value.IsComplete &&
            rules.Value.Items.All(rule => rule.IsActive == false), NativeFailure.ObserverUnavailable);
    }

    internal static NativeSqlDefinitionProfile Profile(DynamicSqlInput input, string variant)
    {
        variant = NormalizeSqlVariant(variant);
        DynamicPasswordInput? password = variant == "passwordRequirements.value" ? input.PasswordRequirements : null;
        using NativePasswordRequirements? requirements = password is null ? null :
            new(password.Length, password.Lowercase, password.Uppercase, password.Digits, password.Symbols, password.AllowedSymbols);
        return new(input.Engine, input.Host, input.Port, input.Username, input.Password, input.Database,
            input.CreationStatement, input.RevocationStatement,
            variant == "sql.renewStatement.omitted" ? null : input.RenewalStatement,
            variant == "sql.ca.omitted" ? null : input.Ca,
            variant switch
            {
                "sql.sslEnabled.omitted" => null,
                "sql.sslEnabled.false" => false,
                "sql.sslEnabled.true" => true,
                _ => input.SslEnabled
            },
            variant == "gatewayId.value" ? input.GatewayId : null,
            variant == "gatewayPoolId.value" ? input.GatewayPoolId : null,
            requirements, clearGatewayId: variant == "gatewayId.null", clearGatewayPoolId: variant == "gatewayPoolId.null");
    }

    private static NativeDynamicDefinitionOptions? Options(DynamicInput input, string variant) =>
        variant == "options.omitted" ? null : new(
            variant == "usernameTemplate.value" ? input.UsernameTemplate : null,
            variant == "metadata.omitted" ? null : variant == "metadata.value" ?
                input.Metadata.Select(m => new NativeDynamicMetadata(m.Key, m.Value)).ToArray() : []);

    internal sealed record DynamicInput(LifecycleSandbox Sandbox, DynamicSqlInput? Profile,
        int DefaultSeconds, int MaximumSeconds, int TtlSeconds, string? UsernameTemplate,
        DynamicMetadata[] Metadata, string[] AllowedActions, string[] DeniedActions,
        InfisicalDynamicProfileInput? NonSqlProfile = null,
        InfisicalDynamicAlternativeProfileInput? AlternativeProfile = null,
        InfisicalDynamicProvider? OptionProvider = null, string? AlternativeVariant = null,
        string? BaselineUsernameTemplate = null, SqlInputWitnessInput? SqlInputWitness = null,
        NonSqlInputWitnessInput? NonSqlInputWitness = null)
    {
        public override string ToString() => "[DynamicInput]";
    }
    internal sealed record DynamicMetadata(string Key, string? Value)
    {
        public override string ToString() => "[DynamicMetadata]";
    }
}

internal sealed record DynamicSqlInput(NativeSqlEngine Engine, string Host, int Port, string Database,
    string Username, string Password, string CreationStatement, string RevocationStatement,
    string? RenewalStatement, string? Ca, bool? SslEnabled, string? GatewayId, string? GatewayPoolId,
    DynamicPasswordInput? PasswordRequirements = null, DynamicPasswordInput? BaselinePasswordRequirements = null)
{
    public override string ToString() => "[DynamicSqlInput]";
}
internal sealed record DynamicPasswordInput(int Length, int Lowercase, int Uppercase, int Digits,
    int Symbols, string? AllowedSymbols)
{
    public override string ToString() => "[DynamicPasswordInput]";
}
internal enum BackendAuthentication { Accepted, Rejected, Unavailable }
internal sealed record DynamicBackendCoordinate(NativeSqlEngine Engine, string Host, int Port,
    string Database, Guid DefinitionId, Guid LeaseId)
{
    public override string ToString() => "[DynamicBackendCoordinate]";
}
internal sealed record DynamicBackendFacts(DynamicBackendCoordinate Coordinate,
    BackendAuthentication Authentication, string[] AllowedActions, string[] DeniedActions, DateTimeOffset? ExpiresAt)
{
    public override string ToString() => "[DynamicBackendFacts]";
}
internal interface IInfisicalDynamicBackendObserver
{
    ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate,
        SecretMaterial username, SecretMaterial password, CancellationToken token);
}

internal sealed record DynamicUsernameCoordinate(NativeSqlEngine Engine, string Host, int Port, string Database)
{
    public override string ToString() => "[DynamicUsernameCoordinate]";
}
internal sealed record DynamicUsernameFacts(DynamicUsernameCoordinate Coordinate,
    string[] RequestedUsernames, string[] ExistingUsernames, bool IsComplete)
{
    public override string ToString() => "[DynamicUsernameFacts]";
}
internal interface IInfisicalDynamicUsernameObserver
{
    ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
        IReadOnlyList<string> usernames, CancellationToken token);
}
