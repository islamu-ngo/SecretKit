using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class OwnedDynamicValidation : IAsyncDisposable
{
    private readonly ValidationPoliciesEffects.DynamicValidationInput input;
    private readonly NativeCaseProbe probe;
    private readonly IInfisicalDynamicBackendObserver backend;
    private readonly IInfisicalDynamicUsernameObserver usernames;
    private readonly InfisicalDynamicClient client;
    private readonly InfisicalDynamicClient observer;
    private readonly string name = "validation-" + Guid.NewGuid().ToString("N");
    private readonly List<Captured> captured = [];
    private InfisicalDynamicDefinition? definition;
    private bool attempted;
    private bool uncertainIssuance;

    private sealed record Captured(DynamicBackendCoordinate Coordinate, SecretMaterial User,
        SecretMaterial Password, DateTimeOffset ExpiresAt)
    {
        public override string ToString() => "[Captured]";
    }

    internal OwnedDynamicValidation(NativeEnvironment env, ValidationPoliciesEffects.DynamicValidationInput input,
        StaticOwnedFixture fixture, NativeCaseProbe probe, IInfisicalDynamicBackendObserver backend)
    {
        this.input = input;
        this.probe = probe;
        this.backend = backend;
        usernames = (IInfisicalDynamicUsernameObserver)backend;
        var scope = new InfisicalDynamicScope(input.ProjectSlug!, fixture.Input.Environment,
            fixture.Folder, Guid.Parse(fixture.FolderId));
        client = new(env.Origin, env.Tokens(NativeIdentityRole.Administrative), scope,
            new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        observer = new(env.Origin, env.Tokens(NativeIdentityRole.Observer), scope,
            new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
    }

    internal static async ValueTask AdmitAsync(NativeEnvironment env, ValidationPoliciesEffects.PolicyInput input,
        NativeCaseDefinition row, NativeCaseProbe probe, IInfisicalDynamicBackendObserver? backend, CancellationToken token)
    {
        var trial = input.DynamicTrial;
        if (trial is null || trial.Profile is null)
            throw new NativeCaseFailureException("missing-input");
        probe.Contract(!string.IsNullOrWhiteSpace(trial.ProjectSlug) && trial.DefaultSeconds > 0 &&
            trial.MaximumSeconds > trial.DefaultSeconds && trial.MaximumSeconds <= 31536000 &&
            trial.AllowedActions is { Length: > 0 } && trial.DeniedActions is { Length: > 0 },
            NativeFailure.MissingInput);
        if (trial.Profile.Engine != NativeSqlEngine.Postgres ||
            trial.Profile.PasswordRequirements is not
            { Length: 32, Lowercase: 8, Uppercase: 8, Digits: 8, Symbols: 8, AllowedSymbols: "!" } ||
            row.Key.Variant is not ("kind.DynamicSecrets" or "DynamicSecrets.SqlDatabase" or "isActive.true" or "isActive.false") ||
            input.AllKinds || !SupportedRule(input.Seed) || !SupportedRule(input.Change))
            probe.Effect(NativeObservation.Unavailable);
        if (backend is not IInfisicalDynamicUsernameObserver) probe.Effect(NativeObservation.Unavailable);
        probe.Contract(input.Entitled, NativeFailure.MissingPrerequisite);
        await using var reader = env.CreateObserverClient();
        var rules = await reader.ListValidationRulesAsync(new(reader.Authority,
            new InfisicalValidationAddress(input.Fixture.ProjectId, InfisicalValidationKind.DynamicSecrets)),
            cancellationToken: token);
        probe.Contract(rules.IsSuccess && rules.Value.IsComplete, NativeFailure.ObserverUnavailable);
        // Even inactive rules can conflict at save time. Do not infer glob matching,
        // precedence or ownership from another project's configured resource.
        probe.Contract(rules.Value.Items.Count == 0, NativeFailure.MissingPrerequisite);
    }

    private static bool SupportedRule(ValidationPoliciesEffects.RuleInput? rule) =>
        rule is
        {
            Name: null, IsActive: not null, SupplyEnvironment: true, SupplySecretPath: true,
            KeyConstraints: null, ValueConstraints: null, ClearEnvironment: false,
            ClearKeyConstraints: false, ClearValueConstraints: false
        } &&
        rule.Providers is [InfisicalValidationProvider.SqlDatabase] &&
        ValidationPoliciesEffects.SupportedPasswordConstraints(rule.PasswordConstraints);

    internal async ValueTask InitializeAsync(CancellationToken token)
    {
        var target = client.Definition(name);
        attempted = true;
        using var profile = InfisicalDynamicClientEffects.Profile(input.Profile, "passwordRequirements.value");
        var created = await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromSeconds(input.DefaultSeconds)), new(TimeSpan.FromSeconds(input.MaximumSeconds)),
            new(target, InfisicalDynamicOperation.CreateDefinition), token);
        probe.Contract(created.IsSuccess, NativeFailure.MissingPrerequisite);
        definition = created.Value;
        await DefinitionAsync(token);
    }

    private async ValueTask DefinitionAsync(CancellationToken token)
    {
        var read = await observer.InspectDefinitionAsync(observer.Definition(name), token);
        probe.Contract(read.IsSuccess, NativeFailure.ObserverUnavailable);
        probe.Contract(read.Value.Id == definition!.Id && read.Value.Version == definition.Version &&
            read.Value.Provider == InfisicalDynamicProvider.SqlDatabase &&
            read.Value.DefaultTtl.Duration == TimeSpan.FromSeconds(input.DefaultSeconds) &&
            read.Value.MaximumTtl?.Duration == TimeSpan.FromSeconds(input.MaximumSeconds), NativeFailure.EffectMismatch);
    }

    internal async ValueTask TrialAsync(ValidationPoliciesEffects.Constraints? constraints, CancellationToken token)
    {
        await DefinitionAsync(token);
        var receipt = new InfisicalDynamicMutationReceipt(definition!.Target, InfisicalDynamicOperation.Acquire);
        uncertainIssuance = true;
        var issued = await client.AcquireDatabaseAsync(definition!,
            receipt, cancellationToken: token);
        if (receipt.Evidence is DispatchEvidence.Rejected or DispatchEvidence.NotDispatched)
            uncertainIssuance = false;
        probe.Contract(issued.IsSuccess, NativeFailure.EffectMismatch);
        using var lease = issued.Value;
        var copied = lease.CopyCredentials();
        probe.Contract(copied.IsSuccess, NativeFailure.EffectMismatch);
        using var credentials = copied.Value;
        var item = new Captured(new(input.Profile.Engine, input.Profile.Host, input.Profile.Port,
            input.Profile.Database, definition.Id, lease.Reference.Id),
            SecretMaterial.FromText(credentials.RevealUsername()), SecretMaterial.FromText(credentials.RevealPassword()),
            lease.Observation.ExpiresAt);
        // Capture before assertions so even bad returned credentials enter reconciliation.
        captured.Add(item);
        uncertainIssuance = false;
        probe.Contract(captured.Count(c => c.Coordinate.LeaseId == item.Coordinate.LeaseId) == 1 &&
            captured.Count(c => c.User.Reveal() == item.User.Reveal()) == 1, NativeFailure.EffectMismatch);
        string password = item.Password.Reveal();
        probe.Contract(ValidationPoliciesEffects.GeneratedPasswordMatches(password, constraints), NativeFailure.EffectMismatch);
        var current = await observer.InspectDefinitionAsync(observer.Definition(name), token);
        probe.Contract(current.IsSuccess, NativeFailure.ObserverUnavailable);
        var inventory = await observer.ListLeasesAsync(current.Value, token);
        probe.Contract(inventory.IsSuccess && inventory.Value.IsComplete, NativeFailure.ObserverUnavailable);
        probe.Contract(inventory.Value.Items.Count == captured.Count &&
            inventory.Value.Items.Select(l => l.Reference.Id).Distinct().Count() == captured.Count &&
            inventory.Value.Items.All(l => captured.Any(c => c.Coordinate.LeaseId == l.Reference.Id)),
            NativeFailure.EffectMismatch);
        var observed = inventory.Value.Items.SingleOrDefault(l => l.Reference.Id == lease.Reference.Id);
        probe.Contract(observed is not null && observed.CreatedAt == lease.Observation.CreatedAt &&
            observed.ExpiresAt == lease.Observation.ExpiresAt && observed.Version == lease.Observation.Version,
            NativeFailure.EffectMismatch);
        await AcceptedAsync(item, token);
        // A fresh wrong-password attempt must fail on the same route. Rechecking the
        // valid pair excludes an unavailable database as the explanation for rejection.
        using var wrong = SecretMaterial.FromText(password + "wrong");
        var denied = await backend.MeasureAsync(item.Coordinate, item.User, wrong, token);
        if (denied.Authentication == BackendAuthentication.Unavailable) probe.Effect(NativeObservation.Unavailable);
        probe.Contract(denied.Coordinate == item.Coordinate && denied.Authentication == BackendAuthentication.Rejected,
            NativeFailure.EffectMismatch);
        await AcceptedAsync(item, token);
    }

    private async ValueTask AcceptedAsync(Captured item, CancellationToken token)
    {
        var facts = await backend.MeasureAsync(item.Coordinate, item.User, item.Password, token);
        if (facts.Authentication == BackendAuthentication.Unavailable) probe.Effect(NativeObservation.Unavailable);
        probe.Contract(facts.Coordinate == item.Coordinate && facts.Authentication == BackendAuthentication.Accepted &&
            facts.AllowedActions is not null && facts.DeniedActions is not null &&
            facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
            facts.DeniedActions.SequenceEqual(input.DeniedActions) && facts.ExpiresAt == item.ExpiresAt,
            NativeFailure.EffectMismatch);
    }

    internal ValueTask VerifyBaselineAsync(CancellationToken token) => AcceptedAsync(captured[0], token);

    public async ValueTask DisposeAsync()
    {
        // Listing/revocation can reconcile provider records after an uncertain
        // issuance, but missing material prevents independent rejection measurement.
        bool clean = !uncertainIssuance;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            if (attempted)
            {
                var current = await client.InspectDefinitionAsync(client.Definition(name), deadline.Token);
                if (current.IsSuccess)
                {
                    var leases = await client.ListLeasesAsync(current.Value, deadline.Token);
                    clean &= leases.IsSuccess && leases.Value.IsComplete;
                    if (leases.IsSuccess)
                        foreach (var lease in leases.Value.Items)
                        {
                            var removed = await client.RevokeLeaseAsync(lease.Reference,
                                new(lease.Reference, InfisicalDynamicOperation.Revoke), cancellationToken: deadline.Token);
                            clean &= removed.IsSuccess;
                        }
                    var remaining = await client.ListLeasesAsync(current.Value, deadline.Token);
                    clean &= remaining.IsSuccess && remaining.Value.IsComplete && remaining.Value.Items.Count == 0;
                    var deleted = await client.DeleteDefinitionAsync(current.Value,
                        new(current.Value.Target, InfisicalDynamicOperation.DeleteDefinition), cancellationToken: deadline.Token);
                    clean &= deleted.IsSuccess;
                }
                else clean &= current.Status == SecretStatus.Absent;
                var absence = await observer.InspectDefinitionAsync(observer.Definition(name), deadline.Token);
                clean &= absence.Status == SecretStatus.Absent;
            }
        }
        catch (Exception) { clean = false; }
        foreach (var item in captured)
        {
            try
            {
                var state = await backend.MeasureAsync(item.Coordinate, item.User, item.Password, deadline.Token);
                clean &= state.Coordinate == item.Coordinate && state.Authentication == BackendAuthentication.Rejected;
            }
            catch (Exception) { clean = false; }
        }
        if (captured.Count > 0)
        {
            try
            {
                string[] names = captured.Select(c => c.User.Reveal()).ToArray();
                var coordinate = new DynamicUsernameCoordinate(input.Profile.Engine, input.Profile.Host,
                    input.Profile.Port, input.Profile.Database);
                var absence = await usernames.InspectUsernamesAsync(coordinate, names, deadline.Token);
                clean &= absence is not null && absence.Coordinate == coordinate && absence.IsComplete &&
                    absence.RequestedUsernames is not null && absence.RequestedUsernames.SequenceEqual(names) &&
                    absence.ExistingUsernames is { Length: 0 };
            }
            catch (Exception) { clean = false; }
        }
        foreach (var item in captured)
        {
            item.User.Dispose();
            item.Password.Dispose();
        }
        try { await client.DisposeAsync(); }
        catch (Exception) { clean = false; }
        try { await observer.DisposeAsync(); }
        catch (Exception) { clean = false; }
        if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
    }
}
