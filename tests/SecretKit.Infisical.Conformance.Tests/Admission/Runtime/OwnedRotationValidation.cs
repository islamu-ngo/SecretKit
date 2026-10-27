using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class OwnedRotationValidation : IAsyncDisposable
{
    private readonly NativeEnvironment env;
    private readonly ValidationPoliciesEffects.RotationValidationInput input;
    private readonly StaticOwnedFixture folder;
    private readonly NativeCaseProbe probe;
    private readonly IInfisicalRotationValidationAccountFactory factory;
    private readonly IInfisicalRotationCredentialObserver backend;
    private readonly ManagementClient management;
    private readonly HttpClient http;
    private readonly string name = "rotation-validation-" + Guid.NewGuid().ToString("N");
    private readonly List<Pair> captured = [];
    private IInfisicalRotationValidationAccounts? accounts;
    private InfisicalRotationAddress? address;
    private readonly InfisicalRotationClient client;
    private bool accountsValidated;
    private bool attempted;
    private bool uncertainRotation;
    private RotationIdentityCatalogFacts? identitySnapshot;
    private readonly Dictionary<string, byte[]> loginSids = new(StringComparer.Ordinal);
    private string UserKey => name + "_USER";
    private string PasswordKey => name + "_PASSWORD";

    private sealed record Pair(SecretMaterial User, SecretMaterial Password)
    {
        public override string ToString() => "[RotationPair]";
    }

    internal OwnedRotationValidation(NativeEnvironment env, ValidationPoliciesEffects.RotationValidationInput input,
        StaticOwnedFixture folder, NativeCaseProbe probe, IInfisicalRotationValidationAccountFactory factory,
        IInfisicalRotationCredentialObserver backend, HttpMessageHandler? offlineTransport)
    {
        this.env = env;
        this.input = input;
        this.folder = folder;
        this.probe = probe;
        this.factory = factory;
        this.backend = backend;
        management = env.CreateManagementClient();
        http = offlineTransport is null ? new(new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false }) :
            new(offlineTransport, disposeHandler: false);
        http.Timeout = Timeout.InfiniteTimeSpan;
        var authority = new SecretAuthority();
        // Only an injected offline handler accepts the scheme-adjusted loopback
        // URI. Native execution retains the configured trusted HTTPS origin.
        var origin = offlineTransport is null ? env.Origin : new UriBuilder(env.Origin) { Scheme = "https" }.Uri;
        client = new(origin, authority, new(authority, env.Tokens(NativeIdentityRole.Administrative),
            folder.Input.ProjectId), new() { Transport = InfisicalTransportOptions.HostControlled(http) });
    }

    internal static async ValueTask AdmitAsync(NativeEnvironment env, ValidationPoliciesEffects.PolicyInput input,
        NativeCaseDefinition row, NativeCaseProbe probe, IInfisicalRotationValidationAccountFactory? factory,
        IInfisicalRotationCredentialObserver? backend, HttpMessageHandler? offlineTransport, CancellationToken token)
    {
        var trial = input.RotationTrial;
        if (trial is null) throw new NativeCaseFailureException("missing-input");
        probe.Contract(input.MaximumItems is >= 1 and <= 1000 && !string.IsNullOrWhiteSpace(trial.OrganizationId) &&
            Guid.TryParseExact(trial.ConnectionId, "D", out _) && !string.IsNullOrWhiteSpace(trial.Host) &&
            trial.Port is >= 1 and <= 65535 && !string.IsNullOrWhiteSpace(trial.Database) &&
            trial.RotationInterval >= 1 && trial.AllowedActions is { Length: > 0 } &&
            trial.DeniedActions is { Length: > 0 }, NativeFailure.MissingInput);
        InfisicalValidationProvider? provider = trial.Profile switch
        {
            InfisicalRotationProfile.PostgresCredentials => InfisicalValidationProvider.PostgresCredentials,
            InfisicalRotationProfile.MysqlCredentials => InfisicalValidationProvider.MysqlCredentials,
            InfisicalRotationProfile.MssqlCredentials => InfisicalValidationProvider.MssqlCredentials,
            _ => null
        };
        if (provider is null || row.Key.Variant != "SecretRotations." + provider &&
            row.Key.Variant is not ("kind.SecretRotations" or "isActive.true" or "isActive.false") ||
            input.AllKinds || !Supported(input.Seed, provider) || !Supported(input.Change, provider))
            probe.Effect(NativeObservation.Unavailable);
        if (factory is null || (trial.Profile == InfisicalRotationProfile.PostgresCredentials ?
            backend is not IInfisicalDynamicUsernameObserver : backend is not IInfisicalRotationIdentityCatalogObserver))
            probe.Effect(NativeObservation.Unavailable);
        // RequestHeadersStart cancellation preserves dispatch uncertainty. A native
        // post-cancel snapshot does not prove the server will not commit later.
        // The controlled offline adapter tests pre-send non-occurrence only.
        if (row.Key.Case == "cancellation-boundary" && offlineTransport is null)
            probe.Effect(NativeObservation.Unavailable);
        probe.Contract(input.Entitled, NativeFailure.MissingPrerequisite);
        await using var observer = env.CreateObserverClient();
        var rules = await observer.ListValidationRulesAsync(new(observer.Authority,
            new InfisicalValidationAddress(input.Fixture.ProjectId, InfisicalValidationKind.SecretRotations)),
            cancellationToken: token);
        probe.Contract(rules.IsSuccess && rules.Value.IsComplete, NativeFailure.ObserverUnavailable);
        probe.Contract(rules.Value.Items.Count == 0, NativeFailure.MissingPrerequisite);
    }

    private static bool Supported(ValidationPoliciesEffects.RuleInput? rule, InfisicalValidationProvider? provider) =>
        rule is
        {
            Name: null, IsActive: not null, SupplyEnvironment: true, SupplySecretPath: true,
            KeyConstraints: null, ValueConstraints: null, ClearEnvironment: false,
            ClearKeyConstraints: false, ClearValueConstraints: false
        } &&
        rule.Providers is [var selected] && selected == provider &&
        ValidationPoliciesEffects.SupportedPasswordConstraints(rule.PasswordConstraints);

    internal async ValueTask InitializeAsync(CancellationToken token)
    {
        accounts = await factory.CreateAsync(folder.Input.ProjectId, input, token);
        var expected = new RotationBackendCoordinate(input.Profile,
            input.Host, input.Port, input.Database, accounts.Username1);
        probe.Contract(accounts.Coordinate == expected && accounts.Username1 is { Length: 24 } first &&
            first.StartsWith("sk_rv_", StringComparison.Ordinal) && first.EndsWith("_a", StringComparison.Ordinal) &&
            !first.AsSpan(6, 16).ContainsAnyExcept("0123456789abcdef") &&
            accounts.Username2 == first[..^1] + "b", NativeFailure.ObserverUnavailable);
        accountsValidated = true;
        if (input.Profile != InfisicalRotationProfile.PostgresCredentials)
        {
            var observed = await ((IInfisicalRotationIdentityCatalogObserver)backend)
                .InspectIdentityCatalogAsync(expected, [accounts.Username1, accounts.Username2], token);
            probe.Contract(RotationSqlIdentityEvidence.Bound(observed, expected, [accounts.Username1, accounts.Username2]) &&
                RotationSqlIdentityEvidence.Owned(observed, [accounts.Username1, accounts.Username2]) &&
                RotationSqlIdentityEvidence.PolicyCompatible(observed), NativeFailure.ObserverUnavailable);
            identitySnapshot = observed.Mysql is { } mysql ? observed with
            {
                Mysql = mysql with
                {
                    PasswordPolicy = mysql.PasswordPolicy with
                    {
                        ActiveValidationPlugins = [.. mysql.PasswordPolicy.ActiveValidationPlugins],
                        InstalledValidationComponents = [.. mysql.PasswordPolicy.InstalledValidationComponents]
                    }
                }
            } : observed;
            if (observed.Mssql is { } mssql)
                foreach (var login in mssql.ServerPrincipals) loginSids.Add(login.Name, login.Sid.ToArray());
        }
        attempted = true;
        var value = await CreateAsync(token);
        probe.Contract(value is not null, NativeFailure.MissingPrerequisite);
        address = new(folder.Input.ProjectId, folder.Input.Environment, folder.Folder,
            input.Profile, value!.Id);
        Matches(value);
        await InspectAsync(token);
    }

    private sealed record State(string Id, string Name, string ProjectId, string Environment, string EnvironmentId,
        string SecretPath, string FolderId, string ConnectionId, string Username1, string Username2,
        bool HasStatement, bool? Auto, double Interval, double? ActiveIndex, string UserKey, string PasswordKey,
        DatabasePasswordRequirements? PasswordPolicy)
    {
        public override string ToString() => "[RotationValidationState]";
    }

    private static State Project(PostgresSecretRotationSummary s) => new(s.Id, s.Name, s.ProjectId, s.Environment,
        s.EnvironmentId, s.SecretPath, s.FolderId, s.ConnectionId, s.Parameters.Username1, s.Parameters.Username2,
        s.Parameters.RotationStatement is not null, s.IsAutoRotationEnabled, s.RotationInterval, s.ActiveIndex,
        s.SecretsMapping.Username, s.SecretsMapping.Password, s.Parameters.PasswordRequirements is { } p ?
            new(p.Length, p.Digits, p.Lowercase, p.Symbols, p.Uppercase, p.AllowedSymbols) : null);
    private static State Project(MySqlSecretRotationSummary s) => new(s.Id, s.Name, s.ProjectId, s.Environment,
        s.EnvironmentId, s.SecretPath, s.FolderId, s.ConnectionId, s.Parameters.Username1, s.Parameters.Username2,
        s.Parameters.RotationStatement is not null, s.IsAutoRotationEnabled, s.RotationInterval, s.ActiveIndex,
        s.SecretsMapping.Username, s.SecretsMapping.Password, s.Parameters.PasswordRequirements is { } p ?
            new(p.Length, p.Digits, p.Lowercase, p.Symbols, p.Uppercase, p.AllowedSymbols) : null);
    private static State Project(MsSqlSecretRotationSummary s) => new(s.Id, s.Name, s.ProjectId, s.Environment,
        s.EnvironmentId, s.SecretPath, s.FolderId, s.ConnectionId, s.Parameters.Username1, s.Parameters.Username2,
        s.Parameters.RotationStatement is not null, s.IsAutoRotationEnabled, s.RotationInterval, s.ActiveIndex,
        s.SecretsMapping.Username, s.SecretsMapping.Password, s.Parameters.PasswordRequirements is { } p ?
            new(p.Length, p.Digits, p.Lowercase, p.Symbols, p.Uppercase, p.AllowedSymbols) : null);

    private async ValueTask<State?> ExecuteAsync<T>(ManagementRequest<T> request, NativeIdentityRole role, bool mutation,
        Func<T, State> project, CancellationToken token) where T : IDisposable
    {
        var authority = env.CreateManagementAuthority(management, role, input.OrganizationId, folder.Input.ProjectId);
        var receipt = mutation ? management.CreateReceipt(request) : null;
        var result = await management.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        if (result.Status == SecretStatus.Absent) return null;
        probe.Contract(result.IsSuccess, role == NativeIdentityRole.Setup ?
            NativeFailure.MissingPrerequisite : NativeFailure.ObserverUnavailable);
        using var value = result.Value;
        if (mutation) probe.Contract(receipt!.Evidence == DispatchEvidence.Applied, NativeFailure.ContractMismatch);
        return project(value);
    }

    private async ValueTask<State?> CreateAsync(CancellationToken token)
    {
        switch (input.Profile)
        {
            case InfisicalRotationProfile.PostgresCredentials:
                using (var p = new PostgresRotationParameters(accounts!.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!")))
                using (var r = PostgresSecretRotationOperations.Create(input.OrganizationId, new(name, folder.Input.ProjectId,
                    folder.Input.Environment, folder.Folder, input.ConnectionId, input.RotationInterval, p,
                    new(UserKey, PasswordKey), isAutoRotationEnabled: false)))
                    return await ExecuteAsync(r, NativeIdentityRole.Setup, true, Project, token);
            case InfisicalRotationProfile.MysqlCredentials:
                using (var p = new MySqlRotationParameters(accounts!.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!")))
                using (var r = MySqlSecretRotationOperations.Create(input.OrganizationId, new(name, folder.Input.ProjectId,
                    folder.Input.Environment, folder.Folder, input.ConnectionId, input.RotationInterval, p,
                    new(UserKey, PasswordKey), isAutoRotationEnabled: false)))
                    return await ExecuteAsync(r, NativeIdentityRole.Setup, true, Project, token);
            case InfisicalRotationProfile.MssqlCredentials:
                using (var p = new MsSqlRotationParameters(accounts!.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!")))
                using (var r = MsSqlSecretRotationOperations.Create(input.OrganizationId, new(name, folder.Input.ProjectId,
                    folder.Input.Environment, folder.Folder, input.ConnectionId, input.RotationInterval, p,
                    new(UserKey, PasswordKey), isAutoRotationEnabled: false)))
                    return await ExecuteAsync(r, NativeIdentityRole.Setup, true, Project, token);
            default: throw new NativeCaseFailureException("observer-unavailable");
        }
    }

    private async ValueTask<State?> ReadAsync(NativeIdentityRole role, CancellationToken token,
        bool byName = false, bool delete = false)
    {
        switch (input.Profile)
        {
            case InfisicalRotationProfile.PostgresCredentials:
                using (var r = delete ? PostgresSecretRotationOperations.Delete(input.OrganizationId, address!, true, true) :
                    byName ? PostgresSecretRotationOperations.GetByName(input.OrganizationId, folder.Input.ProjectId,
                        folder.Input.Environment, folder.Folder, name) : PostgresSecretRotationOperations.Get(input.OrganizationId, address!))
                    return await ExecuteAsync(r, role, delete, Project, token);
            case InfisicalRotationProfile.MysqlCredentials:
                using (var r = delete ? MySqlSecretRotationOperations.Delete(input.OrganizationId, address!, true, true) :
                    byName ? MySqlSecretRotationOperations.GetByName(input.OrganizationId, folder.Input.ProjectId,
                        folder.Input.Environment, folder.Folder, name) : MySqlSecretRotationOperations.Get(input.OrganizationId, address!))
                    return await ExecuteAsync(r, role, delete, Project, token);
            case InfisicalRotationProfile.MssqlCredentials:
                using (var r = delete ? MsSqlSecretRotationOperations.Delete(input.OrganizationId, address!, true, true) :
                    byName ? MsSqlSecretRotationOperations.GetByName(input.OrganizationId, folder.Input.ProjectId,
                        folder.Input.Environment, folder.Folder, name) : MsSqlSecretRotationOperations.Get(input.OrganizationId, address!))
                    return await ExecuteAsync(r, role, delete, Project, token);
            default: throw new NativeCaseFailureException("observer-unavailable");
        }
    }

    private int Matches(State value)
    {
        var policy = value.PasswordPolicy;
        probe.Contract(value.Id == address!.RotationId && value.Name == name &&
            value.ProjectId == folder.Input.ProjectId && value.Environment == folder.Input.Environment &&
            value.EnvironmentId == folder.Input.EnvironmentId && value.SecretPath == folder.Folder &&
            value.FolderId == folder.FolderId && value.ConnectionId == input.ConnectionId &&
            value.Username1 == accounts!.Username1 && value.Username2 == accounts.Username2 &&
            !value.HasStatement && value.Auto == false && value.Interval == input.RotationInterval &&
            value.UserKey == UserKey && value.PasswordKey == PasswordKey &&
            policy is { Length: 32, Digits: 8, Lowercase: 8, Symbols: 8, Uppercase: 8, AllowedSymbols: "!" },
            NativeFailure.EffectMismatch);
        probe.Contract(value.ActiveIndex is 0 or 1, NativeFailure.ObserverUnavailable);
        return (int)value.ActiveIndex!.Value;
    }

    private async ValueTask<int> InspectAsync(CancellationToken token)
    {
        var observed = await ReadAsync(NativeIdentityRole.Observer, token);
        probe.Contract(observed is not null, NativeFailure.ObserverUnavailable);
        return Matches(observed!);
    }

    internal async ValueTask TrialAsync(ValidationPoliciesEffects.Constraints? constraints, CancellationToken token)
    {
        int prior = await InspectAsync(token);
        var target = new SecretReference(client.Authority, address!);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        uncertainRotation = true;
        var rotated = await client.RotateSecretsAsync(target, receipt, cancellationToken: token);
        if (receipt.Dispatch is InfisicalRotationDispatch.NotDispatched or InfisicalRotationDispatch.Rejected)
            uncertainRotation = false;
        probe.Contract(rotated.IsSuccess && receipt.Dispatch == InfisicalRotationDispatch.ResponseObserved &&
            receipt.Effect == InfisicalRotationEffect.AcceptedPending, NativeFailure.ObserverUnavailable);
        int active = 1 - prior;
        // Both reads are performed even if one fails; dispose every successful
        // result before reporting failure instead of abandoning the first material.
        var user = await folder.Runtime.ReadAsync(folder.Secret(folder.Runtime, UserKey), token);
        using var ownedUser = user.IsSuccess ? user.Value : null;
        var password = await folder.Runtime.ReadAsync(folder.Secret(folder.Runtime, PasswordKey), token);
        using var ownedPassword = password.IsSuccess ? password.Value : null;
        probe.Contract(user.IsSuccess && password.IsSuccess, NativeFailure.ObserverUnavailable);
        var pair = new Pair(ownedUser!.Material.Copy(), ownedPassword!.Material.Copy());
        captured.Add(pair);
        uncertainRotation = false;
        probe.Contract(await InspectAsync(token) == active, NativeFailure.EffectMismatch);
        probe.Contract(pair.User.Reveal() == (active == 0 ? accounts!.Username1 : accounts!.Username2) &&
            captured.Count(p => p.User.Reveal() == pair.User.Reveal()) == 1, NativeFailure.EffectMismatch);
        string secret = pair.Password.Reveal();
        probe.Contract(ValidationPoliciesEffects.GeneratedPasswordMatches(secret, constraints), NativeFailure.EffectMismatch);
        await AcceptedAsync(pair, token);
        using var wrong = SecretMaterial.FromText(secret + "wrong");
        var rejected = await backend.MeasureCredentialsAsync(accounts!.Coordinate, pair.User, wrong, token);
        if (rejected.Authentication == BackendAuthentication.Unavailable) probe.Effect(NativeObservation.Unavailable);
        probe.Contract(rejected.Coordinate == accounts.Coordinate &&
            rejected.Authentication == BackendAuthentication.Rejected && rejected.AuthenticatedUsername is null &&
            rejected.Identity is null,
            NativeFailure.EffectMismatch);
        await AcceptedAsync(pair, token);
    }

    private async ValueTask AcceptedAsync(Pair pair, CancellationToken token)
    {
        var facts = await backend.MeasureCredentialsAsync(accounts!.Coordinate, pair.User, pair.Password, token);
        if (facts.Authentication == BackendAuthentication.Unavailable) probe.Effect(NativeObservation.Unavailable);
        probe.Contract(facts.Coordinate == accounts.Coordinate && facts.Authentication == BackendAuthentication.Accepted &&
            facts.AuthenticatedUsername == pair.User.Reveal() && facts.AllowedActions is not null &&
            facts.DeniedActions is not null && facts.AllowedActions.SequenceEqual(input.AllowedActions) &&
            facts.DeniedActions.SequenceEqual(input.DeniedActions) && IdentityMatches(facts.Identity, pair.User.Reveal()),
            NativeFailure.EffectMismatch);
    }

    private bool IdentityMatches(RotationCredentialIdentity? identity, string username)
    {
        if (input.Profile == InfisicalRotationProfile.PostgresCredentials) return identity is null;
        if (input.Profile == InfisicalRotationProfile.MysqlCredentials)
            return identity is { Mssql: null, Mysql: { } mysql } &&
                mysql.CurrentUser == username + "@%" && mysql.Database == input.Database;
        return identity is { Mysql: null, Mssql: { } mssql } && loginSids.TryGetValue(username, out var sid) &&
            mssql.OriginalLogin == username && mssql.ExecutionLogin == username && mssql.DatabaseUser == username &&
            mssql.Database == input.Database && mssql.OriginalLoginSid is not null &&
            mssql.ExecutionLoginSid is not null && mssql.DatabaseUserSid is not null &&
            mssql.OriginalLoginSid.AsSpan().SequenceEqual(sid) &&
            mssql.ExecutionLoginSid.AsSpan().SequenceEqual(sid) && mssql.DatabaseUserSid.AsSpan().SequenceEqual(sid);
    }

    internal ValueTask VerifyBaselineAsync(CancellationToken token) => AcceptedAsync(captured[0], token);

    public async ValueTask DisposeAsync()
    {
        bool clean = !uncertainRotation;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            if (attempted)
            {
                var current = await ReadAsync(NativeIdentityRole.Administrative, deadline.Token, byName: true);
                if (current is not null)
                {
                    if (address is not null && current.Id != address.RotationId) clean = false;
                    else
                    {
                        address ??= new(folder.Input.ProjectId, folder.Input.Environment, folder.Folder,
                            input.Profile, current.Id);
                        await ReadAsync(NativeIdentityRole.Administrative, deadline.Token, delete: true);
                        clean &= await ReadAsync(NativeIdentityRole.Observer, deadline.Token) is null;
                    }
                }
                foreach (string key in new[] { UserKey, PasswordKey })
                {
                    var gone = await folder.Observer.ReadAsync(folder.Secret(folder.Observer, key), deadline.Token);
                    if (gone.IsSuccess) gone.Value.Dispose();
                    clean &= gone.Status == SecretStatus.Absent;
                }
            }
        }
        catch (Exception) { clean = false; }
        foreach (var pair in captured)
        {
            try
            {
                var rejected = await backend.MeasureCredentialsAsync(accounts!.Coordinate, pair.User, pair.Password, deadline.Token);
                clean &= rejected.Coordinate == accounts.Coordinate && rejected.Authentication == BackendAuthentication.Rejected &&
                    rejected.AuthenticatedUsername is null && rejected.Identity is null;
            }
            catch (Exception) { clean = false; }
        }
        if (accounts is not null)
        {
            try { await accounts.DisposeAsync(); }
            catch (Exception) { clean = false; }
            if (input.Profile != InfisicalRotationProfile.PostgresCredentials)
            {
                try
                {
                    string[] names = [accounts.Username1, accounts.Username2];
                    var coordinate = new RotationBackendCoordinate(input.Profile, input.Host, input.Port, input.Database, names[0]);
                    var absence = await ((IInfisicalRotationIdentityCatalogObserver)backend)
                        .InspectIdentityCatalogAsync(coordinate, names, deadline.Token);
                    clean &= RotationSqlIdentityEvidence.Bound(absence, coordinate, names) &&
                        RotationSqlIdentityEvidence.IsAbsent(absence) && RotationSqlIdentityEvidence.PolicyCompatible(absence) &&
                        (input.Profile != InfisicalRotationProfile.MysqlCredentials || identitySnapshot is null ||
                            RotationSqlIdentityEvidence.SameMysqlPolicy(identitySnapshot, absence));
                }
                catch (Exception) { clean = false; }
            }
            else if (accountsValidated)
            {
                try
                {
                    string[] names = [accounts.Username1, accounts.Username2];
                    var coordinate = new DynamicUsernameCoordinate(NativeSqlEngine.Postgres, input.Host, input.Port, input.Database);
                    var absence = await ((IInfisicalDynamicUsernameObserver)backend).InspectUsernamesAsync(coordinate, names, deadline.Token);
                    clean &= absence is not null && absence.Coordinate == coordinate && absence.IsComplete &&
                        absence.RequestedUsernames is not null && absence.RequestedUsernames.SequenceEqual(names) &&
                        absence.ExistingUsernames is { Length: 0 };
                }
                catch (Exception) { clean = false; }
            }
        }
        foreach (var pair in captured)
        {
            pair.User.Dispose();
            pair.Password.Dispose();
        }
        http.Dispose();
        if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
    }
}
