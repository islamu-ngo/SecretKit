using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Transport is explicitly host-owned. The controlled HTTPS facade is supplied
// only by the test host; production never downgrades HTTPS or creates a worker.
internal sealed record RotationPermissionRuntime(Uri Origin, HttpClient Transport);
internal sealed class RotationPermissionTokens(IInfisicalTokenSource source) : IInfisicalTokenSource
{
    private int used;
    internal string Hash { get; private set; } = "";
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        RotationPermissionContract.Require(Interlocked.Exchange(ref used, 1) == 0);
        var result = await source.GetTokenAsync(token);
        if (result.IsSuccess)
        {
            try { token.ThrowIfCancellationRequested(); Hash = RotationPermissionContract.Hash(result.Value.Material.Reveal()); }
            catch { result.Value.Dispose(); throw; }
        }
        return result;
    }
}
internal static class RotationPermissionClient
{
    internal static NativeIdentityRole Role(RotationPermissionRoot root, string principal) =>
        principal == root.Authorities.Setup ? NativeIdentityRole.Setup :
        principal == root.Authorities.Runtime ? NativeIdentityRole.Runtime :
        principal == root.Authorities.Denied ? NativeIdentityRole.Denied :
        principal == root.Authorities.Administrative ? NativeIdentityRole.Administrative :
        principal == root.Authorities.Observer ? NativeIdentityRole.Observer :
        throw new NativeCaseFailureException("missing-input");
    internal static RotationPermissionConfiguration Value(PostgresSecretRotationSummary s)
    {
        var p = s.Parameters; var r = p.PasswordRequirements;
        RotationPermissionContract.Require(r is not null && p.RotationStatement is not null, "effect-mismatch");
        return new(s.Id, s.ProjectId, s.Environment, s.SecretPath, s.ConnectionId, s.Name, p.Username1, p.Username2,
            s.SecretsMapping.Username, s.SecretsMapping.Password, s.RotationInterval, s.RotateAtUtc.Hours,
            s.RotateAtUtc.Minutes, s.IsAutoRotationEnabled == true, s.HasDescription, s.Description, r!.Length,
            r.Digits, r.Lowercase, r.Symbols, r.Uppercase, r.AllowedSymbols ?? "",
            RotationPermissionContract.Hash(p.RotationStatement!.Reveal()), s.EnvironmentId, s.FolderId,
            InfisicalRotationProfile.PostgresCredentials);
    }
    internal static async ValueTask<RotationPermissionAttempt> ExecuteAsync(NativeEnvironment env,
        RotationPermissionRoot root, RotationPermissionRow row, CancellationToken token,
        RotationPermissionRuntime? runtime = null)
    {
        var tokens = new RotationPermissionTokens(env.Tokens(Role(root, row.Principal)));
        if (row.Action == RotationPermissionAction.RotateSecrets)
        {
            // Explicit native transport prerequisite, not a secret read or a
            // fabricated management trigger. Runtime receipts remain native.
            RotationPermissionContract.Require(runtime is not null &&
                (root.Kind == RotationPermissionSourceKind.ControlledFixture || runtime.Origin == env.Origin), "missing-prerequisite");
            await using var client = new InfisicalClient(env.Origin, tokens,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
            var target = new SecretReference(client.Authority, row.Address);
            var authority = new InfisicalNativeAuthority(client.Authority, tokens, row.Project);
            var native = new InfisicalRotationClient(runtime!.Origin, runtime.Transport,
                client.Authority, authority);
            var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
            var result = await native.RotateSecretsAsync(target, receipt, cancellationToken: token);
            return new(row, tokens.Hash, result.Status, null, receipt.Dispatch, [], true, []);
        }
        if (row.SqlProfile == InfisicalRotationProfile.MysqlCredentials)
            return await MySqlAsync(env, root, row, tokens, token);
        if (row.SqlProfile == InfisicalRotationProfile.MssqlCredentials)
            return await MsSqlAsync(env, root, row, tokens, token);
        var management = env.CreateManagementClient();
        using var statement = SecretMaterial.FromText(RotationPermissionContract.Statement);
        using var parameters = new PostgresRotationParameters(row.Username1, row.Username2,
            new(24, 2, 2, 2, 2, "!@"), statement);
        var initial = RotationPermissionContract.Initial(row);
        var edited = RotationPermissionContract.Edited(initial);
        using var editedStatement = SecretMaterial.FromText(RotationPermissionContract.Statement + " -- changed");
        using var editedParameters = new PostgresRotationParameters(row.Username1, row.Username2,
            new(32, 3, 3, 3, 3, "!@#"), editedStatement);
        RotationPermissionAttempt Result(SecretStatus status, ManagementReceipt? receipt,
            RotationPermissionConfiguration[] values, bool complete = true, string[]? hashes = null) =>
            new(row, tokens.Hash, status,
                row.Action is RotationPermissionAction.Read or RotationPermissionAction.ReadGeneratedCredentials ? null : receipt?.Evidence,
                null, values, complete, hashes ?? []);
        async ValueTask<(SecretOutcome<T> Outcome, ManagementReceipt? Receipt)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var authority = new ManagementAuthority(management.Authority, tokens, root.Organization, row.Project);
            var receipt = request.IsMutation ? management.CreateReceipt(request) : null;
            return (await management.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), receipt, token), receipt);
        }
        if (row.List)
        {
            using var request = PostgresSecretRotationOperations.List(root.Organization, row.Project);
            var (outcome, receipt) = await Send(request);
            if (!outcome.IsSuccess) return Result(outcome.Status, receipt, []);
            using var value = outcome.Value;
            return Result(outcome.Status, receipt, value.Items.Select(Value).ToArray(), value.IsComplete);
        }
        if (row.Action == RotationPermissionAction.ReadGeneratedCredentials)
        {
            using var request = PostgresSecretRotationOperations.GetGeneratedCredentials(root.Organization, row.Address);
            var (outcome, receipt) = await Send(request);
            if (!outcome.IsSuccess) return Result(outcome.Status, receipt, []);
            using var value = outcome.Value;
            RotationPermissionContract.Require(value.RotationId == row.Id.ToString() && value.Items.Count == 2 &&
                value.ActiveIndex is 0 or 1, "effect-mismatch");
            return Result(outcome.Status, receipt, [], hashes: value.Items.Select(x =>
                RotationPermissionContract.MaterialHash(x.Username.Reveal(), x.Password.Reveal())).ToArray());
        }
        using var operation = row.Action switch
        {
            RotationPermissionAction.Read => PostgresSecretRotationOperations.Get(root.Organization, row.Address),
            RotationPermissionAction.Create => PostgresSecretRotationOperations.Create(root.Organization,
                new(row.Name, row.Project, row.Environment, row.Path, row.Connection, initial.Interval, parameters,
                    new(row.UsernameKey, row.PasswordKey), new(initial.Hours, initial.Minutes), new(initial.Description), false)),
            RotationPermissionAction.Edit => PostgresSecretRotationOperations.Update(root.Organization, row.Address,
                new(name: edited.Name, description: new(edited.Description), isAutoRotationEnabled: edited.Enabled,
                    rotationInterval: edited.Interval, parameters: editedParameters,
                    secretsMapping: new(edited.UsernameKey, edited.PasswordKey), rotateAtUtc: new(edited.Hours, edited.Minutes))),
            RotationPermissionAction.Delete => PostgresSecretRotationOperations.Delete(root.Organization, row.Address,
                deleteSecrets: true, revokeGeneratedCredentials: true),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var (selected, original) = await Send(operation);
        if (!selected.IsSuccess) return Result(selected.Status, original, []);
        using var summary = selected.Value;
        return Result(selected.Status, original, [Value(summary)]);
    }
    private static RotationPermissionConfiguration Value(MySqlSecretRotationSummary s)
    {
        var p = s.Parameters; var r = p.PasswordRequirements;
        RotationPermissionContract.Require(r is not null && p.RotationStatement is not null, "effect-mismatch");
        return new(s.Id, s.ProjectId, s.Environment, s.SecretPath, s.ConnectionId, s.Name, p.Username1, p.Username2,
            s.SecretsMapping.Username, s.SecretsMapping.Password, s.RotationInterval, s.RotateAtUtc.Hours,
            s.RotateAtUtc.Minutes, s.IsAutoRotationEnabled == true, s.HasDescription, s.Description, r!.Length,
            r.Digits, r.Lowercase, r.Symbols, r.Uppercase, r.AllowedSymbols ?? "",
            RotationPermissionContract.Hash(p.RotationStatement!.Reveal()), s.EnvironmentId, s.FolderId,
            InfisicalRotationProfile.MysqlCredentials);
    }
    private static RotationPermissionConfiguration Value(MsSqlSecretRotationSummary s)
    {
        var p = s.Parameters; var r = p.PasswordRequirements;
        RotationPermissionContract.Require(r is not null && p.RotationStatement is not null, "effect-mismatch");
        return new(s.Id, s.ProjectId, s.Environment, s.SecretPath, s.ConnectionId, s.Name, p.Username1, p.Username2,
            s.SecretsMapping.Username, s.SecretsMapping.Password, s.RotationInterval, s.RotateAtUtc.Hours,
            s.RotateAtUtc.Minutes, s.IsAutoRotationEnabled == true, s.HasDescription, s.Description, r!.Length,
            r.Digits, r.Lowercase, r.Symbols, r.Uppercase, r.AllowedSymbols ?? "",
            RotationPermissionContract.Hash(p.RotationStatement!.Reveal()), s.EnvironmentId, s.FolderId,
            InfisicalRotationProfile.MssqlCredentials);
    }
    private static async ValueTask<RotationPermissionAttempt> MySqlAsync(NativeEnvironment env,
        RotationPermissionRoot root, RotationPermissionRow row, RotationPermissionTokens tokens, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        var authority = new ManagementAuthority(client.Authority, tokens, root.Organization, row.Project);
        using var statement = SecretMaterial.FromText(RotationPermissionContract.ProfileStatement(row.SqlProfile));
        using var editedStatement = SecretMaterial.FromText(RotationPermissionContract.ProfileStatement(row.SqlProfile) + " -- changed");
        using var parameters = new MySqlRotationParameters(row.Username1, row.Username2, new(24, 2, 2, 2, 2, "!@"), statement);
        using var editedParameters = new MySqlRotationParameters(row.Username1, row.Username2, new(32, 3, 3, 3, 3, "!@#"), editedStatement);
        var initial = RotationPermissionContract.Initial(row); var edited = RotationPermissionContract.Edited(initial);
        async ValueTask<(SecretOutcome<T>, ManagementReceipt?)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            return (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), receipt, token), receipt);
        }
        RotationPermissionAttempt Result(SecretStatus status, ManagementReceipt? receipt,
            RotationPermissionConfiguration[] values, bool complete = true, string[]? material = null) =>
            new(row, tokens.Hash, status, receipt?.Evidence, null, values, complete, material ?? []);
        if (row.List)
        {
            using var request = MySqlSecretRotationOperations.List(root.Organization, row.Project);
            var (result, receipt) = await Send(request);
            if (!result.IsSuccess) return Result(result.Status, receipt, []);
            using var list = result.Value;
            return Result(result.Status, receipt, list.Items.Select(Value).ToArray(), list.IsComplete);
        }
        if (row.Action == RotationPermissionAction.ReadGeneratedCredentials)
        {
            using var request = MySqlSecretRotationOperations.GetGeneratedCredentials(root.Organization, row.Address);
            var (result, receipt) = await Send(request);
            if (!result.IsSuccess) return Result(result.Status, receipt, []);
            using var credentials = result.Value;
            RotationPermissionContract.Require(credentials.RotationId == row.Id.ToString() &&
                credentials.Items.Count == 2 && credentials.ActiveIndex is 0 or 1, "effect-mismatch");
            return Result(result.Status, receipt, [], material: credentials.Items.Select(p =>
                RotationPermissionContract.MaterialHash(p.Username.Reveal(), p.Password.Reveal())).ToArray());
        }
        using var operation = row.Action switch
        {
            RotationPermissionAction.Read => MySqlSecretRotationOperations.Get(root.Organization, row.Address),
            RotationPermissionAction.Create => MySqlSecretRotationOperations.Create(root.Organization,
                new(row.Name, row.Project, row.Environment, row.Path, row.Connection, initial.Interval, parameters,
                    new(row.UsernameKey, row.PasswordKey), new(initial.Hours, initial.Minutes), new(initial.Description), false)),
            RotationPermissionAction.Edit => MySqlSecretRotationOperations.Update(root.Organization, row.Address,
                new(name: edited.Name, description: new(edited.Description), isAutoRotationEnabled: edited.Enabled,
                    rotationInterval: edited.Interval, parameters: editedParameters,
                    secretsMapping: new(edited.UsernameKey, edited.PasswordKey), rotateAtUtc: new(edited.Hours, edited.Minutes))),
            RotationPermissionAction.Delete => MySqlSecretRotationOperations.Delete(root.Organization, row.Address,
                deleteSecrets: true, revokeGeneratedCredentials: true),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var (selected, original) = await Send(operation);
        if (!selected.IsSuccess) return Result(selected.Status, original, []);
        using var summary = selected.Value;
        return Result(selected.Status, original, [Value(summary)]);
    }
    private static async ValueTask<RotationPermissionAttempt> MsSqlAsync(NativeEnvironment env,
        RotationPermissionRoot root, RotationPermissionRow row, RotationPermissionTokens tokens, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        var authority = new ManagementAuthority(client.Authority, tokens, root.Organization, row.Project);
        using var statement = SecretMaterial.FromText(RotationPermissionContract.ProfileStatement(row.SqlProfile));
        using var editedStatement = SecretMaterial.FromText(RotationPermissionContract.ProfileStatement(row.SqlProfile) + " -- changed");
        using var parameters = new MsSqlRotationParameters(row.Username1, row.Username2, new(24, 2, 2, 2, 2, "!@"), statement);
        using var editedParameters = new MsSqlRotationParameters(row.Username1, row.Username2, new(32, 3, 3, 3, 3, "!@#"), editedStatement);
        var initial = RotationPermissionContract.Initial(row); var edited = RotationPermissionContract.Edited(initial);
        async ValueTask<(SecretOutcome<T>, ManagementReceipt?)> Send<T>(ManagementRequest<T> request) where T : notnull
        {
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            return (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), receipt, token), receipt);
        }
        RotationPermissionAttempt Result(SecretStatus status, ManagementReceipt? receipt,
            RotationPermissionConfiguration[] values, bool complete = true, string[]? material = null) =>
            new(row, tokens.Hash, status, receipt?.Evidence, null, values, complete, material ?? []);
        if (row.List)
        {
            using var request = MsSqlSecretRotationOperations.List(root.Organization, row.Project);
            var (result, receipt) = await Send(request);
            if (!result.IsSuccess) return Result(result.Status, receipt, []);
            using var list = result.Value;
            return Result(result.Status, receipt, list.Items.Select(Value).ToArray(), list.IsComplete);
        }
        if (row.Action == RotationPermissionAction.ReadGeneratedCredentials)
        {
            using var request = MsSqlSecretRotationOperations.GetGeneratedCredentials(root.Organization, row.Address);
            var (result, receipt) = await Send(request);
            if (!result.IsSuccess) return Result(result.Status, receipt, []);
            using var credentials = result.Value;
            RotationPermissionContract.Require(credentials.RotationId == row.Id.ToString() &&
                credentials.Items.Count == 2 && credentials.ActiveIndex is 0 or 1, "effect-mismatch");
            return Result(result.Status, receipt, [], material: credentials.Items.Select(p =>
                RotationPermissionContract.MaterialHash(p.Username.Reveal(), p.Password.Reveal())).ToArray());
        }
        using var operation = row.Action switch
        {
            RotationPermissionAction.Read => MsSqlSecretRotationOperations.Get(root.Organization, row.Address),
            RotationPermissionAction.Create => MsSqlSecretRotationOperations.Create(root.Organization,
                new(row.Name, row.Project, row.Environment, row.Path, row.Connection, initial.Interval, parameters,
                    new(row.UsernameKey, row.PasswordKey), new(initial.Hours, initial.Minutes), new(initial.Description), false)),
            RotationPermissionAction.Edit => MsSqlSecretRotationOperations.Update(root.Organization, row.Address,
                new(name: edited.Name, description: new(edited.Description), isAutoRotationEnabled: edited.Enabled,
                    rotationInterval: edited.Interval, parameters: editedParameters,
                    secretsMapping: new(edited.UsernameKey, edited.PasswordKey), rotateAtUtc: new(edited.Hours, edited.Minutes))),
            RotationPermissionAction.Delete => MsSqlSecretRotationOperations.Delete(root.Organization, row.Address,
                deleteSecrets: true, revokeGeneratedCredentials: true),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var (selected, original) = await Send(operation);
        if (!selected.IsSuccess) return Result(selected.Status, original, []);
        using var summary = selected.Value;
        return Result(selected.Status, original, [Value(summary)]);
    }
}
