using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Calibration invokes public SDK operations directly. Neither the effect client
// nor dispatch/witness/activation helpers participate. The independent provider
// and SQL journal still check every resulting state and authenticated action.
public sealed class InfisicalRotationPermissionCalibrationTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary)> Cases() =>
        InfisicalRotationPermissionGateTests.Cases();
    [Test]
    public Task DirectSdkSmoke() => DirectSdkSourceAndSqlCalibrateBeforeEffects(
        "i.management.RoleChangeOperations.UpdateProjectRole", "permission.SecretRotation.edit", "independent-effect");
    public static IEnumerable<(int Profile, int Action)> OtherProfiles() =>
        from profile in new[] { InfisicalRotationProfile.MysqlCredentials, InfisicalRotationProfile.MssqlCredentials }
        from action in Enum.GetValues<RotationPermissionAction>()
        select ((int)profile, (int)action);
    [Test]
    [MethodDataSource(nameof(OtherProfiles))]
    public Task OtherSqlSdkSourceAndBackendCalibrateBeforeEffects(int profile, int action) =>
        CalibrateAsync("i.management.RoleChangeOperations.UpdateProjectRole",
            RotationPermissionContract.Variant((RotationPermissionAction)action), "independent-effect",
            (InfisicalRotationProfile)profile);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task DirectSdkSourceAndSqlCalibrateBeforeEffects(string operation, string variant, string boundary)
        => await CalibrateAsync(operation, variant, boundary, InfisicalRotationProfile.PostgresCredentials);
    private static async Task CalibrateAsync(string operation, string variant, string boundary, InfisicalRotationProfile profile)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(profile: profile);
        var action = InfisicalRotationPermissionGateTests.Action(variant);
        using var env = fixture.Environment(action);
        var root = fixture.Root(operation, action, boundary);
        RotationPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("rotation-capability");
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        try
        {
            var trial = await RotationPermissionTrial.OpenAsync(fixture.Source.CreateClient(), root, capability,
                t => retained = t, timeout.Token);
            await Witness(false);
            await trial.ArmAsync(timeout.Token);
            var original = await RotationPermissionDirectOriginal.DispatchAsync(env, root, trial.Issued, timeout.Token);
            await trial.SettleAsync(original, timeout.Token);
            await Assert.That(trial.Outcome).IsEqualTo(boundary is "denied-authority" or "cancellation-boundary" ?
                RotationPermissionOutcome.NonApplied : RotationPermissionOutcome.Applied);
            await RotationPermissionDirectOriginal.ActivateAsync(env, root, trial, timeout.Token);
            await Witness(true);
            async Task Witness(bool after)
            {
                await trial.BeginAsync(after, timeout.Token);
                var attempts = new List<RotationPermissionAttempt>();
                foreach (var row in trial.Rows(after))
                    attempts.Add(await RotationPermissionDirectClient.ExecuteAsync(env, root, row, timeout.Token, fixture.Runtime));
                await trial.ObserveAsync(after, attempts.ToArray(), timeout.Token);
            }
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
    }
}

internal static class RotationPermissionDirectClient
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
            var native = new InfisicalRotationClient(runtime!.Origin, client.Authority, authority,
                new() { Transport = InfisicalTransportOptions.HostControlled(runtime.Transport) });
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
        using var statement = SecretMaterial.FromText("ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';");
        using var editedStatement = SecretMaterial.FromText("ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}'; -- changed");
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
        using var statement = SecretMaterial.FromText("ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}';");
        using var editedStatement = SecretMaterial.FromText("ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}'; -- changed");
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

internal static class RotationPermissionDirectOriginal
{
    internal static async ValueTask<RotationPermissionReceipt> DispatchAsync(NativeEnvironment env,
        RotationPermissionRoot root, RotationPermissionIssued issued, CancellationToken token)
    {
        bool create = RotationPermissionContract.Create(root.Operation);
        var action = RotationPermissionContract.Sdk(root.Action);
        if (RotationPermissionContract.Template(root.Operation))
        {
            var configuration = new ProjectTemplateConfiguration(
                [new(issued.PolicySlug, issued.PolicySlug, [new(ProjectRoleSubject.SecretRotation, action, conditions: RotationPermissionContract.Conditions(issued.Connection)
                    .Select(c => new ProjectTemplateCondition(c.Field, ProjectTemplateStringClause.Literal(c.Field == RoleConditionField.Environment ? "witness" : c.Field == RoleConditionField.SecretPath ? "/owned" : issued.Connection))).ToArray())])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                    [new(root.Authorities.Runtime, [issued.PolicySlug])]));
            return await SendAsync(env, root, () => create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug, configuration: configuration) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId, configuration: configuration), token);
        }
        ProjectRolePermission[] permissions = [new(ProjectRoleSubject.SecretRotation, action, conditions: RotationPermissionContract.Conditions(issued.Connection))];
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
        {
            var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: permissions);
            return await SendAsync(env, root, () => create ?
                RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.Slug,
            root.Authorities.Runtime, issued.Membership);
        var privilege = new ProjectPrivilegeChange(permissions, PrivilegeLifetime.Permanent(), issued.PolicySlug);
        return await SendAsync(env, root, () => create ?
            IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, privilege), token);
    }
    internal static async ValueTask<RotationPermissionReceipt> SendAsync<T>(NativeEnvironment env,
        RotationPermissionRoot root, Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var original = client.CreateReceipt(request);
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var selectedTokens = new RotationPermissionTokens(env.Tokens(role));
        var barrier = root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(selectedTokens) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? (IInfisicalTokenSource)selectedTokens, root.Organization,
            request.Target.ProjectId);
        using var loss = root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancellation) : null;
        using var scope = loss?.Enter();
        Task? entered = barrier?.Entered; // subscribe before the sole mutation
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            original, cancellation.Token).AsTask();
        SecretOutcome<T>? outcome = null; bool cancelled = false;
        try
        {
            if (entered is not null) { await entered.WaitAsync(token); cancellation.Cancel(); barrier!.Release(); }
            try { outcome = await execution; }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested && !token.IsCancellationRequested)
            { cancelled = true; }
            RotationPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
            return new(original, outcome?.Status, cancelled, request.Target.SecondaryId ?? "", selectedTokens.Hash);
        }
        finally
        {
            cancellation.Cancel(); barrier?.Release();
            try { outcome ??= await execution; } catch (OperationCanceledException) { }
            if (outcome is { IsSuccess: true } result && result.Value is IDisposable owned) owned.Dispose();
        }
    }
    internal static async ValueTask ActivateAsync(NativeEnvironment env, RotationPermissionRoot root,
        RotationPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != RotationPermissionOutcome.Applied) return;
        var issued = trial.Issued; var client = env.CreateManagementClient();
        if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
        {
            using var request = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                root.Authorities.Runtime, [new(issued.PolicySlug)]);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
                receipt, token);
            RotationPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
        else if (RotationPermissionContract.Template(root.Operation))
        {
            using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
                template: issued.PolicySlug, createDefaultEnvironments: false);
            var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
            RotationPermissionContract.Require(result.IsSuccess && result.Value.Id == issued.CopyProject &&
                receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(receipt, result.Status, false, request.Target.SecondaryId ?? ""));
        }
    }
}
