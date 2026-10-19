using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ValidationPermissionClient
{
    private sealed class ProbeTokens(NativeEnvironment env, ValidationPermissionRoot root, ValidationPermissionActor actor) : IInfisicalTokenSource
    {
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            using var selected = Tokens(env, root, actor);
            return await selected.GetTokenAsync(token);
        }
    }
    internal static string Method(ValidationPermissionAction action) => action switch
    { ValidationPermissionAction.Read => "GET", ValidationPermissionAction.Create => "POST", ValidationPermissionAction.Edit => "PATCH", _ => "DELETE" };
    internal static string Path(ValidationPermissionRoot root, ValidationPermissionPlan plan, ValidationPermissionIssued issued, ValidationPermissionRow row) =>
        "/api/v1/secret-validation-rules/static-secrets" + (row.Action == ValidationPermissionAction.Create ? "" : "/" + issued.Id(row.Target));
    internal static InfisicalValidationInput Input(ValidationPermissionRow row, bool edit)
    {
        var state = ValidationPermissionPlan.Configuration(row, "", "", "", edit);
        return new(state.Name, state.Description, state.Active, state.Key!.Build(), state.Value!.Build(), environment: state.Environment, secretPath: state.Path);
    }
    internal static MemberPermissionTokens Tokens(NativeEnvironment env, ValidationPermissionRoot root, ValidationPermissionActor actor) =>
        actor.Owned ? new(actor.Credential) : new(env.Tokens(actor.Principal == root.Authorities.Denied ? NativeIdentityRole.Denied : NativeIdentityRole.Runtime));
    internal static async ValueTask<ValidationPermissionAttempt> ExecuteAsync(NativeEnvironment env, ValidationPermissionRoot root,
        ValidationPermissionPlan plan, ValidationPermissionIssued issued, ValidationPermissionRow row, CancellationToken token)
    {
        var before = await WritesAsync(env, root, issued, row, false, token);
        var actor = issued.Actors[row.Actor]; using var tokens = Tokens(env, root, actor);
        await using var client = new InfisicalClient(env.Origin, tokens, new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
        string project = issued.Id(row.Project);
        var target = new SecretReference(client.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets,
            row.Action == ValidationPermissionAction.Create ? null : issued.Id(row.Target), "dev", row.Slug));
        var authority = new InfisicalNativeAuthority(client.Authority, tokens, project); var receipt = new MutationReceipt(target);
        var result = row.Action switch
        {
            ValidationPermissionAction.Read => await client.GetValidationRuleAsync(target, token),
            ValidationPermissionAction.Create => await client.CreateValidationRuleAsync(target, Input(row, false), authority, receipt, token),
            ValidationPermissionAction.Edit => await client.UpdateValidationRuleAsync(target, Input(row, true), authority, receipt, token),
            _ => await client.DeleteValidationRuleAsync(target, authority, receipt, token)
        };
        var after = await WritesAsync(env, root, issued, row, true, token);
        return new(row, tokens.Hash, result.Status, row.Action == ValidationPermissionAction.Read ? null : receipt.Evidence,
            result.IsSuccess ? ValidationPermissionPlan.Snapshot(row, issued.Id(row.Organization), result.Value, row.Action == ValidationPermissionAction.Edit ? 2 : 1) : null, true, RuleInputHash(project, row), before, after);
    }
    internal static string RuleInputHash(string project, ValidationPermissionRow row)
    {
        if (row.Action is ValidationPermissionAction.Read or ValidationPermissionAction.Delete) return ValidationPermissionContract.RawHash([]);
        var state = ValidationPermissionPlan.Configuration(row, "", "", "", row.Action == ValidationPermissionAction.Edit);
        var body = new Dictionary<string, object?>();
        if (row.Action == ValidationPermissionAction.Create) { body["projectId"] = project; body["secretPath"] = state.Path; body["environment"] = state.Environment; }
        body["name"] = state.Name; body["description"] = state.Description; body["environment"] = state.Environment; body["secretPath"] = state.Path; body["isActive"] = state.Active;
        body["keyConstraints"] = Wire(state.Key!); body["valueConstraints"] = Wire(state.Value!);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(body);
        try { return ValidationPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
        static object Wire(ValidationPermissionConstraints c) => new
        {
            minLength = c.MinimumLength,
            maxLength = c.MaximumLength,
            regexPattern = c.RegexPattern,
            requiredPrefix = c.RequiredPrefix,
            requiredSuffix = c.RequiredSuffix
        };
    }
    internal static string InputHash(string project, ValidationPermissionProbe p)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
        {
            projectId = project,
            environment = p.Environment,
            secretPath = p.Path,
            secretValue = p.Value,
            type = "shared",
            skipMultilineEncoding = true
        });
        try { return ValidationPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static async ValueTask<ValidationPermissionWriteAttempt[]> WritesAsync(NativeEnvironment env, ValidationPermissionRoot root,
        ValidationPermissionIssued issued, ValidationPermissionRow row, bool after, CancellationToken token)
    {
        var results = new List<ValidationPermissionWriteAttempt>();
        await using var observer = env.CreateObserverClient();
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp };
        await using var policyClient = new InfisicalClient(env.Origin, new ProbeTokens(env, root, issued.Actors[0]), network);
        await using var writerClient = new InfisicalClient(env.Origin, new ProbeTokens(env, root, issued.Actors[3]), network);
        foreach (var p in ValidationPermissionPlan.Probes(row, after))
        {
            var client = p.Actor == 0 ? policyClient : writerClient;
            string project = issued.Id(row.Project);
            var address = new InfisicalSecretAddress(project, p.Environment, p.Path, p.Name);
            var target = new SecretReference(client.Authority, address); var receipt = new MutationReceipt(target);
            string input = InputHash(project, p);
            using var material = SecretMaterial.FromText(p.Value);
            var result = p.Update ? await client.UpdateValueAsync(target, material, receipt, token) : await client.CreateAsync(target, material, receipt, token);
            var fetched = await observer.ReadAsync(new(observer.Authority, address), token); string? hash = null, version = null;
            if (fetched.IsSuccess)
            {
                using var read = fetched.Value; hash = ValidationPermissionContract.Hash(read.Material.Reveal()); version = read.Observation.Version;
            }
            ValidationPermissionContract.Require(!result.IsSuccess || result.Value.Disposition == InfisicalChangeDisposition.Applied, "effect-mismatch");
            results.Add(new(p, input, result.Status, receipt, receipt.Evidence, result.IsSuccess ? result.Value.Version : null, fetched.Status, hash, version));
        }
        return results.ToArray();
    }
    internal static async ValueTask InventoryAsync(NativeEnvironment env, ValidationPermissionRoot root, ValidationPermissionIssued issued,
        IEnumerable<ValidationPermissionState> expected, CancellationToken token)
    {
        var all = expected.ToArray(); await using var observer = env.CreateObserverClient();
        if (issued.Id(ValidationPermissionPlan.CopyProject).Length > 0)
        {
            string project = issued.Id(ValidationPermissionPlan.CopyProject); var management = env.CreateManagementClient();
            using var get = ProjectOperations.GetProject(root.Organization, project);
            var authority = new ManagementAuthority(management.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, project);
            var read = await management.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
            ValidationPermissionContract.Require(read.IsSuccess && read.Value.Environments.IsPresent && read.Value.Environments.Value.Count == 1 &&
                read.Value.Environments.Value[0].Id == issued.Id("template-environment") && read.Value.Environments.Value[0].Name == "Development" && read.Value.Environments.Value[0].Slug == "dev", "effect-mismatch");
            using var environment = ProjectOperations.GetEnvironmentBySlug(root.Organization, project, "dev");
            var full = await management.ExecuteAsync(environment, authority, authority.IssueGrant(environment.OperationId, environment.Target), cancellationToken: token);
            ValidationPermissionContract.Require(full.IsSuccess && full.Value.Id == issued.Id("template-environment") && full.Value.Position == 1.5, "effect-mismatch");
        }
        foreach (string project in new[] { ValidationPermissionPlan.Project, ValidationPermissionPlan.OtherProject, ValidationPermissionPlan.CopyProject }.Select(issued.Id).Where(p => p.Length != 0))
        {
            var result = await observer.ListValidationRulesAsync(new(observer.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets)), cancellationToken: token);
            ValidationPermissionContract.Require(result.IsSuccess && result.Value.IsComplete && result.Value.Items.Select(r => r.Id).Order().SequenceEqual(all.Where(s => s.Project == project).Select(s => s.Target).Order()), "effect-mismatch");
            foreach (var value in result.Value.Items)
            {
                var state = all.Single(s => s.Target == value.Id); var row = new ValidationPermissionRow(state.Row, "", "", ValidationPermissionAction.Read, "", "", "", state.Name, state.Path, 0);
                ValidationPermissionContract.Require(ValidationPermissionPlan.Snapshot(row, root.Organization, value, state.Version) == state, "effect-mismatch");
                var fetched = await observer.GetValidationRuleAsync(new(observer.Authority, new InfisicalValidationAddress(project, InfisicalValidationKind.StaticSecrets, state.Target, state.Environment, state.Path)), token);
                ValidationPermissionContract.Require(fetched.IsSuccess && ValidationPermissionPlan.Snapshot(row, root.Organization, fetched.Value, state.Version) == state, "effect-mismatch");
            }
        }
    }
}
