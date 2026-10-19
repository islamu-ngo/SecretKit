using System.Security.Cryptography;
using System.Text;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Parent hooks: select Owns + scoped templatePrincipal before ONLY the principal
// unavailable gate. Inject ITemplatePrincipalSource through native registration
// and GovernanceObservers; generic resolver selects users.value for both factory
// labels while retaining the original generic label. No existing files changed.
internal static class TemplatePrincipalEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, ITemplatePrincipalSource? source,
        CancellationToken token)
    {
        c.Probe.Contract(TemplatePrincipalContract.Owns(c.Definition), NativeFailure.ContractMismatch);
        var input = TemplatePrincipalInput.FromScope(c.Input);
        if (input is null) { c.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalTemplatePrincipalSource(new(input.Observer), input.Observer.Identity);
        var root = new TemplatePrincipalRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.Environment.Origin.AbsoluteUri, c.OrganizationId, c.Definition.Key.Operation, c.Variant,
            c.Definition.Key.Case, c.Definition.Key.Scope, source.Identity, source.Kind, input.Shape,
            new(c.Required("setupIdentityId"), c.Required("runtimeIdentityId"), c.Required("deniedIdentityId"),
                c.Required("administrativeIdentityId"), c.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await TemplatePrincipalTrial.OpenAsync(source, root, capability, input.TimeoutSeconds,
            t => c.Cleanup(async _ => { await t.DisposeAsync(); return true; }), token);
        await SetupAsync(c.Environment, trial, token);
        await WitnessAsync(c.Environment, trial, false, token);
        using (var original = Original(root, trial.Issued))
            await trial.ArmAsync(original.Target.SecondaryId!, token);
        await trial.SettleAsync(await DispatchAsync(c.Environment, root, trial.Issued, token), token);
        if (trial.Outcome == TemplatePrincipalOutcome.Partial)
        { c.Probe.Effect(NativeObservation.Unavailable); return; }
        await CopyAsync(c.Environment, trial, true, token);
        await WitnessAsync(c.Environment, trial, true, token);
        c.Probe.Effect(NativeObservation.Matched);
    }
    internal static ProjectTemplateConfiguration Configuration(TemplatePrincipalRoot root,
        TemplatePrincipalIssued issued, bool baseline = false)
    {
        string environment = baseline ? "baseline" : "witness";
        ProjectTemplateCollection<T>? Collection<T>(string field, T value) where T : class
        {
            if (baseline || TemplatePrincipalContract.Field(root.Variant) != field)
                return ProjectTemplateCollection<T>.FromValues([value]);
            if (root.Variant.EndsWith(".omitted", StringComparison.Ordinal)) return null;
            if (root.Variant.EndsWith(".null", StringComparison.Ordinal)) return ProjectTemplateCollection<T>.Null();
            return ProjectTemplateCollection<T>.FromValues(root.Shape == TemplatePrincipalShape.Empty ? [] : [value]);
        }
        string[] roles = baseline ? [issued.ReaderRole] : [issued.ReaderRole, issued.MarkerRole];
        return new([new(issued.ReaderRole, issued.ReaderRole,
            [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal(environment)),
                    new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))])]),
            new(issued.MarkerRole, issued.MarkerRole, [])],
            ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(
                [new("Baseline", "baseline", 1), new("Witness", "witness", 2), new("Outside", "outside", 3)]),
            users: Collection("users", new ProjectTemplateUser(issued.Users[0].Username, roles)),
            groups: Collection("groups", new ProjectTemplateGroup(issued.GroupSlug, roles)),
            projectManagedIdentities: Collection("projectManagedIdentities", new ProjectTemplateManagedIdentity(issued.ManagedName, roles)));
    }
    internal static ManagementRequest<ProjectTemplateSummary> Original(TemplatePrincipalRoot root,
        TemplatePrincipalIssued issued) => root.Operation == TemplatePrincipalContract.Create ?
            ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.TemplateName,
                configuration: Configuration(root, issued)) :
            ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId,
                configuration: Configuration(root, issued));
    internal static async ValueTask SetupAsync(NativeEnvironment env, TemplatePrincipalTrial trial, CancellationToken token)
    {
        var r = trial.Root; var i = trial.Issued;
        var group = await NeedAsync(env, r, () => ScopedAccessOperations.CreateGroup(r.Organization, i.GroupSlug,
            i.GroupSlug, "member"), token);
        TemplatePrincipalContract.Require(group.Id == i.GroupId, "effect-mismatch");
        var member = await NeedAsync(env, r, () => ScopedAccessOperations.AddGroupUser(r.Organization, i.GroupId,
            i.Users[1].Username), token);
        TemplatePrincipalContract.Require(member.Id == i.Users[1].Principal, "effect-mismatch");
        var template = await NeedAsync(env, r, () => ProjectTemplateOperations.CreateProjectTemplate(r.Organization,
            r.Operation == TemplatePrincipalContract.Create ? i.SeedName : i.TemplateName,
            configuration: Configuration(r, i, true)), token);
        TemplatePrincipalContract.Require(template.Name == (r.Operation == TemplatePrincipalContract.Create ? i.SeedName : i.TemplateName),
            "effect-mismatch");
        await CopyAsync(env, trial, false, token);
    }
    internal static async ValueTask CopyAsync(NativeEnvironment env, TemplatePrincipalTrial trial, bool after,
        CancellationToken token)
    {
        var r = trial.Root; var i = trial.Issued;
        string project = after ? i.AfterProject : i.BeforeProject, slug = after ? i.AfterSlug : i.BeforeSlug;
        bool absent = after && r.Operation == TemplatePrincipalContract.Create &&
            trial.Outcome == TemplatePrincipalOutcome.NonApplied;
        var copied = await NeedAsync(env, r, () => ProjectOperations.CreateProject(r.Organization, slug, slug,
            createDefaultEnvironments: false, template: absent ? i.SeedName : r.Operation == TemplatePrincipalContract.Create &&
                !after ? i.SeedName : i.TemplateName), token);
        TemplatePrincipalContract.Require(copied.Id == project && copied.Slug == slug, "effect-mismatch");
        bool managed = !after || TemplatePrincipalContract.Present(r, "projectManagedIdentities", true, trial.Outcome);
        if (absent) managed = true; // independent baseline control, but no original target was created
        if (managed)
        {
            string identity = after ? i.AfterManaged : i.BeforeManaged;
            await NeedAsync(env, r, () => IdentityAuthenticationOperations.AttachTokenAuth(r.Organization, identity,
                new(accessTokenTTL: 600, accessTokenMaxTTL: 600)), token);
            using var issued = await NeedAsync(env, r, () => IdentityAuthenticationOperations.CreateToken(r.Organization,
                identity, "witness"), token);
            trial.AddCredential(identity, project, issued.Metadata.Id, issued.AccessToken);
        }
        await using var setup = env.CreateClient(NativeIdentityRole.Setup);
        using var value = TemplatePrincipalContract.Material(i.Value);
        foreach (string environment in new[] { "baseline", "witness", "outside" })
        {
            var reference = new SecretReference(setup.Authority, new InfisicalSecretAddress(project, environment, "/", i.Key));
            var receipt = new MutationReceipt(reference);
            var created = await setup.CreateAsync(reference, value, receipt, token);
            TemplatePrincipalContract.Require(created.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
        }
    }
    internal static async ValueTask<T> NeedAsync<T>(NativeEnvironment env, TemplatePrincipalRoot root,
        Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, request.Target.ProjectId);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        TemplatePrincipalContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied, "effect-mismatch");
        return result.Value;
    }
    internal static async ValueTask<TemplatePrincipalReceipt> DispatchAsync(NativeEnvironment env,
        TemplatePrincipalRoot root, TemplatePrincipalIssued issued, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        using var request = Original(root, issued);
        var receipt = client.CreateReceipt(request);
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization);
        using var loss = root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
        using var enteredLoss = loss?.Enter();
        Task? entered = barrier?.Entered;
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            receipt, cancel.Token).AsTask();
        SecretOutcome<ProjectTemplateSummary>? result = null;
        bool cancelled = false;
        try
        {
            if (entered is not null) { await entered.WaitAsync(token); cancel.Cancel(); barrier!.Release(); }
            try { result = await execution; }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested && !token.IsCancellationRequested)
            { cancelled = true; }
            TemplatePrincipalContract.Require(loss is null || loss.Reached, "effect-mismatch");
            if (result is { IsSuccess: true })
                TemplatePrincipalContract.Require(result.Value.Name == issued.TemplateName &&
                    result.Value.Id == issued.TemplateId && !result.Value.IncludesPermissionConditionValues,
                    "effect-mismatch");
            return new(receipt.Evidence, result?.Status, cancelled, request.Target.SecondaryId!);
        }
        finally
        {
            cancel.Cancel(); barrier?.Release();
            try { result ??= await execution; } catch (OperationCanceledException) { }
        }
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, TemplatePrincipalTrial trial, bool after,
        CancellationToken token)
    {
        await trial.BeginAsync(after, token);
        var r = trial.Root; var i = trial.Issued;
        string project = after ? i.AfterProject : i.BeforeProject;
        string allowedEnvironment = TemplatePrincipalContract.Environment(after, trial.Outcome);
        var attempts = new List<TemplatePrincipalAttempt>();
        foreach (var selected in trial.Credentials.Where(c => c.Kind == "user" && c != i.Users[2] ||
            c.Kind == "managed" && c.Project == project))
        {
            bool expected = !after || TemplatePrincipalContract.Present(r,
                selected.Kind == "managed" ? "projectManagedIdentities" : selected.Principal == i.Users[0].Principal ? "users" : "groups",
                true, trial.Outcome);
            // A failed create copies a baseline CONTROL: its access proves the
            // original NonApplied outcome did not remove preexisting authority.
            if (after && r.Operation == TemplatePrincipalContract.Create && trial.Outcome == TemplatePrincipalOutcome.NonApplied)
                expected = true;
            await User(selected, allowedEnvironment, expected);
            await User(i.Users[2], allowedEnvironment, false);
            await Host(NativeIdentityRole.Denied, allowedEnvironment, false);
            await User(selected, allowedEnvironment, expected);
            await User(selected, "outside", false);
        }
        await Host(NativeIdentityRole.Runtime, allowedEnvironment, false);
        await Host(NativeIdentityRole.Observer, allowedEnvironment, true);
        await trial.ObserveAsync(after, attempts.ToArray(), token);
        async ValueTask User(TemplatePrincipalCredential c, string environment, bool allowed)
        {
            using var material = TemplatePrincipalContract.Material(c.Bytes);
            await Read(new Tokens(material), c.Principal, c.CredentialId, c.Hash, environment, allowed);
        }
        async ValueTask Host(NativeIdentityRole role, string environment, bool allowed)
        {
            var selected = await env.Tokens(role).GetTokenAsync(token);
            TemplatePrincipalContract.Require(selected.IsSuccess, "missing-input");
            using var credential = selected.Value;
            char[] chars = credential.Material.ExportCharacters();
            byte[] bytes = Encoding.UTF8.GetBytes(chars);
            string hash;
            try { hash = TemplatePrincipalContract.HashBytes(bytes); }
            finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
            TemplatePrincipalContract.Require(trial.Credentials.All(c => c.Hash != hash), "effect-mismatch");
            await Read(env.Tokens(role), role == NativeIdentityRole.Runtime ? r.Authorities.Runtime :
                role == NativeIdentityRole.Denied ? r.Authorities.Denied : r.Authorities.Observer, "host", hash, environment, allowed);
        }
        async ValueTask Read(IInfisicalTokenSource tokens, string principal, string credential, string hash,
            string environment, bool allowed)
        {
            // Fresh PUBLIC SDK client for each positive, control and recheck.
            await using var client = new InfisicalClient(env.Origin, tokens,
                new() { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
            var reference = new SecretReference(client.Authority, new InfisicalSecretAddress(project, environment, "/", i.Key));
            var result = await client.ReadAsync(reference, token);
            string? valueHash = null;
            if (result.IsSuccess)
            {
                using var value = result.Value;
                char[] chars = value.Material.ExportCharacters();
                byte[] bytes = Encoding.UTF8.GetBytes(chars);
                try { valueHash = TemplatePrincipalContract.HashBytes(bytes); }
                finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(bytes); }
            }
            TemplatePrincipalContract.Require(allowed ? result.IsSuccess && valueHash == i.ValueHash :
                result.Status == SecretStatus.Denied, "effect-mismatch");
            attempts.Add(new(principal, credential, hash, project, environment, allowed, valueHash));
        }
    }
    private sealed class Tokens(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
        public override string ToString() => "[TemplatePrincipalTokens]";
    }
}
