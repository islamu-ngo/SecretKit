using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Optional parent hook: select MetadataPermissionContract.Owns and scoped input
// before the existing unavailable gates; inject the source through both native
// registrars and GovernanceObservers. Generic resolver must explicitly choose an
// owned variant while retaining its factory label. Existing files are parent-owned.
internal static class MetadataPermissionEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IMetadataPermissionSource? source,
        CancellationToken token)
    {
        var input = MetadataPermissionInput.FromScope(c.Input);
        if (MetadataPermissionContract.Gate(c.Definition, input) is not null)
        { c.Probe.Effect(NativeObservation.Unavailable); return; }
        source ??= new InfisicalMetadataPermissionSource(new(input!.Observer), input.Observer.Identity);
        var root = new MetadataPermissionRoot(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
            c.Environment.Origin.AbsoluteUri, c.OrganizationId, c.Definition.Key.Operation, c.Variant,
            c.Definition.Key.Case, c.Definition.Key.Scope, source.Identity, source.Kind, input!.Subject, input.Operator,
            new(c.Required("setupIdentityId"), c.Required("runtimeIdentityId"), c.Required("deniedIdentityId"),
                c.Required("administrativeIdentityId"), c.Required("observerIdentityId")), input.Profile);
        using var capability = SecretMaterial.FromText(input.Capability);
        var trial = await MetadataPermissionTrial.OpenAsync(source, root, capability,
            owned => c.Cleanup(async _ => { await owned.DisposeAsync(); return true; }), token);
        await WitnessAsync(c.Environment, root, trial, false, token);
        await trial.ArmAsync(token);
        await trial.SettleAsync(await DispatchAsync(c.Environment, root, trial.Issued, token), token);
        await InstantiateAsync(c.Environment, root, trial, token);
        await WitnessAsync(c.Environment, root, trial, true, token);
        c.Probe.Effect(trial.Outcome == MetadataPermissionOutcome.Partial ?
            NativeObservation.Unavailable : NativeObservation.Matched);
    }

    internal static RoleMetadataMatch Match(MetadataPermissionOperator op) => op switch
    {
        MetadataPermissionOperator.Equal => new(RoleStringClause.Compare(equal: "team"), RoleStringClause.Compare(equal: "blue")),
        MetadataPermissionOperator.Included => new(RoleStringClause.Compare(included: ["team"]), RoleStringClause.Compare(included: ["blue"])),
        MetadataPermissionOperator.NotEqual => new(RoleStringClause.Compare(notEqual: "blocked"), RoleStringClause.Compare(notEqual: "red")),
        MetadataPermissionOperator.EmptyMatch => new(),
        MetadataPermissionOperator.EmptyKey => new(RoleStringClause.Compare()),
        MetadataPermissionOperator.EmptyValue => new(value: RoleStringClause.Compare()),
        MetadataPermissionOperator.EmptyIncluded => new(RoleStringClause.Compare(included: [])),
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectTemplateMetadataMatch TemplateMatch(MetadataPermissionOperator op) => op switch
    {
        MetadataPermissionOperator.Equal => new(ProjectTemplateStringClause.Compare(equal: "team"), ProjectTemplateStringClause.Compare(equal: "blue")),
        MetadataPermissionOperator.Included => new(ProjectTemplateStringClause.Compare(included: ["team"]), ProjectTemplateStringClause.Compare(included: ["blue"])),
        MetadataPermissionOperator.NotEqual => new(ProjectTemplateStringClause.Compare(notEqual: "blocked"), ProjectTemplateStringClause.Compare(notEqual: "red")),
        MetadataPermissionOperator.EmptyMatch => new(),
        MetadataPermissionOperator.EmptyKey => new(ProjectTemplateStringClause.Compare()),
        MetadataPermissionOperator.EmptyValue => new(value: ProjectTemplateStringClause.Compare()),
        MetadataPermissionOperator.EmptyIncluded => new(ProjectTemplateStringClause.Compare(included: [])),
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRolePermission[] Permissions(MetadataPermissionOperator op) =>
        [new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
            conditions: [new(RoleConditionField.Environment, RoleStringClause.Literal("witness")),
                new(RoleConditionField.SecretPath, RoleStringClause.Literal("/"))], metadata: Match(op))];
    internal static ProjectTemplateConfiguration Configuration(MetadataPermissionRoot root, MetadataPermissionIssued issued) =>
        new([new(issued.PolicySlug, issued.PolicySlug,
            [new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.Lease,
                conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("witness")),
                    new(RoleConditionField.SecretPath, ProjectTemplateStringClause.Literal("/"))],
                metadata: TemplateMatch(root.Operator)),
             new(ProjectRoleSubject.DynamicSecrets, ProjectRoleAction.ReadRootCredential)])],
            ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Witness", "witness", 1)]),
            identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                [new(root.Authorities.Runtime, [issued.PolicySlug])]));
    internal static string OriginalPath(MetadataPermissionRoot root, MetadataPermissionIssued issued)
    {
        bool create = MetadataPermissionContract.Create(root.Operation);
        if (MetadataPermissionContract.Template(root.Operation))
            return "/api/v1/project-templates" + (create ? "" : "/" + issued.TemplateId);
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
            return "/api/v1/projects/" + issued.Project + "/roles" + (create ? "" : "/" + issued.PolicyId);
        return "/api/v2/identity-project-additional-privilege" + (create ? "" : "/" + issued.PolicyId);
    }
    internal static async ValueTask<MetadataPermissionReceipt> DispatchAsync(NativeEnvironment env,
        MetadataPermissionRoot root, MetadataPermissionIssued issued, CancellationToken token)
    {
        bool create = MetadataPermissionContract.Create(root.Operation);
        if (MetadataPermissionContract.Template(root.Operation))
            return await SendAsync(env, root, () => create ?
                ProjectTemplateOperations.CreateProjectTemplate(root.Organization, issued.PolicySlug,
                    configuration: Configuration(root, issued)) :
                ProjectTemplateOperations.UpdateProjectTemplate(root.Organization, issued.TemplateId,
                    configuration: Configuration(root, issued)), token);
        if (root.Operation.Contains(".RoleChangeOperations.", StringComparison.Ordinal))
        {
            var change = new ProjectRoleChange(issued.PolicySlug, issued.PolicySlug, permissions: Permissions(root.Operator));
            return await SendAsync(env, root, () => create ?
                RoleChangeOperations.CreateProjectRole(root.Organization, issued.Project, change) :
                RoleChangeOperations.UpdateProjectRole(root.Organization, issued.Project, issued.PolicyId, change), token);
        }
        var selection = new LegacyPrivilegeSelection(root.Organization, issued.Project, issued.ProjectSlug,
            root.Authorities.Runtime, issued.Membership);
        var privilege = new ProjectPrivilegeChange(Permissions(root.Operator), PrivilegeLifetime.Permanent(), issued.PolicySlug);
        return await SendAsync(env, root, () => create ?
            IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, privilege) :
            IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, issued.PolicyId, privilege), token);
    }
    internal static async ValueTask<MetadataPermissionReceipt> SendAsync<T>(NativeEnvironment env,
        MetadataPermissionRoot root, Func<ManagementRequest<T>> factory, CancellationToken token) where T : notnull
    {
        var client = env.CreateManagementClient();
        using var request = factory();
        var receipt = client.CreateReceipt(request);
        var role = root.Boundary == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        var barrier = root.Boundary == "cancellation-boundary" ? new ProjectTokenBarrier(env.Tokens(role)) : null;
        using var cancel = CancellationTokenSource.CreateLinkedTokenSource(token);
        var authority = new ManagementAuthority(client.Authority, barrier ?? env.Tokens(role), root.Organization, request.Target.ProjectId);
        using var loss = root.Boundary == "lost-response-no-replay" ? new ProjectResponseBoundary(env.Origin, cancel) : null;
        using var enteredLoss = loss?.Enter();
        Task? entered = barrier?.Entered;
        var execution = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            receipt, cancel.Token).AsTask();
        SecretOutcome<T>? result = null;
        bool cancelled = false;
        try
        {
            if (entered is not null) { await entered.WaitAsync(token); cancel.Cancel(); barrier!.Release(); }
            try { result = await execution; }
            catch (OperationCanceledException) when (cancel.IsCancellationRequested && !token.IsCancellationRequested)
            { cancelled = true; }
            MetadataPermissionContract.Require(loss is null || loss.Reached, "effect-mismatch");
            return new(receipt.Evidence, result?.Status, cancelled, request.Target.SecondaryId ?? "");
        }
        finally
        {
            cancel.Cancel(); barrier?.Release();
            try { result ??= await execution; } catch (OperationCanceledException) { }
            if (result is { IsSuccess: true } owned && owned.Value is IDisposable value) value.Dispose();
        }
    }
    internal static async ValueTask InstantiateAsync(NativeEnvironment env, MetadataPermissionRoot root,
        MetadataPermissionTrial trial, CancellationToken token)
    {
        if (trial.Outcome != MetadataPermissionOutcome.Applied) return;
        var issued = trial.Issued;
        var client = env.CreateManagementClient();
        if (root.Operation.EndsWith(".CreateProjectRole", StringComparison.Ordinal))
        {
            using var membership = MembershipOperations.UpdateProjectIdentityRoles(root.Organization, issued.Project,
                root.Authorities.Runtime, [new(issued.PolicySlug)]);
            var roleAuthority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization, issued.Project);
            var original = client.CreateReceipt(membership);
            var assigned = await client.ExecuteAsync(membership, roleAuthority,
                roleAuthority.IssueGrant(membership.OperationId, membership.Target), original, token);
            MetadataPermissionContract.Require(assigned.IsSuccess && original.Evidence == DispatchEvidence.Applied, "effect-mismatch");
            trial.Activated(new(original.Evidence, assigned.Status, false, membership.Target.SecondaryId ?? ""));
            return;
        }
        if (!MetadataPermissionContract.Template(root.Operation)) return;
        using var request = ProjectOperations.CreateProject(root.Organization, issued.CopySlug, issued.CopySlug,
            template: issued.PolicySlug, createDefaultEnvironments: false);
        var authority = env.CreateManagementAuthority(client, NativeIdentityRole.Setup, root.Organization);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target), receipt, token);
        MetadataPermissionContract.Require(result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied &&
            result.Value.Id == issued.CopyRows[0].Project && result.Value.Slug == issued.CopySlug, "effect-mismatch");
        trial.Activated(new(receipt.Evidence, result.Status, false, request.Target.SecondaryId ?? ""));
    }
    internal static async ValueTask WitnessAsync(NativeEnvironment env, MetadataPermissionRoot root,
        MetadataPermissionTrial trial, bool after, CancellationToken token)
    {
        await trial.BeginAsync(after, token);
        var attempts = new List<MetadataPermissionAttempt>();
        foreach (var role in new[] { NativeIdentityRole.Runtime, NativeIdentityRole.Denied, NativeIdentityRole.Observer })
        {
            string actor = role == NativeIdentityRole.Runtime ? root.Authorities.Runtime :
                role == NativeIdentityRole.Denied ? root.Authorities.Denied : root.Authorities.Observer;
            var credentials = await env.Tokens(role).GetTokenAsync(token);
            MetadataPermissionContract.Require(credentials.IsSuccess, "missing-input");
            using var access = credentials.Value;
            string tokenHash = MetadataPermissionContract.Hash(access.Material.Reveal());
            foreach (var row in trial.Rows(after))
            {
                bool allowed = role == NativeIdentityRole.Observer || role == NativeIdentityRole.Runtime &&
                    after && trial.Outcome == MetadataPermissionOutcome.Applied &&
                    MetadataPermissionContract.Expected(root.Operator, row);
                await using var client = new InfisicalDynamicClient(env.Origin, env.Tokens(role),
                    new(row.ProjectSlug, row.Environment, row.Path, row.Folder),
                    new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = env.AllowLoopbackDevelopmentHttp });
                var target = client.Definition(row.Name);
                var inspected = await client.InspectDefinitionAsync(target, token);
                // Explicit read-root permission is separate from the conditional lease
                // permission. It permits selection, not credential acquisition.
                MetadataPermissionContract.Require(inspected.IsSuccess && inspected.Value.Id == row.Definition, "effect-mismatch");
                var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.Acquire);
                var result = await client.AcquireDatabaseAsync(inspected.Value, receipt, cancellationToken: token);
                using var lease = result.IsSuccess ? result.Value : null;
                MetadataPermissionContract.Require(allowed ? result.IsSuccess && receipt.Evidence == DispatchEvidence.Applied :
                    result.Status == SecretStatus.Denied && receipt.Evidence == DispatchEvidence.Rejected, "effect-mismatch");
                Guid? leaseId = null; string? material = null;
                if (lease is not null)
                {
                    var copy = lease.CopyCredentials();
                    MetadataPermissionContract.Require(copy.IsSuccess, "effect-mismatch");
                    using var owned = copy.Value;
                    // SDK exports ordinary strings; disposing owned buffers does NOT erase these strings.
                    string username = owned.RevealUsername(), password = owned.RevealPassword();
                    leaseId = lease.Reference.Id;
                    material = MetadataPermissionContract.MaterialHash(username, password);
                    foreach (var action in Enum.GetValues<MetadataPermissionAction>())
                        await trial.MeasureAsync(leaseId.Value, username, password, actor, row.Project, action, after, token);
                }
                attempts.Add(new(actor, tokenHash, row, allowed, leaseId, material));
            }
        }
        await trial.ObserveAsync(after, attempts.ToArray(), token);
    }
}
