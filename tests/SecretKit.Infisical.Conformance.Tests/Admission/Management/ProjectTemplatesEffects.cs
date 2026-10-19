using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProjectTemplatesEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition definition)
    {
        string v = definition.Key.Variant;
        if (v.StartsWith("type.", StringComparison.Ordinal) && v is not ("type.SecretManager" or "type.omitted"))
            return "non-secret-project-instantiation-contract-unavailable";
        if (v == "configuration.omitted") return "default-template-permission-policy-unestablished";
        if (v is "ProjectTemplateConfiguration.users.value" or "ProjectTemplateConfiguration.groups.value" or
            "ProjectTemplateConfiguration.projectManagedIdentities.value")
            return "template-principal-credential-observer-unavailable";
        // The typed model permits metadata only for DynamicSecrets/Certificates,
        // not static Secrets. A static-value canary would exercise an invalid branch.
        if (v is "permissions.metadata.elemMatch" or "condition.metadata.elemMatch")
            return "dynamic-or-certificate-metadata-observer-unavailable";
        if (v.StartsWith("permission.", StringComparison.Ordinal) &&
            v is not ("permission.Secrets.read" or "permission.Secrets.readValue" or "permission.Secrets.describeSecret" or
                "permission.Secrets.create" or "permission.Secrets.edit" or "permission.Secrets.delete"))
        {
            string subject = v.Split('.')[1];
            return subject switch
            {
                "AppConnections" or "SecretSyncs" => "removed-connector-observer-unavailable",
                "Insights" or "Webhooks" or "ApprovalRequests" or "ApprovalRequestGrants" or
                    "SecretApprovalRequest" or "SecretApproval" or "SecretRollback" => "unestablished-capability-observer-unavailable",
                _ => "subject-specific-downstream-fixture-unavailable"
            };
        }
        return null;
    }

    internal static async ValueTask<ProjectTemplateSummary> SeedAsync(ProjectFamilyContext c,
        ProjectTemplateConfiguration configuration, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName();
        OwnTemplate(c, name);
        return await c.NeedAsync(() => ProjectTemplateOperations.CreateProjectTemplate(c.OrganizationId,
            name, configuration: configuration), NativeIdentityRole.Setup, token);
    }

    private static void OwnTemplate(ProjectFamilyContext c, string name)
    {
        c.Cleanup(async token =>
        {
            SecretOutcome<ManagementPage<ProjectTemplateSummary>> found = await c.ExecuteAsync(
                () => ProjectTemplateOperations.ListProjectTemplates(c.OrganizationId), NativeIdentityRole.Observer, token);
            if (!found.IsSuccess || !found.Value.IsComplete) return false;
            ProjectTemplateSummary[] matching = found.Value.Items.Where(t => t.Name == name).ToArray();
            if (matching.Length == 0) return true;
            if (matching.Length != 1) return false;
            string id = matching[0].Id;
            SecretOutcome<ProjectTemplateSummary> deleted = await c.ExecuteAsync(
                () => ProjectTemplateOperations.DeleteProjectTemplate(c.OrganizationId, id), NativeIdentityRole.Setup, token);
            SecretOutcome<ProjectTemplateSummary> observed = await c.ExecuteAsync(
                () => ProjectTemplateOperations.GetProjectTemplate(c.OrganizationId, id), NativeIdentityRole.Observer, token);
            return deleted.IsSuccess && observed.Status == SecretStatus.Absent;
        });
    }

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName(), role = ProjectFamilyContext.FreshName();
        string runtime = c.Required("runtimeIdentityId");
        string v = c.Variant;
        bool create = c.Operation == "CreateProjectTemplate", update = c.Operation == "UpdateProjectTemplate";
        bool remove = c.Operation == "DeleteProjectTemplate";
        bool omittedRoles = v is "ProjectTemplateConfiguration.roles.omitted" or "roles.empty";
        bool unrestricted = omittedRoles || v == "permissions.conditions.empty";
        bool emptyIn = v == "permissions.in.empty";
        bool identitiesOmitted = v is "ProjectTemplateConfiguration.identities.omitted" or "identities.null";
        bool metadataOnly = v == "permission.Secrets.describeSecret";
        ProjectRoleAction action = v switch
        {
            "permission.Secrets.describeSecret" => ProjectRoleAction.DescribeSecret,
            "permission.Secrets.readValue" => ProjectRoleAction.ReadValue,
            "permission.Secrets.create" => ProjectRoleAction.Create,
            "permission.Secrets.edit" => ProjectRoleAction.Edit,
            "permission.Secrets.delete" => ProjectRoleAction.Delete,
            _ => ProjectRoleAction.Read
        };
        bool mutationPermission = action is ProjectRoleAction.Create or ProjectRoleAction.Edit or ProjectRoleAction.Delete;
        bool tagsIn = v is "permissions.secretTags.in" or "condition.secretTags.in";
        bool tagsAll = v is "permissions.secretTags.all" or "condition.secretTags.all";
        ProjectTemplateStringClause clause = v switch
        {
            "permissions.eq" => ProjectTemplateStringClause.Compare(equal: "witness"),
            "permissions.ne" => ProjectTemplateStringClause.Compare(notEqual: "outside"),
            "permissions.in.empty" => ProjectTemplateStringClause.Compare(included: []),
            "permissions.in.values" => ProjectTemplateStringClause.Compare(included: ["witness"]),
            "permissions.glob" => ProjectTemplateStringClause.Compare(glob: "wit*"),
            _ => ProjectTemplateStringClause.Literal("witness")
        };
        ProjectTemplateCondition[]? conditions = tagsIn || tagsAll ? null :
            unrestricted ? [] : [new(RoleConditionField.Environment, clause)];
        ProjectTemplateSecretTags? tags = tagsIn ? new(included: ["admitted"]) :
            tagsAll ? new(all: ["admitted", "second"]) : null;
        ProjectTemplatePermission permission = v == "permissions.action.array" ?
            new(ProjectRoleSubject.Secrets, new[] { action }, conditions: conditions, secretTags: tags) :
            new(ProjectRoleSubject.Secrets, action, conditions: conditions, secretTags: tags);
        ProjectTemplateRole[]? roles = omittedRoles ? v == "roles.empty" ? [] : null : [new(role, role, [permission])];
        string assignedRole = omittedRoles ? "viewer" : role;
        ProjectTemplateCollection<ProjectTemplateEnvironment>? environments = v switch
        {
            "ProjectTemplateConfiguration.environments.omitted" => null,
            "environments.null" => ProjectTemplateCollection<ProjectTemplateEnvironment>.Null(),
            "environments.empty" => ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([]),
            _ => ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(
                [new("Witness", "witness", 1), new("Outside", "outside", 2)])
        };
        ProjectTemplateCollection<ProjectTemplateIdentity>? identities = identitiesOmitted ?
            v == "identities.null" ? ProjectTemplateCollection<ProjectTemplateIdentity>.Null() : null :
            ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([new(runtime, [assignedRole])]);
        var configuration = new ProjectTemplateConfiguration(roles, environments,
            users: v == "users.null" ? ProjectTemplateCollection<ProjectTemplateUser>.Null() : null,
            groups: v == "groups.null" ? ProjectTemplateCollection<ProjectTemplateGroup>.Null() : null,
            identities: identities,
            projectManagedIdentities: v == "projectManagedIdentities.null" ?
                ProjectTemplateCollection<ProjectTemplateManagedIdentity>.Null() : null);
        bool configurationUpdate = update && v is not ("name.omitted" or "name.value" or
            "description.omitted" or "description.value");
        bool baselineIdentitiesEmpty = v == "ProjectTemplateConfiguration.identities.omitted";
        // A distinguishable, independently exercised policy prevents a metadata-only
        // PATCH from certifying an unchanged configuration.
        ProjectTemplateConfiguration seedConfiguration = configurationUpdate ? new(
                [new(role, role, [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read,
                    conditions: [new(RoleConditionField.Environment, ProjectTemplateStringClause.Literal("baseline"))])])],
                ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(
                    [new("Baseline", "baseline", 1), new("Outside", "outside", 2)]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([]),
                groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(
                    baselineIdentitiesEmpty ? [] : [new(runtime, [role])]),
                projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([])) :
            configuration;
        ProjectTemplateSummary? before = create ? null : await SeedAsync(c, seedConfiguration, token);
        string id = before?.Id ?? "";
        if (create) OwnTemplate(c, name);
        string? nextName = update && v != "name.omitted" ? name : null;
        if (nextName is not null) OwnTemplate(c, nextName);
        string? description = v == "description.value" ? ProjectFamilyContext.FreshName() :
            update && v == "name.omitted" ? "witness" : null;
        ProjectTemplateConfiguration? change = update && v is "name.omitted" or "name.value" or
            "description.omitted" or "description.value" ? null : configuration;

        bool Match(ProjectTemplateSummary summary, bool applied) =>
            (create || summary.Id == id) &&
            summary.Name == (create ? name : applied && update ? nextName ?? before!.Name : before!.Name) &&
            (!applied || description is null || summary.Description == description) &&
            !summary.IncludesPermissionConditionValues &&
            (configurationUpdate && !applied ?
                summary.Roles.Any(r => r.Slug == role && r.Permissions.Any(p => p.Action.Values.Contains("read"))) &&
                    summary.Environments is { Count: 2 } &&
                    summary.Identities?.Count == (baselineIdentitiesEmpty ? 0 : 1) :
            (v != "roles.empty" || summary.Roles.Count == 0) &&
            (v != "environments.empty" || summary.Environments is { Count: 0 }) &&
            (v != "environments.null" || summary.Environments is null) &&
            (v != "users.null" || (applied ? summary.Users is null : summary.Users is { Count: 0 })) &&
            (v != "groups.null" || (applied ? summary.Groups is null : summary.Groups is { Count: 0 })) &&
            (v != "identities.null" || (applied ? summary.Identities is null : summary.Identities is { Count: 0 })) &&
            (v != "projectManagedIdentities.null" || (applied ? summary.ProjectManagedIdentities is null : summary.ProjectManagedIdentities is { Count: 0 })) &&
            (omittedRoles || summary.Roles.Any(r => r.Slug == role &&
                r.Permissions.Any(p => !p.IncludesConditionValues && p.Action.IsScalar == (v != "permissions.action.array") &&
                    p.HasConditions && p.Action.Values.Contains(action switch
                    {
                        ProjectRoleAction.DescribeSecret => "describeSecret",
                        ProjectRoleAction.ReadValue => "readValue",
                        ProjectRoleAction.Create => "create",
                        ProjectRoleAction.Edit => "edit",
                        ProjectRoleAction.Delete => "delete",
                        _ => "read"
                    })))));

        ProjectCanary? retained = null, retainedOutside = null;
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool baseline = configurationUpdate && !applied;
            SecretOutcome<ManagementPage<ProjectTemplateSummary>> list = await c.ExecuteAsync(
                () => ProjectTemplateOperations.ListProjectTemplates(c.OrganizationId), NativeIdentityRole.Observer, ct);
            if (!list.IsSuccess || !list.Value.IsComplete) return false;
            ProjectTemplateSummary? current = create ? list.Value.Items.SingleOrDefault(t => t.Name == name) :
                list.Value.Items.SingleOrDefault(t => t.Id == id);
            if (create && !applied) return current is null;
            if (remove && applied)
            {
                if (current is not null) return false;
                // The template is absent; a fresh creation naming it must not apply
                // the removed policy. No existing project is claimed to lose access.
                string rejectedSlug = ProjectFamilyContext.FreshName();
                c.OwnProject(rejectedSlug);
                SecretOutcome<ProjectSummary> rejected = await c.ExecuteAsync(
                    () => ProjectOperations.CreateProject(c.OrganizationId, rejectedSlug, rejectedSlug,
                        template: before!.Id), NativeIdentityRole.Setup, ct);
                SecretOutcome<ProjectSummary> absent = await c.ExecuteAsync(
                    () => ProjectOperations.GetProjectBySlug(c.OrganizationId, rejectedSlug), NativeIdentityRole.Observer, ct);
                return rejected.Status is SecretStatus.Absent or SecretStatus.Invalid &&
                    absent.Status == SecretStatus.Absent && retained is not null && retainedOutside is not null &&
                    await retained.ReadAsync(NativeIdentityRole.Runtime, true, ct) &&
                    await retainedOutside.ReadAsync(NativeIdentityRole.Runtime, false, ct);
            }
            if (current is null || !Match(current, applied)) return false;
            SecretOutcome<ProjectTemplateSummary> observed = await c.ExecuteAsync(
                () => ProjectTemplateOperations.GetProjectTemplate(c.OrganizationId, current.Id), NativeIdentityRole.Observer, ct);
            if (!observed.IsSuccess || !Match(observed.Value, applied)) return false;
            string projectName = ProjectFamilyContext.FreshName();
            c.OwnProject(projectName);
            ProjectSummary project = await c.NeedAsync(() => ProjectOperations.CreateProject(c.OrganizationId,
                projectName, projectName, createDefaultEnvironments: false, template: current.Id), NativeIdentityRole.Setup, ct);
            await c.AddObserversAsync(project.Id, ct);
            ProjectSummary state = await c.NeedAsync(() => ProjectOperations.GetProject(c.OrganizationId, project.Id),
                NativeIdentityRole.Observer, ct);
            if (!state.Environments.IsPresent || state.Environments.IsNull) return false;
            bool hasWitness = state.Environments.Value.Any(e => e.Slug == "witness");
            bool hasOutside = state.Environments.Value.Any(e => e.Slug == "outside");
            if (baseline && (!state.Environments.Value.Any(e => e.Slug == "baseline") || hasWitness)) return false;
            if (!baseline && v is "environments.empty" && state.Environments.Value.Count != 0) return false;
            if (!baseline && v is not ("ProjectTemplateConfiguration.environments.omitted" or "environments.null" or "environments.empty") &&
                (!hasWitness || !hasOutside)) return false;
            if (baseline && baselineIdentitiesEmpty || !baseline && identitiesOmitted)
            {
                SecretOutcome<ProjectIdentityMembershipSummary> absent = await c.ExecuteAsync(
                    () => MembershipOperations.GetProjectIdentityMembership(c.OrganizationId, project.Id, runtime),
                    NativeIdentityRole.Observer, ct);
                if (absent.Status != SecretStatus.Absent) return false;
                await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId, project.Id, runtime,
                    new MembershipRoleSelection(roles: [new(baseline ? role : assignedRole)])), NativeIdentityRole.Setup, ct);
            }
            string[]? allowedTags = null, outsideTags = null;
            if (!baseline && (tagsIn || tagsAll))
            {
                ProjectTag first = await c.NeedAsync(() => ProjectOperations.CreateTag(c.OrganizationId, project.Id,
                    "admitted", "#123456"), NativeIdentityRole.Setup, ct);
                if (tagsAll)
                {
                    ProjectTag second = await c.NeedAsync(() => ProjectOperations.CreateTag(c.OrganizationId, project.Id,
                        "second", "#654321"), NativeIdentityRole.Setup, ct);
                    allowedTags = [first.Id, second.Id];
                    outsideTags = [first.Id];
                }
                else { allowedTags = [first.Id]; outsideTags = []; }
            }
            var allowed = await ProjectCanary.CreateAsync(c, project.Id, baseline ? "baseline" : "witness", ct,
                !baseline && !hasWitness, allowedTags);
            var outside = await ProjectCanary.CreateAsync(c, project.Id, "outside", ct, !hasOutside, outsideTags);
            if (remove) { retained = allowed; retainedOutside = outside; }
            bool effect = baseline ? await allowed.ReadAsync(NativeIdentityRole.Runtime, true, ct) &&
                await outside.ReadAsync(NativeIdentityRole.Runtime, false, ct) &&
                await allowed.ReadAsync(NativeIdentityRole.Denied, false, ct) :
                mutationPermission ? await allowed.ChangeAsync(action, true, ct) &&
                    await outside.ChangeAsync(action, false, ct) : metadataOnly ?
                await allowed.InspectAsync(NativeIdentityRole.Runtime, true, ct) &&
                    await allowed.ReadAsync(NativeIdentityRole.Runtime, false, ct) :
                await allowed.ReadAsync(NativeIdentityRole.Runtime, !emptyIn, ct);
            if (!baseline && !mutationPermission) effect &= await outside.ReadAsync(NativeIdentityRole.Runtime, unrestricted, ct) &&
                await allowed.ReadAsync(NativeIdentityRole.Denied, false, ct);
            if (effect)
            {
                c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope,
                    "intended-principal-permission-observer", NativeObservation.Matched);
                c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "permission-policy-entitlement", NativeObservation.Matched);
            }
            return effect;
        }
        if (remove || configurationUpdate)
            c.Probe.Contract(await Observe(false, token), NativeFailure.MissingPrerequisite);
        if (c.Operation == "ListProjectTemplates")
            await c.CaseAsync(() => ProjectTemplateOperations.ListProjectTemplates(c.OrganizationId,
                v == "type.omitted" ? null : ProjectTemplateType.SecretManager),
                page => page.IsComplete && page.Items.Any(t => Match(t, false)), Observe, token);
        else
        {
            Func<ManagementRequest<ProjectTemplateSummary>> factory = c.Operation switch
            {
                "CreateProjectTemplate" => () => ProjectTemplateOperations.CreateProjectTemplate(c.OrganizationId,
                    name, description: description, configuration: configuration),
                "UpdateProjectTemplate" => () => ProjectTemplateOperations.UpdateProjectTemplate(c.OrganizationId,
                    id, nextName, description, change),
                "GetProjectTemplate" => () => ProjectTemplateOperations.GetProjectTemplate(c.OrganizationId, id),
                "DeleteProjectTemplate" => () => ProjectTemplateOperations.DeleteProjectTemplate(c.OrganizationId, id),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(factory, t => Match(t, true), Observe, token);
        }
    }
}
