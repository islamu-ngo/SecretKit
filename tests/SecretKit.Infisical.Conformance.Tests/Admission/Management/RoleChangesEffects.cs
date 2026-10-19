using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class RoleChangesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        bool organization = c.Operation.Contains("Organization", StringComparison.Ordinal);
        bool create = c.Operation.StartsWith("Create", StringComparison.Ordinal);
        var scenario = await PermissionRoleScenario.CreateAsync(c, organization, !create, true, token);
        Func<ManagementRequest<RoleSummary>> request = c.Operation switch
        {
            "CreateOrganizationRole" => () => RoleChangeOperations.CreateOrganizationRole(
                c.OrganizationId, scenario.OrganizationChange),
            "UpdateOrganizationRole" => () => RoleChangeOperations.UpdateOrganizationRole(
                c.OrganizationId, scenario.Id, scenario.OrganizationChange),
            "CreateProjectRole" => () => RoleChangeOperations.CreateProjectRole(
                c.OrganizationId, c.ProjectId, scenario.ProjectChange),
            "UpdateProjectRole" => () => RoleChangeOperations.UpdateProjectRole(
                c.OrganizationId, c.ProjectId, scenario.Id, scenario.ProjectChange),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        await c.CaseAsync(request, scenario.Match,
            (applied, ct) => scenario.ObserveAsync(create ? applied : true, applied, ct), token);
    }
}

internal sealed class PermissionRoleScenario
{
    private readonly ProjectFamilyContext context;
    private readonly bool organization;
    private readonly PermissionWitness? witness;
    private GroupMetadata? group;
    private bool assigned;
    private bool baselineGranted;
    internal string Id { get; private set; } = "";
    internal string Slug { get; } = ProjectFamilyContext.FreshName();
    internal string Name { get; } = ProjectFamilyContext.FreshName();
    internal OrganizationRoleChange OrganizationChange { get; }
    internal ProjectRoleChange ProjectChange { get; }
    private readonly RoleDescription? description;

    private PermissionRoleScenario(ProjectFamilyContext c, bool organization, PermissionWitness? witness)
    {
        context = c;
        this.organization = organization;
        this.witness = witness;
        description = c.Variant switch
        {
            "description.null" => new(null),
            "description.empty" => new(""),
            "description.value" => new("permission-witness"),
            _ => null
        };
        OrganizationRolePermission[] permissions = c.Variant == "permissions.empty" ? [] :
            [c.Variant == "permissions.action.array" ?
                new(OrganizationRoleSubject.Groups, new[] { OrganizationRoleAction.Read }) :
                new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)];
        OrganizationChange = new(Name, Slug, description, permissions);
        ProjectChange = new(Name, Slug, description, PermissionWitness.Policy(c.Variant));
    }

    internal static async ValueTask<PermissionRoleScenario> CreateAsync(ProjectFamilyContext c,
        bool organization, bool seed, bool emptySeed, CancellationToken token)
    {
        PermissionWitness? witness = null;
        if (!organization)
        {
            await c.EnsureProjectAsync(token);
            await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId, c.ProjectId,
                c.Required("runtimeIdentityId"), new MembershipRoleSelection(roles: [new("no-access")])),
                NativeIdentityRole.Setup, token);
            witness = await PermissionWitness.CreateAsync(c, token);
            c.Probe.Contract(await witness.ObserveAsync(false, token), NativeFailure.MissingPrerequisite);
        }
        var scenario = new PermissionRoleScenario(c, organization, witness);
        scenario.baselineGranted = seed && emptySeed && c.Variant == "permissions.empty";
        c.Cleanup(scenario.CleanupAsync);
        if (organization)
        {
            scenario.group = await ScopedAccessEffects.SeedGroupAsync(c, token);
            await c.NeedAsync(() => ScopedAccessOperations.AddGroupIdentity(c.OrganizationId,
                scenario.group.Id, c.Required("runtimeIdentityId")), NativeIdentityRole.Setup, token);
            c.Probe.Contract(await scenario.ReadGroupAsync(false, token), NativeFailure.MissingPrerequisite);
        }
        if (seed)
        {
            RoleSummary role = await c.NeedAsync(() => organization ?
                RoleChangeOperations.CreateOrganizationRole(c.OrganizationId,
                    scenario.baselineGranted ? new(scenario.Name, scenario.Slug, new("seed"),
                        [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)]) :
                    emptySeed ? new(scenario.Name, scenario.Slug, new("seed"), []) : scenario.OrganizationChange) :
                RoleChangeOperations.CreateProjectRole(c.OrganizationId, c.ProjectId,
                    scenario.baselineGranted ? new(scenario.Name, scenario.Slug, new("seed"),
                        PermissionWitness.Policy("condition.literal")) :
                    emptySeed ? new(scenario.Name, scenario.Slug, new("seed"), []) : scenario.ProjectChange),
                NativeIdentityRole.Setup, token);
            scenario.Id = role.Id;
            await scenario.AssignAsync(token);
            c.Probe.Contract(await scenario.ObserveAsync(true, !emptySeed, token), NativeFailure.MissingPrerequisite);
        }
        return scenario;
    }

    internal bool Match(RoleSummary role) => role.Slug == Slug && role.Name == Name &&
        (Id.Length == 0 || role.Id == Id) &&
        (description is null ? role.Description == (context.Operation.StartsWith("Update", StringComparison.Ordinal) ?
            "seed" : null) : role.Description == description.Value) &&
        (organization ? OrganizationMetadata(role.Permissions, context.Variant) :
            PermissionPrivilegeScenario.PermissionMetadata(role.Permissions, context.Variant));

    private static bool OrganizationMetadata(IReadOnlyList<RolePermissionSummary>? permissions, string variant) =>
        variant == "permissions.empty" ? permissions is { Count: 0 } :
        permissions is { Count: 1 } && !permissions[0].IncludesConditionValues &&
        permissions[0].Subject is { IsScalar: true } subject && subject.Values.SequenceEqual(["groups"]) &&
        permissions[0].Action.Values.SequenceEqual(["read"]) &&
        permissions[0].Action.IsScalar == (variant != "permissions.action.array");

    private async ValueTask AssignAsync(CancellationToken token)
    {
        if (assigned) return;
        if (organization)
        {
            SecretOutcome<MembershipSummary> existing = await context.ExecuteAsync(() =>
                MembershipOperations.GetOrganizationGroup(context.OrganizationId, group!.Id),
                NativeIdentityRole.Observer, token);
            context.Probe.Contract(existing.IsSuccess || existing.Status == SecretStatus.Absent, NativeFailure.MissingPrerequisite);
            await context.NeedAsync(() => existing.IsSuccess ?
                MembershipOperations.UpdateOrganizationGroupRoles(context.OrganizationId, group!.Id, [new(Slug)]) :
                MembershipOperations.AddOrganizationGroup(context.OrganizationId, group!.Id, [new(Slug)]),
                NativeIdentityRole.Setup, token);
        }
        else
            await context.NeedAsync(() => MembershipOperations.UpdateProjectIdentityRoles(
                context.OrganizationId, context.ProjectId, context.Required("runtimeIdentityId"), [new(Slug)]),
                NativeIdentityRole.Setup, token);
        assigned = true;
    }

    internal async ValueTask<bool> ObserveAsync(bool present, bool changed, CancellationToken token)
    {
        SecretOutcome<RoleSummary> observed = await context.ExecuteAsync(() => organization ?
            ScopedAccessOperations.GetOrganizationRoleBySlug(context.OrganizationId, Slug) :
            ProjectOperations.GetProjectRoleBySlug(context.OrganizationId, context.ProjectId, Slug),
            NativeIdentityRole.Observer, token);
        if (!present)
            return observed.Status == SecretStatus.Absent && (organization ?
                await ReadGroupAsync(false, token) : await witness!.ObserveAsync(false, token));
        if (!observed.IsSuccess || Id.Length != 0 && observed.Value.Id != Id) return false;
        Id = observed.Value.Id;
        bool metadata = changed ? Match(observed.Value) :
            observed.Value.Slug == Slug && observed.Value.Name == Name &&
            (organization ? OrganizationMetadata(observed.Value.Permissions, baselineGranted ? "permission.scalar-crud" : "permissions.empty") :
                PermissionPrivilegeScenario.PermissionMetadata(observed.Value.Permissions, baselineGranted ? "permission.scalar-crud" : "permissions.empty")) &&
            observed.Value.Description == "seed";
        if (!metadata) return false;
        SecretOutcome<RoleSummary> exact = await context.ExecuteAsync(() => organization ?
            ScopedAccessOperations.GetOrganizationRole(context.OrganizationId, Id) :
            ProjectOperations.GetProjectRole(context.OrganizationId, context.ProjectId, Id),
            NativeIdentityRole.Observer, token);
        if (!exact.IsSuccess || exact.Value.Slug != Slug || exact.Value.Id != Id) return false;
        await AssignAsync(token);
        bool access = changed ? context.Variant != "permissions.empty" : baselineGranted;
        return organization ? await ReadGroupAsync(access, token) : await witness!.ObserveAsync(access, token);
    }

    private async ValueTask<bool> ReadGroupAsync(bool access, CancellationToken token)
    {
        SecretOutcome<GroupMetadata> allowed = await context.ExecuteAsync(() =>
            ScopedAccessOperations.GetGroup(context.OrganizationId, group!.Id), NativeIdentityRole.Runtime, token);
        SecretOutcome<GroupMetadata> denied = await context.ExecuteAsync(() =>
            ScopedAccessOperations.GetGroup(context.OrganizationId, group!.Id), NativeIdentityRole.Denied, token);
        bool matched = (access ? allowed.IsSuccess && allowed.Value.Id == group!.Id &&
            allowed.Value.Name == group.Name : allowed.Status == SecretStatus.Denied) &&
            denied.Status == SecretStatus.Denied;
        if (matched && access)
        {
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope, "selected-runtime-identity", NativeObservation.Matched);
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope,
                "intended-principal-permission-observer", NativeObservation.Matched);
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope, "permission-policy-entitlement", NativeObservation.Matched);
        }
        return matched;
    }

    private async ValueTask<bool> CleanupAsync(CancellationToken token)
    {
        // Fresh slug ownership also covers a lost creation response.
        SecretOutcome<RoleSummary> found = await context.ExecuteAsync(() => organization ?
            ScopedAccessOperations.GetOrganizationRoleBySlug(context.OrganizationId, Slug) :
            ProjectOperations.GetProjectRoleBySlug(context.OrganizationId, context.ProjectId, Slug),
            NativeIdentityRole.Observer, token);
        if (found.Status == SecretStatus.Absent) return true;
        if (!found.IsSuccess || Id.Length != 0 && found.Value.Id != Id) return false;
        if (!organization && assigned)
            await context.NeedAsync(() => MembershipOperations.UpdateProjectIdentityRoles(context.OrganizationId,
                context.ProjectId, context.Required("runtimeIdentityId"), [new("no-access")]),
                NativeIdentityRole.Setup, token);
        string id = found.Value.Id;
        SecretOutcome<RoleSummary> deleted = await context.ExecuteAsync(() => organization ?
            ScopedAccessOperations.DeleteOrganizationRole(context.OrganizationId, id) :
            ProjectOperations.DeleteProjectRole(context.OrganizationId, context.ProjectId, id),
            NativeIdentityRole.Setup, token);
        SecretOutcome<RoleSummary> absent = await context.ExecuteAsync(() => organization ?
            ScopedAccessOperations.GetOrganizationRole(context.OrganizationId, id) :
            ProjectOperations.GetProjectRole(context.OrganizationId, context.ProjectId, id),
            NativeIdentityRole.Observer, token);
        return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
    }
}
