using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class MembershipsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition definition)
    {
        if (definition.Key.Variant == "roles.omitted" && definition.Key.Operation.EndsWith(".Roles", StringComparison.Ordinal))
            return "default-membership-role-policy-unestablished";
        return null;
    }

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (c.Operation.Contains("Organization", StringComparison.Ordinal))
        {
            await OrganizationAsync(c, token);
            return;
        }
        await c.EnsureProjectAsync(token);
        string org = c.OrganizationId, project = c.ProjectId, runtime = c.Required("runtimeIdentityId");
        bool group = c.Operation.Contains("Group", StringComparison.Ordinal);
        GroupMetadata? ownedGroup = group ? await SeedGroupAsync(c, token) : null;
        string principal = ownedGroup?.Id ?? runtime;
        if (group)
            await c.NeedAsync(() => ScopedAccessOperations.AddGroupIdentity(org, principal, runtime),
                NativeIdentityRole.Setup, token);
        bool add = c.Operation.StartsWith("Add", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool remove = c.Operation.StartsWith("Remove", StringComparison.Ordinal);
        bool empty = c.Variant == "roles.empty";
        string initialRole = update ? "no-access" : "viewer";
        MembershipSummary? before = null;
        if (!add)
            before = await c.NeedAsync(() => group ?
                MembershipOperations.AddProjectGroup(org, project, principal,
                    new MembershipRoleSelection(roles: [new(initialRole)])) :
                MembershipOperations.AddProjectIdentity(org, project, principal,
                    new MembershipRoleSelection(roles: [new(initialRole)])), NativeIdentityRole.Setup, token);
        var canary = await ProjectCanary.CreateAsync(c, project, "witness", token);
        c.Probe.Contract(await canary.ReadAsync(NativeIdentityRole.Runtime, !add && !update, token) &&
            await canary.ReadAsync(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);
        MembershipRole[] roles = empty ? [] : [new("viewer",
            omitPermanentDiscriminator: c.Variant == "roles.permanent-discriminator-omitted")];
        var selection = c.Variant switch
        {
            "role.scalar" or "roles.omitted" => new MembershipRoleSelection(role: "viewer"),
            "role-and-roles.supplied" => new MembershipRoleSelection("viewer", roles),
            _ => new MembershipRoleSelection(roles: roles)
        };
        bool Match(MembershipSummary m) => m.PrincipalId == principal && (add || m.Id == before!.Id);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool present = applied ? !remove : !add;
            bool access = applied ? !remove && !empty : !add && !update;
            bool state;
            if (group)
            {
                SecretOutcome<MembershipSummary> observed = await c.ExecuteAsync(
                    () => MembershipOperations.GetProjectGroup(org, project, principal), NativeIdentityRole.Observer, ct);
                state = present ? observed.IsSuccess && Match(observed.Value) &&
                    observed.Value.Group?.Id == principal && observed.Value.Roles.IsPresent &&
                    (access ? observed.Value.Roles.Value.Any(r => r.Role == "viewer" && r.IsTemporary != true) :
                        !empty || observed.Value.Roles.Value.Count == 0) :
                    observed.Status == SecretStatus.Absent;
            }
            else
            {
                SecretOutcome<ProjectIdentityMembershipSummary> observed = await c.ExecuteAsync(
                    () => MembershipOperations.GetProjectIdentityMembership(org, project, principal), NativeIdentityRole.Observer, ct);
                state = present ? observed.IsSuccess && observed.Value.IdentityId == principal &&
                    (before is null || observed.Value.Id == before.Id) &&
                    (access ? observed.Value.Roles.Any(r => r.Role == "viewer" && r.IsTemporary != true) :
                        !empty || observed.Value.Roles.Count == 0) :
                    observed.Status == SecretStatus.Absent;
            }
            bool matched = state && await canary.ReadAsync(NativeIdentityRole.Runtime, access, ct) &&
                await canary.ReadAsync(NativeIdentityRole.Denied, false, ct);
            if (matched) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "membership-principal-observer", NativeObservation.Matched);
            return matched;
        }
        if (c.Operation == "GetProjectIdentityMembership")
        {
            await c.CaseAsync(() => MembershipOperations.GetProjectIdentityMembership(org, project, principal),
                m => m.Id == before!.Id && m.IdentityId == principal && m.Roles.Any(r => r.Role == "viewer"),
                Observe, token);
        }
        else if (c.Operation == "ListProjectGroups")
        {
            await c.CaseAsync(() => MembershipOperations.ListProjectGroups(org, project),
                p => p.IsComplete && p.Items.Any(Match), Observe, token);
        }
        else if (c.Operation == "UpdateProjectGroupRoles")
        {
            await c.CaseAsync(() => MembershipOperations.UpdateProjectGroupRoles(org, project, principal, before!.Id, roles),
                p => p.IsComplete && p.Items.Any(r => r.MembershipId == before!.Id && r.Role == "viewer" && r.IsTemporary != true),
                Observe, token);
        }
        else
        {
            bool listOverload = c.Definition.Key.Operation.EndsWith(".Roles", StringComparison.Ordinal);
            Func<ManagementRequest<MembershipSummary>> request = c.Operation switch
            {
                "AddProjectGroup" when listOverload => () => MembershipOperations.AddProjectGroup(org, project, principal, roles),
                "AddProjectGroup" => () => MembershipOperations.AddProjectGroup(org, project, principal, selection),
                "AddProjectIdentity" when listOverload => () => MembershipOperations.AddProjectIdentity(org, project, principal, roles),
                "AddProjectIdentity" => () => MembershipOperations.AddProjectIdentity(org, project, principal, selection),
                "GetProjectGroup" => () => MembershipOperations.GetProjectGroup(org, project, principal),
                "RemoveProjectGroup" => () => MembershipOperations.RemoveProjectGroup(org, project, principal),
                "RemoveProjectIdentity" => () => MembershipOperations.RemoveProjectIdentity(org, project, principal),
                "UpdateProjectIdentityRoles" => () => MembershipOperations.UpdateProjectIdentityRoles(org, project, principal, roles),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(request, Match, Observe, token);
        }
    }

    private static async ValueTask OrganizationAsync(ProjectFamilyContext c, CancellationToken token)
    {
        var owner = await OrganizationGroupOwner.CreateAsync(c, token);
        string org = c.OrganizationId;
        string roleName = ProjectFamilyContext.FreshName();
        string? roleId = null;
        var roleChange = new OrganizationRoleChange(roleName, roleName,
            permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)]);
        c.Cleanup(async ct =>
        {
            SecretOutcome<RoleSummary> found = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetOrganizationRoleBySlug(org, roleName), NativeIdentityRole.Observer, ct);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess || roleId is not null && found.Value.Id != roleId) return false;
            SecretOutcome<RoleSummary> deleted = await c.ExecuteAsync(
                () => ScopedAccessOperations.DeleteOrganizationRole(org, found.Value.Id), NativeIdentityRole.Setup, ct);
            SecretOutcome<RoleSummary> absent = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetOrganizationRoleBySlug(org, roleName), NativeIdentityRole.Observer, ct);
            return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        var custom = await c.NeedAsync(() => RoleChangeOperations.CreateOrganizationRole(org, roleChange), NativeIdentityRole.Setup, token);
        roleId = custom.Id;
        GroupMetadata group = await owner.SeedAsync(token);
        bool add = c.Operation == "AddOrganizationGroup", update = c.Operation == "UpdateOrganizationGroupRoles";
        bool remove = c.Operation == "RemoveOrganizationGroup";
        // Parent ownership is separate from the sub-organization assignment.
        SecretOutcome<MembershipSummary> existing = await c.ExecuteAsync(
            () => MembershipOperations.GetOrganizationGroup(org, group.Id), NativeIdentityRole.Observer, token);
        c.Probe.Contract(existing.Status == SecretStatus.Absent, NativeFailure.MissingPrerequisite);
        string? targetId = null;
        owner.CleanupTarget(group, () => targetId);
        MembershipSummary? before = null;
        if (!add)
        {
            before = await c.NeedAsync(() => MembershipOperations.AddOrganizationGroup(org, group.Id,
                [new(update ? "no-access" : roleName)]), NativeIdentityRole.Setup, token);
            targetId = before.Id;
            c.Probe.Contract(before.Id != owner.MembershipId(group) &&
                OrganizationGroupOwner.Parent(before, group.Id, owner.OrganizationId), NativeFailure.MissingPrerequisite);
        }
        SecretOutcome<GroupMetadata> priorAccess = await c.ExecuteAsync(
            () => ScopedAccessOperations.GetGroup(owner.OrganizationId, group.Id), NativeIdentityRole.Runtime, token);
        c.Probe.Contract(!add && !update ? priorAccess.IsSuccess && priorAccess.Value.Id == group.Id :
            priorAccess.Status == SecretStatus.Denied, NativeFailure.MissingPrerequisite);
        MembershipRole[] roles = [new(roleName, omitPermanentDiscriminator: c.Variant == "roles.permanent-discriminator-omitted")];
        bool Match(MembershipSummary m) => OrganizationGroupOwner.Parent(m, group.Id, owner.OrganizationId) &&
            m.Id != owner.MembershipId(group) && (targetId is null || m.Id == targetId);
        bool Role(MembershipSummary m, bool access) => m.Roles.IsPresent && !m.Roles.IsNull &&
            m.Roles.Value.Count == 1 && m.Roles.Value[0].IsTemporary == false &&
            (access ? m.Roles.Value[0].CustomRoleId == roleId && m.Roles.Value[0].CustomRoleSlug == roleName :
                m.Roles.Value[0].Role == "no-access" && m.Roles.Value[0].CustomRoleId is null);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool present = applied ? !remove : !add, access = applied ? !remove : !add && !update;
            SecretOutcome<MembershipSummary> membership = await c.ExecuteAsync(
                () => MembershipOperations.GetOrganizationGroup(org, group.Id), NativeIdentityRole.Observer, ct);
            SecretOutcome<GroupMetadata> allowed = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetGroup(owner.OrganizationId, group.Id), NativeIdentityRole.Runtime, ct);
            SecretOutcome<GroupMetadata> denied = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetGroup(owner.OrganizationId, group.Id), NativeIdentityRole.Denied, ct);
            bool matched = (present ? membership.IsSuccess && Match(membership.Value) && Role(membership.Value, access) :
                    membership.Status == SecretStatus.Absent) &&
                (access ? allowed.IsSuccess && allowed.Value.Id == group.Id : allowed.Status == SecretStatus.Denied) &&
                denied.Status == SecretStatus.Denied && await owner.ObserveAsync(group, ct);
            if (matched && present) targetId ??= membership.Value.Id;
            if (matched) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "membership-principal-observer", NativeObservation.Matched);
            return matched;
        }
        if (c.Operation == "ListOrganizationGroups")
        {
            GroupMetadata second = await owner.SeedAsync(token, "zz" + ProjectFamilyContext.FreshName(), linkRuntime: false);
            string? secondId = null;
            owner.CleanupTarget(second, () => secondId);
            var secondMembership = await c.NeedAsync(() => MembershipOperations.AddOrganizationGroup(org, second.Id,
                [new("viewer")]), NativeIdentityRole.Setup, token);
            secondId = secondMembership.Id;
            c.Probe.Contract(secondId != owner.MembershipId(second) &&
                OrganizationGroupOwner.Parent(secondMembership, second.Id, owner.OrganizationId), NativeFailure.MissingPrerequisite);
            OrganizationGroupOrder? column = c.Variant switch
            {
                "orderBy.Name" => OrganizationGroupOrder.Name,
                "orderBy.Slug" => OrganizationGroupOrder.Slug,
                "orderBy.Role" => OrganizationGroupOrder.Role,
                "order.Ascending" or "order.Descending" => OrganizationGroupOrder.Name,
                _ => null
            };
            ManagementListOrder? order = c.Variant switch
            {
                "order.Ascending" => ManagementListOrder.Ascending,
                "order.Descending" => ManagementListOrder.Descending,
                "orderBy.Name" or "orderBy.Slug" or "orderBy.Role" => ManagementListOrder.Ascending,
                _ => null
            };
            string? search = c.Variant == "search.value" ? group.Name : null;
            bool MatchPage(ManagementPage<MembershipSummary> page)
            {
                if (!page.IsComplete || page.Items.Select(m => m.Id).Distinct().Count() != page.Items.Count ||
                    page.Items.Count(Match) != 1) return false;
                if (search is not null)
                    return page.Items.All(m => m.Group is not null && ProjectsEffects.Field(m.Group.Name, group.Name));
                if (page.Items.Count(m => m.PrincipalId == second.Id) != 1) return false;
                if (column is null || order is null) return true;
                int firstIndex = page.Items.ToList().FindIndex(m => m.PrincipalId == group.Id);
                int secondIndex = page.Items.ToList().FindIndex(m => m.PrincipalId == second.Id);
                // Owned names/slugs and assigned role slugs are distinct ASCII values.
                string firstValue = column == OrganizationGroupOrder.Role ? roleName : group.Name;
                string secondValue = column == OrganizationGroupOrder.Role ? "viewer" : second.Name;
                bool firstBefore = string.CompareOrdinal(firstValue, secondValue) < 0;
                if (order == ManagementListOrder.Descending) firstBefore = !firstBefore;
                return firstBefore ? firstIndex < secondIndex : firstIndex > secondIndex;
            }
            await c.CaseAsync(() => MembershipOperations.ListOrganizationGroups(org, orderBy: column, order: order, search: search),
                MatchPage, async (applied, ct) =>
                {
                    var page = await c.ExecuteAsync(() => MembershipOperations.ListOrganizationGroups(org,
                        orderBy: column, order: order, search: search), NativeIdentityRole.Observer, ct);
                    return page.IsSuccess && MatchPage(page.Value) && await Observe(applied, ct);
                }, token);
        }
        else
        {
            Func<ManagementRequest<MembershipSummary>> request = c.Operation switch
            {
                "AddOrganizationGroup" => () => MembershipOperations.AddOrganizationGroup(org, group.Id, roles),
                "UpdateOrganizationGroupRoles" => () => MembershipOperations.UpdateOrganizationGroupRoles(org, group.Id, roles),
                "RemoveOrganizationGroup" => () => MembershipOperations.RemoveOrganizationGroup(org, group.Id),
                "GetOrganizationGroup" => () => MembershipOperations.GetOrganizationGroup(org, group.Id),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(request, m =>
            {
                bool matches = m.PrincipalId == group.Id && (targetId is null || m.Id == targetId) &&
                    (remove || Match(m) && Role(m, true));
                if (matches && !remove) targetId ??= m.Id;
                return matches;
            }, Observe, token);
        }
    }

    internal static async ValueTask<GroupMetadata> SeedGroupAsync(ProjectFamilyContext c, CancellationToken token,
        string? selectedName = null)
    {
        string name = selectedName ?? ProjectFamilyContext.FreshName();
        c.Cleanup(async ct =>
        {
            SecretOutcome<ManagementPage<GroupMetadata>> groups = await c.ExecuteAsync(
                () => ScopedAccessOperations.ListGroups(c.OrganizationId), NativeIdentityRole.Observer, ct);
            if (!groups.IsSuccess || !groups.Value.IsComplete) return false;
            GroupMetadata[] found = groups.Value.Items.Where(g => g.Name == name && g.Slug == name).ToArray();
            if (found.Length == 0) return true;
            if (found.Length != 1) return false;
            string id = found[0].Id;
            SecretOutcome<GroupMetadata> deleted = await c.ExecuteAsync(
                () => ScopedAccessOperations.DeleteGroup(c.OrganizationId, id), NativeIdentityRole.Setup, ct);
            SecretOutcome<GroupMetadata> absent = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetGroup(c.OrganizationId, id), NativeIdentityRole.Observer, ct);
            return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        return await c.NeedAsync(() => ScopedAccessOperations.CreateGroup(c.OrganizationId, name, name, "no-access"),
            NativeIdentityRole.Setup, token);
    }
}
