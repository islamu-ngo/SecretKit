using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ScopedAccessEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (c.Operation.Contains("OrganizationRole", StringComparison.Ordinal))
        {
            var role = await PermissionRoleScenario.CreateAsync(c, true, true, false, token);
            if (c.Operation == "ListOrganizationRoles")
                await c.CaseAsync(() => ScopedAccessOperations.ListOrganizationRoles(c.OrganizationId),
                    page => Complete(page, r => r.Id) && page.Items.Count(r => r.Id == role.Id && r.Slug == role.Slug &&
                        r.Name == role.Name && !r.IncludesPermissions) == 1,
                    (_, ct) => role.ObserveAsync(true, true, ct), token);
            else
            {
                Func<ManagementRequest<RoleSummary>> factory = c.Operation switch
                {
                    "GetOrganizationRole" => () => ScopedAccessOperations.GetOrganizationRole(c.OrganizationId, role.Id),
                    "GetOrganizationRoleBySlug" => () => ScopedAccessOperations.GetOrganizationRoleBySlug(c.OrganizationId, role.Slug),
                    "DeleteOrganizationRole" => () => ScopedAccessOperations.DeleteOrganizationRole(c.OrganizationId, role.Id),
                    _ => throw new NativeCaseFailureException("contract-mismatch")
                };
                await c.CaseAsync(factory, role.Match, (applied, ct) =>
                    role.ObserveAsync(!(applied && c.Operation == "DeleteOrganizationRole"), true, ct), token);
            }
            return;
        }
        await GroupsAsync(c, token);
    }

    private static void OwnGroup(ProjectFamilyContext c, string name, string? slug, Func<string?> acknowledgedId)
    {
        c.Cleanup(async token =>
        {
            SecretOutcome<ManagementPage<GroupMetadata>> groups = await c.ExecuteAsync(
                () => ScopedAccessOperations.ListGroups(c.OrganizationId), NativeIdentityRole.Observer, token);
            if (!groups.IsSuccess || !Complete(groups.Value, g => g.Id)) return false;
            GroupMetadata[] found = groups.Value.Items.Where(g => g.Name == name &&
                (slug is null || g.Slug == slug)).ToArray();
            if (found.Length == 0) return true;
            if (found.Length != 1) return false;
            string id = found[0].Id;
            if (acknowledgedId() is { } expected && expected != id) return false;
            SecretOutcome<GroupMetadata> exact = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetGroup(c.OrganizationId, id), NativeIdentityRole.Observer, token);
            if (!exact.IsSuccess || exact.Value.Name != name || slug is not null && exact.Value.Slug != slug) return false;
            SecretOutcome<GroupMetadata> removed = await c.ExecuteAsync(
                () => ScopedAccessOperations.DeleteGroup(c.OrganizationId, id), NativeIdentityRole.Setup, token);
            SecretOutcome<GroupMetadata> absent = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetGroup(c.OrganizationId, id), NativeIdentityRole.Observer, token);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
    }

    internal static async ValueTask<GroupMetadata> SeedGroupAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName();
        GroupMetadata? created = null;
        OwnGroup(c, name, name, () => created?.Id);
        created = await c.NeedAsync(() => ScopedAccessOperations.CreateGroup(c.OrganizationId, name, name, "no-access"),
            NativeIdentityRole.Setup, token);
        return created;
    }

    private static async ValueTask<string> SeedRoleAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string slug = ProjectFamilyContext.FreshName();
        string? acknowledgedId = null;
        c.Cleanup(async ct =>
        {
            SecretOutcome<RoleSummary> found = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetOrganizationRoleBySlug(c.OrganizationId, slug), NativeIdentityRole.Observer, ct);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess || found.Value.Name != slug || found.Value.Slug != slug ||
                acknowledgedId is not null && found.Value.Id != acknowledgedId) return false;
            SecretOutcome<RoleSummary> removed = await c.ExecuteAsync(
                () => ScopedAccessOperations.DeleteOrganizationRole(c.OrganizationId, found.Value.Id), NativeIdentityRole.Setup, ct);
            SecretOutcome<RoleSummary> absent = await c.ExecuteAsync(
                () => ScopedAccessOperations.GetOrganizationRoleBySlug(c.OrganizationId, slug), NativeIdentityRole.Observer, ct);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        RoleSummary created = await c.NeedAsync(() => RoleChangeOperations.CreateOrganizationRole(c.OrganizationId,
            new(slug, slug, permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])),
            NativeIdentityRole.Setup, token);
        acknowledgedId = created.Id;
        return slug;
    }

    private static async ValueTask GroupsAsync(ProjectFamilyContext c, CancellationToken token)
    {
        await c.EnsureProjectAsync(token);
        string org = c.OrganizationId, runtime = c.Required("runtimeIdentityId");
        bool create = c.Operation == "CreateGroup", remove = c.Operation == "DeleteGroup";
        bool add = c.Operation is "AddGroupIdentity" or "AddGroupUser";
        bool detach = c.Operation is "RemoveGroupIdentity" or "RemoveGroupUser";
        bool user = c.Operation.Contains("User", StringComparison.Ordinal);
        if (user)
            c.Probe.Contract(c.Required("runtimeUserId") == runtime, NativeFailure.MissingInput);
        string? username = user ? c.Required("runtimeUsername") : null;
        if (user) await EligibleUserAsync(c, runtime, username!, token);
        string? readRole = c.Variant == "role.value" ? await SeedRoleAsync(c, token) : null;
        string name = ProjectFamilyContext.FreshName(), slug = ProjectFamilyContext.FreshName();
        string nextName = ProjectFamilyContext.FreshName(), nextSlug = ProjectFamilyContext.FreshName();
        string? acknowledgedId = null;
        OwnGroup(c, name, create && c.Variant == "slug.omitted" ? null : slug, () => acknowledgedId);
        GroupMetadata? before = create ? null : await c.NeedAsync(() =>
            ScopedAccessOperations.CreateGroup(org, name, slug, "no-access"), NativeIdentityRole.Setup, token);
        string id = before?.Id ?? "";
        acknowledgedId = before?.Id;
        bool member = false, projectAssigned = false;
        var inside = await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token);
        string outsideSlug = ProjectFamilyContext.FreshName();
        c.OwnProject(outsideSlug);
        ProjectSummary outsideProject = await c.NeedAsync(() => ProjectOperations.CreateProject(org,
            outsideSlug, outsideSlug, createDefaultEnvironments: false), NativeIdentityRole.Setup, token);
        await c.AddObserversAsync(outsideProject.Id, token);
        var outside = await ProjectCanary.CreateAsync(c, outsideProject.Id, "witness", token);
        async ValueTask AttachAsync(CancellationToken ct)
        {
            if (!member)
            {
                if (user)
                    await c.NeedAsync(() => ScopedAccessOperations.AddGroupUser(org, id, username!), NativeIdentityRole.Setup, ct);
                else
                    await c.NeedAsync(() => ScopedAccessOperations.AddGroupIdentity(org, id, runtime), NativeIdentityRole.Setup, ct);
                member = true;
            }
            if (!projectAssigned)
            {
                await c.NeedAsync(() => MembershipOperations.AddProjectGroup(org, c.ProjectId, id,
                    new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, ct);
                projectAssigned = true;
            }
        }
        if (!create)
        {
            await c.NeedAsync(() => MembershipOperations.AddProjectGroup(org, c.ProjectId, id,
                new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, token);
            projectAssigned = true;
            if (!add) await AttachAsync(token);
        }
        c.Probe.Contract(await inside.ReadAsync(NativeIdentityRole.Runtime, !create && !add, token) &&
            await outside.ReadAsync(NativeIdentityRole.Runtime, false, token) &&
            await inside.ReadAsync(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);

        string? changedName = c.Operation == "UpdateGroup" && c.Variant != "name.omitted" ? nextName : null;
        string? changedSlug = c.Operation == "UpdateGroup" && c.Variant != "slug.omitted" ? nextSlug : null;
        if (changedName is not null || changedSlug is not null)
            OwnGroup(c, changedName ?? name, changedSlug ?? slug, () => acknowledgedId);
        bool Match(GroupMetadata g) => (id.Length == 0 || g.Id == id) &&
            g.Name == (changedName ?? name) &&
            (create && c.Variant == "slug.omitted" || g.Slug == (changedSlug ?? slug)) &&
            (readRole is null || g.CustomRoleSlug.IsPresent && !g.CustomRoleSlug.IsNull &&
                g.CustomRoleSlug.Value == readRole);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool present = create ? applied : !(remove && applied);
            bool access = present && !(add && !applied || detach && applied);
            SecretOutcome<ManagementPage<GroupMetadata>> list = await c.ExecuteAsync(
                () => ScopedAccessOperations.ListGroups(org), NativeIdentityRole.Observer, ct);
            if (!list.IsSuccess || !Complete(list.Value, g => g.Id)) return false;
            GroupMetadata[] found = list.Value.Items.Where(g => id.Length != 0 ? g.Id == id : g.Name == name).ToArray();
            if (!present)
            {
                if (found.Length != 0) return false;
            }
            else
            {
                if (found.Length != 1) return false;
                if (acknowledgedId is not null && found[0].Id != acknowledgedId) return false;
                id = found[0].Id;
                SecretOutcome<GroupMetadata> exact = await c.ExecuteAsync(() => ScopedAccessOperations.GetGroup(org, id),
                    NativeIdentityRole.Observer, ct);
                if (!exact.IsSuccess || exact.Value.Id != id) return false;
                if (applied && c.Operation is "CreateGroup" or "UpdateGroup")
                {
                    if (!Match(exact.Value)) return false;
                }
                else if (exact.Value.Name != name || exact.Value.Slug != slug) return false;
                if (readRole is null || !applied)
                {
                    if (exact.Value.Role != "no-access" || !exact.Value.CustomRoleSlug.IsPresent ||
                        !exact.Value.CustomRoleSlug.IsNull) return false;
                }
                if (create) await AttachAsync(ct);
                if (user)
                {
                    SecretOutcome<ManagementPage<GroupUser>> users = await c.ExecuteAsync(() =>
                        ScopedAccessOperations.ListGroupUsers(org, id, username: username),
                        NativeIdentityRole.Observer, ct);
                    if (!users.IsSuccess || !users.Value.IsComplete ||
                        !users.Value.Items.Any(u => u.Id == runtime && u.Username == username && u.IsMember == access)) return false;
                }
                else
                {
                    SecretOutcome<ManagementPage<GroupIdentity>> identities = await c.ExecuteAsync(() =>
                        ScopedAccessOperations.ListGroupIdentities(org, id), NativeIdentityRole.Observer, ct);
                    if (!identities.IsSuccess || !identities.Value.IsComplete ||
                        !identities.Value.Items.Any(i => i.Id == runtime && i.IsMember == access)) return false;
                }
                if (readRole is not null)
                {
                    SecretOutcome<GroupMetadata> protectedRead = await c.ExecuteAsync(
                        () => ScopedAccessOperations.GetGroup(org, id), NativeIdentityRole.Runtime, ct);
                    SecretOutcome<GroupMetadata> deniedRead = await c.ExecuteAsync(
                        () => ScopedAccessOperations.GetGroup(org, id), NativeIdentityRole.Denied, ct);
                    if ((applied ? !protectedRead.IsSuccess || protectedRead.Value.Id != id :
                        protectedRead.Status != SecretStatus.Denied) || deniedRead.Status != SecretStatus.Denied) return false;
                }
            }
            bool matched = await inside.ReadAsync(NativeIdentityRole.Runtime, access, ct) &&
                await outside.ReadAsync(NativeIdentityRole.Runtime, false, ct) &&
                await inside.ReadAsync(NativeIdentityRole.Denied, false, ct) &&
                await inside.ReadAsync(NativeIdentityRole.Observer, true, ct);
            if (matched) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope,
                "intended-principal-permission-observer", NativeObservation.Matched);
            return matched;
        }

        string? search = c.Variant == "search.value" ? user ? username : name : null;
        ManagementListOrder order = c.Variant == "order.Descending" ? ManagementListOrder.Descending : ManagementListOrder.Ascending;
        switch (c.Operation)
        {
            case "ListGroupIdentities":
                GroupIdentityFilter? identities = c.Variant switch
                {
                    "filter.Assigned" => GroupIdentityFilter.Assigned,
                    "filter.Unassigned" => GroupIdentityFilter.Unassigned,
                    _ => null
                };
                // Search is the selected machine identity's independently read name, not the group name.
                string identityName = (await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(org, runtime),
                    NativeIdentityRole.Observer, token)).Name;
                IdentitySummary unassigned = await SeedIdentityAsync(c, token);
                c.Probe.Contract(!unassigned.Name.Contains(identityName, StringComparison.OrdinalIgnoreCase),
                    NativeFailure.ObserverUnavailable);
                var identityWitness = await c.NeedAsync(() => ScopedAccessOperations.ListGroupIdentities(org, id),
                    NativeIdentityRole.Observer, token);
                c.Probe.Contract(Complete(identityWitness, i => i.Id) &&
                    identityWitness.Items.Count(i => i.Id == runtime && i.Name == identityName && i.IsMember) == 1 &&
                    identityWitness.Items.Count(i => i.Id == unassigned.Id && i.Name == unassigned.Name && !i.IsMember) == 1,
                    NativeFailure.ObserverUnavailable);
                bool IdentitySelected(string identityId) => identities != GroupIdentityFilter.Unassigned && identityId == runtime ||
                    identities != GroupIdentityFilter.Assigned && c.Variant != "search.value" && identityId == unassigned.Id;
                await c.CaseAsync(() => ScopedAccessOperations.ListGroupIdentities(org, id, filter: identities,
                    search: c.Variant == "search.value" ? identityName : null),
                    page => Complete(page, i => i.Id) &&
                        new[] { runtime, unassigned.Id }.All(key => page.Items.Count(i => i.Id == key) == (IdentitySelected(key) ? 1 : 0)) &&
                        page.Items.All(i => (i.Id != runtime || i.Name == identityName && i.IsMember) &&
                            (i.Id != unassigned.Id || i.Name == unassigned.Name && !i.IsMember) &&
                            (identities is null || i.IsMember == (identities == GroupIdentityFilter.Assigned)) &&
                            (c.Variant != "search.value" || i.Name.Contains(identityName, StringComparison.OrdinalIgnoreCase))),
                    Observe, token);
                break;
            case "ListGroupUsers":
                GroupUserFilter? users = c.Variant switch
                {
                    "filter.Members" => GroupUserFilter.Members,
                    "filter.NonMembers" => GroupUserFilter.NonMembers,
                    _ => null
                };
                string unassignedUserId = c.Required("scopedAccessUnassignedUserId");
                string unassignedUsername = c.Required("scopedAccessUnassignedUsername");
                c.Probe.Contract(unassignedUserId != runtime && unassignedUsername != username, NativeFailure.MissingInput);
                await EligibleUserAsync(c, unassignedUserId, unassignedUsername, token);
                c.Probe.Contract(!unassignedUsername.Contains(username!, StringComparison.OrdinalIgnoreCase),
                    NativeFailure.ObserverUnavailable);
                var userWitness = await c.NeedAsync(() => ScopedAccessOperations.ListGroupUsers(org, id),
                    NativeIdentityRole.Observer, token);
                c.Probe.Contract(Complete(userWitness, u => u.Id) &&
                    userWitness.Items.Count(u => u.Id == runtime && u.Username == username && u.IsMember == true) == 1 &&
                    userWitness.Items.Count(u => u.Id == unassignedUserId && u.Username == unassignedUsername && u.IsMember == false) == 1,
                    NativeFailure.ObserverUnavailable);
                bool UserSelected(string userId) => users != GroupUserFilter.NonMembers && userId == runtime ||
                    users != GroupUserFilter.Members && c.Variant is not ("search.value" or "username.value") && userId == unassignedUserId;
                await c.CaseAsync(() => ScopedAccessOperations.ListGroupUsers(org, id, filter: users,
                    search: search, username: c.Variant == "username.value" ? username : null),
                    page => Complete(page, u => u.Id) &&
                        new[] { runtime, unassignedUserId }.All(key => page.Items.Count(u => u.Id == key) == (UserSelected(key) ? 1 : 0)) &&
                        page.Items.All(u => (u.Id != runtime || u.Username == username && u.IsMember == true) &&
                            (u.Id != unassignedUserId || u.Username == unassignedUsername && u.IsMember == false) &&
                            (users is null || u.IsMember == (users == GroupUserFilter.Members)) &&
                            (search is null || u.Username.Contains(search, StringComparison.OrdinalIgnoreCase)) &&
                            (c.Variant != "username.value" || u.Username == username)),
                    Observe, token);
                break;
            case "ListGroupMembers":
                string memberName = (await c.NeedAsync(() =>
                    IdentityOperations.GetOrganizationIdentity(org, runtime), NativeIdentityRole.Observer, token)).Name;
                string memberUserId = c.Required("scopedAccessUserId"), memberUsername = c.Required("scopedAccessUsername");
                c.Probe.Contract(memberUserId != runtime, NativeFailure.MissingInput);
                await EligibleUserAsync(c, memberUserId, memberUsername, token);
                c.Probe.Contract(!memberUsername.Contains(memberName, StringComparison.OrdinalIgnoreCase) &&
                    memberUsername != memberName, NativeFailure.ObserverUnavailable);
                GroupUser attached = await c.NeedAsync(() => ScopedAccessOperations.AddGroupUser(org, id, memberUsername),
                    NativeIdentityRole.Setup, token);
                c.Probe.Contract(attached.Id == memberUserId, NativeFailure.ObserverUnavailable);
                var memberUsers = await c.NeedAsync(() => ScopedAccessOperations.ListGroupUsers(org, id),
                    NativeIdentityRole.Observer, token);
                c.Probe.Contract(Complete(memberUsers, u => u.Id) &&
                    memberUsers.Items.Count(u => u.Id == memberUserId && u.Username == memberUsername && u.IsMember == true) == 1,
                    NativeFailure.ObserverUnavailable);
                GroupMemberFilter filter = c.Variant switch
                {
                    "members.Users" => GroupMemberFilter.Users,
                    "members.MachineIdentities" => GroupMemberFilter.MachineIdentities,
                    _ => GroupMemberFilter.All
                };
                var expectedMembers = new[] { (Id: runtime, Name: memberName, Kind: GroupMemberKind.MachineIdentity),
                    (Id: memberUserId, Name: memberUsername, Kind: GroupMemberKind.User) }
                    .Where(m => (filter == GroupMemberFilter.All ||
                        m.Kind == (filter == GroupMemberFilter.Users ? GroupMemberKind.User : GroupMemberKind.MachineIdentity)) &&
                        (c.Variant != "search.value" || m.Name.Contains(memberName, StringComparison.OrdinalIgnoreCase)));
                var orderedMembers = (order == ManagementListOrder.Ascending ?
                    expectedMembers.OrderBy(m => m.Name, StringComparer.Ordinal) :
                    expectedMembers.OrderByDescending(m => m.Name, StringComparer.Ordinal)).ToArray();
                await c.CaseAsync(() => ScopedAccessOperations.ListGroupMembers(org, id,
                    search: c.Variant == "search.value" ? memberName : null, order: order,
                    members: filter, memberTypes: c.Variant == "memberTypes.value" ?
                        [GroupMemberFilter.Users, GroupMemberFilter.MachineIdentities] : null),
                    page => Complete(page, m => m.Id) &&
                        page.Items.Select(m => (m.Kind, m.PrincipalId)).Distinct().Count() == page.Items.Count &&
                        page.Items.Where(m => m.PrincipalId == runtime || m.PrincipalId == memberUserId)
                            .Select(m => (m.PrincipalId, m.Name, m.Kind)).SequenceEqual(orderedMembers) &&
                        page.Items.All(m => m.JoinedAt is not null &&
                            (c.Variant != "search.value" || m.Name.Contains(memberName, StringComparison.OrdinalIgnoreCase))) &&
                        (filter == GroupMemberFilter.All || page.Items.All(m =>
                            m.Kind == (filter == GroupMemberFilter.Users ? GroupMemberKind.User : GroupMemberKind.MachineIdentity))) &&
                        Ordered(page.Items.Select(m => m.Name), order),
                    Observe, token);
                break;
            case "ListGroupProjects":
                string contrastSlug = ProjectFamilyContext.FreshName();
                c.OwnProject(contrastSlug);
                ProjectSummary contrastProject = await c.NeedAsync(() => ProjectOperations.CreateProject(org,
                    contrastSlug, contrastSlug, createDefaultEnvironments: false), NativeIdentityRole.Setup, token);
                await c.NeedAsync(() => MembershipOperations.AddProjectGroup(org, contrastProject.Id, id,
                    new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, token);
                GroupProjectSelection selection = c.Variant switch
                {
                    "selection.Unassigned" => GroupProjectSelection.Unassigned,
                    "selection.OrganizationAll" => GroupProjectSelection.OrganizationAll,
                    _ => GroupProjectSelection.Assigned
                };
                var knownProjects = new[] { (Id: c.ProjectId, Name: c.ProjectSlug, Assigned: true),
                    (Id: outsideProject.Id, Name: outsideProject.Name, Assigned: false),
                    (Id: contrastProject.Id, Name: contrastProject.Name, Assigned: true) };
                var expectedProjects = knownProjects.Where(p =>
                    (selection == GroupProjectSelection.OrganizationAll || p.Assigned == (selection == GroupProjectSelection.Assigned)) &&
                    (c.Variant != "search.value" || p.Name.Contains(c.ProjectSlug, StringComparison.OrdinalIgnoreCase)));
                var orderedProjects = (order == ManagementListOrder.Ascending ?
                    expectedProjects.OrderBy(p => p.Name, StringComparer.Ordinal) :
                    expectedProjects.OrderByDescending(p => p.Name, StringComparer.Ordinal)).ToArray();
                await c.CaseAsync(() => ScopedAccessOperations.ListGroupProjects(org, id, selection,
                    search: c.Variant == "search.value" ? c.ProjectSlug : null, order: order),
                    page => Complete(page, p => p.Id) &&
                        page.Items.Where(p => knownProjects.Any(k => k.Id == p.Id))
                            .Select(p => (p.Id, p.Name, p.JoinedAt is not null)).SequenceEqual(orderedProjects) &&
                        page.Items.All(p => (!knownProjects.Any(k => k.Id == p.Id) || p.Slug == p.Name && p.Type == "secret-manager") &&
                            (selection == GroupProjectSelection.OrganizationAll || (p.JoinedAt is not null) == (selection == GroupProjectSelection.Assigned)) &&
                            (c.Variant != "search.value" || p.Name.Contains(c.ProjectSlug, StringComparison.OrdinalIgnoreCase))) &&
                        Ordered(page.Items.Select(p => p.Name), order), Observe, token);
                break;
            case "ListGroups":
                GroupMetadata otherGroup = await SeedGroupAsync(c, token);
                await c.CaseAsync(() => ScopedAccessOperations.ListGroups(org),
                    page => Complete(page, g => g.Id) && page.Items.Count(g => g.Id == id && g.Name == name && g.Slug == slug) == 1 &&
                        page.Items.Count(g => g.Id == otherGroup.Id && g.Name == otherGroup.Name && g.Slug == otherGroup.Slug) == 1, Observe, token);
                break;
            case "AvailableGroups":
                GroupMetadata availableGroup = await SeedGroupAsync(c, token);
                await c.CaseAsync(() => ScopedAccessOperations.AvailableGroups(org),
                    page => Complete(page, g => g.Id) && page.Items.Count(g => g.Id == id && g.Name == name && g.Slug == slug) == 1 &&
                        page.Items.Count(g => g.Id == availableGroup.Id && g.Name == availableGroup.Name && g.Slug == availableGroup.Slug) == 1, Observe, token);
                break;
            case "AvailableIdentities":
                await AvailableIdentityAsync(c, Observe, token);
                break;
            case "AddGroupIdentity":
            case "RemoveGroupIdentity":
                await c.CaseAsync(() => add ? ScopedAccessOperations.AddGroupIdentity(org, id, runtime) :
                    ScopedAccessOperations.RemoveGroupIdentity(org, id, runtime),
                    value => !string.IsNullOrWhiteSpace(value.Id), Observe, token);
                break;
            case "AddGroupUser":
            case "RemoveGroupUser":
                await c.CaseAsync(() => add ? ScopedAccessOperations.AddGroupUser(org, id, username!) :
                    ScopedAccessOperations.RemoveGroupUser(org, id, username!),
                    value => value.Id == runtime && value.Username == username, Observe, token);
                break;
            default:
                Func<ManagementRequest<GroupMetadata>> request = c.Operation switch
                {
                    "CreateGroup" => () => ScopedAccessOperations.CreateGroup(org, name,
                        c.Variant == "slug.omitted" ? null : slug, readRole ?? "no-access"),
                    "UpdateGroup" => () => ScopedAccessOperations.UpdateGroup(org, id, changedName, changedSlug, readRole),
                    "GetGroup" => () => ScopedAccessOperations.GetGroup(org, id),
                    "DeleteGroup" => () => ScopedAccessOperations.DeleteGroup(org, id),
                    _ => throw new NativeCaseFailureException("contract-mismatch")
                };
                // Create responses need not include GetGroup's customRoleSlug field.
                await c.CaseAsync(request, g =>
                {
                    // Retain the acknowledged identity even when another returned field is wrong.
                    if (create) acknowledgedId = g.Id;
                    return (id.Length == 0 || g.Id == id) && g.Name == (changedName ?? name);
                }, Observe, token);
                break;
        }
    }

    private static bool Complete<T>(ManagementPage<T> page, Func<T, string> key) where T : notnull =>
        page.IsComplete && page.Items.Select(key).Distinct(StringComparer.Ordinal).Count() == page.Items.Count;

    private static bool Ordered(IEnumerable<string> names, ManagementListOrder order)
    {
        string[] actual = names.ToArray();
        return actual.SequenceEqual(order == ManagementListOrder.Ascending ?
            actual.Order(StringComparer.Ordinal) : actual.OrderDescending(StringComparer.Ordinal));
    }

    private static async ValueTask EligibleUserAsync(ProjectFamilyContext c, string id, string username, CancellationToken token)
    {
        // Inputs select an existing user, never authority or a fabricated provisioning path.
        // Only the native organization membership read supplies eligibility evidence.
        var result = await c.ExecuteAsync(() => OrganizationMembershipOperations.ListOrganizationMemberships(c.OrganizationId),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(result.IsSuccess && Complete(result.Value, m => m.Id) &&
            result.Value.Items.Count(m => m.User?.Id == id) == 1 &&
            result.Value.Items.Count(m => m.User?.Id == id && m.User.Username == username &&
                m.Status == "accepted" && m.IsActive == true) == 1, NativeFailure.ObserverUnavailable);
    }

    private static async ValueTask<IdentitySummary> SeedIdentityAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName();
        string? acknowledgedId = null;
        c.Cleanup(async ct =>
        {
            SecretOutcome<ManagementPage<IdentitySummary>> list = await c.ExecuteAsync(
                () => IdentityOperations.ListOrganizationIdentities(c.OrganizationId), NativeIdentityRole.Observer, ct);
            if (!list.IsSuccess || !Complete(list.Value, i => i.Id)) return false;
            IdentitySummary[] found = list.Value.Items.Where(i => i.Name == name).ToArray();
            if (found.Length == 0) return true;
            if (found.Length != 1) return false;
            string id = found[0].Id;
            if (acknowledgedId is not null && id != acknowledgedId) return false;
            SecretOutcome<IdentitySummary> exact = await c.ExecuteAsync(
                () => IdentityOperations.GetOrganizationIdentity(c.OrganizationId, id), NativeIdentityRole.Observer, ct);
            if (!exact.IsSuccess || exact.Value.Name != name) return false;
            SecretOutcome<IdentitySummary> removed = await c.ExecuteAsync(
                () => IdentityOperations.DeleteOrganizationIdentity(c.OrganizationId, id), NativeIdentityRole.Setup, ct);
            SecretOutcome<IdentitySummary> absent = await c.ExecuteAsync(
                () => IdentityOperations.GetOrganizationIdentity(c.OrganizationId, id), NativeIdentityRole.Observer, ct);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        IdentitySummary identity = await c.NeedAsync(() => IdentityOperations.CreateOrganizationIdentity(
            c.OrganizationId, name, "no-access"), NativeIdentityRole.Setup, token);
        acknowledgedId = identity.Id;
        IdentitySummary read = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(c.OrganizationId, identity.Id),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(read.Name == name, NativeFailure.ObserverUnavailable);
        return read;
    }

    private static async ValueTask AvailableIdentityAsync(ProjectFamilyContext c,
        Func<bool, CancellationToken, ValueTask<bool>> observe, CancellationToken token)
    {
        IdentitySummary identity = await SeedIdentityAsync(c, token);
        IdentitySummary other = await SeedIdentityAsync(c, token);
        string name = identity.Name;
        await c.CaseAsync(() => ScopedAccessOperations.AvailableIdentities(c.OrganizationId,
            identityName: c.Variant == "identityName.value" ? name : null),
            page => Complete(page, i => i.Id) && page.Items.Count(i => i.Id == identity.Id && i.Name == name) == 1 &&
                page.Items.Count(i => i.Id == other.Id) == (c.Variant == "identityName.value" ? 0 : 1) &&
                page.Items.All(i => i.Id != other.Id || i.Name == other.Name) &&
                (c.Variant != "identityName.value" || page.Items.All(i => i.Name.Contains(name, StringComparison.Ordinal))),
            async (applied, ct) =>
            {
                SecretOutcome<IdentitySummary> exact = await c.ExecuteAsync(() =>
                    IdentityOperations.GetOrganizationIdentity(c.OrganizationId, identity.Id), NativeIdentityRole.Observer, ct);
                return exact.IsSuccess && exact.Value.Name == name && await observe(applied, ct);
            }, token);
    }
}
