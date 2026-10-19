using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ProjectMembershipsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition definition) =>
        null;

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        await c.EnsureProjectAsync(token);
        if (c.Operation is "ListAvailableProjectIdentities" or "ListProjectIdentityMemberships")
        {
            await IdentitiesAsync(c, token);
            return;
        }
        string username = c.Required("runtimeUsername"), userId = c.Required("runtimeUserId");
        var principals = new MembershipPrincipals(usernames: [username]);
        bool update = c.Operation == "UpdateProjectMembershipRoles";
        string initialRole = update ? "no-access" : "viewer";
        await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId, c.ProjectId,
            principals, [initialRole]), NativeIdentityRole.Setup, token);
        ProjectMembershipSummary before = await c.NeedAsync(() =>
            ProjectMembershipOperations.InspectProjectMembershipByUsername(c.OrganizationId, c.ProjectId, username),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(before.UserId == userId && before.User.Username == username &&
            before.Roles.Any(r => r.Role == initialRole), NativeFailure.MissingPrerequisite);
        var canary = await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token);
        c.Probe.Contract(await canary.ReadAsync(NativeIdentityRole.Runtime, !update, token) &&
            await canary.ReadAsync(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);
        bool Match(ProjectMembershipSummary m) => m.Id == before.Id && m.UserId == userId && m.User.Username == username;
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            SecretOutcome<ProjectMembershipSummary> observed = await c.ExecuteAsync(
                () => ProjectMembershipOperations.InspectProjectMembershipByUsername(c.OrganizationId, c.ProjectId, username),
                NativeIdentityRole.Observer, ct);
            string expectedRole = applied && update ? "viewer" : initialRole;
            bool matched = observed.IsSuccess && Match(observed.Value) &&
                observed.Value.Roles.Any(r => r.Role == expectedRole && r.IsTemporary != true) &&
                await canary.ReadAsync(NativeIdentityRole.Runtime, applied || !update, ct) &&
                await canary.ReadAsync(NativeIdentityRole.Denied, false, ct);
            if (matched) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "membership-principal-observer", NativeObservation.Matched);
            return matched;
        }
        switch (c.Operation)
        {
            case "ListProjectMemberships":
                await c.CaseAsync(() => ProjectMembershipOperations.ListProjectMemberships(c.OrganizationId, c.ProjectId),
                    page => page.IsComplete &&
                        page.Items.Select(m => m.Id).Distinct().Count() == page.Items.Count &&
                        page.Items.Count(Match) == 1, Observe, token);
                break;
            case "InspectProjectMembershipByUsername":
                await c.CaseAsync(() => ProjectMembershipOperations.InspectProjectMembershipByUsername(
                    c.OrganizationId, c.ProjectId, username), Match, Observe, token);
                break;
            case "UpdateProjectMembershipRoles":
                MembershipRole[] roles = [new("viewer", omitPermanentDiscriminator: c.Variant == "roles.permanent-discriminator-omitted")];
                await c.CaseAsync(() => ProjectMembershipOperations.UpdateProjectMembershipRoles(c.OrganizationId,
                    c.ProjectId, before.Id, roles),
                    page => page.IsComplete && page.Items.Any(r => r.Role == "viewer" && r.IsTemporary != true),
                    Observe, token);
                break;
            default: throw new NativeCaseFailureException("contract-mismatch");
        }
    }

    private static async ValueTask IdentitiesAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string name = ProjectFamilyContext.FreshName();
        string? id = null;
        c.Cleanup(async ct =>
        {
            SecretOutcome<ManagementPage<IdentitySummary>> inventory = await c.ExecuteAsync(
                () => IdentityOperations.ListOrganizationIdentities(c.OrganizationId), NativeIdentityRole.Observer, ct);
            if (!inventory.IsSuccess || !inventory.Value.IsComplete) return false;
            IdentitySummary[] found = inventory.Value.Items.Where(i => i.Name == name).ToArray();
            if (found.Length == 0) return true;
            if (found.Length != 1 || id is not null && found[0].Id != id) return false;
            string selected = found[0].Id;
            SecretOutcome<IdentitySummary> deleted = await c.ExecuteAsync(
                () => IdentityOperations.DeleteOrganizationIdentity(c.OrganizationId, selected), NativeIdentityRole.Setup, ct);
            SecretOutcome<IdentitySummary> absent = await c.ExecuteAsync(
                () => IdentityOperations.GetOrganizationIdentity(c.OrganizationId, selected), NativeIdentityRole.Observer, ct);
            return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        IdentitySummary identity = await c.NeedAsync(() => IdentityOperations.CreateOrganizationIdentity(
            c.OrganizationId, name, "no-access"), NativeIdentityRole.Setup, token);
        id = identity.Id;
        string? filter = c.Variant == "identityName.value" ? name : null;
        if (c.Operation == "ListAvailableProjectIdentities")
        {
            Func<ManagementRequest<ManagementPage<AccessCandidate>>> request = () =>
                ProjectMembershipOperations.ListAvailableProjectIdentities(c.OrganizationId, c.ProjectId,
                    limit: 100, identityName: filter);
            bool Match(ManagementPage<AccessCandidate> p) => p.IsComplete && p.Items.Any(i => i.Id == id && i.Name == name) &&
                (filter is null || p.Items.All(i => i.Name.Contains(filter, StringComparison.Ordinal)));
            await c.CaseAsync(request, Match, async (_, ct) =>
            {
                SecretOutcome<ManagementPage<AccessCandidate>> page = await c.ExecuteAsync(request, NativeIdentityRole.Observer, ct);
                SecretOutcome<ProjectIdentityMembershipSummary> absent = await c.ExecuteAsync(
                    () => MembershipOperations.GetProjectIdentityMembership(c.OrganizationId, c.ProjectId, id),
                    NativeIdentityRole.Observer, ct);
                return page.IsSuccess && Match(page.Value) && absent.Status == SecretStatus.Absent;
            }, token);
        }
        else
        {
            MembershipSummary membership = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(
                c.OrganizationId, c.ProjectId, id, new MembershipRoleSelection(roles: [new("viewer")])),
                NativeIdentityRole.Setup, token);
            Func<ManagementRequest<ManagementPage<ProjectIdentityMembershipSummary>>> request = () =>
                ProjectMembershipOperations.ListProjectIdentityMemberships(c.OrganizationId, c.ProjectId,
                    limit: 100, identityName: filter);
            bool Match(ManagementPage<ProjectIdentityMembershipSummary> p) => p.IsComplete &&
                p.Items.Any(i => i.IdentityId == id && i.Id == membership.Id && i.Identity.Name == name &&
                    i.Roles.Any(r => r.Role == "viewer"));
            await c.CaseAsync(request, Match, async (_, ct) =>
            {
                SecretOutcome<ProjectIdentityMembershipSummary> observed = await c.ExecuteAsync(
                    () => MembershipOperations.GetProjectIdentityMembership(c.OrganizationId, c.ProjectId, id),
                    NativeIdentityRole.Observer, ct);
                return observed.IsSuccess && observed.Value.Id == membership.Id && observed.Value.IdentityId == id &&
                    observed.Value.Identity.Name == name && observed.Value.Roles.Any(r => r.Role == "viewer");
            }, token);
        }
    }
}
