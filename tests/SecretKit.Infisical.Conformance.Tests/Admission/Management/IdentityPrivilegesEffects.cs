using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityPrivilegesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        var scenario = await PermissionPrivilegeScenario.CreateAsync(c, false, true, false, token);
        if (c.Operation == "ListProjectPrivileges")
        {
            string slug = ProjectFamilyContext.FreshName();
            string? acknowledgedId = null;
            c.Cleanup(async ct =>
            {
                var found = await c.ExecuteAsync(() => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(
                    scenario.Selection, slug), NativeIdentityRole.Observer, ct);
                if (found.Status == SecretStatus.Absent) return true;
                if (!found.IsSuccess || acknowledgedId is not null && found.Value.Id != acknowledgedId) return false;
                var deleted = await c.ExecuteAsync(() => IdentityPrivilegeOperations.DeleteProjectPrivilege(
                    c.OrganizationId, c.ProjectId, scenario.Selection.IdentityId, found.Value.Id), NativeIdentityRole.Setup, ct);
                var absent = await c.ExecuteAsync(() => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(
                    scenario.Selection, slug), NativeIdentityRole.Observer, ct);
                return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
            });
            var peer = await c.NeedAsync(() => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(
                scenario.Selection, new([], PrivilegeLifetime.Permanent(), slug)), NativeIdentityRole.Setup, token);
            acknowledgedId = peer.Id;
            var persisted = await c.NeedAsync(() => IdentityPrivilegeOperations.GetProjectPrivilege(
                c.OrganizationId, c.ProjectId, scenario.Selection.IdentityId, peer.Id), NativeIdentityRole.Observer, token);
            c.Probe.Contract(persisted.Id == peer.Id && persisted.Slug == slug &&
                persisted.Permissions is { Count: 0 }, NativeFailure.MissingPrerequisite);
            await c.CaseAsync(() => IdentityPrivilegeOperations.ListProjectPrivileges(
                c.OrganizationId, c.ProjectId, scenario.Selection.IdentityId),
                page => page.IsComplete && page.Items.Select(p => p.Id).Distinct().Count() == page.Items.Count &&
                    page.Items.Count(p => p.Id == scenario.Id && p.Slug == scenario.Slug && !p.IncludesPermissions) == 1 &&
                    page.Items.Count(p => p.Id == peer.Id && p.Slug == slug && !p.IncludesPermissions) == 1,
                (_, ct) => scenario.ObserveAsync(true, true, ct), token);
        }
        else if (c.Operation == "GetProjectPrivilege")
            await c.CaseAsync(() => IdentityPrivilegeOperations.GetProjectPrivilege(
                c.OrganizationId, c.ProjectId, scenario.Selection.IdentityId, scenario.Id),
                scenario.Match, (_, ct) => scenario.ObserveAsync(true, true, ct), token);
        else if (c.Operation == "DeleteProjectPrivilege")
            await c.CaseAsync(() => IdentityPrivilegeOperations.DeleteProjectPrivilege(
                c.OrganizationId, c.ProjectId, scenario.Selection.IdentityId, scenario.Id),
                scenario.Match, (applied, ct) => scenario.ObserveAsync(!applied, true, ct), token);
        else throw new NativeCaseFailureException("contract-mismatch");
    }
}
