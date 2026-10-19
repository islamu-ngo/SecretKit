using System.Globalization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentitiesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        bool project = c.Operation.Contains("Project", StringComparison.Ordinal);
        if (project) await c.EnsureProjectAsync(token);
        if (c.Operation == "GetSelectedIdentityOrganization")
        {
            IdentityOrganization expected = await c.NeedAsync(
                () => IdentityOperations.GetSelectedIdentityOrganization(c.OrganizationId), NativeIdentityRole.Observer, token);
            await c.CaseAsync(() => IdentityOperations.GetSelectedIdentityOrganization(c.OrganizationId),
                value => value.Id == expected.Id && value.Name == expected.Name && value.Slug == expected.Slug,
                async (_, t) =>
                {
                    var observed = await c.NeedAsync(() => IdentityOperations.GetSelectedIdentityOrganization(c.OrganizationId),
                        NativeIdentityRole.Observer, t);
                    return observed.Id == expected.Id && observed.Name == expected.Name && observed.Slug == expected.Slug;
                }, token);
            return;
        }

        string name = ProjectFamilyContext.FreshName();
        string changed = ProjectFamilyContext.FreshName();
        string role = c.Required("identityRole");
        bool create = c.Operation.StartsWith("Create", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool delete = c.Operation.StartsWith("Delete", StringComparison.Ordinal);
        IdentityAttribute[] baseline = [new("owned", name)];
        IdentityAttribute[]? metadata = c.Variant switch
        {
            "name.omitted" when update => [new("owned", changed)],
            "metadata.empty" => [],
            "metadata.value" => [new("owned", changed)],
            "metadata.values" => [new("owned", changed), new("second", name)],
            _ => null
        };
        bool? protection = c.Variant switch
        {
            "deleteProtection.true" => true,
            "deleteProtection.false" => false,
            _ => null
        };
        MembershipRole[]? roles = !project ? null : c.Variant switch
        {
            "roles.omitted" => null,
            "roles.empty" => [],
            "roles.relative-time" => [new(c.Required("projectIdentityRole"),
                DateTimeOffset.Parse(c.Required("roleStartsAt"), CultureInfo.InvariantCulture),
                c.Required("roleDuration"))],
            _ => [new(c.Required("projectIdentityRole"))]
        };
        string? acknowledgedId = null;
        Own(c, project, name, () => acknowledgedId);
        if (update) Own(c, project, changed, () => acknowledgedId);
        string id = "";
        bool baselineProtection = update && protection != true;
        if (!create)
        {
            IdentitySummary prepared = await c.NeedAsync(() => project
                ? IdentityOperations.CreateProjectIdentity(c.OrganizationId, c.ProjectId, name,
                    deleteProtection: baselineProtection, metadata: baseline)
                : IdentityOperations.CreateOrganizationIdentity(c.OrganizationId, name, role,
                    deleteProtection: baselineProtection, metadata: baseline),
                NativeIdentityRole.Setup, token);
            id = prepared.Id;
            acknowledgedId = prepared.Id;
        }
        string? newName = update && c.Variant != "name.omitted" ? changed : null;
        string? newRole = update && !project && c.Variant == "role.value" ? c.Required("updatedIdentityRole") : null;
        Func<ManagementRequest<IdentitySummary>> read = () => project
            ? IdentityOperations.GetProjectIdentity(c.OrganizationId, c.ProjectId, id)
            : IdentityOperations.GetOrganizationIdentity(c.OrganizationId, id);
        if (update)
        {
            var observedBaseline = await c.NeedAsync(read, NativeIdentityRole.Observer, token);
            c.Probe.Contract(Matches(observedBaseline, id, name, project ? c.ProjectId : null,
                baselineProtection, baseline), NativeFailure.MissingPrerequisite);
        }

        async ValueTask<bool> Observe(bool applied, CancellationToken t)
        {
            if (create)
            {
                var page = await c.NeedAsync(() => project
                    ? IdentityOperations.ListProjectIdentities(c.OrganizationId, c.ProjectId, limit: 100, search: name)
                    : IdentityOperations.ListOrganizationIdentities(c.OrganizationId), NativeIdentityRole.Observer, t);
                if (!page.IsComplete) throw new NativeCaseFailureException("observer-unavailable");
                IdentitySummary[] found = page.Items.Where(x => x.Name == name).ToArray();
                if (!applied) return found.Length == 0;
                if (found.Length != 1) return false;
                if (acknowledgedId is not null && found[0].Id != acknowledgedId) return false;
                id = found[0].Id;
            }
            SecretOutcome<IdentitySummary> result = await c.ExecuteAsync(read, NativeIdentityRole.Observer, t);
            if (delete && applied) return result.Status == SecretStatus.Absent;
            if (!result.IsSuccess) return false;
            IdentitySummary observed = result.Value;
            IdentityAttribute[] expectedMetadata = applied && (create || update) ? metadata ?? (create ? [] : baseline) : baseline;
            string expectedName = applied && update ? newName ?? name : name;
            bool expectedProtection = applied && (create || update)
                ? protection ?? baselineProtection : baselineProtection;
            if (!Matches(observed, id, expectedName, project ? c.ProjectId : null, expectedProtection, expectedMetadata))
                return false;
            if (!project)
            {
                return observed.Membership.IsPresent && observed.Membership.Value.IdentityId == id &&
                    observed.Membership.Value.Role.Value == (applied && update ? newRole ?? role : role);
            }
            if (!create || !applied || roles is null) return true;
            var membership = await c.NeedAsync(() => MembershipOperations.GetProjectIdentityMembership(
                c.OrganizationId, c.ProjectId, id), NativeIdentityRole.Observer, t);
            return membership.IdentityId == id && membership.Roles.Count == roles.Length &&
                roles.All(r => membership.Roles.Any(actual => actual.Role == r.Role &&
                    actual.IsTemporary == r.IsTemporary && (r.StartsAt is null ||
                        actual.Range == r.RelativeDuration &&
                        DateTimeOffset.Parse(actual.StartsAt!, CultureInfo.InvariantCulture) == r.StartsAt)));
        }

        if (c.Operation.StartsWith("List", StringComparison.Ordinal))
        {
            bool search = project && c.Variant == "search.value";
            var fixtures = new List<(string Id, string Name)> { (id, name) };
            foreach (string fixtureName in search ? new[] { name + "b", changed } : [name + "b"])
            {
                string? fixtureId = null;
                Own(c, project, fixtureName, () => fixtureId);
                var prepared = await c.NeedAsync(() => project
                    ? IdentityOperations.CreateProjectIdentity(c.OrganizationId, c.ProjectId, fixtureName)
                    : IdentityOperations.CreateOrganizationIdentity(c.OrganizationId, fixtureName, role),
                    NativeIdentityRole.Setup, token);
                fixtureId = prepared.Id;
                fixtures.Add((prepared.Id, fixtureName));
            }
            bool MatchesInventory(ManagementPage<IdentitySummary> page) =>
                page.IsComplete && page.Items.Select(x => x.Id).Distinct().Count() == page.Items.Count &&
                fixtures.All(fixture => page.Items.Count(x => x.Id == fixture.Id && x.Name == fixture.Name) ==
                    (search && !fixture.Name.Contains(name, StringComparison.Ordinal) ? 0 : 1)) &&
                (!search || page.Items.All(x => x.Name.Contains(name, StringComparison.Ordinal)));
            Func<ManagementRequest<ManagementPage<IdentitySummary>>> list = () => project
                ? IdentityOperations.ListProjectIdentities(c.OrganizationId, c.ProjectId,
                    search: search ? name : null)
                : IdentityOperations.ListOrganizationIdentities(c.OrganizationId);
            var independentlyExpected = await c.NeedAsync(list, NativeIdentityRole.Observer, token);
            c.Probe.Contract(MatchesInventory(independentlyExpected), NativeFailure.EffectMismatch);
            await c.CaseAsync(list, page => MatchesInventory(page) && page.Items.OrderBy(x => x.Id)
                .Select(x => (x.Id, x.Name, x.ProjectId)).SequenceEqual(independentlyExpected.Items.OrderBy(x => x.Id)
                    .Select(x => (x.Id, x.Name, x.ProjectId))),
                (_, t) => Observe(false, t), token);
        }
        else
        {
            Func<ManagementRequest<IdentitySummary>> request = create
                ? () => project ? IdentityOperations.CreateProjectIdentity(c.OrganizationId, c.ProjectId, name,
                    roles, protection ?? false, metadata) : IdentityOperations.CreateOrganizationIdentity(
                        c.OrganizationId, name, role, protection ?? false, metadata)
                : update ? () => project ? IdentityOperations.UpdateProjectIdentity(c.OrganizationId, c.ProjectId,
                    id, newName, protection, metadata) : IdentityOperations.UpdateOrganizationIdentity(c.OrganizationId,
                        id, newName, newRole, protection, metadata)
                : delete ? () => project ? IdentityOperations.DeleteProjectIdentity(c.OrganizationId, c.ProjectId, id)
                    : IdentityOperations.DeleteOrganizationIdentity(c.OrganizationId, id)
                : read;
            await c.CaseAsync(request, value =>
            {
                if (create) acknowledgedId = value.Id;
                return value.Name == (update ? newName ?? name : name) && (create || value.Id == id);
            }, Observe, token);
        }
    }

    internal static bool Matches(IdentitySummary value, string id, string name, string? project,
        bool protection, IReadOnlyList<IdentityAttribute> metadata) =>
        value.Id == id && value.Name == name && value.ProjectId == project &&
        value.HasDeleteProtection.IsPresent && value.HasDeleteProtection.Value == protection &&
        value.Metadata.IsPresent && value.Metadata.Value.Count == metadata.Count &&
        metadata.All(m => value.Metadata.Value.Any(actual => actual.Key == m.Key && actual.Value == m.Value));

    internal static async ValueTask<IdentitySummary> PrepareOrganizationAsync(ProjectFamilyContext c,
        string name, CancellationToken token)
    {
        string? acknowledgedId = null;
        Own(c, false, name, () => acknowledgedId);
        var prepared = await c.NeedAsync(() => IdentityOperations.CreateOrganizationIdentity(c.OrganizationId,
            name, c.Required("identityRole")), NativeIdentityRole.Setup, token);
        acknowledgedId = prepared.Id;
        return prepared;
    }

    private static void Own(ProjectFamilyContext c, bool project, string name, Func<string?> acknowledgedId) => c.Cleanup(async token =>
    {
        var page = await c.ExecuteAsync(() => project
            ? IdentityOperations.ListProjectIdentities(c.OrganizationId, c.ProjectId, search: name)
            : IdentityOperations.ListOrganizationIdentities(c.OrganizationId), NativeIdentityRole.Observer, token);
        if (!page.IsSuccess || !page.Value.IsComplete) return false;
        IdentitySummary[] owned = page.Value.Items.Where(x => x.Name == name).ToArray();
        if (owned.Length > 1) return false;
        foreach (var identity in owned)
        {
            if (acknowledgedId() is { } expected && identity.Id != expected) return false;
            // Always clear protection with a separate receipt before removing our exact owned identity.
            var cleared = await c.ExecuteAsync(() => project
                ? IdentityOperations.UpdateProjectIdentity(c.OrganizationId, c.ProjectId, identity.Id, deleteProtection: false)
                : IdentityOperations.UpdateOrganizationIdentity(c.OrganizationId, identity.Id, deleteProtection: false),
                NativeIdentityRole.Setup, token);
            if (!cleared.IsSuccess) return false;
            var deleted = await c.ExecuteAsync(() => project
                ? IdentityOperations.DeleteProjectIdentity(c.OrganizationId, c.ProjectId, identity.Id)
                : IdentityOperations.DeleteOrganizationIdentity(c.OrganizationId, identity.Id), NativeIdentityRole.Setup, token);
            var observed = await c.ExecuteAsync(() => project
                ? IdentityOperations.GetProjectIdentity(c.OrganizationId, c.ProjectId, identity.Id)
                : IdentityOperations.GetOrganizationIdentity(c.OrganizationId, identity.Id), NativeIdentityRole.Observer, token);
            if (!deleted.IsSuccess || observed.Status != SecretStatus.Absent) return false;
        }
        var absent = await c.ExecuteAsync(() => project
            ? IdentityOperations.ListProjectIdentities(c.OrganizationId, c.ProjectId, search: name)
            : IdentityOperations.ListOrganizationIdentities(c.OrganizationId), NativeIdentityRole.Observer, token);
        return absent.IsSuccess && absent.Value.IsComplete && absent.Value.Items.All(x => x.Name != name);
    });
}
