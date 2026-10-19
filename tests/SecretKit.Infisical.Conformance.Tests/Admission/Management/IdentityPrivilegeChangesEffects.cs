using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityPrivilegeChangesEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        bool legacy = c.Operation.Contains("Legacy", StringComparison.Ordinal);
        bool create = c.Operation.StartsWith("Create", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        var scenario = await PermissionPrivilegeScenario.CreateAsync(c, legacy, !create, update, token);
        Func<ManagementRequest<IdentityPrivilegeSummary>> request = c.Operation switch
        {
            "CreatePermanentLegacyPrivilege" => () => IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(
                scenario.Selection, scenario.LegacyChange),
            "CreateProjectPrivilege" => () => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(
                scenario.Selection, scenario.ProjectChange),
            "UpdateLegacyPrivilege" => () => IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(
                scenario.Selection, scenario.Slug, scenario.LegacyChange),
            "UpdateProjectPrivilege" => () => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(
                scenario.Selection, scenario.Id, scenario.ProjectChange),
            "GetProjectPrivilegeBySlug" => () => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(
                scenario.Selection, scenario.Slug),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        await c.CaseAsync(request, scenario.Match, (applied, ct) =>
            scenario.ObserveAsync(create ? applied : true, update ? applied : !create || applied, ct), token);
    }
}

internal sealed class PermissionPrivilegeScenario
{
    private readonly ProjectFamilyContext context;
    private readonly PermissionWitness witness;
    private readonly bool legacy;
    private bool baselineGranted;
    internal LegacyPrivilegeSelection Selection { get; }
    internal string Slug { get; }
    internal string Id { get; private set; } = "";
    internal ProjectPrivilegeChange ProjectChange { get; }
    internal LegacyPrivilegeChange LegacyChange { get; }

    private PermissionPrivilegeScenario(ProjectFamilyContext c, PermissionWitness witness,
        LegacyPrivilegeSelection selection, bool legacy, string slug)
    {
        context = c;
        this.witness = witness;
        Selection = selection;
        this.legacy = legacy;
        Slug = slug;
        ProjectChange = new(PermissionWitness.Policy(c.Variant), PrivilegeLifetime.Permanent(), slug);
        LegacyChange = c.Variant == "permissions.array" ?
            new(slug, privilegePermission: new([LegacyPrivilegeAction.Read], new("witness", "/"))) :
            new(slug, permissions: c.Variant == "permissions.empty" ? [] :
                [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("witness", "/"))]);
    }

    internal static async ValueTask<PermissionPrivilegeScenario> CreateAsync(ProjectFamilyContext c,
        bool legacy, bool seed, bool emptySeed, CancellationToken token)
    {
        await c.EnsureProjectAsync(token);
        string principal = c.Required("runtimeIdentityId");
        MembershipSummary membership = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(
            c.OrganizationId, c.ProjectId, principal, new MembershipRoleSelection(roles: [new("no-access")])),
            NativeIdentityRole.Setup, token);
        ProjectIdentityMembershipSummary selected = await c.NeedAsync(() =>
            MembershipOperations.GetProjectIdentityMembership(c.OrganizationId, c.ProjectId, principal),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(selected.Id == membership.Id && selected.IdentityId == principal &&
            selected.Roles.All(r => r.Role == "no-access"), NativeFailure.MissingPrerequisite);
        var witness = await PermissionWitness.CreateAsync(c, token);
        c.Probe.Contract(await witness.ObserveAsync(false, token), NativeFailure.MissingPrerequisite);
        var scenario = new PermissionPrivilegeScenario(c, witness,
            new(c.OrganizationId, c.ProjectId, c.ProjectSlug, principal, membership.Id),
            legacy, ProjectFamilyContext.FreshName());
        scenario.baselineGranted = seed && emptySeed && c.Variant == "permissions.empty";
        // Ownership is registered before setup or the tested creation dispatch.
        c.Cleanup(scenario.CleanupAsync);
        if (seed)
        {
            IdentityPrivilegeSummary before = await c.NeedAsync(() => legacy ?
                IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(scenario.Selection,
                    scenario.baselineGranted ? new(scenario.Slug, permissions:
                        [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("witness", "/"))]) :
                    emptySeed ? new(scenario.Slug, permissions: []) : scenario.LegacyChange) :
                IdentityPrivilegeChangeOperations.CreateProjectPrivilege(scenario.Selection,
                    scenario.baselineGranted ? new(PermissionWitness.Policy("condition.literal"),
                        PrivilegeLifetime.Permanent(), scenario.Slug) :
                    emptySeed ? new([], PrivilegeLifetime.Permanent(), scenario.Slug) : scenario.ProjectChange),
                NativeIdentityRole.Setup, token);
            scenario.Id = before.Id;
            c.Probe.Contract(await scenario.ObserveAsync(true, !emptySeed, token), NativeFailure.MissingPrerequisite);
        }
        return scenario;
    }

    internal bool Match(IdentityPrivilegeSummary value) => value.Slug == Slug &&
        (Id.Length == 0 || value.Id == Id) && value.IsTemporary != true &&
        PermissionMetadata(value.Permissions, context.Variant);

    internal static bool PermissionMetadata(IReadOnlyList<RolePermissionSummary>? permissions, string variant)
    {
        if (permissions is null) return false;
        if (variant == "permissions.empty") return permissions.Count == 0;
        string action = variant switch
        {
            "permission.Secrets.describeSecret" => "describeSecret",
            "permission.Secrets.readValue" => "readValue",
            _ => "read"
        };
        int expected = variant == "inverted.true" ? 2 : 1;
        return permissions.Count == expected && permissions.All(p => !p.IncludesConditionValues &&
            p.Subject is { IsScalar: true } && p.Subject.Values.SequenceEqual(["secrets"]) &&
            p.Action.Values.SequenceEqual([action])) &&
            (expected != 1 || permissions[0].Action.IsScalar ==
                (variant is not ("permissions.array" or "permissions.action.array"))) &&
            (expected != 2 || permissions.Any(p => p.Inverted == true));
    }

    internal async ValueTask<bool> ObserveAsync(bool present, bool changed, CancellationToken token)
    {
        SecretOutcome<ManagementPage<IdentityPrivilegeSummary>> inventory = await context.ExecuteAsync(() => legacy ?
            LegacyIdentityPrivilegeOperations.ListPrivileges(Selection) :
            IdentityPrivilegeOperations.ListProjectPrivileges(Selection.OrganizationId, Selection.ProjectId, Selection.IdentityId),
            NativeIdentityRole.Observer, token);
        if (!inventory.IsSuccess || !inventory.Value.IsComplete ||
            inventory.Value.Items.Select(p => p.Id).Distinct().Count() != inventory.Value.Items.Count) return false;
        IdentityPrivilegeSummary[] found = inventory.Value.Items.Where(p => p.Slug == Slug).ToArray();
        if (!present)
            return found.Length == 0 && await witness.ObserveAsync(false, token);
        if (found.Length != 1 || Id.Length != 0 && found[0].Id != Id) return false;
        Id = found[0].Id;
        SecretOutcome<IdentityPrivilegeSummary> observed = await context.ExecuteAsync(() => legacy ?
            LegacyIdentityPrivilegeOperations.GetPrivilege(Selection, Slug) :
            IdentityPrivilegeOperations.GetProjectPrivilege(Selection.OrganizationId, Selection.ProjectId,
                Selection.IdentityId, Id), NativeIdentityRole.Observer, token);
        bool metadata = changed ? observed.IsSuccess && Match(observed.Value) :
            observed.IsSuccess && observed.Value.Id == Id && observed.Value.Slug == Slug &&
                PermissionMetadata(observed.Value.Permissions, baselineGranted ? "permission.scalar-crud" : "permissions.empty");
        return metadata && await witness.ObserveAsync(changed ? context.Variant != "permissions.empty" : baselineGranted, token);
    }

    private async ValueTask<bool> CleanupAsync(CancellationToken token)
    {
        SecretOutcome<ManagementPage<IdentityPrivilegeSummary>> inventory = await context.ExecuteAsync(() => legacy ?
            LegacyIdentityPrivilegeOperations.ListPrivileges(Selection) :
            IdentityPrivilegeOperations.ListProjectPrivileges(Selection.OrganizationId, Selection.ProjectId, Selection.IdentityId),
            NativeIdentityRole.Observer, token);
        if (!inventory.IsSuccess || !inventory.Value.IsComplete) return false;
        IdentityPrivilegeSummary[] owned = inventory.Value.Items.Where(p => p.Slug == Slug).ToArray();
        if (owned.Length == 0) return true;
        if (owned.Length != 1 || Id.Length != 0 && Id != owned[0].Id) return false;
        string id = owned[0].Id;
        SecretOutcome<IdentityPrivilegeSummary> removed = await context.ExecuteAsync(() => legacy ?
            LegacyIdentityPrivilegeOperations.DeletePrivilege(Selection, Slug) :
            IdentityPrivilegeOperations.DeleteProjectPrivilege(Selection.OrganizationId, Selection.ProjectId,
                Selection.IdentityId, id), NativeIdentityRole.Setup, token);
        SecretOutcome<IdentityPrivilegeSummary> absent = await context.ExecuteAsync(() => legacy ?
            LegacyIdentityPrivilegeOperations.GetPrivilege(Selection, Slug) :
            IdentityPrivilegeOperations.GetProjectPrivilege(Selection.OrganizationId, Selection.ProjectId,
                Selection.IdentityId, id), NativeIdentityRole.Observer, token);
        return removed.IsSuccess && absent.Status == SecretStatus.Absent;
    }
}
