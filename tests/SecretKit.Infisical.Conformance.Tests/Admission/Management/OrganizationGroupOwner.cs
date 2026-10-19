using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Owner credentials select provider context independently of host grant scope.
// Nothing here infers a native principal from token text or a request Target.
internal sealed class OrganizationGroupOwner
{
    private readonly ProjectFamilyContext context;
    private readonly ManagementClient client;
    private readonly SelectedTokens setup;
    private readonly SelectedTokens observer;
    private readonly Dictionary<string, Ownership> groups = new(StringComparer.Ordinal);
    internal string OrganizationId { get; }

    private OrganizationGroupOwner(ProjectFamilyContext context, string organizationId, string setupToken, string observerToken)
    {
        this.context = context;
        OrganizationId = organizationId;
        client = context.Environment.CreateManagementClient();
        setup = new(SecretMaterial.FromText(setupToken));
        observer = new(SecretMaterial.FromText(observerToken));
    }

    internal static async ValueTask<OrganizationGroupOwner> CreateAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (!c.Input.TryGetProperty("groupOwner", out var profile) || profile.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        string Required(string name, bool uuid)
        {
            if (!profile.TryGetProperty(name, out var value) || value.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(value.GetString()) || value.GetString()!.Length > 1024 ||
                value.GetString()!.Any(char.IsControl) || uuid && !Guid.TryParseExact(value.GetString(), "D", out _))
                throw new NativeCaseFailureException("missing-input");
            return uuid ? Guid.Parse(value.GetString()!).ToString("D") : value.GetString()!;
        }
        string org = Required("organizationId", true), setupId = Required("setupIdentityId", true),
            observerId = Required("observerIdentityId", true), setupToken = Required("setupToken", false),
            observerToken = Required("observerToken", false);
        string? Normalize(string? id) => Guid.TryParse(id, out var parsed) ? parsed.ToString("D") : id;
        string?[] targetIds = [Normalize(c.Optional("setupIdentityId")), Normalize(c.Required("administrativeIdentityId")),
            Normalize(c.Required("observerIdentityId")), Normalize(c.Required("runtimeIdentityId")), Normalize(c.Optional("deniedIdentityId"))];
        c.Probe.Contract(org != Normalize(c.OrganizationId) && setupId != observerId &&
            !targetIds.Contains(setupId) && !targetIds.Contains(observerId) && setupToken != observerToken,
            NativeFailure.MissingInput);
        var owner = new OrganizationGroupOwner(c, org, setupToken, observerToken);
        try
        {
            foreach (NativeIdentityRole role in Enum.GetValues<NativeIdentityRole>())
            {
                var selected = await c.Environment.Tokens(role).GetTokenAsync(token);
                c.Probe.Contract(selected.IsSuccess, NativeFailure.MissingInput);
                using var credential = selected.Value;
                char[] target = credential.Material.ExportCharacters(), a = owner.setup.Material.ExportCharacters(),
                    b = owner.observer.Material.ExportCharacters();
                try
                {
                    c.Probe.Contract(!target.AsSpan().SequenceEqual(a) && !target.AsSpan().SequenceEqual(b),
                        NativeFailure.MissingInput);
                }
                finally { Array.Clear(target); Array.Clear(a); Array.Clear(b); }
            }
            // Registered first, so credentials outlive every scoped cleanup.
            c.Cleanup(_ =>
            {
                owner.setup.Material.Dispose();
                owner.observer.Material.Dispose();
                return ValueTask.FromResult(true);
            });
            return owner;
        }
        catch
        {
            owner.setup.Material.Dispose();
            owner.observer.Material.Dispose();
            throw;
        }
    }

    internal async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(Func<ManagementRequest<T>> factory,
        bool write, CancellationToken token) where T : notnull
    {
        using var intent = factory();
        using var request = factory();
        context.Probe.Contract(intent.Target.OrganizationId == OrganizationId && intent.Target.ProjectId is null,
            NativeFailure.ContractMismatch);
        var authority = new ManagementAuthority(client.Authority, write ? setup : observer, OrganizationId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(intent.OperationId, intent.Target),
            receipt, token);
    }

    internal async ValueTask<T> NeedAsync<T>(Func<ManagementRequest<T>> factory,
        bool write, CancellationToken token) where T : notnull
    {
        var result = await ExecuteAsync(factory, write, token);
        context.Probe.Contract(result.IsSuccess, NativeFailure.MissingPrerequisite);
        return result.Value;
    }

    internal async ValueTask<GroupMetadata> SeedAsync(CancellationToken token, string? selectedName = null,
        bool linkRuntime = true)
    {
        string name = selectedName ?? ProjectFamilyContext.FreshName();
        var ownership = new Ownership();
        context.Cleanup(async ct =>
        {
            var inventory = await ExecuteAsync(() => ScopedAccessOperations.ListGroups(OrganizationId), false, ct);
            if (!inventory.IsSuccess || !inventory.Value.IsComplete ||
                inventory.Value.Items.Select(g => g.Id).Distinct().Count() != inventory.Value.Items.Count) return false;
            var found = inventory.Value.Items.Where(g => g.Name == name && g.Slug == name).ToArray();
            if (found.Length == 0) return true;
            if (found.Length != 1 || ownership.GroupId is not null && found[0].Id != ownership.GroupId) return false;
            var deleted = await ExecuteAsync(() => ScopedAccessOperations.DeleteGroup(OrganizationId, found[0].Id), true, ct);
            var absent = await ExecuteAsync(() => ScopedAccessOperations.GetGroup(OrganizationId, found[0].Id), false, ct);
            return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        var group = await NeedAsync(() => ScopedAccessOperations.CreateGroup(OrganizationId, name, name, "no-access"),
            true, token);
        ownership.GroupId = group.Id;
        groups.Add(group.Id, ownership);
        var selected = await NeedAsync(() => ScopedAccessOperations.GetGroup(OrganizationId, group.Id), false, token);
        context.Probe.Contract(selected.Id == group.Id && selected.Name == name && selected.Slug == name,
            NativeFailure.MissingPrerequisite);
        var membership = await NeedAsync(() => MembershipOperations.GetOrganizationGroup(OrganizationId, group.Id), false, token);
        context.Probe.Contract(membership.PrincipalId == group.Id && NoAccess(membership), NativeFailure.MissingPrerequisite);
        ownership.MembershipId = membership.Id;
        ownership.RoleId = membership.Roles.Value[0].Id;
        if (linkRuntime)
        {
            string runtime = context.Required("runtimeIdentityId");
            context.Cleanup(async ct =>
            {
                var links = await ExecuteAsync(() => ScopedAccessOperations.ListGroupMembers(OrganizationId, group.Id), false, ct);
                if (!links.IsSuccess || !links.Value.IsComplete) return false;
                var owned = links.Value.Items.Where(m => m.PrincipalId == runtime && m.Kind == GroupMemberKind.MachineIdentity).ToArray();
                if (owned.Length == 0) return true;
                if (owned.Length != 1 || ownership.LinkId is not null && owned[0].Id != ownership.LinkId) return false;
                var removed = await ExecuteAsync(() => ScopedAccessOperations.RemoveGroupIdentity(OrganizationId, group.Id, runtime), true, ct);
                var absent = await ExecuteAsync(() => ScopedAccessOperations.ListGroupMembers(OrganizationId, group.Id), false, ct);
                return removed.IsSuccess && absent.IsSuccess && absent.Value.IsComplete &&
                    absent.Value.Items.All(m => m.PrincipalId != runtime);
            });
            var link = await NeedAsync(() => ScopedAccessOperations.AddGroupIdentity(OrganizationId, group.Id, runtime), true, token);
            ownership.LinkId = link.Id;
        }
        context.Probe.Contract(await ObserveAsync(group, token), NativeFailure.MissingPrerequisite);
        return group;
    }

    internal string MembershipId(GroupMetadata group) => groups[group.Id].MembershipId!;
    internal string RuntimeLinkId(GroupMetadata group) => groups[group.Id].LinkId!;

    internal void CleanupTarget(GroupMetadata group, Func<string?> expected)
    {
        context.Cleanup(async token =>
        {
            var found = await context.ExecuteAsync(() => MembershipOperations.GetOrganizationGroup(
                context.OrganizationId, group.Id), NativeIdentityRole.Observer, token);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess || !Parent(found.Value, group.Id, OrganizationId) ||
                found.Value.Id == MembershipId(group) || expected() is { } id && found.Value.Id != id) return false;
            var removed = await context.ExecuteAsync(() => MembershipOperations.RemoveOrganizationGroup(
                context.OrganizationId, group.Id), NativeIdentityRole.Setup, token);
            var absent = await context.ExecuteAsync(() => MembershipOperations.GetOrganizationGroup(
                context.OrganizationId, group.Id), NativeIdentityRole.Observer, token);
            return removed.IsSuccess && removed.Value.Id == found.Value.Id && absent.Status == SecretStatus.Absent;
        });
    }

    internal async ValueTask<bool> ObserveAsync(GroupMetadata group, CancellationToken token)
    {
        Ownership ownership = groups[group.Id];
        var selected = await ExecuteAsync(() => ScopedAccessOperations.GetGroup(OrganizationId, group.Id), false, token);
        var membership = await ExecuteAsync(() => MembershipOperations.GetOrganizationGroup(OrganizationId, group.Id), false, token);
        var links = await ExecuteAsync(() => ScopedAccessOperations.ListGroupMembers(OrganizationId, group.Id), false, token);
        return selected.IsSuccess && selected.Value.Id == group.Id && selected.Value.Name == group.Name &&
            selected.Value.Slug == group.Slug && membership.IsSuccess && membership.Value.Id == ownership.MembershipId &&
            membership.Value.PrincipalId == group.Id && NoAccess(membership.Value) &&
            membership.Value.Roles.Value[0].Id == ownership.RoleId &&
            links.IsSuccess && links.Value.IsComplete && (ownership.LinkId is null ? links.Value.Items.Count == 0 :
                links.Value.Items.Count == 1 && links.Value.Items[0].Id == ownership.LinkId &&
                    links.Value.Items[0].PrincipalId == context.Required("runtimeIdentityId") &&
                    links.Value.Items[0].Kind == GroupMemberKind.MachineIdentity);
    }

    internal static bool Parent(MembershipSummary membership, string groupId, string ownerOrg) =>
        membership.PrincipalId == groupId && membership.Group?.Id == groupId &&
        (!membership.Group.OrganizationId.IsPresent || !membership.Group.OrganizationId.IsNull &&
            membership.Group.OrganizationId.Value == ownerOrg);

    private static bool NoAccess(MembershipSummary membership) =>
        membership.Roles.IsPresent && !membership.Roles.IsNull && membership.Roles.Value.Count == 1 &&
        membership.Roles.Value[0].Role == "no-access" && membership.Roles.Value[0].IsTemporary == false &&
        membership.Roles.Value[0].Mode is null && membership.Roles.Value[0].Range is null &&
        membership.Roles.Value[0].StartsAt is null && membership.Roles.Value[0].EndsAt is null;
    public override string ToString() => "[OrganizationGroupOwner]";

    private sealed class Ownership
    {
        internal string? GroupId { get; set; }
        internal string? MembershipId { get; set; }
        internal string? RoleId { get; set; }
        internal string? LinkId { get; set; }
        public override string ToString() => "[OrganizationGroupOwnership]";
    }

    private sealed class SelectedTokens(SecretMaterial material) : IInfisicalTokenSource
    {
        internal SecretMaterial Material => material;
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
        public override string ToString() => "[OrganizationGroupTokens]";
    }
}
