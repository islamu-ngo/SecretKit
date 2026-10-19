using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class OrganizationIdentityMembershipsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) => null;

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        await c.EnsureIdentityAsync(token);
        string org = c.OrganizationId;
        OrganizationIdentityOrder orderBy = c.Variant == "orderBy.Role" ? OrganizationIdentityOrder.Role : OrganizationIdentityOrder.Name;
        ManagementListOrder order = c.Variant == "order.Descending" ? ManagementListOrder.Descending : ManagementListOrder.Ascending;
        string? search = c.Variant == "search.value" ? c.IdentityName : null;
        Func<ManagementRequest<ManagementPage<OrganizationIdentityMembershipSummary>>> request = () =>
            OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(org, 0, 100, orderBy, order, search);
        bool Match(ManagementPage<OrganizationIdentityMembershipSummary> page) => page.IsComplete &&
            page.Items.Count(i => i.IdentityId == c.IdentityId && i.Identity.Name == c.IdentityName && i.Role == "member") == 1 &&
            page.Items.All(i => i.Identity.OrganizationIdField is { IsPresent: true, IsNull: false } field ?
                field.Value == org : true) &&
            (search is null || page.Items.All(i => i.Identity.Name.Contains(search, StringComparison.Ordinal)));
        IdentitySummary prepared = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(org, c.IdentityId),
            NativeIdentityRole.Observer, token);
        await c.CaseAsync(request, Match, async (_, ct) =>
        {
            ManagementPage<OrganizationIdentityMembershipSummary> independent = await c.NeedAsync(request,
                NativeIdentityRole.Observer, ct);
            OrganizationIdentityMembershipSummary? owned = independent.Items.SingleOrDefault(i => i.IdentityId == c.IdentityId);
            return Match(independent) && owned is not null && owned.Identity.Name == prepared.Name &&
                owned.Identity.AuthMethods.IsPresent && prepared.AuthMethods.IsPresent &&
                owned.Identity.AuthMethods.Value.SequenceEqual(prepared.AuthMethods.Value);
        }, token);
    }
}
