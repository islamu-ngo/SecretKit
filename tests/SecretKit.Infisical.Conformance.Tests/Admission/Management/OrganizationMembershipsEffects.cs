using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class OrganizationMembershipsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) =>
        d.Key.Variant.StartsWith("metadata.", StringComparison.Ordinal) ? "primary-membership-metadata-readback-unavailable" :
        d.Key.Operation.EndsWith(".ListOrganizationMemberships", StringComparison.Ordinal) ? null :
            "fresh-user-membership-provisioning-and-principal-observer-unavailable";

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        // There is no public organization-user creation factory in this admission.
        // Inventory reads can bind independently selected user state without deleting
        // or modifying a preexisting principal. Mutations remain explicitly unavailable.
        string userId = c.Required("observerUserId"), username = c.Required("observerUsername");
        Func<ManagementRequest<ManagementPage<OrganizationMembershipSummary>>> request = () =>
            OrganizationMembershipOperations.ListOrganizationMemberships(c.OrganizationId);
        ManagementPage<OrganizationMembershipSummary> prepared = await c.NeedAsync(request, NativeIdentityRole.Observer, token);
        c.Probe.Contract(prepared.IsComplete && prepared.Items.Count(m => m.User?.Id == userId &&
            m.User.Username == username) == 1, NativeFailure.MissingPrerequisite);
        var expected = prepared.Items.ToDictionary(m => m.Id,
            m => (m.User!.Id, m.User.Username, m.Role, m.IsActive, m.Status));
        bool Match(ManagementPage<OrganizationMembershipSummary> page) => page.IsComplete &&
            page.Items.Count == expected.Count && page.Items.All(m => m.User is not null &&
                expected.TryGetValue(m.Id, out var before) &&
                before == (m.User.Id, m.User.Username, m.Role, m.IsActive, m.Status));
        await c.CaseAsync(request, Match, async (_, ct) =>
        {
            ManagementPage<OrganizationMembershipSummary> observed = await c.NeedAsync(request, NativeIdentityRole.Observer, ct);
            return Match(observed);
        }, token);
    }
}
