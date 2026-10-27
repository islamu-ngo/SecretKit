using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Reusable UUID field projections selected by family response profiles.
// Only exact declared UUID fields; input UUIDs stay guarded by their factories.
internal static class ManagementResponseUuids
{
    internal sealed record Shape(bool IsUuid, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Fields(params (string Name, Shape Value)[] children) => new(false, children);
    private static Shape Elements(Shape element) => new(false, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(false, [], Discriminator: discriminator, Branches: branches);

    private static readonly Shape Uuid = new(true, []);
    internal static readonly Shape Privilege = Fields(("id", Uuid), ("projectMembershipId", Uuid));
    internal static readonly Shape PrivilegeEnvelope = Fields(("privilege", Privilege));
    internal static readonly Shape PrivilegeRows = Elements(Privilege);
    internal static readonly Shape PrivilegePage = Fields(("privileges", PrivilegeRows));
    internal static readonly Shape IdAndOrganization = Fields(("id", Uuid), ("orgId", Uuid));
    internal static readonly Shape IdAndOrganizationRows = Elements(IdAndOrganization);
    internal static readonly Shape Id = Fields(("id", Uuid));
    internal static readonly Shape IdRows = Elements(Id);
    internal static readonly Shape MachineIdentityPage = Fields(("machineIdentities", IdRows));
    internal static readonly Shape MachineMember = Fields(("machineIdentity", Id));
    internal static readonly Shape UserMember = Fields(("user", Id));
    internal static readonly Shape MemberBranch = Branch("type", ("machineIdentity", MachineMember), ("user", UserMember));
    internal static readonly Shape MemberRows = Elements(MemberBranch);
    internal static readonly Shape MemberPage = Fields(("members", MemberRows));
    internal static readonly Shape UserPage = Fields(("users", IdRows));
    internal static readonly Shape IdentityMembership = Fields(("customRole", Id), ("id", Uuid), ("identity", Id), ("identityId", Uuid), ("orgId", Uuid), ("roleId", Uuid));
    internal static readonly Shape IdentityMembershipRows = Elements(IdentityMembership);
    internal static readonly Shape IdentityPage = Fields(("identities", IdentityMembershipRows));
    internal static readonly Shape IdentityEnvelope = Fields(("identity", IdAndOrganization));
    internal static readonly Shape DetailedIdentityMembership = Fields(("customRole", Id), ("id", Uuid), ("identity", IdAndOrganization), ("identityId", Uuid), ("orgId", Uuid), ("roleId", Uuid));
    internal static readonly Shape DetailedIdentityEnvelope = Fields(("identity", DetailedIdentityMembership));
    internal static readonly Shape Organization = Fields(("orgId", Uuid));
    internal static readonly Shape TemplateBranch = Branch("authMethod", ("kubernetes", Organization), ("ldap", Organization), ("oidc", Organization));
    internal static readonly Shape TemplateRows = Elements(TemplateBranch);
    internal static readonly Shape TemplateSearchPage = Fields(("templates", TemplateRows));
    internal static readonly Shape AuditPage = Fields(("auditLogs", IdAndOrganizationRows));
    internal static readonly Shape AvailableGroups = Fields(("groups", IdRows));
    internal static readonly Shape AvailableIdentities = Fields(("identities", IdRows));
    internal static readonly Shape OrganizationRoles = Fields(("roles", IdAndOrganizationRows));
    internal static readonly Shape OrganizationRole = Fields(("role", IdAndOrganization));
    internal static readonly Shape GroupMembership = Fields(("group", IdAndOrganization), ("groupId", Uuid), ("id", Uuid));
    internal static readonly Shape GroupMembershipRows = Elements(GroupMembership);
    internal static readonly Shape GroupMembershipPage = Fields(("groupMemberships", GroupMembershipRows));
    internal static readonly Shape RemovedGroupMembership = Fields(("groupId", Uuid), ("id", Uuid));
    internal static readonly Shape RemovedGroupEnvelope = Fields(("groupMembership", RemovedGroupMembership));
    internal static readonly Shape GroupMembershipEnvelope = Fields(("groupMembership", GroupMembership));
    internal static readonly Shape ProjectTemplates = Fields(("projectTemplates", IdAndOrganizationRows));
    internal static readonly Shape ProjectTemplate = Fields(("projectTemplate", IdAndOrganization));
    internal static readonly Shape ProjectWithRoles = Fields(("kmsCertificateKeyId", Uuid), ("kmsSecretManagerKeyId", Uuid), ("orgId", Uuid), ("roles", IdRows));
    internal static readonly Shape ProjectRows = Elements(ProjectWithRoles);
    internal static readonly Shape ProjectPage = Fields(("projects", ProjectRows));
    internal static readonly Shape Project = Fields(("kmsCertificateKeyId", Uuid), ("kmsSecretManagerKeyId", Uuid), ("orgId", Uuid));
    internal static readonly Shape ProjectEnvelope = Fields(("project", Project));
    internal static readonly Shape Authorizations = Fields(("authorizations", IdRows));
    internal static readonly Shape Environment = Fields(("deletedByIdentityId", Uuid), ("deletedByUserId", Uuid), ("id", Uuid));
    internal static readonly Shape EnvironmentEnvelope = Fields(("environment", Environment));
    internal static readonly Shape ProjectIdentities = Fields(("identities", IdAndOrganizationRows));
    internal static readonly Shape Integration = Fields(("envId", Uuid), ("id", Uuid), ("integrationAuthId", Uuid));
    internal static readonly Shape IntegrationRows = Elements(Integration);
    internal static readonly Shape Integrations = Fields(("integrations", IntegrationRows));
    internal static readonly Shape UserMembership = Fields(("id", Uuid), ("userId", Uuid));
    internal static readonly Shape UserMembershipRows = Elements(UserMembership);
    internal static readonly Shape UserMembershipMutationEnvelope = Fields(("memberships", UserMembershipRows));
    internal static readonly Shape DetailedUserMembership = Fields(("id", Uuid), ("user", Id), ("userId", Uuid));
    internal static readonly Shape DetailedUserMembershipRows = Elements(DetailedUserMembership);
    internal static readonly Shape UserMembershipPage = Fields(("memberships", DetailedUserMembershipRows));
    internal static readonly Shape MembershipRole = Fields(("customRoleId", Uuid), ("id", Uuid), ("projectMembershipId", Uuid));
    internal static readonly Shape MembershipRoles = Elements(MembershipRole);
    internal static readonly Shape MembershipRolesEnvelope = Fields(("roles", MembershipRoles));
    internal static readonly Shape UserMembershipEnvelope = Fields(("membership", DetailedUserMembership));
    internal static readonly Shape ProjectIdentityRows = Elements(IdentityEnvelope);
    internal static readonly Shape ProjectIdentityPage = Fields(("identityMemberships", ProjectIdentityRows));
    internal static readonly Shape MutatedIdentityMembership = Fields(("id", Uuid), ("identityId", Uuid));
    internal static readonly Shape IdentityMembershipMutationEnvelope = Fields(("identityMembership", MutatedIdentityMembership));
    internal static readonly Shape ProjectIdentityEnvelope = Fields(("identityMembership", IdentityEnvelope));
    internal static readonly Shape ProjectRoles = Fields(("roles", IdRows));
    internal static readonly Shape ProjectRole = Fields(("role", Id));
    internal static readonly Shape Tag = Fields(("createdBy", Uuid), ("id", Uuid));
    internal static readonly Shape TagRows = Elements(Tag);
    internal static readonly Shape TagPage = Fields(("tags", TagRows));
    internal static readonly Shape TagEnvelope = Fields(("tag", Tag));
    internal static readonly Shape Share = Fields(("identityId", Uuid), ("orgId", Uuid), ("userId", Uuid));
    internal static readonly Shape ShareRows = Elements(Share);
    internal static readonly Shape SharePage = Fields(("secrets", ShareRows));
    internal static readonly Shape IdentitySearchPage = Fields(("identities", ProjectIdentityRows));
    internal static readonly Shape ProjectPrivilegePage = Fields(("privileges", IdRows));
    internal static readonly Shape ProjectPrivilegeEnvelope = Fields(("privilege", Id));
    internal static readonly Shape OrganizationUserMembership = Fields(("id", Uuid), ("orgId", Uuid), ("roleId", Uuid), ("userId", Uuid));
    internal static readonly Shape OrganizationUserMembershipRows = Elements(OrganizationUserMembership);
    internal static readonly Shape OrganizationUserMembershipPage = Fields(("memberships", OrganizationUserMembershipRows));
    internal static readonly Shape DetailedOrganizationUserMembership = Fields(("id", Uuid), ("orgId", Uuid), ("roleId", Uuid), ("user", Id), ("userId", Uuid));
    internal static readonly Shape DetailedOrganizationUserMembershipRows = Elements(DetailedOrganizationUserMembership);
    internal static readonly Shape OrganizationUserPage = Fields(("users", DetailedOrganizationUserMembershipRows));
    internal static readonly Shape OrganizationUserMembershipEnvelope = Fields(("membership", OrganizationUserMembership));
    internal static readonly Shape DetailedIdentityMembershipRows = Elements(DetailedIdentityMembership);
    internal static readonly Shape OrganizationIdentityPage = Fields(("identityMemberships", DetailedIdentityMembershipRows));

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, ManagementResponseContracts.AuditRow.Uuids!, 0);

    internal static void Validate(JsonElement value, Shape shape, int depth)
    {
        if (depth > 64) throw new ManagementContractException(SecretStatus.Unknown);
        // Preserve endpoint-owned absence and nullable-field handling.
        if (value.ValueKind == JsonValueKind.Null) return;
        if (shape.IsUuid)
        {
            if (value.ValueKind != JsonValueKind.String || !Guid.TryParseExact(value.GetString(), "D", out _))
                throw new ManagementContractException(SecretStatus.Unknown);
            return;
        }
        if (shape.Discriminator is { } discriminator)
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(discriminator, out var tag) ||
                tag.ValueKind != JsonValueKind.String) return;
            foreach (var branch in shape.Branches!)
                if (string.Equals(tag.GetString(), branch.Name, StringComparison.Ordinal))
                {
                    Validate(value, branch.Value, depth + 1);
                    return;
                }
            return;
        }
        if (shape.Element is { } element)
        {
            if (value.ValueKind != JsonValueKind.Array) throw new ManagementContractException(SecretStatus.Unknown);
            foreach (var item in value.EnumerateArray()) Validate(item, element, depth + 1);
            return;
        }
        if (value.ValueKind != JsonValueKind.Object) throw new ManagementContractException(SecretStatus.Unknown);
        foreach (var child in shape.Children)
            if (value.TryGetProperty(child.Name, out var nested)) Validate(nested, child.Value, depth + 1);
    }
}
