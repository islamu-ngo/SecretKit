using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Exact V05-F02 response date-time fields; absence/nullability stay endpoint-owned.
// Family response profiles select these projections; there is no operation map here.
internal static class ManagementResponseDates
{
    internal sealed record Shape(bool IsDate, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Fields(params (string Name, Shape Value)[] children) => new(false, children);
    private static Shape Elements(Shape element) => new(false, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(false, [], Discriminator: discriminator, Branches: branches);

    private static readonly Shape Date = new(true, []);
    internal static readonly Shape Privilege = Fields(("createdAt", Date), ("temporaryAccessEndTime", Date), ("temporaryAccessStartTime", Date), ("updatedAt", Date));
    internal static readonly Shape PrivilegeEnvelope = Fields(("privilege", Privilege));
    internal static readonly Shape PrivilegeRows = Elements(Privilege);
    internal static readonly Shape PrivilegePage = Fields(("privileges", PrivilegeRows));
    internal static readonly Shape CreatedAndUpdated = Fields(("createdAt", Date), ("updatedAt", Date));
    internal static readonly Shape CreatedAndUpdatedRows = Elements(CreatedAndUpdated);
    internal static readonly Shape JoinedGroup = Fields(("joinedGroupAt", Date));
    internal static readonly Shape JoinedGroupRows = Elements(JoinedGroup);
    internal static readonly Shape MachineIdentityPage = Fields(("machineIdentities", JoinedGroupRows));
    internal static readonly Shape MemberBranch = Branch("type", ("machineIdentity", JoinedGroup), ("user", JoinedGroup));
    internal static readonly Shape MemberRows = Elements(MemberBranch);
    internal static readonly Shape MemberPage = Fields(("members", MemberRows));
    internal static readonly Shape GroupProjects = Fields(("projects", JoinedGroupRows));
    internal static readonly Shape GroupUsers = Fields(("users", JoinedGroupRows));
    internal static readonly Shape IdentityMembership = Fields(("createdAt", Date), ("lastLoginTime", Date), ("updatedAt", Date));
    internal static readonly Shape IdentityMembershipRows = Elements(IdentityMembership);
    internal static readonly Shape IdentityPage = Fields(("identities", IdentityMembershipRows));
    internal static readonly Shape IdentityEnvelope = Fields(("identity", CreatedAndUpdated));
    internal static readonly Shape DetailedIdentityEnvelope = Fields(("identity", IdentityMembership));
    internal static readonly Shape TemplateBranch = Branch("authMethod", ("kubernetes", CreatedAndUpdated), ("ldap", CreatedAndUpdated), ("oidc", CreatedAndUpdated));
    internal static readonly Shape TemplateRows = Elements(TemplateBranch);
    internal static readonly Shape TemplateSearchPage = Fields(("templates", TemplateRows));
    internal static readonly Shape Expiring = Fields(("createdAt", Date), ("expiresAt", Date), ("updatedAt", Date));
    internal static readonly Shape ExpiringRows = Elements(Expiring);
    internal static readonly Shape AuditPage = Fields(("auditLogs", ExpiringRows));
    internal static readonly Shape GroupMembership = Fields(("createdAt", Date), ("roles", PrivilegeRows), ("updatedAt", Date));
    internal static readonly Shape GroupMembershipRows = Elements(GroupMembership);
    internal static readonly Shape GroupMembershipPage = Fields(("groupMemberships", GroupMembershipRows));
    internal static readonly Shape RemovedGroupEnvelope = Fields(("groupMembership", CreatedAndUpdated));
    internal static readonly Shape GroupMembershipEnvelope = Fields(("groupMembership", GroupMembership));
    internal static readonly Shape ProjectTemplates = Fields(("projectTemplates", CreatedAndUpdatedRows));
    internal static readonly Shape ProjectTemplate = Fields(("projectTemplate", CreatedAndUpdated));
    internal static readonly Shape DeletedEnvironment = Fields(("deleteAfter", Date), ("softDeletedAt", Date));
    internal static readonly Shape DeletedEnvironments = Elements(DeletedEnvironment);
    internal static readonly Shape ProjectWithRoles = Fields(("createdAt", Date), ("deletedEnvironments", DeletedEnvironments), ("roles", CreatedAndUpdatedRows), ("updatedAt", Date));
    internal static readonly Shape ProjectRows = Elements(ProjectWithRoles);
    internal static readonly Shape ProjectPage = Fields(("projects", ProjectRows));
    internal static readonly Shape DetailedProject = Fields(("createdAt", Date), ("deletedEnvironments", DeletedEnvironments), ("updatedAt", Date));
    internal static readonly Shape ProjectEnvelope = Fields(("project", DetailedProject));
    internal static readonly Shape ProjectMutationEnvelope = Fields(("project", CreatedAndUpdated));
    internal static readonly Shape Authorizations = Fields(("authorizations", CreatedAndUpdatedRows));
    internal static readonly Shape Environment = Fields(("createdAt", Date), ("deleteAfter", Date), ("softDeletedAt", Date), ("updatedAt", Date));
    internal static readonly Shape EnvironmentEnvelope = Fields(("environment", Environment));
    internal static readonly Shape ProjectIdentities = Fields(("identities", CreatedAndUpdatedRows));
    internal static readonly Shape Integration = Fields(("createdAt", Date), ("lastUsed", Date), ("updatedAt", Date));
    internal static readonly Shape IntegrationRows = Elements(Integration);
    internal static readonly Shape Integrations = Fields(("integrations", IntegrationRows));
    internal static readonly Shape UserMembershipMutations = Fields(("memberships", CreatedAndUpdatedRows));
    internal static readonly Shape TemporaryAccess = Fields(("temporaryAccessEndTime", Date), ("temporaryAccessStartTime", Date));
    internal static readonly Shape TemporaryAccessRows = Elements(TemporaryAccess);
    internal static readonly Shape UserMembership = Fields(("createdAt", Date), ("roles", TemporaryAccessRows));
    internal static readonly Shape UserMembershipRows = Elements(UserMembership);
    internal static readonly Shape UserMembershipPage = Fields(("memberships", UserMembershipRows));
    internal static readonly Shape UpdatedMembershipRoles = Fields(("roles", PrivilegeRows));
    internal static readonly Shape MembershipRoles = Fields(("roles", TemporaryAccessRows));
    internal static readonly Shape UserMembershipEnvelope = Fields(("membership", MembershipRoles));
    internal static readonly Shape ProjectIdentityMembership = Fields(("createdAt", Date), ("roles", TemporaryAccessRows), ("updatedAt", Date));
    internal static readonly Shape IdentityMembershipCollection = Elements(ProjectIdentityMembership);
    internal static readonly Shape IdentityMembershipPage = Fields(("identityMemberships", IdentityMembershipCollection));
    internal static readonly Shape IdentityMembershipMutationEnvelope = Fields(("identityMembership", CreatedAndUpdated));
    internal static readonly Shape DetailedIdentityMembership = Fields(("createdAt", Date), ("lastLoginTime", Date), ("roles", TemporaryAccessRows), ("updatedAt", Date));
    internal static readonly Shape IdentityMembershipEnvelope = Fields(("identityMembership", DetailedIdentityMembership));
    internal static readonly Shape Tags = Fields(("tags", CreatedAndUpdatedRows));
    internal static readonly Shape TagEnvelope = Fields(("tag", CreatedAndUpdated));
    internal static readonly Shape Share = Fields(("createdAt", Date), ("expiresAt", Date), ("lastViewedAt", Date), ("updatedAt", Date));
    internal static readonly Shape ShareRows = Elements(Share);
    internal static readonly Shape SharePage = Fields(("secrets", ShareRows));
    internal static readonly Shape IdentitySearchPage = Fields(("identities", IdentityMembershipCollection));
    internal static readonly Shape OrganizationUserMembershipEnvelope = Fields(("membership", CreatedAndUpdated));
    internal static readonly Shape OrganizationIdentityPage = Fields(("identityMemberships", IdentityMembershipRows));

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, ManagementResponseContracts.AuditRow.Dates!, 0);

    internal static void ValidateDateValue(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String || !value.TryGetDateTimeOffset(out _))
            throw new ManagementContractException(SecretStatus.Unknown);
        string text = value.GetString()!;
        // System.Text.Json also accepts date-only and unzoned timestamps.
        // Require an explicit UTC or signed offset without normalizing copied text.
        if (text.Length < 20 || !(text.EndsWith('Z') ||
            text.Length >= 25 && text[^6] is '+' or '-'))
            throw new ManagementContractException(SecretStatus.Unknown);
    }

    internal static void Validate(JsonElement value, Shape shape, int depth)
    {
        if (depth > 64) throw new ManagementContractException(SecretStatus.Unknown);
        // Typed parsing owns presence and nullability, including conditional fields.
        if (value.ValueKind == JsonValueKind.Null) return;
        if (shape.IsDate)
        {
            ValidateDateValue(value);
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
