using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Exact V05-F02 response date-time fields; absence/nullability stay endpoint-owned.
// Static declaration mapping: 92 operation rows / 302 field+predicate occurrences.
internal static class ManagementResponseDates
{
    private sealed record Shape(bool IsDate, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Fields(params (string Name, Shape Value)[] children) => new(false, children);
    private static Shape Elements(Shape element) => new(false, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(false, [], Discriminator: discriminator, Branches: branches);

    private static readonly Shape Date = new(true, []);
    private static readonly Shape Shape0 = Fields(("createdAt", Date), ("temporaryAccessEndTime", Date), ("temporaryAccessStartTime", Date), ("updatedAt", Date));
    private static readonly Shape Shape1 = Fields(("privilege", Shape0));
    private static readonly Shape Shape2 = Elements(Shape0);
    private static readonly Shape Shape3 = Fields(("privileges", Shape2));
    private static readonly Shape Shape4 = Fields(("createdAt", Date), ("updatedAt", Date));
    private static readonly Shape Shape5 = Elements(Shape4);
    private static readonly Shape Shape6 = Fields(("joinedGroupAt", Date));
    private static readonly Shape Shape7 = Elements(Shape6);
    private static readonly Shape Shape8 = Fields(("machineIdentities", Shape7));
    private static readonly Shape Shape9 = Branch("type", ("machineIdentity", Shape6), ("user", Shape6));
    private static readonly Shape Shape10 = Elements(Shape9);
    private static readonly Shape Shape11 = Fields(("members", Shape10));
    private static readonly Shape Shape12 = Fields(("projects", Shape7));
    private static readonly Shape Shape13 = Fields(("users", Shape7));
    private static readonly Shape Shape14 = Fields(("createdAt", Date), ("lastLoginTime", Date), ("updatedAt", Date));
    private static readonly Shape Shape15 = Elements(Shape14);
    private static readonly Shape Shape16 = Fields(("identities", Shape15));
    private static readonly Shape Shape17 = Fields(("identity", Shape4));
    private static readonly Shape Shape18 = Fields(("identity", Shape14));
    private static readonly Shape Shape19 = Branch("authMethod", ("kubernetes", Shape4), ("ldap", Shape4), ("oidc", Shape4));
    private static readonly Shape Shape20 = Elements(Shape19);
    private static readonly Shape Shape21 = Fields(("templates", Shape20));
    private static readonly Shape Shape22 = Fields(("createdAt", Date), ("expiresAt", Date), ("updatedAt", Date));
    private static readonly Shape Shape23 = Elements(Shape22);
    private static readonly Shape Shape24 = Fields(("auditLogs", Shape23));
    private static readonly Shape Shape25 = Fields(("createdAt", Date), ("roles", Shape2), ("updatedAt", Date));
    private static readonly Shape Shape26 = Elements(Shape25);
    private static readonly Shape Shape27 = Fields(("groupMemberships", Shape26));
    private static readonly Shape Shape28 = Fields(("groupMembership", Shape4));
    private static readonly Shape Shape29 = Fields(("groupMembership", Shape25));
    private static readonly Shape Shape30 = Fields(("projectTemplates", Shape5));
    private static readonly Shape Shape31 = Fields(("projectTemplate", Shape4));
    private static readonly Shape Shape32 = Fields(("deleteAfter", Date), ("softDeletedAt", Date));
    private static readonly Shape Shape33 = Elements(Shape32);
    private static readonly Shape Shape34 = Fields(("createdAt", Date), ("deletedEnvironments", Shape33), ("roles", Shape5), ("updatedAt", Date));
    private static readonly Shape Shape35 = Elements(Shape34);
    private static readonly Shape Shape36 = Fields(("projects", Shape35));
    private static readonly Shape Shape37 = Fields(("createdAt", Date), ("deletedEnvironments", Shape33), ("updatedAt", Date));
    private static readonly Shape Shape38 = Fields(("project", Shape37));
    private static readonly Shape Shape39 = Fields(("project", Shape4));
    private static readonly Shape Shape40 = Fields(("authorizations", Shape5));
    private static readonly Shape Shape41 = Fields(("createdAt", Date), ("deleteAfter", Date), ("softDeletedAt", Date), ("updatedAt", Date));
    private static readonly Shape Shape42 = Fields(("environment", Shape41));
    private static readonly Shape Shape43 = Fields(("identities", Shape5));
    private static readonly Shape Shape44 = Fields(("createdAt", Date), ("lastUsed", Date), ("updatedAt", Date));
    private static readonly Shape Shape45 = Elements(Shape44);
    private static readonly Shape Shape46 = Fields(("integrations", Shape45));
    private static readonly Shape Shape47 = Fields(("memberships", Shape5));
    private static readonly Shape Shape48 = Fields(("temporaryAccessEndTime", Date), ("temporaryAccessStartTime", Date));
    private static readonly Shape Shape49 = Elements(Shape48);
    private static readonly Shape Shape50 = Fields(("createdAt", Date), ("roles", Shape49));
    private static readonly Shape Shape51 = Elements(Shape50);
    private static readonly Shape Shape52 = Fields(("memberships", Shape51));
    private static readonly Shape Shape53 = Fields(("roles", Shape2));
    private static readonly Shape Shape54 = Fields(("roles", Shape49));
    private static readonly Shape Shape55 = Fields(("membership", Shape54));
    private static readonly Shape Shape56 = Fields(("createdAt", Date), ("roles", Shape49), ("updatedAt", Date));
    private static readonly Shape Shape57 = Elements(Shape56);
    private static readonly Shape Shape58 = Fields(("identityMemberships", Shape57));
    private static readonly Shape Shape59 = Fields(("identityMembership", Shape4));
    private static readonly Shape Shape60 = Fields(("createdAt", Date), ("lastLoginTime", Date), ("roles", Shape49), ("updatedAt", Date));
    private static readonly Shape Shape61 = Fields(("identityMembership", Shape60));
    private static readonly Shape Shape62 = Fields(("tags", Shape5));
    private static readonly Shape Shape63 = Fields(("tag", Shape4));
    private static readonly Shape Shape64 = Fields(("createdAt", Date), ("expiresAt", Date), ("lastViewedAt", Date), ("updatedAt", Date));
    private static readonly Shape Shape65 = Elements(Shape64);
    private static readonly Shape Shape66 = Fields(("secrets", Shape65));
    private static readonly Shape Shape67 = Fields(("identities", Shape57));
    private static readonly Shape Shape68 = Fields(("membership", Shape4));
    private static readonly Shape Shape69 = Fields(("identityMemberships", Shape15));

    internal static void Validate(string operationId, JsonElement value)
    {
        Shape? shape = operationId switch
        {
            "infisical.delete.v1.additional.privilege.identity" => Shape1,
            "infisical.get.v1.additional.privilege.identity" => Shape3,
            "infisical.patch.v1.additional.privilege.identity" => Shape1,
            "infisical.get.v1.additional.privilege.identity.by.privilegeSlug" => Shape1,
            "infisical.post.v1.additional.privilege.identity.permanent" => Shape1,
            "infisical.post.v1.additional.privilege.identity.temporary" => Shape1,
            "infisical.get.v1.groups" => Shape5,
            "infisical.post.v1.groups" => Shape4,
            "infisical.delete.v1.groups.by.id" => Shape4,
            "infisical.get.v1.groups.by.id" => Shape4,
            "infisical.patch.v1.groups.by.id" => Shape4,
            "infisical.get.v1.groups.by.id.machine.identities" => Shape8,
            "infisical.get.v1.groups.by.id.members" => Shape11,
            "infisical.get.v1.groups.by.id.projects" => Shape12,
            "infisical.get.v1.groups.by.id.users" => Shape13,
            "infisical.get.v1.identities" => Shape16,
            "infisical.post.v1.identities" => Shape17,
            "infisical.delete.v1.identities.by.identityId" => Shape17,
            "infisical.get.v1.identities.by.identityId" => Shape18,
            "infisical.patch.v1.identities.by.identityId" => Shape17,
            "infisical.get.v1.identity.templates" => Shape20,
            "infisical.post.v1.identity.templates" => Shape19,
            "infisical.get.v1.identity.templates.by.templateId" => Shape19,
            "infisical.patch.v1.identity.templates.by.templateId" => Shape19,
            "infisical.get.v1.identity.templates.search" => Shape21,
            "infisical.get.v1.organization.audit.logs" => null,
            "infisical.get.v1.organizations.memberships.groups" => Shape27,
            "infisical.delete.v1.organizations.memberships.groups.by.groupId" => Shape28,
            "infisical.get.v1.organizations.memberships.groups.by.groupId" => Shape29,
            "infisical.patch.v1.organizations.memberships.groups.by.groupId" => Shape29,
            "infisical.post.v1.organizations.memberships.groups.by.groupId" => Shape29,
            "infisical.get.v1.project.templates" => Shape30,
            "infisical.post.v1.project.templates" => Shape31,
            "infisical.delete.v1.project.templates.by.templateId" => Shape31,
            "infisical.get.v1.project.templates.by.templateId" => Shape31,
            "infisical.patch.v1.project.templates.by.templateId" => Shape31,
            "infisical.get.v1.projects" => Shape36,
            "infisical.post.v1.projects" => Shape38,
            "infisical.delete.v1.projects.by.projectId" => Shape39,
            "infisical.get.v1.projects.by.projectId" => Shape38,
            "infisical.patch.v1.projects.by.projectId" => Shape39,
            "infisical.get.v1.projects.by.projectId.authorizations" => Shape40,
            "infisical.post.v1.projects.by.projectId.environments" => Shape42,
            "infisical.get.v1.projects.by.projectId.environments.by.envId" => Shape42,
            "infisical.delete.v1.projects.by.projectId.environments.by.id" => Shape42,
            "infisical.patch.v1.projects.by.projectId.environments.by.id" => Shape42,
            "infisical.post.v1.projects.by.projectId.environments.by.id.restore" => Shape42,
            "infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug" => Shape42,
            "infisical.get.v1.projects.by.projectId.identities" => Shape43,
            "infisical.post.v1.projects.by.projectId.identities" => Shape17,
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => Shape17,
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => Shape17,
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => Shape17,
            "infisical.get.v1.projects.by.projectId.integrations" => Shape46,
            "infisical.delete.v1.projects.by.projectId.memberships" => Shape47,
            "infisical.get.v1.projects.by.projectId.memberships" => Shape52,
            "infisical.post.v1.projects.by.projectId.memberships" => Shape47,
            "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId" => Shape53,
            "infisical.post.v1.projects.by.projectId.memberships.details" => Shape55,
            "infisical.get.v1.projects.by.projectId.memberships.groups" => Shape27,
            "infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape28,
            "infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape29,
            "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape53,
            "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape29,
            "infisical.get.v1.projects.by.projectId.memberships.identities" => Shape58,
            "infisical.delete.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape59,
            "infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape61,
            "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape59,
            "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape59,
            "infisical.get.v1.projects.by.projectId.tags" => Shape62,
            "infisical.post.v1.projects.by.projectId.tags" => Shape63,
            "infisical.delete.v1.projects.by.projectId.tags.by.tagId" => Shape63,
            "infisical.get.v1.projects.by.projectId.tags.by.tagId" => Shape63,
            "infisical.patch.v1.projects.by.projectId.tags.by.tagId" => Shape63,
            "infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug" => Shape63,
            "infisical.get.v1.projects.slug.by.slug" => Shape37,
            "infisical.get.v1.shared.secrets" => Shape66,
            "infisical.post.v1.shared.secrets" => Shape64,
            "infisical.delete.v1.shared.secrets.by.id" => Shape64,
            "infisical.get.v1.shared.secrets.by.id" => Shape64,
            "infisical.post.v1.shared.secrets.by.id.access" => Shape64,
            "infisical.post.v2.identities.search" => Shape67,
            "infisical.get.v2.identity.project.additional.privilege" => Shape3,
            "infisical.post.v2.identity.project.additional.privilege" => Shape1,
            "infisical.delete.v2.identity.project.additional.privilege.by.id" => Shape1,
            "infisical.get.v2.identity.project.additional.privilege.by.id" => Shape1,
            "infisical.patch.v2.identity.project.additional.privilege.by.id" => Shape1,
            "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug" => Shape1,
            "infisical.delete.v2.organizations.by.organizationId.memberships" => Shape47,
            "infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape68,
            "infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape68,
            "infisical.get.v2.organizations.by.orgId.identity.memberships" => Shape69,
            _ => null
        };
        if (shape is not null) Validate(value, shape, 0);
    }

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, Shape22, 0);

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

    private static void Validate(JsonElement value, Shape shape, int depth)
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
