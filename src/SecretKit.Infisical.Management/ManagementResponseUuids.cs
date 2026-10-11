using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Only the exact declared UUID response fields. Input UUIDs are guarded by their factories.
internal static class ManagementResponseUuids
{
    private sealed record Shape(bool IsUuid, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Fields(params (string Name, Shape Value)[] children) => new(false, children);
    private static Shape Elements(Shape element) => new(false, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(false, [], Discriminator: discriminator, Branches: branches);

    private static readonly Shape Uuid = new(true, []);
    private static readonly Shape Shape0 = Fields(("id", Uuid), ("projectMembershipId", Uuid));
    private static readonly Shape Shape1 = Fields(("privilege", Shape0));
    private static readonly Shape Shape2 = Elements(Shape0);
    private static readonly Shape Shape3 = Fields(("privileges", Shape2));
    private static readonly Shape Shape4 = Fields(("id", Uuid), ("orgId", Uuid));
    private static readonly Shape Shape5 = Elements(Shape4);
    private static readonly Shape Shape6 = Fields(("id", Uuid));
    private static readonly Shape Shape7 = Elements(Shape6);
    private static readonly Shape Shape8 = Fields(("machineIdentities", Shape7));
    private static readonly Shape Shape9 = Fields(("machineIdentity", Shape6));
    private static readonly Shape Shape10 = Fields(("user", Shape6));
    private static readonly Shape Shape11 = Branch("type", ("machineIdentity", Shape9), ("user", Shape10));
    private static readonly Shape Shape12 = Elements(Shape11);
    private static readonly Shape Shape13 = Fields(("members", Shape12));
    private static readonly Shape Shape14 = Fields(("users", Shape7));
    private static readonly Shape Shape15 = Fields(("customRole", Shape6), ("id", Uuid), ("identity", Shape6), ("identityId", Uuid), ("orgId", Uuid), ("roleId", Uuid));
    private static readonly Shape Shape16 = Elements(Shape15);
    private static readonly Shape Shape17 = Fields(("identities", Shape16));
    private static readonly Shape Shape18 = Fields(("identity", Shape4));
    private static readonly Shape Shape19 = Fields(("customRole", Shape6), ("id", Uuid), ("identity", Shape4), ("identityId", Uuid), ("orgId", Uuid), ("roleId", Uuid));
    private static readonly Shape Shape20 = Fields(("identity", Shape19));
    private static readonly Shape Shape21 = Fields(("orgId", Uuid));
    private static readonly Shape Shape22 = Branch("authMethod", ("kubernetes", Shape21), ("ldap", Shape21), ("oidc", Shape21));
    private static readonly Shape Shape23 = Elements(Shape22);
    private static readonly Shape Shape24 = Fields(("templates", Shape23));
    private static readonly Shape Shape25 = Fields(("auditLogs", Shape5));
    private static readonly Shape Shape26 = Fields(("groups", Shape7));
    private static readonly Shape Shape27 = Fields(("identities", Shape7));
    private static readonly Shape Shape28 = Fields(("roles", Shape5));
    private static readonly Shape Shape29 = Fields(("role", Shape4));
    private static readonly Shape Shape30 = Fields(("group", Shape4), ("groupId", Uuid), ("id", Uuid));
    private static readonly Shape Shape31 = Elements(Shape30);
    private static readonly Shape Shape32 = Fields(("groupMemberships", Shape31));
    private static readonly Shape Shape33 = Fields(("groupId", Uuid), ("id", Uuid));
    private static readonly Shape Shape34 = Fields(("groupMembership", Shape33));
    private static readonly Shape Shape35 = Fields(("groupMembership", Shape30));
    private static readonly Shape Shape36 = Fields(("projectTemplates", Shape5));
    private static readonly Shape Shape37 = Fields(("projectTemplate", Shape4));
    private static readonly Shape Shape38 = Fields(("kmsCertificateKeyId", Uuid), ("kmsSecretManagerKeyId", Uuid), ("orgId", Uuid), ("roles", Shape7));
    private static readonly Shape Shape39 = Elements(Shape38);
    private static readonly Shape Shape40 = Fields(("projects", Shape39));
    private static readonly Shape Shape41 = Fields(("kmsCertificateKeyId", Uuid), ("kmsSecretManagerKeyId", Uuid), ("orgId", Uuid));
    private static readonly Shape Shape42 = Fields(("project", Shape41));
    private static readonly Shape Shape43 = Fields(("authorizations", Shape7));
    private static readonly Shape Shape44 = Fields(("deletedByIdentityId", Uuid), ("deletedByUserId", Uuid), ("id", Uuid));
    private static readonly Shape Shape45 = Fields(("environment", Shape44));
    private static readonly Shape Shape46 = Fields(("identities", Shape5));
    private static readonly Shape Shape47 = Fields(("envId", Uuid), ("id", Uuid), ("integrationAuthId", Uuid));
    private static readonly Shape Shape48 = Elements(Shape47);
    private static readonly Shape Shape49 = Fields(("integrations", Shape48));
    private static readonly Shape Shape50 = Fields(("id", Uuid), ("userId", Uuid));
    private static readonly Shape Shape51 = Elements(Shape50);
    private static readonly Shape Shape52 = Fields(("memberships", Shape51));
    private static readonly Shape Shape53 = Fields(("id", Uuid), ("user", Shape6), ("userId", Uuid));
    private static readonly Shape Shape54 = Elements(Shape53);
    private static readonly Shape Shape55 = Fields(("memberships", Shape54));
    private static readonly Shape Shape56 = Fields(("customRoleId", Uuid), ("id", Uuid), ("projectMembershipId", Uuid));
    private static readonly Shape Shape57 = Elements(Shape56);
    private static readonly Shape Shape58 = Fields(("roles", Shape57));
    private static readonly Shape Shape59 = Fields(("membership", Shape53));
    private static readonly Shape Shape60 = Elements(Shape18);
    private static readonly Shape Shape61 = Fields(("identityMemberships", Shape60));
    private static readonly Shape Shape62 = Fields(("id", Uuid), ("identityId", Uuid));
    private static readonly Shape Shape63 = Fields(("identityMembership", Shape62));
    private static readonly Shape Shape64 = Fields(("identityMembership", Shape18));
    private static readonly Shape Shape65 = Fields(("roles", Shape7));
    private static readonly Shape Shape66 = Fields(("role", Shape6));
    private static readonly Shape Shape67 = Fields(("createdBy", Uuid), ("id", Uuid));
    private static readonly Shape Shape68 = Elements(Shape67);
    private static readonly Shape Shape69 = Fields(("tags", Shape68));
    private static readonly Shape Shape70 = Fields(("tag", Shape67));
    private static readonly Shape Shape71 = Fields(("identityId", Uuid), ("orgId", Uuid), ("userId", Uuid));
    private static readonly Shape Shape72 = Elements(Shape71);
    private static readonly Shape Shape73 = Fields(("secrets", Shape72));
    private static readonly Shape Shape74 = Fields(("identities", Shape60));
    private static readonly Shape Shape75 = Fields(("privileges", Shape7));
    private static readonly Shape Shape76 = Fields(("privilege", Shape6));
    private static readonly Shape Shape77 = Fields(("id", Uuid), ("orgId", Uuid), ("roleId", Uuid), ("userId", Uuid));
    private static readonly Shape Shape78 = Elements(Shape77);
    private static readonly Shape Shape79 = Fields(("memberships", Shape78));
    private static readonly Shape Shape80 = Fields(("id", Uuid), ("orgId", Uuid), ("roleId", Uuid), ("user", Shape6), ("userId", Uuid));
    private static readonly Shape Shape81 = Elements(Shape80);
    private static readonly Shape Shape82 = Fields(("users", Shape81));
    private static readonly Shape Shape83 = Fields(("membership", Shape77));
    private static readonly Shape Shape84 = Elements(Shape19);
    private static readonly Shape Shape85 = Fields(("identityMemberships", Shape84));

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
            "infisical.get.v1.groups.by.id.members" => Shape13,
            "infisical.get.v1.groups.by.id.users" => Shape14,
            "infisical.delete.v1.groups.by.id.users.by.username" => Shape6,
            "infisical.post.v1.groups.by.id.users.by.username" => Shape6,
            "infisical.get.v1.identities" => Shape17,
            "infisical.post.v1.identities" => Shape18,
            "infisical.delete.v1.identities.by.identityId" => Shape18,
            "infisical.get.v1.identities.by.identityId" => Shape20,
            "infisical.patch.v1.identities.by.identityId" => Shape18,
            "infisical.get.v1.identity.templates" => Shape23,
            "infisical.post.v1.identity.templates" => Shape22,
            "infisical.get.v1.identity.templates.by.templateId" => Shape22,
            "infisical.patch.v1.identity.templates.by.templateId" => Shape22,
            "infisical.get.v1.identity.templates.search" => Shape24,
            "infisical.get.v1.organization.audit.logs" => null,
            "infisical.get.v1.organization.available.groups" => Shape26,
            "infisical.get.v1.organization.available.identities" => Shape27,
            "infisical.get.v1.organization.roles" => Shape28,
            "infisical.post.v1.organization.roles" => Shape29,
            "infisical.delete.v1.organization.roles.by.roleId" => Shape29,
            "infisical.get.v1.organization.roles.by.roleId" => Shape29,
            "infisical.patch.v1.organization.roles.by.roleId" => Shape29,
            "infisical.get.v1.organization.roles.slug.by.roleSlug" => Shape29,
            "infisical.get.v1.organizations.memberships.groups" => Shape32,
            "infisical.delete.v1.organizations.memberships.groups.by.groupId" => Shape34,
            "infisical.get.v1.organizations.memberships.groups.by.groupId" => Shape35,
            "infisical.patch.v1.organizations.memberships.groups.by.groupId" => Shape35,
            "infisical.post.v1.organizations.memberships.groups.by.groupId" => Shape35,
            "infisical.get.v1.project.templates" => Shape36,
            "infisical.post.v1.project.templates" => Shape37,
            "infisical.delete.v1.project.templates.by.templateId" => Shape37,
            "infisical.get.v1.project.templates.by.templateId" => Shape37,
            "infisical.patch.v1.project.templates.by.templateId" => Shape37,
            "infisical.get.v1.projects" => Shape40,
            "infisical.post.v1.projects" => Shape42,
            "infisical.delete.v1.projects.by.projectId" => Shape42,
            "infisical.get.v1.projects.by.projectId" => Shape42,
            "infisical.patch.v1.projects.by.projectId" => Shape42,
            "infisical.get.v1.projects.by.projectId.authorizations" => Shape43,
            "infisical.post.v1.projects.by.projectId.environments" => Shape45,
            "infisical.get.v1.projects.by.projectId.environments.by.envId" => Shape45,
            "infisical.delete.v1.projects.by.projectId.environments.by.id" => Shape45,
            "infisical.patch.v1.projects.by.projectId.environments.by.id" => Shape45,
            "infisical.post.v1.projects.by.projectId.environments.by.id.restore" => Shape45,
            "infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug" => Shape45,
            "infisical.get.v1.projects.by.projectId.identities" => Shape46,
            "infisical.post.v1.projects.by.projectId.identities" => Shape18,
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => Shape18,
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => Shape18,
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => Shape18,
            "infisical.get.v1.projects.by.projectId.integrations" => Shape49,
            "infisical.delete.v1.projects.by.projectId.memberships" => Shape52,
            "infisical.get.v1.projects.by.projectId.memberships" => Shape55,
            "infisical.post.v1.projects.by.projectId.memberships" => Shape52,
            "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId" => Shape58,
            "infisical.get.v1.projects.by.projectId.memberships.available.identities" => Shape27,
            "infisical.post.v1.projects.by.projectId.memberships.details" => Shape59,
            "infisical.get.v1.projects.by.projectId.memberships.groups" => Shape32,
            "infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape34,
            "infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape35,
            "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape58,
            "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape35,
            "infisical.get.v1.projects.by.projectId.memberships.identities" => Shape61,
            "infisical.delete.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape63,
            "infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape64,
            "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape63,
            "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape63,
            "infisical.get.v1.projects.by.projectId.roles" => Shape65,
            "infisical.post.v1.projects.by.projectId.roles" => Shape66,
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId" => Shape66,
            "infisical.patch.v1.projects.by.projectId.roles.by.roleId" => Shape66,
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug" => Shape66,
            "infisical.get.v1.projects.by.projectId.tags" => Shape69,
            "infisical.post.v1.projects.by.projectId.tags" => Shape70,
            "infisical.delete.v1.projects.by.projectId.tags.by.tagId" => Shape70,
            "infisical.get.v1.projects.by.projectId.tags.by.tagId" => Shape70,
            "infisical.patch.v1.projects.by.projectId.tags.by.tagId" => Shape70,
            "infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug" => Shape70,
            "infisical.get.v1.projects.roles.by.roleId" => Shape66,
            "infisical.get.v1.projects.slug.by.slug" => Shape41,
            "infisical.get.v1.shared.secrets" => Shape73,
            "infisical.post.v1.shared.secrets" => Shape71,
            "infisical.delete.v1.shared.secrets.by.id" => Shape71,
            "infisical.get.v1.shared.secrets.by.id" => Shape71,
            "infisical.post.v1.shared.secrets.by.id.access" => Shape71,
            "infisical.post.v2.identities.search" => Shape74,
            "infisical.get.v2.identity.project.additional.privilege" => Shape75,
            "infisical.post.v2.identity.project.additional.privilege" => Shape76,
            "infisical.delete.v2.identity.project.additional.privilege.by.id" => Shape76,
            "infisical.get.v2.identity.project.additional.privilege.by.id" => Shape76,
            "infisical.patch.v2.identity.project.additional.privilege.by.id" => Shape76,
            "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug" => Shape76,
            "infisical.delete.v2.organizations.by.organizationId.memberships" => Shape79,
            "infisical.get.v2.organizations.by.organizationId.memberships" => Shape82,
            "infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape83,
            "infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape83,
            "infisical.get.v2.organizations.by.orgId.identity.memberships" => Shape85,
            _ => null
        };
        if (shape is not null) Validate(value, shape, 0);
    }

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, Shape4, 0);

    private static void Validate(JsonElement value, Shape shape, int depth)
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
