using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>
/// Native privilege identity/lifetime projection. Permissions are deliberately not
/// projected: this result must not be interpreted as an effective access decision.
/// </summary>
public sealed class IdentityPrivilegeSummary
{
    internal IdentityPrivilegeSummary(JsonElement value, string? id = null)
    {
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        Id = ManagementJson.Required(value, "id");
        Slug = ManagementJson.Required(value, "slug");
        StartsAt = ManagementJson.Optional(value, "temporaryAccessStartTime");
        EndsAt = ManagementJson.Optional(value, "temporaryAccessEndTime");
        Mode = ManagementJson.Optional(value, "temporaryMode");
        Range = ManagementJson.Optional(value, "temporaryRange");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Slug { get; }
    [JsonIgnore] public string? StartsAt { get; }
    [JsonIgnore] public string? EndsAt { get; }
    [JsonIgnore] public string? Mode { get; }
    [JsonIgnore] public string? Range { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[IdentityPrivilegeSummary]";
}

public static class IdentityPrivilegeOperations
{
    public static ManagementRequest<ManagementPage<IdentityPrivilegeSummary>> ListProjectPrivileges(
        string organizationId, string projectId, string identityId) =>
        new("infisical.get.v2.identity.project.additional.privilege", HttpMethod.Get,
            "/api/v2/identity-project-additional-privilege?projectId=" + ManagementJson.Escape(projectId) +
            "&identityId=" + ManagementJson.Escape(identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Array(root, "privileges").Select(value => new IdentityPrivilegeSummary(value)), true), false);

    public static ManagementRequest<IdentityPrivilegeSummary> GetProjectPrivilege(
        string organizationId, string projectId, string identityId, string privilegeId) =>
        new("infisical.get.v2.identity.project.additional.privilege.by.id", HttpMethod.Get,
            "/api/v2/identity-project-additional-privilege/" + ManagementJson.Escape(privilegeId),
            new(organizationId, projectId, identityId, privilegeId), null,
            root => new(ManagementJson.Object(root, "privilege"), privilegeId), false);

    public static ManagementRequest<IdentityPrivilegeSummary> DeleteProjectPrivilege(
        string organizationId, string projectId, string identityId, string privilegeId) =>
        new("infisical.delete.v2.identity.project.additional.privilege.by.id", HttpMethod.Delete,
            "/api/v2/identity-project-additional-privilege/" + ManagementJson.Escape(privilegeId),
            new(organizationId, projectId, identityId, privilegeId), null,
            root => new(ManagementJson.Object(root, "privilege"), privilegeId));
}
