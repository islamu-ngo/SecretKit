using System.Text.Json;
using System.Text.Json.Serialization;

namespace SecretKit.Infisical.Management;

/// <summary>
/// Native privilege identity/lifetime and permission metadata, not an effective access decision.
/// </summary>
public sealed class IdentityPrivilegeSummary
{
    internal IdentityPrivilegeSummary(JsonElement value, string? id = null, bool includePermissions = true)
    {
        if (id is not null) ManagementJson.RequireEqual(value, "id", id);
        Id = ManagementJson.Required(value, "id");
        Slug = ManagementJson.Required(value, "slug");
        StartsAt = ManagementJson.Optional(value, "temporaryAccessStartTime");
        EndsAt = ManagementJson.Optional(value, "temporaryAccessEndTime");
        Mode = ManagementJson.Optional(value, "temporaryMode");
        Range = ManagementJson.Optional(value, "temporaryRange");
        Permissions = includePermissions ? RolePermissionSummary.Read(value) ??
            throw new ManagementContractException(SecretKit.Core.SecretStatus.Unknown) : null;
        if (value.TryGetProperty("isTemporary", out _))
            IsTemporary = ManagementJson.Boolean(value, "isTemporary");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }
    /// <summary>Gets the returned privilege identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the native privilege slug.</summary>
    [JsonIgnore] public string Slug { get; }
    /// <summary>Gets the temporary-access start timestamp, or null when absent or null.</summary>
    [JsonIgnore] public string? StartsAt { get; }
    /// <summary>Gets the temporary-access end timestamp, or null when absent or null.</summary>
    [JsonIgnore] public string? EndsAt { get; }
    /// <summary>Gets the native temporary-access mode, or null when unreturned.</summary>
    [JsonIgnore] public string? Mode { get; }
    /// <summary>Gets the native duration expression, or null when unreturned.</summary>
    [JsonIgnore] public string? Range { get; }
    /// <summary>Gets projected permission metadata, or null when this operation does not include it.</summary>
    [JsonIgnore] public IReadOnlyList<RolePermissionSummary>? Permissions { get; }
    /// <summary>Gets the returned temporary-access flag, or null when not supplied.</summary>
    [JsonIgnore] public bool? IsTemporary { get; }
    /// <summary>Gets the returned privilege creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned privilege update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets whether permission metadata is included; does not attest effective access.</summary>
    public bool IncludesPermissions => Permissions is not null;
    /// <summary>Returns a marker without privilege coordinates or permission values.</summary>
    public override string ToString() => "[IdentityPrivilegeSummary]";
}

/// <summary>Constructs disposable native project-privilege requests, not permission evaluations.</summary>
public static class IdentityPrivilegeOperations
{
    /// <summary>Builds a project privilege inventory request whose summaries omit permissions.</summary>
    public static ManagementRequest<ManagementPage<IdentityPrivilegeSummary>> ListProjectPrivileges(
        string organizationId, string projectId, string identityId) =>
        new("infisical.get.v2.identity.project.additional.privilege", HttpMethod.Get,
            "/api/v2/identity-project-additional-privilege?projectId=" + ManagementJson.Escape(projectId) +
            "&identityId=" + ManagementJson.Escape(identityId), new(organizationId, projectId, identityId), null,
            root => new(ManagementJson.Array(root, "privileges").Select(value => new IdentityPrivilegeSummary(value, includePermissions: false)), true), false);

    /// <summary>Builds an exact privilege lookup with returned permission metadata.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> GetProjectPrivilege(
        string organizationId, string projectId, string identityId, string privilegeId) =>
        new("infisical.get.v2.identity.project.additional.privilege.by.id", HttpMethod.Get,
            "/api/v2/identity-project-additional-privilege/" + ManagementJson.Escape(privilegeId),
            new(organizationId, projectId, identityId, privilegeId), null,
            root => new(ManagementJson.Object(root, "privilege"), privilegeId), false);

    /// <summary>Builds an exact privilege deletion request; retain a mutation receipt during execution.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> DeleteProjectPrivilege(
        string organizationId, string projectId, string identityId, string privilegeId) =>
        new("infisical.delete.v2.identity.project.additional.privilege.by.id", HttpMethod.Delete,
            "/api/v2/identity-project-additional-privilege/" + ManagementJson.Escape(privilegeId),
            new(organizationId, projectId, identityId, privilegeId), null,
            root => new(ManagementJson.Object(root, "privilege"), privilegeId));
}
