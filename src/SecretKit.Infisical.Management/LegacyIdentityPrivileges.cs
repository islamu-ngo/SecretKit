using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Independently selected v1 project/identity membership, including its native project slug.</summary>
public sealed class LegacyPrivilegeSelection
{
    /// <summary>Captures independently trusted organization, project, native slug, identity and membership coordinates.</summary>
    public LegacyPrivilegeSelection(string organizationId, string projectId, string projectSlug,
        string identityId, string membershipId)
    {
        foreach (string value in new[] { organizationId, projectId, projectSlug, identityId, membershipId })
            ManagementJson.Text(value);
        OrganizationId = organizationId;
        ProjectId = projectId;
        ProjectSlug = projectSlug;
        IdentityId = identityId;
        MembershipId = membershipId;
    }
    /// <summary>Gets the selected organization coordinate.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets the canonical project identifier, distinct from its native slug.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Gets the native project slug used by v1 privilege endpoints.</summary>
    [JsonIgnore] public string ProjectSlug { get; }
    /// <summary>Gets the selected machine-identity identifier.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets the expected project-membership identifier for response correspondence.</summary>
    [JsonIgnore] public string MembershipId { get; }

    /// <summary>Build grant intent from trusted host selection, never an incoming request target.</summary>
    public ManagementTarget GrantTarget(string? privilegeSlug = null)
    {
        if (privilegeSlug is not null) ManagementJson.Text(privilegeSlug);
        byte[] coordinates = JsonSerializer.SerializeToUtf8Bytes(new[] { ProjectSlug, MembershipId, privilegeSlug });
        try
        {
            return new(OrganizationId, ProjectId, IdentityId, Convert.ToHexString(SHA256.HashData(coordinates)));
        }
        finally { Array.Clear(coordinates); }
    }
    /// <summary>Returns a marker without trusted selection coordinates.</summary>
    public override string ToString() => "[LegacyPrivilegeSelection]";
}

/// <summary>Native v1 metadata and deletion; permission conditions remain unprojected.</summary>
public static class LegacyIdentityPrivilegeOperations
{
    /// <summary>Builds a disposable v1 inventory request with membership correspondence and duplicate rejection.</summary>
    public static ManagementRequest<ManagementPage<IdentityPrivilegeSummary>> ListPrivileges(LegacyPrivilegeSelection selection)
    {
        ArgumentNullException.ThrowIfNull(selection);
        return new("infisical.get.v1.additional.privilege.identity", HttpMethod.Get,
            "/api/v1/additional-privilege/identity?" + Query(selection), selection.GrantTarget(), null,
            root =>
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                return new(ManagementJson.Array(root, "privileges").Select(value =>
                {
                    IdentityPrivilegeSummary privilege = Parse(value, selection, null);
                    if (!seen.Add(privilege.Id)) throw new ManagementContractException(SecretStatus.Invalid);
                    return privilege;
                }), true);
            }, false);
    }

    /// <summary>Builds an exact v1 privilege-slug lookup for the selected membership.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> GetPrivilege(LegacyPrivilegeSelection selection, string privilegeSlug)
    {
        ArgumentNullException.ThrowIfNull(selection);
        return new("infisical.get.v1.additional.privilege.identity.by.privilegeSlug", HttpMethod.Get,
            "/api/v1/additional-privilege/identity/" + ManagementJson.Escape(privilegeSlug) + "?" + Query(selection),
            selection.GrantTarget(privilegeSlug), null,
            root => Parse(ManagementJson.Object(root, "privilege"), selection, privilegeSlug), false);
    }

    /// <summary>Builds a v1 deletion request bound to the selected membership and privilege slug; does not execute it.</summary>
    public static ManagementRequest<IdentityPrivilegeSummary> DeletePrivilege(LegacyPrivilegeSelection selection, string privilegeSlug)
    {
        ArgumentNullException.ThrowIfNull(selection);
        ManagementJson.Text(privilegeSlug);
        return new("infisical.delete.v1.additional.privilege.identity", HttpMethod.Delete,
            "/api/v1/additional-privilege/identity", selection.GrantTarget(privilegeSlug), writer =>
            {
                writer.WriteStartObject();
                writer.WriteString("identityId", selection.IdentityId);
                writer.WriteString("projectSlug", selection.ProjectSlug);
                writer.WriteString("privilegeSlug", privilegeSlug);
                writer.WriteEndObject();
            }, root => Parse(ManagementJson.Object(root, "privilege"), selection, privilegeSlug));
    }

    private static IdentityPrivilegeSummary Parse(JsonElement value, LegacyPrivilegeSelection selection, string? slug)
    {
        ManagementJson.RequireEqual(value, "projectMembershipId", selection.MembershipId);
        if (slug is not null) ManagementJson.RequireEqual(value, "slug", slug);
        ManagementJson.Required(value, "createdAt");
        ManagementJson.Required(value, "updatedAt");
        ManagementJson.Array(value, "permissions");
        // Permission payloads can contain unestablished condition nodes. Do not export or interpret them.
        return new(value);
    }

    private static string Query(LegacyPrivilegeSelection selection) =>
        "identityId=" + ManagementJson.Escape(selection.IdentityId) + "&projectSlug=" + ManagementJson.Escape(selection.ProjectSlug);
}

internal interface ILegacyIdentityPrivilegeApi
{
    [Get("/api/v1/additional-privilege/identity")]
    Task<HttpRequestMessage> List([AliasAs("identityId")] string identityId,
        [AliasAs("projectSlug")] string projectSlug, CancellationToken cancellationToken);
    [Get("/api/v1/additional-privilege/identity/{privilegeSlug}")]
    Task<HttpRequestMessage> Get(string privilegeSlug, [AliasAs("identityId")] string identityId,
        [AliasAs("projectSlug")] string projectSlug, CancellationToken cancellationToken);
    [Delete("/api/v1/additional-privilege/identity")]
    Task<HttpRequestMessage> Delete([Body] HttpContent body, CancellationToken cancellationToken);
}
