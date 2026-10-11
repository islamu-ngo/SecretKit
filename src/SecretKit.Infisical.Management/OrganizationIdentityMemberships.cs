using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;

namespace SecretKit.Infisical.Management;

public enum OrganizationIdentityOrder { Name, Role }

/// <summary>Organization membership metadata, not authentication material or effective permissions.</summary>
public sealed class OrganizationIdentityMembershipSummary
{
    internal OrganizationIdentityMembershipSummary(JsonElement value, string organizationId)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        Id = ManagementJson.Required(value, "id");
        IdentityId = ManagementJson.Required(value, "identityId");
        Role = ManagementJson.Required(value, "role");
        RoleId = ManagementJson.Optional(value, "roleId");
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
        LastLoginAuthMethod = ManagementJson.Optional(value, "lastLoginAuthMethod");
        LastLoginTime = ManagementJson.Optional(value, "lastLoginTime");
        RoleIdField = IdentityMetadataWire.StringField(value, "roleId", nullable: true);
        LastLoginAuthMethodField = IdentityMetadataWire.StringField(value, "lastLoginAuthMethod", nullable: true);
        LastLoginTimeField = IdentityMetadataWire.StringField(value, "lastLoginTime", nullable: true);
        CustomRole = IdentityMetadataWire.Field(value, "customRole", child => new IdentityCustomRoleMetadata(child));
        Identity = new IdentitySummary(ManagementJson.Object(value, "identity"), organizationId, id: IdentityId,
            requireAuthMethods: true);
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string IdentityId { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public string? RoleId { get; }
    [JsonIgnore] public string CreatedAt { get; }
    [JsonIgnore] public string UpdatedAt { get; }
    [JsonIgnore] public string? LastLoginAuthMethod { get; }
    [JsonIgnore] public string? LastLoginTime { get; }
    [JsonIgnore] public IdentityField<string> RoleIdField { get; }
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethodField { get; }
    [JsonIgnore] public IdentityField<string> LastLoginTimeField { get; }
    [JsonIgnore] public IdentityField<IdentityCustomRoleMetadata> CustomRole { get; }
    [JsonIgnore] public IdentitySummary Identity { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[OrganizationIdentityMembershipSummary]";
}

public static class OrganizationIdentityMembershipOperations
{
    public static ManagementRequest<ManagementPage<OrganizationIdentityMembershipSummary>> ListOrganizationIdentityMemberships(
        string organizationId, int offset = 0, int limit = 100,
        OrganizationIdentityOrder orderBy = OrganizationIdentityOrder.Name,
        ManagementListOrder order = ManagementListOrder.Ascending, string? search = null)
    {
        string column = orderBy switch
        {
            OrganizationIdentityOrder.Name => "name",
            OrganizationIdentityOrder.Role => "role",
            _ => throw new ArgumentOutOfRangeException(nameof(orderBy))
        };
        string direction = order switch
        {
            ManagementListOrder.Ascending => "asc",
            ManagementListOrder.Descending => "desc",
            _ => throw new ArgumentOutOfRangeException(nameof(order))
        };
        string query = ManagementJson.Paging(offset, limit) + "&orderBy=" + column + "&orderDirection=" + direction;
        if (search is not null) query += "&search=" + ManagementJson.Escape(search);
        return new("infisical.get.v2.organizations.by.orgId.identity.memberships", HttpMethod.Get,
            "/api/v2/organizations/" + ManagementJson.Escape(organizationId) + "/identity-memberships?" + query,
            new(organizationId), null,
            root => ScopedAccessOperations.CountedPage(root, "identityMemberships",
                value => new OrganizationIdentityMembershipSummary(value, organizationId), offset, limit), false);
    }
}

internal interface IOrganizationIdentityMembershipApi
{
    [Get("/api/v2/organizations/{orgId}/identity-memberships")]
    Task<HttpRequestMessage> List(string orgId, int offset, int limit, string orderBy,
        string orderDirection, string? search, CancellationToken cancellationToken);
}

internal static class InventorySelectorWire
{
    internal static string Escape(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length > 1024 || value.Any(char.IsControl))
            throw new ArgumentException("Invalid protected inventory selector.");
        return Uri.EscapeDataString(value);
    }

    internal static ManagementTarget Intent(string organizationId, string? projectId, string query,
        bool? roleArray = null, string? resourceId = null)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new { query, roleArray });
        try
        {
            return new(organizationId, projectId, resourceId,
                secondaryId: Convert.ToHexString(SHA256.HashData(bytes)));
        }
        finally { System.Array.Clear(bytes); }
    }
}
