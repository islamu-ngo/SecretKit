using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Refit;

namespace SecretKit.Infisical.Management;

/// <summary>Native sort columns for organization machine-identity membership inventory.</summary>
public enum OrganizationIdentityOrder { /** <summary>Sorts by identity display name.</summary> */ Name, /** <summary>Sorts by assigned role label.</summary> */ Role }

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

    /// <summary>Gets the returned organization membership identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned nested identity coordinate.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets the returned role label, not effective permissions.</summary>
    [JsonIgnore] public string Role { get; }
    /// <summary>Gets the role identifier, or null when omitted or explicitly null.</summary>
    [JsonIgnore] public string? RoleId { get; }
    /// <summary>Gets the returned membership creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned membership update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Gets the last-login method, or null when omitted or explicitly null.</summary>
    [JsonIgnore] public string? LastLoginAuthMethod { get; }
    /// <summary>Gets the last-login time, or null when omitted or explicitly null.</summary>
    [JsonIgnore] public string? LastLoginTime { get; }
    /// <summary>Gets role-identifier presence to distinguish omission from explicit null.</summary>
    [JsonIgnore] public IdentityField<string> RoleIdField { get; }
    /// <summary>Gets last-login method presence, preserving explicit null.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginAuthMethodField { get; }
    /// <summary>Gets last-login time presence, preserving explicit null.</summary>
    [JsonIgnore] public IdentityField<string> LastLoginTimeField { get; }
    /// <summary>Gets custom-role metadata when supplied, without permission values.</summary>
    [JsonIgnore] public IdentityField<IdentityCustomRoleMetadata> CustomRole { get; }
    /// <summary>Gets identity metadata whose identifier matches this membership.</summary>
    [JsonIgnore] public IdentitySummary Identity { get; }
    /// <summary>Always false: membership inventory does not export effective permissions.</summary>
    public bool IncludesPermissions => false;
    /// <summary>Returns a marker without membership or identity details.</summary>
    public override string ToString() => "[OrganizationIdentityMembershipSummary]";
}

/// <summary>Constructs disposable organization identity inventory requests and independent approval targets.</summary>
public static class OrganizationIdentityMembershipOperations
{
    /// <summary>Builds a count-validated inventory page with exact paging, search and order intent; does not acquire credentials.</summary>
    public static ManagementRequest<ManagementPage<OrganizationIdentityMembershipSummary>> ListOrganizationIdentityMemberships(
        string organizationId, int offset = 0, int limit = 100,
        OrganizationIdentityOrder orderBy = OrganizationIdentityOrder.Name,
        ManagementListOrder order = ManagementListOrder.Ascending, string? search = null)
    {
        string query = OrganizationIdentityMembershipQuery(offset, limit, orderBy, order, search);
        return new("infisical.get.v2.organizations.by.orgId.identity.memberships", HttpMethod.Get,
            "/api/v2/organizations/" + ManagementJson.Escape(organizationId) + "/identity-memberships?" + query,
            InventorySelectorWire.Intent(organizationId, null, query), null,
            root => ScopedAccessOperations.CountedPage(root, "identityMemberships",
                value => new OrganizationIdentityMembershipSummary(value, organizationId), offset, limit), false);
    }

    /// <summary>Independently select the organization and every paging, search and order input.</summary>
    public static ManagementTarget OrganizationIdentityMembershipListTarget(
        string organizationId, int offset = 0, int limit = 100,
        OrganizationIdentityOrder orderBy = OrganizationIdentityOrder.Name,
        ManagementListOrder order = ManagementListOrder.Ascending, string? search = null) =>
        InventorySelectorWire.Intent(organizationId, null,
            OrganizationIdentityMembershipQuery(offset, limit, orderBy, order, search));

    private static string OrganizationIdentityMembershipQuery(int offset, int limit,
        OrganizationIdentityOrder orderBy, ManagementListOrder order, string? search)
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
        if (search is not null) query += "&search=" + InventorySelectorWire.Escape(search);
        return query;
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
