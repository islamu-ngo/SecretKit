using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native organization membership metadata, not effective-permission evidence.</summary>
public sealed class OrganizationMembershipSummary
{
    internal OrganizationMembershipSummary(JsonElement value, string organizationId, string? membershipId = null)
    {
        ManagementJson.RequireEqual(value, "orgId", organizationId);
        if (membershipId is not null) ManagementJson.RequireEqual(value, "id", membershipId);
        Id = ManagementJson.Required(value, "id");
        OrganizationId = organizationId;
        Role = ManagementJson.Required(value, "role");
        UserId = ManagementJson.Optional(value, "userId");
        RoleId = ManagementJson.Optional(value, "roleId");
        Status = ManagementJson.Optional(value, "status");
        InviteEmail = ManagementJson.Optional(value, "inviteEmail");
        IsActive = value.TryGetProperty("isActive", out _) ? ManagementJson.Boolean(value, "isActive") : null;
        LastInvitedAt = DateField(value, "lastInvitedAt");
        LastLoginAuthMethod = ProjectWire.StringField(value, "lastLoginAuthMethod", nullable: true);
        LastLoginTime = DateField(value, "lastLoginTime");
        ProjectFavorites = ProjectWire.Collection(value, "projectFavorites", ProjectWire.String, nullable: true);
        if (membershipId is not null)
        {
            CreatedAt = ManagementJson.Required(value, "createdAt");
            UpdatedAt = ManagementJson.Required(value, "updatedAt");
        }
        else
        {
            JsonElement user = ManagementJson.Object(value, "user");
            string id = ManagementJson.Required(user, "id");
            if (UserId is not null && UserId != id) throw new ManagementContractException(SecretStatus.Invalid);
            User = new OrganizationMembershipUser(user);
        }
    }

    /// <summary>Gets the returned membership identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the organization coordinate verified against the selection.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets the returned role label, not an effective-permission decision.</summary>
    [JsonIgnore] public string Role { get; }
    /// <summary>Gets the user coordinate, or null when not supplied.</summary>
    [JsonIgnore] public string? UserId { get; }
    /// <summary>Gets the role coordinate, or null when absent or explicitly null.</summary>
    [JsonIgnore] public string? RoleId { get; }
    /// <summary>Gets the native membership status, or null when not supplied.</summary>
    [JsonIgnore] public string? Status { get; }
    /// <summary>Gets the invitation email, or null when not supplied.</summary>
    [JsonIgnore] public string? InviteEmail { get; }
    /// <summary>Gets the returned active flag, or null when omitted.</summary>
    [JsonIgnore] public bool? IsActive { get; }
    /// <summary>Gets the mutation response creation timestamp, or null for inventory projections.</summary>
    [JsonIgnore] public string? CreatedAt { get; }
    /// <summary>Gets the mutation response update timestamp, or null for inventory projections.</summary>
    [JsonIgnore] public string? UpdatedAt { get; }
    /// <summary>Gets last-invitation timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> LastInvitedAt { get; }
    /// <summary>Gets last-login method presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> LastLoginAuthMethod { get; }
    /// <summary>Gets last-login timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> LastLoginTime { get; }
    /// <summary>Gets favorite-project presence; an empty list differs from absence or null.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> ProjectFavorites { get; }
    /// <summary>Gets the inventory user projection, or null for mutation responses.</summary>
    [JsonIgnore] public OrganizationMembershipUser? User { get; }
    /// <summary>Always false: membership metadata does not include effective permissions.</summary>
    public bool IncludesPermissions => false;
    /// <summary>Returns a marker without membership, email or user details.</summary>
    public override string ToString() => "[OrganizationMembershipSummary]";

    private static ProjectField<string> DateField(JsonElement value, string field)
    {
        var result = ProjectWire.StringField(value, field, nullable: true);
        if (result.IsPresent && !result.IsNull)
            ManagementResponseDates.ValidateDateValue(value.GetProperty(field));
        return result;
    }
}

/// <summary>Protected user projection returned by organization membership inventory.</summary>
public sealed class OrganizationMembershipUser
{
    internal OrganizationMembershipUser(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Username = ManagementJson.Required(value, "username");
        Email = ManagementJson.Optional(value, "email");
        FirstName = ManagementJson.Optional(value, "firstName");
        LastName = ManagementJson.Optional(value, "lastName");
        AuthMethods = ProjectWire.Collection(value, "authMethods", ProjectWire.String, nullable: true);
        IsEmailVerified = ProjectWire.BooleanField(value, "isEmailVerified", nullable: true);
        PublicKey = ProjectWire.StringField(value, "publicKey", nullable: true);
    }

    /// <summary>Gets the returned user identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned username.</summary>
    [JsonIgnore] public string Username { get; }
    /// <summary>Gets the returned email, or null when omitted or explicitly null.</summary>
    [JsonIgnore] public string? Email { get; }
    /// <summary>Gets the returned given name, or null when not supplied.</summary>
    [JsonIgnore] public string? FirstName { get; }
    /// <summary>Gets the returned family name, or null when not supplied.</summary>
    [JsonIgnore] public string? LastName { get; }
    /// <summary>Gets authentication-method presence without proving login capability.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AuthMethods { get; }
    /// <summary>Gets email-verification presence; absent or null is not a false value.</summary>
    [JsonIgnore] public ProjectField<bool> IsEmailVerified { get; }
    /// <summary>Gets public-key presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> PublicKey { get; }
    /// <summary>Returns a marker without protected user metadata.</summary>
    public override string ToString() => "[OrganizationMembershipUser]";
}

/// <summary>Constructs disposable organization membership requests under separately selected authority.</summary>
public static class OrganizationMembershipOperations
{
    /// <summary>The native endpoint is unpaginated; oversized collections fail closed, never truncate.</summary>
    public static ManagementRequest<ManagementPage<OrganizationMembershipSummary>> ListOrganizationMemberships(
        string organizationId) =>
        new("infisical.get.v2.organizations.by.organizationId.memberships", HttpMethod.Get,
            MembershipPath(organizationId), new(organizationId), null,
            root => new(ManagementJson.Array(root, "users")
                .Select(value => new OrganizationMembershipSummary(value, organizationId)), true), false);

    /// <summary>Builds a membership change; null omits each field and empty metadata is explicit.</summary>
    public static ManagementRequest<OrganizationMembershipSummary> UpdateOrganizationMembership(
        string organizationId, string membershipId, string? role = null, bool? isActive = null,
        IReadOnlyList<IdentityAttribute>? metadata = null)
    {
        ManagementJson.Text(membershipId);
        if (role is null && isActive is null && metadata is null)
            throw new ArgumentException("An organization membership change is required.");
        if (role is not null) ManagementJson.Text(role, 255);
        IdentityAttribute[]? copy = metadata?.Take(101).ToArray();
        if (copy is not null && (copy.Length > 100 || copy.Any(item => item is null)))
            throw new ArgumentException("Invalid membership metadata budget.");
        void Write(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            if (role is not null) writer.WriteString("role", role);
            if (isActive is { } active) writer.WriteBoolean("isActive", active);
            if (copy is not null)
            {
                writer.WriteStartArray("metadata");
                foreach (IdentityAttribute item in copy)
                {
                    writer.WriteStartObject();
                    writer.WriteString("key", item.Key);
                    writer.WriteString("value", item.Value);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            }
            writer.WriteEndObject();
        }
        return new("infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId",
            HttpMethod.Patch, MembershipPath(organizationId, membershipId),
            ProjectWire.Intent(organizationId, null, membershipId, Write), Write,
            root => new(ManagementJson.Object(root, "membership"), organizationId, membershipId));
    }

    /// <summary>Builds independently selected approval intent for the complete membership update body.</summary>
    public static ManagementTarget OrganizationMembershipUpdateTarget(string organizationId, string membershipId,
        string? role = null, bool? isActive = null, IReadOnlyList<IdentityAttribute>? metadata = null)
    {
        using var request = UpdateOrganizationMembership(organizationId, membershipId, role, isActive, metadata);
        return request.Target;
    }

    /// <summary>Builds deletion of one exact membership; retain the caller receipt during uncertain execution.</summary>
    public static ManagementRequest<OrganizationMembershipSummary> DeleteOrganizationMembership(
        string organizationId, string membershipId)
    {
        ManagementJson.Text(membershipId);
        return new("infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId",
            HttpMethod.Delete, MembershipPath(organizationId, membershipId),
            new(organizationId, resourceId: membershipId), null,
            root => new(ManagementJson.Object(root, "membership"), organizationId, membershipId));
    }

    private static string MembershipPath(string organizationId, string? membershipId = null) =>
        "/api/v2/organizations/" + ManagementJson.Escape(organizationId) + "/memberships" +
        (membershipId is null ? "" : "/" + ManagementJson.Escape(membershipId));
}
