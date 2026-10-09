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

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public string Role { get; }
    [JsonIgnore] public string? UserId { get; }
    [JsonIgnore] public string? RoleId { get; }
    [JsonIgnore] public string? Status { get; }
    [JsonIgnore] public string? InviteEmail { get; }
    [JsonIgnore] public bool? IsActive { get; }
    [JsonIgnore] public string? CreatedAt { get; }
    [JsonIgnore] public string? UpdatedAt { get; }
    [JsonIgnore] public OrganizationMembershipUser? User { get; }
    public bool IncludesPermissions => false;
    public override string ToString() => "[OrganizationMembershipSummary]";
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
    }

    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Username { get; }
    [JsonIgnore] public string? Email { get; }
    [JsonIgnore] public string? FirstName { get; }
    [JsonIgnore] public string? LastName { get; }
    public override string ToString() => "[OrganizationMembershipUser]";
}

public static class OrganizationMembershipOperations
{
    /// <summary>The native endpoint is unpaginated; oversized collections fail closed, never truncate.</summary>
    public static ManagementRequest<ManagementPage<OrganizationMembershipSummary>> ListOrganizationMemberships(
        string organizationId) =>
        new("infisical.get.v2.organizations.by.organizationId.memberships", HttpMethod.Get,
            MembershipPath(organizationId), new(organizationId), null,
            root => new(ManagementJson.Array(root, "users")
                .Select(value => new OrganizationMembershipSummary(value, organizationId)), true), false);

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
        return new("infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId",
            HttpMethod.Patch, MembershipPath(organizationId, membershipId),
            new(organizationId, resourceId: membershipId), writer =>
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
            }, root => new(ManagementJson.Object(root, "membership"), organizationId, membershipId));
    }

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
