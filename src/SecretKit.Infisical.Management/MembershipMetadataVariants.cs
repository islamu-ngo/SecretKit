using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Protected project-membership user fields, without inferred verification defaults.</summary>
public sealed class ProjectMembershipUser
{
    internal ProjectMembershipUser(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Username = ManagementJson.Required(value, "username");
        Email = ProjectWire.StringField(value, "email", nullable: true);
        FirstName = ProjectWire.StringField(value, "firstName", nullable: true);
        LastName = ProjectWire.StringField(value, "lastName", nullable: true);
        PublicKey = ProjectWire.StringField(value, "publicKey", nullable: true);
        IsEmailVerified = ProjectWire.BooleanField(value, "isEmailVerified", nullable: true);
        AuthMethods = ProjectWire.Collection(value, "authMethods", ProjectWire.String, nullable: true);
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Username { get; }
    [JsonIgnore] public ProjectField<string> Email { get; }
    [JsonIgnore] public ProjectField<string> FirstName { get; }
    [JsonIgnore] public ProjectField<string> LastName { get; }
    [JsonIgnore] public ProjectField<string> PublicKey { get; }
    [JsonIgnore] public ProjectField<bool> IsEmailVerified { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AuthMethods { get; }
    public override string ToString() => "[ProjectMembershipUser]";
}

/// <summary>Group details returned inside a membership, not the organization group endpoint schema.</summary>
public sealed class MembershipGroupDetails
{
    internal MembershipGroupDetails(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Name = ProjectWire.StringField(value, "name");
        Slug = ProjectWire.StringField(value, "slug");
        if (!Name.IsPresent || !Slug.IsPresent)
            throw new ManagementContractException(SecretStatus.Unknown);
        OrganizationId = ProjectWire.StringField(value, "orgId");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public ProjectField<string> Name { get; }
    [JsonIgnore] public ProjectField<string> Slug { get; }
    [JsonIgnore] public ProjectField<string> OrganizationId { get; }
    public override string ToString() => "[MembershipGroupDetails]";
}

/// <summary>Copied identity attributes returned by the project identity membership detail endpoint.</summary>
public sealed class MembershipIdentityAttribute
{
    internal MembershipIdentityAttribute(JsonElement value)
    {
        Id = ManagementJson.Required(value, "id");
        Key = ManagementJson.Required(value, "key");
        Value = ManagementJson.Required(value, "value");
    }
    [JsonIgnore] public string Id { get; }
    [JsonIgnore] public string Key { get; }
    [JsonIgnore] public string Value { get; }
    public override string ToString() => "[MembershipIdentityAttribute]";
}

/// <summary>Endpoint-specific identity metadata. Detail responses do not attest lockout methods.</summary>
public sealed class MembershipIdentityMetadata
{
    internal MembershipIdentityMetadata(JsonElement value, bool details)
    {
        OrganizationId = ManagementJson.Required(value, "orgId");
        ProjectId = ProjectWire.StringField(value, "projectId", nullable: true);
        AuthMethods = ProjectWire.Collection(value, "authMethods", ProjectWire.String);
        if (details)
            Attributes = ProjectWire.Collection(value, "metadata", item => new MembershipIdentityAttribute(item));
        else
            ActiveLockoutAuthMethods = ProjectWire.Collection(value, "activeLockoutAuthMethods", ProjectWire.String);
        if (!AuthMethods.IsPresent || !details && !ActiveLockoutAuthMethods.IsPresent)
            throw new ManagementContractException(Core.SecretStatus.Unknown);
    }
    [JsonIgnore] public string OrganizationId { get; }
    [JsonIgnore] public ProjectField<string> ProjectId { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AuthMethods { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> ActiveLockoutAuthMethods { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<MembershipIdentityAttribute>> Attributes { get; }
    public override string ToString() => "[MembershipIdentityMetadata]";
}
