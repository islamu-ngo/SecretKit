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
    /// <summary>Gets the returned user identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned native username.</summary>
    [JsonIgnore] public string Username { get; }
    /// <summary>Gets email presence, preserving absent and explicit null.</summary>
    [JsonIgnore] public ProjectField<string> Email { get; }
    /// <summary>Gets given-name presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> FirstName { get; }
    /// <summary>Gets family-name presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> LastName { get; }
    /// <summary>Gets public-key presence without inferring a key when omitted.</summary>
    [JsonIgnore] public ProjectField<string> PublicKey { get; }
    /// <summary>Gets verification-flag presence; absent or null is not false.</summary>
    [JsonIgnore] public ProjectField<bool> IsEmailVerified { get; }
    /// <summary>Gets returned authentication-method presence; metadata is not login evidence.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AuthMethods { get; }
    /// <summary>Returns a marker without user metadata.</summary>
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
    /// <summary>Gets the nested group identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the required returned group name with presence information.</summary>
    [JsonIgnore] public ProjectField<string> Name { get; }
    /// <summary>Gets the required native group slug with presence information.</summary>
    [JsonIgnore] public ProjectField<string> Slug { get; }
    /// <summary>Gets the group owner organization when returned.</summary>
    [JsonIgnore] public ProjectField<string> OrganizationId { get; }
    /// <summary>Returns a marker without group details.</summary>
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
    /// <summary>Gets the returned attribute-entry identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the protected attribute key.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>Gets the protected attribute value.</summary>
    [JsonIgnore] public string Value { get; }
    /// <summary>Returns a marker without attribute contents.</summary>
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
    /// <summary>Gets the returned identity organization coordinate.</summary>
    [JsonIgnore] public string OrganizationId { get; }
    /// <summary>Gets project-field presence, including explicit null.</summary>
    [JsonIgnore] public ProjectField<string> ProjectId { get; }
    /// <summary>Gets returned authentication methods; does not attest authentication capability.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AuthMethods { get; }
    /// <summary>Gets returned lockout methods for list responses; detail responses leave this absent.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> ActiveLockoutAuthMethods { get; }
    /// <summary>Gets returned detail attributes; list responses leave this absent.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<MembershipIdentityAttribute>> Attributes { get; }
    /// <summary>Returns a marker without identity or authentication metadata.</summary>
    public override string ToString() => "[MembershipIdentityMetadata]";
}
