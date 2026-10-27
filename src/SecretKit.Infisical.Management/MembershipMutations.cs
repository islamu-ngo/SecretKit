using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Copied, bounded native project-member selectors; neither list is a wildcard.</summary>
public sealed class MembershipPrincipals
{
    /// <summary>Copies one to 128 unique email or username selectors; null contributes no selectors.</summary>
    public MembershipPrincipals(IReadOnlyList<string>? emails = null, IReadOnlyList<string>? usernames = null)
    {
        string[] emailCopy = MembershipMutationOperations.Copy(emails ?? [], 128);
        string[] usernameCopy = MembershipMutationOperations.Copy(usernames ?? [], 128);
        if (emailCopy.Length + usernameCopy.Length is < 1 or > 128)
            throw new ArgumentException("One to one hundred twenty-eight principals are required.");
        if (emailCopy.Any(email => !System.Net.Mail.MailAddress.TryCreate(email, out var address) ||
            address.Address != email))
            throw new ArgumentException("Invalid membership email selector.");
        Emails = Array.AsReadOnly(emailCopy);
        Usernames = Array.AsReadOnly(usernameCopy);
    }

    /// <summary>Gets the copied explicit email selectors, never a wildcard.</summary>
    [JsonIgnore] public IReadOnlyList<string> Emails { get; }
    /// <summary>Gets the copied explicit username selectors, never a wildcard.</summary>
    [JsonIgnore] public IReadOnlyList<string> Usernames { get; }
    /// <summary>Returns a marker without principal selectors.</summary>
    public override string ToString() => "[MembershipPrincipals]";
}

/// <summary>Native changed project membership metadata; no returned selector or assigned-role attestation.</summary>
public sealed class ProjectMembershipMutationSummary
{
    internal ProjectMembershipMutationSummary(JsonElement value, string organizationId, string projectId)
    {
        ManagementJson.RequireEqual(value, "projectId", projectId);
        string? org = ManagementJson.Optional(value, "orgId");
        if (org is not null && org != organizationId) throw new ManagementContractException(SecretStatus.Invalid);
        Id = ManagementJson.Required(value, "id");
        UserId = ManagementJson.Required(value, "userId");
        ProjectId = projectId;
        CreatedAt = ManagementJson.Required(value, "createdAt");
        UpdatedAt = ManagementJson.Required(value, "updatedAt");
    }

    /// <summary>Gets the returned changed membership identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned user coordinate without claiming correspondence to each input selector.</summary>
    [JsonIgnore] public string UserId { get; }
    /// <summary>Gets the returned project identifier matched to the request.</summary>
    [JsonIgnore] public string ProjectId { get; }
    /// <summary>Gets the returned creation timestamp.</summary>
    [JsonIgnore] public string CreatedAt { get; }
    /// <summary>Gets the returned update timestamp.</summary>
    [JsonIgnore] public string UpdatedAt { get; }
    /// <summary>Returns a marker without changed-member metadata.</summary>
    public override string ToString() => "[ProjectMembershipMutationSummary]";
}

/// <summary>Constructs disposable membership mutations; execution requires exact host grants and retained receipts.</summary>
public static class MembershipMutationOperations
{
    /// <summary>Omitted role slugs retain the provider default; an explicit empty role list is invalid.</summary>
    public static ManagementRequest<ManagementPage<ProjectMembershipMutationSummary>> InviteProjectMembers(
        string organizationId, string projectId, MembershipPrincipals principals, IReadOnlyList<string>? roleSlugs = null)
    {
        ArgumentNullException.ThrowIfNull(principals);
        string[]? roles = Roles(roleSlugs);
        return new("infisical.post.v1.projects.by.projectId.memberships", HttpMethod.Post,
            ProjectOperations.ProjectPath(projectId) + "/memberships",
            ProjectTarget(organizationId, projectId, principals, roles),
            writer => WritePrincipals(writer, principals, roles),
            root => ProjectResponse(root, organizationId, projectId));
    }

    /// <summary>Builds removal of explicitly selected project principals; returned rows are not per-input success guarantees.</summary>
    public static ManagementRequest<ManagementPage<ProjectMembershipMutationSummary>> RemoveProjectMembers(
        string organizationId, string projectId, MembershipPrincipals principals)
    {
        ArgumentNullException.ThrowIfNull(principals);
        return new("infisical.delete.v1.projects.by.projectId.memberships", HttpMethod.Delete,
            ProjectOperations.ProjectPath(projectId) + "/memberships",
            ProjectTarget(organizationId, projectId, principals, null),
            writer => WritePrincipals(writer, principals, null),
            root => ProjectResponse(root, organizationId, projectId));
    }

    /// <summary>Bounded native bulk deletion, not a transaction or per-input success guarantee.</summary>
    public static ManagementRequest<ManagementPage<OrganizationMembershipSummary>> DeleteOrganizationMemberships(
        string organizationId, IReadOnlyList<string> membershipIds)
    {
        string[] ids = Ids(membershipIds);
        return new("infisical.delete.v2.organizations.by.organizationId.memberships", HttpMethod.Delete,
            "/api/v2/organizations/" + ManagementJson.Escape(organizationId) + "/memberships",
            OrganizationTarget(organizationId, ids), writer =>
            {
                writer.WriteStartObject();
                WriteStrings(writer, "membershipIds", ids);
                writer.WriteEndObject();
            }, root =>
            {
                var seen = new HashSet<string>(StringComparer.Ordinal);
                return new(ManagementJson.Array(root, "memberships").Select(value =>
                {
                    string id = ManagementJson.Required(value, "id");
                    if (!ids.Contains(id, StringComparer.Ordinal) || !seen.Add(id))
                        throw new ManagementContractException(SecretStatus.Invalid);
                    return new OrganizationMembershipSummary(value, organizationId, id);
                }), true);
            });
    }

    /// <summary>
    /// Build host grant intent from independently selected scope, selectors and roles.
    /// Do not derive authorization from an incoming request's Target.
    /// </summary>
    public static ManagementTarget InvitationTarget(string organizationId, string projectId,
        MembershipPrincipals principals, IReadOnlyList<string>? roleSlugs = null)
    {
        ArgumentNullException.ThrowIfNull(principals);
        return ProjectTarget(organizationId, projectId, principals, Roles(roleSlugs));
    }

    /// <summary>Builds independent host intent for the complete ordered project-principal removal selection.</summary>
    public static ManagementTarget ProjectDeletionTarget(string organizationId, string projectId,
        MembershipPrincipals principals)
    {
        ArgumentNullException.ThrowIfNull(principals);
        return ProjectTarget(organizationId, projectId, principals, null);
    }

    /// <summary>Builds independent host intent for the complete ordered organization membership deletion batch.</summary>
    public static ManagementTarget OrganizationDeletionTarget(string organizationId,
        IReadOnlyList<string> membershipIds) => OrganizationTarget(organizationId, Ids(membershipIds));

    private static ManagementTarget ProjectTarget(string org, string project, MembershipPrincipals principals,
        string[]? roles) => new(org, project, Fingerprint(principals.Emails, principals.Usernames, roles));

    private static ManagementTarget OrganizationTarget(string org, string[] ids) =>
        new(org, resourceId: Fingerprint(ids, [], null));

    // Length-framed fields and explicit absence bind the complete ordered batch intent,
    // including invitation role default versus explicit role selection.
    private static string Fingerprint(IReadOnlyList<string> first, IReadOnlyList<string> second,
        IReadOnlyList<string>? third)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        foreach (IReadOnlyList<string>? list in new[] { first, second, third })
        {
            BinaryPrimitives.WriteInt32BigEndian(length, list?.Count ?? -1);
            hash.AppendData(length);
            if (list is null) continue;
            foreach (string item in list)
            {
                byte[] bytes = Encoding.UTF8.GetBytes(item);
                try
                {
                    BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
                    hash.AppendData(length);
                    hash.AppendData(bytes);
                }
                finally { Array.Clear(bytes); }
            }
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }

    internal static string[] Copy(IReadOnlyList<string> values, int maximum)
    {
        ArgumentNullException.ThrowIfNull(values);
        string[] copy = values.Take(maximum + 1).ToArray();
        if (copy.Length > maximum) throw new ArgumentException("Invalid membership collection budget.");
        foreach (string value in copy) ManagementJson.Text(value, 255);
        if (copy.Distinct(StringComparer.Ordinal).Count() != copy.Length)
            throw new ArgumentException("Duplicate membership input.");
        return copy;
    }

    private static string[] Ids(IReadOnlyList<string> values)
    {
        string[] copy = Copy(values, 128);
        if (copy.Length == 0) throw new ArgumentException("A membership selection is required.");
        return copy;
    }

    private static string[]? Roles(IReadOnlyList<string>? values)
    {
        if (values is null) return null;
        string[] roles = Copy(values, 100);
        if (roles.Length == 0) throw new ArgumentException("An explicit role selection cannot be empty.");
        return roles;
    }

    private static ManagementPage<ProjectMembershipMutationSummary> ProjectResponse(JsonElement root,
        string organizationId, string projectId)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        return new(ManagementJson.Array(root, "memberships").Select(value =>
        {
            var row = new ProjectMembershipMutationSummary(value, organizationId, projectId);
            if (!seen.Add(row.Id)) throw new ManagementContractException(SecretStatus.Invalid);
            return row;
        }), true);
    }

    private static void WritePrincipals(Utf8JsonWriter writer, MembershipPrincipals principals, string[]? roles)
    {
        writer.WriteStartObject();
        WriteStrings(writer, "emails", principals.Emails);
        WriteStrings(writer, "usernames", principals.Usernames);
        if (roles is not null) WriteStrings(writer, "roleSlugs", roles);
        writer.WriteEndObject();
    }

    private static void WriteStrings(Utf8JsonWriter writer, string name, IReadOnlyList<string> values)
    {
        writer.WriteStartArray(name);
        foreach (string value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }
}
