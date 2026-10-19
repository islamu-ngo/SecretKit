using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class MembershipMetadataVariantTests
{
    private const string Membership = "30000000-0000-4000-8000-000000000003";
    private const string GroupId = "40000000-0000-4000-8000-000000000004";
    private const string IdentityId = "20000000-0000-4000-8000-000000000002";
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string UserId = "50000000-0000-4000-8000-000000000005";
    private const string RoleId = "60000000-0000-4000-8000-000000000006";

    private const string Time = "2026-10-10T00:00:00Z";

    [Test]
    [Arguments("identity-add")]
    [Arguments("identity-update")]
    [Arguments("identity-delete")]
    [Arguments("group-delete")]
    [Arguments("org-group-delete")]
    public async Task PrimitiveMutationResultsKeepTimestampsWithoutInventedDetails(string route)
    {
        bool group = route.Contains("group", StringComparison.Ordinal);
        var row = new Dictionary<string, object?>
        {
            ["id"] = Membership,
            [group ? "groupId" : "identityId"] = group ? GroupId : IdentityId,
            ["createdAt"] = Time,
            ["updatedAt"] = Time
        };
        row[route == "org-group-delete" ? "orgId" : "projectId"] = route == "org-group-delete" ? Org : "project";
        using var request = route switch
        {
            "identity-add" => MembershipOperations.AddProjectIdentity(Org, "project", IdentityId, new MembershipRoleSelection()),
            "identity-update" => MembershipOperations.UpdateProjectIdentityRoles(Org, "project", IdentityId, [new("viewer")]),
            "identity-delete" => MembershipOperations.RemoveProjectIdentity(Org, "project", IdentityId),
            "group-delete" => MembershipOperations.RemoveProjectGroup(Org, "project", GroupId),
            _ => MembershipOperations.RemoveOrganizationGroup(Org, GroupId)
        };
        string body = JsonSerializer.Serialize(new Dictionary<string, object?> { [group ? "groupMembership" : "identityMembership"] = row });
        var result = await Execute(request, body);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(result.Value.UpdatedAt.Value).IsEqualTo(Time);
        await Assert.That(result.Value.Group is null).IsTrue();
        await Assert.That(result.Value.Roles.IsPresent).IsFalse();
        await Assert.That(result.Value.IncludesRoles).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("""{"IncludesRoles":false}""");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RoleMutationResultsKeepTimestampsAndOptionalTemporaryFlag(bool group)
    {
        var row = Role();
        row.Remove("isTemporary");
        row["projectMembershipId"] = Membership;
        row["createdAt"] = Time;
        row["updatedAt"] = Time;
        row["customRoleId"] = null;
        row["temporaryRange"] = "";
        string body = JsonSerializer.Serialize(new { roles = new[] { row } });
        if (group)
        {
            using var request = MembershipOperations.UpdateProjectGroupRoles(Org, "project", GroupId, Membership, [new("viewer")]);
            var result = await Execute(request, body);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            var assignment = result.Value.Items.Single();
            await Assert.That(assignment.CreatedAt.Value).IsEqualTo(Time);
            await Assert.That(assignment.UpdatedAt.Value).IsEqualTo(Time);
            await Assert.That(assignment.IsTemporary is null).IsTrue();
            await Assert.That(assignment.CustomRoleIdField.IsNull).IsTrue();
            await Assert.That(assignment.RangeField.Value).IsEqualTo("");
            await Assert.That(assignment.ModeField.IsPresent).IsFalse();
            await Assert.That(JsonSerializer.Serialize(assignment)).IsEqualTo("""{"IsTemporary":null}""");
        }
        else
        {
            using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, "project", Membership, [new("viewer")]);
            var result = await Execute(request, body);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            var assignment = result.Value.Items.Single();
            await Assert.That(assignment.CreatedAtField.Value).IsEqualTo(Time);
            await Assert.That(assignment.UpdatedAtField.Value).IsEqualTo(Time);
            await Assert.That(assignment.IsTemporary is null).IsTrue();
            await Assert.That(assignment.CustomRoleIdField.IsNull).IsTrue();
            await Assert.That(assignment.RangeField.Value).IsEqualTo("");
            await Assert.That(JsonSerializer.Serialize(assignment)).IsEqualTo("{}");
        }
    }

    [Test]
    [Arguments("roles", "null")]
    [Arguments("roles", "[123]")]
    [Arguments("createdAt", "false")]
    [Arguments("updatedAt", "null")]
    public async Task GroupMembershipRejectsMalformedCollectionsAndTimestamps(string field, string json)
    {
        var row = GroupMembership(Group());
        row[field] = JsonSerializer.Deserialize<JsonElement>(json);
        using var request = MembershipOperations.GetProjectGroup(Org, "project", GroupId);
        var result = await Execute(request, JsonSerializer.Serialize(new { groupMembership = row }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task IdentityInventoryCopiesAuthAndLockoutArraysWithoutInventingDetailAttributes()
    {
        var identity = Identity();
        identity["authMethods"] = new[] { "", "private-auth" };
        identity["activeLockoutAuthMethods"] = new[] { "private-lockout" };
        using var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, "project");
        var result = await Execute(request, JsonSerializer.Serialize(new { identityMemberships = new[] { IdentityMembership(identity) }, totalCount = 1 }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var returned = result.Value.Items.Single().IdentityMetadata;
        await Assert.That(returned.AuthMethods.Value[0]).IsEqualTo("");
        await Assert.That(returned.AuthMethods.Value[1]).IsEqualTo("private-auth");
        await Assert.That(returned.ActiveLockoutAuthMethods.Value.Single()).IsEqualTo("private-lockout");
        await Assert.That(((IList<string>)returned.AuthMethods.Value).IsReadOnly).IsTrue();
        await Assert.That(returned.Attributes.IsPresent).IsFalse();
        await Assert.That(JsonSerializer.Serialize(returned)).IsEqualTo("{}");
    }

    [Test]
    [Arguments(false, "missing")]
    [Arguments(false, "null")]
    [Arguments(false, "empty")]
    [Arguments(false, "value")]
    [Arguments(true, "missing")]
    [Arguments(true, "null")]
    [Arguments(true, "empty")]
    [Arguments(true, "value")]
    public async Task UserMetadataPreservesPresenceAndCopiesProtectedValues(bool details, string variant)
    {
        var user = User();
        if (variant != "missing")
        {
            user["authMethods"] = variant == "null" ? null : variant == "empty" ? Array.Empty<string>() : new[] { "", "private-auth" };
            user["isEmailVerified"] = variant == "null" ? null : false;
            user["publicKey"] = variant == "null" ? null : variant == "empty" ? "" : "private-key";
            user["email"] = variant == "null" ? null : "";
        }
        var row = UserMembership(user);
        if (details) row.Remove("createdAt");
        // Each factory has its native result type; the branches execute the same public seam.
        ProjectMembershipUser returned;
        if (details)
        {
            using var detailRequest = ProjectMembershipOperations.InspectProjectMembershipByUsername(Org, "project", "private-user");
            var result = await Execute(detailRequest, JsonSerializer.Serialize(new { membership = row }));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            returned = result.Value.User;
        }
        else
        {
            using var listRequest = ProjectMembershipOperations.ListProjectMemberships(Org, "project");
            var result = await Execute(listRequest, JsonSerializer.Serialize(new { memberships = new[] { row } }));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            returned = result.Value.Items.Single().User;
        }
        await Assert.That(returned.AuthMethods.IsPresent).IsEqualTo(variant != "missing");
        await Assert.That(returned.AuthMethods.IsNull).IsEqualTo(variant == "null");
        await Assert.That(returned.IsEmailVerified.IsPresent).IsEqualTo(variant != "missing");
        await Assert.That(returned.IsEmailVerified.IsNull).IsEqualTo(variant == "null");
        await Assert.That(returned.PublicKey.IsPresent).IsEqualTo(variant != "missing");
        await Assert.That(returned.PublicKey.IsNull).IsEqualTo(variant == "null");
        if (variant is "empty" or "value")
        {
            await Assert.That(returned.IsEmailVerified.Value).IsFalse();
            await Assert.That(returned.AuthMethods.Value.Count).IsEqualTo(variant == "empty" ? 0 : 2);
            await Assert.That(((IList<string>)returned.AuthMethods.Value).IsReadOnly).IsTrue();
            await Assert.That(returned.PublicKey.Value).IsEqualTo(variant == "empty" ? "" : "private-key");
            await Assert.That(returned.Email.Value).IsEqualTo("");
        }
        await Assert.That(JsonSerializer.Serialize(returned)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(returned.AuthMethods).Contains("private-auth", StringComparison.Ordinal)).IsFalse();
        await Assert.That(returned.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("project-get")]
    [Arguments("project-add")]
    [Arguments("org-get")]
    [Arguments("org-add")]
    [Arguments("org-update")]
    public async Task GroupResponsesProjectOnlyTheirReturnedDetailsAndRoles(string route)
    {
        var role = Role();
        role["createdAt"] = Time;
        role["updatedAt"] = Time;
        role["customRoleId"] = null;
        role["customRoleName"] = "";
        role["customRoleSlug"] = "private-role";
        role["temporaryMode"] = null;
        role["temporaryRange"] = "";
        role["temporaryAccessStartTime"] = null;
        role["temporaryAccessEndTime"] = Time;
        var row = GroupMembership(Group());
        row["roles"] = new[] { role };
        if (route.StartsWith("org", StringComparison.Ordinal)) row.Remove("projectId");
        using var request = route switch
        {
            "project-get" => MembershipOperations.GetProjectGroup(Org, "project", GroupId),
            "project-add" => MembershipOperations.AddProjectGroup(Org, "project", GroupId, new MembershipRoleSelection()),
            "org-get" => MembershipOperations.GetOrganizationGroup(Org, GroupId),
            "org-add" => MembershipOperations.AddOrganizationGroup(Org, GroupId, [new("viewer")]),
            _ => MembershipOperations.UpdateOrganizationGroupRoles(Org, GroupId, [new("viewer")])
        };
        var result = await Execute(request, JsonSerializer.Serialize(new { groupMembership = row }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var returned = result.Value;
        await Assert.That(returned.Group!.Name.Value).IsEqualTo("private-group");
        await Assert.That(returned.Group.Slug.Value).IsEqualTo("private-slug");
        await Assert.That(returned.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(returned.UpdatedAt.Value).IsEqualTo(Time);
        await Assert.That(returned.IncludesRoles).IsTrue();
        var assignment = returned.Roles.Value.Single();
        await Assert.That(assignment.Role).IsEqualTo("viewer");
        await Assert.That(assignment.IsTemporary).IsFalse();
        await Assert.That(assignment.CustomRoleIdField.IsNull).IsTrue();
        await Assert.That(assignment.CustomRoleNameField.Value).IsEqualTo("");
        await Assert.That(assignment.RangeField.Value).IsEqualTo("");
        await Assert.That(assignment.ModeField.IsNull).IsTrue();
        await Assert.That(assignment.StartsAtField.IsNull).IsTrue();
        await Assert.That(assignment.EndsAtField.Value).IsEqualTo(Time);
        await Assert.That(assignment.CreatedAtField.Value).IsEqualTo(Time);
        await Assert.That(assignment.UpdatedAtField.Value).IsEqualTo(Time);
        await Assert.That(((IList<ProjectMembershipRole>)returned.Roles.Value).IsReadOnly).IsTrue();
        await Assert.That(JsonSerializer.Serialize(returned)).IsEqualTo("""{"IncludesRoles":true}""");
        await Assert.That(JsonSerializer.Serialize(assignment)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(returned.Group)).IsEqualTo("{}");
        if (route.StartsWith("org", StringComparison.Ordinal))
        {
            row["orgId"] = Org;
            await Assert.That((await Execute(request, JsonSerializer.Serialize(new { groupMembership = row }))).Status)
                .IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments("org-get", true)]
    [Arguments("org-get", false)]
    [Arguments("org-add", true)]
    [Arguments("org-add", false)]
    [Arguments("org-update", true)]
    [Arguments("org-update", false)]
    [Arguments("org-list", true)]
    [Arguments("org-list", false)]
    public async Task OrganizationGroupProjectsOptionalOwnerRatherThanTargetOrganization(string route, bool includesOwner)
    {
        const string owner = "90000000-0000-4000-8000-000000000009";
        var group = Group();
        if (includesOwner) group["orgId"] = owner;
        else group.Remove("orgId");
        var row = GroupMembership(group);
        row.Remove("projectId");
        MembershipSummary returned;
        if (route == "org-list")
        {
            using var request = MembershipOperations.ListOrganizationGroups(Org);
            var result = await Execute(request, JsonSerializer.Serialize(new { groupMemberships = new[] { row }, totalCount = 1 }));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            returned = result.Value.Items.Single();
        }
        else
        {
            using var request = route switch
            {
                "org-get" => MembershipOperations.GetOrganizationGroup(Org, GroupId),
                "org-add" => MembershipOperations.AddOrganizationGroup(Org, GroupId, [new("viewer")]),
                _ => MembershipOperations.UpdateOrganizationGroupRoles(Org, GroupId, [new("viewer")])
            };
            var result = await Execute(request, JsonSerializer.Serialize(new { groupMembership = row }));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            returned = result.Value;
        }
        await Assert.That(returned.PrincipalId).IsEqualTo(GroupId);
        await Assert.That(returned.Group!.Id).IsEqualTo(GroupId);
        await Assert.That(returned.Group.OrganizationId.IsPresent).IsEqualTo(includesOwner);
        if (includesOwner) await Assert.That(returned.Group.OrganizationId.Value).IsEqualTo(owner);
        await Assert.That(returned.Roles.Value.Single().Role).IsEqualTo("viewer");
        await Assert.That(returned.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(returned.UpdatedAt.Value).IsEqualTo(Time);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GroupInventoryIncludesKnownMetadataAndEmptyRoles(bool organization)
    {
        var row = GroupMembership(Group());
        row["roles"] = Array.Empty<object>();
        if (organization) row.Remove("projectId");
        using var request = organization
            ? MembershipOperations.ListOrganizationGroups(Org)
            : MembershipOperations.ListProjectGroups(Org, "project");
        var response = new Dictionary<string, object?> { ["groupMemberships"] = new[] { row } };
        if (organization) response["totalCount"] = 1;
        var result = await Execute(request, JsonSerializer.Serialize(response));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var returned = result.Value.Items.Single();
        await Assert.That(returned.Roles.IsPresent).IsTrue();
        await Assert.That(returned.Roles.Value.Count).IsEqualTo(0);
        await Assert.That(returned.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(returned.Group!.Name.Value).IsEqualTo("private-group");
        if (!organization)
        {
            response["totalCount"] = 1;
            await Assert.That((await Execute(request, JsonSerializer.Serialize(response))).Status)
                .IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments("missing")]
    [Arguments("null")]
    [Arguments("empty")]
    [Arguments("value")]
    public async Task IdentityDetailsRetainMembershipRolesLoginAndIdentityAttributes(string variant)
    {
        var identity = Identity();
        identity.Remove("activeLockoutAuthMethods");
        identity["authMethods"] = new[] { "private-auth" };
        if (variant is "empty" or "value")
            identity["metadata"] = variant == "empty" ? Array.Empty<object>() :
                new object[] { new { id = "attribute", key = "private-key", value = "private-value" } };
        var row = IdentityMembership(identity);
        row.Remove("identityId");
        if (variant != "missing")
        {
            row["lastLoginTime"] = variant == "null" ? null : Time;
            row["lastLoginAuthMethod"] = variant == "null" ? null : variant == "empty" ? "" : "private-auth";
        }
        using var request = MembershipOperations.GetProjectIdentityMembership(Org, "project", IdentityId);
        var result = await Execute(request, JsonSerializer.Serialize(new { identityMembership = row }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var returned = result.Value;
        await Assert.That(returned.Id).IsEqualTo(Membership);
        await Assert.That(returned.Identity.Id).IsEqualTo(IdentityId);
        await Assert.That(returned.Roles.Single().Role).IsEqualTo("viewer");
        await Assert.That(returned.IdentityMetadata.AuthMethods.Value.Single()).IsEqualTo("private-auth");
        await Assert.That(returned.IdentityMetadata.ActiveLockoutAuthMethods.IsPresent).IsFalse();
        await Assert.That(returned.IdentityMetadata.Attributes.IsPresent).IsEqualTo(variant is "empty" or "value");
        await Assert.That(returned.LastLoginTime.IsPresent).IsEqualTo(variant != "missing");
        await Assert.That(returned.LastLoginAuthMethod.IsNull).IsEqualTo(variant == "null");
        if (variant == "value")
        {
            var attribute = returned.IdentityMetadata.Attributes.Value.Single();
            await Assert.That(attribute.Id).IsEqualTo("attribute");
            await Assert.That(attribute.Key).IsEqualTo("private-key");
            await Assert.That(attribute.Value).IsEqualTo("private-value");
            await Assert.That(JsonSerializer.Serialize(attribute)).IsEqualTo("{}");
        }
        await Assert.That(JsonSerializer.Serialize(returned.IdentityMetadata)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(returned)).IsEqualTo("""{"IncludesPermissions":false}""");
    }

    [Test]
    [Arguments("org", SecretStatus.Invalid)]
    [Arguments("id", SecretStatus.Invalid)]
    [Arguments("login", SecretStatus.Unknown)]
    [Arguments("metadata", SecretStatus.Unknown)]
    public async Task IdentityDetailsRejectForeignScopeAndMalformedMetadata(string defect, SecretStatus expected)
    {
        var identity = Identity();
        identity.Remove("activeLockoutAuthMethods");
        if (defect == "org") identity["orgId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "id") identity["id"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "metadata") identity["metadata"] = new[] { new { id = "attribute", key = "key", value = false } };
        var row = IdentityMembership(identity);
        row.Remove("identityId");
        if (defect == "login") row["lastLoginTime"] = false;
        using var request = MembershipOperations.GetProjectIdentityMembership(Org, "project", IdentityId);
        var result = await Execute(request, JsonSerializer.Serialize(new { identityMembership = row }));
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments("authMethods", "123")]
    [Arguments("authMethods", "[null]")]
    [Arguments("isEmailVerified", "\"false\"")]
    [Arguments("publicKey", "false")]
    public async Task UserMetadataRejectsMalformedKnownFields(string field, string json)
    {
        var user = User();
        user[field] = JsonSerializer.Deserialize<JsonElement>(json);
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, "project");
        var result = await Execute(request, JsonSerializer.Serialize(new { memberships = new[] { UserMembership(user) } }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("name", "123")]
    [Arguments("slug", "null")]
    public async Task GroupDetailsRejectMalformedKnownFields(string field, string json)
    {
        var group = Group();
        group[field] = JsonSerializer.Deserialize<JsonElement>(json);
        using var request = MembershipOperations.GetProjectGroup(Org, "project", GroupId);
        var result = await Execute(request, JsonSerializer.Serialize(new { groupMembership = GroupMembership(group) }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("activeLockoutAuthMethods", "false")]
    [Arguments("authMethods", "[{}]")]
    public async Task IdentityInventoryRejectsMalformedAuthArrays(string field, string json)
    {
        var identity = Identity();
        identity[field] = JsonSerializer.Deserialize<JsonElement>(json);
        using var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, "project");
        var result = await Execute(request, JsonSerializer.Serialize(new
        {
            identityMemberships = new[] { IdentityMembership(identity) },
            totalCount = 1
        }));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static Dictionary<string, object?> User() => new()
    {
        ["id"] = UserId,
        ["username"] = "private-user"
    };

    private static Dictionary<string, object?> UserMembership(object user) => new()
    {
        ["id"] = Membership,
        ["userId"] = UserId,
        ["projectId"] = "project",
        ["createdAt"] = Time,
        ["user"] = user,
        ["roles"] = new[] { Role() }
    };

    private static Dictionary<string, object?> Group() => new()
    {
        ["id"] = GroupId,
        ["name"] = "private-group",
        ["slug"] = "private-slug",
        ["orgId"] = Org
    };

    private static Dictionary<string, object?> GroupMembership(object group) => new()
    {
        ["id"] = Membership,
        ["groupId"] = GroupId,
        ["projectId"] = "project",
        ["createdAt"] = Time,
        ["updatedAt"] = Time,
        ["group"] = group,
        ["roles"] = new[] { Role() }
    };

    private static Dictionary<string, object?> Identity() => new()
    {
        ["id"] = IdentityId,
        ["name"] = "private-identity",
        ["orgId"] = Org,
        ["authMethods"] = Array.Empty<string>(),
        ["activeLockoutAuthMethods"] = Array.Empty<string>()
    };

    private static Dictionary<string, object?> IdentityMembership(object identity) => new()
    {
        ["id"] = Membership,
        ["identityId"] = IdentityId,
        ["createdAt"] = Time,
        ["updatedAt"] = Time,
        ["identity"] = identity,
        ["roles"] = new[] { Role() }
    };

    private static Dictionary<string, object?> Role() => new()
    {
        ["id"] = RoleId,
        ["role"] = "viewer",
        ["isTemporary"] = false
    };

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, string body,
        ManagementTarget? approved = null) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire(body));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, request.Target.ProjectId);
        return await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, approved ?? request.Target),
            request.IsMutation ? client.CreateReceipt(request) : null);
    }

    private sealed class Wire(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-only-token"))));
    }
}
