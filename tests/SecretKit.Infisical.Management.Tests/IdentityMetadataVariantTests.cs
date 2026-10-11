using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityMetadataVariantTests
{
    private const string RoleId = "60000000-0000-4000-8000-000000000006";
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Identity = "20000000-0000-4000-8000-000000000002";
    private const string OtherMembership = "30000000-0000-4000-8000-000000000009";
    private const string OptionalRoleId = "60000000-0000-4000-8000-000000000007";
    private const string CustomRoleId = "60000000-0000-4000-8000-000000000008";
    private const string Membership = "30000000-0000-4000-8000-000000000003";

    private const string Time = "2026-10-10T00:00:00Z";

    [Test]
    [Arguments("organization-list")]
    [Arguments("organization-get")]
    [Arguments("project-list")]
    [Arguments("organization-memberships")]
    [Arguments("search")]
    [Arguments("project-memberships")]
    [Arguments("project-membership-get")]
    public async Task IdentityReadersRequireOnlyTheirEndpointMetadata(string row)
    {
        var identity = JsonNode.Parse($$$$$"""
            {"id":"{{{{{Identity}}}}}","name":"service","authMethods":[]}
            """)!.AsObject();
        var membership = JsonNode.Parse($$$$$"""
            {"id":"{{{{{Membership}}}}}","identityId":"{{{{{Identity}}}}}",
             "createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}
            """)!.AsObject();
        if (row != "organization-list") identity["orgId"] = Org;
        if (row is "organization-get" or "search" or "project-memberships")
            identity["activeLockoutAuthMethods"] = new JsonArray();
        if (row is "organization-list" or "organization-get" or "organization-memberships")
        {
            membership["orgId"] = Org;
            membership["role"] = "member";
        }
        else if (row != "project-list") membership["roles"] = new JsonArray();
        if (row == "project-membership-get") membership.Remove("identityId");
        membership["identity"] = identity;
        string[] fields = row switch
        {
            "organization-list" => ["createdAt", "updatedAt", "role", "identity.authMethods"],
            "organization-get" => ["createdAt", "updatedAt", "role", "identity.authMethods", "identity.activeLockoutAuthMethods"],
            "project-list" => ["createdAt", "updatedAt"],
            "project-memberships" or "search" => ["identity.authMethods", "identity.activeLockoutAuthMethods"],
            _ => ["identity.authMethods"]
        };
        switch (row)
        {
            case "organization-list":
                using (var request = IdentityOperations.ListOrganizationIdentities(Org))
                    await Verify(request, new(Org), "identities", true, membership);
                break;
            case "organization-get":
                using (var request = IdentityOperations.GetOrganizationIdentity(Org, Identity))
                    await Verify(request, new(Org, resourceId: Identity), "identity", false, membership);
                break;
            case "project-list":
                identity["projectId"] = "project";
                identity["createdAt"] = Time;
                identity["updatedAt"] = Time;
                using (var request = IdentityOperations.ListProjectIdentities(Org, "project"))
                    await Verify(request, IdentityOperations.ProjectIdentityListTarget(Org, "project"),
                        "identities", true, identity);
                break;
            case "organization-memberships":
                using (var request = OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(Org))
                    await Verify(request, new(Org), "identityMemberships", true, membership);
                break;
            case "search":
                membership["orgId"] = Org;
                membership["scope"] = "project";
                membership["projectId"] = "project";
                using (var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Projects))
                    await Verify(request, IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Projects),
                        "identities", true, membership);
                break;
            case "project-memberships":
                using (var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, "project"))
                    await Verify(request, ProjectMembershipOperations.ProjectIdentityMembershipListTarget(Org, "project"),
                        "identityMemberships", true, membership);
                break;
            default:
                using (var request = MembershipOperations.GetProjectIdentityMembership(Org, "project", Identity))
                    await Verify(request, new(Org, "project", Identity), "identityMembership", false, membership);
                break;
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target, string envelope,
            bool list, JsonObject fixture) where T : notnull
        {
            string Response(JsonObject item)
            {
                var response = new JsonObject { [envelope] = list ? new JsonArray(item) : item };
                if (list) response["totalCount"] = 1;
                return response.ToJsonString();
            }
            await Assert.That((await Execute(request, Response(fixture.DeepClone().AsObject()), target)).Status)
                .IsEqualTo(SecretStatus.Success);
            foreach (string field in fields)
            {
                foreach (string shape in new[] { "absent", "null", "wrong-kind" })
                {
                    var invalid = fixture.DeepClone().AsObject();
                    string[] path = field.Split('.');
                    var owner = path.Length == 1 ? invalid : invalid[path[0]]!.AsObject();
                    if (shape == "absent") owner.Remove(path[^1]);
                    else owner[path[^1]] = shape == "null" ? null : JsonValue.Create(false);
                    await Assert.That((await Execute(request, Response(invalid), target)).Status)
                        .IsEqualTo(SecretStatus.Unknown);
                }
            }
        }
    }

    [Test]
    [Arguments("create", false)]
    [Arguments("update", false)]
    [Arguments("delete", false)]
    [Arguments("create", true)]
    [Arguments("update", true)]
    [Arguments("delete", true)]
    [Arguments("get", true)]
    public async Task IdentityMutationAndProjectInspectionRequireProfileFields(string operation, bool project)
    {
        using var request = project ? ProjectRequest(operation) : OrganizationRequest(operation);
        var target = project ? ProjectTarget(operation) : OrganizationTarget(operation);
        var row = JsonNode.Parse($$$$$"""
            {"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","createdAt":"2026-10-10T00:00:00Z",
             "updatedAt":"2026-10-10T00:00:00Z","authMethods":[],"metadata":[]}
            """)!.AsObject();
        if (project) row["projectId"] = "project";
        else
        {
            if (operation != "create") row.Remove("authMethods");
            if (operation == "delete") row.Remove("metadata");
        }
        string[] fields = project || operation == "delete" ? ["createdAt", "updatedAt"] :
            operation == "create" ? ["createdAt", "updatedAt", "authMethods", "metadata"] :
            ["createdAt", "updatedAt", "metadata"];
        await Assert.That((await Execute(request, new JsonObject { ["identity"] = row.DeepClone() }.ToJsonString(),
            target)).Status).IsEqualTo(SecretStatus.Success);
        foreach (string field in fields)
        {
            foreach (string shape in new[] { "absent", "null", "wrong-kind" })
            {
                var invalid = row.DeepClone().AsObject();
                if (shape == "absent") invalid.Remove(field);
                else invalid[field] = shape == "null" ? null : JsonValue.Create(false);
                var result = await Execute(request,
                    new JsonObject { ["identity"] = invalid }.ToJsonString(), target);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            }
        }
        if (!project && operation != "create")
        {
            foreach (string field in operation == "delete" ? new[] { "authMethods", "metadata" } : new[] { "authMethods" })
            {
                var extra = row.DeepClone().AsObject();
                extra[field] = new JsonArray();
                await Assert.That((await Execute(request,
                    new JsonObject { ["identity"] = extra }.ToJsonString(), target)).Status)
                    .IsEqualTo(SecretStatus.Unknown);
            }
        }
    }

    [Test]
    [Arguments("\"authMethods\":[123]")]
    [Arguments("\"activeLockoutAuthMethods\":null")]
    [Arguments("\"hasDeleteProtection\":\"false\"")]
    [Arguments("\"metadata\":[{\"id\":\"entry\",\"key\":false,\"value\":\"private-canary\"}]")]
    [Arguments("\"createdAt\":123")]
    public async Task MalformedEstablishedProjectMetadataFailsClosed(string field)
    {
        using var request = IdentityOperations.GetProjectIdentity(Org, "project", Identity);
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":"project",""" + field + "}}",
            new(Org, "project", Identity));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("\"customRole\":null")]
    [Arguments("\"customRole\":{\"id\":\"60000000-0000-4000-8000-000000000006\",\"name\":123,\"slug\":\"custom\"}")]
    [Arguments("\"roleId\":false")]
    [Arguments("\"lastLoginTime\":false")]
    public async Task MalformedOrganizationMembershipMetadataFailsClosed(string field)
    {
        using var request = IdentityOperations.GetOrganizationIdentity(Org, Identity);
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Membership}}}}}","orgId":"{{{{{Org}}}}}","identityId":"{{{{{Identity}}}}}","role":"member","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","authMethods":[],"activeLockoutAuthMethods":[]},""" + field + "}}",
            new(Org, resourceId: Identity));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("get")]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    public async Task ProjectRoutesCopyKnownFieldsWithoutInferringRequestValues(string operation)
    {
        using var request = ProjectRequest(operation);
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"returned-canary","orgId":"{{{{{Org}}}}}","projectId":"project","authMethods":["token-auth",""],"activeLockoutAuthMethods":[],"hasDeleteProtection":false,"createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","metadata":[{"id":"","key":"","value":"metadata-canary"}]}}""",
            ProjectTarget(operation));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        IdentitySummary identity = result.Value;
        await Assert.That(identity.Name).IsEqualTo("returned-canary");
        await Assert.That(identity.OrganizationIdField.Value).IsEqualTo(Org);
        await Assert.That(identity.ProjectId).IsEqualTo("project");
        await Assert.That(identity.AuthMethods.Value[0]).IsEqualTo("token-auth");
        await Assert.That(identity.AuthMethods.Value[1]).IsEqualTo("");
        await Assert.That(identity.ActiveLockoutAuthMethods.Value.Count).IsEqualTo(0);
        await Assert.That(identity.HasDeleteProtection.IsPresent).IsTrue();
        await Assert.That(identity.HasDeleteProtection.Value).IsFalse();
        await Assert.That(identity.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(identity.UpdatedAt.Value).IsEqualTo(Time);
        await Assert.That(identity.Metadata.Value.Single().Id).IsEqualTo("");
        await Assert.That(identity.Metadata.Value.Single().Key).IsEqualTo("");
        await Assert.That(identity.Metadata.Value.Single().Value).IsEqualTo("metadata-canary");
        await Assert.That(identity.Membership.IsPresent).IsFalse();
        await Assert.That(identity.AuthMethod.IsPresent).IsFalse();
        await Protected(identity);
        await Assert.That(JsonSerializer.Serialize(identity.Metadata.Value.Single())).IsEqualTo("{}");
        var collection = (IList<string>)identity.AuthMethods.Value;
        await Assert.That(() => collection[0] = "changed").Throws<NotSupportedException>();
    }

    [Test]
    [Arguments("create")]
    [Arguments("update")]
    [Arguments("delete")]
    public async Task OrganizationMutationsPreserveTheirDistinctResponseSchemas(string operation)
    {
        using var request = OrganizationRequest(operation);
        string collections = operation switch
        {
            "create" => ""","authMethods":["token-auth"],"metadata":[{"id":"","key":"","value":""}]""",
            "update" => ""","metadata":[]""",
            _ => ""
        };
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"returned-canary","orgId":"{{{{{Org}}}}}","projectId":null,"createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","authMethod":null""" + collections + "}}",
            OrganizationTarget(operation));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AuthMethod.IsPresent).IsTrue();
        await Assert.That(result.Value.AuthMethod.IsNull).IsTrue();
        await Assert.That(result.Value.HasDeleteProtection.IsPresent).IsFalse();
        await Assert.That(result.Value.ActiveLockoutAuthMethods.IsPresent).IsFalse();
        await Assert.That(result.Value.AuthMethods.IsPresent).IsEqualTo(operation == "create");
        await Assert.That(result.Value.Metadata.IsPresent).IsEqualTo(operation != "delete");
        if (operation == "create")
            await Assert.That(result.Value.Metadata.Value.Single().Value).IsEqualTo("");
        if (operation == "update")
            await Assert.That(result.Value.Metadata.Value.Count).IsEqualTo(0);
        await Assert.That(result.Value.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(result.Value.UpdatedAt.Value).IsEqualTo(Time);
        await Protected(result.Value);
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("empty")]
    public async Task OrganizationGetRetainsOuterMembershipAndNullablePresence(string variant)
    {
        using var request = IdentityOperations.GetOrganizationIdentity(Org, Identity);
        string login = variant switch
        {
            "null" => ""","roleId":null,"lastLoginAuthMethod":null,"lastLoginTime":null""",
            "empty" => $$$$$""","roleId":"{{{{{OptionalRoleId}}}}}","lastLoginAuthMethod":"","lastLoginTime":"2026-10-10T00:00:00Z" """,
            _ => ""
        };
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{OtherMembership}}}}}","orgId":"{{{{{Org}}}}}","identityId":"{{{{{Identity}}}}}","role":"member","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","metadata":[{"id":"entry","key":"key","value":"metadata-canary"}],"customRole":{"id":"{{{{{CustomRoleId}}}}}","name":"","slug":"custom-canary","description":null,"permissions":{"unestablished":["never-export"]}},"identity":{"id":"{{{{{Identity}}}}}","name":"service-canary","orgId":"{{{{{Org}}}}}","authMethods":[],"activeLockoutAuthMethods":["token-auth"]}"""
            + login + "}}", new(Org, resourceId: Identity));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        IdentityMembershipMetadata membership = result.Value.Membership.Value;
        await Assert.That(membership.Id).IsEqualTo(OtherMembership);
        await Assert.That(membership.IdentityId).IsEqualTo(Identity);
        await Assert.That(membership.Role.Value).IsEqualTo("member");
        await Assert.That(membership.CreatedAt.Value).IsEqualTo(Time);
        await Assert.That(membership.UpdatedAt.Value).IsEqualTo(Time);
        await Assert.That(membership.RoleId.IsPresent).IsEqualTo(variant != "absent");
        await Assert.That(membership.RoleId.IsNull).IsEqualTo(variant == "null");
        await Assert.That(membership.LastLoginAuthMethod.IsPresent).IsEqualTo(variant != "absent");
        await Assert.That(membership.LastLoginTime.IsNull).IsEqualTo(variant == "null");
        if (variant == "empty")
        {
            await Assert.That(membership.RoleId.Value).IsEqualTo(OptionalRoleId);
            await Assert.That(membership.LastLoginAuthMethod.Value).IsEqualTo("");
            await Assert.That(membership.LastLoginTime.Value).IsEqualTo(Time);
        }
        IdentityCustomRoleMetadata role = membership.CustomRole.Value;
        await Assert.That(role.Id).IsEqualTo(CustomRoleId);
        await Assert.That(role.Name).IsEqualTo("");
        await Assert.That(role.Slug).IsEqualTo("custom-canary");
        await Assert.That(role.Description.IsNull).IsTrue();
        await Assert.That(role.HasPermissions).IsTrue();
        await Assert.That(role.PermissionsIsNull).IsFalse();
        await Assert.That(role.IncludesPermissionValues).IsFalse();
        await Assert.That(result.Value.Metadata.Value.Single().Value).IsEqualTo("metadata-canary");
        await Assert.That(result.Value.ActiveLockoutAuthMethods.Value.Single()).IsEqualTo("token-auth");
        await Assert.That(result.Value.CreatedAt.IsPresent).IsFalse();
        await Protected(result.Value);
        await Assert.That(JsonSerializer.Serialize(membership)).IsEqualTo("""{"IncludesPermissions":false}""");
        await Assert.That(JsonSerializer.Serialize(role))
            .IsEqualTo("""{"HasPermissions":true,"PermissionsIsNull":false,"IncludesPermissionValues":false}""");
    }

    [Test]
    [Arguments(1, true)]
    [Arguments(2, false)]
    public async Task OrganizationListKeepsCountCorrespondenceAndMembershipMetadata(int total, bool complete)
    {
        using var request = IdentityOperations.ListOrganizationIdentities(Org);
        var result = await Execute(request,
            $$$$$"""{"identities":[{"id":"{{{{{Membership}}}}}","identityId":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","role":"","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","identity":{"id":"{{{{{Identity}}}}}","name":"service","authMethods":[],"hasDeleteProtection":false}}],"totalCount":"""
            + total + "}", new(Org));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        IdentitySummary identity = result.Value.Items.Single();
        await Assert.That(identity.Membership.Value.Id).IsEqualTo(Membership);
        await Assert.That(identity.OrganizationIdField.IsPresent).IsFalse();
        await Assert.That(identity.Membership.Value.Role.Value).IsEqualTo("");
        await Assert.That(identity.AuthMethods.Value.Count).IsEqualTo(0);
        await Assert.That(identity.ActiveLockoutAuthMethods.IsPresent).IsFalse();
        await Assert.That(identity.HasDeleteProtection.Value).IsFalse();
        await Assert.That(result.Value.IsComplete).IsEqualTo(complete);
        await Assert.That(result.Value.NextOffset).IsNull();
        await Protected(identity);
    }

    [Test]
    public async Task SchemaMinimalProjectListDoesNotInventOptionalFields()
    {
        using var request = IdentityOperations.ListProjectIdentities(Org, "project", limit: 1);
        var result = await Execute(request,
            $$$$$"""{"identities":[{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}],"totalCount":2}""",
            IdentityOperations.ProjectIdentityListTarget(Org, "project", limit: 1));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        IdentitySummary identity = result.Value.Items.Single();
        await Assert.That(identity.AuthMethods.IsPresent).IsFalse();
        await Assert.That(identity.ActiveLockoutAuthMethods.IsPresent).IsFalse();
        await Assert.That(identity.HasDeleteProtection.IsPresent).IsFalse();
        await Assert.That(identity.Metadata.IsPresent).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(() => identity.Metadata.Value).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("empty")]
    public async Task V2MembershipFieldsRetainNullableAndCustomRolePresence(string variant)
    {
        using var request = OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(Org);
        string extra = variant switch
        {
            "null" => $$$$$""","roleId":null,"lastLoginAuthMethod":null,"lastLoginTime":null,"customRole":{"id":"{{{{{RoleId}}}}}","name":"name","slug":"slug","description":null,"permissions":null}""",
            "empty" => $$$$$""","roleId":"{{{{{OptionalRoleId}}}}}","lastLoginAuthMethod":"","lastLoginTime":"2026-10-10T00:00:00Z","customRole":{"id":"{{{{{RoleId}}}}}","name":"","slug":"","description":""}""",
            _ => ""
        };
        var result = await Execute(request,
            $$$$$"""{"identityMemberships":[{"id":"{{{{{Membership}}}}}","identityId":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","role":"member","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","authMethods":["token-auth"]}"""
            + extra + "}],\"totalCount\":1}", new(Org));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var membership = result.Value.Items.Single();
        await Assert.That(membership.Identity.AuthMethods.Value.Single()).IsEqualTo("token-auth");
        await Assert.That(membership.RoleIdField.IsPresent).IsEqualTo(variant != "absent");
        await Assert.That(membership.LastLoginAuthMethodField.IsNull).IsEqualTo(variant == "null");
        await Assert.That(membership.LastLoginTimeField.IsPresent).IsEqualTo(variant != "absent");
        await Assert.That(membership.CustomRole.IsPresent).IsEqualTo(variant != "absent");
        if (variant == "null")
        {
            await Assert.That(membership.CustomRole.Value.Description.IsNull).IsTrue();
            await Assert.That(membership.CustomRole.Value.PermissionsIsNull).IsTrue();
        }
        if (variant == "empty")
        {
            await Assert.That(membership.RoleIdField.Value).IsEqualTo(OptionalRoleId);
            await Assert.That(membership.LastLoginAuthMethodField.Value).IsEqualTo("");
            await Assert.That(membership.LastLoginTimeField.Value).IsEqualTo(Time);
            await Assert.That(membership.CustomRole.Value.Description.Value).IsEqualTo("");
            await Assert.That(membership.CustomRole.Value.HasPermissions).IsFalse();
        }
        await Assert.That(JsonSerializer.Serialize(membership)).IsEqualTo("""{"IncludesPermissions":false}""");
    }

    [Test]
    [Arguments("outer", SecretStatus.Invalid)]
    [Arguments("nested", SecretStatus.Invalid)]
    [Arguments("identity", SecretStatus.Invalid)]
    [Arguments("metadata", SecretStatus.Unknown)]
    public async Task OrganizationCorrespondenceAndNonemptyMetadataFailClosed(string defect, SecretStatus expected)
    {
        using var request = IdentityOperations.GetOrganizationIdentity(Org, Identity);
        string response = JsonSerializer.Serialize(new
        {
            identity = new
            {
                id = Membership,
                identityId = Identity,
                orgId = defect == "outer" ? "90000000-0000-4000-8000-000000000009" : Org,
                role = "member",
                createdAt = Time,
                updatedAt = Time,
                identity = new
                {
                    id = defect == "identity" ? "90000000-0000-4000-8000-000000000009" : Identity,
                    name = "service",
                    orgId = defect == "nested" ? "90000000-0000-4000-8000-000000000009" : Org,
                    authMethods = Array.Empty<string>(),
                    activeLockoutAuthMethods = Array.Empty<string>()
                },
                metadata = new[] { new { id = "entry", key = "key", value = defect == "metadata" ? "" : "value" } }
            }
        });
        await Assert.That((await Execute(request, response, new(Org, resourceId: Identity))).Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ProjectMembershipNestedMetadataUsesItsOwnNonemptySchema(bool empty)
    {
        using var request = MembershipOperations.GetProjectIdentityMembership(Org, "project", Identity);
        var result = await Execute(request,
            $$$$$"""{"identityMembership":{"id":"{{{{{Membership}}}}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","roles":[],"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":null,"authMethods":["token-auth"],"metadata":[{"id":"entry","key":"key","value":"""
            + (empty ? "\"\"" : "\"metadata-canary\"") + "}]}}}", new(Org, "project", Identity));
        await Assert.That(result.Status).IsEqualTo(empty ? SecretStatus.Unknown : SecretStatus.Success);
        if (!empty)
        {
            await Assert.That(result.Value.Identity.AuthMethods.Value.Single()).IsEqualTo("token-auth");
            await Assert.That(result.Value.Identity.Metadata.Value.Single().Value).IsEqualTo("metadata-canary");
            await Assert.That(result.Value.Identity.ProjectIdField.IsNull).IsTrue();
            await Assert.That(result.Value.Id).IsEqualTo(Membership);
            await Assert.That(result.Value.Roles.Count).IsEqualTo(0);
            await Assert.That(result.Value.CreatedAt).IsEqualTo(Time);
            await Assert.That(result.Value.UpdatedAt).IsEqualTo(Time);
            await Protected(result.Value.Identity);
        }
    }

    [Test]
    [Arguments("\"authMethods\":null")]
    [Arguments("\"authMethods\":[{}]")]
    [Arguments("\"hasDeleteProtection\":null")]
    [Arguments("\"metadata\":null")]
    [Arguments("\"metadata\":[{\"id\":\"entry\",\"key\":\"key\"}]")]
    [Arguments("\"updatedAt\":null")]
    public async Task PresentInvalidProjectVariantsDoNotBecomeAbsence(string field)
    {
        using var request = IdentityOperations.GetProjectIdentity(Org, "project", Identity);
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":"project",""" + field + "}}",
            new(Org, "project", Identity));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("project")]
    [Arguments("org")]
    [Arguments("identity")]
    public async Task ProjectReturnedCoordinatesStillFailClosed(string defect)
    {
        using var request = IdentityOperations.GetProjectIdentity(Org, "project", Identity);
        string response = JsonSerializer.Serialize(new
        {
            identity = new
            {
                id = defect == "identity" ? "90000000-0000-4000-8000-000000000009" : Identity,
                orgId = defect == "org" ? "90000000-0000-4000-8000-000000000009" : Org,
                projectId = defect == "project" ? "foreign" : "project",
                name = "service",
                createdAt = Time,
                updatedAt = Time
            }
        });
        await Assert.That((await Execute(request, response, new(Org, "project", Identity))).Status)
            .IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task EagerArraysRemainUsableAfterResponseAndTransportDisposal()
    {
        using var request = IdentityOperations.GetProjectIdentity(Org, "project", Identity);
        var wire = new Wire(
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","authMethods":["token-auth"],"metadata":[{"id":"entry","key":"key","value":"metadata-canary"}]}}""");
        var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        SecretOutcome<IdentitySummary> result;
        using (transport)
        {
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, "project");
            result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, "project", Identity)));
            await Assert.That(wire.Content!.Disposed).IsTrue();
        }
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AuthMethods.Value.Single()).IsEqualTo("token-auth");
        await Assert.That(result.Value.Metadata.Value.Single().Value).IsEqualTo("metadata-canary");
        var metadata = (IList<IdentityMetadataEntry>)result.Value.Metadata.Value;
        await Assert.That(() => metadata.Clear()).Throws<NotSupportedException>();
        await Protected(result.Value);
    }

    [Test]
    [Arguments("create", false)]
    [Arguments("create", true)]
    [Arguments("update", false)]
    [Arguments("update", true)]
    [Arguments("delete", false)]
    [Arguments("delete", true)]
    public async Task OrganizationAuthMethodStringAndAbsenceRemainDistinct(string operation, bool present)
    {
        using var request = OrganizationRequest(operation);
        string collections = operation == "create" ? ""","authMethods":[],"metadata":[]"""
            : operation == "update" ? ""","metadata":[]""" : "";
        string method = present ? ""","authMethod":"token-auth" """ : "";
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z" """
            + collections + method + "}}",
            OrganizationTarget(operation));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.AuthMethod.IsPresent).IsEqualTo(present);
        await Assert.That(result.Value.AuthMethod.IsNull).IsFalse();
        if (present) await Assert.That(result.Value.AuthMethod.Value).IsEqualTo("token-auth");
        await Assert.That(result.Value.ProjectIdField.IsPresent).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OrganizationGetDistinguishesAbsentAndEmptyOuterMetadata(bool present)
    {
        using var request = IdentityOperations.GetOrganizationIdentity(Org, Identity);
        var result = await Execute(request,
            $$$$$"""{"identity":{"id":"{{{{{Membership}}}}}","orgId":"{{{{{Org}}}}}","identityId":"{{{{{Identity}}}}}","role":"member","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","authMethods":[],"activeLockoutAuthMethods":[]}"""
            + (present ? ",\"metadata\":[]" : "") + "}}", new(Org, resourceId: Identity));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Metadata.IsPresent).IsEqualTo(present);
        if (present) await Assert.That(result.Value.Metadata.Value.Count).IsEqualTo(0);
        await Assert.That(result.Value.Membership.Value.CustomRole.IsPresent).IsFalse();
    }

    private static async Task Protected(IdentitySummary identity)
    {
        await Assert.That(JsonSerializer.Serialize(identity)).IsEqualTo("{}");
        await Assert.That(identity.ToString()).IsEqualTo("[IdentitySummary]");
        await Assert.That(identity.Metadata.ToString()).IsEqualTo("[IdentityField]");
    }

    private static ManagementRequest<IdentitySummary> ProjectRequest(string operation) => operation switch
    {
        "create" => IdentityOperations.CreateProjectIdentity(Org, "project", "requested",
            deleteProtection: true, metadata: [new("request-key", "request-value")]),
        "update" => IdentityOperations.UpdateProjectIdentity(Org, "project", Identity, name: "requested",
            deleteProtection: true, metadata: [new("request-key", "request-value")]),
        "delete" => IdentityOperations.DeleteProjectIdentity(Org, "project", Identity),
        _ => IdentityOperations.GetProjectIdentity(Org, "project", Identity)
    };

    private static ManagementTarget ProjectTarget(string operation) => operation switch
    {
        "create" => IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "requested",
            deleteProtection: true, metadata: [new("request-key", "request-value")]),
        "update" => IdentityOperations.ProjectIdentityUpdateTarget(Org, "project", Identity, name: "requested",
            deleteProtection: true, metadata: [new("request-key", "request-value")]),
        _ => new(Org, "project", Identity)
    };

    private static ManagementTarget OrganizationTarget(string operation) => operation switch
    {
        "create" => IdentityOperations.OrganizationIdentityCreateTarget(Org, "requested", "member"),
        "update" => IdentityOperations.OrganizationIdentityUpdateTarget(Org, Identity, name: "requested"),
        _ => new(Org, resourceId: Identity)
    };

    private static ManagementRequest<IdentitySummary> OrganizationRequest(string operation) => operation switch
    {
        "create" => IdentityOperations.CreateOrganizationIdentity(Org, "requested", "member"),
        "update" => IdentityOperations.UpdateOrganizationIdentity(Org, Identity, name: "requested"),
        _ => IdentityOperations.DeleteOrganizationIdentity(Org, Identity)
    };

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, string body,
        ManagementTarget independentTarget) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"),
            1024 * 1024, null, false, new Wire(body));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, independentTarget.ProjectId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        return await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, independentTarget), receipt);
    }

    private sealed class Wire(string body) : HttpMessageHandler
    {
        public TrackedContent? Content { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Content = new(body);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = Content
            });
        }
    }

    private sealed class TrackedContent(string body) : StringContent(body, Encoding.UTF8, "application/json")
    {
        public bool Disposed { get; private set; }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("test-only-token"))));
    }
}
