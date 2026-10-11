using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class RoleTimestampTests
{
    private const string Org = "c168ae21-77c8-467a-9a31-d471c8dc3d71";
    private const string RoleId = "9fe7d5c2-a8d3-4b2d-a9f7-f3a6e8c87d14";
    private const string ForeignUuid = "502d6349-cc18-4283-b85b-bad8d03c6109";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task RequiredNativeDatesRejectMalformedValuesAtEveryRoleAdapter(int route)
    {
        var role = Role(route);
        foreach (string field in new[] { "createdAt", "updatedAt" })
        {
            foreach (string defect in new[] { "missing", "null", "number", "boolean", "object", "empty", "date-only", "invalid-calendar", "missing-zone", "malformed" })
            {
                var malformed = role.DeepClone().AsObject();
                if (defect == "missing") malformed.Remove(field);
                else malformed[field] = defect switch
                {
                    "null" => null,
                    "number" => JsonValue.Create(1),
                    "boolean" => JsonValue.Create(false),
                    "object" => new JsonObject(),
                    "empty" => JsonValue.Create(""),
                    "date-only" => JsonValue.Create("2026-01-01"),
                    "invalid-calendar" => JsonValue.Create("2026-02-30T03:04:05Z"),
                    "missing-zone" => JsonValue.Create("2026-01-01T03:04:05"),
                    _ => JsonValue.Create("not-a-date")
                };
                await Assert.That(await ExecuteRoute(route, Envelope(malformed, route))).IsEqualTo(SecretStatus.Unknown);
            }
        }
        foreach (string field in route is 5 or 10 ? new[] { route < 6 ? "orgId" : "projectId", "slug" } :
            route is 0 or 6 or 1 or 7 ? new[] { route < 6 ? "orgId" : "projectId" } :
            new[] { route < 6 ? "orgId" : "projectId", "id" })
        {
            var foreign = role.DeepClone().AsObject();
            foreign[field] = field is "id" or "orgId" ? ForeignUuid : "foreign";
            await Assert.That(await ExecuteRoute(route, Envelope(foreign, route))).IsEqualTo(SecretStatus.Invalid);
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task EveryOriginalRoleRowProjectsNativeDatesAfterAdapterDisposal(int route)
    {
        foreach (string date in new[] { "2026-01-01T00:00:00Z", "2026-01-01T00:00:00.1234567Z",
            "2026-01-01T03:04:05+02:00", "2026-01-01T03:04:05-04:00" })
        {
            var role = Role(route);
            role["createdAt"] = date;
            role["updatedAt"] = date;
            role["description"] = date.EndsWith("+02:00", StringComparison.Ordinal) ? "private-description" :
                date.Contains('.') ? "" : null;
            if (route is 0 or 6)
            {
                using var request = route == 0 ? ScopedAccessOperations.ListOrganizationRoles(Org) :
                    ProjectOperations.ListProjectRoles(Org, "project");
                await Execute(request, route, Envelope(role, route), value => Verify(value.Items[0], date, false));
            }
            else
            {
                using var request = Single(route);
                await Execute(request, route, Envelope(role, route), value => Verify(value, date));
            }
        }
    }

    private static async Task Verify(RoleSummary role, string date, bool includesPermissions = true)
    {
        await Assert.That(role.CreatedAt).IsEqualTo(date);
        await Assert.That(role.UpdatedAt).IsEqualTo(date);
        await Assert.That(role.Id).IsEqualTo(RoleId);
        await Assert.That(role.Slug).IsEqualTo("reader");
        await Assert.That(role.IncludesPermissions).IsEqualTo(includesPermissions);
        if (includesPermissions) await Assert.That(role.Permissions!.Count).IsEqualTo(0);
        else await Assert.That(role.Permissions).IsNull();
        await Assert.That(role.Description).IsEqualTo(date.EndsWith("+02:00", StringComparison.Ordinal) ?
            "private-description" : date.Contains('.') ? "" : null);
        await Assert.That(JsonSerializer.Serialize(role)).IsEqualTo(
            includesPermissions ? """{"IncludesPermissions":true}""" : """{"IncludesPermissions":false}""");
        await Assert.That(role.ToString()).IsEqualTo("[RoleSummary]");
    }

    private static JsonObject Role(int route)
    {
        var role = new JsonObject
        {
            ["id"] = RoleId,
            ["name"] = "Reviewed",
            ["slug"] = "reader",
            [route < 6 ? "orgId" : "projectId"] = route < 6 ? Org : "project",
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-02T03:04:05+02:00"
        };
        if (route is not (0 or 6)) role["permissions"] = new JsonArray();
        return role;
    }

    private static string Envelope(JsonObject role, int route) =>
        (route is 0 or 6 ? new JsonObject { ["roles"] = new JsonArray(role) } :
            new JsonObject { ["role"] = role }).ToJsonString();

    private static ManagementRequest<RoleSummary> Single(int route) => route switch
    {
        1 => RoleChangeOperations.CreateOrganizationRole(Org, new("Reviewed", "reader", permissions: [])),
        2 => ScopedAccessOperations.DeleteOrganizationRole(Org, RoleId),
        3 => ScopedAccessOperations.GetOrganizationRole(Org, RoleId),
        4 => RoleChangeOperations.UpdateOrganizationRole(Org, RoleId, new(name: "Reviewed")),
        5 => ScopedAccessOperations.GetOrganizationRoleBySlug(Org, "reader"),
        7 => RoleChangeOperations.CreateProjectRole(Org, "project", new("Reviewed", "reader", permissions: [])),
        8 => ProjectOperations.DeleteProjectRole(Org, "project", RoleId),
        9 => RoleChangeOperations.UpdateProjectRole(Org, "project", RoleId, new(name: "Reviewed")),
        10 => ProjectOperations.GetProjectRoleBySlug(Org, "project", "reader"),
        11 => ProjectOperations.GetProjectRole(Org, "project", RoleId),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static async Task<SecretStatus> ExecuteRoute(int route, string json)
    {
        if (route is 0 or 6)
        {
            using var request = route == 0 ? ScopedAccessOperations.ListOrganizationRoles(Org) :
                ProjectOperations.ListProjectRoles(Org, "project");
            return await Execute(request, route, json);
        }
        using var single = Single(route);
        return await Execute(single, route, json);
    }

    private static async Task<SecretStatus> Execute<T>(ManagementRequest<T> request, int route, string json,
        Func<T, Task>? verify = null) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false,
            new GroupIntentTests.Wire(json));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new GroupIntentTests.Tokens(), Org, route < 6 ? null : "project");
        ManagementTarget target = route switch
        {
            1 => RoleChangeOperations.OrganizationCreationTarget(Org, new("Reviewed", "reader", permissions: [])),
            4 => RoleChangeOperations.OrganizationUpdateTarget(Org, RoleId, new(name: "Reviewed")),
            7 => RoleChangeOperations.ProjectCreationTarget(Org, "project", new("Reviewed", "reader", permissions: [])),
            9 => RoleChangeOperations.ProjectUpdateTarget(Org, "project", RoleId, new(name: "Reviewed")),
            _ => new(Org, route < 6 ? null : "project",
                route is 0 or 6 ? null : route is 5 or 10 ? "reader" : RoleId)
        };
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
            request.IsMutation ? client.CreateReceipt(request) : null);
        string[] operations =
        [
            "infisical.get.v1.organization.roles",
            "infisical.post.v1.organization.roles",
            "infisical.delete.v1.organization.roles.by.roleId",
            "infisical.get.v1.organization.roles.by.roleId",
            "infisical.patch.v1.organization.roles.by.roleId",
            "infisical.get.v1.organization.roles.slug.by.roleSlug",
            "infisical.get.v1.projects.by.projectId.roles",
            "infisical.post.v1.projects.by.projectId.roles",
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId",
            "infisical.patch.v1.projects.by.projectId.roles.by.roleId",
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug",
            "infisical.get.v1.projects.roles.by.roleId"
        ];
        await Assert.That(request.OperationId).IsEqualTo(operations[route]);
        transport.Dispose();
        if (verify is not null)
        {
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await verify(result.Value);
        }
        return result.Status;
    }
}
