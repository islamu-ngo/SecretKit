using System.Net;
using System.Text;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectAuditWitnessTests
{
    private const string Org = "10000000-0000-0000-0000-000000000001";
    private const string Project = "20000000-0000-0000-0000-000000000002";
    private const string EnvironmentId = "30000000-0000-0000-0000-000000000003";
    private const string Tag = "40000000-0000-0000-0000-000000000004";
    private const string Foreign = "90000000-0000-0000-0000-000000000009";
    private const string Created = "2026-01-01T00:00:00Z";
    private const string Updated = "2026-01-02T00:00:00Z";

    // N04: native 200 profiles 0497 (POST), 0502 (PATCH), 0499 (DELETE).
    // Required children are tested only inside their admitted containing branch.
    [Test]
    [Arguments("create", "", "valid")]
    [Arguments("create", "id", "missing")]
    [Arguments("create", "id", "null")]
    [Arguments("create", "id", "type")]
    [Arguments("create", "name", "missing")]
    [Arguments("create", "name", "null")]
    [Arguments("create", "name", "type")]
    [Arguments("create", "slug", "missing")]
    [Arguments("create", "slug", "null")]
    [Arguments("create", "slug", "type")]
    [Arguments("create", "orgId", "missing")]
    [Arguments("create", "orgId", "null")]
    [Arguments("create", "orgId", "type")]
    [Arguments("create", "type", "missing")]
    [Arguments("create", "type", "null")]
    [Arguments("create", "type", "type")]
    [Arguments("create", "createdAt", "missing")]
    [Arguments("create", "createdAt", "null")]
    [Arguments("create", "createdAt", "type")]
    [Arguments("create", "updatedAt", "missing")]
    [Arguments("create", "updatedAt", "null")]
    [Arguments("create", "updatedAt", "type")]
    [Arguments("create", "orgId", "foreign")]
    [Arguments("create", "type", "foreign")]
    [Arguments("create", "slug", "foreign")]
    [Arguments("update", "", "valid")]
    [Arguments("update", "id", "missing")]
    [Arguments("update", "id", "null")]
    [Arguments("update", "id", "type")]
    [Arguments("update", "name", "missing")]
    [Arguments("update", "name", "null")]
    [Arguments("update", "name", "type")]
    [Arguments("update", "slug", "missing")]
    [Arguments("update", "slug", "null")]
    [Arguments("update", "slug", "type")]
    [Arguments("update", "orgId", "missing")]
    [Arguments("update", "orgId", "null")]
    [Arguments("update", "orgId", "type")]
    [Arguments("update", "type", "missing")]
    [Arguments("update", "type", "null")]
    [Arguments("update", "type", "type")]
    [Arguments("update", "createdAt", "missing")]
    [Arguments("update", "createdAt", "null")]
    [Arguments("update", "createdAt", "type")]
    [Arguments("update", "updatedAt", "missing")]
    [Arguments("update", "updatedAt", "null")]
    [Arguments("update", "updatedAt", "type")]
    [Arguments("update", "orgId", "foreign")]
    [Arguments("update", "type", "foreign")]
    [Arguments("update", "id", "foreign")]
    [Arguments("delete", "", "valid")]
    [Arguments("delete", "id", "missing")]
    [Arguments("delete", "id", "null")]
    [Arguments("delete", "id", "type")]
    [Arguments("delete", "name", "missing")]
    [Arguments("delete", "name", "null")]
    [Arguments("delete", "name", "type")]
    [Arguments("delete", "slug", "missing")]
    [Arguments("delete", "slug", "null")]
    [Arguments("delete", "slug", "type")]
    [Arguments("delete", "orgId", "missing")]
    [Arguments("delete", "orgId", "null")]
    [Arguments("delete", "orgId", "type")]
    [Arguments("delete", "type", "missing")]
    [Arguments("delete", "type", "null")]
    [Arguments("delete", "type", "type")]
    [Arguments("delete", "createdAt", "missing")]
    [Arguments("delete", "createdAt", "null")]
    [Arguments("delete", "createdAt", "type")]
    [Arguments("delete", "updatedAt", "missing")]
    [Arguments("delete", "updatedAt", "null")]
    [Arguments("delete", "updatedAt", "type")]
    [Arguments("delete", "orgId", "foreign")]
    [Arguments("delete", "type", "foreign")]
    [Arguments("delete", "id", "foreign")]
    [Arguments("create", "_id", "missing")]
    [Arguments("create", "_id", "null")]
    [Arguments("create", "_id", "type")]
    [Arguments("create", "environments", "missing")]
    [Arguments("create", "environments", "null")]
    [Arguments("create", "environments", "type")]
    [Arguments("create", "deletedEnvironments", "missing")]
    [Arguments("create", "deletedEnvironments", "null")]
    [Arguments("create", "deletedEnvironments", "type")]
    [Arguments("create", "environments/0/id", "missing")]
    [Arguments("create", "environments/0/id", "null")]
    [Arguments("create", "environments/0/id", "type")]
    [Arguments("create", "environments/0/name", "missing")]
    [Arguments("create", "environments/0/name", "null")]
    [Arguments("create", "environments/0/name", "type")]
    [Arguments("create", "environments/0/slug", "missing")]
    [Arguments("create", "environments/0/slug", "null")]
    [Arguments("create", "environments/0/slug", "type")]
    [Arguments("create", "deletedEnvironments/0/id", "missing")]
    [Arguments("create", "deletedEnvironments/0/id", "null")]
    [Arguments("create", "deletedEnvironments/0/id", "type")]
    [Arguments("create", "deletedEnvironments/1/id", "missing")]
    [Arguments("create", "deletedEnvironments/1/id", "null")]
    [Arguments("create", "deletedEnvironments/1/id", "type")]
    [Arguments("create", "deletedEnvironments/2/id", "missing")]
    [Arguments("create", "deletedEnvironments/2/id", "null")]
    [Arguments("create", "deletedEnvironments/2/id", "type")]
    [Arguments("create", "deletedEnvironments/0/name", "missing")]
    [Arguments("create", "deletedEnvironments/0/name", "null")]
    [Arguments("create", "deletedEnvironments/0/name", "type")]
    [Arguments("create", "deletedEnvironments/1/name", "missing")]
    [Arguments("create", "deletedEnvironments/1/name", "null")]
    [Arguments("create", "deletedEnvironments/1/name", "type")]
    [Arguments("create", "deletedEnvironments/2/name", "missing")]
    [Arguments("create", "deletedEnvironments/2/name", "null")]
    [Arguments("create", "deletedEnvironments/2/name", "type")]
    [Arguments("create", "deletedEnvironments/0/slug", "missing")]
    [Arguments("create", "deletedEnvironments/0/slug", "null")]
    [Arguments("create", "deletedEnvironments/0/slug", "type")]
    [Arguments("create", "deletedEnvironments/1/slug", "missing")]
    [Arguments("create", "deletedEnvironments/1/slug", "null")]
    [Arguments("create", "deletedEnvironments/1/slug", "type")]
    [Arguments("create", "deletedEnvironments/2/slug", "missing")]
    [Arguments("create", "deletedEnvironments/2/slug", "null")]
    [Arguments("create", "deletedEnvironments/2/slug", "type")]
    [Arguments("create", "deletedEnvironments/0/deleteAfter", "missing")]
    [Arguments("create", "deletedEnvironments/0/deleteAfter", "null")]
    [Arguments("create", "deletedEnvironments/0/deleteAfter", "type")]
    [Arguments("create", "deletedEnvironments/1/deleteAfter", "missing")]
    [Arguments("create", "deletedEnvironments/1/deleteAfter", "null")]
    [Arguments("create", "deletedEnvironments/1/deleteAfter", "type")]
    [Arguments("create", "deletedEnvironments/2/deleteAfter", "missing")]
    [Arguments("create", "deletedEnvironments/2/deleteAfter", "null")]
    [Arguments("create", "deletedEnvironments/2/deleteAfter", "type")]
    [Arguments("create", "deletedEnvironments/0/softDeletedAt", "missing")]
    [Arguments("create", "deletedEnvironments/0/softDeletedAt", "null")]
    [Arguments("create", "deletedEnvironments/0/softDeletedAt", "type")]
    [Arguments("create", "deletedEnvironments/1/softDeletedAt", "missing")]
    [Arguments("create", "deletedEnvironments/1/softDeletedAt", "null")]
    [Arguments("create", "deletedEnvironments/1/softDeletedAt", "type")]
    [Arguments("create", "deletedEnvironments/2/softDeletedAt", "missing")]
    [Arguments("create", "deletedEnvironments/2/softDeletedAt", "null")]
    [Arguments("create", "deletedEnvironments/2/softDeletedAt", "type")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/id", "missing")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/id", "null")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/id", "type")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/name", "missing")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/name", "null")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/name", "type")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/type", "missing")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/type", "null")]
    [Arguments("create", "deletedEnvironments/0/deletedBy/type", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/id", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/id", "null")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/id", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/type", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/type", "null")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/type", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/email", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/email", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/username", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/username", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/firstName", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/firstName", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/lastName", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy/lastName", "type")]
    [Arguments("create", "deletedEnvironments/0/deletedBy", "missing")]
    [Arguments("create", "deletedEnvironments/0/deletedBy", "type")]
    [Arguments("create", "deletedEnvironments/1/deletedBy", "missing")]
    [Arguments("create", "deletedEnvironments/1/deletedBy", "type")]
    [Arguments("create", "deletedEnvironments/2/deletedBy", "missing")]
    [Arguments("create", "deletedEnvironments/2/deletedBy", "type")]
    public async Task ProjectMutationRequiredLeavesAndSelectedCoordinates(string row, string field, string defect)
    {
        var project = ProjectFixture(row);
        if (defect != "valid") Defect(project, field, defect);
        using var request = row switch
        {
            "create" => ProjectOperations.CreateProject(Org, "audit-project", "audit-project"),
            "update" => ProjectOperations.UpdateProject(Org, Project, name: "audit-project"),
            _ => ProjectOperations.DeleteProject(Org, Project)
        };
        var approved = row switch
        {
            "create" => ProjectOperations.ProjectCreateTarget(Org, "audit-project", "audit-project"),
            "update" => ProjectOperations.ProjectUpdateTarget(Org, Project, name: "audit-project"),
            _ => new ManagementTarget(Org, Project)
        };
        var result = await Execute(request, approved, new JsonObject { ["project"] = project },
            HttpMethodFor(row), row == "create" ? "/api/v1/projects" : "/api/v1/projects/" + Project,
            defect, row == "create" ? null : Project);
        if (defect == "valid")
        {
            await Assert.That(result.Value.Id).IsEqualTo(Project);
            await Assert.That(result.Value.CreatedAt.Value).IsEqualTo(Created);
            await Assert.That(result.Value.UpdatedAt.Value).IsEqualTo(Updated);
            await Assert.That(result.Value.Environments.IsPresent).IsEqualTo(row == "create");
            await Assert.That(result.Value.DeletedEnvironments.IsPresent).IsEqualTo(row == "create");
            await Assert.That(result.Value.NativeId.IsPresent).IsEqualTo(row == "create");
            if (row == "create")
            {
                await Assert.That(result.Value.Environments.Value[0].Slug).IsEqualTo("dev");
                await Assert.That(result.Value.DeletedEnvironments.Value[0].DeletedBy!.Name).IsEqualTo("machine");
                await Assert.That(result.Value.DeletedEnvironments.Value[1].DeletedBy!.Email is null).IsTrue();
                await Assert.That(result.Value.DeletedEnvironments.Value[2].DeletedBy is null).IsTrue();
            }
        }
    }

    // N05: 0508 inspection has no root projectId/message; 0506 mutation has both.
    [Test]
    [Arguments("get", "", "valid")]
    [Arguments("get", "environment/id", "missing")]
    [Arguments("get", "environment/id", "null")]
    [Arguments("get", "environment/id", "type")]
    [Arguments("get", "environment/name", "missing")]
    [Arguments("get", "environment/name", "null")]
    [Arguments("get", "environment/name", "type")]
    [Arguments("get", "environment/slug", "missing")]
    [Arguments("get", "environment/slug", "null")]
    [Arguments("get", "environment/slug", "type")]
    [Arguments("get", "environment/position", "missing")]
    [Arguments("get", "environment/position", "null")]
    [Arguments("get", "environment/position", "type")]
    [Arguments("get", "environment/projectId", "missing")]
    [Arguments("get", "environment/projectId", "null")]
    [Arguments("get", "environment/projectId", "type")]
    [Arguments("get", "environment/createdAt", "missing")]
    [Arguments("get", "environment/createdAt", "null")]
    [Arguments("get", "environment/createdAt", "type")]
    [Arguments("get", "environment/updatedAt", "missing")]
    [Arguments("get", "environment/updatedAt", "null")]
    [Arguments("get", "environment/updatedAt", "type")]
    [Arguments("get", "environment/projectId", "foreign")]
    [Arguments("get", "environment/id", "foreign")]
    [Arguments("slug", "", "valid")]
    [Arguments("slug", "environment/id", "missing")]
    [Arguments("slug", "environment/id", "null")]
    [Arguments("slug", "environment/id", "type")]
    [Arguments("slug", "environment/name", "missing")]
    [Arguments("slug", "environment/name", "null")]
    [Arguments("slug", "environment/name", "type")]
    [Arguments("slug", "environment/slug", "missing")]
    [Arguments("slug", "environment/slug", "null")]
    [Arguments("slug", "environment/slug", "type")]
    [Arguments("slug", "environment/position", "missing")]
    [Arguments("slug", "environment/position", "null")]
    [Arguments("slug", "environment/position", "type")]
    [Arguments("slug", "environment/projectId", "missing")]
    [Arguments("slug", "environment/projectId", "null")]
    [Arguments("slug", "environment/projectId", "type")]
    [Arguments("slug", "environment/createdAt", "missing")]
    [Arguments("slug", "environment/createdAt", "null")]
    [Arguments("slug", "environment/createdAt", "type")]
    [Arguments("slug", "environment/updatedAt", "missing")]
    [Arguments("slug", "environment/updatedAt", "null")]
    [Arguments("slug", "environment/updatedAt", "type")]
    [Arguments("slug", "environment/projectId", "foreign")]
    [Arguments("slug", "environment/slug", "foreign")]
    [Arguments("delete", "", "valid")]
    [Arguments("delete", "environment/id", "missing")]
    [Arguments("delete", "environment/id", "null")]
    [Arguments("delete", "environment/id", "type")]
    [Arguments("delete", "environment/name", "missing")]
    [Arguments("delete", "environment/name", "null")]
    [Arguments("delete", "environment/name", "type")]
    [Arguments("delete", "environment/slug", "missing")]
    [Arguments("delete", "environment/slug", "null")]
    [Arguments("delete", "environment/slug", "type")]
    [Arguments("delete", "environment/position", "missing")]
    [Arguments("delete", "environment/position", "null")]
    [Arguments("delete", "environment/position", "type")]
    [Arguments("delete", "environment/projectId", "missing")]
    [Arguments("delete", "environment/projectId", "null")]
    [Arguments("delete", "environment/projectId", "type")]
    [Arguments("delete", "environment/createdAt", "missing")]
    [Arguments("delete", "environment/createdAt", "null")]
    [Arguments("delete", "environment/createdAt", "type")]
    [Arguments("delete", "environment/updatedAt", "missing")]
    [Arguments("delete", "environment/updatedAt", "null")]
    [Arguments("delete", "environment/updatedAt", "type")]
    [Arguments("delete", "environment/projectId", "foreign")]
    [Arguments("delete", "environment/id", "foreign")]
    [Arguments("delete", "projectId", "missing")]
    [Arguments("delete", "projectId", "null")]
    [Arguments("delete", "projectId", "type")]
    [Arguments("delete", "projectId", "foreign")]
    [Arguments("restore", "", "valid")]
    [Arguments("restore", "environment/id", "missing")]
    [Arguments("restore", "environment/id", "null")]
    [Arguments("restore", "environment/id", "type")]
    [Arguments("restore", "environment/name", "missing")]
    [Arguments("restore", "environment/name", "null")]
    [Arguments("restore", "environment/name", "type")]
    [Arguments("restore", "environment/slug", "missing")]
    [Arguments("restore", "environment/slug", "null")]
    [Arguments("restore", "environment/slug", "type")]
    [Arguments("restore", "environment/position", "missing")]
    [Arguments("restore", "environment/position", "null")]
    [Arguments("restore", "environment/position", "type")]
    [Arguments("restore", "environment/projectId", "missing")]
    [Arguments("restore", "environment/projectId", "null")]
    [Arguments("restore", "environment/projectId", "type")]
    [Arguments("restore", "environment/createdAt", "missing")]
    [Arguments("restore", "environment/createdAt", "null")]
    [Arguments("restore", "environment/createdAt", "type")]
    [Arguments("restore", "environment/updatedAt", "missing")]
    [Arguments("restore", "environment/updatedAt", "null")]
    [Arguments("restore", "environment/updatedAt", "type")]
    [Arguments("restore", "environment/projectId", "foreign")]
    [Arguments("restore", "environment/id", "foreign")]
    [Arguments("restore", "projectId", "missing")]
    [Arguments("restore", "projectId", "null")]
    [Arguments("restore", "projectId", "type")]
    [Arguments("restore", "projectId", "foreign")]
    public async Task EnvironmentRequiredLeavesAndSelectedCoordinates(string row, string field, string defect)
    {
        var envelope = new JsonObject { ["environment"] = EnvironmentFixture() };
        if (row is "delete" or "restore")
        {
            envelope["projectId"] = Project;
            envelope["message"] = "done";
        }
        if (defect != "valid") Defect(envelope, field, defect);
        using var request = row switch
        {
            "get" => ProjectOperations.GetEnvironment(Org, Project, EnvironmentId),
            "slug" => ProjectOperations.GetEnvironmentBySlug(Org, Project, "dev"),
            "delete" => ProjectOperations.DeleteEnvironment(Org, Project, EnvironmentId),
            _ => ProjectOperations.RestoreEnvironment(Org, Project, EnvironmentId)
        };
        var approved = new ManagementTarget(Org, Project, row == "slug" ? "dev" : EnvironmentId,
            row == "delete" ? "soft-delete" : null);
        string path = "/api/v1/projects/" + Project + "/environments/" +
            (row == "slug" ? "slug/dev" : EnvironmentId) + (row == "restore" ? "/restore" : "");
        var result = await Execute(request, approved, envelope, HttpMethodFor(row), path, defect, Project,
            row == "delete" ? "?hardDelete=false" : "");
        if (defect == "valid")
        {
            await Assert.That(result.Value.Position).IsEqualTo(1.5);
            await Assert.That(result.Value.CreatedAt.Value).IsEqualTo(Created);
            await Assert.That(result.Value.UpdatedAt.Value).IsEqualTo(Updated);
            await Assert.That(result.Value.DeletedByUserId.IsPresent).IsFalse();
            await Assert.That(result.Value.DeletedByIdentityId.IsPresent).IsFalse();
            await Assert.That(result.Value.SoftDeletedAtField.IsPresent).IsFalse();
            await Assert.That(result.Value.DeleteAfterField.IsPresent).IsFalse();
        }
    }

    // N08: 0546 list, 0548 mutations, 0550 GET (the only required name branch).
    [Test]
    [Arguments("list", "", "valid")]
    [Arguments("list", "id", "missing")]
    [Arguments("list", "id", "null")]
    [Arguments("list", "id", "type")]
    [Arguments("list", "slug", "missing")]
    [Arguments("list", "slug", "null")]
    [Arguments("list", "slug", "type")]
    [Arguments("list", "projectId", "missing")]
    [Arguments("list", "projectId", "null")]
    [Arguments("list", "projectId", "type")]
    [Arguments("list", "createdAt", "missing")]
    [Arguments("list", "createdAt", "null")]
    [Arguments("list", "createdAt", "type")]
    [Arguments("list", "updatedAt", "missing")]
    [Arguments("list", "updatedAt", "null")]
    [Arguments("list", "updatedAt", "type")]
    [Arguments("list", "projectId", "foreign")]
    [Arguments("create", "", "valid")]
    [Arguments("create", "id", "missing")]
    [Arguments("create", "id", "null")]
    [Arguments("create", "id", "type")]
    [Arguments("create", "slug", "missing")]
    [Arguments("create", "slug", "null")]
    [Arguments("create", "slug", "type")]
    [Arguments("create", "projectId", "missing")]
    [Arguments("create", "projectId", "null")]
    [Arguments("create", "projectId", "type")]
    [Arguments("create", "createdAt", "missing")]
    [Arguments("create", "createdAt", "null")]
    [Arguments("create", "createdAt", "type")]
    [Arguments("create", "updatedAt", "missing")]
    [Arguments("create", "updatedAt", "null")]
    [Arguments("create", "updatedAt", "type")]
    [Arguments("create", "projectId", "foreign")]
    [Arguments("create", "slug", "foreign")]
    [Arguments("delete", "", "valid")]
    [Arguments("delete", "id", "missing")]
    [Arguments("delete", "id", "null")]
    [Arguments("delete", "id", "type")]
    [Arguments("delete", "slug", "missing")]
    [Arguments("delete", "slug", "null")]
    [Arguments("delete", "slug", "type")]
    [Arguments("delete", "projectId", "missing")]
    [Arguments("delete", "projectId", "null")]
    [Arguments("delete", "projectId", "type")]
    [Arguments("delete", "createdAt", "missing")]
    [Arguments("delete", "createdAt", "null")]
    [Arguments("delete", "createdAt", "type")]
    [Arguments("delete", "updatedAt", "missing")]
    [Arguments("delete", "updatedAt", "null")]
    [Arguments("delete", "updatedAt", "type")]
    [Arguments("delete", "projectId", "foreign")]
    [Arguments("delete", "id", "foreign")]
    [Arguments("get", "", "valid")]
    [Arguments("get", "id", "missing")]
    [Arguments("get", "id", "null")]
    [Arguments("get", "id", "type")]
    [Arguments("get", "slug", "missing")]
    [Arguments("get", "slug", "null")]
    [Arguments("get", "slug", "type")]
    [Arguments("get", "projectId", "missing")]
    [Arguments("get", "projectId", "null")]
    [Arguments("get", "projectId", "type")]
    [Arguments("get", "createdAt", "missing")]
    [Arguments("get", "createdAt", "null")]
    [Arguments("get", "createdAt", "type")]
    [Arguments("get", "updatedAt", "missing")]
    [Arguments("get", "updatedAt", "null")]
    [Arguments("get", "updatedAt", "type")]
    [Arguments("get", "name", "missing")]
    [Arguments("get", "name", "null")]
    [Arguments("get", "name", "type")]
    [Arguments("get", "projectId", "foreign")]
    [Arguments("get", "id", "foreign")]
    [Arguments("update", "", "valid")]
    [Arguments("update", "id", "missing")]
    [Arguments("update", "id", "null")]
    [Arguments("update", "id", "type")]
    [Arguments("update", "slug", "missing")]
    [Arguments("update", "slug", "null")]
    [Arguments("update", "slug", "type")]
    [Arguments("update", "projectId", "missing")]
    [Arguments("update", "projectId", "null")]
    [Arguments("update", "projectId", "type")]
    [Arguments("update", "createdAt", "missing")]
    [Arguments("update", "createdAt", "null")]
    [Arguments("update", "createdAt", "type")]
    [Arguments("update", "updatedAt", "missing")]
    [Arguments("update", "updatedAt", "null")]
    [Arguments("update", "updatedAt", "type")]
    [Arguments("update", "projectId", "foreign")]
    [Arguments("update", "id", "foreign")]
    [Arguments("slug", "", "valid")]
    [Arguments("slug", "id", "missing")]
    [Arguments("slug", "id", "null")]
    [Arguments("slug", "id", "type")]
    [Arguments("slug", "slug", "missing")]
    [Arguments("slug", "slug", "null")]
    [Arguments("slug", "slug", "type")]
    [Arguments("slug", "projectId", "missing")]
    [Arguments("slug", "projectId", "null")]
    [Arguments("slug", "projectId", "type")]
    [Arguments("slug", "createdAt", "missing")]
    [Arguments("slug", "createdAt", "null")]
    [Arguments("slug", "createdAt", "type")]
    [Arguments("slug", "updatedAt", "missing")]
    [Arguments("slug", "updatedAt", "null")]
    [Arguments("slug", "updatedAt", "type")]
    [Arguments("slug", "name", "missing")]
    [Arguments("slug", "name", "null")]
    [Arguments("slug", "name", "type")]
    [Arguments("slug", "projectId", "foreign")]
    [Arguments("slug", "slug", "foreign")]
    public async Task TagRequiredLeavesAndSelectedCoordinates(string row, string field, string defect)
    {
        var tag = TagFixture(row);
        if (defect != "valid") Defect(tag, field, defect);
        var envelope = row == "list" ? new JsonObject { ["tags"] = new JsonArray(tag) }
            : new JsonObject { ["tag"] = tag };
        string path = "/api/v1/projects/" + Project + "/tags";
        if (row == "slug") path += "/slug/audit-tag";
        else if (row is "get" or "update" or "delete") path += "/" + Tag;
        if (row == "list")
        {
            using var request = ProjectOperations.ListTags(Org, Project);
            var result = await Execute(request, new(Org, Project), envelope, HttpMethod.Get, path, defect, Project);
            if (defect == "valid")
            {
                await Assert.That(result.Value.Items.Count).IsEqualTo(1);
                await AssertTag(result.Value.Items[0], row);
            }
        }
        else
        {
            using var request = row switch
            {
                "create" => ProjectOperations.CreateTag(Org, Project, "audit-tag", "blue"),
                "get" => ProjectOperations.GetTag(Org, Project, Tag),
                "slug" => ProjectOperations.GetTagBySlug(Org, Project, "audit-tag"),
                "update" => ProjectOperations.UpdateTag(Org, Project, Tag, "audit-tag", "blue"),
                _ => ProjectOperations.DeleteTag(Org, Project, Tag)
            };
            var approved = row switch
            {
                "create" => ProjectOperations.TagCreateTarget(Org, Project, "audit-tag", "blue"),
                "update" => ProjectOperations.TagUpdateTarget(Org, Project, Tag, "audit-tag", "blue"),
                "slug" => new(Org, Project, "audit-tag"),
                _ => new ManagementTarget(Org, Project, Tag)
            };
            var result = await Execute(request, approved, envelope, HttpMethodFor(row), path, defect, Project);
            if (defect == "valid") await AssertTag(result.Value, row);
        }
    }

    // I08: POST only. Collection grants are separately selected at the same org/name.
    // Name itself is the native creation coordinate; changing it also changes that coordinate.
    [Test]
    [Arguments("roles", "value")]
    [Arguments("roles", "omitted")]
    [Arguments("roles", "empty")]
    [Arguments("roles", "order")]
    [Arguments("environments", "value")]
    [Arguments("environments", "omitted")]
    [Arguments("environments", "empty")]
    [Arguments("environments", "order")]
    [Arguments("users", "value")]
    [Arguments("users", "omitted")]
    [Arguments("users", "empty")]
    [Arguments("users", "order")]
    [Arguments("groups", "value")]
    [Arguments("groups", "omitted")]
    [Arguments("groups", "empty")]
    [Arguments("groups", "order")]
    [Arguments("identities", "value")]
    [Arguments("identities", "omitted")]
    [Arguments("identities", "empty")]
    [Arguments("identities", "order")]
    [Arguments("projectManagedIdentities", "value")]
    [Arguments("projectManagedIdentities", "omitted")]
    [Arguments("projectManagedIdentities", "empty")]
    [Arguments("projectManagedIdentities", "order")]
    [Arguments("name", "value")]
    [Arguments("environments", "null")]
    public async Task TemplateCreationRejectsIndependentConfigurationChoices(string field, string shape)
    {
        using var incoming = ProjectTemplateOperations.CreateProjectTemplate(Org,
            field == "name" ? "other-template" : "audit-template", configuration: Configuration(field, shape));
        var approved = ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "audit-template", configuration: Configuration());
        var server = new Server(TemplateFixture(), HttpMethod.Post, "/api/v1/project-templates");
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var receipt = client.CreateReceipt(incoming);
        var result = await client.ExecuteAsync(incoming, authority, authority.IssueGrant(incoming.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(server.Body is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task TemplateCreationCopiesAllSixCollectionsBeforeDispatch()
    {
        string[] assignedRoles = ["reader"];
        ProjectTemplateRole[] roles = [new("Role", "reader", [])];
        ProjectTemplateEnvironment[] environments = [new("Development", "dev", 1.5)];
        ProjectTemplateUser[] users = [new("user", assignedRoles)];
        ProjectTemplateGroup[] groups = [new("group", assignedRoles)];
        ProjectTemplateIdentity[] identities = [new(Tag, assignedRoles)];
        ProjectTemplateManagedIdentity[] managed = [new("machine", assignedRoles)];
        var configuration = new ProjectTemplateConfiguration(roles,
            ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues(environments),
            ProjectTemplateCollection<ProjectTemplateUser>.FromValues(users),
            ProjectTemplateCollection<ProjectTemplateGroup>.FromValues(groups),
            ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues(identities),
            ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues(managed));
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "audit-template", configuration: configuration);
        assignedRoles[0] = "owner";
        roles[0] = new("Other", "other", []);
        environments[0] = new("Other", "other", 2);
        users[0] = new("other", ["owner"]);
        groups[0] = new("other", ["owner"]);
        identities[0] = new(Foreign, ["owner"]);
        managed[0] = new("other", ["owner"]);
        byte[] wireCopy = request.CopyBody()!;
        Array.Clear(wireCopy);
        var approved = ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "audit-template", configuration: SingleConfiguration());
        var server = new Server(TemplateFixture(single: true), HttpMethod.Post, "/api/v1/project-templates");
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        var body = server.Body!;
        await Assert.That(body.Count).IsEqualTo(8);
        await Assert.That(body.ContainsKey("description")).IsFalse();
        await Assert.That(body["name"]!.GetValue<string>()).IsEqualTo("audit-template");
        await Assert.That(body["roles"]![0]!["name"]!.GetValue<string>()).IsEqualTo("Role");
        await Assert.That(body["environments"]![0]!["slug"]!.GetValue<string>()).IsEqualTo("dev");
        await Assert.That(body["environments"]![0]!["position"]!.GetValue<double>()).IsEqualTo(1.5);
        await Assert.That(body["users"]![0]!["username"]!.GetValue<string>()).IsEqualTo("user");
        await Assert.That(body["groups"]![0]!["groupSlug"]!.GetValue<string>()).IsEqualTo("group");
        await Assert.That(body["identities"]![0]!["identityId"]!.GetValue<string>()).IsEqualTo(Tag);
        await Assert.That(body["projectManagedIdentities"]![0]!["name"]!.GetValue<string>()).IsEqualTo("machine");
        foreach (string field in new[] { "users", "groups", "identities", "projectManagedIdentities" })
            await Assert.That(body[field]![0]!["roles"]![0]!.GetValue<string>()).IsEqualTo("reader");
        await Assert.That(result.Value.Roles[0].Name).IsEqualTo("Role");
        await Assert.That(result.Value.Environments![0].Slug).IsEqualTo("dev");
        await Assert.That(result.Value.Users![0].Username).IsEqualTo("user");
        await Assert.That(result.Value.Groups![0].GroupSlug).IsEqualTo("group");
        await Assert.That(result.Value.Identities![0].IdentityId).IsEqualTo(Tag);
        await Assert.That(result.Value.ProjectManagedIdentities![0].Name).IsEqualTo("machine");
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("empty")]
    [Arguments("null")]
    public async Task TemplateCreationPreservesAdmittedCollectionOmissions(string shape)
    {
        var configuration = shape switch
        {
            "omitted" => null,
            "empty" => new ProjectTemplateConfiguration(roles: [],
                environments: ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([]),
                users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([]),
                groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([]),
                identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([]),
                projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([])),
            _ => new ProjectTemplateConfiguration(environments: ProjectTemplateCollection<ProjectTemplateEnvironment>.Null())
        };
        using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "audit-template", configuration: configuration);
        var fixture = new JsonObject
        {
            ["projectTemplate"] = new JsonObject
            {
                ["id"] = EnvironmentId,
                ["orgId"] = Org,
                ["name"] = "audit-template",
                ["createdAt"] = Created,
                ["updatedAt"] = Updated,
                ["roles"] = new JsonArray(),
                ["environments"] = null,
                ["users"] = null,
                ["groups"] = null,
                ["identities"] = null,
                ["projectManagedIdentities"] = null
            }
        };
        if (shape == "empty")
            foreach (string field in new[] { "environments", "users", "groups", "identities", "projectManagedIdentities" })
                fixture["projectTemplate"]![field] = new JsonArray();
        var server = new Server(fixture, HttpMethod.Post, "/api/v1/project-templates");
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "audit-template", configuration: configuration)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Type is null).IsTrue();
        await Assert.That(result.Value.Description is null).IsTrue();
        await Assert.That(server.Body!.ContainsKey("description")).IsFalse();
        foreach (string field in new[] { "roles", "environments", "users", "groups", "identities", "projectManagedIdentities" })
        {
            bool present = shape == "empty" || (shape == "null" && field == "environments");
            await Assert.That(server.Body.ContainsKey(field)).IsEqualTo(present);
            if (present && shape == "empty") await Assert.That(server.Body[field]!.AsArray().Count).IsEqualTo(0);
        }
        if (shape == "null") await Assert.That(server.Body["environments"] is null).IsTrue();
    }

    private static ProjectTemplateConfiguration SingleConfiguration() => new(
        roles: [new("Role", "reader", [])],
        environments: ProjectTemplateCollection<ProjectTemplateEnvironment>.FromValues([new("Development", "dev", 1.5)]),
        users: ProjectTemplateCollection<ProjectTemplateUser>.FromValues([new("user", ["reader"])]),
        groups: ProjectTemplateCollection<ProjectTemplateGroup>.FromValues([new("group", ["reader"])]),
        identities: ProjectTemplateCollection<ProjectTemplateIdentity>.FromValues([new(Tag, ["reader"])]),
        projectManagedIdentities: ProjectTemplateCollection<ProjectTemplateManagedIdentity>.FromValues([new("machine", ["reader"])]));

    private static ProjectTemplateConfiguration Configuration(string? changed = null, string shape = "value")
    {
        ProjectTemplateRole[] roles = [new(changed == "roles" && shape == "value" ? "Other" : "Role", "reader", []), new("Second", "second", [])];
        ProjectTemplateEnvironment[] environments = [new("Development", changed == "environments" && shape == "value" ? "other" : "dev", 1.5), new("Production", "prod", 2.5)];
        ProjectTemplateUser[] users = [new(changed == "users" && shape == "value" ? "other" : "user", ["reader"]), new("second", ["reader"])];
        ProjectTemplateGroup[] groups = [new(changed == "groups" && shape == "value" ? "other" : "group", ["reader"]), new("second", ["reader"])];
        ProjectTemplateIdentity[] identities = [new(changed == "identities" && shape == "value" ? Foreign : Tag, ["reader"]), new(EnvironmentId, ["reader"])];
        ProjectTemplateManagedIdentity[] managed = [new(changed == "projectManagedIdentities" && shape == "value" ? "other" : "machine", ["reader"]), new("second", ["reader"])];
        if (changed == "roles" && shape == "order") Array.Reverse(roles);
        return new(roles: changed == "roles" && shape == "omitted" ? null : changed == "roles" && shape == "empty" ? [] : roles,
            environments: changed == "environments" && shape == "null" ? ProjectTemplateCollection<ProjectTemplateEnvironment>.Null() : Choice(environments, "environments", changed, shape),
            users: Choice(users, "users", changed, shape), groups: Choice(groups, "groups", changed, shape),
            identities: Choice(identities, "identities", changed, shape), projectManagedIdentities: Choice(managed, "projectManagedIdentities", changed, shape));
    }

    private static ProjectTemplateCollection<T>? Choice<T>(T[] values, string field, string? changed, string shape) where T : class
    {
        if (field == changed)
        {
            if (shape == "omitted") return null;
            if (shape == "empty") return ProjectTemplateCollection<T>.FromValues([]);
            if (shape == "order") Array.Reverse(values);
        }
        return ProjectTemplateCollection<T>.FromValues(values);
    }

    private static JsonObject TemplateFixture(bool single = false)
    {
        using var selected = ProjectTemplateOperations.CreateProjectTemplate(Org, "audit-template",
            configuration: single ? SingleConfiguration() : Configuration());
        byte[] bytes = selected.CopyBody()!;
        try
        {
            var value = JsonNode.Parse(bytes)!.AsObject();
            value.Remove("type");
            value["id"] = EnvironmentId;
            value["orgId"] = Org;
            value["createdAt"] = Created;
            value["updatedAt"] = Updated;
            foreach (var identity in value["identities"]!.AsArray()) identity!["identityName"] = "returned-machine";
            return new JsonObject { ["projectTemplate"] = value };
        }
        finally { Array.Clear(bytes); }
    }

    private static async Task AssertTag(ProjectTag value, string row)
    {
        await Assert.That(value.Id).IsEqualTo(Tag);
        await Assert.That(value.Slug).IsEqualTo("audit-tag");
        await Assert.That(value.CreatedAt.Value).IsEqualTo(Created);
        await Assert.That(value.UpdatedAt.Value).IsEqualTo(Updated);
        await Assert.That(value.Name).IsEqualTo(row is "get" or "slug" ? "audit-tag-name" : null);
        await Assert.That(value.ColorField.IsPresent).IsFalse();
        await Assert.That(value.CreatedBy.IsPresent).IsFalse();
        await Assert.That(value.CreatedByActorType.IsPresent).IsFalse();
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request,
        ManagementTarget approved, JsonObject response, HttpMethod method, string path, string defect,
        string? project, string query = "") where T : notnull
    {
        var server = new Server(response, method, path, query);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, project);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(tokens.Acquired).IsTrue();
        await Assert.That(server.Dispatched).IsTrue();
        await Assert.That(result.Status).IsEqualTo(defect switch
        {
            "valid" => SecretStatus.Success,
            "foreign" => SecretStatus.Invalid,
            _ => SecretStatus.Unknown
        });
        if (receipt is not null)
            await Assert.That(receipt.Evidence).IsEqualTo(defect == "valid" ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        return result;
    }

    private static JsonObject ProjectFixture(string row)
    {
        var project = new JsonObject
        {
            ["id"] = Project,
            ["orgId"] = Org,
            ["name"] = "audit-project",
            ["slug"] = "audit-project",
            ["type"] = "secret-manager",
            ["createdAt"] = Created,
            ["updatedAt"] = Updated
        };
        if (row == "create")
        {
            project["_id"] = Project;
            project["environments"] = new JsonArray(new JsonObject { ["id"] = EnvironmentId, ["name"] = "Development", ["slug"] = "dev" });
            var deleted = new JsonArray();
            for (int i = 0; i < 3; i++)
                deleted.Add(new JsonObject
                {
                    ["id"] = EnvironmentId,
                    ["name"] = "Deleted",
                    ["slug"] = "old",
                    ["deleteAfter"] = Updated,
                    ["softDeletedAt"] = Created,
                    ["deletedBy"] = i switch
                    {
                        0 => new JsonObject { ["type"] = "identity", ["id"] = Tag, ["name"] = "machine" },
                        1 => new JsonObject
                        {
                            ["type"] = "user",
                            ["id"] = Tag,
                            ["email"] = null,
                            ["username"] = "user",
                            ["firstName"] = null,
                            ["lastName"] = "Last"
                        },
                        _ => null
                    }
                });
            project["deletedEnvironments"] = deleted;
        }
        return project;
    }

    private static JsonObject EnvironmentFixture() => new()
    {
        ["id"] = EnvironmentId,
        ["projectId"] = Project,
        ["name"] = "Development",
        ["slug"] = "dev",
        ["position"] = 1.5,
        ["createdAt"] = Created,
        ["updatedAt"] = Updated
    };

    private static JsonObject TagFixture(string row)
    {
        var tag = new JsonObject
        {
            ["id"] = Tag,
            ["projectId"] = Project,
            ["slug"] = "audit-tag",
            ["createdAt"] = Created,
            ["updatedAt"] = Updated
        };
        if (row is "get" or "slug") tag["name"] = "audit-tag-name";
        return tag;
    }

    private static void Defect(JsonObject root, string path, string defect)
    {
        string[] parts = path.Split('/');
        JsonNode node = root;
        foreach (string part in parts[..^1])
            node = node is JsonArray array ? array[int.Parse(part, System.Globalization.CultureInfo.InvariantCulture)]! : node[part]!;
        var parent = node.AsObject();
        string field = parts[^1];
        if (defect == "missing") parent.Remove(field);
        else if (defect == "null") parent[field] = null;
        else if (defect == "type") parent[field] = false;
        else parent[field] = field == "type" ? "kms" : Foreign;
    }

    private static HttpMethod HttpMethodFor(string row) => row switch
    {
        "create" or "restore" => HttpMethod.Post,
        "update" => HttpMethod.Patch,
        "delete" => HttpMethod.Delete,
        _ => HttpMethod.Get
    };

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-token"))));
        }
    }

    private sealed class Server(JsonObject response, HttpMethod method, string path, string query = "") : HttpMessageHandler
    {
        public bool Dispatched { get; private set; }
        public JsonObject? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Dispatched = true;
            await Assert.That(request.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo(path);
            await Assert.That(request.RequestUri.Query).IsEqualTo(query);
            await Assert.That(request.Headers.Authorization!.Scheme).IsEqualTo("Bearer");
            if (request.Content is not null)
                Body = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            return new(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json") };
        }
    }
}
