using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementUuidFormatTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Id = "22222222-2222-4222-8222-222222222222";
    private const string Time = "2026-10-11T00:00:00Z";

    [Test]
    [Arguments("organization-group-get")]
    [Arguments("organization-group-add")]
    [Arguments("organization-group-update")]
    [Arguments("organization-group-delete")]
    [Arguments("project-group-get")]
    [Arguments("project-group-add")]
    [Arguments("project-group-update")]
    [Arguments("project-group-delete")]
    [Arguments("project-audit-get")]
    [Arguments("project-audit-update")]
    [Arguments("project-role-get")]
    public async Task DeclaredInputUuidFormatsRejectBeforeDispatch(string operation)
    {
        using var valid = Request(Id);
        foreach (string invalid in new[] { "not-a-uuid", Id.Replace("-", ""), "{" + Id + "}" })
            await Assert.That(() =>
            {
                using var request = Request(invalid);
            }).Throws<ArgumentException>();

        IDisposable Request(string coordinate) => operation switch
        {
            "organization-group-get" => MembershipOperations.GetOrganizationGroup(Org, coordinate),
            "organization-group-add" => MembershipOperations.AddOrganizationGroup(Org, coordinate, [new("member")]),
            "organization-group-update" => MembershipOperations.UpdateOrganizationGroupRoles(Org, coordinate, [new("member")]),
            "organization-group-delete" => MembershipOperations.RemoveOrganizationGroup(Org, coordinate),
            "project-group-get" => MembershipOperations.GetProjectGroup(Org, Id, coordinate),
            "project-group-add" => MembershipOperations.AddProjectGroup(Org, Id, coordinate, Array.Empty<MembershipRole>()),
            "project-group-update" => MembershipOperations.UpdateProjectGroupRoles(Org, Id, coordinate, Id, [new("member")]),
            "project-group-delete" => MembershipOperations.RemoveProjectGroup(Org, Id, coordinate),
            "project-audit-get" => GovernanceOperations.GetProjectAuditSettings(Org, coordinate),
            "project-audit-update" => GovernanceOperations.SetProjectAuditSettings(Org, coordinate,
                [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)]),
            _ => ProjectOperations.GetProjectRole(Org, Id, coordinate)
        };
    }

    [Test]
    [Arguments("group", "id")]
    [Arguments("group", "orgId")]
    [Arguments("role", "id")]
    [Arguments("role", "orgId")]
    [Arguments("project-template", "id")]
    [Arguments("project-template", "orgId")]
    public async Task MatchingSelectedCoordinatesDoNotReplaceDeclaredUuidValidation(string family, string field)
    {
        foreach (string invalid in new[] { "not-a-uuid", Id.Replace("-", ""), "{" + Id + "}" })
        {
            string selectedOrg = field == "orgId" ? invalid : Org;
            string selectedId = field == "id" ? invalid : Id;
            var row = Row(selectedOrg, selectedId, family);
            await Assert.That(await Execute(family, selectedOrg, selectedId, row,
                listTemplate: family == "project-template" && field == "id")).IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments("group")]
    [Arguments("role")]
    [Arguments("project-template")]
    public async Task CanonicalUuidCaseAndForeignScopeClassificationArePreserved(string family)
    {
        const string upperOrg = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA";
        const string upperId = "BBBBBBBB-BBBB-4BBB-8BBB-BBBBBBBBBBBB";
        await Assert.That(await Execute(family, upperOrg, upperId, Row(upperOrg, upperId, family)))
            .IsEqualTo(SecretStatus.Success);
        var foreign = Row(upperOrg, upperId, family);
        foreign["orgId"] = Org;
        await Assert.That(await Execute(family, upperOrg, upperId, foreign)).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task OpaqueRoleSlugDoesNotAcquireAnInventedUuidRequirement()
    {
        const string opaque = "opaque-role-slug";
        var row = Row(Org, Id, "role");
        row["slug"] = opaque;
        using var request = ScopedAccessOperations.GetOrganizationRoleBySlug(Org, opaque);
        await Assert.That(await Read(request, new(Org, resourceId: opaque), new JsonObject { ["role"] = row },
            "/api/v1/organization/roles/slug/" + opaque)).IsEqualTo(SecretStatus.Success);
    }

    private static JsonObject Row(string organization, string id, string family)
    {
        var row = new JsonObject
        {
            ["id"] = id,
            ["orgId"] = organization,
            ["name"] = "private-name",
            ["createdAt"] = Time,
            ["updatedAt"] = Time
        };
        if (family != "project-template") row["slug"] = "private-slug";
        if (family == "group") row["customRoleSlug"] = null;
        if (family == "role") row["permissions"] = new JsonArray();
        if (family == "project-template")
        {
            row["roles"] = new JsonArray();
            foreach (string field in new[] { "environments", "users", "groups", "identities", "projectManagedIdentities" })
                row[field] = null;
        }
        return row;
    }

    private static async Task<SecretStatus> Execute(string family, string organization, string id, JsonObject row,
        bool listTemplate = false)
    {
        var target = new ManagementTarget(organization, resourceId: id);
        if (listTemplate)
        {
            using var request = ProjectTemplateOperations.ListProjectTemplates(organization);
            return await Read(request, new(organization),
                new JsonObject { ["projectTemplates"] = new JsonArray(row) }, "/api/v1/project-templates");
        }
        switch (family)
        {
            case "group":
                using (var request = ScopedAccessOperations.GetGroup(organization, id))
                    return await Read(request, target, row, "/api/v1/groups/" + Uri.EscapeDataString(id));
            case "role":
                using (var request = ScopedAccessOperations.GetOrganizationRole(organization, id))
                    return await Read(request, target, new JsonObject { ["role"] = row },
                        "/api/v1/organization/roles/" + Uri.EscapeDataString(id));
            default:
                using (var request = ProjectTemplateOperations.GetProjectTemplate(organization, id))
                    return await Read(request, target, new JsonObject { ["projectTemplate"] = row },
                        "/api/v1/project-templates/" + Uri.EscapeDataString(id));
        }
    }

    private static async Task<SecretStatus> Read<T>(ManagementRequest<T> request, ManagementTarget target,
        JsonObject response, string path) where T : notnull
    {
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false,
            new Wire(response.ToJsonString(), path));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), target.OrganizationId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        return result.Status;
    }

    private sealed class Wire(string response, string path) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Assert.That(request.Method.Method).IsEqualTo("GET");
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo(path);
            return new(HttpStatusCode.OK) { Content = new StringContent(response) };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
}
