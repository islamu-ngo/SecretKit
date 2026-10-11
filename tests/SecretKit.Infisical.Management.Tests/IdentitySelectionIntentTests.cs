using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentitySelectionIntentTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Identity = "20000000-0000-4000-8000-000000000002";

    private const string Template = "11111111-1111-4111-8111-111111111111";

    [Test]
    [Arguments("create", "name")]
    [Arguments("create", "role")]
    [Arguments("create", "protection")]
    [Arguments("create", "metadata")]
    [Arguments("create", "empty")]
    [Arguments("create", "omitted")]
    [Arguments("organization-update", "name")]
    [Arguments("organization-update", "role")]
    [Arguments("organization-update", "protection")]
    [Arguments("organization-update", "metadata")]
    [Arguments("organization-update", "empty")]
    [Arguments("organization-update", "omitted")]
    [Arguments("project-update", "name")]
    [Arguments("project-update", "protection")]
    [Arguments("project-update", "metadata")]
    [Arguments("project-update", "empty")]
    [Arguments("project-update", "omitted")]
    public async Task ChangedIdentityBodyCannotBorrowWholeApprovedGrant(string operation, string field)
    {
        string name = field == "name" ? "changed" : "private-name";
        string role = field == "role" ? "admin" : "viewer";
        bool protection = field != "protection";
        IdentityAttribute[]? metadata = field switch
        {
            "metadata" => [new("key", "changed")],
            "empty" => [],
            "omitted" => null,
            _ => [new("key", "value")]
        };
        using var request = operation switch
        {
            "create" => IdentityOperations.CreateOrganizationIdentity(Org, name, role, protection, metadata),
            "organization-update" => IdentityOperations.UpdateOrganizationIdentity(Org, Identity, name, role, protection, metadata),
            _ => IdentityOperations.UpdateProjectIdentity(Org, "project", Identity, name, protection, metadata)
        };
        ManagementTarget approved = operation switch
        {
            "create" => IdentityOperations.OrganizationIdentityCreateTarget(Org, "private-name", "viewer", true, [new("key", "value")]),
            "organization-update" => IdentityOperations.OrganizationIdentityUpdateTarget(Org, Identity, "private-name", "viewer", true, [new("key", "value")]),
            _ => IdentityOperations.ProjectIdentityUpdateTarget(Org, "project", Identity, "private-name", true, [new("key", "value")])
        };
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org,
            operation == "project-update" ? "project" : null);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Method).IsNull();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(false, 0)]
    [Arguments(false, 1)]
    [Arguments(false, 2)]
    [Arguments(false, 3)]
    [Arguments(false, 4)]
    [Arguments(false, 5)]
    [Arguments(false, 6)]
    [Arguments(false, 7)]
    [Arguments(false, 8)]
    [Arguments(false, 9)]
    [Arguments(true, 0)]
    [Arguments(true, 1)]
    [Arguments(true, 2)]
    [Arguments(true, 3)]
    [Arguments(true, 4)]
    [Arguments(true, 5)]
    public async Task EverySearchShapePagingAndOrderIsIndependentlySelected(bool count, int change)
    {
        IdentitySearchFilter? filter = change switch
        {
            0 => new(),
            1 => new(anyOf: []),
            2 => new(anyOf: [new()]),
            3 => new(new(name: IdentitySearchText.Shorthand(""))),
            4 => new(new(name: new(equal: "", contains: "", anyOf: []))),
            5 => new(new(role: new(anyOf: ["viewer", "admin"]))),
            _ => null
        };
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        if (count)
        {
            using var request = IdentitySearchOperations.CountIdentities(Org, IdentitySearchScope.Organization, filter);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentityCountTarget(Org, IdentitySearchScope.Organization)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization, filter,
                offset: change == 6 ? 1 : 0, limit: change == 7 ? 1 : 50,
                order: change == 8 ? IdentitySearchOrder.Role : IdentitySearchOrder.Name,
                direction: change == 9 ? ManagementListOrder.Descending : ManagementListOrder.Ascending);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Method).IsNull();
    }

    [Test]
    [Arguments(false, "scalar")]
    [Arguments(true, "scalar")]
    [Arguments(false, "operator")]
    [Arguments(true, "operator")]
    [Arguments(false, "order")]
    [Arguments(true, "order")]
    [Arguments(false, "logical")]
    [Arguments(true, "logical")]
    public async Task EqualTextDoesNotCollapseNativeFilterShapes(bool count, string shape)
    {
        var approved = new IdentitySearchFilter(new(name: new(equal: "private-name")));
        IdentitySearchFilter changed = shape switch
        {
            "scalar" => new(new(name: IdentitySearchText.Shorthand("private-name"))),
            "operator" => new(new(name: new(contains: "private-name"))),
            "order" => new(new(name: new(anyOf: ["second", "first"]))),
            _ => new(anyOf: [new(name: new(equal: "private-name"))])
        };
        if (shape == "order") approved = new(new(name: new(anyOf: ["first", "second"])));
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        if (count)
        {
            using var request = IdentitySearchOperations.CountIdentities(Org, IdentitySearchScope.Organization, changed);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentityCountTarget(Org, IdentitySearchScope.Organization, approved)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization, changed);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization, approved)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Path).IsNull();
    }

    [Test]
    [Arguments("create", "key")]
    [Arguments("create", "order")]
    [Arguments("organization-update", "key")]
    [Arguments("organization-update", "order")]
    [Arguments("organization-update", "false-omitted")]
    [Arguments("project-update", "key")]
    [Arguments("project-update", "order")]
    [Arguments("project-update", "false-omitted")]
    public async Task MetadataOrderKeysAndOmittedFalseAreNotInterchangeable(string operation, string change)
    {
        IdentityAttribute[] metadata = [new("first", "value"), new("second", "value")];
        IdentityAttribute[] altered = change switch
        {
            "key" => [new("changed", "value"), new("second", "value")],
            "order" => [metadata[1], metadata[0]],
            _ => metadata
        };
        bool? protection = change == "false-omitted" ? null : false;
        using var request = operation switch
        {
            "create" => IdentityOperations.CreateOrganizationIdentity(Org, "private-name", "viewer", false, altered),
            "organization-update" => IdentityOperations.UpdateOrganizationIdentity(Org, Identity, "private-name", "viewer", protection, altered),
            _ => IdentityOperations.UpdateProjectIdentity(Org, "project", Identity, "private-name", protection, altered)
        };
        ManagementTarget target = operation switch
        {
            "create" => IdentityOperations.OrganizationIdentityCreateTarget(Org, "private-name", "viewer", false, metadata),
            "organization-update" => IdentityOperations.OrganizationIdentityUpdateTarget(Org, Identity, "private-name", "viewer", false, metadata),
            _ => IdentityOperations.ProjectIdentityUpdateTarget(Org, "project", Identity, "private-name", false, metadata)
        };
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org,
            operation == "project-update" ? "project" : null);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Method).IsNull();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("offset")]
    [Arguments("limit")]
    [Arguments("search")]
    [Arguments("omitted")]
    public async Task TemplatePagingCannotBorrowApprovedQuery(string field)
    {
        using var request = IdentityTemplateOperations.SearchIdentityTemplates(Org,
            field == "search" ? "changed" : field == "omitted" ? null : "private-name",
            field == "offset" ? 1 : 0, field == "limit" ? 1 : 5);
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentityTemplateOperations.IdentityTemplateSearchTarget(Org, "private-name")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Path).IsNull();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TemplateSearchPositiveHasExactPagingAndProtectedCopiedOutput(bool filtered)
    {
        var wire = new Wire($$$$$"""
            {"templates":[{"id":"{{{{{Template}}}}}","orgId":"{{{{{Org}}}}}","name":"private-template","authMethod":"oidc",
             "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
             "templateFields":{"oidcDiscoveryUrl":"https://id.test","boundIssuer":"private-issuer"}}],"totalCount":3}
            """);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = IdentityTemplateOperations.SearchIdentityTemplates(Org, filtered ? "private?name" : null, 1, 2);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentityTemplateOperations.IdentityTemplateSearchTarget(Org, filtered ? "private?name" : null, 1, 2)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(2);
        request.Dispose();
        await Assert.That(result.Value.Items.Single().Name).IsEqualTo("private-template");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items.Single()).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(wire.Method).IsEqualTo("GET");
        await Assert.That(wire.Path).IsEqualTo("/api/v1/identity-templates/search?offset=1&limit=2" +
            (filtered ? "&search=private%3Fname" : ""));
        await Assert.That(wire.Body).IsNull();
    }

    [Test]
    [Arguments("create")]
    [Arguments("organization-update")]
    [Arguments("project-update")]
    [Arguments("template-search")]
    [Arguments("search")]
    [Arguments("count")]
    public async Task CoordinateOnlyApprovalCannotAuthorizeUnapprovedSelection(string operation)
    {
        var wire = new Wire("{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        string? project = operation == "project-update" ? "project" : null;
        var authority = new ManagementAuthority(client.Authority, tokens, Org, project);
        if (operation is "create" or "organization-update" or "project-update")
        {
            using var request = operation switch
            {
                "create" => IdentityOperations.CreateOrganizationIdentity(Org, "private-name", "admin", true),
                "organization-update" => IdentityOperations.UpdateOrganizationIdentity(Org, Identity, role: "admin"),
                _ => IdentityOperations.UpdateProjectIdentity(Org, "project", Identity, deleteProtection: true)
            };
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, project,
                    operation == "create" ? "private-name" : Identity)), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        else if (operation == "template-search")
        {
            using var request = IdentityTemplateOperations.SearchIdentityTemplates(Org, "private-name", 1, 2);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, secondaryId: "private-name")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else if (operation == "search")
        {
            using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization,
                new(new(name: new(equal: "private-name"))));
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, secondaryId: "organization")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = IdentitySearchOperations.CountIdentities(Org, IdentitySearchScope.Organization,
                new(new(name: new(equal: "private-name"))));
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, secondaryId: "organization")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Method).IsNull();
    }

    [Test]
    [Arguments("lastLoginAuthMethod")]
    [Arguments("lastLoginTime")]
    [Arguments("name")]
    [Arguments("slug")]
    [Arguments("type")]
    [Arguments("customRoleDescription")]
    public async Task MalformedKnownSearchOutputCannotDisappear(string field)
    {
        JsonObject row = SearchRow();
        if (field is "name" or "slug" or "type") row["project"]![field] = false;
        else if (field == "customRoleDescription") row["roles"]![0]![field] = false;
        else row[field] = false;
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Projects);
        var wire = new Wire(new JsonObject { ["identities"] = new JsonArray(row), ["totalCount"] = 1 }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Projects)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Path).IsEqualTo("/api/v2/identities/search");
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("empty")]
    [Arguments("value")]
    public async Task SearchMetadataOwnsNullableAndCopiedProtectedResults(string shape)
    {
        JsonObject row = SearchRow();
        if (shape != "absent")
        {
            row["lastLoginAuthMethod"] = shape == "null" ? null : shape == "empty" ? "" : "oidc";
            row["lastLoginTime"] = shape == "null" ? null : "2026-01-01T00:00:00Z";
            row["roles"]![0]!["customRoleDescription"] = shape == "null" ? null : shape == "empty" ? "" : "private-description";
        }
        if (shape == "absent") row.Remove("project");
        if (shape == "null") row["project"] = null;
        var wire = new Wire(new JsonObject { ["identities"] = new JsonArray(row), ["totalCount"] = 1 }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Projects);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Projects)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.ResponseDisposed).IsTrue();
        await Assert.That(() => tokens.Material!.Reveal()).Throws<ObjectDisposedException>();
        IdentitySearchSummary value = result.Value.Items.Single();
        request.Dispose();
        await Assert.That(value.LastLoginAuthMethod.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.LastLoginAuthMethod.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.LastLoginTime.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.LastLoginTime.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.Project.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.Project.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.Roles[0].CustomRoleDescription.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(value.Roles[0].CustomRoleDescription.IsNull).IsEqualTo(shape == "null");
        if (shape is "empty" or "value")
        {
            await Assert.That(value.LastLoginAuthMethod.Value).IsEqualTo(shape == "empty" ? "" : "oidc");
            await Assert.That(value.LastLoginTime.Value).IsEqualTo("2026-01-01T00:00:00Z");
            await Assert.That(value.Roles[0].CustomRoleDescription.Value).IsEqualTo(shape == "empty" ? "" : "private-description");
            await Assert.That(value.Project.Value.Name).IsEqualTo("private-project");
            await Assert.That(value.Project.Value.Slug).IsEqualTo("private-slug");
            await Assert.That(value.Project.Value.Type).IsEqualTo("secret-manager");
            await Assert.That(JsonSerializer.Serialize(value.Project.Value)).IsEqualTo("{}");
        }
        await Assert.That(() => ((IList<IdentitySearchRole>)value.Roles).Clear()).Throws<NotSupportedException>();
        await Assert.That(JsonSerializer.Serialize(value.Roles[0])).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(value.ToString()).IsEqualTo("[IdentitySearchSummary]");
        await Assert.That(wire.Method).IsEqualTo("POST");
        await Assert.That(wire.Path).IsEqualTo("/api/v2/identities/search");
    }

    [Test]
    [Arguments("project-id", SecretStatus.Invalid)]
    [Arguments("project-name", SecretStatus.Unknown)]
    [Arguments("project-slug", SecretStatus.Unknown)]
    [Arguments("project-type", SecretStatus.Unknown)]
    [Arguments("login-date", SecretStatus.Unknown)]
    public async Task KnownSearchCoordinatesRequiredChildrenAndDatesFailClosed(string defect, SecretStatus expected)
    {
        JsonObject row = SearchRow();
        if (defect == "project-id") row["project"]!["id"] = "90000000-0000-4000-8000-000000000009";
        else if (defect == "login-date") row["lastLoginTime"] = "not-a-date";
        else row["project"]!.AsObject().Remove(defect["project-".Length..]);
        var wire = new Wire(new JsonObject { ["identities"] = new JsonArray(row), ["totalCount"] = 1 }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Projects);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Projects)));
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments("create", "positive")]
    [Arguments("create", "organization")]
    [Arguments("create", "name")]
    [Arguments("create", "metadata")]
    [Arguments("organization-update", "positive")]
    [Arguments("organization-update", "organization")]
    [Arguments("organization-update", "identity")]
    [Arguments("organization-update", "name")]
    [Arguments("organization-delete", "positive")]
    [Arguments("organization-delete", "organization")]
    [Arguments("organization-delete", "identity")]
    [Arguments("organization-delete", "name")]
    [Arguments("project-create", "positive")]
    [Arguments("project-create", "organization")]
    [Arguments("project-create", "project")]
    [Arguments("project-create", "name")]
    [Arguments("project-update", "positive")]
    [Arguments("project-update", "organization")]
    [Arguments("project-update", "project")]
    [Arguments("project-update", "identity")]
    [Arguments("project-update", "name")]
    [Arguments("project-delete", "positive")]
    [Arguments("project-delete", "organization")]
    [Arguments("project-delete", "project")]
    [Arguments("project-delete", "identity")]
    [Arguments("project-delete", "name")]
    public async Task OriginalIdentityMutationRowsValidateExactAdapterAndParser(string operation, string defect)
    {
        bool project = operation.StartsWith("project", StringComparison.Ordinal);
        JsonObject row = JsonNode.Parse($$$$$"""
            {"id":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","name":"private-name","authMethods":[],
             "metadata":[{"id":"entry","key":"key","value":"value"}],
             "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
            """)!.AsObject();
        if (project) row["projectId"] = "project";
        if (operation is "organization-update" or "organization-delete") row.Remove("authMethods");
        if (operation == "organization-delete") row.Remove("metadata");
        if (defect == "organization") row["orgId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "project") row["projectId"] = "foreign";
        if (defect == "identity") row["id"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "name") row.Remove("name");
        if (defect == "metadata") row["metadata"]![0]!["key"] = false;
        using var request = operation switch
        {
            "create" => IdentityOperations.CreateOrganizationIdentity(Org, "private-name", "viewer"),
            "organization-update" => IdentityOperations.UpdateOrganizationIdentity(Org, Identity, name: "private-name"),
            "organization-delete" => IdentityOperations.DeleteOrganizationIdentity(Org, Identity),
            "project-create" => IdentityOperations.CreateProjectIdentity(Org, "project", "private-name"),
            "project-update" => IdentityOperations.UpdateProjectIdentity(Org, "project", Identity, name: "private-name"),
            _ => IdentityOperations.DeleteProjectIdentity(Org, "project", Identity)
        };
        ManagementTarget approved = operation switch
        {
            "create" => IdentityOperations.OrganizationIdentityCreateTarget(Org, "private-name", "viewer"),
            "organization-update" => IdentityOperations.OrganizationIdentityUpdateTarget(Org, Identity, name: "private-name"),
            "project-create" => IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "private-name"),
            "project-update" => IdentityOperations.ProjectIdentityUpdateTarget(Org, "project", Identity, name: "private-name"),
            _ => new(Org, project ? "project" : null, Identity)
        };
        var wire = new Wire(new JsonObject { ["identity"] = row }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, project ? "project" : null);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(defect == "positive" ? SecretStatus.Success :
            defect is "name" or "metadata" ? SecretStatus.Unknown : SecretStatus.Invalid);
        string path = project ? "/api/v1/projects/project/identities" : "/api/v1/identities";
        bool create = operation is "create" or "project-create";
        bool delete = operation.EndsWith("delete", StringComparison.Ordinal);
        await Assert.That(wire.Path).IsEqualTo(path + (create ? "" : "/" + Identity));
        await Assert.That(wire.Method).IsEqualTo(create ? "POST" : delete ? "DELETE" : "PATCH");
        await Assert.That(wire.Body).IsEqualTo(operation switch
        {
            "create" => $$$$$"""{"organizationId":"{{{{{Org}}}}}","name":"private-name","role":"viewer","hasDeleteProtection":false}""",
            "project-create" => """{"name":"private-name","hasDeleteProtection":false}""",
            "organization-update" or "project-update" => """{"name":"private-name"}""",
            _ => null
        });
        if (defect == "positive")
        {
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            request.Dispose();
            await Assert.That(result.Value.Id).IsEqualTo(Identity);
            await Assert.That(result.Value.Metadata.IsPresent).IsEqualTo(operation != "organization-delete");
            if (operation != "organization-delete")
            {
                await Assert.That(result.Value.Metadata.Value[0].Value).IsEqualTo("value");
                await Assert.That(() => ((IList<IdentityMetadataEntry>)result.Value.Metadata.Value).Clear())
                    .Throws<NotSupportedException>();
            }
            await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
        }
    }

    [Test]
    [Arguments("positive")]
    [Arguments("foreign")]
    [Arguments("missing")]
    [Arguments("malformed")]
    public async Task SelectedOrganizationDetailsHasExactSeamWitness(string defect)
    {
        JsonObject row = JsonNode.Parse($$$$$"""{"id":"{{{{{Org}}}}}","name":"private-org","slug":"private-slug"}""")!.AsObject();
        if (defect == "foreign") row["id"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "missing") row.Remove("name");
        if (defect == "malformed") row["slug"] = false;
        var wire = new Wire(new JsonObject { ["identityDetails"] = new JsonObject { ["organization"] = row } }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = IdentityOperations.GetSelectedIdentityOrganization(Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.get.v1.identities.details", new(Org)));
        await Assert.That(result.Status).IsEqualTo(defect == "positive" ? SecretStatus.Success :
            defect == "foreign" ? SecretStatus.Invalid : SecretStatus.Unknown);
        await Assert.That(wire.Path).IsEqualTo("/api/v1/identities/details");
        await Assert.That(wire.Method).IsEqualTo("GET");
        await Assert.That(wire.Body).IsNull();
        if (defect == "positive")
        {
            await Assert.That(result.Value.Id).IsEqualTo(Org);
            await Assert.That(result.Value.Name).IsEqualTo("private-org");
            await Assert.That(result.Value.Slug).IsEqualTo("private-slug");
            await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
        }
    }

    [Test]
    [Arguments("positive")]
    [Arguments("missing-id")]
    [Arguments("missing-name")]
    [Arguments("malformed")]
    public async Task TemplateUsageValidatesOnlyItsKnownReturnedAssociation(string defect)
    {
        JsonObject row = JsonNode.Parse($$$$$"""{"identityId":"{{{{{Identity}}}}}","identityName":"private-name"}""")!.AsObject();
        if (defect == "missing-id") row.Remove("identityId");
        if (defect == "missing-name") row.Remove("identityName");
        if (defect == "malformed") row["identityId"] = false;
        var wire = new Wire(new JsonArray(row).ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = IdentityTemplateOperations.GetIdentityTemplateUsage(Org, Template);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.get.v1.identity.templates.by.templateId.usage", new(Org, resourceId: Template)));
        await Assert.That(result.Status).IsEqualTo(defect == "positive" ? SecretStatus.Success : SecretStatus.Unknown);
        await Assert.That(wire.Method).IsEqualTo("GET");
        await Assert.That(wire.Path).IsEqualTo("/api/v1/identity-templates/" + Template + "/usage");
        await Assert.That(wire.Body).IsNull();
        if (defect == "positive")
        {
            request.Dispose();
            await Assert.That(result.Value.Items.Single().IdentityId).IsEqualTo(Identity);
            await Assert.That(result.Value.Items.Single().IdentityName).IsEqualTo("private-name");
            await Assert.That(result.Value.Items.Single().AuthId).IsNull();
            await Assert.That(result.Value.IsComplete).IsTrue();
            await Assert.That(JsonSerializer.Serialize(result.Value.Items.Single())).IsEqualTo("{}");
        }
    }

    [Test]
    public async Task IdentityInputCopyAndDisposalNeverExposeOrDispatchPrivateBytes()
    {
        IdentityAttribute[] metadata = [new("private-key", "private-value")];
        var approved = IdentityOperations.OrganizationIdentityCreateTarget(Org, "private-name", "viewer", metadata: metadata);
        using var request = IdentityOperations.CreateOrganizationIdentity(Org, "private-name", "viewer", metadata: metadata);
        metadata[0] = new("changed-key", "changed-value");
        byte[] copy = request.CopyBody()!;
        Array.Clear(copy);
        var wire = new Wire($$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","name":"private-name","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","authMethods":[],"metadata":[]}}""");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("metadata")[0].GetProperty("key").GetString()).IsEqualTo("private-key");
        await Assert.That(body.RootElement.GetProperty("metadata")[0].GetProperty("value").GetString()).IsEqualTo("private-value");
        await Assert.That(JsonSerializer.Serialize(approved)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(metadata[0])).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(request).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(request.ToString()).IsEqualTo("[ManagementRequest]");
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
        var unusedTokens = new Tokens();
        var unusedAuthority = new ManagementAuthority(client.Authority, unusedTokens, Org);
        await Assert.That(async () => await client.ExecuteAsync(request, unusedAuthority,
            unusedAuthority.IssueGrant(request.OperationId, approved), client.CreateReceipt(request)))
            .Throws<ObjectDisposedException>();
        await Assert.That(unusedTokens.Acquired).IsFalse();
    }

    private static JsonObject SearchRow() => JsonNode.Parse($$$$$"""
        {"id":"membership","identityId":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","scope":"project","projectId":"project",
         "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
         "identity":{"id":"{{{{{Identity}}}}}","orgId":"{{{{{Org}}}}}","name":"private-name","authMethods":[],"activeLockoutAuthMethods":[]},
         "project":{"id":"project","name":"private-project","slug":"private-slug","type":"secret-manager"},
         "roles":[{"id":"role","role":"viewer","isTemporary":false}]}
        """)!.AsObject();

    private static ManagementTransport Transport(Wire wire) => new(new Uri("https://management.test"),
        1024 * 1024, null, false, wire);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public SecretMaterial? Material { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            Material = SecretMaterial.FromText("test-only-token");
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(Material)));
        }
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        public string? Method { get; private set; }
        public string? Path { get; private set; }
        public string? Body { get; private set; }
        public bool ResponseDisposed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Method = request.Method.Method;
            Path = request.RequestUri!.PathAndQuery;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new OwnedContent(response, () => ResponseDisposed = true) };
        }
    }

    private sealed class OwnedContent(string response, Action disposed) : StringContent(response)
    {
        protected override void Dispose(bool disposing)
        {
            if (disposing) disposed();
            base.Dispose(disposing);
        }
    }
}
