using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectTemplateTests
{
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string OtherOrg = "0000000b-0000-0000-0000-00000000000b";
    private const string TemplateId = "10000000-0000-0000-0000-000000000001";

    [Test]
    public async Task OmittedListTypeDoesNotInventAFilterOrReturnedType()
    {
        var handler = new Wire("GET", "/api/v1/project-templates",
            """{"projectTemplates":[]}""");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = ProjectTemplateOperations.ListProjectTemplates(Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(handler.ObservedPath).IsEqualTo("/api/v1/project-templates");
    }

    [Test]
    public async Task IndependentDescriptionIntentRejectsDifferentWholeChange()
    {
        var approved = ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "private-template",
            description: "approved");
        using var incoming = ProjectTemplateOperations.CreateProjectTemplate(Org, "private-template",
            description: "unapproved");
        var handler = new Wire("POST", "/api/v1/project-templates", """{"projectTemplate":""" + Template() + "}");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var receipt = client.CreateReceipt(incoming);
        // This expected target comes from host-owned approved inputs, not the incoming request.
        var result = await client.ExecuteAsync(incoming, authority,
            authority.IssueGrant(incoming.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(handler.ObservedMethod is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("GET", false)]
    [Arguments("GET", true)]
    [Arguments("POST", false)]
    [Arguments("PATCH", true)]
    [Arguments("DELETE", true)]
    public async Task AllFiveNativeRoutesDispatchThroughControlledClient(string method, bool individual)
    {
        string operation = "infisical." + method.ToLowerInvariant() + ".v1.project.templates" +
            (individual ? ".by.templateId" : "");
        string path = "/api/v1/project-templates" + (individual ? "/" + TemplateId : "");
        if (method == "GET" && !individual) path += "?type=secret-manager";
        var handler = new Wire(method, path, method == "GET" && !individual
            ? """{"projectTemplates":[""" + Template() + "]}"
            : """{"projectTemplate":""" + Template() + "}");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        ProjectTemplateSummary summary;
        if (method == "GET" && !individual)
        {
            using var request = ProjectTemplateOperations.ListProjectTemplates(Org, ProjectTemplateType.SecretManager);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(operation, new(Org, secondaryId: "secret-manager")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.IsComplete).IsTrue();
            await Assert.That(result.Value.Items.Count).IsEqualTo(1);
            summary = result.Value.Items[0];
        }
        else
        {
            using var request = Single(method);
            var grant = authority.IssueGrant(operation, HostTarget(method));
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority, grant, receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            summary = result.Value;
            if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        }
        await Assert.That(handler.ObservedMethod).IsEqualTo(method);
        await Assert.That(handler.ObservedPath).IsEqualTo(path);
        await Assert.That(handler.HadAuthorization).IsTrue();
        await Assert.That(summary.Id).IsEqualTo(TemplateId);
        await Assert.That(summary.OrganizationId).IsEqualTo(Org);
        await Assert.That(summary.Name).IsEqualTo("private-template");
        await Assert.That(summary.Type).IsEqualTo("secret-manager");
        await Assert.That(summary.IncludesConfiguration).IsTrue();
        await Assert.That(summary.IncludesPermissionConditionValues).IsFalse();
        await Assert.That(JsonSerializer.Serialize(summary)).IsEqualTo("""{"IncludesConfiguration":true,"IncludesPermissionConditionValues":false}""");
        await Assert.That(summary.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        if (method is "POST" or "PATCH")
        {
            using JsonDocument body = JsonDocument.Parse(handler.Body!);
            await Assert.That(body.RootElement.GetProperty("name").GetString()).IsEqualTo("private-template");
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(method == "POST" ? 2 : 1);
            if (method == "POST")
                await Assert.That(body.RootElement.GetProperty("type").GetString()).IsEqualTo("secret-manager");
        }
        else await Assert.That(handler.Body is null).IsTrue();
    }

    [Test]
    [Arguments(ProjectTemplateType.SecretManager, "secret-manager")]
    [Arguments(ProjectTemplateType.CertificateManager, "cert-manager")]
    [Arguments(ProjectTemplateType.KeyManagement, "kms")]
    [Arguments(ProjectTemplateType.SecretScanning, "secret-scanning")]
    [Arguments(ProjectTemplateType.PrivilegedAccess, "pam")]
    [Arguments(ProjectTemplateType.AgentVault, "agent-vault")]
    public async Task NativeTypesBindListIntentAndCreateBody(ProjectTemplateType type, string native)
    {
        using var list = ProjectTemplateOperations.ListProjectTemplates(Org, type);
        var handler = new Wire("GET", "/api/v1/project-templates?type=" + native, """{"projectTemplates":[]}""");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(list, authority,
            authority.IssueGrant(list.OperationId, new(Org, secondaryId: native)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        using var create = ProjectTemplateOperations.CreateProjectTemplate(Org, "private-template", type);
        byte[] bytes = create.CopyBody()!;
        try
        {
            using JsonDocument body = JsonDocument.Parse(bytes);
            await Assert.That(body.RootElement.GetProperty("type").GetString()).IsEqualTo(native);
            await Assert.That(create.Target.SecondaryId).IsEqualTo(
                ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "private-template", type).SecondaryId);
        }
        finally { Array.Clear(bytes); }
    }

    [Test]
    [Arguments("organization")]
    [Arguments("template")]
    [Arguments("operation")]
    [Arguments("issuer")]
    public async Task TemplateGrantsRejectIndependentMismatchesBeforeTokens(string mismatch)
    {
        var handler = new Wire("DELETE", "/api/v1/project-templates/" + TemplateId, "{}");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var request = ProjectTemplateOperations.DeleteProjectTemplate(Org, TemplateId);
        var receipt = client.CreateReceipt(request);
        var issuer = mismatch is "organization" or "issuer"
            ? new ManagementAuthority(client.Authority, tokens, mismatch == "organization" ? OtherOrg : Org)
            : authority;
        var grant = issuer.IssueGrant(mismatch == "operation" ? "infisical.get.v1.project.templates.by.templateId" : request.OperationId,
            new(mismatch == "organization" ? OtherOrg : Org,
                resourceId: mismatch == "template" ? "20000000-0000-0000-0000-000000000002" : TemplateId));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(handler.ObservedMethod is null).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TypeSelectionCannotBeAuthorizedByAnotherType(bool create)
    {
        using var transport = Transport(new Wire("POST", "/api/v1/project-templates", "{}"));
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        if (create)
        {
            using var request = ProjectTemplateOperations.CreateProjectTemplate(Org, "private-template");
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
                new(Org, resourceId: "private-template", secondaryId: "kms")), client.CreateReceipt(request));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        else
        {
            using var request = ProjectTemplateOperations.ListProjectTemplates(Org, ProjectTemplateType.SecretManager);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, secondaryId: "kms")));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        }
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    [Arguments("GET")]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task ForeignOrganizationCannotBePublishedOrRecordedApplied(string method)
    {
        using var request = Single(method);
        var handler = new Wire(method, "/api/v1/project-templates" + (method == "POST" ? "" : "/" + TemplateId),
            """{"projectTemplate":""" + Template(org: OtherOrg) + "}");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, HostTarget(method)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        if (receipt is not null)
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("id", "20000000-0000-0000-0000-000000000002", SecretStatus.Invalid)]
    [Arguments("orgId", null, SecretStatus.Unknown)]
    [Arguments("createdAt", null, SecretStatus.Unknown)]
    public async Task IndividualResponseCoordinatesAndRequiredMetadataFailClosed(string field, string? value, SecretStatus status)
    {
        using JsonDocument fixture = JsonDocument.Parse(Template());
        var fields = fixture.RootElement.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value.Clone());
        if (value is null) fields.Remove(field);
        else fields[field] = value;
        using var request = ProjectTemplateOperations.GetProjectTemplate(Org, TemplateId);
        var result = await Read(request, """{"projectTemplate":""" + JsonSerializer.Serialize(fields) + "}");
        await Assert.That(result.Status).IsEqualTo(status);
    }

    [Test]
    public async Task CollectionRejectsForeignOrganizationAndPresentWrongType()
    {
        using var request = ProjectTemplateOperations.ListProjectTemplates(Org, ProjectTemplateType.SecretManager);
        foreach (string item in new[] { Template(org: OtherOrg), Template(type: "kms") })
        {
            var result = await Read(request, """{"projectTemplates":[""" + item + "]}");
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        }
    }

    [Test]
    [Arguments("LIST")]
    [Arguments("GET")]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task OptionalTemplateTypeRejectsNullAcrossEveryRow(string method)
    {
        if (method == "LIST")
        {
            using var request = ProjectTemplateOperations.ListProjectTemplates(Org);
            await Verify(request, new(Org), "GET", "/api/v1/project-templates", "projectTemplates", true);
        }
        else
        {
            using var request = Single(method);
            await Verify(request, HostTarget(method), method,
                method == "POST" ? "/api/v1/project-templates" : "/api/v1/project-templates/" + TemplateId,
                "projectTemplate", false);
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target, string verb,
            string path, string envelope, bool list) where T : notnull
        {
            foreach (string shape in new[] { "absent", "value", "null" })
            {
                var fields = JsonSerializer.Deserialize<Dictionary<string, object?>>(Template(type: null))!;
                if (shape != "absent") fields["type"] = shape == "null" ? null : "secret-manager";
                string item = JsonSerializer.Serialize(fields);
                string response = "{\"" + envelope + "\":" + (list ? "[" + item + "]" : item) + "}";
                using var transport = Transport(new Wire(verb, path, response));
                var client = new ManagementClient(transport);
                var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, target), receipt);
                await Assert.That(result.Status).IsEqualTo(shape == "null" ? SecretStatus.Unknown : SecretStatus.Success);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(shape == "null" ?
                    DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
            }
        }
    }

    [Test]
    public async Task OptionalReturnedTypeIsNotInferredFromListFilter()
    {
        using var request = ProjectTemplateOperations.ListProjectTemplates(Org, ProjectTemplateType.SecretManager);
        var result = await Read(request, """{"projectTemplates":[""" + Template(type: null) + "]}");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items[0].Type is null).IsTrue();
    }

    [Test]
    public async Task PatchDistinguishesOmissionFromEmptyDescriptionOnActualWire()
    {
        using var request = ProjectTemplateOperations.UpdateProjectTemplate(Org, TemplateId, description: "");
        var handler = new Wire("PATCH", "/api/v1/project-templates/" + TemplateId,
            """{"projectTemplate":""" + Template() + "}");
        using var transport = Transport(handler);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, TemplateId, description: "")), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using JsonDocument body = JsonDocument.Parse(handler.Body!);
        await Assert.That(body.RootElement.GetProperty("description").GetString()).IsEqualTo("");
        await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
        var replay = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, TemplateId, description: "")), receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task InvalidTypedInputsFailBeforeAnyDispatch()
    {
        await Assert.That(() => ProjectTemplateOperations.GetProjectTemplate(Org, "../escape")).Throws<ArgumentException>();
        await Assert.That(() => ProjectTemplateOperations.CreateProjectTemplate(Org, new string('x', 65))).Throws<ArgumentException>();
        await Assert.That(() => ProjectTemplateOperations.CreateProjectTemplate(Org, "template",
            description: new string('x', 257))).Throws<ArgumentException>();
        await Assert.That(() => ProjectTemplateOperations.ListProjectTemplates(Org, (ProjectTemplateType)99)).Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => ProjectTemplateOperations.UpdateProjectTemplate(Org, TemplateId)).Throws<ArgumentException>();
    }

    private static ManagementRequest<ProjectTemplateSummary> Single(string method) => method switch
    {
        "GET" => ProjectTemplateOperations.GetProjectTemplate(Org, TemplateId),
        "POST" => ProjectTemplateOperations.CreateProjectTemplate(Org, "private-template"),
        "PATCH" => ProjectTemplateOperations.UpdateProjectTemplate(Org, TemplateId, name: "private-template"),
        "DELETE" => ProjectTemplateOperations.DeleteProjectTemplate(Org, TemplateId),
        _ => throw new ArgumentException("Unsupported test method.")
    };

    private static ManagementTarget HostTarget(string method) => method switch
    {
        "POST" => ProjectTemplateOperations.ProjectTemplateCreateTarget(Org, "private-template"),
        "PATCH" => ProjectTemplateOperations.ProjectTemplateUpdateTarget(Org, TemplateId, name: "private-template"),
        _ => new(Org, resourceId: TemplateId)
    };

    private static string Template(string org = Org, string? type = "secret-manager")
    {
        var value = new Dictionary<string, object?>
        {
            ["id"] = TemplateId,
            ["orgId"] = org,
            ["name"] = "private-template",
            ["description"] = "private-description",
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-02T00:00:00Z",
            ["roles"] = Array.Empty<object>(),
            ["environments"] = null,
            ["users"] = null,
            ["groups"] = null,
            ["identities"] = null,
            ["projectManagedIdentities"] = null
        };
        if (type is not null) value["type"] = type;
        return JsonSerializer.Serialize(value);
    }

    private static async Task<SecretOutcome<T>> Read<T>(ManagementRequest<T> request, string response) where T : notnull
    {
        bool list = request.OperationId == "infisical.get.v1.project.templates";
        using var transport = Transport(new Wire("GET", list ? "/api/v1/project-templates?type=secret-manager" :
            "/api/v1/project-templates/" + TemplateId, response));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            list ? new(Org, secondaryId: "secret-manager") : new(Org, resourceId: TemplateId)));
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Wire(string method, string path, string response) : HttpMessageHandler
    {
        public string? ObservedMethod { get; private set; }
        public string? ObservedPath { get; private set; }
        public bool HadAuthorization { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            ObservedMethod = request.Method.Method;
            ObservedPath = request.RequestUri!.PathAndQuery;
            HadAuthorization = request.Headers.Authorization?.Scheme == "Bearer";
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            if (ObservedMethod != method || ObservedPath != path)
                return new(HttpStatusCode.NotFound);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))))));
        }
    }
}
