using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class PermissionContractVariantTests
{
    private const string Org = "c168ae21-77c8-467a-9a31-d471c8dc3d71";
    private const string Project = "project-private";
    private const string Role = "9fe7d5c2-a8d3-4b2d-a9f7-f3a6e8c87d14";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    public async Task EmptyOperandsRemainDistinctThroughControlledRoleChange(int shape)
    {
        var change = Change(shape);
        using var request = RoleChangeOperations.CreateProjectRole(Org, Project, change);
        var wire = new Wire();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, RoleChangeOperations.ProjectCreationTarget(Org, Project, Change(shape))),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var permission = wire.Body!["permissions"]![0]!.AsObject();
        await Assert.That(permission.ContainsKey("conditions")).IsEqualTo(shape != 0);
        if (shape == 1) await Assert.That(permission["conditions"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 2) await Assert.That(permission["conditions"]!["environment"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 3) await Assert.That(permission["conditions"]!["environment"]!["$in"]!.AsArray().Count).IsEqualTo(0);
        if (shape == 4) await Assert.That(permission["conditions"]!["secretTags"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 5)
        {
            await Assert.That(permission["conditions"]!["secretTags"]!["$in"]!.AsArray().Count).IsEqualTo(0);
            await Assert.That(permission["conditions"]!["secretTags"]!["$all"]!.AsArray().Count).IsEqualTo(0);
        }
        if (shape == 6) await Assert.That(permission["conditions"]!["metadata"]!["$elemMatch"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 7) await Assert.That(permission["conditions"]!["metadata"]!["$elemMatch"]!["key"]!.AsObject().Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(0, 1)]
    [Arguments(1, 0)]
    [Arguments(2, 3)]
    [Arguments(3, 2)]
    [Arguments(4, 5)]
    [Arguments(5, 4)]
    [Arguments(6, 7)]
    [Arguments(7, 6)]
    public async Task IndependentIntentRejectsDifferentEmptyShapeBeforeTokens(int selected, int granted)
    {
        using var request = RoleChangeOperations.CreateProjectRole(Org, Project, Change(selected));
        var wire = new Wire();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, RoleChangeOperations.ProjectCreationTarget(Org, Project, Change(granted))), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Body).IsNull();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task EmptyShapesDoNotRelaxSubjectOperatorActionOrBudgetConstraints()
    {
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Secrets, Array.Empty<ProjectRoleAction>())).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.Role, ProjectRoleAction.Read, conditions: [])).Throws<ArgumentException>();
        await Assert.That(() => new OrganizationRolePermission(OrganizationRoleSubject.Role, OrganizationRoleAction.Read, conditions: [])).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.SecretFolders, ProjectRoleAction.Read, secretTags: new())).Throws<ArgumentException>();
        await Assert.That(() => new RoleMetadataMatch(key: RoleStringClause.Literal(""))).Throws<ArgumentException>();
        await Assert.That(() => RoleStringClause.Compare(equal: "")).Throws<ArgumentException>();
        await Assert.That(() => RoleStringClause.Compare(included: [""])).Throws<ArgumentException>();
        await Assert.That(() => RoleStringClause.Compare(included: Enumerable.Repeat("private", 101).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => new ProjectRolePermission(ProjectRoleSubject.SecretFolders, ProjectRoleAction.Read,
            conditions: [new(RoleConditionField.Environment, RoleStringClause.Compare(glob: "*"))])).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task OrganizationEmptyConditionsAndComparisonsRetainExactIntent(int shape)
    {
        OrganizationRoleChange Change() => new("Reviewed", "reader-private", permissions:
        [
            new(OrganizationRoleSubject.AppConnections, OrganizationRoleAction.Read, inverted: false,
                conditions: shape switch
                {
                    0 => null,
                    1 => [],
                    2 => [new(RoleConditionField.ConnectionId, RoleStringClause.Compare())],
                    _ => [new(RoleConditionField.ConnectionId, RoleStringClause.Compare(included: []))]
                })
        ]);
        using var request = RoleChangeOperations.CreateOrganizationRole(Org, Change());
        var wire = new Wire { Organization = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, RoleChangeOperations.OrganizationCreationTarget(Org, Change())),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var permission = wire.Body!["permissions"]![0]!.AsObject();
        await Assert.That(permission.ContainsKey("conditions")).IsEqualTo(shape != 0);
        await Assert.That(permission["inverted"]!.GetValue<bool>()).IsFalse();
        if (shape == 1) await Assert.That(permission["conditions"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 2) await Assert.That(permission["conditions"]!["connectionId"]!.AsObject().Count).IsEqualTo(0);
        if (shape == 3) await Assert.That(permission["conditions"]!["connectionId"]!["$in"]!.AsArray().Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("""{"action":"read-private"}""", true, false)]
    [Arguments("""{"action":["read-private","edit-private"],"subject":"secrets-private","inverted":false}""", false, true)]
    [Arguments("""{"action":[],"subject":[],"inverted":true,"conditions":{"unknown-private":[null,42]}}""", false, false)]
    public async Task KnownReturnedSelectionsCopyBeforeDocumentDisposal(string json, bool scalar, bool subjectScalar)
    {
        RolePermissionSummary summary;
        using (var document = JsonDocument.Parse(json)) summary = new(document.RootElement);
        await Assert.That(summary.Action.IsScalar).IsEqualTo(scalar);
        await Assert.That(summary.Action.Values.Count).IsEqualTo(scalar ? 1 : subjectScalar ? 2 : 0);
        if (summary.Subject is not null) await Assert.That(summary.Subject.IsScalar).IsEqualTo(subjectScalar);
        else await Assert.That(summary.Inverted).IsNull();
        await Assert.That(summary.IncludesConditionValues).IsFalse();
        await Assert.That(summary.HasConditions).IsEqualTo(json.Contains("conditions", StringComparison.Ordinal));
        foreach (object value in new object[] { summary, summary.Action, summary.Subject ?? summary.Action })
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task ReturnedArrayItemsDoNotInventScalarMinimumLength()
    {
        using var document = JsonDocument.Parse("""{"action":[""],"subject":[""]}""");
        var summary = new RolePermissionSummary(document.RootElement);
        await Assert.That(summary.Action.Values[0]).IsEqualTo("");
        await Assert.That(summary.Subject!.Values[0]).IsEqualTo("");
    }

    [Test]
    [Arguments("""{}""")]
    [Arguments("""{"action":null}""")]
    [Arguments("""{"action":""}""")]
    [Arguments("""{"action":[null]}""")]
    [Arguments("""{"action":"read","subject":null}""")]
    [Arguments("""{"action":"read","subject":""}""")]
    [Arguments("""{"action":"read","inverted":null}""")]
    [Arguments("""{"action":"read","inverted":"false"}""")]
    public async Task MalformedReturnedKnownFieldsStayUnknown(string json)
    {
        using var document = JsonDocument.Parse(json);
        var exception = await Assert.That(() => new RolePermissionSummary(document.RootElement))
            .Throws<ManagementContractException>();
        await Assert.That(exception!.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task ReturnedSelectionBudgetsAndAbsentPermissionInventoryRemainExplicit()
    {
        foreach (string json in new[]
        {
            JsonSerializer.Serialize(new { action = new string('x', 16385) }),
            JsonSerializer.Serialize(new { action = Enumerable.Repeat("read", 1001).ToArray() })
        })
        {
            using var document = JsonDocument.Parse(json);
            await Assert.That(() => new RolePermissionSummary(document.RootElement)).Throws<ManagementContractException>();
        }
        using var absent = JsonDocument.Parse("{}");
        using var empty = JsonDocument.Parse("""{"permissions":[]}""");
        using var unknown = JsonDocument.Parse("""{"permissions":null}""");
        await Assert.That(RolePermissionSummary.Read(absent.RootElement)).IsNull();
        await Assert.That(RolePermissionSummary.Read(empty.RootElement)!.Count).IsEqualTo(0);
        await Assert.That(() => RolePermissionSummary.Read(unknown.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    public async Task InputCollectionsCopyEagerlyAndDisposedRequestsNeverDispatch()
    {
        string[] included = ["original-private"];
        RoleCondition[] conditions = [new(RoleConditionField.Environment, RoleStringClause.Compare(included: included))];
        var change = new ProjectRoleChange("Reviewed", "reader-private", permissions:
            [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read, conditions: conditions)]);
        using var request = RoleChangeOperations.CreateProjectRole(Org, Project, change);
        included[0] = "broadened-private";
        conditions[0] = new(RoleConditionField.Environment, RoleStringClause.Compare());
        var wire = new Wire();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, RoleChangeOperations.ProjectCreationTarget(Org, Project, change)),
            client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Body!["permissions"]![0]!["conditions"]!["environment"]!["$in"]![0]!.GetValue<string>())
            .IsEqualTo("original-private");
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
    }

    private static ProjectRoleChange Change(int shape) => new("Reviewed", "reader-private", permissions:
    [
        new(shape >= 6 ? ProjectRoleSubject.DynamicSecrets : ProjectRoleSubject.Secrets,
            shape >= 6 ? ProjectRoleAction.Lease : ProjectRoleAction.Read,
            conditions: shape switch
            {
                1 => [],
                2 => [new(RoleConditionField.Environment, RoleStringClause.Compare())],
                3 => [new(RoleConditionField.Environment, RoleStringClause.Compare(included: []))],
                _ => null
            },
            secretTags: shape == 4 ? new() : shape == 5 ? new(included: [], all: []) : null,
            metadata: shape == 6 ? new() : shape == 7 ? new(key: RoleStringClause.Compare()) : null)
    ]);

    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-fixture-token"))));
        }
    }

    private sealed class Wire : HttpMessageHandler
    {
        public bool Organization { get; init; }
        public JsonObject? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsolutePath != (Organization ? "/api/v1/organization/roles" : $"/api/v1/projects/{Project}/roles") ||
                request.Method != HttpMethod.Post || request.Headers.Authorization?.Scheme != "Bearer")
                return new(HttpStatusCode.NotFound);
            Body = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
            var role = Body.DeepClone().AsObject();
            role["id"] = Role;
            role[Organization ? "orgId" : "projectId"] = Organization ? Org : Project;
            role["createdAt"] = "2026-01-01T00:00:00Z";
            role["updatedAt"] = "2026-01-01T00:00:00Z";
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(new JsonObject { ["role"] = role }.ToJsonString(), Encoding.UTF8, "application/json")
            };
        }
    }
}
