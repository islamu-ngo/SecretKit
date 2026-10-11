using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectConnectionTests
{
    private const string Authorization = "00000001-0000-0000-0000-000000000001";
    private const string Integration = "00000002-0000-0000-0000-000000000002";
    private const string Environment = "00000003-0000-0000-0000-000000000003";
    private const string OtherEnvironment = "00000004-0000-0000-0000-000000000004";

    [Test]
    public async Task AuthorizationUsesExactGetAndProtectedProjectAttestedMetadata()
    {
        using var request = ProjectConnectionOperations.ListAuthorizations("org", "project");
        var wire = new Wire("authorizations", Response(false));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(request.IsMutation).IsFalse();
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(result.Value.NextOffset).IsNull();
        var row = result.Value.Items.Single();
        await Assert.That(row.Id).IsEqualTo(Authorization);
        await Assert.That(row.ProjectId).IsEqualTo("project");
        await Assert.That(row.Integration).IsEqualTo("native-provider");
        await Assert.That(row.TeamId).IsEqualTo("private-team");
        await Assert.That(row.Url).IsEqualTo("https://destination.test");
        await Assert.That(row.Namespace).IsEqualTo("private-namespace");
        await Assert.That(row.AccountId).IsEqualTo("private-account");
        await Assert.That(row.CreatedAt).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(row.UpdatedAt).IsEqualTo(row.CreatedAt);
        await Assert.That(row.HasProjectScopeAttestation).IsTrue();
        await Assert.That(row.HasOrganizationScopeAttestation).IsFalse();
        await Assert.That(row.IncludesMetadata).IsFalse();
        await Assert.That(JsonSerializer.Serialize(row).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(row.ToString().Contains("project", StringComparison.Ordinal)).IsFalse();
        await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
    }

    [Test]
    public async Task IntegrationUsesExactGetWithoutInventingScopeOrDeliveryAttestation()
    {
        using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
        using var transport = Transport(new Wire("integrations", Response(true)));
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(request.IsMutation).IsFalse();
        await Assert.That(result.Value.IsComplete).IsTrue();
        var row = result.Value.Items.Single();
        await Assert.That(row.Id).IsEqualTo(Integration);
        await Assert.That(row.AuthorizationId).IsEqualTo(Authorization);
        await Assert.That(row.EnvironmentId).IsEqualTo(Environment);
        await Assert.That(row.Environment.Id).IsEqualTo(row.EnvironmentId);
        await Assert.That(row.Environment.Name).IsEqualTo("private-environment");
        await Assert.That(row.Environment.Slug).IsEqualTo("development");
        await Assert.That(row.IsActive).IsTrue();
        await Assert.That(row.IsSynced).IsFalse();
        await Assert.That(row.Url).IsEqualTo("https://destination.test");
        await Assert.That(row.App).IsEqualTo("private-app");
        await Assert.That(row.AppId).IsEqualTo("app-id");
        await Assert.That(row.TargetEnvironment).IsEqualTo("target");
        await Assert.That(row.TargetEnvironmentId).IsEqualTo("target-id");
        await Assert.That(row.TargetService).IsEqualTo("service");
        await Assert.That(row.TargetServiceId).IsEqualTo("service-id");
        await Assert.That(row.Owner).IsEqualTo("private-owner");
        await Assert.That(row.Path).IsEqualTo("/destination");
        await Assert.That(row.Region).IsEqualTo("region");
        await Assert.That(row.Scope).IsEqualTo("scope");
        await Assert.That(row.SecretPath).IsEqualTo("/private-secrets");
        await Assert.That(row.LastUsed).IsEqualTo(row.CreatedAt);
        await Assert.That(row.LastSyncJobId).IsEqualTo("job");
        await Assert.That(row.HasProjectScopeAttestation).IsFalse();
        await Assert.That(row.HasOrganizationScopeAttestation).IsFalse();
        await Assert.That(row.IncludesMetadata).IsFalse();
        await Assert.That(row.IncludesSyncMessage).IsFalse();
        await Assert.That(JsonSerializer.Serialize(row).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(row.Environment)).IsEqualTo("{}");
        await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EmptyNativeListsAreCompleteAndReadOnly(bool integrations)
    {
        string field = Field(integrations);
        using var transport = Transport(new Wire(field, "{\"" + field + "\":[]}"));
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        if (integrations)
        {
            using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
            var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        }
        else
        {
            using var request = ProjectConnectionOperations.ListAuthorizations("org", "project");
            var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        }
    }

    [Test]
    public async Task OptionalIntegrationSecretPathRejectsNull()
    {
        var row = Row(true);
        row["secretPath"] = null;
        await Assert.That(await Execute(true, Response(true, row))).IsEqualTo(SecretStatus.Unknown);
        row.Remove("secretPath");
        await Assert.That(await Execute(true, Response(true, row))).IsEqualTo(SecretStatus.Success);
        row["secretPath"] = "";
        await Assert.That(await Execute(true, Response(true, row))).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NullableOptionalFieldsRemainAbsentRatherThanFabricated(bool integrations)
    {
        var row = Row(integrations);
        foreach (string key in new[] { "url", "app", "appId", "teamId", "namespace", "accountId",
            "targetEnvironment", "targetEnvironmentId", "targetService", "targetServiceId",
            "owner", "path", "region", "scope", "secretPath", "lastUsed", "lastSyncJobId", "isSynced" })
            row.Remove(key);
        using var transport = Transport(new Wire(Field(integrations), Response(integrations, row)));
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        if (integrations)
        {
            using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
            var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items[0].SecretPath).IsNull();
            await Assert.That(result.Value.Items[0].IsSynced).IsNull();
        }
        else
        {
            using var request = ProjectConnectionOperations.ListAuthorizations("org", "project");
            var result = await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items[0].AccountId).IsNull();
        }
    }

    [Test]
    [Arguments(false, "projectId", SecretStatus.Invalid)]
    [Arguments(true, "environment", SecretStatus.Invalid)]
    [Arguments(false, "id", SecretStatus.Unknown)]
    [Arguments(false, "integration", SecretStatus.Unknown)]
    [Arguments(false, "createdAt", SecretStatus.Unknown)]
    [Arguments(false, "updatedAt", SecretStatus.Unknown)]
    [Arguments(true, "id", SecretStatus.Unknown)]
    [Arguments(true, "isActive", SecretStatus.Unknown)]
    [Arguments(true, "integrationAuthId", SecretStatus.Unknown)]
    [Arguments(true, "envId", SecretStatus.Unknown)]
    [Arguments(true, "isSynced", SecretStatus.Unknown)]
    public async Task ReturnedScopeCoordinatesAndMalformedRequiredFieldsFailClosed(
        bool integrations, string defect, SecretStatus expected)
    {
        var row = Row(integrations);
        if (defect == "projectId") row[defect] = "other-project";
        else if (defect == "environment") row[defect] = new { id = OtherEnvironment, name = "name", slug = "slug" };
        else if (defect == "isSynced") row[defect] = "not-a-boolean";
        else row.Remove(defect);
        await Assert.That(await Execute(integrations, Response(integrations, row))).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CollectionAndStreamingResponseBudgetsFailClosed(bool integrations)
    {
        var rows = Enumerable.Repeat(Row(integrations), 1001).ToArray();
        string response = JsonSerializer.Serialize(new Dictionary<string, object> { [Field(integrations)] = rows });
        await Assert.That(await Execute(integrations, response)).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(await Execute(integrations, Response(integrations) + new string(' ', 2048), 1024))
            .IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments(false, "project")]
    [Arguments(true, "project")]
    [Arguments(false, "operation")]
    [Arguments(true, "operation")]
    [Arguments(false, "identity")]
    [Arguments(true, "identity")]
    [Arguments(false, "client")]
    [Arguments(true, "client")]
    public async Task IndependentlySelectedGrantRejectsBeforeTokenOrWire(bool integrations, string defect)
    {
        var tokens = new Tokens();
        var wire = new Wire(Field(integrations), Response(integrations));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var issuer = new ManagementAuthority(client.Authority, tokens, "org", defect == "project" ? "other" : "project");
        var selected = defect == "identity" ? Authority(client, tokens) : issuer;
        var executing = defect == "client" ? new ManagementClient(transport) : client;
        string operation = "infisical.get.v1.projects.by.projectId." + Field(integrations);
        var grant = issuer.IssueGrant(defect == "operation" ? "different-operation" : operation,
            new("org", defect == "project" ? "other" : "project"));
        SecretStatus status;
        if (integrations)
        {
            using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
            status = (await executing.ExecuteAsync(request, selected, grant)).Status;
        }
        else
        {
            using var request = ProjectConnectionOperations.ListAuthorizations("org", "project");
            status = (await executing.ExecuteAsync(request, selected, grant)).Status;
        }
        await Assert.That(status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Entered.Task.IsCompleted).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationPropagatesAtExactTransportBarrier(bool integrations)
    {
        var wire = new Wire(Field(integrations), "{}") { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        using var cancel = new CancellationTokenSource();
        Task pending;
        if (integrations)
        {
            using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
            pending = client.ExecuteAsync(request, authority, Grant(authority, request.OperationId),
                cancellationToken: cancel.Token).AsTask();
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        }
        else
        {
            using var request = ProjectConnectionOperations.ListAuthorizations("org", "project");
            pending = client.ExecuteAsync(request, authority, Grant(authority, request.OperationId),
                cancellationToken: cancel.Token).AsTask();
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        }
    }

    private static string Field(bool integrations) => integrations ? "integrations" : "authorizations";
    private static Dictionary<string, object?> Row(bool integrations)
    {
        var row = new Dictionary<string, object?>
        {
            ["id"] = integrations ? Integration : Authorization,
            ["integration"] = "native-provider",
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:00Z",
            ["url"] = "https://destination.test",
            ["metadata"] = new { unknownCredential = "private-do-not-project" }
        };
        if (integrations)
        {
            row["isActive"] = true;
            row["integrationAuthId"] = Authorization;
            row["envId"] = Environment;
            row["environment"] = new { id = Environment, name = "private-environment", slug = "development" };
            row["app"] = "private-app";
            row["appId"] = "app-id";
            row["targetEnvironment"] = "target";
            row["targetEnvironmentId"] = "target-id";
            row["targetService"] = "service";
            row["targetServiceId"] = "service-id";
            row["owner"] = "private-owner";
            row["path"] = "/destination";
            row["region"] = "region";
            row["scope"] = "scope";
            row["secretPath"] = "/private-secrets";
            row["lastUsed"] = row["createdAt"];
            row["isSynced"] = false;
            row["syncMessage"] = "private-error-do-not-project";
            row["lastSyncJobId"] = "job";
        }
        else
        {
            row["projectId"] = "project";
            row["teamId"] = "private-team";
            row["namespace"] = "private-namespace";
            row["accountId"] = "private-account";
        }
        return row;
    }

    private static string Response(bool integrations, Dictionary<string, object?>? row = null) =>
        JsonSerializer.Serialize(new Dictionary<string, object> { [Field(integrations)] = new[] { row ?? Row(integrations) } });

    private static async Task<SecretStatus> Execute(bool integrations, string response, int budget = 1024 * 1024)
    {
        using var transport = Transport(new Wire(Field(integrations), response), budget);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        if (integrations)
        {
            using var request = ProjectConnectionOperations.ListIntegrations("org", "project");
            return (await client.ExecuteAsync(request, authority, Grant(authority, request.OperationId))).Status;
        }
        using var authorizations = ProjectConnectionOperations.ListAuthorizations("org", "project");
        return (await client.ExecuteAsync(authorizations, authority, Grant(authority, authorizations.OperationId))).Status;
    }

    private static ManagementTransport Transport(HttpMessageHandler wire, int budget = 1024 * 1024) =>
        new(new Uri("https://management.test"), budget, null, false, wire);
    private static ManagementAuthority Authority(ManagementClient client, Tokens? tokens = null) =>
        new(client.Authority, tokens ?? new Tokens(), "org", "project");
    private static ManagementGrant Grant(ManagementAuthority authority, string operation) =>
        authority.IssueGrant(operation, new("org", "project"));

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("test-only-token"))));
        }
    }

    private sealed class Wire(string field, string response) : HttpMessageHandler
    {
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get ||
                request.RequestUri!.PathAndQuery != "/api/v1/projects/project/" + field ||
                request.Headers.Authorization?.Parameter != "test-only-token" ||
                request.Content is not null && (await request.Content.ReadAsByteArrayAsync(cancellationToken)).Length != 0)
                return new(HttpStatusCode.BadRequest);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK)
            {
                // No Content-Length: exercise the controlled stream budget rather than only the header gate.
                Content = new StreamContent(new ResponseStream(System.Text.Encoding.UTF8.GetBytes(response)))
            };
        }
    }

    private sealed class ResponseStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }
}
