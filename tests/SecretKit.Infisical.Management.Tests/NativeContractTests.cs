using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class NativeContractTests
{
    [Test]
    public async Task GroupProjectsRespectExplicitSelectionAndCountedPages()
    {
        using var request = ScopedAccessOperations.ListGroupProjects("org", "group",
            GroupProjectSelection.Assigned, limit: 1, search: "private canary",
            order: ManagementListOrder.Descending);
        var result = await Execute(request,
            """{"projects":[{"id":"project","name":"private-canary","slug":"project","type":"secret-manager","joinedGroupAt":null}],"totalCount":2}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.Items[0].Id).IsEqualTo("project");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("{}");
        await Assert.That(request.Target.SecondaryId).IsEqualTo("assignedProjects");
    }

    [Test]
    public async Task AssignedProjectGrantCannotAuthorizeOrganizationWideInventory()
    {
        using var transport = Transport(new Response("{}"));
        var client = new ManagementClient(transport);
        var tokens = new NoTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = ScopedAccessOperations.ListGroupProjects("org", "group",
            GroupProjectSelection.OrganizationAll);
        var grant = authority.IssueGrant(request.OperationId,
            new("org", resourceId: "group", secondaryId: "assignedProjects"));
        var result = await client.ExecuteAsync(request, authority, grant);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task MixedGroupMemberSearchUsesNativeQueryNames()
    {
        using var request = ScopedAccessOperations.ListGroupMembers("org", "group", search: "a+b",
            order: ManagementListOrder.Descending, members: GroupMemberFilter.MachineIdentities);
        var result = await Execute(request, """{"members":[],"totalCount":0}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsTrue();
    }

    [Test]
    public async Task MixedGroupMembershipKeepsNativeKindsAndPaging()
    {
        using var request = ScopedAccessOperations.ListGroupMembers("org", "group", 0, 2);
        var result = await Execute(request,
            """{"members":[{"id":"membership-a","joinedGroupAt":null,"type":"user","user":{"id":"principal-a","username":"private-canary","email":null}},{"id":"membership-b","joinedGroupAt":null,"type":"machineIdentity","machineIdentity":{"id":"principal-b","name":"private-service-canary"}}],"totalCount":3}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(2);
        await Assert.That(result.Value.Items[0].Kind).IsEqualTo(GroupMemberKind.User);
        await Assert.That(result.Value.Items[1].Kind).IsEqualTo(GroupMemberKind.MachineIdentity);
        await Assert.That(result.Value.Items[0].Id).IsEqualTo("membership-a");
        await Assert.That(result.Value.Items[0].PrincipalId).IsEqualTo("principal-a");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0]).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task GroupRoleUpdateUsesNativeRolesResponseAndExpectedMembership()
    {
        using var request = MembershipOperations.UpdateProjectGroupRoles("org", "project", "group",
            "membership", [new MembershipRole("member")]);
        var result = await Execute(request,
            """{"roles":[{"id":"assignment","role":"member","projectMembershipId":"membership","isTemporary":false}]}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items[0].MembershipId).IsEqualTo("membership");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("""{"IsTemporary":false}""");
    }

    [Test]
    public async Task GroupRoleUpdateCannotPublishForeignMembershipRoles()
    {
        using var request = MembershipOperations.UpdateProjectGroupRoles("org", "project", "group",
            "membership", [new MembershipRole("member")]);
        var result = await Execute(request,
            """{"roles":[{"id":"assignment","role":"member","projectMembershipId":"other","isTemporary":false}]}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task GroupRoleUpdateGrantBindsExpectedMembershipBeforeTokens()
    {
        using var transport = Transport(new Response("{}"));
        var client = new ManagementClient(transport);
        var tokens = new NoTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "org", "project");
        using var request = MembershipOperations.UpdateProjectGroupRoles("org", "project", "group",
            "membership", [new MembershipRole("member")]);
        var grant = authority.IssueGrant(request.OperationId, new("org", "project", "group", "other"));
        var result = await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task ProjectSlugUsesUnwrappedNativeResponse()
    {
        using var request = ProjectOperations.GetProjectBySlug("org", "project-slug");
        var result = await Execute(request, """{"id":"project","orgId":"org","name":"project","slug":"project-slug","type":"secret-manager"}""");
        await Assert.That(result.Value.Id).IsEqualTo("project");
        await Assert.That(request.Path).IsEqualTo("/api/v1/projects/slug/project-slug");
    }

    [Test]
    [Arguments("project", SecretStatus.Success)]
    [Arguments("foreign", SecretStatus.Invalid)]
    public async Task EnvironmentValidatesBothResponseScopeLocations(string returnedProject, SecretStatus expected)
    {
        using var request = ProjectOperations.CreateEnvironment("org", "project", "Production", "prod");
        string response = JsonSerializer.Serialize(new
        {
            projectId = returnedProject,
            environment = new { id = "environment", name = "Production", slug = "prod", projectId = "project", position = 1 }
        });
        var result = await Execute(request, response);
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    public async Task HardDeleteGrantCannotAuthorizeSoftDeleteOrConversely()
    {
        using var transport = Transport(new Response("""{}"""));
        var client = new ManagementClient(transport);
        var tokens = new NoTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "org", "project");
        using var hard = ProjectOperations.DeleteEnvironment("org", "project", "environment", true);
        var grant = authority.IssueGrant(hard.OperationId, new("org", "project", "environment", "soft-delete"));
        var receipt = client.CreateReceipt(hard);
        var result = await client.ExecuteAsync(hard, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task ProjectIdentityRejectsAnOrganizationOwnedIdentityResponse()
    {
        using var request = IdentityOperations.GetProjectIdentity("org", "project", "identity");
        var result = await Execute(request, """{"identity":{"id":"identity","name":"service","orgId":"org","projectId":null}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task OrganizationIdentityRequiresBothMembershipAndIdentityScope()
    {
        using var request = IdentityOperations.GetOrganizationIdentity("org", "identity");
        var result = await Execute(request, """{"identity":{"identityId":"identity","orgId":"org","identity":{"id":"identity","name":"service","orgId":"other"}}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task RoleSummariesRejectWrongProjectWithoutInventingEffectivePermissions()
    {
        using var request = ProjectOperations.GetProjectRole("org", "project", "role");
        var good = await Execute(request, """{"role":{"id":"role","name":"Role","slug":"role-slug","projectId":"project","permissions":[{"opaque":"not exported"}]}}""");
        var bad = await Execute(request, """{"role":{"id":"role","name":"Role","slug":"role-slug","projectId":"other"}}""");
        await Assert.That(good.Value.IncludesPermissions).IsFalse();
        await Assert.That(bad.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(good.Value)).IsEqualTo("""{"IncludesPermissions":false}""");
    }

    [Test]
    public async Task MembershipWritesCopyRoleInputsAndValidateReturnedIdentity()
    {
        var roles = new[] { new MembershipRole("member", DateTimeOffset.UnixEpoch, "1h") };
        using var request = MembershipOperations.AddProjectIdentity("org", "project", "identity", roles);
        roles[0] = new MembershipRole("admin");
        byte[] bytes = request.CopyBody()!;
        try
        {
            using JsonDocument body = JsonDocument.Parse(bytes);
            JsonElement role = body.RootElement.GetProperty("roles")[0];
            await Assert.That(role.GetProperty("role").GetString()).IsEqualTo("member");
            await Assert.That(role.GetProperty("temporaryRange").GetString()).IsEqualTo("1h");
            await Assert.That(role.GetProperty("isTemporary").GetBoolean()).IsTrue();
        }
        finally { Array.Clear(bytes); }
        var result = await Execute(request, """{"identityMembership":{"id":"membership","identityId":"other","projectId":"project"}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task PrivilegeDeletionChecksReturnedPrivilegeAndPreservesHostTarget()
    {
        using var request = IdentityPrivilegeOperations.DeleteProjectPrivilege("org", "project", "identity", "privilege");
        var good = await Execute(request, """{"privilege":{"id":"privilege","slug":"limited"}}""");
        var bad = await Execute(request, """{"privilege":{"id":"foreign","slug":"limited"}}""");
        await Assert.That(good.Value.IncludesPermissions).IsFalse();
        await Assert.That(bad.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(request.Target.ResourceId).IsEqualTo("identity");
        await Assert.That(request.Target.SecondaryId).IsEqualTo("privilege");
    }

    [Test]
    public async Task AuditSettingsUseNativeDiscriminatorsAndCopyInputs()
    {
        var settings = new[] { new AuditClassSetting(AuditEventClass.DataAccess, true) };
        using var request = GovernanceOperations.SetProjectAuditSettings("org", "project", settings);
        settings[0] = new AuditClassSetting(AuditEventClass.Management, false);
        byte[] bytes = request.CopyBody()!;
        try
        {
            using JsonDocument body = JsonDocument.Parse(bytes);
            await Assert.That(body.RootElement.GetProperty("eventClasses")[0].GetProperty("eventClass").GetString())
                .IsEqualTo("data-access");
        }
        finally { Array.Clear(bytes); }
        var result = await Execute(request, """{"auditLogSettings":{"eventClasses":[{"eventClass":"data-access","isEnabled":true}],"shouldUseNewPrivilegeSystem":true}}""");
        await Assert.That(result.Value.Classes[0].EventClass).IsEqualTo(AuditEventClass.DataAccess);
    }

    [Test]
    public async Task RedirectIsNotFollowedByTheRealManagedTransport()
    {
        using var server = new TcpListener(IPAddress.Loopback, 0);
        server.Start();
        int port = ((IPEndPoint)server.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        Task<TcpClient> accepted = server.AcceptTcpClientAsync(timeout.Token).AsTask();
        using var transport = new ManagementTransport(new Uri($"http://127.0.0.1:{port}"),
            allowLoopbackDevelopmentHttp: true);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new TokenSource(), "org");
        using var request = ScopedAccessOperations.GetGroup("org", "group");
        Task<SecretOutcome<GroupMetadata>> operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org", resourceId: "group")),
            cancellationToken: timeout.Token).AsTask();
        using TcpClient socket = await accepted;
        using NetworkStream stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, leaveOpen: true);
        string firstLine = (await reader.ReadLineAsync(timeout.Token))!;
        var headers = new List<string>();
        for (string? line = await reader.ReadLineAsync(timeout.Token); !string.IsNullOrEmpty(line);
            line = await reader.ReadLineAsync(timeout.Token))
        {
            headers.Add(line);
        }
        // Redirect to a different path on this listener. Following it would leave
        // the operation pending until the bounded test cancellation, not Unknown.
        byte[] response = Encoding.ASCII.GetBytes($"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/escape\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(response, timeout.Token);
        SecretOutcome<GroupMetadata> result = await operation;
        await Assert.That(firstLine).IsEqualTo("GET /api/v1/groups/group HTTP/1.1");
        await Assert.That(headers.Any(line => line.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase))).IsTrue();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, string response) where T : notnull
    {
        using var transport = Transport(new Response(response));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new TokenSource(),
            request.Target.OrganizationId, request.Target.ProjectId);
        // Contract tests construct independent coordinates, not a grant from request identity.
        var target = new ManagementTarget(request.Target.OrganizationId, request.Target.ProjectId,
            request.Target.ResourceId, request.Target.SecondaryId);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
            request.IsMutation ? client.CreateReceipt(request) : null);
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Response(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
    }

    private sealed class NoTokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            throw new InvalidOperationException("No token is authorized.");
        }
    }

    private sealed class TokenSource : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText(Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))))));
    }
}
