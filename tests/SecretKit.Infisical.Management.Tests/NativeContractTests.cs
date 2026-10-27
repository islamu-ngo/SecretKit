using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class NativeContractTests
{
    private const string ProjectId = "66666666-6666-4666-8666-666666666666";
    private const string EnvironmentId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string GroupId = "22222222-2222-4222-8222-222222222222";
    private const string IdentityId = "33333333-3333-4333-8333-333333333333";
    private const string MembershipId = "44444444-4444-4444-8444-444444444444";
    private const string AssignmentId = "55555555-5555-4555-8555-555555555555";
    private const string ForeignId = "99999999-9999-4999-8999-999999999999";
    private const string RoleId = "77777777-7777-4777-8777-777777777777";
    private const string PrivilegeId = "88888888-8888-4888-8888-888888888888";
    private const string UserId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    private const string OtherIdentityId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    [Test]
    [Arguments(0, 1, 0, 1, SecretStatus.Unknown, false)]
    [Arguments(2, 2, 2, 1, SecretStatus.Unknown, false)]
    [Arguments(2, 2, 3, 2, SecretStatus.Unknown, false)]
    [Arguments(0, 2, 3, 1, SecretStatus.Unknown, false)]
    [Arguments(0, 2, 1, 0, SecretStatus.Unknown, false)]
    [Arguments(0, 2, 0, 0, SecretStatus.Success, true)]
    [Arguments(2, 2, 1, 0, SecretStatus.Success, true)]
    [Arguments(2, 2, 2, 0, SecretStatus.Success, true)]
    [Arguments(2, 2, 3, 1, SecretStatus.Success, true)]
    [Arguments(2, 2, 5, 2, SecretStatus.Success, false)]
    [Arguments(1000000, 1, 1000000, 1, SecretStatus.Unknown, false)]
    public async Task CountedProjectPageRejectsContradictionsWithinOneResponse(
        int offset, int limit, int total, int returned, SecretStatus expected, bool complete)
    {
        using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId,
            GroupProjectSelection.Assigned, offset: offset, limit: limit);
        string body = JsonSerializer.Serialize(new
        {
            projects = Enumerable.Range(0, returned).Select(i => new
            {
                id = "project-" + i,
                name = "private",
                slug = "project-" + i,
                type = "secret-manager",
                joinedGroupAt = (string?)null
            }),
            totalCount = total
        });
        var result = await Execute(request, body,
            ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId,
                GroupProjectSelection.Assigned, offset: offset, limit: limit));
        await Assert.That(result.Status).IsEqualTo(expected);
        if (expected == SecretStatus.Success)
        {
            await Assert.That(result.Value.IsComplete).IsEqualTo(complete);
            await Assert.That(result.Value.NextOffset).IsEqualTo(complete ? (int?)null : offset + returned);
        }
    }

    [Test]
    [Arguments(1, true)]
    [Arguments(2, false)]
    public async Task OrganizationIdentityListUsesOuterScopeWithoutInventingNestedEcho(int total, bool complete)
    {
        using var request = IdentityOperations.ListOrganizationIdentities(OrgId);
        var result = await Execute(request,
            $$$$"""{"identities":[{"id":"{{{{MembershipId}}}}","role":"no-access","orgId":"{{{{OrgId}}}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","identityId":"{{{{IdentityId}}}}","identity":{"id":"{{{{IdentityId}}}}","name":"service","authMethods":[]}}],"totalCount":"""
            + total + "}");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Single().Id).IsEqualTo(IdentityId);
        await Assert.That(result.Value.IsComplete).IsEqualTo(complete);
        await Assert.That(result.Value.NextOffset).IsNull();
    }

    [Test]
    [Arguments("outer-org", SecretStatus.Invalid)]
    [Arguments("identity", SecretStatus.Invalid)]
    [Arguments("nested-org", SecretStatus.Invalid)]
    [Arguments("total", SecretStatus.Unknown)]
    public async Task OrganizationIdentityListRejectsOnlyTheDefectiveCorrespondence(string defect, SecretStatus expected)
    {
        string response = JsonSerializer.Serialize(new
        {
            identities = new[]
            {
                new
                {
                    id = MembershipId,
                    role = "no-access",
                    orgId = defect == "outer-org" ? ForeignId : OrgId,
                    createdAt = "2026-10-10T00:00:00Z",
                    updatedAt = "2026-10-10T00:00:00Z",
                    identityId = IdentityId,
                    identity = new
                    {
                        id = defect == "identity" ? ForeignId : IdentityId,
                        name = "service",
                        authMethods = Array.Empty<string>(),
                        orgId = defect == "nested-org" ? ForeignId : OrgId
                    }
                }
            },
            totalCount = defect == "total" ? 0 : 1
        });
        using var request = IdentityOperations.ListOrganizationIdentities(OrgId);
        await Assert.That((await Execute(request, response)).Status).IsEqualTo(expected);
    }

    [Test]
    public async Task ReturnedGroupRoleDoesNotInventAnAbsentTemporaryFlag()
    {
        using var request = MembershipOperations.UpdateProjectGroupRoles(OrgId, "project", GroupId,
            MembershipId, [new MembershipRole("member")]);
        var result = await Execute(request, $$$$"""{"roles":[{"id":"{{{{AssignmentId}}}}","role":"member","projectMembershipId":"{{{{MembershipId}}}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}]}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items.Single())).IsEqualTo("""{"IsTemporary":null}""");
    }

    [Test]
    [Arguments("missing", SecretStatus.Success)]
    [Arguments("null", SecretStatus.Success)]
    [Arguments("matching", SecretStatus.Success)]
    [Arguments("foreign", SecretStatus.Invalid)]
    [Arguments("malformed", SecretStatus.Unknown)]
    public async Task ShareScopeValidatesPresentEchoWithoutRequiringUnpublishedScope(string echo, SecretStatus expected)
    {
        string scope = echo switch
        {
            "missing" => "",
            "null" => ",\"orgId\":null",
            "matching" => ",\"orgId\":\"" + OrgId + "\"",
            "foreign" => ",\"orgId\":\"" + ForeignId + "\"",
            _ => ",\"orgId\":123"
        };
        using var request = SharingOperations.GetShare(OrgId, "share");
        var result = await Execute(request, """{"id":"share","expiresAt":"2026-10-10T00:00:00Z","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","isPasswordProtected":false,"isAuthorizedUser":true """ + scope + "}");
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    public async Task GroupProjectsRespectExplicitSelectionAndCountedPages()
    {
        using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId,
            GroupProjectSelection.Assigned, limit: 1, search: "private canary",
            order: ManagementListOrder.Descending);
        var result = await Execute(request,
            """{"projects":[{"id":"project","name":"private-canary","slug":"project","type":"secret-manager","joinedGroupAt":null}],"totalCount":2}""",
            ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId, GroupProjectSelection.Assigned,
                limit: 1, search: "private canary", order: ManagementListOrder.Descending));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.Items[0].Id).IsEqualTo("project");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("{}");
        await Assert.That(request.Target.SameTarget(ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId,
            GroupProjectSelection.Assigned, limit: 1, search: "private canary",
            order: ManagementListOrder.Descending))).IsTrue();
    }

    [Test]
    public async Task AssignedProjectGrantCannotAuthorizeOrganizationWideInventory()
    {
        using var transport = Transport(new Response("{}"));
        var client = new ManagementClient(transport);
        var tokens = new NoTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId,
            GroupProjectSelection.OrganizationAll);
        var grant = authority.IssueGrant(request.OperationId,
            new(OrgId, resourceId: GroupId, secondaryId: "assignedProjects"));
        var result = await client.ExecuteAsync(request, authority, grant);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task MixedGroupMemberSearchUsesNativeQueryNames()
    {
        using var request = ScopedAccessOperations.ListGroupMembers(OrgId, GroupId, search: "a+b",
            order: ManagementListOrder.Descending, members: GroupMemberFilter.MachineIdentities);
        var result = await Execute(request, """{"members":[],"totalCount":0}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsTrue();
    }

    [Test]
    public async Task MixedGroupMembershipKeepsNativeKindsAndPaging()
    {
        using var request = ScopedAccessOperations.ListGroupMembers(OrgId, GroupId, 0, 2);
        var result = await Execute(request,
            $$$$"""{"members":[{"id":"membership-a","joinedGroupAt":null,"type":"user","user":{"id":"{{{{UserId}}}}","username":"private-canary","email":null}},{"id":"membership-b","joinedGroupAt":null,"type":"machineIdentity","machineIdentity":{"id":"{{{{OtherIdentityId}}}}","name":"private-service-canary"}}],"totalCount":3}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(2);
        await Assert.That(result.Value.Items[0].Kind).IsEqualTo(GroupMemberKind.User);
        await Assert.That(result.Value.Items[1].Kind).IsEqualTo(GroupMemberKind.MachineIdentity);
        await Assert.That(result.Value.Items[0].Id).IsEqualTo("membership-a");
        await Assert.That(result.Value.Items[0].PrincipalId).IsEqualTo(UserId);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0]).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task GroupRoleUpdateUsesNativeRolesResponseAndExpectedMembership()
    {
        using var request = MembershipOperations.UpdateProjectGroupRoles(OrgId, "project", GroupId,
            MembershipId, [new MembershipRole("member")]);
        var result = await Execute(request,
            $$$$"""{"roles":[{"id":"{{{{AssignmentId}}}}","role":"member","projectMembershipId":"{{{{MembershipId}}}}","isTemporary":false}]}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items[0].MembershipId).IsEqualTo(MembershipId);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("""{"IsTemporary":false}""");
    }

    [Test]
    public async Task GroupRoleUpdateCannotPublishForeignMembershipRoles()
    {
        using var request = MembershipOperations.UpdateProjectGroupRoles(OrgId, "project", GroupId,
            MembershipId, [new MembershipRole("member")]);
        var result = await Execute(request,
            $$$$"""{"roles":[{"id":"{{{{AssignmentId}}}}","role":"member","projectMembershipId":"{{{{ForeignId}}}}","isTemporary":false}]}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task GroupRoleUpdateGrantBindsExpectedMembershipBeforeTokens()
    {
        using var transport = Transport(new Response("{}"));
        var client = new ManagementClient(transport);
        var tokens = new NoTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId, "project");
        using var request = MembershipOperations.UpdateProjectGroupRoles(OrgId, "project", GroupId,
            MembershipId, [new MembershipRole("member")]);
        var grant = authority.IssueGrant(request.OperationId, new(OrgId, "project", GroupId, ForeignId));
        var result = await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task ProjectSlugUsesUnwrappedNativeResponse()
    {
        using var request = ProjectOperations.GetProjectBySlug(OrgId, "project-slug");
        var result = await Execute(request, $$$$"""{"id":"project","orgId":"{{{{OrgId}}}}","name":"project","slug":"project-slug","type":"secret-manager","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}""");
        await Assert.That(result.Value.Id).IsEqualTo("project");
        await Assert.That(request.Path).IsEqualTo("/api/v1/projects/slug/project-slug");
    }

    [Test]
    [Arguments("project", SecretStatus.Success)]
    [Arguments("foreign", SecretStatus.Invalid)]
    public async Task EnvironmentValidatesBothResponseScopeLocations(string returnedProject, SecretStatus expected)
    {
        using var request = ProjectOperations.CreateEnvironment(OrgId, "project", "Production", "prod");
        string response = JsonSerializer.Serialize(new
        {
            projectId = returnedProject,
            environment = new
            {
                id = EnvironmentId,
                name = "Production",
                slug = "prod",
                projectId = "project",
                position = 1,
                createdAt = "2026-10-10T00:00:00Z",
                updatedAt = "2026-10-10T00:00:00Z"
            }
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
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId, "project");
        using var hard = ProjectOperations.DeleteEnvironment(OrgId, "project", "environment", true);
        var grant = authority.IssueGrant(hard.OperationId, new(OrgId, "project", "environment", "soft-delete"));
        var receipt = client.CreateReceipt(hard);
        var result = await client.ExecuteAsync(hard, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task ProjectIdentityRejectsAnOrganizationOwnedIdentityResponse()
    {
        using var request = IdentityOperations.GetProjectIdentity(OrgId, "project", IdentityId);
        var result = await Execute(request, $$$$"""{"identity":{"id":"{{{{IdentityId}}}}","name":"service","orgId":"{{{{OrgId}}}}","projectId":null}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task OrganizationIdentityRequiresBothMembershipAndIdentityScope()
    {
        using var request = IdentityOperations.GetOrganizationIdentity(OrgId, IdentityId);
        var result = await Execute(request, $$$$"""{"identity":{"identityId":"{{{{IdentityId}}}}","orgId":"{{{{OrgId}}}}","identity":{"id":"{{{{IdentityId}}}}","name":"service","orgId":"{{{{ForeignId}}}}"}}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task RoleSummariesRejectWrongProjectWithoutInventingEffectivePermissions()
    {
        using var request = ProjectOperations.GetProjectRole(OrgId, "project", RoleId);
        var good = await Execute(request, $$$$"""{"role":{"id":"{{{{RoleId}}}}","name":"Role","slug":"role-slug","projectId":"project","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","permissions":[{"action":"read","conditions":{"opaque":"not exported"}}]}}""");
        var malformed = await Execute(request, $$$$"""{"role":{"id":"{{{{RoleId}}}}","name":"Role","slug":"role-slug","projectId":"project","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z","permissions":[{"opaque":"not exported"}]}}""");
        var bad = await Execute(request, $$$$"""{"role":{"id":"{{{{RoleId}}}}","name":"Role","slug":"role-slug","projectId":"other"}}""");
        await Assert.That(good.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(good.Value.IncludesPermissions).IsTrue();
        await Assert.That(good.Value.Permissions![0].IncludesConditionValues).IsFalse();
        await Assert.That(malformed.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(bad.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(good.Value)).IsEqualTo("""{"IncludesPermissions":true}""");
    }

    [Test]
    public async Task MembershipWritesCopyRoleInputsAndValidateReturnedIdentity()
    {
        var roles = new[] { new MembershipRole("member", DateTimeOffset.UnixEpoch, "1h") };
        using var request = MembershipOperations.AddProjectIdentity(OrgId, "project", IdentityId, roles);
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
        var result = await Execute(request, $$$$"""{"identityMembership":{"id":"{{{{MembershipId}}}}","identityId":"{{{{ForeignId}}}}","projectId":"project"}}""");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task PrivilegeDeletionChecksReturnedPrivilegeAndPreservesHostTarget()
    {
        using var request = IdentityPrivilegeOperations.DeleteProjectPrivilege(OrgId, "project", IdentityId, PrivilegeId);
        var good = await Execute(request, $$$$"""{"privilege":{"id":"{{{{PrivilegeId}}}}","slug":"limited","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","permissions":[]}}""");
        var bad = await Execute(request, $$$$"""{"privilege":{"id":"{{{{ForeignId}}}}","slug":"limited"}}""");
        await Assert.That(good.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(good.Value.IncludesPermissions).IsTrue();
        await Assert.That(good.Value.Permissions!.Count).IsEqualTo(0);
        await Assert.That(bad.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(request.Target.ResourceId).IsEqualTo(IdentityId);
        await Assert.That(request.Target.SecondaryId).IsEqualTo(PrivilegeId);
    }

    [Test]
    public async Task AuditSettingsUseNativeDiscriminatorsAndCopyInputs()
    {
        var settings = new[] { new AuditClassSetting(AuditEventClass.Authentication, true),
            new AuditClassSetting(AuditEventClass.Authorization, false) };
        using var request = GovernanceOperations.SetProjectAuditSettings(OrgId, ProjectId, settings);
        settings[0] = new AuditClassSetting(AuditEventClass.Authorization, true);
        byte[] bytes = request.CopyBody()!;
        try
        {
            using JsonDocument body = JsonDocument.Parse(bytes);
            await Assert.That(body.RootElement.GetProperty("eventClasses")[0].GetProperty("eventClass").GetString())
                .IsEqualTo("authentication");
            await Assert.That(body.RootElement.GetProperty("eventClasses")[0].GetProperty("isEnabled").GetBoolean()).IsTrue();
            await Assert.That(body.RootElement.GetProperty("eventClasses")[1].GetProperty("eventClass").GetString())
                .IsEqualTo("authorization");
            await Assert.That(body.RootElement.GetProperty("eventClasses")[1].GetProperty("isEnabled").GetBoolean()).IsFalse();
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
            new() { AllowLoopbackDevelopmentHttp = true });
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new TokenSource(), OrgId);
        using var request = ScopedAccessOperations.GetGroup(OrgId, GroupId);
        Task<SecretOutcome<GroupMetadata>> operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(OrgId, resourceId: GroupId)),
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
        await Assert.That(firstLine).IsEqualTo($"GET /api/v1/groups/{GroupId} HTTP/1.1");
        await Assert.That(headers.Any(line => line.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase))).IsTrue();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, string response,
        ManagementTarget? approved = null) where T : notnull
    {
        using var transport = Transport(new Response(response));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new TokenSource(),
            request.Target.OrganizationId, request.Target.ProjectId);
        // Contract tests construct independent coordinates, not a grant from request identity.
        var target = approved ?? new ManagementTarget(request.Target.OrganizationId, request.Target.ProjectId,
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
