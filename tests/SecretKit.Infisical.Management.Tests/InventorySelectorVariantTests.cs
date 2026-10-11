using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class InventorySelectorVariantTests
{
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string GroupId = "22222222-2222-4222-8222-222222222222";
    private const string IdentityId = "33333333-3333-4333-8333-333333333333";
    private const string MembershipId = "44444444-4444-4444-8444-444444444444";
    private const string ForeignId = "99999999-9999-4999-8999-999999999999";

    [Test]
    [Arguments(null)]
    [Arguments("")]
    [Arguments("private+service & name")]
    public async Task ProjectSearchUsesExactNativeQueryAndProtectedCountedResult(string? search)
    {
        using var request = IdentityOperations.ListProjectIdentities(OrgId, "project", limit: 1, search: search);
        var target = IdentityOperations.ProjectIdentityListTarget(OrgId, "project", limit: 1, search: search);
        string query = "?offset=0&limit=1" + (search is null ? "" : "&search=" + Uri.EscapeDataString(search));
        var result = await Execute(request, target,
            $$$$"""{"identities":[{"id":"{{{{IdentityId}}}}","name":"private-name","orgId":"{{{{OrgId}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}],"totalCount":2}""",
            "/api/v1/projects/project/identities", query);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.Items[0].Id).IsEqualTo(IdentityId);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("{}");
    }

    [Test]
    [Arguments(OrganizationGroupOrder.Name, ManagementListOrder.Ascending)]
    [Arguments(OrganizationGroupOrder.Slug, ManagementListOrder.Descending)]
    [Arguments(OrganizationGroupOrder.Role, ManagementListOrder.Ascending)]
    public async Task OrganizationGroupOrderingAndSearchUseExactNativeQuery(
        OrganizationGroupOrder orderBy, ManagementListOrder order)
    {
        using var request = MembershipOperations.ListOrganizationGroups(OrgId, limit: 1,
            orderBy: orderBy, order: order, search: "private+group");
        var target = MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1,
            orderBy: orderBy, order: order, search: "private+group");
        string query = "?offset=0&limit=1&orderBy=" + orderBy.ToString().ToLowerInvariant() +
            "&orderDirection=" + (order == ManagementListOrder.Ascending ? "asc" : "desc") + "&search=private%2Bgroup";
        var result = await Execute(request, target, GroupResponse(),
            "/api/v1/organizations/memberships/groups", query);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.Items[0].PrincipalId).IsEqualTo(GroupId);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("""{"IncludesRoles":true}""");
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("scalar")]
    [Arguments("empty")]
    [Arguments("one")]
    [Arguments("multiple")]
    public async Task OrganizationRoleFiltersPreserveCopiedNativeAlternatives(string variant)
    {
        string[] source = variant == "multiple" ? ["member", "admin+custom"] : ["member"];
        OrganizationGroupRoleFilter? roles = variant switch
        {
            "omitted" => null,
            "scalar" => OrganizationGroupRoleFilter.Scalar("member"),
            "empty" => OrganizationGroupRoleFilter.Array([]),
            _ => OrganizationGroupRoleFilter.Array(source)
        };
        OrganizationGroupRoleFilter? approved = variant switch
        {
            "omitted" => null,
            "scalar" => OrganizationGroupRoleFilter.Scalar("member"),
            "empty" => OrganizationGroupRoleFilter.Array([]),
            "one" => OrganizationGroupRoleFilter.Array(["member"]),
            _ => OrganizationGroupRoleFilter.Array(["member", "admin+custom"])
        };
        source[0] = "unapproved";
        using var request = MembershipOperations.ListOrganizationGroups(OrgId, limit: 1, roles: roles);
        var target = MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, roles: approved);
        string query = "?offset=0&limit=1" + (variant is "omitted" or "empty" ? "" : "&roles=member") +
            (variant == "multiple" ? "&roles=admin%2Bcustom" : "");
        var result = await Execute(request, target, GroupResponse(),
            "/api/v1/organizations/memberships/groups", query);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        if (roles is not null)
        {
            await Assert.That(JsonSerializer.Serialize(roles)).IsEqualTo("{}");
            await Assert.That(roles.ToString().Contains("member", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    [Arguments("paging")]
    [Arguments("search")]
    [Arguments("order")]
    [Arguments("roles")]
    [Arguments("shape")]
    [Arguments("empty")]
    public async Task ChangedInventoryIntentIsRejectedBeforeTokenOrDispatch(string difference)
    {
        var roles = OrganizationGroupRoleFilter.Scalar("member");
        using var request = MembershipOperations.ListOrganizationGroups(OrgId, limit: 1, roles: roles);
        var approved = difference switch
        {
            "paging" => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 2, roles: roles),
            "search" => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, search: "", roles: roles),
            "order" => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, orderBy: OrganizationGroupOrder.Name, roles: roles),
            "roles" => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, roles: OrganizationGroupRoleFilter.Scalar("admin")),
            "shape" => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, roles: OrganizationGroupRoleFilter.Array(["member"])),
            _ => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1, roles: OrganizationGroupRoleFilter.Array([]))
        };
        await RejectIntent(request, approved);
    }

    [Test]
    public async Task EmptyRoleArrayAndOmissionHaveDifferentGrants()
    {
        using var request = MembershipOperations.ListOrganizationGroups(OrgId, roles: OrganizationGroupRoleFilter.Array([]));
        await RejectIntent(request, MembershipOperations.OrganizationGroupListTarget(OrgId));
    }

    [Test]
    public async Task ProjectSearchAndScopeHaveIndependentGrants()
    {
        using var request = IdentityOperations.ListProjectIdentities(OrgId, "project", search: "selected");
        await RejectIntent(request, IdentityOperations.ProjectIdentityListTarget(OrgId, "project", search: "other"));
        await RejectIntent(request, IdentityOperations.ProjectIdentityListTarget(OrgId, "project"));
    }

    [Test]
    [Arguments("org")]
    [Arguments("project")]
    public async Task ForeignProjectInventoryCoordinatesFailClosed(string field)
    {
        using var request = IdentityOperations.ListProjectIdentities(OrgId, "project");
        string body = JsonSerializer.Serialize(new
        {
            identities = new[] { new { id = IdentityId, name = "private", orgId = field == "org" ? ForeignId : OrgId,
                projectId = field == "project" ? "foreign" : "project" } },
            totalCount = 1
        });
        var result = await Execute(request, IdentityOperations.ProjectIdentityListTarget(OrgId, "project"), body,
            "/api/v1/projects/project/identities", "?offset=0&limit=100");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ForeignOrganizationGroupEchoFailsClosed()
    {
        using var request = MembershipOperations.ListOrganizationGroups(OrgId, limit: 1);
        var result = await Execute(request, MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 1),
            GroupResponse(ForeignId), "/api/v1/organizations/memberships/groups", "?offset=0&limit=1");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task InvalidSelectorsFailBeforeTransportConstruction()
    {
        await Assert.That(() => OrganizationGroupRoleFilter.Array(Enumerable.Repeat("role", 101).ToArray()))
            .Throws<ArgumentException>();
        await Assert.That(() => OrganizationGroupRoleFilter.Array([null!])).Throws<ArgumentNullException>();
        await Assert.That(() => IdentityOperations.ListProjectIdentities(OrgId, "project", search: "private\n"))
            .Throws<ArgumentException>();
        await Assert.That(() => MembershipOperations.ListOrganizationGroups(OrgId, orderBy: (OrganizationGroupOrder)999))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => MembershipOperations.ListOrganizationGroups(OrgId, order: (ManagementListOrder)999))
            .Throws<ArgumentOutOfRangeException>();
        await Assert.That(() => MembershipOperations.OrganizationGroupListTarget(OrgId, limit: 101))
            .Throws<ArgumentException>();
    }

    private static string GroupResponse(string organizationId = OrgId) => JsonSerializer.Serialize(new
    {
        groupMemberships = new[] { new { id = MembershipId, groupId = GroupId,
            createdAt = "2026-10-10T00:00:00Z", updatedAt = "2026-10-10T00:00:00Z", roles = Array.Empty<object>(),
            group = new { id = GroupId, name = "private-group", slug = "private-group", orgId = organizationId } } },
        totalCount = 2
    });

    private static async Task RejectIntent<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var tokens = new Tokens();
        var wire = new Wire("{}");
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId, target.ProjectId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, ManagementTarget target,
        string body, string path, string query) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024,
            null, false, new Wire(body, path, query));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId, target.ProjectId);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CoordinateOnlyGrantCannotAuthorizeInventorySelection(bool project)
    {
        if (project)
        {
            using var request = IdentityOperations.ListProjectIdentities(OrgId, "project", offset: 1);
            await RejectCoordinateOnlyGrant(request, project);
        }
        else
        {
            using var request = MembershipOperations.ListOrganizationGroups(OrgId, offset: 1);
            await RejectCoordinateOnlyGrant(request, project);
        }
    }

    private static async Task RejectCoordinateOnlyGrant<T>(ManagementRequest<T> request, bool project) where T : notnull
    {
        var tokens = new Tokens();
        var wire = new Wire(project ? """{"identities":[],"totalCount":0}""" :
            """{"groupMemberships":[],"totalCount":0}""");
        using var transport = new ManagementTransport(new Uri("https://management.test"),
            1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId, project ? "project" : null);
        var outcome = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(OrgId, project ? "project" : null)));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
    }

    private sealed class Wire(string body, string? expectedPath = null, string? expectedQuery = null) : HttpMessageHandler
    {
        public bool Sent { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            bool matches = request.Method == HttpMethod.Get &&
                (expectedPath is null || request.RequestUri!.AbsolutePath == expectedPath) &&
                (expectedQuery is null || request.RequestUri!.Query == expectedQuery);
            return Task.FromResult(new HttpResponseMessage(matches ? HttpStatusCode.OK : HttpStatusCode.NotFound)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
        }
    }

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
}
