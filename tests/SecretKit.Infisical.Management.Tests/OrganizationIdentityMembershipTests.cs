using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class OrganizationIdentityMembershipTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Identity = "20000000-0000-4000-8000-000000000002";
    private const string Membership = "30000000-0000-4000-8000-000000000003";

    [Test]
    public async Task CountedNativeInventoryValidatesNestedIdentityAndProtectsMetadata()
    {
        using var request = OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(
            Org, limit: 1, orderBy: OrganizationIdentityOrder.Role,
            order: ManagementListOrder.Descending, search: "private+service");
        var outcome = await Execute(request, Response(), new(Org),
            "?offset=0&limit=1&orderBy=role&orderDirection=desc&search=private%2Bservice");
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(outcome.Value.IsComplete).IsFalse();
        await Assert.That(outcome.Value.NextOffset).IsEqualTo(1);
        await Assert.That(outcome.Value.Items[0].IdentityId).IsEqualTo(Identity);
        await Assert.That(outcome.Value.Items[0].Identity.Id).IsEqualTo(Identity);
        await Assert.That(JsonSerializer.Serialize(outcome.Value.Items[0]))
            .IsEqualTo("""{"IncludesPermissions":false}""");
    }

    [Test]
    [Arguments("outer-org")]
    [Arguments("nested-org")]
    [Arguments("identity")]
    public async Task ForeignMembershipCoordinatesFailClosed(string defect)
    {
        using var request = OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(Org, limit: 1);
        var outcome = await Execute(request, Response(defect), new(Org));
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task OrganizationGrantMismatchFailsBeforeTokens()
    {
        using var request = OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(Org);
        var tokens = new Tokens();
        using var transport = Transport("{}");
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var other = new ManagementAuthority(client.Authority, tokens, "other");
        var result = await client.ExecuteAsync(request, authority,
            other.IssueGrant(request.OperationId, new("other")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    private static string Response(string? defect = null) => JsonSerializer.Serialize(new
    {
        identityMemberships = new[]
        {
            new
            {
                id = Membership,
                orgId = defect == "outer-org" ? "90000000-0000-4000-8000-000000000009" : Org,
                identityId = Identity,
                role = "member",
                createdAt = "2026-01-01T00:00:00Z",
                updatedAt = "2026-01-01T00:00:00Z",
                identity = new
                {
                    id = defect == "identity" ? "90000000-0000-4000-8000-000000000009" : Identity,
                    orgId = defect == "nested-org" ? "90000000-0000-4000-8000-000000000009" : Org,
                    name = "private-service",
                    authMethods = new[] { "token-auth" }
                }
            }
        },
        totalCount = 2
    });

    private static async Task<SecretOutcome<ManagementPage<OrganizationIdentityMembershipSummary>>> Execute(
        ManagementRequest<ManagementPage<OrganizationIdentityMembershipSummary>> request,
        string body, ManagementTarget independentTarget,
        string expectedQuery = "?offset=0&limit=1&orderBy=name&orderDirection=asc")
    {
        using var transport = Transport(body, expectedQuery);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, independentTarget));
    }

    private static ManagementTransport Transport(string body, string? expectedQuery = null) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire(body, expectedQuery));

    private sealed class Wire(string body, string? expectedQuery) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Get ||
                request.RequestUri!.AbsolutePath != "/api/v2/organizations/10000000-0000-4000-8000-000000000001/identity-memberships" ||
                expectedQuery is not null && request.RequestUri.Query != expectedQuery)
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
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
