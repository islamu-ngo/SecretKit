using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class OrganizationSelectionIntentTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Membership = "30000000-0000-4000-8000-000000000003";

    [Test]
    [Arguments("available", "same")]
    [Arguments("available", "name")]
    [Arguments("available", "offset")]
    [Arguments("available", "limit")]
    [Arguments("members", "same")]
    [Arguments("members", "name")]
    [Arguments("members", "offset")]
    [Arguments("members", "limit")]
    [Arguments("members", "roles")]
    [Arguments("update", "same")]
    [Arguments("update", "role")]
    [Arguments("update", "active")]
    [Arguments("update", "metadata")]
    public async Task WholeIndependentMembershipSelectionCannotBeBorrowed(string operation, string changed)
    {
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire());
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org, operation == "update" ? null : "project");
        if (operation == "update")
        {
            IdentityAttribute[] metadata = [new("key", changed == "metadata" ? "other" : "value")];
            using var request = OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership,
                changed == "role" ? "member" : "admin", changed == "active" ? true : false, metadata);
            metadata[0] = new("mutated", "after-copy");
            await Verify(request, OrganizationMembershipOperations.OrganizationMembershipUpdateTarget(Org, Membership,
                "admin", false, [new("key", "value")]));
        }
        else
        {
            int offset = changed == "offset" ? 1 : 0;
            int limit = changed == "limit" ? 3 : 2;
            string name = changed == "name" ? "other" : "chosen";
            if (operation == "available")
            {
                using var request = ProjectMembershipOperations.ListAvailableProjectIdentities(Org, "project", offset, limit, name);
                await Verify(request, ProjectMembershipOperations.AvailableProjectIdentityListTarget(Org, "project", 0, 2, "chosen"));
            }
            else
            {
                using var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, "project", offset, limit,
                    name, changed == "roles" ? "member" : "");
                await Verify(request, ProjectMembershipOperations.ProjectIdentityMembershipListTarget(Org, "project", 0, 2, "chosen", ""));
            }
        }
        await Assert.That(tokens.Acquired).IsEqualTo(changed == "same");
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
            await Assert.That(result.Status).IsEqualTo(changed == "same" ? SecretStatus.Success : SecretStatus.Denied);
            if (receipt is not null)
                await Assert.That(receipt.Evidence).IsEqualTo(changed == "same" ? DispatchEvidence.Applied : DispatchEvidence.NotDispatched);
        }
    }

    [Test]
    [Arguments("available")]
    [Arguments("members")]
    [Arguments("update")]
    public async Task CoordinateApprovalCannotAuthorizeMembershipSelections(string operation)
    {
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire());
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org, operation == "update" ? null : "project");
        switch (operation)
        {
            case "available":
                await Denied(ProjectMembershipOperations.ListAvailableProjectIdentities(Org, "project", identityName: "chosen"),
                    new(Org, "project"));
                break;
            case "members":
                await Denied(ProjectMembershipOperations.ListProjectIdentityMemberships(Org, "project", identityName: "chosen", roles: "admin"),
                    new(Org, "project"));
                break;
            default:
                await Denied(OrganizationMembershipOperations.UpdateOrganizationMembership(Org, Membership, role: "admin"),
                    new(Org, resourceId: Membership));
                break;
        }
        await Assert.That(tokens.Acquired).IsFalse();
        async Task Denied<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            }
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
    private sealed class Wire : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.Method == HttpMethod.Patch
                ? $$$$$"""{"membership":{"id":"{{{{{Membership}}}}}","orgId":"{{{{{Org}}}}}","role":"admin","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}}"""
                : request.RequestUri!.AbsolutePath.EndsWith("/available-identities", StringComparison.Ordinal)
                    ? """{"identities":[]}"""
                    : """{"identityMemberships":[],"totalCount":0}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}
