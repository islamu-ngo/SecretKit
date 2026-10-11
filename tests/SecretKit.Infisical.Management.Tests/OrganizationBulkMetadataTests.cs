using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class OrganizationBulkMetadataTests
{
    private const string Membership = "30000000-0000-4000-8000-000000000003";
    private const string Org = "10000000-0000-4000-8000-000000000001";

    [Test]
    [Arguments("lastInvitedAt")]
    [Arguments("lastLoginAuthMethod")]
    [Arguments("lastLoginTime")]
    [Arguments("projectFavorites")]
    public async Task MalformedKnownBulkMetadataRemainsUnknown(string field)
    {
        var row = Row();
        row[field] = true;
        var result = await Delete(row);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("null")]
    [Arguments("value")]
    [Arguments("empty")]
    public async Task BulkMetadataPreservesPresenceAndCopiedFavorites(string shape)
    {
        var row = Row();
        string[] favorites = ["private-project"];
        if (shape != "missing")
        {
            row["lastInvitedAt"] = shape == "null" ? null : "2026-10-01T00:00:00Z";
            row["lastLoginTime"] = shape == "null" ? null : "2026-10-02T00:00:00+02:00";
            row["lastLoginAuthMethod"] = shape == "null" ? null : shape == "empty" ? "" : "private-method";
            row["projectFavorites"] = shape == "null" ? null : shape == "empty" ? Array.Empty<string>() : favorites;
        }
        var result = await Delete(row);
        favorites[0] = "changed";
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var value = result.Value.Items[0];
        await Assert.That(value.LastInvitedAt.IsPresent).IsEqualTo(shape != "missing");
        await Assert.That(value.LastLoginTime.IsPresent).IsEqualTo(shape != "missing");
        await Assert.That(value.LastLoginAuthMethod.IsPresent).IsEqualTo(shape != "missing");
        await Assert.That(value.ProjectFavorites.IsPresent).IsEqualTo(shape != "missing");
        await Assert.That(value.LastInvitedAt.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.LastLoginTime.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.LastLoginAuthMethod.IsNull).IsEqualTo(shape == "null");
        await Assert.That(value.ProjectFavorites.IsNull).IsEqualTo(shape == "null");
        if (shape is "value" or "empty")
        {
            await Assert.That(value.LastLoginTime.Value).IsEqualTo("2026-10-02T00:00:00+02:00");
            await Assert.That(value.LastLoginAuthMethod.Value).IsEqualTo(shape == "empty" ? "" : "private-method");
            await Assert.That(value.ProjectFavorites.Value.Count).IsEqualTo(shape == "empty" ? 0 : 1);
            if (shape == "value") await Assert.That(value.ProjectFavorites.Value[0]).IsEqualTo("private-project");
        }
        await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("""{"IncludesPermissions":false}""");
        await Assert.That(value.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("lastInvitedAt")]
    [Arguments("lastLoginTime")]
    public async Task MalformedNativeDateRemainsUnknown(string field)
    {
        var row = Row();
        row[field] = "not-a-date";
        await Assert.That((await Delete(row)).Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task UndeclaredBulkMetadataCannotBeBorrowedFromRequestFields()
    {
        var row = Row();
        row["metadata"] = null;
        await Assert.That((await Delete(row)).Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static Dictionary<string, object?> Row() => new()
    {
        ["id"] = Membership,
        ["orgId"] = Org,
        ["role"] = "member",
        ["isActive"] = false,
        ["userId"] = null,
        ["inviteEmail"] = null,
        ["createdAt"] = "2026-10-01T00:00:00Z",
        ["updatedAt"] = "2026-10-01T00:00:00Z"
    };

    private static async Task<SecretOutcome<ManagementPage<OrganizationMembershipSummary>>> Delete(Dictionary<string, object?> row)
    {
        string[] ids = [Membership];
        using var request = MembershipMutationOperations.DeleteOrganizationMemberships(Org, ids);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false,
            new Wire(JsonSerializer.Serialize(new { memberships = new[] { row } })));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            MembershipMutationOperations.OrganizationDeletionTarget(Org, ids)), client.CreateReceipt(request));
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-only-token"))));
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") });
    }
}
