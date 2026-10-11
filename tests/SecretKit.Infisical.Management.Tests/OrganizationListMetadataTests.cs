using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class OrganizationListMetadataTests
{
    private const string User = "50000000-0000-4000-8000-000000000005";
    private const string Membership = "30000000-0000-4000-8000-000000000003";
    private const string Org = "10000000-0000-4000-8000-000000000001";

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("empty")]
    [Arguments("value")]
    public async Task OptionalNullableUserAndMembershipFieldsRemainDistinct(string shape)
    {
        var row = Row();
        var user = row["user"]!.AsObject();
        if (shape != "absent")
        {
            bool nil = shape == "null";
            row["lastInvitedAt"] = nil ? null : "2026-10-10T00:00:00Z";
            row["lastLoginTime"] = nil ? null : "2026-10-10T01:00:00+01:00";
            row["lastLoginAuthMethod"] = nil ? null : shape == "empty" ? "" : "private-method";
            row["projectFavorites"] = nil ? null : shape == "empty" ? new JsonArray() : new JsonArray("", "private-project");
            user["authMethods"] = nil ? null : shape == "empty" ? new JsonArray() : new JsonArray("", "private-auth");
            user["isEmailVerified"] = nil ? null : shape == "value";
            user["publicKey"] = nil ? null : shape == "empty" ? "" : "private-key";
        }
        var result = await Execute(row);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var metadata = result.Value.Items.Single();
        await Assert.That(metadata.LastInvitedAt.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.LastInvitedAt.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.LastLoginTime.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.LastLoginTime.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.LastLoginAuthMethod.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.LastLoginAuthMethod.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.ProjectFavorites.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.ProjectFavorites.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.User!.AuthMethods.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.User.AuthMethods.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.User.IsEmailVerified.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.User.IsEmailVerified.IsNull).IsEqualTo(shape == "null");
        await Assert.That(metadata.User.PublicKey.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(metadata.User.PublicKey.IsNull).IsEqualTo(shape == "null");
        if (shape is "empty" or "value")
        {
            await Assert.That(metadata.LastInvitedAt.Value).IsEqualTo("2026-10-10T00:00:00Z");
            await Assert.That(metadata.LastLoginTime.Value).IsEqualTo("2026-10-10T01:00:00+01:00");
            await Assert.That(metadata.LastLoginAuthMethod.Value).IsEqualTo(shape == "empty" ? "" : "private-method");
            await Assert.That(metadata.User.IsEmailVerified.Value).IsEqualTo(shape == "value");
            await Assert.That(metadata.User.PublicKey.Value).IsEqualTo(shape == "empty" ? "" : "private-key");
            await Assert.That(metadata.ProjectFavorites.Value.Count).IsEqualTo(shape == "empty" ? 0 : 2);
            await Assert.That(metadata.User.AuthMethods.Value.Count).IsEqualTo(shape == "empty" ? 0 : 2);
            if (shape == "value")
            {
                await Assert.That(metadata.ProjectFavorites.Value[0]).IsEqualTo("");
                await Assert.That(metadata.ProjectFavorites.Value[1]).IsEqualTo("private-project");
                await Assert.That(metadata.User.AuthMethods.Value[0]).IsEqualTo("");
                await Assert.That(metadata.User.AuthMethods.Value[1]).IsEqualTo("private-auth");
                await Assert.That(() => ((IList<string>)metadata.User.AuthMethods.Value)[0] = "mutated").Throws<NotSupportedException>();
                await Assert.That(() => ((IList<string>)metadata.ProjectFavorites.Value)[0] = "mutated").Throws<NotSupportedException>();
            }
        }
        await Assert.That(JsonSerializer.Serialize(metadata).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(metadata.User)).IsEqualTo("{}");
    }

    [Test]
    [Arguments("lastInvitedAt")]
    [Arguments("lastLoginTime")]
    [Arguments("lastLoginAuthMethod")]
    [Arguments("projectFavorites")]
    [Arguments("projectFavoritesElement")]
    [Arguments("authMethods")]
    [Arguments("authMethodsElement")]
    [Arguments("isEmailVerified")]
    [Arguments("publicKey")]
    public async Task WrongKnownFieldTypesFailClosed(string field)
    {
        var row = Row();
        var target = field is "authMethods" or "authMethodsElement" or "isEmailVerified" or "publicKey"
            ? row["user"]!.AsObject() : row;
        if (field is "lastInvitedAt" or "lastLoginTime") target[field] = "not-a-date";
        else if (field.EndsWith("Element", StringComparison.Ordinal)) target[field[..^7]] = new JsonArray(123);
        else target[field] = 123;
        await Assert.That((await Execute(row)).Status).IsEqualTo(SecretStatus.Unknown);
    }

    private static JsonObject Row() => JsonNode.Parse(
        $$$$$"""{"id":"{{{{{Membership}}}}}","orgId":"{{{{{Org}}}}}","role":"member","user":{"id":"{{{{{User}}}}}","username":"user"}}""")!.AsObject();

    private static async Task<SecretOutcome<ManagementPage<OrganizationMembershipSummary>>> Execute(JsonObject row)
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false,
            new Wire(new JsonObject { ["users"] = new JsonArray(row) }.ToJsonString()));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, new(Org)));
    }

    [Test]
    public async Task ListMembershipMetadataIsNotLostInTheInventoryBranch()
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false,
            new Wire($$$$$"""{"users":[{"id":"{{{{{Membership}}}}}","orgId":"{{{{{Org}}}}}","role":"member","lastInvitedAt":"2026-10-10T00:00:00Z","lastLoginAuthMethod":"","lastLoginTime":null,"projectFavorites":["","private"],"user":{"id":"{{{{{User}}}}}","username":"user"}}]}"""));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = OrganizationMembershipOperations.ListOrganizationMemberships(Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, new(Org)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var row = result.Value.Items.Single();
        await Assert.That(row.LastInvitedAt.IsPresent).IsTrue();
        await Assert.That(row.LastInvitedAt.Value).IsEqualTo("2026-10-10T00:00:00Z");
        await Assert.That(row.LastLoginAuthMethod.Value).IsEqualTo("");
        await Assert.That(row.LastLoginTime.IsNull).IsTrue();
        await Assert.That(row.ProjectFavorites.Value.Count).IsEqualTo(2);
        await Assert.That(JsonSerializer.Serialize(row)).IsEqualTo("""{"IncludesPermissions":false}""");
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
    private sealed class Wire(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
    }
}
