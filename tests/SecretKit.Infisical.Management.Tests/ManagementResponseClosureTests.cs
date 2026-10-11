using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementResponseClosureTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Id = "22222222-2222-4222-8222-222222222222";
    private const string Principal = "33333333-3333-4333-8333-333333333333";
    private const string Time = "2026-10-11T00:00:00Z";

    [Test]
    [Arguments("root")]
    [Arguments("role")]
    [Arguments("permission")]
    public async Task RoleClosedNodesRejectExtraMembersButKeepOpaqueConditions(string node)
    {
        var permission = new JsonObject
        {
            ["action"] = "read",
            ["conditions"] = new JsonObject { ["unestablished-private"] = new JsonArray(1, 2) }
        };
        var role = new JsonObject
        {
            ["id"] = Id,
            ["orgId"] = Org,
            ["name"] = "private-role",
            ["slug"] = "private-role",
            ["createdAt"] = Time,
            ["updatedAt"] = Time,
            ["permissions"] = new JsonArray(permission)
        };
        var root = new JsonObject { ["role"] = role };
        using var request = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        var target = new ManagementTarget(Org, resourceId: Id);
        var good = await Execute(request, target, root, "/api/v1/organization/roles/" + Id);
        await Assert.That(good.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(good.Value.Permissions![0].HasConditions).IsTrue();
        await Assert.That(good.Value.Permissions[0].IncludesConditionValues).IsFalse();
        (node == "root" ? root : node == "role" ? role : permission)["undeclared-private"] = true;
        await Assert.That((await Execute(request, target, root, "/api/v1/organization/roles/" + Id)).Status)
            .IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("user", false)]
    [Arguments("user", true)]
    [Arguments("machineIdentity", false)]
    [Arguments("machineIdentity", true)]
    public async Task GroupMemberClosedBranchesRejectExtraPrincipalAndCrossBranchFields(string kind, bool crossBranch)
    {
        var principal = new JsonObject { ["id"] = Principal, [kind == "user" ? "username" : "name"] = "private-principal" };
        var member = new JsonObject { ["id"] = Id, ["type"] = kind, ["joinedGroupAt"] = null, [kind] = principal };
        var root = new JsonObject { ["members"] = new JsonArray(member), ["totalCount"] = 1 };
        using var request = ScopedAccessOperations.ListGroupMembers(Org, Id);
        var target = ScopedAccessOperations.GroupMemberListTarget(Org, Id);
        string path = "/api/v1/groups/" + Id + "/members";
        await Assert.That((await Execute(request, target, root, path)).Status).IsEqualTo(SecretStatus.Success);
        if (crossBranch)
            member[kind == "user" ? "machineIdentity" : "user"] = new JsonObject { ["id"] = Principal };
        else principal["undeclared-private"] = true;
        await Assert.That((await Execute(request, target, root, path)).Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("row")]
    [Arguments("actor")]
    [Arguments("event")]
    public async Task AuditClosedRowFailuresPreserveOrdinalsAndOpaqueNeighbors(string node)
    {
        var row = new JsonObject
        {
            ["id"] = Id,
            ["orgId"] = Org,
            ["createdAt"] = Time,
            ["updatedAt"] = Time,
            ["actor"] = new JsonObject { ["type"] = "identity", ["metadata"] = new JsonObject { ["unknown-private"] = true } },
            ["event"] = new JsonObject
            {
                ["type"] = "get-secret",
                ["class"] = "data-access",
                ["metadata"] = new JsonObject { ["unknown-private"] = new JsonArray(1, 2) }
            }
        };
        var invalid = row.DeepClone().AsObject();
        (node == "row" ? invalid : invalid[node]!.AsObject())["undeclared-private"] = true;
        var foreign = row.DeepClone().AsObject();
        foreign["orgId"] = Principal;
        foreign["undeclared-private"] = true;
        var root = new JsonObject { ["auditLogs"] = new JsonArray(row.DeepClone(), invalid, foreign, row.DeepClone()) };
        var from = DateTimeOffset.UnixEpoch;
        using var request = GovernanceOperations.ReadAudit(Org, from, from.AddDays(1), offset: 7);
        var result = await Execute(request, GovernanceOperations.AuditReadTarget(Org, from, from.AddDays(1), offset: 7),
            root, "/api/v1/organization/audit-logs");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(4);
        for (int index = 0; index < 4; index++)
        {
            await Assert.That(result.Value.Items[index].Ordinal).IsEqualTo(7 + index);
            await Assert.That(result.Value.Items[index].Outcome.Status).IsEqualTo(
                index == 1 ? SecretStatus.Unknown : index == 2 ? SecretStatus.Invalid : SecretStatus.Success);
        }
        await Assert.That(JsonSerializer.Serialize(result).Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ArrayRootGroupInventoryRejectsExtraItemMembers()
    {
        var group = new JsonObject
        {
            ["id"] = Id,
            ["orgId"] = Org,
            ["name"] = "private-group",
            ["slug"] = "private-group",
            ["createdAt"] = Time,
            ["updatedAt"] = Time
        };
        var root = new JsonArray(group);
        using var request = ScopedAccessOperations.ListGroups(Org);
        await Assert.That((await Execute(request, new(Org), root, "/api/v1/groups")).Status)
            .IsEqualTo(SecretStatus.Success);
        group["undeclared-private"] = true;
        await Assert.That((await Execute(request, new(Org), root, "/api/v1/groups")).Status)
            .IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task ForeignRoleWithAnExtraMemberRetainsInvalidClassification()
    {
        var root = new JsonObject
        {
            ["role"] = new JsonObject
            {
                ["id"] = Principal,
                ["orgId"] = Org,
                ["name"] = "private-role",
                ["slug"] = "private-role",
                ["createdAt"] = Time,
                ["updatedAt"] = Time,
                ["permissions"] = new JsonArray()
            },
            ["undeclared-private"] = true
        };
        using var request = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        await Assert.That((await Execute(request, new(Org, resourceId: Id), root,
            "/api/v1/organization/roles/" + Id)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task DirectParserRejectsCaseSensitiveExtraNames()
    {
        var root = new JsonObject
        {
            ["role"] = new JsonObject
            {
                ["id"] = Id,
                ["orgId"] = Org,
                ["name"] = "private-role",
                ["slug"] = "private-role",
                ["createdAt"] = Time,
                ["updatedAt"] = Time,
                ["permissions"] = new JsonArray()
            }
        };
        using var request = ScopedAccessOperations.GetOrganizationRole(Org, Id);
        await Assert.That(request.Parse(JsonSerializer.SerializeToElement(root)).Id).IsEqualTo(Id);
        root["Role"] = new JsonObject();
        await Assert.That(() => request.Parse(JsonSerializer.SerializeToElement(root)))
            .Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("organization-role")]
    [Arguments("project-role")]
    [Arguments("privilege")]
    public async Task InventoryProfilesRejectPermissionPayloadsFromRicherResults(string kind)
    {
        var row = new JsonObject { ["id"] = Principal, ["slug"] = "private-role", ["createdAt"] = Time, ["updatedAt"] = Time };
        if (kind != "privilege")
        {
            row["name"] = "private-role";
            row[kind == "project-role" ? "projectId" : "orgId"] = kind == "project-role" ? Id : Org;
        }
        var root = new JsonObject { [kind == "privilege" ? "privileges" : "roles"] = new JsonArray(row) };
        switch (kind)
        {
            case "organization-role":
                using (var request = ScopedAccessOperations.ListOrganizationRoles(Org))
                    await Verify(request, new(Org), "/api/v1/organization/roles");
                break;
            case "project-role":
                using (var request = ProjectOperations.ListProjectRoles(Org, Id))
                    await Verify(request, new(Org, Id), "/api/v1/projects/" + Id + "/roles");
                break;
            default:
                using (var request = IdentityPrivilegeOperations.ListProjectPrivileges(Org, Id, Principal))
                    await Verify(request, new(Org, Id, Principal), "/api/v2/identity-project-additional-privilege");
                break;
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target, string path) where T : notnull
        {
            await Assert.That((await Execute(request, target, root, path)).Status).IsEqualTo(SecretStatus.Success);
            row["permissions"] = new JsonArray();
            await Assert.That((await Execute(request, target, root, path)).Status).IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    public async Task PostParseClosureFailureDisposesConstructedMaterialAndRetainsDispatchUncertainty()
    {
        using var input = SecretMaterial.FromText("private-input");
        using var native = SharingOperations.CreateShare(Org, "private-share", input, 5, ShareAudience.Organization);
        byte[] body = native.CopyBody()!;
        using var document = JsonDocument.Parse(body);
        CreatedShare? captured = null;
        var target = SharingOperations.CreateShareTarget(Org, "private-share", input, 5, ShareAudience.Organization);
        using var request = new ManagementRequest<CreatedShare>(
            "infisical.post.v1.shared.secrets", HttpMethod.Post, "/api/v1/shared-secrets", target,
            writer => document.RootElement.WriteTo(writer),
            value => captured = new CreatedShare(new SharedSecretMetadata(value, Org),
                AuthenticationJson.Material(value, "sharedSecretLink")));
        Array.Clear(body);
        var root = new JsonObject
        {
            ["id"] = Id,
            ["name"] = "private-share",
            ["orgId"] = Org,
            ["sharedSecretLink"] = "private-link",
            ["createdAt"] = Time,
            ["updatedAt"] = Time,
            ["expiresAt"] = Time,
            ["undeclared-private"] = true
        };
        var wire = new Wire(root.ToJsonString(), "/api/v1/shared-secrets", "POST");
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, target.ProjectId);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            SharingOperations.CreateShareTarget(Org, "private-share", input, 5, ShareAudience.Organization)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(captured).IsNotNull();
        await Assert.That(() => captured!.Link.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(JsonSerializer.Serialize(result).Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, ManagementTarget target,
        JsonNode response, string path) where T : notnull
    {
        var wire = new Wire(response.ToJsonString(), path);
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, target.ProjectId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        await Assert.That(wire.Observed).IsTrue();
        return result;
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }

    private sealed class Wire(string response, string path, string method = "GET") : HttpMessageHandler
    {
        internal bool Observed { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Observed = true;
            await Assert.That(request.Method.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.AbsolutePath).IsEqualTo(path);
            return new(HttpStatusCode.OK) { Content = new StringContent(response) };
        }
    }
}
