using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GroupIntentTests
{
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string GroupId = "22222222-2222-4222-8222-222222222222";
    private const string IdentityId = "33333333-3333-4333-8333-333333333333";
    private const string ForeignId = "99999999-9999-4999-8999-999999999999";
    private const string UserId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    private const string Group = $$$$"""{"id":"{{{{GroupId}}}}","orgId":"{{{{OrgId}}}}","name":"Reviewed","slug":"reviewed","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}""";

    [Test]
    [Arguments("name")]
    [Arguments("slug")]
    [Arguments("role")]
    [Arguments("omitted-role")]
    public async Task CreationBindsEveryChoiceWithExplicitSlug(string changed)
    {
        using var request = ScopedAccessOperations.CreateGroup(OrgId, changed == "name" ? "Other" : "Reviewed",
            changed == "slug" ? "another" : "reviewed", changed == "role" ? "admin" : changed == "omitted-role" ? null : "member");
        await Deny(request, ScopedAccessOperations.GroupCreationTarget(OrgId, "Reviewed", "reviewed", "member"));
    }

    [Test]
    [Arguments("name")]
    [Arguments("slug")]
    [Arguments("role")]
    [Arguments("omitted-name")]
    [Arguments("omitted-slug")]
    [Arguments("omitted-role")]
    public async Task UpdateBindsEverySuppliedAndOmittedChoice(string changed)
    {
        using var request = ScopedAccessOperations.UpdateGroup(OrgId, GroupId,
            changed == "name" ? "Other" : changed == "omitted-name" ? null : "Reviewed",
            changed == "slug" ? "another" : changed == "omitted-slug" ? null : "reviewed",
            changed == "role" ? "admin" : changed == "omitted-role" ? null : "member");
        await Deny(request, ScopedAccessOperations.GroupUpdateTarget(OrgId, GroupId, "Reviewed", "reviewed", "member"));
    }

    [Test]
    [Arguments("offset")]
    [Arguments("limit")]
    [Arguments("search")]
    [Arguments("empty-search")]
    [Arguments("order")]
    [Arguments("selection")]
    public async Task ProjectInventoryBindsAllSelectorsBeforeTokens(string changed)
    {
        using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId,
            changed == "selection" ? GroupProjectSelection.Unassigned : GroupProjectSelection.Assigned,
            offset: changed == "offset" ? 1 : 0, limit: changed == "limit" ? 1 : 100,
            search: changed == "search" ? "other" : changed == "empty-search" ? "" : null,
            order: changed == "order" ? ManagementListOrder.Descending : ManagementListOrder.Ascending);
        await Deny(request, ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId, GroupProjectSelection.Assigned));
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task ApprovedBodyUsesIndependentTargetAndImmutableSerializedCopy(int route)
    {
        using var request = route == 0 ? ScopedAccessOperations.CreateGroup(OrgId, "Reviewed", "reviewed", "member") :
            ScopedAccessOperations.UpdateGroup(OrgId, GroupId, role: "member");
        byte[] copy = request.CopyBody()!;
        Array.Fill(copy, (byte)0);
        var wire = new Wire(Group);
        var target = route == 0 ? ScopedAccessOperations.GroupCreationTarget(OrgId, "Reviewed", "reviewed", "member") :
            ScopedAccessOperations.GroupUpdateTarget(OrgId, GroupId, role: "member");
        await Accept(request, target, wire, async value =>
        {
            await Assert.That(value.Id).IsEqualTo(GroupId);
            await Assert.That(value.Name).IsEqualTo("Reviewed");
        });
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("role").GetString()).IsEqualTo("member");
        await Assert.That(body.RootElement.TryGetProperty("slug", out _)).IsEqualTo(route == 0);
        await Assert.That(JsonSerializer.Serialize(target)).IsEqualTo("{}");
    }

    [Test]
    [Arguments(GroupProjectSelection.Assigned, null)]
    [Arguments(GroupProjectSelection.Unassigned, "")]
    [Arguments(GroupProjectSelection.OrganizationAll, "private + &")]
    public async Task ProjectInventoryPreservesNativeSelectionAndEmptySearch(GroupProjectSelection selection, string? search)
    {
        using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId, selection, limit: 1, search: search,
            order: ManagementListOrder.Descending);
        var wire = new Wire("""{"projects":[{"id":"project","name":"Reviewed","slug":"project","type":"secret-manager","joinedGroupAt":null}],"totalCount":2}""");
        await Accept(request, ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId, selection, limit: 1, search: search,
            order: ManagementListOrder.Descending), wire, async page =>
        {
            await Assert.That(page.Items[0].Id).IsEqualTo("project");
            await Assert.That(page.IsComplete).IsFalse();
            await Assert.That(page.NextOffset).IsEqualTo(1);
        });
        string query = $"/api/v1/groups/{GroupId}/projects?offset=0&limit=1&orderBy=name&orderDirection=desc";
        if (search is not null) query += "&search=" + Uri.EscapeDataString(search);
        if (selection != GroupProjectSelection.OrganizationAll)
            query += "&filter=" + (selection == GroupProjectSelection.Assigned ? "assignedProjects" : "unassignedProjects");
        await Assert.That(wire.Path).IsEqualTo(query);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task GroupMetadataRowsValidateTheirNativeEnvelopeAndReturnedScope(int route)
    {
        var group = JsonNode.Parse(Group)!.AsObject();
        if (route == 3) group["customRoleSlug"] = null;
        if (route == 0)
        {
            using var request = ScopedAccessOperations.ListGroups(OrgId);
            await CheckMetadata(request, new(OrgId), group, true);
        }
        else
        {
            using var request = route switch
            {
                1 => ScopedAccessOperations.CreateGroup(OrgId, "Reviewed", "reviewed"),
                2 => ScopedAccessOperations.DeleteGroup(OrgId, GroupId),
                3 => ScopedAccessOperations.GetGroup(OrgId, GroupId),
                _ => ScopedAccessOperations.UpdateGroup(OrgId, GroupId, name: "Reviewed")
            };
            var target = route == 1 ? ScopedAccessOperations.GroupCreationTarget(OrgId, "Reviewed", "reviewed") :
                route == 4 ? ScopedAccessOperations.GroupUpdateTarget(OrgId, GroupId, name: "Reviewed") :
                new ManagementTarget(OrgId, resourceId: GroupId);
            await CheckMetadata(request, target, group, false);
        }
    }

    private static async Task CheckMetadata<T>(ManagementRequest<T> request, ManagementTarget target,
        JsonObject group, bool list) where T : notnull
    {
        await Assert.That(request.OperationId).IsEqualTo(list ? "infisical.get.v1.groups" :
            request.IsMutation ? request.Method == HttpMethod.Post ? "infisical.post.v1.groups" :
            request.Method == HttpMethod.Delete ? "infisical.delete.v1.groups.by.id" : "infisical.patch.v1.groups.by.id" :
            "infisical.get.v1.groups.by.id");
        string Envelope() => list ? new JsonArray(group.DeepClone()).ToJsonString() : group.ToJsonString();
        await Accept(request, target, new Wire(Envelope()), async value =>
        {
            var metadata = value is GroupMetadata item ? item : ((ManagementPage<GroupMetadata>)(object)value).Items[0];
            await Assert.That(metadata.Id).IsEqualTo(GroupId);
            await Assert.That(metadata.Name).IsEqualTo("Reviewed");
            await Assert.That(metadata.OrganizationId).IsEqualTo(OrgId);
            await Assert.That(metadata.CustomRoleSlug.IsPresent).IsEqualTo(group.ContainsKey("customRoleSlug"));
            await Assert.That(JsonSerializer.Serialize(metadata)).IsEqualTo("{}");
        });
        foreach (string field in new[] { "orgId", "id" })
        {
            var original = group[field]!.GetValue<string>();
            group[field] = field == "orgId" || (!list && request.OperationId != "infisical.post.v1.groups")
                ? ForeignId : null;
            await Assert.That(await Status(request, target, Envelope())).IsEqualTo(group[field] is null ? SecretStatus.Unknown : SecretStatus.Invalid);
            group[field] = original;
        }
        group["name"] = false;
        await Assert.That(await Status(request, target, Envelope())).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task GetGroupRequiredNullableCustomRoleRetainsNullEmptyAndCopiedValue()
    {
        using var request = ScopedAccessOperations.GetGroup(OrgId, GroupId);
        var target = new ManagementTarget(OrgId, resourceId: GroupId);
        foreach (string? slug in new string?[] { null, "", "private-role" })
        {
            var group = JsonNode.Parse(Group)!.AsObject();
            group["customRoleSlug"] = slug;
            await Accept(request, target, new Wire(group.ToJsonString()), async value =>
            {
                await Assert.That(value.CustomRoleSlug.IsPresent).IsTrue();
                await Assert.That(value.CustomRoleSlug.IsNull).IsEqualTo(slug is null);
                if (slug is not null) await Assert.That(value.CustomRoleSlug.Value).IsEqualTo(slug);
                await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            });
        }
        await Assert.That(await Status(request, target, Group)).IsEqualTo(SecretStatus.Unknown);
        var malformed = JsonNode.Parse(Group)!.AsObject();
        malformed["customRoleSlug"] = false;
        await Assert.That(await Status(request, target, malformed.ToJsonString())).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    public async Task RemainingGroupRowsHaveControlledPositiveAndMalformedWitnesses(int route)
    {
        if (route < 2)
        {
            using var request = route == 0 ? ScopedAccessOperations.AddGroupIdentity(OrgId, GroupId, "identity") :
                ScopedAccessOperations.RemoveGroupIdentity(OrgId, GroupId, "identity");
            var target = new ManagementTarget(OrgId, resourceId: GroupId, secondaryId: "identity");
            await Assert.That(request.OperationId).IsEqualTo(route == 0 ?
                "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" :
                "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId");
            await Accept(request, target, new Wire("""{"id":"membership"}"""), async value =>
                await Assert.That(value.Id).IsEqualTo("membership"));
            await Assert.That(await Status(request, target, """{"id":null}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else if (route < 4)
        {
            using var request = route == 2 ? ScopedAccessOperations.AddGroupUser(OrgId, GroupId, "user") :
                ScopedAccessOperations.RemoveGroupUser(OrgId, GroupId, "user");
            var target = new ManagementTarget(OrgId, resourceId: GroupId, secondaryId: "user");
            await Assert.That(request.OperationId).IsEqualTo(route == 2 ?
                "infisical.post.v1.groups.by.id.users.by.username" : "infisical.delete.v1.groups.by.id.users.by.username");
            await Accept(request, target, new Wire($$$$"""{"id":"{{{{UserId}}}}","username":"user"}"""), async value =>
                await Assert.That(value.Username).IsEqualTo("user"));
            await Assert.That(await Status(request, target, $$$$"""{"id":"{{{{UserId}}}}","username":"foreign"}""")).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(await Status(request, target, """{"username":"user"}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else if (route == 4)
        {
            using var request = ScopedAccessOperations.AvailableGroups(OrgId);
            await Assert.That(request.OperationId).IsEqualTo("infisical.get.v1.organization.available.groups");
            await Accept(request, new(OrgId), new Wire($$$$"""{"groups":[{"id":"{{{{GroupId}}}}","name":"Reviewed"}]}"""), async value =>
                await Assert.That(value.Items[0].Id).IsEqualTo(GroupId));
            await Assert.That(await Status(request, new(OrgId), """{"groups":[{"id":null,"name":"Reviewed"}]}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else if (route == 5)
        {
            using var request = ScopedAccessOperations.ListGroupIdentities(OrgId, GroupId);
            await Assert.That(request.OperationId).IsEqualTo("infisical.get.v1.groups.by.id.machine.identities");
            var target = ScopedAccessOperations.GroupIdentityListTarget(OrgId, GroupId);
            await Accept(request, target, new Wire($$$$"""{"machineIdentities":[{"id":"{{{{IdentityId}}}}","name":"Reviewed","isPartOfGroup":false,"joinedGroupAt":null}],"totalCount":1}"""),
                async value => await Assert.That(value.Items[0].IsMember).IsFalse());
            await Assert.That(await Status(request, target, $$$$"""{"machineIdentities":[{"id":"{{{{IdentityId}}}}","name":"Reviewed","isPartOfGroup":null,"joinedGroupAt":null}],"totalCount":1}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else if (route == 6)
        {
            using var request = ScopedAccessOperations.ListGroupMembers(OrgId, GroupId);
            await Assert.That(request.OperationId).IsEqualTo("infisical.get.v1.groups.by.id.members");
            var target = ScopedAccessOperations.GroupMemberListTarget(OrgId, GroupId);
            await Accept(request, target, new Wire($$$$"""{"members":[{"id":"membership","type":"machineIdentity","joinedGroupAt":null,"machineIdentity":{"id":"{{{{IdentityId}}}}","name":"Reviewed"}}],"totalCount":1}"""),
                async value => await Assert.That(value.Items[0].PrincipalId).IsEqualTo(IdentityId));
            await Assert.That(await Status(request, target, """{"members":[{"id":"membership","type":"machineIdentity","joinedGroupAt":null,"machineIdentity":null}],"totalCount":1}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else if (route == 7)
        {
            using var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId, GroupProjectSelection.Assigned);
            await Assert.That(request.OperationId).IsEqualTo("infisical.get.v1.groups.by.id.projects");
            var target = ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId, GroupProjectSelection.Assigned);
            await Accept(request, target, new Wire("""{"projects":[{"id":"project","name":"Reviewed","slug":"project","type":"secret-manager","joinedGroupAt":null}],"totalCount":1}"""),
                async value => await Assert.That(value.Items[0].Id).IsEqualTo("project"));
            await Assert.That(await Status(request, target, """{"projects":[{"id":"project","name":"Reviewed","slug":"project","joinedGroupAt":null}],"totalCount":1}""")).IsEqualTo(SecretStatus.Unknown);
        }
        else
        {
            using var request = ScopedAccessOperations.ListGroupUsers(OrgId, GroupId);
            await Assert.That(request.OperationId).IsEqualTo("infisical.get.v1.groups.by.id.users");
            var target = ScopedAccessOperations.GroupUserListTarget(OrgId, GroupId);
            await Accept(request, target, new Wire($$$$"""{"users":[{"id":"{{{{UserId}}}}","username":"user","isPartOfGroup":false,"joinedGroupAt":null}],"totalCount":1}"""),
                async value => await Assert.That(value.Items[0].IsMember).IsFalse());
            await Assert.That(await Status(request, target, $$$$"""{"users":[{"id":"{{{{UserId}}}}","username":"user","isPartOfGroup":"false","joinedGroupAt":null}],"totalCount":1}""")).IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task GroupInventoryRequiresJoinedTimestampButAcceptsNull(int row)
    {
        var item = JsonNode.Parse(row switch
        {
            0 => $$$$"""{"id":"{{{{IdentityId}}}}","name":"Reviewed","isPartOfGroup":false}""",
            1 => $$$$"""{"id":"{{{{UserId}}}}","username":"Reviewed","isPartOfGroup":false}""",
            2 => """{"id":"project","name":"Reviewed","slug":"reviewed","type":"secret-manager"}""",
            3 => $$$$"""{"id":"membership","type":"user","user":{"id":"{{{{UserId}}}}","username":"Reviewed"}}""",
            _ => $$$$"""{"id":"membership","type":"machineIdentity","machineIdentity":{"id":"{{{{IdentityId}}}}","name":"Reviewed"}}"""
        })!.AsObject();
        string field = row switch { 0 => "machineIdentities", 1 => "users", 2 => "projects", _ => "members" };
        var envelope = new JsonObject { [field] = new JsonArray(item), ["totalCount"] = 1 };
        switch (row)
        {
            case 0:
                using (var request = ScopedAccessOperations.ListGroupIdentities(OrgId, GroupId))
                    await Verify(request, ScopedAccessOperations.GroupIdentityListTarget(OrgId, GroupId),
                        page => page.Items[0].JoinedAt);
                break;
            case 1:
                using (var request = ScopedAccessOperations.ListGroupUsers(OrgId, GroupId))
                    await Verify(request, ScopedAccessOperations.GroupUserListTarget(OrgId, GroupId),
                        page => page.Items[0].JoinedAt);
                break;
            case 2:
                using (var request = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId, GroupProjectSelection.Assigned))
                    await Verify(request, ScopedAccessOperations.GroupProjectListTarget(OrgId, GroupId, GroupProjectSelection.Assigned),
                        page => page.Items[0].JoinedAt);
                break;
            default:
                using (var request = ScopedAccessOperations.ListGroupMembers(OrgId, GroupId))
                    await Verify(request, ScopedAccessOperations.GroupMemberListTarget(OrgId, GroupId),
                        page => page.Items[0].JoinedAt);
                break;
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target, Func<T, string?> joined) where T : notnull
        {
            foreach (string? date in new[] { null, "2026-10-11T00:00:00+02:00" })
            {
                item["joinedGroupAt"] = date;
                await Accept(request, target, new Wire(envelope.ToJsonString()), async value =>
                {
                    await Assert.That(joined(value)).IsEqualTo(date);
                    await Assert.That(JsonSerializer.Serialize(value).Contains("2026", StringComparison.Ordinal)).IsFalse();
                });
            }
            item.Remove("joinedGroupAt");
            await Assert.That(await Status(request, target, envelope.ToJsonString())).IsEqualTo(SecretStatus.Unknown);
            item["joinedGroupAt"] = false;
            await Assert.That(await Status(request, target, envelope.ToJsonString())).IsEqualTo(SecretStatus.Unknown);
        }
    }

    private static async Task<SecretStatus> Status<T>(ManagementRequest<T> request, ManagementTarget target, string json) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire(json));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        return (await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
            request.IsMutation ? client.CreateReceipt(request) : null)).Status;
    }

    private static async Task Accept<T>(ManagementRequest<T> request, ManagementTarget target, Wire wire,
        Func<T, Task> verify) where T : notnull
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
            request.IsMutation ? client.CreateReceipt(request) : null);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        transport.Dispose();
        await verify(result.Value);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task CoordinateOnlyGrantCannotApproveGroupChoices(int route)
    {
        using var request = route == 0
            ? ScopedAccessOperations.CreateGroup(OrgId, "Reviewed", "reviewed", "admin")
            : ScopedAccessOperations.UpdateGroup(OrgId, GroupId, name: "Reviewed");
        if (route == 2)
        {
            using var list = ScopedAccessOperations.ListGroupProjects(OrgId, GroupId, GroupProjectSelection.Assigned);
            await Deny(list, new(OrgId, resourceId: GroupId, secondaryId: "assignedProjects"));
        }
        else await Deny(request, new(OrgId, resourceId: route == 0 ? "reviewed" : GroupId));
    }

    internal static async Task Deny<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var tokens = new Tokens();
        var wire = new Wire("{}");
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    internal sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }

    internal sealed class Wire(string json) : HttpMessageHandler
    {
        public bool Sent { get; private set; }
        public string? Path { get; private set; }
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            Path = request.RequestUri!.PathAndQuery;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }
    }
}
