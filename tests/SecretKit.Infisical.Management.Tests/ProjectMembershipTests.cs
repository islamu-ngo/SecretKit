using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProjectMembershipTests
{
    private const string User = "00000014-0000-0000-0000-000000000014";
    private const string Identity = "00000015-0000-0000-0000-000000000015";
    private const string OtherUser = "00000016-0000-0000-0000-000000000016";
    private const string OtherIdentity = "00000017-0000-0000-0000-000000000017";
    private const string OtherOrg = "00000018-0000-0000-0000-000000000018";
    private const string OtherMember = "00000019-0000-0000-0000-000000000019";
    private const string Role = "0000001a-0000-0000-0000-00000000001a";
    private const string Org = "0000000a-0000-0000-0000-00000000000a";
    private const string Project = "project";
    private const string Member = "0000001b-0000-0000-0000-00000000001b";
    private const string Username = "private+user@example.test";
    private const string Prefix = "/api/v1/projects/project/memberships";

    [Test]
    public async Task UserInventoryUsesExactUnpaginatedWireAndProtectedProjection()
    {
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var wire = new Wire("GET", Prefix, JsonSerializer.Serialize(new { memberships = new[] { UserRow() } }));
        var result = await Execute(request, wire, new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(result.Value.NextOffset is null).IsTrue();
        var row = result.Value.Items[0];
        await Assert.That(row.Id).IsEqualTo(Member);
        await Assert.That(row.UserId).IsEqualTo(User);
        await Assert.That(row.User.Username).IsEqualTo(Username);
        await Assert.That(row.Roles[0].Role).IsEqualTo("viewer");
        await Assert.That(JsonSerializer.Serialize(row)).IsEqualTo("""{"IncludesPermissions":false}""");
        await Assert.That(JsonSerializer.Serialize(row.User)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(row.Roles[0])).IsEqualTo("{}");
        await Assert.That(row.ToString().Contains(Member, StringComparison.Ordinal)).IsFalse();
        await Assert.That(wire.Body is null).IsTrue();
    }

    [Test]
    public async Task UserInventoryRequiresCreationTimestampWhileDetailsRemainOptional()
    {
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var row = UserRow();
        row.Remove("createdAt");
        var result = await Execute(request, new Wire("GET", Prefix,
            JsonSerializer.Serialize(new { memberships = new[] { row } })), new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        row["createdAt"] = false;
        result = await Execute(request, new Wire("GET", Prefix,
            JsonSerializer.Serialize(new { memberships = new[] { row } })), new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task PostDetailsIsInspectionWithUsernameBoundGrantAndNoReceipt()
    {
        using var request = ProjectMembershipOperations.InspectProjectMembershipByUsername(Org, Project, Username);
        var row = UserRow();
        row.Remove("createdAt");
        var wire = new Wire("POST", Prefix + "/details", JsonSerializer.Serialize(new { membership = row }));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        await Assert.That(request.IsMutation).IsFalse();
        await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.post.v1.projects.by.projectId.memberships.details", new(Org, Project, Username)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.CreatedAt is null).IsTrue();
        await Assert.That(result.Value.User.Username).IsEqualTo(Username);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
        await Assert.That(body.RootElement.GetProperty("username").GetString()).IsEqualTo(Username);
    }

    [Test]
    public async Task PatchUsesNativeRelativeRolesOwnedInputAndRolesOnlyResponse()
    {
        MembershipRole[] roles = [new("viewer"), new("admin", DateTimeOffset.Parse("2026-01-01T00:00:00Z"), "1h")];
        using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, roles);
        roles[0] = new("changed");
        var wire = new Wire("PATCH", Prefix + "/" + Member, PatchBody());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant("infisical.patch.v1.projects.by.projectId.memberships.by.membershipId",
            MembershipOperations.RoleChangeTarget(Org, Project, Member,
                [new("viewer"), new("admin", DateTimeOffset.Parse("2026-01-01T00:00:00Z"), "1h")]));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(result.Value.Items[0].Role).IsEqualTo("viewer");
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
        var first = body.RootElement.GetProperty("roles")[0];
        await Assert.That(first.GetProperty("role").GetString()).IsEqualTo("viewer");
        await Assert.That(first.GetProperty("isTemporary").GetBoolean()).IsFalse();
        var temporary = body.RootElement.GetProperty("roles")[1];
        await Assert.That(temporary.GetProperty("isTemporary").GetBoolean()).IsTrue();
        await Assert.That(temporary.GetProperty("temporaryMode").GetString()).IsEqualTo("relative");
        await Assert.That(temporary.GetProperty("temporaryRange").GetString()).IsEqualTo("1h");
        await Assert.That(temporary.GetProperty("temporaryAccessStartTime").GetDateTimeOffset())
            .IsEqualTo(DateTimeOffset.Parse("2026-01-01T00:00:00Z"));
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(0, true)]
    [Arguments(1, false)]
    public async Task AvailableIdentitiesUseNativePagingWithoutInventedCount(int count, bool complete)
    {
        using var request = ProjectMembershipOperations.ListAvailableProjectIdentities(Org, Project,
            offset: 7, limit: 1, identityName: "private+service");
        var wire = new Wire("GET", Prefix + "/available-identities?offset=7&limit=1&identityName=private%2Bservice",
            JsonSerializer.Serialize(new { identities = Enumerable.Repeat(new { id = Identity, name = "private-service" }, count) }));
        var result = await Execute(request, wire, ProjectMembershipOperations.AvailableProjectIdentityListTarget(
            Org, Project, 7, 1, "private+service"));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsEqualTo(complete);
        await Assert.That(result.Value.NextOffset).IsEqualTo(complete ? (int?)null : 8);
        if (count > 0)
        {
            await Assert.That(result.Value.Items[0].Id).IsEqualTo(Identity);
            await Assert.That(JsonSerializer.Serialize(result.Value.Items[0])).IsEqualTo("{}");
        }
    }

    [Test]
    [Arguments(null)]
    [Arguments(Project)]
    public async Task IdentityMembershipInventoryChecksOwnerAndCountedPaging(string? owner)
    {
        using var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, Project,
            limit: 1, identityName: "private+service", roles: "viewer,admin");
        var wire = new Wire("GET", Prefix + "/identities?offset=0&limit=1&identityName=private%2Bservice&roles=viewer%2Cadmin",
            IdentityBody(owner: owner, count: 2));
        var result = await Execute(request, wire, ProjectMembershipOperations.ProjectIdentityMembershipListTarget(
            Org, Project, 0, 1, "private+service", "viewer,admin"));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        var row = result.Value.Items[0];
        await Assert.That(row.IdentityId).IsEqualTo(Identity);
        await Assert.That(row.Identity.Id).IsEqualTo(Identity);
        await Assert.That(row.Identity.ProjectId).IsEqualTo(owner);
        await Assert.That(row.Roles[0].Role).IsEqualTo("viewer");
        await Assert.That(JsonSerializer.Serialize(row)).IsEqualTo("""{"IncludesPermissions":false}""");
    }

    [Test]
    [Arguments("list", "organization")]
    [Arguments("list", "project")]
    [Arguments("list", "operation")]
    [Arguments("patch", "organization")]
    [Arguments("patch", "project")]
    [Arguments("patch", "principal")]
    [Arguments("details", "organization")]
    [Arguments("details", "project")]
    [Arguments("details", "principal")]
    [Arguments("available", "organization")]
    [Arguments("available", "project")]
    [Arguments("identities", "organization")]
    [Arguments("identities", "project")]
    [Arguments("identities", "issuer")]
    public async Task IndependentGrantsRejectBeforeTokens(string route, string mismatch)
    {
        using var request = Request(route);
        var tokens = new Tokens();
        var wire = new Wire("", "", "{}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        string org = mismatch == "organization" ? OtherOrg : Org;
        string project = mismatch == "project" ? "other" : Project;
        var issuer = mismatch is "organization" or "project" or "issuer"
            ? new ManagementAuthority(client.Authority, tokens, org, project) : authority;
        string? principal = route == "patch" ? Member : route == "details" ? Username : null;
        var grant = issuer.IssueGrant(mismatch == "operation" ? "other" : request.OperationId,
            route == "patch" ? MembershipOperations.RoleChangeTarget(org, project,
                mismatch == "principal" ? OtherMember : Member, [new("viewer")]) :
                new ManagementTarget(org, project, mismatch == "principal" ? "other" : principal));
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That((SecretStatus)result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("list", "projectId", "other", SecretStatus.Invalid)]
    [Arguments("list", "userId", OtherUser, SecretStatus.Invalid)]
    [Arguments("list", "createdAt", null, SecretStatus.Unknown)]
    [Arguments("list", "roles", null, SecretStatus.Unknown)]
    [Arguments("details", "projectId", "other", SecretStatus.Invalid)]
    [Arguments("details", "username", "other", SecretStatus.Invalid)]
    [Arguments("details", "userId", OtherUser, SecretStatus.Invalid)]
    [Arguments("details", "user", null, SecretStatus.Unknown)]
    [Arguments("patch", "projectMembershipId", OtherMember, SecretStatus.Invalid)]
    [Arguments("patch", "projectMembershipId", null, SecretStatus.Unknown)]
    [Arguments("patch", "createdAt", null, SecretStatus.Unknown)]
    public async Task UserAndRoleCoordinatesFailClosed(string route, string field, string? value, SecretStatus expected)
    {
        using var request = Request(route);
        var row = route == "patch" ? RoleRow(patch: true) : UserRow();
        if (field == "username") row["user"] = new { id = User, username = value };
        else if (value is null) row.Remove(field);
        else row[field] = value;
        string response = route switch
        {
            "list" => JsonSerializer.Serialize(new { memberships = new[] { row } }),
            "details" => JsonSerializer.Serialize(new { membership = row }),
            _ => JsonSerializer.Serialize(new { roles = new[] { row } })
        };
        var result = await Execute(request, new Wire(Method(route), RoutePath(route), response), Target(route));
        await Assert.That((SecretStatus)result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments("organization", SecretStatus.Invalid)]
    [Arguments("owner", SecretStatus.Invalid)]
    [Arguments("identity", SecretStatus.Invalid)]
    [Arguments("missing-identity", SecretStatus.Unknown)]
    [Arguments("negative-count", SecretStatus.Unknown)]
    [Arguments("missing-count", SecretStatus.Unknown)]
    public async Task IdentityInventoryRejectsForeignCoordinatesAndMalformedPaging(string defect, SecretStatus expected)
    {
        using var request = ProjectMembershipOperations.ListProjectIdentityMemberships(Org, Project, limit: 1);
        var result = await Execute(request, new Wire("GET", Prefix + "/identities?offset=0&limit=1",
            IdentityBody(defect)), ProjectMembershipOperations.ProjectIdentityMembershipListTarget(Org, Project, limit: 1));
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments(0, SecretStatus.Success)]
    [Arguments(1000, SecretStatus.Success)]
    [Arguments(1001, SecretStatus.Unknown)]
    public async Task UnpaginatedInventoryNeverTruncates(int count, SecretStatus expected)
    {
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var result = await Execute(request, new Wire("GET", Prefix,
            JsonSerializer.Serialize(new { memberships = Enumerable.Repeat(UserRow(), count) })), new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(expected);
        if (expected == SecretStatus.Success) await Assert.That(result.Value.Items.Count).IsEqualTo(count);
    }

    [Test]
    [Arguments("available")]
    [Arguments("identities")]
    public async Task PagedInventoryRejectsOverfullPage(string route)
    {
        using var request = Request(route);
        string response = route == "available"
            ? JsonSerializer.Serialize(new { identities = new[] { new { id = Identity, name = "a" }, new { id = OtherIdentity, name = "b" } } })
            : IdentityBody(rows: 2, count: 2);
        var result = await Execute(request, new Wire("GET", RoutePath(route), response), Target(route));
        await Assert.That((SecretStatus)result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("list")]
    [Arguments("patch")]
    [Arguments("details")]
    [Arguments("available")]
    [Arguments("identities")]
    public async Task ResponseByteBudgetFailsClosed(string route)
    {
        using var request = Request(route);
        var result = await Execute(request, new Wire(Method(route), RoutePath(route), new string('x', 1025)),
            Target(route), responseLimit: 1024);
        await Assert.That((SecretStatus)result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("list", true)]
    [Arguments("list", false)]
    [Arguments("patch", true)]
    [Arguments("patch", false)]
    [Arguments("details", true)]
    [Arguments("details", false)]
    [Arguments("available", true)]
    [Arguments("available", false)]
    [Arguments("identities", true)]
    [Arguments("identities", false)]
    public async Task CancellationUsesExactEventBarrier(string route, bool before)
    {
        using var request = Request(route);
        var wire = new Wire(Method(route), RoutePath(route), "{}") { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        Task operation = client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, Target(route)),
            receipt, cancel.Token).AsTask();
        if (!before)
        {
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(before
            ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PatchCommittedStateAndLostResponseNeverReplay(bool drop)
    {
        var wire = new StatefulWire(drop);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var patch = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [new("admin")]);
        var receipt = client.CreateReceipt(patch);
        var grant = authority.IssueGrant(patch.OperationId,
            MembershipOperations.RoleChangeTarget(Org, Project, Member, [new("admin")]));
        var result = await client.ExecuteAsync(patch, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(drop ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(drop ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
        await Assert.That((await client.ExecuteAsync(patch, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        using var list = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var observed = await client.ExecuteAsync(list, authority, authority.IssueGrant(list.OperationId, new(Org, Project)));
        await Assert.That(observed.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(observed.Value.Items[0].Roles[0].Role).IsEqualTo("admin");
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    public async Task InputAndCollectionBudgetsRejectBeforeDispatch()
    {
        await Assert.That(() => ProjectMembershipOperations.ListProjectMemberships(Org, "..")).Throws<ArgumentException>();
        await Assert.That(() => ProjectMembershipOperations.InspectProjectMembershipByUsername(Org, Project, "")).Throws<ArgumentException>();
        await Assert.That(() => ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [])).Throws<ArgumentException>();
        await Assert.That(() => ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member,
            Enumerable.Repeat(new MembershipRole("viewer"), 101).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => ProjectMembershipOperations.ListAvailableProjectIdentities(Org, Project, limit: 101)).Throws<ArgumentException>();
        await Assert.That(() => ProjectMembershipOperations.ListProjectIdentityMemberships(Org, Project, offset: -1)).Throws<ArgumentException>();
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var row = UserRow();
        row["roles"] = Enumerable.Repeat(RoleRow(), 101);
        var result = await Execute(request, new Wire("GET", Prefix, JsonSerializer.Serialize(new { memberships = new[] { row } })),
            new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("request")]
    [Arguments("client")]
    public async Task MutationReceiptMismatchRejectsBeforeTokens(string mismatch)
    {
        using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [new("viewer")]);
        using var otherRequest = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [new("viewer")]);
        var wire = new Wire("PATCH", Prefix + "/" + Member, PatchBody());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        ManagementReceipt? receipt = mismatch switch
        {
            "missing" => null,
            "request" => client.CreateReceipt(otherRequest),
            _ => new ManagementClient(transport).CreateReceipt(request)
        };
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                MembershipOperations.RoleChangeTarget(Org, Project, Member, [new("viewer")])), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    [Test]
    public async Task OmittedOptionalMutationBooleanAndRoleFieldsRemainUnattested()
    {
        using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [new("viewer")]);
        var row = RoleRow(patch: true);
        row.Remove("isTemporary");
        var result = await Execute(request, new Wire("PATCH", Prefix + "/" + Member,
            JsonSerializer.Serialize(new { roles = new[] { row } })), new(Org, Project, Member));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items[0].IsTemporary is null).IsTrue();
        await Assert.That(result.Value.Items[0].CustomRoleId is null).IsTrue();
        await Assert.That(result.Value.Items[0].Mode is null).IsTrue();
    }

    [Test]
    public async Task AllReturnedTemporaryRoleMetadataIsProtected()
    {
        using var request = ProjectMembershipOperations.ListProjectMemberships(Org, Project);
        var row = UserRow();
        var role = RoleRow();
        role["isTemporary"] = true;
        role["customRoleId"] = "custom-id";
        role["customRoleName"] = "private-role";
        role["customRoleSlug"] = "private-slug";
        role["temporaryMode"] = "relative";
        role["temporaryRange"] = "1h";
        role["temporaryAccessStartTime"] = "2026-01-01T00:00:00Z";
        role["temporaryAccessEndTime"] = "2026-01-01T01:00:00Z";
        row["roles"] = new[] { role };
        var result = await Execute(request, new Wire("GET", Prefix,
            JsonSerializer.Serialize(new { memberships = new[] { row } })), new(Org, Project));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var returned = result.Value.Items[0].Roles[0];
        await Assert.That(returned.IsTemporary).IsTrue();
        await Assert.That(returned.CustomRoleName).IsEqualTo("private-role");
        await Assert.That(returned.CustomRoleSlug).IsEqualTo("private-slug");
        await Assert.That(returned.Range).IsEqualTo("1h");
        await Assert.That(returned.EndsAt).IsEqualTo("2026-01-01T01:00:00Z");
        await Assert.That(JsonSerializer.Serialize(returned)).IsEqualTo("{}");
    }

    [Test]
    public async Task ProjectAndMembershipCoordinatesAreEscapedOnPublicWire()
    {
        const string project = "project/with?query#fragment";
        foreach (string member in new[] { Member, "membership/with?query#fragment" })
        {
            using var request = ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, project, member, [new("viewer")]);
            var row = RoleRow(patch: true);
            row["projectMembershipId"] = member;
            var wire = new Wire("PATCH", "/api/v1/projects/" + Uri.EscapeDataString(project) +
                "/memberships/" + Uri.EscapeDataString(member), JsonSerializer.Serialize(new { roles = new[] { row } }));
            using var transport = Transport(wire);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, project);
            var receipt = client.CreateReceipt(request);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId,
                    MembershipOperations.RoleChangeTarget(Org, project, member, [new("viewer")])), receipt);
            await Assert.That(result.Status).IsEqualTo(member == Member ? SecretStatus.Success : SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(member == Member ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
            await Assert.That(wire.Observed).IsTrue();
            await Assert.That(JsonSerializer.Serialize(request.Target)).IsEqualTo("{}");
            await Assert.That(JsonSerializer.Serialize(request).Contains(project, StringComparison.Ordinal)).IsFalse();
        }
    }

    // The test matrix retains each named factory's actual closed request type.
    private static dynamic Request(string route) => route switch
    {
        "list" => ProjectMembershipOperations.ListProjectMemberships(Org, Project),
        "patch" => ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, Project, Member, [new("viewer")]),
        "details" => ProjectMembershipOperations.InspectProjectMembershipByUsername(Org, Project, Username),
        "available" => ProjectMembershipOperations.ListAvailableProjectIdentities(Org, Project, limit: 1),
        "identities" => ProjectMembershipOperations.ListProjectIdentityMemberships(Org, Project, limit: 1),
        _ => throw new ArgumentOutOfRangeException(nameof(route))
    };

    private static ManagementTarget Target(string route) => route switch
    {
        "patch" => MembershipOperations.RoleChangeTarget(Org, Project, Member, [new("viewer")]),
        "available" => ProjectMembershipOperations.AvailableProjectIdentityListTarget(Org, Project, limit: 1),
        "identities" => ProjectMembershipOperations.ProjectIdentityMembershipListTarget(Org, Project, limit: 1),
        _ => new(Org, Project, route == "details" ? Username : null)
    };
    private static string Method(string route) => route == "patch" ? "PATCH" : route == "details" ? "POST" : "GET";
    private static string RoutePath(string route) => Prefix + (route switch
    {
        "list" => "",
        "patch" => "/" + Member,
        "details" => "/details",
        "available" => "/available-identities?offset=0&limit=1",
        _ => "/identities?offset=0&limit=1"
    });

    private static Dictionary<string, object?> RoleRow(bool patch = false, string role = "viewer")
    {
        var row = new Dictionary<string, object?> { ["id"] = patch ? Role : "role-id", ["role"] = role, ["isTemporary"] = false };
        if (patch)
        {
            row["projectMembershipId"] = Member;
            row["createdAt"] = "2026-01-01T00:00:00Z";
            row["updatedAt"] = "2026-01-01T00:00:00Z";
        }
        return row;
    }

    private static Dictionary<string, object?> UserRow(string role = "viewer") => new()
    {
        ["id"] = Member,
        ["projectId"] = Project,
        ["userId"] = User,
        ["createdAt"] = "2026-01-01T00:00:00Z",
        ["user"] = new { id = User, username = Username, email = "private@example.test" },
        ["roles"] = new[] { RoleRow(role: role) }
    };

    private static string PatchBody() => JsonSerializer.Serialize(new { roles = new[] { RoleRow(patch: true) } });
    private static string IdentityBody(string? defect = null, string? owner = null, int rows = 1, int count = 1)
    {
        var row = new Dictionary<string, object?>
        {
            ["id"] = Member,
            ["identityId"] = Identity,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-01T00:00:00Z",
            ["roles"] = new[] { RoleRow() },
            ["identity"] = new
            {
                id = defect == "identity" ? OtherIdentity : Identity,
                name = "private-service",
                orgId = defect == "organization" ? OtherOrg : Org,
                projectId = defect == "owner" ? "other" : owner,
                authMethods = new[] { "token-auth" },
                activeLockoutAuthMethods = Array.Empty<string>()
            }
        };
        if (defect == "missing-identity") row.Remove("identity");
        var root = new Dictionary<string, object?>
        {
            ["identityMemberships"] = Enumerable.Repeat(row, rows),
            ["totalCount"] = defect == "negative-count" ? -1 : count
        };
        if (defect == "missing-count") root.Remove("totalCount");
        return JsonSerializer.Serialize(root);
    }

    private static async Task<SecretOutcome<T>> Execute<T>(ManagementRequest<T> request, Wire wire,
        ManagementTarget target, int responseLimit = 1024 * 1024) where T : notnull
    {
        using var transport = Transport(wire, responseLimit);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        ManagementTarget approved = request.IsMutation ? MembershipOperations.RoleChangeTarget(
            target.OrganizationId, target.ProjectId, target.ResourceId!, [new("viewer")]) : target;
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved),
            request.IsMutation ? client.CreateReceipt(request) : null);
    }

    private static ManagementTransport Transport(HttpMessageHandler wire, int responseLimit = 1024 * 1024) =>
        new(new Uri("https://management.test"), responseLimit, null, false, wire);

    private sealed class Wire(string method, string path, string response) : HttpMessageHandler
    {
        public string? Body { get; private set; }
        public bool Observed { get; private set; }
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method.Method != method || request.RequestUri!.PathAndQuery != path ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.NotFound);
            Observed = true;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-only-token"))));
        }
    }

    private sealed class StatefulWire(bool drop) : HttpMessageHandler
    {
        private string _role = "viewer";
        public int Revision { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Patch && request.RequestUri!.PathAndQuery == Prefix + "/" + Member)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                _role = body.RootElement.GetProperty("roles")[0].GetProperty("role").GetString()!;
                Revision++;
                if (drop) throw new IOException("Fixture dropped a committed response.");
                return new(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new { roles = new[] { RoleRow(true, _role) } }))
                };
            }
            if (request.Method == HttpMethod.Get && request.RequestUri!.PathAndQuery == Prefix)
                return new(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(new { memberships = new[] { UserRow(_role) } }))
                };
            return new(HttpStatusCode.NotFound);
        }
    }
}
