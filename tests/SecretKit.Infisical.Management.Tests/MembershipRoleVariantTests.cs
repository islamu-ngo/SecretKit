using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class MembershipRoleVariantTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Group = "40000000-0000-4000-8000-000000000004";
    private const string Membership = "30000000-0000-4000-8000-000000000003";
    private const string Identity = "20000000-0000-4000-8000-000000000002";

    [Test]
    [Arguments("create-identity", 0)]
    [Arguments("create-identity", 330)]
    [Arguments("add-identity", 0)]
    [Arguments("add-identity", 330)]
    [Arguments("add-group", 0)]
    [Arguments("add-group", 330)]
    [Arguments("update-identity", 0)]
    [Arguments("update-identity", 330)]
    [Arguments("update-group", 0)]
    [Arguments("update-group", 330)]
    [Arguments("add-org-group", 0)]
    [Arguments("add-org-group", 330)]
    [Arguments("update-org-group", 0)]
    [Arguments("update-org-group", 330)]
    [Arguments("update-user", 0)]
    [Arguments("update-user", 330)]
    public async Task RelativeAssignmentsWriteUtcZWithoutLosingFractionalTicks(string operation, int offsetMinutes)
    {
        var instant = new DateTimeOffset(2026, 10, 13, 12, 34, 56, TimeSpan.Zero).AddTicks(1234567);
        var start = instant.ToOffset(TimeSpan.FromMinutes(offsetMinutes));
        MembershipRole[] roles = [new("viewer", start, "1m")];
        MembershipRole[] approved = [new("viewer", instant, "1m")];
        var wire = await Run(operation, roles, approved, SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        var timestamp = body.RootElement.GetProperty("roles")[0].GetProperty("temporaryAccessStartTime");
        await Assert.That(timestamp.GetString()).IsEqualTo("2026-10-13T12:34:56.1234567Z");
        await Assert.That(timestamp.GetDateTimeOffset().UtcTicks).IsEqualTo(instant.UtcTicks);
    }

    [Test]
    [Arguments("create-identity")]
    [Arguments("add-identity")]
    [Arguments("add-group")]
    public async Task AdmittedEmptyArraysRemainExplicit(string operation)
    {
        var wire = await Run(operation, [], [], SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("roles").GetArrayLength()).IsEqualTo(0);
    }

    [Test]
    [Arguments("create-identity")]
    [Arguments("add-identity")]
    [Arguments("add-group")]
    [Arguments("update-identity")]
    [Arguments("update-group")]
    [Arguments("add-org-group")]
    [Arguments("update-org-group")]
    [Arguments("update-user")]
    public async Task ChangedRoleCannotReuseIndependentApproval(string operation)
    {
        await Run(operation, [new("admin")], [new("viewer")], SecretStatus.Denied);
    }

    [Test]
    [Arguments("create-identity")]
    [Arguments("add-identity")]
    [Arguments("add-group")]
    [Arguments("update-identity")]
    [Arguments("update-group")]
    [Arguments("add-org-group")]
    [Arguments("update-org-group")]
    [Arguments("update-user")]
    public async Task EveryEndpointPreservesPermanentAndRelativeAssignments(string operation)
    {
        MembershipRole[] roles =
        [
            new("viewer"),
            new("member", omitPermanentDiscriminator: true),
            new("admin", DateTimeOffset.UnixEpoch, "1h")
        ];
        var wire = await Run(operation, roles, roles, SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        var values = body.RootElement.GetProperty("roles");
        await Assert.That(values.GetArrayLength()).IsEqualTo(3);
        await Assert.That(values[0].GetProperty("isTemporary").GetBoolean()).IsFalse();
        await Assert.That(values[0].EnumerateObject().Count()).IsEqualTo(2);
        await Assert.That(values[1].GetProperty("role").GetString()).IsEqualTo("member");
        await Assert.That(values[1].TryGetProperty("isTemporary", out _)).IsFalse();
        await Assert.That(values[1].EnumerateObject().Count()).IsEqualTo(1);
        await Assert.That(values[2].GetProperty("role").GetString()).IsEqualTo("admin");
        await Assert.That(values[2].GetProperty("isTemporary").GetBoolean()).IsTrue();
        await Assert.That(values[2].GetProperty("temporaryMode").GetString()).IsEqualTo("relative");
        await Assert.That(values[2].GetProperty("temporaryRange").GetString()).IsEqualTo("1h");
        await Assert.That(values[2].GetProperty("temporaryAccessStartTime").GetDateTimeOffset()).IsEqualTo(DateTimeOffset.UnixEpoch);
        await Assert.That(values[2].EnumerateObject().Count()).IsEqualTo(5);
    }

    [Test]
    [Arguments("create-identity")]
    [Arguments("add-identity")]
    [Arguments("add-group")]
    [Arguments("update-identity")]
    [Arguments("update-group")]
    [Arguments("add-org-group")]
    [Arguments("update-org-group")]
    [Arguments("update-user")]
    public async Task TimingPresenceOrderAndMultiplicityAreCompleteIntent(string operation)
    {
        MembershipRole[] approved = [new("viewer", DateTimeOffset.UnixEpoch, "1h"), new("admin")];
        MembershipRole[][] changes =
        [
            [new("viewer", DateTimeOffset.UnixEpoch.AddSeconds(1), "1h"), new("admin")],
            [new("viewer", DateTimeOffset.UnixEpoch, "2h"), new("admin")],
            [new("viewer"), new("admin")],
            [new("viewer", DateTimeOffset.UnixEpoch, "1h"), new("admin", omitPermanentDiscriminator: true)],
            [new("admin"), new("viewer", DateTimeOffset.UnixEpoch, "1h")],
            [new("viewer", DateTimeOffset.UnixEpoch, "1h")]
        ];
        foreach (var change in changes) await Run(operation, change, approved, SecretStatus.Denied);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CreationPreservesScalarArrayOmissionAndCoexistingFields(bool group)
    {
        MembershipRoleSelection[] selections =
        [
            new(),
            new(role: "viewer"),
            new(roles: []),
            new(roles: [new("viewer")]),
            new(role: "viewer", roles: []),
            new(role: "viewer", roles: [new("viewer")])
        ];
        string[] expected = ["{}", """{"role":"viewer"}""", """{"roles":[]}""",
            """{"roles":[{"role":"viewer","isTemporary":false}]}""", """{"role":"viewer","roles":[]}""",
            """{"role":"viewer","roles":[{"role":"viewer","isTemporary":false}]}"""];
        for (int i = 0; i < selections.Length; i++)
        {
            var wire = await RunSelection(group, selections[i], selections[i], SecretStatus.Success);
            await Assert.That(wire.Body).IsEqualTo(expected[i]);
            var different = selections[(i + 1) % selections.Length];
            await RunSelection(group, selections[i], different, SecretStatus.Denied);
        }
    }

    [Test]
    public async Task CreationOmissionDoesNotManufactureProviderRole()
    {
        var wire = await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service"),
            "create-identity", IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service"), SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.TryGetProperty("roles", out _)).IsFalse();
        await Assert.That(body.RootElement.TryGetProperty("role", out _)).IsFalse();
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", []),
            "create-identity", IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service"), SecretStatus.Denied);
    }

    [Test]
    public async Task IdentityCreationBindsAllFieldsIncludingMetadataPresence()
    {
        var approved = IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service", [new("viewer")],
            deleteProtection: true, metadata: [new("key", "value")]);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", [new("viewer")],
            deleteProtection: true, metadata: [new("key", "value")]), "create-identity", approved, SecretStatus.Success);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "other", [new("viewer")],
            deleteProtection: true, metadata: [new("key", "value")]), "create-identity", approved, SecretStatus.Denied);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", [new("viewer")],
            metadata: [new("key", "value")]), "create-identity", approved, SecretStatus.Denied);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", [new("viewer")],
            deleteProtection: true, metadata: [new("different", "value")]), "create-identity", approved, SecretStatus.Denied);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", [new("viewer")],
            deleteProtection: true, metadata: [new("key", "different")]), "create-identity", approved, SecretStatus.Denied);
        var absent = IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service", []);
        await Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", [], metadata: []),
            "create-identity", absent, SecretStatus.Denied);
    }

    [Test]
    public async Task GroupUpdateBindsExpectedMembershipAlongsideRoleIntent()
    {
        await Execute(MembershipOperations.UpdateProjectGroupRoles(Org, "project", Group, Membership, [new("viewer")]),
            "update-group", MembershipOperations.RoleChangeTarget(Org, "project", Group, [new("viewer")], "other"),
            SecretStatus.Denied);
    }

    [Test]
    public async Task SelectionsAndRequestsOwnCopiesAndSuppressProtectedFields()
    {
        MembershipRole[] source = [new("viewer", omitPermanentDiscriminator: true)];
        var selection = new MembershipRoleSelection(roles: source);
        var approved = new MembershipRoleSelection(roles: [new("viewer", omitPermanentDiscriminator: true)]);
        source[0] = new("admin");
        var wire = await RunSelection(true, selection, approved, SecretStatus.Success);
        await Assert.That(wire.Body).IsEqualTo("""{"roles":[{"role":"viewer"}]}""");
        MembershipRole[] roles = [new("viewer")];
        IdentityAttribute[] metadata = [new("key", "value")];
        using var request = IdentityOperations.CreateProjectIdentity(Org, "project", "service", roles, metadata: metadata);
        roles[0] = new("admin");
        metadata[0] = new("other", "changed");
        var identityWire = await Execute(request, "create-identity",
            IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service", [new("viewer")],
                metadata: [new("key", "value")]), SecretStatus.Success);
        using var body = JsonDocument.Parse(identityWire.Body!);
        await Assert.That(body.RootElement.GetProperty("roles")[0].GetProperty("role").GetString()).IsEqualTo("viewer");
        await Assert.That(body.RootElement.GetProperty("metadata")[0].GetProperty("value").GetString()).IsEqualTo("value");
        await Assert.That(JsonSerializer.Serialize(selection)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(new MembershipRole("viewer"))).IsEqualTo("{}");
        await Assert.That(selection.ToString().Contains("viewer", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("update-identity")]
    [Arguments("update-group")]
    [Arguments("add-org-group")]
    [Arguments("update-org-group")]
    [Arguments("update-user")]
    public async Task RequiredNonemptyArraysRemainEndpointSpecific(string operation)
    {
        await Assert.That(() => { _ = Run(operation, [], [], SecretStatus.Success); }).Throws<ArgumentException>();
    }

    [Test]
    public async Task RoleBudgetsNullElementsAndInvalidTimingFailBeforeDispatch()
    {
        await Assert.That(() => new MembershipRoleSelection(roles: Enumerable.Repeat(new MembershipRole("viewer"), 101).ToArray()))
            .Throws<ArgumentException>();
        await Assert.That(() => new MembershipRoleSelection(roles: [null!])).Throws<ArgumentException>();
        await Assert.That(() => new MembershipRole("viewer", DateTimeOffset.UnixEpoch)).Throws<ArgumentException>();
        await Assert.That(() => new MembershipRole("viewer", relativeDuration: "1h")).Throws<ArgumentException>();
        await Assert.That(() => new MembershipRole("viewer", DateTimeOffset.UnixEpoch, "1h", true)).Throws<ArgumentException>();
        var max = Enumerable.Repeat(new MembershipRole("viewer"), 100).ToArray();
        var wire = await RunSelection(false, new(roles: max), new(roles: max), SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("roles").GetArrayLength()).IsEqualTo(100);
    }

    private static Task<Wire> RunSelection(bool group, MembershipRoleSelection roles,
        MembershipRoleSelection approved, SecretStatus expected)
    {
        string operation = group ? "add-group" : "add-identity";
        string principal = group ? Group : Identity;
        var target = MembershipOperations.RoleChangeTarget(Org, "project", principal, approved);
        return group ? Execute(MembershipOperations.AddProjectGroup(Org, "project", principal, roles), operation, target, expected) :
            Execute(MembershipOperations.AddProjectIdentity(Org, "project", principal, roles), operation, target, expected);
    }

    private static Task<Wire> Run(string operation, IReadOnlyList<MembershipRole> roles,
        IReadOnlyList<MembershipRole> approved, SecretStatus expected)
    {
        var target = ApprovedTarget(operation, approved);
        return operation switch
        {
            "create-identity" => Execute(IdentityOperations.CreateProjectIdentity(Org, "project", "service", roles), operation, target, expected),
            "add-identity" => Execute(MembershipOperations.AddProjectIdentity(Org, "project", Identity, roles), operation, target, expected),
            "add-group" => Execute(MembershipOperations.AddProjectGroup(Org, "project", Group, roles), operation, target, expected),
            "update-identity" => Execute(MembershipOperations.UpdateProjectIdentityRoles(Org, "project", Identity, roles), operation, target, expected),
            "update-group" => Execute(MembershipOperations.UpdateProjectGroupRoles(Org, "project", Group, Membership, roles), operation, target, expected),
            "add-org-group" => Execute(MembershipOperations.AddOrganizationGroup(Org, Group, roles), operation, target, expected),
            "update-org-group" => Execute(MembershipOperations.UpdateOrganizationGroupRoles(Org, Group, roles), operation, target, expected),
            "update-user" => Execute(ProjectMembershipOperations.UpdateProjectMembershipRoles(Org, "project", Membership, roles), operation, target, expected),
            _ => throw new ArgumentException("Unknown fixture operation.")
        };
    }

    private static async Task<Wire> Execute<T>(ManagementRequest<T> request, string operation,
        ManagementTarget approved, SecretStatus expected) where T : notnull
    {
        using var owned = request;
        var wire = new Wire();
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project(operation));
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(OperationId(operation), approved), receipt);
        await Assert.That(result.Status).IsEqualTo(expected);
        if (expected == SecretStatus.Denied)
        {
            await Assert.That(tokens.Acquired).IsFalse();
            await Assert.That(wire.Body is null).IsTrue();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        else await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        return wire;
    }

    private static string? Project(string operation) => operation.Contains("org", StringComparison.Ordinal) ? null : "project";

    private static string OperationId(string operation) => operation switch
    {
        "create-identity" => "infisical.post.v1.projects.by.projectId.identities",
        "add-identity" => "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId",
        "add-group" => "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId",
        "update-identity" => "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId",
        "update-group" => "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId",
        "add-org-group" => "infisical.post.v1.organizations.memberships.groups.by.groupId",
        "update-org-group" => "infisical.patch.v1.organizations.memberships.groups.by.groupId",
        "update-user" => "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId",
        _ => throw new ArgumentException("Unknown fixture operation.")
    };

    private static ManagementTarget ApprovedTarget(string operation, IReadOnlyList<MembershipRole> roles) =>
        operation == "create-identity" ? IdentityOperations.ProjectIdentityCreateTarget(Org, "project", "service", roles) :
            MembershipOperations.RoleChangeTarget(Org, Project(operation),
                operation == "update-user" ? Membership : operation.Contains("group", StringComparison.Ordinal) ? Group : Identity,
                roles, operation == "update-group" ? Membership : null);

    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);

    private sealed class Wire : HttpMessageHandler
    {
        public string? Body { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            string response = request.RequestUri!.AbsolutePath.EndsWith("/identities", StringComparison.Ordinal)
                ? $$$$$"""{"identity":{"id":"{{{{{Identity}}}}}","name":"service","orgId":"{{{{{Org}}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}}"""
                : request.RequestUri.AbsolutePath.Contains("/identities/", StringComparison.Ordinal)
                    ? $$$$$"""{"identityMembership":{"id":"{{{{{Membership}}}}}","identityId":"{{{{{Identity}}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}}"""
                    : request.Method == HttpMethod.Patch && !request.RequestUri.AbsolutePath.Contains("/organizations/", StringComparison.Ordinal)
                        ? """{"roles":[]}"""
                        : request.RequestUri.AbsolutePath.Contains("/organizations/", StringComparison.Ordinal)
                            ? $$$$$"""{"groupMembership":{"id":"{{{{{Membership}}}}}","groupId":"{{{{{Group}}}}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","roles":[],"group":{"id":"{{{{{Group}}}}}","name":"private-group","slug":"private-group","orgId":"{{{{{Org}}}}}"}}}"""
                            : $$$$$"""{"groupMembership":{"id":"{{{{{Membership}}}}}","groupId":"{{{{{Group}}}}}","projectId":"project","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","roles":[],"group":{"id":"{{{{{Group}}}}}","name":"private-group","slug":"private-group","orgId":"{{{{{Org}}}}}"}}}""";
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
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
