using System.Net;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AdministrationAuditWitnessTests
{
    private const string ProjectId = "66666666-6666-4666-8666-666666666666";

    [Test]
    [Arguments("valid")]
    [Arguments("missing-id")]
    [Arguments("id-type")]
    [Arguments("missing-slug")]
    [Arguments("slug-type")]
    [Arguments("foreign-membership")]
    public async Task LegacyInventoryRejectsMalformedKnownLeavesAndForeignMembership(string defect)
    {
        var row = JsonNode.Parse("""
            {"id":"11111111-1111-4111-8111-111111111111","slug":"private-slug","projectMembershipId":"22222222-2222-4222-8222-222222222222",
             "permissions":[],"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z"}
            """)!.AsObject();
        if (defect.StartsWith("missing-", StringComparison.Ordinal)) row.Remove(defect[8..]);
        if (defect.EndsWith("-type", StringComparison.Ordinal)) row[defect[..^5]] = 42;
        if (defect == "foreign-membership") row["projectMembershipId"] = "33333333-3333-4333-8333-333333333333";
        var wire = new Wire(new JsonObject { ["privileges"] = new JsonArray(row) }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var selection = new LegacyPrivilegeSelection("org", "project", "project-slug", "identity", "22222222-2222-4222-8222-222222222222");
        using var request = LegacyIdentityPrivilegeOperations.ListPrivileges(selection);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org", "project");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.get.v1.additional.privilege.identity", selection.GrantTarget()));
        await Assert.That(wire.Path).IsEqualTo("/api/v1/additional-privilege/identity");
        await Assert.That(result.Status).IsEqualTo(defect == "valid" ? SecretStatus.Success :
            defect == "foreign-membership" ? SecretStatus.Invalid : SecretStatus.Unknown);
        if (result.IsSuccess) await Assert.That(result.Value.Items.Single().Slug).IsEqualTo("private-slug");
    }

    [Test]
    [Arguments("valid")]
    [Arguments("missing-id")]
    [Arguments("id-type")]
    [Arguments("missing-name")]
    [Arguments("name-type")]
    public async Task AvailableOrganizationIdentitiesRejectMalformedRequiredLeaves(string defect)
    {
        const string identityId = "11111111-1111-4111-8111-111111111111";
        var row = new JsonObject { ["id"] = identityId, ["name"] = "private-name" };
        if (defect.StartsWith("missing-", StringComparison.Ordinal)) row.Remove(defect[8..]);
        if (defect.EndsWith("-type", StringComparison.Ordinal)) row[defect[..^5]] = 42;
        var wire = new Wire(new JsonObject { ["identities"] = new JsonArray(row) }.ToJsonString());
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        using var request = ScopedAccessOperations.AvailableIdentities("org");
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(
            "infisical.get.v1.organization.available.identities", ScopedAccessOperations.AvailableIdentityListTarget("org")));
        await Assert.That(wire.Path).IsEqualTo("/api/v1/organization/available-identities");
        await Assert.That(result.Status).IsEqualTo(defect == "valid" ? SecretStatus.Success : SecretStatus.Unknown);
        if (result.IsSuccess) await Assert.That(result.Value.Items.Single().Id).IsEqualTo(identityId);
    }

    [Test]
    [Arguments(false, "equal")]
    [Arguments(false, "class")]
    [Arguments(false, "order")]
    [Arguments(false, "value")]
    [Arguments(false, "length")]
    [Arguments(true, "equal")]
    [Arguments(true, "class")]
    [Arguments(true, "order")]
    [Arguments(true, "value")]
    [Arguments(true, "length")]
    public async Task AuditSettingClassesOrderAndCardinalityHaveIndependentApproval(bool projectScope, string change)
    {
        AuditClassSetting[] trusted = [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)];
        AuditClassSetting[] incoming = change switch
        {
            "class" => [new(AuditEventClass.Management, true), trusted[1]],
            "order" => [trusted[1], trusted[0]],
            "value" => [new(AuditEventClass.Authentication, false), trusted[1]],
            "length" => [trusted[0]],
            _ => trusted.ToArray()
        };
        var wire = new Wire("""
            {"auditLogSettings":{"eventClasses":[],"shouldUseNewPrivilegeSystem":false}}
            """);
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        string? project = projectScope ? ProjectId : null;
        var authority = new ManagementAuthority(client.Authority, tokens, "org", project);
        if (change is "class" or "length")
        {
            await Assert.That(() => GovernanceOperations.AuditSettingsTarget("org", incoming, project))
                .Throws<ArgumentException>();
            await Assert.That(() =>
            {
                using var rejected = projectScope ? GovernanceOperations.SetProjectAuditSettings("org", ProjectId, incoming) :
                    GovernanceOperations.SetOrganizationAuditSettings("org", incoming);
            }).Throws<ArgumentException>();
            await Assert.That(tokens.Acquired).IsFalse();
            await Assert.That(wire.Dispatched).IsFalse();
            return;
        }
        var target = GovernanceOperations.AuditSettingsTarget("org", trusted, project);
        using var request = projectScope ? GovernanceOperations.SetProjectAuditSettings("org", ProjectId, incoming) :
            GovernanceOperations.SetOrganizationAuditSettings("org", incoming);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        bool equal = change == "equal";
        await Assert.That(result.Status).IsEqualTo(equal ? SecretStatus.Success : SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsEqualTo(equal);
        await Assert.That(wire.Dispatched).IsEqualTo(equal);
        await Assert.That(receipt.Evidence).IsEqualTo(equal ? DispatchEvidence.Applied : DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ShareListLimitIsIndependentlyApproved(bool changed)
    {
        var wire = new Wire("""{"secrets":[],"totalCount":0}""");
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = SharingOperations.ListShares("org", 0, changed ? 3 : 2);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, SharingOperations.ListSharesTarget("org", 0, 2)));
        await Assert.That(result.Status).IsEqualTo(changed ? SecretStatus.Denied : SecretStatus.Success);
        await Assert.That(tokens.Acquired).IsEqualTo(!changed);
        await Assert.That(wire.Dispatched).IsEqualTo(!changed);
    }

    [Test]
    [Arguments(null, "")]
    [Arguments("", null)]
    [Arguments(null, "private-password")]
    [Arguments("private-password", null)]
    [Arguments("", "private-password")]
    [Arguments("private-password", "")]
    public async Task ShareProofOmissionEmptyAndValueCannotBorrowApproval(string? selected, string? incoming)
    {
        using var trusted = selected is null ? null : SecretMaterial.FromText(selected);
        using var supplied = incoming is null ? null : SecretMaterial.FromText(incoming);
        var wire = new Wire("{}");
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        using var request = SharingOperations.AccessShare("org", "share", supplied);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            SharingOperations.AccessShareTarget("org", "share", trusted)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task GroupSlugOmissionCannotBorrowExplicitSameCoordinateApproval(bool selectedExplicit)
    {
        var wire = new Wire("{}");
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        const string name = "same-coordinate";
        var approved = ScopedAccessOperations.GroupCreationTarget("org", name, selectedExplicit ? name : null);
        using var request = ScopedAccessOperations.CreateGroup("org", name, selectedExplicit ? null : name);
        await Assert.That(request.Target.ResourceId).IsEqualTo(approved.ResourceId);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("available-name", false)]
    [Arguments("available-name", true)]
    [Arguments("members-name", false)]
    [Arguments("members-name", true)]
    [Arguments("members-roles", false)]
    [Arguments("members-roles", true)]
    public async Task ProjectMemberEmptySelectorsCannotBorrowOmittedSelectorApproval(string choice, bool selectedEmpty)
    {
        var wire = new Wire("{}");
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org", "project");
        string? selected = selectedEmpty ? "" : null;
        string? incoming = selectedEmpty ? null : "";
        if (choice == "available-name")
            await Denied(ProjectMembershipOperations.ListAvailableProjectIdentities("org", "project", identityName: incoming),
                ProjectMembershipOperations.AvailableProjectIdentityListTarget("org", "project", identityName: selected));
        else
            await Denied(ProjectMembershipOperations.ListProjectIdentityMemberships("org", "project",
                    identityName: choice == "members-name" ? incoming : null, roles: choice == "members-roles" ? incoming : null),
                ProjectMembershipOperations.ProjectIdentityMembershipListTarget("org", "project",
                    identityName: choice == "members-name" ? selected : null, roles: choice == "members-roles" ? selected : null));
        async Task Denied<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            using (request)
            {
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
                await Assert.That(tokens.Acquired).IsFalse();
                await Assert.That(wire.Dispatched).IsFalse();
            }
        }
    }

    [Test]
    [Arguments("identities", "offset")]
    [Arguments("identities", "limit")]
    [Arguments("users", "offset")]
    [Arguments("users", "limit")]
    [Arguments("available", "offset")]
    [Arguments("available", "limit")]
    [Arguments("members", "offset")]
    [Arguments("members", "limit")]
    [Arguments("members", "search-absent-empty")]
    [Arguments("members", "search-absent-value")]
    [Arguments("members", "search-empty-value")]
    [Arguments("members", "direction")]
    [Arguments("members", "types-order")]
    [Arguments("members", "types-value")]
    [Arguments("members", "types-length")]
    public async Task GroupInventoryChoicesCannotBorrowIndependentSelectorApproval(string route, string change)
    {
        var wire = new Wire("{}");
        var tokens = new Tokens();
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        int offset = change == "offset" ? 1 : 0;
        int limit = change == "limit" ? 2 : 1;
        if (route == "identities")
            await Denied(ScopedAccessOperations.ListGroupIdentities("org", "group", offset, limit),
                ScopedAccessOperations.GroupIdentityListTarget("org", "group", limit: 1));
        else if (route == "users")
            await Denied(ScopedAccessOperations.ListGroupUsers("org", "group", offset, limit),
                ScopedAccessOperations.GroupUserListTarget("org", "group", limit: 1));
        else if (route == "available")
            await Denied(ScopedAccessOperations.AvailableIdentities("org", offset, limit),
                ScopedAccessOperations.AvailableIdentityListTarget("org", limit: 1));
        else
        {
            string? approvedSearch = change == "search-empty-value" ? "" : null;
            string? incomingSearch = change == "search-absent-empty" ? "" :
                change.StartsWith("search-", StringComparison.Ordinal) ? "private-search" : null;
            GroupMemberFilter[]? approvedTypes = change == "types-order" ? [GroupMemberFilter.Users, GroupMemberFilter.MachineIdentities] :
                change.StartsWith("types-", StringComparison.Ordinal) ? [GroupMemberFilter.Users] : null;
            GroupMemberFilter[]? incomingTypes = change switch
            {
                "types-order" => [GroupMemberFilter.MachineIdentities, GroupMemberFilter.Users],
                "types-value" => [GroupMemberFilter.MachineIdentities],
                "types-length" => [GroupMemberFilter.Users, GroupMemberFilter.MachineIdentities],
                _ => null
            };
            await Denied(ScopedAccessOperations.ListGroupMembers("org", "group", offset, limit, incomingSearch,
                    change == "direction" ? ManagementListOrder.Descending : ManagementListOrder.Ascending, memberTypes: incomingTypes),
                ScopedAccessOperations.GroupMemberListTarget("org", "group", limit: 1, search: approvedSearch, memberTypes: approvedTypes));
        }
        async Task Denied<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            using (request)
            {
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
                await Assert.That(tokens.Acquired).IsFalse();
                await Assert.That(wire.Dispatched).IsFalse();
            }
        }
    }

    private static ManagementTransport Transport(Wire wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
    private sealed class Wire(string response) : HttpMessageHandler
    {
        public bool Dispatched { get; private set; }
        public string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Dispatched = true;
            Path = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) });
        }
    }
}
