using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GroupSelectorVariantTests
{
    [Test]
    public async Task MixedMemberSelectionCannotUseCoordinateOnlyGrant()
    {
        using var request = ScopedAccessOperations.ListGroupMembers("org", "group", search: "private",
            members: GroupMemberFilter.Users);
        await Reject(request, 3, new("org", resourceId: "group"));
    }

    [Test]
    [Arguments("omitted")]
    [Arguments("empty")]
    [Arguments("one")]
    [Arguments("both")]
    [Arguments("scalar")]
    public async Task MixedMemberArraysAreCopiedAndPreserveTheirSelectionKind(string shape)
    {
        GroupMemberFilter[]? source = shape switch
        {
            "empty" => [],
            "one" => [GroupMemberFilter.Users],
            "both" => [GroupMemberFilter.Users, GroupMemberFilter.MachineIdentities],
            _ => null
        };
        var approved = source?.ToArray();
        var scalar = shape == "scalar" ? GroupMemberFilter.Users : GroupMemberFilter.All;
        using var request = ScopedAccessOperations.ListGroupMembers("org", "group", search: "",
            members: scalar, memberTypes: source);
        if (source is { Length: > 0 }) source[0] = GroupMemberFilter.All;
        string query = "?offset=0&limit=100&orderBy=name&orderDirection=asc&search=";
        if (shape is "one" or "both" or "scalar") query += "&memberTypeFilter=users";
        if (shape == "both") query += "&memberTypeFilter=machineIdentities";
        await Accept(request, ScopedAccessOperations.GroupMemberListTarget("org", "group", search: "",
            members: scalar, memberTypes: approved), 3, query);
        if (shape == "one")
            await Reject(request, 3, ScopedAccessOperations.GroupMemberListTarget("org", "group",
                search: "", members: GroupMemberFilter.Users));
        if (shape == "empty")
            await Reject(request, 3, ScopedAccessOperations.GroupMemberListTarget("org", "group", search: ""));
    }

    [Test]
    public async Task MixedMemberArraysRejectUnsupportedItemsAndConflictingSelectors()
    {
        await Assert.That(() => ScopedAccessOperations.ListGroupMembers("org", "group",
            memberTypes: [GroupMemberFilter.All])).Throws<ArgumentException>();
        await Assert.That(() => ScopedAccessOperations.ListGroupMembers("org", "group",
            memberTypes: [(GroupMemberFilter)99])).Throws<ArgumentException>();
        await Assert.That(() => ScopedAccessOperations.ListGroupMembers("org", "group",
            members: GroupMemberFilter.Users, memberTypes: [])).Throws<ArgumentException>();
        await Assert.That(() => ScopedAccessOperations.ListGroupMembers("org", "group",
            memberTypes: Enumerable.Repeat(GroupMemberFilter.Users, 101).ToArray())).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task InventoryGrantBindsItsWholeSelectionBeforeAcquiringTokens(int route)
    {
        if (route == 0)
        {
            using var request = ScopedAccessOperations.ListGroupIdentities("org", "group", offset: 1);
            await Reject(request, route);
        }
        else if (route == 1)
        {
            using var request = ScopedAccessOperations.ListGroupUsers("org", "group", offset: 1);
            await Reject(request, route);
        }
        else
        {
            using var request = ScopedAccessOperations.AvailableIdentities("org", offset: 1);
            await Reject(request, route);
        }
    }

    private static async Task Reject<T>(ManagementRequest<T> request, int route, ManagementTarget? approved = null) where T : notnull
    {
        var tokens = new Tokens();
        var wire = new Wire(route, null);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        var target = approved ?? new ManagementTarget("org", resourceId: route < 2 ? "group" : null);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
    }

    [Test]
    [Arguments(0, "filter")]
    [Arguments(0, "search")]
    [Arguments(1, "filter")]
    [Arguments(1, "search")]
    [Arguments(1, "username")]
    [Arguments(2, "identityName")]
    public async Task AnotherSelectorCannotBorrowTheApprovedInventoryGrant(int route, string changed)
    {
        if (route == 0)
        {
            using var request = ScopedAccessOperations.ListGroupIdentities("org", "group",
                filter: changed == "filter" ? GroupIdentityFilter.Unassigned : GroupIdentityFilter.Assigned,
                search: changed == "search" ? "other" : "approved");
            await Reject(request, route, ScopedAccessOperations.GroupIdentityListTarget("org", "group",
                filter: GroupIdentityFilter.Assigned, search: "approved"));
        }
        else if (route == 1)
        {
            using var request = ScopedAccessOperations.ListGroupUsers("org", "group",
                filter: changed == "filter" ? GroupUserFilter.NonMembers : GroupUserFilter.Members,
                search: changed == "search" ? "other" : "approved",
                username: changed == "username" ? "other" : "approved");
            await Reject(request, route, ScopedAccessOperations.GroupUserListTarget("org", "group",
                filter: GroupUserFilter.Members, search: "approved", username: "approved"));
        }
        else
        {
            using var request = ScopedAccessOperations.AvailableIdentities("org", identityName: "other");
            await Reject(request, route, ScopedAccessOperations.AvailableIdentityListTarget("org", identityName: "approved"));
        }
    }

    [Test]
    [Arguments(0, 0)]
    [Arguments(0, 1)]
    [Arguments(0, 2)]
    [Arguments(0, 3)]
    [Arguments(1, 0)]
    [Arguments(1, 1)]
    [Arguments(1, 2)]
    [Arguments(1, 3)]
    [Arguments(2, 0)]
    [Arguments(2, 1)]
    [Arguments(2, 3)]
    public async Task NativeSelectorsPreserveOmissionEmptyAndEscapedValues(int route, int variant)
    {
        string? search = variant == 0 ? null : variant == 3 ? "" : "private+service & name";
        string query = "?offset=0&limit=1";
        if (route == 0)
        {
            GroupIdentityFilter? filter = variant == 1 ? GroupIdentityFilter.Assigned :
                variant == 2 ? GroupIdentityFilter.Unassigned : null;
            if (filter is not null)
                query += "&filter=" + (variant == 1 ? "assignedMachineIdentities" : "nonAssignedMachineIdentities");
            if (search is not null) query += "&search=" + Uri.EscapeDataString(search);
            using var request = ScopedAccessOperations.ListGroupIdentities("org", "group", limit: 1, filter: filter, search: search);
            await Accept(request, ScopedAccessOperations.GroupIdentityListTarget("org", "group", limit: 1, filter: filter, search: search), route, query);
        }
        else if (route == 1)
        {
            GroupUserFilter? filter = variant == 1 ? GroupUserFilter.Members :
                variant == 2 ? GroupUserFilter.NonMembers : null;
            if (filter is not null) query += "&filter=" + (variant == 1 ? "existingMembers" : "nonMembers");
            if (search is not null) query += "&search=" + Uri.EscapeDataString(search) + "&username=" + Uri.EscapeDataString(search);
            using var request = ScopedAccessOperations.ListGroupUsers("org", "group", limit: 1, filter: filter, search: search, username: search);
            await Accept(request, ScopedAccessOperations.GroupUserListTarget("org", "group", limit: 1, filter: filter, search: search, username: search), route, query);
        }
        else
        {
            if (search is not null) query += "&identityName=" + Uri.EscapeDataString(search);
            using var request = ScopedAccessOperations.AvailableIdentities("org", limit: 1, identityName: search);
            await Accept(request, ScopedAccessOperations.AvailableIdentityListTarget("org", limit: 1, identityName: search), route, query);
        }
    }

    private static async Task Accept<T>(ManagementRequest<T> request, ManagementTarget target, int route, string query) where T : notnull
    {
        var wire = new Wire(route, query);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Sent).IsTrue();
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

    private sealed class Wire(int route, string? expectedQuery) : HttpMessageHandler
    {
        public bool Sent { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            string response = route switch
            {
                0 => """{"machineIdentities":[],"totalCount":0}""",
                1 => """{"users":[],"totalCount":0}""",
                3 => """{"members":[],"totalCount":0}""",
                _ => """{"identities":[]}"""
            };
            return Task.FromResult(new HttpResponseMessage(expectedQuery is null ||
                request.RequestUri!.Query == expectedQuery ? HttpStatusCode.OK : HttpStatusCode.NotFound)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            });
        }
    }
}
