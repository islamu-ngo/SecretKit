using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentitySearchTests
{
    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Identity = "20000000-0000-4000-8000-000000000002";

    [Test]
    [Arguments(false, 0)]
    [Arguments(false, 1)]
    [Arguments(false, 2)]
    [Arguments(false, 3)]
    [Arguments(false, 4)]
    [Arguments(false, 5)]
    [Arguments(true, 0)]
    [Arguments(true, 1)]
    [Arguments(true, 2)]
    [Arguments(true, 3)]
    [Arguments(true, 4)]
    [Arguments(true, 5)]
    public async Task AdmittedEmptyFilterOperandsReachControlledInspection(bool count, int variant)
    {
        IdentitySearchFilter filter = variant switch
        {
            0 => new(),
            1 => new(anyOf: []),
            2 => new(anyOf: [new()]),
            3 => new(new(name: new(), role: new())),
            4 => new(new(name: new(equal: "", contains: "", anyOf: [""]),
                role: new(equal: "", contains: "", anyOf: []))),
            _ => new(anyOf: [new(name: new(equal: "", contains: "", anyOf: []),
                role: new(equal: "", contains: "", anyOf: [""]))])
        };
        string[] expected =
        [
            "{}",
            """{"$or":[]}""",
            """{"$or":[{}]}""",
            """{"name":{},"role":{}}""",
            """{"name":{"$eq":"","$contains":"","$in":[""]},"role":{"$eq":"","$contains":"","$in":[]}}""",
            """{"$or":[{"name":{"$eq":"","$contains":"","$in":[]},"role":{"$eq":"","$contains":"","$in":[""]}}]}"""
        ];
        await InspectFilter(count, filter, expected[variant]);
    }

    private static async Task InspectFilter(bool count, IdentitySearchFilter filter, string expected)
    {
        var wire = new Wire(count, count ? """{"counts":{"organization":0}}""" :
            """{"identities":[],"totalCount":0}""");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        if (count)
        {
            using var request = IdentitySearchOperations.CountIdentities(Org, IdentitySearchScope.Organization, filter);
            await Assert.That(request.IsMutation).IsFalse();
            await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId,
                    IdentitySearchOperations.IdentityCountTarget(Org, IdentitySearchScope.Organization, filter)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Organization).IsEqualTo(0);
        }
        else
        {
            using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization, filter);
            await Assert.That(request.IsMutation).IsFalse();
            await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId,
                    IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization, filter)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Value.Items.Count).IsEqualTo(0);
        }
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("search").GetRawText()).IsEqualTo(expected);
        await Assert.That(body.RootElement.GetProperty("scope")[0].GetString()).IsEqualTo("organization");
        await Assert.That(JsonSerializer.Serialize(filter)).IsEqualTo("{}");
    }

    [Test]
    [Arguments(false, "")]
    [Arguments(true, "")]
    [Arguments(false, "private-name")]
    [Arguments(true, "private-name")]
    public async Task ShorthandPreservesScalarDialectInEveryAdmittedPosition(bool count, string value)
    {
        var text = IdentitySearchText.Shorthand(value);
        var filter = new IdentitySearchFilter(new(name: text, role: text), [new(name: text, role: text)]);
        string scalar = JsonSerializer.Serialize(value);
        await InspectFilter(count, filter,
            $$$$$"""{"name":{{{{{scalar}}}}},"role":{{{{{scalar}}}}},"$or":[{"name":{{{{{scalar}}}}},"role":{{{{{scalar}}}}}}]}""");
        await Assert.That(text.ShorthandValue).IsEqualTo(value);
        await Assert.That(text.Equal).IsNull();
        await Assert.That(JsonSerializer.Serialize(text)).IsEqualTo("{}");
        await Assert.That(text.ToString()).IsEqualTo("[IdentitySearchText]");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EmptyInclusionItemsAndLogicalClausesAreEagerlyCopied(bool count)
    {
        string[] values = [""];
        var text = new IdentitySearchText(anyOf: values);
        values[0] = "changed-before-request";
        IdentitySearchClause[] clauses = [new(name: text)];
        var filter = new IdentitySearchFilter(anyOf: clauses);
        clauses[0] = new(role: new(equal: "changed-before-request"));
        await InspectFilter(count, filter, """{"$or":[{"name":{"$in":[""]}}]}""");
        await Assert.That(() => ((IList<string>)text.AnyOf!)[0] = "changed").Throws<NotSupportedException>();
        await Assert.That(() => ((IList<IdentitySearchClause>)filter.AnyOf!)[0] = new()).Throws<NotSupportedException>();
    }

    [Test]
    public async Task BroadenedOperandsRetainNullTextAndLocalBudgets()
    {
        await Assert.That(() => IdentitySearchText.Shorthand(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => IdentitySearchText.Shorthand(new string('a', 256))).Throws<ArgumentException>();
        await Assert.That(() => new IdentitySearchText(equal: new string('a', 256))).Throws<ArgumentException>();
        await Assert.That(() => new IdentitySearchText(contains: new string('a', 256))).Throws<ArgumentException>();
        await Assert.That(() => new IdentitySearchText(anyOf: [null!])).Throws<ArgumentNullException>();
        await Assert.That(() => new IdentitySearchText(anyOf: [new string('a', 256)])).Throws<ArgumentException>();
        await Assert.That(() => new IdentitySearchFilter(anyOf: [null!])).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(IdentitySearchScope.Organization)]
    [Arguments(IdentitySearchScope.Projects)]
    [Arguments(IdentitySearchScope.Organization | IdentitySearchScope.Projects)]
    public async Task SearchUsesNativeBodyCopiedFiltersAndProtectedCountedProjection(IdentitySearchScope scope)
    {
        string[] names = ["private-name"];
        var filter = new IdentitySearchFilter(new(name: new(anyOf: names)),
            [new(role: new(contains: "viewer"))]);
        names[0] = "changed";
        using var request = IdentitySearchOperations.SearchIdentities(Org, scope, filter, limit: 1,
            order: IdentitySearchOrder.LastLogin, direction: ManagementListOrder.Descending);
        var wire = new Wire(false, SearchBody(scope));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, IdentitySearchOperations.IdentitySearchTarget(Org, scope,
                filter, limit: 1, order: IdentitySearchOrder.LastLogin, direction: ManagementListOrder.Descending)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(request.IsMutation).IsFalse();
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(1);
        await Assert.That(result.Value.Items[0].Identity.Id).IsEqualTo(Identity);
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0]).Contains("private-name", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(filter)).IsEqualTo("{}");
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.GetProperty("search").GetProperty("name").GetProperty("$in")[0].GetString())
            .IsEqualTo("private-name");
        await Assert.That(body.RootElement.GetProperty("orderBy").GetString()).IsEqualTo("lastLogin");
        await Assert.That(body.RootElement.GetProperty("orderDirection").GetString()).IsEqualTo("desc");
        await Assert.That(body.RootElement.GetProperty("scope").GetArrayLength())
            .IsEqualTo(scope == (IdentitySearchScope.Organization | IdentitySearchScope.Projects) ? 2 : 1);
    }

    [Test]
    [Arguments(IdentitySearchScope.Organization)]
    [Arguments(IdentitySearchScope.Projects)]
    [Arguments(IdentitySearchScope.Organization | IdentitySearchScope.Projects)]
    public async Task CountIsNativePostInspectionAndDoesNotInventMissingScope(IdentitySearchScope scope)
    {
        using var request = IdentitySearchOperations.CountIdentities(Org, scope);
        var counts = new Dictionary<string, int>();
        if ((scope & IdentitySearchScope.Organization) != 0) counts["organization"] = 2;
        if ((scope & IdentitySearchScope.Projects) != 0) counts["project"] = 3;
        var wire = new Wire(true, JsonSerializer.Serialize(new { counts }));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentitySearchOperations.IdentityCountTarget(Org, scope)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Organization).IsEqualTo(counts.ContainsKey("organization") ? (int?)2 : null);
        await Assert.That(result.Value.Projects).IsEqualTo(counts.ContainsKey("project") ? (int?)3 : null);
        await Assert.That(JsonSerializer.Serialize(result.Value)).IsEqualTo("{}");
        await Assert.That(() => client.CreateReceipt(request)).Throws<ArgumentException>();
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
    }

    [Test]
    [Arguments("organization")]
    [Arguments("identity")]
    [Arguments("scope")]
    [Arguments("project")]
    public async Task ReturnedCoordinatesFailClosed(string defect)
    {
        var row = Row(IdentitySearchScope.Organization);
        if (defect == "organization") row["orgId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "identity") row["identityId"] = "90000000-0000-4000-8000-000000000009";
        if (defect == "scope") { row["scope"] = "project"; row["projectId"] = "project"; }
        if (defect == "project") row["projectId"] = "project";
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization);
        var wire = new Wire(false, JsonSerializer.Serialize(new { identities = new[] { row }, totalCount = 1 }));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("""{"counts":{}}""")]
    [Arguments("""{"counts":{"organization":-1}}""")]
    public async Task CountRequiresNonnegativeRequestedNativeField(string response)
    {
        using var request = IdentitySearchOperations.CountIdentities(Org, IdentitySearchScope.Organization);
        var wire = new Wire(true, response);
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentityCountTarget(Org, IdentitySearchScope.Organization)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    public async Task WiderScopeGrantMismatchRejectsBeforeCredentials()
    {
        using var request = IdentitySearchOperations.SearchIdentities(Org,
            IdentitySearchScope.Organization | IdentitySearchScope.Projects);
        var tokens = new Tokens();
        using var transport = Transport(new Wire(false, "{}"));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task SearchCancellationPropagatesAtExactTransportBarrier()
    {
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization);
        var wire = new Wire(false, "{}") { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var cancel = new CancellationTokenSource();
        var pending = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId,
                IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization)),
            cancellationToken: cancel.Token).AsTask();
        await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
    }

    [Test]
    public async Task NativeFilterAndPageBudgetsAreEnforced()
    {
        await Assert.That(() => new IdentitySearchText(anyOf: Enumerable.Repeat("name", 101).ToArray()))
            .Throws<ArgumentException>();
        await Assert.That(() => new IdentitySearchFilter(anyOf: Enumerable.Repeat(new IdentitySearchClause(), 6).ToArray()))
            .Throws<ArgumentException>();
        await Assert.That(() => IdentitySearchOperations.SearchIdentities(Org, 0)).Throws<ArgumentException>();
        await Assert.That(() => IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization, limit: 101))
            .Throws<ArgumentException>();
    }

    private static Dictionary<string, object?> Row(IdentitySearchScope scope) => new()
    {
        ["id"] = "membership",
        ["identityId"] = Identity,
        ["orgId"] = Org,
        ["scope"] = scope == IdentitySearchScope.Projects ? "project" : "organization",
        ["projectId"] = scope == IdentitySearchScope.Projects ? "project" : null,
        ["createdAt"] = "2026-01-01T00:00:00Z",
        ["updatedAt"] = "2026-01-01T00:00:00Z",
        ["roles"] = new[] { new { id = "role", role = "viewer", isTemporary = false } },
        ["identity"] = new
        {
            id = Identity,
            orgId = Org,
            name = "private-name",
            authMethods = Array.Empty<string>(),
            activeLockoutAuthMethods = Array.Empty<string>()
        }
    };

    [Test]
    [Arguments("2026-01-01")]
    [Arguments("2026-01-01T03:04:05")]
    [Arguments("2026-02-30T03:04:05Z")]
    public async Task LastLoginDateRejectsDateOnlyMissingZoneAndInvalidCalendar(string invalid)
    {
        // Given valid selected UUIDs and one defective optional login date.
        var row = Row(IdentitySearchScope.Organization);
        row["lastLoginTime"] = invalid;
        // When the native public search adapter dispatches.
        var result = await ExecuteLoginRow(row);
        // Then the string cannot become verified login metadata.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("2026-01-01T03:04:05Z")]
    [Arguments("2026-01-01T03:04:05.1234567+02:30")]
    [Arguments("2026-01-01T03:04:05-04:00")]
    public async Task LastLoginDatePreservesPresenceAndOriginalSignedOffsetText(string shape)
    {
        // Given absent, null, or explicitly zoned native login metadata.
        var row = Row(IdentitySearchScope.Organization);
        if (shape != "absent") row["lastLoginTime"] = shape == "null" ? null : shape;
        // When the public search completes and its transport is disposed.
        var result = await ExecuteLoginRow(row);
        // Then presence and copied original text retain endpoint meaning.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var date = result.Value.Items.Single().LastLoginTime;
        await Assert.That(date.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(date.IsNull).IsEqualTo(shape == "null");
        if (shape is not ("absent" or "null")) await Assert.That(date.Value).IsEqualTo(shape);
    }

    private static async Task<SecretOutcome<ManagementPage<IdentitySearchSummary>>> ExecuteLoginRow(
        Dictionary<string, object?> row)
    {
        using var request = IdentitySearchOperations.SearchIdentities(Org, IdentitySearchScope.Organization);
        var wire = new Wire(false, JsonSerializer.Serialize(new { identities = new[] { row }, totalCount = 1 }));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            IdentitySearchOperations.IdentitySearchTarget(Org, IdentitySearchScope.Organization)));
    }

    private static string SearchBody(IdentitySearchScope scope) =>
        JsonSerializer.Serialize(new { identities = new[] { Row(scope) }, totalCount = 2 });
    private static ManagementTransport Transport(HttpMessageHandler wire) => new(new Uri("https://management.test"),
        1024 * 1024, null, false, wire);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("test-only-token"))));
        }
    }

    private sealed class Wire(bool count, string response) : HttpMessageHandler
    {
        public string? Body { get; private set; }
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Post ||
                request.RequestUri!.PathAndQuery != "/api/v2/identities/search" + (count ? "/count" : ""))
                return new(HttpStatusCode.NotFound);
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response) };
        }
    }
}
