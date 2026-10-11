using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class LegacyPrivilegeTests
{
    private const string Membership = "4dc64d95-bc40-4d5f-86a2-e5b7459cd018";
    private const string Privilege = "cf96114b-6b85-48f8-b25a-9f456747d74f";
    private const string ForeignMembership = "70bc9c42-31b3-4a13-ac45-dc937db4eb63";

    private static LegacyPrivilegeSelection Selection(string slug = "native-project") =>
        new("org", "project-id", slug, "identity", Membership);
    private static string Row(string membership = Membership, string slug = "private-privilege") =>
        JsonSerializer.Serialize(new
        {
            id = Privilege,
            slug,
            projectMembershipId = membership,
            permissions = Array.Empty<object>(),
            createdAt = "2026-01-01T00:00:00Z",
            updatedAt = "2026-01-01T00:00:00Z"
        });

    [Test]
    public async Task InventoryChecksKnownMembershipWithoutProjectIdSlugInference()
    {
        var selection = Selection();
        using var request = LegacyIdentityPrivilegeOperations.ListPrivileges(selection);
        var wire = new Wire("list", "{\"privileges\":[" + Row() + "]}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, selection.GrantTarget()));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items[0].Id).IsEqualTo(Privilege);
        await Assert.That(result.Value.IsComplete).IsTrue();
        await Assert.That(JsonSerializer.Serialize(selection)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(result.Value.Items[0]).Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NativeSlugInspectionAndDeletionKeepProtectedSelectedResponse(bool delete)
    {
        var selection = Selection();
        using var request = Request(selection, delete);
        var wire = new Wire(delete ? "delete" : "get", "{\"privilege\":" + Row() + "}");
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = delete ? client.CreateReceipt(request) : null;
        var grant = authority.IssueGrant(request.OperationId, selection.GrantTarget("private-privilege"));
        var result = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Slug).IsEqualTo("private-privilege");
        if (delete)
        {
            await Assert.That(receipt!.Evidence).IsEqualTo(DispatchEvidence.Applied);
            using var body = JsonDocument.Parse(wire.Body!);
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(3);
            await Assert.That(body.RootElement.GetProperty("projectSlug").GetString()).IsEqualTo("native-project");
            await Assert.That(body.RootElement.GetProperty("identityId").GetString()).IsEqualTo("identity");
        }
        else await Assert.That(request.IsMutation).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ForeignMembershipResponseNeverBecomesApplied(bool delete)
    {
        var selection = Selection();
        using var request = Request(selection, delete);
        using var transport = Transport(new Wire(delete ? "delete" : "get", "{\"privilege\":" + Row(ForeignMembership) + "}"));
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = delete ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, selection.GrantTarget("private-privilege")), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        if (delete) await Assert.That(receipt!.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task NativeSlugMustMatchIndependentGrantBeforeTokens()
    {
        using var request = LegacyIdentityPrivilegeOperations.ListPrivileges(Selection());
        var tokens = new Tokens();
        using var transport = Transport(new Wire("list", "{}"));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org", "project-id");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, Selection("other-slug").GrantTarget()));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task ForeignReturnedPrivilegeSlugFailsClosed()
    {
        var selection = Selection();
        using var request = Request(selection, false);
        using var transport = Transport(new Wire("get", "{\"privilege\":" + Row(slug: "other") + "}"));
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, selection.GrantTarget("private-privilege")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task CommittedDeletionLostResponseRetainsUncertaintyWithoutReplay()
    {
        var selection = Selection();
        using var request = Request(selection, true);
        var wire = new Wire("delete", "{}") { Drop = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant(request.OperationId, selection.GrantTarget("private-privilege"));
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Exists).IsFalse();
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationPreservesPreAndPostDispatchEvidence(bool before)
    {
        var selection = Selection();
        using var request = Request(selection, true);
        var wire = new Wire("delete", "{}") { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var pending = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, selection.GrantTarget("private-privilege")), receipt, cancel.Token).AsTask();
        if (!before) { await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5)); cancel.Cancel(); }
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(before ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
    }

    private static ManagementRequest<IdentityPrivilegeSummary> Request(LegacyPrivilegeSelection selection, bool delete) =>
        delete ? LegacyIdentityPrivilegeOperations.DeletePrivilege(selection, "private-privilege") :
            LegacyIdentityPrivilegeOperations.GetPrivilege(selection, "private-privilege");
    private static ManagementAuthority Authority(ManagementClient client) => new(client.Authority, new Tokens(), "org", "project-id");
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
    private sealed class Wire(string route, string response) : HttpMessageHandler
    {
        public string? Body { get; private set; }
        public bool Drop { get; init; }
        public bool Hold { get; init; }
        public bool Exists { get; private set; } = true;
        public int Revision { get; private set; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = "/api/v1/additional-privilege/identity" +
                (route == "get" ? "/private-privilege" : "") +
                (route == "delete" ? "" : "?identityId=identity&projectSlug=native-project");
            if (request.Method != (route == "delete" ? HttpMethod.Delete : HttpMethod.Get) ||
                request.RequestUri!.PathAndQuery != path) return new(HttpStatusCode.NotFound);
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            if (route == "delete") { Exists = false; Revision++; }
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            if (Drop) throw new IOException("Committed fixture response lost.");
            return new(HttpStatusCode.OK) { Content = new StringContent(response) };
        }
    }
}
