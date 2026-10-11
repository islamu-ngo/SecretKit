using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class MembershipMutationTests
{
    private const string User = "50000000-0000-4000-8000-000000000005";

    private const string Org = "10000000-0000-4000-8000-000000000001";
    private const string Project = "project";
    private const string Member = "30000000-0000-4000-8000-000000000003";
    private const string Email = "private+member@example.test";
    private const string Username = "private-user";
    private static MembershipPrincipals Principals() => new([Email], [Username]);

    [Test]
    [Arguments("invite")]
    [Arguments("project-delete")]
    [Arguments("org-delete")]
    public async Task NativeMutationsRouteCopiedInputsAndProtectedResults(string route)
    {
        string[] emails = [Email], usernames = [Username], ids = [Member], roles = ["viewer", "custom"];
        var principals = new MembershipPrincipals(emails, usernames);
        using var request = route switch
        {
            "invite" => ProjectRequest(MembershipMutationOperations.InviteProjectMembers(Org, Project, principals, roles)),
            "project-delete" => ProjectRequest(MembershipMutationOperations.RemoveProjectMembers(Org, Project, principals)),
            _ => OrganizationRequest(MembershipMutationOperations.DeleteOrganizationMemberships(Org, ids))
        };
        emails[0] = "changed@example.test";
        usernames[0] = ids[0] = roles[0] = "changed";
        var wire = new Wire(route, Response(route));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        var result = await request.ExecuteAsync(client, authority, authority.IssueGrant(Operation(route), Target(route)), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(request.SerializedTarget).IsEqualTo("{}");
        await Assert.That(request.SerializedRequest.Contains(Email, StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(principals)).IsEqualTo("{}");
        using var body = JsonDocument.Parse(wire.Body!);
        if (route == "org-delete")
        {
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(1);
            await Assert.That(body.RootElement.GetProperty("membershipIds")[0].GetString()).IsEqualTo(Member);
            var page = (ManagementPage<OrganizationMembershipSummary>)result.Value;
            await Assert.That(page.Items[0].Id).IsEqualTo(Member);
            await Assert.That(JsonSerializer.Serialize(page.Items[0])).IsEqualTo("""{"IncludesPermissions":false}""");
        }
        else
        {
            await Assert.That(body.RootElement.EnumerateObject().Count()).IsEqualTo(route == "invite" ? 3 : 2);
            await Assert.That(body.RootElement.GetProperty("emails")[0].GetString()).IsEqualTo(Email);
            await Assert.That(body.RootElement.GetProperty("usernames")[0].GetString()).IsEqualTo(Username);
            if (route == "invite")
                await Assert.That(body.RootElement.GetProperty("roleSlugs")[0].GetString()).IsEqualTo("viewer");
            var page = (ManagementPage<ProjectMembershipMutationSummary>)result.Value;
            await Assert.That(page.Items[0].Id).IsEqualTo(Member);
            await Assert.That(page.Items[0].UserId).IsEqualTo(User);
            await Assert.That(page.Items[0].ProjectId).IsEqualTo(Project);
            await Assert.That(JsonSerializer.Serialize(page.Items[0])).IsEqualTo("{}");
            await Assert.That(page.Items[0].ToString().Contains(Member, StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That((await request.ExecuteAsync(client, authority,
            authority.IssueGrant(Operation(route), Target(route)), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task InvitationRetainsDefaultRolesAndBothSelectorForms(bool email)
    {
        var principals = email ? new MembershipPrincipals(emails: [Email]) : new MembershipPrincipals(usernames: [Username]);
        using var request = MembershipMutationOperations.InviteProjectMembers(Org, Project, principals);
        var wire = new Wire("invite", Response("invite"));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, "invite");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(Operation("invite"),
            MembershipMutationOperations.InvitationTarget(Org, Project, principals)), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var body = JsonDocument.Parse(wire.Body!);
        await Assert.That(body.RootElement.TryGetProperty("roleSlugs", out _)).IsFalse();
        await Assert.That(body.RootElement.GetProperty(email ? "emails" : "usernames").GetArrayLength()).IsEqualTo(1);
        await Assert.That(body.RootElement.GetProperty(email ? "usernames" : "emails").GetArrayLength()).IsEqualTo(0);
    }

    [Test]
    [Arguments("invite", "batch")]
    [Arguments("invite", "roles")]
    [Arguments("invite", "default-roles")]
    [Arguments("invite", "organization")]
    [Arguments("invite", "project")]
    [Arguments("invite", "issuer")]
    [Arguments("project-delete", "batch")]
    [Arguments("project-delete", "selector-kind")]
    [Arguments("project-delete", "operation")]
    [Arguments("project-delete", "organization")]
    [Arguments("project-delete", "project")]
    [Arguments("org-delete", "batch")]
    [Arguments("org-delete", "organization")]
    [Arguments("org-delete", "issuer")]
    [Arguments("org-delete", "missing")]
    public async Task IndependentScopeAndCompleteBatchIntentRejectBeforeTokens(string route, string defect)
    {
        using var request = Request(route);
        var wire = new Wire(route, Response(route));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = Authority(client, route, tokens);
        string org = defect == "organization" ? "other" : Org;
        string project = defect == "project" ? "other" : Project;
        var issuer = defect is "issuer" or "organization" or "project"
            ? new ManagementAuthority(client.Authority, tokens, org, route == "org-delete" ? null : project) : authority;
        MembershipPrincipals principals = defect == "batch" ? new(usernames: ["other"]) :
            defect == "selector-kind" ? new(emails: [Email, "private-user@example.test"]) : Principals();
        var target = route switch
        {
            "invite" => MembershipMutationOperations.InvitationTarget(org, project, principals,
                defect == "default-roles" ? null : defect == "roles" ? ["admin"] : ["viewer", "custom"]),
            "project-delete" => MembershipMutationOperations.ProjectDeletionTarget(org, project, principals),
            _ => MembershipMutationOperations.OrganizationDeletionTarget(org, [defect == "batch" ? "other" : Member])
        };
        var receipt = request.CreateReceipt(client);
        var result = await request.ExecuteAsync(client, authority, defect == "missing" ? null :
            issuer.IssueGrant(defect == "operation" ? "other" : Operation(route), target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("invite", "projectId", "other", SecretStatus.Invalid)]
    [Arguments("project-delete", "projectId", "other", SecretStatus.Invalid)]
    [Arguments("invite", "orgId", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("project-delete", "userId", null, SecretStatus.Unknown)]
    [Arguments("invite", "createdAt", null, SecretStatus.Unknown)]
    [Arguments("invite", "updatedAt", null, SecretStatus.Unknown)]
    [Arguments("org-delete", "orgId", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("org-delete", "id", "90000000-0000-4000-8000-000000000009", SecretStatus.Invalid)]
    [Arguments("org-delete", "role", null, SecretStatus.Unknown)]
    [Arguments("org-delete", "orgId", null, SecretStatus.Unknown)]
    [Arguments("org-delete", "createdAt", null, SecretStatus.Unknown)]
    public async Task NativeRequiredFieldsAndReturnedCoordinatesFailClosed(string route, string field,
        string? value, SecretStatus expected)
    {
        var row = Row(route);
        if (value is null) row.Remove(field);
        else row[field] = value;
        using var request = Request(route);
        var wire = new Wire(route, JsonSerializer.Serialize(new { memberships = new[] { row } }));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        var result = await request.ExecuteAsync(client, authority, authority.IssueGrant(Operation(route), Target(route)), receipt);
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("invite", 0, SecretStatus.Success)]
    [Arguments("project-delete", 0, SecretStatus.Success)]
    [Arguments("org-delete", 0, SecretStatus.Success)]
    [Arguments("invite", 1001, SecretStatus.Unknown)]
    [Arguments("project-delete", 1001, SecretStatus.Unknown)]
    [Arguments("org-delete", 1001, SecretStatus.Unknown)]
    [Arguments("invite", 2, SecretStatus.Invalid)]
    [Arguments("project-delete", 2, SecretStatus.Invalid)]
    [Arguments("org-delete", 2, SecretStatus.Invalid)]
    public async Task ReturnedBatchesNeverInventPerInputCompletionOrTruncate(string route, int count, SecretStatus expected)
    {
        using var request = Request(route);
        var wire = new Wire(route, JsonSerializer.Serialize(new { memberships = Enumerable.Repeat(Row(route), count) }));
        var result = await Execute(request, route, wire);
        await Assert.That(result.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments("invite", true)]
    [Arguments("invite", false)]
    [Arguments("project-delete", true)]
    [Arguments("project-delete", false)]
    [Arguments("org-delete", true)]
    [Arguments("org-delete", false)]
    public async Task CancellationUsesExactDispatchEvent(string route, bool before)
    {
        using var request = Request(route);
        var wire = new Wire(route, Response(route)) { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var operation = request.ExecuteAsync(client, authority, authority.IssueGrant(Operation(route), Target(route)),
            receipt, cancel.Token);
        if (!before)
        {
            await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(before
            ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("invite", false)]
    [Arguments("invite", true)]
    [Arguments("project-delete", false)]
    [Arguments("project-delete", true)]
    [Arguments("org-delete", false)]
    [Arguments("org-delete", true)]
    public async Task CommittedBatchLostResponseNeverReplays(string route, bool drop)
    {
        using var request = Request(route);
        var wire = new Wire(route, Response(route)) { Drop = drop, HoldAfterCommit = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        var grant = authority.IssueGrant(Operation(route), Target(route));
        var operation = request.ExecuteAsync(client, authority, grant, receipt);
        await wire.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That(wire.Members.Contains(Username)).IsEqualTo(route == "invite");
        wire.ReturnResponse.TrySetResult();
        var result = await operation;
        await Assert.That(result.Status).IsEqualTo(drop ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(drop ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
        await Assert.That((await request.ExecuteAsync(client, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Members.Contains(Username)).IsEqualTo(route == "invite");
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments("invite")]
    [Arguments("project-delete")]
    [Arguments("org-delete")]
    public async Task CancellationAfterCommitRetainsUnknownEvidenceAndActualState(string route)
    {
        using var request = Request(route);
        var wire = new Wire(route, Response(route)) { HoldAfterCommit = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        using var cancel = new CancellationTokenSource();
        var operation = request.ExecuteAsync(client, authority,
            authority.IssueGrant(Operation(route), Target(route)), receipt, cancel.Token);
        await wire.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Members.Contains(Username)).IsEqualTo(route == "invite");
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    [Arguments("invite")]
    [Arguments("project-delete")]
    [Arguments("org-delete")]
    public async Task ReceiptCannotCrossRequestOrClientAndConcurrentUseDispatchesOnce(string route)
    {
        using var request = Request(route);
        using var other = Request(route);
        var wire = new Wire(route, Response(route)) { Hold = true };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var foreign = new ManagementClient(transport);
        var authority = Authority(client, route);
        var receipt = request.CreateReceipt(client);
        var grant = authority.IssueGrant(Operation(route), Target(route));
        await Assert.That((await other.ExecuteAsync(client, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var foreignAuthority = Authority(foreign, route);
        await Assert.That((await request.ExecuteAsync(foreign, foreignAuthority,
            foreignAuthority.IssueGrant(Operation(route), Target(route)), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        var pending = request.ExecuteAsync(client, authority, grant, receipt);
        await wire.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That((await request.ExecuteAsync(client, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        wire.Release.TrySetResult();
        await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    [Test]
    public async Task InvalidTypedCollectionsRejectLocally()
    {
        await Assert.That(() => new MembershipPrincipals()).Throws<ArgumentException>();
        await Assert.That(() => new MembershipPrincipals(emails: ["invalid"])).Throws<ArgumentException>();
        await Assert.That(() => new MembershipPrincipals(usernames: [null!])).Throws<ArgumentException>();
        await Assert.That(() => new MembershipPrincipals(usernames: ["same", "same"])).Throws<ArgumentException>();
        await Assert.That(() => new MembershipPrincipals(usernames: Enumerable.Range(0, 129).Select(i => "u" + i).ToArray()))
            .Throws<ArgumentException>();
        await Assert.That(() => MembershipMutationOperations.InviteProjectMembers(Org, Project, Principals(), []))
            .Throws<ArgumentException>();
        await Assert.That(() => MembershipMutationOperations.InviteProjectMembers(Org, Project, Principals(),
            Enumerable.Range(0, 101).Select(i => "r" + i).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => MembershipMutationOperations.DeleteOrganizationMemberships(Org, []))
            .Throws<ArgumentException>();
        await Assert.That(() => MembershipMutationOperations.DeleteOrganizationMemberships(Org, null!))
            .Throws<ArgumentNullException>();
        await Assert.That(() => MembershipMutationOperations.DeleteOrganizationMemberships(Org, [Member, Member]))
            .Throws<ArgumentException>();
        var large = new MembershipPrincipals(usernames: Enumerable.Range(0, 128)
            .Select(i => new string('\u4e00', 250) + i).ToArray());
        await Assert.That(() => MembershipMutationOperations.InviteProjectMembers(Org, Project, large))
            .Throws<ArgumentException>();
    }

    private static Mutation ProjectRequest(
        ManagementRequest<ManagementPage<ProjectMembershipMutationSummary>> request) =>
        Bind(request);
    private static Mutation OrganizationRequest(
        ManagementRequest<ManagementPage<OrganizationMembershipSummary>> request) => Bind(request);

    // Execute the actual public factory request, including its own receipt binding.
    private static Mutation Bind<T>(ManagementRequest<T> request) where T : notnull =>
        new(request, JsonSerializer.Serialize(request.Target), JsonSerializer.Serialize(request),
            client => client.CreateReceipt(request), async (client, authority, grant, receipt, cancellation) =>
            {
                var outcome = await client.ExecuteAsync(request, authority, grant, receipt, cancellation);
                return outcome.IsSuccess ? SecretOutcome<object>.Success(outcome.Value) :
                    SecretOutcome<object>.Failure(outcome.Status, outcome.RetryAfter);
            });

    private sealed class Mutation(IDisposable request, string serializedTarget, string serializedRequest,
        Func<ManagementClient, ManagementReceipt> createReceipt,
        Func<ManagementClient, ManagementAuthority, ManagementGrant?, ManagementReceipt, CancellationToken,
            Task<SecretOutcome<object>>> execute) : IDisposable
    {
        public string SerializedTarget => serializedTarget;
        public string SerializedRequest => serializedRequest;
        public ManagementReceipt CreateReceipt(ManagementClient client) => createReceipt(client);
        public Task<SecretOutcome<object>> ExecuteAsync(ManagementClient client, ManagementAuthority authority,
            ManagementGrant? grant, ManagementReceipt receipt, CancellationToken cancellationToken = default) =>
            execute(client, authority, grant, receipt, cancellationToken);
        public void Dispose() => request.Dispose();
    }
    private static Mutation Request(string route) => route switch
    {
        "invite" => ProjectRequest(MembershipMutationOperations.InviteProjectMembers(Org, Project, Principals(), ["viewer", "custom"])),
        "project-delete" => ProjectRequest(MembershipMutationOperations.RemoveProjectMembers(Org, Project, Principals())),
        _ => OrganizationRequest(MembershipMutationOperations.DeleteOrganizationMemberships(Org, [Member]))
    };
    private static ManagementTarget Target(string route) => route switch
    {
        "invite" => MembershipMutationOperations.InvitationTarget(Org, Project, Principals(), ["viewer", "custom"]),
        "project-delete" => MembershipMutationOperations.ProjectDeletionTarget(Org, Project, Principals()),
        _ => MembershipMutationOperations.OrganizationDeletionTarget(Org, [Member])
    };
    private static string Operation(string route) => route switch
    {
        "invite" => "infisical.post.v1.projects.by.projectId.memberships",
        "project-delete" => "infisical.delete.v1.projects.by.projectId.memberships",
        _ => "infisical.delete.v2.organizations.by.organizationId.memberships"
    };
    private static Dictionary<string, object?> Row(string route)
    {
        var row = new Dictionary<string, object?>
        {
            ["id"] = Member,
            ["userId"] = User,
            ["createdAt"] = "2026-01-01T00:00:00Z",
            ["updatedAt"] = "2026-01-02T00:00:00Z"
        };
        if (route == "org-delete") { row["orgId"] = Org; row["role"] = "member"; }
        else row["projectId"] = Project;
        return row;
    }
    private static string Response(string route) => JsonSerializer.Serialize(new { memberships = new[] { Row(route) } });
    private static ManagementAuthority Authority(ManagementClient client, string route, Tokens? tokens = null) =>
        new(client.Authority, tokens ?? new Tokens(), Org, route == "org-delete" ? null : Project);
    private static ManagementTransport Transport(HttpMessageHandler wire) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
    private static async Task<SecretOutcome<object>> Execute(Mutation request, string route, Wire wire)
    {
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = Authority(client, route);
        return await request.ExecuteAsync(client, authority,
            authority.IssueGrant(Operation(route), Target(route)), request.CreateReceipt(client));
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
    private sealed class Wire(string route, string response) : HttpMessageHandler
    {
        public bool Observed { get; private set; }
        public string? Body { get; private set; }
        public bool Hold { get; init; }
        public bool Drop { get; init; }
        public bool HoldAfterCommit { get; init; }
        public int Revision { get; private set; }
        public HashSet<string> Members { get; } = route == "invite" ? [] : [Username];
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReturnResponse { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string path = route == "org-delete" ? "/api/v2/organizations/" + Org + "/memberships" : "/api/v1/projects/project/memberships";
            if (request.Method.Method != (route == "invite" ? "POST" : "DELETE") ||
                request.RequestUri!.PathAndQuery != path || request.Headers.Authorization?.Scheme != "Bearer")
                return new(HttpStatusCode.NotFound);
            Observed = true;
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await Release.Task.WaitAsync(cancellationToken);
            using var body = JsonDocument.Parse(Body);
            if (route == "invite")
                foreach (JsonElement username in body.RootElement.GetProperty("usernames").EnumerateArray())
                    Members.Add(username.GetString()!);
            else if (route == "project-delete")
                foreach (JsonElement username in body.RootElement.GetProperty("usernames").EnumerateArray())
                    Members.Remove(username.GetString()!);
            else if (body.RootElement.GetProperty("membershipIds").EnumerateArray().Any(id => id.GetString() == Member))
                Members.Remove(Username);
            Revision++;
            Committed.TrySetResult();
            if (HoldAfterCommit) await ReturnResponse.Task.WaitAsync(cancellationToken);
            if (Drop) throw new IOException("Lost committed fixture response.");
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
