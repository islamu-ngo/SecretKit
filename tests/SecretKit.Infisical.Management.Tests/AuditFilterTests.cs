using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class AuditFilterTests
{
    private static readonly DateTimeOffset From = new(2026, 10, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Until = From.AddDays(1);

    [Test]
    public async Task CoordinateOnlyGrantCannotAuthorizeAnAuditSelection()
    {
        using var request = GovernanceOperations.ReadAudit("org", From, Until);
        var tokens = new Tokens();
        var wire = new Wire();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("org")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Sent).IsFalse();
    }

    [Test]
    [Arguments("scalar")]
    [Arguments("array")]
    [Arguments("empty")]
    [Arguments("omitted")]
    public async Task EveryNativeSelectorPreservesItsWireShapeAndCopy(string shape)
    {
        AuditEventClass[] classes = [AuditEventClass.Management, AuditEventClass.Authentication];
        string[] types = ["get-secrets", "create-secret"];
        var selectors = new AuditSelectors("private+actor & name", "identity", "",
            shape == "scalar" ? AuditEventFilter.Class("management") :
                shape == "array" ? AuditEventFilter.Classes(classes) :
                shape == "empty" ? AuditEventFilter.Classes([]) : null,
            "",
            shape == "scalar" ? AuditEventFilter.Type("get-secrets") :
                shape == "array" ? AuditEventFilter.Types(types) :
                shape == "empty" ? AuditEventFilter.Types([]) : null,
            "private+key", "/private & path", "InfisicalPythonSDK");
        classes[0] = (AuditEventClass)99;
        types[0] = "invalid";
        using var request = GovernanceOperations.ReadAudit("org", From, Until, selectors: selectors);
        var target = GovernanceOperations.AuditReadTarget("org", From, Until, selectors: selectors);
        var (status, query, _) = await Execute(request, target);
        await Assert.That(status).IsEqualTo(SecretStatus.Success);
        foreach ((string key, string value) in new[]
        {
            ("actor", "private+actor & name"), ("actorType", "identity"), ("environment", ""),
            ("eventMetadata", ""), ("secretKey", "private+key"), ("secretPath", "/private & path"),
            ("userAgentType", "InfisicalPythonSDK")
        })
            await Assert.That(query!.Contains("&" + key + "=" + Uri.EscapeDataString(value), StringComparison.Ordinal)).IsTrue();
        await Assert.That(query!.Contains("eventClass=", StringComparison.Ordinal)).IsEqualTo(shape is "scalar" or "array");
        await Assert.That(query.Contains("eventType=", StringComparison.Ordinal)).IsEqualTo(shape is "scalar" or "array");
        if (shape == "array")
        {
            await Assert.That(query.Contains("&eventClass=management&eventClass=authentication", StringComparison.Ordinal)).IsTrue();
            await Assert.That(query.Contains("&eventType=get-secrets&eventType=create-secret", StringComparison.Ordinal)).IsTrue();
        }
        if (shape == "empty")
        {
            var omitted = new AuditSelectors("private+actor & name", "identity", "", eventMetadata: "",
                secretKey: "private+key", secretPath: "/private & path", userAgentType: "InfisicalPythonSDK");
            await Assert.That(target.SameTarget(GovernanceOperations.AuditReadTarget("org", From, Until, selectors: omitted))).IsFalse();
        }
        await Assert.That(JsonSerializer.Serialize(selectors)).IsEqualTo("{}");
        await Assert.That(selectors.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("actor")]
    [Arguments("environment")]
    [Arguments("metadata")]
    [Arguments("key")]
    [Arguments("path")]
    [Arguments("class")]
    [Arguments("type")]
    [Arguments("agent")]
    [Arguments("window")]
    public async Task AnotherAuditSelectionCannotBorrowTheApprovedGrant(string changed)
    {
        var approved = new AuditSelectors("actor", environment: "dev", eventClass: AuditEventFilter.Class("management"),
            eventMetadata: "metadata", eventType: AuditEventFilter.Type("get-secrets"),
            secretKey: "key", secretPath: "/path", userAgentType: "web");
        var incoming = new AuditSelectors(changed == "actor" ? "other" : "actor",
            environment: changed == "environment" ? "prod" : "dev",
            eventClass: AuditEventFilter.Class(changed == "class" ? "authentication" : "management"),
            eventMetadata: changed == "metadata" ? "other" : "metadata",
            eventType: AuditEventFilter.Type(changed == "type" ? "create-secret" : "get-secrets"),
            secretKey: changed == "key" ? "other" : "key", secretPath: changed == "path" ? "/other" : "/path",
            userAgentType: changed == "agent" ? "cli" : "web");
        using var request = GovernanceOperations.ReadAudit("org", From,
            changed == "window" ? Until.AddDays(1) : Until, selectors: incoming);
        var result = await Execute(request, GovernanceOperations.AuditReadTarget("org", From, Until, selectors: approved));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Acquired).IsFalse();
    }

    [Test]
    public async Task UnsupportedDiscriminatorsAndBudgetsRejectBeforeDispatch()
    {
        await Assert.That(() => new AuditSelectors(actorType: "invalid")).Throws<ArgumentException>();
        await Assert.That(() => new AuditSelectors(userAgentType: "invalid")).Throws<ArgumentException>();
        await Assert.That(() => new AuditSelectors(eventClass: AuditEventFilter.Type("get-secrets"))).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Classes([(AuditEventClass)99])).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Classes(Enumerable.Repeat(AuditEventClass.Management, 5).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Types(["invalid"])).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Types(Enumerable.Repeat("get-secrets", 692).ToArray())).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Class(new string('x', 52))).Throws<ArgumentException>();
        await Assert.That(() => AuditEventFilter.Type(new string('x', 17468))).Throws<ArgumentException>();
    }

    private static async Task<(SecretStatus Status, string? Query, bool Acquired)> Execute(
        ManagementRequest<ManagementPage<AuditRow>> request, ManagementTarget target)
    {
        var tokens = new Tokens();
        var wire = new Wire();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target));
        return (result.Status, wire.Query, tokens.Acquired);
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

    private sealed class Wire : HttpMessageHandler
    {
        public bool Sent { get; private set; }
        public string? Query { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sent = true;
            Query = request.RequestUri!.Query;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"auditLogs":[]}""", Encoding.UTF8, "application/json")
            });
        }
    }
}
