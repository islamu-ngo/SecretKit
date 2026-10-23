using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GovernanceGrantTests
{
    private const string ProjectId = "22222222-2222-4222-8222-222222222222";

    [Test]
    [Arguments("organization", false)]
    [Arguments("organization", true)]
    [Arguments("project", false)]
    [Arguments("project", true)]
    [Arguments("list", false)]
    [Arguments("list", true)]
    [Arguments("access", false)]
    [Arguments("access", true)]
    public async Task IndependentlySelectedGovernanceInputsMustMatch(string selection, bool changed)
    {
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire());
        var client = new ManagementClient(transport);
        string? project = selection == "project" ? ProjectId : null;
        var authority = new ManagementAuthority(client.Authority, tokens, "org", project);
        AuditClassSetting[] trusted = [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)];
        AuditClassSetting[] incoming = [new(AuditEventClass.Authentication, !changed), new(AuditEventClass.Authorization, false)];
        using var proof = SecretMaterial.FromText(changed ? "other-proof" : "private-proof");
        using var approved = SecretMaterial.FromText("private-proof");
        switch (selection)
        {
            case "organization":
                await Verify(GovernanceOperations.SetOrganizationAuditSettings("org", incoming),
                    GovernanceOperations.AuditSettingsTarget("org", trusted));
                break;
            case "project":
                await Verify(GovernanceOperations.SetProjectAuditSettings("org", ProjectId, incoming),
                    GovernanceOperations.AuditSettingsTarget("org", trusted, ProjectId));
                break;
            case "list":
                await Verify(SharingOperations.ListShares("org", changed ? 1 : 0, 3),
                    SharingOperations.ListSharesTarget("org", 0, 3));
                break;
            default:
                await Verify(SharingOperations.AccessShare("org", "share", proof),
                    SharingOperations.AccessShareTarget("org", "share", approved));
                break;
        }
        await Assert.That(tokens.Acquired).IsEqualTo(!changed);
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
                (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
                await Assert.That(result.Status).IsEqualTo(changed ? SecretStatus.Denied : SecretStatus.Success);
                if (receipt is not null)
                    await Assert.That(receipt.Evidence).IsEqualTo(changed ? DispatchEvidence.NotDispatched : DispatchEvidence.Applied);
            }
        }
    }

    [Test]
    [Arguments("organization")]
    [Arguments("project")]
    [Arguments("list")]
    [Arguments("access")]
    public async Task CoordinateOnlyApprovalCannotAuthorizeGovernanceInputs(string selection)
    {
        var tokens = new Tokens();
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire());
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org", selection == "project" ? ProjectId : null);
        using var proof = SecretMaterial.FromText("private-proof");
        AuditClassSetting[] settings = [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)];
        switch (selection)
        {
            case "organization":
                await Denied(GovernanceOperations.SetOrganizationAuditSettings("org", settings), new("org"));
                break;
            case "project":
                await Denied(GovernanceOperations.SetProjectAuditSettings("org", ProjectId, settings), new("org", ProjectId));
                break;
            case "list":
                await Denied(SharingOperations.ListShares("org", 1, 3), new("org"));
                break;
            default:
                await Denied(SharingOperations.AccessShare("org", "share", proof), new("org", resourceId: "share"));
                break;
        }
        await Assert.That(tokens.Acquired).IsFalse();
        async Task Denied<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
                (result.IsSuccess ? result.Value as IDisposable : null)?.Dispose();
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
                if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            }
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
    private sealed class Wire : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string body = request.RequestUri!.AbsolutePath.Contains("audit-log-settings", StringComparison.Ordinal)
                ? """{"auditLogSettings":{"eventClasses":[{"eventClass":"management","isEnabled":true}],"shouldUseNewPrivilegeSystem":false}}"""
                : request.RequestUri.AbsolutePath.EndsWith("/access", StringComparison.Ordinal)
                ? """{"id":"share","expiresAt":"2026-10-11T00:00:00Z","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z","secretValue":"private-value"}"""
                : """{"secrets":[],"totalCount":0}""";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}
