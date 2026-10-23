using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GovernanceRowWitnessTests
{
    private const string ProjectId = "66666666-6666-4666-8666-666666666666";
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string PrivilegeId = "88888888-8888-4888-8888-888888888888";

    [Test]
    [Arguments(0, false)]
    [Arguments(0, true)]
    [Arguments(1, false)]
    [Arguments(1, true)]
    [Arguments(2, false)]
    [Arguments(2, true)]
    [Arguments(3, false)]
    [Arguments(3, true)]
    [Arguments(4, false)]
    [Arguments(4, true)]
    [Arguments(5, false)]
    [Arguments(5, true)]
    [Arguments(6, false)]
    [Arguments(6, true)]
    [Arguments(7, false)]
    [Arguments(7, true)]
    [Arguments(8, false)]
    [Arguments(8, true)]
    [Arguments(9, false)]
    [Arguments(9, true)]
    [Arguments(10, false)]
    [Arguments(10, true)]
    [Arguments(11, false)]
    [Arguments(11, true)]
    [Arguments(12, false)]
    [Arguments(12, true)]
    public async Task EveryRemainingCallableRowParsesItsOwnClosedFixture(int route, bool malformed)
    {
        AuditClassSetting[] settings = [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)];
        const string audit = """{"auditLogSettings":{"eventClasses":[{"eventClass":"management","isEnabled":true}],"shouldUseNewPrivilegeSystem":false}}""";
        const string share = $$$$"""{"id":"share","orgId":"{{{{OrgId}}}}","name":"private-share","expiresAt":"2026-10-11T00:00:00Z","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-10T00:00:00Z"}""";
        string privilege = route == 11
            ? $$$$"""{"id":"{{{{PrivilegeId}}}}","slug":"private-privilege","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z"}"""
            : $$$$"""{"id":"{{{{PrivilegeId}}}}","slug":"private-privilege","createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-02T00:00:00Z","permissions":[]}""";
        using var material = SecretMaterial.FromText("private-value");
        var from = DateTimeOffset.UnixEpoch;
        string response = route switch
        {
            <= 3 => audit,
            4 => """{"auditLogs":[]}""",
            5 => "{\"secrets\":[" + share + "],\"totalCount\":1}",
            6 => share[..^1] + ""","isAuthorizedUser":false,"isPasswordProtected":true}""",
            7 => share[..^1] + ""","sharedSecretLink":"private-link"}""",
            8 => share,
            9 => share[..^1] + ""","secretValue":"private-value"}""",
            10 => $$$$"""{"identityDetails":{"organization":{"id":"{{{{OrgId}}}}","name":"private-org","slug":"org"}}}""",
            11 => "{\"privileges\":[" + privilege + "]}",
            _ => "{\"privilege\":" + privilege + "}"
        };
        var wire = new Wire(malformed ? "[]" : response);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId, route is 2 or 3 ? ProjectId : route is 11 or 12 ? "project" : null);
        switch (route)
        {
            case 0:
                await Verify(GovernanceOperations.GetOrganizationAuditSettings(OrgId), new(OrgId),
                    "infisical.get.v1.organization.audit.log.settings", "GET", "/api/v1/organization/audit-log-settings");
                break;
            case 1:
                await Verify(GovernanceOperations.SetOrganizationAuditSettings(OrgId, settings),
                    GovernanceOperations.AuditSettingsTarget(OrgId, settings),
                    "infisical.put.v1.organization.audit.log.settings", "PUT", "/api/v1/organization/audit-log-settings");
                break;
            case 2:
                await Verify(GovernanceOperations.GetProjectAuditSettings(OrgId, ProjectId), new(OrgId, ProjectId),
                    "infisical.get.v1.projects.by.projectId.audit.log.settings", "GET", $"/api/v1/projects/{ProjectId}/audit-log-settings");
                break;
            case 3:
                await Verify(GovernanceOperations.SetProjectAuditSettings(OrgId, ProjectId, settings),
                    GovernanceOperations.AuditSettingsTarget(OrgId, settings, ProjectId),
                    "infisical.put.v1.projects.by.projectId.audit.log.settings", "PUT", $"/api/v1/projects/{ProjectId}/audit-log-settings");
                break;
            case 4:
                await Verify(GovernanceOperations.ReadAudit(OrgId, from, from.AddDays(1)),
                    GovernanceOperations.AuditReadTarget(OrgId, from, from.AddDays(1)),
                    "infisical.get.v1.organization.audit.logs", "GET", "/api/v1/organization/audit-logs");
                break;
            case 5:
                await Verify(SharingOperations.ListShares(OrgId), SharingOperations.ListSharesTarget(OrgId),
                    "infisical.get.v1.shared.secrets", "GET", "/api/v1/shared-secrets");
                break;
            case 6:
                await Verify(SharingOperations.GetShare(OrgId, "share"), new(OrgId, resourceId: "share"),
                    "infisical.get.v1.shared.secrets.by.id", "GET", "/api/v1/shared-secrets/share");
                break;
            case 7:
                await Verify(SharingOperations.CreateShare(OrgId, "private-share", material, 5, ShareAudience.Organization),
                    SharingOperations.CreateShareTarget(OrgId, "private-share", material, 5, ShareAudience.Organization),
                    "infisical.post.v1.shared.secrets", "POST", "/api/v1/shared-secrets");
                break;
            case 8:
                await Verify(SharingOperations.DeleteShare(OrgId, "share"), new(OrgId, resourceId: "share"),
                    "infisical.delete.v1.shared.secrets.by.id", "DELETE", "/api/v1/shared-secrets/share");
                break;
            case 9:
                await Verify(SharingOperations.AccessShare(OrgId, "share"), SharingOperations.AccessShareTarget(OrgId, "share"),
                    "infisical.post.v1.shared.secrets.by.id.access", "POST", "/api/v1/shared-secrets/share/access");
                break;
            case 10:
                await Verify(IdentityOperations.GetSelectedIdentityOrganization(OrgId), new(OrgId),
                    "infisical.get.v1.identities.details", "GET", "/api/v1/identities/details");
                break;
            case 11:
                await Verify(IdentityPrivilegeOperations.ListProjectPrivileges(OrgId, "project", "identity"), new(OrgId, "project", "identity"),
                    "infisical.get.v2.identity.project.additional.privilege", "GET", "/api/v2/identity-project-additional-privilege");
                break;
            default:
                await Verify(IdentityPrivilegeOperations.GetProjectPrivilege(OrgId, "project", "identity", PrivilegeId),
                    new(OrgId, "project", "identity", PrivilegeId),
                    "infisical.get.v2.identity.project.additional.privilege.by.id", "GET", $"/api/v2/identity-project-additional-privilege/{PrivilegeId}");
                break;
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget approved, string id, string method, string path) where T : notnull
        {
            using (request)
            {
                await Assert.That(request.OperationId).IsEqualTo(id);
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(id, approved), receipt);
                await Assert.That(result.Status).IsEqualTo(malformed ? SecretStatus.Unknown : SecretStatus.Success);
                await Assert.That(wire.Method).IsEqualTo(method);
                await Assert.That(wire.Path).IsEqualTo(path);
                if (receipt is not null)
                    await Assert.That(receipt.Evidence).IsEqualTo(malformed ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Applied);
                if (result.IsSuccess)
                {
                    await Assert.That(JsonSerializer.Serialize(result).Contains("private", StringComparison.Ordinal)).IsFalse();
                    (result.Value as IDisposable)?.Dispose();
                }
            }
        }
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
    private sealed class Wire(string response) : HttpMessageHandler
    {
        public string? Method { get; private set; }
        public string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Method = request.Method.Method;
            Path = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(response) });
        }
    }
}
