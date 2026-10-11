using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GovernanceAuditWitnessTests
{
    private const string Time = "2026-10-10T00:00:00Z";
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Project = "22222222-2222-4222-8222-222222222222";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task EverySettingsAdapterPreservesKnownClassesAndRejectsMalformedLeaves(int route)
    {
        foreach (var eventClass in Enum.GetValues<AuditEventClass>())
            foreach (bool enabled in new[] { false, true })
            {
                var root = Settings(eventClass, enabled);
                var result = await ExecuteSettings(route, root);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
                await Assert.That(result.Value.Classes.Single().EventClass).IsEqualTo(eventClass);
                await Assert.That(result.Value.Classes.Single().IsEnabled).IsEqualTo(enabled);
                await Assert.That(result.Value.UsesNewPrivilegeSystem).IsEqualTo(enabled);
            }
        foreach (string defect in new[] { "missing-class", "class-type", "unknown-class", "missing-enabled", "enabled-type", "missing-policy", "policy-type" })
        {
            var root = Settings(AuditEventClass.Management, false);
            var settings = root["auditLogSettings"]!.AsObject();
            var item = settings["eventClasses"]![0]!.AsObject();
            switch (defect)
            {
                case "missing-class": item.Remove("eventClass"); break;
                case "class-type": item["eventClass"] = 42; break;
                case "unknown-class": item["eventClass"] = "unestablished"; break;
                case "missing-enabled": item.Remove("isEnabled"); break;
                case "enabled-type": item["isEnabled"] = 42; break;
                case "missing-policy": settings.Remove("shouldUseNewPrivilegeSystem"); break;
                default: settings["shouldUseNewPrivilegeSystem"] = 42; break;
            }
            await Assert.That((await ExecuteSettings(route, root)).Status).IsEqualTo(SecretStatus.Unknown);
        }
    }

    private static JsonObject Settings(AuditEventClass eventClass, bool enabled) => new()
    {
        ["auditLogSettings"] = new JsonObject
        {
            ["eventClasses"] = new JsonArray(new JsonObject
            {
                ["eventClass"] = eventClass switch
                {
                    AuditEventClass.Management => "management",
                    AuditEventClass.Authentication => "authentication",
                    AuditEventClass.Authorization => "authorization",
                    _ => "data-access"
                },
                ["isEnabled"] = enabled
            }),
            ["shouldUseNewPrivilegeSystem"] = enabled
        }
    };

    private static async Task<SecretOutcome<AuditSettings>> ExecuteSettings(int route, JsonObject root)
    {
        using var transport = Transport(root);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, route >= 2 ? Project : null);
        AuditClassSetting[] input = [new(AuditEventClass.Management, false)];
        using var request = route switch
        {
            0 => GovernanceOperations.GetOrganizationAuditSettings(Org),
            1 => GovernanceOperations.SetOrganizationAuditSettings(Org, input),
            2 => GovernanceOperations.GetProjectAuditSettings(Org, Project),
            _ => GovernanceOperations.SetProjectAuditSettings(Org, Project, input)
        };
        var target = route % 2 == 0 ? new ManagementTarget(Org, route >= 2 ? Project : null) :
            GovernanceOperations.AuditSettingsTarget(Org, input, route >= 2 ? Project : null);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        if (receipt is not null)
            await Assert.That(receipt.Evidence).IsEqualTo(result.IsSuccess ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        return result;
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task EverySharingAdapterPreservesKnownFieldsAndRejectsRequiredLeafDefects(int route)
    {
        foreach (string shape in new[] { "absent", "null", "empty", "value" })
        {
            var row = Share(route);
            if (shape != "absent")
            {
                row["name"] = shape == "null" ? null : shape == "empty" ? "" : "private-name";
                row["expiresAfterViews"] = shape == "null" ? null : shape == "empty" ? 0 : 2.5;
                row["identityId"] = shape == "null" ? null : Org;
                row["lastViewedAt"] = shape == "null" ? null : Time;
                row["userId"] = shape == "null" ? null : Org;
                if (route != 1) row["allowExternalEmails"] = shape == "null" ? null : shape == "value";
                if (route == 4) row["orgName"] = shape == "empty" ? "" : "private-org";
            }
            await ExecuteShare(route, row, true, async metadata =>
            {
                await Assert.That(metadata.ExpiresAfterViews.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(metadata.ExpiresAfterViews.IsNull).IsEqualTo(shape == "null");
                await Assert.That(metadata.IdentityId.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(metadata.IdentityId.IsNull).IsEqualTo(shape == "null");
                await Assert.That(metadata.LastViewedAt.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(metadata.LastViewedAt.IsNull).IsEqualTo(shape == "null");
                await Assert.That(metadata.UserId.IsPresent).IsEqualTo(shape != "absent");
                await Assert.That(metadata.UserId.IsNull).IsEqualTo(shape == "null");
                if (route != 1)
                {
                    await Assert.That(metadata.AllowExternalEmails.IsPresent).IsEqualTo(shape != "absent");
                    await Assert.That(metadata.AllowExternalEmails.IsNull).IsEqualTo(shape == "null");
                }
                if (shape is "empty" or "value")
                {
                    await Assert.That(metadata.Name).IsEqualTo(shape == "empty" ? "" : "private-name");
                    await Assert.That(metadata.ExpiresAfterViews.Value).IsEqualTo(shape == "empty" ? 0 : 2.5);
                    await Assert.That(metadata.IdentityId.Value).IsEqualTo(Org);
                    await Assert.That(metadata.UserId.Value).IsEqualTo(Org);
                    await Assert.That(metadata.LastViewedAt.Value).IsEqualTo(Time);
                    if (route != 1) await Assert.That(metadata.AllowExternalEmails.Value).IsEqualTo(shape == "value");
                }
            });
        }
        foreach (string field in new[] { "id", "expiresAt", "createdAt", "updatedAt" }.Concat(
            route == 1 ? new[] { "isAuthorizedUser", "isPasswordProtected" } : []))
            foreach (bool missing in new[] { true, false })
            {
                var row = Share(route);
                if (missing) row.Remove(field); else row[field] = 42;
                await ExecuteShare(route, row, false);
            }
    }

    private static JsonObject Share(int route)
    {
        var row = new JsonObject { ["id"] = "share", ["expiresAt"] = Time, ["createdAt"] = Time, ["updatedAt"] = Time };
        if (route == 1) { row["isAuthorizedUser"] = false; row["isPasswordProtected"] = true; }
        if (route == 2) row["sharedSecretLink"] = "private-link";
        if (route == 4) row["secretValue"] = "private-value";
        return row;
    }

    private static async Task ExecuteShare(int route, JsonObject row, bool valid, Func<SharedSecretMetadata, Task>? inspect = null)
    {
        var root = route == 0 ? new JsonObject { ["secrets"] = new JsonArray(row), ["totalCount"] = 1 } : row;
        using var transport = Transport(root);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var material = SecretMaterial.FromText("private-value");
        switch (route)
        {
            case 0:
                await Verify(SharingOperations.ListShares(Org), SharingOperations.ListSharesTarget(Org),
                page => page.Items.Single()); break;
            case 1: await Verify(SharingOperations.GetShare(Org, "share"), new(Org, resourceId: "share"), value => value); break;
            case 2:
                await Verify(SharingOperations.CreateShare(Org, "private-name", material, 5, ShareAudience.Organization),
                SharingOperations.CreateShareTarget(Org, "private-name", material, 5, ShareAudience.Organization),
                value => value.Metadata); break;
            case 3: await Verify(SharingOperations.DeleteShare(Org, "share"), new(Org, resourceId: "share"), value => value); break;
            default:
                await Verify(SharingOperations.AccessShare(Org, "share"), SharingOperations.AccessShareTarget(Org, "share"),
                value => value.Metadata); break;
        }
        async Task Verify<T>(ManagementRequest<T> request, ManagementTarget approved, Func<T, SharedSecretMetadata> metadata) where T : notnull
        {
            using (request)
            {
                var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
                var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, approved), receipt);
                await Assert.That(result.Status).IsEqualTo(valid ? SecretStatus.Success : SecretStatus.Unknown);
                if (receipt is not null)
                    await Assert.That(receipt.Evidence).IsEqualTo(valid ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
                if (result.IsSuccess)
                {
                    try
                    {
                        var value = metadata(result.Value);
                        await Assert.That(value.CreatedAt.Value).IsEqualTo(Time);
                        await Assert.That(value.UpdatedAt.Value).IsEqualTo(Time);
                        await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
                        if (inspect is not null) await inspect(value);
                    }
                    finally { (result.Value as IDisposable)?.Dispose(); }
                }
            }
        }
    }

    [Test]
    public async Task NonemptyAuditRowsOwnKnownMetadataAndKeepOpenNodesPrivate()
    {
        var row = JsonNode.Parse("""
            {"id":"11111111-1111-4111-8111-111111111111","orgId":"11111111-1111-4111-8111-111111111111",
             "createdAt":"2026-10-10T00:00:00Z","actor":{"type":"identity","metadata":{"private":"hidden"}},
             "event":{"type":"get-secrets","class":"data-access","metadata":{"private":"hidden"}},
             "expiresAt":null,"ipAddress":"","projectName":null,"updatedAt":"2026-10-10T00:00:00Z",
             "userAgent":"private-agent","userAgentType":null}
            """)!.AsObject();
        using var transport = Transport(new JsonObject { ["auditLogs"] = new JsonArray(row) });
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var from = DateTimeOffset.UnixEpoch;
        using var request = GovernanceOperations.ReadAudit(Org, from, from.AddDays(1));
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            GovernanceOperations.AuditReadTarget(Org, from, from.AddDays(1))));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        var value = result.Value.Items.Single().Outcome.Value;
        await Assert.That(value.EventClass).IsEqualTo(AuditEventClass.DataAccess);
        await Assert.That(value.EventType).IsEqualTo("get-secrets");
        await Assert.That(value.ActorType).IsEqualTo("identity");
        await Assert.That(value.ExpiresAt.IsNull).IsTrue();
        await Assert.That(value.IpAddress.Value).IsEqualTo("");
        await Assert.That(value.ProjectName.IsNull).IsTrue();
        await Assert.That(value.UpdatedAt.Value).IsEqualTo(Time);
        await Assert.That(value.UserAgent.Value).IsEqualTo("private-agent");
        await Assert.That(value.UserAgentType.IsNull).IsTrue();
        await Assert.That(value.IncludesActorMetadata).IsFalse();
        await Assert.That(value.IncludesEventMetadata).IsFalse();
        await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    private static ManagementTransport Transport(JsonObject root) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, new Wire(root.ToJsonString()));
    private sealed class Wire(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
    }
    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
}
