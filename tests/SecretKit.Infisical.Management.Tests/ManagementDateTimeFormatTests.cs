using System.Net;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementDateTimeFormatTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Id = "22222222-2222-4222-8222-222222222222";
    private const string Time = "2026-10-11T03:04:05Z";

    // A shared-invariant dispatch basis, not 302 independently exercised declarations.
    [Test]
    [Arguments("group")]
    [Arguments("groups")]
    [Arguments("ldap")]
    [Arguments("kubernetes")]
    [Arguments("oidc")]
    [Arguments("share")]
    public async Task ExactDeclaredDatesRejectMissingZoneAndInvalidCalendar(string route)
    {
        foreach (string invalid in new[] { "2026-10-11", "2026-10-11T03:04:05", "2026-02-30T03:04:05Z" })
        {
            // Given one invalid declared leaf and otherwise valid native metadata.
            var row = Row(route);
            row[route == "share" ? "expiresAt" : "createdAt"] = invalid;
            // When a named public operation dispatches through its HTTP boundary.
            // Then the malformed date cannot become a successful result.
            await Assert.That((await Execute(route, row)).Status).IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments("group")]
    [Arguments("groups")]
    [Arguments("ldap")]
    [Arguments("kubernetes")]
    [Arguments("oidc")]
    [Arguments("share")]
    public async Task AcceptedDatesCopyOriginalZuluAndSignedOffsetText(string route)
    {
        foreach (string text in new[] { Time, "2026-10-11T03:04:05.1234567+02:30", "2026-10-11T03:04:05-04:00" })
        {
            // Given independently specified original date text.
            var row = Row(route);
            row["createdAt"] = text;
            row["updatedAt"] = text;
            if (route == "share") row["expiresAt"] = text;
            // When the public operation and transport have completed and been disposed.
            var result = await Execute(route, row);
            // Then the projection preserves the source text including its offset.
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(result.Date).IsEqualTo(text);
        }
    }

    [Test]
    [Arguments("machineIdentity")]
    [Arguments("user")]
    public async Task DiscriminatedNullableMemberDateRetainsNullAndRejectsMalformedText(string type)
    {
        foreach (string? date in new string?[] { null, Time, "2026-10-11T03:04:05" })
        {
            // Given a nullable leaf inside the selected member branch.
            var row = new JsonObject
            {
                ["id"] = Id,
                ["type"] = type,
                ["joinedGroupAt"] = date,
                [type == "user" ? "user" : "machineIdentity"] = type == "user"
                    ? new JsonObject { ["id"] = Id, ["username"] = "private-user" }
                    : new JsonObject { ["id"] = Id, ["name"] = "private-identity" }
            };
            using var request = ScopedAccessOperations.ListGroupMembers(Org, Id);
            // When the typed branch is parsed before its date guard.
            var result = await Read(request, ScopedAccessOperations.GroupMemberListTarget(Org, Id),
                new JsonObject { ["members"] = new JsonArray(row), ["totalCount"] = 1 });
            // Then null stays admitted and missing-zone text fails closed.
            await Assert.That(result.Status).IsEqualTo(date is null || date == Time ? SecretStatus.Success : SecretStatus.Unknown);
        }
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("valid")]
    [Arguments("invalid")]
    public async Task OptionalShareDatePreservesEndpointPresence(string shape)
    {
        // Given an endpoint-owned optional nullable field.
        var row = Row("share");
        if (shape != "absent") row["lastViewedAt"] = shape switch
        {
            "null" => null,
            "valid" => JsonValue.Create(Time),
            _ => JsonValue.Create("2026-10-11T03:04:05")
        };
        using var request = SharingOperations.GetShare(Org, Id);
        // When dispatched through the public client.
        var result = await Read(request, new(Org, resourceId: Id), row);
        // Then presence and null survive, without accepting malformed text.
        await Assert.That(result.Status).IsEqualTo(shape == "invalid" ? SecretStatus.Unknown : SecretStatus.Success);
        if (!result.IsSuccess) return;
        await Assert.That(result.Value.LastViewedAt.IsPresent).IsEqualTo(shape != "absent");
        await Assert.That(result.Value.LastViewedAt.IsNull).IsEqualTo(shape == "null");
        if (shape == "valid") await Assert.That(result.Value.LastViewedAt.Value).IsEqualTo(Time);
    }

    [Test]
    [Arguments("createdAt")]
    [Arguments("expiresAt")]
    [Arguments("updatedAt")]
    public async Task AuditDatesFailOnlyTheirOrdinalAndLeaveOpaqueMetadataAlone(string field)
    {
        // Given one invalid row between valid rows and date-like opaque metadata.
        var first = Audit(Time);
        first["event"]!["metadata"] = new JsonObject { ["createdAt"] = "opaque-not-a-date" };
        var malformed = Audit(Time);
        malformed[field] = "2026-10-11T03:04:05";
        using var request = GovernanceOperations.ReadAudit(Org, DateTimeOffset.Parse(Time),
            DateTimeOffset.Parse(Time).AddDays(1), offset: 7);
        // When the audit envelope is parsed.
        var result = await Read(request, GovernanceOperations.AuditReadTarget(Org, DateTimeOffset.Parse(Time),
            DateTimeOffset.Parse(Time).AddDays(1), offset: 7),
            new JsonObject { ["auditLogs"] = new JsonArray(first, malformed, Audit(Time)) });
        // Then the middle row alone fails and native ordinals are unchanged.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(3);
        for (int index = 0; index < 3; index++)
        {
            await Assert.That(result.Value.Items[index].Ordinal).IsEqualTo(7 + index);
            await Assert.That(result.Value.Items[index].Outcome.Status)
                .IsEqualTo(index == 1 ? SecretStatus.Unknown : SecretStatus.Success);
        }
    }

    [Test]
    public async Task ForeignScopeWinsBeforeLaterMalformedDate()
    {
        // Given a foreign typed coordinate plus a date defect.
        var row = Row("group");
        row["orgId"] = Id;
        row["createdAt"] = "2026-10-11T03:04:05";
        // When parsed through the selected native request.
        var result = await Execute("group", row);
        // Then typed Invalid classification is preserved.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task UnsupportedMemberBranchWinsBeforeLaterMalformedDate()
    {
        // Given an unsupported typed branch with a date defect.
        var row = new JsonObject { ["id"] = Id, ["type"] = "unknown", ["joinedGroupAt"] = "2026-10-11T03:04:05" };
        using var request = ScopedAccessOperations.ListGroupMembers(Org, Id);
        // When typed parsing reaches the branch before the shared date guard.
        var result = await Read(request, ScopedAccessOperations.GroupMemberListTarget(Org, Id),
            new JsonObject { ["members"] = new JsonArray(row), ["totalCount"] = 1 });
        // Then Unsupported is not replaced by Unknown.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unsupported);
    }

    [Test]
    public async Task LaterDateFailureDisposesCompletedOwnedMaterial()
    {
        // Given the shared cleanup wrapper with a completed typed owned result.
        var row = Row("share");
        row["expiresAt"] = "2026-10-11T03:04:05";
        row.Remove("isAuthorizedUser");
        row.Remove("isPasswordProtected");
        row["secretValue"] = "private-value";
        SecretMaterial? completed = null;
        using var request = new ManagementRequest<SharedValue>("infisical.post.v1.shared.secrets.by.id.access",
            HttpMethod.Post, "/api/v1/shared-secrets/" + Id + "/access", new(Org, resourceId: Id), null, value =>
            {
                var metadata = new SharedSecretMetadata(value, Org, Id);
                completed = SecretMaterial.FromText(ManagementJson.Required(value, "secretValue"));
                return new(metadata, completed);
            });
        // When date validation rejects after typed ownership was established.
        var result = await Read(request, new(Org, resourceId: Id), row);
        if (result.IsSuccess) result.Value.Dispose();
        // Then the failure remains uncertain and completed material is erased.
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(completed).IsNotNull();
        await Assert.That(() => completed!.Reveal()).Throws<ObjectDisposedException>();
    }

    private static JsonObject Row(string route)
    {
        var row = new JsonObject
        {
            ["id"] = Id,
            ["orgId"] = Org,
            ["name"] = "private-name",
            ["createdAt"] = Time,
            ["updatedAt"] = Time
        };
        if (route is "group" or "groups")
        {
            row["slug"] = "private-slug";
            if (route == "group") row["customRoleSlug"] = null;
        }
        else if (route == "share")
        {
            row["expiresAt"] = Time;
            row["isAuthorizedUser"] = true;
            row["isPasswordProtected"] = false;
        }
        else
        {
            row["authMethod"] = route;
            row["templateFields"] = route switch
            {
                "ldap" => new JsonObject { ["hasBindPass"] = false },
                "kubernetes" => new JsonObject { ["hasTokenReviewerJwt"] = false },
                _ => new JsonObject { ["oidcDiscoveryUrl"] = "https://identity.test", ["boundIssuer"] = "private-issuer" }
            };
        }
        return row;
    }

    private static JsonObject Audit(string date) => new()
    {
        ["id"] = Id,
        ["orgId"] = Org,
        ["createdAt"] = date,
        ["updatedAt"] = Time,
        ["actor"] = new JsonObject { ["type"] = "user" },
        ["event"] = new JsonObject { ["type"] = "get-secrets", ["class"] = "data-access" }
    };

    private static async Task<(SecretStatus Status, string? Date)> Execute(string route, JsonObject row)
    {
        if (route == "groups")
        {
            using var request = ScopedAccessOperations.ListGroups(Org);
            var result = await Read(request, new(Org), new JsonArray(row));
            return (result.Status, result.IsSuccess ? result.Value.Items[0].CreatedAt : null);
        }
        if (route == "group")
        {
            using var request = ScopedAccessOperations.GetGroup(Org, Id);
            var result = await Read(request, new(Org, resourceId: Id), row);
            return (result.Status, result.IsSuccess ? result.Value.CreatedAt : null);
        }
        if (route == "share")
        {
            using var request = SharingOperations.GetShare(Org, Id);
            var result = await Read(request, new(Org, resourceId: Id), row);
            return (result.Status, result.IsSuccess ? result.Value.ExpiresAt : null);
        }
        using var template = IdentityTemplateOperations.GetIdentityTemplate(Org, Id);
        var outcome = await Read(template, new(Org, resourceId: Id), row);
        return (outcome.Status, outcome.IsSuccess ? outcome.Value.CreatedAt : null);
    }

    private static async Task<SecretOutcome<T>> Read<T>(ManagementRequest<T> request, ManagementTarget target,
        JsonNode response) where T : notnull
    {
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false,
            new Wire(response.ToJsonString(), request.Method, request.Path));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        if (receipt is not null)
            await Assert.That(receipt.Evidence).IsEqualTo(result.IsSuccess ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        return result;
    }

    private sealed class Wire(string body, HttpMethod method, string path) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await Assert.That(request.Method).IsEqualTo(method);
            await Assert.That(request.RequestUri!.PathAndQuery).IsEqualTo(path);
            return new(HttpStatusCode.OK) { Content = new StringContent(body) };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
    }
}
