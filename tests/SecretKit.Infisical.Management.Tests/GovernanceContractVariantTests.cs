using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class GovernanceContractVariantTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string User = "33333333-3333-4333-8333-333333333333";

    [Test]
    public async Task DisposedSharePasswordFailsBeforeDispatchWithoutOwningCallerValue()
    {
        var server = new Server(Share);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var material = SecretMaterial.FromText("private-value");
        using var independent = SecretMaterial.FromText("private-value");
        using var password = SecretMaterial.FromText("private-password");
        password.Dispose();

        await Assert.That(async () =>
        {
            using var request = SharingOperations.CreateShare(Org, "share", material, 5,
                ShareAudience.Organization, password: password);
            using var result = (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, request.Target), client.CreateReceipt(request))).Value;
        }).Throws<ObjectDisposedException>();

        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(material.Reveal()).IsEqualTo("private-value");
        material.Dispose();
        await Assert.That(independent.Reveal()).IsEqualTo("private-value");
    }

    [Test]
    public async Task DifferentShareMaterialCannotUseSelectedGrant()
    {
        var server = new Server(Share);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var first = SecretMaterial.FromText("selected-private-value");
        using var second = SecretMaterial.FromText("incoming-private-value");
        using var selected = SharingOperations.CreateShare(Org, "share", first, 5, ShareAudience.Organization);
        using var incoming = SharingOperations.CreateShare(Org, "share", second, 5, ShareAudience.Organization);
        var receipt = client.CreateReceipt(incoming);
        var result = await client.ExecuteAsync(incoming, authority,
            authority.IssueGrant(incoming.OperationId, selected.Target), receipt);
        if (result.Status == SecretStatus.Success) result.Value.Dispose();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    public async Task MalformedKnownShareBooleanIsNotDropped()
    {
        using var transport = Transport(new Server(Share.Replace("\"allowExternalEmails\":false",
            "\"allowExternalEmails\":\"false\"", StringComparison.Ordinal)));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = SharingOperations.GetShare(Org, "share");
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, resourceId: "share")));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments(null)]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RecipientPolicyCopiesAndPreservesOmittedEmptyAndMultipleEmails(bool? external)
    {
        foreach (string[]? emails in new string[]?[] { null, [], ["first@example.test", "second@example.test"] })
        {
            var server = new Server(Share);
            using var transport = Transport(server);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
            using var material = SecretMaterial.FromText("private-value");
            using var password = SecretMaterial.FromText("private-password");
            var target = SharingOperations.CreateShareTarget(Org, "share", material, 5,
                ShareAudience.Anyone, 2, password, external, emails);
            using var request = SharingOperations.CreateShare(Org, "share", material, 5,
                ShareAudience.Anyone, 2, password, external, emails);
            if (emails?.Length > 0) emails[0] = "mutated@example.test";
            material.Dispose();
            password.Dispose();
            var receipt = client.CreateReceipt(request);
            using var result = (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, target), receipt)).Value;
            using var body = JsonDocument.Parse(server.Body!);
            var wire = body.RootElement;
            await Assert.That(wire.TryGetProperty("allowExternalEmails", out var flag)).IsEqualTo(external is not null);
            if (external is not null) await Assert.That(flag.GetBoolean()).IsEqualTo(external.Value);
            await Assert.That(wire.TryGetProperty("authorizedEmails", out var array)).IsEqualTo(emails is not null);
            if (emails is not null)
            {
                await Assert.That(array.GetArrayLength()).IsEqualTo(emails.Length);
                if (emails.Length > 0) await Assert.That(array[0].GetString()).IsEqualTo("first@example.test");
            }
            await Assert.That(wire.GetProperty("secretValue").GetString()).IsEqualTo("private-value");
            await Assert.That(wire.GetProperty("password").GetString()).IsEqualTo("private-password");
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            await Assert.That(result.Link.Reveal()).IsEqualTo("private-link");
            result.Dispose();
            await Assert.That(() => result.Link.Reveal()).Throws<ObjectDisposedException>();
            request.Dispose();
            await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
            await Assert.That(JsonSerializer.Serialize(target)).IsEqualTo("{}");
        }
    }

    [Test]
    [Arguments("lifetime")]
    [Arguments("audience")]
    [Arguments("views")]
    [Arguments("password")]
    [Arguments("external")]
    [Arguments("emails")]
    public async Task EveryShareInputParticipatesInIndependentGrant(string changed)
    {
        var server = new Server(Share);
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var material = SecretMaterial.FromText("private-value");
        using var password = SecretMaterial.FromText("private-password");
        var selected = SharingOperations.CreateShareTarget(Org, "share", material, 5, ShareAudience.Organization);
        using var incoming = SharingOperations.CreateShare(Org, "share", material,
            changed == "lifetime" ? 6 : 5, changed == "audience" ? ShareAudience.Anyone : ShareAudience.Organization,
            changed == "views" ? 1 : null, changed == "password" ? password : null,
            changed == "external" ? false : null, changed == "emails" ? [] : null);
        var receipt = client.CreateReceipt(incoming);
        var result = await client.ExecuteAsync(incoming, authority,
            authority.IssueGrant(incoming.OperationId, selected), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(server.Dispatched).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("list")]
    [Arguments("get")]
    [Arguments("delete")]
    [Arguments("create")]
    [Arguments("access")]
    public async Task SharePrimitiveOutputsStayProtectedAcrossEveryParser(string operation)
    {
        using var transport = Transport(new Server(operation == "list"
            ? "{\"secrets\":[" + ShareResponse(operation) + "],\"totalCount\":1}" : ShareResponse(operation)));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        SharedSecretMetadata metadata;
        if (operation == "list")
        {
            using var request = SharingOperations.ListShares(Org);
            metadata = (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, SharingOperations.ListSharesTarget(Org)))).Value.Items[0];
        }
        else if (operation is "create" or "access")
        {
            using var material = SecretMaterial.FromText("private-value");
            if (operation == "create")
            {
                using var request = SharingOperations.CreateShare(Org, "share", material, 5, ShareAudience.Organization);
                using var result = (await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, SharingOperations.CreateShareTarget(
                        Org, "share", material, 5, ShareAudience.Organization)), client.CreateReceipt(request))).Value;
                metadata = result.Metadata;
            }
            else
            {
                using var request = SharingOperations.AccessShare(Org, "share");
                using var result = (await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, SharingOperations.AccessShareTarget(Org, "share")), client.CreateReceipt(request))).Value;
                metadata = result.Metadata;
            }
        }
        else
        {
            using var request = operation == "get" ? SharingOperations.GetShare(Org, "share")
                : SharingOperations.DeleteShare(Org, "share");
            metadata = (await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(Org, resourceId: "share")),
                request.IsMutation ? client.CreateReceipt(request) : null)).Value;
        }
        await Assert.That(metadata.AllowExternalEmails.IsPresent).IsEqualTo(operation != "get");
        if (operation != "get") await Assert.That(metadata.AllowExternalEmails.Value).IsFalse();
        await Assert.That(metadata.ExpiresAfterViews.Value).IsEqualTo(1.5);
        await Assert.That(metadata.IdentityId.IsNull).IsTrue();
        await Assert.That(metadata.LastViewedAt.IsNull).IsTrue();
        await Assert.That(metadata.OrganizationId.IsNull).IsTrue();
        await Assert.That(metadata.CreatedAt.Value).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(metadata.UpdatedAt.Value).IsEqualTo("2026-01-01T00:00:00Z");
        await Assert.That(metadata.Type.Value).IsEqualTo("private-type");
        await Assert.That(metadata.UserId.Value).IsEqualTo(User);
        await Assert.That(metadata.IsAuthorizedUser.IsPresent).IsEqualTo(operation == "get");
        await Assert.That(metadata.IsPasswordProtected.IsPresent).IsEqualTo(operation == "get");
        if (operation == "get")
        {
            await Assert.That(metadata.IsAuthorizedUser.Value).IsFalse();
            await Assert.That(metadata.IsPasswordProtected.Value).IsTrue();
        }
        await Assert.That(metadata.OrganizationName.IsPresent).IsEqualTo(operation == "access");
        if (operation == "access") await Assert.That(metadata.OrganizationName.Value).IsEqualTo("private-org");
        await Assert.That(metadata.IncludesRecipientPolicy).IsFalse();
        await Assert.That(JsonSerializer.Serialize(metadata).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(metadata.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("absent")]
    [Arguments("null")]
    [Arguments("wrong-kind")]
    public async Task AuditRequiresUpdateTimestampWithoutDiscardingRowOrdinals(string shape)
    {
        const string valid = """
            {"id":"44444444-4444-4444-8444-444444444444","orgId":"11111111-1111-4111-8111-111111111111","createdAt":"2026-01-01T00:00:00Z",
            "updatedAt":"2026-01-02T00:00:00Z","actor":{"type":"identity"},
            "event":{"type":"get-secret","class":"data-access"}}
            """;
        var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(valid)!;
        if (shape == "absent") fields.Remove("updatedAt");
        else
        {
            using var malformed = JsonDocument.Parse(shape == "null" ? "null" : "false");
            fields["updatedAt"] = malformed.RootElement.Clone();
        }
        using var transport = Transport(new Server("{\"auditLogs\":[" + valid + "," +
            JsonSerializer.Serialize(fields) + "," + valid + "]}"));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = GovernanceOperations.ReadAudit(Org, DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddDays(1), offset: 7);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            GovernanceOperations.AuditReadTarget(Org, DateTimeOffset.UnixEpoch,
                DateTimeOffset.UnixEpoch.AddDays(1), offset: 7)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Value.Items.Count).IsEqualTo(3);
        for (int index = 0; index < 3; index++)
        {
            await Assert.That(result.Value.Items[index].Ordinal).IsEqualTo(7 + index);
            await Assert.That(result.Value.Items[index].Outcome.Status).IsEqualTo(
                index == 1 ? SecretStatus.Unknown : SecretStatus.Success);
        }
    }

    [Test]
    [Arguments("null")]
    [Arguments("\"private-metadata\"")]
    [Arguments("123")]
    public async Task AuditPrimitiveFieldsPreserveNullableValuesAndMalformedRowOrdinals(string value)
    {
        string row = """
            {"id":"44444444-4444-4444-8444-444444444444","orgId":"11111111-1111-4111-8111-111111111111","createdAt":"2026-01-01T00:00:00Z",
            "updatedAt":"2026-01-02T00:00:00Z","actor":{"type":"identity","metadata":{"unspecified":1}},
            "event":{"type":"get-secret","class":"data-access","metadata":{"unspecified":1}}}
            """;
        using var document = JsonDocument.Parse(row);
        var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(row)!;
        foreach (string field in new[] { "expiresAt", "ipAddress", "projectName", "userAgent", "userAgentType" })
        {
            using var fieldValue = JsonDocument.Parse(value);
            fields[field] = fieldValue.RootElement.Clone();
        }
        if (value == "\"private-metadata\"")
            fields["expiresAt"] = JsonSerializer.SerializeToElement("2026-01-03T03:04:05+02:30");
        using var transport = Transport(new Server("{\"auditLogs\":[" + JsonSerializer.Serialize(fields) + "," + row + "]}"));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = GovernanceOperations.ReadAudit(Org, DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddDays(1), offset: 7);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            GovernanceOperations.AuditReadTarget(Org, DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1), offset: 7)));
        var first = result.Value.Items[0];
        await Assert.That(first.Ordinal).IsEqualTo(7);
        await Assert.That(first.Outcome.Status).IsEqualTo(value == "123" ? SecretStatus.Unknown : SecretStatus.Success);
        await Assert.That(result.Value.Items[1].Ordinal).IsEqualTo(8);
        await Assert.That(result.Value.Items[1].Outcome.Value.ExpiresAt.IsPresent).IsFalse();
        if (value != "123")
        {
            var entry = first.Outcome.Value;
            await Assert.That(entry.ExpiresAt.IsPresent).IsTrue();
            await Assert.That(entry.ExpiresAt.IsNull).IsEqualTo(value == "null");
            if (value != "null") await Assert.That(entry.ExpiresAt.Value).IsEqualTo("2026-01-03T03:04:05+02:30");
            foreach (var field in new[] { entry.IpAddress, entry.ProjectName, entry.UserAgent, entry.UserAgentType })
            {
                await Assert.That(field.IsPresent).IsTrue();
                await Assert.That(field.IsNull).IsEqualTo(value == "null");
                if (value != "null") await Assert.That(field.Value).IsEqualTo("private-metadata");
            }
            await Assert.That(entry.UpdatedAt.Value).IsEqualTo("2026-01-02T00:00:00Z");
            await Assert.That(entry.IncludesActorMetadata).IsFalse();
            await Assert.That(entry.IncludesEventMetadata).IsFalse();
            await Assert.That(JsonSerializer.Serialize(entry).Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task NullableShareFieldsKeepOmissionDistinctAndRejectMalformedPrimitives()
    {
        foreach (string field in new[] { "allowExternalEmails", "expiresAfterViews", "identityId", "lastViewedAt",
            "orgId", "userId", "type", "createdAt", "updatedAt", "isAuthorizedUser", "isPasswordProtected", "orgName" })
        {
            bool access = field is "allowExternalEmails" or "orgName";
            var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(ShareResponse(access ? "access" : "get"))!;
            using var malformed = JsonDocument.Parse("[]");
            fields[field] = malformed.RootElement.Clone();
            using var transport = Transport(new Server(JsonSerializer.Serialize(fields)));
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
            if (access)
            {
                using var request = SharingOperations.AccessShare(Org, "share");
                var receipt = client.CreateReceipt(request);
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, SharingOperations.AccessShareTarget(Org, "share")), receipt);
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
            }
            else
            {
                using var request = SharingOperations.GetShare(Org, "share");
                var result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(request.OperationId, new(Org, resourceId: "share")));
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            }
        }
        var nullableFields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(ShareResponse("access"))!;
        using var nullValue = JsonDocument.Parse("null");
        foreach (string field in new[] { "allowExternalEmails", "expiresAfterViews", "userId" })
            nullableFields[field] = nullValue.RootElement.Clone();
        nullableFields.Remove("identityId");
        using var nullableTransport = Transport(new Server(JsonSerializer.Serialize(nullableFields)));
        var nullableClient = new ManagementClient(nullableTransport);
        var nullableAuthority = new ManagementAuthority(nullableClient.Authority, new Tokens(), Org);
        using var nullableRequest = SharingOperations.AccessShare(Org, "share");
        using var nullableResult = (await nullableClient.ExecuteAsync(nullableRequest, nullableAuthority,
            nullableAuthority.IssueGrant(nullableRequest.OperationId, SharingOperations.AccessShareTarget(Org, "share")),
            nullableClient.CreateReceipt(nullableRequest))).Value;
        var metadata = nullableResult.Metadata;
        await Assert.That(metadata.AllowExternalEmails.IsNull).IsTrue();
        await Assert.That(metadata.ExpiresAfterViews.IsNull).IsTrue();
        await Assert.That(metadata.UserId.IsNull).IsTrue();
        await Assert.That(metadata.IdentityId.IsPresent).IsFalse();
    }

    [Test]
    public async Task RecipientInputBudgetsRejectBeforeIdentitySelection()
    {
        using var material = SecretMaterial.FromText("private-value");
        foreach (string[] emails in new[] { Enumerable.Repeat("a@example.test", 101).ToArray(),
            new[] { "not-an-email" }, new[] { "Display Name <a@example.test>" }, new string[] { null! } })
            await Assert.That(() => SharingOperations.CreateShare(Org, "share", material, 5,
                ShareAudience.Organization, authorizedEmails: emails)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task RecipientPolicyCancellationRetainsDispatchEvidence(bool before)
    {
        var server = new Server(Share) { Hold = true };
        using var transport = Transport(server);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org);
        using var material = SecretMaterial.FromText("private-value");
        using var request = SharingOperations.CreateShare(Org, "share", material, 5,
            ShareAudience.Organization, allowExternalEmails: false, authorizedEmails: []);
        var target = SharingOperations.CreateShareTarget(Org, "share", material, 5,
            ShareAudience.Organization, allowExternalEmails: false, authorizedEmails: []);
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        var operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, target), receipt, cancel.Token).AsTask();
        if (!before)
        {
            await server.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
        await Assert.That(server.Dispatched).IsEqualTo(!before);
        await Assert.That(receipt.Evidence).IsEqualTo(before ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
    }

    private const string Share = """
        {"id":"share","orgId":null,"name":"private-name","expiresAt":"2026-01-02T00:00:00Z",
        "createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-01-01T00:00:00Z",
        "allowExternalEmails":false,"expiresAfterViews":1.5,"identityId":null,
        "lastViewedAt":null,"type":"private-type","userId":"33333333-3333-4333-8333-333333333333",
        "sharedSecretLink":"private-link","authorizedEmails":{"unspecified":true}}
        """;

    private static string ShareResponse(string operation)
    {
        var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Share)!;
        if (operation != "create") fields.Remove("sharedSecretLink");
        if (operation == "get")
        {
            fields.Remove("allowExternalEmails");
            fields.Remove("authorizedEmails");
            fields["isAuthorizedUser"] = JsonSerializer.SerializeToElement(false);
            fields["isPasswordProtected"] = JsonSerializer.SerializeToElement(true);
        }
        if (operation == "access")
        {
            fields["orgName"] = JsonSerializer.SerializeToElement("private-org");
            fields["secretValue"] = JsonSerializer.SerializeToElement("private-value");
        }
        return JsonSerializer.Serialize(fields);
    }

    private static ManagementTransport Transport(HttpMessageHandler handler) =>
        new(new Uri("https://management.test"), 1024 * 1024, null, false, handler);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(SecretMaterial.FromText("test-token"))));
        }
    }

    private sealed class Server(string response) : HttpMessageHandler
    {
        public bool Dispatched { get; private set; }
        public string? Body { get; private set; }
        public bool Hold { get; init; }
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Dispatched = true;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Entered.TrySetResult();
            if (Hold) await _release.Task.WaitAsync(cancellationToken);
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
