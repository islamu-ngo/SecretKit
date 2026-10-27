using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ManagementBoundaryTests
{
    private const string GroupId = "22222222-2222-4222-8222-222222222222";
    private const string IdentityId = "33333333-3333-4333-8333-333333333333";
    private const string OtherIdentityId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    private const string AuditId = "44444444-4444-4444-8444-444444444444";
    private const string OtherAuditId = "55555555-5555-4555-8555-555555555555";
    private const string OrgId = "11111111-1111-4111-8111-111111111111";
    private const string ForeignId = "99999999-9999-4999-8999-999999999999";

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task SafeManagementTransportValidatesPrivateIssuerAndHostname(bool trustRoot, bool wrongHostname)
    {
        using RSA rootKey = RSA.Create(2048);
        var rootRequest = new CertificateRequest("CN=Management Test Issuer", rootKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 root = rootRequest.CreateSelfSigned(now.AddDays(-1), now.AddDays(2));
        using RSA serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=Management Loopback", serverKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        if (wrongHostname) names.AddDnsName("unselected.invalid");
        else names.AddIpAddress(IPAddress.Loopback);
        serverRequest.CertificateExtensions.Add(names.Build());
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        serverRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
        using X509Certificate2 issued = serverRequest.Create(root, now.AddHours(-1), now.AddDays(1),
            RandomNumberGenerator.GetBytes(16));
        using X509Certificate2 certificate = issued.CopyWithPrivateKey(serverKey);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"https://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Task<TcpClient> accepted = listener.AcceptTcpClientAsync(deadline.Token).AsTask();
        Task<bool> server = ReceiveAsync();
        try
        {
            using var transport = new ManagementTransport(origin, new()
            {
                Transport = trustRoot
                    ? InfisicalTransportOptions.SafeWithPrivateTrust(root)
                    : InfisicalTransportOptions.SafeDefault
            });
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
            using var request = ScopedAccessOperations.GetGroup(OrgId, GroupId);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(OrgId, resourceId: GroupId)),
                cancellationToken: deadline.Token);
            await Assert.That(await server.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(trustRoot && !wrongHostname);
            // An empty response is deliberately not native success evidence.
            await Assert.That(result.IsSuccess).IsFalse();
        }
        finally
        {
            await deadline.CancelAsync();
            listener.Stop();
            await server.WaitAsync(TimeSpan.FromSeconds(10));
        }

        async Task<bool> ReceiveAsync()
        {
            try
            {
                using TcpClient socket = await accepted;
                await using var tls = new SslStream(socket.GetStream());
                await tls.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = certificate
                }, deadline.Token);
                using var reader = new StreamReader(tls, Encoding.UTF8, false, 1024, leaveOpen: true);
                string? start = await reader.ReadLineAsync(deadline.Token);
                bool credential = false;
                while (await reader.ReadLineAsync(deadline.Token) is { Length: > 0 } header)
                    credential |= header.StartsWith("Authorization: Bearer ", StringComparison.OrdinalIgnoreCase);
                await tls.WriteAsync(Encoding.ASCII.GetBytes(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}"),
                    deadline.Token);
                return credential && start == $"GET /api/v1/groups/{GroupId} HTTP/1.1";
            }
            catch (AuthenticationException) { return false; }
            catch (IOException) { return false; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { return false; }
        }
    }

    [Test]
    [Arguments("infisical.get.v1.app.connections", "/api/v1/app-connections")]
    [Arguments("infisical.get.v1.app.connections.1password", "/api/v1/app-connections/1password")]
    [Arguments("infisical.get.v1.secret.syncs.azure.key.vault", "/api/v1/secret-syncs/azure-key-vault")]
    public async Task RetiredConnectorRoutesRejectBeforeTokenAcquisition(string operationId, string path)
    {
        using var transport = Transport(new Backend());
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Forbidden = true };
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var request = new ManagementRequest<GroupMetadata>(operationId, HttpMethod.Get, path,
            new(OrgId), null, _ => throw new InvalidOperationException("Retired routes must not parse responses."),
            mutation: false);

        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(operationId, new(OrgId)));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.ContractNotEstablished);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("operation")]
    [Arguments("organization")]
    [Arguments("target")]
    [Arguments("principal")]
    [Arguments("client")]
    public async Task IndependentGrantsRejectMismatchesBeforeTokenAcquisition(string mismatch)
    {
        var backend = new Backend();
        using ManagementTransport transport = Transport(backend);
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Forbidden = true };
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var request = ScopedAccessOperations.DeleteGroup(OrgId, GroupId);
        ManagementReceipt receipt = client.CreateReceipt(request);
        ManagementGrant? grant = mismatch switch
        {
            "missing" => null,
            "operation" => authority.IssueGrant("infisical.get.v1.groups.by.id", new(OrgId, resourceId: GroupId)),
            "organization" => new ManagementAuthority(client.Authority, tokens, ForeignId)
                .IssueGrant(request.OperationId, new(ForeignId, resourceId: GroupId)),
            "target" => authority.IssueGrant(request.OperationId, new(OrgId, resourceId: ForeignId)),
            "principal" => new ManagementAuthority(client.Authority, tokens, OrgId)
                .IssueGrant(request.OperationId, new(OrgId, resourceId: GroupId)),
            "client" => new ManagementAuthority(new SecretAuthority(), tokens, OrgId)
                .IssueGrant(request.OperationId, new(OrgId, resourceId: GroupId)),
            _ => throw new InvalidOperationException()
        };

        SecretOutcome<GroupMetadata> result = await client.ExecuteAsync(request, authority, grant, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Groups.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ExactScopeNeverTreatsNullProjectAsWildcard()
    {
        using var transport = Transport(new Backend());
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        await Assert.That(() => authority.IssueGrant("op", new(OrgId, "project"))).Throws<ArgumentException>();
    }

    [Test]
    public async Task GroupMutationAndReadObserveBackendStateAndOwnedToken()
    {
        var backend = new Backend();
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var create = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        ManagementReceipt receipt = client.CreateReceipt(create);
        var created = await client.ExecuteAsync(create, authority,
            authority.IssueGrant(create.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group")), receipt);
        using var get = ScopedAccessOperations.GetGroup(OrgId, backend.CreatedGroupId);
        var observed = await client.ExecuteAsync(get, authority,
            authority.IssueGrant(get.OperationId, new(OrgId, resourceId: backend.CreatedGroupId)));
        await Assert.That(created.Value.Id).IsEqualTo(backend.CreatedGroupId);
        await Assert.That(created.Value.Slug).IsEqualTo("group");
        await Assert.That(created.Value.Id).IsNotEqualTo(created.Value.Slug);
        await Assert.That(created.Value.Name).IsEqualTo("first");
        await Assert.That(observed.Value.Name).IsEqualTo("first");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(backend.Groups[backend.CreatedGroupId]).IsEqualTo("first");
        await Assert.That(() => tokens.LastMaterial!.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(403, SecretStatus.Denied, DispatchEvidence.Rejected)]
    [Arguments(202, SecretStatus.Pending, DispatchEvidence.Pending)]
    [Arguments(409, SecretStatus.Conflict, DispatchEvidence.Conflict)]
    public async Task NativeFailureEvidenceDoesNotPretendMutationApplied(int status, SecretStatus outcome, DispatchEvidence evidence)
    {
        var backend = new Backend { MutationStatus = status };
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        using var create = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(create);
        var result = await client.ExecuteAsync(create, authority,
            authority.IssueGrant(create.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group")), receipt);
        await Assert.That(result.Status).IsEqualTo(outcome);
        await Assert.That(receipt.Evidence).IsEqualTo(evidence);
        await Assert.That(backend.Groups.Count).IsEqualTo(0);
    }

    [Test]
    public async Task LostCommitResponseAndReplayPreserveActualState()
    {
        var backend = new Backend { DropAfterCommit = true };
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        using var create = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(create);
        var grant = authority.IssueGrant(create.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group"));

        var result = await client.ExecuteAsync(create, authority, grant, receipt);
        var replay = await client.ExecuteAsync(create, authority, grant, receipt);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Groups[backend.CreatedGroupId]).IsEqualTo("first");
        await Assert.That(backend.Revision).IsEqualTo(1);
    }

    [Test]
    public async Task ConcurrentSubmissionOfOneReceiptCommitsOnlyOnce()
    {
        var backend = new Backend();
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var tokens = new RendezvousTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var request = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(request);
        var grant = authority.IssueGrant(request.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group"));
        Task<SecretOutcome<GroupMetadata>> first = client.ExecuteAsync(request, authority, grant, receipt).AsTask();
        Task<SecretOutcome<GroupMetadata>> second = client.ExecuteAsync(request, authority, grant, receipt).AsTask();
        await tokens.BothEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        tokens.Release.SetResult();
        SecretOutcome<GroupMetadata>[] outcomes = await Task.WhenAll(first, second);
        await Assert.That(outcomes.Count(result => result.Status == SecretStatus.Success)).IsEqualTo(1);
        await Assert.That(outcomes.Count(result => result.Status == SecretStatus.Invalid)).IsEqualTo(1);
        await Assert.That(backend.Revision).IsEqualTo(1);
        await Assert.That(backend.Groups[backend.CreatedGroupId]).IsEqualTo("first");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CancellationRetainsDispatchBoundaryEvidence(bool before)
    {
        var backend = new Backend { HoldAfterCommit = !before };
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Forbidden = before };
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var create = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(create);
        using var cancel = new CancellationTokenSource();
        if (before) cancel.Cancel();
        Task<SecretOutcome<GroupMetadata>> operation = client.ExecuteAsync(create, authority,
            authority.IssueGrant(create.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group")), receipt, cancel.Token).AsTask();
        if (!before)
        {
            await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
        }
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(before ? DispatchEvidence.NotDispatched : DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Groups.Count).IsEqualTo(before ? 0 : 1);
        await Assert.That(tokens.Acquired).IsEqualTo(!before);
    }

    [Test]
    public async Task CancelDuringTokenAcquisitionIsNotDispatch()
    {
        var backend = new Backend();
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var tokens = new BlockingTokens();
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var request = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        Task<SecretOutcome<GroupMetadata>> operation = client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group")), receipt, cancel.Token).AsTask();
        await tokens.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancel.Cancel();
        await Assert.That(async () => await operation).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Groups.Count).IsEqualTo(0);
    }

    [Test]
    public async Task WrongReturnedOrganizationDoesNotUndoAnAlreadyCommittedMutation()
    {
        var backend = new Backend { ReturnedOrganization = ForeignId };
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        using var request = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "first", "group")), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Groups[backend.CreatedGroupId]).IsEqualTo("first");
    }

    [Test]
    public async Task ReceiptCannotMoveBetweenRequestsEvenForSameResource()
    {
        using var transport = Transport(new Backend());
        var client = new ManagementClient(transport);
        var tokens = new Tokens { Forbidden = true };
        var authority = new ManagementAuthority(client.Authority, tokens, OrgId);
        using var first = ScopedAccessOperations.CreateGroup(OrgId, "first", "group");
        using var second = ScopedAccessOperations.CreateGroup(OrgId, "second", "group");
        var receipt = client.CreateReceipt(first);
        var result = await client.ExecuteAsync(second, authority,
            authority.IssueGrant(second.OperationId, ScopedAccessOperations.GroupCreationTarget(OrgId, "second", "group")), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
    }

    [Test]
    public async Task StreamingResponseBudgetAndDuplicateScopesFailClosed()
    {
        foreach (string response in new[]
        {
            "{\"id\":\"" + GroupId + "\",\"name\":\"" + new string('x', 2048) + "\",\"orgId\":\"" + OrgId + "\"}",
            "{\"id\":\"" + GroupId + "\",\"name\":\"first\",\"slug\":\"group\",\"orgId\":\"" + ForeignId + "\",\"orgId\":\"" + OrgId + "\",\"createdAt\":\"now\",\"updatedAt\":\"now\"}"
        })
        {
            using var transport = Transport(new FixedResponse(response), 1024);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
            using var request = ScopedAccessOperations.GetGroup(OrgId, GroupId);
            var result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, new(OrgId, resourceId: GroupId)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        }
    }

    [Test]
    public async Task AuditPartialRowsKeepOrdinalsAndNeverReturnWrongScopePayload()
    {
        string body = JsonSerializer.Serialize(new
        {
            auditLogs = new[]
            {
                Audit(AuditId, OrgId, "project"),
                Audit(ForeignId, ForeignId, "project"),
                Audit(OtherAuditId, OrgId, "other-project")
            }
        });
        using var transport = Transport(new FixedResponse(body));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId, "project");
        using var request = GovernanceOperations.ReadAudit(OrgId, DateTimeOffset.UnixEpoch,
            DateTimeOffset.UnixEpoch.AddDays(1), "project", offset: 7);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, GovernanceOperations.AuditReadTarget(OrgId,
                DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1), "project", offset: 7)));
        await Assert.That(result.Value.Items.Select(item => item.Ordinal).ToArray()).IsEquivalentTo(new[] { 7, 8, 9 });
        await Assert.That(result.Value.Items[0].Outcome.Value.Id).IsEqualTo(AuditId);
        await Assert.That(result.Value.Items[1].Outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(result.Value.Items[2].Outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(JsonSerializer.Serialize(result).Contains(ForeignId, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task SharedMaterialIsOwnedAndAccessConsumesExactlyOneView()
    {
        string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var backend = new ShareBackend(secret);
        using var transport = Transport(backend);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        using var request = SharingOperations.AccessShare(OrgId, "share");
        var grant = authority.IssueGrant(request.OperationId, SharingOperations.AccessShareTarget(OrgId, "share"));
        var firstReceipt = client.CreateReceipt(request);
        using SharedValue first = (await client.ExecuteAsync(request, authority, grant, firstReceipt)).Value;
        using SharedValue second = (await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request))).Value;
        first.Dispose();
        await Assert.That(second.Material.Reveal()).IsEqualTo(secret);
        await Assert.That(() => first.Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(backend.Views).IsEqualTo(2);
        await Assert.That(firstReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(second).Contains(secret, StringComparison.Ordinal)).IsFalse();
        await Assert.That(second.ToString().Contains(secret, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task RequestMaterialCopyAndAllProtectedSurfacesStayRedacted()
    {
        string secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        using SecretMaterial material = SecretMaterial.FromText(secret);
        using var request = SharingOperations.CreateShare("sensitive-org", "sensitive-name", material, 5, ShareAudience.Organization);
        material.Dispose();
        byte[] body = request.CopyBody()!;
        try
        {
            using JsonDocument parsed = JsonDocument.Parse(body);
            await Assert.That(parsed.RootElement.GetProperty("secretValue").GetString()).IsEqualTo(secret);
            await Assert.That(parsed.RootElement.GetProperty("expiresIn").GetString()).IsEqualTo("5m");
        }
        finally { Array.Clear(body); }
        await Assert.That(JsonSerializer.Serialize(request).Contains("sensitive", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(request.Target)).IsEqualTo("{}");
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task InputAndPaginationLimitsRejectBeforeAnyIdentityIsSelected()
    {
        await Assert.That(() => ScopedAccessOperations.ListGroupUsers(OrgId, "group", limit: 101)).Throws<ArgumentException>();
        await Assert.That(() => ScopedAccessOperations.CreateGroup(OrgId, new string('x', 256))).Throws<ArgumentException>();
        await Assert.That(() => SharingOperations.ListShares(OrgId, offset: 101)).Throws<ArgumentException>();
        using SecretMaterial large = SecretMaterial.FromText(new string('x', 10001));
        await Assert.That(() => SharingOperations.CreateShare(OrgId, "share", large, 5, ShareAudience.Organization)).Throws<ArgumentException>();
        var metadata = Enumerable.Range(0, 100).Select(i => new IdentityAttribute(i.ToString(), new string('x', 4096))).ToArray();
        await Assert.That(() => IdentityOperations.CreateOrganizationIdentity(OrgId, "identity", "member", metadata: metadata))
            .Throws<ArgumentException>();
    }

    [Test]
    public async Task FixedOriginRejectsUnsafeEndpointsAndCoordinatesRemainEscaped()
    {
        foreach (string address in new[] { "http://example.test", "https://example.test/path", "https://user@example.test", "https://example.test/?a=b" })
        {
            await Assert.That(() => new ManagementTransport(new Uri(address))).Throws<ArgumentException>();
        }
        using var request = ScopedAccessOperations.GetGroup(OrgId, "not/a?query#fragment");
        await Assert.That(request.Path).IsEqualTo("/api/v1/groups/not%2Fa%3Fquery%23fragment");
    }

    [Test]
    public async Task PaginationIsExplicitAndOverfullPagesAreNotTruncatedSuccess()
    {
        string body = JsonSerializer.Serialize(new
        {
            identities = new[] { new { id = IdentityId, name = "One" }, new { id = OtherIdentityId, name = "Two" } }
        });
        using var transport = Transport(new FixedResponse(body));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), OrgId);
        using var limited = ScopedAccessOperations.AvailableIdentities(OrgId, limit: 1);
        var invalid = await client.ExecuteAsync(limited, authority,
            authority.IssueGrant(limited.OperationId, ScopedAccessOperations.AvailableIdentityListTarget(OrgId, limit: 1)));
        await Assert.That(invalid.Status).IsEqualTo(SecretStatus.Unknown);
        using var page = ScopedAccessOperations.AvailableIdentities(OrgId, limit: 2);
        var result = await client.ExecuteAsync(page, authority, authority.IssueGrant(page.OperationId,
            ScopedAccessOperations.AvailableIdentityListTarget(OrgId, limit: 2)));
        await Assert.That(result.Value.IsComplete).IsFalse();
        await Assert.That(result.Value.NextOffset).IsEqualTo(2);
    }

    private static object Audit(string id, string org, string project) => new
    {
        id,
        orgId = org,
        projectId = project,
        createdAt = "1970-01-01T00:00:00Z",
        updatedAt = "1970-01-01T00:00:00Z",
        actor = new { type = "identity" },
        @event = new { type = "create-secret", @class = "management" }
    };

    private static ManagementTransport Transport(HttpMessageHandler backend, int limit = 1024 * 1024) =>
        new(new Uri("https://management.test"), limit, null, false, backend);

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Forbidden { get; init; }
        public bool Acquired { get; private set; }
        public SecretMaterial? LastMaterial { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            if (Forbidden) throw new InvalidOperationException("Unexpected identity acquisition.");
            Acquired = true;
            LastMaterial = SecretMaterial.FromText(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)));
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(LastMaterial)));
        }
    }

    private sealed class BlockingTokens : IInfisicalTokenSource
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _blocked = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Entered.SetResult();
            await _blocked.Task.WaitAsync(cancellationToken);
            throw new InvalidOperationException("Unreachable token completion.");
        }
    }

    private sealed class RendezvousTokens : IInfisicalTokenSource
    {
        private int _entered;
        public TaskCompletionSource BothEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Increment(ref _entered) == 2) BothEntered.SetResult();
            await Release.Task.WaitAsync(cancellationToken);
            return SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(
                Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)))));
        }
    }

    private sealed class Backend : HttpMessageHandler
    {
        public Dictionary<string, string> Groups { get; } = new(StringComparer.Ordinal);
        public string CreatedGroupId { get; } = Guid.NewGuid().ToString("D");
        private string? _slug;
        public int Revision { get; private set; }
        public int MutationStatus { get; init; } = 200;
        public bool DropAfterCommit { get; init; }
        public bool HoldAfterCommit { get; init; }
        public string ReturnedOrganization { get; init; } = OrgId;
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _hold = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.Authorization?.Scheme != "Bearer") return Json(401, new { });
            string id = request.RequestUri!.Segments[^1];
            if (request.Method != HttpMethod.Get)
            {
                if (MutationStatus != 200) return Json(MutationStatus, new { });
                using JsonDocument body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(cancellationToken));
                id = CreatedGroupId;
                _slug = body.RootElement.GetProperty("slug").GetString()!;
                Groups[id] = body.RootElement.GetProperty("name").GetString()!;
                Revision++;
                Committed.TrySetResult();
                if (DropAfterCommit) throw new HttpRequestException("Provider text must not escape.");
                if (HoldAfterCommit) await _hold.Task.WaitAsync(cancellationToken);
            }
            if (!Groups.TryGetValue(id, out string? name)) return Json(404, new { });
            var result = new Dictionary<string, object?>
            {
                ["id"] = id,
                ["name"] = name,
                ["slug"] = _slug,
                ["orgId"] = ReturnedOrganization,
                ["createdAt"] = "2026-01-01T00:00:00Z",
                ["updatedAt"] = "2026-01-01T00:00:00Z"
            };
            if (request.Method == HttpMethod.Get) result["customRoleSlug"] = null;
            return Json(200, result);
        }
    }

    private sealed class ShareBackend(string value) : HttpMessageHandler
    {
        public int Views { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Post || request.RequestUri!.AbsolutePath != "/api/v1/shared-secrets/share/access")
                return Task.FromResult(Json(400, new { }));
            Views++;
            return Task.FromResult(Json(200, new
            {
                id = "share",
                orgId = OrgId,
                expiresAt = "2026-12-01T00:00:00Z",
                createdAt = "2026-10-10T00:00:00Z",
                updatedAt = "2026-10-10T00:00:00Z",
                secretValue = value
            }));
        }
    }

    private sealed class FixedResponse(string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StreamContent(new NonSeekingStream(Encoding.UTF8.GetBytes(body)))
            });
    }

    private sealed class NonSeekingStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }

    private static HttpResponseMessage Json(int status, object body) =>
        new((HttpStatusCode)status) { Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json") };
}
