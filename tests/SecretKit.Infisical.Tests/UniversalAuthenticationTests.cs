using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class UniversalAuthenticationTests
{
    [Test]
    public async Task LoginHandoffPreservesRequestBoundAndExpiryAfterLoginDisposal()
    {
        var clock = new Clock();
        DateTimeOffset requestStarted = clock.GetUtcNow();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"),
            new Wire(onResponse: () => clock.Now = requestStarted.AddSeconds(20)), timeProvider: clock);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        using var login = (await client.LoginAsync("client-canary", secret, client.CreateReceipt())).Value;
        var evidence = login.BindLifetimeEvidence(PeriodicEvidence(login));
        clock.Now = requestStarted.AddSeconds(115);

        await using var session = new InfisicalPeriodicTokenSession(login, evidence,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5));
        login.Dispose();
        secret.Dispose();
        using var token = (await session.GetTokenAsync(CancellationToken.None)).Value;

        await Assert.That(login.RequestStartedAt).IsEqualTo(requestStarted);
        await Assert.That(evidence.OriginalIssuedAt).IsEqualTo(requestStarted);
        await Assert.That(token.ExpiresAt).IsEqualTo(requestStarted.AddSeconds(120));
        await Assert.That(token.Material.Reveal()).IsEqualTo("issued-canary");
        await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.RenewalDue);
        await Assert.That(session.LastRenewal).IsNull();
        clock.Now = requestStarted.AddSeconds(120);
        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(token.Material.Reveal()).IsEqualTo("issued-canary");
    }

    [Test]
    public async Task BoundPolicyCannotBeCrossWiredAcrossLoginsTokensOrOrigins()
    {
        var clock = new Clock();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), new Wire(), timeProvider: clock);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        using var first = (await client.LoginAsync("client-canary", secret, client.CreateReceipt())).Value;
        using var second = (await client.LoginAsync("client-canary", secret, client.CreateReceipt())).Value;
        var bound = first.BindLifetimeEvidence(PeriodicEvidence(first));

        await Assert.That(() => new InfisicalPeriodicTokenSession(second, bound,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5))).Throws<ArgumentException>();
        await Assert.That(() => second.BindLifetimeEvidence(bound)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalPeriodicTokenSession(first, PeriodicEvidence(first),
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5))).Throws<ArgumentException>();
        using var foreign = SecretMaterial.FromText("other-token");
        await Assert.That(() => new InfisicalPeriodicTokenSession(new("https://auth.test"), foreign, bound,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalPeriodicTokenSession(new("https://other.test"), first.Token.Material, bound,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5))).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("expiry")]
    [Arguments("issue")]
    [Arguments("maximum")]
    public async Task HandoffCannotReplaceReportedExpiryOrResetOriginalTiming(string mismatch)
    {
        var clock = new Clock();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), new Wire(), timeProvider: clock);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        using var login = (await client.LoginAsync("client-canary", secret, client.CreateReceipt())).Value;
        var evidence = new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = login.RequestStartedAt.AddSeconds(mismatch == "issue" ? 1 : 0),
            ExpiresAt = login.Token.ExpiresAt!.Value.AddSeconds(mismatch == "expiry" ? 1 : 0),
            Lifetime = InfisicalTokenLifetime.Periodic,
            Period = TimeSpan.FromSeconds(120),
            ReportedMaximumTtl = TimeSpan.FromSeconds(mismatch == "maximum" ? 31 : 30)
        };

        await Assert.That(() => login.BindLifetimeEvidence(evidence)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(InfisicalTokenLifetime.Unknown)]
    [Arguments(InfisicalTokenLifetime.Finite)]
    public async Task HandoffNeverInfersPeriodicPolicyFromMaximumTtl(InfisicalTokenLifetime lifetime)
    {
        var clock = new Clock();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), new Wire(), timeProvider: clock);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        using var login = (await client.LoginAsync("client-canary", secret, client.CreateReceipt())).Value;
        var evidence = login.BindLifetimeEvidence(new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = login.RequestStartedAt,
            ExpiresAt = login.Token.ExpiresAt!.Value,
            Lifetime = lifetime,
            ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL)
        });
        await using var session = new InfisicalPeriodicTokenSession(login, evidence,
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5));

        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsNull();
    }

    private static InfisicalTokenLifetimeEvidence PeriodicEvidence(InfisicalUniversalLogin login) => new()
    {
        OriginalIssuedAt = login.RequestStartedAt,
        ExpiresAt = login.Token.ExpiresAt!.Value,
        Lifetime = InfisicalTokenLifetime.Periodic,
        Period = TimeSpan.FromSeconds(120),
        ReportedMaximumTtl = TimeSpan.FromSeconds(login.AccessTokenMaxTTL)
    };

    [Test]
    public async Task ExplicitLoginProtectsMaterialAndPreservesReportedExpiryWithoutFiniteCap()
    {
        var handler = new Wire();
        var clock = new Clock();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), handler, timeProvider: clock);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        var receipt = client.CreateReceipt();
        var result = await client.LoginAsync("client-canary", secret, receipt, "selected-org");
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var login = result.Value;
        await Assert.That(login.ExpiresIn).IsEqualTo(120d);
        await Assert.That(login.AccessTokenMaxTTL).IsEqualTo(30d);
        await Assert.That(login.Token.ExpiresAt).IsEqualTo(clock.GetUtcNow().AddSeconds(120));
        using var copy = login.Token.Material.Copy();
        login.Dispose();
        await Assert.That(copy.Reveal()).IsEqualTo("issued-canary");
        await Assert.That(secret.Reveal()).IsEqualTo("bootstrap-canary");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(login).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(handler.Observed).IsTrue();
        var replay = await client.LoginAsync("client-canary", secret, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(handler.Requests).IsEqualTo(1);
    }

    [Test]
    [Arguments("lost")]
    [Arguments("malformed")]
    [Arguments("duplicate")]
    [Arguments("extra")]
    [Arguments("denied")]
    [Arguments("oversize")]
    public async Task FailedResponsesRetainEvidenceWithoutReplay(string mode)
    {
        var handler = new Wire(mode);
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), handler);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        var receipt = client.CreateReceipt();
        var result = await client.LoginAsync("client-canary", secret, receipt);
        await Assert.That(result.Status).IsEqualTo(mode == "denied" ? SecretStatus.Denied : SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(mode == "denied" ? DispatchEvidence.Rejected : DispatchEvidence.PossiblyDispatched);
        await Assert.That(handler.Requests).IsEqualTo(1);
    }

    [Test]
    public async Task CanceledBeforeSendAndForeignReceiptNeverDispatch()
    {
        var handler = new Wire();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), handler);
        using var other = new InfisicalUniversalAuthentication(new("https://other.test"), new Wire());
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        var result = await client.LoginAsync("client-canary", secret, other.CreateReceipt());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();
        await Assert.That(async () => await client.LoginAsync("client-canary", secret,
            client.CreateReceipt(), cancellationToken: canceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(handler.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task CommittedCancellationRetainsReceiptAndConcurrentAttemptCannotReplay()
    {
        var handler = new CommittedWire();
        using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), handler);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        using var cancellation = new CancellationTokenSource();
        var receipt = client.CreateReceipt();
        Task observed = handler.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task<SecretOutcome<InfisicalUniversalLogin>> pending = client.LoginAsync("client-canary", secret,
            receipt, cancellationToken: cancellation.Token).AsTask();
        await observed;
        var replay = await client.LoginAsync("client-canary", secret, receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        cancellation.Cancel();
        await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(handler.Requests).IsEqualTo(1);
        await Assert.That(secret.Reveal()).IsEqualTo("bootstrap-canary");
    }

    [Test]
    public async Task FixedOriginAndHostTransportRulesRejectCredentialEgress()
    {
        await Assert.That(() => new InfisicalUniversalAuthentication(new("https://auth.test/redirect"))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalUniversalAuthentication(new("http://auth.test"))).Throws<ArgumentException>();
        using var unsafeTransport = new SocketsHttpHandler();
        using var explicitHost = new InfisicalUniversalAuthentication(new("http://auth.test"),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(unsafeTransport) });
        using var safeTransport = new SocketsHttpHandler
        { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null };
        using (var client = new InfisicalUniversalAuthentication(new("https://auth.test"),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(safeTransport) }))
            await Assert.That(client.ToString()).IsEqualTo("[InfisicalUniversalAuthentication]");
        // Disposal of the client did not dispose or freeze its host-owned handler.
        safeTransport.MaxConnectionsPerServer = 3;
        await Assert.That(safeTransport.MaxConnectionsPerServer).IsEqualTo(3);
    }

    private sealed class CommittedWire : HttpMessageHandler
    {
        internal TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _never = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal int Requests { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            await request.Content!.ReadAsStringAsync(cancellationToken);
            Committed.TrySetResult();
            await _never.Task.WaitAsync(cancellationToken);
            throw new InvalidOperationException("The response barrier must be canceled.");
        }
    }

    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class Wire(string mode = "success", Action? onResponse = null) : HttpMessageHandler
    {
        public bool Observed { get; private set; }
        public int Requests { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://auth.test/api/v1/auth/universal-auth/login");
            await Assert.That(request.Headers.Authorization is null).IsTrue();
            string text = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var body = JsonDocument.Parse(text);
            await Assert.That(body.RootElement.GetProperty("clientId").GetString()).IsEqualTo("client-canary");
            await Assert.That(body.RootElement.GetProperty("clientSecret").GetString()).IsEqualTo("bootstrap-canary");
            if (body.RootElement.TryGetProperty("organizationSlug", out var slug))
                await Assert.That(slug.GetString()).IsEqualTo("selected-org");
            Observed = true;
            if (mode == "lost") throw new HttpRequestException("private-canary");
            onResponse?.Invoke();
            string response = mode switch
            {
                "malformed" => """{"accessToken":"issued-canary","expiresIn":0,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""",
                "duplicate" => """{"accessToken":"issued-canary","accessToken":"other","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""",
                "extra" => """{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer","notDeclared":"private-extra"}""",
                "oversize" => new string('x', 1024 * 1024 + 1),
                _ => """{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}"""
            };
            return new(mode == "denied" ? HttpStatusCode.Unauthorized : HttpStatusCode.OK)
            { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
