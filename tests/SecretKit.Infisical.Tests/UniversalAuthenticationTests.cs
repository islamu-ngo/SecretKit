using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class UniversalAuthenticationTests
{
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
        await Assert.That(() => new InfisicalUniversalAuthentication(new("https://auth.test"), unsafeTransport)).Throws<ArgumentException>();
        using var safeTransport = new SocketsHttpHandler
        { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null };
        using (var client = new InfisicalUniversalAuthentication(new("https://auth.test"), safeTransport))
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
        public override DateTimeOffset GetUtcNow() => new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class Wire(string mode = "success") : HttpMessageHandler
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
