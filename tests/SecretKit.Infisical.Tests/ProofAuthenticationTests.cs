using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class ProofAuthenticationTests
{
    private const string Identity = "a15371c1-1f98-4d08-a54e-5e8d76fbe9c2";
    private const string Success = """{"accessToken":"issued-canary","expiresIn":120.5,"accessTokenMaxTTL":30.25,"tokenType":"Bearer"}""";

    [Test]
    [Arguments("alicloud")]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("jwt")]
    [Arguments("kubernetes")]
    [Arguments("ldap")]
    [Arguments("oci")]
    [Arguments("oidc")]
    [Arguments("spiffe")]
    [Arguments("tls-cert")]
    public async Task NamedProofExchangesBindExactRouteFieldsAndReportedExpiry(string strategy)
    {
        using var source = SecretMaterial.FromText("proof-canary");
        using var proof = Create(strategy, source, "selected-org");
        source.Dispose();
        var wire = new Wire(async request =>
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo($"https://auth.test/api/v1/auth/{strategy}-auth/login");
            await Assert.That(request.Headers.Authorization is null).IsTrue();
            await Assert.That(request.Headers.Contains("X-Client-Cert")).IsFalse();
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var body = json.RootElement;
            await Assert.That(body.GetProperty("identityId").GetString()).IsEqualTo(Identity);
            await Assert.That(body.GetProperty("organizationSlug").GetString()).IsEqualTo("selected-org");
            string[] fields = strategy switch
            {
                "alicloud" => ["identityId", "organizationSlug", "AccessKeyId", "Action", "Format", "Signature",
                    "SignatureMethod", "SignatureNonce", "SignatureVersion", "Timestamp", "Version"],
                "aws" => ["identityId", "organizationSlug", "iamRequestBody", "iamRequestHeaders"],
                "ldap" => ["identityId", "organizationSlug", "username", "password"],
                "oci" => ["identityId", "organizationSlug", "headers", "userOcid"],
                "tls-cert" => ["identityId", "organizationSlug"],
                _ => ["identityId", "organizationSlug", "jwt"]
            };
            await Assert.That(body.EnumerateObject().Select(p => p.Name).Order().ToArray()).IsEquivalentTo(fields.Order().ToArray());
            if (strategy == "alicloud")
            {
                await Assert.That(body.GetProperty("Action").GetString()).IsEqualTo("GetCallerIdentity");
                await Assert.That(body.GetProperty("Format").GetString()).IsEqualTo("JSON");
                await Assert.That(body.GetProperty("SignatureMethod").GetString()).IsEqualTo("HMAC-SHA1");
                await Assert.That(body.GetProperty("SignatureVersion").GetString()).IsEqualTo("1.0");
                foreach (string field in new[] { "AccessKeyId", "Signature", "SignatureNonce" })
                    await Assert.That(body.GetProperty(field).GetString()).IsEqualTo("proof-canary");
                await Assert.That(body.GetProperty("Timestamp").GetString()).IsEqualTo("2026-10-10T12:00:00Z");
                await Assert.That(body.GetProperty("Version").GetString()).IsEqualTo("2015-04-01");
            }
            else if (strategy == "aws")
            {
                await Assert.That(body.GetProperty("iamRequestBody").GetString()).IsEqualTo("proof-canary");
                await Assert.That(body.GetProperty("iamRequestHeaders").GetString()).IsEqualTo("proof-canary");
            }
            else if (strategy == "ldap")
            {
                await Assert.That(body.GetProperty("username").GetString()).IsEqualTo("user-canary");
                await Assert.That(body.GetProperty("password").GetString()).IsEqualTo("proof-canary");
            }
            else if (strategy == "oci")
            {
                await Assert.That(body.GetProperty("userOcid").GetString()).IsEqualTo("user-canary");
                var headers = body.GetProperty("headers");
                await Assert.That(headers.EnumerateObject().Select(p => p.Name).Order().ToArray()).IsEquivalentTo(new[] { "authorization", "host" });
                await Assert.That(headers.GetProperty("authorization").GetString()).IsEqualTo("proof-canary");
                await Assert.That(headers.GetProperty("host").GetString()).IsEqualTo("signed.test");
            }
            else if (strategy != "tls-cert")
                await Assert.That(body.GetProperty("jwt").GetString()).IsEqualTo("proof-canary");
            return Response(Success);
        });
        var clock = new Clock();
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire, timeProvider: clock);
        var receipt = client.CreateReceipt();
        var outcome = await client.LoginAsync(proof, receipt);
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        using var result = outcome.Value;
        await Assert.That(result.ExpiresIn).IsEqualTo(120.5d);
        await Assert.That(result.AccessTokenMaxTTL).IsEqualTo(30.25d);
        await Assert.That(result.Token.ExpiresAt).IsEqualTo(clock.GetUtcNow().AddSeconds(120.5));
        using var copy = result.Token.Material.Copy();
        result.Dispose();
        await Assert.That(copy.Reveal()).IsEqualTo("issued-canary");
        await Assert.That(() => result.Token.Material.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(JsonSerializer.Serialize(proof).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result).Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(proof.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That((await client.LoginAsync(proof, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(1);
        using var extraClient = new InfisicalProofAuthentication(new("https://auth.test"),
            new Wire(_ => Task.FromResult(Response(Success[..^1] + ""","notDeclared":"private-extra"}"""))));
        var extraReceipt = extraClient.CreateReceipt();
        var extra = await extraClient.LoginAsync(proof, extraReceipt);
        if (extra.IsSuccess) extra.Value.Dispose();
        await Assert.That(extra.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(extraReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await extraClient.LoginAsync(proof, extraReceipt)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments("aws", 0)]
    [Arguments("oci", 0)]
    [Arguments("oci", 1)]
    [Arguments("oci", 2)]
    [Arguments("oci", 3)]
    public async Task OptionalSignedFieldsPreserveOmissionAndBothOciDates(string strategy, int dates)
    {
        using var source = SecretMaterial.FromText("proof-canary");
        using var proof = strategy == "aws"
            ? InfisicalLoginProof.Aws(Identity, source, source, iamHttpRequestMethod: "POST")
            : InfisicalLoginProof.Oci(Identity, "user", source, "signed.test",
                date: (dates & 1) != 0 ? "signed-date" : null, xDate: (dates & 2) != 0 ? "signed-x-date" : null);
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), new Wire(async request =>
        {
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var body = json.RootElement;
            await Assert.That(body.TryGetProperty("organizationSlug", out _)).IsFalse();
            if (strategy == "aws")
                await Assert.That(body.GetProperty("iamHttpRequestMethod").GetString()).IsEqualTo("POST");
            else
            {
                var headers = body.GetProperty("headers");
                await Assert.That(headers.TryGetProperty("date", out _)).IsEqualTo((dates & 1) != 0);
                await Assert.That(headers.TryGetProperty("x-date", out _)).IsEqualTo((dates & 2) != 0);
                if ((dates & 1) != 0) await Assert.That(headers.GetProperty("date").GetString()).IsEqualTo("signed-date");
                if ((dates & 2) != 0) await Assert.That(headers.GetProperty("x-date").GetString()).IsEqualTo("signed-x-date");
            }
            return Response(Success);
        }));
        var outcome = await client.LoginAsync(proof, client.CreateReceipt());
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        outcome.Value.Dispose();
    }

    [Test]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":0,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":-1,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":1e300,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":"120","accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":-1,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":1e400,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":7}""")]
    [Arguments("""{"accessToken":null,"expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"bad\ncanary","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","accessToken":"other","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","accessTokenMaxTTL":30,"tokenType":"Bearer"}""")]
    [Arguments("""{"accessToken":"issued-canary","expiresIn":120,"accessTokenMaxTTL":30}""")]
    [Arguments("[]")]
    [Arguments("not-json")]
    public async Task MalformedSuccessRemainsUncertainAndCannotReplay(string json)
    {
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        var wire = new Wire(_ => Task.FromResult(Response(json)));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateReceipt();
        await Assert.That((await client.LoginAsync(proof, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.LoginAsync(proof, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    [Arguments(0d)]
    [Arguments(1e300)]
    public async Task FiniteMaximumIsReportedMetadataNotAnExpiryCeiling(double maximum)
    {
        string json = JsonSerializer.Serialize(new { accessToken = "issued-canary", expiresIn = 120.5, accessTokenMaxTTL = maximum, tokenType = "Bearer" });
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        var clock = new Clock();
        using var client = new InfisicalProofAuthentication(new("https://auth.test"),
            new Wire(_ => Task.FromResult(Response(json))), timeProvider: clock);
        var outcome = await client.LoginAsync(proof, client.CreateReceipt());
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        using var login = outcome.Value;
        await Assert.That(login.AccessTokenMaxTTL).IsEqualTo(maximum);
        await Assert.That(login.Token.ExpiresAt).IsEqualTo(clock.GetUtcNow().AddSeconds(120.5));
    }

    [Test]
    [Arguments(400, SecretStatus.Invalid)]
    [Arguments(401, SecretStatus.Denied)]
    [Arguments(403, SecretStatus.Denied)]
    [Arguments(422, SecretStatus.Invalid)]
    [Arguments(429, SecretStatus.Throttled)]
    [Arguments(404, SecretStatus.Unknown)]
    [Arguments(500, SecretStatus.Unknown)]
    [Arguments(302, SecretStatus.Unknown)]
    public async Task NativeErrorsAreBoundedAndRetainDispatchEvidence(int code, SecretStatus expected)
    {
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        using var client = new InfisicalProofAuthentication(new("https://auth.test"),
            new Wire(_ => Task.FromResult(Response("private-error-canary", (HttpStatusCode)code))));
        var receipt = client.CreateReceipt();
        var result = await client.LoginAsync(proof, receipt);
        await Assert.That(result.Status).IsEqualTo(expected);
        await Assert.That(receipt.Evidence).IsEqualTo(expected == SecretStatus.Unknown
            ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.Rejected);
        await Assert.That(result.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ResponseBudgetsBoundDeclaredAndStreamingBodies(bool declared)
    {
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), new Wire(_ =>
        {
            HttpContent content = declared ? new StringContent(new string('x', 1025))
                : new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(new string('x', 1025))));
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = content });
        }), new InfisicalNetworkOptions { MaximumResponseBytes = 1024 });
        var receipt = client.CreateReceipt();
        await Assert.That((await client.LoginAsync(proof, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task MaterialAndFactoryValidationPrecedesDispatch()
    {
        using var material = SecretMaterial.FromText("canary");
        await Assert.That(() => InfisicalLoginProof.Jwt("", material)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalLoginProof.Jwt(Identity, material, "")).Throws<ArgumentException>();
        await Assert.That(() => InfisicalLoginProof.Jwt(Identity, material, new string('o', 65))).Throws<ArgumentException>();
        await Assert.That(() => InfisicalLoginProof.Ldap("not-uuid", "user", material)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalLoginProof.Ldap(Identity, new string('u', 256), material)).Throws<ArgumentException>();
        using var password = SecretMaterial.FromText(new string('p', 1025));
        await Assert.That(() => InfisicalLoginProof.Ldap(Identity, "user", password)).Throws<ArgumentException>();
        using var huge = SecretMaterial.FromText(new string('p', 16385));
        await Assert.That(() => InfisicalLoginProof.Jwt(Identity, huge)).Throws<ArgumentException>();
        using var empty = SecretMaterial.FromText("");
        await Assert.That(() => InfisicalLoginProof.Jwt(Identity, empty)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalLoginProof.AliCloud(Identity, material, material, material,
            "invalid", "version")).Throws<ArgumentException>();
        using var proof = InfisicalLoginProof.Jwt(Identity, material);
        proof.Dispose();
        var wire = new Wire(_ => Task.FromResult(Response(Success)));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateReceipt();
        await Assert.That(async () => await client.LoginAsync(proof, receipt)).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
        await Assert.That(material.Reveal()).IsEqualTo("canary");
    }

    [Test]
    public async Task ForeignReceiptAndPreCanceledAttemptDoNotSend()
    {
        using var proof = InfisicalLoginProof.TlsCertificate(Identity);
        var wire = new Wire(_ => Task.FromResult(Response(Success)));
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        using var other = new InfisicalProofAuthentication(new("https://other.test"), new Wire(_ => Task.FromResult(Response(Success))));
        await Assert.That((await client.LoginAsync(proof, other.CreateReceipt())).Status).IsEqualTo(SecretStatus.Invalid);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var receipt = client.CreateReceipt();
        await Assert.That(async () => await client.LoginAsync(proof, receipt, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CommittedLossOrCancellationCannotReplayAndInFlightCopySurvivesDisposal(bool cancel)
    {
        using var material = SecretMaterial.FromText("proof-canary");
        using var proof = InfisicalLoginProof.Jwt(Identity, material);
        var committed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        var wire = new Wire(async request =>
        {
            committed.TrySetResult();
            await release.Task.WaitAsync(cancellation.Token);
            using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            await Assert.That(json.RootElement.GetProperty("jwt").GetString()).IsEqualTo("proof-canary");
            throw new HttpRequestException("private-loss-canary");
        });
        using var client = new InfisicalProofAuthentication(new("https://auth.test"), wire);
        var receipt = client.CreateReceipt();
        Task observed = committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var pending = client.LoginAsync(proof, receipt, cancellation.Token).AsTask();
        await observed;
        await Assert.That((await client.LoginAsync(proof, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        proof.Dispose();
        if (cancel)
        {
            cancellation.Cancel();
            await Assert.That(async () => await pending).Throws<OperationCanceledException>();
        }
        else
        {
            release.TrySetResult();
            await Assert.That((await pending).Status).IsEqualTo(SecretStatus.Unknown);
        }
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Requests).IsEqualTo(1);
        await Assert.That(material.Reveal()).IsEqualTo("proof-canary");
    }

    [Test]
    public async Task FixedOriginAndSafeHostOwnedTransportAreRequired()
    {
        await Assert.That(() => new InfisicalProofAuthentication(new("https://auth.test/path"))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalProofAuthentication(new("http://auth.test"))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalProofAuthentication(new("https://user:pass@auth.test"))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalProofAuthentication(new("https://auth.test?query"))).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalProofAuthentication(new("https://auth.test#fragment"))).Throws<ArgumentException>();
        using var unsafeHandler = new SocketsHttpHandler();
        await Assert.That(() => new InfisicalProofAuthentication(new("https://auth.test"), unsafeHandler)).Throws<ArgumentException>();
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false, ActivityHeadersPropagator = null };
        using (var client = new InfisicalProofAuthentication(new("https://auth.test:8443"), handler))
            await Assert.That(client.ToString()).IsEqualTo("[InfisicalProofAuthentication]");
        handler.MaxConnectionsPerServer = 3;
        await Assert.That(handler.MaxConnectionsPerServer).IsEqualTo(3);
    }

    private static InfisicalLoginProof Create(string strategy, SecretMaterial material, string? organization) => strategy switch
    {
        "alicloud" => InfisicalLoginProof.AliCloud(Identity, material, material, material, "2026-10-10T12:00:00Z", "2015-04-01", organization),
        "aws" => InfisicalLoginProof.Aws(Identity, material, material, organizationSlug: organization),
        "azure" => InfisicalLoginProof.Azure(Identity, material, organization),
        "gcp" => InfisicalLoginProof.Gcp(Identity, material, organization),
        "jwt" => InfisicalLoginProof.Jwt(Identity, material, organization),
        "kubernetes" => InfisicalLoginProof.Kubernetes(Identity, material, organization),
        "ldap" => InfisicalLoginProof.Ldap(Identity, "user-canary", material, organization),
        "oci" => InfisicalLoginProof.Oci(Identity, "user-canary", material, "signed.test", organizationSlug: organization),
        "oidc" => InfisicalLoginProof.Oidc(Identity, material, organization),
        "spiffe" => InfisicalLoginProof.Spiffe(Identity, material, organization),
        "tls-cert" => InfisicalLoginProof.TlsCertificate(Identity, organization),
        _ => throw new ArgumentException("Unknown test strategy.")
    };

    private static HttpResponseMessage Response(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
    }

    private sealed class Wire(Func<HttpRequestMessage, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return send(request);
        }
    }
}
