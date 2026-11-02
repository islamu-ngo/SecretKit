using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Authentication = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationDeliveryAuthentication;
using Webhook = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationWebhookDeliveryCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    private const string DeliveryIssuer = "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0";
    private const string DeliveryAudience = "api://notification-receiver";
    private const string DeliverySubject = "selected-app-only-subject";
    private const string DeliveryRole = "AzureEventGridSecureWebhookSubscriber";
    private static readonly Guid DeliveryTenant = new("11111111-1111-1111-1111-111111111111");
    private static readonly Guid DeliveryApplication = new("22222222-2222-2222-2222-222222222222");
    private static readonly Guid DeliveryPrincipal = new("33333333-3333-3333-3333-333333333333");
    private static Authentication.Limits DeliveryLimits => new(4096, TimeSpan.FromMinutes(10),
        TimeSpan.FromMinutes(5), TimeSpan.FromHours(1));

    private static Authentication DeliveryTrust(RSA rsa, TimeProvider time,
        Authentication.AccessTokenVersion version = Authentication.AccessTokenVersion.V2,
        Authentication.SigningKey[]? keys = null) =>
        new(version == Authentication.AccessTokenVersion.V1 ? "https://sts.windows.net/" + DeliveryTenant.ToString("D") + "/" : DeliveryIssuer,
            DeliveryTenant, DeliveryAudience, DeliveryApplication, DeliveryPrincipal,
            DeliverySubject, DeliveryRole, version,
            keys ?? [new("selected-key", rsa.ExportParameters(false), time.GetUtcNow(), time.GetUtcNow().AddHours(1))],
            DeliveryLimits, time);

    private static Webhook Receiver(NotificationCaptureScope f, Authentication authentication) =>
        new(f.Fixture.Journal, Owner, WebhookEndpoint,
            new(4096, 16, 16, 128, 8, 16, 8192, TimeSpan.FromSeconds(10)), f.Clock, authentication);

    private static JsonObject DeliveryClaims(TimeProvider time,
        Authentication.AccessTokenVersion version = Authentication.AccessTokenVersion.V2)
    {
        long now = time.GetUtcNow().ToUnixTimeSeconds();
        return new()
        {
            ["iss"] = version == Authentication.AccessTokenVersion.V1 ? "https://sts.windows.net/" + DeliveryTenant.ToString("D") + "/" : DeliveryIssuer,
            ["aud"] = DeliveryAudience,
            ["tid"] = DeliveryTenant.ToString("D"),
            ["oid"] = DeliveryPrincipal.ToString("D"),
            ["sub"] = DeliverySubject,
            ["ver"] = version == Authentication.AccessTokenVersion.V1 ? "1.0" : "2.0",
            ["idtyp"] = "app",
            [version == Authentication.AccessTokenVersion.V1 ? "appid" : "azp"] = DeliveryApplication.ToString("D"),
            [version == Authentication.AccessTokenVersion.V1 ? "appidacr" : "azpacr"] = "1",
            ["roles"] = new JsonArray(DeliveryRole),
            ["iat"] = now - 30,
            ["nbf"] = now - 30,
            ["exp"] = now + 120
        };
    }

    private static string SignDelivery(RSA rsa, string payload, string? kid = "selected-key",
        string algorithm = SecurityAlgorithms.RsaSha256, Dictionary<string, object>? headers = null)
    {
        var key = new RsaSecurityKey(rsa)
        {
            KeyId = kid,
            CryptoProviderFactory = new() { CacheSignatureProviders = false }
        };
        var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
        return handler.CreateToken(payload, new SigningCredentials(key, algorithm), headers ?? []);
    }

    private static async Task AssertDeliveryUnauthorized(Webhook receiver, Webhook.Window window,
        HttpRequestMessage request)
    {
        request.Content!.Dispose();
        using var unread = new UnreadDeliveryContent();
        request.Content = unread;
        request.Content.Headers.ContentType = new("application/json");
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.Unauthorized);
        await Assert.That(unread.Read).IsFalse();
        await Assert.That(await response.Content.ReadAsStringAsync())
            .IsEqualTo("{\"error\":\"notification-webhook-unavailable\"}");
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task SignedAppOnlyDeliveryRemainsCandidateEvidence(bool v1)
    {
        var version = v1 ? Authentication.AccessTokenVersion.V1 : Authentication.AccessTokenVersion.V2;
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock, version));
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, ["x-correlation"]);
        var linked = receiver.WaitForLinkedDeliveryAsync(window, default);
        var capture = await Trigger(f);
        receiver.AttachCapture(window, f.Source, capture);
        using var request = Packet(f);
        request.Headers.Authorization = new("Bearer", SignDelivery(signing, DeliveryClaims(f.Clock, version).ToJsonString()));
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await linked.WaitAsync(TimeSpan.FromSeconds(10));
        var measurement = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measurement.Available).IsTrue();
        await Assert.That(measurement.Deliveries.Count).IsEqualTo(1);
        await Assert.That(measurement.Deliveries.Single().Headers.Single().Name).IsEqualTo("x-correlation");
        await Assert.That(measurement.ProviderIdentityEstablished || measurement.NativeFilterExclusionEstablished ||
            measurement.NativeWindowClosureEstablished || f.Source.Read(capture, f.Binding).EmissionEstablished).IsFalse();
        await Assert.That(f.Credential.Disposed || f.Native.Disposed).IsFalse();
    }

    [Test]
    [Arguments("iss")]
    [Arguments("aud")]
    [Arguments("tid")]
    [Arguments("azp")]
    [Arguments("oid")]
    [Arguments("sub")]
    [Arguments("roles")]
    [Arguments("idtyp")]
    [Arguments("ver")]
    [Arguments("azpacr")]
    [Arguments("missing-iss")]
    [Arguments("missing-aud")]
    [Arguments("missing-tid")]
    [Arguments("missing-azp")]
    [Arguments("missing-oid")]
    [Arguments("missing-sub")]
    [Arguments("missing-roles")]
    [Arguments("missing-idtyp")]
    [Arguments("missing-ver")]
    [Arguments("missing-azpacr")]
    [Arguments("missing-iat")]
    [Arguments("missing-nbf")]
    [Arguments("missing-exp")]
    [Arguments("expiry")]
    [Arguments("future-nbf")]
    [Arguments("future-iat")]
    [Arguments("too-old")]
    [Arguments("long-lifetime")]
    [Arguments("long-not-before")]
    [Arguments("fractional-time")]
    [Arguments("string-time")]
    [Arguments("overflow-time")]
    [Arguments("negative-time")]
    [Arguments("audience-array")]
    [Arguments("audience-slash")]
    [Arguments("role-string")]
    [Arguments("duplicate-roles")]
    [Arguments("duplicate-claim")]
    [Arguments("case-duplicate")]
    [Arguments("escaped-duplicate")]
    [Arguments("null-claim")]
    [Arguments("object-claim")]
    [Arguments("scp")]
    [Arguments("nonce")]
    [Arguments("preferred_username")]
    [Arguments("amr")]
    [Arguments("act")]
    [Arguments("actort")]
    [Arguments("appid")]
    [Arguments("deep")]
    [Arguments("nodes")]
    public async Task SignedUntrustedProfilesCannotReadDeliveryBody(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock));
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, []);
        var claims = DeliveryClaims(f.Clock);
        long now = f.Clock.GetUtcNow().ToUnixTimeSeconds();
        if (fault.StartsWith("missing-", StringComparison.Ordinal)) claims.Remove(fault[8..]);
        else
        {
            switch (fault)
            {
                case "roles":
                    claims["roles"] = new JsonArray("foreign-role");
                    break;
                case "expiry":
                    claims["exp"] = now;
                    break;
                case "future-nbf":
                    claims["nbf"] = now + 1;
                    break;
                case "future-iat":
                    claims["iat"] = now + 1;
                    break;
                case "too-old":
                    claims["iat"] = now - 301;
                    break;
                case "long-lifetime":
                    claims["exp"] = now + 601;
                    break;
                case "long-not-before":
                    claims["nbf"] = now - 601;
                    break;
                case "fractional-time":
                    claims["exp"] = now + 0.5;
                    break;
                case "string-time":
                    claims["exp"] = (now + 120).ToString(System.Globalization.CultureInfo.InvariantCulture);
                    break;
                case "overflow-time":
                    claims["exp"] = long.MaxValue;
                    break;
                case "negative-time":
                    claims["iat"] = -1;
                    break;
                case "audience-array":
                    claims["aud"] = new JsonArray(DeliveryAudience, "foreign");
                    break;
                case "audience-slash":
                    claims["aud"] = DeliveryAudience + "/";
                    break;
                case "role-string":
                    claims["roles"] = DeliveryRole;
                    break;
                case "duplicate-roles":
                    claims["roles"] = new JsonArray(DeliveryRole, DeliveryRole);
                    break;
                case "null-claim":
                    claims["oid"] = null;
                    break;
                case "object-claim":
                    claims["oid"] = new JsonObject { ["value"] = DeliveryPrincipal.ToString("D") };
                    break;
                case "duplicate-claim" or "case-duplicate" or "escaped-duplicate":
                    break;
                case "deep":
                    JsonNode child = new JsonObject();
                    for (int i = 0; i < 9; i++) child = new JsonObject { ["nested"] = child };
                    claims["extra"] = child;
                    break;
                case "nodes":
                    var nodes = new JsonArray();
                    for (int i = 0; i < 260; i++) nodes.Add(0);
                    claims["extra"] = nodes;
                    break;
                default:
                    claims[fault] = "foreign";
                    break;
            }
        }
        string payload = claims.ToJsonString();
        if (fault is "duplicate-claim" or "case-duplicate" or "escaped-duplicate")
        {
            string name = fault == "case-duplicate" ? "OID" : fault == "escaped-duplicate" ? "\\u006fid" : "oid";
            payload = payload[..^1] + ",\"" + name + "\":\"" + DeliveryPrincipal.ToString("D") + "\"}";
        }
        using var request = Packet(f);
        request.Headers.Authorization = new("Bearer", SignDelivery(signing, payload));
        await AssertDeliveryUnauthorized(receiver, window, request);
        var measured = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measured.Available || measured.ProviderIdentityEstablished).IsFalse();
        await Assert.That(measured.Deliveries.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("wrong-key")]
    [Arguments("missing-kid")]
    [Arguments("wrong-kid")]
    [Arguments("kid-case")]
    [Arguments("bad-signature")]
    [Arguments("missing-signature")]
    [Arguments("unsigned")]
    [Arguments("HS256")]
    [Arguments("RS512")]
    [Arguments("jku")]
    [Arguments("x5u")]
    [Arguments("jwk")]
    [Arguments("x5c")]
    [Arguments("crit")]
    [Arguments("b64")]
    [Arguments("typ")]
    [Arguments("duplicate-header")]
    [Arguments("case-duplicate-header")]
    [Arguments("malformed")]
    [Arguments("malformed-json")]
    [Arguments("padded")]
    [Arguments("encrypted")]
    public async Task DeliveryRejectsSignatureAndKeySelectionAttacks(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        using var foreign = RSA.Create(2048);
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock));
        var window = receiver.Arm(WebhookBinding(f), []);
        string payload = DeliveryClaims(f.Clock).ToJsonString();
        var extra = new Dictionary<string, object>();
        if (fault is "jku" or "x5u") extra[fault] = "https://untrusted.example/keys";
        if (fault is "jwk" or "x5c" or "crit" or "b64") extra[fault] = "untrusted";
        if (fault == "typ") extra["typ"] = "id_token";
        string token = SignDelivery(fault == "wrong-key" ? foreign : signing, payload,
            fault == "missing-kid" ? null : fault == "wrong-kid" ? "foreign" : fault == "kid-case" ? "SELECTED-KEY" : "selected-key",
            fault == "RS512" ? SecurityAlgorithms.RsaSha512 : SecurityAlgorithms.RsaSha256, extra);
        string[] parts = token.Split('.');
        switch (fault)
        {
            case "bad-signature":
                byte[] signature = Base64UrlEncoder.DecodeBytes(parts[2]);
                signature[0] ^= 1;
                token = parts[0] + "." + parts[1] + "." + Base64UrlEncoder.Encode(signature);
                break;
            case "missing-signature": token = parts[0] + "." + parts[1] + "."; break;
            case "unsigned":
                token = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(payload);
                break;
            case "HS256":
                var symmetric = new SymmetricSecurityKey(signing.ExportParameters(false).Modulus!) { KeyId = "selected-key" };
                token = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false }.CreateToken(payload,
                    new SigningCredentials(symmetric, SecurityAlgorithms.HmacSha256));
                break;
            case "duplicate-header":
            case "case-duplicate-header":
                string header = Encoding.UTF8.GetString(Base64UrlEncoder.DecodeBytes(parts[0]));
                string duplicateName = fault == "duplicate-header" ? "kid" : "KID";
                string input = Base64UrlEncoder.Encode(header[..^1] + ",\"" + duplicateName + "\":\"selected-key\"}") +
                    "." + parts[1];
                token = input + "." + Base64UrlEncoder.Encode(signing.SignData(
                    Encoding.ASCII.GetBytes(input), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                break;
            case "malformed": token = "not-a-token"; break;
            case "malformed-json": token = Base64UrlEncoder.Encode("{") + "." + parts[1] + "." + parts[2]; break;
            case "padded": token = parts[0] + "=." + parts[1] + "." + parts[2]; break;
            case "encrypted": token += ".extra.part"; break;
        }
        using var request = Packet(f);
        await Assert.That(request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + token)).IsTrue();
        await AssertDeliveryUnauthorized(receiver, window, request);
    }

    [Test]
    [Arguments("missing")]
    [Arguments("duplicate")]
    [Arguments("combined")]
    [Arguments("basic")]
    [Arguments("empty")]
    [Arguments("leading-space")]
    [Arguments("extra-space")]
    [Arguments("trailing-space")]
    [Arguments("tab")]
    [Arguments("newline")]
    [Arguments("oversized-token")]
    [Arguments("oversized-header")]
    [Arguments("too-many-headers")]
    public async Task DeliveryAuthorizationAndHeaderBoundsPrecedeBodyRead(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock));
        var window = receiver.Arm(WebhookBinding(f), []);
        string token = SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString());
        string header = "Bearer " + token;
        using var request = Packet(f);
        string? value = fault switch
        {
            "missing" => null,
            "combined" => header + ", " + header,
            "basic" => "Basic " + token,
            "empty" => "Bearer ",
            "leading-space" => " " + header,
            "extra-space" => "Bearer  " + token,
            "trailing-space" => header + " ",
            "tab" => "Bearer\t" + token,
            "newline" => header + "\r\n",
            "oversized-token" => "Bearer " + new string('x', 4097),
            _ => header
        };
        if (value is not null) await Assert.That(request.Headers.TryAddWithoutValidation("Authorization", value)).IsTrue();
        if (fault == "duplicate") await Assert.That(request.Headers.TryAddWithoutValidation("Authorization", header)).IsTrue();
        if (fault == "oversized-header") request.Headers.TryAddWithoutValidation("X-Large", new string('x', 8193));
        if (fault == "too-many-headers")
            for (int i = 0; i < 17; i++) request.Headers.TryAddWithoutValidation("X-" + i, "v");
        await AssertDeliveryUnauthorized(receiver, window, request);
    }

    [Test]
    [Arguments("expired-key")]
    [Arguments("stale-key")]
    [Arguments("expired-token")]
    public async Task DeliveryTrustExpiresOnInjectedTimeWithoutRefresh(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        DateTimeOffset now = f.Clock.GetUtcNow();
        Authentication.SigningKey[] keys = [new("selected-key", signing.ExportParameters(false),
            fault == "stale-key" ? now.AddMinutes(-59) : now,
            fault == "expired-key" ? now.AddMinutes(1) : now.AddHours(1))];
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock, keys: keys));
        var window = receiver.Arm(WebhookBinding(f), []);
        string old = SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString());
        f.Clock.Elapsed = TimeSpan.FromMinutes(2);
        using var request = Packet(f);
        request.Headers.Authorization = new("Bearer",
            fault == "expired-token" ? old : SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString()));
        await AssertDeliveryUnauthorized(receiver, window, request);
    }

    [Test]
    public async Task DeliveryTrustCopiesKeyArraysAndDoesNotOwnSigningHandle()
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        var parameters = signing.ExportParameters(false);
        var key = new Authentication.SigningKey("selected-key", parameters, f.Clock.GetUtcNow(), f.Clock.GetUtcNow().AddHours(1));
        Authentication.SigningKey[] keys = [key];
        var trust = DeliveryTrust(signing, f.Clock, keys: keys);
        Array.Clear(parameters.Modulus!);
        Array.Clear(parameters.Exponent!);
        keys[0] = new("foreign", default, default, default);
        await using (var receiver = Receiver(f, trust))
        {
            var window = receiver.Arm(WebhookBinding(f), []);
            using var request = Packet(f);
            request.Headers.Authorization = new("Bearer", SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString()));
            using var response = await receiver.ReceiveAsync(window, request, default);
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        }
        // Both the caller's signer and the immutable policy survive receiver disposal.
        await Assert.That(signing.ExportParameters(false).Modulus!.Length).IsEqualTo(256);
        using var probe = new HttpRequestMessage();
        probe.Headers.Authorization = new("Bearer", SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString()));
        await Assert.That(await trust.AuthenticateAsync(probe, default)).IsTrue();
        await Assert.That(JsonSerializer.Serialize(trust)).IsEqualTo("{}");
        await Assert.That(JsonSerializer.Serialize(key)).IsEqualTo("{}");
        await Assert.That(trust.ToString()).IsEqualTo("[NotificationDeliveryAuthentication]");
        await Assert.That(key.ToString()).IsEqualTo("[NotificationSigningKey]");
    }

    [Test]
    [Arguments("empty-keys")]
    [Arguments("duplicate-kid")]
    [Arguments("missing-kid")]
    [Arguments("weak-key")]
    [Arguments("private-key")]
    [Arguments("future-key")]
    [Arguments("expired-key")]
    [Arguments("stale-key")]
    [Arguments("common-issuer")]
    [Arguments("wildcard-issuer")]
    [Arguments("http-issuer")]
    [Arguments("empty-tenant")]
    [Arguments("empty-actor")]
    [Arguments("empty-principal")]
    [Arguments("empty-subject")]
    [Arguments("empty-role")]
    [Arguments("bad-version")]
    [Arguments("unbounded-token")]
    [Arguments("unbounded-lifetime")]
    [Arguments("unbounded-age")]
    [Arguments("unbounded-key-age")]
    public async Task DeliveryTrustRequiresExplicitBoundedPublicConfiguration(string fault)
    {
        using var signing = RSA.Create(fault == "weak-key" ? 1024 : 2048);
        var time = new NotificationRuntimeClock();
        var now = time.GetUtcNow();
        var key = new Authentication.SigningKey(fault == "missing-kid" ? "" : "selected-key",
            signing.ExportParameters(fault == "private-key"),
            fault == "future-key" ? now.AddMinutes(1) : fault == "stale-key" ? now.AddHours(-2) : now,
            fault == "expired-key" ? now : now.AddHours(1));
        Authentication.SigningKey[] keys = fault == "empty-keys" ? [] : fault == "duplicate-kid" ? [key, key] : [key];
        var limits = DeliveryLimits;
        limits = fault switch
        {
            "unbounded-token" => limits with { MaximumTokenBytes = int.MaxValue },
            "unbounded-lifetime" => limits with { MaximumTokenLifetime = TimeSpan.MaxValue },
            "unbounded-age" => limits with { MaximumTokenAge = TimeSpan.MaxValue },
            "unbounded-key-age" => limits with { MaximumKeyAge = TimeSpan.MaxValue },
            _ => limits
        };
        InvalidOperationException? failure = null;
        try
        {
            _ = new Authentication(
                fault == "common-issuer" ? "https://login.microsoftonline.com/common/v2.0" :
                fault == "wildcard-issuer" ? "https://*.example/tenant" :
                fault == "http-issuer" ? DeliveryIssuer.Replace("https:", "http:", StringComparison.Ordinal) : DeliveryIssuer,
                fault == "empty-tenant" ? Guid.Empty : DeliveryTenant, DeliveryAudience,
                fault == "empty-actor" ? Guid.Empty : DeliveryApplication,
                fault == "empty-principal" ? Guid.Empty : DeliveryPrincipal,
                fault == "empty-subject" ? "" : DeliverySubject, fault == "empty-role" ? "" : DeliveryRole,
                fault == "bad-version" ? (Authentication.AccessTokenVersion)99 : Authentication.AccessTokenVersion.V2,
                keys, limits, time);
        }
        catch (InvalidOperationException exception) { failure = exception; }
        await Assert.That(failure is not null).IsTrue();
        await Assert.That(failure!.Message).IsEqualTo("notification-authentication-unavailable");
    }

    [Test]
    [Arguments("endpoint", HttpStatusCode.Unauthorized)]
    [Arguments("subscription", HttpStatusCode.BadRequest)]
    [Arguments("topic", HttpStatusCode.BadRequest)]
    [Arguments("version", HttpStatusCode.OK)]
    public async Task SignedDeliveryCannotBypassOriginalCollectorNegatives(string fault, HttpStatusCode status)
    {
        await using var f = await NotificationCaptureScope.Create(notifications: ["owned-notification"]);
        using var signing = RSA.Create(2048);
        await using var receiver = Receiver(f, DeliveryTrust(signing, f.Clock));
        var binding = WebhookBinding(f);
        var window = receiver.Arm(binding, []);
        receiver.AttachCapture(window, f.Source, await Trigger(f));
        using var request = Packet(f, fault);
        request.Headers.Authorization = new("Bearer", SignDelivery(signing, DeliveryClaims(f.Clock).ToJsonString()));
        using var response = await receiver.ReceiveAsync(window, request, default);
        await Assert.That(response.StatusCode).IsEqualTo(status);
        var measured = await receiver.CloseAsync(window, binding, default);
        await Assert.That(measured.Available || measured.ProviderIdentityEstablished ||
            measured.NativeWindowClosureEstablished || measured.NativeFilterExclusionEstablished).IsFalse();
        await Assert.That(measured.UnlinkedEvents).IsEqualTo(fault == "version" ? 1 : 0);
    }

    private sealed class UnreadDeliveryContent : HttpContent
    {
        internal bool Read;
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            Read = true;
            throw new InvalidOperationException("body-must-not-be-read");
        }
    }
}
