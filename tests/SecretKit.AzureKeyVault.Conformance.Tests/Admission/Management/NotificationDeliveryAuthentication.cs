using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Explicit host trust, not observed enrollment. This authenticates a bearer,
// not event causality, subscription writers, exclusion or provider queue closure.
// Replacement keys require a new policy; no discovery, refresh or remote I/O.
internal sealed class NotificationDeliveryAuthentication
{
    internal enum AccessTokenVersion { V1, V2 }
    internal sealed record Limits(int MaximumTokenBytes, TimeSpan MaximumTokenLifetime,
        TimeSpan MaximumTokenAge, TimeSpan MaximumKeyAge);
    internal sealed record SigningKey([property: JsonIgnore] string Id,
        [property: JsonIgnore] RSAParameters PublicKey,
        [property: JsonIgnore] DateTimeOffset SuppliedAt,
        [property: JsonIgnore] DateTimeOffset ExpiresAt)
    {
        public override string ToString() => "[NotificationSigningKey]";
    }

    private readonly string issuer, tenant, audience, application, principal, subject, role;
    private readonly AccessTokenVersion version;
    private readonly Dictionary<string, SigningKey> keys = new(StringComparer.Ordinal);
    private readonly Limits limits;
    private readonly TimeProvider time;

    internal NotificationDeliveryAuthentication(string issuer, Guid tenant, string audience,
        Guid application, Guid principal, string subject, string role, AccessTokenVersion version,
        SigningKey[] signingKeys, Limits limits, TimeProvider time)
    {
        try
        {
            Require(Text(issuer, 2048) && !issuer.Contains('*') &&
                Uri.TryCreate(issuer, UriKind.Absolute, out var uri) &&
                uri is { Scheme: "https", UserInfo.Length: 0, Query.Length: 0, Fragment.Length: 0 } &&
                uri.Segments.All(s => !new[] { "common", "organizations", "consumers" }
                    .Contains(Uri.UnescapeDataString(s).Trim('/'), StringComparer.OrdinalIgnoreCase)));
            Require(tenant != Guid.Empty && application != Guid.Empty && principal != Guid.Empty &&
                Text(audience, 2048) && !audience.Contains('*') && Text(subject, 256) && Text(role, 256) &&
                version is AccessTokenVersion.V1 or AccessTokenVersion.V2 &&
                signingKeys is { Length: > 0 and <= 8 } && limits is not null && time is not null &&
                limits.MaximumTokenBytes is >= 1024 and <= 16384 &&
                limits.MaximumTokenLifetime > TimeSpan.Zero && limits.MaximumTokenLifetime <= TimeSpan.FromHours(2) &&
                limits.MaximumTokenAge > TimeSpan.Zero && limits.MaximumTokenAge <= TimeSpan.FromHours(2) &&
                limits.MaximumKeyAge > TimeSpan.Zero && limits.MaximumKeyAge <= TimeSpan.FromDays(7));
            this.issuer = issuer;
            this.tenant = tenant.ToString("D");
            this.audience = audience;
            this.application = application.ToString("D");
            this.principal = principal.ToString("D");
            this.subject = subject;
            this.role = role;
            this.version = version;
            this.limits = limits with { };
            this.time = time;
            var now = time.GetUtcNow();
            foreach (var input in signingKeys)
            {
                Require(input is not null && Text(input.Id, 128) &&
                    input.Id.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') &&
                    input.PublicKey is { D: null, P: null, Q: null, DP: null, DQ: null, InverseQ: null });
                byte[]? modulus = input.PublicKey.Modulus, exponent = input.PublicKey.Exponent;
                Require(modulus is { Length: >= 256 and <= 512 } && exponent is { Length: > 0 and <= 4 });
                modulus = modulus.ToArray();
                exponent = exponent.ToArray();
                Require(modulus[0] >= 128 && exponent[0] != 0 && (exponent[^1] & 1) == 1 &&
                    (exponent.Length > 1 || exponent[0] >= 3));
                var copy = input with
                {
                    PublicKey = new RSAParameters { Modulus = modulus, Exponent = exponent }
                };
                Require(Fresh(copy, now) && keys.TryAdd(copy.Id, copy));
                using var check = RSA.Create();
                check.ImportParameters(copy.PublicKey);
            }
        }
        catch (Exception)
        {
            // Do not retain provider/library exceptions, selectors or key material.
            throw Invalid();
        }
    }

    internal async Task<bool> AuthenticateAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        byte[]? headerBytes = null, payloadBytes = null, signatureBytes = null;
        try
        {
            if (!request.Headers.NonValidated.TryGetValues("Authorization", out var values) || values.Count != 1)
                return false;
            string authorization = values.Single();
            if (authorization.Length <= 7 || authorization.Length > limits.MaximumTokenBytes + 7 ||
                !authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                return false;
            string token = authorization[7..];
            // Only compact, unpadded ASCII JWS; this also rejects whitespace,
            // comma-joined credentials, control characters and encrypted tokens.
            if (!token.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')) return false;
            string[] parts = token.Split('.');
            if (parts.Length != 3 || parts.Any(p => p.Length == 0)) return false;
            headerBytes = Decode(parts[0]);
            payloadBytes = Decode(parts[1]);
            signatureBytes = Decode(parts[2]);
            using var headerDocument = JsonDocument.Parse(headerBytes, new JsonDocumentOptions { MaxDepth = 4 });
            using var payloadDocument = JsonDocument.Parse(payloadBytes, new JsonDocumentOptions { MaxDepth = 8 });
            var header = headerDocument.RootElement;
            var payload = payloadDocument.RootElement;
            int nodes = 0;
            Unique(header, ref nodes);
            Unique(payload, ref nodes);
            Require(header.ValueKind == JsonValueKind.Object && payload.ValueKind == JsonValueKind.Object &&
                header.EnumerateObject().All(p => p.Name is "alg" or "kid" or "typ" or "x5t") &&
                String(header, "alg", 16) == SecurityAlgorithms.RsaSha256 && String(header, "typ", 16) == "JWT");
            // x5t is permitted only as signed metadata, never as a key resolver.
            if (header.TryGetProperty("x5t", out _)) _ = String(header, "x5t", 128);
            string kid = String(header, "kid", 128);
            if (!keys.TryGetValue(kid, out var key) || signatureBytes.Length != key.PublicKey.Modulus!.Length)
                return false;
            long issued = NumericDate(payload, "iat"), notBefore = NumericDate(payload, "nbf"),
                expires = NumericDate(payload, "exp");
            var now = time.GetUtcNow();
            if (!Fresh(key, now) || !Lifetime(issued, notBefore, expires, now)) return false;

            // A new library-owned verifier per call avoids mutable host handles
            // and cached signature providers outliving their RSA instance.
            using var rsa = RSA.Create();
            rsa.ImportParameters(key.PublicKey);
            var securityKey = new RsaSecurityKey(rsa)
            {
                KeyId = key.Id,
                CryptoProviderFactory = new() { CacheSignatureProviders = false }
            };
            var validation = new TokenValidationParameters
            {
                RequireSignedTokens = true,
                RequireExpirationTime = true,
                RequireAudience = true,
                ValidateIssuer = true,
                ValidIssuer = issuer,
                ValidateAudience = true,
                ValidAudience = audience,
                IgnoreTrailingSlashWhenValidatingAudience = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = securityKey,
                TryAllIssuerSigningKeys = false,
                ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                ValidTypes = ["JWT"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                LifetimeValidator = (nbf, exp, _, _) =>
                    nbf == DateTimeOffset.FromUnixTimeSeconds(notBefore).UtcDateTime &&
                    exp == DateTimeOffset.FromUnixTimeSeconds(expires).UtcDateTime &&
                    Lifetime(issued, notBefore, expires, now),
                LogValidationExceptions = false,
                LogTokenId = false,
                IncludeTokenOnFailedValidation = false,
                SaveSigninToken = false
            };
            var handler = new JsonWebTokenHandler
            {
                MapInboundClaims = false,
                MaximumTokenSizeInBytes = limits.MaximumTokenBytes
            };
            var result = await handler.ValidateTokenAsync(token, validation).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (!result.IsValid) return false;

            // Inspect the same signed bytes, not a mapped/flattened ClaimsIdentity.
            // idtyp=app is mandatory: roles/appid alone can occur on user tokens.
            Require(String(payload, "iss", 2048) == issuer && String(payload, "aud", 2048) == audience &&
                String(payload, "tid", 64) == tenant && String(payload, "oid", 64) == principal &&
                String(payload, "sub", 256) == subject && String(payload, "idtyp", 16) == "app" &&
                String(payload, "ver", 8) == (version == AccessTokenVersion.V1 ? "1.0" : "2.0"));
            string actor = version == AccessTokenVersion.V1 ? "appid" : "azp";
            string actorMethod = version == AccessTokenVersion.V1 ? "appidacr" : "azpacr";
            Require(String(payload, actor, 64) == application && String(payload, actorMethod, 8) is "1" or "2" &&
                !payload.TryGetProperty(version == AccessTokenVersion.V1 ? "azp" : "appid", out _) &&
                !payload.TryGetProperty(version == AccessTokenVersion.V1 ? "azpacr" : "appidacr", out _) &&
                !payload.EnumerateObject().Any(p => new[]
                {
                    "scp", "nonce", "auth_time", "amr", "acr", "upn", "unique_name", "preferred_username",
                    "email", "name", "given_name", "family_name", "sid", "act", "actort"
                }.Contains(p.Name, StringComparer.OrdinalIgnoreCase)));
            var roles = payload.GetProperty("roles");
            Require(roles.ValueKind == JsonValueKind.Array && roles.GetArrayLength() is > 0 and <= 16);
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in roles.EnumerateArray())
            {
                Require(item.ValueKind == JsonValueKind.String && Text(item.GetString(), 256));
                Require(distinct.Add(item.GetString()!));
            }
            if (!distinct.Contains(role)) return false;
            var completedAt = time.GetUtcNow();
            return Fresh(key, completedAt) && Lifetime(issued, notBefore, expires, completedAt);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) { return false; }
        finally
        {
            if (headerBytes is not null) CryptographicOperations.ZeroMemory(headerBytes);
            if (payloadBytes is not null) CryptographicOperations.ZeroMemory(payloadBytes);
            if (signatureBytes is not null) CryptographicOperations.ZeroMemory(signatureBytes);
        }
    }

    private bool Fresh(SigningKey key, DateTimeOffset now) => key.SuppliedAt <= now &&
        now < key.ExpiresAt && now - key.SuppliedAt <= limits.MaximumKeyAge;

    private bool Lifetime(long issued, long notBefore, long expires, DateTimeOffset now)
    {
        var iat = DateTimeOffset.FromUnixTimeSeconds(issued);
        var nbf = DateTimeOffset.FromUnixTimeSeconds(notBefore);
        var exp = DateTimeOffset.FromUnixTimeSeconds(expires);
        return iat <= now && nbf <= now && now < exp && iat < exp && nbf < exp &&
            exp - iat <= limits.MaximumTokenLifetime && exp - nbf <= limits.MaximumTokenLifetime &&
            now - iat <= limits.MaximumTokenAge;
    }

    private static byte[] Decode(string segment)
    {
        byte[] bytes = Base64UrlEncoder.DecodeBytes(segment);
        if (Base64UrlEncoder.Encode(bytes) == segment) return bytes;
        CryptographicOperations.ZeroMemory(bytes);
        throw Invalid();
    }

    private static long NumericDate(JsonElement payload, string name)
    {
        var value = payload.GetProperty(name);
        Require(value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _));
        long number = value.GetInt64();
        Require(number is >= 0 and <= 253402300799);
        return number;
    }

    private static string String(JsonElement value, string name, int maximum)
    {
        var property = value.GetProperty(name);
        Require(property.ValueKind == JsonValueKind.String && Text(property.GetString(), maximum));
        return property.GetString()!;
    }

    private static void Unique(JsonElement value, ref int nodes)
    {
        Require(++nodes <= 256);
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in value.EnumerateObject())
            {
                Require(Text(property.Name, 128) && names.Add(property.Name));
                Unique(property.Value, ref nodes);
            }
        }
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray()) Unique(item, ref nodes);
    }

    private static bool Text(string? value, int maximum) => value is { Length: > 0 } &&
        value.Length <= maximum && !string.IsNullOrWhiteSpace(value) &&
        value.All(c => !char.IsControl(c));
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Invalid(); }
    private static InvalidOperationException Invalid() => new("notification-authentication-unavailable");
    public override string ToString() => "[NotificationDeliveryAuthentication]";
}
