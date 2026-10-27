using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native IP or CIDR input; never a free-form policy document.</summary>
public sealed class IdentityTrustedIp
{
    /// <summary>Validates a literal IPv4/IPv6 address or CIDR prefix without resolving hostnames.</summary>
    public IdentityTrustedIp(string ipAddress)
    {
        ManagementJson.Text(ipAddress, 128);
        string[] parts = ipAddress.Split('/');
        if (parts.Length is < 1 or > 2 || !IPAddress.TryParse(parts[0], out var address) ||
            parts.Length == 2 && (!int.TryParse(parts[1], out int prefix) || prefix < 0 ||
                prefix > (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)))
            throw new ArgumentException("Invalid trusted IP or CIDR.");
        IpAddress = ipAddress;
    }
    /// <summary>Gets the protected native IP or CIDR input.</summary>
    [JsonIgnore] public string IpAddress { get; }
    /// <summary>Returns a marker without network selectors.</summary>
    public override string ToString() => "[IdentityTrustedIp]";
}

/// <summary>Null omits an input. Zero remains native zero, never a client-invented expiry.</summary>
public sealed class TokenAuthConfigurationInput
{
    /// <summary>Captures optional token policy fields and copies trusted IPs; null omits and zero retains native meaning.</summary>
    public TokenAuthConfigurationInput(int? accessTokenTTL = null, int? accessTokenMaxTTL = null,
        long? accessTokenNumUsesLimit = null, IEnumerable<IdentityTrustedIp>? accessTokenTrustedIps = null)
    {
        AuthenticationJson.Number(accessTokenTTL, 0, 315360000);
        AuthenticationJson.Number(accessTokenMaxTTL, 0, 315360000);
        if (accessTokenNumUsesLimit < 0) throw new ArgumentException("Invalid use limit.");
        AccessTokenTTL = accessTokenTTL;
        AccessTokenMaxTTL = accessTokenMaxTTL;
        AccessTokenNumUsesLimit = accessTokenNumUsesLimit;
        AccessTokenTrustedIps = AuthenticationJson.CopyIps(accessTokenTrustedIps);
    }
    /// <summary>Gets token TTL seconds, or null to omit the field.</summary>
    [JsonIgnore] public int? AccessTokenTTL { get; }
    /// <summary>Gets maximum token TTL seconds, or null to omit the field.</summary>
    [JsonIgnore] public int? AccessTokenMaxTTL { get; }
    /// <summary>Gets the native token-use limit, or null to omit it.</summary>
    [JsonIgnore] public long? AccessTokenNumUsesLimit { get; }
    /// <summary>Gets copied trusted IPs, or null when omitted; explicit collections must be nonempty.</summary>
    [JsonIgnore] public IReadOnlyList<IdentityTrustedIp>? AccessTokenTrustedIps { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        AuthenticationJson.Number(writer, "accessTokenTTL", AccessTokenTTL);
        AuthenticationJson.Number(writer, "accessTokenMaxTTL", AccessTokenMaxTTL);
        if (AccessTokenNumUsesLimit is { } uses) writer.WriteNumber("accessTokenNumUsesLimit", uses);
        AuthenticationJson.Ips(writer, "accessTokenTrustedIps", AccessTokenTrustedIps);
    }
    /// <summary>Returns a marker without policy selectors.</summary>
    public override string ToString() => "[TokenAuthConfigurationInput]";
}

/// <summary>Universal policy only. Period does not imply a finite original max-TTL ceiling.</summary>
public sealed class UniversalAuthConfigurationInput
{
    /// <summary>Captures optional Universal Auth policy and lockout fields without inferring session lifetime.</summary>
    public UniversalAuthConfigurationInput(int? accessTokenTTL = null, int? accessTokenMaxTTL = null,
        long? accessTokenNumUsesLimit = null, int? accessTokenPeriod = null,
        IEnumerable<IdentityTrustedIp>? clientSecretTrustedIps = null,
        IEnumerable<IdentityTrustedIp>? accessTokenTrustedIps = null, bool? lockoutEnabled = null,
        double? lockoutThreshold = null, double? lockoutDurationSeconds = null,
        double? lockoutCounterResetSeconds = null)
    {
        Policy = new(accessTokenTTL, accessTokenMaxTTL, accessTokenNumUsesLimit, accessTokenTrustedIps);
        AuthenticationJson.Number(accessTokenPeriod, 0, int.MaxValue);
        AuthenticationJson.Number(lockoutThreshold, 1, 30);
        AuthenticationJson.Number(lockoutDurationSeconds, 30, 86400);
        AuthenticationJson.Number(lockoutCounterResetSeconds, 5, 3600);
        AccessTokenPeriod = accessTokenPeriod;
        ClientSecretTrustedIps = AuthenticationJson.CopyIps(clientSecretTrustedIps);
        LockoutEnabled = lockoutEnabled;
        LockoutThreshold = lockoutThreshold;
        LockoutDurationSeconds = lockoutDurationSeconds;
        LockoutCounterResetSeconds = lockoutCounterResetSeconds;
    }
    /// <summary>Gets selected common token-policy fields.</summary>
    [JsonIgnore] public TokenAuthConfigurationInput Policy { get; }
    /// <summary>Gets token period seconds, or null when omitted; zero remains native zero.</summary>
    [JsonIgnore] public int? AccessTokenPeriod { get; }
    /// <summary>Gets copied client-secret trusted IPs, or null when omitted.</summary>
    [JsonIgnore] public IReadOnlyList<IdentityTrustedIp>? ClientSecretTrustedIps { get; }
    /// <summary>Gets the explicit lockout switch, or null to leave it omitted.</summary>
    [JsonIgnore] public bool? LockoutEnabled { get; }
    /// <summary>Gets the lockout attempt threshold, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutThreshold { get; }
    /// <summary>Gets lockout duration seconds, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    /// <summary>Gets lockout counter reset seconds, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        Policy.Write(writer);
        AuthenticationJson.Number(writer, "accessTokenPeriod", AccessTokenPeriod);
        AuthenticationJson.Ips(writer, "clientSecretTrustedIps", ClientSecretTrustedIps);
        if (LockoutEnabled is { } enabled) writer.WriteBoolean("lockoutEnabled", enabled);
        AuthenticationJson.Number(writer, "lockoutThreshold", LockoutThreshold);
        AuthenticationJson.Number(writer, "lockoutDurationSeconds", LockoutDurationSeconds);
        AuthenticationJson.Number(writer, "lockoutCounterResetSeconds", LockoutCounterResetSeconds);
    }
    /// <summary>Returns a marker without Universal Auth policy details.</summary>
    public override string ToString() => "[UniversalAuthConfigurationInput]";
}

/// <summary>Protected native configuration metadata, not an effective permission or lifetime proof.</summary>
public sealed class IdentityAuthenticationConfiguration
{
    internal IdentityAuthenticationConfiguration(JsonElement value, string identityId, bool universal)
    {
        string[] members = universal
            ? ["id", "identityId", "createdAt", "updatedAt", "accessTokenTTL", "accessTokenMaxTTL",
                "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "clientId",
                "clientSecretTrustedIps", "lockoutEnabled", "lockoutThreshold", "lockoutDurationSeconds",
                "lockoutCounterResetSeconds"]
            : ["id", "identityId", "createdAt", "updatedAt", "accessTokenTTL", "accessTokenMaxTTL",
                "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps"];
        AuthenticationJson.ClosedObject(value, members);
        ManagementJson.RequireEqual(value, "identityId", identityId);
        Id = ManagementJson.Required(value, "id");
        IdentityId = identityId;
        AuthenticationJson.Uuid(Id);
        AuthenticationJson.Uuid(IdentityId);
        ClientId = universal ? ManagementJson.Required(value, "clientId") : null;
        CreatedAt = AuthenticationJson.Date(value, "createdAt")!.Value;
        UpdatedAt = AuthenticationJson.Date(value, "updatedAt")!.Value;
        AccessTokenTTL = AuthenticationJson.OptionalNumber(value, "accessTokenTTL");
        AccessTokenMaxTTL = AuthenticationJson.OptionalNumber(value, "accessTokenMaxTTL");
        AccessTokenNumUsesLimit = AuthenticationJson.OptionalNumber(value, "accessTokenNumUsesLimit");
        AccessTokenPeriod = AuthenticationJson.OptionalNumber(value, "accessTokenPeriod");
        LockoutEnabled = universal ? AuthenticationJson.OptionalBoolean(value, "lockoutEnabled") : null;
        LockoutThreshold = universal ? AuthenticationJson.OptionalNumber(value, "lockoutThreshold") : null;
        LockoutDurationSeconds = universal ? AuthenticationJson.OptionalNumber(value, "lockoutDurationSeconds") : null;
        LockoutCounterResetSeconds = universal ? AuthenticationJson.OptionalNumber(value, "lockoutCounterResetSeconds") : null;
        // Public response schemas deliberately give these fields no established shape.
        // Do not convert them into a guessed trusted-IP policy or effective authorization.
        HasUnestablishedTrustedIpProjection = value.TryGetProperty("accessTokenTrustedIps", out _) ||
            universal && value.TryGetProperty("clientSecretTrustedIps", out _);
    }
    /// <summary>Gets the returned authentication-configuration identifier.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the identity identifier verified against the request.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets the Universal Auth client identifier; Token Auth configurations leave this null.</summary>
    [JsonIgnore] public string? ClientId { get; }
    /// <summary>Gets the returned configuration creation time with its offset.</summary>
    [JsonIgnore] public DateTimeOffset CreatedAt { get; }
    /// <summary>Gets the returned configuration update time with its offset.</summary>
    [JsonIgnore] public DateTimeOffset UpdatedAt { get; }
    /// <summary>Gets returned token TTL seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenTTL { get; }
    /// <summary>Gets returned maximum TTL seconds, or null when absent; does not infer a session deadline.</summary>
    [JsonIgnore] public double? AccessTokenMaxTTL { get; }
    /// <summary>Gets the returned use limit, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenNumUsesLimit { get; }
    /// <summary>Gets returned token period seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    /// <summary>Gets the returned lockout switch, or null for absence or a non-Universal configuration.</summary>
    [JsonIgnore] public bool? LockoutEnabled { get; }
    /// <summary>Gets the returned lockout threshold, or null when not projected.</summary>
    [JsonIgnore] public double? LockoutThreshold { get; }
    /// <summary>Gets returned lockout duration seconds, or null when not projected.</summary>
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    /// <summary>Gets returned counter reset seconds, or null when not projected.</summary>
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    /// <summary>Gets whether a trusted-IP node exists whose shape is deliberately not interpreted as policy.</summary>
    [JsonIgnore] public bool HasUnestablishedTrustedIpProjection { get; }
    /// <summary>Returns a marker without client or policy metadata.</summary>
    public override string ToString() => "[IdentityAuthenticationConfiguration]";
}

/// <summary>Client-secret metadata never contains usable credential material.</summary>
public sealed class UniversalAuthClientSecret
{
    internal UniversalAuthClientSecret(JsonElement value, string? secretId = null)
    {
        AuthenticationJson.ClosedObject(value, "id", "identityUAId", "description", "clientSecretPrefix",
            "createdAt", "updatedAt", "clientSecretNumUses", "clientSecretNumUsesLimit", "clientSecretTTL",
            "isClientSecretRevoked");
        if (secretId is not null) ManagementJson.RequireEqual(value, "id", secretId);
        Id = ManagementJson.Required(value, "id");
        IdentityUAId = ManagementJson.Required(value, "identityUAId");
        AuthenticationJson.Uuid(IdentityUAId);
        Description = ManagementJson.Required(value, "description");
        ClientSecretPrefix = ManagementJson.Required(value, "clientSecretPrefix");
        CreatedAt = AuthenticationJson.Date(value, "createdAt")!.Value;
        UpdatedAt = AuthenticationJson.Date(value, "updatedAt")!.Value;
        ClientSecretNumUses = AuthenticationJson.OptionalNumber(value, "clientSecretNumUses");
        ClientSecretNumUsesLimit = AuthenticationJson.OptionalNumber(value, "clientSecretNumUsesLimit");
        ClientSecretTTL = AuthenticationJson.OptionalNumber(value, "clientSecretTTL");
        IsClientSecretRevoked = AuthenticationJson.OptionalBoolean(value, "isClientSecretRevoked");
    }
    /// <summary>Gets the returned client-secret identifier, not its usable credential.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the owning Universal Auth configuration identifier.</summary>
    [JsonIgnore] public string IdentityUAId { get; }
    /// <summary>Gets the returned protected client-secret description.</summary>
    [JsonIgnore] public string Description { get; }
    /// <summary>Gets the native secret prefix, not the full client secret.</summary>
    [JsonIgnore] public string ClientSecretPrefix { get; }
    /// <summary>Gets the returned client-secret creation time.</summary>
    [JsonIgnore] public DateTimeOffset CreatedAt { get; }
    /// <summary>Gets the returned client-secret update time.</summary>
    [JsonIgnore] public DateTimeOffset UpdatedAt { get; }
    /// <summary>Gets reported use count, or null when absent.</summary>
    [JsonIgnore] public double? ClientSecretNumUses { get; }
    /// <summary>Gets reported use limit, or null when absent.</summary>
    [JsonIgnore] public double? ClientSecretNumUsesLimit { get; }
    /// <summary>Gets reported client-secret TTL seconds, or null when absent.</summary>
    [JsonIgnore] public double? ClientSecretTTL { get; }
    /// <summary>Gets reported revocation state, or null when absent; absence is not false.</summary>
    [JsonIgnore] public bool? IsClientSecretRevoked { get; }
    /// <summary>Returns a marker without client-secret metadata.</summary>
    public override string ToString() => "[UniversalAuthClientSecret]";
}

/// <summary>Owned client-secret issuance result; dispose after use, and treat revealed strings as ordinary plaintext.</summary>
public sealed class UniversalAuthClientSecretCreation : IDisposable
{
    internal UniversalAuthClientSecretCreation(JsonElement root)
    {
        AuthenticationJson.ClosedObject(root, "clientSecret", "clientSecretData");
        Metadata = new(ManagementJson.Object(root, "clientSecretData"));
        ClientSecret = AuthenticationJson.Material(root, "clientSecret");
    }
    /// <summary>Gets metadata associated with the issued client secret.</summary>
    [JsonIgnore] public UniversalAuthClientSecret Metadata { get; }
    /// <summary>Gets owned secret material; revealing it creates a string that disposal cannot erase.</summary>
    [JsonIgnore] public SecretMaterial ClientSecret { get; }
    /// <summary>Disposes the owned client-secret material without revoking the remote credential.</summary>
    public void Dispose() => ClientSecret.Dispose();
    /// <summary>Returns a marker without client-secret material.</summary>
    public override string ToString() => "[UniversalAuthClientSecretCreation]";
}

/// <summary>Token metadata, not a token source or permission grant.</summary>
public sealed class TokenAuthToken
{
    internal TokenAuthToken(JsonElement value, string? identityId = null, string? tokenId = null)
    {
        AuthenticationJson.ClosedObject(value, "id", "identityId", "authMethod", "createdAt", "updatedAt",
            "name", "subOrganizationId", "identityUAClientSecretId", "accessTokenTTL", "accessTokenMaxTTL",
            "accessTokenNumUses", "accessTokenNumUsesLimit", "accessTokenPeriod", "isAccessTokenRevoked",
            "accessTokenLastUsedAt", "accessTokenLastRenewedAt");
        if (identityId is not null) ManagementJson.RequireEqual(value, "identityId", identityId);
        if (tokenId is not null) ManagementJson.RequireEqual(value, "id", tokenId);
        Id = ManagementJson.Required(value, "id");
        IdentityId = ManagementJson.Required(value, "identityId");
        AuthenticationJson.Uuid(IdentityId);
        Name = ProjectWire.StringField(value, "name", nullable: true);
        SubOrganizationId = ProjectWire.StringField(value, "subOrganizationId", nullable: true);
        if (SubOrganizationId.IsPresent && !SubOrganizationId.IsNull)
            AuthenticationJson.Uuid(SubOrganizationId.Value);
        AuthMethod = ManagementJson.Required(value, "authMethod");
        AccessTokenTTL = AuthenticationJson.OptionalNumber(value, "accessTokenTTL");
        AccessTokenMaxTTL = AuthenticationJson.OptionalNumber(value, "accessTokenMaxTTL");
        AccessTokenNumUses = AuthenticationJson.OptionalNumber(value, "accessTokenNumUses");
        AccessTokenNumUsesLimit = AuthenticationJson.OptionalNumber(value, "accessTokenNumUsesLimit");
        AccessTokenPeriod = AuthenticationJson.OptionalNumber(value, "accessTokenPeriod");
        IsAccessTokenRevoked = AuthenticationJson.OptionalBoolean(value, "isAccessTokenRevoked");
        IdentityUAClientSecretId = ProjectWire.StringField(value, "identityUAClientSecretId", nullable: true);
        CreatedAt = AuthenticationJson.Date(value, "createdAt")!.Value;
        UpdatedAt = AuthenticationJson.Date(value, "updatedAt")!.Value;
        AccessTokenLastUsedAt = ProjectWire.Field(value, "accessTokenLastUsedAt",
            _ => AuthenticationJson.Date(value, "accessTokenLastUsedAt", true)!.Value, nullable: true);
        AccessTokenLastRenewedAt = ProjectWire.Field(value, "accessTokenLastRenewedAt",
            _ => AuthenticationJson.Date(value, "accessTokenLastRenewedAt", true)!.Value, nullable: true);
    }
    /// <summary>Gets the returned token identifier, not the bearer token.</summary>
    [JsonIgnore] public string Id { get; }
    /// <summary>Gets the returned owning identity identifier.</summary>
    [JsonIgnore] public string IdentityId { get; }
    /// <summary>Gets token-name presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> Name { get; }
    /// <summary>Gets suborganization presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> SubOrganizationId { get; }
    /// <summary>Gets the returned native authentication-method label.</summary>
    [JsonIgnore] public string AuthMethod { get; }
    /// <summary>Gets Universal Auth client-secret identifier presence when supplied.</summary>
    [JsonIgnore] public ProjectField<string> IdentityUAClientSecretId { get; }
    /// <summary>Gets reported TTL seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenTTL { get; }
    /// <summary>Gets reported maximum TTL seconds, or null when absent; not an inferred finite lifetime.</summary>
    [JsonIgnore] public double? AccessTokenMaxTTL { get; }
    /// <summary>Gets reported use count, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenNumUses { get; }
    /// <summary>Gets reported token-use limit, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenNumUsesLimit { get; }
    /// <summary>Gets reported token period seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    /// <summary>Gets reported revocation state, or null when absent.</summary>
    [JsonIgnore] public bool? IsAccessTokenRevoked { get; }
    /// <summary>Gets the returned token creation time.</summary>
    [JsonIgnore] public DateTimeOffset CreatedAt { get; }
    /// <summary>Gets the returned token update time.</summary>
    [JsonIgnore] public DateTimeOffset UpdatedAt { get; }
    /// <summary>Gets last-use timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<DateTimeOffset> AccessTokenLastUsedAt { get; }
    /// <summary>Gets last-renewal timestamp presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<DateTimeOffset> AccessTokenLastRenewedAt { get; }
    /// <summary>Returns a marker without token metadata or identifiers.</summary>
    public override string ToString() => "[TokenAuthToken]";
}

/// <summary>Native reported seconds, not an inferred finite session lifetime.</summary>
public sealed class TokenAuthTokenCreation : IDisposable
{
    internal TokenAuthTokenCreation(JsonElement root, string identityId)
    {
        AuthenticationJson.ClosedObject(root, "tokenData", "accessToken", "tokenType", "expiresIn", "accessTokenMaxTTL");
        Metadata = new(ManagementJson.Object(root, "tokenData"), identityId);
        ExpiresIn = AuthenticationJson.RequiredNumber(root, "expiresIn");
        AccessTokenMaxTTL = AuthenticationJson.RequiredNumber(root, "accessTokenMaxTTL");
        if (ManagementJson.Required(root, "tokenType") != "Bearer")
            throw new ManagementContractException(SecretStatus.Unknown);
        AccessToken = AuthenticationJson.Material(root, "accessToken");
    }
    /// <summary>Gets metadata associated with the issued bearer token.</summary>
    [JsonIgnore] public TokenAuthToken Metadata { get; }
    /// <summary>Gets owned bearer material; reveal is a deliberate plaintext export.</summary>
    [JsonIgnore] public SecretMaterial AccessToken { get; }
    /// <summary>Gets native reported expiry seconds without manufacturing a local session deadline.</summary>
    [JsonIgnore] public double ExpiresIn { get; }
    /// <summary>Gets native reported maximum TTL seconds, retaining native zero semantics.</summary>
    [JsonIgnore] public double AccessTokenMaxTTL { get; }
    /// <summary>Disposes owned bearer material; does not revoke the provider token or erase exported strings.</summary>
    public void Dispose() => AccessToken.Dispose();
    /// <summary>Returns a marker without bearer material.</summary>
    public override string ToString() => "[TokenAuthTokenCreation]";
}

/// <summary>Native lockout-clear or revocation acknowledgement, not a runtime capability attestation.</summary>
public sealed class IdentityAuthenticationAcknowledgement
{
    internal IdentityAuthenticationAcknowledgement(JsonElement root, bool lockout)
    {
        AuthenticationJson.ClosedObject(root, lockout ? "deleted" : "message");
        if (lockout) Deleted = AuthenticationJson.RequiredNumber(root, "deleted");
        else Message = ManagementJson.Required(root, "message");
    }
    /// <summary>Gets the native deleted-lockout count, or null for token revocation acknowledgements.</summary>
    [JsonIgnore] public double? Deleted { get; }
    /// <summary>Gets the native revocation message, or null for lockout-clear acknowledgements.</summary>
    [JsonIgnore] public string? Message { get; }
    /// <summary>Returns a marker without the acknowledgement message.</summary>
    public override string ToString() => "[IdentityAuthenticationAcknowledgement]";
}

internal static class AuthenticationJson
{
    internal static void Uuid(ProjectField<string> value)
    {
        if (value.IsPresent && !value.IsNull) Uuid(value.Value);
    }

    internal static void Uuid(string value)
    {
        if (!Guid.TryParseExact(value, "D", out _))
            throw new ManagementContractException(SecretStatus.Unknown);
    }

    internal static JsonElement Object(JsonElement root, string field)
    {
        ClosedObject(root, field);
        return ManagementJson.Object(root, field);
    }

    internal static void ClosedObject(JsonElement value, params string[] members)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            value.EnumerateObject().Any(property => !members.Contains(property.Name, StringComparer.Ordinal)))
            throw new ManagementContractException(SecretStatus.Unknown);
    }

    internal static void Number(double? value, double minimum, double maximum)
    {
        if (value is { } number && (!double.IsFinite(number) || number < minimum || number > maximum))
            throw new ArgumentException("Invalid native authentication number.");
    }
    internal static void Number(Utf8JsonWriter writer, string field, double? value)
    {
        if (value is { } number) writer.WriteNumber(field, number);
    }
    internal static double? OptionalNumber(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out var child)) return null;
        if (!child.TryGetDouble(out double result) || !double.IsFinite(result) || result < 0)
            throw new ManagementContractException(SecretStatus.Unknown);
        return result;
    }
    internal static double RequiredNumber(JsonElement value, string field) =>
        OptionalNumber(value, field) ?? throw new ManagementContractException(SecretStatus.Unknown);
    internal static bool? OptionalBoolean(JsonElement value, string field) =>
        value.TryGetProperty(field, out _) ? ManagementJson.Boolean(value, field) : null;
    internal static DateTimeOffset? Date(JsonElement value, string field, bool nullable = false)
    {
        if (nullable && (!value.TryGetProperty(field, out var optional) || optional.ValueKind == JsonValueKind.Null))
            return null;
        if (!value.TryGetProperty(field, out var child) || !child.TryGetDateTimeOffset(out var result))
            throw new ManagementContractException(SecretStatus.Unknown);
        string text = child.GetString()!;
        if (text.Length < 20 || !(text.EndsWith('Z') ||
            text.Length >= 25 && text[^6] is '+' or '-'))
            throw new ManagementContractException(SecretStatus.Unknown);
        return result;
    }
    internal static SecretMaterial Material(JsonElement root, string field)
    {
        string value = ManagementJson.Required(root, field);
        if (value.Length is < 1 or > 16384 || value.Any(char.IsControl))
            throw new ManagementContractException(SecretStatus.Unknown);
        return SecretMaterial.FromText(value);
    }
    internal static IReadOnlyList<IdentityTrustedIp>? CopyIps(IEnumerable<IdentityTrustedIp>? values)
    {
        if (values is null) return null;
        var copy = values.Take(101).ToArray();
        if (copy.Length is < 1 or > 100 || copy.Any(value => value is null))
            throw new ArgumentException("Invalid trusted IP input budget.");
        return Array.AsReadOnly(copy);
    }
    internal static void Ips(Utf8JsonWriter writer, string field, IReadOnlyList<IdentityTrustedIp>? values)
    {
        if (values is null) return;
        writer.WriteStartArray(field);
        foreach (var value in values)
        {
            writer.WriteStartObject();
            writer.WriteString("ipAddress", value.IpAddress);
            writer.WriteEndObject();
        }
        writer.WriteEndArray();
    }
    internal static void OptionalText(string? value, int maximum)
    {
        if (value is not null && (value.Length > maximum || value.Any(char.IsControl)))
            throw new ArgumentException("Invalid protected authentication text.");
    }
    internal static ManagementTarget Intent(string organizationId, string resourceId, string action,
        Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray();
                writer.WriteStringValue(action);
                write(writer);
                writer.WriteEndArray();
            }
            return new(organizationId, resourceId: resourceId,
                secondaryId: Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("Authentication input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }
}
