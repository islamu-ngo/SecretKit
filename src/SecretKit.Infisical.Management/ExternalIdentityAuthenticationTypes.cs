using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native LDAP attribute predicate; no effective permission claim.</summary>
public sealed class LdapAuthAllowedField
{
    public LdapAuthAllowedField(string key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        WorkloadAuthJson.Text(key);
        WorkloadAuthJson.Text(value);
        Key = key;
        Value = value;
    }
    [JsonIgnore] public string Key { get; }
    [JsonIgnore] public string Value { get; }
    public override string ToString() => "[LdapAuthAllowedField]";
}

/// <summary>Shared optional LDAP policy; omitted values never acquire server defaults.</summary>
public sealed class LdapAuthSettings
{
    public LdapAuthSettings(string? searchFilter = null, IEnumerable<LdapAuthAllowedField>? allowedFields = null,
        bool? lockoutEnabled = null, double? lockoutThreshold = null, double? lockoutDurationSeconds = null,
        double? lockoutCounterResetSeconds = null, WorkloadAuthTokenPolicy? policy = null)
    {
        ExternalAuthJson.Text(searchFilter, 1);
        ExternalAuthJson.Range(lockoutThreshold, 1, 30);
        ExternalAuthJson.Range(lockoutDurationSeconds, 30, 86400);
        ExternalAuthJson.Range(lockoutCounterResetSeconds, 5, 3600);
        var copy = allowedFields?.Take(101).ToArray();
        if (copy is not null && (copy.Length > 100 || copy.Any(field => field is null)))
            throw new ArgumentException("Invalid LDAP field budget.");
        SearchFilter = searchFilter;
        AllowedFields = copy is null ? null : Array.AsReadOnly(copy);
        LockoutEnabled = lockoutEnabled;
        LockoutThreshold = lockoutThreshold;
        LockoutDurationSeconds = lockoutDurationSeconds;
        LockoutCounterResetSeconds = lockoutCounterResetSeconds;
        Policy = policy ?? new();
    }
    [JsonIgnore] public string? SearchFilter { get; }
    [JsonIgnore] public IReadOnlyList<LdapAuthAllowedField>? AllowedFields { get; }
    [JsonIgnore] public bool? LockoutEnabled { get; }
    [JsonIgnore] public double? LockoutThreshold { get; }
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        WorkloadAuthJson.String(writer, "searchFilter", SearchFilter);
        if (AllowedFields is not null)
        {
            writer.WriteStartArray("allowedFields");
            foreach (var field in AllowedFields)
            {
                writer.WriteStartObject();
                writer.WriteString("key", field.Key);
                writer.WriteString("value", field.Value);
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
        }
        if (LockoutEnabled is { } enabled) writer.WriteBoolean("lockoutEnabled", enabled);
        ExternalAuthJson.Number(writer, "lockoutThreshold", LockoutThreshold);
        ExternalAuthJson.Number(writer, "lockoutDurationSeconds", LockoutDurationSeconds);
        ExternalAuthJson.Number(writer, "lockoutCounterResetSeconds", LockoutCounterResetSeconds);
        Policy.Write(writer);
    }
    public override string ToString() => "[LdapAuthSettings]";
}

/// <summary>Two established undiscriminated attachment alternatives. Owns copied bind material.</summary>
public sealed class LdapAuthConfigurationInput : IDisposable
{
    private readonly SecretMaterial? _bindPass;
    private readonly SecretMaterial? _certificate;
    private bool _disposed;
    private LdapAuthConfigurationInput(string? templateId, string? url, string? bindDN, SecretMaterial? bindPass,
        string? searchBase, SecretMaterial? ldapCaCertificate, LdapAuthSettings? settings, bool update)
    {
        ExternalAuthJson.Text(templateId);
        foreach (var text in new[] { url, bindDN, searchBase }) ExternalAuthJson.Text(text, update ? 1 : 0);
        if (ldapCaCertificate is not null) ExternalAuthJson.Text(ldapCaCertificate.Reveal());
        if (bindPass is not null) ExternalAuthJson.Text(bindPass.Reveal(), update ? 1 : 0);
        TemplateId = templateId;
        Url = url;
        BindDN = bindDN;
        SearchBase = searchBase;
        Settings = settings ?? new();
        if (!update) ExternalAuthJson.AttachPolicy(Settings.Policy);
        IsUpdate = update;
        _bindPass = bindPass?.Copy();
        try { _certificate = ldapCaCertificate?.Copy(); }
        catch { _bindPass?.Dispose(); throw; }
    }
    public static LdapAuthConfigurationInput FromTemplate(string templateId, SecretMaterial? ldapCaCertificate = null,
        LdapAuthSettings? settings = null)
    {
        ArgumentNullException.ThrowIfNull(templateId);
        return new(templateId, null, null, null, null, ldapCaCertificate, settings, false);
    }
    public static LdapAuthConfigurationInput FromConnection(string url, string bindDN, SecretMaterial bindPass,
        string searchBase, SecretMaterial? ldapCaCertificate = null, LdapAuthSettings? settings = null)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(bindDN);
        ArgumentNullException.ThrowIfNull(bindPass);
        ArgumentNullException.ThrowIfNull(searchBase);
        return new(null, url, bindDN, bindPass, searchBase, ldapCaCertificate, settings, false);
    }
    public static LdapAuthConfigurationInput Patch(string? templateId = null, string? url = null,
        string? bindDN = null, SecretMaterial? bindPass = null, string? searchBase = null,
        LdapAuthSettings? settings = null) => new(templateId, url, bindDN, bindPass, searchBase, null, settings, true);
    [JsonIgnore] public string? TemplateId { get; }
    [JsonIgnore] public string? Url { get; }
    [JsonIgnore] public string? BindDN { get; }
    [JsonIgnore] public string? SearchBase { get; }
    [JsonIgnore] public LdapAuthSettings Settings { get; }
    [JsonIgnore] public bool IsUpdate { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        WorkloadAuthJson.String(writer, "templateId", TemplateId);
        WorkloadAuthJson.String(writer, "url", Url);
        WorkloadAuthJson.String(writer, "bindDN", BindDN);
        if (_bindPass is not null) writer.WriteString("bindPass", _bindPass.Reveal());
        WorkloadAuthJson.String(writer, "searchBase", SearchBase);
        if (_certificate is not null) writer.WriteString("ldapCaCertificate", _certificate.Reveal());
        Settings.Write(writer);
    }
    public void Dispose()
    {
        _disposed = true;
        _bindPass?.Dispose();
        _certificate?.Dispose();
    }
    public override string ToString() => "[LdapAuthConfigurationInput]";
}

public sealed class OciAuthConfigurationInput
{
    public OciAuthConfigurationInput(string tenancyOcid, WorkloadAuthNullableText? allowedUsernames = null,
        WorkloadAuthTokenPolicy? policy = null)
    {
        ArgumentNullException.ThrowIfNull(tenancyOcid);
        ExternalAuthJson.Text(tenancyOcid, 1);
        ExternalAuthJson.Text(allowedUsernames?.Value, maximum: 500);
        TenancyOcid = tenancyOcid;
        AllowedUsernames = allowedUsernames;
        Policy = policy ?? new();
    }
    [JsonIgnore] public string TenancyOcid { get; }
    [JsonIgnore] public WorkloadAuthNullableText? AllowedUsernames { get; }
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteString("tenancyOcid", TenancyOcid);
        WorkloadAuthJson.Nullable(writer, "allowedUsernames", AllowedUsernames);
        Policy.Write(writer);
    }
    public override string ToString() => "[OciAuthConfigurationInput]";
}

/// <summary>Host-supplied bundle distribution, never bundle acquisition or issuer provisioning.</summary>
public sealed class SpiffeTrustBundleInput : IDisposable
{
    private readonly SecretMaterial? _bundle;
    private readonly SecretMaterial? _caCert;
    private bool _disposed;
    private SpiffeTrustBundleInput(SecretMaterial? bundle, string? endpointUrl, SecretMaterial? caCert,
        long? refreshHintSeconds)
    {
        if (bundle is not null) ExternalAuthJson.Text(bundle.Reveal(), 1);
        if (endpointUrl is not null) WorkloadAuthJson.Uri(endpointUrl);
        if (caCert is not null) ExternalAuthJson.Text(caCert.Reveal());
        if (refreshHintSeconds < 0) throw new ArgumentException("Invalid bundle refresh hint.");
        EndpointUrl = endpointUrl;
        RefreshHintSeconds = refreshHintSeconds;
        _bundle = bundle?.Copy();
        try { _caCert = caCert?.Copy(); }
        catch { _bundle?.Dispose(); throw; }
    }
    public static SpiffeTrustBundleInput Static(SecretMaterial bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        return new(bundle, null, null, null);
    }
    public static SpiffeTrustBundleInput HttpsWebBundle(string endpointUrl, SecretMaterial? caCert = null,
        long? refreshHintSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(endpointUrl);
        return new(null, endpointUrl, caCert, refreshHintSeconds);
    }
    [JsonIgnore] public string? EndpointUrl { get; }
    [JsonIgnore] public long? RefreshHintSeconds { get; }
    internal SpiffeTrustBundleInput Copy()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new(_bundle, EndpointUrl, _caCert, RefreshHintSeconds);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        writer.WriteStartObject("trustBundleDistribution");
        writer.WriteString("profile", EndpointUrl is null ? "static" : "https_web_bundle");
        if (_bundle is not null) writer.WriteString("bundle", _bundle.Reveal());
        WorkloadAuthJson.String(writer, "endpointUrl", EndpointUrl);
        if (_caCert is not null) writer.WriteString("caCert", _caCert.Reveal());
        if (RefreshHintSeconds is { } hint) writer.WriteNumber("refreshHintSeconds", hint);
        writer.WriteEndObject();
    }
    public void Dispose()
    {
        _disposed = true;
        _bundle?.Dispose();
        _caCert?.Dispose();
    }
    public override string ToString() => "[SpiffeTrustBundleInput]";
}

public sealed class SpiffeAuthConfigurationInput : IDisposable
{
    private readonly SpiffeTrustBundleInput? _distribution;
    private bool _disposed;
    public SpiffeAuthConfigurationInput(string? trustDomain = null, string? allowedSpiffeIds = null,
        string? allowedAudiences = null, SpiffeTrustBundleInput? trustBundleDistribution = null,
        WorkloadAuthTokenPolicy? policy = null)
    {
        foreach (var text in new[] { trustDomain, allowedSpiffeIds, allowedAudiences }) ExternalAuthJson.Text(text, 1);
        TrustDomain = trustDomain;
        AllowedSpiffeIds = allowedSpiffeIds;
        AllowedAudiences = allowedAudiences;
        Policy = policy ?? new();
        _distribution = trustBundleDistribution?.Copy();
    }
    [JsonIgnore] public string? TrustDomain { get; }
    [JsonIgnore] public string? AllowedSpiffeIds { get; }
    [JsonIgnore] public string? AllowedAudiences { get; }
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (TrustDomain is null || AllowedSpiffeIds is null || AllowedAudiences is null || _distribution is null)
            throw new ArgumentException("SPIFFE attachment requires trust domain, IDs, audiences and bundle distribution.");
    }
    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        WorkloadAuthJson.String(writer, "trustDomain", TrustDomain);
        WorkloadAuthJson.String(writer, "allowedSpiffeIds", AllowedSpiffeIds);
        WorkloadAuthJson.String(writer, "allowedAudiences", AllowedAudiences);
        _distribution?.Write(writer);
        Policy.Write(writer);
    }
    public void Dispose()
    {
        _disposed = true;
        _distribution?.Dispose();
    }
    public override string ToString() => "[SpiffeAuthConfigurationInput]";
}

/// <summary>A null argument omits SANs; Null explicitly clears them; an empty array remains explicit.</summary>
public sealed class TlsAuthSubjectAltNames
{
    private TlsAuthSubjectAltNames(IReadOnlyList<string>? values) => Values = values;
    internal IReadOnlyList<string>? Values { get; }
    public static TlsAuthSubjectAltNames Null() => new(null);
    public static TlsAuthSubjectAltNames FromValues(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return new(WorkloadAuthJson.Strings(values, true));
    }
    public override string ToString() => "[TlsAuthSubjectAltNames]";
}

public sealed class TlsCertAuthConfigurationInput : IDisposable
{
    private readonly SecretMaterial? _certificate;
    private bool _disposed;
    public TlsCertAuthConfigurationInput(SecretMaterial? caCertificate = null,
        WorkloadAuthNullableText? allowedCommonNames = null, TlsAuthSubjectAltNames? allowedSubjectAltNames = null,
        bool? verifyClientCertificateChain = null, WorkloadAuthTokenPolicy? policy = null)
    {
        if (caCertificate is not null) ExternalAuthJson.Text(caCertificate.Reveal(), 1, 10240);
        ExternalAuthJson.Text(allowedCommonNames?.Value, 1);
        AllowedCommonNames = allowedCommonNames;
        AllowedSubjectAltNames = allowedSubjectAltNames;
        VerifyClientCertificateChain = verifyClientCertificateChain;
        Policy = policy ?? new();
        _certificate = caCertificate?.Copy();
    }
    [JsonIgnore] public WorkloadAuthNullableText? AllowedCommonNames { get; }
    [JsonIgnore] public TlsAuthSubjectAltNames? AllowedSubjectAltNames { get; }
    [JsonIgnore] public bool? VerifyClientCertificateChain { get; }
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void ValidateAttach()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_certificate is null) throw new ArgumentException("TLS attachment requires a CA certificate.");
        ExternalAuthJson.AttachPolicy(Policy);
    }
    internal void Write(Utf8JsonWriter writer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_certificate is not null) writer.WriteString("caCertificate", _certificate.Reveal());
        WorkloadAuthJson.Nullable(writer, "allowedCommonNames", AllowedCommonNames);
        if (AllowedSubjectAltNames is not null)
        {
            if (AllowedSubjectAltNames.Values is null) writer.WriteNull("allowedSubjectAltNames");
            else WorkloadAuthJson.Strings(writer, "allowedSubjectAltNames", AllowedSubjectAltNames.Values);
        }
        if (VerifyClientCertificateChain is { } verify) writer.WriteBoolean("verifyClientCertificateChain", verify);
        Policy.Write(writer);
    }
    public void Dispose()
    {
        _disposed = true;
        _certificate?.Dispose();
    }
    public override string ToString() => "[TlsCertAuthConfigurationInput]";
}

public sealed class LdapAuthConfiguration : WorkloadAuthConfiguration, IDisposable
{
    internal LdapAuthConfiguration(JsonElement value, string identityId, bool read) : base(value, identityId)
    {
        Url = ManagementJson.Required(value, "url");
        SearchBase = ManagementJson.Required(value, "searchBase");
        SearchFilter = ManagementJson.Required(value, "searchFilter");
        TemplateId = WorkloadAuthJson.NullableResponse(value, "templateId");
        AuthenticationJson.Uuid(TemplateId);
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
        LockoutEnabled = AuthenticationJson.OptionalBoolean(value, "lockoutEnabled");
        LockoutThreshold = WorkloadAuthJson.Number(value, "lockoutThreshold");
        LockoutDurationSeconds = WorkloadAuthJson.Number(value, "lockoutDurationSeconds");
        LockoutCounterResetSeconds = WorkloadAuthJson.Number(value, "lockoutCounterResetSeconds");
        HasUnestablishedAllowedFieldsProjection = value.TryGetProperty("allowedFields", out _);
        if (read)
        {
            BindDN = ManagementJson.Required(value, "bindDN");
            var certificate = WorkloadAuthJson.OptionalResponse(value, "ldapCaCertificate");
            if (certificate is not null) LdapCaCertificate = SecretMaterial.FromText(certificate);
        }
    }
    [JsonIgnore] public string Url { get; }
    [JsonIgnore] public string SearchBase { get; }
    [JsonIgnore] public string SearchFilter { get; }
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    [JsonIgnore] public bool? LockoutEnabled { get; }
    [JsonIgnore] public double? LockoutThreshold { get; }
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    [JsonIgnore] public bool HasUnestablishedAllowedFieldsProjection { get; }
    [JsonIgnore] public string? BindDN { get; }
    [JsonIgnore] public SecretMaterial? LdapCaCertificate { get; }
    public void Dispose() => LdapCaCertificate?.Dispose();
}

public sealed class OciAuthConfiguration : WorkloadAuthConfiguration
{
    internal OciAuthConfiguration(JsonElement value, string identityId) : base(value, identityId)
    {
        TenancyOcid = ManagementJson.Required(value, "tenancyOcid");
        Type = ManagementJson.Required(value, "type");
        AllowedUsernames = WorkloadAuthJson.NullableResponse(value, "allowedUsernames");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    [JsonIgnore] public string TenancyOcid { get; }
    [JsonIgnore] public string Type { get; }
    [JsonIgnore] public ProjectField<string> AllowedUsernames { get; }
    [JsonIgnore] public double? AccessTokenPeriod { get; }
}

/// <summary>Protected known bundle fields; unknown profile values fail closed.</summary>
public sealed class SpiffeTrustBundleConfiguration : IDisposable
{
    internal SpiffeTrustBundleConfiguration(JsonElement value)
    {
        Profile = ManagementJson.Required(value, "profile");
        if (Profile == "static")
        {
            AuthenticationJson.ClosedObject(value, "profile", "bundle");
            Bundle = SecretMaterial.FromText(ManagementJson.Required(value, "bundle"));
        }
        else if (Profile == "https_web_bundle")
        {
            AuthenticationJson.ClosedObject(value, "profile", "endpointUrl", "caCert",
                "refreshHintSeconds", "cachedBundleLastRefreshedAt");
            EndpointUrl = ManagementJson.Required(value, "endpointUrl");
            RefreshHintSeconds = WorkloadAuthJson.Number(value, "refreshHintSeconds")
                ?? throw new ManagementContractException(SecretStatus.Unknown);
            CachedBundleLastRefreshedAt = ExternalAuthJson.NullableDate(value, "cachedBundleLastRefreshedAt");
            CaCert = SecretMaterial.FromText(ManagementJson.Required(value, "caCert"));
        }
        else throw new ManagementContractException(SecretStatus.Unknown);
    }
    [JsonIgnore] public string Profile { get; }
    [JsonIgnore] public SecretMaterial? Bundle { get; }
    [JsonIgnore] public string? EndpointUrl { get; }
    [JsonIgnore] public SecretMaterial? CaCert { get; }
    [JsonIgnore] public double? RefreshHintSeconds { get; }
    [JsonIgnore] public ProjectField<DateTimeOffset> CachedBundleLastRefreshedAt { get; }
    public void Dispose()
    {
        Bundle?.Dispose();
        CaCert?.Dispose();
    }
    public override string ToString() => "[SpiffeTrustBundleConfiguration]";
}

public sealed class SpiffeAuthConfiguration : WorkloadAuthConfiguration, IDisposable
{
    internal SpiffeAuthConfiguration(JsonElement value, string identityId) : base(value, identityId)
    {
        TrustDomain = ManagementJson.Required(value, "trustDomain");
        AllowedSpiffeIds = ManagementJson.Required(value, "allowedSpiffeIds");
        AllowedAudiences = ManagementJson.Required(value, "allowedAudiences");
        // Sensitive allocation is last: malformed coordinates/fields cannot strand owned material.
        TrustBundleDistribution = new(ManagementJson.Object(value, "trustBundleDistribution"));
    }
    [JsonIgnore] public string TrustDomain { get; }
    [JsonIgnore] public string AllowedSpiffeIds { get; }
    [JsonIgnore] public string AllowedAudiences { get; }
    [JsonIgnore] public SpiffeTrustBundleConfiguration TrustBundleDistribution { get; }
    public void Dispose() => TrustBundleDistribution.Dispose();
}

public sealed class TlsCertAuthConfiguration : WorkloadAuthConfiguration, IDisposable
{
    internal TlsCertAuthConfiguration(JsonElement value, string identityId, bool read) : base(value, identityId)
    {
        AllowedCommonNames = WorkloadAuthJson.NullableResponse(value, "allowedCommonNames");
        if (!value.TryGetProperty("allowedSubjectAltNames", out var names))
            throw new ManagementContractException(SecretStatus.Unknown);
        AllowedSubjectAltNames = names.ValueKind == JsonValueKind.Null ? ProjectField<IReadOnlyList<string>>.Null()
            : ProjectField<IReadOnlyList<string>>.Present(WorkloadAuthJson.ResponseStrings(value, "allowedSubjectAltNames"));
        VerifyClientCertificateChain = AuthenticationJson.OptionalBoolean(value, "verifyClientCertificateChain");
        if (!value.TryGetProperty("encryptedCaCertificate", out _))
            throw new ManagementContractException(SecretStatus.Unknown);
        HasUnestablishedEncryptedCaCertificateProjection = true;
        if (read) CaCertificate = SecretMaterial.FromText(ManagementJson.Required(value, "caCertificate"));
    }
    [JsonIgnore] public ProjectField<string> AllowedCommonNames { get; }
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AllowedSubjectAltNames { get; }
    [JsonIgnore] public bool? VerifyClientCertificateChain { get; }
    [JsonIgnore] public bool HasUnestablishedEncryptedCaCertificateProjection { get; }
    [JsonIgnore] public SecretMaterial? CaCertificate { get; }
    public void Dispose() => CaCertificate?.Dispose();
}

public sealed class LdapAuthLockoutResult
{
    internal LdapAuthLockoutResult(JsonElement value) => Deleted = WorkloadAuthJson.Number(value, "deleted")
        ?? throw new ManagementContractException(SecretStatus.Unknown);
    [JsonIgnore] public double Deleted { get; }
    public override string ToString() => "[LdapAuthLockoutResult]";
}

internal static class ExternalAuthJson
{
    internal static void Text(string? value, int minimum = 0, int maximum = 16384)
    {
        if (value is not null && (value.Length < minimum || value.Length > maximum))
            throw new ArgumentException("Invalid external authentication input budget.");
    }
    internal static void Range(double? value, double minimum, double maximum)
    {
        if (value is { } number && (!double.IsFinite(number) || number < minimum || number > maximum))
            throw new ArgumentException("Invalid external authentication number.");
    }
    internal static void Number(Utf8JsonWriter writer, string field, double? value)
    {
        if (value is { } number) writer.WriteNumber(field, number);
    }
    internal static void AttachPolicy(WorkloadAuthTokenPolicy policy)
    {
        if (policy.AccessTokenMaxTTL == 0) throw new ArgumentException("Attachment requires a positive maximum TTL.");
    }
    internal static ProjectField<DateTimeOffset> NullableDate(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out var child)) return default;
        if (child.ValueKind == JsonValueKind.Null) return ProjectField<DateTimeOffset>.Null();
        return ProjectField<DateTimeOffset>.Present(AuthenticationJson.Date(value, field)!.Value);
    }
}
