using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Native LDAP attribute predicate; no effective permission claim.</summary>
public sealed class LdapAuthAllowedField
{
    /// <summary>Captures a bounded native LDAP attribute predicate without evaluating directory access.</summary>
    public LdapAuthAllowedField(string key, string value)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(value);
        WorkloadAuthJson.Text(key);
        WorkloadAuthJson.Text(value);
        Key = key;
        Value = value;
    }
    /// <summary>Gets the selected LDAP attribute name.</summary>
    [JsonIgnore] public string Key { get; }
    /// <summary>Gets the selected protected attribute value.</summary>
    [JsonIgnore] public string Value { get; }
    /// <summary>Returns a marker without LDAP predicates.</summary>
    public override string ToString() => "[LdapAuthAllowedField]";
}

/// <summary>Shared optional LDAP policy; omitted values never acquire server defaults.</summary>
public sealed class LdapAuthSettings
{
    /// <summary>Copies optional LDAP settings; null fields are omitted and empty predicate arrays remain explicit.</summary>
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
    /// <summary>Gets the optional search filter; null leaves it omitted.</summary>
    [JsonIgnore] public string? SearchFilter { get; }
    /// <summary>Gets copied allowed-field predicates, or null when omitted.</summary>
    [JsonIgnore] public IReadOnlyList<LdapAuthAllowedField>? AllowedFields { get; }
    /// <summary>Gets the explicit lockout switch, or null when omitted.</summary>
    [JsonIgnore] public bool? LockoutEnabled { get; }
    /// <summary>Gets the selected failed-attempt threshold, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutThreshold { get; }
    /// <summary>Gets selected lockout duration seconds, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    /// <summary>Gets selected counter reset seconds, or null when omitted.</summary>
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    /// <summary>Gets selected token-policy fields without inferring defaults.</summary>
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
    /// <summary>Returns a marker without LDAP settings.</summary>
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
    /// <summary>Creates attachment from a template and copies optional CA material; caller retains the originals.</summary>
    public static LdapAuthConfigurationInput FromTemplate(string templateId, SecretMaterial? ldapCaCertificate = null,
        LdapAuthSettings? settings = null)
    {
        ArgumentNullException.ThrowIfNull(templateId);
        return new(templateId, null, null, null, null, ldapCaCertificate, settings, false);
    }
    /// <summary>Creates attachment from explicit connection fields, copying bind password and optional CA material.</summary>
    public static LdapAuthConfigurationInput FromConnection(string url, string bindDN, SecretMaterial bindPass,
        string searchBase, SecretMaterial? ldapCaCertificate = null, LdapAuthSettings? settings = null)
    {
        ArgumentNullException.ThrowIfNull(url);
        ArgumentNullException.ThrowIfNull(bindDN);
        ArgumentNullException.ThrowIfNull(bindPass);
        ArgumentNullException.ThrowIfNull(searchBase);
        return new(null, url, bindDN, bindPass, searchBase, ldapCaCertificate, settings, false);
    }
    /// <summary>Creates update input; null fields omit changes and supplied bind material is copied.</summary>
    public static LdapAuthConfigurationInput Patch(string? templateId = null, string? url = null,
        string? bindDN = null, SecretMaterial? bindPass = null, string? searchBase = null,
        LdapAuthSettings? settings = null) => new(templateId, url, bindDN, bindPass, searchBase, null, settings, true);
    /// <summary>Gets the template selector, or null when omitted.</summary>
    [JsonIgnore] public string? TemplateId { get; }
    /// <summary>Gets the directory URL, or null when omitted.</summary>
    [JsonIgnore] public string? Url { get; }
    /// <summary>Gets the bind distinguished name, or null when omitted.</summary>
    [JsonIgnore] public string? BindDN { get; }
    /// <summary>Gets the search base, or null when omitted.</summary>
    [JsonIgnore] public string? SearchBase { get; }
    /// <summary>Gets selected LDAP policy and predicate settings.</summary>
    [JsonIgnore] public LdapAuthSettings Settings { get; }
    /// <summary>Gets whether this input is valid for the update path rather than attachment.</summary>
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
    /// <summary>Disposes owned bind-password and certificate copies and prevents further serialization.</summary>
    public void Dispose()
    {
        _disposed = true;
        _bindPass?.Dispose();
        _certificate?.Dispose();
    }
    /// <summary>Returns a marker without bind material or connection coordinates.</summary>
    public override string ToString() => "[LdapAuthConfigurationInput]";
}

/// <summary>OCI authentication input with explicit tenancy and nullable username constraints.</summary>
public sealed class OciAuthConfigurationInput
{
    /// <summary>Captures tenancy and optional username intent; a Null wrapper explicitly sends JSON null.</summary>
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
    /// <summary>Gets the selected tenancy OCID.</summary>
    [JsonIgnore] public string TenancyOcid { get; }
    /// <summary>Gets username selection; null omits, while a Null wrapper sends explicit null.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? AllowedUsernames { get; }
    /// <summary>Gets selected token-policy fields.</summary>
    [JsonIgnore] public WorkloadAuthTokenPolicy Policy { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteString("tenancyOcid", TenancyOcid);
        WorkloadAuthJson.Nullable(writer, "allowedUsernames", AllowedUsernames);
        Policy.Write(writer);
    }
    /// <summary>Returns a marker without tenancy or username selectors.</summary>
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
    /// <summary>Copies a supplied static bundle; the caller retains ownership of the original material.</summary>
    public static SpiffeTrustBundleInput Static(SecretMaterial bundle)
    {
        ArgumentNullException.ThrowIfNull(bundle);
        return new(bundle, null, null, null);
    }
    /// <summary>Selects a provider bundle endpoint and copies optional CA material; performs no bundle acquisition.</summary>
    public static SpiffeTrustBundleInput HttpsWebBundle(string endpointUrl, SecretMaterial? caCert = null,
        long? refreshHintSeconds = null)
    {
        ArgumentNullException.ThrowIfNull(endpointUrl);
        return new(null, endpointUrl, caCert, refreshHintSeconds);
    }
    /// <summary>Gets the selected distribution endpoint, or null for a static bundle.</summary>
    [JsonIgnore] public string? EndpointUrl { get; }
    /// <summary>Gets refresh hint seconds, or null when omitted; starts no SDK timer.</summary>
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
    /// <summary>Disposes owned bundle and CA copies and prevents further serialization.</summary>
    public void Dispose()
    {
        _disposed = true;
        _bundle?.Dispose();
        _caCert?.Dispose();
    }
    /// <summary>Returns a marker without bundle material or endpoint details.</summary>
    public override string ToString() => "[SpiffeTrustBundleInput]";
}

/// <summary>SPIFFE authentication input owning an independent copy of optional bundle distribution material.</summary>
public sealed class SpiffeAuthConfigurationInput : IDisposable
{
    private readonly SpiffeTrustBundleInput? _distribution;
    private bool _disposed;
    /// <summary>Copies supplied bundle distribution and captures optional selectors; attachment requires all trust fields.</summary>
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
    /// <summary>Gets the trust domain, or null when omitted.</summary>
    [JsonIgnore] public string? TrustDomain { get; }
    /// <summary>Gets allowed SPIFFE identifiers, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedSpiffeIds { get; }
    /// <summary>Gets allowed audiences, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedAudiences { get; }
    /// <summary>Gets selected token-policy fields.</summary>
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
    /// <summary>Disposes the independent distribution copy and prevents further serialization.</summary>
    public void Dispose()
    {
        _disposed = true;
        _distribution?.Dispose();
    }
    /// <summary>Returns a marker without trust selectors or bundle material.</summary>
    public override string ToString() => "[SpiffeAuthConfigurationInput]";
}

/// <summary>A null argument omits SANs; Null explicitly clears them; an empty array remains explicit.</summary>
public sealed class TlsAuthSubjectAltNames
{
    private TlsAuthSubjectAltNames(IReadOnlyList<string>? values) => Values = values;
    internal IReadOnlyList<string>? Values { get; }
    /// <summary>Selects explicit JSON null for SAN clearing rather than omission.</summary>
    public static TlsAuthSubjectAltNames Null() => new(null);
    /// <summary>Copies up to 100 nonempty SAN strings; an empty sequence remains an explicit array.</summary>
    public static TlsAuthSubjectAltNames FromValues(IEnumerable<string> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        return new(WorkloadAuthJson.Strings(values, true));
    }
    /// <summary>Returns a marker without subject alternative names.</summary>
    public override string ToString() => "[TlsAuthSubjectAltNames]";
}

/// <summary>TLS-certificate authentication input owning an independent CA-material copy.</summary>
public sealed class TlsCertAuthConfigurationInput : IDisposable
{
    private readonly SecretMaterial? _certificate;
    private bool _disposed;
    /// <summary>Copies supplied CA material and captures nullable name constraints; attachment requires a CA.</summary>
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
    /// <summary>Gets common-name intent; null omits and a Null wrapper explicitly clears.</summary>
    [JsonIgnore] public WorkloadAuthNullableText? AllowedCommonNames { get; }
    /// <summary>Gets SAN intent; null omits, Null clears, and an empty array remains explicit.</summary>
    [JsonIgnore] public TlsAuthSubjectAltNames? AllowedSubjectAltNames { get; }
    /// <summary>Gets provider-side client-chain verification intent, or null when omitted.</summary>
    [JsonIgnore] public bool? VerifyClientCertificateChain { get; }
    /// <summary>Gets selected token-policy fields, not SDK transport policy.</summary>
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
    /// <summary>Disposes the owned CA copy and prevents further serialization.</summary>
    public void Dispose()
    {
        _disposed = true;
        _certificate?.Dispose();
    }
    /// <summary>Returns a marker without certificate material or name constraints.</summary>
    public override string ToString() => "[TlsCertAuthConfigurationInput]";
}

/// <summary>LDAP response metadata owning optional returned CA material; dispose after inspection.</summary>
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
    /// <summary>Gets the returned directory URL.</summary>
    [JsonIgnore] public string Url { get; }
    /// <summary>Gets the returned directory search base.</summary>
    [JsonIgnore] public string SearchBase { get; }
    /// <summary>Gets the returned search filter.</summary>
    [JsonIgnore] public string SearchFilter { get; }
    /// <summary>Gets template presence, retaining explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<string> TemplateId { get; }
    /// <summary>Gets reported token period seconds, or null when absent.</summary>
    [JsonIgnore] public double? AccessTokenPeriod { get; }
    /// <summary>Gets reported lockout switch, or null when absent.</summary>
    [JsonIgnore] public bool? LockoutEnabled { get; }
    /// <summary>Gets reported failed-attempt threshold, or null when absent.</summary>
    [JsonIgnore] public double? LockoutThreshold { get; }
    /// <summary>Gets reported lockout duration seconds, or null when absent.</summary>
    [JsonIgnore] public double? LockoutDurationSeconds { get; }
    /// <summary>Gets reported counter reset seconds, or null when absent.</summary>
    [JsonIgnore] public double? LockoutCounterResetSeconds { get; }
    /// <summary>Gets whether an unestablished allowed-fields node exists without exporting its values.</summary>
    [JsonIgnore] public bool HasUnestablishedAllowedFieldsProjection { get; }
    /// <summary>Gets returned bind DN for inspection responses; other operations leave it null.</summary>
    [JsonIgnore] public string? BindDN { get; }
    /// <summary>Gets owned returned LDAP CA material, or null when not returned.</summary>
    [JsonIgnore] public SecretMaterial? LdapCaCertificate { get; }
    /// <summary>Disposes returned LDAP CA material, not remote directory credentials.</summary>
    public void Dispose() => LdapCaCertificate?.Dispose();
}

/// <summary>Returned OCI authentication metadata without inferred permissions.</summary>
public sealed class OciAuthConfiguration : WorkloadAuthConfiguration
{
    internal OciAuthConfiguration(JsonElement value, string identityId) : base(value, identityId)
    {
        TenancyOcid = ManagementJson.Required(value, "tenancyOcid");
        Type = ManagementJson.Required(value, "type");
        AllowedUsernames = WorkloadAuthJson.NullableResponse(value, "allowedUsernames");
        AccessTokenPeriod = WorkloadAuthJson.Number(value, "accessTokenPeriod");
    }
    /// <summary>Gets the returned tenancy OCID.</summary>
    [JsonIgnore] public string TenancyOcid { get; }
    /// <summary>Gets the native returned authentication type.</summary>
    [JsonIgnore] public string Type { get; }
    /// <summary>Gets username-constraint presence, preserving explicit null.</summary>
    [JsonIgnore] public ProjectField<string> AllowedUsernames { get; }
    /// <summary>Gets reported token period seconds, or null when absent.</summary>
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
    /// <summary>Gets the native static or HTTPS-web-bundle profile.</summary>
    [JsonIgnore] public string Profile { get; }
    /// <summary>Gets owned static bundle material, or null for endpoint distribution.</summary>
    [JsonIgnore] public SecretMaterial? Bundle { get; }
    /// <summary>Gets the returned distribution endpoint, or null for a static bundle.</summary>
    [JsonIgnore] public string? EndpointUrl { get; }
    /// <summary>Gets owned distribution CA material, or null for a static bundle.</summary>
    [JsonIgnore] public SecretMaterial? CaCert { get; }
    /// <summary>Gets returned refresh hint seconds, or null for a static bundle.</summary>
    [JsonIgnore] public double? RefreshHintSeconds { get; }
    /// <summary>Gets cached-refresh timestamp presence, preserving explicit null and omission.</summary>
    [JsonIgnore] public ProjectField<DateTimeOffset> CachedBundleLastRefreshedAt { get; }
    /// <summary>Disposes owned bundle and CA material; exported plaintext strings remain outside this lifetime.</summary>
    public void Dispose()
    {
        Bundle?.Dispose();
        CaCert?.Dispose();
    }
    /// <summary>Returns a marker without bundle contents or endpoint coordinates.</summary>
    public override string ToString() => "[SpiffeTrustBundleConfiguration]";
}

/// <summary>SPIFFE response metadata owning its returned trust-bundle distribution.</summary>
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
    /// <summary>Gets the returned trust domain.</summary>
    [JsonIgnore] public string TrustDomain { get; }
    /// <summary>Gets returned allowed SPIFFE identifiers.</summary>
    [JsonIgnore] public string AllowedSpiffeIds { get; }
    /// <summary>Gets returned allowed audiences.</summary>
    [JsonIgnore] public string AllowedAudiences { get; }
    /// <summary>Gets owned bundle distribution; dispose the containing result after use.</summary>
    [JsonIgnore] public SpiffeTrustBundleConfiguration TrustBundleDistribution { get; }
    /// <summary>Disposes the owned returned distribution without changing provider trust configuration.</summary>
    public void Dispose() => TrustBundleDistribution.Dispose();
}

/// <summary>TLS-certificate response metadata owning CA material only when returned by inspection.</summary>
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
    /// <summary>Gets returned common-name presence, retaining explicit null.</summary>
    [JsonIgnore] public ProjectField<string> AllowedCommonNames { get; }
    /// <summary>Gets returned SAN presence; explicit null differs from an empty array.</summary>
    [JsonIgnore] public ProjectField<IReadOnlyList<string>> AllowedSubjectAltNames { get; }
    /// <summary>Gets reported provider-side chain-verification state, or null when absent.</summary>
    [JsonIgnore] public bool? VerifyClientCertificateChain { get; }
    /// <summary>Gets whether the required opaque encrypted-CA node was present; no value is projected.</summary>
    [JsonIgnore] public bool HasUnestablishedEncryptedCaCertificateProjection { get; }
    /// <summary>Gets owned returned CA material; non-inspection responses leave it null.</summary>
    [JsonIgnore] public SecretMaterial? CaCertificate { get; }
    /// <summary>Disposes returned CA material without revoking certificates or erasing exported strings.</summary>
    public void Dispose() => CaCertificate?.Dispose();
}

/// <summary>Native LDAP lockout-clear acknowledgement, not evidence of subsequent authentication.</summary>
public sealed class LdapAuthLockoutResult
{
    internal LdapAuthLockoutResult(JsonElement value) => Deleted = WorkloadAuthJson.Number(value, "deleted")
        ?? throw new ManagementContractException(SecretStatus.Unknown);
    /// <summary>Gets the provider-reported deleted lockout count.</summary>
    [JsonIgnore] public double Deleted { get; }
    /// <summary>Returns a marker without identity or directory details.</summary>
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
