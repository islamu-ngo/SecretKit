using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Method-specific native fields; construction does not attest provider acceptance.</summary>
public abstract class IdentityTemplateFields
{
    private protected IdentityTemplateFields(string method) => Method = method;
    internal string Method { get; }
    internal abstract void Write(Utf8JsonWriter writer);
    internal virtual void ValidateCreate() { }
    /// <summary>Disposes the independent bind-password copy; does not erase caller material or exported strings.</summary>
    public override string ToString() => "[IdentityTemplateFields]";
}

/// <summary>Explicit nullable native text. A null argument omits; Null emits JSON null.</summary>
public sealed class IdentityTemplateNullableText
{
    private IdentityTemplateNullableText(string? value) => Value = value;
    internal string? Value { get; }
    /// <summary>Native Kubernetes template token-review routing.</summary>
    public static IdentityTemplateNullableText Null() => new(null);
    /// <summary>Selects direct Kubernetes API token review.</summary>
    public static IdentityTemplateNullableText FromValue(string value)
    {
        ManagementJson.Text(value);
        return new(value);
    }
    /// <summary>Selects gateway token review.</summary>
    public override string ToString() => "[IdentityTemplateNullableText]";
}

/// <summary>Partial OIDC patch. Null arguments omit; empty optional strings are explicit.</summary>
public sealed class IdentityTemplateOidcPatch : IdentityTemplateFields
{
    private readonly string? _discovery;
    private readonly string? _issuer;
    private readonly string? _audiences;
    private readonly string? _ca;
    /// <summary>Copies optional reviewer JWT and captures native nullable host/gateway fields; null arguments omit fields.</summary>
    public IdentityTemplateOidcPatch(string? discoveryUrl = null, string? boundIssuer = null,
        string? boundAudiences = null, string? caCertificate = null) : base("oidc")
    {
        if (discoveryUrl is not null)
        {
            ManagementJson.Text(discoveryUrl, 2048);
            if (!Uri.TryCreate(discoveryUrl, UriKind.Absolute, out _))
                throw new ArgumentException("Invalid identity template discovery URL.");
        }
        if (boundIssuer is not null) ManagementJson.Text(boundIssuer, 2048);
        IdentityTemplateWire.Text(boundAudiences, 2048);
        IdentityTemplateWire.Text(caCertificate, 102400);
        _discovery = discoveryUrl;
        _issuer = boundIssuer;
        _audiences = boundAudiences;
        _ca = caCertificate;
    }
    internal override void ValidateCreate() => throw new ArgumentException("Creation requires full OIDC fields.");
    internal override void Write(Utf8JsonWriter writer)
    {
        IdentityTemplateWire.String(writer, "oidcDiscoveryUrl", _discovery);
        IdentityTemplateWire.String(writer, "boundIssuer", _issuer);
        IdentityTemplateWire.String(writer, "boundAudiences", _audiences);
        IdentityTemplateWire.String(writer, "caCert", _ca);
    }
}

/// <summary>LDAP create or partial patch fields. Owns a copy of supplied password material.</summary>
public sealed class IdentityTemplateLdapFields : IdentityTemplateFields, IDisposable
{
    private readonly string? _url;
    private readonly string? _dn;
    private readonly string? _base;
    private readonly string? _ca;
    private readonly SecretMaterial? _password;
    /// <summary>Disposes the independent reviewer JWT copy without changing the provider template.</summary>
    public IdentityTemplateLdapFields(string? url = null, string? bindDn = null,
        SecretMaterial? bindPassword = null, string? searchBase = null, string? caCertificate = null) : base("ldap")
    {
        foreach (string? value in new[] { url, bindDn, searchBase })
            if (value is not null) ManagementJson.Text(value, 16384);
        IdentityTemplateWire.Text(caCertificate, 102400);
        if (bindPassword is not null) IdentityTemplateWire.ValidateSecret(bindPassword, 65536, false);
        _url = url;
        _dn = bindDn;
        _base = searchBase;
        _ca = caCertificate;
        _password = bindPassword?.Copy();
    }
    internal override void ValidateCreate()
    {
        if (_url is null || _dn is null || _base is null || _password is null)
            throw new ArgumentException("LDAP creation requires URL, bind DN, password and search base.");
    }
    internal override void Write(Utf8JsonWriter writer)
    {
        IdentityTemplateWire.String(writer, "url", _url);
        IdentityTemplateWire.String(writer, "bindDN", _dn);
        IdentityTemplateWire.Secret(writer, "bindPass", _password);
        IdentityTemplateWire.String(writer, "searchBase", _base);
        IdentityTemplateWire.String(writer, "ldapCaCertificate", _ca);
    }
    /// <summary>Builds disposable LDAP template creation; required creation fields are checked before execution.</summary>
    public void Dispose() => _password?.Dispose();
}

/// <summary>Builds disposable Kubernetes template creation using only explicitly supplied fields.</summary>
public enum IdentityTemplateTokenReviewMode { /** <summary>Builds template configuration update; omitted name is retained and fields select the native method.</summary> */ Api, /** <summary>Builds independent approval intent for the complete name/configuration update, preserving omission.</summary> */ Gateway }

/// <summary>Kubernetes create or partial patch. Omitted values never become client-authored defaults.</summary>
public sealed class IdentityTemplateKubernetesFields : IdentityTemplateFields, IDisposable
{
    private readonly IdentityTemplateTokenReviewMode? _mode;
    private readonly IdentityTemplateNullableText? _host;
    private readonly IdentityTemplateNullableText? _gateway;
    private readonly IdentityTemplateNullableText? _pool;
    private readonly string? _ca;
    private readonly string? _audience;
    private readonly bool? _tls;
    private readonly SecretMaterial? _jwt;
    /// <summary>Builds independent approval intent for the exact ordered identity unlink selection.</summary>
    public IdentityTemplateKubernetesFields(IdentityTemplateTokenReviewMode? tokenReviewMode = null,
        IdentityTemplateNullableText? kubernetesHost = null, string? caCertificate = null,
        bool? verifyTlsCertificate = null, SecretMaterial? tokenReviewerJwt = null,
        IdentityTemplateNullableText? gatewayId = null, IdentityTemplateNullableText? gatewayPoolId = null,
        string? allowedAudience = null) : base("kubernetes")
    {
        if (tokenReviewMode is { } mode && !Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(tokenReviewMode));
        if (kubernetesHost?.Value is { } host) ManagementJson.Text(host, 255);
        foreach (var coordinate in new[] { gatewayId, gatewayPoolId })
            if (coordinate?.Value is { } value && !Guid.TryParseExact(value, "D", out _))
                throw new ArgumentException("Invalid identity template gateway coordinate.");
        IdentityTemplateWire.Text(caCertificate, 102400);
        IdentityTemplateWire.Text(allowedAudience, 1000);
        if (tokenReviewerJwt is not null) IdentityTemplateWire.ValidateSecret(tokenReviewerJwt, 65536, true);
        _mode = tokenReviewMode;
        _host = kubernetesHost;
        _gateway = gatewayId;
        _pool = gatewayPoolId;
        _ca = caCertificate;
        _audience = allowedAudience;
        _tls = verifyTlsCertificate;
        _jwt = tokenReviewerJwt?.Copy();
    }
    internal override void Write(Utf8JsonWriter writer)
    {
        if (_mode is { } mode) writer.WriteString("tokenReviewMode", mode == IdentityTemplateTokenReviewMode.Api ? "api" : "gateway");
        IdentityTemplateWire.Nullable(writer, "kubernetesHost", _host);
        IdentityTemplateWire.String(writer, "caCert", _ca);
        if (_tls is { } tls) writer.WriteBoolean("verifyTlsCertificate", tls);
        IdentityTemplateWire.Secret(writer, "tokenReviewerJwt", _jwt);
        IdentityTemplateWire.Nullable(writer, "gatewayId", _gateway);
        IdentityTemplateWire.Nullable(writer, "gatewayPoolId", _pool);
        IdentityTemplateWire.String(writer, "allowedAudience", _audience);
    }
    /// <summary>Builds bounded template unlinking for selected identities; returned rows do not prove runtime delivery.</summary>
    public void Dispose() => _jwt?.Dispose();
}

public static partial class IdentityTemplateOperations
{
    /// <summary>Returns a marker without method-specific fields or material.</summary>
    public static ManagementRequest<IdentityTemplateSummary> CreateLdapIdentityTemplate(
        string organizationId, string name, IdentityTemplateLdapFields fields) => Create(organizationId, name, fields);

    /// <summary>Selects explicit JSON null rather than omitting the field.</summary>
    public static ManagementRequest<IdentityTemplateSummary> CreateKubernetesIdentityTemplate(
        string organizationId, string name, IdentityTemplateKubernetesFields fields) => Create(organizationId, name, fields);

    /// <summary>Selects a validated nonempty native string value.</summary>
    public static ManagementRequest<IdentityTemplateSummary> UpdateIdentityTemplateConfiguration(
        string organizationId, string templateId, IdentityTemplateFields fields, string? name = null)
    {
        ArgumentNullException.ThrowIfNull(fields);
        return Update(organizationId, templateId, name, fields);
    }

    /// <summary>Build from independently approved fields, never from an untrusted request's Target.</summary>
    public static ManagementTarget IdentityTemplateCreateTarget(string organizationId, string name, IdentityTemplateFields fields)
    {
        ManagementJson.Text(name, 64);
        ArgumentNullException.ThrowIfNull(fields);
        fields.ValidateCreate();
        return IdentityTemplateWire.Intent(organizationId, name, fields.Method, writer => WriteChange(writer, name, fields, true));
    }

    /// <summary>Returns a marker without nullable text contents.</summary>
    public static ManagementTarget IdentityTemplateUpdateTarget(string organizationId, string templateId,
        string? name = null, IdentityTemplateFields? fields = null)
    {
        ManagementJson.Text(templateId);
        if (name is not null) ManagementJson.Text(name, 64);
        return IdentityTemplateWire.Intent(organizationId, templateId, fields?.Method, writer => WriteChange(writer, name, fields, false));
    }

    /// <summary>Captures partial OIDC changes; null omits fields and creation requires the full OIDC variant.</summary>
    public static ManagementTarget IdentityTemplateUnlinkTarget(string organizationId, string templateId, IReadOnlyList<string> identityIds)
    {
        string[] identities = CopyIdentities(identityIds);
        ManagementJson.Text(templateId);
        return IdentityTemplateWire.Intent(organizationId, templateId, null, writer => WriteUnlink(writer, identities));
    }

    /// <summary>Copies optional LDAP bind material; creation later requires URL, DN, password and search base.</summary>
    public static ManagementRequest<ManagementPage<IdentityTemplateUsage>> DeleteIdentityTemplateUsages(
        string organizationId, string templateId, IReadOnlyList<string> identityIds)
    {
        string[] identities = CopyIdentities(identityIds);
        return new("infisical.post.v1.identity.templates.by.templateId.delete.usage", HttpMethod.Post,
            TemplatePath(templateId) + "/delete-usage", IdentityTemplateUnlinkTarget(organizationId, templateId, identities),
            writer => WriteUnlink(writer, identities), root =>
            {
                IdentityTemplateUsage[] rows = ManagementJson.Array(root).Select(value => new IdentityTemplateUsage(value, true)).ToArray();
                if (rows.Any(row => !identities.Contains(row.IdentityId, StringComparer.Ordinal)) ||
                    rows.Select(row => row.IdentityId).Distinct(StringComparer.Ordinal).Count() != rows.Length)
                    throw new ManagementContractException(SecretStatus.Invalid);
                return new(rows, true);
            });
    }

    private static ManagementRequest<IdentityTemplateSummary> Create(string organizationId, string name, IdentityTemplateFields fields) =>
        new("infisical.post.v1.identity.templates", HttpMethod.Post, "/api/v1/identity-templates",
            IdentityTemplateCreateTarget(organizationId, name, fields), writer => WriteChange(writer, name, fields, true),
            root => new(root, organizationId, name: name, authMethod: fields.Method));

    private static ManagementRequest<IdentityTemplateSummary> Update(string organizationId, string templateId,
        string? name, IdentityTemplateFields? fields) =>
        new("infisical.patch.v1.identity.templates.by.templateId", HttpMethod.Patch, TemplatePath(templateId),
            IdentityTemplateUpdateTarget(organizationId, templateId, name, fields), writer => WriteChange(writer, name, fields, false),
            root => new(root, organizationId, templateId, name, fields?.Method));

    private static void WriteChange(Utf8JsonWriter writer, string? name, IdentityTemplateFields? fields, bool create)
    {
        writer.WriteStartObject();
        if (name is not null) writer.WriteString("name", name);
        if (create) writer.WriteString("authMethod", fields!.Method);
        if (fields is not null)
        {
            writer.WriteStartObject("templateFields");
            fields.Write(writer);
            writer.WriteEndObject();
        }
        writer.WriteEndObject();
    }

    private static string[] CopyIdentities(IReadOnlyList<string> identityIds)
    {
        ArgumentNullException.ThrowIfNull(identityIds);
        if (identityIds.Count > 1000) throw new ArgumentException("Identity selection exceeds its local budget.");
        string[] identities = identityIds.ToArray();
        foreach (string identity in identities) ManagementJson.Text(identity);
        if (identities.Distinct(StringComparer.Ordinal).Count() != identities.Length)
            throw new ArgumentException("Duplicate identity selection.");
        return identities;
    }

    private static void WriteUnlink(Utf8JsonWriter writer, string[] identities)
    {
        writer.WriteStartObject();
        writer.WriteStartArray("identityIds");
        foreach (string identity in identities) writer.WriteStringValue(identity);
        writer.WriteEndArray();
        writer.WriteEndObject();
    }
}

internal static class IdentityTemplateWire
{
    internal static void Text(string? value, int maximum)
    {
        if (value?.Length > maximum) throw new ArgumentException("Identity template field exceeds its local budget.");
    }
    internal static void String(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is not null) writer.WriteString(name, value);
    }
    internal static void Nullable(Utf8JsonWriter writer, string name, IdentityTemplateNullableText? value)
    {
        if (value is not null) writer.WriteString(name, value.Value);
    }
    internal static void ValidateSecret(SecretMaterial material, int maximum, bool allowEmpty)
    {
        char[] characters = material.ExportCharacters();
        try
        {
            if (characters.Length > maximum || !allowEmpty && characters.Length == 0)
                throw new ArgumentException("Invalid identity template credential length.");
        }
        finally { Array.Clear(characters); }
    }
    internal static void Secret(Utf8JsonWriter writer, string name, SecretMaterial? material)
    {
        if (material is null) return;
        char[] characters = material.ExportCharacters();
        try { writer.WriteString(name, characters.AsSpan()); }
        finally { Array.Clear(characters); }
    }
    internal static ManagementTarget Intent(string organizationId, string resourceId, string? method, Action<Utf8JsonWriter> write)
    {
        byte[] storage = new byte[64 * 1024];
        try
        {
            using var stream = new MemoryStream(storage, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartArray();
                writer.WriteStringValue(method);
                write(writer);
                writer.WriteEndArray();
            }
            return new(organizationId, resourceId: resourceId,
                secondaryId: Convert.ToHexString(SHA256.HashData(storage.AsSpan(0, (int)stream.Position))));
        }
        catch (NotSupportedException) { throw new ArgumentException("The identity template input exceeds its byte budget."); }
        finally { Array.Clear(storage); }
    }
}
