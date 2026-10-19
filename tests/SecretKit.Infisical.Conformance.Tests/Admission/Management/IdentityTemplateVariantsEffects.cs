using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentityTemplateVariantsEffects
{
    internal static ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token) =>
        IdentityTemplatesEffects.ExecuteAsync(c, token);

    internal static IdentityTemplateAuthMethod Method(ProjectFamilyContext c) =>
        c.Operation == "CreateLdapIdentityTemplate" || c.Variant.Contains("Ldap", StringComparison.Ordinal)
            ? IdentityTemplateAuthMethod.Ldap
            : c.Operation == "CreateKubernetesIdentityTemplate" || c.Variant.Contains("Kubernetes", StringComparison.Ordinal)
                ? IdentityTemplateAuthMethod.Kubernetes : IdentityTemplateAuthMethod.Oidc;

    internal static TemplateFields Build(ProjectFamilyContext c, IdentityTemplateAuthMethod method,
        bool patch, bool baseline = false, TemplateFields? desired = null)
    {
        string variant = baseline ? "" : c.Variant;
        bool full = c.Variant is "fields.OidcFull" or "fields.Ldap" or "fields.Kubernetes";
        bool Omitted(string field) => variant.EndsWith("." + field + ".omitted", StringComparison.Ordinal);
        bool Value(string field) => variant.EndsWith("." + field + ".value", StringComparison.Ordinal);
        string? Optional(string field, string input) => Omitted(field) ? null
            : Value(field) ? c.Required(input) : baseline || !patch || full ? c.Optional(input) : null;
        string RequiredBaseline(string key, string input) => baseline && desired?.Expected.ContainsKey(key) == true
            ? c.Required("baseline" + char.ToUpperInvariant(input[0]) + input[1..]) : c.Required(input);
        string? OptionalBaseline(string key, string? value) =>
            baseline && desired?.Expected.ContainsKey(key) == true ? null : value;
        var expected = new Dictionary<string, object?>(StringComparer.Ordinal);
        IdentityTemplateFields fields;
        if (method == IdentityTemplateAuthMethod.Oidc)
        {
            string? discovery = patch && !baseline && c.Variant != "fields.OidcFull"
                ? Optional("discoveryUrl", "oidcDiscoveryUrl") : RequiredBaseline("discovery", "oidcDiscoveryUrl");
            string? issuer = patch && !baseline && c.Variant != "fields.OidcFull"
                ? Optional("boundIssuer", "boundIssuer") : RequiredBaseline("issuer", "boundIssuer");
            string? audiences = OptionalBaseline("audiences", Optional("boundAudiences", "boundAudiences"));
            string? ca = OptionalBaseline("ca", Optional("caCertificate", "caCertificate"));
            if (discovery is not null) expected["discovery"] = discovery;
            if (issuer is not null) expected["issuer"] = issuer;
            if (audiences is not null) expected["audiences"] = audiences;
            if (ca is not null) expected["ca"] = ca;
            fields = patch && c.Variant != "fields.OidcFull"
                ? new IdentityTemplateOidcPatch(discovery, issuer, audiences, ca)
                : new IdentityTemplateOidcFields(discovery!, issuer!, audiences, ca);
        }
        else if (method == IdentityTemplateAuthMethod.Ldap)
        {
            string? url = patch && !baseline && !full ? Optional("url", "ldapUrl")
                : Omitted("url") ? null : RequiredBaseline("url", "ldapUrl");
            string? dn = patch && !baseline && !full ? Optional("bindDn", "bindDn")
                : Omitted("bindDn") ? null : RequiredBaseline("dn", "bindDn");
            string? search = patch && !baseline && !full ? Optional("searchBase", "searchBase")
                : Omitted("searchBase") ? null : RequiredBaseline("base", "searchBase");
            string? password = baseline && c.Input.TryGetProperty("ldapWitness", out _)
                ? c.Required("originalBindPassword")
                : patch && !baseline && !full ? Optional("bindPassword", "bindPassword")
                    : Omitted("bindPassword") ? null : c.Required("bindPassword");
            string? ca = OptionalBaseline("ldapCa", Optional("caCertificate", "ldapCaCertificate"));
            using SecretMaterial? material = password is null ? null : SecretMaterial.FromText(password);
            fields = new IdentityTemplateLdapFields(url, dn, material, search, ca);
            if (url is not null) expected["url"] = url;
            if (dn is not null) expected["dn"] = dn;
            if (search is not null) expected["base"] = search;
            if (ca is not null) expected["ldapCa"] = ca;
            if (password is not null) expected["stored"] = true;
            if (!baseline && password is not null) expected["password-content"] = true;
        }
        else
        {
            IdentityTemplateTokenReviewMode? mode = variant.EndsWith("tokenReviewMode.Gateway", StringComparison.Ordinal)
                ? IdentityTemplateTokenReviewMode.Gateway
                : Omitted("tokenReviewMode") ? null : !patch || baseline || full ||
                    variant.EndsWith("tokenReviewMode.Api", StringComparison.Ordinal) ? IdentityTemplateTokenReviewMode.Api : null;
            // Omit optional settings in setup instead of inventing another issuer, gateway or credential.
            if (baseline && desired?.Expected.ContainsKey("mode") == true)
                mode = c.Required("baselineTokenReviewMode") switch
                {
                    "api" => IdentityTemplateTokenReviewMode.Api,
                    "gateway" => IdentityTemplateTokenReviewMode.Gateway,
                    _ => throw new NativeCaseFailureException("missing-input")
                };
            string? host = OptionalBaseline("host", Optional("kubernetesHost", "kubernetesHost"));
            string? gateway = OptionalBaseline("gateway", Optional("gatewayId", "gatewayId"));
            string? pool = OptionalBaseline("pool", Optional("gatewayPoolId", "gatewayPoolId"));
            string? jwt = OptionalBaseline("stored", Optional("tokenReviewerJwt", "tokenReviewerJwt"));
            string? ca = OptionalBaseline("ca", Optional("caCertificate", "caCertificate"));
            string? audience = OptionalBaseline("audience", Optional("allowedAudience", "allowedAudience"));
            bool? tls = variant.EndsWith("verifyTlsCertificate.true", StringComparison.Ordinal) ? true
                : variant.EndsWith("verifyTlsCertificate.false", StringComparison.Ordinal) ? false : null;
            if (baseline && desired?.Expected.TryGetValue("tls", out object? desiredTls) == true)
                tls = !(bool)desiredTls!;
            using SecretMaterial? material = jwt is null ? null : SecretMaterial.FromText(jwt);
            fields = new IdentityTemplateKubernetesFields(mode,
                host is null ? null : IdentityTemplateNullableText.FromValue(host), ca, tls, material,
                gateway is null ? null : IdentityTemplateNullableText.FromValue(gateway),
                pool is null ? null : IdentityTemplateNullableText.FromValue(pool), audience);
            if (mode is not null) expected["mode"] = mode == IdentityTemplateTokenReviewMode.Api ? "api" : "gateway";
            if (host is not null) expected["host"] = host;
            if (gateway is not null) expected["gateway"] = gateway;
            if (pool is not null) expected["pool"] = pool;
            if (jwt is not null) expected["stored"] = jwt.Length > 0;
            if (ca is not null) expected["ca"] = ca;
            if (audience is not null) expected["audience"] = audience;
            if (tls is not null) expected["tls"] = tls;
        }
        return new(fields, expected);
    }
}

internal sealed class TemplateFields(IdentityTemplateFields fields, Dictionary<string, object?> expected) : IDisposable
{
    internal IdentityTemplateFields Fields { get; } = fields;
    internal Dictionary<string, object?> Expected { get; } = expected;
    internal bool HasUnavailableContents => Expected.ContainsKey("password-content");
    internal bool Matches(IdentityTemplateSummary value)
    {
        var settings = value.Configuration;
        return Expected.Where(pair => pair.Key != "password-content").All(pair => Equals(pair.Value, pair.Key switch
        {
            "discovery" => settings.OidcDiscoveryUrl,
            "issuer" => settings.BoundIssuer,
            "audiences" => settings.BoundAudiences,
            "ca" => settings.CaCertificate,
            "url" => settings.Url,
            "dn" => settings.BindDn,
            "base" => settings.SearchBase,
            "ldapCa" => settings.LdapCaCertificate,
            "stored" => value.HasStoredCredential,
            "mode" => settings.TokenReviewMode,
            "host" => settings.KubernetesHost,
            "gateway" => settings.GatewayId,
            "pool" => settings.GatewayPoolId,
            "audience" => settings.AllowedAudience,
            "tls" => settings.VerifyTlsCertificate,
            _ => throw new InvalidOperationException("contract-mismatch")
        }));
    }
    public void Dispose() { if (Fields is IDisposable owned) owned.Dispose(); }
    public override string ToString() => "[TemplateFields]";
}
