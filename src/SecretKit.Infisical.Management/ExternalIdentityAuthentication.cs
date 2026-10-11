using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>External identity configuration administration with independently approved whole-change targets.</summary>
public static class ExternalIdentityAuthenticationOperations
{
    public static ManagementTarget LdapAuthConfigurationTarget(string organizationId, string identityId,
        LdapAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.IsUpdate != update) throw new ArgumentException("LDAP input does not match the selected operation.");
        return Intent(organizationId, identityId, "ldap", update, input.Write);
    }
    public static ManagementTarget OciAuthConfigurationTarget(string organizationId, string identityId,
        OciAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) ExternalAuthJson.AttachPolicy(input.Policy);
        return Intent(organizationId, identityId, "oci", update, input.Write);
    }
    public static ManagementTarget SpiffeAuthConfigurationTarget(string organizationId, string identityId,
        SpiffeAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "spiffe", update, input.Write);
    }
    public static ManagementTarget TlsCertAuthConfigurationTarget(string organizationId, string identityId,
        TlsCertAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "tls-cert", update, input.Write);
    }
    public static ManagementRequest<LdapAuthConfiguration> AttachLdapAuth(string organizationId, string identityId,
        LdapAuthConfigurationInput input) => Configuration("ldap", HttpMethod.Post, identityId,
            LdapAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new LdapAuthConfiguration(ManagementJson.Object(root, "identityLdapAuth"), identityId, false));
    public static ManagementRequest<LdapAuthConfiguration> UpdateLdapAuth(string organizationId, string identityId,
        LdapAuthConfigurationInput input) => Configuration("ldap", HttpMethod.Patch, identityId,
            LdapAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new LdapAuthConfiguration(ManagementJson.Object(root, "identityLdapAuth"), identityId, false));
    public static ManagementRequest<LdapAuthConfiguration> GetLdapAuth(string organizationId, string identityId) =>
        Configuration("ldap", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new LdapAuthConfiguration(ManagementJson.Object(root, "identityLdapAuth"), identityId, true));
    public static ManagementRequest<LdapAuthConfiguration> DeleteLdapAuth(string organizationId, string identityId) =>
        Configuration("ldap", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new LdapAuthConfiguration(ManagementJson.Object(root, "identityLdapAuth"), identityId, false));
    public static ManagementRequest<LdapAuthLockoutResult> ClearLdapAuthLockouts(string organizationId, string identityId) =>
        Configuration("ldap", HttpMethod.Post, identityId, new(organizationId, resourceId: identityId), null,
            root => new LdapAuthLockoutResult(root), "clear-lockouts");

    public static ManagementRequest<OciAuthConfiguration> AttachOciAuth(string organizationId, string identityId,
        OciAuthConfigurationInput input) => Configuration("oci", HttpMethod.Post, identityId,
            OciAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new OciAuthConfiguration(ManagementJson.Object(root, "identityOciAuth"), identityId));
    public static ManagementRequest<OciAuthConfiguration> UpdateOciAuth(string organizationId, string identityId,
        OciAuthConfigurationInput input) => Configuration("oci", HttpMethod.Patch, identityId,
            OciAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new OciAuthConfiguration(ManagementJson.Object(root, "identityOciAuth"), identityId));
    public static ManagementRequest<OciAuthConfiguration> GetOciAuth(string organizationId, string identityId) =>
        Configuration("oci", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new OciAuthConfiguration(ManagementJson.Object(root, "identityOciAuth"), identityId));
    public static ManagementRequest<OciAuthConfiguration> DeleteOciAuth(string organizationId, string identityId) =>
        Configuration("oci", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new OciAuthConfiguration(ManagementJson.Object(root, "identityOciAuth"), identityId));

    public static ManagementRequest<SpiffeAuthConfiguration> AttachSpiffeAuth(string organizationId, string identityId,
        SpiffeAuthConfigurationInput input) => Configuration("spiffe", HttpMethod.Post, identityId,
            SpiffeAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new SpiffeAuthConfiguration(ManagementJson.Object(root, "identitySpiffeAuth"), identityId));
    public static ManagementRequest<SpiffeAuthConfiguration> UpdateSpiffeAuth(string organizationId, string identityId,
        SpiffeAuthConfigurationInput input) => Configuration("spiffe", HttpMethod.Patch, identityId,
            SpiffeAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new SpiffeAuthConfiguration(ManagementJson.Object(root, "identitySpiffeAuth"), identityId));
    public static ManagementRequest<SpiffeAuthConfiguration> GetSpiffeAuth(string organizationId, string identityId) =>
        Configuration("spiffe", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new SpiffeAuthConfiguration(ManagementJson.Object(root, "identitySpiffeAuth"), identityId));
    public static ManagementRequest<SpiffeAuthConfiguration> DeleteSpiffeAuth(string organizationId, string identityId) =>
        Configuration("spiffe", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new SpiffeAuthConfiguration(ManagementJson.Object(root, "identitySpiffeAuth"), identityId));
    public static ManagementRequest<SpiffeAuthConfiguration> RefreshSpiffeBundle(string organizationId, string identityId) =>
        Configuration("spiffe", HttpMethod.Post, identityId, new(organizationId, resourceId: identityId), null,
            root => new SpiffeAuthConfiguration(ManagementJson.Object(root, "identitySpiffeAuth"), identityId), "refresh-bundle");

    public static ManagementRequest<TlsCertAuthConfiguration> AttachTlsCertAuth(string organizationId, string identityId,
        TlsCertAuthConfigurationInput input) => Configuration("tls-cert", HttpMethod.Post, identityId,
            TlsCertAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new TlsCertAuthConfiguration(ManagementJson.Object(root, "identityTlsCertAuth"), identityId, false));
    public static ManagementRequest<TlsCertAuthConfiguration> UpdateTlsCertAuth(string organizationId, string identityId,
        TlsCertAuthConfigurationInput input) => Configuration("tls-cert", HttpMethod.Patch, identityId,
            TlsCertAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new TlsCertAuthConfiguration(ManagementJson.Object(root, "identityTlsCertAuth"), identityId, false));
    public static ManagementRequest<TlsCertAuthConfiguration> GetTlsCertAuth(string organizationId, string identityId) =>
        Configuration("tls-cert", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new TlsCertAuthConfiguration(ManagementJson.Object(root, "identityTlsCertAuth"), identityId, true));
    public static ManagementRequest<TlsCertAuthConfiguration> DeleteTlsCertAuth(string organizationId, string identityId) =>
        Configuration("tls-cert", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new TlsCertAuthConfiguration(ManagementJson.Object(root, "identityTlsCertAuth"), identityId, false));

    private static ManagementTarget Intent(string organizationId, string identityId, string strategy, bool update,
        Action<Utf8JsonWriter> fields) => AuthenticationJson.Intent(organizationId, identityId,
            (update ? "patch-" : "attach-") + strategy, writer => Write(writer, fields));
    private static ManagementRequest<T> Configuration<T>(string strategy, HttpMethod method, string identityId,
        ManagementTarget target, Action<Utf8JsonWriter>? fields, Func<JsonElement, T> parse, string? auxiliary = null)
        where T : notnull => new(
            $"infisical.{method.Method.ToLowerInvariant()}.v1.auth.{strategy.Replace('-', '.')}.auth.identities.by.identityId" +
            (auxiliary is null ? "" : "." + auxiliary.Replace('-', '.')),
            method, $"/api/v1/auth/{strategy}-auth/identities/" + ManagementJson.Escape(identityId) +
            (auxiliary is null ? "" : "/" + auxiliary), target,
            fields is null ? null : writer => Write(writer, fields), root =>
            {
                if (auxiliary == "clear-lockouts")
                {
                    AuthenticationJson.ClosedObject(root, "deleted");
                    return parse(root);
                }
                string envelope = strategy switch
                {
                    "ldap" => "identityLdapAuth",
                    "oci" => "identityOciAuth",
                    "spiffe" => "identitySpiffeAuth",
                    _ => "identityTlsCertAuth"
                };
                AuthenticationJson.ClosedObject(root, envelope);
                string[] members = strategy switch
                {
                    "ldap" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "allowedFields", "bindDN", "ldapCaCertificate", "lockoutCounterResetSeconds",
                        "lockoutDurationSeconds", "lockoutEnabled", "lockoutThreshold", "searchBase",
                        "searchFilter", "templateId", "url"],
                    "oci" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "allowedUsernames", "tenancyOcid", "type"],
                    "spiffe" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenTrustedIps", "accessTokenTTL", "allowedAudiences",
                        "allowedSpiffeIds", "trustBundleDistribution", "trustDomain"],
                    _ => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenTrustedIps", "accessTokenTTL", "allowedCommonNames",
                        "allowedSubjectAltNames", "caCertificate", "encryptedCaCertificate",
                        "verifyClientCertificateChain"]
                };
                if (method != HttpMethod.Get)
                    members = members.Except(["bindDN", "ldapCaCertificate", "caCertificate"],
                        StringComparer.Ordinal).ToArray();
                AuthenticationJson.ClosedObject(ManagementJson.Object(root, envelope), members);
                return parse(root);
            }, method != HttpMethod.Get);
    private static void Write(Utf8JsonWriter writer, Action<Utf8JsonWriter> fields)
    {
        writer.WriteStartObject();
        fields(writer);
        writer.WriteEndObject();
    }
}
