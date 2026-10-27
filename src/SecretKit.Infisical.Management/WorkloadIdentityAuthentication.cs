using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Configuration administration only, using host-supplied settings and whole-change grants.</summary>
public static class WorkloadIdentityAuthenticationOperations
{
    /// <summary>Builds independent JWT attachment or update approval; attachment requires explicit bound claims.</summary>
    public static ManagementTarget JwtAuthConfigurationTarget(string organizationId, string identityId,
        JwtAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "jwt", update, input.Write);
    }
    /// <summary>Builds independent OIDC attachment or update approval; attachment rejects an explicit null template.</summary>
    public static ManagementTarget OidcAuthConfigurationTarget(string organizationId, string identityId,
        OidcAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "oidc", update, input.Write);
    }
    /// <summary>Builds independent Kubernetes configuration approval including reviewer and nullable-field intent.</summary>
    public static ManagementTarget KubernetesAuthConfigurationTarget(string organizationId, string identityId,
        KubernetesAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "kubernetes", update, input.Write);
    }

    /// <summary>Builds disposable JWT configuration attachment; does not authenticate a workload.</summary>
    public static ManagementRequest<JwtAuthConfiguration> AttachJwtAuth(string organizationId, string identityId,
        JwtAuthConfigurationInput input) => Configuration("jwt", HttpMethod.Post, identityId,
            JwtAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new JwtAuthConfiguration(ManagementJson.Object(root, "identityJwtAuth"), identityId, false));
    /// <summary>Builds JWT configuration update with exact copied settings.</summary>
    public static ManagementRequest<JwtAuthConfiguration> UpdateJwtAuth(string organizationId, string identityId,
        JwtAuthConfigurationInput input) => Configuration("jwt", HttpMethod.Patch, identityId,
            JwtAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new JwtAuthConfiguration(ManagementJson.Object(root, "identityJwtAuth"), identityId, false));
    /// <summary>Builds JWT configuration inspection, not a token or permission probe.</summary>
    public static ManagementRequest<JwtAuthConfiguration> GetJwtAuth(string organizationId, string identityId) =>
        Configuration("jwt", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new JwtAuthConfiguration(ManagementJson.Object(root, "identityJwtAuth"), identityId, false));
    /// <summary>Builds JWT configuration removal; returned deletion metadata omits key material fields.</summary>
    public static ManagementRequest<JwtAuthConfiguration> DeleteJwtAuth(string organizationId, string identityId) =>
        Configuration("jwt", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new JwtAuthConfiguration(ManagementJson.Object(root, "identityJwtAuth"), identityId, true));

    /// <summary>Builds OIDC attachment with explicit bound-claim selection.</summary>
    public static ManagementRequest<OidcAuthConfiguration> AttachOidcAuth(string organizationId, string identityId,
        OidcAuthConfigurationInput input) => Configuration("oidc", HttpMethod.Post, identityId,
            OidcAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new OidcAuthConfiguration(ManagementJson.Object(root, "identityOidcAuth"), identityId, false));
    /// <summary>Builds OIDC update preserving omitted versus explicit null template intent.</summary>
    public static ManagementRequest<OidcAuthConfiguration> UpdateOidcAuth(string organizationId, string identityId,
        OidcAuthConfigurationInput input) => Configuration("oidc", HttpMethod.Patch, identityId,
            OidcAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new OidcAuthConfiguration(ManagementJson.Object(root, "identityOidcAuth"), identityId, false));
    /// <summary>Builds OIDC configuration inspection without effective-permission claims.</summary>
    public static ManagementRequest<OidcAuthConfiguration> GetOidcAuth(string organizationId, string identityId) =>
        Configuration("oidc", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new OidcAuthConfiguration(ManagementJson.Object(root, "identityOidcAuth"), identityId, false));
    /// <summary>Builds OIDC configuration removal; deletion responses omit CA material.</summary>
    public static ManagementRequest<OidcAuthConfiguration> DeleteOidcAuth(string organizationId, string identityId) =>
        Configuration("oidc", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new OidcAuthConfiguration(ManagementJson.Object(root, "identityOidcAuth"), identityId, true));

    /// <summary>Builds Kubernetes attachment from explicit names, namespaces and reviewer settings.</summary>
    public static ManagementRequest<KubernetesAuthConfiguration> AttachKubernetesAuth(string organizationId, string identityId,
        KubernetesAuthConfigurationInput input) => Configuration("kubernetes", HttpMethod.Post, identityId,
            KubernetesAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new KubernetesAuthConfiguration(ManagementJson.Object(root, "identityKubernetesAuth"), identityId, false));
    /// <summary>Builds Kubernetes update including explicit reviewer clearing when selected.</summary>
    public static ManagementRequest<KubernetesAuthConfiguration> UpdateKubernetesAuth(string organizationId, string identityId,
        KubernetesAuthConfigurationInput input) => Configuration("kubernetes", HttpMethod.Patch, identityId,
            KubernetesAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new KubernetesAuthConfiguration(ManagementJson.Object(root, "identityKubernetesAuth"), identityId, false));
    /// <summary>Builds Kubernetes configuration inspection; dispose the successful reviewer-bearing result.</summary>
    public static ManagementRequest<KubernetesAuthConfiguration> GetKubernetesAuth(string organizationId, string identityId) =>
        Configuration("kubernetes", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new KubernetesAuthConfiguration(ManagementJson.Object(root, "identityKubernetesAuth"), identityId, false));
    /// <summary>Builds Kubernetes configuration removal; retain the mutation receipt if execution is uncertain.</summary>
    public static ManagementRequest<KubernetesAuthConfiguration> DeleteKubernetesAuth(string organizationId, string identityId) =>
        Configuration("kubernetes", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new KubernetesAuthConfiguration(ManagementJson.Object(root, "identityKubernetesAuth"), identityId, true));

    private static ManagementTarget Intent(string organizationId, string identityId, string strategy, bool update,
        Action<Utf8JsonWriter> fields) => AuthenticationJson.Intent(organizationId, identityId,
            (update ? "patch-" : "attach-") + strategy, writer => Write(writer, fields));
    private static ManagementRequest<T> Configuration<T>(string strategy, HttpMethod method, string identityId,
        ManagementTarget target, Action<Utf8JsonWriter>? fields, Func<JsonElement, T> parse) where T : notnull =>
        new($"infisical.{method.Method.ToLowerInvariant()}.v1.auth.{strategy}.auth.identities.by.identityId",
            method, $"/api/v1/auth/{strategy}-auth/identities/" + ManagementJson.Escape(identityId), target,
            fields is null ? null : writer => Write(writer, fields), root =>
            {
                string envelope = strategy switch
                {
                    "jwt" => "identityJwtAuth",
                    "oidc" => "identityOidcAuth",
                    _ => "identityKubernetesAuth"
                };
                AuthenticationJson.ClosedObject(root, envelope);
                string[] members = strategy switch
                {
                    "jwt" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "boundAudiences", "boundClaims", "boundIssuer", "boundSubject", "configurationType",
                        "jwksCaCert", "jwksUrl", "publicKeys"],
                    "oidc" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenTrustedIps", "accessTokenTTL", "boundAudiences",
                        "boundClaims", "boundIssuer", "boundSubject", "caCert", "claimMetadataMapping",
                        "oidcDiscoveryUrl", "templateId"],
                    _ => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenTrustedIps", "accessTokenTTL", "allowedAudience",
                        "allowedNames", "allowedNamespaces", "caCert", "gatewayId", "gatewayPoolId",
                        "isTokenReviewerJwtTemplateSourced", "kubernetesHost", "templateId", "tokenReviewerJwt",
                        "tokenReviewMode", "verifyTlsCertificate"]
                };
                if (method == HttpMethod.Delete)
                    members = members.Except(["caCert", "jwksCaCert", "publicKeys", "tokenReviewerJwt"],
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
