using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Protected stored settings, not stored credentials or issuer acceptance.</summary>
public sealed class IdentityTemplateConfigurationSummary
{
    internal IdentityTemplateConfigurationSummary(JsonElement value, IdentityTemplateAuthMethod method)
    {
        if (method == IdentityTemplateAuthMethod.Ldap)
        {
            Url = Text(value, "url", minimum: 1);
            BindDn = Text(value, "bindDN", minimum: 1);
            SearchBase = Text(value, "searchBase", minimum: 1);
            LdapCaCertificate = Text(value, "ldapCaCertificate");
        }
        else if (method == IdentityTemplateAuthMethod.Oidc)
        {
            OidcDiscoveryUrl = Text(value, "oidcDiscoveryUrl", required: true);
            BoundIssuer = Text(value, "boundIssuer", required: true, minimum: 1, maximum: 2048);
            BoundAudiences = Text(value, "boundAudiences");
            CaCertificate = Text(value, "caCert", maximum: 102400);
        }
        else
        {
            HasKubernetesHost = value.TryGetProperty("kubernetesHost", out _);
            HasGatewayId = value.TryGetProperty("gatewayId", out _);
            HasGatewayPoolId = value.TryGetProperty("gatewayPoolId", out _);
            KubernetesHost = Text(value, "kubernetesHost", minimum: 1, maximum: 255, nullable: true);
            GatewayId = Text(value, "gatewayId", nullable: true);
            GatewayPoolId = Text(value, "gatewayPoolId", nullable: true);
            foreach (string? id in new[] { GatewayId, GatewayPoolId })
                if (id is not null && !Guid.TryParseExact(id, "D", out _))
                    throw new ManagementContractException(SecretStatus.Unknown);
            CaCertificate = Text(value, "caCert", maximum: 102400);
            AllowedAudience = Text(value, "allowedAudience", maximum: 1000);
            TokenReviewMode = Text(value, "tokenReviewMode");
            if (TokenReviewMode is not (null or "api" or "gateway"))
                throw new ManagementContractException(SecretStatus.Unknown);
            if (value.TryGetProperty("verifyTlsCertificate", out _))
                VerifyTlsCertificate = ManagementJson.Boolean(value, "verifyTlsCertificate");
        }
    }

    /// <summary>Gets returned LDAP URL, or null when absent or not an LDAP template.</summary>
    [JsonIgnore] public string? Url { get; }
    /// <summary>Gets returned LDAP bind DN, or null when not supplied.</summary>
    [JsonIgnore] public string? BindDn { get; }
    /// <summary>Gets returned LDAP search base, or null when not supplied.</summary>
    [JsonIgnore] public string? SearchBase { get; }
    /// <summary>Gets returned LDAP CA certificate text, or null when not supplied; no bind credential is exported.</summary>
    [JsonIgnore] public string? LdapCaCertificate { get; }
    /// <summary>Gets returned OIDC discovery URL, or null for another method.</summary>
    [JsonIgnore] public string? OidcDiscoveryUrl { get; }
    /// <summary>Gets returned OIDC issuer constraint, or null for another method.</summary>
    [JsonIgnore] public string? BoundIssuer { get; }
    /// <summary>Gets returned OIDC audience constraints, or null when absent.</summary>
    [JsonIgnore] public string? BoundAudiences { get; }
    /// <summary>Gets returned OIDC or Kubernetes CA text, or null when absent.</summary>
    [JsonIgnore] public string? CaCertificate { get; }
    /// <summary>Gets whether a Kubernetes host field was returned, even if explicitly null.</summary>
    [JsonIgnore] public bool HasKubernetesHost { get; }
    /// <summary>Gets returned Kubernetes host text; use HasKubernetesHost to distinguish absent from null.</summary>
    [JsonIgnore] public string? KubernetesHost { get; }
    /// <summary>Gets whether a gateway identifier field was returned, even if null.</summary>
    [JsonIgnore] public bool HasGatewayId { get; }
    /// <summary>Gets returned gateway identifier; use HasGatewayId to distinguish absence.</summary>
    [JsonIgnore] public string? GatewayId { get; }
    /// <summary>Gets whether a gateway-pool identifier field was returned, even if null.</summary>
    [JsonIgnore] public bool HasGatewayPoolId { get; }
    /// <summary>Gets returned gateway-pool identifier; use HasGatewayPoolId to distinguish absence.</summary>
    [JsonIgnore] public string? GatewayPoolId { get; }
    /// <summary>Gets returned Kubernetes audience constraint, or null when absent.</summary>
    [JsonIgnore] public string? AllowedAudience { get; }
    /// <summary>Gets returned API/gateway review mode, or null when absent.</summary>
    [JsonIgnore] public string? TokenReviewMode { get; }
    /// <summary>Gets reported provider-side TLS-verification state, or null when absent.</summary>
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
    /// <summary>Returns a marker without template configuration details.</summary>
    public override string ToString() => "[IdentityTemplateConfigurationSummary]";

    private static string? Text(JsonElement value, string field, bool required = false,
        int minimum = 0, int maximum = 16384, bool nullable = false)
    {
        if (!value.TryGetProperty(field, out var child))
        {
            if (required) throw new ManagementContractException(SecretStatus.Unknown);
            return null;
        }
        if (nullable && child.ValueKind == JsonValueKind.Null) return null;
        if (child.ValueKind != JsonValueKind.String)
            throw new ManagementContractException(SecretStatus.Unknown);
        string text = child.GetString()!;
        if (text.Length < minimum || text.Length > maximum)
            throw new ManagementContractException(SecretStatus.Unknown);
        return text;
    }
}
