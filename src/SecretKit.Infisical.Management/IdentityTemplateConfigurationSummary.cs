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

    [JsonIgnore] public string? Url { get; }
    [JsonIgnore] public string? BindDn { get; }
    [JsonIgnore] public string? SearchBase { get; }
    [JsonIgnore] public string? LdapCaCertificate { get; }
    [JsonIgnore] public string? OidcDiscoveryUrl { get; }
    [JsonIgnore] public string? BoundIssuer { get; }
    [JsonIgnore] public string? BoundAudiences { get; }
    [JsonIgnore] public string? CaCertificate { get; }
    [JsonIgnore] public bool HasKubernetesHost { get; }
    [JsonIgnore] public string? KubernetesHost { get; }
    [JsonIgnore] public bool HasGatewayId { get; }
    [JsonIgnore] public string? GatewayId { get; }
    [JsonIgnore] public bool HasGatewayPoolId { get; }
    [JsonIgnore] public string? GatewayPoolId { get; }
    [JsonIgnore] public string? AllowedAudience { get; }
    [JsonIgnore] public string? TokenReviewMode { get; }
    [JsonIgnore] public bool? VerifyTlsCertificate { get; }
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
