namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record InfisicalDynamicAlternativeProfileInput(
    DynamicElasticSearchApiKeyInput? ElasticSearchApiKey = null,
    DynamicKubernetesStaticAccountInput? KubernetesStaticAccount = null,
    DynamicLdapStaticAccountInput? LdapStaticAccount = null,
    DynamicTotpManualSecretInput? TotpManualSecret = null,
    DynamicTailscaleOAuthAuthorityInput? TailscaleOAuthAuthority = null,
    DynamicTailscaleFederatedApiKeyInput? TailscaleFederatedApiKey = null,
    DynamicTailscaleFederatedOAuthInput? TailscaleFederatedOAuth = null,
    DynamicTailscaleOAuthKeyApiKeyInput? TailscaleOAuthKeyApiKey = null,
    DynamicTailscaleOAuthKeyOAuthInput? TailscaleOAuthKeyOAuth = null)
{
    public override string ToString() => "[InfisicalDynamicAlternativeProfileInput]";
}

internal sealed record DynamicElasticSearchApiKeyInput(
    string Host,
    int Port,
    string ApiKeyId,
    string ApiKey,
    string[] Roles,
    string? Ca = null)
{
    public override string ToString() => "[DynamicElasticSearchApiKeyInput]";
}

internal sealed record DynamicKubernetesStaticAccountInput(
    string NameSpace,
    string ServiceAccountName,
    string[] Audiences,
    string? ClusterToken = null,
    string? Url = null,
    string? Ca = null,
    NativeKubernetesAuthentication? Authentication = null,
    DynamicGatewayInput? Gateway = null,
    bool? SslEnabled = null)
{
    public override string ToString() => "[DynamicKubernetesStaticAccountInput]";
}

internal sealed record DynamicLdapStaticAccountInput(
    string Url,
    string BindDn,
    string BindPassword,
    string RotationLdif,
    string? Ca = null)
{
    public override string ToString() => "[DynamicLdapStaticAccountInput]";
}

internal sealed record DynamicTotpManualSecretInput(
    string Secret,
    NativeTotpAlgorithm Algorithm = NativeTotpAlgorithm.Sha1,
    int? Digits = null,
    int? Period = null)
{
    public override string ToString() => "[DynamicTotpManualSecretInput]";
}

internal sealed record DynamicTailscaleOAuthAuthorityInput(
    string ClientId,
    string ClientSecret,
    DynamicTailscaleOptionsInput? Options = null)
{
    public override string ToString() => "[DynamicTailscaleOAuthAuthorityInput]";
}

internal sealed record DynamicTailscaleFederatedApiKeyInput(
    string ApiKey,
    string Issuer,
    string Subject,
    string[] Scopes,
    DynamicTailscaleOptionsInput? Options = null)
{
    public override string ToString() => "[DynamicTailscaleFederatedApiKeyInput]";
}

internal sealed record DynamicTailscaleFederatedOAuthInput(
    string ClientId,
    string ClientSecret,
    string Issuer,
    string Subject,
    string[] Scopes,
    DynamicTailscaleOptionsInput? Options = null)
{
    public override string ToString() => "[DynamicTailscaleFederatedOAuthInput]";
}

internal sealed record DynamicTailscaleOAuthKeyApiKeyInput(
    string ApiKey,
    string[] Scopes,
    DynamicTailscaleOptionsInput? Options = null)
{
    public override string ToString() => "[DynamicTailscaleOAuthKeyApiKeyInput]";
}

internal sealed record DynamicTailscaleOAuthKeyOAuthInput(
    string ClientId,
    string ClientSecret,
    string[] Scopes,
    DynamicTailscaleOptionsInput? Options = null)
{
    public override string ToString() => "[DynamicTailscaleOAuthKeyOAuthInput]";
}

internal sealed record DynamicTailscaleOptionsInput(
    string? Tailnet = null,
    string[]? Tags = null,
    string? Description = null,
    string? Audience = null,
    bool? Reusable = null,
    bool? Preauthorized = null)
{
    public override string ToString() => "[DynamicTailscaleOptionsInput]";
}

// Closed private host inputs select only public SDK factories. They grant no backend authority.
internal static class InfisicalDynamicAlternativeProfileInputs
{
    internal static bool TryProvider(string variant, out InfisicalDynamicProvider provider)
    {
        InfisicalDynamicProvider? selected = variant switch
        {
            "ElasticSearch.api-key" => InfisicalDynamicProvider.ElasticSearch,
            "Kubernetes.static-account" => InfisicalDynamicProvider.Kubernetes,
            "Ldap.static-account" => InfisicalDynamicProvider.Ldap,
            "Totp.manual.Sha1" or "Totp.manual.Sha256" or "Totp.manual.Sha512" => InfisicalDynamicProvider.Totp,
            "Tailscale.auth_keys.oauth" or "Tailscale.federated_keys.api_key" or "Tailscale.federated_keys.oauth" or
                "Tailscale.oauth_keys.api_key" or "Tailscale.oauth_keys.oauth" => InfisicalDynamicProvider.Tailscale,
            _ => null
        };
        provider = selected.GetValueOrDefault();
        return selected.HasValue;
    }

    internal static InfisicalDynamicProfile Create(string variant, InfisicalDynamicAlternativeProfileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        int selections =
            (input.ElasticSearchApiKey is null ? 0 : 1) +
            (input.KubernetesStaticAccount is null ? 0 : 1) +
            (input.LdapStaticAccount is null ? 0 : 1) +
            (input.TotpManualSecret is null ? 0 : 1) +
            (input.TailscaleOAuthAuthority is null ? 0 : 1) +
            (input.TailscaleFederatedApiKey is null ? 0 : 1) +
            (input.TailscaleFederatedOAuth is null ? 0 : 1) +
            (input.TailscaleOAuthKeyApiKey is null ? 0 : 1) +
            (input.TailscaleOAuthKeyOAuth is null ? 0 : 1);
        if (selections != 1) throw new ArgumentException("Exactly one typed alternative profile input is required.");

        switch (variant)
        {
            case "ElasticSearch.api-key" when input.ElasticSearchApiKey is { } p &&
                p.Host is not null && p.ApiKeyId is not null && p.ApiKey is not null && p.Roles is not null:
                return NativeElasticsearchDefinitionProfile.ForApiKey(p.Host, p.Port, p.ApiKeyId, p.ApiKey, p.Roles, p.Ca);
            case "Kubernetes.static-account" when input.KubernetesStaticAccount is { } p &&
                p.NameSpace is not null && p.ServiceAccountName is not null && p.Audiences is not null:
                using (var gateway = p.Gateway is { } g
                    ? new NativeGatewayOptions(g.GatewayId, g.GatewayPoolId, g.ClearGatewayId, g.ClearGatewayPoolId) : null)
                    return NativeKubernetesDefinitionProfile.ForStaticAccount(p.NameSpace, p.ServiceAccountName,
                        p.Audiences, p.ClusterToken, p.Url, p.Ca, p.Authentication, gateway, p.SslEnabled);
            case "Ldap.static-account" when input.LdapStaticAccount is { } p &&
                p.Url is not null && p.BindDn is not null && p.BindPassword is not null && p.RotationLdif is not null:
                return NativeLdapDefinitionProfile.ForStaticAccount(p.Url, p.BindDn, p.BindPassword, p.RotationLdif, p.Ca);
            case "Totp.manual.Sha1" or "Totp.manual.Sha256" or "Totp.manual.Sha512"
                when input.TotpManualSecret is { } p && p.Secret is not null &&
                variant == (p.Algorithm switch
                {
                    NativeTotpAlgorithm.Sha1 => "Totp.manual.Sha1",
                    NativeTotpAlgorithm.Sha256 => "Totp.manual.Sha256",
                    NativeTotpAlgorithm.Sha512 => "Totp.manual.Sha512",
                    _ => null
                }):
                return NativeTotpDefinitionProfile.ForManualSecret(p.Secret, p.Algorithm, p.Digits, p.Period);
            case "Tailscale.auth_keys.oauth" when input.TailscaleOAuthAuthority is { } p &&
                p.ClientId is not null && p.ClientSecret is not null:
                using (var options = Tailscale(p.Options))
                    return NativeTailscaleDefinitionProfile.ForOAuthAuthority(p.ClientId, p.ClientSecret, options);
            case "Tailscale.federated_keys.api_key" when input.TailscaleFederatedApiKey is { } p &&
                p.ApiKey is not null && p.Issuer is not null && p.Subject is not null && p.Scopes is not null:
                using (var options = Tailscale(p.Options))
                    return NativeTailscaleDefinitionProfile.ForFederatedApiKey(p.ApiKey, p.Issuer, p.Subject, p.Scopes, options);
            case "Tailscale.federated_keys.oauth" when input.TailscaleFederatedOAuth is { } p &&
                p.ClientId is not null && p.ClientSecret is not null && p.Issuer is not null &&
                p.Subject is not null && p.Scopes is not null:
                using (var options = Tailscale(p.Options))
                    return NativeTailscaleDefinitionProfile.ForFederatedOAuth(p.ClientId, p.ClientSecret,
                        p.Issuer, p.Subject, p.Scopes, options);
            case "Tailscale.oauth_keys.api_key" when input.TailscaleOAuthKeyApiKey is { } p &&
                p.ApiKey is not null && p.Scopes is not null:
                using (var options = Tailscale(p.Options))
                    return NativeTailscaleDefinitionProfile.ForOAuthKeyApiKey(p.ApiKey, p.Scopes, options);
            case "Tailscale.oauth_keys.oauth" when input.TailscaleOAuthKeyOAuth is { } p &&
                p.ClientId is not null && p.ClientSecret is not null && p.Scopes is not null:
                using (var options = Tailscale(p.Options))
                    return NativeTailscaleDefinitionProfile.ForOAuthKeyOAuth(p.ClientId, p.ClientSecret, p.Scopes, options);
            default:
                throw new ArgumentException("The alternative variant and typed profile input must match.");
        }
    }

    private static NativeTailscaleOptions? Tailscale(DynamicTailscaleOptionsInput? input) => input is { } p
        ? new(p.Tailnet, p.Tags, p.Description, p.Audience, p.Reusable, p.Preauthorized) : null;
}
