namespace SecretKit.Infisical.Dynamic;

/// <summary>Owned LDAP definition inputs with distinct static rotation and dynamic lifecycle forms.</summary>
public sealed class NativeLdapDefinitionProfile : InfisicalDynamicProfile
{
    private NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "static"); Text("url", url); Text("binddn", bindDn);
        Text("bindpass", bindPassword); Text("rotationLdif", rotationLdif); Optional("ca", ca);
    }
    /// <summary>Copies static-account bind credentials and rotation LDIF; LDIF is not executed locally.</summary>
    public static NativeLdapDefinitionProfile ForStaticAccount(string url, string bindDn, string bindPassword,
        string rotationLdif, string? ca = null) => new(url, bindDn, bindPassword, rotationLdif, ca);
    /// <summary>Copies dynamic-account creation/revocation and optional rollback LDIF plus bind/TLS inputs.</summary>
    public NativeLdapDefinitionProfile(string url, string bindDn, string bindPassword, string creationLdif,
        string revocationLdif, string? rollbackLdif = null, string? ca = null) : base(InfisicalDynamicProvider.Ldap)
    {
        Text("credentialType", "dynamic"); Text("url", url); Text("binddn", bindDn); Text("bindpass", bindPassword);
        Text("creationLdif", creationLdif); Text("revocationLdif", revocationLdif);
        Optional("rollbackLdif", rollbackLdif); Optional("ca", ca);
    }
}
/// <summary>Closed native TOTP digest selection; the SDK does not generate an OTP locally.</summary>
public enum NativeTotpAlgorithm { /** <summary>SHA-1.</summary> */ Sha1, /** <summary>SHA-256.</summary> */ Sha256, /** <summary>SHA-512.</summary> */ Sha512 }
/// <summary>Owned TOTP definition inputs using an explicit manual secret or provisioning URL.</summary>
public sealed class NativeTotpDefinitionProfile : InfisicalDynamicProfile
{
    private NativeTotpDefinitionProfile(string secret, NativeTotpAlgorithm algorithm, int? digits, int? period)
        : base(InfisicalDynamicProvider.Totp)
    {
        string wireAlgorithm = algorithm switch
        {
            NativeTotpAlgorithm.Sha1 => "sha1",
            NativeTotpAlgorithm.Sha256 => "sha256",
            NativeTotpAlgorithm.Sha512 => "sha512",
            _ => throw new ArgumentException("Unknown native TOTP algorithm.")
        };
        Text("configType", "manual"); Text("secret", secret); Text("algorithm", wireAlgorithm);
        if (digits is { } digitCount) { Number("digits", digitCount, 1, int.MaxValue); }
        if (period is { } seconds) { Number("period", seconds, 1, int.MaxValue); }
    }
    /// <summary>Copies a manual secret and selected digest, with optional positive digit count and period.</summary>
    public static NativeTotpDefinitionProfile ForManualSecret(string secret,
        NativeTotpAlgorithm algorithm = NativeTotpAlgorithm.Sha1, int? digits = null, int? period = null) =>
        new(secret, algorithm, digits, period);
    /// <summary>Copies an absolute provisioning URL without URI user-info; no URL is fetched locally.</summary>
    public NativeTotpDefinitionProfile(string provisioningUrl) : base(InfisicalDynamicProvider.Totp)
    {
        Text("configType", "url"); SafeUri("url", provisioningUrl);
    }
}
/// <summary>Explicit native OAuth client-secret authentication method.</summary>
public enum NativeOauthClientAuthentication { /** <summary>Client secret via HTTP Basic.</summary> */ Basic, /** <summary>Client secret in POST fields.</summary> */ Post }
/// <summary>Owned native client-credentials OAuth definition, not a host-side OAuth client.</summary>
public sealed class NativeOauthDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies client authority, absolute token/revocation URLs and at most 20 typed extra parameters.</summary>
    public NativeOauthDefinitionProfile(string clientId, string clientSecret, NativeOauthClientAuthentication method,
        string tokenUrl, string revocationUrl, string? scope = null,
        IReadOnlyList<NativeOauthExtraParameter>? extraParameters = null) : base(InfisicalDynamicProvider.Oauth2)
    {
        if (!Enum.IsDefined(method))
        {
            throw new ArgumentException("Unknown native OAuth client authentication.");
        }
        Text("grantType", "client-credentials"); Text("clientId", clientId, 1024);
        Text("clientAuth.clientSecret", clientSecret, 4096); Text("clientAuth.method", method switch
        {
            NativeOauthClientAuthentication.Basic => "client_secret_basic",
            NativeOauthClientAuthentication.Post => "client_secret_post",
            _ => throw new ArgumentException("Unknown native OAuth client authentication.")
        });
        SafeUri("tokenUrl", tokenUrl); SafeUri("revocationUrl", revocationUrl); Optional("scope", scope, 2048);
        ObjectOptions("extraParams", extraParameters, 20);
    }
}
