namespace SecretKit.Infisical.Dynamic;

/// <summary>Owned GitHub application/installation selectors and private-key input.</summary>
public sealed class NativeGithubDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Validates positive native IDs and copies the private key without minting a GitHub token.</summary>
    public NativeGithubDefinitionProfile(long applicationId, long installationId, string privateKey)
        : base(InfisicalDynamicProvider.Github)
    {
        Number("appId", applicationId, 1, long.MaxValue); Number("installationId", installationId, 1, long.MaxValue);
        Text("privateKey", privateKey);
    }
}
/// <summary>Owned RabbitMQ connection and virtual-host permission inputs, not a local authorization policy.</summary>
public sealed class NativeRabbitDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies credentials, explicit configure/write/read permissions, tags and optional CA.</summary>
    public NativeRabbitDefinitionProfile(string host, int port, string username, string password,
        string virtualHost, string configurePermission, string writePermission, string readPermission,
        IReadOnlyList<string>? tags = null, string? ca = null) : base(InfisicalDynamicProvider.RabbitMq)
    {
        Text("host", host); Number("port", port, 1, 65535); Text("username", username); Text("password", password);
        Text("virtualHost.name", virtualHost); Text("virtualHost.permissions.configure", configurePermission);
        Text("virtualHost.permissions.write", writePermission); Text("virtualHost.permissions.read", readPermission);
        Optional("ca", ca); if (tags is not null) { Strings("tags", tags, true); }
    }
}
/// <summary>Owned Kubernetes definition inputs for explicit static-service-account or dynamic-role selection.</summary>
public sealed class NativeKubernetesDefinitionProfile : InfisicalDynamicProfile
{
    private NativeKubernetesDefinitionProfile(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string? clusterToken, string? url, string? ca,
        NativeKubernetesAuthentication? authentication, NativeGatewayOptions? gateway, bool? sslEnabled)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "static"); Text("namespace", nameSpace); Text("serviceAccountName", serviceAccountName);
        Strings("audiences", audiences, true); ClusterAuthority(clusterToken, url, authentication, gateway, sslEnabled);
        Optional("ca", ca); Flag("sslRejectUnauthorized", true);
    }
    /// <summary>Copies service-account/audience and optional cluster/gateway/TLS inputs without reading host cluster credentials.</summary>
    public static NativeKubernetesDefinitionProfile ForStaticAccount(string nameSpace, string serviceAccountName,
        IReadOnlyList<string> audiences, string? clusterToken = null, string? url = null, string? ca = null,
        NativeKubernetesAuthentication? authentication = null, NativeGatewayOptions? gateway = null, bool? sslEnabled = null) =>
        new(nameSpace, serviceAccountName, audiences, clusterToken, url, ca, authentication, gateway, sslEnabled);
    /// <summary>Copies dynamic role or cluster-role selectors and explicit native authentication inputs.</summary>
    public NativeKubernetesDefinitionProfile(string nameSpace, string role, bool clusterRole,
        IReadOnlyList<string> audiences, string? clusterToken = null, string? url = null, string? ca = null,
        NativeKubernetesAuthentication? authentication = null, NativeGatewayOptions? gateway = null, bool? sslEnabled = null)
        : base(InfisicalDynamicProvider.Kubernetes)
    {
        Text("credentialType", "dynamic"); Text("namespace", nameSpace); Text("role", role);
        Text("roleType", clusterRole ? "cluster-role" : "role"); Strings("audiences", audiences, true);
        ClusterAuthority(clusterToken, url, authentication, gateway, sslEnabled); Optional("ca", ca);
        Flag("sslRejectUnauthorized", true);
    }
    private void ClusterAuthority(string? clusterToken, string? url, NativeKubernetesAuthentication? authentication,
        NativeGatewayOptions? gateway, bool? sslEnabled)
    {
        if (authentication is { } invalid && !Enum.IsDefined(invalid))
        {
            Dispose(); throw new ArgumentException("Unknown native Kubernetes authentication.");
        }
        if (authentication is { } method)
            Text("authMethod", method switch
            {
                NativeKubernetesAuthentication.Api => "api",
                NativeKubernetesAuthentication.Gateway => "gateway",
                _ => throw new ArgumentException("Unknown native Kubernetes authentication.")
            });
        Optional("clusterToken", clusterToken);
        if (url is not null)
        {
            if (url.Length == 0) Optional("url", url);
            else SafeUri("url", url);
        }
        Options(gateway);
        if (sslEnabled is { } enabled) Flag("sslEnabled", enabled);
    }
}
/// <summary>Owned SSH principal and optional key-algorithm inputs; no local key generation or issuance.</summary>
public sealed class NativeSshDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Validates closed algorithms and copies a bounded nonempty principal list.</summary>
    public NativeSshDefinitionProfile(IReadOnlyList<string> principals, NativeSshKeyAlgorithm? keyAlgorithm = null,
        NativeSshKeyAlgorithm? caKeyAlgorithm = null) : base(InfisicalDynamicProvider.Ssh)
    {
        // Validate both enum values before allocating protected principals.
        string? key = keyAlgorithm is { } algorithm ? Algorithm(algorithm) : null;
        string? ca = caKeyAlgorithm is { } caAlgorithm ? Algorithm(caAlgorithm) : null;
        Strings("principals", principals); Optional("keyAlgorithm", key); Optional("caKeyAlgorithm", ca);
    }
    private static string Algorithm(NativeSshKeyAlgorithm value) => value switch
    {
        NativeSshKeyAlgorithm.Rsa2048 => "RSA_2048",
        NativeSshKeyAlgorithm.Rsa4096 => "RSA_4096",
        NativeSshKeyAlgorithm.EcPrime256v1 => "EC_prime256v1",
        NativeSshKeyAlgorithm.EcSecp384r1 => "EC_secp384r1",
        NativeSshKeyAlgorithm.Ed25519 => "ED25519",
        _ => throw new ArgumentException("Unknown native SSH key algorithm.")
    };
}
/// <summary>Owned IBM API Connect authority and resource selectors with optional copied gateway options.</summary>
public sealed class NativeIbmApiDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies API/client credentials and explicit organization/catalog/application coordinates without I/O.</summary>
    public NativeIbmApiDefinitionProfile(string apiKey, string applicationId, string clientId, string clientSecret,
        string organizationId, string catalogId, string consumerOrganizationId, string instanceUrl,
        NativeGatewayOptions? gateway = null)
        : base(InfisicalDynamicProvider.IbmApiConnect)
    {
        Text("apiKey", apiKey); Text("appId", applicationId); Text("clientId", clientId); Text("clientSecret", clientSecret);
        Text("orgId", organizationId); Text("catalogId", catalogId); Text("consumerOrgId", consumerOrganizationId);
        SafeUri("instanceUrl", instanceUrl);
        Options(gateway);
    }
}
/// <summary>Owned Tailscale inputs with explicit authority and auth-key, federated-key or OAuth-key branches.</summary>
public sealed class NativeTailscaleDefinitionProfile : InfisicalDynamicProfile
{
    private NativeTailscaleDefinitionProfile(string authType, string? apiKey, string? clientId,
        string? clientSecret, string? issuer, string? subject, IReadOnlyList<string>? scopes, NativeTailscaleOptions? options)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        if (options?.HasAuthKeyFlags == true && authType != "auth_keys" ||
            options?.HasAudience == true && authType != "federated_keys")
            throw new ArgumentException("Unsupported native Tailscale branch options.");
        if ((authType != "auth_keys" && scopes is null) ||
            (authType == "federated_keys" && (issuer is null || subject is null)))
        {
            throw new ArgumentException("Required native Tailscale fields are missing.");
        }
        Text("authType", authType);
        if (apiKey is not null)
        {
            Text("auth.method", "api_key"); Text("auth.apiKey", apiKey);
        }
        else
        {
            Text("auth.method", "oauth"); Text("auth.clientId", clientId!); Text("auth.clientSecret", clientSecret!);
        }
        if (issuer is not null) { Text("issuer", issuer); }
        if (subject is not null) { Text("subject", subject); }
        if (scopes is not null) { Strings("scopes", scopes); }
        Options(options);
    }
    /// <summary>Copies OAuth authority for native auth-key creation, including optional auth-key flags.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthAuthority(string clientId, string clientSecret,
        NativeTailscaleOptions? options = null) =>
        new("auth_keys", null, clientId, clientSecret, null, null, null, options);
    /// <summary>Copies API-key authority and explicit issuer/subject/scopes for native federated keys.</summary>
    public static NativeTailscaleDefinitionProfile ForFederatedApiKey(string apiKey, string issuer, string subject,
        IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("federated_keys", apiKey, null, null, issuer, subject, scopes, options);
    /// <summary>Copies OAuth authority and issuer/subject/scopes for native federated keys.</summary>
    public static NativeTailscaleDefinitionProfile ForFederatedOAuth(string clientId, string clientSecret,
        string issuer, string subject, IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("federated_keys", null, clientId, clientSecret, issuer, subject, scopes, options);
    /// <summary>Copies API-key authority and scopes for native OAuth-key creation.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthKeyApiKey(string apiKey, IReadOnlyList<string> scopes,
        NativeTailscaleOptions? options = null) =>
        new("oauth_keys", apiKey, null, null, null, null, scopes, options);
    /// <summary>Copies OAuth authority and scopes for native OAuth-key creation.</summary>
    public static NativeTailscaleDefinitionProfile ForOAuthKeyOAuth(string clientId, string clientSecret,
        IReadOnlyList<string> scopes, NativeTailscaleOptions? options = null) =>
        new("oauth_keys", null, clientId, clientSecret, null, null, scopes, options);
    /// <summary>Copies API-key authority and explicit auth-key selectors/flags; no key is created by construction.</summary>
    public NativeTailscaleDefinitionProfile(string apiKey, string? tailnet = null, bool reusable = false,
        bool preauthorized = false, IReadOnlyList<string>? tags = null, string? description = null)
        : base(InfisicalDynamicProvider.Tailscale)
    {
        Text("authType", "auth_keys"); Text("auth.method", "api_key"); Text("auth.apiKey", apiKey);
        Optional("tailnet", tailnet); Flag("reusable", reusable); Flag("preauthorized", preauthorized);
        Optional("description", description, 50); if (tags is not null) { Strings("tags", tags, true); }
    }
}
