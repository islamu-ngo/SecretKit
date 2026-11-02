using Refit;

namespace SecretKit.Infisical;

internal interface IInfisicalProofAuthenticationWire
{
    [Post("/api/v1/auth/alicloud-auth/login")]
    Task<HttpRequestMessage> AliCloudAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/aws-auth/login")]
    Task<HttpRequestMessage> AwsAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/azure-auth/login")]
    Task<HttpRequestMessage> AzureAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/gcp-auth/login")]
    Task<HttpRequestMessage> GcpAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/jwt-auth/login")]
    Task<HttpRequestMessage> JwtAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/kubernetes-auth/login")]
    Task<HttpRequestMessage> KubernetesAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/ldap-auth/login")]
    Task<HttpRequestMessage> LdapAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/oci-auth/login")]
    Task<HttpRequestMessage> OciAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/oidc-auth/login")]
    Task<HttpRequestMessage> OidcAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/spiffe-auth/login")]
    Task<HttpRequestMessage> SpiffeAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/tls-cert-auth/login")]
    Task<HttpRequestMessage> TlsCertificateAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/token/revoke")]
    Task<HttpRequestMessage> RevokeTokenAsync([Body] HttpContent body, CancellationToken cancellationToken);
}
