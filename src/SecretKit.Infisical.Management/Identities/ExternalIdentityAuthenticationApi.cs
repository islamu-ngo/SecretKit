using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten request construction; the parent owns the fixed dispatcher binding.
internal interface IExternalIdentityAuthenticationApi
{
    [Get("/api/v1/auth/ldap-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetLdap(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/ldap-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachLdap(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/ldap-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateLdap(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/ldap-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteLdap(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/ldap-auth/identities/{identityId}/clear-lockouts")]
    Task<HttpRequestMessage> ClearLdapLockouts(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/oci-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetOci(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/oci-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachOci(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/oci-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateOci(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/oci-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteOci(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/spiffe-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetSpiffe(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/spiffe-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachSpiffe(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/spiffe-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateSpiffe(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/spiffe-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteSpiffe(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/spiffe-auth/identities/{identityId}/refresh-bundle")]
    Task<HttpRequestMessage> RefreshSpiffeBundle(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/tls-cert-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetTlsCert(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/tls-cert-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachTlsCert(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/tls-cert-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateTlsCert(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/tls-cert-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteTlsCert(string identityId, CancellationToken cancellationToken);
}
