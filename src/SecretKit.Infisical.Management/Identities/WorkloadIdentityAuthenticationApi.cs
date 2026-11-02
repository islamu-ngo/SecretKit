using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten request construction only. The parent owns its builder binding.
internal interface IWorkloadIdentityAuthenticationApi
{
    [Get("/api/v1/auth/jwt-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetJwt(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/jwt-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachJwt(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/jwt-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateJwt(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/jwt-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteJwt(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/oidc-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetOidc(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/oidc-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachOidc(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/oidc-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateOidc(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/oidc-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteOidc(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/kubernetes-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetKubernetes(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/kubernetes-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachKubernetes(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/kubernetes-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateKubernetes(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/kubernetes-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteKubernetes(string identityId, CancellationToken cancellationToken);
}
