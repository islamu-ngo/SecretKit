using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten request construction only; the parent owns the dispatch table binding.
internal interface ICloudIdentityAuthenticationApi
{
    [Get("/api/v1/auth/aws-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetAws(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/aws-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachAws(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/aws-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateAws(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/aws-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteAws(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/azure-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetAzure(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/azure-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachAzure(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/azure-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateAzure(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/azure-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteAzure(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/gcp-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetGcp(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/gcp-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachGcp(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/gcp-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateGcp(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/gcp-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteGcp(string identityId, CancellationToken cancellationToken);
    [Get("/api/v1/auth/alicloud-auth/identities/{identityId}")]
    Task<HttpRequestMessage> GetAliCloud(string identityId, CancellationToken cancellationToken);
    [Post("/api/v1/auth/alicloud-auth/identities/{identityId}")]
    Task<HttpRequestMessage> AttachAliCloud(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/auth/alicloud-auth/identities/{identityId}")]
    Task<HttpRequestMessage> UpdateAliCloud(string identityId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/auth/alicloud-auth/identities/{identityId}")]
    Task<HttpRequestMessage> DeleteAliCloud(string identityId, CancellationToken cancellationToken);
}
