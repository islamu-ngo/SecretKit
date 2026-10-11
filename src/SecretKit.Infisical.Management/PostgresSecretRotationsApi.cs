using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten fixed construction only. Parent owns ManagementRequestBuilder bindings.
internal interface IPostgresSecretRotationApi
{
    [Get("/api/v2/secret-rotations/postgres-credentials")]
    Task<HttpRequestMessage> List(string projectId, CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/postgres-credentials")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/postgres-credentials/{rotationId}")]
    Task<HttpRequestMessage> Get(string rotationId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/postgres-credentials/rotation-name/{rotationName}")]
    Task<HttpRequestMessage> GetByName(string rotationName, string projectId, string environment, string secretPath,
        CancellationToken cancellationToken);
    [Patch("/api/v2/secret-rotations/postgres-credentials/{rotationId}")]
    Task<HttpRequestMessage> Update(string rotationId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v2/secret-rotations/postgres-credentials/{rotationId}")]
    Task<HttpRequestMessage> Delete(string rotationId, string? deleteSecrets, string? revokeGeneratedCredentials,
        CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/postgres-credentials/{rotationId}/check-credentials")]
    Task<HttpRequestMessage> CheckCredentials(string rotationId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/postgres-credentials/{rotationId}/generated-credentials")]
    Task<HttpRequestMessage> GeneratedCredentials(string rotationId, CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/postgres-credentials/{rotationId}/move")]
    Task<HttpRequestMessage> Move(string rotationId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations")]
    Task<HttpRequestMessage> ListCatalog(string projectId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/options")]
    Task<HttpRequestMessage> Options(CancellationToken cancellationToken);
}
