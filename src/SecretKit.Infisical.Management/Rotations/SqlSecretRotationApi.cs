using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten fixed construction only. Parent owns ManagementRequestBuilder bindings.
// credentialType is always a fixed SqlSecretRotationFamily constant, and the builder
// independently verifies every constructed path against the operation's declared path.
internal interface ISqlSecretRotationApi
{
    [Get("/api/v2/secret-rotations/{credentialType}")]
    Task<HttpRequestMessage> List(string credentialType, string projectId, CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/{credentialType}")]
    Task<HttpRequestMessage> Create(string credentialType, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/{credentialType}/{rotationId}")]
    Task<HttpRequestMessage> Get(string credentialType, string rotationId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/{credentialType}/rotation-name/{rotationName}")]
    Task<HttpRequestMessage> GetByName(string credentialType, string rotationName, string projectId, string environment,
        string secretPath, CancellationToken cancellationToken);
    [Patch("/api/v2/secret-rotations/{credentialType}/{rotationId}")]
    Task<HttpRequestMessage> Update(string credentialType, string rotationId, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Delete("/api/v2/secret-rotations/{credentialType}/{rotationId}")]
    Task<HttpRequestMessage> Delete(string credentialType, string rotationId, string? deleteSecrets,
        string? revokeGeneratedCredentials, CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/{credentialType}/{rotationId}/check-credentials")]
    Task<HttpRequestMessage> CheckCredentials(string credentialType, string rotationId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/{credentialType}/{rotationId}/generated-credentials")]
    Task<HttpRequestMessage> GeneratedCredentials(string credentialType, string rotationId, CancellationToken cancellationToken);
    [Post("/api/v2/secret-rotations/{credentialType}/{rotationId}/move")]
    Task<HttpRequestMessage> Move(string credentialType, string rotationId, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations")]
    Task<HttpRequestMessage> ListCatalog(string projectId, CancellationToken cancellationToken);
    [Get("/api/v2/secret-rotations/options")]
    Task<HttpRequestMessage> Options(CancellationToken cancellationToken);
}
