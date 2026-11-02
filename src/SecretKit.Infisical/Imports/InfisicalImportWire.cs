using Refit;

namespace SecretKit.Infisical;

internal interface IInfisicalImportWire
{
    [Get("/api/v2/secret-imports")]
    Task<HttpRequestMessage> ListImportsAsync([Query] string projectId, [Query] string environment, [Query] string path,
        CancellationToken cancellationToken);

    [Post("/api/v2/secret-imports")]
    Task<HttpRequestMessage> CreateImportAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v2/secret-imports/{importId}")]
    Task<HttpRequestMessage> GetImportAsync(string importId,
        CancellationToken cancellationToken);

    [Patch("/api/v2/secret-imports/{importId}")]
    Task<HttpRequestMessage> UpdateImportAsync(string importId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v2/secret-imports/{importId}")]
    Task<HttpRequestMessage> DeleteImportAsync(string importId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v2/secret-imports/secrets")]
    Task<HttpRequestMessage> ReadImportedSecretsAsync([Query] string projectId, [Query] string environment, [Query] string path,
        CancellationToken cancellationToken);
}
