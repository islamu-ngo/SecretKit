using Refit;

namespace SecretKit.Infisical;

internal interface IInfisicalBulkWire
{
    [Post("/api/v4/secrets/batch")]
    Task<HttpRequestMessage> CreateSecretsAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Patch("/api/v4/secrets/batch")]
    Task<HttpRequestMessage> UpdateSecretsAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v4/secrets/batch")]
    Task<HttpRequestMessage> DeleteSecretsAsync([Body] HttpContent body,
        CancellationToken cancellationToken);
}
