using Refit;

namespace SecretKit.Infisical;

internal interface IInfisicalValidationWire
{
    [Get("/api/v1/secret-validation-rules")]
    Task<HttpRequestMessage> ListAllAsync([Query] string projectId,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/static-secrets")]
    Task<HttpRequestMessage> ListStaticAsync([Query] string projectId,
        CancellationToken cancellationToken);

    [Post("/api/v1/secret-validation-rules/static-secrets")]
    Task<HttpRequestMessage> CreateStaticAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/static-secrets/{ruleId}")]
    Task<HttpRequestMessage> GetStaticAsync(string ruleId,
        CancellationToken cancellationToken);

    [Patch("/api/v1/secret-validation-rules/static-secrets/{ruleId}")]
    Task<HttpRequestMessage> UpdateStaticAsync(string ruleId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v1/secret-validation-rules/static-secrets/{ruleId}")]
    Task<HttpRequestMessage> DeleteStaticAsync(string ruleId,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/dynamic-secrets")]
    Task<HttpRequestMessage> ListDynamicAsync([Query] string projectId,
        CancellationToken cancellationToken);

    [Post("/api/v1/secret-validation-rules/dynamic-secrets")]
    Task<HttpRequestMessage> CreateDynamicAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}")]
    Task<HttpRequestMessage> GetDynamicAsync(string ruleId,
        CancellationToken cancellationToken);

    [Patch("/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}")]
    Task<HttpRequestMessage> UpdateDynamicAsync(string ruleId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v1/secret-validation-rules/dynamic-secrets/{ruleId}")]
    Task<HttpRequestMessage> DeleteDynamicAsync(string ruleId,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/secret-rotations")]
    Task<HttpRequestMessage> ListRotationAsync([Query] string projectId,
        CancellationToken cancellationToken);

    [Post("/api/v1/secret-validation-rules/secret-rotations")]
    Task<HttpRequestMessage> CreateRotationAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v1/secret-validation-rules/secret-rotations/{ruleId}")]
    Task<HttpRequestMessage> GetRotationAsync(string ruleId,
        CancellationToken cancellationToken);

    [Patch("/api/v1/secret-validation-rules/secret-rotations/{ruleId}")]
    Task<HttpRequestMessage> UpdateRotationAsync(string ruleId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v1/secret-validation-rules/secret-rotations/{ruleId}")]
    Task<HttpRequestMessage> DeleteRotationAsync(string ruleId,
        CancellationToken cancellationToken);
}
