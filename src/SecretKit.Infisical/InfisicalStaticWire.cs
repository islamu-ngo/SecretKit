using Refit;

namespace SecretKit.Infisical;

// Handwritten native bindings only. Responses, identity, budgets and dispatch
// evidence remain under the adapter's controlled HttpClient, not a wire DTO API.
internal interface IInfisicalStaticWire
{
    [Get("/api/v4/secrets/{key}")]
    Task<HttpRequestMessage> ReadAsync(string key, [Query] string projectId,
        [Query] string environment, [Query] string secretPath, [Query] string viewSecretValue,
        [Query] string type, [Query] string expandSecretReferences, [Query] string includeImports,
        [Query] int? version, CancellationToken cancellationToken);

    [Get("/api/v4/secrets")]
    Task<HttpRequestMessage> InspectAsync([Query] string projectId, [Query] string environment,
        [Query] string secretPath, [Query] string viewSecretValue, [Query] string expandSecretReferences,
        [Query] string recursive, [Query] string includeImports, [Query] string includePersonalOverrides,
        CancellationToken cancellationToken);

    [Post("/api/v4/secrets/{key}")]
    Task<HttpRequestMessage> CreateAsync(string key, [Body] HttpContent payload,
        CancellationToken cancellationToken);

    [Patch("/api/v4/secrets/{key}")]
    Task<HttpRequestMessage> UpdateAsync(string key, [Body] HttpContent payload,
        CancellationToken cancellationToken);
}
