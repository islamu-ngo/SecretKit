using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical;

// Handwritten route declarations only. Bodies are privately constructed typed-profile content;
// Request builders preserve the controlled HttpClient send and bounded native parser seam.
internal interface IInfisicalDynamicWire
{
    [Get("/api/v1/dynamic-secrets")]
    Task<HttpRequestMessage> ListDefinitionsAsync(string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> InspectDefinitionAsync(string name, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets")]
    Task<HttpRequestMessage> CreateDefinitionAsync([Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Patch("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> UpdateDefinitionAsync(string name, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Delete("/api/v1/dynamic-secrets/{name}")]
    Task<HttpRequestMessage> DeleteDefinitionAsync(string name, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/{name}/leases")]
    Task<HttpRequestMessage> ListLeasesAsync(string name, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Get("/api/v1/dynamic-secrets/leases/{leaseId}")]
    Task<HttpRequestMessage> InspectLeaseAsync(Guid leaseId, string projectSlug, string environmentSlug,
        [AliasAs("path")] string folder, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets/leases")]
    Task<HttpRequestMessage> AcquireAsync([Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Post("/api/v1/dynamic-secrets/leases/{leaseId}/renew")]
    Task<HttpRequestMessage> RenewAsync(Guid leaseId, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);

    [Delete("/api/v1/dynamic-secrets/leases/{leaseId}")]
    Task<HttpRequestMessage> RevokeAsync(Guid leaseId, [Body] HttpContent content,
        [Property("SecretKit.DynamicReceipt")] InfisicalDynamicMutationReceipt receipt, CancellationToken cancellationToken);
}
