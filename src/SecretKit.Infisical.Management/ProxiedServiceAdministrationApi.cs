using Refit;

namespace SecretKit.Infisical.Management;

internal interface IProxiedServiceAdministrationApi
{
    [Get("/api/v1/proxied-services")]
    Task<HttpRequestMessage> List(string projectId, string environment, string? secretPath, CancellationToken cancellationToken);
    [Post("/api/v1/proxied-services")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/proxied-services/{serviceId}")]
    Task<HttpRequestMessage> Get(string serviceId, CancellationToken cancellationToken);
    [Patch("/api/v1/proxied-services/{serviceId}")]
    Task<HttpRequestMessage> Update(string serviceId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/proxied-services/{serviceId}")]
    Task<HttpRequestMessage> Delete(string serviceId, CancellationToken cancellationToken);
    [Get("/api/v1/proxied-services/slug/{name}")]
    Task<HttpRequestMessage> GetByName(string name, string projectId, string environment, string? secretPath, CancellationToken cancellationToken);
}
