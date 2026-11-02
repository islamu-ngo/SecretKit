using Refit;

namespace SecretKit.Infisical.Management;

internal interface IGatewayAdministrationApi
{
    [Post("/api/v3/gateways")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v3/gateways/{gatewayId}")]
    Task<HttpRequestMessage> Get(string gatewayId, CancellationToken cancellationToken);
    [Patch("/api/v3/gateways/{gatewayId}")]
    Task<HttpRequestMessage> Update(string gatewayId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v3/gateways/{gatewayId}/token-auth/generate-enrollment-token")]
    Task<HttpRequestMessage> GenerateEnrollmentToken(string gatewayId, CancellationToken cancellationToken);
}
