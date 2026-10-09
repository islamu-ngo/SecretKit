using System.Text.Json.Serialization;
using Refit;

namespace SecretKit.Infisical;

// Handwritten, internal, native endpoints. Profile values come only from the closed native enum.
// Build requests without sending them; status and bounded body inspection remain adapter-owned.
internal interface IInfisicalRotationApi
{
    [Get("/api/v2/secret-rotations")]
    Task<HttpRequestMessage> ListAsync([AliasAs("projectId")] string projectId,
        [Header("Authorization")] string authorization, CancellationToken cancellationToken);

    [Get("/api/v2/secret-rotations/{profile}/{rotationId}")]
    Task<HttpRequestMessage> GetAsync(string profile, string rotationId,
        [Header("Authorization")] string authorization, CancellationToken cancellationToken);

    [Post("/api/v2/secret-rotations/{profile}/{rotationId}/rotate-secrets")]
    Task<HttpRequestMessage> RotateAsync(string profile, string rotationId,
        [Header("Authorization")] string authorization, CancellationToken cancellationToken);

    [Patch("/api/v2/secret-rotations/{profile}/{rotationId}")]
    Task<HttpRequestMessage> SetAutomaticAsync(string profile, string rotationId,
        [Body] InfisicalRotationEnablementBody body,
        [Header("Authorization")] string authorization, CancellationToken cancellationToken);
}

internal sealed class InfisicalRotationEnablementBody(bool enabled)
{
    [JsonPropertyName("isAutoRotationEnabled")]
    public bool Enabled { get; } = enabled;
    public override string ToString() => "[InfisicalRotationEnablementBody]";
}
