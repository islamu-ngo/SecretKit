using Refit;

namespace SecretKit.Infisical;

// Handwritten wire declarations only. Public contracts and JSON parsing remain protected and typed.
// Refit builds requests only; the shared managed parser owns dispatch, streaming, status and size limits.
internal interface IInfisicalOrganizationWire
{
    [Post("/api/v1/projects/{projectId}/environments")]
    Task<HttpRequestMessage> CreateEnvironmentAsync(string projectId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v1/projects/{projectId}/environments/{environmentId}")]
    Task<HttpRequestMessage> GetEnvironmentAsync(string projectId, string environmentId,
        CancellationToken cancellationToken);

    [Get("/api/v1/projects/{projectId}/environments/slug/{slug}")]
    Task<HttpRequestMessage> GetEnvironmentBySlugAsync(string projectId, string slug,
        CancellationToken cancellationToken);

    [Patch("/api/v1/projects/{projectId}/environments/{environmentId}")]
    Task<HttpRequestMessage> UpdateEnvironmentAsync(string projectId, string environmentId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v1/projects/{projectId}/environments/{environmentId}")]
    Task<HttpRequestMessage> DeleteEnvironmentAsync(string projectId, string environmentId, [Query] string hardDelete,
        CancellationToken cancellationToken);

    [Post("/api/v1/projects/{projectId}/environments/{environmentId}/restore")]
    Task<HttpRequestMessage> RestoreEnvironmentAsync(string projectId, string environmentId,
        CancellationToken cancellationToken);

    [Get("/api/v1/projects/{projectId}/tags")]
    Task<HttpRequestMessage> ListTagsAsync(string projectId,
        CancellationToken cancellationToken);

    [Post("/api/v1/projects/{projectId}/tags")]
    Task<HttpRequestMessage> CreateTagAsync(string projectId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v1/projects/{projectId}/tags/{tagId}")]
    Task<HttpRequestMessage> GetTagAsync(string projectId, string tagId,
        CancellationToken cancellationToken);

    [Get("/api/v1/projects/{projectId}/tags/slug/{slug}")]
    Task<HttpRequestMessage> GetTagBySlugAsync(string projectId, string slug,
        CancellationToken cancellationToken);

    [Patch("/api/v1/projects/{projectId}/tags/{tagId}")]
    Task<HttpRequestMessage> UpdateTagAsync(string projectId, string tagId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v1/projects/{projectId}/tags/{tagId}")]
    Task<HttpRequestMessage> DeleteTagAsync(string projectId, string tagId,
        CancellationToken cancellationToken);

    [Get("/api/v2/folders")]
    Task<HttpRequestMessage> ListFoldersAsync([Query] string projectId, [Query] string environment,
        [Query] string path, [Query] string recursive, [Query] string? lastSecretModified,
        CancellationToken cancellationToken);

    [Post("/api/v2/folders")]
    Task<HttpRequestMessage> CreateFolderAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Get("/api/v2/folders/{folderId}")]
    Task<HttpRequestMessage> GetFolderAsync(string folderId,
        CancellationToken cancellationToken);

    [Patch("/api/v2/folders/{folderId}")]
    Task<HttpRequestMessage> UpdateFolderAsync(string folderId, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Delete("/api/v2/folders/{folderIdOrName}")]
    Task<HttpRequestMessage> DeleteFolderAsync(string folderIdOrName, [Body] HttpContent body,
        CancellationToken cancellationToken);

    [Patch("/api/v2/folders/batch")]
    Task<HttpRequestMessage> UpdateFoldersAsync([Body] HttpContent body,
        CancellationToken cancellationToken);

    [Post("/api/v2/folders/move")]
    Task<HttpRequestMessage> MoveFolderAsync([Body] HttpContent body,
        CancellationToken cancellationToken);
}
