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

internal interface IInfisicalProofAuthenticationWire
{
    [Post("/api/v1/auth/alicloud-auth/login")]
    Task<HttpRequestMessage> AliCloudAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/aws-auth/login")]
    Task<HttpRequestMessage> AwsAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/azure-auth/login")]
    Task<HttpRequestMessage> AzureAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/gcp-auth/login")]
    Task<HttpRequestMessage> GcpAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/jwt-auth/login")]
    Task<HttpRequestMessage> JwtAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/kubernetes-auth/login")]
    Task<HttpRequestMessage> KubernetesAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/ldap-auth/login")]
    Task<HttpRequestMessage> LdapAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/oci-auth/login")]
    Task<HttpRequestMessage> OciAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/oidc-auth/login")]
    Task<HttpRequestMessage> OidcAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/spiffe-auth/login")]
    Task<HttpRequestMessage> SpiffeAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/tls-cert-auth/login")]
    Task<HttpRequestMessage> TlsCertificateAsync([Body] HttpContent body, CancellationToken cancellationToken);

    [Post("/api/v1/auth/token/revoke")]
    Task<HttpRequestMessage> RevokeTokenAsync([Body] HttpContent body, CancellationToken cancellationToken);
}
