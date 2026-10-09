using System.Net.Http.Headers;
using Refit;

namespace SecretKit.Infisical;

public sealed partial class InfisicalClient
{
    private IInfisicalOrganizationWire? _nativeOrganizationWire;
    private IInfisicalImportWire? _nativeImportWire;
    private IInfisicalBulkWire? _nativeBulkWire;
    private IInfisicalValidationWire? _nativeValidationWire;
    private static readonly RefitSettings NativeRefitSettings = new()
    {
        CaptureRequestContent = false,
        CaptureMethodArguments = false,
        ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null)
    };

    private IInfisicalOrganizationWire OrganizationWire =>
        LazyInitializer.EnsureInitialized(ref _nativeOrganizationWire,
            () => RestService.For<IInfisicalOrganizationWire>(_http, NativeRefitSettings));
    private IInfisicalImportWire ImportWire =>
        LazyInitializer.EnsureInitialized(ref _nativeImportWire,
            () => RestService.For<IInfisicalImportWire>(_http, NativeRefitSettings));
    private IInfisicalBulkWire BulkWire =>
        LazyInitializer.EnsureInitialized(ref _nativeBulkWire,
            () => RestService.For<IInfisicalBulkWire>(_http, NativeRefitSettings));
    private IInfisicalValidationWire ValidationWire =>
        LazyInitializer.EnsureInitialized(ref _nativeValidationWire,
            () => RestService.For<IInfisicalValidationWire>(_http, NativeRefitSettings));

    // These switches bind protected typed addresses to the fixed handwritten interfaces.
    // No caller can choose an endpoint, arbitrary method, raw body or wire request.
    private async Task<HttpRequestMessage> BuildNativeRequestAsync(InfisicalNativeAddress address,
        string path, HttpMethod method, byte[]? payload, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ByteArrayContent? content = payload is null ? null : new ByteArrayContent(payload);
        if (content is not null) { content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
        bool transferred = false;
        try
        {
            Task<HttpRequestMessage> building = address switch
            {
                InfisicalEnvironmentAddress environment => BuildEnvironmentRequest(environment, path, method, content, cancellationToken),
                InfisicalTagAddress tag => BuildTagRequest(tag, method, content, cancellationToken),
                InfisicalFolderAddress folder => BuildFolderRequest(folder, path, method, content, cancellationToken),
                InfisicalImportAddress import => BuildImportRequest(import, path, method, content, cancellationToken),
                InfisicalBulkAddress => method.Method switch
                {
                    "POST" => BulkWire.CreateSecretsAsync(content!, cancellationToken),
                    "PATCH" => BulkWire.UpdateSecretsAsync(content!, cancellationToken),
                    "DELETE" => BulkWire.DeleteSecretsAsync(content!, cancellationToken),
                    _ => throw new InvalidOperationException("Invalid native bulk binding.")
                },
                InfisicalValidationAddress validation => BuildValidationRequest(validation, path, method, content, cancellationToken),
                _ => throw new InvalidOperationException("Invalid native address binding.")
            };
            HttpRequestMessage request = await building.ConfigureAwait(false);
            Uri uri = request.RequestUri is { } returned ? new Uri(_origin, returned) :
                throw new InvalidOperationException("Native request has no destination.");
            if (uri.Scheme != _origin.Scheme || uri.Host != _origin.Host || uri.Port != _origin.Port ||
                uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || request.Method != method)
            {
                request.Dispose();
                throw new InvalidOperationException("Invalid native destination.");
            }
            request.RequestUri = uri;
            transferred = true;
            return request;
        }
        finally
        {
            if (!transferred) { content?.Dispose(); }
        }
    }

    private Task<HttpRequestMessage> BuildEnvironmentRequest(InfisicalEnvironmentAddress address, string path,
        HttpMethod method, HttpContent? content, CancellationToken cancellationToken) => method.Method switch
        {
            "GET" when address.Selection == InfisicalOrganizationSelector.Slug =>
                OrganizationWire.GetEnvironmentBySlugAsync(address.ProjectId, address.Selector, cancellationToken),
            "GET" => OrganizationWire.GetEnvironmentAsync(address.ProjectId, address.Selector, cancellationToken),
            "POST" when path.EndsWith("/restore", StringComparison.Ordinal) =>
                OrganizationWire.RestoreEnvironmentAsync(address.ProjectId, address.Selector, cancellationToken),
            "POST" => OrganizationWire.CreateEnvironmentAsync(address.ProjectId, content!, cancellationToken),
            "PATCH" => OrganizationWire.UpdateEnvironmentAsync(address.ProjectId, address.Selector, content!, cancellationToken),
            "DELETE" => OrganizationWire.DeleteEnvironmentAsync(address.ProjectId, address.Selector,
                NativeQueryValue(path, "hardDelete")!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid environment binding.")
        };

    private Task<HttpRequestMessage> BuildTagRequest(InfisicalTagAddress address, HttpMethod method,
        HttpContent? content, CancellationToken cancellationToken) => method.Method switch
        {
            "GET" when address.Selector is null => OrganizationWire.ListTagsAsync(address.ProjectId, cancellationToken),
            "GET" when address.Selection == InfisicalOrganizationSelector.Slug =>
                OrganizationWire.GetTagBySlugAsync(address.ProjectId, address.Selector!, cancellationToken),
            "GET" => OrganizationWire.GetTagAsync(address.ProjectId, address.Selector!, cancellationToken),
            "POST" => OrganizationWire.CreateTagAsync(address.ProjectId, content!, cancellationToken),
            "PATCH" => OrganizationWire.UpdateTagAsync(address.ProjectId, address.Selector!, content!, cancellationToken),
            "DELETE" => OrganizationWire.DeleteTagAsync(address.ProjectId, address.Selector!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid tag binding.")
        };

    private Task<HttpRequestMessage> BuildFolderRequest(InfisicalFolderAddress address, string path, HttpMethod method,
        HttpContent? content, CancellationToken cancellationToken) => method.Method switch
        {
            "GET" when path.StartsWith("api/v2/folders?", StringComparison.Ordinal) =>
                OrganizationWire.ListFoldersAsync(address.ProjectId, address.Environment!, address.Folder!,
                    NativeQueryValue(path, "recursive")!, NativeQueryValue(path, "lastSecretModified"), cancellationToken),
            "GET" => OrganizationWire.GetFolderAsync(address.Id!, cancellationToken),
            "POST" when path == "api/v2/folders/move" => OrganizationWire.MoveFolderAsync(content!, cancellationToken),
            "POST" => OrganizationWire.CreateFolderAsync(content!, cancellationToken),
            "PATCH" when path == "api/v2/folders/batch" => OrganizationWire.UpdateFoldersAsync(content!, cancellationToken),
            "PATCH" => OrganizationWire.UpdateFolderAsync(address.Id!, content!, cancellationToken),
            "DELETE" => OrganizationWire.DeleteFolderAsync(address.Id ?? address.Name!, content!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid folder binding.")
        };

    private Task<HttpRequestMessage> BuildImportRequest(InfisicalImportAddress address, string path, HttpMethod method,
        HttpContent? content, CancellationToken cancellationToken) => method.Method switch
        {
            "GET" when path.StartsWith("api/v2/secret-imports/secrets?", StringComparison.Ordinal) =>
                ImportWire.ReadImportedSecretsAsync(address.ProjectId, address.Environment!, address.Folder!, cancellationToken),
            "GET" when address.ImportId is null =>
                ImportWire.ListImportsAsync(address.ProjectId, address.Environment!, address.Folder!, cancellationToken),
            "GET" => ImportWire.GetImportAsync(address.ImportId!, cancellationToken),
            "POST" => ImportWire.CreateImportAsync(content!, cancellationToken),
            "PATCH" => ImportWire.UpdateImportAsync(address.ImportId!, content!, cancellationToken),
            "DELETE" => ImportWire.DeleteImportAsync(address.ImportId!, content!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid import binding.")
        };

    private Task<HttpRequestMessage> BuildValidationRequest(InfisicalValidationAddress address, string path, HttpMethod method,
        HttpContent? content, CancellationToken cancellationToken)
    {
        if (method == HttpMethod.Get && path.StartsWith("api/v1/secret-validation-rules?", StringComparison.Ordinal))
        {
            return ValidationWire.ListAllAsync(address.ProjectId, cancellationToken);
        }
        return (address.Kind, method.Method, address.RuleId is null) switch
        {
            (InfisicalValidationKind.StaticSecrets, "GET", true) => ValidationWire.ListStaticAsync(address.ProjectId, cancellationToken),
            (InfisicalValidationKind.StaticSecrets, "GET", false) => ValidationWire.GetStaticAsync(address.RuleId!, cancellationToken),
            (InfisicalValidationKind.StaticSecrets, "POST", _) => ValidationWire.CreateStaticAsync(content!, cancellationToken),
            (InfisicalValidationKind.StaticSecrets, "PATCH", _) => ValidationWire.UpdateStaticAsync(address.RuleId!, content!, cancellationToken),
            (InfisicalValidationKind.StaticSecrets, "DELETE", _) => ValidationWire.DeleteStaticAsync(address.RuleId!, cancellationToken),
            (InfisicalValidationKind.DynamicSecrets, "GET", true) => ValidationWire.ListDynamicAsync(address.ProjectId, cancellationToken),
            (InfisicalValidationKind.DynamicSecrets, "GET", false) => ValidationWire.GetDynamicAsync(address.RuleId!, cancellationToken),
            (InfisicalValidationKind.DynamicSecrets, "POST", _) => ValidationWire.CreateDynamicAsync(content!, cancellationToken),
            (InfisicalValidationKind.DynamicSecrets, "PATCH", _) => ValidationWire.UpdateDynamicAsync(address.RuleId!, content!, cancellationToken),
            (InfisicalValidationKind.DynamicSecrets, "DELETE", _) => ValidationWire.DeleteDynamicAsync(address.RuleId!, cancellationToken),
            (InfisicalValidationKind.SecretRotations, "GET", true) => ValidationWire.ListRotationAsync(address.ProjectId, cancellationToken),
            (InfisicalValidationKind.SecretRotations, "GET", false) => ValidationWire.GetRotationAsync(address.RuleId!, cancellationToken),
            (InfisicalValidationKind.SecretRotations, "POST", _) => ValidationWire.CreateRotationAsync(content!, cancellationToken),
            (InfisicalValidationKind.SecretRotations, "PATCH", _) => ValidationWire.UpdateRotationAsync(address.RuleId!, content!, cancellationToken),
            (InfisicalValidationKind.SecretRotations, "DELETE", _) => ValidationWire.DeleteRotationAsync(address.RuleId!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid validation binding.")
        };
    }

    private static string? NativeQueryValue(string path, string name)
    {
        int start = path.IndexOf('?');
        if (start < 0) { return null; }
        foreach (string pair in path[(start + 1)..].Split('&'))
        {
            int separator = pair.IndexOf('=');
            if (separator >= 0 && pair[..separator] == name)
            {
                return Uri.UnescapeDataString(pair[(separator + 1)..]);
            }
        }
        return null;
    }
}
