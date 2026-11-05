using System.Globalization;
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
            () => RestService.ForGenerated<IInfisicalOrganizationWire>(_binding.Requests, NativeRefitSettings));
    private IInfisicalImportWire ImportWire =>
        LazyInitializer.EnsureInitialized(ref _nativeImportWire,
            () => RestService.ForGenerated<IInfisicalImportWire>(_binding.Requests, NativeRefitSettings));
    private IInfisicalBulkWire BulkWire =>
        LazyInitializer.EnsureInitialized(ref _nativeBulkWire,
            () => RestService.ForGenerated<IInfisicalBulkWire>(_binding.Requests, NativeRefitSettings));
    private IInfisicalValidationWire ValidationWire =>
        LazyInitializer.EnsureInitialized(ref _nativeValidationWire,
            () => RestService.ForGenerated<IInfisicalValidationWire>(_binding.Requests, NativeRefitSettings));

    // These switches bind protected typed addresses to the fixed handwritten interfaces.
    // No caller can choose an endpoint, arbitrary method, raw body or wire request.
    private async Task<HttpRequestMessage> BuildNativeRequestAsync(InfisicalNativeAddress address,
        InfisicalNativeOperation operation, byte[]? payload, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        HttpMethod method = operation.Method;
        ByteArrayContent? content = payload is null ? null : new ByteArrayContent(payload);
        if (content is not null) { content.Headers.ContentType = new MediaTypeHeaderValue("application/json"); }
        bool transferred = false;
        try
        {
            Task<HttpRequestMessage> building = address switch
            {
                InfisicalEnvironmentAddress environment => BuildEnvironmentRequest(environment, operation, content, cancellationToken),
                InfisicalTagAddress tag when operation.Kind == InfisicalNativeOperationKind.Standard => BuildTagRequest(tag, method, content, cancellationToken),
                InfisicalFolderAddress folder => BuildFolderRequest(folder, operation, content, cancellationToken),
                InfisicalImportAddress import => BuildImportRequest(import, operation, content, cancellationToken),
                InfisicalBulkAddress when operation.Kind == InfisicalNativeOperationKind.Standard => method.Method switch
                {
                    "POST" => BulkWire.CreateSecretsAsync(content!, cancellationToken),
                    "PATCH" => BulkWire.UpdateSecretsAsync(content!, cancellationToken),
                    "DELETE" => BulkWire.DeleteSecretsAsync(content!, cancellationToken),
                    _ => throw new InvalidOperationException("Invalid native bulk binding.")
                },
                InfisicalValidationAddress validation => BuildValidationRequest(validation, operation, content, cancellationToken),
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

    private Task<HttpRequestMessage> BuildEnvironmentRequest(InfisicalEnvironmentAddress address,
        InfisicalNativeOperation operation, HttpContent? content, CancellationToken cancellationToken) =>
        (operation.Method.Method, operation.Kind) switch
        {
            ("GET", InfisicalNativeOperationKind.Standard) when address.Selection == InfisicalOrganizationSelector.Slug =>
                OrganizationWire.GetEnvironmentBySlugAsync(address.ProjectId, address.Selector, cancellationToken),
            ("GET", InfisicalNativeOperationKind.Standard) => OrganizationWire.GetEnvironmentAsync(address.ProjectId, address.Selector, cancellationToken),
            ("POST", InfisicalNativeOperationKind.RestoreEnvironment) =>
                OrganizationWire.RestoreEnvironmentAsync(address.ProjectId, address.Selector, cancellationToken),
            ("POST", InfisicalNativeOperationKind.Standard) => OrganizationWire.CreateEnvironmentAsync(address.ProjectId, content!, cancellationToken),
            ("PATCH", InfisicalNativeOperationKind.Standard) => OrganizationWire.UpdateEnvironmentAsync(address.ProjectId, address.Selector, content!, cancellationToken),
            ("DELETE", InfisicalNativeOperationKind.Standard) => OrganizationWire.DeleteEnvironmentAsync(address.ProjectId, address.Selector,
                Boolean(operation.HardDelete), cancellationToken),
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

    private Task<HttpRequestMessage> BuildFolderRequest(InfisicalFolderAddress address, InfisicalNativeOperation operation,
        HttpContent? content, CancellationToken cancellationToken) => (operation.Method.Method, operation.Kind) switch
        {
            ("GET", InfisicalNativeOperationKind.ListFolders) =>
                OrganizationWire.ListFoldersAsync(address.ProjectId, address.Environment!, address.Folder!,
                    Boolean(operation.Recursive), operation.LastSecretModified?.ToString("O", CultureInfo.InvariantCulture), cancellationToken),
            ("GET", InfisicalNativeOperationKind.Standard) => OrganizationWire.GetFolderAsync(address.Id!, cancellationToken),
            ("POST", InfisicalNativeOperationKind.MoveFolder) => OrganizationWire.MoveFolderAsync(content!, cancellationToken),
            ("POST", InfisicalNativeOperationKind.Standard) => OrganizationWire.CreateFolderAsync(content!, cancellationToken),
            ("PATCH", InfisicalNativeOperationKind.UpdateFolders) => OrganizationWire.UpdateFoldersAsync(content!, cancellationToken),
            ("PATCH", InfisicalNativeOperationKind.Standard) => OrganizationWire.UpdateFolderAsync(address.Id!, content!, cancellationToken),
            ("DELETE", InfisicalNativeOperationKind.Standard) => OrganizationWire.DeleteFolderAsync(address.Id ?? address.Name!, content!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid folder binding.")
        };

    private Task<HttpRequestMessage> BuildImportRequest(InfisicalImportAddress address, InfisicalNativeOperation operation,
        HttpContent? content, CancellationToken cancellationToken) => (operation.Method.Method, operation.Kind) switch
        {
            ("GET", InfisicalNativeOperationKind.ReadImportedSecrets) =>
                ImportWire.ReadImportedSecretsAsync(address.ProjectId, address.Environment!, address.Folder!, cancellationToken),
            ("GET", InfisicalNativeOperationKind.Standard) when address.ImportId is null =>
                ImportWire.ListImportsAsync(address.ProjectId, address.Environment!, address.Folder!, cancellationToken),
            ("GET", InfisicalNativeOperationKind.Standard) => ImportWire.GetImportAsync(address.ImportId!, cancellationToken),
            ("POST", InfisicalNativeOperationKind.Standard) => ImportWire.CreateImportAsync(content!, cancellationToken),
            ("PATCH", InfisicalNativeOperationKind.Standard) => ImportWire.UpdateImportAsync(address.ImportId!, content!, cancellationToken),
            ("DELETE", InfisicalNativeOperationKind.Standard) => ImportWire.DeleteImportAsync(address.ImportId!, content!, cancellationToken),
            _ => throw new InvalidOperationException("Invalid import binding.")
        };

    private Task<HttpRequestMessage> BuildValidationRequest(InfisicalValidationAddress address, InfisicalNativeOperation operation,
        HttpContent? content, CancellationToken cancellationToken)
    {
        if (operation.Method == HttpMethod.Get && operation.Kind == InfisicalNativeOperationKind.ListValidationRules)
        {
            return ValidationWire.ListAllAsync(address.ProjectId, cancellationToken);
        }
        if (operation.Kind != InfisicalNativeOperationKind.Standard)
        {
            throw new InvalidOperationException("Invalid validation binding.");
        }
        return (address.Kind, operation.Method.Method, address.RuleId is null) switch
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

}
