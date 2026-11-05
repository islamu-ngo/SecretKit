namespace SecretKit.Infisical;

internal enum InfisicalNativeOperationKind
{
    Standard,
    RestoreEnvironment,
    ListFolders,
    MoveFolder,
    UpdateFolders,
    ReadImportedSecrets,
    ListValidationRules
}

internal readonly record struct InfisicalNativeOperation(
    HttpMethod Method,
    InfisicalNativeOperationKind Kind = InfisicalNativeOperationKind.Standard,
    bool HardDelete = false,
    bool Recursive = false,
    DateTimeOffset? LastSecretModified = null);
