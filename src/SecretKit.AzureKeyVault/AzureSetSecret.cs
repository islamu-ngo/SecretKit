using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

public enum AzureSetSecretPrecondition
{
    None,
    CreateOnly,
    MatchVersion
}

/// <summary>
/// A selected native version-creating write. Material remains caller-owned.
/// Mandatory create-only and version-match conditions are unsupported by SetSecret.
/// </summary>
public sealed class AzureSetSecretRequest
{
    public AzureSetSecretRequest(SecretReference target, SecretMaterial material,
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        Target = target;
        Material = material;
        Precondition = precondition;
    }

    [JsonIgnore]
    public SecretReference Target { get; }

    [JsonIgnore]
    public SecretMaterial Material { get; }

    [JsonIgnore]
    public AzureSetSecretPrecondition Precondition { get; }

    public override string ToString() => "[AzureSetSecretRequest]";
}

/// <summary>Validated address of the newly created version, not a cross-provider transaction.</summary>
public sealed class AzureSetSecretResult
{
    internal AzureSetSecretResult(SecretReference reference) => Reference = reference;

    [JsonIgnore]
    public SecretReference Reference { get; }

    public override string ToString() => "[AzureSetSecretResult]";
}
