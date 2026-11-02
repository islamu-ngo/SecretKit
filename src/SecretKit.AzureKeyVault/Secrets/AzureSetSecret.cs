using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

/// <summary>Requested write conditions; native SetSecret, property update and restore support only None.</summary>
public enum AzureSetSecretPrecondition
{
    /// <summary>Do not require conditional creation or version matching.</summary>
    None,
    /// <summary>Require absence; the adapter rejects this unsupported condition before dispatch.</summary>
    CreateOnly,
    /// <summary>Require a matching current version; the adapter rejects this unsupported condition before dispatch.</summary>
    MatchVersion
}

/// <summary>
/// A selected native version-creating write. Material remains caller-owned.
/// Mandatory create-only and version-match conditions are unsupported by SetSecret.
/// </summary>
public sealed class AzureSetSecretRequest
{
    /// <summary>Describes a version-creating write without copying or taking ownership of material.</summary>
    /// <param name="target">The owning client's unversioned secret reference.</param>
    /// <param name="material">Caller-owned material that must remain usable until the operation completes.</param>
    /// <param name="precondition">The requested condition; only None is supported by execution.</param>
    /// <exception cref="ArgumentNullException">The target or material is null.</exception>
    public AzureSetSecretRequest(SecretReference target, SecretMaterial material,
        AzureSetSecretPrecondition precondition = AzureSetSecretPrecondition.None)
    {
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(material);
        Target = target;
        Material = material;
        Precondition = precondition;
    }

    /// <summary>Gets the protected unversioned write target.</summary>
    [JsonIgnore]
    public SecretReference Target { get; }

    /// <summary>Gets borrowed material; the request does not dispose it.</summary>
    [JsonIgnore]
    public SecretMaterial Material { get; }

    /// <summary>Gets the caller's required write condition.</summary>
    [JsonIgnore]
    public AzureSetSecretPrecondition Precondition { get; }

    /// <summary>Returns a marker without the target or material.</summary>
    public override string ToString() => "[AzureSetSecretRequest]";
}

/// <summary>Validated address of the newly created version, not a cross-provider transaction.</summary>
public sealed class AzureSetSecretResult
{
    internal AzureSetSecretResult(SecretReference reference) => Reference = reference;

    /// <summary>Gets the authority-bound reference to the version established by the response.</summary>
    [JsonIgnore]
    public SecretReference Reference { get; }

    /// <summary>Returns a marker without the created version's coordinates.</summary>
    public override string ToString() => "[AzureSetSecretResult]";
}
