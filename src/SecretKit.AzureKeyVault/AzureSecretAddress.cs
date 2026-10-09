using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

public sealed class AzureSecretAddress : SecretAddress
{
    public AzureSecretAddress(string name, string? version = null)
    {
        if (string.IsNullOrEmpty(name) || name.Length > 127 ||
            !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-'))
        {
            throw new ArgumentException("Invalid secret name.", nameof(name));
        }

        if (version is not null && (version.Length != 32 || !version.All(char.IsAsciiHexDigit)))
        {
            throw new ArgumentException("Invalid secret version.", nameof(version));
        }

        Name = name;
        Version = version;
    }

    [JsonIgnore]
    public string Name { get; }

    [JsonIgnore]
    public string? Version { get; }
}

/// <summary>Bounded latest-version metadata collection, not a remote snapshot.</summary>
public sealed class AzureInventoryScope : SecretInventoryScope
{
    public AzureInventoryScope(SecretAuthority authority, int maximumPages = 10, int maximumItems = 1000)
        : base(authority)
    {
        if (maximumPages is < 1 or > 1000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumPages));
        }

        if (maximumItems is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumItems));
        }

        MaximumPages = maximumPages;
        MaximumItems = maximumItems;
    }

    [JsonIgnore]
    public int MaximumPages { get; }

    [JsonIgnore]
    public int MaximumItems { get; }
}
