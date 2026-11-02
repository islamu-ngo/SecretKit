using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault;

/// <summary>A validated secret name and optional exact version within a separately selected vault.</summary>
public sealed class AzureSecretAddress : SecretAddress
{
    /// <summary>Creates coordinates without selecting credentials or performing I/O.</summary>
    /// <param name="name">A 1–127 character Azure secret name containing ASCII letters, digits or hyphens.</param>
    /// <param name="version">A 32-character hexadecimal version, or null to select the current version.</param>
    /// <exception cref="ArgumentException">The name or version has an invalid native shape.</exception>
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

    /// <summary>Gets the protected native secret name, omitted from default JSON serialization.</summary>
    [JsonIgnore]
    public string Name { get; }

    /// <summary>Gets the exact native version, or null for the current version.</summary>
    [JsonIgnore]
    public string? Version { get; }
}

/// <summary>Bounded latest-version metadata collection, not a remote snapshot.</summary>
public sealed class AzureInventoryScope : SecretInventoryScope
{
    /// <summary>Sets local page/item bounds for metadata collection under one client's authority.</summary>
    /// <param name="authority">The authority of the client that will perform collection.</param>
    /// <param name="maximumPages">The maximum number of pages, from 1 through 1000.</param>
    /// <param name="maximumItems">The maximum number of items, from 1 through 10000.</param>
    /// <exception cref="ArgumentOutOfRangeException">A collection bound is outside its supported range.</exception>
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

    /// <summary>Gets the local page limit; exhausting it does not establish remote completeness.</summary>
    [JsonIgnore]
    public int MaximumPages { get; }

    /// <summary>Gets the local item limit for the returned collection.</summary>
    [JsonIgnore]
    public int MaximumItems { get; }
}
