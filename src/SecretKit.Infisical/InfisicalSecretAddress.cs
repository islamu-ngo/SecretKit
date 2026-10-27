using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Selects whether native reads expand referenced values.</summary>
public enum InfisicalResolution
{
    /// <summary>Read the stored value without reference expansion.</summary>
    Raw,
    /// <summary>Ask the provider to expand references; no resource-only revision is implied.</summary>
    ExpandedReferences
}

/// <summary>Native v4 coordinates; expansion and import lookup are explicit provider operations.</summary>
public sealed class InfisicalSecretAddress : SecretAddress
{
    /// <summary>Selects protected native coordinates, optional positive version and explicit expansion/import behavior.</summary>
    public InfisicalSecretAddress(string projectId, string environment, string folder, string key,
        int? version = null, InfisicalResolution resolution = InfisicalResolution.Raw,
        bool includeImports = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        if (!folder.StartsWith('/') || folder.Split('/').Any(part => part is "." or ".."))
        {
            throw new ArgumentException("An absolute provider folder is required.", nameof(folder));
        }

        if (key is "." or ".." || version is <= 0 || !Enum.IsDefined(resolution))
        {
            throw new ArgumentException("Invalid native secret selector.");
        }

        ProjectId = projectId;
        Environment = environment;
        Folder = folder;
        Key = key;
        Version = version;
        Resolution = resolution;
        IncludeImports = includeImports;
    }

    /// <summary>The selected project identifier; do not include it in diagnostics.</summary>
    [JsonIgnore]
    public string ProjectId { get; }
    /// <summary>The selected environment slug.</summary>
    [JsonIgnore]
    public string Environment { get; }
    /// <summary>The absolute provider folder without traversal segments.</summary>
    [JsonIgnore]
    public string Folder { get; }
    /// <summary>The protected secret key, not an endpoint selector.</summary>
    [JsonIgnore]
    public string Key { get; }
    /// <summary>The requested positive version, or null for the current version.</summary>
    [JsonIgnore]
    public int? Version { get; }
    /// <summary>The explicit raw or expanded-reference read selection.</summary>
    [JsonIgnore]
    public InfisicalResolution Resolution { get; }
    /// <summary>Whether the provider may resolve imported secrets for this read.</summary>
    [JsonIgnore]
    public bool IncludeImports { get; }
}

/// <summary>Direct-folder metadata inventory without recursion, reference expansion or acquisition.</summary>
public sealed class InfisicalInventoryScope : SecretInventoryScope
{
    /// <summary>Binds a direct-folder inventory to the exact client authority and a 1..10,000 item budget.</summary>
    public InfisicalInventoryScope(SecretAuthority authority, string projectId, string environment,
        string folder, int maximumItems = 1000) : base(authority)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(environment);
        ArgumentException.ThrowIfNullOrWhiteSpace(folder);
        if (!folder.StartsWith('/') || folder.Split('/').Any(part => part is "." or ".."))
        {
            throw new ArgumentException("An absolute provider folder is required.", nameof(folder));
        }

        if (maximumItems is < 1 or > 10000)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumItems));
        }

        ProjectId = projectId;
        Environment = environment;
        Folder = folder;
        MaximumItems = maximumItems;
    }

    /// <summary>The protected project identifier.</summary>
    [JsonIgnore]
    public string ProjectId { get; }
    /// <summary>The selected environment slug.</summary>
    [JsonIgnore]
    public string Environment { get; }
    /// <summary>The absolute direct-folder path; inventory does not recurse.</summary>
    [JsonIgnore]
    public string Folder { get; }
    /// <summary>The local item limit; truncation is reported by the inventory's completeness evidence.</summary>
    [JsonIgnore]
    public int MaximumItems { get; }
}
