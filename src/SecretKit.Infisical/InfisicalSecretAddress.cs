using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

public enum InfisicalResolution
{
    Raw,
    ExpandedReferences
}

/// <summary>Native v4 coordinates; expansion and import lookup are explicit provider operations.</summary>
public sealed class InfisicalSecretAddress : SecretAddress
{
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

    [JsonIgnore]
    public string ProjectId { get; }
    [JsonIgnore]
    public string Environment { get; }
    [JsonIgnore]
    public string Folder { get; }
    [JsonIgnore]
    public string Key { get; }
    [JsonIgnore]
    public int? Version { get; }
    [JsonIgnore]
    public InfisicalResolution Resolution { get; }
    [JsonIgnore]
    public bool IncludeImports { get; }
}

/// <summary>Direct-folder metadata inventory without recursion, reference expansion or acquisition.</summary>
public sealed class InfisicalInventoryScope : SecretInventoryScope
{
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

    [JsonIgnore]
    public string ProjectId { get; }
    [JsonIgnore]
    public string Environment { get; }
    [JsonIgnore]
    public string Folder { get; }
    [JsonIgnore]
    public int MaximumItems { get; }
}
