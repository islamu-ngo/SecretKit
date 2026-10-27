using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Protected native coordinates, never an endpoint selector.</summary>
public abstract class InfisicalNativeAddress : SecretAddress
{
    /// <summary>Validates protected project and optional environment/folder coordinates without granting authority.</summary>
    protected InfisicalNativeAddress(string projectId, string? environment = null, string? folder = null)
    {
        NativeText(projectId);
        if (environment is not null)
        {
            NativeText(environment);
        }
        if (folder is not null)
        {
            NativeFolder(folder);
        }
        ProjectId = projectId;
        Environment = environment;
        Folder = folder;
    }

    /// <summary>The protected project identifier.</summary>
    [JsonIgnore]
    public string ProjectId { get; }
    /// <summary>The selected environment, or null for project-wide coordinates.</summary>
    [JsonIgnore]
    public string? Environment { get; }
    /// <summary>The absolute folder, or null when no folder is selected.</summary>
    [JsonIgnore]
    public string? Folder { get; }

    internal static void NativeText(string value, int maximumLength = 1024)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength ||
            value is "." or ".." || value.Any(char.IsControl))
        {
            throw new ArgumentException("Invalid protected native input.");
        }
    }

    internal static void NativeFolder(string value)
    {
        NativeText(value);
        if (!value.StartsWith('/') || value.Split('/').Any(part => part is "." or ".."))
        {
            throw new ArgumentException("An absolute native folder is required.");
        }
    }
}

/// <summary>
/// Host-selected administrative credentials and exact local scope. This selection does not
/// grant server permissions. The token source remains host-owned.
/// </summary>
public sealed class InfisicalNativeAuthority
{
    private readonly SecretAuthority _clientAuthority;
    internal IInfisicalTokenSource Tokens { get; }
    private readonly string _project;
    private readonly string? _environment;
    private readonly string? _folder;

    /// <summary>Binds a borrowed token source to the exact client authority and explicitly selected local scope.</summary>
    /// <remarks>A folder requires an environment. Selection never grants server permission or supplies a fallback identity.</remarks>
    public InfisicalNativeAuthority(SecretAuthority clientAuthority, IInfisicalTokenSource tokens,
        string projectId, string? environment = null, string? folder = null)
    {
        ArgumentNullException.ThrowIfNull(clientAuthority);
        ArgumentNullException.ThrowIfNull(tokens);
        InfisicalNativeAddress.NativeText(projectId);
        if (environment is not null)
        {
            InfisicalNativeAddress.NativeText(environment);
        }
        if (folder is not null)
        {
            InfisicalNativeAddress.NativeFolder(folder);
            if (environment is null)
            {
                throw new ArgumentException("A folder requires an environment.");
            }
        }
        _clientAuthority = clientAuthority;
        Tokens = tokens;
        _project = projectId;
        _environment = environment;
        _folder = folder;
    }

    internal bool Matches(SecretAuthority clientAuthority, InfisicalNativeAddress address) =>
        ReferenceEquals(_clientAuthority, clientAuthority) && _project == address.ProjectId &&
        (_environment is null || _environment == address.Environment) &&
        (_folder is null || _folder == address.Folder);

    /// <summary>Returns a fixed label without identity or scope details.</summary>
    public override string ToString() => "[InfisicalNativeAuthority]";
}

/// <summary>A bounded observation, not a transactional provider snapshot.</summary>
public sealed class InfisicalNativeList<T> where T : notnull
{
    internal InfisicalNativeList(IEnumerable<T> items, bool complete)
    {
        Items = Array.AsReadOnly(items.ToArray());
        IsComplete = complete;
    }

    /// <summary>A read-only snapshot of observed items, not a provider transaction.</summary>
    [JsonIgnore]
    public IReadOnlyList<T> Items { get; }
    /// <summary>Whether the response fit the observation's local item budget.</summary>
    public bool IsComplete { get; }
    /// <summary>Returns a fixed label without item contents.</summary>
    public override string ToString() => "[InfisicalNativeList]";
}
