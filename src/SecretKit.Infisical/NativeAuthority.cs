using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Protected native coordinates, never an endpoint selector.</summary>
public abstract class InfisicalNativeAddress : SecretAddress
{
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

    [JsonIgnore]
    public string ProjectId { get; }
    [JsonIgnore]
    public string? Environment { get; }
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

    [JsonIgnore]
    public IReadOnlyList<T> Items { get; }
    public bool IsComplete { get; }
    public override string ToString() => "[InfisicalNativeList]";
}
