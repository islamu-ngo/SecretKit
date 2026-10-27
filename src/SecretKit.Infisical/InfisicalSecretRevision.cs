using System.Text.Json.Serialization;

namespace SecretKit.Infisical;

/// <summary>
/// Equality of one raw, non-imported resource version within its trusted namespace.
/// This is not a revision of expanded references or a grant of client authority.
/// </summary>
public sealed class InfisicalSecretRevision : IEquatable<InfisicalSecretRevision>
{
    private readonly Uri _origin;
    private readonly string _project;
    private readonly string _environment;
    private readonly string _folder;
    private readonly string _resource;

    internal InfisicalSecretRevision(Uri origin, string project, string environment,
        string folder, string resource, int version)
    {
        _origin = origin;
        _project = project;
        _environment = environment;
        _folder = folder;
        _resource = resource;
        Version = version;
    }

    /// <summary>The positive native version observed for this raw resource.</summary>
    [JsonIgnore]
    public int Version { get; }

    /// <summary>Compares origin, project, environment, folder, resource identity and version.</summary>
    public bool Equals(InfisicalSecretRevision? other) =>
        other is not null && _origin == other._origin && _project == other._project &&
        _environment == other._environment && _folder == other._folder &&
        _resource == other._resource && Version == other.Version;

    /// <summary>Compares a qualified revision, returning false for other types.</summary>
    public override bool Equals(object? obj) => obj is InfisicalSecretRevision other && Equals(other);
    /// <summary>Hashes the qualified resource coordinates and version; not a material digest.</summary>
    public override int GetHashCode() => HashCode.Combine(_origin, _project, _environment, _folder, _resource, Version);
    /// <summary>Tests qualified revision equality, including null equality.</summary>
    public static bool operator ==(InfisicalSecretRevision? left, InfisicalSecretRevision? right) =>
        Equals(left, right);
    /// <summary>Tests qualified revision inequality.</summary>
    public static bool operator !=(InfisicalSecretRevision? left, InfisicalSecretRevision? right) =>
        !Equals(left, right);
    /// <summary>Returns a fixed label without protected resource coordinates.</summary>
    public override string ToString() => "[InfisicalSecretRevision]";
}
