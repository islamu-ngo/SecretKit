using SecretKit.Core;

namespace SecretKit.Infisical;

/// <summary>Reads and inventories secrets through one explicitly selected Infisical authority.</summary>
public interface IInfisicalSecretReader : ISecretReader, ISecretInventory;

/// <summary>Creates scopes without acquiring credentials or performing network I/O.</summary>
public static class InfisicalSecretReaderExtensions
{
    /// <summary>Binds reusable native coordinates to this reader; each read still acquires fresh material.</summary>
    public static InfisicalSecretScope CreateScope(this IInfisicalSecretReader reader,
        string projectId, string environment, string folder = "/") => new(reader, projectId, environment, folder);
}

/// <summary>Reusable native coordinates without a material cache or implicit identity selection.</summary>
public sealed class InfisicalSecretScope
{
    private readonly IInfisicalSecretReader _reader;
    private readonly InfisicalInventoryScope _scope;

    internal InfisicalSecretScope(IInfisicalSecretReader reader, string projectId, string environment, string folder)
    {
        ArgumentNullException.ThrowIfNull(reader);
        _reader = reader;
        _scope = new(reader.Authority, projectId, environment, folder);
    }

    /// <summary>Reads independently owned material; the caller disposes a successful read.</summary>
    public ValueTask<SecretOutcome<SecretRead>> ReadAsync(string key, CancellationToken cancellationToken = default) =>
        _reader.ReadAsync(Reference(key), cancellationToken);

    /// <summary>Reads a required secret or throws a coordinate-free classified failure.</summary>
    public ValueTask<SecretRead> GetSecretAsync(string key, CancellationToken cancellationToken = default) =>
        _reader.GetSecretAsync(Reference(key), cancellationToken);

    /// <summary>Returns null only for an absent secret; the caller disposes any returned read.</summary>
    public ValueTask<SecretRead?> TryGetSecretAsync(string key, CancellationToken cancellationToken = default) =>
        _reader.TryGetSecretAsync(Reference(key), cancellationToken);

    /// <summary>Finds value-free metadata in bounded direct-folder inventory without acquiring secret material.</summary>
    /// <remarks>A missing item in incomplete inventory remains Unknown. This does not establish value-read permission.</remarks>
    public async ValueTask<SecretOutcome<SecretObservation>> InspectAsync(string key, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        SecretReference reference = Reference(key);
        SecretOutcome<SecretInventory> outcome = await _reader.InspectAsync(_scope, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (!outcome.IsSuccess)
            return SecretOutcome<SecretObservation>.Failure(outcome.Status, outcome.RetryAfter, outcome.Reason);
        foreach (SecretObservation observation in outcome.Value.Items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!observation.Reference.BelongsTo(_reader.Authority) ||
                observation.Reference.Address is not InfisicalSecretAddress address ||
                address.ProjectId != _scope.ProjectId || address.Environment != _scope.Environment || address.Folder != _scope.Folder)
                return SecretOutcome<SecretObservation>.Failure(SecretStatus.Invalid, reason: SecretFailureReason.AuthorityMismatch);
            if (address.Key == key)
                return SecretOutcome<SecretObservation>.Success(new(reference, observation.Version,
                    observation.ObservedAt, observation.Validity, observation.ExpiresAt));
        }
        return SecretOutcome<SecretObservation>.Failure(outcome.Value.IsComplete ? SecretStatus.Absent : SecretStatus.Unknown);
    }

    private SecretReference Reference(string key) => new(_reader.Authority,
        new InfisicalSecretAddress(_scope.ProjectId, _scope.Environment, _scope.Folder, key));

    /// <summary>Returns a fixed marker without coordinates or authority details.</summary>
    public override string ToString() => "[InfisicalSecretScope]";
}
