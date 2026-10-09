namespace SecretKit.Core;

/// <summary>Reads only the selected authority. There is no implicit cache or fallback.</summary>
public interface ISecretReader
{
    SecretAuthority Authority { get; }

    ValueTask<SecretOutcome<SecretRead>> ReadAsync(
        SecretReference reference, CancellationToken cancellationToken = default);
}
