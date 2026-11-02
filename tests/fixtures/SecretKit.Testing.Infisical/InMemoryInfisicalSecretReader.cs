using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Testing.Infisical;

/// <summary>Matches complete native selectors; does not simulate imports or provider resolution.</summary>
public sealed class InMemoryInfisicalSecretReader(TimeProvider? clock = null)
    : InMemorySecretReader(clock), IInfisicalSecretReader
{
    public ValueTask<SecretOutcome<SecretInventory>> InspectAsync(SecretInventoryScope scope,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(scope);
        cancellationToken.ThrowIfCancellationRequested();
        if (scope is not InfisicalInventoryScope native)
            return ValueTask.FromResult(SecretOutcome<SecretInventory>.Failure(SecretStatus.Invalid));
        return InspectCollection(scope, address => address is InfisicalSecretAddress item &&
            item.ProjectId == native.ProjectId && item.Environment == native.Environment &&
            item.Folder == native.Folder && item.Version is null &&
            item.Resolution == InfisicalResolution.Raw && !item.IncludeImports,
            native.MaximumItems, cancellationToken);
    }

    protected override object? SelectKey(SecretAddress address) => address is InfisicalSecretAddress native
        ? (native.ProjectId, native.Environment, native.Folder, native.Key,
            native.Version, native.Resolution, native.IncludeImports)
        : null;
}
