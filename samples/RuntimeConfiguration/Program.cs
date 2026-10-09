using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Samples.RuntimeConfiguration;

// The executable runs an offline workflow, not a database or a real secret provider.
var selected = new DemonstrationReader();
var required = new Dictionary<string, SecretReference>
{
    ["Database:Username"] = new(selected.Authority, new DemonstrationAddress()),
    ["Database:Password"] = new(selected.Authority, new DemonstrationAddress())
};
SecretOutcome<BootstrapCandidate> prepared = await BootstrapScenario.PrepareAsync(selected, required);
if (!prepared.IsSuccess)
{
    Console.WriteLine($"BOOTSTRAP_{prepared.Status}");
    return 1;
}

using BootstrapCandidate candidate = prepared.Value;
using SecretRead username = candidate.Read("Database:Username");
using SecretRead password = candidate.Read("Database:Password");
// A real consumer constructs its own database-dependent services here, after validation.
Console.WriteLine("BOOTSTRAP_PREPARED_OPTIONAL_INTEGRATION_DISABLED");
using var generations = new SecretSnapshotLoader(required.Select(binding =>
    new SecretSelection(binding.Key, selected, binding.Value)));
await generations.RefreshAsync();
using SecretSnapshotHandle logicalOperation = generations.Acquire();
using SecretRead oldUsername = logicalOperation.Read("Database:Username");
await generations.RefreshAsync();
using SecretRead oldPassword = logicalOperation.Read("Database:Password");
using SecretSnapshotHandle nextOperation = generations.Acquire();
Console.WriteLine($"LOGICAL_GENERATION_{logicalOperation.Generation}_NEXT_{nextOperation.Generation}_REMOTE_SNAPSHOT_{logicalOperation.RemoteSnapshotGuaranteed}");
return 0;

sealed class DemonstrationAddress : SecretAddress;

sealed class DemonstrationReader : ISecretReader
{
    public SecretAuthority Authority { get; } = new();

    public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(SecretOutcome<SecretRead>.Success(new SecretRead(
            SecretMaterial.FromText(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))),
            new SecretObservation(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid))));
    }
}
