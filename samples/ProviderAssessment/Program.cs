using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;

// Offline demonstration only. Hosts inject their own separately authenticated clients.
var admin = new DemonstrationInventory();
var intended = new DemonstrationReader();
var scenario = new AssessmentScenario(admin, intended);
var scope = new InfisicalInventoryScope(admin.Authority, "demo-project", "demo", "/");
FeatureRequirement[] features =
[
    new("optional-integration", false,
    [
        new("credential", new SecretReference(intended.Authority,
            new InfisicalSecretAddress("demo-project", "demo", "/", "demo-key",
                resolution: InfisicalResolution.Raw, includeImports: false)), DeliveryKind.Direct)
    ])
];
var json = new JsonSerializerOptions { WriteIndented = true };
json.Converters.Add(new JsonStringEnumConverter());

Console.WriteLine("Offline controlled identities: administrator visibility does not prove delivery.");
Console.WriteLine(JsonSerializer.Serialize(await scenario.CheckAsync(scope, features), json));
intended.Available = true; // Simulates an operator provisioning outside this read-only workflow.
Console.WriteLine("Check again: fresh intended-identity evidence, without activating a business integration.");
Console.WriteLine(JsonSerializer.Serialize(await scenario.CheckAsync(scope, features), json));

internal sealed class DemonstrationInventory : ISecretInventory
{
    public SecretAuthority Authority { get; } = new();

    public ValueTask<SecretOutcome<SecretInventory>> InspectAsync(SecretInventoryScope scope,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var reference = new SecretReference(Authority,
            new InfisicalSecretAddress("demo-project", "demo", "/", "demo-key"));
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return ValueTask.FromResult(SecretOutcome<SecretInventory>.Success(
            new([new(reference, null, now, SecretValidity.Unknown)], now, now, complete: true)));
    }
}

internal sealed class DemonstrationReader : ISecretReader
{
    public SecretAuthority Authority { get; } = new();
    public bool Available { get; set; }

    public ValueTask<SecretOutcome<SecretRead>> ReadAsync(SecretReference reference,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!reference.BelongsTo(Authority))
        {
            return ValueTask.FromResult(SecretOutcome<SecretRead>.Failure(SecretStatus.Invalid));
        }

        return ValueTask.FromResult(Available
            ? SecretOutcome<SecretRead>.Success(new(SecretMaterial.FromText(Guid.NewGuid().ToString("N")),
                new(reference, null, DateTimeOffset.UtcNow, SecretValidity.Valid)))
            : SecretOutcome<SecretRead>.Failure(SecretStatus.Absent));
    }
}
