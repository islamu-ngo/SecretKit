using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Samples.Infisical;

internal sealed class WorkerInput(DemoInput connection, InfisicalTokenLifetimeEvidence lifetimeEvidence) : IDisposable
{
    private const int MaximumLifetimeSeconds = 315360000;
    private const int MaximumInputBytes = 65536;

    internal DemoInput Connection { get; } = connection;
    internal InfisicalTokenLifetimeEvidence LifetimeEvidence { get; } = lifetimeEvidence;

    internal static async Task<WorkerInput> ReadAsync(Stream source, CancellationToken cancellationToken)
    {
        byte[] frame = await DemoInputReader.ReadFrameAsync(source, MaximumInputBytes, cancellationToken) ??
            throw new ArgumentException("Missing input.");
        try
        {
            return DemoInputReader.Parse(frame, Parse);
        }
        finally
        {
            Array.Clear(frame);
        }
    }

    private static WorkerInput Parse(JsonElement input)
    {
        DemoInputReader.ValidateFields(input, "originalIssuedAt", "expiresAt", "lifetime",
            "maximumTtlSeconds", "periodSeconds");
        InfisicalTokenLifetime lifetime = DemoInputReader.Text(input, "lifetime", 16) switch
        {
            "finite" => InfisicalTokenLifetime.Finite,
            "periodic" => InfisicalTokenLifetime.Periodic,
            "unknown" => InfisicalTokenLifetime.Unknown,
            _ => throw new ArgumentException("Invalid lifetime.")
        };
        int maximum = input.GetProperty("maximumTtlSeconds").GetInt32();
        int? period = input.TryGetProperty("periodSeconds", out var selectedPeriod) ? selectedPeriod.GetInt32() : null;
        if (maximum is < 0 or > MaximumLifetimeSeconds || period is <= 0 or > MaximumLifetimeSeconds)
            throw new ArgumentException("Invalid lifetime.");
        var evidence = new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = input.GetProperty("originalIssuedAt").GetDateTimeOffset(),
            ExpiresAt = input.GetProperty("expiresAt").GetDateTimeOffset(),
            Lifetime = lifetime,
            ReportedMaximumTtl = TimeSpan.FromSeconds(maximum),
            Period = period is { } seconds ? TimeSpan.FromSeconds(seconds) : null
        };
        SecretMaterial? token = input.GetProperty("token").ValueKind == JsonValueKind.Null
            ? null : SecretMaterial.FromText(DemoInputReader.Text(input, "token", 16384));
        return new WorkerInput(DemoInput.Create(input, token), evidence);
    }

    public void Dispose() => Connection.Dispose();

    public override string ToString() => "[WorkerInput]";
}
