using System.Buffers;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.Infisical;

internal sealed class InfisicalOperationBudget(TimeSpan timeout, TimeProvider time, CancellationToken caller,
    CancellationToken shutdown = default) : OperationBudget(timeout, time, caller, shutdown)
{
    internal static readonly SearchValues<char> ControlCharacters =
        SearchValues.Create(Enumerable.Range(0, 0x20).Concat(Enumerable.Range(0x7F, 0x21)).Select(static c => (char)c).ToArray());

    internal static readonly SearchValues<char> VisibleAsciiCharacters =
        SearchValues.Create(Enumerable.Range(0x21, 0x7E - 0x21 + 1).Select(static c => (char)c).ToArray());
    internal static ValueTask<JsonDocument?> ReadJsonAsync(HttpResponseMessage response, int maximumBytes,
        int maxDepth, bool allowDuplicateProperties = false, Func<int, bool>? onChunkRead = null,
        CancellationToken cancellationToken = default) =>
        BoundedJson.ReadJsonAsync(response, maximumBytes, maxDepth, allowDuplicateProperties, onChunkRead, cancellationToken);

    internal static byte[] Serialize(Action<Utf8JsonWriter> write, int maximum) => BoundedJson.Serialize(write, maximum);

    internal static byte[]? SerializeAccessToken(SecretMaterial token, int maximum) =>
        token.Use(maximum, static (chars, limit) =>
        {
            if (chars.Length is < 1 or > 16384 || chars.ContainsAny(ControlCharacters))
                return null;
            using var buffer = new BoundedRequestBuffer(limit);
            try
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("accessToken", chars);
                    writer.WriteEndObject();
                }
                return buffer.ToArray();
            }
            catch (NotSupportedException) { return []; }
        });

    internal static byte[] SerializeUniversalLogin(string clientId, SecretMaterial clientSecret,
        string? organizationSlug, int maximum) =>
        clientSecret.Use((clientId, organizationSlug, maximum), static (chars, state) =>
        {
            if (chars.Length is < 1 or > 16384 || chars.ContainsAny(ControlCharacters))
                throw new ArgumentException("Invalid bootstrap credential.");
            using var buffer = new BoundedRequestBuffer(state.maximum);
            try
            {
                using (var writer = new Utf8JsonWriter(buffer))
                {
                    writer.WriteStartObject();
                    writer.WriteString("clientId", state.clientId);
                    writer.WriteString("clientSecret", chars);
                    if (state.organizationSlug is not null) writer.WriteString("organizationSlug", state.organizationSlug);
                    writer.WriteEndObject();
                }
                return buffer.ToArray();
            }
            catch (NotSupportedException) { return []; }
        });

    internal static void WriteStringIfNotNull(Utf8JsonWriter writer, string propertyName, string? value)
    {
        if (value is not null) writer.WriteString(propertyName, value);
    }

    internal static void WriteOptionalNumber(Utf8JsonWriter writer, string propertyName, double? value)
    {
        if (value is { } number) writer.WriteNumber(propertyName, number);
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1068", Justification = "Caller cancellation and adapter shutdown are distinct authorities; keeping the required caller token before optional evidence makes their precedence explicit.")]
    internal static ValueTask<SecretOutcome<T>> RunAsync<T>(TimeSpan timeout, TimeProvider time,
        CancellationToken caller, InfisicalOperation? operation,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> execute,
        Func<DispatchEvidence>? evidence = null, CancellationToken shutdown = default,
        OperationObservation? observation = null) where T : notnull =>
        RunWithBudgetAsync(timeout, time, operation, budget => execute(budget.Token), evidence, observation, shutdown, caller);

    internal static async ValueTask<SecretOutcome<T>> RunWithBudgetAsync<T>(TimeSpan timeout, TimeProvider time,
        InfisicalOperation? operation, Func<OperationBudget, ValueTask<SecretOutcome<T>>> execute,
        Func<DispatchEvidence>? evidence = null, OperationObservation? observation = null,
        CancellationToken shutdown = default, CancellationToken caller = default) where T : notnull
    {
        OperationDiagnosticStart? started = InfisicalDiagnostics.Capture(time);
        using var deferred = InfisicalDiagnostics.Defer();
        observation ??= new();
        try
        {
            return await OperationBudget.RunAsync(timeout, time, execute, observation, evidence, shutdown, caller)
                .ConfigureAwait(false);
        }
        finally
        {
            OperationDiagnosticInterval? interval = InfisicalDiagnostics.Complete(started, time);
            if (operation is { } selected && observation.Completion is { } completion)
            {
                // Leave a synchronous shutdown notification before listeners can join disposal.
                await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
                InfisicalDiagnostics.Emit(selected, completion, interval);
            }
        }
    }
}
