using System.Globalization;
using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical;

internal static class InfisicalFailureResponse
{
    internal static async ValueTask<SecretOutcome<T>> ReadAsync<T>(HttpResponseMessage response,
        int maximumBytes, TimeProvider time, SecretStatus status, bool resource = true,
        Action<int>? consumeBytes = null, CancellationToken cancellationToken = default) where T : notnull
    {
        SecretFailureReason reason = resource && response.StatusCode == HttpStatusCode.NotFound
            ? SecretFailureReason.NotFoundOrInaccessible : SecretFailureReason.None;
        TimeSpan? advice = status is SecretStatus.Throttled or SecretStatus.Unavailable
            ? InfisicalOperationBudget.RetryAfter(response, time) : null;
        SecretOutcome<T> fallback = SecretOutcome<T>.Failure(status, advice, reason);
        if (response.IsSuccessStatusCode) return fallback;
        try
        {
            using JsonDocument? document = await InfisicalOperationBudget.ReadJsonAsync(
                response, maximumBytes, 16, allowDuplicateProperties: false,
                onChunkRead: consumeBytes is null ? null : chunk =>
                {
                    consumeBytes(chunk);
                    return true;
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (document is null) return fallback;
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return fallback;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                bool invalid = property.Name switch
                {
                    "reqId" or "error" => property.Value.ValueKind != JsonValueKind.String,
                    "statusCode" => property.Value.ValueKind != JsonValueKind.Number ||
                        !property.Value.TryGetInt32(out int code) || code != (int)response.StatusCode,
                    "message" => property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Array),
                    _ => false
                };
                if (invalid) return fallback;
            }
            string? error = root.TryGetProperty("error", out JsonElement errorField) ? errorField.GetString() : null;
            if (root.TryGetProperty("message", out JsonElement messageShape) &&
                messageShape.ValueKind == JsonValueKind.Array &&
                (error != "ValidationFailure" || (int)response.StatusCode != 422))
                return fallback;
            reason = ((int)response.StatusCode, error) switch
            {
                (400, "BadRequest") or (422, "ValidationFailure") => SecretFailureReason.ValidationFailed,
                (401, "UnauthorizedError") => SecretFailureReason.AuthenticationRejected,
                (403, "PermissionDenied" or "ForbiddenError") => SecretFailureReason.PermissionDenied,
                _ => reason
            };
            SecretCorrelationId? correlation = null;
            if (root.TryGetProperty("reqId", out JsonElement identifier))
            {
                _ = SecretCorrelationId.TryCreate(identifier.GetString(), out correlation);
            }
            if (advice is null && status == SecretStatus.Throttled &&
                response.StatusCode == HttpStatusCode.TooManyRequests &&
                root.TryGetProperty("message", out JsonElement message) && message.ValueKind == JsonValueKind.String)
                advice = BodyAdvice(message.GetString()!);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretOutcome<T>.Failure(status, advice, reason, correlation);
        }
        catch (OperationCanceledException)
        {
            // Detail is optional. The operation owner still enforces caller and
            // shutdown cancellation; an elapsed detail budget cannot erase HTTP evidence.
            return fallback;
        }
        catch (Exception error) when (error is JsonException or HttpRequestException or IOException or
            InvalidOperationException or NotSupportedException)
        {
            return fallback;
        }
    }

    private static TimeSpan? BodyAdvice(string message)
    {
        const string prefix = "Rate limit exceeded. Please try again in ";
        const string suffix = " seconds";
        if (!message.StartsWith(prefix, StringComparison.Ordinal) ||
            !message.EndsWith(suffix, StringComparison.Ordinal)) return null;
        ReadOnlySpan<char> number = message.AsSpan(prefix.Length, message.Length - prefix.Length - suffix.Length);
        if (number.IsEmpty || !long.TryParse(number, NumberStyles.None, CultureInfo.InvariantCulture, out long seconds))
            return null;
        return TimeSpan.FromSeconds(Math.Min(seconds, 86400));
    }
}
