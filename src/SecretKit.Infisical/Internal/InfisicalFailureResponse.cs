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
        byte[] bytes = new byte[maximumBytes + 1];
        try
        {
            if (response.Content.Headers.ContentLength > maximumBytes) return fallback;
            using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int count = await body.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                consumeBytes?.Invoke(count);
                cancellationToken.ThrowIfCancellationRequested();
                if (count == 0) break;
                length += count;
            }
            if (length > maximumBytes) return fallback;
            using JsonDocument document = JsonDocument.Parse(bytes.AsMemory(0, length),
                new JsonDocumentOptions { MaxDepth = 16, AllowDuplicateProperties = true });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return fallback;
            int seen = 0;
            foreach (JsonProperty property in root.EnumerateObject())
            {
                int bit = property.Name switch
                {
                    "reqId" => 1,
                    "statusCode" => 2,
                    "error" => 4,
                    "message" => 8,
                    "details" => 16,
                    _ => 0
                };
                if ((seen & bit) != 0) return fallback;
                seen |= bit;
                if (bit is 1 or 4 && property.Value.ValueKind != JsonValueKind.String ||
                    bit == 2 && (property.Value.ValueKind != JsonValueKind.Number ||
                        !property.Value.TryGetInt32(out int code) || code != (int)response.StatusCode) ||
                    bit == 8 && property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Array))
                    return fallback;
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
                string value = identifier.GetString()!;
                if (value.Length is >= 1 and <= 128 &&
                    value.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_' or '.'))
                    correlation = new(value);
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
        finally
        {
            Array.Clear(bytes);
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
