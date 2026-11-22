using System.Globalization;
using System.Net;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Internal;

namespace SecretKit.Infisical;

internal static class InfisicalFailureResponse
{
    internal static ValueTask<SecretOutcome<T>> ReadAsync<T>(HttpResponseMessage response,
        int maximumBytes, TimeProvider time, SecretStatus status, bool resource = true,
        Action<int>? consumeBytes = null, CancellationToken cancellationToken = default) where T : notnull =>
        HttpFailureResponse.ReadAsync<T>(response, maximumBytes, time, status,
            InfisicalErrorResponse.Project<T>, resource, consumeBytes, cancellationToken);
}

/// <summary>Projects an Infisical error body into closed failure metadata without retaining its message or details.</summary>
public static class InfisicalErrorResponse
{
    /// <summary>Enriches an already selected HTTP failure with an admitted reason, retry advice and protected correlation ID.</summary>
    /// <remarks>The caller owns and bounds the JSON body and selects the HTTP failure status.
    /// Invalid or mismatched error envelopes retain the supplied fallback. This method performs no I/O,
    /// retains no JSON, and never exposes native messages or details. Correlation remains explicitly protected.</remarks>
    public static SecretOutcome<T> Project<T>(JsonElement root, HttpStatusCode statusCode,
        SecretOutcome<T> fallback) where T : notnull
    {
        ArgumentNullException.ThrowIfNull(fallback);
        if (fallback.IsSuccess) throw new ArgumentException("An HTTP failure fallback is required.", nameof(fallback));
        if (root.ValueKind != JsonValueKind.Object) return fallback;
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in root.EnumerateObject())
        {
            if (!names.Add(property.Name)) return fallback;
            bool invalid = property.Name switch
            {
                "reqId" or "error" => property.Value.ValueKind != JsonValueKind.String,
                "statusCode" => property.Value.ValueKind != JsonValueKind.Number ||
                    !property.Value.TryGetInt32(out int code) || code != (int)statusCode,
                "message" => property.Value.ValueKind is not (JsonValueKind.String or JsonValueKind.Array),
                _ => false
            };
            if (invalid) return fallback;
        }
        string? error = root.TryGetProperty("error", out JsonElement errorField) ? errorField.GetString() : null;
        if (root.TryGetProperty("message", out JsonElement messageShape) &&
            messageShape.ValueKind == JsonValueKind.Array &&
            (error != "ValidationFailure" || (int)statusCode != 422))
            return fallback;
        SecretFailureReason reason = ((int)statusCode, error) switch
        {
            (400, "BadRequest") or (422, "ValidationFailure") => SecretFailureReason.ValidationFailed,
            (401, "UnauthorizedError") => SecretFailureReason.AuthenticationRejected,
            (403, "PermissionDenied" or "ForbiddenError") => SecretFailureReason.PermissionDenied,
            _ => fallback.Reason
        };
        SecretCorrelationId? correlation = null;
        if (root.TryGetProperty("reqId", out JsonElement identifier))
        {
            _ = SecretCorrelationId.TryCreate(identifier.GetString(), out correlation);
        }
        TimeSpan? advice = fallback.RetryAfter;
        if (advice is null && fallback.Status == SecretStatus.Throttled &&
            statusCode == HttpStatusCode.TooManyRequests &&
            root.TryGetProperty("message", out JsonElement message) && message.ValueKind == JsonValueKind.String)
            advice = BodyAdvice(message.GetString()!);
        return SecretOutcome<T>.Failure(fallback.Status, advice, reason, correlation);
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
