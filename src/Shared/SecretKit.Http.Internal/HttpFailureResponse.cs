using System.Net;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Internal;

internal static class HttpFailureResponse
{
    internal static TimeSpan? RetryAfter(HttpResponseMessage response, TimeProvider time)
    {
        if (response.StatusCode is not (HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable))
            return null;
        TimeSpan? advice = response.Headers.RetryAfter?.Delta;
        if (advice is null && response.Headers.RetryAfter?.Date is { } date)
            advice = date - time.GetUtcNow();
        return advice is { } value ? TimeSpan.FromTicks(Math.Clamp(value.Ticks, 0, TimeSpan.FromDays(1).Ticks)) : null;
    }

    internal static async ValueTask<SecretOutcome<T>> ReadAsync<T>(HttpResponseMessage response,
        int maximumBytes, TimeProvider time, SecretStatus status,
        Func<JsonElement, HttpStatusCode, SecretOutcome<T>, SecretOutcome<T>> project,
        bool resource = true, Action<int>? consumeBytes = null, CancellationToken cancellationToken = default) where T : notnull
    {
        SecretFailureReason reason = resource && response.StatusCode == HttpStatusCode.NotFound
            ? SecretFailureReason.NotFoundOrInaccessible : SecretFailureReason.None;
        TimeSpan? advice = status is SecretStatus.Throttled or SecretStatus.Unavailable
            ? RetryAfter(response, time) : null;
        SecretOutcome<T> fallback = SecretOutcome<T>.Failure(status, advice, reason);
        if (response.IsSuccessStatusCode) return fallback;
        try
        {
            using JsonDocument? document = await BoundedJson.ReadJsonAsync(
                response, maximumBytes, 16, allowDuplicateProperties: false,
                onChunkRead: consumeBytes is null ? null : chunk =>
                {
                    consumeBytes(chunk);
                    return true;
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);
            if (document is null) return fallback;
            SecretOutcome<T> projected = project(document.RootElement, response.StatusCode, fallback);
            cancellationToken.ThrowIfCancellationRequested();
            return projected;
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
}
