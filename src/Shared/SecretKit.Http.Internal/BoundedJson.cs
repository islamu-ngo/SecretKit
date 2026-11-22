using System.Buffers;
using System.Security.Cryptography;
using System.Text.Json;

namespace SecretKit.Internal;

internal static class BoundedJson
{
    internal static async ValueTask<JsonDocument?> ReadJsonAsync(
        HttpResponseMessage response,
        int maximumBytes,
        int maxDepth,
        bool allowDuplicateProperties = false,
        Func<int, bool>? onChunkRead = null,
        CancellationToken cancellationToken = default)
    {
        // Accounting callbacks observe actual wire bytes, including the overflow byte.
        if (onChunkRead is null && response.Content.Headers.ContentLength > maximumBytes)
            return null;

        int initialCapacity = response.Content.Headers.ContentLength is { } contentLength and > 0
            ? (int)Math.Min(maximumBytes, contentLength) + 1
            : Math.Min(maximumBytes + 1, 8192);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(initialCapacity);
        int length = 0;
        try
        {
            Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            await using var bodyDisposal = body.ConfigureAwait(false);
            while (true)
            {
                if (length >= buffer.Length)
                {
                    if (length > maximumBytes)
                        return null;
                    int grownCapacity = Math.Min(maximumBytes + 1,
                        Math.Max(buffer.Length * 2, buffer.Length + 8192));
                    if (grownCapacity <= buffer.Length)
                        return null;
                    byte[] grown = ArrayPool<byte>.Shared.Rent(grownCapacity);
                    buffer.AsSpan(0, length).CopyTo(grown);
                    CryptographicOperations.ZeroMemory(buffer);
                    ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
                    buffer = grown;
                }

                int writable = Math.Min(buffer.Length - length, maximumBytes + 1 - length);
                int read = await body.ReadAsync(buffer.AsMemory(length, writable), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                    break;
                length += read;
                if (onChunkRead is not null && !onChunkRead(read))
                    return null;
                cancellationToken.ThrowIfCancellationRequested();
                if (length > maximumBytes)
                    return null;
            }

            // JsonDocument.Parse(Stream) copies the payload into JsonDocument's owned buffer so
            // the pooled transport read buffer can be zeroed and returned before this method exits.
            using var input = new MemoryStream(buffer, 0, length, writable: false);
            return JsonDocument.Parse(input, new JsonDocumentOptions
            {
                MaxDepth = maxDepth,
                AllowDuplicateProperties = allowDuplicateProperties
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer, clearArray: false);
        }
    }

    // Fixed-capacity output bounds the encoded body while writing. Empty is the
    // internal overflow marker: every admitted native body is a JSON object.
    internal static byte[] Serialize(Action<Utf8JsonWriter> write, int maximum)
    {
        using var buffer = new BoundedRequestBuffer(maximum);
        try
        {
            using (var writer = new Utf8JsonWriter(buffer)) write(writer);
            return buffer.ToArray();
        }
        catch (NotSupportedException) { return []; }
    }
}
