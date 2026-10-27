using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical;

public sealed partial class InfisicalProofAuthentication
{
    /// <summary>Creates single-dispatch revocation evidence bound to this authentication client.</summary>
    public InfisicalTokenRevocationReceipt CreateRevocationReceipt()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return new(this);
    }

    /// <summary>
    /// Revokes the explicitly supplied token through its native route. Success means
    /// provider acknowledgement, not an independently observed invalidation effect.
    /// No token source, fallback, renewal or replay is invoked.
    /// </summary>
    public async ValueTask<SecretStatus> RevokeTokenAsync(SecretMaterial token,
        InfisicalTokenRevocationReceipt receipt, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(receipt);
        cancellationToken.ThrowIfCancellationRequested();
        if (!ReferenceEquals(receipt.Owner, this) || receipt.Evidence != DispatchEvidence.NotDispatched)
            return SecretStatus.Invalid;
        char[] characters = token.ExportCharacters();
        byte[] payload = new byte[128 * 1024];
        byte[] bytes = new byte[_responseLimit + 1];
        try
        {
            if (characters.Length is < 1 or > 16384 || characters.Any(char.IsControl))
                return SecretStatus.Invalid;
            using var stream = new MemoryStream(payload, writable: true);
            using (var writer = new Utf8JsonWriter(stream))
            {
                writer.WriteStartObject();
                writer.WriteString("accessToken", characters.AsSpan());
                writer.WriteEndObject();
            }
            using var content = new ByteArrayContent(payload, 0, checked((int)stream.Position));
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var request = await _wire.RevokeTokenAsync(content, cancellationToken).ConfigureAwait(false);
            if (request.RequestUri is { IsAbsoluteUri: false } relative) request.RequestUri = new(_origin, relative);
            if (request.Method != HttpMethod.Post || request.RequestUri != new Uri(_origin, "/api/v1/auth/token/revoke"))
                return SecretStatus.Invalid;
            cancellationToken.ThrowIfCancellationRequested();
            if (!receipt.TryBeginDispatch()) return SecretStatus.Invalid;
            using var response = await _transport.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                SecretStatus status = response.StatusCode switch
                {
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                    HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                    HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                    _ => SecretStatus.Unknown
                };
                if (status != SecretStatus.Unknown) receipt.Record(DispatchEvidence.Rejected);
                return status;
            }
            if (response.Content.Headers.ContentLength > _responseLimit) return SecretStatus.Unknown;
            using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            int length = 0;
            while (length < bytes.Length)
            {
                int read = await body.ReadAsync(bytes.AsMemory(length), cancellationToken).ConfigureAwait(false);
                if (read == 0) break;
                length += read;
            }
            if (length > _responseLimit) return SecretStatus.Unknown;
            using var document = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
                !root.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.String)
                return SecretStatus.Unknown;
            receipt.Record(DispatchEvidence.Applied);
            cancellationToken.ThrowIfCancellationRequested();
            return SecretStatus.Success;
        }
        catch (OperationCanceledException) { throw new OperationCanceledException("Token revocation canceled.", cancellationToken); }
        catch (Exception error) when (error is HttpRequestException or IOException or JsonException or InvalidOperationException)
        {
            return SecretStatus.Unknown;
        }
        finally
        {
            Array.Clear(characters);
            Array.Clear(payload);
            Array.Clear(bytes);
        }
    }
}

/// <summary>Single-use dispatch evidence. No reconciliation or remote rollback is implied.</summary>
public sealed class InfisicalTokenRevocationReceipt
{
    internal InfisicalTokenRevocationReceipt(object owner) => Owner = owner;
    internal object Owner { get; }
    private int _evidence;
    /// <summary>Local dispatch or acknowledgement evidence; retain it after cancellation or transport loss.</summary>
    public DispatchEvidence Evidence => (DispatchEvidence)Volatile.Read(ref _evidence);
    internal bool TryBeginDispatch() => Interlocked.CompareExchange(ref _evidence,
        (int)DispatchEvidence.PossiblyDispatched, (int)DispatchEvidence.NotDispatched) == (int)DispatchEvidence.NotDispatched;
    internal void Record(DispatchEvidence evidence) => Volatile.Write(ref _evidence, (int)evidence);
    /// <summary>Returns evidence without token material.</summary>
    public override string ToString() => $"[InfisicalTokenRevocationReceipt:{Evidence}]";
}
