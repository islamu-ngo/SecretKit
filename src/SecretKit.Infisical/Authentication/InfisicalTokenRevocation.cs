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
        _lease.ThrowIfDisposed(this);
        return new(this);
    }

    /// <summary>
    /// Revokes the explicitly supplied token through its native route. Success means
    /// provider acknowledgement, not an independently observed invalidation effect.
    /// No token source, fallback, renewal or replay is invoked.
    /// </summary>
    public async ValueTask<SecretOutcome<InfisicalTokenRevocationReceipt>> RevokeTokenAsync(SecretMaterial token,
        InfisicalTokenRevocationReceipt receipt, CancellationToken cancellationToken = default)
    {
        _lease.BeginOperation(this, cancellationToken);
        try
        {
            return await InfisicalOperationBudget.RunAsync(_operationTimeout, _time,
                cancellationToken, InfisicalOperation.Revocation, ExecuteAsync, () => receipt?.Evidence ?? DispatchEvidence.NotDispatched).ConfigureAwait(false);
        }
        finally
        {
            _lease.EndOperation();
        }

        async ValueTask<SecretOutcome<InfisicalTokenRevocationReceipt>> ExecuteAsync(CancellationToken operationToken)
        {
            ArgumentNullException.ThrowIfNull(token);
            ArgumentNullException.ThrowIfNull(receipt);
            operationToken.ThrowIfCancellationRequested();
            if (!ReferenceEquals(receipt.Owner, this) || receipt.Evidence != DispatchEvidence.NotDispatched)
                return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Invalid);
            char[] characters = token.ExportCharacters();
            byte[] payload = new byte[Math.Min(128 * 1024, _requestLimit)];
            byte[] bytes = new byte[_responseLimit + 1];
            try
            {
                if (characters.Length is < 1 or > 16384 || characters.Any(char.IsControl))
                    return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Invalid);
                using var stream = new MemoryStream(payload, writable: true);
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writer.WriteStartObject();
                    writer.WriteString("accessToken", characters.AsSpan());
                    writer.WriteEndObject();
                }
                using var content = new ByteArrayContent(payload, 0, checked((int)stream.Position));
                content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using var request = await _wire.RevokeTokenAsync(content, operationToken).ConfigureAwait(false);
                if (request.RequestUri is { IsAbsoluteUri: false } relative) request.RequestUri = new(_origin, relative);
                if (request.Method != HttpMethod.Post || request.RequestUri != new Uri(_origin, "/api/v1/auth/token/revoke"))
                    return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Invalid);
                operationToken.ThrowIfCancellationRequested();
                if (!receipt.TryBeginDispatch()) return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Invalid);
                using var response = await _transport.SendAsync(request, HttpCompletionOption.ResponseHeadersRead,
                    operationToken).ConfigureAwait(false);
                if (response.StatusCode != HttpStatusCode.OK)
                {
                    SecretStatus status = response.StatusCode switch
                    {
                        HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden => SecretStatus.Denied,
                        HttpStatusCode.BadRequest or HttpStatusCode.UnprocessableEntity => SecretStatus.Invalid,
                        HttpStatusCode.TooManyRequests => SecretStatus.Throttled,
                        HttpStatusCode.ServiceUnavailable => SecretStatus.Unavailable,
                        _ => SecretStatus.Unknown
                    };
                    if ((int)response.StatusCode is >= 400 and < 500 && status != SecretStatus.Unknown)
                        receipt.Record(DispatchEvidence.Rejected);
                    return await InfisicalFailureResponse.ReadAsync<InfisicalTokenRevocationReceipt>(response,
                        _responseLimit, _time, status, resource: false, cancellationToken: operationToken).ConfigureAwait(false);
                }
                if (response.Content.Headers.ContentLength > _responseLimit)
                    return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.ResponseTooLarge);
                using Stream body = await response.Content.ReadAsStreamAsync(operationToken).ConfigureAwait(false);
                int length = 0;
                while (length < bytes.Length)
                {
                    int read = await body.ReadAsync(bytes.AsMemory(length), operationToken).ConfigureAwait(false);
                    if (read == 0) break;
                    length += read;
                }
                if (length > _responseLimit)
                    return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.ResponseTooLarge);
                using var document = JsonDocument.Parse(bytes.AsMemory(0, length), new JsonDocumentOptions { MaxDepth = 8 });
                JsonElement root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 1 ||
                    !root.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.String)
                    return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Unknown, reason: SecretFailureReason.InvalidResponse);
                receipt.Record(DispatchEvidence.Applied);
                operationToken.ThrowIfCancellationRequested();
                return SecretOutcome<InfisicalTokenRevocationReceipt>.Success(receipt);
            }
            catch (OperationCanceledException) { throw new OperationCanceledException("Token revocation canceled.", operationToken); }
            catch (Exception error) when (error is HttpRequestException or IOException or JsonException or InvalidOperationException or NotSupportedException)
            {
                return SecretOutcome<InfisicalTokenRevocationReceipt>.Failure(SecretStatus.Unknown,
                    reason: error is HttpRequestException or IOException ? SecretFailureReason.TransportFailure : SecretFailureReason.InvalidResponse);
            }
            finally
            {
                Array.Clear(characters);
                Array.Clear(payload);
                Array.Clear(bytes);
            }
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
