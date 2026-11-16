using System.Buffers;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical;

internal sealed class InfisicalOperationBudget : IDisposable
{
    private static readonly AsyncLocal<InfisicalOperationObservation?> CurrentObservation = new();
    private readonly InfisicalOperationObservation? _observation;
    private readonly CancellationToken _caller;
    private readonly CancellationToken _shutdown;
    private readonly TimeProvider _time;
    private readonly long _started;
    private readonly TimeSpan _timeout;
    private readonly CancellationTokenSource _deadline;
    private readonly CancellationTokenSource _linked;

    internal InfisicalOperationBudget(TimeSpan timeout, TimeProvider time, CancellationToken caller,
        CancellationToken shutdown = default)
    {
        _observation = CurrentObservation.Value;
        _caller = caller;
        _shutdown = shutdown;
        _time = time;
        _started = time.GetTimestamp();
        _timeout = timeout;
        _deadline = new(timeout, time);
        _linked = CancellationTokenSource.CreateLinkedTokenSource(caller, shutdown, _deadline.Token);
    }

    internal CancellationToken Token => _linked.Token;
    internal bool Expired => _deadline.IsCancellationRequested || _time.GetElapsedTime(_started) >= _timeout;

    internal void Check()
    {
        _caller.ThrowIfCancellationRequested();
        _shutdown.ThrowIfCancellationRequested();
        if (Expired) throw new OperationCanceledException(Token);
    }

    internal SecretFailureReason CancellationReason()
    {
        _observation?.ObserveCancellation(CancellationTermination());
        _caller.ThrowIfCancellationRequested();
        _shutdown.ThrowIfCancellationRequested();
        return Expired ? SecretFailureReason.DeadlineExceeded : SecretFailureReason.TransportFailure;
    }

    internal InfisicalTermination CancellationTermination() =>
        _caller.IsCancellationRequested ? InfisicalTermination.CallerCanceled :
        _shutdown.IsCancellationRequested ? InfisicalTermination.ShutdownCanceled :
        Expired ? InfisicalTermination.DeadlineExceeded : InfisicalTermination.DependencyCanceled;

    public void Dispose()
    {
        _linked.Dispose();
        _deadline.Dispose();
    }

    internal static TimeSpan? RetryAfter(HttpResponseMessage response, TimeProvider time)
    {
        if (response.StatusCode is not (HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable))
            return null;
        TimeSpan? advice = response.Headers.RetryAfter?.Delta;
        if (advice is null && response.Headers.RetryAfter?.Date is { } date)
            advice = date - time.GetUtcNow();
        return advice is { } value ? TimeSpan.FromTicks(Math.Clamp(value.Ticks, 0, TimeSpan.FromDays(1).Ticks)) : null;
    }

    internal static readonly SearchValues<char> ControlCharacters =
        SearchValues.Create(Enumerable.Range(0, 0x20).Concat(Enumerable.Range(0x7F, 0x21)).Select(static c => (char)c).ToArray());

    internal static readonly SearchValues<char> VisibleAsciiCharacters =
        SearchValues.Create(Enumerable.Range(0x21, 0x7E - 0x21 + 1).Select(static c => (char)c).ToArray());

    internal static readonly SearchValues<char> Rfc6750BearerCharacters =
        SearchValues.Create("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.~+/=");

    internal static async ValueTask<JsonDocument?> ReadJsonAsync(
        HttpResponseMessage response,
        int maximumBytes,
        int maxDepth,
        bool allowDuplicateProperties = false,
        Func<int, bool>? onChunkRead = null,
        CancellationToken cancellationToken = default)
    {
        // Inventory callers with onChunkRead still stream ContentLength <= _responseLimit so exact wire bytes are accounted against inventory.RemainingBytes.
        if (onChunkRead is null && response.Content.Headers.ContentLength > maximumBytes)
            return null;

        int initialCapacity = response.Content.Headers.ContentLength is { } contentLength and > 0
            ? Math.Min(maximumBytes + 1, checked((int)contentLength + 1))
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
        using var buffer = new RequestBuffer(maximum);
        try
        {
            using (var writer = new Utf8JsonWriter(buffer)) write(writer);
            return buffer.ToArray();
        }
        catch (NotSupportedException) { return []; }
    }

    internal static byte[]? SerializeAccessToken(SecretMaterial token, int maximum) =>
        token.Use(maximum, static (chars, limit) =>
        {
            if (chars.Length is < 1 or > 16384 || chars.ContainsAny(ControlCharacters))
                return null;
            using var buffer = new RequestBuffer(limit);
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
            using var buffer = new RequestBuffer(state.maximum);
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

    internal sealed class RequestBuffer(int maximum) : IBufferWriter<byte>, IDisposable
    {
        private byte[] _buffer = [];
        private int _written;

        public void Advance(int count)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (count > maximum - _written)
                throw new NotSupportedException("Request body exceeds its byte budget.");
            _written += count;
        }

        public Memory<byte> GetMemory(int sizeHint = 0)
        {
            EnsureCapacity(sizeHint);
            return _buffer.AsMemory(_written);
        }

        public Span<byte> GetSpan(int sizeHint = 0)
        {
            EnsureCapacity(sizeHint);
            return _buffer.AsSpan(_written);
        }

        private void EnsureCapacity(int sizeHint)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
            int required = Math.Max(1, sizeHint);
            // Utf8JsonWriter reserves for six-byte JSON escaping even for ASCII.
            // Permit that bounded reservation, but enforce actual bytes in Advance.
            int reservationLimit = checked((maximum - _written) * 6 + 4096);
            if (required > reservationLimit)
                throw new NotSupportedException("Request token exceeds its byte budget.");
            int needed = checked(_written + required);
            if (needed <= _buffer.Length) return;
            int capacity = Math.Min(checked(maximum * 6 + 4096),
                Math.Max(needed, Math.Max(4096, _buffer.Length * 2)));
            byte[] replacement = new byte[capacity];
            _buffer.AsSpan(0, _written).CopyTo(replacement);
            CryptographicOperations.ZeroMemory(_buffer);
            _buffer = replacement;
        }

        internal byte[] ToArray() => _buffer.AsSpan(0, _written).ToArray();

        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(_buffer);
            _buffer = [];
            _written = 0;
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1068", Justification = "Caller cancellation and adapter shutdown are distinct authorities; keeping the required caller token before optional evidence makes their precedence explicit.")]
    internal static async ValueTask<SecretOutcome<T>> RunAsync<T>(TimeSpan timeout, TimeProvider time,
        CancellationToken caller, InfisicalOperation? operation,
        Func<CancellationToken, ValueTask<SecretOutcome<T>>> execute,
        Func<DispatchEvidence>? evidence = null, CancellationToken shutdown = default,
        InfisicalOperationObservation? observation = null) where T : notnull
    {
        InfisicalDiagnosticStart? started = InfisicalDiagnostics.Capture(time);
        using var deferred = InfisicalDiagnostics.Defer();
        observation ??= new();
        InfisicalOperationObservation? previous = CurrentObservation.Value;
        CurrentObservation.Value = observation;
        SecretStatus status = SecretStatus.Unknown;
        SecretFailureReason reason = SecretFailureReason.None;
        InfisicalTermination termination = InfisicalTermination.Faulted;
        try
        {
            using var budget = new InfisicalOperationBudget(timeout, time, caller, shutdown);
            SecretOutcome<T> result;
            try
            {
                budget.Check();
                result = await execute(budget.Token).ConfigureAwait(false);
                try
                {
                    caller.ThrowIfCancellationRequested();
                    shutdown.ThrowIfCancellationRequested();
                    if (result.IsSuccess) budget.Check();
                    else if (budget.Expired) observation.ObserveCancellation(InfisicalTermination.DeadlineExceeded);
                }
                catch
                {
                    // A host clock may throw during validation too. Every unpublished
                    // disposable result remains owned until validation succeeds.
                    if (result.IsSuccess && result.Value is IDisposable owned) owned.Dispose();
                    throw;
                }
            }
            catch (OperationCanceledException)
            {
                termination = budget.CancellationTermination();
                reason = budget.CancellationReason();
                result = SecretOutcome<T>.Failure(evidence?.Invoke() == DispatchEvidence.PossiblyDispatched
                    ? SecretStatus.Unknown : SecretStatus.Unavailable, reason: reason);
            }
            status = result.Status;
            reason = result.Reason;
            termination = observation.Cancellation ?? InfisicalTermination.Completed;
            return result;
        }
        finally
        {
            CurrentObservation.Value = previous;
            InfisicalDiagnosticInterval? interval = InfisicalDiagnostics.Complete(started, time);
            var completion = new InfisicalOperationCompletion(status, reason,
                evidence?.Invoke() ?? DispatchEvidence.NotDispatched, termination);
            observation.Complete(completion);
            if (operation is { } selected)
            {
                // A cooperative dependency can complete inline in a shutdown
                // notification. Shutdown drains that notification too: leave
                // its stack before a listener can synchronously join disposal.
                await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
                InfisicalDiagnostics.Emit(selected, completion, interval);
            }
        }
    }
}
