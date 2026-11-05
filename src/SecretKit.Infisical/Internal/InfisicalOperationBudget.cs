using System.Buffers;
using System.Net;
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

    internal const string PayloadTrimmingMessage = "Native mutation payloads use reflection-based JSON serialization. Trimming is not supported for these operations.";

    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode(PayloadTrimmingMessage)]
    internal static Func<int, byte[]> Payload<T>(T value, JsonSerializerOptions? options = null) =>
        maximum => Serialize(writer => JsonSerializer.Serialize(writer, value, options), maximum);

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
            Array.Clear(_buffer);
            _buffer = replacement;
        }

        internal byte[] ToArray() => _buffer.AsSpan(0, _written).ToArray();

        public void Dispose()
        {
            Array.Clear(_buffer);
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
                    budget.Check();
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
