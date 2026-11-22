using SecretKit.Core;

namespace SecretKit.Internal;

internal class OperationBudget : IDisposable
{
    private static readonly AsyncLocal<OperationObservation?> CurrentObservation = new();
    private readonly OperationObservation? _observation;
    private readonly CancellationToken _caller;
    private readonly CancellationToken _shutdown;
    private readonly TimeProvider _time;
    private readonly long _started;
    private readonly TimeSpan _timeout;
    private readonly CancellationTokenSource _deadline;
    private readonly CancellationTokenSource _linked;

    internal OperationBudget(TimeSpan timeout, TimeProvider time, CancellationToken caller,
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

    internal OperationTermination CancellationTermination() =>
        _caller.IsCancellationRequested ? OperationTermination.CallerCanceled :
        _shutdown.IsCancellationRequested ? OperationTermination.ShutdownCanceled :
        Expired ? OperationTermination.DeadlineExceeded : OperationTermination.DependencyCanceled;

    public void Dispose()
    {
        _linked.Dispose();
        _deadline.Dispose();
    }

    internal static async ValueTask<SecretOutcome<T>> RunAsync<T>(TimeSpan timeout, TimeProvider time,
        Func<OperationBudget, ValueTask<SecretOutcome<T>>> execute, OperationObservation observation,
        Func<DispatchEvidence>? evidence = null, CancellationToken shutdown = default,
        CancellationToken caller = default) where T : notnull
    {
        OperationObservation? previous = CurrentObservation.Value;
        CurrentObservation.Value = observation;
        SecretStatus status = SecretStatus.Unknown;
        SecretFailureReason reason = SecretFailureReason.None;
        OperationTermination termination = OperationTermination.Faulted;
        try
        {
            using var budget = new OperationBudget(timeout, time, caller, shutdown);
            SecretOutcome<T> result;
            try
            {
                budget.Check();
                result = await execute(budget).ConfigureAwait(false);
                try
                {
                    caller.ThrowIfCancellationRequested();
                    shutdown.ThrowIfCancellationRequested();
                    if (result.IsSuccess) budget.Check();
                    else if (budget.Expired) observation.ObserveCancellation(OperationTermination.DeadlineExceeded);
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
            termination = observation.Cancellation ?? OperationTermination.Completed;
            return result;
        }
        finally
        {
            CurrentObservation.Value = previous;
            var completion = new OperationCompletion(status, reason,
                evidence?.Invoke() ?? DispatchEvidence.NotDispatched, termination);
            observation.Complete(completion);
        }
    }
}
