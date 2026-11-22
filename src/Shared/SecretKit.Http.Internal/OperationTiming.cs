using System.Diagnostics;
using SecretKit.Core;

namespace SecretKit.Internal;

internal enum OperationTermination
{
    Completed, CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled, Faulted
}

internal readonly record struct OperationCompletion(SecretStatus Status, SecretFailureReason Reason,
    DispatchEvidence Dispatch, OperationTermination Termination);

internal sealed class OperationObservation
{
    internal OperationCompletion? Completion { get; private set; }
    internal OperationTermination? Cancellation { get; private set; }
    internal void ObserveCancellation(OperationTermination termination) => Cancellation = termination;
    internal void Complete(OperationCompletion completion) => Completion = completion;
}

internal readonly record struct OperationDiagnosticStart(DateTime Utc, long Timestamp, ActivityContext Parent);
internal readonly record struct OperationDiagnosticInterval(DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);

internal static class OperationTiming
{
    internal static OperationDiagnosticStart? Capture(TimeProvider time)
    {
        try
        {
            ActivityContext context = Activity.Current?.Context ?? default;
            return new(time.GetUtcNow().UtcDateTime, time.GetTimestamp(),
                new(context.TraceId, context.SpanId, context.TraceFlags));
        }
        catch (Exception) { return null; }
    }

    internal static OperationDiagnosticInterval? Complete(OperationDiagnosticStart? start, TimeProvider time)
    {
        if (start is not { } captured) return null;
        try
        {
            TimeSpan elapsed = time.GetElapsedTime(captured.Timestamp);
            // Activity represents zero/subtick intervals as one tick (100 ns).
            // Apply that floor once, before callbacks, to both span and histogram.
            return new(captured.Utc, elapsed < TimeSpan.FromTicks(1) ? TimeSpan.FromTicks(1) : elapsed, captured.Parent);
        }
        catch (Exception) { return null; }
    }
}
