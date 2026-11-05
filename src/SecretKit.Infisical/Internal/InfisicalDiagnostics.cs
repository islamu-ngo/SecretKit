using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.Infisical;

internal enum InfisicalOperation
{
    Read, Inventory, Native, StaticMutation, Dynamic, Rotation, UniversalLogin, ProofLogin, Renewal, Revocation
}

internal enum InfisicalTermination
{
    Completed, CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled, Faulted
}

internal readonly record struct InfisicalOperationCompletion(SecretStatus Status, SecretFailureReason Reason,
    DispatchEvidence Dispatch, InfisicalTermination Termination);

internal sealed class InfisicalOperationObservation
{
    internal InfisicalOperationCompletion? Completion { get; private set; }
    internal InfisicalTermination? Cancellation { get; private set; }
    internal void ObserveCancellation(InfisicalTermination termination) => Cancellation = termination;
    internal void Complete(InfisicalOperationCompletion completion) => Completion = completion;
}

internal readonly record struct InfisicalDiagnosticStart(DateTime Utc, long Timestamp, ActivityContext Parent);
internal readonly record struct InfisicalDiagnosticInterval(DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);

internal static class InfisicalDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);
    private static readonly AsyncLocal<bool> Emitting = new();
    private static readonly AsyncLocal<Scope?> Deferred = new();

    internal static InfisicalDiagnosticStart? Capture(TimeProvider time)
    {
        try
        {
            ActivityContext context = Activity.Current?.Context ?? default;
            return new(time.GetUtcNow().UtcDateTime, time.GetTimestamp(),
                new(context.TraceId, context.SpanId, context.TraceFlags));
        }
        catch (Exception) { return null; }
    }

    internal static InfisicalDiagnosticInterval? Complete(InfisicalDiagnosticStart? start, TimeProvider time)
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

    internal static IDisposable Defer()
    {
        var scope = new Scope(Deferred.Value);
        Deferred.Value = scope;
        return scope;
    }

    private readonly record struct Record(InfisicalOperation Operation, InfisicalOperationCompletion Completion,
        InfisicalDiagnosticInterval Interval);

    // A native owner transfers completed metadata to its enclosing SDK operation.
    // Closing detaches the list before callbacks; a racing child sees closed
    // ownership and forwards to the next owner instead of stranding its record.
    private sealed class Scope(Scope? parent) : IDisposable
    {
        private readonly object _gate = new();
        private List<Record>? _records = [];

        internal void Submit(Record record)
        {
            lock (_gate)
            {
                if (_records is not null)
                {
                    _records.Add(record);
                    return;
                }
            }
            if (parent is not null) parent.Submit(record);
            else Export(record);
        }

        public void Dispose()
        {
            Deferred.Value = parent;
            List<Record>? records;
            lock (_gate)
            {
                records = _records;
                _records = null;
            }
            if (records is null) return;
            foreach (Record record in records)
            {
                if (parent is not null) parent.Submit(record);
                else Export(record);
            }
        }
    }

    internal static void Emit(InfisicalOperation operation, InfisicalOperationCompletion completion,
        InfisicalDiagnosticInterval? interval)
    {
        if (interval is not { } measured || Emitting.Value) return;
        var record = new Record(operation, completion, measured);
        if (Deferred.Value is { } scope) scope.Submit(record);
        else Export(record);
    }

    private static void Export(Record record)
    {
        if (Emitting.Value) return;
        Activity? ambient = Activity.Current;
        Emitting.Value = true;
        try
        {
            InfisicalOperationCompletion completion = record.Completion;
            TagList tags = new()
            {
                { "operation", record.Operation.ToString() }, { "outcome", completion.Status.ToString() },
                { "reason", completion.Reason.ToString() }, { "dispatch", completion.Dispatch.ToString() },
                { "termination", completion.Termination.ToString() }
            };
            // Every listener entry point is independent host code. A throwing
            // activity listener cannot suppress measurements or alter evidence.
            try
            {
                Activity.Current = null;
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource("SecretKit.Infisical");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = record.Interval.Parent;
                // An explicit root trace prevents a sampler's ambient replacement
                // from becoming a parent when there was no W3C caller context.
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity("infisical.operation",
                    ActivityKind.Internal, parent, tags, idFormat: ActivityIdFormat.W3C);
                if (activity is not null)
                {
                    activity.SetStartTime(record.Interval.StartUtc);
                    activity.SetEndTime(record.Interval.StartUtc + record.Interval.Duration);
                    Activity.Current = null;
                    activity.Start();
                }
            }
            catch (Exception) { }
            Instruments? instruments = Volatile.Read(ref _instruments);
            try
            {
                Activity.Current = null;
                if (instruments is null)
                {
                    var meter = new Meter("SecretKit.Infisical");
                    try
                    {
                        var created = new Instruments(meter, meter.CreateCounter<long>("infisical.operations"),
                            meter.CreateHistogram<double>("infisical.duration", "s"));
                        instruments = Interlocked.CompareExchange(ref _instruments, created, null) ?? created;
                        if (!ReferenceEquals(instruments, created)) meter.Dispose();
                    }
                    catch { meter.Dispose(); throw; }
                }
            }
            catch (Exception) { }
            try
            {
                Activity.Current = null;
                instruments?.Operations.Add(1, tags);
            }
            catch (Exception) { }
            try
            {
                Activity.Current = null;
                instruments?.Duration.Record(record.Interval.Duration.TotalSeconds, tags);
            }
            catch (Exception) { }
        }
        finally
        {
            try { Activity.Current = ambient; }
            finally { Emitting.Value = false; }
        }
    }
}
