using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.Extensions.Hosting;

internal enum HostingOperation { Admission, AdmissionStop, MaintenanceStart, Maintenance, MaintenanceStop }
internal enum HostingTermination { Completed, CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled, Faulted }
internal enum HostingLifecycleState { Unknown, NotStarted, Started, Authenticated, RecoveryRequired, Expired, Stopped }

internal readonly record struct HostingCompletion(SecretStatus Outcome, SecretFailureReason Reason,
    HostingTermination Termination, HostingLifecycleState State);

// Capturing an interval must not initialize instruments or invoke their listeners.
internal readonly record struct HostingDiagnosticStart(DateTime Utc, long Timestamp, ActivityContext Parent)
{
    internal static HostingDiagnosticStart? Capture(TimeProvider time)
    {
        try
        {
            ActivityContext parent = Activity.Current?.Context ?? default;
            return new(time.GetUtcNow().UtcDateTime, time.GetTimestamp(),
                new(parent.TraceId, parent.SpanId, parent.TraceFlags));
        }
        catch (Exception) { return null; }
    }

    internal HostingDiagnosticInterval? Complete(TimeProvider time)
    {
        try
        {
            TimeSpan duration = time.GetElapsedTime(Timestamp);
            // Match Activity's 100 ns representation floor, before any callbacks.
            return new(Utc, duration < TimeSpan.FromTicks(1) ? TimeSpan.FromTicks(1) : duration, Parent);
        }
        catch (Exception) { return null; }
    }
}

internal readonly record struct HostingDiagnosticInterval(DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);

internal static class HostingDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private static readonly AsyncLocal<bool> Emitting = new();
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);

    internal static void Emit(HostingOperation operation, HostingCompletion completion, HostingDiagnosticInterval? interval)
    {
        if (interval is not { } measured || Emitting.Value) return;
        // A synchronous listener can stop the caller's Activity object. Restoring
        // Activity.Current then rejects that stopped object. Isolate callback
        // context changes so the caller retains its original AsyncLocal value.
        bool suppressed = ExecutionContext.IsFlowSuppressed();
        if (suppressed) ExecutionContext.RestoreFlow();
        ExecutionContext context;
        try { context = ExecutionContext.Capture()!; }
        finally { if (suppressed) ExecutionContext.SuppressFlow(); }
        ExecutionContext.Run(context, _ =>
        {
            if (suppressed)
            {
                using var flow = ExecutionContext.SuppressFlow();
                Export(operation, completion, measured);
            }
            else Export(operation, completion, measured);
        }, null);
    }

    private static void Export(HostingOperation operation, HostingCompletion completion, HostingDiagnosticInterval measured)
    {
        Activity? ambient = Activity.Current;
        Emitting.Value = true;
        try
        {
            TagList tags = new()
            {
                { "operation", operation.ToString() }, { "outcome", completion.Outcome.ToString() },
                { "reason", completion.Reason.ToString() }, { "termination", completion.Termination.ToString() },
                { "state", completion.State.ToString() }
            };
            try
            {
                Activity.Current = null;
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource("SecretKit.Extensions.Hosting");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = measured.Parent;
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity("hosting.operation", ActivityKind.Internal,
                    parent, tags, idFormat: ActivityIdFormat.W3C);
                if (activity is not null)
                {
                    activity.SetStartTime(measured.StartUtc);
                    activity.SetEndTime(measured.StartUtc + measured.Duration);
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
                    var meter = new Meter("SecretKit.Extensions.Hosting");
                    try
                    {
                        var created = new Instruments(meter, meter.CreateCounter<long>("hosting.operations"),
                            meter.CreateHistogram<double>("hosting.duration", "s"));
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
                instruments?.Duration.Record(measured.Duration.TotalSeconds, tags);
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
