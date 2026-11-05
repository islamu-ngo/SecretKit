using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.Extensions.Configuration;

internal enum ConfigurationOperation { Collection, Publication, Retirement }
internal enum ConfigurationTermination { Completed, CallerCanceled, DeadlineExceeded, DependencyCanceled, Faulted }
internal enum ConfigurationState { Published, Rejected, Validated, Superseded, Fresh, Stale, DeadlineElapsed, Retired, RetirementFailed }

internal sealed class ConfigurationCollectionObservation
{
    internal ConfigurationTermination Termination { get; set; }
}

internal readonly record struct ConfigurationDiagnosticStart(DateTime Utc, long Timestamp, ActivityContext Parent);
internal readonly record struct ConfigurationDiagnosticInterval(DateTime Utc, TimeSpan Duration, ActivityContext Parent);

internal static class ConfigurationDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);
    private static readonly AsyncLocal<bool> Emitting = new();
    private static readonly AsyncLocal<Scope?> Deferred = new();

    internal static ConfigurationDiagnosticStart? Capture(TimeProvider time)
    {
        try
        {
            ActivityContext parent = Activity.Current?.Context ?? default;
            return new(time.GetUtcNow().UtcDateTime, time.GetTimestamp(),
                new(parent.TraceId, parent.SpanId, parent.TraceFlags));
        }
        catch (Exception) { return null; }
    }

    internal static ConfigurationDiagnosticInterval? Complete(ConfigurationDiagnosticStart? start, TimeProvider time)
    {
        if (start is not { } captured) return null;
        try
        {
            TimeSpan duration = time.GetElapsedTime(captured.Timestamp);
            return new(captured.Utc, duration < TimeSpan.FromTicks(1) ? TimeSpan.FromTicks(1) : duration, captured.Parent);
        }
        catch (Exception) { return null; }
    }

    internal static IDisposable Defer()
    {
        var scope = new Scope(Deferred.Value);
        Deferred.Value = scope;
        return scope;
    }

    private readonly record struct Record(ConfigurationOperation Operation, SecretStatus Status,
        SecretFailureReason Reason, ConfigurationTermination Termination, ConfigurationState State,
        ConfigurationDiagnosticInterval Interval);

    // Only completed, material-free records cross lexical owners. Closing releases
    // the queue before invoking host code; a late child forwards to its next owner.
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
            lock (_gate) { records = _records; _records = null; }
            if (records is null) return;
            foreach (Record record in records)
            {
                if (parent is not null) parent.Submit(record);
                else Export(record);
            }
        }
    }

    internal static void Emit(ConfigurationOperation operation, SecretStatus status, SecretFailureReason reason,
        ConfigurationTermination termination, ConfigurationState state, ConfigurationDiagnosticInterval? interval)
    {
        if (interval is not { } measured || Emitting.Value) return;
        var record = new Record(operation, status, reason, termination, state, measured);
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
            TagList tags = new()
            {
                { "operation", record.Operation.ToString() }, { "outcome", record.Status.ToString() },
                { "reason", record.Reason.ToString() }, { "termination", record.Termination.ToString() },
                { "state", record.State.ToString() }
            };
            try
            {
                Activity.Current = null;
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource("SecretKit.Extensions.Configuration");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = record.Interval.Parent;
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity("configuration.operation", ActivityKind.Internal,
                    parent, tags, idFormat: ActivityIdFormat.W3C);
                if (activity is not null)
                {
                    activity.SetStartTime(record.Interval.Utc);
                    activity.SetEndTime(record.Interval.Utc + record.Interval.Duration);
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
                    var meter = new Meter("SecretKit.Extensions.Configuration");
                    try
                    {
                        var created = new Instruments(meter, meter.CreateCounter<long>("configuration.operations"),
                            meter.CreateHistogram<double>("configuration.duration", "s"));
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
            Activity.Current = ambient;
            Emitting.Value = false;
        }
    }
}
