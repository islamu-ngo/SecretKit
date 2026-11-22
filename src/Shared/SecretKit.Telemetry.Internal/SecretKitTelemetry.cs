using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SecretKit.Telemetry.Internal;

// Each domain retains its source and closed tag vocabulary. Only completed,
// material-free metadata crosses this observer boundary.
internal sealed class SecretKitTelemetry(string sourceName, string activityName, string counterName, string durationName)
{
    private ActivitySource? _activities;
    private Instruments? _instruments;
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);
    private readonly AsyncLocal<bool> _emitting = new();
    private readonly AsyncLocal<Scope?> _deferred = new();
    private readonly record struct Record(TagList Tags, DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);

    internal IDisposable Defer()
    {
        var scope = new Scope(this, _deferred.Value);
        _deferred.Value = scope;
        return scope;
    }

    // Detach before invoking observers. Children carrying a closed lexical
    // scope forward to its parent, including when that parent has also closed.
    private sealed class Scope(SecretKitTelemetry owner, Scope? parent) : IDisposable
    {
        private readonly Lock _gate = new();
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
            else owner.Export(record);
        }

        public void Dispose()
        {
            owner._deferred.Value = parent;
            List<Record>? records;
            lock (_gate) { records = _records; _records = null; }
            if (records is null) return;
            foreach (Record record in records)
            {
                if (parent is not null) parent.Submit(record);
                else owner.Export(record);
            }
        }
    }

    internal void Emit(TagList tags, DateTime startUtc, TimeSpan duration, ActivityContext parent)
    {
        if (_emitting.Value) return;
        var record = new Record(tags, startUtc, duration, parent);
        if (_deferred.Value is { } scope) scope.Submit(record);
        else Export(record);
    }

    private void Export(Record record)
    {
        if (_emitting.Value) return;
        // Restoring Activity.Current via its setter cannot restore a parent
        // stopped by host code. Run callbacks in a copied ExecutionContext so
        // AsyncLocal changes (including reentrant operations) cannot escape.
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
                ExportIsolated(record);
            }
            else ExportIsolated(record);
        }, null);
    }

    private void ExportIsolated(Record record)
    {
        _emitting.Value = true;
        try
        {
            TagList tags = record.Tags;
            // Independent observer entry points cannot suppress each other's
            // instruments, change product outcomes, or mask cancellation.
            try
            {
                Activity.Current = null;
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource(sourceName);
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = record.Parent;
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity(activityName, ActivityKind.Internal,
                    parent, tags, idFormat: ActivityIdFormat.W3C);
                if (activity is not null)
                {
                    activity.SetStartTime(record.StartUtc);
                    activity.SetEndTime(record.StartUtc + record.Duration);
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
                    var meter = new Meter(sourceName);
                    try
                    {
                        var created = new Instruments(meter, meter.CreateCounter<long>(counterName),
                            meter.CreateHistogram<double>(durationName, "s"));
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
                instruments?.Duration.Record(record.Duration.TotalSeconds, tags);
            }
            catch (Exception) { }
        }
        finally
        {
            // ExecutionContext.Run restores the caller context. Assigning
            // Activity.Current here would invoke untrusted change observers
            // outside the guarded export boundaries.
            _emitting.Value = false;
        }
    }
}
