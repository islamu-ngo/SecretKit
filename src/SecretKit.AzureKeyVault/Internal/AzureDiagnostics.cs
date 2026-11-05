using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SecretKit.AzureKeyVault;

internal enum AzureDiagnosticOperation
{
    Read, Inventory, SetSecret, NativeRead, NativeInventory, NativeMutation, LifecycleCheck, Backup
}
internal enum AzureDiagnosticTermination
{
    Completed, CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled, Faulted
}
internal readonly record struct AzureDiagnosticCompletion(SecretKit.Core.SecretStatus Status,
    SecretKit.Core.SecretFailureReason Reason, SecretKit.Core.DispatchEvidence Dispatch, AzureDiagnosticTermination Termination);
internal readonly record struct AzureDiagnosticInterval(DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);


internal static class AzureDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private static readonly AsyncLocal<bool> Emitting = new();
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);

    internal static void Emit(string operation, AzureDiagnosticCompletion completion,
        AzureDiagnosticInterval interval)
    {
        if (Emitting.Value) return;
        Activity? ambient = Activity.Current;
        Emitting.Value = true;
        try
        {
            TagList tags = new()
            {
                { "operation", operation }, { "outcome", completion.Status.ToString() },
                { "reason", completion.Reason.ToString() }, { "dispatch", completion.Dispatch.ToString() },
                { "termination", completion.Termination.ToString() }
            };
            try
            {
                Activity.Current = null;
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource("SecretKit.AzureKeyVault");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = interval.Parent;
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity("azure.operation",
                    ActivityKind.Internal, parent, tags, idFormat: ActivityIdFormat.W3C);
                if (activity is not null)
                {
                    activity.SetStartTime(interval.StartUtc);
                    activity.SetEndTime(interval.StartUtc + interval.Duration);
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
                    var meter = new Meter("SecretKit.AzureKeyVault");
                    try
                    {
                        var created = new Instruments(meter,
                            meter.CreateCounter<long>("azure.operations"),
                            meter.CreateHistogram<double>("azure.duration", "s"));
                        instruments = Interlocked.CompareExchange(ref _instruments, created, null) ?? created;
                        if (!ReferenceEquals(instruments, created)) meter.Dispose();
                    }
                    catch
                    {
                        meter.Dispose();
                        throw;
                    }
                }
                instruments.Operations.Add(1, tags);
            }
            catch (Exception) { }
            try
            {
                Activity.Current = null;
                instruments?.Duration.Record(interval.Duration.TotalSeconds, tags);
            }
            catch (Exception) { }
        }
        finally
        {
            Activity.Current = ambient;
            Emitting.Value = false;
        }
    }

    internal sealed class Observation : IDisposable
    {
        private readonly AzureDiagnosticOperation _operation;
        private readonly TimeProvider _time;
        private readonly CancellationToken _caller;
        private readonly DateTime _utc;
        private readonly long _timestamp;
        private readonly ActivityContext _parent;
        private readonly bool _timed;
        private readonly SecretKit.Core.MutationReceipt? _receipt;
        private SecretKit.Core.SecretStatus _status = SecretKit.Core.SecretStatus.Unknown;
        private SecretKit.Core.SecretFailureReason _reason;
        private AzureDiagnosticTermination _termination;
        private bool _settled;

        internal Observation(AzureDiagnosticOperation operation, TimeProvider time, CancellationToken caller, SecretKit.Core.MutationReceipt? receipt = null)
        {
            _operation = operation;
            _time = time;
            _caller = caller;
            _receipt = receipt;
            try
            {
                _utc = time.GetUtcNow().UtcDateTime;
                _timestamp = time.GetTimestamp();
                ActivityContext context = Activity.Current?.Context ?? default;
                _parent = new(context.TraceId, context.SpanId, context.TraceFlags);
                _timed = true;
            }
            catch (Exception) { }
        }

        internal SecretKit.Core.SecretOutcome<T> Record<T>(SecretKit.Core.SecretOutcome<T> result) where T : notnull
        {
            _status = result.Status;
            _reason = result.Reason;
            _settled = true;
            return result;
        }
        internal SecretKit.Core.SecretStatus Record(SecretKit.Core.SecretStatus status)
        {
            _status = status;
            _settled = true;
            return status;
        }

        internal void Cancel(bool deadline = false)
        {
            _termination = _caller.IsCancellationRequested ? AzureDiagnosticTermination.CallerCanceled :
                deadline ? AzureDiagnosticTermination.DeadlineExceeded : AzureDiagnosticTermination.DependencyCanceled;
            if (_termination == AzureDiagnosticTermination.DeadlineExceeded)
                _reason = SecretKit.Core.SecretFailureReason.DeadlineExceeded;
        }
        public void Dispose()
        {
            if (!_timed) return;
            TimeSpan duration;
            try { duration = _time.GetElapsedTime(_timestamp); }
            catch (Exception) { return; }
            // Activity's zero/subtick interval is one tick (100 ns). Freeze this
            // same floor for both the completed span and histogram, before listeners.
            if (duration < TimeSpan.FromTicks(1)) duration = TimeSpan.FromTicks(1);
            var termination = !_settled && _termination == AzureDiagnosticTermination.Completed
                ? _caller.IsCancellationRequested ? AzureDiagnosticTermination.CallerCanceled : AzureDiagnosticTermination.Faulted
                : _termination;
            AzureDiagnostics.Emit(_operation.ToString(),
                new(_status, _reason, _receipt?.Evidence ?? SecretKit.Core.DispatchEvidence.NotDispatched, termination),
                new(_utc, duration, _parent));
        }
    }
}
