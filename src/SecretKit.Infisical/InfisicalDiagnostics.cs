using System.Diagnostics;
using System.Diagnostics.Metrics;
using SecretKit.Core;

namespace SecretKit.Infisical;

internal enum InfisicalOperation
{
    Read, Inventory, Native, StaticMutation, Dynamic, Rotation, UniversalLogin, ProofLogin, Renewal, Revocation
}

internal static class InfisicalDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);
    private static readonly AsyncLocal<bool> Emitting = new();

    internal static void Emit(InfisicalOperation operation, SecretStatus outcome, SecretFailureReason reason,
        DispatchEvidence dispatch, long started)
    {
        if (Emitting.Value) return;
        Emitting.Value = true;
        try
        {
            TagList tags = new()
            {
                { "operation", operation.ToString() }, { "outcome", outcome.ToString() },
                { "reason", reason.ToString() }, { "dispatch", dispatch.ToString() }
            };
            // Every listener entry point is independent host code. A throwing
            // activity listener cannot suppress measurements or alter evidence.
            try
            {
                ActivitySource? source = Volatile.Read(ref _activities);
                if (source is null)
                {
                    var created = new ActivitySource("SecretKit.Infisical");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                using Activity? activity = source.StartActivity("infisical.operation",
                    ActivityKind.Internal, default(ActivityContext), tags);
            }
            catch (Exception) { }
            Instruments? instruments = Volatile.Read(ref _instruments);
            try
            {
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
            try { instruments?.Operations.Add(1, tags); }
            catch (Exception) { }
            try { instruments?.Duration.Record(Stopwatch.GetElapsedTime(started).TotalSeconds, tags); }
            catch (Exception) { }
        }
        finally { Emitting.Value = false; }
    }
}
