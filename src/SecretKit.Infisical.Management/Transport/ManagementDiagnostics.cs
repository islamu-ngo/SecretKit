using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace SecretKit.Infisical.Management;

internal static class ManagementDiagnostics
{
    private static ActivitySource? _activities;
    private static Instruments? _instruments;
    private static readonly AsyncLocal<bool> Emitting = new();
    private sealed record Instruments(Meter Meter, Counter<long> Operations, Histogram<double> Duration);

    internal static void Emit(string operation, InfisicalOperationCompletion completion,
        InfisicalDiagnosticInterval? interval)
    {
        if (interval is not { } measured || Emitting.Value) return;
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
                    var created = new ActivitySource("SecretKit.Infisical.Management");
                    source = Interlocked.CompareExchange(ref _activities, created, null) ?? created;
                    if (!ReferenceEquals(source, created)) created.Dispose();
                }
                Activity.Current = null;
                ActivityContext parent = measured.Parent;
                if (parent.TraceId == default)
                    parent = new(ActivityTraceId.CreateRandom(), default, ActivityTraceFlags.None);
                using Activity? activity = source.CreateActivity("infisical.management.operation",
                    ActivityKind.Internal, parent, tags, idFormat: ActivityIdFormat.W3C);
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
                    var meter = new Meter("SecretKit.Infisical.Management");
                    try
                    {
                        var created = new Instruments(meter,
                            meter.CreateCounter<long>("infisical.management.operations"),
                            meter.CreateHistogram<double>("infisical.management.duration", "s"));
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
                instruments?.Duration.Record(measured.Duration.TotalSeconds, tags);
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
