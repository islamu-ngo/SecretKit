using System.Diagnostics;
using SecretKit.Core;
using SecretKit.Telemetry.Internal;

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
    private static readonly SecretKitTelemetry Telemetry = new("SecretKit.Extensions.Hosting",
        "hosting.operation", "hosting.operations", "hosting.duration");

    internal static void Emit(HostingOperation operation, HostingCompletion completion, HostingDiagnosticInterval? interval)
    {
        if (interval is not { } measured) return;
        TagList tags = new()
        {
            { "operation", operation.ToString() }, { "outcome", completion.Outcome.ToString() },
            { "reason", completion.Reason.ToString() }, { "termination", completion.Termination.ToString() },
            { "state", completion.State.ToString() }
        };
        Telemetry.Emit(tags, measured.StartUtc, measured.Duration, measured.Parent);
    }
}
