using System.Diagnostics;
using SecretKit.Core;
using SecretKit.Telemetry.Internal;

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
    private static readonly SecretKitTelemetry Telemetry = new("SecretKit.Extensions.Configuration",
        "configuration.operation", "configuration.operations", "configuration.duration");

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

    internal static IDisposable Defer() => Telemetry.Defer();

    internal static void Emit(ConfigurationOperation operation, SecretStatus status, SecretFailureReason reason,
        ConfigurationTermination termination, ConfigurationState state, ConfigurationDiagnosticInterval? interval)
    {
        if (interval is not { } measured) return;
        TagList tags = new()
        {
            { "operation", operation.ToString() }, { "outcome", status.ToString() },
            { "reason", reason.ToString() }, { "termination", termination.ToString() },
            { "state", state.ToString() }
        };
        Telemetry.Emit(tags, measured.Utc, measured.Duration, measured.Parent);
    }
}
