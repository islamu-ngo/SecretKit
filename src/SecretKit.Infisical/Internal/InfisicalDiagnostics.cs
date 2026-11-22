using System.Diagnostics;
using SecretKit.Internal;
using SecretKit.Telemetry.Internal;

namespace SecretKit.Infisical;

internal enum InfisicalOperation
{
    Read, Inventory, Native, StaticMutation, Dynamic, Rotation, UniversalLogin, ProofLogin, Renewal, Revocation
}

/// <summary>Controls deferred export of completed Infisical runtime diagnostics.</summary>
public static class InfisicalDiagnostics
{
    private static readonly SecretKitTelemetry Telemetry = new("SecretKit.Infisical",
        "infisical.operation", "infisical.operations", "infisical.duration");

    internal static OperationDiagnosticStart? Capture(TimeProvider time) => OperationTiming.Capture(time);
    internal static OperationDiagnosticInterval? Complete(OperationDiagnosticStart? start, TimeProvider time) =>
        OperationTiming.Complete(start, time);

    /// <summary>Defers completed runtime observations until the returned scope is disposed.</summary>
    /// <remarks>Use a lexical scope while composing runtime calls into a larger operation.
    /// Disposal exports only material-free completed metadata and never changes operation results.
    /// It grants no provider authority and starts no work.</remarks>
    public static IDisposable Defer() => Telemetry.Defer();

    internal static void Emit(InfisicalOperation operation, OperationCompletion completion,
        OperationDiagnosticInterval? interval)
    {
        if (interval is not { } measured) return;
        TagList tags = new()
        {
            { "operation", operation.ToString() }, { "outcome", completion.Status.ToString() },
            { "reason", completion.Reason.ToString() }, { "dispatch", completion.Dispatch.ToString() },
            { "termination", completion.Termination.ToString() }
        };
        Telemetry.Emit(tags, measured.StartUtc, measured.Duration, measured.Parent);
    }
}
