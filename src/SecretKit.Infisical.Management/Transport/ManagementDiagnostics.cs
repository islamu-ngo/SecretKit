using System.Diagnostics;
using SecretKit.Internal;
using SecretKit.Telemetry.Internal;

namespace SecretKit.Infisical.Management;

internal static class ManagementDiagnostics
{
    private static readonly SecretKitTelemetry Telemetry = new("SecretKit.Infisical.Management",
        "infisical.management.operation", "infisical.management.operations", "infisical.management.duration");

    internal static void Emit(string operation, OperationCompletion completion,
        OperationDiagnosticInterval? interval)
    {
        if (interval is not { } measured) return;
        TagList tags = new()
        {
            { "operation", operation }, { "outcome", completion.Status.ToString() },
            { "reason", completion.Reason.ToString() }, { "dispatch", completion.Dispatch.ToString() },
            { "termination", completion.Termination.ToString() }
        };
        Telemetry.Emit(tags, measured.StartUtc, measured.Duration, measured.Parent);
    }
}
