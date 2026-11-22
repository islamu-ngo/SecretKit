using System.Diagnostics;
using SecretKit.Telemetry.Internal;

namespace SecretKit.AzureKeyVault.Management;

internal enum AzureDiagnosticOperation
{
    AdministrativeRead, AdministrativeInventory, AdministrativeMutation, NameAvailability, Audit, AuditBatch, StatusCheck
}
internal enum AzureDiagnosticTermination
{
    Completed, CallerCanceled, ShutdownCanceled, DeadlineExceeded, DependencyCanceled, Faulted
}
internal readonly record struct AzureDiagnosticCompletion(SecretKit.Core.SecretStatus Status,
    SecretKit.Core.SecretFailureReason Reason, SecretKit.Core.DispatchEvidence Dispatch, AzureDiagnosticTermination Termination);
internal readonly record struct AzureDiagnosticInterval(DateTime StartUtc, TimeSpan Duration, ActivityContext Parent);


internal static class AzureManagementDiagnostics
{
    private static readonly SecretKitTelemetry Telemetry = new("SecretKit.AzureKeyVault.Management",
        "azure.management.operation", "azure.management.operations", "azure.management.duration");

    internal static void Emit(string operation, AzureDiagnosticCompletion completion,
        AzureDiagnosticInterval interval)
    {
        TagList tags = new()
        {
            { "operation", operation }, { "outcome", completion.Status.ToString() },
            { "reason", completion.Reason.ToString() }, { "dispatch", completion.Dispatch.ToString() },
            { "termination", completion.Termination.ToString() }
        };
        Telemetry.Emit(tags, interval.StartUtc, interval.Duration, interval.Parent);
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
        private readonly ManagementReceipt? _receipt;
        private SecretKit.Core.SecretStatus _status = SecretKit.Core.SecretStatus.Unknown;
        private SecretKit.Core.SecretFailureReason _reason;
        private AzureDiagnosticTermination _termination;
        private bool _settled;

        internal Observation(AzureDiagnosticOperation operation, TimeProvider time, CancellationToken caller, ManagementReceipt? receipt = null)
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
            if (_reason == SecretKit.Core.SecretFailureReason.None) _reason = result.Reason;
            _settled = true;
            return result;
        }
        internal SecretKit.Core.SecretStatus Record(SecretKit.Core.SecretStatus status)
        {
            _status = status;
            _settled = true;
            return status;
        }

        internal ManagementInventory<T> Record<T>(ManagementInventory<T> result) where T : notnull
        {
            Record(result.Status);
            return result;
        }
        internal AuditQueryResult Record(AuditQueryResult result)
        {
            Record(result.Status);
            return result;
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
            AzureManagementDiagnostics.Emit(_operation.ToString(),
                new(_status, _reason, _receipt?.Evidence ?? SecretKit.Core.DispatchEvidence.NotDispatched, termination),
                new(_utc, duration, _parent));
        }
    }
}
