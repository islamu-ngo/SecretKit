using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Extensions.Hosting;

internal sealed class InfisicalStartupAdmissionService(InfisicalRuntimeSession runtime,
    ILogger<InfisicalStartupAdmissionService> logger) : IHostedLifecycleService
{
    private int _stopping;

    public async Task StartingAsync(CancellationToken cancellationToken)
    {
        var started = HostingDiagnosticStart.Capture(TimeProvider.System);
        HostingDiagnosticInterval? interval = null;
        var completed = new HostingCompletion(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.Faulted, HostingLifecycleState.Unknown);
        try
        {
            var outcome = await runtime.EnsureAuthenticatedAsync(cancellationToken).ConfigureAwait(false);
            completed = new(outcome.Status, outcome.Reason,
                outcome.Reason == SecretFailureReason.DeadlineExceeded
                    ? HostingTermination.DeadlineExceeded : HostingTermination.Completed,
                outcome.IsSuccess ? HostingLifecycleState.Authenticated : HostingLifecycleState.Unknown);
            interval = started?.Complete(TimeProvider.System);
            try
            {
                InfisicalHostingLog.Authentication(logger, outcome.Status, outcome.Reason,
                    runtime.OpeningAttempt.LoginReceipt?.Evidence ?? DispatchEvidence.NotDispatched);
            }
            catch (Exception) { } // A host logger cannot change authentication evidence or expose its own exception.
            _ = outcome.GetValueOrThrow();
        }
        catch (OperationCanceledException)
        {
            completed = completed with
            {
                Termination = cancellationToken.IsCancellationRequested ? HostingTermination.CallerCanceled :
                    Volatile.Read(ref _stopping) != 0 ? HostingTermination.ShutdownCanceled :
                    HostingTermination.DependencyCanceled
            };
            throw;
        }
        finally
        {
            interval ??= started?.Complete(TimeProvider.System);
            HostingDiagnostics.Emit(HostingOperation.Admission, completed, interval);
        }
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StartedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StoppingAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        var started = HostingDiagnosticStart.Capture(TimeProvider.System);
        var completed = new HostingCompletion(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.Faulted, HostingLifecycleState.Stopped);
        Interlocked.Exchange(ref _stopping, 1);
        try
        {
            await runtime.StopAsync().WaitAsync(cancellationToken).ConfigureAwait(false);
            completed = completed with { Outcome = SecretStatus.Success, Termination = HostingTermination.Completed };
        }
        catch (OperationCanceledException)
        {
            completed = completed with
            {
                Termination = cancellationToken.IsCancellationRequested
                    ? HostingTermination.CallerCanceled : HostingTermination.DependencyCanceled
            };
            throw;
        }
        catch (TimeoutException)
        {
            completed = completed with
            {
                Outcome = SecretStatus.Unavailable,
                Reason = SecretFailureReason.DeadlineExceeded,
                Termination = HostingTermination.DeadlineExceeded
            };
            throw;
        }
        finally
        {
            HostingDiagnostics.Emit(HostingOperation.AdmissionStop, completed, started?.Complete(TimeProvider.System));
        }
    }
    public Task StoppedAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
