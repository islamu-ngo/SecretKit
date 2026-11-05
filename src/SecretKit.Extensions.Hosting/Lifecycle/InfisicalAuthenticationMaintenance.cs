using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Extensions.Hosting;

/// <summary>Material-free scheduling and session evidence, not application readiness or delivery.</summary>
public enum AuthenticationMaintenanceState
{
    /// <summary>No explicit start has admitted the maintenance schedule.</summary>
    NotStarted,
    /// <summary>The started session has usable material before its renewal window.</summary>
    Ready,
    /// <summary>The session's original lifetime evidence places it in its renewal window.</summary>
    RenewalDue,
    /// <summary>A single shared native renewal is in flight.</summary>
    Renewing,
    /// <summary>The current session material has expired and cannot be used.</summary>
    Expired,
    /// <summary>Explicit authorized recovery is required; the helper never logs in or changes principal.</summary>
    RecoveryRequired,
    /// <summary>The helper has stopped admitting scheduling; cleanup may still be pending after timeout.</summary>
    Stopped
}

/// <summary>
/// One explicitly started in-memory token schedule, not a fleet scheduler.
/// Registering/constructing this object does not start it. The session and transport
/// remain host-owned. Stop ends this session's credential generation and cancels/drains
/// its renewal. The host must not share that lifecycle with a separately running helper.
/// </summary>
public sealed class InfisicalAuthenticationMaintenance : IHostedService, IHealthCheck, IAsyncDisposable
{
    private readonly object _gate = new();
    private readonly InfisicalPeriodicTokenSession _session;
    private readonly CancellationTokenSource _stop = new();
    private readonly TimeSpan _shutdownTimeout;
    private Task? _worker;
    private Task? _stopTask;
    private bool _stopped;

    /// <summary>Borrows a session and selects the helper's single shutdown wait budget without starting work.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The budget is not positive or exceeds one minute.</exception>
    public InfisicalAuthenticationMaintenance(InfisicalPeriodicTokenSession session, TimeSpan shutdownTimeout)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (shutdownTimeout <= TimeSpan.Zero || shutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
        _session = session;
        _shutdownTimeout = shutdownTimeout;
    }

    /// <summary>Reports whether scheduling started and the session's current bounded state, without material.</summary>
    public AuthenticationMaintenanceState State
    {
        get
        {
            lock (_gate)
            {
                if (_stopped) return AuthenticationMaintenanceState.Stopped;
                if (_worker is null) return AuthenticationMaintenanceState.NotStarted;
            }
            return _session.State switch
            {
                InfisicalTokenSessionState.Ready => AuthenticationMaintenanceState.Ready,
                InfisicalTokenSessionState.RenewalDue => AuthenticationMaintenanceState.RenewalDue,
                InfisicalTokenSessionState.Renewing => AuthenticationMaintenanceState.Renewing,
                InfisicalTokenSessionState.Expired => AuthenticationMaintenanceState.Expired,
                InfisicalTokenSessionState.RecoveryRequired => AuthenticationMaintenanceState.RecoveryRequired,
                _ => AuthenticationMaintenanceState.Stopped
            };
        }
    }

    /// <summary>Starts the one caller-requested schedule; repeated starts share it and never acquire a new principal.</summary>
    /// <exception cref="OperationCanceledException">The caller canceled before admission.</exception>
    /// <exception cref="ObjectDisposedException">The helper has stopped and cannot be restarted.</exception>
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var started = HostingDiagnosticStart.Capture(_session.TimeProvider);
        var completed = new HostingCompletion(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.Faulted, HostingLifecycleState.Unknown);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            TaskCompletionSource? worker = null;
            lock (_gate)
            {
                completed = completed with { State = _stopped ? HostingLifecycleState.Stopped : HostingLifecycleState.Started };
                ObjectDisposedException.ThrowIf(_stopped, this);
                if (_worker is null)
                {
                    worker = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    _worker = worker.Task;
                }
            }
            if (worker is not null) _ = RunMaintenanceAsync(worker);
            completed = completed with { Outcome = SecretStatus.Success, Termination = HostingTermination.Completed };
            return Task.CompletedTask;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            lock (_gate)
                completed = completed with
                {
                    Termination = HostingTermination.CallerCanceled,
                    State = _stopped ? HostingLifecycleState.Stopped :
                        _worker is null ? HostingLifecycleState.NotStarted : HostingLifecycleState.Started
                };
            throw;
        }
        finally
        {
            HostingDiagnostics.Emit(HostingOperation.MaintenanceStart, completed, started?.Complete(_session.TimeProvider));
        }
    }

    private async Task RunMaintenanceAsync(TaskCompletionSource completion)
    {
        var started = HostingDiagnosticStart.Capture(_session.TimeProvider);
        var completed = new HostingCompletion(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.Faulted, HostingLifecycleState.Unknown);
        bool faulted = false;
        try
        {
            completed = await MaintainAsync().ConfigureAwait(false);
        }
        catch (Exception) { faulted = true; }
        // Cancellation notification can complete this await inline. Leave its
        // stack before signaling the tracked worker or invoking host listeners.
        await Task.CompletedTask.ConfigureAwait(ConfigureAwaitOptions.ForceYielding);
        var interval = started?.Complete(_session.TimeProvider);
        if (faulted)
            completion.TrySetException(new InvalidOperationException("Authentication maintenance failed."));
        else
            completion.TrySetResult();
        Task? stopping;
        lock (_gate) stopping = _stopTask;
        if (stopping is not null)
        {
            // Worker ownership is already released. Let the existing stop owner
            // fix its interval before this worker's listeners can run.
            try { await stopping.ConfigureAwait(false); }
            catch (Exception) { } // Its latched failure remains on the stop task.
        }
        HostingDiagnostics.Emit(HostingOperation.Maintenance, completed, interval);
    }

    private async Task<HostingCompletion> MaintainAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                InfisicalTokenSessionState state = _session.State;
                if (state == InfisicalTokenSessionState.Expired)
                    return new(SecretStatus.Expired, SecretFailureReason.None,
                        HostingTermination.Completed, HostingLifecycleState.Expired);
                if (state == InfisicalTokenSessionState.RecoveryRequired)
                    return new(SecretStatus.RecoveryRequired, SecretFailureReason.None,
                        HostingTermination.Completed, HostingLifecycleState.RecoveryRequired);
                if (state == InfisicalTokenSessionState.Stopped)
                    break;
                TimeSpan delay = _session.RenewalDueAt - _session.TimeProvider.GetUtcNow();
                if (delay > TimeSpan.Zero)
                {
                    // BCL timers have a finite duration range; re-evaluate long deadlines
                    // without renewing early or introducing a general-purpose scheduler.
                    await Task.Delay(delay > TimeSpan.FromDays(40) ? TimeSpan.FromDays(40) : delay,
                        _session.TimeProvider, _stop.Token).ConfigureAwait(false);
                    continue;
                }
                SecretStatus outcome = await _session.RenewAsync(_stop.Token).ConfigureAwait(false);
                if (outcome != SecretStatus.Success)
                    return new(outcome, SecretFailureReason.None,
                        HostingTermination.Completed, HostingLifecycleState.RecoveryRequired);
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_session.State == InfisicalTokenSessionState.Stopped) { }
        return new(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.ShutdownCanceled, HostingLifecycleState.Stopped);
    }

    /// <summary>Stops scheduling and the selected session generation using one latched shutdown attempt.</summary>
    /// <remarks>Cancellation ends only this caller's wait. Notification, drain and cleanup share the
    /// original injected-time budget. Timeout does not abandon eventual cleanup or imply successful drain.
    /// The helper never disposes the borrowed session or host-supplied transports.</remarks>
    /// <exception cref="TimeoutException">The original wait budget elapsed; later callers observe the same timeout.</exception>
    /// <exception cref="InvalidOperationException">Shutdown observed a sanitized callback or operation failure.</exception>
    /// <exception cref="OperationCanceledException">This caller canceled its wait.</exception>
    public Task StopAsync(CancellationToken cancellationToken)
    {
        var started = HostingDiagnosticStart.Capture(_session.TimeProvider);
        TaskCompletionSource? completion = null;
        Task? worker = null;
        Task stop;
        lock (_gate)
        {
            if (_stopTask is null)
            {
                _stopped = true;
                completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
                _stopTask = completion.Task;
                worker = _worker;
            }
            stop = _stopTask;
        }
        if (completion is not null) _ = StopCoreAsync(worker, completion, started);
        return cancellationToken.CanBeCanceled ? WaitForStopAsync(stop, started, cancellationToken) : stop;
    }

    private async Task WaitForStopAsync(Task stop, HostingDiagnosticStart? started, CancellationToken cancellationToken)
    {
        try { await stop.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            HostingDiagnostics.Emit(HostingOperation.MaintenanceStop,
                new(SecretStatus.Unknown, SecretFailureReason.None, HostingTermination.CallerCanceled, HostingLifecycleState.Stopped),
                started?.Complete(_session.TimeProvider));
            throw;
        }
    }

    private async Task StopCoreAsync(Task? worker, TaskCompletionSource completion, HostingDiagnosticStart? started)
    {
        var cleanup = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<bool> bounded = cleanup.Task.WaitAsync(_shutdownTimeout, _session.TimeProvider);
        Task sessionStop = _session.StopAsync();
        _ = Task.Run(async () =>
        {
            bool succeeded = true;
            try
            {
                Task notification = _stop.CancelAsync();
                try
                {
                    await Task.WhenAll(notification, sessionStop, worker ?? Task.CompletedTask).ConfigureAwait(false);
                }
                catch (Exception) { succeeded = false; }
            }
            finally
            {
                _stop.Dispose();
                cleanup.TrySetResult(succeeded);
            }
        });
        var completed = new HostingCompletion(SecretStatus.Unknown, SecretFailureReason.None,
            HostingTermination.Faulted, HostingLifecycleState.Stopped);
        Exception? failure = null;
        try
        {
            if (await bounded.ConfigureAwait(false))
                completed = completed with { Outcome = SecretStatus.Success, Termination = HostingTermination.Completed };
            else
                failure = new InvalidOperationException("Authentication maintenance shutdown failed.");
        }
        catch (TimeoutException)
        {
            completed = completed with
            {
                Outcome = SecretStatus.Unavailable,
                Reason = SecretFailureReason.DeadlineExceeded,
                Termination = HostingTermination.DeadlineExceeded
            };
            failure = new TimeoutException("Authentication maintenance shutdown timed out.");
        }
        var interval = started?.Complete(_session.TimeProvider);
        if (failure is null) completion.TrySetResult();
        else completion.TrySetException(failure);
        HostingDiagnostics.Emit(HostingOperation.MaintenanceStop, completed, interval);
    }

    /// <summary>Maps Ready to healthy, due/renewing to degraded and every other state to unhealthy.</summary>
    /// <remarks>This check performs no provider I/O and does not establish downstream readiness.</remarks>
    /// <exception cref="OperationCanceledException">The caller canceled the check.</exception>
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(State switch
        {
            AuthenticationMaintenanceState.Ready => HealthCheckResult.Healthy(),
            AuthenticationMaintenanceState.RenewalDue or AuthenticationMaintenanceState.Renewing =>
                HealthCheckResult.Degraded(),
            _ => HealthCheckResult.Unhealthy()
        });
    }

    /// <summary>Awaits the same bounded stop attempt, retaining its original timeout or sanitized failure.</summary>
    /// <remarks>A later disposal does not reset the budget or dispose the borrowed session.</remarks>
    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None).ConfigureAwait(false);
}
