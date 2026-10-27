using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Hosting;
using SecretKit.Core;
using SecretKit.Infisical;

namespace SecretKit.Extensions.Hosting;

public enum AuthenticationMaintenanceState
{
    NotStarted,
    Ready,
    RenewalDue,
    Renewing,
    Expired,
    RecoveryRequired,
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

    public InfisicalAuthenticationMaintenance(InfisicalPeriodicTokenSession session, TimeSpan shutdownTimeout)
    {
        ArgumentNullException.ThrowIfNull(session);
        if (shutdownTimeout <= TimeSpan.Zero || shutdownTimeout > TimeSpan.FromMinutes(1))
            throw new ArgumentOutOfRangeException(nameof(shutdownTimeout));
        _session = session;
        _shutdownTimeout = shutdownTimeout;
    }

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

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        TaskCompletionSource? worker = null;
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_stopped, this);
            if (_worker is null)
            {
                worker = new(TaskCreationOptions.RunContinuationsAsynchronously);
                _worker = worker.Task;
            }
        }
        if (worker is not null) _ = RunMaintenanceAsync(worker);
        return Task.CompletedTask;
    }

    private async Task RunMaintenanceAsync(TaskCompletionSource completion)
    {
        try
        {
            await MaintainAsync().ConfigureAwait(false);
            completion.TrySetResult();
        }
        catch (Exception)
        {
            completion.TrySetException(new InvalidOperationException("Authentication maintenance failed."));
        }
    }

    private async Task MaintainAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                if (_session.State is InfisicalTokenSessionState.Expired or
                    InfisicalTokenSessionState.RecoveryRequired or InfisicalTokenSessionState.Stopped)
                    return;
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
                if (outcome != SecretStatus.Success) return;
            }
        }
        catch (OperationCanceledException) when (_stop.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (_session.State == InfisicalTokenSessionState.Stopped) { }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
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
        if (completion is not null) _ = StopCoreAsync(worker, completion);
        return stop.WaitAsync(cancellationToken);
    }

    private async Task StopCoreAsync(Task? worker, TaskCompletionSource completion)
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
        try
        {
            if (await bounded.ConfigureAwait(false))
                completion.TrySetResult();
            else
                completion.TrySetException(new InvalidOperationException("Authentication maintenance shutdown failed."));
        }
        catch (TimeoutException)
        {
            completion.TrySetException(new TimeoutException("Authentication maintenance shutdown timed out."));
        }
    }

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

    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None).ConfigureAwait(false);
}
