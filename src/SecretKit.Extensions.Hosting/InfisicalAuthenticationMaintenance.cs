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
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_stopped, this);
            _worker ??= MaintainAsync();
        }
        return Task.CompletedTask;
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
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Task? worker;
        lock (_gate)
        {
            _stopped = true;
            _stop.Cancel();
            worker = _worker;
        }
        Task sessionStop = _session.StopAsync();
        await Task.WhenAll(worker ?? Task.CompletedTask, sessionStop)
            .WaitAsync(_shutdownTimeout, _session.TimeProvider, cancellationToken).ConfigureAwait(false);
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
