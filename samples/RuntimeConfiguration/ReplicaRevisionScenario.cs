namespace SecretKit.Samples.RuntimeConfiguration;

/// <summary>Material-free local message shape. No persistence or actual fleet convergence is claimed.</summary>
public sealed record RuntimeDesiredRevision(long Revision, bool Enabled);
public sealed record RuntimeReplicaAcknowledgement(string Replica, long DesiredRevision,
    long ObservedRevision, bool Active);

/// <summary>Independent replica objects reconcile explicit monotonic desired revisions.</summary>
public sealed class ReplicaRevisionScenario(string replica, RuntimeIntegrationCoordinator coordinator)
{
    private readonly object _gate = new();
    private long _desired;
    private long _observed;
    private bool _enabled;

    public async ValueTask<RuntimeReplicaAcknowledgement> ApplyAsync(RuntimeDesiredRevision desired,
        CancellationToken cancellationToken = default)
    {
        ValueTask<RuntimeActivationObservation> activation;
        lock (_gate)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (desired.Revision <= 0) throw new ArgumentOutOfRangeException(nameof(desired));
            if (desired.Revision == _desired && desired.Enabled != _enabled)
                throw new ArgumentException("A revision cannot change its desired state.", nameof(desired));
            if (desired.Revision < _desired || desired.Revision == _observed)
                return Acknowledge();
            _desired = desired.Revision;
            _enabled = desired.Enabled;
            if (!desired.Enabled)
            {
                coordinator.Disable();
                _observed = desired.Revision;
                return Acknowledge();
            }
            // Reserve the coordinator revision before a later disable can enter this gate.
            activation = coordinator.EnableAsync(cancellationToken);
        }
        RuntimeActivationObservation local = await activation.ConfigureAwait(false);
        lock (_gate)
        {
            if (_desired == desired.Revision && _enabled && local.Active &&
                local.ObservedRevision == local.DesiredRevision)
                _observed = desired.Revision;
            return Acknowledge();
        }
    }

    private RuntimeReplicaAcknowledgement Acknowledge() =>
        new(replica, _desired, _observed, coordinator.Observe().Active);
}
