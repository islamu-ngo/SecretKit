using Azure.ResourceManager;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>In-memory SDK status handle, not a serialized URL or idempotency token.</summary>
public sealed class ManagementOperation
{
    private readonly Func<bool> _hasCompleted;
    private readonly Func<CancellationToken, ValueTask<Azure.Response>> _update;
    private readonly ControlledTransport _transport;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Func<bool>? _validateValue;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;

    private ManagementOperation(Func<bool> hasCompleted, Func<CancellationToken, ValueTask<Azure.Response>> update,
        ControlledTransport transport,
        TimeSpan timeout, TimeProvider time, Func<bool>? validateValue = null)
    {
        _hasCompleted = hasCompleted;
        _update = update;
        _transport = transport;
        _timeout = timeout;
        _time = time;
        _validateValue = validateValue;
        State = hasCompleted() ? NativeProvisioningState.Succeeded : NativeProvisioningState.Pending;
    }

    internal static ManagementOperation From(ArmOperation operation, ControlledTransport transport,
        TimeSpan timeout, TimeProvider time, Func<bool>? validateValue = null) =>
        new(() => operation.HasCompleted, operation.UpdateStatusAsync, transport, timeout, time, validateValue);

    internal static ManagementOperation From<T>(ArmOperation<T> operation, ControlledTransport transport,
        TimeSpan timeout, TimeProvider time, Func<bool>? validateValue = null) where T : notnull =>
        new(() => operation.HasCompleted, operation.UpdateStatusAsync, transport, timeout, time, validateValue);

    internal static ManagementOperation Completed(ControlledTransport transport, TimeSpan timeout, TimeProvider time) =>
        new(() => true, _ => throw new InvalidOperationException("The operation is already complete."),
            transport, timeout, time);

    public NativeProvisioningState State { get; private set; }
    public bool RuntimeDeliveryProven => false;

    /// <summary>One explicit SDK status update, at most two reads including a final resource fetch. No waiting loop.</summary>
    public async ValueTask<SecretStatus> CheckStatusAsync(CancellationToken cancellationToken = default)
    {
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        bool entered = false;
        try
        {
            await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
            entered = true;
            if (State != NativeProvisioningState.Pending)
            {
                return State == NativeProvisioningState.Succeeded ? SecretStatus.Success : SecretStatus.Unknown;
            }

            _transport.CheckingStatus = true;
            _transport.StatusRequests = 0;
            _transport.LastOperationState = NativeProvisioningState.Unknown;
            await _update(linked.Token).ConfigureAwait(false);
            if (_transport.LastOperationState is NativeProvisioningState.Failed or NativeProvisioningState.Canceled)
            {
                State = _transport.LastOperationState;
                return SecretStatus.Unknown;
            }

            if (!_hasCompleted())
            {
                return SecretStatus.Pending;
            }

            if (_validateValue is not null && !_validateValue())
            {
                State = NativeProvisioningState.Unknown;
                return SecretStatus.Unknown;
            }

            State = NativeProvisioningState.Succeeded;
            return SecretStatus.Success;
        }
        catch (OperationCanceledException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return SecretStatus.Unavailable;
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var status = ControlledTransport.Failure(exception);
            if (exception is Azure.RequestFailedException && status is not (SecretStatus.Throttled or SecretStatus.Unavailable))
            {
                State = _transport.LastOperationState == NativeProvisioningState.Canceled
                    ? NativeProvisioningState.Canceled : NativeProvisioningState.Failed;
            }

            return status;
        }
        finally
        {
            if (entered)
            {
                _transport.CheckingStatus = false;
                _gate.Release();
            }
        }
    }

    public override string ToString() => $"[ManagementOperation:{State}]";
}
