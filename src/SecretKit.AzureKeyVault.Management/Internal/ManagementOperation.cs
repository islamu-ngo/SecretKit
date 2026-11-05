using Azure.ResourceManager;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management;

/// <summary>In-memory SDK status handle, not a serialized URL or idempotency token.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001", Justification = "The private semaphore is async-only and never exposes AvailableWaitHandle, so no unmanaged handle is allocated; disposing it would race ongoing status checks without an owned resource lifecycle to close.")]
public sealed class ManagementOperation
{
    private readonly Func<bool> _hasCompleted;
    private readonly Func<CancellationToken, ValueTask<Azure.Response>> _update;
    private readonly ControlledTransport _transport;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Func<bool>? _validateValue;
    private readonly TimeSpan _timeout;
    private readonly TimeProvider _time;
    private bool _validatedSuccess;

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
        _validatedSuccess = hasCompleted() && (validateValue is null || validateValue());
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

    /// <summary>Gets the most recent local native-operation state; reads do not initiate polling.</summary>
    public NativeProvisioningState State { get; private set; }
    /// <summary>Always false: provisioning completion does not establish intended-identity secret delivery.</summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822", Justification = "The absence of runtime-delivery proof belongs to each operation's evidence contract.")]
    public bool RuntimeDeliveryProven => false;

    /// <summary>One explicit SDK status update, at most two reads including a final resource fetch. No waiting loop.</summary>
    /// <param name="cancellationToken">Cancels this local check, not the underlying administrative operation.</param>
    /// <returns>Success, Pending or a bounded failure. Deadline expiry is Unavailable; receipt evidence is not rewritten.</returns>
    /// <exception cref="OperationCanceledException">Caller cancellation was observed.</exception>
    public async ValueTask<SecretStatus> CheckStatusAsync(CancellationToken cancellationToken = default)
    {
        using var deadline = new CancellationTokenSource(_timeout, _time);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        bool entered = false;
        try
        {
            await _gate.WaitAsync(linked.Token).ConfigureAwait(false);
            entered = true;
            if (_validatedSuccess || State is NativeProvisioningState.Failed or NativeProvisioningState.Canceled)
            {
                linked.Token.ThrowIfCancellationRequested();
                return _validatedSuccess ? SecretStatus.Success : SecretStatus.Unknown;
            }

            _transport.CheckingStatus = true;
            _transport.StatusRequests = 0;
            _transport.LastOperationState = NativeProvisioningState.Unknown;
            await _update(linked.Token).ConfigureAwait(false);
            if (_transport.LastOperationState != NativeProvisioningState.Unknown)
            {
                State = _transport.LastOperationState;
            }
            linked.Token.ThrowIfCancellationRequested();
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
                return SecretStatus.Unknown;
            }

            linked.Token.ThrowIfCancellationRequested();
            State = NativeProvisioningState.Succeeded;
            _validatedSuccess = true;
            return SecretStatus.Success;
        }
        catch (OperationCanceledException)
        {
            if (entered && _transport.LastOperationState != NativeProvisioningState.Unknown)
                State = _transport.LastOperationState;
            cancellationToken.ThrowIfCancellationRequested();
            return SecretStatus.Unavailable;
        }
        catch (Exception exception)
        {
            if (entered && _transport.LastOperationState != NativeProvisioningState.Unknown)
            {
                State = _transport.LastOperationState;
            }

            cancellationToken.ThrowIfCancellationRequested();
            return deadline.IsCancellationRequested ? SecretStatus.Unavailable : ControlledTransport.Failure(exception);
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

    /// <summary>Returns only provisioning state, without status URLs or resource coordinates.</summary>
    public override string ToString() => $"[ManagementOperation:{State}]";
}
