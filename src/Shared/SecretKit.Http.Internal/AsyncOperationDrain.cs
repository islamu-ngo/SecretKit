namespace SecretKit.Internal;

internal sealed class AsyncOperationDrain
{
    private readonly Lock _gate = new();
    private int _active;
    private TaskCompletionSource? _closed;

    internal IDisposable Enter()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_closed is not null, this);
            var lease = new Lease(this);
            _active++;
            return lease;
        }
    }

    internal Task Close()
    {
        lock (_gate)
        {
            if (_closed is null)
            {
                _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
                if (_active == 0) _closed.SetResult();
            }
            return _closed.Task;
        }
    }

    private sealed class Lease(AsyncOperationDrain owner) : IDisposable
    {
        private AsyncOperationDrain? _owner = owner;

        public void Dispose()
        {
            AsyncOperationDrain? current = Interlocked.Exchange(ref _owner, null);
            if (current is null) return;
            lock (current._gate)
            {
                if (--current._active == 0) current._closed?.TrySetResult();
            }
        }
    }
}
