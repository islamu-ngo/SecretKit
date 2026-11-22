namespace SecretKit.Internal;

internal sealed class ResponseBudgetExceededException() : IOException("Provider response exceeded its configured budget.");

internal sealed class BoundedResponseStream(Stream inner, int maximumBytes) : Stream
{
    private int _read;
    private int _disposed;
    private bool _exceeded;

    public override bool CanRead => _disposed == 0 && inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int count = inner.Read(buffer[..Allowed(buffer.Length)]);
        Observe(count);
        return count;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        int count = await inner.ReadAsync(buffer[..Allowed(buffer.Length)], cancellationToken).ConfigureAwait(false);
        Observe(count);
        return count;
    }

    private int Allowed(int requested)
    {
        ObjectDisposedException.ThrowIf(_disposed != 0, this);
        if (_exceeded) throw new ResponseBudgetExceededException();
        return Math.Min(requested, maximumBytes - _read + 1);
    }

    private void Observe(int count)
    {
        if (count > maximumBytes - _read)
        {
            _exceeded = true;
            throw new ResponseBudgetExceededException();
        }
        _read += count;
    }

    public override void Flush() => inner.Flush();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing && Interlocked.Exchange(ref _disposed, 1) == 0) inner.Dispose();
        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) == 0)
            await inner.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }
}
