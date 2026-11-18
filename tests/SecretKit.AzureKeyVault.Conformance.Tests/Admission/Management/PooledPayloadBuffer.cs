using System.Buffers;
using System.Security.Cryptography;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Logical capacity stays bounded even when the pool supplies a larger array.
// Consumers keep this owner alive until every borrowed view has drained.
internal sealed class PooledPayloadBuffer(int capacity) : IDisposable
{
    private byte[]? storage = ArrayPool<byte>.Shared.Rent(capacity);
    internal byte[] Array => storage ?? throw new ObjectDisposedException(nameof(PooledPayloadBuffer));
    internal Memory<byte> Memory => Array.AsMemory(0, capacity);

    internal async ValueTask<int> ReadAsync(Stream input, CancellationToken token)
    {
        int count = 0;
        while (count < capacity)
        {
            int read = await input.ReadAsync(Memory[count..], token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (read == 0) break;
            count += read;
        }
        return count;
    }

    public void Dispose()
    {
        byte[]? released = Interlocked.Exchange(ref storage, null);
        if (released is null) return;
        // A stream may write into capacity and then throw without reporting a count.
        CryptographicOperations.ZeroMemory(released);
        ArrayPool<byte>.Shared.Return(released);
    }
}
