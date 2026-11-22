using System.Buffers;
using System.Security.Cryptography;

namespace SecretKit.Internal;

// Pooled, bounded request writer. Utf8JsonWriter may write reserved bytes past the
// committed count, so every rented array is zeroed in full before it is returned.
internal sealed class BoundedRequestBuffer(int maximum, ArrayPool<byte>? pool = null) : IBufferWriter<byte>, IDisposable
{
    private readonly ArrayPool<byte> _pool = pool ?? ArrayPool<byte>.Shared;
    private byte[] _buffer = [];
    private int _written;

    internal ReadOnlySpan<byte> WrittenSpan => _buffer.AsSpan(0, _written);

    public void Advance(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);
        if (count > maximum - _written)
            throw new NotSupportedException("Request body exceeds its byte budget.");
        _written += count;
    }

    public Memory<byte> GetMemory(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _buffer.AsMemory(_written);
    }

    public Span<byte> GetSpan(int sizeHint = 0)
    {
        EnsureCapacity(sizeHint);
        return _buffer.AsSpan(_written);
    }

    private void EnsureCapacity(int sizeHint)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(sizeHint);
        int required = Math.Max(1, sizeHint);
        // Utf8JsonWriter reserves for six-byte JSON escaping even for ASCII.
        // Permit that bounded reservation, but enforce actual bytes in Advance.
        int reservationLimit = checked((maximum - _written) * 6 + 4096);
        if (required > reservationLimit)
            throw new NotSupportedException("Request token exceeds its byte budget.");
        int needed = checked(_written + required);
        if (needed <= _buffer.Length) return;
        int capacity = Math.Min(checked(maximum * 6 + 4096),
            Math.Max(needed, Math.Max(4096, _buffer.Length * 2)));
        byte[] replacement = _pool.Rent(capacity);
        _buffer.AsSpan(0, _written).CopyTo(replacement);
        Release(_buffer);
        _buffer = replacement;
    }

    internal byte[] ToArray() => WrittenSpan.ToArray();

    public void Dispose()
    {
        Release(_buffer);
        _buffer = [];
        _written = 0;
    }

    private void Release(byte[] buffer)
    {
        if (buffer.Length == 0) return;
        CryptographicOperations.ZeroMemory(buffer);
        _pool.Return(buffer);
    }
}
