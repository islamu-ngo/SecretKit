using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Unicode;

namespace SecretKit.Core;

/// <summary>Owns pinned, clearable UTF-8 storage. Explicit exports have independent lifetimes.</summary>
/// <remarks>Dispose this owner to clear its array. Disposal cannot erase inputs, earlier copies or exported strings.</remarks>
public sealed class SecretMaterial : IDisposable
{
    private readonly Lock _gate = new();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private byte[]? _utf8;

    private SecretMaterial(byte[] utf8) => _utf8 = utf8;

    /// <summary>Copies supplied text; neither this object nor disposal can erase the supplied text.</summary>
    /// <param name="text">Characters to copy into independent owned storage.</param>
    /// <returns>A material owner that the caller must dispose.</returns>
    /// <exception cref="ArgumentException">The input is malformed UTF-16; rejected characters are not retained in the exception.</exception>
    public static SecretMaterial FromText(ReadOnlySpan<char> text)
    {
        byte[]? buffer = null;
        try
        {
            buffer = GC.AllocateArray<byte>(StrictUtf8.GetByteCount(text), pinned: true);
            StrictUtf8.GetBytes(text, buffer);
            var material = new SecretMaterial(buffer);
            buffer = null;
            return material;
        }
        catch (EncoderFallbackException)
        {
            throw new ArgumentException("Material must contain valid UTF-16.", nameof(text));
        }
        finally
        {
            if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Validates and copies UTF-8 input into independent pinned storage.</summary>
    /// <param name="utf8">Encoded text to copy.</param>
    /// <returns>An independently disposable material owner.</returns>
    /// <exception cref="ArgumentException">The input is malformed UTF-8; no rejected input is retained in the exception.</exception>
    public static SecretMaterial FromUtf8(ReadOnlySpan<byte> utf8)
    {
        if (!Utf8.IsValid(utf8))
            throw new ArgumentException("Material must contain valid UTF-8.", nameof(utf8));
        byte[]? buffer = GC.AllocateArray<byte>(utf8.Length, pinned: true);
        try
        {
            utf8.CopyTo(buffer);
            var material = new SecretMaterial(buffer);
            buffer = null;
            return material;
        }
        finally
        {
            if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
        }
    }

    /// <summary>Gets the encoded payload size without exporting a string.</summary>
    /// <returns>The number of UTF-8 bytes.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public int GetUtf8ByteCount()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_utf8 is null, this);
            return _utf8.Length;
        }
    }

    /// <summary>Copies UTF-8 to caller-owned storage if it fits.</summary>
    /// <param name="destination">Caller-owned destination.</param>
    /// <param name="bytesWritten">The complete byte count or zero on capacity failure.</param>
    /// <returns>Whether the complete value fitted.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public bool TryCopyUtf8To(Span<byte> destination, out int bytesWritten)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_utf8 is null, this);
            bytesWritten = 0;
            if (!_utf8.AsSpan().TryCopyTo(destination)) return false;
            bytesWritten = _utf8.Length;
            return true;
        }
    }

    /// <summary>Returns an independent, caller-owned material object.</summary>
    /// <returns>A copy that survives disposal of this owner and must be disposed separately.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public SecretMaterial Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_utf8 is null, this);
            byte[]? buffer = GC.AllocateArray<byte>(_utf8.Length, pinned: true);
            try
            {
                _utf8.CopyTo(buffer, 0);
                var material = new SecretMaterial(buffer);
                buffer = null;
                return material;
            }
            finally
            {
                if (buffer is not null) CryptographicOperations.ZeroMemory(buffer);
            }
        }
    }

    /// <summary>Deliberately exports a plaintext string that cannot be cleared by this owner.</summary>
    /// <returns>An ordinary managed string whose lifetime is outside this owner's control.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public string Reveal()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_utf8 is null, this);
            return StrictUtf8.GetString(_utf8);
        }
    }

    /// <summary>Exports independent characters. The caller is responsible for clearing them.</summary>
    /// <returns>A new array; changing or clearing it does not change this owner's material.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public char[] ExportCharacters()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_utf8 is null, this);
            return StrictUtf8.GetChars(_utf8);
        }
    }

    /// <summary>Consumes a temporary character snapshot outside the owner's lock.</summary>
    /// <param name="action">A synchronous callback; the span is valid only during its invocation.</param>
    /// <remarks>The snapshot is cleared on return or exception. Copies made by the callback remain caller-owned.</remarks>
    public void Use(SecretSpanAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        Use(action, static (span, callback) => { callback(span); return 0; });
    }

    /// <summary>Consumes a temporary character snapshot with caller-supplied state.</summary>
    /// <typeparam name="TState">The caller's state type.</typeparam>
    /// <param name="state">State supplied to the callback.</param>
    /// <param name="action">A synchronous callback; the span is valid only during its invocation.</param>
    public void Use<TState>(TState state, SecretSpanAction<TState> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        Use((state, action), static (span, context) => { context.action(span, context.state); return 0; });
    }

    /// <summary>Projects a temporary character snapshot outside the owner's lock.</summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="function">A synchronous callback; the span is valid only during its invocation.</param>
    /// <returns>The callback result. Any copied material becomes caller-owned.</returns>
    public TResult Use<TResult>(SecretSpanFunc<TResult> function)
    {
        ArgumentNullException.ThrowIfNull(function);
        return Use(function, static (span, callback) => callback(span));
    }

    /// <summary>Projects a temporary character snapshot with caller-supplied state outside the owner's lock.</summary>
    /// <typeparam name="TState">The caller's state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="state">State supplied to the callback.</param>
    /// <param name="function">A synchronous callback; the span is valid only during its invocation.</param>
    /// <returns>The callback result. Any copied material becomes caller-owned.</returns>
    /// <exception cref="ArgumentNullException">The callback is null.</exception>
    /// <exception cref="ObjectDisposedException">This owner was disposed before the snapshot was taken.</exception>
    /// <remarks>Concurrent or reentrant disposal does not invalidate the callback's snapshot. The snapshot is cleared even if the callback throws.</remarks>
    public TResult Use<TState, TResult>(TState state, SecretSpanFunc<TState, TResult> function)
    {
        ArgumentNullException.ThrowIfNull(function);
        Span<char> snapshot = stackalloc char[256];
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_utf8 is null, this);
                int length = StrictUtf8.GetCharCount(_utf8);
                if (length > snapshot.Length) snapshot = GC.AllocateArray<char>(length, pinned: true);
                snapshot = snapshot[..length];
                StrictUtf8.GetChars(_utf8, snapshot);
            }
            return function(snapshot, state);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(snapshot));
        }
    }

    /// <summary>Consumes a temporary UTF-8 snapshot outside the owner's lock.</summary>
    /// <param name="action">A synchronous callback; the span is valid only during its invocation.</param>
    /// <remarks>The snapshot is cleared on return or exception. Copies made by the callback remain caller-owned.</remarks>
    public void UseUtf8(SecretUtf8SpanAction action)
    {
        ArgumentNullException.ThrowIfNull(action);
        UseUtf8(action, static (span, callback) => { callback(span); return 0; });
    }

    /// <summary>Consumes a temporary UTF-8 snapshot with caller-supplied state.</summary>
    /// <typeparam name="TState">The caller's state type.</typeparam>
    /// <param name="state">State supplied to the callback.</param>
    /// <param name="action">A synchronous callback; the span is valid only during its invocation.</param>
    public void UseUtf8<TState>(TState state, SecretUtf8SpanAction<TState> action)
    {
        ArgumentNullException.ThrowIfNull(action);
        UseUtf8((state, action), static (span, context) => { context.action(span, context.state); return 0; });
    }

    /// <summary>Projects a temporary UTF-8 snapshot outside the owner's lock.</summary>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="function">A synchronous callback; the span is valid only during its invocation.</param>
    /// <returns>The callback result. Any copied material becomes caller-owned.</returns>
    public TResult UseUtf8<TResult>(SecretUtf8SpanFunc<TResult> function)
    {
        ArgumentNullException.ThrowIfNull(function);
        return UseUtf8(function, static (span, callback) => callback(span));
    }

    /// <summary>Projects a temporary UTF-8 snapshot with caller-supplied state outside the owner's lock.</summary>
    /// <typeparam name="TState">The caller's state type.</typeparam>
    /// <typeparam name="TResult">The result type.</typeparam>
    /// <param name="state">State supplied to the callback.</param>
    /// <param name="function">A synchronous callback; the span is valid only during its invocation.</param>
    /// <returns>The callback result. Any copied material becomes caller-owned.</returns>
    /// <exception cref="ArgumentNullException">The callback is null.</exception>
    /// <exception cref="ObjectDisposedException">This owner was disposed before the snapshot was taken.</exception>
    /// <remarks>Concurrent or reentrant disposal does not invalidate the callback's snapshot. The snapshot is cleared even if the callback throws.</remarks>
    public TResult UseUtf8<TState, TResult>(TState state, SecretUtf8SpanFunc<TState, TResult> function)
    {
        ArgumentNullException.ThrowIfNull(function);
        Span<byte> snapshot = stackalloc byte[256];
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_utf8 is null, this);
                int length = _utf8.Length;
                if (length > snapshot.Length) snapshot = GC.AllocateArray<byte>(length, pinned: true);
                snapshot = snapshot[..length];
                _utf8.AsSpan().CopyTo(snapshot);
            }
            return function(snapshot, state);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(snapshot);
        }
    }

    /// <summary>Clears owned UTF-8 bytes and prevents further copies or exports; repeated disposal is harmless.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_utf8 is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(_utf8);
            _utf8 = null;
        }
    }

    /// <summary>Returns a fixed marker without revealing material, including after disposal.</summary>
    public override string ToString() => "[SecretMaterial]";
}
