using System.Buffers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace SecretKit.Core;

/// <summary>Owns clearable character storage. Explicit exports have independent lifetimes.</summary>
/// <remarks>Dispose this owner to clear its array. Disposal cannot erase inputs, earlier copies or exported strings.</remarks>
public sealed class SecretMaterial : IDisposable
{
    private readonly object _gate = new();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private char[]? _characters;

    private SecretMaterial(char[] characters) => _characters = characters;

    /// <summary>Copies supplied text; neither this object nor disposal can erase the supplied text.</summary>
    /// <param name="text">Characters to copy into independent owned storage.</param>
    /// <returns>A material owner that the caller must dispose.</returns>
    public static SecretMaterial FromText(ReadOnlySpan<char> text) => new(text.ToArray());

    /// <summary>Copies UTF-8 input into independent character storage.</summary>
    /// <param name="utf8">Encoded text to copy.</param>
    /// <returns>An independently disposable material owner.</returns>
    /// <exception cref="ArgumentException">The input is malformed UTF-8; no rejected input is retained in the exception.</exception>
    public static SecretMaterial FromUtf8(ReadOnlySpan<byte> utf8)
    {
        char[]? characters = null;
        try
        {
            characters = new char[StrictUtf8.GetCharCount(utf8)];
            StrictUtf8.GetChars(utf8, characters);
            return new SecretMaterial(characters);
        }
        catch (DecoderFallbackException)
        {
            if (characters is not null)
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(characters.AsSpan()));
            throw new ArgumentException("Material must contain valid UTF-8.", nameof(utf8));
        }
    }

    /// <summary>Gets the encoded payload size without exporting a string.</summary>
    /// <returns>The number of UTF-8 bytes.</returns>
    /// <exception cref="ArgumentException">Owned text contains invalid UTF-16; no rejected characters are retained in the exception.</exception>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public int GetUtf8ByteCount()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            try
            {
                return StrictUtf8.GetByteCount(_characters);
            }
            catch (EncoderFallbackException)
            {
                throw new ArgumentException("Material must contain valid UTF-16.");
            }
        }
    }

    /// <summary>Copies UTF-8 to caller-owned storage if it fits.</summary>
    /// <param name="destination">Caller-owned destination.</param>
    /// <param name="bytesWritten">The complete byte count or zero on capacity failure.</param>
    /// <returns>Whether the complete value fitted.</returns>
    /// <exception cref="ArgumentException">Owned text contains invalid UTF-16. The destination remains unchanged.</exception>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public bool TryCopyUtf8To(Span<byte> destination, out int bytesWritten)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            bytesWritten = 0;
            try
            {
                if (StrictUtf8.GetByteCount(_characters) > destination.Length)
                    return false;
                bytesWritten = StrictUtf8.GetBytes(_characters, destination);
                return true;
            }
            catch (EncoderFallbackException)
            {
                throw new ArgumentException("Material must contain valid UTF-16.");
            }
        }
    }

    /// <summary>Returns an independent, caller-owned material object.</summary>
    /// <returns>A copy that survives disposal of this owner and must be disposed separately.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public SecretMaterial Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return new SecretMaterial((char[])_characters.Clone());
        }
    }

    /// <summary>Deliberately exports a plaintext string that cannot be cleared by this owner.</summary>
    /// <returns>An ordinary managed string whose lifetime is outside this owner's control.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public string Reveal()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return new string(_characters);
        }
    }

    /// <summary>Exports independent characters. The caller is responsible for clearing them.</summary>
    /// <returns>A new array; changing or clearing it does not change this owner's material.</returns>
    /// <exception cref="ObjectDisposedException">This owner has been disposed.</exception>
    public char[] ExportCharacters()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return (char[])_characters.Clone();
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
        char[]? snapshot = null;
        int length = 0;
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_characters is null, this);
                length = _characters.Length;
                snapshot = ArrayPool<char>.Shared.Rent(length);
                _characters.AsSpan().CopyTo(snapshot);
            }
            return function(snapshot.AsSpan(0, length), state);
        }
        finally
        {
            if (snapshot is not null)
            {
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(snapshot.AsSpan(0, length)));
                ArrayPool<char>.Shared.Return(snapshot);
            }
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
    /// <exception cref="ArgumentException">Owned text contains invalid UTF-16; no rejected text is retained in the exception.</exception>
    /// <exception cref="ObjectDisposedException">This owner was disposed before the snapshot was taken.</exception>
    /// <remarks>Concurrent or reentrant disposal does not invalidate the callback's snapshot. The snapshot is cleared even if the callback throws.</remarks>
    public TResult UseUtf8<TState, TResult>(TState state, SecretUtf8SpanFunc<TState, TResult> function)
    {
        ArgumentNullException.ThrowIfNull(function);
        byte[]? snapshot = null;
        int length = 0;
        try
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_characters is null, this);
                try
                {
                    length = StrictUtf8.GetByteCount(_characters);
                    snapshot = ArrayPool<byte>.Shared.Rent(length);
                    StrictUtf8.GetBytes(_characters, snapshot);
                }
                catch (EncoderFallbackException)
                {
                    throw new ArgumentException("Material must contain valid UTF-16.");
                }
            }
            return function(snapshot.AsSpan(0, length), state);
        }
        finally
        {
            if (snapshot is not null)
            {
                CryptographicOperations.ZeroMemory(snapshot.AsSpan(0, length));
                ArrayPool<byte>.Shared.Return(snapshot);
            }
        }
    }

    /// <summary>Clears owned characters and prevents further copies or exports; repeated disposal is harmless.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_characters is null)
            {
                return;
            }

            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(_characters.AsSpan()));
            _characters = null;
        }
    }

    /// <summary>Returns a fixed marker without revealing material, including after disposal.</summary>
    public override string ToString() => "[SecretMaterial]";
}
