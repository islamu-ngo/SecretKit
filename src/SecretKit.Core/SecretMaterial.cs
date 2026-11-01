using System.Text;
using System.Text.Json.Serialization;

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
                Array.Clear(characters);
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

    /// <summary>Clears owned characters and prevents further copies or exports; repeated disposal is harmless.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_characters is null)
            {
                return;
            }

            Array.Clear(_characters);
            _characters = null;
        }
    }

    /// <summary>Returns a fixed marker without revealing material, including after disposal.</summary>
    public override string ToString() => "[SecretMaterial]";
}
