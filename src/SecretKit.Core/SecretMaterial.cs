using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Owns clearable character storage. Explicit exports have independent lifetimes.</summary>
/// <remarks>Dispose this owner to clear its array. Disposal cannot erase inputs, earlier copies or exported strings.</remarks>
public sealed class SecretMaterial : IDisposable
{
    private readonly object _gate = new();
    private char[]? _characters;

    private SecretMaterial(char[] characters) => _characters = characters;

    /// <summary>Copies supplied text; neither this object nor disposal can erase the supplied text.</summary>
    /// <param name="text">Characters to copy into independent owned storage.</param>
    /// <returns>A material owner that the caller must dispose.</returns>
    public static SecretMaterial FromText(ReadOnlySpan<char> text) => new(text.ToArray());

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
