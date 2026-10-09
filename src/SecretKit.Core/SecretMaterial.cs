using System.Text.Json.Serialization;

namespace SecretKit.Core;

/// <summary>Owns clearable character storage. Explicit exports have independent lifetimes.</summary>
public sealed class SecretMaterial : IDisposable
{
    private readonly object _gate = new();
    private char[]? _characters;

    private SecretMaterial(char[] characters) => _characters = characters;

    /// <summary>Copies supplied text; neither this object nor disposal can erase the supplied text.</summary>
    public static SecretMaterial FromText(ReadOnlySpan<char> text) => new(text.ToArray());

    /// <summary>Returns an independent, caller-owned material object.</summary>
    public SecretMaterial Copy()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return new SecretMaterial((char[])_characters.Clone());
        }
    }

    /// <summary>Deliberately exports a plaintext string that cannot be cleared by this owner.</summary>
    public string Reveal()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return new string(_characters);
        }
    }

    /// <summary>Exports independent characters. The caller is responsible for clearing them.</summary>
    public char[] ExportCharacters()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_characters is null, this);
            return (char[])_characters.Clone();
        }
    }

    /// <inheritdoc />
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

    /// <inheritdoc />
    public override string ToString() => "[SecretMaterial]";
}
