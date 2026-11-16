using System.Buffers;
using System.Diagnostics.CodeAnalysis;

namespace SecretKit.Core;

/// <summary>A bounded provider correlation identifier requiring explicit disclosure.</summary>
/// <remarks>Syntax does not establish nonsensitivity, authority, idempotency or permission to replay.</remarks>
public sealed class SecretCorrelationId
{
    private static readonly SearchValues<char> AllowedCharacters =
        SearchValues.Create("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_.");
    private readonly string _value;

    /// <summary>Retains 1..128 ASCII letters, digits, hyphens, underscores or dots.</summary>
    /// <exception cref="ArgumentException">The identifier does not satisfy the bounded syntax.</exception>
    public SecretCorrelationId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!IsValid(value))
            throw new ArgumentException("Invalid correlation identifier.", nameof(value));
        _value = value;
    }

    /// <summary>Validates and wraps a candidate correlation identifier without throwing on malformed wire values.</summary>
    public static bool TryCreate(string? value, [NotNullWhen(true)] out SecretCorrelationId? correlation)
    {
        if (value is not null && IsValid(value))
        {
            correlation = new(value, validated: true);
            return true;
        }
        correlation = null;
        return false;
    }

    private SecretCorrelationId(string value, bool validated) => _value = value;

    private static bool IsValid(string value) =>
        value.Length is >= 1 and <= 128 && !value.AsSpan().ContainsAnyExcept(AllowedCharacters);

    /// <summary>Explicitly exports the identifier as an ordinary string under caller custody.</summary>
    public string Reveal() => _value;

    /// <summary>Returns a fixed marker without disclosing the identifier.</summary>
    public override string ToString() => "[SecretCorrelationId]";
}
