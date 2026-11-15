namespace SecretKit.Core;

/// <summary>A bounded provider correlation identifier requiring explicit disclosure.</summary>
/// <remarks>Syntax does not establish nonsensitivity, authority, idempotency or permission to replay.</remarks>
public sealed class SecretCorrelationId
{
    private readonly string _value;

    /// <summary>Retains 1..128 ASCII letters, digits, hyphens, underscores or dots.</summary>
    /// <exception cref="ArgumentException">The identifier does not satisfy the bounded syntax.</exception>
    public SecretCorrelationId(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length is < 1 or > 128 ||
            value.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_' or '.')))
            throw new ArgumentException("Invalid correlation identifier.", nameof(value));
        _value = value;
    }

    /// <summary>Explicitly exports the identifier as an ordinary string under caller custody.</summary>
    public string Reveal() => _value;

    /// <summary>Returns a fixed marker without disclosing the identifier.</summary>
    public override string ToString() => "[SecretCorrelationId]";
}
