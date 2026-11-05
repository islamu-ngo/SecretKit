using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A protected, detached JSON number returned by a bounded management response.</summary>
/// <remarks>
/// The original token is canonical. Explicit exports create ordinary managed strings.
/// Checked access never rounds, underflows or expands an unbounded exponent.
/// The default value is uninitialized, not zero; no numeric equality or implicit conversion is defined.
/// </remarks>
public readonly struct ManagementNumber
{
    private readonly string? _token;

    internal ManagementNumber(JsonElement value, bool nonnegative = false)
    {
        if (value.ValueKind != JsonValueKind.Number)
            throw new ManagementContractException(SecretStatus.Unknown);
        _token = value.GetRawText();
        if (nonnegative && _token[0] == '-')
        {
            foreach (char digit in _token.AsSpan(1))
            {
                if (digit is 'e' or 'E') break;
                if (digit is >= '1' and <= '9')
                    throw new ManagementContractException(SecretStatus.Unknown);
            }
        }
    }

    /// <summary>Gets whether a response supplied this number; default is uninitialized.</summary>
    [JsonIgnore] public bool IsInitialized => _token is not null;

    /// <summary>Explicitly exports the original JSON numeric token without normalization or rounding.</summary>
    /// <exception cref="InvalidOperationException">This value is uninitialized.</exception>
    public string Export() => _token ?? throw new InvalidOperationException("Uninitialized management number.");

    /// <summary>Returns the exact signed 64-bit integer, rejecting fractional values and overflow.</summary>
    /// <exception cref="InvalidOperationException">This value is uninitialized.</exception>
    /// <exception cref="OverflowException">The number is not exactly representable as a signed 64-bit integer.</exception>
    public long GetInt64()
    {
        _ = Export();
        return TryGetInt64(out long value) ? value :
            throw new OverflowException("Management number is not an exact Int64.");
    }

    /// <summary>Returns the exact decimal, rejecting range loss, precision loss and nonzero underflow.</summary>
    /// <exception cref="InvalidOperationException">This value is uninitialized.</exception>
    /// <exception cref="OverflowException">The number is not exactly representable as a decimal.</exception>
    public decimal GetDecimal()
    {
        _ = Export();
        return TryGetDecimal(out decimal value) ? value :
            throw new OverflowException("Management number is not an exact Decimal.");
    }

    /// <summary>Attempts exact signed 64-bit access; false includes uninitialized, fractional and out-of-range values.</summary>
    public bool TryGetInt64(out long value)
    {
        value = default;
        // Every Int64 is exactly representable as decimal. Testing integrality and
        // bounds after exact decimal conversion cannot discard a valid Int64.
        if (!TryGetDecimal(out decimal number) || number < long.MinValue || number > long.MaxValue ||
            decimal.Truncate(number) != number)
            return false;
        value = (long)number;
        return true;
    }

    /// <summary>Attempts exact decimal access; false never consumes or changes the retained token.</summary>
    public bool TryGetDecimal(out decimal value)
    {
        value = default;
        if (_token is null) return false;
        ReadOnlySpan<char> token = _token;
        bool negative = token[0] == '-';
        int start = negative ? 1 : 0;
        int exponentStart = token.IndexOfAny('e', 'E');
        int end = exponentStart < 0 ? token.Length : exponentStart;
        int digits = 0, fraction = 0, first = -1, last = -1;
        bool afterPoint = false;
        for (int i = start; i < end; i++)
        {
            if (token[i] == '.')
            {
                afterPoint = true;
                continue;
            }
            if (token[i] != '0')
            {
                if (first < 0) first = digits;
                last = digits;
            }
            digits++;
            if (afterPoint) fraction++;
        }
        // Zero is exact for every exponent, including exponents too large for Int64.
        if (first < 0) return true;
        if (last - first + 1 > 29) return false;

        long exponent = 0;
        if (exponentStart >= 0)
        {
            int cursor = exponentStart + 1;
            bool exponentNegative = token[cursor] == '-';
            if (token[cursor] is '+' or '-') cursor++;
            // Fractional digits and trailing zeroes can shift the exponent by at
            // most token.Length. Beyond this cap neither can restore decimal range.
            long cap = (long)token.Length + 29;
            for (; cursor < token.Length; cursor++)
                exponent = Math.Min(cap, exponent * 10 + token[cursor] - '0');
            if (exponentNegative) exponent = -exponent;
        }
        exponent += digits - last - 1L - fraction;
        if (exponent is < -28 or > 28) return false;

        UInt128 coefficient = 0;
        int position = 0;
        for (int i = start; i < end; i++)
        {
            if (token[i] == '.') continue;
            if (position >= first && position <= last)
                coefficient = coefficient * 10 + (uint)(token[i] - '0');
            position++;
        }
        // The coefficient has no trailing zeroes. Negative scale below -28 cannot
        // be reduced exactly; coefficient overflow cannot be fixed by rounding.
        UInt128 maximum = ((UInt128)1 << 96) - 1;
        while (exponent > 0)
        {
            if (coefficient > maximum / 10) return false;
            coefficient *= 10;
            exponent--;
        }
        if (coefficient > maximum) return false;
        value = new decimal(unchecked((int)(uint)coefficient),
            unchecked((int)(uint)(coefficient >> 32)),
            unchecked((int)(uint)(coefficient >> 64)), negative, (byte)-exponent);
        return true;
    }

    /// <summary>Returns a marker without the numeric token.</summary>
    public override string ToString() => "[ManagementNumber]";
}
