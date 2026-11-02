using System.Text.Json;
using System.Text.RegularExpressions;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

internal static class SqlSecretRotationShared
{
    private const string SymbolPattern = """[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~]""";

    internal static void Validate(double length, double digits, double lowercase,
        double symbols, double uppercase, string? allowedSymbols)
    {
        if (!InRange(length, 1, 250) || !InRange(digits, 0) || !InRange(lowercase, 0) ||
            !InRange(symbols, 0) || !InRange(uppercase, 0))
            throw new ArgumentException("Invalid rotation password number.");
        if (allowedSymbols is not null && !ValidSymbols(allowedSymbols))
            throw new ArgumentException("Invalid rotation symbols.");
    }

    internal static (double Length, double Digits, double Lowercase, double Symbols, double Uppercase,
        string? AllowedSymbols) Read(JsonElement value)
    {
        Only(value, "length", "required", "allowedSymbols");
        JsonElement required = ManagementJson.Object(value, "required");
        Only(required, "digits", "lowercase", "symbols", "uppercase");
        double length = Number(value, "length", 1, 250);
        double digits = Number(required, "digits", 0);
        double lowercase = Number(required, "lowercase", 0);
        double symbols = Number(required, "symbols", 0);
        double uppercase = Number(required, "uppercase", 0);
        string? allowedSymbols = ManagementJson.Optional(value, "allowedSymbols", nullable: false);
        if (allowedSymbols is not null && !ValidSymbols(allowedSymbols))
            throw new ManagementContractException(SecretStatus.Unknown);
        return (length, digits, lowercase, symbols, uppercase, allowedSymbols);
    }

    internal static void Write(Utf8JsonWriter writer, double length, double digits, double lowercase,
        double symbols, double uppercase, string? allowedSymbols)
    {
        writer.WriteStartObject("passwordRequirements");
        writer.WriteNumber("length", length);
        if (allowedSymbols is not null) writer.WriteString("allowedSymbols", allowedSymbols);
        writer.WriteStartObject("required");
        writer.WriteNumber("digits", digits);
        writer.WriteNumber("lowercase", lowercase);
        writer.WriteNumber("symbols", symbols);
        writer.WriteNumber("uppercase", uppercase);
        writer.WriteEndObject();
        writer.WriteEndObject();
    }

    private static bool InRange(double value, double minimum, double maximum = double.MaxValue) =>
        double.IsFinite(value) && value >= minimum && value <= maximum;

    private static double Number(JsonElement value, string field, double minimum, double maximum = double.MaxValue)
    {
        double result = ManagementJson.Number(value, field);
        return InRange(result, minimum, maximum) ? result : throw new ManagementContractException(SecretStatus.Unknown);
    }

    private static bool ValidSymbols(string value) => value.Length <= 16384 &&
        Regex.IsMatch(value, SymbolPattern, RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));

    private static void Only(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            value.EnumerateObject().Any(property => !fields.Contains(property.Name, StringComparer.Ordinal)))
            throw new ManagementContractException(SecretStatus.Unknown);
    }
}
