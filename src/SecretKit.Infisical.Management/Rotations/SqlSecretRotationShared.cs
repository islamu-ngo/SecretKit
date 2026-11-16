using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>A supplied nullable SQL rotation description; no wrapper means omission.</summary>
public sealed class SqlRotationNullableText
{
    /// <summary>Captures a bounded description; a null value explicitly sends JSON null rather than omitting the wrapper.</summary>
    public SqlRotationNullableText(string? value)
    {
        if (value?.Length > 16384) throw new ArgumentException("Invalid SQL rotation text budget.");
        Value = value;
    }
    /// <summary>Gets the explicit description value, including null.</summary>
    [JsonIgnore] public string? Value { get; }
    /// <summary>Returns a marker without description text.</summary>
    public override string ToString() => "[SqlRotationNullableText]";
}

/// <summary>Published numeric password requirements across SQL rotation dialects; fractional numbers are preserved.</summary>
/// <remarks>Unknown response fields in the requirements or required counts fail closed as Unknown.</remarks>
public sealed class SqlRotationPasswordRequirements
{
    /// <summary>Captures native numeric password requirements without rounding fractional values.</summary>
    public SqlRotationPasswordRequirements(double length, double digits, double lowercase,
        double symbols, double uppercase, string? allowedSymbols = null)
    {
        SqlSecretRotationShared.Validate(length, digits, lowercase, symbols, uppercase, allowedSymbols);
        Length = length;
        Digits = digits;
        Lowercase = lowercase;
        Symbols = symbols;
        Uppercase = uppercase;
        AllowedSymbols = allowedSymbols;
    }
    internal SqlRotationPasswordRequirements(JsonElement value)
    {
        (Length, Digits, Lowercase, Symbols, Uppercase, AllowedSymbols) = SqlSecretRotationShared.Read(value);
    }
    /// <summary>Gets the native requested password length.</summary>
    [JsonIgnore] public double Length { get; }
    /// <summary>Gets the required digit count.</summary>
    [JsonIgnore] public double Digits { get; }
    /// <summary>Gets the required lowercase-character count.</summary>
    [JsonIgnore] public double Lowercase { get; }
    /// <summary>Gets the required symbol count.</summary>
    [JsonIgnore] public double Symbols { get; }
    /// <summary>Gets the required uppercase-character count.</summary>
    [JsonIgnore] public double Uppercase { get; }
    /// <summary>Gets allowed symbol text, or null when omitted.</summary>
    [JsonIgnore] public string? AllowedSymbols { get; }
    internal void Write(Utf8JsonWriter writer) =>
        SqlSecretRotationShared.Write(writer, Length, Digits, Lowercase, Symbols, Uppercase, AllowedSymbols);
    /// <summary>Returns a marker without password-generation settings.</summary>
    public override string ToString() => "[SqlRotationPasswordRequirements]";
}

/// <summary>Native UTC rotation time fields shared across SQL rotation dialects; numeric values are preserved.</summary>
public sealed class SqlRotationTime
{
    /// <summary>Captures hours from 0 through 23 and minutes from 0 through 59.</summary>
    public SqlRotationTime(double hours, double minutes)
    {
        SqlSecretRotationShared.InputNumber(hours, 0, 23);
        SqlSecretRotationShared.InputNumber(minutes, 0, 59);
        Hours = hours;
        Minutes = minutes;
    }
    internal SqlRotationTime(JsonElement value, bool strictFields = false)
    {
        if (strictFields) SqlSecretRotationShared.Only(value, "hours", "minutes");
        Hours = SqlSecretRotationShared.Number(value, "hours", 0, 23);
        Minutes = SqlSecretRotationShared.Number(value, "minutes", 0, 59);
    }
    /// <summary>Gets the native UTC hour value.</summary>
    [JsonIgnore] public double Hours { get; }
    /// <summary>Gets the native UTC minute value.</summary>
    [JsonIgnore] public double Minutes { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("rotateAtUtc");
        writer.WriteNumber("hours", Hours);
        writer.WriteNumber("minutes", Minutes);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without schedule details.</summary>
    public override string ToString() => "[SqlRotationTime]";
}

/// <summary>Destination secret key mapping shared across SQL rotation dialects, not generated credentials.</summary>
public sealed class SqlRotationSecretsMapping
{
    /// <summary>Captures destination secret key names, not username or password values.</summary>
    public SqlRotationSecretsMapping(string username, string password)
    {
        ManagementJson.Text(username, 16384);
        ManagementJson.Text(password, 16384);
        Username = username;
        Password = password;
    }
    internal SqlRotationSecretsMapping(JsonElement value, bool nonempty = true, bool strictFields = false)
    {
        if (strictFields) SqlSecretRotationShared.Only(value, "username", "password");
        Username = nonempty ? ManagementJson.Nonempty(value, "username") : ManagementJson.Required(value, "username");
        Password = nonempty ? ManagementJson.Nonempty(value, "password") : ManagementJson.Required(value, "password");
    }
    /// <summary>Gets the destination key name for generated usernames.</summary>
    [JsonIgnore] public string Username { get; }
    /// <summary>Gets the destination key name for generated passwords.</summary>
    [JsonIgnore] public string Password { get; }
    internal void Write(Utf8JsonWriter writer)
    {
        writer.WriteStartObject("secretsMapping");
        writer.WriteString("username", Username);
        writer.WriteString("password", Password);
        writer.WriteEndObject();
    }
    /// <summary>Returns a marker without secret key mappings.</summary>
    public override string ToString() => "[SqlRotationSecretsMapping]";
}

internal static partial class SqlSecretRotationShared
{
    private const string SymbolPattern = """\A[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?~]+\z""";

    [GeneratedRegex(SymbolPattern, RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)]
    private static partial Regex SymbolRegex();

    internal static void InputNumber(double value, double minimum, double maximum = double.MaxValue)
    {
        if (!InRange(value, minimum, maximum))
            throw new ArgumentException("Invalid SQL rotation number.");
    }

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

    internal static double Number(JsonElement value, string field, double minimum, double maximum = double.MaxValue)
    {
        double result = ManagementJson.Number(value, field);
        return InRange(result, minimum, maximum) ? result : throw new ManagementContractException(SecretStatus.Unknown);
    }

    private static bool ValidSymbols(string value) => value.Length <= 16384 && SymbolRegex().IsMatch(value);

    internal static void Only(JsonElement value, params string[] fields)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            value.EnumerateObject().Any(property => !fields.Contains(property.Name, StringComparer.Ordinal)))
            throw new ManagementContractException(SecretStatus.Unknown);
    }
}
