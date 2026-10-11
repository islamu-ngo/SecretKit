using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>
/// Immutable native operation, constructible only through named operation factories.
/// Owns its bounded wire body; dispose it when no longer needed.
/// </summary>
public sealed class ManagementRequest<T> : IDisposable where T : notnull
{
    private readonly object _gate = new();
    private byte[]? _body;
    private bool _disposed;
    internal HttpMethod Method { get; }
    internal string Path { get; }
    internal Func<JsonElement, T> Parse { get; }
    [JsonIgnore] public ManagementTarget Target { get; }
    public string OperationId { get; }
    public bool IsMutation { get; }

    internal ManagementRequest(string operationId, HttpMethod method, string path,
        ManagementTarget target, Action<Utf8JsonWriter>? writeBody, Func<JsonElement, T> parse,
        bool mutation = true)
    {
        OperationId = operationId;
        Method = method;
        Path = path;
        Target = target;
        Parse = root =>
        {
            T result = parse(root);
            try
            {
                ManagementResponseContracts.Validate(operationId, root);
                ManagementResponseUuids.Validate(operationId, root);
                ManagementResponseDates.Validate(operationId, root);
                return result;
            }
            catch
            {
                (result as IDisposable)?.Dispose();
                throw;
            }
        };
        IsMutation = mutation;
        if (writeBody is not null)
        {
            // The fixed backing array bounds serialization before any identity or I/O is used.
            byte[] storage = new byte[64 * 1024];
            try
            {
                using var stream = new MemoryStream(storage, writable: true);
                using (var writer = new Utf8JsonWriter(stream))
                {
                    writeBody(writer);
                }
                _body = storage.AsSpan(0, (int)stream.Position).ToArray();
            }
            catch (NotSupportedException)
            {
                throw new ArgumentException("The management input exceeds its byte budget.");
            }
            finally
            {
                Array.Clear(storage);
            }
        }
    }

    internal byte[]? CopyBody()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _body?.ToArray();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            if (_body is not null)
            {
                Array.Clear(_body);
                _body = null;
            }
        }
    }

    public override string ToString() => "[ManagementRequest]";
}

/// <summary>A bounded page, not a transactional or cross-page snapshot.</summary>
public sealed class ManagementPage<T> where T : notnull
{
    internal ManagementPage(IEnumerable<T> items, bool isComplete, int? nextOffset = null)
    {
        T[] copy = items.Take(1001).ToArray();
        if (copy.Length > 1000)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        Items = Array.AsReadOnly(copy);
        IsComplete = isComplete;
        NextOffset = nextOffset;
    }

    [JsonIgnore] public IReadOnlyList<T> Items { get; }
    public bool IsComplete { get; }
    public int? NextOffset { get; }
    public override string ToString() => "[ManagementPage]";
}

internal sealed class ManagementContractException(SecretStatus status) : Exception("Invalid management response.")
{
    internal SecretStatus Status { get; } = status;
}

internal static class ManagementJson
{
    internal static void Text(string value, int maximum = 1024)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximum ||
            value is "." or ".." || value.Any(char.IsControl))
        {
            throw new ArgumentException("Invalid protected management input.");
        }
    }

    internal static string Escape(string value)
    {
        Text(value);
        return Uri.EscapeDataString(value);
    }

    internal static string UuidInput(string value)
    {
        if (!Guid.TryParseExact(value, "D", out _))
            throw new ArgumentException("Invalid management UUID coordinate.");
        return value;
    }

    internal static JsonElement Object(JsonElement value, string field)
    {
        if (value.ValueKind != JsonValueKind.Object ||
            !value.TryGetProperty(field, out JsonElement child) || child.ValueKind != JsonValueKind.Object)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        return child;
    }

    internal static string Required(JsonElement value, string field)
    {
        string? result = Optional(value, field);
        return result ?? throw new ManagementContractException(SecretStatus.Unknown);
    }

    internal static string? Optional(JsonElement value, string field, bool nullable = true)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        if (!value.TryGetProperty(field, out JsonElement child))
        {
            return null;
        }
        if (child.ValueKind == JsonValueKind.Null && nullable) return null;
        if (child.ValueKind != JsonValueKind.String)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        string result = child.GetString()!;
        if (result.Length > 16384)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        return result;
    }

    internal static string Nonempty(JsonElement value, string field)
    {
        string result = Required(value, field);
        return result.Length > 0 ? result : throw new ManagementContractException(SecretStatus.Unknown);
    }

    internal static double Number(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out JsonElement child) || child.ValueKind != JsonValueKind.Number ||
            !child.TryGetDouble(out double result) || !double.IsFinite(result))
            throw new ManagementContractException(SecretStatus.Unknown);
        return result;
    }

    internal static string? Timestamp(JsonElement value, string field, bool required)
    {
        string? text = required ? Required(value, field) : Optional(value, field);
        if (text is not null && !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind, out _)) throw new ManagementContractException(SecretStatus.Unknown);
        return text;
    }

    internal static string? RequiredNullableString(JsonElement value, string field)
    {
        if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(field, out _))
            throw new ManagementContractException(SecretStatus.Unknown);
        return Optional(value, field);
    }

    internal static bool Boolean(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out JsonElement child) ||
            child.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        return child.GetBoolean();
    }

    internal static int Integer(JsonElement value, string field)
    {
        if (!value.TryGetProperty(field, out JsonElement child) || !child.TryGetInt32(out int result))
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        return result;
    }

    internal static void RequireEqual(JsonElement value, string field, string expected)
    {
        if (!string.Equals(Required(value, field), expected, StringComparison.Ordinal))
        {
            throw new ManagementContractException(SecretStatus.Invalid);
        }
    }

    internal static JsonElement.ArrayEnumerator Array(JsonElement value, string? field = null)
    {
        JsonElement array = value;
        if (field is not null && (value.ValueKind != JsonValueKind.Object ||
            !value.TryGetProperty(field, out array)))
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        if (array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 1000)
        {
            throw new ManagementContractException(SecretStatus.Unknown);
        }
        return array.EnumerateArray();
    }

    internal static string Paging(int offset, int limit)
    {
        if (offset is < 0 or > 1000000 || limit is < 1 or > 100)
        {
            throw new ArgumentException("Invalid management page budget.");
        }
        return $"offset={offset.ToString(CultureInfo.InvariantCulture)}&limit={limit.ToString(CultureInfo.InvariantCulture)}";
    }
}
