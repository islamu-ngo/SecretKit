using System.Text.Json;

namespace SecretKit.Samples.Infisical;

// All demos share the same bounded wire format, not application policy.
internal static class DemoInputReader
{
    private const int MaximumInputBytes = 65536;

    internal static async Task<T> ReadAsync<T>(Stream source, Func<JsonElement, T> parse,
        CancellationToken cancellationToken)
    {
        byte[] bytes = new byte[MaximumInputBytes + 1];
        try
        {
            int length = 0;
            while (length < bytes.Length)
            {
                int count = await source.ReadAsync(bytes.AsMemory(length), cancellationToken);
                if (count == 0) break;
                length += count;
            }
            if (length is 0 or > MaximumInputBytes)
                throw new ArgumentException("Invalid input size.");
            return Parse(bytes.AsMemory(0, length), parse);
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    internal static async Task<byte[]?> ReadFrameAsync(Stream source, int maximum,
        CancellationToken cancellationToken)
    {
        byte[] bytes = new byte[maximum + 1];
        try
        {
            int length = 0;
            while (length <= maximum)
            {
                int count = await source.ReadAsync(bytes.AsMemory(length, 1), cancellationToken);
                if (count == 0)
                {
                    if (length == 0) return null;
                    throw new ArgumentException("Incomplete input frame.");
                }
                if (bytes[length] == (byte)'\n') return bytes[..length];
                length++;
            }
            throw new ArgumentException("Invalid input size.");
        }
        finally
        {
            Array.Clear(bytes);
        }
    }

    internal static T Parse<T>(ReadOnlyMemory<byte> bytes, Func<JsonElement, T> parse)
    {
        using JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 4 });
        if (document.RootElement.ValueKind != JsonValueKind.Object)
            throw new ArgumentException("Invalid input.");
        // Parse while the document and its backing buffer are still owned here.
        return parse(document.RootElement);
    }

    internal static void ValidateFields(JsonElement input, params string[] additionalFields)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in input.EnumerateObject())
        {
            bool common = property.Name is "origin" or "project" or "environment" or
                "folder" or "key" or "token" or "allowLoopbackDevelopmentHttp";
            if (!names.Add(property.Name) ||
                !(common || additionalFields.Contains(property.Name, StringComparer.Ordinal)))
                throw new ArgumentException("Invalid input fields.");
        }
    }

    internal static string Text(JsonElement input, string name, int maximum)
    {
        if (!input.TryGetProperty(name, out JsonElement element) || element.ValueKind != JsonValueKind.String)
            throw new ArgumentException("Missing input.");
        string value = element.GetString()!;
        if (value.Length == 0 || value.Length > maximum)
            throw new ArgumentException("Invalid input size.");
        return value;
    }
}
