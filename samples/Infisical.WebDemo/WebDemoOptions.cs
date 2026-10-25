using System.Net;
using System.Text.Json;
using SecretKit.Samples.Infisical;

namespace SecretKit.Samples.Infisical.WebDemo;

internal sealed record WebDemoOptions(Uri Downstream, string? OptionalKey)
{
    public override string ToString() => "[WebDemoOptions]";

    internal static async Task<WebDemoOptions> ReadAsync(Stream source, CancellationToken token)
    {
        byte[] frame = await DemoInputReader.ReadFrameAsync(source, 8192, token) ??
            throw new ArgumentException("Missing options.");
        try
        {
            return Parse(frame);
        }
        finally
        {
            Array.Clear(frame);
        }
    }

    private static WebDemoOptions Parse(byte[] frame)
    {
        using JsonDocument document = JsonDocument.Parse(frame, new JsonDocumentOptions { MaxDepth = 2 });
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in document.RootElement.EnumerateObject())
        {
            if (!names.Add(property.Name) || property.Name is not ("downstream" or "optionalKey"))
                throw new ArgumentException("Invalid options.");
        }
        var downstream = new Uri(document.RootElement.GetProperty("downstream").GetString()!, UriKind.Absolute);
        if (downstream.Scheme != "http" || !IPAddress.TryParse(downstream.Host, out IPAddress? address) ||
            !IPAddress.IsLoopback(address) || downstream.UserInfo.Length != 0 ||
            downstream.AbsolutePath != "/" || downstream.Query.Length != 0 || downstream.Fragment.Length != 0)
            throw new ArgumentException("Invalid downstream.");
        string? optional = document.RootElement.TryGetProperty("optionalKey", out var key) ? key.GetString() : null;
        if (optional is { Length: 0 or > 4096 })
            throw new ArgumentException("Invalid optional key.");
        return new(downstream, optional);
    }
}
