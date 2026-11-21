using System.Net;
using System.Text.Json;

namespace SecretKit.LiveProvisioner;

internal static class ProviderStatus
{
    internal static HttpClient CreateHttpClient() => new(new SocketsHttpHandler
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false
    })
    { Timeout = TimeSpan.FromSeconds(20) };

    internal static async Task ReportAsync(LiveEnvConfig config, TextWriter output, CancellationToken ct, HttpClient? pipeline = null)
    {
        using var owned = pipeline is null ? CreateHttpClient() : null;
        using var response = await (pipeline ?? owned!).GetAsync(new Uri(config.Origin, "/api/status"),
            HttpCompletionOption.ResponseHeadersRead, ct);
        await output.WriteLineAsync($"server-status: HTTP {(int)response.StatusCode}");
        using var status = await ReadAsync(response, "server status", ct);
        await output.WriteLineAsync("organization-plan/edition: unverified (server health is not entitlement evidence)");
    }

    internal static async Task<JsonDocument> ReadAsync(HttpResponseMessage response, string step, CancellationToken ct)
    {
        if (!response.IsSuccessStatusCode)
        {
            string restriction = response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Forbidden
                ? " Check permissions, request contract, and plan/edition." : "";
            throw new ProvisioningException($"{step}: HTTP {(int)response.StatusCode}.{restriction}");
        }
        const int max = 128 * 1024;
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        var buffer = new byte[max + 1];
        try
        {
            int length = await stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false, cancellationToken: ct);
            if (length > max)
                throw new ProvisioningException($"{step}: response exceeded the byte limit.");
            // JsonDocument's stream overload copies data it owns.
            using var copy = new MemoryStream(buffer, 0, length, writable: false);
            return await JsonDocument.ParseAsync(copy, cancellationToken: ct);
        }
        catch (JsonException)
        {
            throw new ProvisioningException($"{step}: invalid response.");
        }
        finally
        {
            Array.Clear(buffer);
        }
    }
}
