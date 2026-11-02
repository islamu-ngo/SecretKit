using System.Net.Http.Headers;
using System.Text;
using SecretKit.Samples.RuntimeConfiguration;

namespace SecretKit.Samples.Infisical.WebDemo;

internal sealed class JobClient : IRuntimeIntegrationClient
{
    private readonly HttpClient _http;

    internal JobClient(Uri downstream, string credential)
    {
        // No redirects, proxies, ambient credentials or instrumentation carrying coordinates.
        _http = new HttpClient(new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            ActivityHeadersPropagator = null
        })
        { BaseAddress = downstream, Timeout = Timeout.InfiniteTimeSpan };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", credential);
    }

    public async ValueTask<string> ExecuteAsync(CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "jobs")
        {
            Content = new StringContent("{\"operation\":\"reconcile\"}", Encoding.UTF8, "application/json")
        };
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        // Acceptance alone crosses the app boundary, never downstream response prose.
        return response.IsSuccessStatusCode ? "accepted" : "unavailable";
    }

    public ValueTask DisposeAsync()
    {
        _http.Dispose();
        return ValueTask.CompletedTask;
    }
}
