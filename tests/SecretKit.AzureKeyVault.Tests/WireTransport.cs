using System.Net;
using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Tests;

internal sealed class WireTransport : HttpPipelineTransport
{
    private readonly HttpClientTransport _transport;

    public WireTransport(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
    {
        _transport = new HttpClientTransport(new HttpClient(new Handler(respond)));
    }

    public List<Uri> Requests { get; } = [];

    public List<bool> Authorized { get; } = [];

    public override Request CreateRequest() => _transport.CreateRequest();

    public override void Process(HttpMessage message) => throw new InvalidOperationException("Async only.");

    public override ValueTask ProcessAsync(HttpMessage message)
    {
        Requests.Add(message.Request.Uri.ToUri());
        Authorized.Add(message.Request.Headers.Contains("Authorization"));
        return _transport.ProcessAsync(message);
    }

    public static HttpResponseMessage Json(int status, string json) =>
        new((HttpStatusCode)status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    public static HttpResponseMessage Challenge(string resource = "https://vault.azure.net")
    {
        var response = Json(401, "{}");
        response.Headers.TryAddWithoutValidation("WWW-Authenticate",
            $"Bearer authorization=\"https://login.microsoftonline.com/test-tenant\", resource=\"{resource}\"");
        return response;
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => respond(request, cancellationToken);
    }
}

internal sealed class TestCredential : TokenCredential
{
    public List<string[]> Scopes { get; } = [];

    public bool Fail { get; init; }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
        => throw new InvalidOperationException("Async only.");

    public override ValueTask<AccessToken> GetTokenAsync(
        TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Fail)
        {
            throw new InvalidOperationException("credential-canary");
        }

        Scopes.Add(requestContext.Scopes);
        return ValueTask.FromResult(new AccessToken("token-canary", DateTimeOffset.MaxValue));
    }
}

internal sealed class FixedTime : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeSeconds(2_000_000_000);
}
