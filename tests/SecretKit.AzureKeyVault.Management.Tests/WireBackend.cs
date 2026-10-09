using System.Net;
using System.Text;
using Azure.Core;
using Azure.Core.Pipeline;

namespace SecretKit.AzureKeyVault.Management.Tests;

internal sealed class WireBackend(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
    : HttpPipelineTransport
{
    private readonly HttpClientTransport _inner = new(new HttpClient(new Handler(respond)));
    public override Request CreateRequest() => _inner.CreateRequest();
    public override void Process(HttpMessage message) => throw new InvalidOperationException("Async only.");
    public override ValueTask ProcessAsync(HttpMessage message) => _inner.ProcessAsync(message);
    public static HttpResponseMessage Json(int status, string content) =>
        new((HttpStatusCode)status) { Content = new StringContent(content, Encoding.UTF8, "application/json") };

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) => respond(request, cancellationToken);
    }
}

internal sealed class Credential : TokenCredential
{
    public List<string> Audiences { get; } = [];
    public bool Fail { get; init; }
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("Async only.");
    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (Fail)
        {
            throw new InvalidOperationException("credential-failure-canary");
        }
        Audiences.AddRange(requestContext.Scopes);
        return ValueTask.FromResult(new AccessToken("credential-canary", DateTimeOffset.MaxValue));
    }
}
