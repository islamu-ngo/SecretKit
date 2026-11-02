using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class TypedDispatchGuardTests
{
    [Test]
    [Arguments("userinfo")]
    [Arguments("scheme")]
    [Arguments("origin")]
    [Arguments("expected-origin")]
    [Arguments("port")]
    [Arguments("path")]
    [Arguments("fragment")]
    [Arguments("method")]
    [Arguments("query")]
    [Arguments("duplicate-query")]
    public async Task MismappedFactoryCannotAcquireCredentialsOrDispatch(string mismatch)
    {
        string destination = mismatch switch
        {
            "userinfo" => "https://user-fixture@management.test/api/v1/projects?type=secret-manager",
            "scheme" => "http://management.test/api/v1/projects?type=secret-manager",
            "origin" or "expected-origin" => "https://other.test/api/v1/projects?type=secret-manager",
            "port" => "https://management.test:8443/api/v1/projects?type=secret-manager",
            "path" => "https://management.test/api/v1/identities?type=secret-manager",
            "fragment" => "https://management.test/api/v1/projects?type=secret-manager#fragment",
            "query" => "https://management.test/api/v1/projects?type=certificate-manager",
            "duplicate-query" => "https://management.test/api/v1/projects?type=secret-manager&type=secret-manager",
            _ => "https://management.test/api/v1/projects?type=secret-manager"
        };
        var content = new DisposalContent();
        using var outgoing = new HttpRequestMessage(mismatch == "method" ? HttpMethod.Delete : HttpMethod.Get, destination)
        { Content = content };
        using var wire = new Wire();
        using var transport = new ManagementTransport(new Uri("https://management.test"),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "organization-fixture");
        using var request = new ManagementRequest<string>("infisical.get.v1.projects",
            (_, _, _) => Task.FromResult(outgoing), HttpMethod.Get,
            mismatch == "expected-origin" ? destination : "/api/v1/projects?type=secret-manager",
            new("organization-fixture"), null, _ => "accepted", mutation: false);

        SecretOutcome<string> result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new("organization-fixture")));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.AuthorizedRequestObserved).IsFalse();
        await Assert.That(content.Disposed).IsTrue();
    }

    [Test]
    public async Task GrantMismatchPreventsTypedConstruction()
    {
        using var wire = new Wire();
        using var transport = new ManagementTransport(new Uri("https://management.test"),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, "organization-fixture");
        bool constructed = false;
        using var request = new ManagementRequest<string>("infisical.get.v1.projects",
            (apis, _, token) =>
            {
                constructed = true;
                return apis.Projects.List(null, null, token);
            }, HttpMethod.Get, "/api/v1/projects", new("organization-fixture"), null, _ => "accepted", mutation: false);

        SecretOutcome<string> result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant("infisical.delete.v1.projects.by.projectId", new("organization-fixture")));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(constructed).IsFalse();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.AuthorizedRequestObserved).IsFalse();
    }

    [Test]
    public async Task TypedRefitConstructionDoesNotSend()
    {
        using var cannotSend = new CannotSend();
        using var http = new HttpClient(cannotSend) { BaseAddress = new Uri("https://management.test") };
        var builders = new ManagementRequestBuilder(http);
        using HttpRequestMessage message = await builders.Projects.Get("project/with space", CancellationToken.None);
        await Assert.That(message.Method).IsEqualTo(HttpMethod.Get);
        await Assert.That(new Uri(http.BaseAddress, message.RequestUri!).AbsolutePath)
            .IsEqualTo("/api/v1/projects/project%2Fwith%20space");
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new InfisicalAccessToken(SecretMaterial.FromText("token-fixture"))));
        }
    }

    private sealed class Wire : HttpMessageHandler
    {
        internal bool AuthorizedRequestObserved { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            AuthorizedRequestObserved = request.Headers.Authorization is not null;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"projects\":[]}") });
        }
    }

    private sealed class CannotSend : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Typed request builders must not send.");
    }

    private sealed class DisposalContent : HttpContent
    {
        internal bool Disposed { get; private set; }
        protected override bool TryComputeLength(out long length) { length = 0; return true; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) => Task.CompletedTask;
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }
}
