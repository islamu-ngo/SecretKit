using System.Net;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class BearerAdmissionTests
{
    [Test]
    [Arguments("token-canary", true)]
    [Arguments("aZ09-._~+/", true)]
    [Arguments("dG9rZW4=", true)]
    [Arguments("dG9rZQ==", true)]
    [Arguments("", false)]
    [Arguments("=", false)]
    [Arguments("ab=cd", false)]
    [Arguments("token canary", false)]
    [Arguments("token\r\nX-Injected: 1", false)]
    [Arguments("token\u0000", false)]
    [Arguments("t\u00f6ken", false)]
    [Arguments("\"token\"", false)]
    public async Task OnlyRfc6750TokensAreAdmitted(string token, bool admitted)
    {
        await Assert.That(InfisicalBearer.IsValid(token)).IsEqualTo(admitted);
    }

    [Test]
    public async Task LengthBoundIsInclusive()
    {
        await Assert.That(InfisicalBearer.IsValid(new string('a', InfisicalBearer.MaximumLength))).IsTrue();
        await Assert.That(InfisicalBearer.IsValid(new string('a', InfisicalBearer.MaximumLength + 1))).IsFalse();
    }

    [Test]
    [Arguments("token canary")]
    [Arguments("token\r\ncanary")]
    public async Task RuntimeReadRejectsMalformedTokenBeforeDispatch(string token)
    {
        using var wire = new CountingWire();
        await using var client = new InfisicalClient(new("https://api.test"), new FixedTokens(token),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) });

        var outcome = await client.ReadAsync(
            new SecretReference(client.Authority, new InfisicalSecretAddress("p", "e", "/", "k")));

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(outcome.Reason).IsEqualTo(SecretFailureReason.CredentialUnavailable);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    private sealed class FixedTokens(string token) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText(token))));
    }

    private sealed class CountingWire : HttpMessageHandler
    {
        internal int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.InternalServerError));
        }
    }
}
