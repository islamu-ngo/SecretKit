using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class DxBoundaryTests
{
    [Test]
    [Arguments(315360001d, 0d)]
    [Arguments(120d, 315360001d)]
    [Arguments(0d, 0d)]
    [Arguments(-1d, 0d)]
    [Arguments(0.00000001d, 0d)]
    [Arguments(120d, -1d)]
    public async Task ExcessiveLoginLifetimesAreRejected(double expiry, double maximum)
    {
        using var handler = new LoginWire(expiry, maximum);
        using var authentication = new InfisicalUniversalAuthentication(new("https://auth.test"), handler);
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        var outcome = await authentication.LoginAsync("client-canary", secret, authentication.CreateReceipt());
        using var login = outcome.IsSuccess ? outcome.Value : null;
        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(outcome.Reason).IsEqualTo(SecretFailureReason.InvalidResponse);
    }

    [Test]
    public async Task NativeProfilesAreIsolatedFromTheRuntimeNamespace()
    {
        await Assert.That(typeof(Dynamic.NativeSqlDefinitionProfile).Namespace).IsEqualTo("SecretKit.Infisical.Dynamic");
        await Assert.That(typeof(Dynamic.NativeDynamicDefinitionOptions).Namespace).IsEqualTo("SecretKit.Infisical.Dynamic");
    }

    [Test]
    public async Task InvalidSelectorsIdentifyParametersWithoutCoordinates()
    {
        try
        {
            _ = new InfisicalSecretAddress("canary-project", "canary-environment", "/", "key", version: 0);
            throw new InvalidOperationException("Invalid version was accepted.");
        }
        catch (ArgumentException error)
        {
            await Assert.That(error.ParamName).IsEqualTo("version");
            await Assert.That(error.Message.Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
    }

    private sealed class LoginWire(double expiry, double maximum) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(FormattableString.Invariant($"{{\"accessToken\":\"issued-canary\",\"tokenType\":\"Bearer\",\"expiresIn\":{expiry},\"accessTokenMaxTTL\":{maximum}}}"), Encoding.UTF8, "application/json")
            });
    }
}
