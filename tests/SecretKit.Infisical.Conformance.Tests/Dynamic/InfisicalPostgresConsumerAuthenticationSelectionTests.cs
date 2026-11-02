using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalPostgresConsumerAuthenticationSelectionTests
{
    private const string Family = "C08-IR-InfisicalRotationClient";

    [Test]
    [Arguments("missing-ca")]
    [Arguments("foreign-field")]
    [Arguments("port")]
    [Arguments("null")]
    public async Task ExplicitMalformedNativeAuthenticationCannotSelectRemoteCredentials(string fault)
    {
        JsonObject profile = Profile();
        if (fault == "missing-ca") profile.Remove("rootCertificate");
        if (fault == "foreign-field") profile["executable"] = "unselected";
        if (fault == "port") profile["port"] = 0;
        using var environment = Environment(fault == "null" ? null : profile);

        await Assert.That(() => InfisicalLifecycleObservers.FromInputs(environment, Family))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    [Arguments(InfisicalRotationProfile.PostgresCredentials)]
    public async Task SelectedNativeSourceNeverFallsBackForForeignCoordinates(InfisicalRotationProfile profile)
    {
        using var environment = Environment(Profile());
        using var transport = new UnexpectedObserverTransport();
        bool launched = false;
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, transport,
            postgresAuthenticationProcess: (_, _, _, _) =>
            {
                launched = true;
                throw new InvalidOperationException("unexpected-native-attempt");
            })!;
        using var user = SecretMaterial.FromText("owned_a");
        using var password = SecretMaterial.FromText("private-password");

        var result = await observer.AuthenticateAsync(
            new(profile, "foreign.invalid", 5432, "owned", "fixture-account"), user, password, default);

        await Assert.That(result).IsEqualTo(BackendAuthentication.Unavailable);
        await Assert.That(launched).IsFalse();
        await Assert.That(transport.Requests).IsEqualTo(0);
    }

    private sealed class UnexpectedObserverTransport : HttpMessageHandler
    {
        internal int Requests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            throw new InvalidOperationException("unexpected-remote-authentication");
        }
    }

    [Test]
    public async Task CancelledForeignProfilePreservesCallerCancellationWithoutRemoteFallback()
    {
        using var environment = Environment(Profile());
        using var transport = new UnexpectedObserverTransport();
        var observer = InfisicalLifecycleObservers.FromInputs(environment, Family, transport)!;
        using var user = SecretMaterial.FromText("owned_a");
        using var password = SecretMaterial.FromText("private-password");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.That(async () => await observer.AuthenticateAsync(
            new(InfisicalRotationProfile.MssqlCredentials, "database.invalid", 5432, "owned", "fixture-account"),
            user, password, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(transport.Requests).IsEqualTo(0);
    }

    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 5432,
        ["database"] = "owned",
        ["account"] = "fixture-account",
        ["username1"] = "owned_a",
        ["username2"] = "owned_b",
        ["rootCertificate"] = Path.Combine(Path.GetTempPath(), "selected-ca.pem"),
        ["timeoutSeconds"] = 10
    };

    private static NativeEnvironment Environment(JsonNode? profile)
    {
        using var settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject
            {
                [Family] = new JsonObject
                {
                    ["postgresConsumerAuthentication"] = profile,
                    ["observer"] = new JsonObject
                    {
                        ["endpoint"] = "https://observer.invalid/owned/",
                        ["token"] = "private-observer-token",
                        ["identity"] = "independent-service",
                        ["timeoutSeconds"] = 10
                    }
                }
            }
        }.ToJsonString());
        return NativeEnvironment.Create(settings.RootElement);
    }
}
