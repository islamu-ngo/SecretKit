using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalMysqlConsumerAuthenticationSelectionTests
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

    private static JsonObject Profile() => new()
    {
        ["host"] = "database.invalid",
        ["port"] = 3306,
        ["database"] = "owned",
        ["account"] = "fixture-account",
        ["username1"] = "owned_a",
        ["username2"] = "owned_b",
        ["accountHost1"] = "%",
        ["accountHost2"] = "%",
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
                    ["mysqlConsumerAuthentication"] = profile,
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
