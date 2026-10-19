using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthenticationIssuanceOriginalTests
{
    [Test]
    [Arguments(false, "organizationSlug.omitted")]
    [Arguments(false, "organizationSlug.value")]
    [Arguments(true, "proof.AliCloud")]
    [Arguments(true, "proof.Aws.method-omitted")]
    [Arguments(true, "proof.Aws.method-value")]
    [Arguments(true, "proof.Azure")]
    [Arguments(true, "proof.Gcp")]
    [Arguments(true, "proof.Jwt")]
    [Arguments(true, "proof.Kubernetes")]
    [Arguments(true, "proof.Oidc")]
    [Arguments(true, "proof.Spiffe.JWT-SVID")]
    [Arguments(true, "proof.TlsCertificate.host-mtls")]
    [Arguments(true, "proof.Ldap")]
    [Arguments(true, "proof.Oci.date")]
    [Arguments(true, "proof.Oci.x-date")]
    [Arguments(true, "proof.Oci.date-and-x-date")]
    [Arguments(true, "proof.Oci.dates-omitted")]
    [Arguments(true, "organizationSlug.omitted")]
    [Arguments(true, "organizationSlug.value")]
    [Arguments(true, "maximumTTL.zero")]
    [Arguments(true, "maximumTTL.positive")]
    public async Task OriginalRegistrarsSettleOwnedInterruptedIssuance(bool proof, string variant)
    {
        foreach (string boundary in new[] { "cancellation-boundary", "lost-response-no-replay" })
            foreach (bool applied in new[] { false, true })
            {
                bool tls = variant == "proof.TlsCertificate.host-mtls";
                await using var fixture = new InfisicalAuthenticationIssuanceFixture(tls);
                fixture.Server.Apply = applied;
                var root = fixture.Root(variant, proof, boundary);
                var definition = new NativeCaseDefinition(new("Infisical", root.Operation, variant, "local", boundary), root.Member);
                using var environment = Environment(fixture.Server, definition, proof, fixture);
                var registry = new NativeCaseRegistry();
                InfisicalAuthenticationFamilies.Register(registry, environment, [definition], issuanceSource: fixture.Source,
                    configureProofTransport: tls ? fixture.Server.TrustServer : null);
                using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
                var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
                await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode + ";" + boundary + ";applied=" + applied);
                // Cancellation at RequestHeadersStart can prevent issuer ingress.
                await Assert.That(fixture.Server.Logins <= 1).IsTrue();
                if (tls && fixture.Server.Logins != 0)
                    await Assert.That(fixture.Server.PeerCertificates.Single()).IsEqualTo(fixture.Server.AllowedCertificateHash);
                if (boundary == "lost-response-no-replay")
                {
                    await Assert.That(fixture.Server.Logins).IsEqualTo(1);
                    await Assert.That(fixture.Server.Applied).IsEqualTo(applied);
                }
                await InfisicalAuthenticationIssuanceTests.ReleasedAsync(fixture);
            }
    }

    [Test]
    public async Task OriginalTlsDeniedPeerCannotIssueCredential()
    {
        await using var server = new InfisicalAuthenticationIssuanceServer(true) { HoldResponse = false };
        var definition = new NativeCaseDefinition(new("Infisical", InfisicalProofAuthenticationEffects.Operation,
            "proof.TlsCertificate.host-mtls", "local", "denied-authority"), InfisicalProofAuthenticationEffects.Member);
        using var environment = Environment(server, definition, true);
        var registry = new NativeCaseRegistry();
        InfisicalAuthenticationFamilies.Register(registry, environment, [definition], configureProofTransport: server.TrustServer);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(server.PeerCertificates.Single()).IsEqualTo(server.DeniedCertificateHash);
        await Assert.That(server.Applied).IsFalse();
        await Assert.That(server.Exists).IsFalse();
    }

    [Test]
    [Arguments(false, "wrong-credential", "effect-mismatch")]
    [Arguments(true, "wrong-credential", "effect-mismatch")]
    [Arguments(false, "omitted-capture", "observer-unavailable")]
    [Arguments(true, "omitted-capture", "observer-unavailable")]
    [Arguments(false, "bad-signature", "observer-unavailable")]
    [Arguments(true, "bad-signature", "observer-unavailable")]
    [Arguments(false, "lost-open", "observer-unavailable")]
    [Arguments(true, "lost-open", "observer-unavailable")]
    public async Task OriginalRegistrarsRejectUnprovenIssuanceAndRecover(bool proof, string fault, string reason)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture { Fault = fault };
        var root = fixture.Root(proof ? "proof.Jwt" : "organizationSlug.omitted", proof);
        var definition = new NativeCaseDefinition(new("Infisical", root.Operation, root.Variant, "local",
            "lost-response-no-replay"), root.Member);
        using var environment = Environment(fixture.Server, definition, proof, fixture);
        var registry = new NativeCaseRegistry();
        InfisicalAuthenticationFamilies.Register(registry, environment, [definition], issuanceSource: fixture.Source);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(fixture.FaultReached).IsTrue();
        await InfisicalAuthenticationIssuanceTests.ReleasedAsync(fixture);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalPositiveInterruptedCaseIsUnavailableWithoutPrearmedSource(bool proof)
    {
        await using var server = new InfisicalAuthenticationIssuanceServer();
        var definition = new NativeCaseDefinition(new("Infisical", proof ?
            InfisicalProofAuthenticationEffects.Operation : InfisicalUniversalAuthenticationEffects.Operation,
            proof ? "proof.Jwt" : "organizationSlug.omitted", "local", "lost-response-no-replay"),
            proof ? InfisicalProofAuthenticationEffects.Member : InfisicalUniversalAuthenticationEffects.Member);
        using var environment = Environment(server, definition, proof);
        var registry = new NativeCaseRegistry();
        InfisicalAuthenticationFamilies.Register(registry, environment, [definition]);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], deadline.Token)).Single();
        Console.WriteLine($"authentication-issuance-original: passed={result.Passed} reason={result.ReasonCode}");
        // This is the original positive native case's Red, not a fabricated
        // exception or compiler failure. Source-absent behavior must stay closed.
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(server.Logins).IsEqualTo(1);
        await Assert.That(server.Applied).IsTrue();
        await Assert.That(server.Exists).IsFalse();
        Console.WriteLine("authentication-issuance-original-red: cases=1 applied=1 passed=0 reason=observer-unavailable");
    }

    internal static AuthenticationFixtureInput Fixture() => new(
        InfisicalAuthenticationIssuanceServer.Organization, InfisicalAuthenticationIssuanceServer.Identity,
        InfisicalAuthenticationIssuanceServer.Name, "project", "dev", "/", "ALLOWED", "DENIED", "owned-material",
        600, 1200, 0, 600, 1200, AuthenticationApiRevision.AuthV1IdentitiesV1SecretsV4);

    private static NativeEnvironment Environment(InfisicalAuthenticationIssuanceServer server,
        NativeCaseDefinition definition, bool proof, InfisicalAuthenticationIssuanceFixture? issuance = null)
    {
        bool tls = definition.Key.Variant == "proof.TlsCertificate.host-mtls";
        object Fields(string jwt) => new
        {
            strategy = InfisicalAuthenticationIssuanceFixture.Method(definition.Key.Variant)[..^5],
            jwt,
            certificate = tls ? server.Packet(jwt == "denied-proof") : null,
            iamRequestBody = jwt,
            iamRequestHeaders = jwt,
            method = definition.Key.Variant == "proof.Aws.method-value" ? "POST" : null,
            accessKeyId = jwt,
            signature = jwt,
            signatureNonce = jwt,
            timestamp = "2026-10-14T00:00:00Z",
            version = "2015-04-01",
            username = "owned-user",
            password = jwt,
            userOcid = "owned-user",
            authorization = jwt,
            host = "issuer",
            date = definition.Key.Variant is "proof.Oci.date" or "proof.Oci.date-and-x-date" ? "date" : null,
            xDate = definition.Key.Variant is "proof.Oci.x-date" or "proof.Oci.date-and-x-date" ? "x-date" : null
        };
        var selectedFixture = Fixture() with
        {
            ExpectedMaximumTtl = definition.Key.Variant == "maximumTTL.zero" ? 0 : 1200,
            ExpectedReportedMaximumTtl = definition.Key.Variant == "maximumTTL.zero" ? 0 : 1200
        };
        string? slug = definition.Key.Variant == "organizationSlug.value" ? "owned" : null;
        object input = proof ? new
        {
            fixture = selectedFixture,
            organizationSlug = slug,
            proof = Fields("original-proof"),
            deniedProof = Fields("denied-proof")
        } :
            new
            {
                fixture = selectedFixture,
                clientId = "original-client",
                clientSecret = "original-proof",
                deniedClientSecret = "denied-proof",
                organizationSlug = slug
            };
        var scopeInput = new Dictionary<string, object>
        {
            [definition.Key.Operation] = new Dictionary<string, object>
            {
                [definition.Key.Variant] = new Dictionary<string, object> { [definition.Key.Case] = input }
            }
        };
        if (issuance is not null)
            scopeInput["authIssuance"] = new AuthenticationIssuanceInput(
                new(new Uri("https://issuance.invalid/"), "private-channel", issuance.Source.Identity, 15),
                issuance.Root(definition.Key.Variant, proof).Profile, "owned-capability", "observer");
        var families = new Dictionary<string, object>
        {
            [proof ? "C08-IR-InfisicalProofAuthentication" : "C08-IR-InfisicalUniversalAuthentication"] =
                new
                {
                    scopes = new Dictionary<string, object>
                    {
                        ["local"] = scopeInput
                    }
                }
        };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = server.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, new JsonSerializerOptions(NativeRunProtocol.JsonOptions) { IgnoreReadOnlyProperties = false }), server.ControlOrigin);
    }
}
