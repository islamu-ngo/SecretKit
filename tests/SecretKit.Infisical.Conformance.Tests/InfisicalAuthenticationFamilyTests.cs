using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthenticationFamilyTests
{
    private const string Identity = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string Organization = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string TokenId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    private const string OwnedName = "sk-auth-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Test]
    public async Task ExactInventoryHasOneHundredTenRegisteredMissingInputFailures()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using JsonDocument inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        string[] operations = [InfisicalProofAuthenticationEffects.Operation,
            InfisicalUniversalAuthenticationEffects.Operation, InfisicalTokenRevocationEffects.Operation];
        NativeCaseDefinition[] expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => operations.Contains(o.GetProperty("id").GetString(), StringComparer.Ordinal))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        using NativeEnvironment environment = Environment(new("http://127.0.0.1:1"), new { });
        IReadOnlyList<NativeCaseResult> results = await RunAsync(environment, expected);
        await Assert.That(results.Count).IsEqualTo(110);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task ContractTamperingFailsBeforeNetworkOrInput(string field)
    {
        NativeCaseDefinition good = Definition("proof", "proof.Jwt", "selected-contract");
        NativeCaseDefinition bad = new(good.Key with
        {
            Variant = field == "variant" ? "invented" : good.Key.Variant,
            Case = field == "case" ? "invented" : good.Key.Case
        }, field == "member" ? good.Member + ".wrong" : good.Member);
        using NativeEnvironment environment = Environment(new("http://127.0.0.1:1"), new { });
        NativeCaseResult result = (await RunAsync(environment, [bad])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
    }

    [Test]
    [Arguments("proof.AliCloud")]
    [Arguments("proof.Aws.method-omitted")]
    [Arguments("proof.Aws.method-value")]
    [Arguments("proof.Azure")]
    [Arguments("proof.Gcp")]
    [Arguments("proof.Jwt")]
    [Arguments("proof.Kubernetes")]
    [Arguments("proof.Oidc")]
    [Arguments("proof.Spiffe.JWT-SVID")]
    [Arguments("proof.Ldap")]
    [Arguments("proof.Oci.date")]
    [Arguments("proof.Oci.x-date")]
    [Arguments("proof.Oci.date-and-x-date")]
    [Arguments("proof.Oci.dates-omitted")]
    [Arguments("proof.TlsCertificate.host-mtls")]
    [Arguments("organizationSlug.omitted")]
    [Arguments("organizationSlug.value")]
    [Arguments("maximumTTL.zero")]
    [Arguments("maximumTTL.positive")]
    public async Task EveryProofFactoryPreservesVariantAndCannotCertifyLifetime(string variant)
    {
        await using var backend = new Backend("good", variant == "maximumTTL.zero" ? 0 : 1200);
        NativeCaseDefinition definition = Definition("proof", variant, "independent-effect");
        using NativeEnvironment environment = Environment(backend.Origin, Family("proof", definition, ProofInput(variant)));
        NativeCaseResult result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(
            variant == "proof.TlsCertificate.host-mtls" ? "missing-input" : "observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        if (variant == "proof.TlsCertificate.host-mtls")
        {
            await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
            return;
        }
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(1);
        await Assert.That(backend.IssuedAllowedReads).IsEqualTo(1);
        await Assert.That(backend.IssuedDeniedReads).IsEqualTo(1);
        await Assert.That(backend.IdentityExists).IsFalse();
        await Assert.That(backend.Proof!.Value.GetProperty("identityId").GetString()).IsEqualTo(Identity);
        if (variant.StartsWith("proof.Aws.", StringComparison.Ordinal))
            await Assert.That(backend.Proof.Value.TryGetProperty("iamHttpRequestMethod", out _))
                .IsEqualTo(variant.EndsWith("value", StringComparison.Ordinal));
        if (variant.StartsWith("proof.Oci.", StringComparison.Ordinal))
        {
            JsonElement headers = backend.Proof.Value.GetProperty("headers");
            await Assert.That(headers.TryGetProperty("date", out _))
                .IsEqualTo(variant is "proof.Oci.date" or "proof.Oci.date-and-x-date");
            await Assert.That(headers.TryGetProperty("x-date", out _))
                .IsEqualTo(variant is "proof.Oci.x-date" or "proof.Oci.date-and-x-date");
        }
        if (variant.StartsWith("organizationSlug.", StringComparison.Ordinal))
            await Assert.That(backend.Proof.Value.TryGetProperty("organizationSlug", out _))
                .IsEqualTo(variant == "organizationSlug.value");
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task HostTlsRequiresProtectedCertificatePairBeforeOwnership(string caseName)
    {
        await using var backend = new Backend("good");
        var definition = Definition("proof", "proof.TlsCertificate.host-mtls", caseName);
        // No TLS handshake is attempted: missing accepted/denied packets must
        // fail before even acquiring fixture cleanup authority.
        using var environment = Environment(new UriBuilder(backend.Origin) { Scheme = "https" }.Uri,
            Family("proof", definition, ProofInput(definition.Key.Variant)));
        var result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task HostTlsPacketsCannotAttachToNonTlsProof(bool deniedPacket)
    {
        await using var backend = new Backend("good");
        var definition = Definition("proof", "proof.Jwt", "independent-effect");
        var input = JsonSerializer.SerializeToNode(ProofInput("proof.Jwt"))!.AsObject();
        input[deniedPacket ? "deniedProof" : "proof"]!["certificate"] =
            new System.Text.Json.Nodes.JsonObject { ["pkcs12Base64"] = "invalid", ["password"] = "private" };
        using var environment = Environment(backend.Origin, Family("proof", definition, input));
        var result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
    }

    [Test]
    [Arguments("proof", "denied", "observed")]
    [Arguments("universal", "denied", "observed")]
    [Arguments("universal", "good", "observer-unavailable")]
    [Arguments("universal", "bad-value", "effect-mismatch")]
    [Arguments("universal", "bad-scope", "effect-mismatch")]
    [Arguments("universal", "bad-metadata", "effect-mismatch")]
    [Arguments("universal", "observer", "observer-unavailable")]
    [Arguments("universal", "cleanup", "cleanup-incomplete")]
    [Arguments("proof", "lost", "observer-unavailable")]
    [Arguments("proof", "cancel", "observer-unavailable")]
    [Arguments("universal", "lost", "observer-unavailable")]
    [Arguments("universal", "cancel", "observer-unavailable")]
    [Arguments("revoke", "good", "observed")]
    [Arguments("revoke", "denied", "observed")]
    [Arguments("revoke", "no-effect", "effect-mismatch")]
    [Arguments("revoke", "lost", "observed")]
    [Arguments("revoke", "cancel", "observed")]
    public async Task ActualSdkRequiresIndependentAccessAndSafeCleanup(string family, string mode, string reason)
    {
        await using var backend = new Backend(mode);
        string caseName = mode switch
        {
            "denied" => "denied-authority",
            "lost" => "lost-response-no-replay",
            "cancel" => "cancellation-boundary",
            _ => "independent-effect"
        };
        string variant = family == "proof" ? "proof.Jwt" :
            family == "revoke" ? "input.token" : "organizationSlug.omitted";
        NativeCaseDefinition definition = Definition(family, variant, caseName);
        object input = family == "proof" ? ProofInput(variant) : family == "revoke" ?
            new { fixture = Fixture() } : UniversalInput();
        using NativeEnvironment environment = Environment(backend.Origin, Family(family, definition, input));
        NativeCaseResult result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsEqualTo(reason == "observed");
        if (mode is not ("observer" or "cleanup"))
            await Assert.That(backend.IdentityExists).IsFalse();
        if (mode == "lost")
            await Assert.That(family == "revoke" ? backend.RevocationCalls : backend.AuthenticationCalls).IsEqualTo(1);
        if (mode == "cancel")
            await Assert.That(family == "revoke" ? backend.RevocationCalls : backend.AuthenticationCalls).IsLessThanOrEqualTo(1);
    }

    [Test]
    public async Task StrictSettingsRejectUnknownFieldsWithoutDispatch()
    {
        await using var backend = new Backend("good");
        NativeCaseDefinition definition = Definition("universal", "organizationSlug.omitted", "selected-contract");
        using NativeEnvironment environment = Environment(backend.Origin, Family("universal", definition,
            new
            {
                fixture = Fixture(),
                clientId = "client",
                clientSecret = "allowed",
                deniedClientSecret = "denied-proof",
                organizationSlug = (string?)null,
                unexpected = true
            }));
        NativeCaseResult result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UniversalVariantsKeepPeriodicReportsSeparateFromConfiguredCeilings(bool slug)
    {
        await using var backend = new Backend("periodic");
        NativeCaseDefinition definition = Definition("universal",
            slug ? "organizationSlug.value" : "organizationSlug.omitted", "independent-effect");
        object input = new
        {
            fixture = Fixture() with
            {
                ExpectedTtl = 10,
                ExpectedMaximumTtl = 20,
                ExpectedPeriod = 60,
                ExpectedExpiresIn = 60,
                ExpectedReportedMaximumTtl = 0
            },
            clientId = "client",
            clientSecret = "allowed",
            deniedClientSecret = "denied-proof",
            organizationSlug = slug ? "owned" : null
        };
        using NativeEnvironment environment = Environment(backend.Origin, Family("universal", definition, input));
        NativeCaseResult result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.IssuedAllowedReads).IsEqualTo(1);
        await Assert.That(backend.IssuedDeniedReads).IsEqualTo(1);
        await Assert.That(backend.IdentityExists).IsFalse();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("already-issued")]
    public async Task UnownedOrNonfreshIdentityIsNeverUsedOrDeleted(string mode)
    {
        await using var backend = new Backend(mode);
        NativeCaseDefinition definition = Definition("universal", "organizationSlug.omitted", "selected-contract");
        using NativeEnvironment environment = Environment(backend.Origin, Family("universal", definition, UniversalInput()));
        NativeCaseResult result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-prerequisite");
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
    }

    [Test]
    [Arguments("universal", "organizationSlug.omitted", "selected-contract")]
    [Arguments("universal", "organizationSlug.omitted", "independent-effect")]
    [Arguments("universal", "organizationSlug.value", "selected-contract")]
    [Arguments("universal", "organizationSlug.value", "independent-effect")]
    [Arguments("proof", "proof.Jwt", "selected-contract")]
    [Arguments("proof", "proof.Jwt", "independent-effect")]
    [Arguments("proof", "proof.Ldap", "selected-contract")]
    [Arguments("proof", "proof.Ldap", "independent-effect")]
    public async Task IssuedAuthenticationExpirySuccessfulReturnedCredentialRequiresBothWindows(
        string family, string variant, string caseName)
    {
        await using var backend = new Backend("good");
        var source = new ExpirySource(backend);
        var definition = Definition(family, variant, caseName);
        using var environment = LifetimeEnvironment(backend, definition);
        var result = (await RunAsync(environment, [definition], source)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(source.Attempt!.Source).IsEqualTo(AuthenticationExpirySource.ControlledFixture);
        await Assert.That(source.Attempt.Policy).IsEqualTo(new AuthenticationExpiryPolicy(600, 1200, 0, 0));
        await Assert.That(source.Attempt.DeploymentId).IsEqualTo("offline-auth-deployment");
        await Assert.That(source.Attempt.IdentityId).IsEqualTo(Identity);
        await Assert.That(source.Attempt.OrganizationId).IsEqualTo(Organization);
        await Assert.That(source.Attempt.Operation).IsEqualTo(definition.Key.Operation);
        await Assert.That(source.Attempt.Member).IsEqualTo(definition.Member);
        await Assert.That(source.Attempt.AuthenticationMethod).IsEqualTo(
            family == "universal" ? "universal-auth" : variant == "proof.Ldap" ? "ldap-auth" : "jwt-auth");
        await Assert.That(source.Windows).IsEqualTo(2);
        await Assert.That(backend.ExpiredAllowedReads).IsEqualTo(1);
        await Assert.That(backend.ExpiredDeniedReads).IsEqualTo(1);
        await Assert.That(source.ObserverSuccesses).IsEqualTo(2);
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(1);
        await Assert.That(backend.RevocationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsFalse();
        await AssertKeysClosedAsync(source);
    }

    [Test]
    [Arguments("maximumTTL.zero", 0, 600)]
    [Arguments("maximumTTL.positive", 1200, 600)]
    [Arguments("maximumTTL.positive", 1200, 300)]
    public async Task IssuedAuthenticationExpiryActualResponseLifetimeIsNotPolicyArithmetic(
        string variant, double maximum, double issuedSeconds)
    {
        await using var backend = new Backend("good", maximum, issuedSeconds);
        var source = new ExpirySource(backend);
        var definition = Definition("proof", variant, "independent-effect");
        var input = JsonSerializer.SerializeToNode(ProofInput(variant), LifetimeJson)!.AsObject();
        input["fixture"] = JsonSerializer.SerializeToNode(Fixture(maximum) with
        { ExpectedExpiresIn = issuedSeconds }, LifetimeJson);
        using var environment = LifetimeEnvironment(backend, definition, input);
        var result = (await RunAsync(environment, [definition], source)).Single();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(source.Attempt!.Policy.Ttl).IsEqualTo(600);
        await Assert.That(source.Attempt.Policy.MaximumTtl).IsEqualTo(maximum);
        await Assert.That(source.Attempt.ExpectedExpiresIn).IsEqualTo(issuedSeconds);
        await Assert.That(source.Binding!.ExpiresAt - source.Binding.IssuedAt)
            .IsEqualTo(TimeSpan.FromSeconds(issuedSeconds));
        await Assert.That(backend.ExpiredAllowedReads).IsEqualTo(1);
        await AssertKeysClosedAsync(source);
    }

    [Test]
    [Arguments("wrong-mac")]
    [Arguments("malformed-mac")]
    [Arguments("metadata-id")]
    [Arguments("handle")]
    [Arguments("method")]
    [Arguments("identity")]
    [Arguments("organization")]
    [Arguments("deployment")]
    [Arguments("policy")]
    [Arguments("response-lifetime")]
    [Arguments("response-maximum")]
    [Arguments("receipt")]
    [Arguments("source-clock")]
    [Arguments("early-expiry")]
    [Arguments("ignored-expiry")]
    [Arguments("permission-mutation")]
    [Arguments("ip-mutation")]
    [Arguments("use-exhaustion")]
    [Arguments("renewal")]
    [Arguments("revocation")]
    [Arguments("resource-gone")]
    [Arguments("local-expiry-hint")]
    [Arguments("no-http")]
    [Arguments("lost-arm")]
    [Arguments("duplicate-events")]
    [Arguments("callback-straddles")]
    [Arguments("cleanup-key")]
    [Arguments("cleanup-registration")]
    [Arguments("cleanup-delivery")]
    public async Task IssuedAuthenticationExpiryFaultMustActuallyReachSourceBeforeRejection(string fault)
    {
        await using var backend = new Backend("good");
        var source = new ExpirySource(backend, fault);
        var definition = Definition("universal", "organizationSlug.omitted", "independent-effect");
        using var environment = LifetimeEnvironment(backend, definition);
        var result = (await RunAsync(environment, [definition], source)).Single();
        // Failure alone is insufficient: the old unavailable handler must be Red.
        await Assert.That(source.Armed).IsTrue();
        await Assert.That(source.FaultReached).IsTrue();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsNotEqualTo("observed");
        await Assert.That(source.Closed).IsTrue();
        await Assert.That(source.HostKey is { Length: 32 } && source.HostKey.All(b => b == 0)).IsTrue();
        if (fault != "cleanup-key")
            await Assert.That(source.SourceKey is { Length: 32 } && source.SourceKey.All(b => b == 0)).IsTrue();
        if (fault.StartsWith("cleanup-", StringComparison.Ordinal))
            await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("missing")]
    [Arguments("null")]
    [Arguments("number")]
    [Arguments("deployment-missing")]
    [Arguments("deployment-null")]
    [Arguments("deployment-number")]
    [Arguments("deployment-empty")]
    [Arguments("source-missing")]
    [Arguments("source-null")]
    [Arguments("source-number")]
    [Arguments("source-unknown")]
    [Arguments("timeout-missing")]
    [Arguments("timeout-null")]
    [Arguments("timeout-string")]
    [Arguments("timeout-zero")]
    [Arguments("timeout-fraction")]
    [Arguments("timeout-excess")]
    public async Task IssuedAuthenticationExpiryInvalidProfileFailsBeforeFixtureOwnership(string fault)
    {
        await using var backend = new Backend("good");
        var definition = Definition("universal", "organizationSlug.omitted", "selected-contract");
        var source = new ExpirySource(backend);
        using var environment = LifetimeEnvironment(backend, definition, profileFault: fault);
        var result = (await RunAsync(environment, [definition], source)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityReads).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
        await Assert.That(source.Armed).IsFalse();
    }

    [Test]
    [Arguments("universal", "organizationSlug.omitted")]
    [Arguments("proof", "proof.Jwt")]
    public async Task IssuedAuthenticationExpiryMissingNativeSourceFailsBeforeOwnership(
        string family, string variant)
    {
        await using var backend = new Backend("good");
        var definition = Definition(family, variant, "independent-effect");
        using var environment = LifetimeEnvironment(backend, definition, sourceProfile: "NativeProvider");
        var result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(backend.IdentityReads).IsEqualTo(0);
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
    }

    [Test]
    [Arguments("\"ControlledFixture\"")]
    [Arguments("1")]
    [Arguments("99")]
    public async Task IssuedAuthenticationExpiryFamilyRootObserverCannotDeclareControlledAuthority(string source)
    {
        await using var backend = new Backend("good");
        var definition = Definition("universal", "organizationSlug.omitted", "independent-effect");
        var families = JsonSerializer.SerializeToNode(Family("universal", definition, UniversalInput()), LifetimeJson)!;
        var family = families["C08-IR-InfisicalUniversalAuthentication"]!.AsObject();
        family["scopes"]!["local"]!["authLifetime"] = new JsonObject
        {
            ["deploymentId"] = "offline-auth-deployment",
            ["sourceProfile"] = "NativeProvider",
            ["caseTimeoutSeconds"] = 120
        };
        family["observer"] = new JsonObject
        {
            ["endpoint"] = backend.Origin.AbsoluteUri,
            ["identity"] = "independent-response-capture",
            ["token"] = "offline-source-channel",
            ["timeoutSeconds"] = 10,
            ["source"] = JsonNode.Parse(source)
        };
        using var environment = Environment(backend.Origin, families);
        var result = (await RunAsync(environment, [definition])).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.IdentityReads).IsEqualTo(0);
        await Assert.That(backend.AuthenticationCalls).IsEqualTo(0);
        await Assert.That(backend.IdentityExists).IsTrue();
    }

    [Test]
    [Arguments("proof", "denied")]
    [Arguments("universal", "denied")]
    [Arguments("proof", "cancel")]
    [Arguments("universal", "cancel")]
    [Arguments("proof", "lost")]
    [Arguments("universal", "lost")]
    public async Task IssuedAuthenticationExpiryDeniedAndInaccessibleResponsesKeepExistingBoundary(
        string family, string mode)
    {
        await using var backend = new Backend(mode);
        var source = new ExpirySource(backend);
        var definition = Definition(family, family == "proof" ? "proof.Jwt" : "organizationSlug.omitted",
            mode == "denied" ? "denied-authority" : mode == "lost" ?
                "lost-response-no-replay" : "cancellation-boundary");
        using var environment = LifetimeEnvironment(backend, definition);
        var result = (await RunAsync(environment, [definition], source)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(mode == "denied" ? "observed" : "observer-unavailable");
        await Assert.That(result.Passed).IsEqualTo(mode == "denied");
        await Assert.That(source.Windows).IsEqualTo(0);
        await Assert.That(backend.AuthenticationCalls).IsLessThanOrEqualTo(1);
        await Assert.That(backend.IdentityExists).IsFalse();
        if (source.Armed) await AssertKeysClosedAsync(source);
    }

    // These are independently Green before handler forwarding: actual public
    // login/read requests, independently captured response HMAC, and a server
    // clock enforcing the complete 600-second interval without wall-clock waits.
    [Test]
    [Arguments("universal")]
    [Arguments("jwt")]
    [Arguments("ldap")]
    public async Task IssuedAuthenticationExpiryPublicSdkCharacterizesSourceClockAndKeyAssociation(string method)
    {
        await using var backend = new Backend("good");
        var source = new ExpirySource(backend);
        var definition = Definition(method == "universal" ? "universal" : "proof",
            method == "universal" ? "organizationSlug.omitted" : method == "ldap" ? "proof.Ldap" : "proof.Jwt",
            "independent-effect");
        var attempt = new AuthenticationExpiryAttempt(Guid.NewGuid().ToString("N"), "offline-case",
            definition.Key.Operation, definition.Member, "v0.166.3", "offline-auth-deployment",
            Organization, Identity, method + "-auth", new(600, 1200, 0, 0), 600, 1200,
            AuthenticationExpirySource.ControlledFixture);
        byte[] key = RandomNumberGenerator.GetBytes(32);
        try
        {
            var arm = await source.ArmAsync(attempt, key, CancellationToken.None);
            using var credential = SecretMaterial.FromText(method == "ldap" ? "password" : "jwt-proof");
            using var universal = new InfisicalUniversalAuthentication(backend.Origin, DevelopmentNetwork);
            using var proofAuthentication = new InfisicalProofAuthentication(backend.Origin, DevelopmentNetwork);
            InfisicalAccessToken issued;
            IDisposable login;
            DispatchEvidence receipt;
            if (method == "universal")
            {
                var dispatch = universal.CreateReceipt();
                var result = await universal.LoginAsync("client", credential, dispatch);
                await Assert.That(result.IsSuccess).IsTrue();
                login = result.Value;
                issued = result.Value.Token;
                receipt = dispatch.Evidence;
            }
            else
            {
                using var proof = method == "ldap" ? InfisicalLoginProof.Ldap(Identity, "user", credential) :
                    InfisicalLoginProof.Jwt(Identity, credential);
                var dispatch = proofAuthentication.CreateReceipt();
                var result = await proofAuthentication.LoginAsync(proof, dispatch);
                await Assert.That(result.IsSuccess).IsTrue();
                login = result.Value;
                issued = result.Value.Token;
                receipt = dispatch.Evidence;
            }
            using (login)
            {
                var binding = await source.CompleteAsync(arm, receipt, CancellationToken.None);
                byte[] expected = Witness(key, attempt, issued.Material);
                byte[] actual = Convert.FromBase64String(binding.CredentialWitness);
                try
                {
                    await Assert.That(CryptographicOperations.FixedTimeEquals(actual, expected)).IsTrue();
                    using var otherCredential = SecretMaterial.FromText("other-issued");
                    byte[] wrong = Witness(key, attempt, otherCredential);
                    byte[] otherDomain = Witness(key, attempt with { Id = "another-attempt" }, issued.Material);
                    try
                    {
                        await Assert.That(CryptographicOperations.FixedTimeEquals(actual, wrong)).IsFalse();
                        await Assert.That(CryptographicOperations.FixedTimeEquals(actual, otherDomain)).IsFalse();
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(wrong);
                        CryptographicOperations.ZeroMemory(otherDomain);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(expected);
                    CryptographicOperations.ZeroMemory(actual);
                }
                using var environment = Environment(backend.Origin, new { });
                var management = environment.CreateManagementClient();
                using var list = IdentityAuthenticationOperations.ListTokens(Organization, Identity);
                var authority = environment.CreateManagementAuthority(management, NativeIdentityRole.Observer, Organization);
                var rows = await management.ExecuteAsync(list, authority,
                    authority.IssueGrant(list.OperationId, new(Organization, resourceId: Identity)));
                await Assert.That(rows.IsSuccess).IsTrue();
                var row = rows.Value.Items.Single(r => r.Id == binding.TokenMetadataId);
                await Assert.That(row.AuthMethod).IsEqualTo(method + "-auth");
                await Assert.That(row.IdentityId).IsEqualTo(Identity);
                await Assert.That(row.AccessTokenNumUsesLimit).IsEqualTo(0);
                // Deliberately expired local hint: material-only source must strip it.
                using var hinted = new InfisicalAccessToken(issued.Material.Copy(), DateTimeOffset.UnixEpoch);
                await using var locallyExpired = new InfisicalClient(backend.Origin,
                    new HintedTokenSource(hinted.Material), DevelopmentNetwork);
                int readsBeforeHint = backend.IssuedAllowedReads;
                await Assert.That(await ReadCanaryAsync(locallyExpired, "ALLOWED", CancellationToken.None))
                    .IsEqualTo(SecretStatus.Expired);
                await Assert.That(backend.IssuedAllowedReads).IsEqualTo(readsBeforeHint);
                await using var consumer = new InfisicalClient(backend.Origin,
                    new AuthenticationTokenSource(hinted.Material), DevelopmentNetwork);
                foreach (var phase in Enum.GetValues<AuthenticationExpiryPhase>())
                {
                    var observation = await source.ObserveAsync(binding, phase, async token =>
                    {
                        var allowed = await ReadCanaryAsync(consumer, "ALLOWED", token);
                        var denied = await ReadCanaryAsync(consumer, "DENIED", token);
                        return (Allowed: allowed, Denied: denied);
                    }, CancellationToken.None);
                    await Assert.That(observation.Sample.Allowed).IsEqualTo(
                        phase == AuthenticationExpiryPhase.Active ? SecretStatus.Success : SecretStatus.Denied);
                    await Assert.That(observation.Sample.Denied).IsEqualTo(SecretStatus.Denied);
                    await Assert.That(observation.Window.ClosedAt).IsEqualTo(backend.SourceClock);
                }
                await Assert.That(backend.ExpiredAllowedReads).IsEqualTo(1);
                await Assert.That(backend.ExpiredDeniedReads).IsEqualTo(1);
                await Assert.That(source.ObserverSuccesses).IsEqualTo(2);
                await Assert.That(backend.RevocationCalls).IsEqualTo(0);
                await Assert.That(backend.SourceClock).IsEqualTo(binding.ExpiresAt);
            }
        }
        finally
        {
            await source.CloseAsync(attempt, CancellationToken.None);
            CryptographicOperations.ZeroMemory(key);
        }
        await AssertKeysClosedAsync(source);
    }

    private static InfisicalNetworkOptions DevelopmentNetwork => new() { AllowLoopbackDevelopmentHttp = true };
    private sealed class HintedTokenSource(SecretMaterial material) : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                new(material.Copy(), DateTimeOffset.UnixEpoch)));
        }
    }
    private static JsonSerializerOptions LifetimeJson { get; } =
        new(NativeRunProtocol.JsonOptions) { IgnoreReadOnlyProperties = false };

    private static NativeEnvironment LifetimeEnvironment(Backend backend, NativeCaseDefinition definition,
        object? input = null, string? profileFault = null, string sourceProfile = "ControlledFixture")
    {
        string family = definition.Key.Operation == InfisicalProofAuthenticationEffects.Operation ? "proof" : "universal";
        input ??= family == "proof" ? ProofInput(definition.Key.Variant) : UniversalInput();
        var packet = JsonSerializer.SerializeToNode(input, LifetimeJson)!.AsObject();
        if (family == "universal" && definition.Key.Variant == "organizationSlug.value")
            packet["organizationSlug"] = "owned";
        var families = JsonSerializer.SerializeToNode(Family(family, definition, packet), LifetimeJson)!.AsObject();
        var scope = families.First().Value!["scopes"]!["local"]!.AsObject();
        scope["authLifetime"] = new JsonObject
        {
            ["deploymentId"] = "offline-auth-deployment",
            ["sourceProfile"] = sourceProfile,
            ["caseTimeoutSeconds"] = 120
        };
        var profile = scope["authLifetime"]!.AsObject();
        switch (profileFault)
        {
            case "missing": scope.Remove("authLifetime"); break;
            case "null": scope["authLifetime"] = null; break;
            case "number": scope["authLifetime"] = 0; break;
            case "deployment-missing": profile.Remove("deploymentId"); break;
            case "deployment-null": profile["deploymentId"] = null; break;
            case "deployment-number": profile["deploymentId"] = 0; break;
            case "deployment-empty": profile["deploymentId"] = ""; break;
            case "source-missing": profile.Remove("sourceProfile"); break;
            case "source-null": profile["sourceProfile"] = null; break;
            case "source-number": profile["sourceProfile"] = 0; break;
            case "source-unknown": profile["sourceProfile"] = "LocalClock"; break;
            case "timeout-missing": profile.Remove("caseTimeoutSeconds"); break;
            case "timeout-null": profile["caseTimeoutSeconds"] = null; break;
            case "timeout-string": profile["caseTimeoutSeconds"] = "120"; break;
            case "timeout-zero": profile["caseTimeoutSeconds"] = 0; break;
            case "timeout-fraction": profile["caseTimeoutSeconds"] = 1.5; break;
            case "timeout-excess": profile["caseTimeoutSeconds"] = 901; break;
        }
        return Environment(backend.Origin, families);
    }

    private static async ValueTask<SecretStatus> ReadCanaryAsync(InfisicalClient client, string key,
        CancellationToken token)
    {
        var result = await client.ReadAsync(new SecretReference(client.Authority,
            new InfisicalSecretAddress("project", "dev", "/", key)), token);
        if (result.IsSuccess)
        {
            using var value = result.Value;
            if (value.Material.Reveal() != "owned-material") return SecretStatus.Unavailable;
        }
        return result.Status;
    }

    private static byte[] Witness(ReadOnlySpan<byte> key, AuthenticationExpiryAttempt attempt, SecretMaterial material)
    {
        char[] characters = material.ExportCharacters();
        byte[] credential = new byte[Encoding.UTF8.GetByteCount(characters)];
        byte[] domain = Encoding.UTF8.GetBytes("secretkit-issued-token-v1\0" + attempt.Id + "\0" +
            attempt.Operation + "\0" + attempt.IdentityId + "\0");
        try
        {
            Encoding.UTF8.GetBytes(characters, credential);
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            hmac.AppendData(domain);
            hmac.AppendData(credential);
            return hmac.GetHashAndReset();
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(credential);
            CryptographicOperations.ZeroMemory(domain);
        }
    }

    private static async Task AssertKeysClosedAsync(ExpirySource source)
    {
        await Assert.That(source.Armed).IsTrue();
        await Assert.That(source.Closed).IsTrue();
        await Assert.That(source.HostKey is { Length: 32 } && source.HostKey.All(b => b == 0)).IsTrue();
        await Assert.That(source.SourceKey is { Length: 32 } && source.SourceKey.All(b => b == 0)).IsTrue();
        await Assert.That(source.Registered).IsFalse();
    }

    private static AuthenticationFixtureInput Fixture(double maximum = 1200) =>
        new(Organization, Identity, OwnedName, "project", "dev", "/", "ALLOWED", "DENIED",
            "owned-material", 600, maximum, 0, 600, maximum,
            AuthenticationApiRevision.AuthV1IdentitiesV1SecretsV4);

    private static object UniversalInput() => new
    {
        fixture = Fixture(),
        clientId = "client",
        clientSecret = "allowed",
        deniedClientSecret = "denied-proof",
        organizationSlug = (string?)null
    };

    private static object ProofInput(string variant)
    {
        string strategy = variant switch
        {
            "proof.AliCloud" => "alicloud",
            "proof.Azure" => "azure",
            "proof.Gcp" => "gcp",
            "proof.Kubernetes" => "kubernetes",
            "proof.Oidc" => "oidc",
            "proof.Spiffe.JWT-SVID" => "spiffe",
            "proof.Ldap" => "ldap",
            "proof.TlsCertificate.host-mtls" => "tls-cert",
            _ when variant.StartsWith("proof.Aws.", StringComparison.Ordinal) => "aws",
            _ when variant.StartsWith("proof.Oci.", StringComparison.Ordinal) => "oci",
            _ => "jwt"
        };
        object Fields(bool denied) => new
        {
            strategy,
            jwt = denied ? "denied-proof" : "jwt-proof",
            iamRequestBody = denied ? "denied-proof" : "body",
            iamRequestHeaders = "headers",
            method = variant == "proof.Aws.method-value" ? "POST" : null,
            accessKeyId = "key",
            signature = denied ? "denied-proof" : "signature",
            signatureNonce = "nonce",
            timestamp = "2026-10-12T00:00:00Z",
            version = "2015-04-01",
            username = "user",
            password = denied ? "denied-proof" : "password",
            userOcid = "user",
            authorization = denied ? "denied-proof" : "signed",
            host = "issuer",
            date = variant is "proof.Oci.date" or "proof.Oci.date-and-x-date" ? "date" : null,
            xDate = variant is "proof.Oci.x-date" or "proof.Oci.date-and-x-date" ? "xdate" : null
        };
        return new
        {
            fixture = Fixture(variant == "maximumTTL.zero" ? 0 : 1200),
            organizationSlug = variant == "organizationSlug.value" ? "owned" : null,
            proof = Fields(false),
            deniedProof = Fields(true)
        };
    }

    private static NativeCaseDefinition Definition(string family, string variant, string @case) =>
        new(new("Infisical", family switch
        {
            "proof" => InfisicalProofAuthenticationEffects.Operation,
            "revoke" => InfisicalTokenRevocationEffects.Operation,
            _ => InfisicalUniversalAuthenticationEffects.Operation
        }, variant, "local", @case), family switch
        {
            "proof" => InfisicalProofAuthenticationEffects.Member,
            "revoke" => InfisicalTokenRevocationEffects.Member,
            _ => InfisicalUniversalAuthenticationEffects.Member
        });

    private static object Family(string family, NativeCaseDefinition definition, object input) =>
        new Dictionary<string, object>
        {
            [family switch
            {
                "proof" => "C08-IR-InfisicalProofAuthentication",
                "revoke" => "C08-IR-InfisicalTokenRevocation",
                _ => "C08-IR-InfisicalUniversalAuthentication"
            }] = new
            {
                scopes = new Dictionary<string, object>
                {
                    [definition.Key.Scope] = new Dictionary<string, object>
                    {
                        [definition.Key.Operation] = new Dictionary<string, object>
                        {
                            [definition.Key.Variant] = new Dictionary<string, object> { [definition.Key.Case] = input }
                        }
                    }
                }
            }
        };

    private static NativeEnvironment Environment(Uri origin, object families) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, new JsonSerializerOptions(NativeRunProtocol.JsonOptions) { IgnoreReadOnlyProperties = false }));

    private static async Task<IReadOnlyList<NativeCaseResult>> RunAsync(NativeEnvironment environment,
        NativeCaseDefinition[] expected, IAuthenticationExpiryObserver? expiryObserver = null)
    {
        var registry = new NativeCaseRegistry();
        InfisicalAuthenticationFamilies.Register(registry, environment, expected, expiryObserver);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        return await NativeCaseRunner.RunAsync(registry, expected, deadline.Token);
    }

    private sealed class ExpirySource(Backend backend, string? fault = null) : IAuthenticationExpiryObserver
    {
        internal AuthenticationExpiryAttempt? Attempt { get; private set; }
        internal AuthenticationExpiryFence? Binding { get; private set; }
        internal byte[]? HostKey { get; private set; }
        internal byte[]? SourceKey { get; private set; }
        internal bool Armed { get; private set; }
        internal bool Registered { get; private set; }
        internal bool Closed { get; private set; }
        internal bool FaultReached { get; private set; }
        internal int Windows { get; private set; }
        internal int ObserverSuccesses { get; private set; }
        private string? capturedWitness;
        private double capturedExpiresIn;
        private double capturedMaximum;
        private string? capturedMethod;
        private DateTimeOffset capturedAt;
        private long sequence;

        public ValueTask<AuthenticationExpiryArm> ArmAsync(AuthenticationExpiryAttempt attempt,
            ReadOnlyMemory<byte> correlationKey, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (Registered || correlationKey.Length != 32 ||
                !MemoryMarshal.TryGetArray(correlationKey, out ArraySegment<byte> callerKey) ||
                callerKey.Offset != 0 || callerKey.Count != callerKey.Array!.Length)
                throw new NativeCaseFailureException("observer-unavailable");
            Attempt = attempt;
            HostKey = callerKey.Array;
            SourceKey = correlationKey.ToArray();
            Armed = Registered = true;
            backend.Capture = Capture;
            if (fault == "lost-arm")
            {
                FaultReached = true;
                throw new NativeCaseFailureException("observer-unavailable");
            }
            return ValueTask.FromResult(new AuthenticationExpiryArm(attempt, "registration-" + attempt.Id,
                "independent-response-capture", "offline-provider-clock", "offline-epoch",
                backend.SourceClock, sequence, "actual-policy-snapshot", true));
        }

        // Called on the provider's serialized successful response, before HTTP
        // delivery, independently of the SDK outcome. Metadata join is the
        // provider's actual issuance row, never inferred from host singleton data.
        private void Capture(ReadOnlyMemory<byte> payload)
        {
            if (!Registered || Attempt is null || SourceKey is null)
                throw new InvalidOperationException("capture-not-armed");
            using var response = JsonDocument.Parse(payload);
            var value = response.RootElement;
            var reader = new Utf8JsonReader(payload.Span);
            byte[]? credential = null;
            while (reader.Read())
            {
                if (reader.TokenType != JsonTokenType.PropertyName || !reader.ValueTextEquals("accessToken")) continue;
                reader.Read();
                if (reader.TokenType != JsonTokenType.String || reader.ValueIsEscaped)
                    throw new InvalidOperationException("fixture-response");
                credential = reader.ValueSpan.ToArray();
                break;
            }
            if (credential is null) throw new InvalidOperationException("fixture-response");
            byte[] domain = Encoding.UTF8.GetBytes(string.Join('\0',
                "secretkit-issued-token-v1", Attempt.Id, Attempt.Operation, Attempt.IdentityId, ""));
            try
            {
                using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, SourceKey);
                hmac.AppendData(domain);
                hmac.AppendData(credential);
                byte[] digest = hmac.GetHashAndReset();
                try { capturedWitness = Convert.ToBase64String(digest); }
                finally { CryptographicOperations.ZeroMemory(digest); }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(credential);
                CryptographicOperations.ZeroMemory(domain);
            }
            capturedExpiresIn = value.GetProperty("expiresIn").GetDouble();
            capturedMaximum = value.GetProperty("accessTokenMaxTTL").GetDouble();
            capturedMethod = backend.IssuedMethod;
            capturedAt = backend.SourceClock;
        }

        public ValueTask<AuthenticationExpiryFence> CompleteAsync(AuthenticationExpiryArm arm,
            DispatchEvidence receipt, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (!Registered || capturedWitness is null || receipt != DispatchEvidence.Applied)
                throw new NativeCaseFailureException("observer-unavailable");
            var observedArm = arm with
            {
                Attempt = arm.Attempt with
                {
                    AuthenticationMethod = capturedMethod!,
                    OrganizationId = Organization,
                    IdentityId = Identity,
                    DeploymentId = "offline-auth-deployment"
                }
            };
            var binding = new AuthenticationExpiryFence(observedArm, receipt, "actual-provider-request",
                TokenId, "actual-issued-handle", capturedWitness, backend.Policy,
                capturedExpiresIn, capturedMaximum, capturedAt, backend.IssuedExpiresAt,
                ++sequence, 1, true, true, true);
            binding = fault switch
            {
                "wrong-mac" => binding with { CredentialWitness = Convert.ToBase64String(new byte[32]) },
                "malformed-mac" => binding with { CredentialWitness = "not-base64" },
                "metadata-id" => binding with { TokenMetadataId = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee" },
                "handle" => binding with { CredentialHandle = "other-issued-handle" },
                "method" => binding with
                {
                    Arm = observedArm with
                    { Attempt = observedArm.Attempt with { AuthenticationMethod = "token-auth" } }
                },
                "identity" => binding with
                {
                    Arm = observedArm with
                    { Attempt = observedArm.Attempt with { IdentityId = TokenId } }
                },
                "organization" => binding with
                {
                    Arm = observedArm with
                    { Attempt = observedArm.Attempt with { OrganizationId = TokenId } }
                },
                "deployment" => binding with
                {
                    Arm = observedArm with
                    { Attempt = observedArm.Attempt with { DeploymentId = "other-deployment" } }
                },
                "policy" => binding with { ObservedPolicy = backend.Policy with { Ttl = 599 } },
                "response-lifetime" => binding with { ResponseExpiresIn = capturedExpiresIn + 1 },
                "response-maximum" => binding with { ResponseMaximumTtl = capturedMaximum + 1 },
                "receipt" => binding with { Disposition = DispatchEvidence.Rejected },
                "source-clock" => binding with { Arm = observedArm with { ClockEpoch = "other-epoch" } },
                _ => binding
            };
            if (fault is "wrong-mac" or "malformed-mac" or "metadata-id" or "handle" or "method" or
                "identity" or "organization" or "deployment" or "policy" or "response-lifetime" or
                "response-maximum" or "receipt" or "source-clock") FaultReached = true;
            Binding = binding;
            return ValueTask.FromResult(binding);
        }

        public async ValueTask<AuthenticationExpiryObservation<T>> ObserveAsync<T>(AuthenticationExpiryFence binding,
            AuthenticationExpiryPhase phase, Func<CancellationToken, ValueTask<T>> sample, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (!Registered || binding != Binding) throw new NativeCaseFailureException("observer-unavailable");
            backend.SourceClock = phase == AuthenticationExpiryPhase.Active ? capturedAt : backend.IssuedExpiresAt;
            bool expired = phase == AuthenticationExpiryPhase.Expired;
            backend.ExpiryFault = fault;
            DateTimeOffset opened = backend.SourceClock;
            bool reachedHere = fault is "early-expiry" or "ignored-expiry" or "permission-mutation" or
                "ip-mutation" or "use-exhaustion" or "renewal" or "revocation" or "resource-gone" or
                "local-expiry-hint" or "no-http" or "duplicate-events" or "callback-straddles";
            if (reachedHere && (expired || fault is "early-expiry" or "callback-straddles")) FaultReached = true;
            T sampled;
            if (expired && fault == "local-expiry-hint")
            {
                // Deliberately false witness: SDK local Expired, not provider
                // Denied, and no HTTP. The host must reject an absent callback.
                using var material = SecretMaterial.FromText("issued");
                await using var hinted = new InfisicalClient(backend.Origin,
                    new HintedTokenSource(material), DevelopmentNetwork);
                if (await ReadCanaryAsync(hinted, "ALLOWED", token) != SecretStatus.Expired)
                    throw new InvalidOperationException("local-hint-fault-not-reached");
                sampled = default!;
            }
            else sampled = expired && fault == "no-http" ? default! : await sample(token);
            using var observerMaterial = SecretMaterial.FromText("observer");
            await using var observer = new InfisicalClient(backend.Origin,
                new AuthenticationTokenSource(observerMaterial), DevelopmentNetwork);
            if (await ReadCanaryAsync(observer, "ALLOWED", token) == SecretStatus.Success) ObserverSuccesses++;
            if (fault == "callback-straddles" && !expired) backend.SourceClock = backend.IssuedExpiresAt;
            Windows++;
            var window = new AuthenticationExpiryWindow(
                binding with { CredentialHandle = "actual-issued-handle" }, phase,
                "window-" + phase, fault == "duplicate-events" ? "same-event" : "event-" + phase,
                ++sequence, opened, backend.SourceClock, true, true, expired,
                !expired || fault != "permission-mutation", !expired || fault != "ip-mutation", !expired || fault != "renewal",
                !expired || fault != "revocation", !expired || fault != "use-exhaustion");
            return new(window, sampled);
        }

        public ValueTask<AuthenticationExpiryCleanup> CloseAsync(AuthenticationExpiryAttempt attempt,
            CancellationToken token)
        {
            if (attempt != Attempt) throw new NativeCaseFailureException("cleanup-incomplete");
            if (fault != "cleanup-key" && SourceKey is not null) CryptographicOperations.ZeroMemory(SourceKey);
            backend.Capture = null;
            capturedWitness = null;
            Registered = fault == "cleanup-registration";
            Closed = true;
            if (fault is "cleanup-key" or "cleanup-registration" or "cleanup-delivery") FaultReached = true;
            return ValueTask.FromResult(new AuthenticationExpiryCleanup(attempt, true, true, true, true,
                fault != "cleanup-key", Registered ? 1 : 0, fault == "cleanup-delivery" ? 1 : 0));
        }
    }

    // Stateful offline provider: authentication responses cannot alter observations
    // by themselves. Separate protected SDK requests inspect actual fixture state.
    private sealed class Backend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Task accept;
        private readonly string mode;
        private readonly double maximum;
        private readonly double issuedSeconds;
        private bool issued;
        private bool revoked;
        private string method = "token-auth";
        internal Uri Origin { get; }
        internal bool IdentityExists { get; private set; } = true;
        internal int AuthenticationCalls { get; private set; }
        internal int RevocationCalls { get; private set; }
        internal int IssuedAllowedReads { get; private set; }
        internal int IssuedDeniedReads { get; private set; }
        internal int ExpiredAllowedReads { get; private set; }
        internal int ExpiredDeniedReads { get; private set; }
        internal int IdentityReads { get; private set; }
        internal JsonElement? Proof { get; private set; }
        internal DateTimeOffset SourceClock { get; set; } = DateTimeOffset.UnixEpoch.AddDays(1);
        internal DateTimeOffset IssuedExpiresAt { get; private set; }
        internal string IssuedMethod => method;
        internal AuthenticationExpiryPolicy Policy => new(mode == "periodic" ? 10 : 600,
            mode == "periodic" ? 20 : maximum, mode == "periodic" ? 60 : 0, 0);
        internal Action<ReadOnlyMemory<byte>>? Capture { get; set; }
        internal string? ExpiryFault { get; set; }

        internal Backend(string mode, double maximum = 1200, double issuedSeconds = 600)
        {
            this.mode = mode;
            this.maximum = maximum;
            this.issuedSeconds = issuedSeconds;
            issued = mode == "already-issued";
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                try
                {
                    NetworkStream stream = socket.GetStream();
                    var header = new List<byte>();
                    byte[] one = new byte[1];
                    while (header.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        header.Add(one[0]);
                        if (header.Count >= 4 && header.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n");
                    string[] first = lines[0].Split(' ');
                    string role = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                        ?.Split(' ').Last() ?? "";
                    int length = int.Parse(lines.FirstOrDefault(l =>
                        l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                    if (length is < 0 or > 131072) throw new InvalidOperationException("fixture-input");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    using JsonDocument json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                    string path = new Uri(Origin, first[1]).AbsolutePath;
                    (int Status, object Body) response = Handle(first[0], path, role, json.RootElement);
                    byte[] payload = JsonSerializer.SerializeToUtf8Bytes(response.Body);
                    byte[] headers = Encoding.ASCII.GetBytes($"HTTP/1.1 {response.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n");
                    try
                    {
                        if (response.Status == 200 && path.EndsWith("/login", StringComparison.Ordinal))
                            Capture?.Invoke(payload);
                        await stream.WriteAsync(headers, shutdown.Token);
                        if (mode == "lost" && (path.EndsWith("/login", StringComparison.Ordinal) ||
                            path == "/api/v1/auth/token/revoke"))
                        {
                            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                            await release.Task.WaitAsync(shutdown.Token);
                        }
                        await stream.WriteAsync(payload, shutdown.Token);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(body);
                        CryptographicOperations.ZeroMemory(payload);
                    }
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private (int, object) Handle(string verb, string path, string role, JsonElement body)
        {
            if (role == "observer" && mode == "observer" && path.Contains("/tokens", StringComparison.Ordinal))
                return (403, new { });
            if (path == "/api/v1/identities/" + Identity)
            {
                if (verb == "GET") IdentityReads++;
                if (!IdentityExists) return (404, new { });
                object identity = new
                {
                    id = Identity,
                    orgId = Organization,
                    name = mode == "foreign" ? "foreign" : OwnedName,
                    hasDeleteProtection = false,
                    createdAt = "2026-10-12T00:00:00Z",
                    updatedAt = "2026-10-12T00:00:00Z"
                };
                if (verb == "DELETE")
                {
                    if (role != "administrative" || mode == "cleanup") return (403, new { });
                    IdentityExists = false;
                    return (200, new { identity });
                }
                return (200, new
                {
                    identity = new
                    {
                        id = "dddddddd-dddd-dddd-dddd-dddddddddddd",
                        orgId = Organization,
                        identityId = Identity,
                        role = "member",
                        createdAt = "2026-10-12T00:00:00Z",
                        updatedAt = "2026-10-12T00:00:00Z",
                        identity = new
                        {
                            id = Identity,
                            orgId = Organization,
                            name = mode == "foreign" ? "foreign" : OwnedName,
                            hasDeleteProtection = false,
                            authMethods = Array.Empty<string>(),
                            activeLockoutAuthMethods = Array.Empty<string>()
                        }
                    }
                });
            }
            if (path == "/api/v1/auth/token-auth/identities/" + Identity + "/tokens")
            {
                if (verb == "POST")
                {
                    if (role != "setup") return (403, new { });
                    issued = true;
                    method = "token-auth";
                    return (200, new
                    {
                        tokenData = TokenRow(),
                        accessToken = "issued",
                        tokenType = "Bearer",
                        expiresIn = 600,
                        accessTokenMaxTTL = maximum
                    });
                }
                return (200, new { tokens = issued ? new[] { TokenRow() } : Array.Empty<object>() });
            }
            if (path.EndsWith("/login", StringComparison.Ordinal))
            {
                AuthenticationCalls++;
                Proof = body.Clone();
                if (body.GetRawText().Contains("denied-proof", StringComparison.Ordinal)) return (403, new { });
                issued = true;
                method = path.Split('/')[4];
                IssuedExpiresAt = SourceClock.AddSeconds(mode == "periodic" ? 60 : issuedSeconds);
                return (200, new
                {
                    accessToken = "issued",
                    tokenType = "Bearer",
                    expiresIn = mode == "periodic" ? 60 : issuedSeconds,
                    accessTokenMaxTTL = mode == "periodic" ? 0 : maximum
                });
            }
            if (path == "/api/v1/auth/token-auth/tokens/" + TokenId + "/revoke")
            {
                if (role != "administrative") return (403, new { });
                revoked = true;
                return (200, new { message = "revoked" });
            }
            if (path == "/api/v1/auth/token/revoke")
            {
                RevocationCalls++;
                if (revoked) return (403, new { });
                if (mode != "no-effect") revoked = true;
                return (200, new { message = "accepted" });
            }
            if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
            {
                bool deniedKey = path.EndsWith("/DENIED", StringComparison.Ordinal);
                if (role == "issued")
                {
                    if (deniedKey) IssuedDeniedReads++; else IssuedAllowedReads++;
                    if (SourceClock >= IssuedExpiresAt && Capture is not null)
                    {
                        if (deniedKey) ExpiredDeniedReads++; else ExpiredAllowedReads++;
                    }
                }
                if (Capture is not null && ExpiryFault == "resource-gone" &&
                    SourceClock >= IssuedExpiresAt) return (404, new { });
                bool alternativeDenial = Capture is not null && SourceClock >= IssuedExpiresAt &&
                    ExpiryFault is "permission-mutation" or "ip-mutation" or "use-exhaustion" or "revocation";
                bool naturalExpiry = Capture is not null && SourceClock >= IssuedExpiresAt &&
                    ExpiryFault is not ("ignored-expiry" or "renewal" or "permission-mutation" or
                        "ip-mutation" or "use-exhaustion" or "revocation");
                if (role == "denied" || role == "issued" &&
                    (revoked || deniedKey && mode != "bad-scope" ||
                        alternativeDenial || naturalExpiry || Capture is not null && ExpiryFault == "early-expiry"))
                    return (403, new { });
                return (200, new
                {
                    secret = new
                    {
                        secretKey = deniedKey ? "DENIED" : "ALLOWED",
                        version = 1,
                        secretValueHidden = false,
                        secretValue = role == "issued" && mode == "bad-value" ? "wrong" : "owned-material"
                    }
                });
            }
            return (404, new { });
        }

        private object TokenRow() => new
        {
            id = TokenId,
            identityId = Identity,
            authMethod = method,
            createdAt = "2026-10-12T00:00:00Z",
            updatedAt = "2026-10-12T00:00:00Z",
            accessTokenTTL = mode == "bad-metadata" ? 1 : mode == "periodic" ? 10 : 600,
            accessTokenMaxTTL = mode == "periodic" ? 20 : maximum,
            accessTokenPeriod = mode == "periodic" ? 60 : 0,
            accessTokenNumUses = ExpiryFault == "use-exhaustion" && SourceClock >= IssuedExpiresAt ? 1 : 0,
            accessTokenNumUsesLimit = ExpiryFault == "use-exhaustion" && SourceClock >= IssuedExpiresAt ? 1 : 0,
            isAccessTokenRevoked = revoked
        };

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
    }
}
