using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalManagementTlsTests
{
    private const string Org = "00000000-0000-0000-0000-000000000001";
    private const string Identity = "00000000-0000-0000-0000-000000000011";
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(30);

    public static IEnumerable<(string Operation, string Variant, string Case)> Cases()
    {
        foreach (var (operation, binding) in InfisicalIdentityAuthenticationFamilies.Bindings
            .Where(b => b.Key.Contains("TlsCert", StringComparison.Ordinal)))
            foreach (string variant in binding.Variants)
                if (!variant.Contains("unestablished", StringComparison.Ordinal) &&
                    !variant.Contains("TrustedIps.value", StringComparison.Ordinal))
                    foreach (string boundary in binding.Mutation ?
                        new[] { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary", "lost-response-no-replay" } :
                        new[] { "selected-contract", "independent-effect", "denied-authority", "cancellation-boundary" })
                        yield return (operation, variant, boundary);
    }

    [Test]
    public async Task DeniedPeerPresentsItsOwnIntermediateChainWithoutTransportLeakage()
    {
        await using var backend = new InfisicalIdentityAuthenticationFamilyTests.Backend("good");
        await using var control = new InfisicalManagementTlsControl(backend.IssueTls);
        backend.TlsControl = control;
        JsonObject scope = Scope(control, "response.known-fields");
        scope["issuers"]!["tls-cert"]!["denied"] = new JsonObject
        {
            ["certificate"] = InfisicalManagementTlsControl.Packet(control.Chained),
            ["intermediatesPem"] = new JsonArray(control.Intermediate.ExportCertificatePem())
        };
        using NativeEnvironment environment = InfisicalIdentityAuthenticationFamilyTests.Environment(backend.Origin, scope);
        var definition = InfisicalIdentityAuthenticationFamilyTests.Definition(
            "ExternalIdentityAuthenticationOperations.GetTlsCertAuth", "response.known-fields", "independent-effect");
        var registry = new NativeCaseRegistry();
        bool presented = false;
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition], (_, handler) =>
        {
            if (handler.SslOptions.ClientCertificates![0].GetCertHashString(HashAlgorithmName.SHA256) ==
                control.Chained.GetCertHashString(HashAlgorithmName.SHA256))
                presented |= handler.SslOptions.ClientCertificateContext is not null;
            TrustControl(handler, control);
            return new(control.Origin, handler);
        });
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(presented).IsTrue();
        await Assert.That(control.Logins.Any(l => !l.Allowed &&
            l.Leaf == control.Chained.GetCertHashString(HashAlgorithmName.SHA256))).IsTrue();
        await Assert.That(control.Leaked).IsFalse();
        await Assert.That(backend.IdentityCount + backend.ProjectCount + control.Count + backend.TlsTokenCount).IsEqualTo(0);
    }

    [Test]
    public async Task EveryRetainedTlsLabelHasAnExplicitAdmissionDecision()
    {
        var labels = InfisicalIdentityAuthenticationFamilies.Bindings.Where(b => b.Key.Contains("TlsCert", StringComparison.Ordinal))
            .SelectMany(b => b.Value.Variants.Select(v => (b.Key, Variant: v))).ToArray();
        await Assert.That(labels.Length).IsEqualTo(65);
        await Assert.That(labels.Count(l => !l.Variant.Contains("unestablished", StringComparison.Ordinal))).IsEqualTo(57);
        await Assert.That(Cases().Select(c => (c.Operation, c.Variant)).Distinct().Count()).IsEqualTo(55);
        await Assert.That(Cases().Count()).IsEqualTo(273);
        foreach (var label in labels)
        {
            var definition = new NativeCaseDefinition(new("Infisical", label.Key, label.Variant, "local", "selected-contract"),
                InfisicalIdentityAuthenticationFamilies.Bindings[label.Key].Member);
            string? expected = label.Variant.Contains("unestablished", StringComparison.Ordinal) ? "primary-auth-response-shapes" :
                label.Variant.Contains("TrustedIps.value", StringComparison.Ordinal) ? "trusted-ip-enforcement-observer-unavailable" : null;
            await Assert.That(InfisicalIdentityAuthenticationFamilies.UnavailableReason(definition)).IsEqualTo(expected);
            Console.WriteLine($"MANAGEMENT TLS label: {label.Key}/{label.Variant}: {expected ?? "authored-private-witness"}");
        }
    }

    [Test]
    [Arguments("ignore-caCertificate", "TlsCertAuthConfigurationInput.caCertificate.value")]
    [Arguments("ignore-allowedCommonNames", "allowedCommonNames.value")]
    [Arguments("ignore-allowedSubjectAltNames", "allowedSubjectAltNames.values")]
    [Arguments("ignore-verifyClientCertificateChain", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.true")]
    [Arguments("ignore-accessTokenTTL", "WorkloadAuthTokenPolicy.accessTokenTTL.value")]
    [Arguments("ignore-accessTokenMaxTTL", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value")]
    [Arguments("ignore-accessTokenNumUsesLimit", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value")]
    [Arguments("ca-readback", "response.known-fields")]
    [Arguments("accept-denied", "response.known-fields")]
    [Arguments("deny-valid", "response.known-fields")]
    [Arguments("expired-peer", "response.known-fields")]
    [Arguments("future-peer", "response.known-fields")]
    public async Task IndependentStateAndPeerCounterexamplesCannotPass(string fault, string variant)
    {
        await using var backend = new InfisicalIdentityAuthenticationFamilyTests.Backend("good");
        await using var control = new InfisicalManagementTlsControl(backend.IssueTls, fault);
        backend.TlsControl = control;
        using NativeEnvironment environment = InfisicalIdentityAuthenticationFamilyTests.Environment(backend.Origin, Scope(control, variant));
        var definition = InfisicalIdentityAuthenticationFamilyTests.Definition(
            "ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth", variant, "lost-response-no-replay");
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition], (_, handler) =>
        {
            TrustControl(handler, control);
            return new(control.Origin, handler);
        });
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode is "effect-mismatch" or "missing-prerequisite").IsTrue().Because(result.ReasonCode);
        await Assert.That(backend.IdentityCount + backend.ProjectCount + control.Count + backend.TlsTokenCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("absent-accepted")]
    [Arguments("absent-denied")]
    [Arguments("same-leaf")]
    [Arguments("malformed")]
    [Arguments("unexpected-proof-field")]
    [Arguments("unexpected-packet-field")]
    [Arguments("insecure-origin")]
    [Arguments("malformed-denied-chain")]
    public async Task InvalidPrivateCertificateSelectionFailsBeforeOwnership(string fault)
    {
        await using var backend = new InfisicalIdentityAuthenticationFamilyTests.Backend("good");
        await using var control = new InfisicalManagementTlsControl(backend.IssueTls);
        backend.TlsControl = control;
        JsonObject scope = Scope(control, "response.known-fields");
        JsonObject issuer = scope["issuers"]!["tls-cert"]!.AsObject();
        switch (fault)
        {
            case "absent-accepted": issuer["allowed"]!.AsObject().Remove("certificate"); break;
            case "absent-denied": issuer["denied"]!.AsObject().Remove("certificate"); break;
            case "same-leaf": issuer["denied"] = issuer["allowed"]!.DeepClone(); break;
            case "malformed": issuer["allowed"]!["certificate"]!["pkcs12Base64"] = "private-malformed"; break;
            case "unexpected-proof-field": issuer["allowed"]!["bearer"] = "private-bearer"; break;
            case "unexpected-packet-field": issuer["allowed"]!["certificate"]!["key"] = "private-key"; break;
            case "malformed-denied-chain": issuer["denied"]!["intermediatesPem"] = new JsonArray("private-malformed-chain"); break;
        }
        using NativeEnvironment environment = InfisicalIdentityAuthenticationFamilyTests.Environment(backend.Origin, scope);
        var definition = InfisicalIdentityAuthenticationFamilyTests.Definition(
            "ExternalIdentityAuthenticationOperations.AttachTlsCertAuth", "response.known-fields", "independent-effect");
        var registry = new NativeCaseRegistry();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition],
            fault == "insecure-origin" ? null : (_, handler) =>
            {
                TrustControl(handler, control);
                return new(control.Origin, handler);
            });
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(backend.RequestCount).IsEqualTo(0);
        await Assert.That(control.Logins.Count + control.Count).IsEqualTo(0);
    }

    [Test]
    public async Task IndependentSdkCalibrationUsesWriteOnlyMutationsReadbackAndActualTlsPeer()
    {
        await using var backend = new InfisicalIdentityAuthenticationFamilyTests.Backend("good");
        await using var control = new InfisicalManagementTlsControl(backend.IssueTls);
        backend.TlsControl = control;
        using NativeEnvironment environment = InfisicalIdentityAuthenticationFamilyTests.Environment(backend.Origin,
            InfisicalIdentityAuthenticationFamilyTests.Scope());
        using SecretMaterial ca = SecretMaterial.FromText(control.Ca.ExportCertificatePem());
        using var input = new TlsCertAuthConfigurationInput(ca, WorkloadAuthNullableText.FromValue("selected"),
            TlsAuthSubjectAltNames.FromValues(["DNS:selected.invalid"]), false, new(600, 1800, 2000));
        using TlsCertAuthConfiguration attached = await Need(environment,
            () => ExternalIdentityAuthenticationOperations.AttachTlsCertAuth(Org, Identity, input));
        await Assert.That(attached.CaCertificate is null).IsTrue();
        await Assert.That(attached.HasUnestablishedEncryptedCaCertificateProjection).IsTrue();
        using TlsCertAuthConfiguration read = await Need(environment,
            () => ExternalIdentityAuthenticationOperations.GetTlsCertAuth(Org, Identity));
        await Assert.That(read.CaCertificate!.Reveal()).IsEqualTo(ca.Reveal());
        using var pair = ProofCertificatePair.Load(Packet(control.Accepted), Packet(control.Denied));
        foreach (bool denied in new[] { false, true })
        {
            using SocketsHttpHandler handler = pair.CreateHandler(denied);
            TrustControl(handler, control);
            using var authentication = new InfisicalProofAuthentication(control.Origin, handler);
            using var proof = InfisicalLoginProof.TlsCertificate(Identity);
            var receipt = authentication.CreateReceipt();
            SecretOutcome<InfisicalProofLogin> outcome = await authentication.LoginAsync(proof, receipt).AsTask().WaitAsync(Deadline);
            using InfisicalProofLogin? login = outcome.IsSuccess ? outcome.Value : null;
            await Assert.That(outcome.Status).IsEqualTo(denied ? SecretStatus.Denied : SecretStatus.Success);
            await Assert.That(receipt.Evidence).IsEqualTo(denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied);
        }
        using var patch = new TlsCertAuthConfigurationInput(allowedCommonNames: WorkloadAuthNullableText.Null(),
            allowedSubjectAltNames: TlsAuthSubjectAltNames.FromValues([]), verifyClientCertificateChain: true,
            policy: new(300, 1200, 1000));
        using TlsCertAuthConfiguration updated = await Need(environment,
            () => ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth(Org, Identity, patch));
        using TlsCertAuthConfiguration after = await Need(environment,
            () => ExternalIdentityAuthenticationOperations.GetTlsCertAuth(Org, Identity));
        await Assert.That(updated.CaCertificate is null && after.AllowedCommonNames.IsNull &&
            after.AllowedSubjectAltNames.Value.Count == 0 && after.VerifyClientCertificateChain == true).IsTrue();
        await Assert.That(after.CaCertificate!.Reveal()).IsEqualTo(ca.Reveal());
        await Assert.That(control.Writes.Count).IsEqualTo(2);
        await Assert.That(control.Writes[1].Input.ContainsKey("caCertificate")).IsFalse();
        using TlsCertAuthConfiguration removed = await Need(environment,
            () => ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth(Org, Identity));
        await Assert.That(removed.CaCertificate is null).IsTrue();
        await Assert.That(control.Count).IsEqualTo(0);
        await Assert.That(control.Logins.Select(l => l.Allowed).SequenceEqual([true, false])).IsTrue();
        await Assert.That(control.Leaked).IsFalse();
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRegistrationRetainsEverySupportedLabelAndBoundary(string operation, string variant, string boundary)
    {
        await using var backend = new InfisicalIdentityAuthenticationFamilyTests.Backend("good");
        await using var control = new InfisicalManagementTlsControl(backend.IssueTls);
        backend.TlsControl = control;
        using NativeEnvironment environment = InfisicalIdentityAuthenticationFamilyTests.Environment(backend.Origin, Scope(control, variant));
        var definition = new NativeCaseDefinition(new("Infisical", operation, variant, "local", boundary),
            InfisicalIdentityAuthenticationFamilies.Bindings[operation].Member);
        var registry = new NativeCaseRegistry();
        var imported = new List<X509Certificate2>();
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, [definition], (_, handler) =>
        {
            imported.Add((X509Certificate2)handler.SslOptions.ClientCertificates![0]);
            TrustControl(handler, control);
            return new(control.Origin, handler);
        });
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(operation + "/" + variant + "/" + boundary + ": " + result.ReasonCode);
        await Assert.That(backend.IdentityCount + backend.ProjectCount + control.Count + backend.TlsTokenCount).IsEqualTo(0);
        await Assert.That(control.Leaked).IsFalse();
        await Assert.That(imported.All(c => c.Handle == IntPtr.Zero)).IsTrue();
        await Assert.That(control.Accepted.HasPrivateKey && control.Denied.HasPrivateKey).IsTrue();
    }

    internal static JsonObject Scope(InfisicalManagementTlsControl control, string variant)
    {
        JsonObject scope = InfisicalIdentityAuthenticationFamilyTests.Scope();
        bool oldCa = variant.EndsWith("caCertificate.value", StringComparison.Ordinal);
        bool oldNames = variant.EndsWith("allowedCommonNames.value", StringComparison.Ordinal);
        bool oldSans = variant.EndsWith("allowedSubjectAltNames.value", StringComparison.Ordinal) ||
            variant == "allowedSubjectAltNames.values";
        bool selectedChain = variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal);
        bool previousChain = variant.EndsWith("verifyClientCertificateChain.false", StringComparison.Ordinal);
        JsonObject Allowed(X509Certificate2 certificate, bool chain)
        {
            var proof = new JsonObject { ["certificate"] = InfisicalManagementTlsControl.Packet(certificate) };
            if (chain) proof["intermediatesPem"] = new JsonArray(control.Intermediate.ExportCertificatePem());
            return proof;
        }
        scope["issuers"] = new JsonObject
        {
            ["tls-cert"] = new JsonObject
            {
                ["configuration"] = new JsonObject
                {
                    ["caCertificate"] = control.Ca.ExportCertificatePem(),
                    ["allowedCommonNames"] = "selected",
                    ["allowedSubjectAltNames"] = new JsonArray("DNS:selected.invalid"),
                    ["defaultAllowedCommonNames"] = null,
                    ["defaultAllowedSubjectAltNames"] = null,
                    ["defaultTTL"] = "300",
                    ["defaultMaxTTL"] = "1200",
                    ["defaultUses"] = "1000"
                },
                ["baselineParameters"] = new JsonObject
                {
                    ["caCertificate"] = oldCa ? control.PreviousCa.ExportCertificatePem() : control.Ca.ExportCertificatePem(),
                    ["allowedCommonNames"] = oldNames ? "previous" : "selected",
                    ["allowedSubjectAltNames"] = new JsonArray(oldSans ? "DNS:previous.invalid" : "DNS:selected.invalid")
                },
                ["allowed"] = Allowed(selectedChain ? control.Chained : control.Accepted, selectedChain),
                ["baselineAllowed"] = Allowed(oldCa ? control.OldCaLeaf : oldNames ? control.Previous :
                    oldSans ? control.PreviousSan : previousChain ? control.Chained : control.Accepted, previousChain),
                ["denied"] = new JsonObject { ["certificate"] = InfisicalManagementTlsControl.Packet(control.Denied) }
            }
        };
        return scope;
    }

    internal static void TrustControl(SocketsHttpHandler handler, InfisicalManagementTlsControl control) =>
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) =>
            certificate is not null && certificate.GetCertHashString(HashAlgorithmName.SHA256) ==
                control.Server.GetCertHashString(HashAlgorithmName.SHA256);

    private static ProofCertificatePacket Packet(X509Certificate2 certificate)
    {
        JsonObject value = InfisicalManagementTlsControl.Packet(certificate);
        return new(value["pkcs12Base64"]!.GetValue<string>(), value["password"]!.GetValue<string>());
    }

    private static async ValueTask<TlsCertAuthConfiguration> Need(NativeEnvironment environment,
        Func<ManagementRequest<TlsCertAuthConfiguration>> factory)
    {
        ManagementClient client = environment.CreateManagementClient();
        using ManagementRequest<TlsCertAuthConfiguration> request = factory();
        ManagementAuthority authority = environment.CreateManagementAuthority(client, NativeIdentityRole.Administrative, Org);
        SecretOutcome<TlsCertAuthConfiguration> outcome = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, request.Target),
            request.IsMutation ? client.CreateReceipt(request) : null);
        if (!outcome.IsSuccess) throw new InvalidOperationException("SDK calibration: " + outcome.Status);
        return outcome.Value;
    }
}
