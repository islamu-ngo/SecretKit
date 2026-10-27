using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalProofAuthenticationEffects
{
    internal const string Operation = "i.runtime.InfisicalProofAuthentication.LoginAsync";
    internal const string Member = "SecretKit.Infisical.InfisicalProofAuthentication.LoginAsync(SecretKit.Infisical.InfisicalLoginProof,SecretKit.Infisical.InfisicalProofLoginReceipt,System.Threading.CancellationToken)";
    internal static readonly string[] Variants =
    [
        "proof.AliCloud", "proof.Aws.method-omitted", "proof.Aws.method-value", "proof.Azure",
        "proof.Gcp", "proof.Jwt", "proof.Kubernetes", "proof.Oidc", "proof.Spiffe.JWT-SVID",
        "proof.Ldap", "proof.Oci.date", "proof.Oci.x-date", "proof.Oci.date-and-x-date",
        "proof.Oci.dates-omitted", "proof.TlsCertificate.host-mtls", "organizationSlug.omitted",
        "organizationSlug.value", "maximumTTL.zero", "maximumTTL.positive"
    ];

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IAuthenticationExpiryObserver? expiryObserver = null,
        IAuthenticationIssuanceSource? issuanceSource = null, Action<SocketsHttpHandler>? configureProofTransport = null) =>
        InfisicalAuthenticationFamilies.RegisterFamily(registry, environment, expected, Operation, Member,
            Variants, (definition, probe, token) => ExecuteAsync(environment, definition, probe, expiryObserver, issuanceSource, configureProofTransport, token),
            expiryObserver);

    private static async ValueTask ExecuteAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, IAuthenticationExpiryObserver? expiryObserver,
        IAuthenticationIssuanceSource? issuanceSource, Action<SocketsHttpHandler>? configureProofTransport, CancellationToken token)
    {
        ProofInput input = InfisicalAuthenticationFamilies.Input<ProofInput>(environment,
            "C08-IR-InfisicalProofAuthentication", definition);
        probe.Contract(Matches(definition.Key.Variant, input.Proof, input.OrganizationSlug,
            input.Fixture.ExpectedReportedMaximumTtl), NativeFailure.MissingInput);
        bool tls = input.Proof.Strategy == "tls-cert";
        probe.Contract(tls ? environment.Origin.Scheme == Uri.UriSchemeHttps &&
            input.DeniedProof.Strategy == "tls-cert" && input.Proof.Certificate is not null &&
            input.DeniedProof.Certificate is not null :
            input.Proof.Certificate is null && input.DeniedProof.Certificate is null, NativeFailure.MissingInput);
        // Both packets are admitted before fixture ownership. Presentation is
        // host transport state, never proof JSON or a synthetic header.
        using ProofCertificatePair? certificates = tls ?
            ProofCertificatePair.Load(input.Proof.Certificate!, input.DeniedProof.Certificate!) : null;
        AuthenticationExpiryTrial? trial = AuthenticationExpiryTrial.Create(environment, definition, input.Fixture,
            input.Proof.Strategy + "-auth", expiryObserver);
        await using var fixture = new AuthenticationFixture(environment, input.Fixture, probe, definition.Key.Scope);
        AuthenticationIssuanceTrial? issuance = null;
        try
        {
            await AuthenticationIssuanceEffects.OpenAsync(environment, definition, input.Fixture,
                input.Proof.Strategy + "-auth", issuanceSource, value => issuance = value, token);
            await fixture.InitializeAsync(token);
            await using AuthenticationExpiryTrial? ownedTrial = trial;
            if (trial is not null) await trial.ArmAsync(token);
            bool denied = definition.Key.Case == "denied-authority";
            ProofFields selected = denied ? input.DeniedProof : input.Proof;
            probe.Contract(selected.Strategy == input.Proof.Strategy &&
                Matches(definition.Key.Variant, selected, input.OrganizationSlug,
                    input.Fixture.ExpectedReportedMaximumTtl), NativeFailure.MissingInput);
            using InfisicalLoginProof proof = CreateProof(fixture.IdentityId, input.OrganizationSlug, selected);
            using var handler = certificates?.CreateHandler(denied);
            if (handler is not null) configureProofTransport?.Invoke(handler);
            using var authentication = handler is null ?
                new InfisicalProofAuthentication(environment.Origin, fixture.Network) :
                new InfisicalProofAuthentication(environment.Origin,
                    new()
                    {
                        AllowLoopbackDevelopmentHttp = fixture.Network.AllowLoopbackDevelopmentHttp,
                        Transport = InfisicalTransportOptions.HostControlled(handler)
                    });
            InfisicalProofLoginReceipt receipt = authentication.CreateReceipt();
            if (issuance is not null) await issuance.ArmAsync(receipt, token);
            AuthenticationDispatchResult<InfisicalProofLogin> dispatch = await AuthenticationDispatch.InvokeAsync(
                environment, definition, probe, "/api/v1/auth/" + selected.Strategy + "-auth/login",
                ct => authentication.LoginAsync(proof, receipt, ct), token);
            if (dispatch.Interrupted)
            {
                probe.Contract(receipt.Evidence == DispatchEvidence.PossiblyDispatched, NativeFailure.ContractMismatch);
                if (issuance is not null)
                    await AuthenticationIssuanceEffects.ObserveAsync(issuance, environment, input.Fixture, probe, token);
                else await fixture.ObserveInterruptedAsync(token);
                return;
            }
            SecretOutcome<InfisicalProofLogin> outcome = dispatch.Outcome!;
            using InfisicalProofLogin? issued = outcome.IsSuccess ? outcome.Value : null;
            probe.Contract(outcome.Status == (denied ? SecretStatus.Denied : SecretStatus.Success) &&
                receipt.Evidence == (denied ? DispatchEvidence.Rejected : DispatchEvidence.Applied),
                NativeFailure.ContractMismatch);
            if (denied) await fixture.ObserveRejectedAsync(token);
            else await fixture.ObserveLoginAsync(issued!.Token, issued.ExpiresIn, issued.AccessTokenMaxTTL,
                selected.Strategy + "-auth", token, trial, receipt.Evidence);
        }
        finally { if (issuance is not null) await issuance.DisposeAsync(); }
    }

    private static bool Matches(string variant, ProofFields proof, string? slug, double maximum) => variant switch
    {
        "proof.AliCloud" => proof.Strategy == "alicloud",
        "proof.Aws.method-omitted" => proof.Strategy == "aws" && proof.Method is null,
        "proof.Aws.method-value" => proof.Strategy == "aws" && proof.Method is not null,
        "proof.Azure" => proof.Strategy == "azure",
        "proof.Gcp" => proof.Strategy == "gcp",
        "proof.Jwt" => proof.Strategy == "jwt",
        "proof.Kubernetes" => proof.Strategy == "kubernetes",
        "proof.Oidc" => proof.Strategy == "oidc",
        "proof.Spiffe.JWT-SVID" => proof.Strategy == "spiffe",
        "proof.Ldap" => proof.Strategy == "ldap",
        "proof.Oci.date" => proof.Strategy == "oci" && proof.Date is not null && proof.XDate is null,
        "proof.Oci.x-date" => proof.Strategy == "oci" && proof.Date is null && proof.XDate is not null,
        "proof.Oci.date-and-x-date" => proof.Strategy == "oci" && proof.Date is not null && proof.XDate is not null,
        "proof.Oci.dates-omitted" => proof.Strategy == "oci" && proof.Date is null && proof.XDate is null,
        "proof.TlsCertificate.host-mtls" => proof.Strategy == "tls-cert",
        "organizationSlug.omitted" => slug is null,
        "organizationSlug.value" => !string.IsNullOrWhiteSpace(slug),
        "maximumTTL.zero" => maximum == 0,
        "maximumTTL.positive" => maximum > 0,
        _ => false
    };

    private static InfisicalLoginProof CreateProof(string identity, string? slug, ProofFields fields)
    {
        // Each public factory copies its protected arguments. These input copies are
        // disposed immediately after construction, including on validation failure.
        using SecretMaterial? jwt = Material(fields.Jwt);
        using SecretMaterial? body = Material(fields.IamRequestBody);
        using SecretMaterial? headers = Material(fields.IamRequestHeaders);
        using SecretMaterial? key = Material(fields.AccessKeyId);
        using SecretMaterial? signature = Material(fields.Signature);
        using SecretMaterial? nonce = Material(fields.SignatureNonce);
        using SecretMaterial? password = Material(fields.Password);
        using SecretMaterial? authorization = Material(fields.Authorization);
        return fields.Strategy switch
        {
            "alicloud" => InfisicalLoginProof.AliCloud(identity, Required(key), Required(signature),
                Required(nonce), Required(fields.Timestamp), Required(fields.Version), slug),
            "aws" => InfisicalLoginProof.Aws(identity, Required(body), Required(headers), fields.Method, slug),
            "azure" => InfisicalLoginProof.Azure(identity, Required(jwt), slug),
            "gcp" => InfisicalLoginProof.Gcp(identity, Required(jwt), slug),
            "jwt" => InfisicalLoginProof.Jwt(identity, Required(jwt), slug),
            "kubernetes" => InfisicalLoginProof.Kubernetes(identity, Required(jwt), slug),
            "oidc" => InfisicalLoginProof.Oidc(identity, Required(jwt), slug),
            "spiffe" => InfisicalLoginProof.Spiffe(identity, Required(jwt), slug),
            "ldap" => InfisicalLoginProof.Ldap(identity, Required(fields.Username), Required(password), slug),
            "oci" => InfisicalLoginProof.Oci(identity, Required(fields.UserOcid), Required(authorization),
                Required(fields.Host), fields.Date, fields.XDate, slug),
            "tls-cert" => InfisicalLoginProof.TlsCertificate(identity, slug),
            _ => throw new NativeCaseFailureException("missing-input")
        };
    }

    private static SecretMaterial? Material(string? value) => value is null ? null : SecretMaterial.FromText(value);
    private static T Required<T>(T? value) where T : class =>
        value ?? throw new NativeCaseFailureException("missing-input");

    private sealed record ProofInput(AuthenticationFixtureInput Fixture, string? OrganizationSlug,
        ProofFields Proof, ProofFields DeniedProof)
    {
        public override string ToString() => "[ProofInput]";
    }
    private sealed record ProofFields(string Strategy, string? Jwt, string? IamRequestBody,
        string? IamRequestHeaders, string? Method, string? AccessKeyId, string? Signature,
        string? SignatureNonce, string? Timestamp, string? Version, string? Username,
        string? Password, string? UserOcid, string? Authorization, string? Host,
        string? Date, string? XDate, ProofCertificatePacket? Certificate = null)
    {
        public override string ToString() => "[ProofFields]";
    }
}
