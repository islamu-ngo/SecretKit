using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ManagementTlsAuthenticationEffects
{
    // Source/operator protocol (native qualification remains external):
    // C08-IM-ExternalIdentityAuthentication.scopes.<selected>.issuers.tls-cert
    // supplies configuration.caCertificate (PEM), allowedCommonNames (nonempty
    // text), allowedSubjectAltNames (string array), defaultTTL/defaultMaxTTL/
    // defaultUses (the selected deployment's measured policy defaults), plus
    // defaultAllowedCommonNames (null/string) and defaultAllowedSubjectAltNames
    // (null/string array) measured independently for omitted attachment fields.
    // The allowed/denied objects contain only certificate:{pkcs12Base64,password}
    // and optional organizationSlug/intermediatesPem (bounded public PEM array).
    // Intermediate packets are host-owned public certificates, not keys. The
    // direct-issuer/chain contrasts use actual presented TLS intermediates.
    // Distinct leaves with private keys must complete TLS; denied means
    // application denial, never a broken handshake.
    // Updates of CA/CN/SAN/chain verification require baselineParameters plus baselineAllowed,
    // with a genuinely contrasting CA/name/SAN and corresponding actual leaf.
    // No source label, token string, or configuration acknowledgement establishes
    // principal separation. Setup/admin/observer/denied authority stays in the
    // original five-role protocol; issued material alone accesses the canaries.
    // Native Origin must be HTTPS with ordinary trusted server certificates,
    // correctly configured mTLS forwarding and the actual deployment revision.
    // The optional channel factory is a caller-owned isolated host seam, never
    // private JSON server-trust configuration or native self-signed family trust.
    // POST/PATCH/DELETE CA is write-only; independent observer GET supplies the
    // protected plaintext CA. encryptedCaCertificate remains unconstrained and
    // is tested only for declared presence, never decoded or called plaintext.
    // Primary public interface facts, retrieved via Tavily on 2026-10-14:
    // https://infisical.com/docs/api-reference/endpoints/tls-cert-auth/attach
    // https://infisical.com/docs/api-reference/endpoints/tls-cert-auth/retrieve
    // https://infisical.com/docs/api-reference/endpoints/tls-cert-auth/update
    // https://infisical.com/docs/api-reference/endpoints/tls-cert-auth/revoke
    // https://infisical.com/docs/documentation/platform/identities/tls-cert-auth
    // No vendor implementation was used. Missing source/rights/clocks are not
    // local authoring gaps; offline control evidence is not native certification.
    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        c.RequireIssuer("tls-cert");
        string variant = c.Variant;
        bool attaching = c.Operation.StartsWith("Attach", StringComparison.Ordinal);
        bool updating = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool seed = !attaching;
        JsonElement settings = c.TlsSettings(false);
        JsonElement baseline = updating ? c.TlsSettings(true) : settings;
        string Text(JsonElement values, string field) => values.GetProperty(field).GetString() ??
            throw new NativeCaseFailureException("missing-input");
        string[] Names(JsonElement values) => values.GetProperty("allowedSubjectAltNames").EnumerateArray()
            .Select(n => n.GetString() ?? throw new NativeCaseFailureException("missing-input")).ToArray();
        bool Omitted(string field) => variant.EndsWith(field + ".omitted", StringComparison.Ordinal);
        bool Contrast(string field) => updating && variant.EndsWith(field + ".value", StringComparison.Ordinal);
        string selectedCa = Text(settings, "caCertificate");
        string initialCa = Contrast("caCertificate") ? Text(baseline, "caCertificate") : selectedCa;
        string selectedCn = Text(settings, "allowedCommonNames");
        string initialCn = Contrast("allowedCommonNames") ? Text(baseline, "allowedCommonNames") : selectedCn;
        string[] selectedSans = Names(settings);
        JsonElement defaultCn = settings.GetProperty("defaultAllowedCommonNames");
        JsonElement defaultSans = settings.GetProperty("defaultAllowedSubjectAltNames");
        if (defaultCn.ValueKind is not (JsonValueKind.Null or JsonValueKind.String) ||
            defaultSans.ValueKind is not (JsonValueKind.Null or JsonValueKind.Array))
            throw new NativeCaseFailureException("missing-input");
        string? defaultCommonNames = defaultCn.ValueKind == JsonValueKind.Null ? null : defaultCn.GetString();
        string[]? defaultSubjectNames = defaultSans.ValueKind == JsonValueKind.Null ? null :
            defaultSans.EnumerateArray().Select(n => n.GetString() ?? throw new NativeCaseFailureException("missing-input")).ToArray();
        string[] initialSans = Contrast("allowedSubjectAltNames") || updating && variant == "allowedSubjectAltNames.values" ?
            Names(baseline) : selectedSans;
        if (Contrast("caCertificate") && initialCa == selectedCa ||
            Contrast("allowedCommonNames") && initialCn == selectedCn ||
            (Contrast("allowedSubjectAltNames") || updating && variant == "allowedSubjectAltNames.values") &&
                initialSans.SequenceEqual(selectedSans, StringComparer.Ordinal))
            throw new NativeCaseFailureException("missing-input");
        bool selectedVerify = variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal);
        bool initialVerify = updating && (variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal) ||
            variant.EndsWith("verifyClientCertificateChain.false", StringComparison.Ordinal)) ? !selectedVerify : selectedVerify;
        WorkloadAuthTokenPolicy selectedPolicy = c.Policy(), baselinePolicy = c.Policy(true);
        using SecretMaterial ca = SecretMaterial.FromText(selectedCa);
        using SecretMaterial oldCa = SecretMaterial.FromText(initialCa);

        WorkloadAuthNullableText? CommonNames(bool before) => !before && Omitted("allowedCommonNames") ? null :
            !before && variant == "allowedCommonNames.null" ? WorkloadAuthNullableText.Null() :
                WorkloadAuthNullableText.FromValue(before ? initialCn : selectedCn);
        TlsAuthSubjectAltNames? SubjectNames(bool before) => !before && Omitted("allowedSubjectAltNames") ? null :
            !before && variant == "allowedSubjectAltNames.null" ? TlsAuthSubjectAltNames.Null() :
                TlsAuthSubjectAltNames.FromValues(!before && variant == "allowedSubjectAltNames.empty" ? [] :
                    before ? initialSans : selectedSans);
        TlsCertAuthConfigurationInput Input(bool before) => new(
            !before && Omitted("caCertificate") ? null : before ? oldCa : ca,
            CommonNames(before), SubjectNames(before),
            !before && Omitted("verifyClientCertificateChain") ? null : before ? initialVerify : selectedVerify,
            before ? baselinePolicy : selectedPolicy);

        // All private packets and contrast inputs are validated before acquiring
        // fixture ownership. Attach CA omission is the retained typed rejection,
        // not a fabricated remote configuration or successful empty attachment.
        if (attaching && Omitted("caCertificate"))
        {
            await c.EnsureIdentityAsync(token);
            await c.RejectionAsync(() =>
            {
                using var input = Input(false);
                using var rejected = ExternalIdentityAuthenticationOperations.AttachTlsCertAuth(c.OrganizationId, c.IdentityId, input);
            }, () => ExternalIdentityAuthenticationOperations.GetTlsCertAuth(c.OrganizationId, c.IdentityId), token);
            return;
        }
        using TlsCertAuthConfigurationInput initial = Input(seed);
        using TlsCertAuthConfigurationInput update = Input(false);
        bool Fields(TlsCertAuthConfiguration configuration, bool changed)
        {
            bool before = seed && !changed;
            WorkloadAuthTokenPolicy policy = changed ? selectedPolicy : seed ? baselinePolicy : selectedPolicy;
            bool mutation = configuration.CaCertificate is null;
            string expectedCa = before || updating && Omitted("caCertificate") ? initialCa : selectedCa;
            // CA is known only on GET. Mutations must remain write-only; the
            // ConfigurationAsync observer GET independently measures persistence.
            bool cnNull = !before && variant == "allowedCommonNames.null" ||
                !before && attaching && Omitted("allowedCommonNames") && defaultCommonNames is null;
            string? expectedCn = !before && attaching && Omitted("allowedCommonNames") ? defaultCommonNames :
                before || updating && Omitted("allowedCommonNames") ? initialCn : selectedCn;
            bool sanNull = !before && variant == "allowedSubjectAltNames.null" ||
                !before && attaching && Omitted("allowedSubjectAltNames") && defaultSubjectNames is null;
            string[] expectedSans = !before && attaching && Omitted("allowedSubjectAltNames") ? defaultSubjectNames ?? [] :
                !before && variant == "allowedSubjectAltNames.empty" ? [] :
                before || updating && Omitted("allowedSubjectAltNames") ? initialSans : selectedSans;
            bool verify = before || updating && Omitted("verifyClientCertificateChain") ? initialVerify : selectedVerify;
            return c.PolicyMatches(configuration, policy) &&
                configuration.HasUnestablishedEncryptedCaCertificateProjection &&
                (mutation || configuration.CaCertificate!.Reveal() == expectedCa) &&
                configuration.AllowedCommonNames.IsPresent &&
                (cnNull ? configuration.AllowedCommonNames.IsNull : !configuration.AllowedCommonNames.IsNull &&
                    configuration.AllowedCommonNames.Value == expectedCn) &&
                configuration.AllowedSubjectAltNames.IsPresent &&
                (sanNull ? configuration.AllowedSubjectAltNames.IsNull : !configuration.AllowedSubjectAltNames.IsNull &&
                    configuration.AllowedSubjectAltNames.Value.SequenceEqual(expectedSans, StringComparer.Ordinal)) &&
                configuration.VerifyClientCertificateChain == verify;
        }
        await c.EnsureIdentityAsync(token);
        await c.ConfigurationAsync(
            () => ExternalIdentityAuthenticationOperations.AttachTlsCertAuth(c.OrganizationId, c.IdentityId, initial),
            () => ExternalIdentityAuthenticationOperations.GetTlsCertAuth(c.OrganizationId, c.IdentityId),
            () => ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth(c.OrganizationId, c.IdentityId, update),
            () => ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth(c.OrganizationId, c.IdentityId),
            Fields, "tls-cert", token);
    }
}
