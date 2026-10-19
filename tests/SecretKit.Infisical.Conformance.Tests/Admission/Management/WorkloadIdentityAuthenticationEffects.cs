using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class WorkloadIdentityAuthenticationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d)
    {
        string v = d.Key.Variant;
        if (v.StartsWith("boundClaims.", StringComparison.Ordinal) || v.StartsWith("claimMetadataMapping.", StringComparison.Ordinal))
            return "primary-auth-response-shapes";
        if (v.EndsWith(".rejected", StringComparison.Ordinal)) return null;
        if (v == "publicKeys.empty") return "empty-static-key-authentication-witness-unavailable";
        if (v.Contains("templateId", StringComparison.Ordinal) || v.Contains("reviewerJwt", StringComparison.Ordinal) ||
            v.Contains("tokenReviewerJwt", StringComparison.Ordinal) || v.Contains("clearTokenReviewerJwt", StringComparison.Ordinal))
            return "reviewer-template-transition-observer-unavailable";
        return null;
    }

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        if (c.Variant.EndsWith(".rejected", StringComparison.Ordinal))
        {
            await c.EnsureIdentityAsync(token);
            await c.RejectionAsync(() =>
            {
                using var input = new KubernetesAuthConfigurationInput(
                    allowedNames: c.Variant.Contains("allowedNames", StringComparison.Ordinal) ? null : "owned-name",
                    allowedNamespaces: c.Variant.Contains("allowedNamespaces", StringComparison.Ordinal) ? null : "owned-namespace",
                    clearTokenReviewerJwt: c.Variant.Contains("clearTokenReviewerJwt", StringComparison.Ordinal));
                using var rejected = WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(c.OrganizationId, c.IdentityId, input);
            }, () => WorkloadIdentityAuthenticationOperations.GetKubernetesAuth(c.OrganizationId, c.IdentityId), token);
            return;
        }
        string mechanism = c.Operation.Contains("Jwt", StringComparison.Ordinal) ? "jwt" :
            c.Operation.Contains("Oidc", StringComparison.Ordinal) ? "oidc" : "kubernetes";
        c.RequireIssuer(mechanism);
        await c.EnsureIdentityAsync(token);
        bool seed = !c.Operation.StartsWith("Attach", StringComparison.Ordinal);
        string org = c.OrganizationId, id = c.IdentityId, v = c.Variant;
        WorkloadAuthTokenPolicy initialPolicy = seed ? c.Policy(true) : c.Policy(), selected = c.Policy();
        bool Policy(WorkloadAuthConfiguration config, bool changed) =>
            c.PolicyMatches(config, changed ? selected : initialPolicy);
        if (mechanism == "jwt")
        {
            bool isStatic = v.EndsWith(".Static", StringComparison.Ordinal) ||
                v is "JwtAuthConfigurationInput.jwksUrl.omitted" or "JwtAuthConfigurationInput.publicKeys.value" or "publicKeys.multiple";
            string[] keys = v == "publicKeys.multiple" ? [c.Setting("publicKey"), c.Setting("secondPublicKey")] :
                [c.Setting("publicKey")];
            bool updateType = c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
                (v.EndsWith("configurationType.Static", StringComparison.Ordinal) ||
                    v.EndsWith("configurationType.Jwks", StringComparison.Ordinal));
            bool initialStatic = updateType ? c.BaselineSetting("configurationType", isStatic ? "static" : "jwks") switch
            {
                "static" => true,
                "jwks" => false,
                _ => throw new NativeCaseFailureException("missing-input")
            } : isStatic;
            string[] initialKeys = c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
                (v.EndsWith("publicKeys.value", StringComparison.Ordinal) || v == "publicKeys.multiple") ?
                    [c.BaselineSetting("publicKey", keys[0])] : keys;
            JwtAuthConfigurationInput Input(bool before) => new(
                (before ? initialStatic : isStatic) ? JwtAuthConfigurationType.Static : JwtAuthConfigurationType.Jwks,
                jwksUrl: c.TextInput("jwksUrl", before),
                publicKeys: (before ? initialStatic : isStatic) ? before ? initialKeys : keys :
                    updateType ? Array.Empty<string>() : null,
                boundClaims: new Dictionary<string, string>(),
                jwksCaCert: c.TextInput("jwksCaCert", before), boundIssuer: c.TextInput("boundIssuer", before),
                boundAudiences: c.TextInput("boundAudiences", before), boundSubject: c.TextInput("boundSubject", before),
                policy: before ? c.Policy(true) : selected);
            JwtAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Fields(JwtAuthConfiguration config, bool changed)
            {
                JwtAuthConfigurationInput input = changed ? update : initial;
                return Policy(config, changed) &&
                    config.ConfigurationType == (input.ConfigurationType == JwtAuthConfigurationType.Static ? "static" : "jwks") &&
                    config.JwksUrl == c.ExpectedText("jwksUrl", input.JwksUrl) &&
                    config.BoundIssuer == c.ExpectedText("boundIssuer", input.BoundIssuer) &&
                    config.BoundAudiences == c.ExpectedText("boundAudiences", input.BoundAudiences) &&
                    config.BoundSubject == c.ExpectedText("boundSubject", input.BoundSubject) &&
                    (config.JwksCaCert is null && !v.EndsWith("jwksCaCert.value", StringComparison.Ordinal) ||
                        config.JwksCaCert == c.ExpectedText("jwksCaCert", input.JwksCaCert)) &&
                    (config.PublicKeys is null && c.Operation.StartsWith("Delete", StringComparison.Ordinal) ||
                        config.PublicKeys is not null && config.PublicKeys.SequenceEqual(input.PublicKeys ??
                            initial.PublicKeys ?? Array.Empty<string>()));
            }
            await c.ConfigurationAsync(
                () => WorkloadIdentityAuthenticationOperations.AttachJwtAuth(org, id, initial),
                () => WorkloadIdentityAuthenticationOperations.GetJwtAuth(org, id),
                () => WorkloadIdentityAuthenticationOperations.UpdateJwtAuth(org, id, update),
                () => WorkloadIdentityAuthenticationOperations.DeleteJwtAuth(org, id), Fields, mechanism, token);
        }
        else if (mechanism == "oidc")
        {
            OidcAuthConfigurationInput Input(bool before) => new(boundClaims: new Dictionary<string, string>(),
                oidcDiscoveryUrl: c.TextInput("oidcDiscoveryUrl", before), boundIssuer: c.TextInput("boundIssuer", before),
                boundAudiences: c.TextInput("boundAudiences", before), boundSubject: c.TextInput("boundSubject", before),
                caCert: c.TextInput("caCert", before), policy: before ? c.Policy(true) : selected);
            OidcAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Fields(OidcAuthConfiguration config, bool changed)
            {
                OidcAuthConfigurationInput input = changed ? update : initial;
                return Policy(config, changed) && config.OidcDiscoveryUrl == c.ExpectedText("oidcDiscoveryUrl", input.OidcDiscoveryUrl) &&
                    config.BoundIssuer == c.ExpectedText("boundIssuer", input.BoundIssuer) &&
                    config.BoundAudiences == c.ExpectedText("boundAudiences", input.BoundAudiences) &&
                    config.BoundSubject.IsPresent && !config.BoundSubject.IsNull &&
                    config.BoundSubject.Value == c.ExpectedText("boundSubject", input.BoundSubject) &&
                    (config.CaCert is null && !v.EndsWith("caCert.value", StringComparison.Ordinal) ||
                        config.CaCert == c.ExpectedText("caCert", input.CaCert));
            }
            await c.ConfigurationAsync(
                () => WorkloadIdentityAuthenticationOperations.AttachOidcAuth(org, id, initial),
                () => WorkloadIdentityAuthenticationOperations.GetOidcAuth(org, id),
                () => WorkloadIdentityAuthenticationOperations.UpdateOidcAuth(org, id, update),
                () => WorkloadIdentityAuthenticationOperations.DeleteOidcAuth(org, id), Fields, mechanism, token);
        }
        else
        {
            bool gateway = v.EndsWith(".Gateway", StringComparison.Ordinal);
            bool initialGateway = gateway;
            bool verifyTls = !v.EndsWith("verifyTlsCertificate.false", StringComparison.Ordinal), initialVerifyTls = verifyTls;
            if (c.Operation.StartsWith("Update", StringComparison.Ordinal))
            {
                if (v.EndsWith("tokenReviewMode.Api", StringComparison.Ordinal) ||
                    v.EndsWith("tokenReviewMode.Gateway", StringComparison.Ordinal))
                    initialGateway = c.BaselineSetting("tokenReviewMode", gateway ? "gateway" : "api") switch
                    {
                        "gateway" => true,
                        "api" => false,
                        _ => throw new NativeCaseFailureException("missing-input")
                    };
                if (v.EndsWith("verifyTlsCertificate.true", StringComparison.Ordinal) ||
                    v.EndsWith("verifyTlsCertificate.false", StringComparison.Ordinal))
                    initialVerifyTls = c.BaselineSetting("verifyTlsCertificate", verifyTls ? "true" : "false") switch
                    {
                        "true" => true,
                        "false" => false,
                        _ => throw new NativeCaseFailureException("missing-input")
                    };
            }
            WorkloadAuthNullableText? Text(string field, bool before)
            {
                if (!before && v.EndsWith(field + ".null", StringComparison.Ordinal)) return WorkloadAuthNullableText.Null();
                string? text = c.TextInput(field, before);
                return text is null ? null : WorkloadAuthNullableText.FromValue(text);
            }
            KubernetesAuthConfigurationInput Input(bool before) => new(
                allowedNames: c.TextInput("allowedNames", before), allowedNamespaces: c.TextInput("allowedNamespaces", before),
                allowedAudience: c.TextInput("allowedAudience", before), caCert: c.TextInput("caCert", before),
                kubernetesHost: Text("kubernetesHost", before), gatewayId: Text("gatewayId", before),
                gatewayPoolId: Text("gatewayPoolId", before),
                tokenReviewMode: !before && v.EndsWith("tokenReviewMode.omitted", StringComparison.Ordinal) ? null :
                    (before ? initialGateway : gateway) ? KubernetesTokenReviewMode.Gateway : KubernetesTokenReviewMode.Api,
                verifyTlsCertificate: !before && v.EndsWith("verifyTlsCertificate.omitted", StringComparison.Ordinal) ?
                    null : before ? initialVerifyTls : verifyTls,
                policy: before ? c.Policy(true) : selected);
            using KubernetesAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Field(ProjectField<string> field, string name, bool changed) =>
                (!seed || changed) && v.EndsWith(name + ".null", StringComparison.Ordinal) ? field.IsPresent && field.IsNull :
                    field.IsPresent && !field.IsNull && field.Value == c.ExpectedText(name, c.TextInput(name, seed && !changed));
            bool Fields(KubernetesAuthConfiguration config, bool changed)
            {
                KubernetesAuthConfigurationInput input = changed ? update : initial;
                return Policy(config, changed) && config.AllowedNames == c.ExpectedText("allowedNames", input.AllowedNames) &&
                    config.AllowedNamespaces == c.ExpectedText("allowedNamespaces", input.AllowedNamespaces) &&
                    config.AllowedAudience == c.ExpectedText("allowedAudience", input.AllowedAudience) &&
                    Field(config.KubernetesHost, "kubernetesHost", changed) &&
                    Field(config.GatewayId, "gatewayId", changed) && Field(config.GatewayPoolId, "gatewayPoolId", changed) &&
                    config.TokenReviewMode == ((input.TokenReviewMode ?? initial.TokenReviewMode) ==
                        KubernetesTokenReviewMode.Gateway ? "gateway" : "api") &&
                    config.VerifyTlsCertificate == (input.VerifyTlsCertificate ?? true) &&
                    (config.CaCert is null && !v.EndsWith("caCert.value", StringComparison.Ordinal) ||
                        config.CaCert == c.ExpectedText("caCert", input.CaCert));
            }
            await c.ConfigurationAsync(
                () => WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(org, id, initial),
                () => WorkloadIdentityAuthenticationOperations.GetKubernetesAuth(org, id),
                () => WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth(org, id, update),
                () => WorkloadIdentityAuthenticationOperations.DeleteKubernetesAuth(org, id), Fields, mechanism, token);
        }
    }
}
