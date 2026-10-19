using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class ExternalIdentityAuthenticationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d)
    {
        if (d.Key.Operation.EndsWith(".RefreshSpiffeBundle", StringComparison.Ordinal)) return "issuer-key-rollover-event-observer-unavailable";
        if (d.Key.Variant.Contains("allowedFields", StringComparison.Ordinal)) return "primary-auth-response-shapes";
        return null;
    }

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        if (c.Operation.Contains("TlsCert", StringComparison.Ordinal))
        {
            await ManagementTlsAuthenticationEffects.ExecuteAsync(c, token);
            return;
        }
        if (c.Variant.EndsWith(".rejected", StringComparison.Ordinal))
        {
            await c.EnsureIdentityAsync(token);
            await c.RejectionAsync(() =>
            {
                using SecretMaterial bundle = SecretMaterial.FromText("owned-bundle");
                using SpiffeTrustBundleInput distribution = SpiffeTrustBundleInput.Static(bundle);
                using var input = new SpiffeAuthConfigurationInput(
                    trustDomain: c.Variant.Contains("trustDomain", StringComparison.Ordinal) ? null : "issuer.invalid",
                    allowedSpiffeIds: c.Variant.Contains("allowedSpiffeIds", StringComparison.Ordinal) ? null : "spiffe://issuer.invalid/owned",
                    allowedAudiences: c.Variant.Contains("allowedAudiences", StringComparison.Ordinal) ? null : "owned-audience",
                    trustBundleDistribution: c.Variant.Contains("trustBundleDistribution", StringComparison.Ordinal) ? null : distribution);
                using var rejected = ExternalIdentityAuthenticationOperations.AttachSpiffeAuth(c.OrganizationId, c.IdentityId, input);
            }, () => ExternalIdentityAuthenticationOperations.GetSpiffeAuth(c.OrganizationId, c.IdentityId), token);
            return;
        }
        string mechanism = c.Operation.Contains("Ldap", StringComparison.Ordinal) ? "ldap" :
            c.Operation.Contains("Oci", StringComparison.Ordinal) ? "oci" : "spiffe";
        c.RequireIssuer(mechanism);
        await c.EnsureIdentityAsync(token);
        bool seed = !c.Operation.StartsWith("Attach", StringComparison.Ordinal);
        string org = c.OrganizationId, id = c.IdentityId, v = c.Variant;
        WorkloadAuthTokenPolicy baseline = c.Policy(true), selected = c.Policy();
        bool Policy(WorkloadAuthConfiguration config, bool changed) =>
            c.PolicyMatches(config, changed ? selected : seed ? baseline : selected);
        if (mechanism == "oci")
        {
            WorkloadAuthNullableText? Usernames(bool before) => !before && v == "allowedUsernames.null" ?
                WorkloadAuthNullableText.Null() : c.TextInput("allowedUsernames", before) is { } text ?
                    WorkloadAuthNullableText.FromValue(text) : null;
            var initial = new OciAuthConfigurationInput(c.Setting("tenancyOcid"), Usernames(seed), seed ? baseline : selected);
            var update = new OciAuthConfigurationInput(c.Setting("tenancyOcid"), Usernames(false), selected);
            bool Fields(OciAuthConfiguration config, bool changed)
            {
                OciAuthConfigurationInput input = changed ? update : initial;
                return Policy(config, changed) && config.TenancyOcid == input.TenancyOcid &&
                    ((!seed || changed) && v == "allowedUsernames.null" ? config.AllowedUsernames.IsPresent && config.AllowedUsernames.IsNull :
                        config.AllowedUsernames.IsPresent && !config.AllowedUsernames.IsNull &&
                        config.AllowedUsernames.Value == c.ExpectedText("allowedUsernames", c.TextInput("allowedUsernames", seed && !changed)));
            }
            await c.ConfigurationAsync(
                () => ExternalIdentityAuthenticationOperations.AttachOciAuth(org, id, initial),
                () => ExternalIdentityAuthenticationOperations.GetOciAuth(org, id),
                () => ExternalIdentityAuthenticationOperations.UpdateOciAuth(org, id, update),
                () => ExternalIdentityAuthenticationOperations.DeleteOciAuth(org, id), Fields, mechanism, token);
        }
        else if (mechanism == "ldap")
        {
            bool clear = c.Operation == "ClearLdapAuthLockouts";
            bool Contrast(string field, bool before) => before && c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
                v.EndsWith(field + ".value", StringComparison.Ordinal);
            bool Enabled(bool before)
            {
                bool enabled = v.EndsWith("lockoutEnabled.true", StringComparison.Ordinal);
                return before && c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
                    (v.EndsWith("lockoutEnabled.true", StringComparison.Ordinal) ||
                        v.EndsWith("lockoutEnabled.false", StringComparison.Ordinal)) ? !enabled : enabled;
            }
            LdapAuthSettings Settings(bool before) => new(c.TextInput("searchFilter", before),
                lockoutEnabled: clear ? true : !before && v.EndsWith("lockoutEnabled.omitted", StringComparison.Ordinal) ? null :
                    Enabled(before),
                lockoutThreshold: clear ? 1 : !before && v.EndsWith("lockoutThreshold.omitted", StringComparison.Ordinal) ? null :
                    Contrast("lockoutThreshold", before) ? 4 : 5,
                lockoutDurationSeconds: !before && v.EndsWith("lockoutDurationSeconds.omitted", StringComparison.Ordinal) ? null :
                    Contrast("lockoutDurationSeconds", before) ? 43200 : 86400,
                lockoutCounterResetSeconds: !before && v.EndsWith("lockoutCounterResetSeconds.omitted", StringComparison.Ordinal) ? null :
                    Contrast("lockoutCounterResetSeconds", before) ? 1800 : 3600,
                policy: before ? baseline : selected);
            using SecretMaterial password = SecretMaterial.FromText(c.Setting("bindPass"));
            bool template = v == "input.template";
            using LdapAuthConfigurationInput initial = template ? LdapAuthConfigurationInput.FromTemplate(c.Setting("templateId"),
                settings: Settings(seed)) : LdapAuthConfigurationInput.FromConnection(c.Setting("url"), c.Setting("bindDN"),
                    password, c.Setting("searchBase"), settings: Settings(seed));
            using LdapAuthConfigurationInput update = LdapAuthConfigurationInput.Patch(settings: Settings(false));
            if (clear)
            {
                await c.EnsureConsumerAsync(token);
                using LdapAuthConfiguration attached = await c.NeedAsync(
                    () => ExternalIdentityAuthenticationOperations.AttachLdapAuth(org, id, initial), NativeIdentityRole.Setup, token);
                await c.InduceLockoutAsync("ldap", token);
                await c.CaseAsync(() => ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts(org, id),
                    result => result.Deleted > 0, async (applied, ct) =>
                    {
                        IdentitySummary observed = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(org, id),
                            NativeIdentityRole.Observer, ct);
                        return observed.ActiveLockoutAuthMethods.IsPresent &&
                            observed.ActiveLockoutAuthMethods.Value.Contains("ldap-auth", StringComparer.Ordinal) == !applied &&
                            await c.ObserveProofAsync("ldap", applied, ct);
                    }, token);
                return;
            }
            bool Fields(LdapAuthConfiguration config, bool changed)
            {
                LdapAuthSettings input = changed ? update.Settings : initial.Settings;
                double Expected(string field, double? supplied, double before) => supplied ??
                    (c.Operation.StartsWith("Update", StringComparison.Ordinal) ? before :
                        double.Parse(c.Setting("default-" + field), System.Globalization.CultureInfo.InvariantCulture));
                return Policy(config, changed) && config.SearchFilter == c.ExpectedText("searchFilter", input.SearchFilter) &&
                    (!template ? config.Url == c.Setting("url") && config.SearchBase == c.Setting("searchBase") :
                        config.TemplateId.IsPresent && !config.TemplateId.IsNull && config.TemplateId.Value == c.Setting("templateId")) &&
                    config.LockoutEnabled == (input.LockoutEnabled ?? false) &&
                    config.LockoutThreshold == Expected("lockoutThreshold", input.LockoutThreshold, 5) &&
                    config.LockoutDurationSeconds == Expected("lockoutDurationSeconds", input.LockoutDurationSeconds, 86400) &&
                    config.LockoutCounterResetSeconds == Expected("lockoutCounterResetSeconds", input.LockoutCounterResetSeconds, 3600);
            }
            await c.ConfigurationAsync(
                () => ExternalIdentityAuthenticationOperations.AttachLdapAuth(org, id, initial),
                () => ExternalIdentityAuthenticationOperations.GetLdapAuth(org, id),
                () => ExternalIdentityAuthenticationOperations.UpdateLdapAuth(org, id, update),
                () => ExternalIdentityAuthenticationOperations.DeleteLdapAuth(org, id), Fields, mechanism, token);
        }
        else
        {
            bool https = v is "bundle.https_web_bundle" or "response.bundle.https_web_bundle" or
                "bundle.caCert.omitted" or "bundle.caCert.value" or "refreshHintSeconds.omitted" or "refreshHintSeconds.value";
            bool updating = c.Operation.StartsWith("Update", StringComparison.Ordinal);
            bool initialHttps = updating && v is "bundle.static" or "bundle.https_web_bundle" ?
                c.BaselineSetting("bundleProfile", https ? "https_web_bundle" : "static") switch
                {
                    "static" => false,
                    "https_web_bundle" => true,
                    _ => throw new NativeCaseFailureException("missing-input")
                } : https;
            using SecretMaterial bundle = SecretMaterial.FromText(c.Setting("bundle"));
            using SecretMaterial ca = SecretMaterial.FromText(c.Setting("caCert"));
            using SecretMaterial initialBundle = SecretMaterial.FromText(updating &&
                v == "SpiffeAuthConfigurationInput.trustBundleDistribution.value" ?
                    c.BaselineSetting("bundle", bundle.Reveal()) : bundle.Reveal());
            using SecretMaterial initialCa = SecretMaterial.FromText(updating && v == "bundle.caCert.value" ?
                c.BaselineSetting("caCert", ca.Reveal()) : ca.Reveal());
            long initialRefresh = updating && v == "refreshHintSeconds.value" ? 30 : 60;
            using SpiffeTrustBundleInput initialDistribution = initialHttps ?
                SpiffeTrustBundleInput.HttpsWebBundle(c.Setting("endpointUrl"),
                    v == "bundle.caCert.omitted" ? null : initialCa,
                    v == "refreshHintSeconds.omitted" ? null : initialRefresh) : SpiffeTrustBundleInput.Static(initialBundle);
            using SpiffeTrustBundleInput distribution = https ? SpiffeTrustBundleInput.HttpsWebBundle(c.Setting("endpointUrl"),
                v == "bundle.caCert.omitted" ? null : ca, v == "refreshHintSeconds.omitted" ? null : 60) :
                    SpiffeTrustBundleInput.Static(bundle);
            SpiffeAuthConfigurationInput Input(bool before) => new(c.TextInput("trustDomain", before),
                c.TextInput("allowedSpiffeIds", before), c.TextInput("allowedAudiences", before),
                !before && v.EndsWith("trustBundleDistribution.omitted", StringComparison.Ordinal) ? null :
                    before ? initialDistribution : distribution,
                before ? baseline : selected);
            using SpiffeAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Fields(SpiffeAuthConfiguration config, bool changed)
            {
                SpiffeAuthConfigurationInput input = changed ? update : initial;
                SpiffeTrustBundleConfiguration returned = config.TrustBundleDistribution;
                bool before = seed && !changed;
                return Policy(config, changed) && config.TrustDomain == c.ExpectedText("trustDomain", input.TrustDomain) &&
                    config.AllowedSpiffeIds == c.ExpectedText("allowedSpiffeIds", input.AllowedSpiffeIds) &&
                    config.AllowedAudiences == c.ExpectedText("allowedAudiences", input.AllowedAudiences) &&
                    ((before ? initialHttps : https) ? returned.Profile == "https_web_bundle" && returned.EndpointUrl == c.Setting("endpointUrl") &&
                        returned.CaCert?.Reveal() == (v == "bundle.caCert.omitted" ? c.Setting("default-caCert") :
                            (before ? initialCa : ca).Reveal()) &&
                        returned.RefreshHintSeconds == (v == "refreshHintSeconds.omitted" ?
                            double.Parse(c.Setting("default-refreshHintSeconds"), System.Globalization.CultureInfo.InvariantCulture) :
                                before ? initialRefresh : 60) :
                        returned.Profile == "static" && returned.Bundle?.Reveal() == (before ? initialBundle : bundle).Reveal());
            }
            await c.ConfigurationAsync(
                () => ExternalIdentityAuthenticationOperations.AttachSpiffeAuth(org, id, initial),
                () => ExternalIdentityAuthenticationOperations.GetSpiffeAuth(org, id),
                () => ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth(org, id, update),
                () => ExternalIdentityAuthenticationOperations.DeleteSpiffeAuth(org, id), Fields, mechanism, token);
        }
    }
}
