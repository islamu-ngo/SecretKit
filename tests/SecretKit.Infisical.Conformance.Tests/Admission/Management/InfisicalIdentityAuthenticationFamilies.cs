using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record IdentityAuthBinding(string Member, string[] Variants, bool Mutation);

internal static class InfisicalIdentityAuthenticationFamilies
{
    // Literal compiler/admission obligations; not discovered from scenarios that happen to pass.
    internal static readonly Dictionary<string, IdentityAuthBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.CloudIdentityAuthenticationOperations.AttachAliCloudAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.AttachAliCloudAuth(System.String,System.String,SecretKit.Infisical.Management.AliCloudAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AliCloudAuthConfigurationInput.policy.omitted", "AliCloudAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.AttachAwsAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.AttachAwsAuth(System.String,System.String,SecretKit.Infisical.Management.AwsAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AwsAuthConfigurationInput.allowedPrincipalArns.omitted", "AwsAuthConfigurationInput.allowedPrincipalArns.value", "AwsAuthConfigurationInput.allowedAccountIds.omitted", "AwsAuthConfigurationInput.allowedAccountIds.value", "AwsAuthConfigurationInput.stsEndpoint.omitted", "AwsAuthConfigurationInput.stsEndpoint.value", "AwsAuthConfigurationInput.policy.omitted", "AwsAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.AttachAzureAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.AttachAzureAuth(System.String,System.String,SecretKit.Infisical.Management.AzureAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AzureAuthConfigurationInput.tenantId.omitted.rejected", "AzureAuthConfigurationInput.tenantId.value", "AzureAuthConfigurationInput.resource.omitted.rejected", "AzureAuthConfigurationInput.resource.value", "AzureAuthConfigurationInput.allowedServicePrincipalIds.omitted", "AzureAuthConfigurationInput.allowedServicePrincipalIds.value", "AzureAuthConfigurationInput.policy.omitted", "AzureAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.AttachGcpAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.AttachGcpAuth(System.String,System.String,SecretKit.Infisical.Management.GcpAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "GcpAuthConfigurationInput.type.Iam", "GcpAuthConfigurationInput.type.Gce", "GcpAuthConfigurationInput.type.omitted.rejected", "GcpAuthConfigurationInput.allowedServiceAccounts.omitted", "GcpAuthConfigurationInput.allowedServiceAccounts.value", "GcpAuthConfigurationInput.allowedProjects.omitted", "GcpAuthConfigurationInput.allowedProjects.value", "GcpAuthConfigurationInput.allowedZones.omitted", "GcpAuthConfigurationInput.allowedZones.value", "GcpAuthConfigurationInput.policy.omitted", "GcpAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "type.Iam", "type.Gce", "response.type.Iam", "response.type.Gce"], true),
        ["i.management.CloudIdentityAuthenticationOperations.DeleteAliCloudAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.DeleteAliCloudAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.CloudIdentityAuthenticationOperations.DeleteAwsAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.DeleteAwsAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.CloudIdentityAuthenticationOperations.DeleteAzureAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.DeleteAzureAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.CloudIdentityAuthenticationOperations.DeleteGcpAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.DeleteGcpAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.type.Iam", "response.type.Gce"], true),
        ["i.management.CloudIdentityAuthenticationOperations.GetAliCloudAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.GetAliCloudAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.CloudIdentityAuthenticationOperations.GetAwsAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.GetAwsAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.CloudIdentityAuthenticationOperations.GetAzureAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.GetAzureAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.CloudIdentityAuthenticationOperations.GetGcpAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.GetGcpAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.type.Iam", "response.type.Gce"], false),
        ["i.management.CloudIdentityAuthenticationOperations.UpdateAliCloudAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.UpdateAliCloudAuth(System.String,System.String,SecretKit.Infisical.Management.AliCloudAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AliCloudAuthConfigurationInput.policy.omitted", "AliCloudAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.UpdateAwsAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.UpdateAwsAuth(System.String,System.String,SecretKit.Infisical.Management.AwsAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AwsAuthConfigurationInput.allowedPrincipalArns.omitted", "AwsAuthConfigurationInput.allowedPrincipalArns.value", "AwsAuthConfigurationInput.allowedAccountIds.omitted", "AwsAuthConfigurationInput.allowedAccountIds.value", "AwsAuthConfigurationInput.stsEndpoint.omitted", "AwsAuthConfigurationInput.stsEndpoint.value", "AwsAuthConfigurationInput.policy.omitted", "AwsAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.UpdateAzureAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.UpdateAzureAuth(System.String,System.String,SecretKit.Infisical.Management.AzureAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "AzureAuthConfigurationInput.tenantId.omitted", "AzureAuthConfigurationInput.tenantId.value", "AzureAuthConfigurationInput.resource.omitted", "AzureAuthConfigurationInput.resource.value", "AzureAuthConfigurationInput.allowedServicePrincipalIds.omitted", "AzureAuthConfigurationInput.allowedServicePrincipalIds.value", "AzureAuthConfigurationInput.policy.omitted", "AzureAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value"], true),
        ["i.management.CloudIdentityAuthenticationOperations.UpdateGcpAuth"] = new("SecretKit.Infisical.Management.CloudIdentityAuthenticationOperations.UpdateGcpAuth(System.String,System.String,SecretKit.Infisical.Management.GcpAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "GcpAuthConfigurationInput.type.Iam", "GcpAuthConfigurationInput.type.Gce", "GcpAuthConfigurationInput.type.omitted", "GcpAuthConfigurationInput.allowedServiceAccounts.omitted", "GcpAuthConfigurationInput.allowedServiceAccounts.value", "GcpAuthConfigurationInput.allowedProjects.omitted", "GcpAuthConfigurationInput.allowedProjects.value", "GcpAuthConfigurationInput.allowedZones.omitted", "GcpAuthConfigurationInput.allowedZones.value", "GcpAuthConfigurationInput.policy.omitted", "GcpAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "type.Iam", "type.Gce", "response.type.Iam", "response.type.Gce"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.AttachLdapAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.AttachLdapAuth(System.String,System.String,SecretKit.Infisical.Management.LdapAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.allowedFields-unestablished", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "input.template", "input.connection", "LdapAuthSettings.searchFilter.omitted", "LdapAuthSettings.searchFilter.value", "LdapAuthSettings.allowedFields.omitted", "LdapAuthSettings.allowedFields.value", "LdapAuthSettings.lockoutEnabled.omitted", "LdapAuthSettings.lockoutEnabled.false", "LdapAuthSettings.lockoutEnabled.true", "LdapAuthSettings.lockoutThreshold.omitted", "LdapAuthSettings.lockoutThreshold.value", "LdapAuthSettings.lockoutDurationSeconds.omitted", "LdapAuthSettings.lockoutDurationSeconds.value", "LdapAuthSettings.lockoutCounterResetSeconds.omitted", "LdapAuthSettings.lockoutCounterResetSeconds.value", "LdapAuthSettings.policy.omitted", "LdapAuthSettings.policy.value"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.AttachOciAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.AttachOciAuth(System.String,System.String,SecretKit.Infisical.Management.OciAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "OciAuthConfigurationInput.allowedUsernames.omitted", "OciAuthConfigurationInput.allowedUsernames.value", "OciAuthConfigurationInput.policy.omitted", "OciAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "allowedUsernames.omitted", "allowedUsernames.null", "allowedUsernames.value"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.AttachSpiffeAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.AttachSpiffeAuth(System.String,System.String,SecretKit.Infisical.Management.SpiffeAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "SpiffeAuthConfigurationInput.trustDomain.omitted.rejected", "SpiffeAuthConfigurationInput.trustDomain.value", "SpiffeAuthConfigurationInput.allowedSpiffeIds.omitted.rejected", "SpiffeAuthConfigurationInput.allowedSpiffeIds.value", "SpiffeAuthConfigurationInput.allowedAudiences.omitted.rejected", "SpiffeAuthConfigurationInput.allowedAudiences.value", "SpiffeAuthConfigurationInput.trustBundleDistribution.omitted.rejected", "SpiffeAuthConfigurationInput.trustBundleDistribution.value", "SpiffeAuthConfigurationInput.policy.omitted", "SpiffeAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "bundle.static", "bundle.https_web_bundle", "bundle.caCert.omitted", "bundle.caCert.value", "refreshHintSeconds.omitted", "refreshHintSeconds.value", "response.bundle.static", "response.bundle.https_web_bundle"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.AttachTlsCertAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.AttachTlsCertAuth(System.String,System.String,SecretKit.Infisical.Management.TlsCertAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.encryptedCaCertificate-unestablished", "TlsCertAuthConfigurationInput.caCertificate.omitted", "TlsCertAuthConfigurationInput.caCertificate.value", "TlsCertAuthConfigurationInput.allowedCommonNames.omitted", "TlsCertAuthConfigurationInput.allowedCommonNames.value", "TlsCertAuthConfigurationInput.allowedSubjectAltNames.omitted", "TlsCertAuthConfigurationInput.allowedSubjectAltNames.value", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.omitted", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.false", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.true", "TlsCertAuthConfigurationInput.policy.omitted", "TlsCertAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "allowedCommonNames.omitted", "allowedCommonNames.null", "allowedCommonNames.value", "allowedSubjectAltNames.omitted", "allowedSubjectAltNames.null", "allowedSubjectAltNames.empty", "allowedSubjectAltNames.values"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts(System.String,System.String)",
            ["input.organizationId-identityId"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.DeleteLdapAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.DeleteLdapAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.allowedFields-unestablished"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.DeleteOciAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.DeleteOciAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.DeleteSpiffeAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.DeleteSpiffeAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.bundle.static", "response.bundle.https_web_bundle"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.encryptedCaCertificate-unestablished"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.GetLdapAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.GetLdapAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.allowedFields-unestablished"], false),
        ["i.management.ExternalIdentityAuthenticationOperations.GetOciAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.GetOciAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.ExternalIdentityAuthenticationOperations.GetSpiffeAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.GetSpiffeAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.bundle.static", "response.bundle.https_web_bundle"], false),
        ["i.management.ExternalIdentityAuthenticationOperations.GetTlsCertAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.GetTlsCertAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.encryptedCaCertificate-unestablished"], false),
        ["i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle(System.String,System.String)",
            ["input.organizationId-identityId"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.UpdateLdapAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.UpdateLdapAuth(System.String,System.String,SecretKit.Infisical.Management.LdapAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.allowedFields-unestablished", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "input.patch", "LdapAuthSettings.searchFilter.omitted", "LdapAuthSettings.searchFilter.value", "LdapAuthSettings.allowedFields.omitted", "LdapAuthSettings.allowedFields.value", "LdapAuthSettings.lockoutEnabled.omitted", "LdapAuthSettings.lockoutEnabled.false", "LdapAuthSettings.lockoutEnabled.true", "LdapAuthSettings.lockoutThreshold.omitted", "LdapAuthSettings.lockoutThreshold.value", "LdapAuthSettings.lockoutDurationSeconds.omitted", "LdapAuthSettings.lockoutDurationSeconds.value", "LdapAuthSettings.lockoutCounterResetSeconds.omitted", "LdapAuthSettings.lockoutCounterResetSeconds.value", "LdapAuthSettings.policy.omitted", "LdapAuthSettings.policy.value"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.UpdateOciAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.UpdateOciAuth(System.String,System.String,SecretKit.Infisical.Management.OciAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "OciAuthConfigurationInput.allowedUsernames.omitted", "OciAuthConfigurationInput.allowedUsernames.value", "OciAuthConfigurationInput.policy.omitted", "OciAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "allowedUsernames.omitted", "allowedUsernames.null", "allowedUsernames.value"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth(System.String,System.String,SecretKit.Infisical.Management.SpiffeAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "SpiffeAuthConfigurationInput.trustDomain.omitted", "SpiffeAuthConfigurationInput.trustDomain.value", "SpiffeAuthConfigurationInput.allowedSpiffeIds.omitted", "SpiffeAuthConfigurationInput.allowedSpiffeIds.value", "SpiffeAuthConfigurationInput.allowedAudiences.omitted", "SpiffeAuthConfigurationInput.allowedAudiences.value", "SpiffeAuthConfigurationInput.trustBundleDistribution.omitted", "SpiffeAuthConfigurationInput.trustBundleDistribution.value", "SpiffeAuthConfigurationInput.policy.omitted", "SpiffeAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "bundle.static", "bundle.https_web_bundle", "bundle.caCert.omitted", "bundle.caCert.value", "refreshHintSeconds.omitted", "refreshHintSeconds.value", "response.bundle.static", "response.bundle.https_web_bundle"], true),
        ["i.management.ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth"] = new("SecretKit.Infisical.Management.ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth(System.String,System.String,SecretKit.Infisical.Management.TlsCertAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.encryptedCaCertificate-unestablished", "TlsCertAuthConfigurationInput.caCertificate.omitted", "TlsCertAuthConfigurationInput.caCertificate.value", "TlsCertAuthConfigurationInput.allowedCommonNames.omitted", "TlsCertAuthConfigurationInput.allowedCommonNames.value", "TlsCertAuthConfigurationInput.allowedSubjectAltNames.omitted", "TlsCertAuthConfigurationInput.allowedSubjectAltNames.value", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.omitted", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.false", "TlsCertAuthConfigurationInput.verifyClientCertificateChain.true", "TlsCertAuthConfigurationInput.policy.omitted", "TlsCertAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "allowedCommonNames.omitted", "allowedCommonNames.null", "allowedCommonNames.value", "allowedSubjectAltNames.omitted", "allowedSubjectAltNames.null", "allowedSubjectAltNames.empty", "allowedSubjectAltNames.values"], true),
        ["i.management.IdentityAuthenticationOperations.AttachTokenAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.AttachTokenAuth(System.String,System.String,SecretKit.Infisical.Management.TokenAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "TokenAuthConfigurationInput.accessTokenTTL.omitted", "TokenAuthConfigurationInput.accessTokenTTL.value", "TokenAuthConfigurationInput.accessTokenMaxTTL.omitted", "TokenAuthConfigurationInput.accessTokenMaxTTL.value", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.value", "TokenAuthConfigurationInput.accessTokenTrustedIps.omitted", "TokenAuthConfigurationInput.accessTokenTrustedIps.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "tokenTTL.zero", "tokenTTL.positive", "tokenMaxTTL.zero", "tokenMaxTTL.positive", "trustedIps.ipv4", "trustedIps.ipv6", "trustedIps.cidr"], true),
        ["i.management.IdentityAuthenticationOperations.AttachUniversalAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.AttachUniversalAuth(System.String,System.String,SecretKit.Infisical.Management.UniversalAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "UniversalAuthConfigurationInput.accessTokenTTL.omitted", "UniversalAuthConfigurationInput.accessTokenTTL.value", "UniversalAuthConfigurationInput.accessTokenMaxTTL.omitted", "UniversalAuthConfigurationInput.accessTokenMaxTTL.value", "UniversalAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "UniversalAuthConfigurationInput.accessTokenNumUsesLimit.value", "UniversalAuthConfigurationInput.accessTokenPeriod.omitted", "UniversalAuthConfigurationInput.accessTokenPeriod.value", "UniversalAuthConfigurationInput.clientSecretTrustedIps.omitted", "UniversalAuthConfigurationInput.clientSecretTrustedIps.value", "UniversalAuthConfigurationInput.accessTokenTrustedIps.omitted", "UniversalAuthConfigurationInput.accessTokenTrustedIps.value", "UniversalAuthConfigurationInput.lockoutEnabled.omitted", "UniversalAuthConfigurationInput.lockoutEnabled.false", "UniversalAuthConfigurationInput.lockoutEnabled.true", "UniversalAuthConfigurationInput.lockoutThreshold.omitted", "UniversalAuthConfigurationInput.lockoutThreshold.value", "UniversalAuthConfigurationInput.lockoutDurationSeconds.omitted", "UniversalAuthConfigurationInput.lockoutDurationSeconds.value", "UniversalAuthConfigurationInput.lockoutCounterResetSeconds.omitted", "UniversalAuthConfigurationInput.lockoutCounterResetSeconds.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "TokenAuthConfigurationInput.accessTokenTTL.omitted", "TokenAuthConfigurationInput.accessTokenTTL.value", "TokenAuthConfigurationInput.accessTokenMaxTTL.omitted", "TokenAuthConfigurationInput.accessTokenMaxTTL.value", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.value", "TokenAuthConfigurationInput.accessTokenTrustedIps.omitted", "TokenAuthConfigurationInput.accessTokenTrustedIps.value", "tokenTTL.zero", "tokenTTL.positive", "tokenMaxTTL.zero", "tokenMaxTTL.positive", "tokenPeriod.zero", "tokenPeriod.positive", "trustedIps.ipv4", "trustedIps.ipv6", "trustedIps.cidr"], true),
        ["i.management.IdentityAuthenticationOperations.ClearUniversalAuthLockouts"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.ClearUniversalAuthLockouts(System.String,System.String)",
            ["input.organizationId-identityId"], true),
        ["i.management.IdentityAuthenticationOperations.CreateToken"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.CreateToken(System.String,System.String,System.String,System.String)",
            ["name.omitted", "name.value", "organizationSlug.omitted", "organizationSlug.value"], true),
        ["i.management.IdentityAuthenticationOperations.CreateUniversalClientSecret"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.CreateUniversalClientSecret(System.String,System.String,System.String,System.Nullable<System.Double>,System.Nullable<System.Double>)",
            ["description.omitted", "description.value", "numUsesLimit.omitted", "numUsesLimit.value", "ttl.omitted", "ttl.value"], true),
        ["i.management.IdentityAuthenticationOperations.DeleteTokenAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.DeleteTokenAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.IdentityAuthenticationOperations.DeleteUniversalAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.DeleteUniversalAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.IdentityAuthenticationOperations.GetToken"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.GetToken(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityAuthenticationOperations.GetTokenAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.GetTokenAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.IdentityAuthenticationOperations.GetUniversalAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.GetUniversalAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.IdentityAuthenticationOperations.GetUniversalClientSecret"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.GetUniversalClientSecret(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.IdentityAuthenticationOperations.ListTokens"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.ListTokens(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.IdentityAuthenticationOperations.ListUniversalClientSecrets"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.ListUniversalClientSecrets(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.IdentityAuthenticationOperations.RenameToken"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.RenameToken(System.String,System.String,System.String)",
            ["name.omitted", "name.value"], true),
        ["i.management.IdentityAuthenticationOperations.RevokeToken"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.RevokeToken(System.String,System.String)",
            ["input.organizationId-tokenId"], true),
        ["i.management.IdentityAuthenticationOperations.RevokeUniversalClientSecret"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.RevokeUniversalClientSecret(System.String,System.String,System.String)",
            ["input.organizationId-identityId-clientSecretId"], true),
        ["i.management.IdentityAuthenticationOperations.UpdateTokenAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.UpdateTokenAuth(System.String,System.String,SecretKit.Infisical.Management.TokenAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "TokenAuthConfigurationInput.accessTokenTTL.omitted", "TokenAuthConfigurationInput.accessTokenTTL.value", "TokenAuthConfigurationInput.accessTokenMaxTTL.omitted", "TokenAuthConfigurationInput.accessTokenMaxTTL.value", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.value", "TokenAuthConfigurationInput.accessTokenTrustedIps.omitted", "TokenAuthConfigurationInput.accessTokenTrustedIps.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "tokenTTL.zero", "tokenTTL.positive", "tokenMaxTTL.zero", "tokenMaxTTL.positive", "trustedIps.ipv4", "trustedIps.ipv6", "trustedIps.cidr"], true),
        ["i.management.IdentityAuthenticationOperations.UpdateUniversalAuth"] = new("SecretKit.Infisical.Management.IdentityAuthenticationOperations.UpdateUniversalAuth(System.String,System.String,SecretKit.Infisical.Management.UniversalAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "UniversalAuthConfigurationInput.accessTokenTTL.omitted", "UniversalAuthConfigurationInput.accessTokenTTL.value", "UniversalAuthConfigurationInput.accessTokenMaxTTL.omitted", "UniversalAuthConfigurationInput.accessTokenMaxTTL.value", "UniversalAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "UniversalAuthConfigurationInput.accessTokenNumUsesLimit.value", "UniversalAuthConfigurationInput.accessTokenPeriod.omitted", "UniversalAuthConfigurationInput.accessTokenPeriod.value", "UniversalAuthConfigurationInput.clientSecretTrustedIps.omitted", "UniversalAuthConfigurationInput.clientSecretTrustedIps.value", "UniversalAuthConfigurationInput.accessTokenTrustedIps.omitted", "UniversalAuthConfigurationInput.accessTokenTrustedIps.value", "UniversalAuthConfigurationInput.lockoutEnabled.omitted", "UniversalAuthConfigurationInput.lockoutEnabled.false", "UniversalAuthConfigurationInput.lockoutEnabled.true", "UniversalAuthConfigurationInput.lockoutThreshold.omitted", "UniversalAuthConfigurationInput.lockoutThreshold.value", "UniversalAuthConfigurationInput.lockoutDurationSeconds.omitted", "UniversalAuthConfigurationInput.lockoutDurationSeconds.value", "UniversalAuthConfigurationInput.lockoutCounterResetSeconds.omitted", "UniversalAuthConfigurationInput.lockoutCounterResetSeconds.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "TokenAuthConfigurationInput.accessTokenTTL.omitted", "TokenAuthConfigurationInput.accessTokenTTL.value", "TokenAuthConfigurationInput.accessTokenMaxTTL.omitted", "TokenAuthConfigurationInput.accessTokenMaxTTL.value", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.omitted", "TokenAuthConfigurationInput.accessTokenNumUsesLimit.value", "TokenAuthConfigurationInput.accessTokenTrustedIps.omitted", "TokenAuthConfigurationInput.accessTokenTrustedIps.value", "tokenTTL.zero", "tokenTTL.positive", "tokenMaxTTL.zero", "tokenMaxTTL.positive", "tokenPeriod.zero", "tokenPeriod.positive", "trustedIps.ipv4", "trustedIps.ipv6", "trustedIps.cidr"], true),
        ["i.management.OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships"] = new("SecretKit.Infisical.Management.OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships(System.String,System.Int32,System.Int32,SecretKit.Infisical.Management.OrganizationIdentityOrder,SecretKit.Infisical.Management.ManagementListOrder,System.String)",
            ["orderBy.Name", "orderBy.Role", "order.Ascending", "order.Descending", "search.omitted", "search.value"], false),
        ["i.management.OrganizationMembershipOperations.DeleteOrganizationMembership"] = new("SecretKit.Infisical.Management.OrganizationMembershipOperations.DeleteOrganizationMembership(System.String,System.String)",
            ["input.organizationId-membershipId"], true),
        ["i.management.OrganizationMembershipOperations.ListOrganizationMemberships"] = new("SecretKit.Infisical.Management.OrganizationMembershipOperations.ListOrganizationMemberships(System.String)",
            ["collection.bounded"], false),
        ["i.management.OrganizationMembershipOperations.UpdateOrganizationMembership"] = new("SecretKit.Infisical.Management.OrganizationMembershipOperations.UpdateOrganizationMembership(System.String,System.String,System.String,System.Nullable<System.Boolean>,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.IdentityAttribute>)",
            ["role.omitted", "role.value", "isActive.omitted", "isActive.false", "isActive.true", "metadata.omitted", "metadata.value"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.AttachJwtAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.AttachJwtAuth(System.String,System.String,SecretKit.Infisical.Management.JwtAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "JwtAuthConfigurationInput.jwksUrl.omitted", "JwtAuthConfigurationInput.jwksUrl.value", "JwtAuthConfigurationInput.publicKeys.omitted", "JwtAuthConfigurationInput.publicKeys.value", "JwtAuthConfigurationInput.jwksCaCert.omitted", "JwtAuthConfigurationInput.jwksCaCert.value", "JwtAuthConfigurationInput.boundIssuer.omitted", "JwtAuthConfigurationInput.boundIssuer.value", "JwtAuthConfigurationInput.boundAudiences.omitted", "JwtAuthConfigurationInput.boundAudiences.value", "JwtAuthConfigurationInput.boundSubject.omitted", "JwtAuthConfigurationInput.boundSubject.value", "JwtAuthConfigurationInput.policy.omitted", "JwtAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "configurationType.Jwks", "configurationType.Static", "boundClaims.empty", "boundClaims.key-value", "publicKeys.empty", "publicKeys.multiple", "response.configurationType.Jwks", "response.configurationType.Static"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth(System.String,System.String,SecretKit.Infisical.Management.KubernetesAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "KubernetesAuthConfigurationInput.allowedNames.omitted.rejected", "KubernetesAuthConfigurationInput.allowedNames.value", "KubernetesAuthConfigurationInput.allowedNamespaces.omitted.rejected", "KubernetesAuthConfigurationInput.allowedNamespaces.value", "KubernetesAuthConfigurationInput.allowedAudience.omitted", "KubernetesAuthConfigurationInput.allowedAudience.value", "KubernetesAuthConfigurationInput.caCert.omitted", "KubernetesAuthConfigurationInput.caCert.value", "KubernetesAuthConfigurationInput.kubernetesHost.omitted", "KubernetesAuthConfigurationInput.kubernetesHost.value", "KubernetesAuthConfigurationInput.gatewayId.omitted", "KubernetesAuthConfigurationInput.gatewayId.value", "KubernetesAuthConfigurationInput.gatewayPoolId.omitted", "KubernetesAuthConfigurationInput.gatewayPoolId.value", "KubernetesAuthConfigurationInput.templateId.omitted", "KubernetesAuthConfigurationInput.templateId.value", "KubernetesAuthConfigurationInput.tokenReviewerJwt.omitted", "KubernetesAuthConfigurationInput.tokenReviewerJwt.value", "KubernetesAuthConfigurationInput.clearTokenReviewerJwt.false", "KubernetesAuthConfigurationInput.clearTokenReviewerJwt.true.rejected", "KubernetesAuthConfigurationInput.tokenReviewMode.Api", "KubernetesAuthConfigurationInput.tokenReviewMode.Gateway", "KubernetesAuthConfigurationInput.tokenReviewMode.omitted", "KubernetesAuthConfigurationInput.verifyTlsCertificate.omitted", "KubernetesAuthConfigurationInput.verifyTlsCertificate.false", "KubernetesAuthConfigurationInput.verifyTlsCertificate.true", "KubernetesAuthConfigurationInput.policy.omitted", "KubernetesAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "tokenReviewMode.omitted", "tokenReviewMode.Api", "tokenReviewMode.Gateway", "gatewayId.omitted", "gatewayId.null", "gatewayId.value", "gatewayPoolId.omitted", "gatewayPoolId.null", "gatewayPoolId.value", "kubernetesHost.null", "kubernetesHost.value", "templateId.value"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.AttachOidcAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.AttachOidcAuth(System.String,System.String,SecretKit.Infisical.Management.OidcAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.claimMetadataMapping-unestablished", "OidcAuthConfigurationInput.oidcDiscoveryUrl.omitted", "OidcAuthConfigurationInput.oidcDiscoveryUrl.value", "OidcAuthConfigurationInput.boundIssuer.omitted", "OidcAuthConfigurationInput.boundIssuer.value", "OidcAuthConfigurationInput.boundAudiences.omitted", "OidcAuthConfigurationInput.boundAudiences.value", "OidcAuthConfigurationInput.boundSubject.omitted", "OidcAuthConfigurationInput.boundSubject.value", "OidcAuthConfigurationInput.caCert.omitted", "OidcAuthConfigurationInput.caCert.value", "OidcAuthConfigurationInput.templateId.omitted", "OidcAuthConfigurationInput.templateId.value", "OidcAuthConfigurationInput.policy.omitted", "OidcAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "boundClaims.empty", "boundClaims.key-value", "claimMetadataMapping.empty", "claimMetadataMapping.key-value", "templateId.value"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.DeleteJwtAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.DeleteJwtAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.configurationType.Jwks", "response.configurationType.Static"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.DeleteKubernetesAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.DeleteKubernetesAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.DeleteOidcAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.DeleteOidcAuth(System.String,System.String)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.claimMetadataMapping-unestablished"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.GetJwtAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.GetJwtAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.configurationType.Jwks", "response.configurationType.Static"], false),
        ["i.management.WorkloadIdentityAuthenticationOperations.GetKubernetesAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.GetKubernetesAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished"], false),
        ["i.management.WorkloadIdentityAuthenticationOperations.GetOidcAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.GetOidcAuth(System.String,System.String)",
            ["selector.exact", "response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.claimMetadataMapping-unestablished"], false),
        ["i.management.WorkloadIdentityAuthenticationOperations.UpdateJwtAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.UpdateJwtAuth(System.String,System.String,SecretKit.Infisical.Management.JwtAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "JwtAuthConfigurationInput.jwksUrl.omitted", "JwtAuthConfigurationInput.jwksUrl.value", "JwtAuthConfigurationInput.publicKeys.omitted", "JwtAuthConfigurationInput.publicKeys.value", "JwtAuthConfigurationInput.jwksCaCert.omitted", "JwtAuthConfigurationInput.jwksCaCert.value", "JwtAuthConfigurationInput.boundIssuer.omitted", "JwtAuthConfigurationInput.boundIssuer.value", "JwtAuthConfigurationInput.boundAudiences.omitted", "JwtAuthConfigurationInput.boundAudiences.value", "JwtAuthConfigurationInput.boundSubject.omitted", "JwtAuthConfigurationInput.boundSubject.value", "JwtAuthConfigurationInput.policy.omitted", "JwtAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "configurationType.Jwks", "configurationType.Static", "boundClaims.empty", "boundClaims.key-value", "publicKeys.empty", "publicKeys.multiple", "response.configurationType.Jwks", "response.configurationType.Static"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth(System.String,System.String,SecretKit.Infisical.Management.KubernetesAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "KubernetesAuthConfigurationInput.allowedNames.omitted", "KubernetesAuthConfigurationInput.allowedNames.value", "KubernetesAuthConfigurationInput.allowedNamespaces.omitted", "KubernetesAuthConfigurationInput.allowedNamespaces.value", "KubernetesAuthConfigurationInput.allowedAudience.omitted", "KubernetesAuthConfigurationInput.allowedAudience.value", "KubernetesAuthConfigurationInput.caCert.omitted", "KubernetesAuthConfigurationInput.caCert.value", "KubernetesAuthConfigurationInput.kubernetesHost.omitted", "KubernetesAuthConfigurationInput.kubernetesHost.value", "KubernetesAuthConfigurationInput.gatewayId.omitted", "KubernetesAuthConfigurationInput.gatewayId.value", "KubernetesAuthConfigurationInput.gatewayPoolId.omitted", "KubernetesAuthConfigurationInput.gatewayPoolId.value", "KubernetesAuthConfigurationInput.templateId.omitted", "KubernetesAuthConfigurationInput.templateId.value", "KubernetesAuthConfigurationInput.tokenReviewerJwt.omitted", "KubernetesAuthConfigurationInput.tokenReviewerJwt.value", "KubernetesAuthConfigurationInput.clearTokenReviewerJwt.false", "KubernetesAuthConfigurationInput.clearTokenReviewerJwt.true", "KubernetesAuthConfigurationInput.tokenReviewMode.Api", "KubernetesAuthConfigurationInput.tokenReviewMode.Gateway", "KubernetesAuthConfigurationInput.tokenReviewMode.omitted", "KubernetesAuthConfigurationInput.verifyTlsCertificate.omitted", "KubernetesAuthConfigurationInput.verifyTlsCertificate.false", "KubernetesAuthConfigurationInput.verifyTlsCertificate.true", "KubernetesAuthConfigurationInput.policy.omitted", "KubernetesAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "tokenReviewMode.omitted", "tokenReviewMode.Api", "tokenReviewMode.Gateway", "gatewayId.omitted", "gatewayId.null", "gatewayId.value", "gatewayPoolId.omitted", "gatewayPoolId.null", "gatewayPoolId.value", "kubernetesHost.null", "kubernetesHost.value", "templateId.value", "templateId.null", "reviewerJwt.null"], true),
        ["i.management.WorkloadIdentityAuthenticationOperations.UpdateOidcAuth"] = new("SecretKit.Infisical.Management.WorkloadIdentityAuthenticationOperations.UpdateOidcAuth(System.String,System.String,SecretKit.Infisical.Management.OidcAuthConfigurationInput)",
            ["response.known-fields", "response.trusted-ip-projection-unestablished", "response.boundClaims-unestablished", "response.claimMetadataMapping-unestablished", "OidcAuthConfigurationInput.oidcDiscoveryUrl.omitted", "OidcAuthConfigurationInput.oidcDiscoveryUrl.value", "OidcAuthConfigurationInput.boundIssuer.omitted", "OidcAuthConfigurationInput.boundIssuer.value", "OidcAuthConfigurationInput.boundAudiences.omitted", "OidcAuthConfigurationInput.boundAudiences.value", "OidcAuthConfigurationInput.boundSubject.omitted", "OidcAuthConfigurationInput.boundSubject.value", "OidcAuthConfigurationInput.caCert.omitted", "OidcAuthConfigurationInput.caCert.value", "OidcAuthConfigurationInput.templateId.omitted", "OidcAuthConfigurationInput.templateId.value", "OidcAuthConfigurationInput.policy.omitted", "OidcAuthConfigurationInput.policy.value", "WorkloadAuthTokenPolicy.accessTokenTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenTTL.value", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.omitted", "WorkloadAuthTokenPolicy.accessTokenMaxTTL.value", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.omitted", "WorkloadAuthTokenPolicy.accessTokenNumUsesLimit.value", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.omitted", "WorkloadAuthTokenPolicy.accessTokenTrustedIps.value", "boundClaims.empty", "boundClaims.key-value", "claimMetadataMapping.empty", "claimMetadataMapping.key-value", "templateId.value", "templateId.null"], true),
    };

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected)
        => Register(registry, environment, expected, null);

    internal static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected,
        Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? tlsChannel = null,
        IInfisicalSpiffeRefreshSource? spiffeRefresh = null,
        IOrganizationUserSource? organizationUsers = null, IWorkloadTransitionSource? workloadTransitions = null)
    {
        foreach (NativeCaseDefinition definition in expected.Where(d => Owns(d.Key.Operation)))
            registry.Add(new(definition, (probe, token) => RunAsync(environment, definition, probe, token,
                tlsChannel, spiffeRefresh, organizationUsers, workloadTransitions)));
    }

    internal static bool Owns(string operation) => Bindings.ContainsKey(operation);
    internal static bool Valid(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        !string.IsNullOrWhiteSpace(d.Key.Scope) && Bindings.TryGetValue(d.Key.Operation, out IdentityAuthBinding? b) &&
        d.Member == b.Member && b.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) &&
        (d.Key.Case is "selected-contract" or "independent-effect" or "denied-authority" or "cancellation-boundary" ||
            b.Mutation && d.Key.Case == "lost-response-no-replay");

    internal static string? UnavailableReason(NativeCaseDefinition d)
    {
        if (!Valid(d)) return "contract-mismatch";
        if (d.Key.Variant.Contains("unestablished", StringComparison.Ordinal)) return "primary-auth-response-shapes";
        if (d.Key.Variant.StartsWith("trustedIps.", StringComparison.Ordinal) ||
            d.Key.Variant.Contains("TrustedIps.value", StringComparison.Ordinal)) return "trusted-ip-enforcement-observer-unavailable";
        return Family(d) switch
        {
            "IdentityAuthentication" => IdentityAuthenticationEffects.UnavailableReason(d),
            "CloudIdentityAuthentication" => CloudIdentityAuthenticationEffects.UnavailableReason(d),
            "ExternalIdentityAuthentication" => ExternalIdentityAuthenticationEffects.UnavailableReason(d),
            "WorkloadIdentityAuthentication" => WorkloadIdentityAuthenticationEffects.UnavailableReason(d),
            "OrganizationIdentityMemberships" => OrganizationIdentityMembershipsEffects.UnavailableReason(d),
            _ => OrganizationMembershipsEffects.UnavailableReason(d)
        };
    }

    private static string Family(NativeCaseDefinition d) => d.Key.Operation.Split('.')[2] switch
    {
        "OrganizationIdentityMembershipOperations" => "OrganizationIdentityMemberships",
        "OrganizationMembershipOperations" => "OrganizationMemberships",
        var name => name[..^"Operations".Length]
    };

    private static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, CancellationToken token,
        Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? tlsChannel,
        IInfisicalSpiffeRefreshSource? spiffeRefresh, IOrganizationUserSource? organizationUsers,
        IWorkloadTransitionSource? workloadTransitions)
    {
        probe.Contract(Valid(d), NativeFailure.ContractMismatch);
        bool refreshSelected = d.Key.Operation == InfisicalSpiffeRefreshEffects.Operation &&
            environment.TryGetFamilyInput("ExternalIdentityAuthentication", out var family) &&
            family.TryGetProperty("spiffeRefresh", out _);
        bool organizationUserSelected = OrganizationUserInput.Selected(environment, "C08-IM-" + Family(d), d);
        bool workloadTransitionSelected = WorkloadTransitionInput.Selected(environment, "C08-IM-" + Family(d), d);
        if (UnavailableReason(d) is not null && !refreshSelected && !organizationUserSelected && !workloadTransitionSelected)
        { probe.Effect(NativeObservation.Unavailable); return; }
        IdentityAuthContext? context = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(60));
        try
        {
            context = new(environment, "C08-IM-" + Family(d), d, probe, tlsChannel);
            if (workloadTransitionSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Core.Input));
                await WorkloadTransitionEffects.ExecuteAsync(context, workloadTransitions, deadline.Token);
                return;
            }
            if (organizationUserSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Core.Input));
                await OrganizationUserEffects.ExecuteAsync(context.Core, organizationUsers, deadline.Token);
                return;
            }
            switch (Family(d))
            {
                case "IdentityAuthentication": await IdentityAuthenticationEffects.ExecuteAsync(context, deadline.Token); break;
                case "CloudIdentityAuthentication": await CloudIdentityAuthenticationEffects.ExecuteAsync(context, deadline.Token); break;
                case "ExternalIdentityAuthentication":
                    if (refreshSelected)
                        await InfisicalSpiffeRefreshEffects.ExecuteAsync(context, deadline.Token, spiffeRefresh);
                    else await ExternalIdentityAuthenticationEffects.ExecuteAsync(context, deadline.Token);
                    break;
                case "WorkloadIdentityAuthentication": await WorkloadIdentityAuthenticationEffects.ExecuteAsync(context, deadline.Token); break;
                case "OrganizationIdentityMemberships": await OrganizationIdentityMembershipsEffects.ExecuteAsync(context, deadline.Token); break;
                case "OrganizationMemberships": await OrganizationMembershipsEffects.ExecuteAsync(context, deadline.Token); break;
            }
        }
        catch (OperationCanceledException)
        { probe.Contract(false, token.IsCancellationRequested ? NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded); }
        catch (Exception error) when (error is JsonException or ArgumentException or KeyNotFoundException or InvalidOperationException)
        { probe.Contract(false, NativeFailure.MissingInput); }
        finally { if (context is not null) await context.DisposeAsync(); }
    }
}

// Every case owns fresh resources. Host-selected tokens only authorize setup,
// administration and observation; they never stand in for the issued consumer.
internal sealed class IdentityAuthContext : IAsyncDisposable
{
    private readonly ManagementClient[] clients;
    private JsonElement issuer;
    private string allowedProject = "", deniedProject = "", key = "";
    private SecretMaterial? canary;
    private ManagementTlsCertificates? tlsCertificates;
    private readonly Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? tlsChannel;
    public ProjectFamilyContext Core { get; }
    public NativeEnvironment Environment => Core.Environment;
    public NativeCaseProbe Probe => Core.Probe;
    public NativeCaseDefinition Definition => Core.Definition;
    public string OrganizationId => Core.OrganizationId;
    public string Operation => Core.Operation;
    public string Variant => Core.Variant;
    public string IdentityId { get; private set; } = "";
    public string IdentityName { get; private set; } = "";
    public InfisicalNetworkOptions Network => new()
    { AllowLoopbackDevelopmentHttp = Environment.AllowLoopbackDevelopmentHttp };

    internal IdentityAuthContext(NativeEnvironment environment, string family, NativeCaseDefinition definition,
        NativeCaseProbe probe, Func<Uri, SocketsHttpHandler, TlsCertificateProofChannel>? tlsChannel = null)
    {
        this.tlsChannel = tlsChannel;
        Core = new(environment, family["C08-IM-".Length..], definition, probe);
        clients = Enum.GetValues<NativeIdentityRole>().Select(_ => environment.CreateManagementClient()).ToArray();
        Probe.Contract(Required("apiRevision") == "AuthV1IdentitiesV1SecretsV4", NativeFailure.MissingInput);
    }

    public string Required(string name) => Core.Required(name);
    public string? Optional(string name) => Core.Optional(name);
    public string Setting(string name) => issuer.ValueKind == JsonValueKind.Object &&
        issuer.GetProperty("configuration").TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String ? value.GetString()! : throw new NativeCaseFailureException("missing-input");

    public void RequireIssuer(string strategy)
    {
        if (!Core.Input.TryGetProperty("issuers", out JsonElement issuers) ||
            !issuers.TryGetProperty(strategy, out issuer) || issuer.ValueKind != JsonValueKind.Object ||
            !issuer.TryGetProperty("configuration", out JsonElement config) || config.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        if (strategy == "tls-cert")
        {
            if (Environment.Origin.Scheme != Uri.UriSchemeHttps && tlsChannel is null)
                throw new NativeCaseFailureException("missing-input");
            bool contrast = Operation.StartsWith("Update", StringComparison.Ordinal) &&
                (Variant.EndsWith("caCertificate.value", StringComparison.Ordinal) ||
                    Variant.EndsWith("allowedCommonNames.value", StringComparison.Ordinal) ||
                    Variant.EndsWith("allowedSubjectAltNames.value", StringComparison.Ordinal) ||
                    Variant == "allowedSubjectAltNames.values" ||
                    Variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal) ||
                    Variant.EndsWith("verifyClientCertificateChain.false", StringComparison.Ordinal));
            tlsCertificates = new(issuer, contrast);
            contrastingProof = contrast;
        }
        // Validate both proof branches before acquiring any remote resource ownership.
        using InfisicalLoginProof allowed = Proof(strategy, "00000000-0000-0000-0000-000000000001", false);
        using InfisicalLoginProof denied = Proof(strategy, "00000000-0000-0000-0000-000000000001", true);
        Probe.Contract(issuer.GetProperty("allowed").GetRawText() != issuer.GetProperty("denied").GetRawText(),
            NativeFailure.MissingInput);
    }

    public async ValueTask<T> NeedAsync<T>(Func<ManagementRequest<T>> factory, NativeIdentityRole role,
        CancellationToken token) where T : notnull
    {
        SecretOutcome<T> result = await ExecuteAsync(factory, role, token);
        Probe.Contract(result.IsSuccess, NativeFailure.MissingPrerequisite);
        return result.Value;
    }

    public async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(Func<ManagementRequest<T>> factory,
        NativeIdentityRole role, CancellationToken token) where T : notnull
    {
        using ManagementRequest<T> intent = factory();
        using ManagementRequest<T> request = factory();
        ManagementClient client = clients[(int)role];
        ManagementAuthority authority = Environment.CreateManagementAuthority(client, role,
            intent.Target.OrganizationId, intent.Target.ProjectId);
        SecretOutcome<T> result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(intent.OperationId, intent.Target),
            request.IsMutation ? client.CreateReceipt(request) : null, token);
        if (request.IsMutation && result.IsSuccess) Core.RememberProject(result.Value);
        return result;
    }

    public async ValueTask EnsureIdentityAsync(CancellationToken token)
    {
        IdentityName = "sk-auth-" + Guid.NewGuid().ToString("N");
        // Register cleanup by a fresh, collision-checked name before dispatch.
        ManagementPage<IdentitySummary> baseline = await NeedAsync(
            () => IdentityOperations.ListOrganizationIdentities(OrganizationId), NativeIdentityRole.Observer, token);
        Probe.Contract(baseline.IsComplete && baseline.Items.All(i => i.Name != IdentityName), NativeFailure.MissingPrerequisite);
        Core.Cleanup(async ct =>
        {
            SecretOutcome<ManagementPage<IdentitySummary>> listed = await ExecuteAsync(
                () => IdentityOperations.ListOrganizationIdentities(OrganizationId), NativeIdentityRole.Observer, ct);
            if (!listed.IsSuccess || !listed.Value.IsComplete) return false;
            IdentitySummary[] matches = listed.Value.Items.Where(i => i.Name == IdentityName).ToArray();
            if (matches.Length == 0) return true;
            if (matches.Length != 1 || IdentityId.Length != 0 && matches[0].Id != IdentityId) return false;
            string id = matches[0].Id;
            SecretOutcome<IdentitySummary> deleted = await ExecuteAsync(
                () => IdentityOperations.DeleteOrganizationIdentity(OrganizationId, id), NativeIdentityRole.Setup, ct);
            SecretOutcome<IdentitySummary> remaining = await ExecuteAsync(
                () => IdentityOperations.GetOrganizationIdentity(OrganizationId, id), NativeIdentityRole.Observer, ct);
            return deleted.IsSuccess && remaining.Status == SecretStatus.Absent;
        });
        IdentitySummary created = await NeedAsync(() => IdentityOperations.CreateOrganizationIdentity(
            OrganizationId, IdentityName, "member"), NativeIdentityRole.Setup, token);
        IdentityId = created.Id;
        IdentitySummary observed = await NeedAsync(() => IdentityOperations.GetOrganizationIdentity(
            OrganizationId, IdentityId), NativeIdentityRole.Observer, token);
        Probe.Contract(observed.Name == IdentityName && observed.HasDeleteProtection is { IsPresent: true, Value: false } &&
            observed.AuthMethods.IsPresent && observed.AuthMethods.Value.Count == 0, NativeFailure.MissingPrerequisite);
    }

    public async ValueTask EnsureConsumerAsync(CancellationToken token)
    {
        if (canary is not null) return;
        await Core.EnsureProjectAsync(token);
        allowedProject = Core.ProjectId;
        string roleSlug = ProjectFamilyContext.FreshName();
        string? acknowledgedRoleId = null;
        Core.Cleanup(async ct =>
        {
            SecretOutcome<RoleSummary> found = await ExecuteAsync(
                () => ProjectOperations.GetProjectRoleBySlug(OrganizationId, allowedProject, roleSlug), NativeIdentityRole.Observer, ct);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess) return false;
            if (acknowledgedRoleId is not null && found.Value.Id != acknowledgedRoleId) return false;
            SecretOutcome<RoleSummary> deleted = await ExecuteAsync(
                () => ProjectOperations.DeleteProjectRole(OrganizationId, allowedProject, found.Value.Id), NativeIdentityRole.Setup, ct);
            SecretOutcome<RoleSummary> absent = await ExecuteAsync(
                () => ProjectOperations.GetProjectRoleBySlug(OrganizationId, allowedProject, roleSlug), NativeIdentityRole.Observer, ct);
            return deleted.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        acknowledgedRoleId = (await NeedAsync(() => RoleChangeOperations.CreateProjectRole(OrganizationId, allowedProject,
            new ProjectRoleChange(roleSlug, roleSlug,
                permissions: [new ProjectRolePermission(ProjectRoleSubject.Secrets, ProjectRoleAction.Read)])),
            NativeIdentityRole.Setup, token)).Id;
        await NeedAsync(() => MembershipOperations.AddProjectIdentity(OrganizationId, allowedProject, IdentityId,
            new MembershipRoleSelection(role: roleSlug)), NativeIdentityRole.Setup, token);
        string slug = ProjectFamilyContext.FreshName();
        Core.OwnProject(slug);
        deniedProject = (await NeedAsync(() => ProjectOperations.CreateProject(OrganizationId, slug, slug,
            createDefaultEnvironments: false), NativeIdentityRole.Setup, token)).Id;
        await Core.AddObserversAsync(deniedProject, token);
        key = "K" + Guid.NewGuid().ToString("N");
        canary = SecretMaterial.FromText(Guid.NewGuid().ToString("N"));
        foreach (string project in new[] { allowedProject, deniedProject })
        {
            await NeedAsync(() => ProjectOperations.CreateEnvironment(OrganizationId, project, "Witness", "witness"),
                NativeIdentityRole.Setup, token);
            await using InfisicalClient setup = Environment.CreateClient(NativeIdentityRole.Setup);
            var reference = new SecretReference(setup.Authority, new InfisicalSecretAddress(project, "witness", "/", key));
            var receipt = new MutationReceipt(reference);
            SecretOutcome<InfisicalStaticChange> created = await setup.CreateAsync(reference, canary, receipt, token);
            Probe.Contract(created.IsSuccess && created.Value.Disposition == InfisicalChangeDisposition.Applied &&
                receipt.Evidence == DispatchEvidence.Applied, NativeFailure.MissingPrerequisite);
            await using InfisicalClient observer = Environment.CreateObserverClient();
            Probe.Contract(await ReadCanaryAsync(observer, project, true, token), NativeFailure.MissingPrerequisite);
        }
        await using InfisicalClient denied = Environment.CreateDeniedClient();
        Probe.Contract(await ReadCanaryAsync(denied, allowedProject, false, token), NativeFailure.MissingPrerequisite);
    }

    public async ValueTask<bool> UseTokenAsync(SecretMaterial material, bool enabled, CancellationToken token)
    {
        await using var consumer = new InfisicalClient(Environment.Origin, new AuthenticationTokenSource(material), Network);
        bool matched = await ReadCanaryAsync(consumer, allowedProject, enabled, token) &&
            await ReadCanaryAsync(consumer, deniedProject, false, token);
        if (matched && enabled)
            Environment.ConfirmPrerequisite(Definition.Key.Scope, "intended-auth-consumer", NativeObservation.Matched);
        return matched;
    }

    private async ValueTask<bool> ReadCanaryAsync(InfisicalClient client, string project, bool allowed, CancellationToken token)
    {
        SecretOutcome<SecretRead> result = await client.ReadAsync(new(client.Authority,
            new InfisicalSecretAddress(project, "witness", "/", key)), token);
        if (!result.IsSuccess) return !allowed && result.Status == SecretStatus.Denied;
        using SecretRead read = result.Value;
        return allowed && read.Material.Reveal() == canary!.Reveal();
    }

    internal sealed record IssuedPolicy(double Ttl, double MaximumTtl, double UsesLimit);

    private static IssuedPolicy CapturePolicy<T>(T value) where T : notnull
    {
        if (value is not WorkloadAuthConfiguration configuration || configuration.AccessTokenTTL is null ||
            configuration.AccessTokenMaxTTL is null || configuration.AccessTokenNumUsesLimit is null)
            throw new NativeCaseFailureException("observer-unavailable");
        return new(configuration.AccessTokenTTL.Value, configuration.AccessTokenMaxTTL.Value,
            configuration.AccessTokenNumUsesLimit.Value);
    }

    private static bool SameTokenState(TokenAuthToken a, TokenAuthToken b) =>
        a.Id == b.Id && a.IdentityId == b.IdentityId && a.AuthMethod == b.AuthMethod &&
        a.Name.Equals(b.Name) && a.SubOrganizationId.Equals(b.SubOrganizationId) &&
        a.IdentityUAClientSecretId.Equals(b.IdentityUAClientSecretId) &&
        a.AccessTokenTTL == b.AccessTokenTTL && a.AccessTokenMaxTTL == b.AccessTokenMaxTTL &&
        a.AccessTokenNumUses == b.AccessTokenNumUses && a.AccessTokenNumUsesLimit == b.AccessTokenNumUsesLimit &&
        a.AccessTokenPeriod == b.AccessTokenPeriod && a.IsAccessTokenRevoked == b.IsAccessTokenRevoked &&
        a.CreatedAt == b.CreatedAt && a.UpdatedAt == b.UpdatedAt &&
        a.AccessTokenLastUsedAt.Equals(b.AccessTokenLastUsedAt) &&
        a.AccessTokenLastRenewedAt.Equals(b.AccessTokenLastRenewedAt);

    public async ValueTask<bool> ObserveProofAsync(string strategy, bool enabled, CancellationToken token,
        IssuedPolicy? policy = null, bool baselinePolicy = false)
    {
        if (enabled && policy is null)
        {
            if (strategy != "ldap") throw new NativeCaseFailureException("observer-unavailable");
            using var configuration = await NeedAsync(() => ExternalIdentityAuthenticationOperations.GetLdapAuth(
                OrganizationId, IdentityId), NativeIdentityRole.Observer, token);
            policy = CapturePolicy(configuration);
        }
        bool chainContrast = strategy == "tls-cert" && Operation.StartsWith("Update", StringComparison.Ordinal) &&
            (Variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal) ||
                Variant.EndsWith("verifyClientCertificateChain.false", StringComparison.Ordinal));
        bool selectedChain = Variant.EndsWith("verifyClientCertificateChain.true", StringComparison.Ordinal);
        var exchanges = chainContrast ?
            new[] { (Denied: false, Baseline: true, Allowed: enabled && (!baselinePolicy ? selectedChain : true)),
                (Denied: false, Baseline: false, Allowed: enabled && (!baselinePolicy ? true : !selectedChain)),
                (Denied: true, Baseline: false, Allowed: false) } : contrastingProof ?
            new[] { (Denied: false, Baseline: true, Allowed: enabled && baselinePolicy),
                (Denied: false, Baseline: false, Allowed: enabled && !baselinePolicy),
                (Denied: true, Baseline: false, Allowed: false) } :
            new[] { (Denied: false, Baseline: false, Allowed: enabled),
                (Denied: true, Baseline: false, Allowed: false) };
        foreach (var exchange in exchanges)
        {
            using TlsCertificateProofChannel? channel = strategy == "tls-cert" ?
                tlsCertificates!.Open(Environment.Origin, exchange.Denied, exchange.Baseline, tlsChannel) : null;
            using var authentication = channel?.CreateAuthentication() ?? new InfisicalProofAuthentication(Environment.Origin, Network);
            ManagementPage<TokenAuthToken> before = await NeedAsync(
                () => IdentityAuthenticationOperations.ListTokens(OrganizationId, IdentityId), NativeIdentityRole.Observer, token);
            if (!before.IsComplete) return false;
            using InfisicalLoginProof proof = Proof(strategy, IdentityId, exchange.Denied, exchange.Baseline);
            InfisicalProofLoginReceipt receipt = authentication.CreateReceipt();
            SecretOutcome<InfisicalProofLogin> result = await authentication.LoginAsync(proof, receipt, token);
            using InfisicalProofLogin? login = result.IsSuccess ? result.Value : null;
            bool allowed = exchange.Allowed;
            if (!allowed)
            {
                if (result.Status != SecretStatus.Denied || receipt.Evidence != DispatchEvidence.Rejected) return false;
            }
            else if (!result.IsSuccess || receipt.Evidence != DispatchEvidence.Applied ||
                !await UseTokenAsync(login!.Token.Material, true, token)) return false;
            ManagementPage<TokenAuthToken> after = await NeedAsync(
                () => IdentityAuthenticationOperations.ListTokens(OrganizationId, IdentityId), NativeIdentityRole.Observer, token);
            if (!after.IsComplete || after.Items.Count != before.Items.Count + (allowed ? 1 : 0)) return false;
            if (before.Items.Select(t => t.Id).Distinct().Count() != before.Items.Count ||
                after.Items.Select(t => t.Id).Distinct().Count() != after.Items.Count ||
                before.Items.Any(previous => !after.Items.Any(current => SameTokenState(previous, current)))) return false;
            TokenAuthToken[] issued = after.Items.Where(t => before.Items.All(b => b.Id != t.Id)).ToArray();
            if (allowed && (issued.Length != 1 || issued[0].IdentityId != IdentityId ||
                issued[0].AuthMethod != strategy + "-auth" || issued[0].IsAccessTokenRevoked != false)) return false;
            if (allowed && (policy is null || issued[0].AccessTokenTTL != policy.Ttl ||
                issued[0].AccessTokenMaxTTL != policy.MaximumTtl || issued[0].AccessTokenNumUsesLimit != policy.UsesLimit ||
                login!.ExpiresIn != policy.Ttl || login.AccessTokenMaxTTL != policy.MaximumTtl)) return false;
        }
        return true;
    }

    public async ValueTask InduceLockoutAsync(string strategy, CancellationToken token)
    {
        using var authentication = new InfisicalProofAuthentication(Environment.Origin, Network);
        using InfisicalLoginProof proof = Proof(strategy, IdentityId, true);
        SecretOutcome<InfisicalProofLogin> outcome = await authentication.LoginAsync(proof, authentication.CreateReceipt(), token);
        if (outcome.IsSuccess) outcome.Value.Dispose();
        Probe.Contract(outcome.Status == SecretStatus.Denied, NativeFailure.MissingPrerequisite);
        IdentitySummary observed = await NeedAsync(() => IdentityOperations.GetOrganizationIdentity(OrganizationId, IdentityId),
            NativeIdentityRole.Observer, token);
        Probe.Contract(observed.ActiveLockoutAuthMethods.IsPresent &&
            observed.ActiveLockoutAuthMethods.Value.Contains(strategy + "-auth", StringComparer.Ordinal),
            NativeFailure.MissingPrerequisite);
    }

    private bool contrastingProof;

    private InfisicalLoginProof Proof(string strategy, string identity, bool denied, bool baseline = false)
    {
        JsonElement input = issuer.GetProperty(baseline ? "baselineAllowed" : denied ? "denied" : "allowed");
        string Text(string name) => input.GetProperty(name).GetString() ?? throw new NativeCaseFailureException("missing-input");
        string? OptionalText(string name) => input.TryGetProperty(name, out JsonElement value) ? value.GetString() : null;
        using SecretMaterial? jwt = input.TryGetProperty("jwt", out _) ? SecretMaterial.FromText(Text("jwt")) : null;
        using SecretMaterial? body = input.TryGetProperty("iamRequestBody", out _) ? SecretMaterial.FromText(Text("iamRequestBody")) : null;
        using SecretMaterial? headers = input.TryGetProperty("iamRequestHeaders", out _) ? SecretMaterial.FromText(Text("iamRequestHeaders")) : null;
        using SecretMaterial? access = input.TryGetProperty("accessKeyId", out _) ? SecretMaterial.FromText(Text("accessKeyId")) : null;
        using SecretMaterial? signature = input.TryGetProperty("signature", out _) ? SecretMaterial.FromText(Text("signature")) : null;
        using SecretMaterial? nonce = input.TryGetProperty("signatureNonce", out _) ? SecretMaterial.FromText(Text("signatureNonce")) : null;
        using SecretMaterial? password = input.TryGetProperty("password", out _) ? SecretMaterial.FromText(Text("password")) : null;
        using SecretMaterial? authorization = input.TryGetProperty("authorization", out _) ? SecretMaterial.FromText(Text("authorization")) : null;
        return strategy switch
        {
            "aws" => InfisicalLoginProof.Aws(identity, body!, headers!, OptionalText("method")),
            "azure" => InfisicalLoginProof.Azure(identity, jwt!),
            "gcp" => InfisicalLoginProof.Gcp(identity, jwt!),
            "alicloud" => InfisicalLoginProof.AliCloud(identity, access!, signature!, nonce!, Text("timestamp"), Text("version")),
            "jwt" => InfisicalLoginProof.Jwt(identity, jwt!),
            "oidc" => InfisicalLoginProof.Oidc(identity, jwt!),
            "kubernetes" => InfisicalLoginProof.Kubernetes(identity, jwt!),
            "spiffe" => InfisicalLoginProof.Spiffe(identity, jwt!),
            "ldap" => InfisicalLoginProof.Ldap(identity, Text("username"), password!),
            "oci" => InfisicalLoginProof.Oci(identity, Text("userOcid"), authorization!, Text("host"),
                OptionalText("date"), OptionalText("xDate")),
            "tls-cert" => InfisicalLoginProof.TlsCertificate(identity, OptionalText("organizationSlug")),
            _ => throw new NativeCaseFailureException("missing-input")
        };
    }

    public WorkloadAuthTokenPolicy Policy(bool baseline = false)
    {
        bool omit(string field) => !baseline && Variant.EndsWith(field + ".omitted", StringComparison.Ordinal);
        if (!baseline && Variant.EndsWith(".policy.omitted", StringComparison.Ordinal)) return new();
        return new(omit("accessTokenTTL") ? null : baseline ? 300 : 600,
            omit("accessTokenMaxTTL") ? null : baseline ? 1200 : 1800,
            omit("accessTokenNumUsesLimit") ? null : baseline ? 1000 : 2000);
    }

    public string BaselineSetting(string field, string selected)
    {
        if (!issuer.TryGetProperty("baselineParameters", out var parameters) || parameters.ValueKind != JsonValueKind.Object ||
            !parameters.TryGetProperty(field, out var value) || value.ValueKind != JsonValueKind.String ||
            !issuer.TryGetProperty("baselineAllowed", out var proof) || proof.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("observer-unavailable");
        string result = value.GetString()!;
        if (result.Length == 0 || result == selected) throw new NativeCaseFailureException("missing-input");
        contrastingProof = true;
        return result;
    }

    public string? TextInput(string field, bool baseline = false)
    {
        if (!baseline && Variant.EndsWith(field + ".omitted", StringComparison.Ordinal)) return null;
        string selected = Setting(field);
        if (baseline && Operation.StartsWith("Update", StringComparison.Ordinal) &&
            Variant.EndsWith(field + ".value", StringComparison.Ordinal))
            return BaselineSetting(field, selected);
        return selected;
    }
    public string ExpectedText(string field, string? selected) => selected ??
        Setting(Operation.StartsWith("Update", StringComparison.Ordinal) ? field : "default-" + field);

    internal JsonElement TlsSettings(bool baseline) => issuer.GetProperty(baseline ? "baselineParameters" : "configuration");

    public async ValueTask RejectionAsync<T>(Action construct, Func<ManagementRequest<T>> get,
        CancellationToken token) where T : notnull
    {
        bool rejected = false;
        try { construct(); } catch (ArgumentException) { rejected = true; }
        Probe.Contract(rejected, NativeFailure.ContractMismatch);
        // This is an explicit input-rejection branch. No request or receipt can be
        // dispatched; independent observation still proves absence on a fresh owner.
        SecretOutcome<T> absent = await ExecuteAsync(get, NativeIdentityRole.Observer, token);
        if (absent.IsSuccess && absent.Value is IDisposable owned) owned.Dispose();
        Probe.Effect(absent.Status == SecretStatus.Absent ? NativeObservation.Matched : NativeObservation.Mismatched);
    }

    public bool PolicyMatches(WorkloadAuthConfiguration config, WorkloadAuthTokenPolicy input)
    {
        double Expected(string name, long? selected, long initial) => selected ?? (Operation.StartsWith("Update",
            StringComparison.Ordinal) ? initial : double.Parse(Setting(name), System.Globalization.CultureInfo.InvariantCulture));
        return config.IdentityId == IdentityId && config.AccessTokenTTL == Expected("defaultTTL", input.AccessTokenTTL, 300) &&
            config.AccessTokenMaxTTL == Expected("defaultMaxTTL", input.AccessTokenMaxTTL, 1200) &&
            config.AccessTokenNumUsesLimit == Expected("defaultUses", input.AccessTokenNumUsesLimit, 1000);
    }

    public bool TokenMatchesPolicy(TokenAuthToken issued, IdentityAuthenticationConfiguration configuration) =>
        issued.IdentityId == IdentityId && configuration.IdentityId == IdentityId &&
        configuration.AccessTokenTTL is not null && configuration.AccessTokenMaxTTL is not null &&
        configuration.AccessTokenNumUsesLimit is not null &&
        issued.AccessTokenTTL == configuration.AccessTokenTTL &&
        issued.AccessTokenMaxTTL == configuration.AccessTokenMaxTTL &&
        issued.AccessTokenNumUsesLimit == configuration.AccessTokenNumUsesLimit &&
        issued.AccessTokenPeriod == configuration.AccessTokenPeriod;

    public async ValueTask ConfigurationAsync<T>(Func<ManagementRequest<T>> attach, Func<ManagementRequest<T>> get,
        Func<ManagementRequest<T>> update, Func<ManagementRequest<T>> delete,
        Func<T, bool, bool> match, string strategy, CancellationToken token) where T : notnull
    {
        bool attaching = Operation.StartsWith("Attach", StringComparison.Ordinal);
        bool updating = Operation.StartsWith("Update", StringComparison.Ordinal);
        bool deleting = Operation.StartsWith("Delete", StringComparison.Ordinal);
        await EnsureConsumerAsync(token);
        if (!attaching)
        {
            T seeded = await NeedAsync(attach, NativeIdentityRole.Setup, token);
            if (seeded is IDisposable owned) owned.Dispose();
            SecretOutcome<T> baseline = await ExecuteAsync(get, NativeIdentityRole.Observer, token);
            IssuedPolicy? baselineIssuedPolicy = null;
            try
            {
                Probe.Contract(baseline.IsSuccess && match(baseline.Value, false), NativeFailure.MissingPrerequisite);
                baselineIssuedPolicy = CapturePolicy(baseline.Value);
            }
            finally { if (baseline.IsSuccess && baseline.Value is IDisposable observedOwned) observedOwned.Dispose(); }
            Probe.Contract(await ObserveProofAsync(strategy, true, token, baselineIssuedPolicy, true), NativeFailure.MissingPrerequisite);
        }
        else
        {
            SecretOutcome<T> absent = await ExecuteAsync(get, NativeIdentityRole.Observer, token);
            if (absent.IsSuccess && absent.Value is IDisposable owned) owned.Dispose();
            Probe.Contract(absent.Status == SecretStatus.Absent, NativeFailure.MissingPrerequisite);
        }
        await CaseAsync(attaching ? attach : updating ? update : deleting ? delete : get,
            value => match(value, attaching || updating), async (applied, ct) =>
            {
                bool present = attaching ? applied : !(deleting && applied);
                SecretOutcome<T> observed = await ExecuteAsync(get, NativeIdentityRole.Observer, ct);
                bool state;
                IssuedPolicy? issuedPolicy = null;
                try
                {
                    state = present ? observed.IsSuccess && match(observed.Value, applied && (attaching || updating)) :
                    observed.Status == SecretStatus.Absent;
                    if (state && present) issuedPolicy = CapturePolicy(observed.Value);
                }
                finally { if (observed.IsSuccess && observed.Value is IDisposable owned) owned.Dispose(); }
                return state && await ObserveProofAsync(strategy, present, ct, issuedPolicy,
                    !(applied && (attaching || updating)));
            }, token);
    }

    public async ValueTask CaseAsync<T>(Func<ManagementRequest<T>> factory, Func<T, bool> match,
        Func<bool, CancellationToken, ValueTask<bool>> observe, CancellationToken token) where T : notnull
    {
        using ManagementRequest<T> intent = factory();
        using ManagementRequest<T> request = factory();
        bool applied = Definition.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        NativeIdentityRole role = Definition.Key.Case == "denied-authority" ? NativeIdentityRole.Denied : NativeIdentityRole.Administrative;
        ManagementClient client = clients[(int)role];
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        if (Definition.Key.Case == "cancellation-boundary")
        {
            var barrier = new ProjectTokenBarrier(Environment.Tokens(role));
            var authority = new ManagementAuthority(client.Authority, barrier, intent.Target.OrganizationId, intent.Target.ProjectId);
            Task entered = barrier.Entered; // Subscribe before triggering acquisition.
            Task<SecretOutcome<T>> execution = client.ExecuteAsync(request, authority,
                authority.IssueGrant(intent.OperationId, intent.Target), receipt, cancellation.Token).AsTask();
            try
            {
                await entered.WaitAsync(token);
                cancellation.Cancel();
                barrier.Release();
                bool cancelled = false;
                try { await execution; }
                catch (OperationCanceledException) { cancelled = cancellation.IsCancellationRequested; }
                Probe.Contract(cancelled && (receipt is null || receipt.Evidence == DispatchEvidence.NotDispatched),
                    NativeFailure.ContractMismatch);
            }
            finally
            {
                cancellation.Cancel();
                barrier.Release();
                try { await execution; } catch (OperationCanceledException) { }
            }
        }
        else
        {
            ManagementAuthority authority = Environment.CreateManagementAuthority(client, role,
                intent.Target.OrganizationId, intent.Target.ProjectId);
            if (Definition.Key.Case == "lost-response-no-replay")
            {
                using var boundary = new ProjectResponseBoundary(Environment.Origin, cancellation);
                bool cancelled = false;
                using (boundary.Enter())
                    try
                    {
                        await client.ExecuteAsync(request, authority, authority.IssueGrant(intent.OperationId, intent.Target),
                        receipt, cancellation.Token);
                    }
                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                    { cancelled = cancellation.IsCancellationRequested; }
                Probe.Contract(boundary.Reached && cancelled && receipt!.Evidence == DispatchEvidence.PossiblyDispatched,
                    NativeFailure.ContractMismatch);
            }
            else
            {
                SecretOutcome<T> result = await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(intent.OperationId, intent.Target), receipt, token);
                try
                {
                    Probe.Contract(applied ? result.IsSuccess && match(result.Value) &&
                        (receipt is null || receipt.Evidence == DispatchEvidence.Applied) :
                        result.Status == SecretStatus.Denied && (receipt is null || receipt.Evidence == DispatchEvidence.Rejected),
                        NativeFailure.ContractMismatch);
                }
                finally { if (result.IsSuccess && result.Value is IDisposable owned) owned.Dispose(); }
            }
        }
        Probe.Effect(await observe(applied, token) ? NativeObservation.Matched : NativeObservation.Mismatched);
        if (applied)
        {
            Environment.ConfirmPrerequisite(Definition.Key.Scope, "selected-administrative-identity", NativeObservation.Matched);
            Environment.ConfirmPrerequisite(Definition.Key.Scope, "scoped-administrative-rights", NativeObservation.Matched);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try { await Core.CleanupAsync(); }
        finally
        {
            canary?.Dispose();
            tlsCertificates?.Dispose();
        }
    }

    public override string ToString() => "[IdentityAuthContext]";
}
