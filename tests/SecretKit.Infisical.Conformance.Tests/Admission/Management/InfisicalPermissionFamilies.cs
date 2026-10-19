using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class InfisicalPermissionFamilies
{
    private static readonly string[] Variants0 =
    [
        "permission.scalar-crud",
        "permissions.array",
        "permissions.empty",
        "lifetime.permanent",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants1 =
    [
        "permission.scalar-crud",
        "permissions.array",
        "permissions.empty",
        "lifetime.permanent",
        "lifetime.relative-minute",
        "lifetime.relative-hour",
        "lifetime.relative-day",
        "permission.Secrets.read",
        "permission.Secrets.describeSecret",
        "permission.Secrets.readValue",
        "permission.Secrets.create",
        "permission.Secrets.edit",
        "permission.Secrets.delete",
        "permission.DynamicSecrets.read-root-credential",
        "permission.DynamicSecrets.create-root-credential",
        "permission.DynamicSecrets.edit-root-credential",
        "permission.DynamicSecrets.delete-root-credential",
        "permission.DynamicSecrets.lease",
        "permission.Identity.read",
        "permission.Identity.create",
        "permission.Identity.edit",
        "permission.Identity.delete",
        "permission.Identity.grant-privileges",
        "permission.Identity.assign-role",
        "permission.Identity.assign-additional-privileges",
        "permission.Identity.assume-privileges",
        "permission.Identity.revoke-auth",
        "permission.Identity.edit-auth",
        "permission.Identity.create-token",
        "permission.Identity.get-token",
        "permission.Identity.delete-token",
        "permission.PkiSubscribers.read",
        "permission.PkiSubscribers.create",
        "permission.PkiSubscribers.edit",
        "permission.PkiSubscribers.delete",
        "permission.PkiSubscribers.issue-cert",
        "permission.PkiSubscribers.list-certs",
        "permission.CertificateTemplates.read",
        "permission.CertificateTemplates.create",
        "permission.CertificateTemplates.edit",
        "permission.CertificateTemplates.delete",
        "permission.CertificateTemplates.issue-cert",
        "permission.CertificateTemplates.list-certs",
        "permission.SecretRotation.read",
        "permission.SecretRotation.read-generated-credentials",
        "permission.SecretRotation.create",
        "permission.SecretRotation.edit",
        "permission.SecretRotation.delete",
        "permission.SecretRotation.rotate-secrets",
        "permission.SecretSyncs.read",
        "permission.SecretSyncs.create",
        "permission.SecretSyncs.edit",
        "permission.SecretSyncs.delete",
        "permission.SecretSyncs.sync-secrets",
        "permission.SecretSyncs.import-secrets",
        "permission.SecretSyncs.remove-secrets",
        "permission.PkiSyncs.read",
        "permission.PkiSyncs.create",
        "permission.PkiSyncs.edit",
        "permission.PkiSyncs.delete",
        "permission.PkiSyncs.sync-certificates",
        "permission.PkiSyncs.import-certificates",
        "permission.PkiSyncs.remove-certificates",
        "permission.PkiSyncs.set-post-sync-command",
        "permission.PkiSyncs.set-health-check-command",
        "permission.PkiSyncs.set-target-host",
        "permission.SecretEventSubscriptions.subscribe-to-creation-events",
        "permission.SecretEventSubscriptions.subscribe-to-update-events",
        "permission.SecretEventSubscriptions.subscribe-to-deletion-events",
        "permission.SecretEventSubscriptions.subscribe-to-import-mutation-events",
        "permission.CertificateProfiles.read",
        "permission.CertificateProfiles.create",
        "permission.CertificateProfiles.edit",
        "permission.CertificateProfiles.delete",
        "permission.CertificateProfiles.issue-cert",
        "permission.CertificateProfiles.reveal-acme-eab-secret",
        "permission.CertificateProfiles.rotate-acme-eab-secret",
        "permission.CertificateProfiles.manage-application-attachments",
        "permission.CertificateApplication.read",
        "permission.CertificateApplication.list",
        "permission.CertificateApplication.create",
        "permission.CertificateAuthorities.read",
        "permission.CertificateAuthorities.create",
        "permission.CertificateAuthorities.edit",
        "permission.CertificateAuthorities.delete",
        "permission.CertificateAuthorities.issue-ca-certificate",
        "permission.CertificateAuthorities.sign-intermediate",
        "permission.Certificates.read",
        "permission.Certificates.create",
        "permission.Certificates.edit",
        "permission.Certificates.delete",
        "permission.Certificates.read-private-key",
        "permission.Certificates.import",
        "permission.SecretRollback.read",
        "permission.SecretRollback.create",
        "permission.ApprovalRequests.read",
        "permission.ApprovalRequests.create",
        "permission.Member.read",
        "permission.Member.create",
        "permission.Member.edit",
        "permission.Member.delete",
        "permission.Member.grant-privileges",
        "permission.Member.assign-role",
        "permission.Member.assign-additional-privileges",
        "permission.Member.assume-privileges",
        "permission.Groups.read",
        "permission.Groups.create",
        "permission.Groups.edit",
        "permission.Groups.delete",
        "permission.Groups.grant-privileges",
        "permission.Groups.assign-role",
        "permission.AuditLogs.read",
        "permission.AuditLogs.edit",
        "permission.Insights.read",
        "permission.Insights.generate-report",
        "permission.Insights.delete-report",
        "permission.PkiDiscovery.read",
        "permission.PkiDiscovery.create",
        "permission.PkiDiscovery.edit",
        "permission.PkiDiscovery.delete",
        "permission.PkiDiscovery.run-scan",
        "permission.PkiCertificateInstallations.read",
        "permission.PkiCertificateInstallations.edit",
        "permission.PkiCertificateInstallations.delete",
        "permission.CodeSigners.read",
        "permission.CodeSigners.create",
        "permission.CodeSigners.edit",
        "permission.CodeSigners.delete",
        "permission.CodeSigners.sign",
        "permission.Workspace.edit",
        "permission.Workspace.delete",
        "permission.Kms.edit",
        "permission.Cmek.read",
        "permission.Cmek.create",
        "permission.Cmek.edit",
        "permission.Cmek.delete",
        "permission.Cmek.encrypt",
        "permission.Cmek.decrypt",
        "permission.Cmek.sign",
        "permission.Cmek.verify",
        "permission.Cmek.generate-mac",
        "permission.Cmek.verify-mac",
        "permission.Cmek.rotate",
        "permission.Cmek.export-private-key",
        "permission.Kmip.create-clients",
        "permission.Kmip.update-clients",
        "permission.Kmip.delete-clients",
        "permission.Kmip.read-clients",
        "permission.Kmip.generate-client-certificates",
        "permission.Commits.read",
        "permission.Commits.perform-rollback",
        "permission.SecretScanningDataSources.read-data-sources",
        "permission.SecretScanningDataSources.create-data-sources",
        "permission.SecretScanningDataSources.edit-data-sources",
        "permission.SecretScanningDataSources.delete-data-sources",
        "permission.SecretScanningDataSources.trigger-data-source-scans",
        "permission.SecretScanningDataSources.read-data-source-scans",
        "permission.SecretScanningDataSources.read-data-source-resources",
        "permission.SecretScanningFindings.read-findings",
        "permission.SecretScanningFindings.update-findings",
        "permission.SecretScanningConfigs.read-configs",
        "permission.SecretScanningConfigs.update-configs",
        "permission.AppConnections.read-app-connections",
        "permission.AppConnections.create-app-connections",
        "permission.AppConnections.edit-app-connections",
        "permission.AppConnections.delete-app-connections",
        "permission.AppConnections.connect-app-connections",
        "permission.AppConnections.rotate-credentials",
        "permission.HsmConnectors.read-hsm-connectors",
        "permission.HsmConnectors.create-hsm-connectors",
        "permission.HsmConnectors.edit-hsm-connectors",
        "permission.HsmConnectors.delete-hsm-connectors",
        "permission.HsmConnectors.test-hsm-connectors",
        "permission.HsmConnectors.attach-hsm-connectors",
        "permission.HoneyTokens.read",
        "permission.HoneyTokens.read-credentials",
        "permission.HoneyTokens.create",
        "permission.HoneyTokens.edit",
        "permission.HoneyTokens.reset",
        "permission.HoneyTokens.revoke",
        "permission.ProxiedServices.read",
        "permission.ProxiedServices.create",
        "permission.ProxiedServices.edit",
        "permission.ProxiedServices.delete",
        "permission.ProxiedServices.proxy",
        "permission.ProxiedServices.report-usage",
        "permission.AgentVaultAccessBundles.read",
        "permission.AgentVaultAccessBundles.create",
        "permission.AgentVaultAccessBundles.edit",
        "permission.AgentVaultAccessBundles.delete",
        "permission.AgentVaultAccessBundles.manage-members",
        "permission.AgentVaultSessions.read",
        "permission.AgentVaultSessions.create",
        "permission.AgentVaultSessions.revoke",
        "permission.AgentVaultProxies.read",
        "permission.AgentVaultProxies.create",
        "permission.AgentVaultProxies.edit",
        "permission.AgentVaultProxies.delete",
        "permission.AgentVaultProxies.issue-token",
        "permission.AgentVaultProxies.revoke",
        "permission.ApprovalRequestGrants.read",
        "permission.ApprovalRequestGrants.revoke",
        "permission.SecretApprovalRequest.read",
        "permission.ProjectFolderGrant.read-grant",
        "permission.ProjectFolderGrant.create-grant",
        "permission.ProjectFolderGrant.revoke-grant",
        "permission.SecretFolders.read",
        "permission.SecretFolders.create",
        "permission.SecretFolders.edit",
        "permission.SecretFolders.delete",
        "permission.SecretImports.read",
        "permission.SecretImports.create",
        "permission.SecretImports.edit",
        "permission.SecretImports.delete",
        "permission.CertificatePolicies.read",
        "permission.CertificatePolicies.create",
        "permission.CertificatePolicies.edit",
        "permission.CertificatePolicies.delete",
        "permission.SecretApproval.read",
        "permission.SecretApproval.create",
        "permission.SecretApproval.edit",
        "permission.SecretApproval.delete",
        "permission.Role.read",
        "permission.Role.create",
        "permission.Role.edit",
        "permission.Role.delete",
        "permission.Integrations.read",
        "permission.Integrations.create",
        "permission.Integrations.edit",
        "permission.Integrations.delete",
        "permission.Webhooks.read",
        "permission.Webhooks.create",
        "permission.Webhooks.edit",
        "permission.Webhooks.delete",
        "permission.ServiceTokens.read",
        "permission.ServiceTokens.create",
        "permission.ServiceTokens.edit",
        "permission.ServiceTokens.delete",
        "permission.Settings.read",
        "permission.Settings.create",
        "permission.Settings.edit",
        "permission.Settings.delete",
        "permission.SecretValidationRules.read",
        "permission.SecretValidationRules.create",
        "permission.SecretValidationRules.edit",
        "permission.SecretValidationRules.delete",
        "permission.Environments.read",
        "permission.Environments.create",
        "permission.Environments.edit",
        "permission.Environments.delete",
        "permission.Tags.read",
        "permission.Tags.create",
        "permission.Tags.edit",
        "permission.Tags.delete",
        "permission.IpAllowlist.read",
        "permission.IpAllowlist.create",
        "permission.IpAllowlist.edit",
        "permission.IpAllowlist.delete",
        "permission.PkiAlerts.read",
        "permission.PkiAlerts.create",
        "permission.PkiAlerts.edit",
        "permission.PkiAlerts.delete",
        "permission.PkiCollections.read",
        "permission.PkiCollections.create",
        "permission.PkiCollections.edit",
        "permission.PkiCollections.delete",
        "permission.CertificateInventoryViews.read",
        "permission.CertificateInventoryViews.create",
        "permission.CertificateInventoryViews.edit",
        "permission.CertificateInventoryViews.delete",
        "condition.metadata.elemMatch",
        "condition.secretTags.in",
        "condition.secretTags.all",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants2 =
    [
        "permission.scalar-crud",
        "permissions.array",
        "permissions.empty",
        "lifetime.relative-minute",
        "lifetime.relative-hour",
        "lifetime.relative-day",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants3 =
    [
        "selector.slug",
        "response.permanent",
        "response.relative",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants4 =
    [
        "permission.scalar-crud",
        "permissions.array",
        "permissions.empty",
        "lifetime.permanent",
        "lifetime.relative-minute",
        "lifetime.relative-hour",
        "lifetime.relative-day",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants5 =
    [
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants6 =
    [
        "selector.exact",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants7 =
    [
        "collection.bounded",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants8 =
    [
        "permissions.action.scalar",
        "permissions.action.array",
        "permissions.empty",
        "description.omitted",
        "description.null",
        "description.empty",
        "description.value",
        "condition.literal",
        "condition.eq",
        "condition.ne",
        "condition.in",
        "condition.glob",
        "inverted.omitted",
        "inverted.false",
        "inverted.true",
        "permission.Workspace.create",
        "permission.Project.create",
        "permission.Project.request-access",
        "permission.SubOrganization.create",
        "permission.SubOrganization.edit",
        "permission.SubOrganization.delete",
        "permission.SubOrganization.direct-access",
        "permission.SubOrganization.link-group",
        "permission.Member.read",
        "permission.Member.create",
        "permission.Member.edit",
        "permission.Member.delete",
        "permission.Member.grant-privileges",
        "permission.Sso.read",
        "permission.Sso.create",
        "permission.Sso.edit",
        "permission.Sso.delete",
        "permission.Sso.bypass-sso-enforcement",
        "permission.Groups.read",
        "permission.Groups.create",
        "permission.Groups.edit",
        "permission.Groups.delete",
        "permission.Groups.grant-privileges",
        "permission.Groups.add-identities",
        "permission.Groups.add-members",
        "permission.Groups.remove-members",
        "permission.Groups.remove-identities",
        "permission.Billing.read",
        "permission.Billing.manage-billing",
        "permission.Identity.read",
        "permission.Identity.create",
        "permission.Identity.edit",
        "permission.Identity.delete",
        "permission.Identity.grant-privileges",
        "permission.Identity.revoke-auth",
        "permission.Identity.edit-auth",
        "permission.Identity.create-token",
        "permission.Identity.get-token",
        "permission.Identity.delete-token",
        "permission.AuditLogs.read",
        "permission.AuditLogs.edit",
        "permission.AppConnections.read",
        "permission.AppConnections.create",
        "permission.AppConnections.edit",
        "permission.AppConnections.delete",
        "permission.AppConnections.connect",
        "permission.AppConnections.rotate-credentials",
        "permission.OrganizationAdminConsole.access-all-projects",
        "permission.SecretShare.manage-settings",
        "permission.Kmip.proxy",
        "permission.MachineIdentityAuthTemplate.list-templates",
        "permission.MachineIdentityAuthTemplate.edit-templates",
        "permission.MachineIdentityAuthTemplate.create-templates",
        "permission.MachineIdentityAuthTemplate.delete-templates",
        "permission.MachineIdentityAuthTemplate.unlink-templates",
        "permission.MachineIdentityAuthTemplate.attach-templates",
        "permission.Gateway.create-gateways",
        "permission.Gateway.list-gateways",
        "permission.Gateway.edit-gateways",
        "permission.Gateway.delete-gateways",
        "permission.Gateway.attach-gateways",
        "permission.Gateway.revoke-gateway-access",
        "permission.GatewayPool.create-gateway-pools",
        "permission.GatewayPool.list-gateway-pools",
        "permission.GatewayPool.edit-gateway-pools",
        "permission.GatewayPool.delete-gateway-pools",
        "permission.GatewayPool.attach-gateway-pools",
        "permission.Relay.create-relays",
        "permission.Relay.list-relays",
        "permission.Relay.edit-relays",
        "permission.Relay.delete-relays",
        "permission.Relay.revoke-relay-access",
        "permission.KmipServer.create-kmip-servers",
        "permission.KmipServer.list-kmip-servers",
        "permission.KmipServer.edit-kmip-servers",
        "permission.KmipServer.delete-kmip-servers",
        "permission.KmipServer.revoke-kmip-server-access",
        "permission.EmailDomains.read",
        "permission.EmailDomains.create",
        "permission.EmailDomains.verify-domain",
        "permission.EmailDomains.delete",
        "permission.CertificateManager.read",
        "permission.CertificateManager.manage-instance",
        "permission.CertificateManager.manage-settings",
        "permission.HoneyTokens.setup",
        "permission.SecretsManagementInsights.read",
        "permission.SecretsManagementInsights.generate-report",
        "permission.SecretsManagementInsights.delete-report",
        "permission.SecretsManagementInsights.search-all-secret-values",
        "permission.Role.read",
        "permission.Role.create",
        "permission.Role.edit",
        "permission.Role.delete",
        "permission.Settings.read",
        "permission.Settings.create",
        "permission.Settings.edit",
        "permission.Settings.delete",
        "permission.IncidentContact.read",
        "permission.IncidentContact.create",
        "permission.IncidentContact.edit",
        "permission.IncidentContact.delete",
        "permission.Scim.read",
        "permission.Scim.create",
        "permission.Scim.edit",
        "permission.Scim.delete",
        "permission.GithubOrgSync.read",
        "permission.GithubOrgSync.create",
        "permission.GithubOrgSync.edit",
        "permission.GithubOrgSync.delete",
        "permission.GithubOrgSyncManual.read",
        "permission.GithubOrgSyncManual.create",
        "permission.GithubOrgSyncManual.edit",
        "permission.GithubOrgSyncManual.delete",
        "permission.Ldap.read",
        "permission.Ldap.create",
        "permission.Ldap.edit",
        "permission.Ldap.delete",
        "permission.SecretScanning.read",
        "permission.SecretScanning.create",
        "permission.SecretScanning.edit",
        "permission.SecretScanning.delete",
        "permission.Kms.read",
        "permission.Kms.create",
        "permission.Kms.edit",
        "permission.Kms.delete",
        "permission.ProjectTemplates.read",
        "permission.ProjectTemplates.create",
        "permission.ProjectTemplates.edit",
        "permission.ProjectTemplates.delete",
        "permission.OauthClients.read",
        "permission.OauthClients.create",
        "permission.OauthClients.edit",
        "permission.OauthClients.delete",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants9 =
    [
        "permissions.action.scalar",
        "permissions.action.array",
        "permissions.empty",
        "description.omitted",
        "description.null",
        "description.empty",
        "description.value",
        "condition.literal",
        "condition.eq",
        "condition.ne",
        "condition.in",
        "condition.glob",
        "inverted.omitted",
        "inverted.false",
        "inverted.true",
        "permission.Secrets.read",
        "permission.Secrets.describeSecret",
        "permission.Secrets.readValue",
        "permission.Secrets.create",
        "permission.Secrets.edit",
        "permission.Secrets.delete",
        "permission.DynamicSecrets.read-root-credential",
        "permission.DynamicSecrets.create-root-credential",
        "permission.DynamicSecrets.edit-root-credential",
        "permission.DynamicSecrets.delete-root-credential",
        "permission.DynamicSecrets.lease",
        "permission.Identity.read",
        "permission.Identity.create",
        "permission.Identity.edit",
        "permission.Identity.delete",
        "permission.Identity.grant-privileges",
        "permission.Identity.assign-role",
        "permission.Identity.assign-additional-privileges",
        "permission.Identity.assume-privileges",
        "permission.Identity.revoke-auth",
        "permission.Identity.edit-auth",
        "permission.Identity.create-token",
        "permission.Identity.get-token",
        "permission.Identity.delete-token",
        "permission.PkiSubscribers.read",
        "permission.PkiSubscribers.create",
        "permission.PkiSubscribers.edit",
        "permission.PkiSubscribers.delete",
        "permission.PkiSubscribers.issue-cert",
        "permission.PkiSubscribers.list-certs",
        "permission.CertificateTemplates.read",
        "permission.CertificateTemplates.create",
        "permission.CertificateTemplates.edit",
        "permission.CertificateTemplates.delete",
        "permission.CertificateTemplates.issue-cert",
        "permission.CertificateTemplates.list-certs",
        "permission.SecretRotation.read",
        "permission.SecretRotation.read-generated-credentials",
        "permission.SecretRotation.create",
        "permission.SecretRotation.edit",
        "permission.SecretRotation.delete",
        "permission.SecretRotation.rotate-secrets",
        "permission.SecretSyncs.read",
        "permission.SecretSyncs.create",
        "permission.SecretSyncs.edit",
        "permission.SecretSyncs.delete",
        "permission.SecretSyncs.sync-secrets",
        "permission.SecretSyncs.import-secrets",
        "permission.SecretSyncs.remove-secrets",
        "permission.PkiSyncs.read",
        "permission.PkiSyncs.create",
        "permission.PkiSyncs.edit",
        "permission.PkiSyncs.delete",
        "permission.PkiSyncs.sync-certificates",
        "permission.PkiSyncs.import-certificates",
        "permission.PkiSyncs.remove-certificates",
        "permission.PkiSyncs.set-post-sync-command",
        "permission.PkiSyncs.set-health-check-command",
        "permission.PkiSyncs.set-target-host",
        "permission.SecretEventSubscriptions.subscribe-to-creation-events",
        "permission.SecretEventSubscriptions.subscribe-to-update-events",
        "permission.SecretEventSubscriptions.subscribe-to-deletion-events",
        "permission.SecretEventSubscriptions.subscribe-to-import-mutation-events",
        "permission.CertificateProfiles.read",
        "permission.CertificateProfiles.create",
        "permission.CertificateProfiles.edit",
        "permission.CertificateProfiles.delete",
        "permission.CertificateProfiles.issue-cert",
        "permission.CertificateProfiles.reveal-acme-eab-secret",
        "permission.CertificateProfiles.rotate-acme-eab-secret",
        "permission.CertificateProfiles.manage-application-attachments",
        "permission.CertificateApplication.read",
        "permission.CertificateApplication.list",
        "permission.CertificateApplication.create",
        "permission.CertificateAuthorities.read",
        "permission.CertificateAuthorities.create",
        "permission.CertificateAuthorities.edit",
        "permission.CertificateAuthorities.delete",
        "permission.CertificateAuthorities.issue-ca-certificate",
        "permission.CertificateAuthorities.sign-intermediate",
        "permission.Certificates.read",
        "permission.Certificates.create",
        "permission.Certificates.edit",
        "permission.Certificates.delete",
        "permission.Certificates.read-private-key",
        "permission.Certificates.import",
        "permission.SecretRollback.read",
        "permission.SecretRollback.create",
        "permission.ApprovalRequests.read",
        "permission.ApprovalRequests.create",
        "permission.Member.read",
        "permission.Member.create",
        "permission.Member.edit",
        "permission.Member.delete",
        "permission.Member.grant-privileges",
        "permission.Member.assign-role",
        "permission.Member.assign-additional-privileges",
        "permission.Member.assume-privileges",
        "permission.Groups.read",
        "permission.Groups.create",
        "permission.Groups.edit",
        "permission.Groups.delete",
        "permission.Groups.grant-privileges",
        "permission.Groups.assign-role",
        "permission.AuditLogs.read",
        "permission.AuditLogs.edit",
        "permission.Insights.read",
        "permission.Insights.generate-report",
        "permission.Insights.delete-report",
        "permission.PkiDiscovery.read",
        "permission.PkiDiscovery.create",
        "permission.PkiDiscovery.edit",
        "permission.PkiDiscovery.delete",
        "permission.PkiDiscovery.run-scan",
        "permission.PkiCertificateInstallations.read",
        "permission.PkiCertificateInstallations.edit",
        "permission.PkiCertificateInstallations.delete",
        "permission.CodeSigners.read",
        "permission.CodeSigners.create",
        "permission.CodeSigners.edit",
        "permission.CodeSigners.delete",
        "permission.CodeSigners.sign",
        "permission.Workspace.edit",
        "permission.Workspace.delete",
        "permission.Kms.edit",
        "permission.Cmek.read",
        "permission.Cmek.create",
        "permission.Cmek.edit",
        "permission.Cmek.delete",
        "permission.Cmek.encrypt",
        "permission.Cmek.decrypt",
        "permission.Cmek.sign",
        "permission.Cmek.verify",
        "permission.Cmek.generate-mac",
        "permission.Cmek.verify-mac",
        "permission.Cmek.rotate",
        "permission.Cmek.export-private-key",
        "permission.Kmip.create-clients",
        "permission.Kmip.update-clients",
        "permission.Kmip.delete-clients",
        "permission.Kmip.read-clients",
        "permission.Kmip.generate-client-certificates",
        "permission.Commits.read",
        "permission.Commits.perform-rollback",
        "permission.SecretScanningDataSources.read-data-sources",
        "permission.SecretScanningDataSources.create-data-sources",
        "permission.SecretScanningDataSources.edit-data-sources",
        "permission.SecretScanningDataSources.delete-data-sources",
        "permission.SecretScanningDataSources.trigger-data-source-scans",
        "permission.SecretScanningDataSources.read-data-source-scans",
        "permission.SecretScanningDataSources.read-data-source-resources",
        "permission.SecretScanningFindings.read-findings",
        "permission.SecretScanningFindings.update-findings",
        "permission.SecretScanningConfigs.read-configs",
        "permission.SecretScanningConfigs.update-configs",
        "permission.AppConnections.read-app-connections",
        "permission.AppConnections.create-app-connections",
        "permission.AppConnections.edit-app-connections",
        "permission.AppConnections.delete-app-connections",
        "permission.AppConnections.connect-app-connections",
        "permission.AppConnections.rotate-credentials",
        "permission.HsmConnectors.read-hsm-connectors",
        "permission.HsmConnectors.create-hsm-connectors",
        "permission.HsmConnectors.edit-hsm-connectors",
        "permission.HsmConnectors.delete-hsm-connectors",
        "permission.HsmConnectors.test-hsm-connectors",
        "permission.HsmConnectors.attach-hsm-connectors",
        "permission.HoneyTokens.read",
        "permission.HoneyTokens.read-credentials",
        "permission.HoneyTokens.create",
        "permission.HoneyTokens.edit",
        "permission.HoneyTokens.reset",
        "permission.HoneyTokens.revoke",
        "permission.ProxiedServices.read",
        "permission.ProxiedServices.create",
        "permission.ProxiedServices.edit",
        "permission.ProxiedServices.delete",
        "permission.ProxiedServices.proxy",
        "permission.ProxiedServices.report-usage",
        "permission.AgentVaultAccessBundles.read",
        "permission.AgentVaultAccessBundles.create",
        "permission.AgentVaultAccessBundles.edit",
        "permission.AgentVaultAccessBundles.delete",
        "permission.AgentVaultAccessBundles.manage-members",
        "permission.AgentVaultSessions.read",
        "permission.AgentVaultSessions.create",
        "permission.AgentVaultSessions.revoke",
        "permission.AgentVaultProxies.read",
        "permission.AgentVaultProxies.create",
        "permission.AgentVaultProxies.edit",
        "permission.AgentVaultProxies.delete",
        "permission.AgentVaultProxies.issue-token",
        "permission.AgentVaultProxies.revoke",
        "permission.ApprovalRequestGrants.read",
        "permission.ApprovalRequestGrants.revoke",
        "permission.SecretApprovalRequest.read",
        "permission.ProjectFolderGrant.read-grant",
        "permission.ProjectFolderGrant.create-grant",
        "permission.ProjectFolderGrant.revoke-grant",
        "permission.SecretFolders.read",
        "permission.SecretFolders.create",
        "permission.SecretFolders.edit",
        "permission.SecretFolders.delete",
        "permission.SecretImports.read",
        "permission.SecretImports.create",
        "permission.SecretImports.edit",
        "permission.SecretImports.delete",
        "permission.CertificatePolicies.read",
        "permission.CertificatePolicies.create",
        "permission.CertificatePolicies.edit",
        "permission.CertificatePolicies.delete",
        "permission.SecretApproval.read",
        "permission.SecretApproval.create",
        "permission.SecretApproval.edit",
        "permission.SecretApproval.delete",
        "permission.Role.read",
        "permission.Role.create",
        "permission.Role.edit",
        "permission.Role.delete",
        "permission.Integrations.read",
        "permission.Integrations.create",
        "permission.Integrations.edit",
        "permission.Integrations.delete",
        "permission.Webhooks.read",
        "permission.Webhooks.create",
        "permission.Webhooks.edit",
        "permission.Webhooks.delete",
        "permission.ServiceTokens.read",
        "permission.ServiceTokens.create",
        "permission.ServiceTokens.edit",
        "permission.ServiceTokens.delete",
        "permission.Settings.read",
        "permission.Settings.create",
        "permission.Settings.edit",
        "permission.Settings.delete",
        "permission.SecretValidationRules.read",
        "permission.SecretValidationRules.create",
        "permission.SecretValidationRules.edit",
        "permission.SecretValidationRules.delete",
        "permission.Environments.read",
        "permission.Environments.create",
        "permission.Environments.edit",
        "permission.Environments.delete",
        "permission.Tags.read",
        "permission.Tags.create",
        "permission.Tags.edit",
        "permission.Tags.delete",
        "permission.IpAllowlist.read",
        "permission.IpAllowlist.create",
        "permission.IpAllowlist.edit",
        "permission.IpAllowlist.delete",
        "permission.PkiAlerts.read",
        "permission.PkiAlerts.create",
        "permission.PkiAlerts.edit",
        "permission.PkiAlerts.delete",
        "permission.PkiCollections.read",
        "permission.PkiCollections.create",
        "permission.PkiCollections.edit",
        "permission.PkiCollections.delete",
        "permission.CertificateInventoryViews.read",
        "permission.CertificateInventoryViews.create",
        "permission.CertificateInventoryViews.edit",
        "permission.CertificateInventoryViews.delete",
        "condition.metadata.elemMatch",
        "condition.secretTags.in",
        "condition.secretTags.all",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants10 =
    [
        "input.organizationId-groupId-identityId",
    ];

    private static readonly string[] Variants11 =
    [
        "input.organizationId-groupId-username",
    ];

    private static readonly string[] Variants12 =
    [
        "selector.exact",
    ];

    private static readonly string[] Variants13 =
    [
        "identityName.omitted",
        "identityName.value",
    ];

    private static readonly string[] Variants14 =
    [
        "slug.omitted",
        "slug.value",
        "role.omitted",
        "role.value",
    ];

    private static readonly string[] Variants15 =
    [
        "input.organizationId-groupId",
    ];

    private static readonly string[] Variants16 =
    [
        "selector.slug",
        "response.conditions-unprojected",
    ];

    private static readonly string[] Variants17 =
    [
        "filter.Assigned",
        "filter.Unassigned",
        "filter.omitted",
        "search.omitted",
        "search.value",
    ];

    private static readonly string[] Variants18 =
    [
        "search.omitted",
        "search.value",
        "order.Ascending",
        "order.Descending",
        "members.All",
        "members.Users",
        "members.MachineIdentities",
        "memberTypes.omitted",
        "memberTypes.value",
    ];

    private static readonly string[] Variants19 =
    [
        "selection.Assigned",
        "selection.Unassigned",
        "selection.OrganizationAll",
        "search.omitted",
        "search.value",
        "order.Ascending",
        "order.Descending",
    ];

    private static readonly string[] Variants20 =
    [
        "collection.bounded",
    ];

    private static readonly string[] Variants21 =
    [
        "filter.Members",
        "filter.NonMembers",
        "filter.omitted",
        "search.omitted",
        "search.value",
        "username.omitted",
        "username.value",
    ];

    private static readonly string[] Variants22 =
    [
        "name.omitted",
        "name.value",
        "slug.omitted",
        "slug.value",
        "role.omitted",
        "role.value",
    ];

    internal static readonly Dictionary<string, ProjectFamilyBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,SecretKit.Infisical.Management.LegacyPrivilegeChange)", Variants0, true),
        ["i.management.IdentityPrivilegeChangeOperations.CreateProjectPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.CreateProjectPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,SecretKit.Infisical.Management.ProjectPrivilegeChange)", Variants1, true),
        ["i.management.IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,SecretKit.Infisical.Management.LegacyPrivilegeChange,SecretKit.Infisical.Management.PrivilegeLifetime)", Variants2, true),
        ["i.management.IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(SecretKit.Infisical.Management.LegacyPrivilegeSelection,System.String)", Variants3, false),
        ["i.management.IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,System.String,SecretKit.Infisical.Management.LegacyPrivilegeChange)", Variants4, true),
        ["i.management.IdentityPrivilegeChangeOperations.UpdateProjectPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,System.String,SecretKit.Infisical.Management.ProjectPrivilegeChange)", Variants1, true),
        ["i.management.IdentityPrivilegeOperations.DeleteProjectPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeOperations.DeleteProjectPrivilege(System.String,System.String,System.String,System.String)", Variants5, true),
        ["i.management.IdentityPrivilegeOperations.GetProjectPrivilege"] = new("SecretKit.Infisical.Management.IdentityPrivilegeOperations.GetProjectPrivilege(System.String,System.String,System.String,System.String)", Variants6, false),
        ["i.management.IdentityPrivilegeOperations.ListProjectPrivileges"] = new("SecretKit.Infisical.Management.IdentityPrivilegeOperations.ListProjectPrivileges(System.String,System.String,System.String)", Variants7, false),
        ["i.management.LegacyIdentityPrivilegeOperations.DeletePrivilege"] = new("SecretKit.Infisical.Management.LegacyIdentityPrivilegeOperations.DeletePrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,System.String)", Variants5, true),
        ["i.management.LegacyIdentityPrivilegeOperations.GetPrivilege"] = new("SecretKit.Infisical.Management.LegacyIdentityPrivilegeOperations.GetPrivilege(SecretKit.Infisical.Management.LegacyPrivilegeSelection,System.String)", Variants6, false),
        ["i.management.LegacyIdentityPrivilegeOperations.ListPrivileges"] = new("SecretKit.Infisical.Management.LegacyIdentityPrivilegeOperations.ListPrivileges(SecretKit.Infisical.Management.LegacyPrivilegeSelection)", Variants7, false),
        ["i.management.RoleChangeOperations.CreateOrganizationRole"] = new("SecretKit.Infisical.Management.RoleChangeOperations.CreateOrganizationRole(System.String,SecretKit.Infisical.Management.OrganizationRoleChange)", Variants8, true),
        ["i.management.RoleChangeOperations.CreateProjectRole"] = new("SecretKit.Infisical.Management.RoleChangeOperations.CreateProjectRole(System.String,System.String,SecretKit.Infisical.Management.ProjectRoleChange)", Variants9, true),
        ["i.management.RoleChangeOperations.UpdateOrganizationRole"] = new("SecretKit.Infisical.Management.RoleChangeOperations.UpdateOrganizationRole(System.String,System.String,SecretKit.Infisical.Management.OrganizationRoleChange)", Variants8, true),
        ["i.management.RoleChangeOperations.UpdateProjectRole"] = new("SecretKit.Infisical.Management.RoleChangeOperations.UpdateProjectRole(System.String,System.String,System.String,SecretKit.Infisical.Management.ProjectRoleChange)", Variants9, true),
        ["i.management.ScopedAccessOperations.AddGroupIdentity"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.AddGroupIdentity(System.String,System.String,System.String)", Variants10, true),
        ["i.management.ScopedAccessOperations.AddGroupUser"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.AddGroupUser(System.String,System.String,System.String)", Variants11, true),
        ["i.management.ScopedAccessOperations.AvailableGroups"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.AvailableGroups(System.String)", Variants12, false),
        ["i.management.ScopedAccessOperations.AvailableIdentities"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.AvailableIdentities(System.String,System.Int32,System.Int32,System.String)", Variants13, false),
        ["i.management.ScopedAccessOperations.CreateGroup"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.CreateGroup(System.String,System.String,System.String,System.String)", Variants14, true),
        ["i.management.ScopedAccessOperations.DeleteGroup"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.DeleteGroup(System.String,System.String)", Variants15, true),
        ["i.management.ScopedAccessOperations.DeleteOrganizationRole"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.DeleteOrganizationRole(System.String,System.String)", Variants5, true),
        ["i.management.ScopedAccessOperations.GetGroup"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.GetGroup(System.String,System.String)", Variants12, false),
        ["i.management.ScopedAccessOperations.GetOrganizationRole"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.GetOrganizationRole(System.String,System.String)", Variants6, false),
        ["i.management.ScopedAccessOperations.GetOrganizationRoleBySlug"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.GetOrganizationRoleBySlug(System.String,System.String)", Variants16, false),
        ["i.management.ScopedAccessOperations.ListGroupIdentities"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListGroupIdentities(System.String,System.String,System.Int32,System.Int32,System.Nullable<SecretKit.Infisical.Management.GroupIdentityFilter>,System.String)", Variants17, false),
        ["i.management.ScopedAccessOperations.ListGroupMembers"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListGroupMembers(System.String,System.String,System.Int32,System.Int32,System.String,SecretKit.Infisical.Management.ManagementListOrder,SecretKit.Infisical.Management.GroupMemberFilter,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.GroupMemberFilter>)", Variants18, false),
        ["i.management.ScopedAccessOperations.ListGroupProjects"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListGroupProjects(System.String,System.String,SecretKit.Infisical.Management.GroupProjectSelection,System.Int32,System.Int32,System.String,SecretKit.Infisical.Management.ManagementListOrder)", Variants19, false),
        ["i.management.ScopedAccessOperations.ListGroups"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListGroups(System.String)", Variants20, false),
        ["i.management.ScopedAccessOperations.ListGroupUsers"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListGroupUsers(System.String,System.String,System.Int32,System.Int32,System.Nullable<SecretKit.Infisical.Management.GroupUserFilter>,System.String,System.String)", Variants21, false),
        ["i.management.ScopedAccessOperations.ListOrganizationRoles"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.ListOrganizationRoles(System.String)", Variants7, false),
        ["i.management.ScopedAccessOperations.RemoveGroupIdentity"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.RemoveGroupIdentity(System.String,System.String,System.String)", Variants10, true),
        ["i.management.ScopedAccessOperations.RemoveGroupUser"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.RemoveGroupUser(System.String,System.String,System.String)", Variants11, true),
        ["i.management.ScopedAccessOperations.UpdateGroup"] = new("SecretKit.Infisical.Management.ScopedAccessOperations.UpdateGroup(System.String,System.String,System.String,System.String,System.String)", Variants22, true),
    };

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IPrivilegeExpiryObserver? observer = null,
        IMetadataPermissionSource? metadataPermissions = null, IDynamicPermissionSource? dynamicPermissions = null,
        IFolderPermissionSource? folderPermissions = null, ITagPermissionSource? tagPermissions = null,
        IImportPermissionSource? importPermissions = null, IRotationPermissionSource? rotationPermissions = null,
        RotationPermissionRuntime? rotationPermissionRuntime = null, IMemberPermissionSource? memberPermissions = null,
        IGroupPermissionSource? groupPermissions = null, IIdentityPermissionSource? identityPermissions = null,
        IProjectTemplatePermissionSource? projectTemplatePermissions = null, IRolePermissionSource? rolePermissions = null, IEnvironmentPermissionSource? environmentPermissions = null, IAuditPermissionSource? auditPermissions = null, IWorkspacePermissionSource? workspacePermissions = null, IGatewayPermissionSource? gatewayPermissions = null, IProxyPermissionSource? proxyPermissions = null, IValidationPermissionSource? validationPermissions = null, IIntegrationPermissionSource? integrationPermissions = null, ISettingsPermissionSource? settingsPermissions = null, IAuthTemplatePermissionSource? authTemplatePermissions = null)
    {
        foreach (NativeCaseDefinition definition in expected)
            if (Owns(definition.Key.Operation))
                registry.Add(new(definition, (probe, token) => RunAsync(environment, definition, probe, observer, metadataPermissions, dynamicPermissions, folderPermissions, tagPermissions, importPermissions, rotationPermissions, rotationPermissionRuntime, memberPermissions, groupPermissions, identityPermissions, projectTemplatePermissions, rolePermissions, environmentPermissions, auditPermissions, workspacePermissions, gatewayPermissions, proxyPermissions, validationPermissions, integrationPermissions, settingsPermissions, authTemplatePermissions, token)));
    }

    internal static bool Owns(string operation) => Bindings.ContainsKey(operation) ||
        operation.StartsWith("i.management.IdentityPrivilegeChangeOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.IdentityPrivilegeOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.LegacyIdentityPrivilegeOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.RoleChangeOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.ScopedAccessOperations.", StringComparison.Ordinal);

    internal static bool Valid(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        !string.IsNullOrWhiteSpace(d.Key.Scope) && Bindings.TryGetValue(d.Key.Operation, out var b) &&
        d.Member == b.Member && b.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) &&
        (d.Key.Case is "selected-contract" or "denied-authority" or "cancellation-boundary" or "independent-effect" ||
            b.Mutation && d.Key.Case == "lost-response-no-replay");

    internal static string Family(string operation) => operation.Split('.')[2] switch
    {
        "IdentityPrivilegeChangeOperations" => "IdentityPrivilegeChanges",
        "IdentityPrivilegeOperations" => "IdentityPrivileges",
        "LegacyIdentityPrivilegeOperations" => "LegacyIdentityPrivileges",
        "RoleChangeOperations" => "RoleChanges",
        "ScopedAccessOperations" => "ScopedAccess",
        _ => throw new NativeCaseFailureException("contract-mismatch")
    };

    internal static string? UnavailableReason(NativeCaseDefinition d)
    {
        if (!Valid(d)) return "contract-mismatch";
        string v = d.Key.Variant;
        if (v == "response.conditions-unprojected") return "primary-permission-response-shapes-unestablished";
        if (v.Contains("relative", StringComparison.Ordinal) ||
            d.Key.Operation.EndsWith("CreateTemporaryLegacyPrivilege", StringComparison.Ordinal))
            if (!TemporalPrivilegeEffects.Owns(d)) return "provider-expiry-event-observer-unavailable";
        if (v == "condition.metadata.elemMatch") return "dynamic-or-certificate-metadata-observer-unavailable";
        if (v.StartsWith("permission.", StringComparison.Ordinal) && v != "permission.scalar-crud" &&
            v is not ("permission.Secrets.read" or "permission.Secrets.readValue" or
                "permission.Secrets.describeSecret" or "permission.Groups.read"))
            return "subject-action-protected-observer-unavailable";
        if (d.Key.Operation.Contains("OrganizationRole", StringComparison.Ordinal) &&
            (v.StartsWith("condition.", StringComparison.Ordinal) || v.StartsWith("inverted.", StringComparison.Ordinal)))
            return "organization-app-connection-policy-observer-unavailable";
        if (d.Key.Operation.EndsWith("CreateGroup", StringComparison.Ordinal) && v == "role.omitted")
            return "default-group-role-policy-unestablished";
        // Group policy actions cannot substitute for project Secrets permission.
        if (v == "permission.Groups.read" && !d.Key.Operation.Contains("OrganizationRole", StringComparison.Ordinal))
            return "subject-action-protected-observer-unavailable";
        return null;
    }

    private static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, IPrivilegeExpiryObserver? observer, IMetadataPermissionSource? metadataPermissions,
        IDynamicPermissionSource? dynamicPermissions, IFolderPermissionSource? folderPermissions,
        ITagPermissionSource? tagPermissions, IImportPermissionSource? importPermissions,
        IRotationPermissionSource? rotationPermissions, RotationPermissionRuntime? rotationPermissionRuntime,
        IMemberPermissionSource? memberPermissions, IGroupPermissionSource? groupPermissions,
        IIdentityPermissionSource? identityPermissions, IProjectTemplatePermissionSource? projectTemplatePermissions,
        IRolePermissionSource? rolePermissions, IEnvironmentPermissionSource? environmentPermissions, IAuditPermissionSource? auditPermissions, IWorkspacePermissionSource? workspacePermissions, IGatewayPermissionSource? gatewayPermissions, IProxyPermissionSource? proxyPermissions, IValidationPermissionSource? validationPermissions, IIntegrationPermissionSource? integrationPermissions, ISettingsPermissionSource? settingsPermissions, IAuthTemplatePermissionSource? authTemplatePermissions, CancellationToken token)
    {
        probe.Contract(Valid(d), NativeFailure.ContractMismatch);
        bool metadataSelected = MetadataPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool dynamicSelected = DynamicPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool folderSelected = FolderPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool tagSelected = TagPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool importSelected = ImportPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool rotationSelected = RotationPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool memberSelected = MemberPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool groupSelected = GroupPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool identitySelected = IdentityPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool projectTemplateSelected = ProjectTemplatePermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool roleSelected = RolePermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool environmentSelected = EnvironmentPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool auditSelected = AuditPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool workspaceSelected = WorkspacePermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool gatewaySelected = GatewayPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool proxySelected = ProxyPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool validationSelected = ValidationPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool integrationSelected = IntegrationPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool settingsSelected = SettingsPermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        bool authTemplateSelected = AuthTemplatePermissionInput.Selected(environment, "C08-IM-" + Family(d.Key.Operation), d);
        if (UnavailableReason(d) is not null && !metadataSelected && !dynamicSelected && !folderSelected && !tagSelected && !importSelected && !rotationSelected && !memberSelected && !groupSelected && !identitySelected && !projectTemplateSelected && !roleSelected && !environmentSelected && !auditSelected && !workspaceSelected && !gatewaySelected && !proxySelected && !validationSelected && !integrationSelected && !settingsSelected && !authTemplateSelected) { probe.Effect(NativeObservation.Unavailable); return; }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        ProjectFamilyContext? context = null;
        try
        {
            string family = Family(d.Key.Operation);
            context = new(environment, family, d, probe);
            PermissionWitness.ValidatePrincipals(context);
            if (authTemplateSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await AuthTemplatePermissionEffects.ExecuteAsync(context, authTemplatePermissions, deadline.Token);
                return;
            }
            if (settingsSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await SettingsPermissionEffects.ExecuteAsync(context, settingsPermissions, deadline.Token);
                return;
            }
            if (integrationSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await IntegrationPermissionEffects.ExecuteAsync(context, integrationPermissions, deadline.Token);
                return;
            }
            if (validationSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await ValidationPermissionEffects.ExecuteAsync(context, validationPermissions, deadline.Token);
                return;
            }
            if (proxySelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await ProxyPermissionEffects.ExecuteAsync(context, proxyPermissions, deadline.Token);
                return;
            }
            if (gatewaySelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await GatewayPermissionEffects.ExecuteAsync(context, gatewayPermissions, deadline.Token);
                return;
            }
            if (workspaceSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await WorkspacePermissionEffects.ExecuteAsync(context, workspacePermissions, deadline.Token);
                return;
            }
            if (auditSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await AuditPermissionEffects.ExecuteAsync(context, auditPermissions, deadline.Token);
                return;
            }
            if (environmentSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await EnvironmentPermissionEffects.ExecuteAsync(context, environmentPermissions, deadline.Token);
                return;
            }
            if (roleSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await RolePermissionEffects.ExecuteAsync(context, rolePermissions, deadline.Token);
                return;
            }
            if (projectTemplateSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await ProjectTemplatePermissionEffects.ExecuteAsync(context, projectTemplatePermissions, deadline.Token);
                return;
            }
            if (identitySelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await IdentityPermissionEffects.ExecuteAsync(context, identityPermissions, deadline.Token);
                return;
            }
            if (groupSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await GroupPermissionEffects.ExecuteAsync(context, groupPermissions, deadline.Token);
                return;
            }
            if (memberSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await MemberPermissionEffects.ExecuteAsync(context, memberPermissions, deadline.Token);
                return;
            }
            if (rotationSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await RotationPermissionEffects.ExecuteAsync(context, rotationPermissions, deadline.Token, rotationPermissionRuntime);
                return;
            }
            if (tagSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await TagPermissionEffects.ExecuteAsync(context, tagPermissions, deadline.Token);
                return;
            }
            if (importSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await ImportPermissionEffects.ExecuteAsync(context, importPermissions, deadline.Token);
                return;
            }
            if (folderSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await FolderPermissionEffects.ExecuteAsync(context, folderPermissions, deadline.Token);
                return;
            }
            if (dynamicSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await DynamicPermissionEffects.ExecuteAsync(context, dynamicPermissions, deadline.Token);
                return;
            }
            if (metadataSelected)
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await MetadataPermissionEffects.ExecuteAsync(context, metadataPermissions, deadline.Token);
                return;
            }
            if (TemporalPrivilegeEffects.Owns(d))
            {
                deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
                await TemporalPrivilegeEffects.ExecuteAsync(context, observer, deadline.Token);
                return;
            }
            switch (family)
            {
                case "IdentityPrivilegeChanges": await IdentityPrivilegeChangesEffects.ExecuteAsync(context, deadline.Token); break;
                case "IdentityPrivileges": await IdentityPrivilegesEffects.ExecuteAsync(context, deadline.Token); break;
                case "LegacyIdentityPrivileges": await LegacyIdentityPrivilegesEffects.ExecuteAsync(context, deadline.Token); break;
                case "RoleChanges": await RoleChangesEffects.ExecuteAsync(context, deadline.Token); break;
                case "ScopedAccess": await ScopedAccessEffects.ExecuteAsync(context, deadline.Token); break;
            }
        }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        {
            probe.Contract(false, token.IsCancellationRequested ? NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
        }
        catch (Exception error) when (error is ArgumentException or System.Text.Json.JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
        finally { if (context is not null) await context.CleanupAsync(); }
    }
}

// Reuses only host-owned setup/receipt/boundary infrastructure. No response is a permission oracle.
internal sealed class PermissionWitness(ProjectFamilyContext context, ProjectCanary inside, ProjectCanary outside)
{
    internal static void ValidatePrincipals(ProjectFamilyContext c)
    {
        string[] identities = [c.Required("setupIdentityId"), c.Required("runtimeIdentityId"),
            c.Required("deniedIdentityId"), c.Required("administrativeIdentityId"), c.Required("observerIdentityId")];
        c.Probe.Contract(identities.Distinct(StringComparer.Ordinal).Count() == 5, NativeFailure.MissingInput);
    }

    internal static async ValueTask<PermissionWitness> CreateAsync(ProjectFamilyContext c, CancellationToken token)
    {
        bool tags = c.Variant.StartsWith("condition.secretTags.", StringComparison.Ordinal);
        string[]? allowedTags = null, deniedTags = null;
        if (tags)
        {
            ProjectTag first = await c.NeedAsync(() => ProjectOperations.CreateTag(c.OrganizationId, c.ProjectId,
                "admitted", "#123456"), NativeIdentityRole.Setup, token);
            if (c.Variant == "condition.secretTags.all")
            {
                ProjectTag second = await c.NeedAsync(() => ProjectOperations.CreateTag(c.OrganizationId, c.ProjectId,
                    "second", "#654321"), NativeIdentityRole.Setup, token);
                allowedTags = [first.Id, second.Id]; deniedTags = [first.Id];
            }
            else { allowedTags = [first.Id]; deniedTags = []; }
        }
        return new(c, await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token, tagIds: allowedTags),
            await ProjectCanary.CreateAsync(c, c.ProjectId, "outside", token, tagIds: deniedTags));
    }

    internal static ProjectRolePermission[] Policy(string variant)
    {
        if (variant == "permissions.empty") return [];
        RoleStringClause clause = variant switch
        {
            "condition.eq" => RoleStringClause.Compare(equal: "witness"),
            "condition.ne" => RoleStringClause.Compare(notEqual: "outside"),
            "condition.in" => RoleStringClause.Compare(included: ["witness"]),
            "condition.glob" => RoleStringClause.Compare(glob: "wit*"),
            _ => RoleStringClause.Literal("witness")
        };
        bool? inverted = variant switch { "inverted.true" => true, "inverted.false" => false, _ => null };
        if (inverted == true) clause = RoleStringClause.Literal("outside");
        bool tags = variant.StartsWith("condition.secretTags.", StringComparison.Ordinal);
        RoleCondition[]? conditions = tags ? null : [new(RoleConditionField.Environment, clause)];
        RoleSecretTags? tagClause = variant switch
        {
            "condition.secretTags.in" => new(included: ["admitted"]),
            "condition.secretTags.all" => new(all: ["admitted", "second"]),
            _ => null
        };
        ProjectRoleAction action = variant switch
        {
            "permission.Secrets.describeSecret" => ProjectRoleAction.DescribeSecret,
            "permission.Secrets.readValue" => ProjectRoleAction.ReadValue,
            _ => ProjectRoleAction.Read
        };
        if (inverted == true)
            return [new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read),
                new(ProjectRoleSubject.Secrets, ProjectRoleAction.Read, true, conditions)];
        return [variant is "permissions.action.array" or "permissions.array" ?
            new(ProjectRoleSubject.Secrets, new[] { action }, inverted, conditions, tagClause) :
            new(ProjectRoleSubject.Secrets, action, inverted, conditions, tagClause)];
    }

    internal async ValueTask<bool> ObserveAsync(bool access, CancellationToken token)
    {
        bool describe = context.Variant == "permission.Secrets.describeSecret";
        bool result = describe ? await inside.InspectAsync(NativeIdentityRole.Runtime, access, token) &&
                await inside.ReadAsync(NativeIdentityRole.Runtime, false, token) :
            await inside.ReadAsync(NativeIdentityRole.Runtime, access, token);
        result &= await outside.ReadAsync(NativeIdentityRole.Runtime, false, token) &&
            await inside.ReadAsync(NativeIdentityRole.Denied, false, token) &&
            await inside.ReadAsync(NativeIdentityRole.Observer, true, token) &&
            await outside.ReadAsync(NativeIdentityRole.Observer, true, token);
        if (result && access)
        {
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope,
                "intended-principal-permission-observer", NativeObservation.Matched);
            context.Environment.ConfirmPrerequisite(context.Definition.Key.Scope,
                "permission-policy-entitlement", NativeObservation.Matched);
        }
        return result;
    }
}
