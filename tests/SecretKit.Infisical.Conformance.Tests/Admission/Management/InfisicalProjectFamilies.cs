using System.Diagnostics.Tracing;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record ProjectFamilyBinding(string Member, string[] Variants, bool Mutation);

internal static class InfisicalProjectFamilies
{
    // These are local scenario obligations, not measurements or certification.
    internal static readonly Dictionary<string, ProjectFamilyBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.MembershipMutationOperations.DeleteOrganizationMemberships"] = new("SecretKit.Infisical.Management.MembershipMutationOperations.DeleteOrganizationMemberships(System.String,System.Collections.Generic.IReadOnlyList<System.String>)",
            ["input.organizationId-membershipIds"], true),
        ["i.management.MembershipMutationOperations.InviteProjectMembers"] = new("SecretKit.Infisical.Management.MembershipMutationOperations.InviteProjectMembers(System.String,System.String,SecretKit.Infisical.Management.MembershipPrincipals,System.Collections.Generic.IReadOnlyList<System.String>)",
            ["roleSlugs.omitted", "roleSlugs.value", "principals.emails", "principals.usernames", "principals.emails-and-usernames", "result.partial"], true),
        ["i.management.MembershipMutationOperations.RemoveProjectMembers"] = new("SecretKit.Infisical.Management.MembershipMutationOperations.RemoveProjectMembers(System.String,System.String,SecretKit.Infisical.Management.MembershipPrincipals)",
            ["principals.emails", "principals.usernames", "principals.emails-and-usernames", "result.partial"], true),
        ["i.management.MembershipOperations.AddOrganizationGroup"] = new("SecretKit.Infisical.Management.MembershipOperations.AddOrganizationGroup(System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time"], true),
        ["i.management.MembershipOperations.AddProjectGroup.Selection"] = new("SecretKit.Infisical.Management.MembershipOperations.AddProjectGroup(System.String,System.String,System.String,SecretKit.Infisical.Management.MembershipRoleSelection)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time", "role.omitted", "role.scalar", "roles.omitted", "roles.empty", "role-and-roles.supplied"], true),
        ["i.management.MembershipOperations.AddProjectGroup.Roles"] = new("SecretKit.Infisical.Management.MembershipOperations.AddProjectGroup(System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.omitted", "roles.value", "roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time", "roles.empty"], true),
        ["i.management.MembershipOperations.AddProjectIdentity.Selection"] = new("SecretKit.Infisical.Management.MembershipOperations.AddProjectIdentity(System.String,System.String,System.String,SecretKit.Infisical.Management.MembershipRoleSelection)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time", "role.omitted", "role.scalar", "roles.omitted", "roles.empty", "role-and-roles.supplied"], true),
        ["i.management.MembershipOperations.AddProjectIdentity.Roles"] = new("SecretKit.Infisical.Management.MembershipOperations.AddProjectIdentity(System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.omitted", "roles.value", "roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time", "roles.empty"], true),
        ["i.management.MembershipOperations.GetOrganizationGroup"] = new("SecretKit.Infisical.Management.MembershipOperations.GetOrganizationGroup(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.MembershipOperations.GetProjectGroup"] = new("SecretKit.Infisical.Management.MembershipOperations.GetProjectGroup(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.MembershipOperations.GetProjectIdentityMembership"] = new("SecretKit.Infisical.Management.MembershipOperations.GetProjectIdentityMembership(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.MembershipOperations.ListOrganizationGroups"] = new("SecretKit.Infisical.Management.MembershipOperations.ListOrganizationGroups(System.String,System.Int32,System.Int32,System.Nullable<SecretKit.Infisical.Management.OrganizationGroupOrder>,System.Nullable<SecretKit.Infisical.Management.ManagementListOrder>,System.String,SecretKit.Infisical.Management.OrganizationGroupRoleFilter)",
            ["orderBy.Name", "orderBy.Slug", "orderBy.Role", "orderBy.omitted", "order.Ascending", "order.Descending", "order.omitted", "search.omitted", "search.value"], false),
        ["i.management.MembershipOperations.ListProjectGroups"] = new("SecretKit.Infisical.Management.MembershipOperations.ListProjectGroups(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.MembershipOperations.RemoveOrganizationGroup"] = new("SecretKit.Infisical.Management.MembershipOperations.RemoveOrganizationGroup(System.String,System.String)",
            ["input.organizationId-groupId"], true),
        ["i.management.MembershipOperations.RemoveProjectGroup"] = new("SecretKit.Infisical.Management.MembershipOperations.RemoveProjectGroup(System.String,System.String,System.String)",
            ["input.organizationId-projectId-groupId"], true),
        ["i.management.MembershipOperations.RemoveProjectIdentity"] = new("SecretKit.Infisical.Management.MembershipOperations.RemoveProjectIdentity(System.String,System.String,System.String)",
            ["input.organizationId-projectId-identityId"], true),
        ["i.management.MembershipOperations.UpdateOrganizationGroupRoles"] = new("SecretKit.Infisical.Management.MembershipOperations.UpdateOrganizationGroupRoles(System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time"], true),
        ["i.management.MembershipOperations.UpdateProjectGroupRoles"] = new("SecretKit.Infisical.Management.MembershipOperations.UpdateProjectGroupRoles(System.String,System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time"], true),
        ["i.management.MembershipOperations.UpdateProjectIdentityRoles"] = new("SecretKit.Infisical.Management.MembershipOperations.UpdateProjectIdentityRoles(System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time"], true),
        ["i.management.ProjectMembershipOperations.InspectProjectMembershipByUsername"] = new("SecretKit.Infisical.Management.ProjectMembershipOperations.InspectProjectMembershipByUsername(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.ProjectMembershipOperations.ListAvailableProjectIdentities"] = new("SecretKit.Infisical.Management.ProjectMembershipOperations.ListAvailableProjectIdentities(System.String,System.String,System.Int32,System.Int32,System.String)",
            ["identityName.omitted", "identityName.value"], false),
        ["i.management.ProjectMembershipOperations.ListProjectIdentityMemberships"] = new("SecretKit.Infisical.Management.ProjectMembershipOperations.ListProjectIdentityMemberships(System.String,System.String,System.Int32,System.Int32,System.String,System.String)",
            ["identityName.omitted", "identityName.value"], false),
        ["i.management.ProjectMembershipOperations.ListProjectMemberships"] = new("SecretKit.Infisical.Management.ProjectMembershipOperations.ListProjectMemberships(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.ProjectMembershipOperations.UpdateProjectMembershipRoles"] = new("SecretKit.Infisical.Management.ProjectMembershipOperations.UpdateProjectMembershipRoles(System.String,System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.MembershipRole>)",
            ["roles.permanent", "roles.permanent-discriminator-omitted", "roles.relative-time"], true),
        ["i.management.ProjectOperations.CreateEnvironment"] = new("SecretKit.Infisical.Management.ProjectOperations.CreateEnvironment(System.String,System.String,System.String,System.String,System.Nullable<System.Double>)",
            ["position.omitted", "position.value"], true),
        ["i.management.ProjectOperations.CreateProject"] = new("SecretKit.Infisical.Management.ProjectOperations.CreateProject(System.String,System.String,System.String,System.String,System.Boolean,System.Boolean,System.String,System.String)",
            ["description.omitted", "description.value", "deleteProtection.false", "deleteProtection.true", "createDefaultEnvironments.false", "createDefaultEnvironments.true", "template.omitted", "template.value", "kmsKeyId.omitted", "kmsKeyId.value"], true),
        ["i.management.ProjectOperations.CreateTag"] = new("SecretKit.Infisical.Management.ProjectOperations.CreateTag(System.String,System.String,System.String,System.String)",
            ["input.organizationId-projectId-slug-color"], true),
        ["i.management.ProjectOperations.DeleteEnvironment"] = new("SecretKit.Infisical.Management.ProjectOperations.DeleteEnvironment(System.String,System.String,System.String,System.Boolean)",
            ["permanently.false", "permanently.true"], true),
        ["i.management.ProjectOperations.DeleteProject"] = new("SecretKit.Infisical.Management.ProjectOperations.DeleteProject(System.String,System.String)",
            ["input.organizationId-projectId"], true),
        ["i.management.ProjectOperations.DeleteProjectRole"] = new("SecretKit.Infisical.Management.ProjectOperations.DeleteProjectRole(System.String,System.String,System.String)",
            ["response.conditions-unprojected"], true),
        ["i.management.ProjectOperations.DeleteTag"] = new("SecretKit.Infisical.Management.ProjectOperations.DeleteTag(System.String,System.String,System.String)",
            ["input.organizationId-projectId-tagId"], true),
        ["i.management.ProjectOperations.GetEnvironment"] = new("SecretKit.Infisical.Management.ProjectOperations.GetEnvironment(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.ProjectOperations.GetEnvironmentBySlug"] = new("SecretKit.Infisical.Management.ProjectOperations.GetEnvironmentBySlug(System.String,System.String,System.String)",
            ["selector.slug"], false),
        ["i.management.ProjectOperations.GetProject"] = new("SecretKit.Infisical.Management.ProjectOperations.GetProject(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.ProjectOperations.GetProjectBySlug"] = new("SecretKit.Infisical.Management.ProjectOperations.GetProjectBySlug(System.String,System.String)",
            ["selector.slug"], false),
        ["i.management.ProjectOperations.GetProjectRole"] = new("SecretKit.Infisical.Management.ProjectOperations.GetProjectRole(System.String,System.String,System.String)",
            ["selector.exact", "response.conditions-unprojected"], false),
        ["i.management.ProjectOperations.GetProjectRoleBySlug"] = new("SecretKit.Infisical.Management.ProjectOperations.GetProjectRoleBySlug(System.String,System.String,System.String)",
            ["selector.slug", "response.conditions-unprojected"], false),
        ["i.management.ProjectOperations.GetTag"] = new("SecretKit.Infisical.Management.ProjectOperations.GetTag(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.ProjectOperations.GetTagBySlug"] = new("SecretKit.Infisical.Management.ProjectOperations.GetTagBySlug(System.String,System.String,System.String)",
            ["selector.slug"], false),
        ["i.management.ProjectOperations.ListProjectRoles"] = new("SecretKit.Infisical.Management.ProjectOperations.ListProjectRoles(System.String,System.String)",
            ["collection.bounded", "response.conditions-unprojected"], false),
        ["i.management.ProjectOperations.ListProjects"] = new("SecretKit.Infisical.Management.ProjectOperations.ListProjects(System.String,System.Nullable<SecretKit.Infisical.Management.ProjectType>,System.Nullable<System.Boolean>)",
            ["type.SecretManager", "type.CertificateManager", "type.Kms", "type.SecretScanning", "type.Pam", "type.AgentVault", "type.omitted", "includeRoles.omitted", "includeRoles.false", "includeRoles.true"], false),
        ["i.management.ProjectOperations.ListTags"] = new("SecretKit.Infisical.Management.ProjectOperations.ListTags(System.String,System.String)",
            ["collection.bounded"], false),
        ["i.management.ProjectOperations.RestoreEnvironment"] = new("SecretKit.Infisical.Management.ProjectOperations.RestoreEnvironment(System.String,System.String,System.String)",
            ["input.organizationId-projectId-environmentId"], true),
        ["i.management.ProjectOperations.UpdateEnvironment"] = new("SecretKit.Infisical.Management.ProjectOperations.UpdateEnvironment(System.String,System.String,System.String,System.String,System.String,System.Nullable<System.Double>)",
            ["name.omitted", "name.value", "slug.omitted", "slug.value", "position.omitted", "position.value"], true),
        ["i.management.ProjectOperations.UpdateProject"] = new("SecretKit.Infisical.Management.ProjectOperations.UpdateProject(System.String,System.String,System.String,System.String,System.String,System.Nullable<System.Boolean>,System.Nullable<System.Int32>,System.Nullable<System.Boolean>,System.Nullable<System.Boolean>,System.Nullable<System.Boolean>,System.Nullable<System.Int32>,System.Nullable<System.Boolean>,System.Collections.Generic.IReadOnlyList<System.String>)",
            ["name.omitted", "name.value", "slug.omitted", "slug.value", "description.omitted", "description.value", "deleteProtection.omitted", "deleteProtection.false", "deleteProtection.true", "auditRetentionDays.omitted", "auditRetentionDays.value", "secretSharing.omitted", "secretSharing.false", "secretSharing.true", "autoCapitalization.omitted", "autoCapitalization.false", "autoCapitalization.true", "encryptedMetadata.omitted", "encryptedMetadata.false", "encryptedMetadata.true", "pointInTimeVersionLimit.omitted", "pointInTimeVersionLimit.value", "showLegacySnapshots.omitted", "showLegacySnapshots.false", "showLegacySnapshots.true", "secretDetectionIgnoreValues.omitted", "secretDetectionIgnoreValues.value"], true),
        ["i.management.ProjectOperations.UpdateTag"] = new("SecretKit.Infisical.Management.ProjectOperations.UpdateTag(System.String,System.String,System.String,System.String,System.String)",
            ["input.organizationId-projectId-tagId-slug-color"], true),
        ["i.management.ProjectTemplateOperations.CreateProjectTemplate"] = new("SecretKit.Infisical.Management.ProjectTemplateOperations.CreateProjectTemplate(System.String,System.String,SecretKit.Infisical.Management.ProjectTemplateType,System.String,SecretKit.Infisical.Management.ProjectTemplateConfiguration)",
            ["type.SecretManager", "type.CertificateManager", "type.KeyManagement", "type.SecretScanning", "type.PrivilegedAccess", "type.AgentVault", "description.omitted", "description.value", "configuration.omitted", "configuration.value", "ProjectTemplateConfiguration.roles.omitted", "ProjectTemplateConfiguration.roles.value", "ProjectTemplateConfiguration.environments.omitted", "ProjectTemplateConfiguration.environments.value", "ProjectTemplateConfiguration.users.omitted", "ProjectTemplateConfiguration.users.value", "ProjectTemplateConfiguration.groups.omitted", "ProjectTemplateConfiguration.groups.value", "ProjectTemplateConfiguration.identities.omitted", "ProjectTemplateConfiguration.identities.value", "ProjectTemplateConfiguration.projectManagedIdentities.omitted", "ProjectTemplateConfiguration.projectManagedIdentities.value", "roles.empty", "roles.values", "environments.null", "environments.empty", "environments.values", "permissions.action.scalar", "permissions.action.array", "permissions.conditions.empty", "permissions.literal", "permissions.eq", "permissions.ne", "permissions.in.empty", "permissions.in.values", "permissions.glob", "permissions.metadata.elemMatch", "permissions.secretTags.in", "permissions.secretTags.all", "permission.Secrets.read", "permission.Secrets.describeSecret", "permission.Secrets.readValue", "permission.Secrets.create", "permission.Secrets.edit", "permission.Secrets.delete", "permission.DynamicSecrets.read-root-credential", "permission.DynamicSecrets.create-root-credential", "permission.DynamicSecrets.edit-root-credential", "permission.DynamicSecrets.delete-root-credential", "permission.DynamicSecrets.lease", "permission.Identity.read", "permission.Identity.create", "permission.Identity.edit", "permission.Identity.delete", "permission.Identity.grant-privileges", "permission.Identity.assign-role", "permission.Identity.assign-additional-privileges", "permission.Identity.assume-privileges", "permission.Identity.revoke-auth", "permission.Identity.edit-auth", "permission.Identity.create-token", "permission.Identity.get-token", "permission.Identity.delete-token", "permission.PkiSubscribers.read", "permission.PkiSubscribers.create", "permission.PkiSubscribers.edit", "permission.PkiSubscribers.delete", "permission.PkiSubscribers.issue-cert", "permission.PkiSubscribers.list-certs", "permission.CertificateTemplates.read", "permission.CertificateTemplates.create", "permission.CertificateTemplates.edit", "permission.CertificateTemplates.delete", "permission.CertificateTemplates.issue-cert", "permission.CertificateTemplates.list-certs", "permission.SecretRotation.read", "permission.SecretRotation.read-generated-credentials", "permission.SecretRotation.create", "permission.SecretRotation.edit", "permission.SecretRotation.delete", "permission.SecretRotation.rotate-secrets", "permission.SecretSyncs.read", "permission.SecretSyncs.create", "permission.SecretSyncs.edit", "permission.SecretSyncs.delete", "permission.SecretSyncs.sync-secrets", "permission.SecretSyncs.import-secrets", "permission.SecretSyncs.remove-secrets", "permission.PkiSyncs.read", "permission.PkiSyncs.create", "permission.PkiSyncs.edit", "permission.PkiSyncs.delete", "permission.PkiSyncs.sync-certificates", "permission.PkiSyncs.import-certificates", "permission.PkiSyncs.remove-certificates", "permission.PkiSyncs.set-post-sync-command", "permission.PkiSyncs.set-health-check-command", "permission.PkiSyncs.set-target-host", "permission.SecretEventSubscriptions.subscribe-to-creation-events", "permission.SecretEventSubscriptions.subscribe-to-update-events", "permission.SecretEventSubscriptions.subscribe-to-deletion-events", "permission.SecretEventSubscriptions.subscribe-to-import-mutation-events", "permission.CertificateProfiles.read", "permission.CertificateProfiles.create", "permission.CertificateProfiles.edit", "permission.CertificateProfiles.delete", "permission.CertificateProfiles.issue-cert", "permission.CertificateProfiles.reveal-acme-eab-secret", "permission.CertificateProfiles.rotate-acme-eab-secret", "permission.CertificateProfiles.manage-application-attachments", "permission.CertificateApplication.read", "permission.CertificateApplication.list", "permission.CertificateApplication.create", "permission.CertificateAuthorities.read", "permission.CertificateAuthorities.create", "permission.CertificateAuthorities.edit", "permission.CertificateAuthorities.delete", "permission.CertificateAuthorities.issue-ca-certificate", "permission.CertificateAuthorities.sign-intermediate", "permission.Certificates.read", "permission.Certificates.create", "permission.Certificates.edit", "permission.Certificates.delete", "permission.Certificates.read-private-key", "permission.Certificates.import", "permission.SecretRollback.read", "permission.SecretRollback.create", "permission.ApprovalRequests.read", "permission.ApprovalRequests.create", "permission.Member.read", "permission.Member.create", "permission.Member.edit", "permission.Member.delete", "permission.Member.grant-privileges", "permission.Member.assign-role", "permission.Member.assign-additional-privileges", "permission.Member.assume-privileges", "permission.Groups.read", "permission.Groups.create", "permission.Groups.edit", "permission.Groups.delete", "permission.Groups.grant-privileges", "permission.Groups.assign-role", "permission.AuditLogs.read", "permission.AuditLogs.edit", "permission.Insights.read", "permission.Insights.generate-report", "permission.Insights.delete-report", "permission.PkiDiscovery.read", "permission.PkiDiscovery.create", "permission.PkiDiscovery.edit", "permission.PkiDiscovery.delete", "permission.PkiDiscovery.run-scan", "permission.PkiCertificateInstallations.read", "permission.PkiCertificateInstallations.edit", "permission.PkiCertificateInstallations.delete", "permission.CodeSigners.read", "permission.CodeSigners.create", "permission.CodeSigners.edit", "permission.CodeSigners.delete", "permission.CodeSigners.sign", "permission.Workspace.edit", "permission.Workspace.delete", "permission.Kms.edit", "permission.Cmek.read", "permission.Cmek.create", "permission.Cmek.edit", "permission.Cmek.delete", "permission.Cmek.encrypt", "permission.Cmek.decrypt", "permission.Cmek.sign", "permission.Cmek.verify", "permission.Cmek.generate-mac", "permission.Cmek.verify-mac", "permission.Cmek.rotate", "permission.Cmek.export-private-key", "permission.Kmip.create-clients", "permission.Kmip.update-clients", "permission.Kmip.delete-clients", "permission.Kmip.read-clients", "permission.Kmip.generate-client-certificates", "permission.Commits.read", "permission.Commits.perform-rollback", "permission.SecretScanningDataSources.read-data-sources", "permission.SecretScanningDataSources.create-data-sources", "permission.SecretScanningDataSources.edit-data-sources", "permission.SecretScanningDataSources.delete-data-sources", "permission.SecretScanningDataSources.trigger-data-source-scans", "permission.SecretScanningDataSources.read-data-source-scans", "permission.SecretScanningDataSources.read-data-source-resources", "permission.SecretScanningFindings.read-findings", "permission.SecretScanningFindings.update-findings", "permission.SecretScanningConfigs.read-configs", "permission.SecretScanningConfigs.update-configs", "permission.AppConnections.read-app-connections", "permission.AppConnections.create-app-connections", "permission.AppConnections.edit-app-connections", "permission.AppConnections.delete-app-connections", "permission.AppConnections.connect-app-connections", "permission.AppConnections.rotate-credentials", "permission.HsmConnectors.read-hsm-connectors", "permission.HsmConnectors.create-hsm-connectors", "permission.HsmConnectors.edit-hsm-connectors", "permission.HsmConnectors.delete-hsm-connectors", "permission.HsmConnectors.test-hsm-connectors", "permission.HsmConnectors.attach-hsm-connectors", "permission.HoneyTokens.read", "permission.HoneyTokens.read-credentials", "permission.HoneyTokens.create", "permission.HoneyTokens.edit", "permission.HoneyTokens.reset", "permission.HoneyTokens.revoke", "permission.ProxiedServices.read", "permission.ProxiedServices.create", "permission.ProxiedServices.edit", "permission.ProxiedServices.delete", "permission.ProxiedServices.proxy", "permission.ProxiedServices.report-usage", "permission.AgentVaultAccessBundles.read", "permission.AgentVaultAccessBundles.create", "permission.AgentVaultAccessBundles.edit", "permission.AgentVaultAccessBundles.delete", "permission.AgentVaultAccessBundles.manage-members", "permission.AgentVaultSessions.read", "permission.AgentVaultSessions.create", "permission.AgentVaultSessions.revoke", "permission.AgentVaultProxies.read", "permission.AgentVaultProxies.create", "permission.AgentVaultProxies.edit", "permission.AgentVaultProxies.delete", "permission.AgentVaultProxies.issue-token", "permission.AgentVaultProxies.revoke", "permission.ApprovalRequestGrants.read", "permission.ApprovalRequestGrants.revoke", "permission.SecretApprovalRequest.read", "permission.ProjectFolderGrant.read-grant", "permission.ProjectFolderGrant.create-grant", "permission.ProjectFolderGrant.revoke-grant", "permission.SecretFolders.read", "permission.SecretFolders.create", "permission.SecretFolders.edit", "permission.SecretFolders.delete", "permission.SecretImports.read", "permission.SecretImports.create", "permission.SecretImports.edit", "permission.SecretImports.delete", "permission.CertificatePolicies.read", "permission.CertificatePolicies.create", "permission.CertificatePolicies.edit", "permission.CertificatePolicies.delete", "permission.SecretApproval.read", "permission.SecretApproval.create", "permission.SecretApproval.edit", "permission.SecretApproval.delete", "permission.Role.read", "permission.Role.create", "permission.Role.edit", "permission.Role.delete", "permission.Integrations.read", "permission.Integrations.create", "permission.Integrations.edit", "permission.Integrations.delete", "permission.Webhooks.read", "permission.Webhooks.create", "permission.Webhooks.edit", "permission.Webhooks.delete", "permission.ServiceTokens.read", "permission.ServiceTokens.create", "permission.ServiceTokens.edit", "permission.ServiceTokens.delete", "permission.Settings.read", "permission.Settings.create", "permission.Settings.edit", "permission.Settings.delete", "permission.SecretValidationRules.read", "permission.SecretValidationRules.create", "permission.SecretValidationRules.edit", "permission.SecretValidationRules.delete", "permission.Environments.read", "permission.Environments.create", "permission.Environments.edit", "permission.Environments.delete", "permission.Tags.read", "permission.Tags.create", "permission.Tags.edit", "permission.Tags.delete", "permission.IpAllowlist.read", "permission.IpAllowlist.create", "permission.IpAllowlist.edit", "permission.IpAllowlist.delete", "permission.PkiAlerts.read", "permission.PkiAlerts.create", "permission.PkiAlerts.edit", "permission.PkiAlerts.delete", "permission.PkiCollections.read", "permission.PkiCollections.create", "permission.PkiCollections.edit", "permission.PkiCollections.delete", "permission.CertificateInventoryViews.read", "permission.CertificateInventoryViews.create", "permission.CertificateInventoryViews.edit", "permission.CertificateInventoryViews.delete", "condition.metadata.elemMatch", "condition.secretTags.in", "condition.secretTags.all", "response.conditions-unprojected"], true),
        ["i.management.ProjectTemplateOperations.DeleteProjectTemplate"] = new("SecretKit.Infisical.Management.ProjectTemplateOperations.DeleteProjectTemplate(System.String,System.String)",
            ["response.conditions-unprojected"], true),
        ["i.management.ProjectTemplateOperations.GetProjectTemplate"] = new("SecretKit.Infisical.Management.ProjectTemplateOperations.GetProjectTemplate(System.String,System.String)",
            ["selector.exact", "response.conditions-unprojected"], false),
        ["i.management.ProjectTemplateOperations.ListProjectTemplates"] = new("SecretKit.Infisical.Management.ProjectTemplateOperations.ListProjectTemplates(System.String,System.Nullable<SecretKit.Infisical.Management.ProjectTemplateType>)",
            ["type.SecretManager", "type.CertificateManager", "type.KeyManagement", "type.SecretScanning", "type.PrivilegedAccess", "type.AgentVault", "type.omitted", "response.conditions-unprojected"], false),
        ["i.management.ProjectTemplateOperations.UpdateProjectTemplate"] = new("SecretKit.Infisical.Management.ProjectTemplateOperations.UpdateProjectTemplate(System.String,System.String,System.String,System.String,SecretKit.Infisical.Management.ProjectTemplateConfiguration)",
            ["name.omitted", "name.value", "description.omitted", "description.value", "configuration.omitted", "configuration.value", "ProjectTemplateConfiguration.roles.omitted", "ProjectTemplateConfiguration.roles.value", "ProjectTemplateConfiguration.environments.omitted", "ProjectTemplateConfiguration.environments.value", "ProjectTemplateConfiguration.users.omitted", "ProjectTemplateConfiguration.users.value", "ProjectTemplateConfiguration.groups.omitted", "ProjectTemplateConfiguration.groups.value", "ProjectTemplateConfiguration.identities.omitted", "ProjectTemplateConfiguration.identities.value", "ProjectTemplateConfiguration.projectManagedIdentities.omitted", "ProjectTemplateConfiguration.projectManagedIdentities.value", "roles.empty", "roles.values", "environments.null", "environments.empty", "environments.values", "permissions.action.scalar", "permissions.action.array", "permissions.conditions.empty", "permissions.literal", "permissions.eq", "permissions.ne", "permissions.in.empty", "permissions.in.values", "permissions.glob", "permissions.metadata.elemMatch", "permissions.secretTags.in", "permissions.secretTags.all", "users.null", "groups.null", "identities.null", "projectManagedIdentities.null", "permission.Secrets.read", "permission.Secrets.describeSecret", "permission.Secrets.readValue", "permission.Secrets.create", "permission.Secrets.edit", "permission.Secrets.delete", "permission.DynamicSecrets.read-root-credential", "permission.DynamicSecrets.create-root-credential", "permission.DynamicSecrets.edit-root-credential", "permission.DynamicSecrets.delete-root-credential", "permission.DynamicSecrets.lease", "permission.Identity.read", "permission.Identity.create", "permission.Identity.edit", "permission.Identity.delete", "permission.Identity.grant-privileges", "permission.Identity.assign-role", "permission.Identity.assign-additional-privileges", "permission.Identity.assume-privileges", "permission.Identity.revoke-auth", "permission.Identity.edit-auth", "permission.Identity.create-token", "permission.Identity.get-token", "permission.Identity.delete-token", "permission.PkiSubscribers.read", "permission.PkiSubscribers.create", "permission.PkiSubscribers.edit", "permission.PkiSubscribers.delete", "permission.PkiSubscribers.issue-cert", "permission.PkiSubscribers.list-certs", "permission.CertificateTemplates.read", "permission.CertificateTemplates.create", "permission.CertificateTemplates.edit", "permission.CertificateTemplates.delete", "permission.CertificateTemplates.issue-cert", "permission.CertificateTemplates.list-certs", "permission.SecretRotation.read", "permission.SecretRotation.read-generated-credentials", "permission.SecretRotation.create", "permission.SecretRotation.edit", "permission.SecretRotation.delete", "permission.SecretRotation.rotate-secrets", "permission.SecretSyncs.read", "permission.SecretSyncs.create", "permission.SecretSyncs.edit", "permission.SecretSyncs.delete", "permission.SecretSyncs.sync-secrets", "permission.SecretSyncs.import-secrets", "permission.SecretSyncs.remove-secrets", "permission.PkiSyncs.read", "permission.PkiSyncs.create", "permission.PkiSyncs.edit", "permission.PkiSyncs.delete", "permission.PkiSyncs.sync-certificates", "permission.PkiSyncs.import-certificates", "permission.PkiSyncs.remove-certificates", "permission.PkiSyncs.set-post-sync-command", "permission.PkiSyncs.set-health-check-command", "permission.PkiSyncs.set-target-host", "permission.SecretEventSubscriptions.subscribe-to-creation-events", "permission.SecretEventSubscriptions.subscribe-to-update-events", "permission.SecretEventSubscriptions.subscribe-to-deletion-events", "permission.SecretEventSubscriptions.subscribe-to-import-mutation-events", "permission.CertificateProfiles.read", "permission.CertificateProfiles.create", "permission.CertificateProfiles.edit", "permission.CertificateProfiles.delete", "permission.CertificateProfiles.issue-cert", "permission.CertificateProfiles.reveal-acme-eab-secret", "permission.CertificateProfiles.rotate-acme-eab-secret", "permission.CertificateProfiles.manage-application-attachments", "permission.CertificateApplication.read", "permission.CertificateApplication.list", "permission.CertificateApplication.create", "permission.CertificateAuthorities.read", "permission.CertificateAuthorities.create", "permission.CertificateAuthorities.edit", "permission.CertificateAuthorities.delete", "permission.CertificateAuthorities.issue-ca-certificate", "permission.CertificateAuthorities.sign-intermediate", "permission.Certificates.read", "permission.Certificates.create", "permission.Certificates.edit", "permission.Certificates.delete", "permission.Certificates.read-private-key", "permission.Certificates.import", "permission.SecretRollback.read", "permission.SecretRollback.create", "permission.ApprovalRequests.read", "permission.ApprovalRequests.create", "permission.Member.read", "permission.Member.create", "permission.Member.edit", "permission.Member.delete", "permission.Member.grant-privileges", "permission.Member.assign-role", "permission.Member.assign-additional-privileges", "permission.Member.assume-privileges", "permission.Groups.read", "permission.Groups.create", "permission.Groups.edit", "permission.Groups.delete", "permission.Groups.grant-privileges", "permission.Groups.assign-role", "permission.AuditLogs.read", "permission.AuditLogs.edit", "permission.Insights.read", "permission.Insights.generate-report", "permission.Insights.delete-report", "permission.PkiDiscovery.read", "permission.PkiDiscovery.create", "permission.PkiDiscovery.edit", "permission.PkiDiscovery.delete", "permission.PkiDiscovery.run-scan", "permission.PkiCertificateInstallations.read", "permission.PkiCertificateInstallations.edit", "permission.PkiCertificateInstallations.delete", "permission.CodeSigners.read", "permission.CodeSigners.create", "permission.CodeSigners.edit", "permission.CodeSigners.delete", "permission.CodeSigners.sign", "permission.Workspace.edit", "permission.Workspace.delete", "permission.Kms.edit", "permission.Cmek.read", "permission.Cmek.create", "permission.Cmek.edit", "permission.Cmek.delete", "permission.Cmek.encrypt", "permission.Cmek.decrypt", "permission.Cmek.sign", "permission.Cmek.verify", "permission.Cmek.generate-mac", "permission.Cmek.verify-mac", "permission.Cmek.rotate", "permission.Cmek.export-private-key", "permission.Kmip.create-clients", "permission.Kmip.update-clients", "permission.Kmip.delete-clients", "permission.Kmip.read-clients", "permission.Kmip.generate-client-certificates", "permission.Commits.read", "permission.Commits.perform-rollback", "permission.SecretScanningDataSources.read-data-sources", "permission.SecretScanningDataSources.create-data-sources", "permission.SecretScanningDataSources.edit-data-sources", "permission.SecretScanningDataSources.delete-data-sources", "permission.SecretScanningDataSources.trigger-data-source-scans", "permission.SecretScanningDataSources.read-data-source-scans", "permission.SecretScanningDataSources.read-data-source-resources", "permission.SecretScanningFindings.read-findings", "permission.SecretScanningFindings.update-findings", "permission.SecretScanningConfigs.read-configs", "permission.SecretScanningConfigs.update-configs", "permission.AppConnections.read-app-connections", "permission.AppConnections.create-app-connections", "permission.AppConnections.edit-app-connections", "permission.AppConnections.delete-app-connections", "permission.AppConnections.connect-app-connections", "permission.AppConnections.rotate-credentials", "permission.HsmConnectors.read-hsm-connectors", "permission.HsmConnectors.create-hsm-connectors", "permission.HsmConnectors.edit-hsm-connectors", "permission.HsmConnectors.delete-hsm-connectors", "permission.HsmConnectors.test-hsm-connectors", "permission.HsmConnectors.attach-hsm-connectors", "permission.HoneyTokens.read", "permission.HoneyTokens.read-credentials", "permission.HoneyTokens.create", "permission.HoneyTokens.edit", "permission.HoneyTokens.reset", "permission.HoneyTokens.revoke", "permission.ProxiedServices.read", "permission.ProxiedServices.create", "permission.ProxiedServices.edit", "permission.ProxiedServices.delete", "permission.ProxiedServices.proxy", "permission.ProxiedServices.report-usage", "permission.AgentVaultAccessBundles.read", "permission.AgentVaultAccessBundles.create", "permission.AgentVaultAccessBundles.edit", "permission.AgentVaultAccessBundles.delete", "permission.AgentVaultAccessBundles.manage-members", "permission.AgentVaultSessions.read", "permission.AgentVaultSessions.create", "permission.AgentVaultSessions.revoke", "permission.AgentVaultProxies.read", "permission.AgentVaultProxies.create", "permission.AgentVaultProxies.edit", "permission.AgentVaultProxies.delete", "permission.AgentVaultProxies.issue-token", "permission.AgentVaultProxies.revoke", "permission.ApprovalRequestGrants.read", "permission.ApprovalRequestGrants.revoke", "permission.SecretApprovalRequest.read", "permission.ProjectFolderGrant.read-grant", "permission.ProjectFolderGrant.create-grant", "permission.ProjectFolderGrant.revoke-grant", "permission.SecretFolders.read", "permission.SecretFolders.create", "permission.SecretFolders.edit", "permission.SecretFolders.delete", "permission.SecretImports.read", "permission.SecretImports.create", "permission.SecretImports.edit", "permission.SecretImports.delete", "permission.CertificatePolicies.read", "permission.CertificatePolicies.create", "permission.CertificatePolicies.edit", "permission.CertificatePolicies.delete", "permission.SecretApproval.read", "permission.SecretApproval.create", "permission.SecretApproval.edit", "permission.SecretApproval.delete", "permission.Role.read", "permission.Role.create", "permission.Role.edit", "permission.Role.delete", "permission.Integrations.read", "permission.Integrations.create", "permission.Integrations.edit", "permission.Integrations.delete", "permission.Webhooks.read", "permission.Webhooks.create", "permission.Webhooks.edit", "permission.Webhooks.delete", "permission.ServiceTokens.read", "permission.ServiceTokens.create", "permission.ServiceTokens.edit", "permission.ServiceTokens.delete", "permission.Settings.read", "permission.Settings.create", "permission.Settings.edit", "permission.Settings.delete", "permission.SecretValidationRules.read", "permission.SecretValidationRules.create", "permission.SecretValidationRules.edit", "permission.SecretValidationRules.delete", "permission.Environments.read", "permission.Environments.create", "permission.Environments.edit", "permission.Environments.delete", "permission.Tags.read", "permission.Tags.create", "permission.Tags.edit", "permission.Tags.delete", "permission.IpAllowlist.read", "permission.IpAllowlist.create", "permission.IpAllowlist.edit", "permission.IpAllowlist.delete", "permission.PkiAlerts.read", "permission.PkiAlerts.create", "permission.PkiAlerts.edit", "permission.PkiAlerts.delete", "permission.PkiCollections.read", "permission.PkiCollections.create", "permission.PkiCollections.edit", "permission.PkiCollections.delete", "permission.CertificateInventoryViews.read", "permission.CertificateInventoryViews.create", "permission.CertificateInventoryViews.edit", "permission.CertificateInventoryViews.delete", "condition.metadata.elemMatch", "condition.secretTags.in", "condition.secretTags.all", "response.conditions-unprojected"], true),
    };

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, IMembershipExpiryObserver? expiryObserver = null,
        IOrganizationGroupExpiryObserver? organizationExpiryObserver = null,
        IOrganizationUserSource? organizationUsers = null, IProjectTypeSource? projectTypes = null,
        IMetadataPermissionSource? metadataPermissions = null, ITemplatePrincipalSource? templatePrincipals = null,
        IDynamicPermissionSource? dynamicPermissions = null, IFolderPermissionSource? folderPermissions = null,
        ITagPermissionSource? tagPermissions = null, IImportPermissionSource? importPermissions = null,
        IRotationPermissionSource? rotationPermissions = null, RotationPermissionRuntime? rotationPermissionRuntime = null,
        IMemberPermissionSource? memberPermissions = null, IGroupPermissionSource? groupPermissions = null,
        IIdentityPermissionSource? identityPermissions = null, IProjectTemplatePermissionSource? projectTemplatePermissions = null,
        IRolePermissionSource? rolePermissions = null, IEnvironmentPermissionSource? environmentPermissions = null, IAuditPermissionSource? auditPermissions = null, IWorkspacePermissionSource? workspacePermissions = null, IGatewayPermissionSource? gatewayPermissions = null, IProxyPermissionSource? proxyPermissions = null, IValidationPermissionSource? validationPermissions = null, IIntegrationPermissionSource? integrationPermissions = null, ISettingsPermissionSource? settingsPermissions = null)
    {
        foreach (NativeCaseDefinition definition in expected)
        {
            if (!Owns(definition.Key.Operation)) continue;
            registry.Add(new(definition, (probe, token) => RunAsync(environment, definition, probe, expiryObserver, organizationExpiryObserver, organizationUsers, projectTypes, metadataPermissions, templatePrincipals, dynamicPermissions, folderPermissions, tagPermissions, importPermissions, rotationPermissions, rotationPermissionRuntime, memberPermissions, groupPermissions, identityPermissions, projectTemplatePermissions, rolePermissions, environmentPermissions, auditPermissions, workspacePermissions, gatewayPermissions, proxyPermissions, validationPermissions, integrationPermissions, settingsPermissions, token)));
        }
    }

    internal static bool Owns(string operation) => operation.StartsWith("i.management.ProjectOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.ProjectTemplateOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.ProjectMembershipOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.MembershipMutationOperations.", StringComparison.Ordinal) ||
        operation.StartsWith("i.management.MembershipOperations.", StringComparison.Ordinal);

    internal static bool Valid(NativeCaseDefinition definition) =>
        definition.Key.Provider == "Infisical" && !string.IsNullOrWhiteSpace(definition.Key.Scope) &&
        Bindings.TryGetValue(definition.Key.Operation, out ProjectFamilyBinding? binding) &&
        definition.Member == binding.Member && binding.Variants.Contains(definition.Key.Variant, StringComparer.Ordinal) &&
        (definition.Key.Case is "selected-contract" or "denied-authority" or "cancellation-boundary" or "independent-effect" ||
            binding.Mutation && definition.Key.Case == "lost-response-no-replay");

    internal static string? UnavailableReason(NativeCaseDefinition definition)
    {
        if (!Valid(definition)) return "contract-mismatch";
        return Family(definition.Key.Operation) switch
        {
            "Projects" => ProjectsEffects.UnavailableReason(definition),
            "ProjectTemplates" => ProjectTemplatesEffects.UnavailableReason(definition),
            "ProjectMemberships" => ProjectMembershipsEffects.UnavailableReason(definition),
            "MembershipMutations" => MembershipMutationsEffects.UnavailableReason(definition),
            _ => MembershipsEffects.UnavailableReason(definition)
        };
    }

    private static string Family(string operation) => operation.Split('.')[2] switch
    {
        "ProjectOperations" => "Projects",
        "ProjectTemplateOperations" => "ProjectTemplates",
        "ProjectMembershipOperations" => "ProjectMemberships",
        "MembershipMutationOperations" => "MembershipMutations",
        _ => "Memberships"
    };

    private static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition definition,
        NativeCaseProbe probe, IMembershipExpiryObserver? expiryObserver,
        IOrganizationGroupExpiryObserver? organizationExpiryObserver, IOrganizationUserSource? organizationUsers,
        IProjectTypeSource? projectTypes, IMetadataPermissionSource? metadataPermissions,
        ITemplatePrincipalSource? templatePrincipals, IDynamicPermissionSource? dynamicPermissions,
        IFolderPermissionSource? folderPermissions, ITagPermissionSource? tagPermissions,
        IImportPermissionSource? importPermissions, IRotationPermissionSource? rotationPermissions,
        RotationPermissionRuntime? rotationPermissionRuntime, IMemberPermissionSource? memberPermissions,
        IGroupPermissionSource? groupPermissions, IIdentityPermissionSource? identityPermissions,
        IProjectTemplatePermissionSource? projectTemplatePermissions, IRolePermissionSource? rolePermissions, IEnvironmentPermissionSource? environmentPermissions, IAuditPermissionSource? auditPermissions, IWorkspacePermissionSource? workspacePermissions, IGatewayPermissionSource? gatewayPermissions, IProxyPermissionSource? proxyPermissions, IValidationPermissionSource? validationPermissions, IIntegrationPermissionSource? integrationPermissions, ISettingsPermissionSource? settingsPermissions, CancellationToken token)
    {
        probe.Contract(Valid(definition), NativeFailure.ContractMismatch);
        bool organizationUserSelected = OrganizationUserInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool projectTypeSelected = ProjectTypeInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool metadataSelected = MetadataPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool templatePrincipalSelected = TemplatePrincipalInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool dynamicSelected = DynamicPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool folderSelected = FolderPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool tagSelected = TagPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool importSelected = ImportPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool rotationSelected = RotationPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool memberSelected = MemberPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool groupSelected = GroupPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool identitySelected = IdentityPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool projectTemplateSelected = ProjectTemplatePermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool roleSelected = RolePermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool environmentSelected = EnvironmentPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool auditSelected = AuditPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool workspaceSelected = WorkspacePermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool gatewaySelected = GatewayPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool proxySelected = ProxyPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool validationSelected = ValidationPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool integrationSelected = IntegrationPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        bool settingsSelected = SettingsPermissionInput.Selected(environment, "C08-IM-" + Family(definition.Key.Operation), definition);
        if (UnavailableReason(definition) is not null && !organizationUserSelected && !projectTypeSelected && !metadataSelected && !templatePrincipalSelected && !dynamicSelected && !folderSelected && !tagSelected && !importSelected && !rotationSelected && !memberSelected && !groupSelected && !identitySelected && !projectTemplateSelected && !roleSelected && !environmentSelected && !auditSelected && !workspaceSelected && !gatewaySelected && !proxySelected && !validationSelected && !integrationSelected && !settingsSelected)
        {
            probe.Effect(NativeObservation.Unavailable);
            return;
        }
        string family = Family(definition.Key.Operation);
        ProjectFamilyContext? context = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            context = new ProjectFamilyContext(environment, family, definition, probe);
            deadline.CancelAfter(InfisicalGovernanceFamilies.CaseTimeout(context.Input));
            if (settingsSelected)
            {
                await SettingsPermissionEffects.ExecuteAsync(context, settingsPermissions, deadline.Token);
                return;
            }
            if (integrationSelected)
            {
                await IntegrationPermissionEffects.ExecuteAsync(context, integrationPermissions, deadline.Token);
                return;
            }
            if (validationSelected)
            {
                await ValidationPermissionEffects.ExecuteAsync(context, validationPermissions, deadline.Token);
                return;
            }
            if (proxySelected)
            {
                await ProxyPermissionEffects.ExecuteAsync(context, proxyPermissions, deadline.Token);
                return;
            }
            if (gatewaySelected)
            {
                await GatewayPermissionEffects.ExecuteAsync(context, gatewayPermissions, deadline.Token);
                return;
            }
            if (workspaceSelected)
            {
                await WorkspacePermissionEffects.ExecuteAsync(context, workspacePermissions, deadline.Token);
                return;
            }
            if (auditSelected)
            {
                await AuditPermissionEffects.ExecuteAsync(context, auditPermissions, deadline.Token);
                return;
            }
            if (environmentSelected)
            {
                await EnvironmentPermissionEffects.ExecuteAsync(context, environmentPermissions, deadline.Token);
                return;
            }
            if (roleSelected)
            {
                await RolePermissionEffects.ExecuteAsync(context, rolePermissions, deadline.Token);
                return;
            }
            if (projectTemplateSelected)
            {
                await ProjectTemplatePermissionEffects.ExecuteAsync(context, projectTemplatePermissions, deadline.Token);
                return;
            }
            if (identitySelected)
            {
                await IdentityPermissionEffects.ExecuteAsync(context, identityPermissions, deadline.Token);
                return;
            }
            if (groupSelected)
            {
                await GroupPermissionEffects.ExecuteAsync(context, groupPermissions, deadline.Token);
                return;
            }
            if (memberSelected)
            {
                await MemberPermissionEffects.ExecuteAsync(context, memberPermissions, deadline.Token);
                return;
            }
            if (rotationSelected)
            {
                await RotationPermissionEffects.ExecuteAsync(context, rotationPermissions, deadline.Token, rotationPermissionRuntime);
                return;
            }
            if (tagSelected)
            {
                await TagPermissionEffects.ExecuteAsync(context, tagPermissions, deadline.Token);
                return;
            }
            if (importSelected)
            {
                await ImportPermissionEffects.ExecuteAsync(context, importPermissions, deadline.Token);
                return;
            }
            if (folderSelected)
            {
                await FolderPermissionEffects.ExecuteAsync(context, folderPermissions, deadline.Token);
                return;
            }
            if (dynamicSelected)
            {
                await DynamicPermissionEffects.ExecuteAsync(context, dynamicPermissions, deadline.Token);
                return;
            }
            if (templatePrincipalSelected)
            {
                await TemplatePrincipalEffects.ExecuteAsync(context, templatePrincipals, deadline.Token);
                return;
            }
            if (metadataSelected)
            {
                await MetadataPermissionEffects.ExecuteAsync(context, metadataPermissions, deadline.Token);
                return;
            }
            if (projectTypeSelected)
            {
                await ProjectTypeEffects.ExecuteAsync(context, projectTypes, deadline.Token);
                return;
            }
            if (organizationUserSelected)
            {
                await OrganizationUserEffects.ExecuteAsync(context, organizationUsers, deadline.Token);
                return;
            }
            if (definition.Key.Variant == "roles.relative-time")
            {
                if (definition.Key.Operation.Contains("Organization", StringComparison.Ordinal))
                    await TemporalOrganizationGroupEffects.ExecuteAsync(context, organizationExpiryObserver, deadline.Token);
                else
                    await TemporalMembershipEffects.ExecuteAsync(context, expiryObserver, deadline.Token);
                return;
            }
            switch (family)
            {
                case "Projects": await ProjectsEffects.ExecuteAsync(context, deadline.Token); break;
                case "ProjectTemplates": await ProjectTemplatesEffects.ExecuteAsync(context, deadline.Token); break;
                case "ProjectMemberships": await ProjectMembershipsEffects.ExecuteAsync(context, deadline.Token); break;
                case "MembershipMutations": await MembershipMutationsEffects.ExecuteAsync(context, deadline.Token); break;
                case "Memberships": await MembershipsEffects.ExecuteAsync(context, deadline.Token); break;
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
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
        finally
        {
            if (context is not null) await context.CleanupAsync();
        }
    }
}

/// <summary>Family-owned setup, execution and observation; no remote declaration can mark a case passed.</summary>
internal sealed class ProjectFamilyContext
{
    private readonly ManagementClient client;
    private readonly Stack<Func<CancellationToken, ValueTask<bool>>> cleanup = new();
    private readonly Dictionary<string, string?> ownedProjects = new(StringComparer.Ordinal);
    public NativeEnvironment Environment { get; }
    public NativeCaseDefinition Definition { get; }
    public NativeCaseProbe Probe { get; }
    internal ILdapLoginObserver? LdapObserver { get; init; }
    internal bool LdapWitnessObserved { get; set; }
    public JsonElement Input { get; }
    public string OrganizationId { get; }
    public string ProjectId { get; private set; } = "";
    public string ProjectSlug { get; private set; } = "";
    public string Operation => Definition.Key.Operation.Split('.')[3];
    public string Variant => Definition.Key.Variant;

    public ProjectFamilyContext(NativeEnvironment environment, string family,
        NativeCaseDefinition definition, NativeCaseProbe probe)
    {
        Environment = environment;
        Definition = definition;
        Probe = probe;
        JsonElement familyInput = environment.RequireFamilyInput("C08-IM-" + family);
        if (!familyInput.TryGetProperty("scopes", out JsonElement scopes) || scopes.ValueKind != JsonValueKind.Object ||
            !scopes.TryGetProperty(definition.Key.Scope, out JsonElement selected) || selected.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        Input = selected;
        OrganizationId = Required("organizationId");
        client = environment.CreateManagementClient();
    }

    public string Required(string name) => Optional(name) ?? throw new NativeCaseFailureException("missing-input");
    public string? Optional(string name)
    {
        if (!Input.TryGetProperty(name, out JsonElement value)) return null;
        if (value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()) ||
            value.GetString()!.Length > 1024 || value.GetString()!.Any(char.IsControl))
            throw new NativeCaseFailureException("missing-input");
        return value.GetString();
    }
    public static string FreshName() => "sk" + Guid.NewGuid().ToString("N");
    public void Cleanup(Func<CancellationToken, ValueTask<bool>> action) => cleanup.Push(action);

    public async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(Func<ManagementRequest<T>> factory,
        NativeIdentityRole role, CancellationToken token) where T : notnull
    {
        // Both requests are built from the locally owned scenario, not an incoming target.
        using ManagementRequest<T> intent = factory();
        using ManagementRequest<T> request = factory();
        ManagementAuthority authority = Environment.CreateManagementAuthority(client, role,
            intent.Target.OrganizationId, intent.Target.ProjectId);
        ManagementGrant grant = authority.IssueGrant(intent.OperationId, intent.Target);
        ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        SecretOutcome<T> result = await client.ExecuteAsync(request, authority, grant, receipt, token);
        if (request.IsMutation && result.IsSuccess) RememberProject(result.Value);
        return result;
    }

    public async ValueTask<T> NeedAsync<T>(Func<ManagementRequest<T>> factory,
        NativeIdentityRole role, CancellationToken token) where T : notnull
    {
        SecretOutcome<T> result = await ExecuteAsync(factory, role, token);
        Probe.Contract(result.IsSuccess, NativeFailure.MissingPrerequisite);
        return result.Value;
    }

    public async ValueTask CaseAsync<T>(Func<ManagementRequest<T>> factory, Func<T, bool> match,
        Func<bool, CancellationToken, ValueTask<bool>> observe, CancellationToken token,
        Func<DispatchEvidence, CancellationToken, ValueTask>? complete = null) where T : notnull
    {
        using ManagementRequest<T> intent = factory();
        using ManagementRequest<T> request = factory();
        bool applied = Definition.Key.Case is "selected-contract" or "independent-effect" or "lost-response-no-replay";
        DispatchEvidence evidence = DispatchEvidence.NotDispatched;
        if (Definition.Key.Case == "cancellation-boundary")
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            var barrier = new ProjectTokenBarrier(Environment.Tokens(NativeIdentityRole.Administrative));
            var authority = new ManagementAuthority(client.Authority, barrier,
                intent.Target.OrganizationId, intent.Target.ProjectId);
            ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            // Subscribe before execution. The barrier is a token-acquisition state event,
            // before dispatch, and never masquerades as a post-send cancellation.
            Task entered = barrier.Entered;
            Task<SecretOutcome<T>> execution = client.ExecuteAsync(request, authority,
                authority.IssueGrant(intent.OperationId, intent.Target), receipt, cancellation.Token).AsTask();
            SecretOutcome<T>? completed = null;
            try
            {
                await entered.WaitAsync(token);
                cancellation.Cancel();
                barrier.Release();
                bool cancelled = false;
                try { completed = await execution; }
                catch (OperationCanceledException) { cancelled = cancellation.IsCancellationRequested; }
                Probe.Contract(cancelled && (receipt is null || receipt.Evidence == DispatchEvidence.NotDispatched),
                    NativeFailure.ContractMismatch);
            }
            finally
            {
                cancellation.Cancel();
                barrier.Release();
                try { completed ??= await execution; }
                catch (OperationCanceledException) { }
                if (completed is { IsSuccess: true } unexpected && unexpected.Value is IDisposable owned)
                    owned.Dispose();
            }
            evidence = receipt?.Evidence ?? DispatchEvidence.NotDispatched;
        }
        else if (Definition.Key.Case == "lost-response-no-replay")
        {
            using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
            ManagementAuthority authority = Environment.CreateManagementAuthority(client, NativeIdentityRole.Administrative,
                intent.Target.OrganizationId, intent.Target.ProjectId);
            ManagementReceipt receipt = client.CreateReceipt(request);
            using var boundary = new ProjectResponseBoundary(Environment.Origin, cancellation);
            bool cancelled = false;
            // With ResponseHeadersRead, HttpClient's correlated RequestStop event
            // precedes the SDK body read. ActivityHeadersPropagator=null suppresses
            // DiagnosticListener, so use the independently tested BCL EventSource.
            using (boundary.Enter())
            {
                SecretOutcome<T>? completed = null;
                try
                {
                    completed = await client.ExecuteAsync(request, authority, authority.IssueGrant(intent.OperationId, intent.Target),
                        receipt, cancellation.Token);
                }
                catch (OperationCanceledException) when (!token.IsCancellationRequested)
                {
                    cancelled = cancellation.IsCancellationRequested;
                }
                finally
                {
                    if (completed is { IsSuccess: true } unexpected && unexpected.Value is IDisposable owned)
                        owned.Dispose();
                }
            }
            Probe.Contract(boundary.Reached, NativeFailure.ObserverUnavailable);
            Probe.Contract(cancelled && receipt.Evidence == DispatchEvidence.PossiblyDispatched,
                NativeFailure.ContractMismatch);
            evidence = receipt.Evidence;
        }
        else
        {
            NativeIdentityRole role = applied ? NativeIdentityRole.Administrative : NativeIdentityRole.Denied;
            ManagementAuthority authority = Environment.CreateManagementAuthority(client, role,
                intent.Target.OrganizationId, intent.Target.ProjectId);
            ManagementReceipt? receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            SecretOutcome<T> result = await client.ExecuteAsync(request, authority,
                authority.IssueGrant(intent.OperationId, intent.Target), receipt, token);
            if (request.IsMutation && result.IsSuccess) RememberProject(result.Value);
            try
            {
                Probe.Contract(applied ? result.IsSuccess && match(result.Value) &&
                    (receipt is null || receipt.Evidence == DispatchEvidence.Applied) :
                    result.Status == SecretStatus.Denied && (receipt is null || receipt.Evidence == DispatchEvidence.Rejected),
                    NativeFailure.ContractMismatch);
                if (applied)
                {
                    Environment.ConfirmPrerequisite(Definition.Key.Scope, "selected-administrative-identity", NativeObservation.Matched);
                    Environment.ConfirmPrerequisite(Definition.Key.Scope, "scoped-administrative-rights", NativeObservation.Matched);
                }
            }
            finally { if (result.IsSuccess && result.Value is IDisposable owned) owned.Dispose(); }
            evidence = receipt?.Evidence ?? DispatchEvidence.NotDispatched;
        }
        if (complete is not null) await complete(evidence, token);
        Probe.Effect(await observe(applied, token) ? NativeObservation.Matched : NativeObservation.Mismatched);
    }

    public async ValueTask EnsureProjectAsync(CancellationToken token, bool runtimeMember = false)
    {
        ProjectSlug = FreshName();
        OwnProject(ProjectSlug);
        ProjectSummary project = await NeedAsync(() => ProjectOperations.CreateProject(OrganizationId,
            ProjectSlug, ProjectSlug, createDefaultEnvironments: false), NativeIdentityRole.Setup, token);
        ProjectId = project.Id;
        await AddObserversAsync(ProjectId, token);
        if (runtimeMember)
            await NeedAsync(() => MembershipOperations.AddProjectIdentity(OrganizationId, ProjectId,
                Required("runtimeIdentityId"), new MembershipRoleSelection(roles: [new("viewer")])),
                NativeIdentityRole.Setup, token);
    }

    public async ValueTask AddObserversAsync(string projectId, CancellationToken token)
    {
        string admin = Required("administrativeIdentityId");
        string observer = Required("observerIdentityId");
        Probe.Contract(admin != observer && admin != Optional("runtimeIdentityId") &&
            observer != Optional("runtimeIdentityId"), NativeFailure.MissingInput);
        await NeedAsync(() => MembershipOperations.AddProjectIdentity(OrganizationId, projectId,
            admin, new MembershipRoleSelection(roles: [new("admin")])), NativeIdentityRole.Setup, token);
        await NeedAsync(() => MembershipOperations.AddProjectIdentity(OrganizationId, projectId,
            observer, new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, token);
    }

    internal void RememberProject<T>(T value) where T : notnull
    {
        if (value is ProjectSummary project && ownedProjects.TryGetValue(project.Slug, out string? id) && id is null)
            ownedProjects[project.Slug] = project.Id;
    }

    public void OwnProject(string slug, string? acknowledgedId = null)
    {
        ownedProjects.Add(slug, acknowledgedId);
        // Register before dispatch: even a lost setup acknowledgement must be inspected.
        Cleanup(async token =>
        {
            SecretOutcome<ProjectSummary> found = await ExecuteAsync(
                () => ProjectOperations.GetProjectBySlug(OrganizationId, slug), NativeIdentityRole.Observer, token);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess) return false;
            string id = found.Value.Id;
            if (ownedProjects[slug] is { } expected && id != expected) return false;
            if (found.Value.HasDeleteProtection.IsPresent && !found.Value.HasDeleteProtection.IsNull &&
                found.Value.HasDeleteProtection.Value)
            {
                SecretOutcome<ProjectSummary> cleared = await ExecuteAsync(
                    () => ProjectOperations.UpdateProject(OrganizationId, id, deleteProtection: false),
                    NativeIdentityRole.Setup, token);
                if (!cleared.IsSuccess) return false;
            }
            SecretOutcome<ProjectSummary> deleted = await ExecuteAsync(
                () => ProjectOperations.DeleteProject(OrganizationId, id), NativeIdentityRole.Setup, token);
            SecretOutcome<ProjectSummary> observed = await ExecuteAsync(
                () => ProjectOperations.GetProject(OrganizationId, id), NativeIdentityRole.Observer, token);
            return deleted.IsSuccess && observed.Status == SecretStatus.Absent;
        });
    }

    public async ValueTask CleanupAsync()
    {
        bool complete = true;
        bool observed = false;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        while (cleanup.TryPop(out Func<CancellationToken, ValueTask<bool>>? action))
        {
            observed = true;
            try { complete &= await action(deadline.Token); }
            catch (Exception) { complete = false; }
        }
        Probe.Contract(complete, NativeFailure.CleanupIncomplete);
        if (complete && observed)
            Environment.ConfirmPrerequisite(Definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
    }
}

internal sealed class ProjectTokenBarrier(IInfisicalTokenSource selected) : IInfisicalTokenSource
{
    private readonly TaskCompletionSource entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource released = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public Task Entered => entered.Task;
    public void Release() => released.TrySetResult();
    public async ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
    {
        SecretOutcome<InfisicalAccessToken> result = await selected.GetTokenAsync(token);
        entered.TrySetResult();
        try { await released.Task.WaitAsync(token); }
        catch
        {
            if (result.IsSuccess) result.Value.Dispose();
            throw;
        }
        return result;
    }
}

// BCL System.Net.Http events are not a transport replacement. Only the request
// started inside this operation's AsyncLocal scope can arm its stop event. HTTP
// propagation is disabled by the SDK, so ActivityId is empty and cannot correlate.
internal sealed class ProjectResponseBoundary : EventListener
{
    private static readonly AsyncLocal<ProjectResponseBoundary?> current = new();
    private readonly Uri origin;
    private readonly CancellationTokenSource cancellation;
    private int started;
    internal bool Reached { get; private set; }

    internal ProjectResponseBoundary(Uri origin, CancellationTokenSource cancellation)
    {
        this.origin = origin;
        this.cancellation = cancellation;
    }
    internal IDisposable Enter()
    {
        ProjectResponseBoundary? previous = current.Value;
        current.Value = this;
        return new Scope(previous);
    }
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http")
            EnableEvents(source, EventLevel.Informational, EventKeywords.All);
    }
    protected override void OnEventWritten(EventWrittenEventArgs message)
    {
        if (!ReferenceEquals(current.Value, this)) return;
        if (message.EventName == "RequestStart" && message.PayloadNames is not null && message.Payload is not null)
        {
            int scheme = message.PayloadNames.IndexOf("scheme"), host = message.PayloadNames.IndexOf("host"),
                port = message.PayloadNames.IndexOf("port");
            if (scheme >= 0 && host >= 0 && port >= 0 &&
                message.Payload[scheme] is string observedScheme && observedScheme == origin.Scheme &&
                message.Payload[host] is string observedHost && observedHost == origin.Host &&
                message.Payload[port] is int observedPort && observedPort == origin.Port)
                Interlocked.Increment(ref started);
            return;
        }
        if (message.EventName != "RequestStop" || Volatile.Read(ref started) != 1) return;
        Reached = true;
        cancellation.Cancel();
    }
    private sealed class Scope(ProjectResponseBoundary? previous) : IDisposable
    {
        public void Dispose() => current.Value = previous;
    }
}
