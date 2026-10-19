using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record GovernanceFamilyBinding(string Member, string[] Variants, bool Mutation);

// Host-owned observers are selected explicitly; registration never creates or disposes them.
internal sealed class GovernanceObservers
{
    public IGatewayAgentObserver? Gateway { get; init; }
    public IGatewayPatchObserver? GatewayPatch { get; init; }
    public IProxyBackendObserver? Proxy { get; init; }
    public IProxyPatchObserver? ProxyPatch { get; init; }
    public IAuditEventObserver? Audit { get; init; }
    public IShareRecipientObserver? Share { get; init; }
    public IDatabaseFixtureFactory? Database { get; init; }
    public IInfisicalSpiffeRefreshSource? SpiffeRefresh { get; init; }
    public IOrganizationUserSource? OrganizationUsers { get; init; }
    public IProjectTypeSource? ProjectTypes { get; init; }
    public IWorkloadTransitionSource? WorkloadTransitions { get; init; }
    public IMetadataPermissionSource? MetadataPermissions { get; init; }
    public ITemplatePrincipalSource? TemplatePrincipals { get; init; }
    public IDynamicPermissionSource? DynamicPermissions { get; init; }
    public IFolderPermissionSource? FolderPermissions { get; init; }
    public ITagPermissionSource? TagPermissions { get; init; }
    public IImportPermissionSource? ImportPermissions { get; init; }
    public IRotationPermissionSource? RotationPermissions { get; init; }
    public RotationPermissionRuntime? RotationPermissionRuntime { get; init; }
    public IMemberPermissionSource? MemberPermissions { get; init; }
    public IGroupPermissionSource? GroupPermissions { get; init; }
    public IIdentityPermissionSource? IdentityPermissions { get; init; }
    public IProjectTemplatePermissionSource? ProjectTemplatePermissions { get; init; }
    public IRolePermissionSource? RolePermissions { get; init; }
    public IEnvironmentPermissionSource? EnvironmentPermissions { get; init; }
    public IAuditPermissionSource? AuditPermissions { get; init; }
    public IWorkspacePermissionSource? WorkspacePermissions { get; init; }
    public IGatewayPermissionSource? GatewayPermissions { get; init; }
    public IProxyPermissionSource? ProxyPermissions { get; init; }
    public IValidationPermissionSource? ValidationPermissions { get; init; }
    public IIntegrationPermissionSource? IntegrationPermissions { get; init; }
    public ISettingsPermissionSource? SettingsPermissions { get; init; }
    public IAuthTemplatePermissionSource? AuthTemplatePermissions { get; init; }
}

internal static class InfisicalGovernanceFamilies
{
    internal static readonly Dictionary<string, GovernanceFamilyBinding> Bindings = new(StringComparer.Ordinal)
    {
        ["i.management.GatewayAdministrationOperations.Create"] = new("SecretKit.Infisical.Management.GatewayAdministrationOperations.Create(System.String,SecretKit.Infisical.Management.GatewayCreation)",
            ["auth.Aws", "auth.Gcp.type-omitted", "auth.Gcp.Gce", "auth.Gcp.Iam", "auth.Kubernetes.review-omitted", "auth.Kubernetes.Api", "auth.Kubernetes.Gateway", "auth.Token", "gatewayId.omitted", "gatewayId.null", "gatewayId.value", "gatewayPoolId.omitted", "gatewayPoolId.null", "gatewayPoolId.value", "verifyTlsCertificate.omitted", "verifyTlsCertificate.false", "verifyTlsCertificate.true", "response.auth.Aws", "response.auth.Gcp", "response.auth.Kubernetes", "response.auth.Token", "response.auth.Identity", "Aws.allowedAccountIds.omitted", "Aws.allowedAccountIds.empty", "Aws.allowedAccountIds.value", "Aws.allowedPrincipalArns.omitted", "Aws.allowedPrincipalArns.empty", "Aws.allowedPrincipalArns.value", "Gcp.allowedProjects.omitted", "Gcp.allowedProjects.empty", "Gcp.allowedProjects.value", "Gcp.allowedServiceAccounts.omitted", "Gcp.allowedServiceAccounts.empty", "Gcp.allowedServiceAccounts.value", "Gcp.allowedZones.omitted", "Gcp.allowedZones.empty", "Gcp.allowedZones.value", "Kubernetes.tokenReviewerJwt.omitted", "Kubernetes.tokenReviewerJwt.empty", "Kubernetes.tokenReviewerJwt.value", "Kubernetes.kubernetesHost.omitted", "Kubernetes.kubernetesHost.value", "Kubernetes.caCertificate.omitted", "Kubernetes.caCertificate.empty", "Kubernetes.caCertificate.value"], true),
        ["i.management.GatewayAdministrationOperations.GenerateEnrollmentToken"] = new("SecretKit.Infisical.Management.GatewayAdministrationOperations.GenerateEnrollmentToken(System.String,System.String)",
            ["input.organizationId-gatewayId"], true),
        ["i.management.GatewayAdministrationOperations.Get"] = new("SecretKit.Infisical.Management.GatewayAdministrationOperations.Get(System.String,System.String)",
            ["selector.exact", "response.auth.Aws", "response.auth.Gcp", "response.auth.Kubernetes", "response.auth.Token", "response.auth.Identity"], false),
        ["i.management.GatewayAdministrationOperations.Update"] = new("SecretKit.Infisical.Management.GatewayAdministrationOperations.Update(System.String,System.String,SecretKit.Infisical.Management.GatewayUpdate)",
            ["auth.Aws", "auth.Gcp.type-omitted", "auth.Gcp.Gce", "auth.Gcp.Iam", "auth.Kubernetes.review-omitted", "auth.Kubernetes.Api", "auth.Kubernetes.Gateway", "auth.Token", "gatewayId.omitted", "gatewayId.null", "gatewayId.value", "gatewayPoolId.omitted", "gatewayPoolId.null", "gatewayPoolId.value", "verifyTlsCertificate.omitted", "verifyTlsCertificate.false", "verifyTlsCertificate.true", "patch.empty", "name.omitted", "name.value", "authentication.omitted", "response.auth.Aws", "response.auth.Gcp", "response.auth.Kubernetes", "response.auth.Token", "response.auth.Identity", "patch.persistence-unestablished", "Aws.allowedAccountIds.omitted", "Aws.allowedAccountIds.empty", "Aws.allowedAccountIds.value", "Aws.allowedPrincipalArns.omitted", "Aws.allowedPrincipalArns.empty", "Aws.allowedPrincipalArns.value", "Gcp.allowedProjects.omitted", "Gcp.allowedProjects.empty", "Gcp.allowedProjects.value", "Gcp.allowedServiceAccounts.omitted", "Gcp.allowedServiceAccounts.empty", "Gcp.allowedServiceAccounts.value", "Gcp.allowedZones.omitted", "Gcp.allowedZones.empty", "Gcp.allowedZones.value", "Kubernetes.tokenReviewerJwt.omitted", "Kubernetes.tokenReviewerJwt.empty", "Kubernetes.tokenReviewerJwt.value", "Kubernetes.kubernetesHost.omitted", "Kubernetes.kubernetesHost.value", "Kubernetes.caCertificate.omitted", "Kubernetes.caCertificate.empty", "Kubernetes.caCertificate.value"], true),
        ["i.management.GovernanceOperations.GetOrganizationAuditSettings"] = new("SecretKit.Infisical.Management.GovernanceOperations.GetOrganizationAuditSettings(System.String)",
            ["selector.exact", "eventClass.Management", "eventClass.Authentication", "eventClass.Authorization", "eventClass.DataAccess"], false),
        ["i.management.GovernanceOperations.GetProjectAuditSettings"] = new("SecretKit.Infisical.Management.GovernanceOperations.GetProjectAuditSettings(System.String,System.String)",
            ["selector.exact", "eventClass.Management", "eventClass.Authentication", "eventClass.Authorization", "eventClass.DataAccess"], false),
        ["i.management.GovernanceOperations.ReadAudit"] = new("SecretKit.Infisical.Management.GovernanceOperations.ReadAudit(System.String,System.DateTimeOffset,System.DateTimeOffset,System.String,System.Int32,System.Int32,SecretKit.Infisical.Management.AuditSelectors)",
            ["projectId.omitted", "projectId.value", "selectors.omitted", "selectors.value", "eventClass.Management", "eventClass.Authentication", "eventClass.Authorization", "eventClass.DataAccess", "selector.organization", "selector.project", "eventClass.scalar", "eventClass.array.empty", "eventClass.array.values", "eventType.scalar", "eventType.array.empty", "eventType.array.catalog-values", "eventMetadata.omitted", "eventMetadata.value", "actor.omitted", "actor.value", "actorType.selected", "environment.omitted", "environment.value", "secretKey.omitted", "secretKey.value", "secretPath.omitted", "secretPath.value", "userAgentType.selected", "rows.complete", "rows.partial-invalid"], false),
        ["i.management.GovernanceOperations.SetOrganizationAuditSettings"] = new("SecretKit.Infisical.Management.GovernanceOperations.SetOrganizationAuditSettings(System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.AuditClassSetting>)",
            ["eventClass.Management", "eventClass.Authentication", "eventClass.Authorization", "eventClass.DataAccess", "isEnabled.false", "isEnabled.true"], true),
        ["i.management.GovernanceOperations.SetProjectAuditSettings"] = new("SecretKit.Infisical.Management.GovernanceOperations.SetProjectAuditSettings(System.String,System.String,System.Collections.Generic.IReadOnlyList<SecretKit.Infisical.Management.AuditClassSetting>)",
            ["eventClass.Management", "eventClass.Authentication", "eventClass.Authorization", "eventClass.DataAccess", "isEnabled.false", "isEnabled.true"], true),
        ["i.management.ProxiedServiceAdministrationOperations.Create"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.Create(System.String,SecretKit.Infisical.Management.ProxiedServiceCreation)",
            ["ProxiedServiceCredentialInput.dynamicSecretField.omitted", "ProxiedServiceCredentialInput.dynamicSecretField.value", "ProxiedServiceCredentialInput.dynamicSecretName.omitted", "ProxiedServiceCredentialInput.dynamicSecretName.value", "ProxiedServiceCredentialInput.headerName.omitted", "ProxiedServiceCredentialInput.headerName.value", "ProxiedServiceCredentialInput.headerPrefix.omitted", "ProxiedServiceCredentialInput.headerPrefix.value", "ProxiedServiceCredentialInput.headerPurpose.Username", "ProxiedServiceCredentialInput.headerPurpose.Password", "ProxiedServiceCredentialInput.headerPurpose.omitted", "ProxiedServiceCredentialInput.placeholderKey.omitted", "ProxiedServiceCredentialInput.placeholderKey.value", "ProxiedServiceCredentialInput.placeholderValue.omitted", "ProxiedServiceCredentialInput.placeholderValue.value", "ProxiedServiceCredentialInput.secretKey.omitted", "ProxiedServiceCredentialInput.secretKey.value", "ProxiedServiceCredentialInput.substitutionSurfaces.omitted", "ProxiedServiceCredentialInput.substitutionSurfaces.value", "ProxiedServiceCreation.secretPath.omitted", "ProxiedServiceCreation.secretPath.value", "ProxiedServiceCreation.isEnabled.omitted", "ProxiedServiceCreation.isEnabled.false", "ProxiedServiceCreation.isEnabled.true", "credential.role.HeaderRewrite", "credential.role.CredentialSubstitution", "credential.surface.Header", "credential.surface.Path", "credential.surface.Query", "credential.surface.Body", "credential.static-secret", "credential.dynamic-secret"], true),
        ["i.management.ProxiedServiceAdministrationOperations.Delete"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.Delete(System.String,System.String,System.String)",
            ["input.organizationId-projectId-serviceId"], true),
        ["i.management.ProxiedServiceAdministrationOperations.Get"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.Get(System.String,System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.ProxiedServiceAdministrationOperations.GetByName"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.GetByName(System.String,System.String,System.String,System.String,System.String)",
            ["secretPath.omitted", "secretPath.value"], false),
        ["i.management.ProxiedServiceAdministrationOperations.List"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.List(System.String,System.String,System.String,System.String)",
            ["secretPath.omitted", "secretPath.value"], false),
        ["i.management.ProxiedServiceAdministrationOperations.Update"] = new("SecretKit.Infisical.Management.ProxiedServiceAdministrationOperations.Update(System.String,System.String,System.String,SecretKit.Infisical.Management.ProxiedServiceUpdate)",
            ["ProxiedServiceCredentialInput.dynamicSecretField.omitted", "ProxiedServiceCredentialInput.dynamicSecretField.value", "ProxiedServiceCredentialInput.dynamicSecretName.omitted", "ProxiedServiceCredentialInput.dynamicSecretName.value", "ProxiedServiceCredentialInput.headerName.omitted", "ProxiedServiceCredentialInput.headerName.value", "ProxiedServiceCredentialInput.headerPrefix.omitted", "ProxiedServiceCredentialInput.headerPrefix.value", "ProxiedServiceCredentialInput.headerPurpose.Username", "ProxiedServiceCredentialInput.headerPurpose.Password", "ProxiedServiceCredentialInput.headerPurpose.omitted", "ProxiedServiceCredentialInput.placeholderKey.omitted", "ProxiedServiceCredentialInput.placeholderKey.value", "ProxiedServiceCredentialInput.placeholderValue.omitted", "ProxiedServiceCredentialInput.placeholderValue.value", "ProxiedServiceCredentialInput.secretKey.omitted", "ProxiedServiceCredentialInput.secretKey.value", "ProxiedServiceCredentialInput.substitutionSurfaces.omitted", "ProxiedServiceCredentialInput.substitutionSurfaces.value", "ProxiedServiceUpdate.name.omitted", "ProxiedServiceUpdate.name.value", "ProxiedServiceUpdate.hostPattern.omitted", "ProxiedServiceUpdate.hostPattern.value", "ProxiedServiceUpdate.isEnabled.omitted", "ProxiedServiceUpdate.isEnabled.false", "ProxiedServiceUpdate.isEnabled.true", "ProxiedServiceUpdate.credentials.omitted", "ProxiedServiceUpdate.credentials.value", "credential.role.HeaderRewrite", "credential.role.CredentialSubstitution", "credential.surface.Header", "credential.surface.Path", "credential.surface.Query", "credential.surface.Body", "credential.static-secret", "credential.dynamic-secret", "patch.empty", "credentials.omitted", "credentials.supplied-persistence-unestablished", "patch.persistence-unestablished"], true),
        ["i.management.SharingOperations.AccessShare"] = new("SecretKit.Infisical.Management.SharingOperations.AccessShare(System.String,System.String,SecretKit.Core.SecretMaterial)",
            ["password.omitted", "password.value"], true),
        ["i.management.SharingOperations.CreateShare"] = new("SecretKit.Infisical.Management.SharingOperations.CreateShare(System.String,System.String,SecretKit.Core.SecretMaterial,System.Int32,SecretKit.Infisical.Management.ShareAudience,System.Nullable<System.Int32>,SecretKit.Core.SecretMaterial,System.Nullable<System.Boolean>,System.Collections.Generic.IReadOnlyList<System.String>)",
            ["audience.Organization", "audience.Anyone", "maximumViews.omitted", "maximumViews.value", "password.omitted", "password.value", "allowExternalEmails.omitted", "allowExternalEmails.false", "allowExternalEmails.true", "authorizedEmails.omitted", "authorizedEmails.value", "authorizedEmails.empty", "authorizedEmails.values"], true),
        ["i.management.SharingOperations.DeleteShare"] = new("SecretKit.Infisical.Management.SharingOperations.DeleteShare(System.String,System.String)",
            ["input.organizationId-shareId"], true),
        ["i.management.SharingOperations.GetShare"] = new("SecretKit.Infisical.Management.SharingOperations.GetShare(System.String,System.String)",
            ["selector.exact"], false),
        ["i.management.SharingOperations.ListShares"] = new("SecretKit.Infisical.Management.SharingOperations.ListShares(System.String,System.Int32,System.Int32)",
            ["collection.bounded"], false),
        ["i.management.ManagementClient.ExecuteAsync"] = new("SecretKit.Infisical.Management.ManagementClient.ExecuteAsync(SecretKit.Infisical.Management.ManagementRequest<!!0>,SecretKit.Infisical.Management.ManagementAuthority,SecretKit.Infisical.Management.ManagementGrant,SecretKit.Infisical.Management.ManagementReceipt,System.Threading.CancellationToken)",
            ["factory.i.management.CloudIdentityAuthenticationOperations.AttachAliCloudAuth", "factory.i.management.CloudIdentityAuthenticationOperations.AttachAwsAuth", "factory.i.management.CloudIdentityAuthenticationOperations.AttachAzureAuth", "factory.i.management.CloudIdentityAuthenticationOperations.AttachGcpAuth", "factory.i.management.CloudIdentityAuthenticationOperations.DeleteAliCloudAuth", "factory.i.management.CloudIdentityAuthenticationOperations.DeleteAwsAuth", "factory.i.management.CloudIdentityAuthenticationOperations.DeleteAzureAuth", "factory.i.management.CloudIdentityAuthenticationOperations.DeleteGcpAuth", "factory.i.management.CloudIdentityAuthenticationOperations.GetAliCloudAuth", "factory.i.management.CloudIdentityAuthenticationOperations.GetAwsAuth", "factory.i.management.CloudIdentityAuthenticationOperations.GetAzureAuth", "factory.i.management.CloudIdentityAuthenticationOperations.GetGcpAuth", "factory.i.management.CloudIdentityAuthenticationOperations.UpdateAliCloudAuth", "factory.i.management.CloudIdentityAuthenticationOperations.UpdateAwsAuth", "factory.i.management.CloudIdentityAuthenticationOperations.UpdateAzureAuth", "factory.i.management.CloudIdentityAuthenticationOperations.UpdateGcpAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.AttachLdapAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.AttachOciAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.AttachSpiffeAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.AttachTlsCertAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.ClearLdapAuthLockouts", "factory.i.management.ExternalIdentityAuthenticationOperations.DeleteLdapAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.DeleteOciAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.DeleteSpiffeAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.DeleteTlsCertAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.GetLdapAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.GetOciAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.GetSpiffeAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.GetTlsCertAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.RefreshSpiffeBundle", "factory.i.management.ExternalIdentityAuthenticationOperations.UpdateLdapAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.UpdateOciAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.UpdateSpiffeAuth", "factory.i.management.ExternalIdentityAuthenticationOperations.UpdateTlsCertAuth", "factory.i.management.GatewayAdministrationOperations.Create", "factory.i.management.GatewayAdministrationOperations.GenerateEnrollmentToken", "factory.i.management.GatewayAdministrationOperations.Get", "factory.i.management.GatewayAdministrationOperations.Update", "factory.i.management.GovernanceOperations.GetOrganizationAuditSettings", "factory.i.management.GovernanceOperations.GetProjectAuditSettings", "factory.i.management.GovernanceOperations.ReadAudit", "factory.i.management.GovernanceOperations.SetOrganizationAuditSettings", "factory.i.management.GovernanceOperations.SetProjectAuditSettings", "factory.i.management.IdentityAuthenticationOperations.AttachTokenAuth", "factory.i.management.IdentityAuthenticationOperations.AttachUniversalAuth", "factory.i.management.IdentityAuthenticationOperations.ClearUniversalAuthLockouts", "factory.i.management.IdentityAuthenticationOperations.CreateToken", "factory.i.management.IdentityAuthenticationOperations.CreateUniversalClientSecret", "factory.i.management.IdentityAuthenticationOperations.DeleteTokenAuth", "factory.i.management.IdentityAuthenticationOperations.DeleteUniversalAuth", "factory.i.management.IdentityAuthenticationOperations.GetToken", "factory.i.management.IdentityAuthenticationOperations.GetTokenAuth", "factory.i.management.IdentityAuthenticationOperations.GetUniversalAuth", "factory.i.management.IdentityAuthenticationOperations.GetUniversalClientSecret", "factory.i.management.IdentityAuthenticationOperations.ListTokens", "factory.i.management.IdentityAuthenticationOperations.ListUniversalClientSecrets", "factory.i.management.IdentityAuthenticationOperations.RenameToken", "factory.i.management.IdentityAuthenticationOperations.RevokeToken", "factory.i.management.IdentityAuthenticationOperations.RevokeUniversalClientSecret", "factory.i.management.IdentityAuthenticationOperations.UpdateTokenAuth", "factory.i.management.IdentityAuthenticationOperations.UpdateUniversalAuth", "factory.i.management.IdentityOperations.CreateOrganizationIdentity", "factory.i.management.IdentityOperations.CreateProjectIdentity", "factory.i.management.IdentityOperations.DeleteOrganizationIdentity", "factory.i.management.IdentityOperations.DeleteProjectIdentity", "factory.i.management.IdentityOperations.GetOrganizationIdentity", "factory.i.management.IdentityOperations.GetProjectIdentity", "factory.i.management.IdentityOperations.GetSelectedIdentityOrganization", "factory.i.management.IdentityOperations.ListOrganizationIdentities", "factory.i.management.IdentityOperations.ListProjectIdentities", "factory.i.management.IdentityOperations.UpdateOrganizationIdentity", "factory.i.management.IdentityOperations.UpdateProjectIdentity", "factory.i.management.IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege", "factory.i.management.IdentityPrivilegeChangeOperations.CreateProjectPrivilege", "factory.i.management.IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege", "factory.i.management.IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug", "factory.i.management.IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege", "factory.i.management.IdentityPrivilegeChangeOperations.UpdateProjectPrivilege", "factory.i.management.IdentityPrivilegeOperations.DeleteProjectPrivilege", "factory.i.management.IdentityPrivilegeOperations.GetProjectPrivilege", "factory.i.management.IdentityPrivilegeOperations.ListProjectPrivileges", "factory.i.management.IdentitySearchOperations.CountIdentities", "factory.i.management.IdentitySearchOperations.SearchIdentities", "factory.i.management.IdentityTemplateOperations.CreateIdentityTemplate", "factory.i.management.IdentityTemplateOperations.CreateKubernetesIdentityTemplate", "factory.i.management.IdentityTemplateOperations.CreateLdapIdentityTemplate", "factory.i.management.IdentityTemplateOperations.DeleteIdentityTemplate", "factory.i.management.IdentityTemplateOperations.DeleteIdentityTemplateUsage", "factory.i.management.IdentityTemplateOperations.DeleteIdentityTemplateUsages", "factory.i.management.IdentityTemplateOperations.GetIdentityTemplate", "factory.i.management.IdentityTemplateOperations.GetIdentityTemplateUsage", "factory.i.management.IdentityTemplateOperations.ListIdentityTemplates", "factory.i.management.IdentityTemplateOperations.SearchIdentityTemplates", "factory.i.management.IdentityTemplateOperations.UpdateIdentityTemplate", "factory.i.management.IdentityTemplateOperations.UpdateIdentityTemplateConfiguration", "factory.i.management.LegacyIdentityPrivilegeOperations.DeletePrivilege", "factory.i.management.LegacyIdentityPrivilegeOperations.GetPrivilege", "factory.i.management.LegacyIdentityPrivilegeOperations.ListPrivileges", "factory.i.management.MembershipMutationOperations.DeleteOrganizationMemberships", "factory.i.management.MembershipMutationOperations.InviteProjectMembers", "factory.i.management.MembershipMutationOperations.RemoveProjectMembers", "factory.i.management.MembershipOperations.AddOrganizationGroup", "factory.i.management.MembershipOperations.AddProjectGroup.Selection", "factory.i.management.MembershipOperations.AddProjectGroup.Roles", "factory.i.management.MembershipOperations.AddProjectIdentity.Selection", "factory.i.management.MembershipOperations.AddProjectIdentity.Roles", "factory.i.management.MembershipOperations.GetOrganizationGroup", "factory.i.management.MembershipOperations.GetProjectGroup", "factory.i.management.MembershipOperations.GetProjectIdentityMembership", "factory.i.management.MembershipOperations.ListOrganizationGroups", "factory.i.management.MembershipOperations.ListProjectGroups", "factory.i.management.MembershipOperations.RemoveOrganizationGroup", "factory.i.management.MembershipOperations.RemoveProjectGroup", "factory.i.management.MembershipOperations.RemoveProjectIdentity", "factory.i.management.MembershipOperations.UpdateOrganizationGroupRoles", "factory.i.management.MembershipOperations.UpdateProjectGroupRoles", "factory.i.management.MembershipOperations.UpdateProjectIdentityRoles", "factory.i.management.MsSqlSecretRotationOperations.CheckCredentials", "factory.i.management.MsSqlSecretRotationOperations.Create", "factory.i.management.MsSqlSecretRotationOperations.Delete", "factory.i.management.MsSqlSecretRotationOperations.Get", "factory.i.management.MsSqlSecretRotationOperations.GetByName", "factory.i.management.MsSqlSecretRotationOperations.GetGeneratedCredentials", "factory.i.management.MsSqlSecretRotationOperations.List", "factory.i.management.MsSqlSecretRotationOperations.ListMsSqlSubset", "factory.i.management.MsSqlSecretRotationOperations.Move", "factory.i.management.MsSqlSecretRotationOperations.MsSqlOptionsSubset", "factory.i.management.MsSqlSecretRotationOperations.Update", "factory.i.management.MySqlSecretRotationOperations.CheckCredentials", "factory.i.management.MySqlSecretRotationOperations.Create", "factory.i.management.MySqlSecretRotationOperations.Delete", "factory.i.management.MySqlSecretRotationOperations.Get", "factory.i.management.MySqlSecretRotationOperations.GetByName", "factory.i.management.MySqlSecretRotationOperations.GetGeneratedCredentials", "factory.i.management.MySqlSecretRotationOperations.List", "factory.i.management.MySqlSecretRotationOperations.ListMySqlSubset", "factory.i.management.MySqlSecretRotationOperations.Move", "factory.i.management.MySqlSecretRotationOperations.MySqlOptionsSubset", "factory.i.management.MySqlSecretRotationOperations.Update", "factory.i.management.OrganizationIdentityMembershipOperations.ListOrganizationIdentityMemberships", "factory.i.management.OrganizationMembershipOperations.DeleteOrganizationMembership", "factory.i.management.OrganizationMembershipOperations.ListOrganizationMemberships", "factory.i.management.OrganizationMembershipOperations.UpdateOrganizationMembership", "factory.i.management.PostgresSecretRotationOperations.CheckCredentials", "factory.i.management.PostgresSecretRotationOperations.Create", "factory.i.management.PostgresSecretRotationOperations.Delete", "factory.i.management.PostgresSecretRotationOperations.Get", "factory.i.management.PostgresSecretRotationOperations.GetByName", "factory.i.management.PostgresSecretRotationOperations.GetGeneratedCredentials", "factory.i.management.PostgresSecretRotationOperations.List", "factory.i.management.PostgresSecretRotationOperations.ListPostgresSubset", "factory.i.management.PostgresSecretRotationOperations.Move", "factory.i.management.PostgresSecretRotationOperations.PostgresOptionsSubset", "factory.i.management.PostgresSecretRotationOperations.Update", "factory.i.management.ProjectConnectionOperations.ListAuthorizations", "factory.i.management.ProjectConnectionOperations.ListIntegrations", "factory.i.management.ProjectMembershipOperations.InspectProjectMembershipByUsername", "factory.i.management.ProjectMembershipOperations.ListAvailableProjectIdentities", "factory.i.management.ProjectMembershipOperations.ListProjectIdentityMemberships", "factory.i.management.ProjectMembershipOperations.ListProjectMemberships", "factory.i.management.ProjectMembershipOperations.UpdateProjectMembershipRoles", "factory.i.management.ProjectOperations.CreateEnvironment", "factory.i.management.ProjectOperations.CreateProject", "factory.i.management.ProjectOperations.CreateTag", "factory.i.management.ProjectOperations.DeleteEnvironment", "factory.i.management.ProjectOperations.DeleteProject", "factory.i.management.ProjectOperations.DeleteProjectRole", "factory.i.management.ProjectOperations.DeleteTag", "factory.i.management.ProjectOperations.GetEnvironment", "factory.i.management.ProjectOperations.GetEnvironmentBySlug", "factory.i.management.ProjectOperations.GetProject", "factory.i.management.ProjectOperations.GetProjectBySlug", "factory.i.management.ProjectOperations.GetProjectRole", "factory.i.management.ProjectOperations.GetProjectRoleBySlug", "factory.i.management.ProjectOperations.GetTag", "factory.i.management.ProjectOperations.GetTagBySlug", "factory.i.management.ProjectOperations.ListProjectRoles", "factory.i.management.ProjectOperations.ListProjects", "factory.i.management.ProjectOperations.ListTags", "factory.i.management.ProjectOperations.RestoreEnvironment", "factory.i.management.ProjectOperations.UpdateEnvironment", "factory.i.management.ProjectOperations.UpdateProject", "factory.i.management.ProjectOperations.UpdateTag", "factory.i.management.ProjectTemplateOperations.CreateProjectTemplate", "factory.i.management.ProjectTemplateOperations.DeleteProjectTemplate", "factory.i.management.ProjectTemplateOperations.GetProjectTemplate", "factory.i.management.ProjectTemplateOperations.ListProjectTemplates", "factory.i.management.ProjectTemplateOperations.UpdateProjectTemplate", "factory.i.management.ProxiedServiceAdministrationOperations.Create", "factory.i.management.ProxiedServiceAdministrationOperations.Delete", "factory.i.management.ProxiedServiceAdministrationOperations.Get", "factory.i.management.ProxiedServiceAdministrationOperations.GetByName", "factory.i.management.ProxiedServiceAdministrationOperations.List", "factory.i.management.ProxiedServiceAdministrationOperations.Update", "factory.i.management.RoleChangeOperations.CreateOrganizationRole", "factory.i.management.RoleChangeOperations.CreateProjectRole", "factory.i.management.RoleChangeOperations.UpdateOrganizationRole", "factory.i.management.RoleChangeOperations.UpdateProjectRole", "factory.i.management.ScopedAccessOperations.AddGroupIdentity", "factory.i.management.ScopedAccessOperations.AddGroupUser", "factory.i.management.ScopedAccessOperations.AvailableGroups", "factory.i.management.ScopedAccessOperations.AvailableIdentities", "factory.i.management.ScopedAccessOperations.CreateGroup", "factory.i.management.ScopedAccessOperations.DeleteGroup", "factory.i.management.ScopedAccessOperations.DeleteOrganizationRole", "factory.i.management.ScopedAccessOperations.GetGroup", "factory.i.management.ScopedAccessOperations.GetOrganizationRole", "factory.i.management.ScopedAccessOperations.GetOrganizationRoleBySlug", "factory.i.management.ScopedAccessOperations.ListGroupIdentities", "factory.i.management.ScopedAccessOperations.ListGroupMembers", "factory.i.management.ScopedAccessOperations.ListGroupProjects", "factory.i.management.ScopedAccessOperations.ListGroups", "factory.i.management.ScopedAccessOperations.ListGroupUsers", "factory.i.management.ScopedAccessOperations.ListOrganizationRoles", "factory.i.management.ScopedAccessOperations.RemoveGroupIdentity", "factory.i.management.ScopedAccessOperations.RemoveGroupUser", "factory.i.management.ScopedAccessOperations.UpdateGroup", "factory.i.management.SharingOperations.AccessShare", "factory.i.management.SharingOperations.CreateShare", "factory.i.management.SharingOperations.DeleteShare", "factory.i.management.SharingOperations.GetShare", "factory.i.management.SharingOperations.ListShares", "factory.i.management.WorkloadIdentityAuthenticationOperations.AttachJwtAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.AttachKubernetesAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.AttachOidcAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.DeleteJwtAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.DeleteKubernetesAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.DeleteOidcAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.GetJwtAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.GetKubernetesAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.GetOidcAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.UpdateJwtAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.UpdateKubernetesAuth", "factory.i.management.WorkloadIdentityAuthenticationOperations.UpdateOidcAuth"], true),
    };

    internal static TimeSpan CaseTimeout(JsonElement input)
    {
        if (!input.TryGetProperty("caseTimeoutSeconds", out JsonElement value)) return TimeSpan.FromSeconds(45);
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out int seconds) || seconds is < 1 or > 900)
            throw new NativeCaseFailureException("missing-input");
        return TimeSpan.FromSeconds(seconds);
    }

    internal static bool Owns(string operation) => Bindings.ContainsKey(operation);
    internal static bool Valid(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        !string.IsNullOrWhiteSpace(d.Key.Scope) && Bindings.TryGetValue(d.Key.Operation, out var b) &&
        d.Member == b.Member && b.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) &&
        (d.Key.Case is "selected-contract" or "denied-authority" or "independent-effect" or "cancellation-boundary" ||
            b.Mutation && d.Key.Case == "lost-response-no-replay");

    internal static string Family(string operation) => operation.Split('.')[2] switch
    {
        "GatewayAdministrationOperations" => "GatewayAdministration",
        "ProxiedServiceAdministrationOperations" => "ProxiedServiceAdministration",
        "ManagementClient" => "ManagementClient",
        _ => "Governance"
    };

    internal static string? UnavailableReason(NativeCaseDefinition d) => !Valid(d) ? "contract-mismatch" :
        Family(d.Key.Operation) switch
        {
            "GatewayAdministration" => GatewayAdministrationEffects.UnavailableReason(d),
            "ProxiedServiceAdministration" => ProxiedServiceAdministrationEffects.UnavailableReason(d),
            "ManagementClient" => ManagementClientEffects.UnavailableReason(d),
            _ => GovernanceEffects.UnavailableReason(d)
        };

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected) => Register(registry, environment, expected, new());

    public static void Register(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected, GovernanceObservers observers)
    {
        foreach (var d in expected.Where(d => Owns(d.Key.Operation)))
            registry.Add(new(d, (probe, token) => RunAsync(environment, d, probe, observers, token)));
    }

    internal static async ValueTask RunAsync(NativeEnvironment environment, NativeCaseDefinition d,
        NativeCaseProbe probe, GovernanceObservers observers, CancellationToken token)
    {
        probe.Contract(Valid(d), NativeFailure.ContractMismatch);
        if (Family(d.Key.Operation) == "ManagementClient")
        {
            // The selected native registry applies its own scoped witness gate.
            // A static factory label cannot decide whether that witness exists.
            await ManagementClientEffects.ExecuteAsync(environment, d, probe, observers, token);
            return;
        }
        bool proxyPatch = Family(d.Key.Operation) == "ProxiedServiceAdministration" &&
            d.Key.Operation.EndsWith(".Update", StringComparison.Ordinal) &&
            environment.TryGetFamilyInput("C08-IM-ProxiedServiceAdministration", out var proxyInput) &&
            proxyInput.TryGetProperty("scopes", out var proxyScopes) && proxyScopes.ValueKind == JsonValueKind.Object &&
            proxyScopes.TryGetProperty(d.Key.Scope, out var proxyScope) && proxyScope.ValueKind == JsonValueKind.Object &&
            proxyScope.TryGetProperty("proxyPatchWitness", out _);
        bool gatewayPatch = Family(d.Key.Operation) == "GatewayAdministration" &&
            d.Key.Operation.EndsWith(".Update", StringComparison.Ordinal) &&
            environment.TryGetFamilyInput("C08-IM-GatewayAdministration", out var gatewayInput) &&
            gatewayInput.TryGetProperty("scopes", out var gatewayScopes) && gatewayScopes.ValueKind == JsonValueKind.Object &&
            gatewayScopes.TryGetProperty(d.Key.Scope, out var gatewayScope) && gatewayScope.ValueKind == JsonValueKind.Object &&
            gatewayScope.TryGetProperty("gatewayPatchWitness", out _);
        if (UnavailableReason(d) is not null && !proxyPatch && !gatewayPatch) { probe.Effect(NativeObservation.Unavailable); return; }
        ProjectFamilyContext? context = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            context = new(environment, Family(d.Key.Operation), d, probe);
            deadline.CancelAfter(CaseTimeout(context.Input));
            switch (Family(d.Key.Operation))
            {
                case "GatewayAdministration":
                    if (gatewayPatch)
                        await GatewayPatchEffects.ExecuteAsync(context,
                            observers.Gateway ?? InfisicalGatewayObserver.FromInputs(environment) ??
                                throw new NativeCaseFailureException("missing-input"),
                            observers.GatewayPatch ?? observers.Gateway as IGatewayPatchObserver, deadline.Token);
                    else await GatewayAdministrationEffects.ExecuteAsync(context, observers, deadline.Token);
                    break;
                case "ProxiedServiceAdministration":
                    if (proxyPatch) await ProxyPatchEffects.ExecuteAsync(context, observers, deadline.Token);
                    else await ProxiedServiceAdministrationEffects.ExecuteAsync(context, observers, deadline.Token);
                    break;
                default: await GovernanceEffects.ExecuteAsync(context, observers, deadline.Token); break;
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
                "contract-mismatch" => NativeFailure.ContractMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        { probe.Contract(false, token.IsCancellationRequested ? NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded); }
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException or FormatException)
        { probe.Contract(false, NativeFailure.MissingInput); }
        finally { if (context is not null) await context.CleanupAsync(); }
    }
}
