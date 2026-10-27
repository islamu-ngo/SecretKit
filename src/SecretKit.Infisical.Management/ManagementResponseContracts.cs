using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Family-owned response profiles from the admitted in-repository field contracts.
// Each operation selects closure, UUID and date rules together; typed projections
// still own presence, nullability and scope. No runtime manifest loading.
internal static class ManagementResponseContracts
{
    internal sealed record Shape(string[]? Members, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Object(string[]? members, params (string Name, Shape Value)[] children) => new(members, children);
    private static Shape Elements(Shape element) => new(null, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(null, [], Discriminator: discriminator, Branches: branches);

    internal sealed record ResponseContract(Shape Closure, ManagementResponseUuids.Shape? Uuids,
        ManagementResponseDates.Shape? Dates);

    private static class Common
    {
        internal static readonly Shape Permission = Object(["action", "conditions", "inverted", "subject"]);
        internal static readonly Shape Permissions = Elements(Permission);
        internal static readonly Shape Identifier = Object(["id"]);
        internal static readonly Shape NamedIdentity = Object(["id", "name"]);
        internal static readonly Shape UserSummary = Object(["email", "firstName", "id", "lastName", "username"]);
        internal static readonly Shape CustomRole = Object(["description", "id", "name", "permissions", "slug"]);
        internal static readonly Shape MetadataEntry = Object(["id", "key", "value"]);
        internal static readonly Shape Metadata = Elements(MetadataEntry);
        internal static readonly Shape NamedSlug = Object(["id", "name", "slug"]);
        internal static readonly Shape Message = Object(["message"]);
        internal static readonly Shape NamedSlugs = Elements(NamedSlug);
        internal static readonly Shape NamedIdentities = Elements(NamedIdentity);
        internal static readonly Shape GroupSummary = Object(["id", "name", "orgId", "slug"]);
        internal static readonly Shape MembershipRole = Object(["createdAt", "customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
        internal static readonly Shape MembershipRoles = Elements(MembershipRole);
        internal static readonly Shape TemporaryRole = Object(["customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange"]);
        internal static readonly Shape TemporaryRoles = Elements(TemporaryRole);
        internal static readonly Shape MembershipUser = Object(["authMethods", "email", "firstName", "id", "isEmailVerified", "lastName", "publicKey", "username"]);
    }

    private static class IdentityPrivileges
    {
        internal static readonly Shape MembershipPrivilege = Object(["createdAt", "id", "isTemporary", "permissions", "projectMembershipId", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"], ("permissions", Common.Permissions));
        internal static readonly Shape MembershipPrivilegeEnvelope = Object(["privilege"], ("privilege", MembershipPrivilege));
        internal static readonly Shape MembershipPrivilegeRows = Elements(MembershipPrivilege);
        internal static readonly Shape MembershipPrivilegePage = Object(["privileges"], ("privileges", MembershipPrivilegeRows));
        internal static readonly Shape ProjectPrivilegeSummary = Object(["createdAt", "id", "isTemporary", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
        internal static readonly Shape ProjectPrivilegeRows = Elements(ProjectPrivilegeSummary);
        internal static readonly Shape ProjectPrivilegePage = Object(["privileges"], ("privileges", ProjectPrivilegeRows));
        internal static readonly Shape ProjectPrivilege = Object(["createdAt", "id", "isTemporary", "permissions", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"], ("permissions", Common.Permissions));
        internal static readonly Shape ProjectPrivilegeEnvelope = Object(["privilege"], ("privilege", ProjectPrivilege));

        internal static readonly ResponseContract MembershipPrivilegeEnvelopeResponse = new(MembershipPrivilegeEnvelope, ManagementResponseUuids.PrivilegeEnvelope, ManagementResponseDates.PrivilegeEnvelope);
        internal static readonly ResponseContract MembershipPrivilegePageResponse = new(MembershipPrivilegePage, ManagementResponseUuids.PrivilegePage, ManagementResponseDates.PrivilegePage);
        internal static readonly ResponseContract ProjectPrivilegePageResponse = new(ProjectPrivilegePage, ManagementResponseUuids.ProjectPrivilegePage, ManagementResponseDates.PrivilegePage);
        internal static readonly ResponseContract ProjectPrivilegeEnvelopeResponse = new(ProjectPrivilegeEnvelope, ManagementResponseUuids.ProjectPrivilegeEnvelope, ManagementResponseDates.PrivilegeEnvelope);
    }

    private static class Groups
    {
        internal static readonly Shape InventoryGroup = Object(["createdAt", "id", "name", "orgId", "role", "roleId", "slug", "updatedAt"]);
        internal static readonly Shape InventoryRows = Elements(InventoryGroup);
        internal static readonly Shape MutationGroup = Object(["createdAt", "id", "name", "orgId", "slug", "updatedAt"]);
        internal static readonly Shape DetailGroup = Object(["createdAt", "customRoleSlug", "id", "name", "orgId", "role", "roleId", "slug", "updatedAt"]);
        internal static readonly Shape MachineIdentity = Object(["id", "isPartOfGroup", "joinedGroupAt", "name"]);
        internal static readonly Shape MachineIdentityRows = Elements(MachineIdentity);
        internal static readonly Shape MachineIdentityPage = Object(["machineIdentities", "totalCount"], ("machineIdentities", MachineIdentityRows));
        internal static readonly Shape MachineMember = Object(["id", "joinedGroupAt", "machineIdentity", "type"], ("machineIdentity", Common.NamedIdentity));
        internal static readonly Shape UserMember = Object(["id", "joinedGroupAt", "type", "user"], ("user", Common.UserSummary));
        internal static readonly Shape MemberBranch = Branch("type", ("machineIdentity", MachineMember), ("user", UserMember));
        internal static readonly Shape MemberRows = Elements(MemberBranch);
        internal static readonly Shape MemberPage = Object(["members", "totalCount"], ("members", MemberRows));
        internal static readonly Shape Project = Object(["description", "id", "joinedGroupAt", "name", "slug", "type"]);
        internal static readonly Shape ProjectRows = Elements(Project);
        internal static readonly Shape ProjectPage = Object(["projects", "totalCount"], ("projects", ProjectRows));
        internal static readonly Shape User = Object(["email", "firstName", "id", "isPartOfGroup", "joinedGroupAt", "lastName", "username"]);
        internal static readonly Shape UserRows = Elements(User);
        internal static readonly Shape UserPage = Object(["totalCount", "users"], ("users", UserRows));

        internal static readonly ResponseContract InventoryRowsResponse = new(InventoryRows, ManagementResponseUuids.IdAndOrganizationRows, ManagementResponseDates.CreatedAndUpdatedRows);
        internal static readonly ResponseContract MutationGroupResponse = new(MutationGroup, ManagementResponseUuids.IdAndOrganization, ManagementResponseDates.CreatedAndUpdated);
        internal static readonly ResponseContract DetailGroupResponse = new(DetailGroup, ManagementResponseUuids.IdAndOrganization, ManagementResponseDates.CreatedAndUpdated);
        internal static readonly ResponseContract MachineIdentityPageResponse = new(MachineIdentityPage, ManagementResponseUuids.MachineIdentityPage, ManagementResponseDates.MachineIdentityPage);
        internal static readonly ResponseContract MachineIdentityMutationResponse = new(Common.Identifier, null, null);
        internal static readonly ResponseContract MemberPageResponse = new(MemberPage, ManagementResponseUuids.MemberPage, ManagementResponseDates.MemberPage);
        internal static readonly ResponseContract ProjectPageResponse = new(ProjectPage, null, ManagementResponseDates.GroupProjects);
        internal static readonly ResponseContract UserPageResponse = new(UserPage, ManagementResponseUuids.UserPage, ManagementResponseDates.GroupUsers);
        internal static readonly ResponseContract UserMutationResponse = new(Common.UserSummary, ManagementResponseUuids.Id, null);
    }

    private static class Identities
    {
        internal static readonly Shape ListedIdentity = Object(["authMethods", "hasDeleteProtection", "id", "name"]);
        internal static readonly Shape ListedMembership = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "role", "roleId", "updatedAt"], ("customRole", Common.CustomRole), ("identity", ListedIdentity));
        internal static readonly Shape ListedMembershipRows = Elements(ListedMembership);
        internal static readonly Shape ListPage = Object(["identities", "totalCount"], ("identities", ListedMembershipRows));
        internal static readonly Shape CreatedIdentity = Object(["authMethod", "authMethods", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Common.Metadata));
        internal static readonly Shape CreatedEnvelope = Object(["identity"], ("identity", CreatedIdentity));
        internal static readonly Shape DeletedIdentity = Object(["authMethod", "createdAt", "hasDeleteProtection", "id", "name", "orgId", "projectId", "updatedAt"]);
        internal static readonly Shape DeletedEnvelope = Object(["identity"], ("identity", DeletedIdentity));
        internal static readonly Shape LockoutIdentity = Object(["activeLockoutAuthMethods", "authMethods", "hasDeleteProtection", "id", "name", "orgId"]);
        internal static readonly Shape DetailedMembership = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "metadata", "orgId", "role", "roleId", "updatedAt"], ("customRole", Common.CustomRole), ("identity", LockoutIdentity), ("metadata", Common.Metadata));
        internal static readonly Shape DetailEnvelope = Object(["identity"], ("identity", DetailedMembership));
        internal static readonly Shape UpdatedIdentity = Object(["authMethod", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Common.Metadata));
        internal static readonly Shape UpdatedEnvelope = Object(["identity"], ("identity", UpdatedIdentity));
        internal static readonly Shape OrganizationEnvelope = Object(["organization"], ("organization", Common.NamedSlug));
        internal static readonly Shape DetailsEnvelope = Object(["identityDetails"], ("identityDetails", OrganizationEnvelope));
        internal static readonly Shape ProjectIdentity = Object(["activeLockoutAuthMethods", "authMethods", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Common.Metadata));
        internal static readonly Shape ProjectRows = Elements(ProjectIdentity);
        internal static readonly Shape ProjectListPage = Object(["identities", "totalCount"], ("identities", ProjectRows));
        internal static readonly Shape ProjectEnvelope = Object(["identity"], ("identity", ProjectIdentity));

        internal static readonly ResponseContract ListPageResponse = new(ListPage, ManagementResponseUuids.IdentityPage, ManagementResponseDates.IdentityPage);
        internal static readonly ResponseContract CreatedEnvelopeResponse = new(CreatedEnvelope, ManagementResponseUuids.IdentityEnvelope, ManagementResponseDates.IdentityEnvelope);
        internal static readonly ResponseContract DeletedEnvelopeResponse = new(DeletedEnvelope, ManagementResponseUuids.IdentityEnvelope, ManagementResponseDates.IdentityEnvelope);
        internal static readonly ResponseContract DetailEnvelopeResponse = new(DetailEnvelope, ManagementResponseUuids.DetailedIdentityEnvelope, ManagementResponseDates.DetailedIdentityEnvelope);
        internal static readonly ResponseContract UpdatedEnvelopeResponse = new(UpdatedEnvelope, ManagementResponseUuids.IdentityEnvelope, ManagementResponseDates.IdentityEnvelope);
        internal static readonly ResponseContract DetailsEnvelopeResponse = new(DetailsEnvelope, null, null);
        internal static readonly ResponseContract ProjectListPageResponse = new(ProjectListPage, ManagementResponseUuids.ProjectIdentities, ManagementResponseDates.ProjectIdentities);
        internal static readonly ResponseContract ProjectEnvelopeResponse = new(ProjectEnvelope, ManagementResponseUuids.IdentityEnvelope, ManagementResponseDates.IdentityEnvelope);
    }

    private static class IdentityTemplates
    {
        internal static readonly Shape KubernetesFields = Object(["allowedAudience", "caCert", "gatewayId", "gatewayPoolId", "hasTokenReviewerJwt", "kubernetesHost", "tokenReviewMode", "verifyTlsCertificate"]);
        internal static readonly Shape Kubernetes = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", KubernetesFields));
        internal static readonly Shape LdapFields = Object(["bindDN", "hasBindPass", "ldapCaCertificate", "searchBase", "url"]);
        internal static readonly Shape Ldap = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", LdapFields));
        internal static readonly Shape OidcFields = Object(["boundAudiences", "boundIssuer", "caCert", "oidcDiscoveryUrl"]);
        internal static readonly Shape Oidc = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", OidcFields));
        internal static readonly Shape AuthMethod = Branch("authMethod", ("kubernetes", Kubernetes), ("ldap", Ldap), ("oidc", Oidc));
        internal static readonly Shape Rows = Elements(AuthMethod);
        internal static readonly Shape DeletedUsage = Object(["authId", "identityId", "identityName"]);
        internal static readonly Shape DeletedUsageRows = Elements(DeletedUsage);
        internal static readonly Shape Usage = Object(["identityId", "identityName"]);
        internal static readonly Shape UsageRows = Elements(Usage);
        internal static readonly Shape SearchPage = Object(["templates", "totalCount"], ("templates", Rows));

        internal static readonly ResponseContract RowsResponse = new(Rows, ManagementResponseUuids.TemplateRows, ManagementResponseDates.TemplateRows);
        internal static readonly ResponseContract AuthMethodResponse = new(AuthMethod, ManagementResponseUuids.TemplateBranch, ManagementResponseDates.TemplateBranch);
        internal static readonly ResponseContract DeleteResponse = new(Common.Message, null, null);
        internal static readonly ResponseContract DeletedUsageRowsResponse = new(DeletedUsageRows, null, null);
        internal static readonly ResponseContract UsageRowsResponse = new(UsageRows, null, null);
        internal static readonly ResponseContract SearchPageResponse = new(SearchPage, ManagementResponseUuids.TemplateSearchPage, ManagementResponseDates.TemplateSearchPage);
    }

    private static class Audit
    {
        internal static readonly Shape ClassSetting = Object(["eventClass", "isEnabled"]);
        internal static readonly Shape ClassSettings = Elements(ClassSetting);
        internal static readonly Shape Settings = Object(["eventClasses", "shouldUseNewPrivilegeSystem"], ("eventClasses", ClassSettings));
        internal static readonly Shape SettingsEnvelope = Object(["auditLogSettings"], ("auditLogSettings", Settings));
        internal static readonly Shape Envelope = Object(["auditLogs"]);
        internal static readonly Shape Actor = Object(["metadata", "type"]);
        internal static readonly Shape Event = Object(["class", "metadata", "type"]);
        internal static readonly Shape Row = Object(["actor", "createdAt", "event", "expiresAt", "id", "ipAddress", "orgId", "projectId", "projectName", "updatedAt", "userAgent", "userAgentType"], ("actor", Actor), ("event", Event));

        internal static readonly ResponseContract SettingsEnvelopeResponse = new(SettingsEnvelope, null, null);
        internal static readonly ResponseContract EnvelopeResponse = new(Envelope, null, null);
        internal static readonly ResponseContract RowResponse = new(Row, ManagementResponseUuids.IdAndOrganization, ManagementResponseDates.Expiring);
    }

    private static class OrganizationAccess
    {
        internal static readonly Shape AvailableGroups = Object(["groups"], ("groups", Common.NamedSlugs));
        internal static readonly Shape AvailableIdentities = Object(["identities"], ("identities", Common.NamedIdentities));

        internal static readonly ResponseContract AvailableGroupsResponse = new(AvailableGroups, ManagementResponseUuids.AvailableGroups, null);
        internal static readonly ResponseContract AvailableIdentitiesResponse = new(AvailableIdentities, ManagementResponseUuids.AvailableIdentities, null);
    }

    private static class OrganizationRoles
    {
        internal static readonly Shape InventoryRole = Object(["createdAt", "description", "id", "name", "orgId", "slug", "updatedAt"]);
        internal static readonly Shape InventoryRows = Elements(InventoryRole);
        internal static readonly Shape InventoryEnvelope = Object(["roles"], ("roles", InventoryRows));
        internal static readonly Shape Role = Object(["createdAt", "description", "id", "name", "orgId", "permissions", "slug", "updatedAt"], ("permissions", Common.Permissions));
        internal static readonly Shape Envelope = Object(["role"], ("role", Role));

        internal static readonly ResponseContract InventoryEnvelopeResponse = new(InventoryEnvelope, ManagementResponseUuids.OrganizationRoles, null);
        internal static readonly ResponseContract EnvelopeResponse = new(Envelope, ManagementResponseUuids.OrganizationRole, null);
    }

    private static class Memberships
    {
        internal static readonly Shape OrganizationGroup = Object(["createdAt", "group", "groupId", "id", "roles", "updatedAt"], ("group", Common.GroupSummary), ("roles", Common.MembershipRoles));
        internal static readonly Shape OrganizationGroupRows = Elements(OrganizationGroup);
        internal static readonly Shape OrganizationGroupPage = Object(["groupMemberships", "totalCount"], ("groupMemberships", OrganizationGroupRows));
        internal static readonly Shape RemovedOrganizationGroup = Object(["createdAt", "groupId", "id", "orgId", "updatedAt"]);
        internal static readonly Shape RemovedOrganizationGroupEnvelope = Object(["groupMembership"], ("groupMembership", RemovedOrganizationGroup));
        internal static readonly Shape OrganizationGroupEnvelope = Object(["groupMembership"], ("groupMembership", OrganizationGroup));
        internal static readonly Shape ProjectUserMutation = Object(["createdAt", "id", "projectId", "updatedAt", "userId"]);
        internal static readonly Shape ProjectUserMutationRows = Elements(ProjectUserMutation);
        internal static readonly Shape ProjectUserMutationEnvelope = Object(["memberships"], ("memberships", ProjectUserMutationRows));
        internal static readonly Shape ProjectUser = Object(["createdAt", "id", "projectId", "roles", "user", "userId"], ("roles", Common.TemporaryRoles), ("user", Common.MembershipUser));
        internal static readonly Shape ProjectUserRows = Elements(ProjectUser);
        internal static readonly Shape ProjectUserEnvelope = Object(["memberships"], ("memberships", ProjectUserRows));
        internal static readonly Shape UpdatedRole = Object(["createdAt", "customRoleId", "id", "isTemporary", "projectMembershipId", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
        internal static readonly Shape UpdatedRoles = Elements(UpdatedRole);
        internal static readonly Shape UpdatedRolesEnvelope = Object(["roles"], ("roles", UpdatedRoles));
        internal static readonly Shape ProjectUserDetails = Object(["id", "projectId", "roles", "user", "userId"], ("roles", Common.TemporaryRoles), ("user", Common.MembershipUser));
        internal static readonly Shape ProjectUserDetailsEnvelope = Object(["membership"], ("membership", ProjectUserDetails));
        internal static readonly Shape ProjectGroup = Object(["createdAt", "group", "groupId", "id", "projectId", "roles", "updatedAt"], ("group", Common.GroupSummary), ("roles", Common.MembershipRoles));
        internal static readonly Shape ProjectGroupRows = Elements(ProjectGroup);
        internal static readonly Shape ProjectGroupList = Object(["groupMemberships"], ("groupMemberships", ProjectGroupRows));
        internal static readonly Shape RemovedProjectGroup = Object(["createdAt", "groupId", "id", "projectId", "updatedAt"]);
        internal static readonly Shape RemovedProjectGroupEnvelope = Object(["groupMembership"], ("groupMembership", RemovedProjectGroup));
        internal static readonly Shape ProjectGroupEnvelope = Object(["groupMembership"], ("groupMembership", ProjectGroup));
        internal static readonly Shape ProjectIdentity = Object(["activeLockoutAuthMethods", "authMethods", "id", "name", "orgId", "projectId"]);
        internal static readonly Shape ProjectIdentityMembership = Object(["createdAt", "id", "identity", "identityId", "roles", "updatedAt"], ("identity", ProjectIdentity), ("roles", Common.TemporaryRoles));
        internal static readonly Shape ProjectIdentityRows = Elements(ProjectIdentityMembership);
        internal static readonly Shape ProjectIdentityPage = Object(["identityMemberships", "totalCount"], ("identityMemberships", ProjectIdentityRows));
        internal static readonly Shape MutatedProjectIdentity = Object(["createdAt", "id", "identityId", "projectId", "updatedAt"]);
        internal static readonly Shape ProjectIdentityMutationEnvelope = Object(["identityMembership"], ("identityMembership", MutatedProjectIdentity));
        internal static readonly Shape DetailedProjectIdentity = Object(["authMethods", "id", "metadata", "name", "orgId", "projectId"], ("metadata", Common.Metadata));
        internal static readonly Shape DetailedProjectIdentityMembership = Object(["createdAt", "id", "identity", "lastLoginAuthMethod", "lastLoginTime", "roles", "updatedAt"], ("identity", DetailedProjectIdentity), ("roles", Common.TemporaryRoles));
        internal static readonly Shape ProjectIdentityEnvelope = Object(["identityMembership"], ("identityMembership", DetailedProjectIdentityMembership));
        internal static readonly Shape OrganizationUser = Object(["createdAt", "id", "inviteEmail", "isActive", "lastInvitedAt", "lastLoginAuthMethod", "lastLoginTime", "orgId", "projectFavorites", "role", "roleId", "status", "updatedAt", "userId"]);
        internal static readonly Shape OrganizationUserRows = Elements(OrganizationUser);
        internal static readonly Shape OrganizationUserMutationEnvelope = Object(["memberships"], ("memberships", OrganizationUserRows));
        internal static readonly Shape OrganizationUserDetails = Object(["id", "inviteEmail", "isActive", "lastInvitedAt", "lastLoginAuthMethod", "lastLoginTime", "orgId", "projectFavorites", "role", "roleId", "status", "user", "userId"], ("user", Common.MembershipUser));
        internal static readonly Shape OrganizationUserDetailRows = Elements(OrganizationUserDetails);
        internal static readonly Shape OrganizationUserPage = Object(["users"], ("users", OrganizationUserDetailRows));
        internal static readonly Shape OrganizationUserEnvelope = Object(["membership"], ("membership", OrganizationUser));
        internal static readonly Shape OrganizationIdentity = Object(["authMethods", "id", "name", "orgId"]);
        internal static readonly Shape OrganizationIdentityMembership = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "role", "roleId", "updatedAt"], ("customRole", Common.CustomRole), ("identity", OrganizationIdentity));
        internal static readonly Shape OrganizationIdentityRows = Elements(OrganizationIdentityMembership);
        internal static readonly Shape OrganizationIdentityPage = Object(["identityMemberships", "totalCount"], ("identityMemberships", OrganizationIdentityRows));

        internal static readonly ResponseContract OrganizationGroupPageResponse = new(OrganizationGroupPage, ManagementResponseUuids.GroupMembershipPage, ManagementResponseDates.GroupMembershipPage);
        internal static readonly ResponseContract RemovedOrganizationGroupEnvelopeResponse = new(RemovedOrganizationGroupEnvelope, ManagementResponseUuids.RemovedGroupEnvelope, ManagementResponseDates.RemovedGroupEnvelope);
        internal static readonly ResponseContract OrganizationGroupEnvelopeResponse = new(OrganizationGroupEnvelope, ManagementResponseUuids.GroupMembershipEnvelope, ManagementResponseDates.GroupMembershipEnvelope);
        internal static readonly ResponseContract ProjectUserMutationEnvelopeResponse = new(ProjectUserMutationEnvelope, ManagementResponseUuids.UserMembershipMutationEnvelope, ManagementResponseDates.UserMembershipMutations);
        internal static readonly ResponseContract ProjectUserEnvelopeResponse = new(ProjectUserEnvelope, ManagementResponseUuids.UserMembershipPage, ManagementResponseDates.UserMembershipPage);
        internal static readonly ResponseContract UpdatedRolesEnvelopeResponse = new(UpdatedRolesEnvelope, ManagementResponseUuids.MembershipRolesEnvelope, ManagementResponseDates.UpdatedMembershipRoles);
        internal static readonly ResponseContract ProjectUserDetailsEnvelopeResponse = new(ProjectUserDetailsEnvelope, ManagementResponseUuids.UserMembershipEnvelope, ManagementResponseDates.UserMembershipEnvelope);
        internal static readonly ResponseContract ProjectGroupListResponse = new(ProjectGroupList, ManagementResponseUuids.GroupMembershipPage, ManagementResponseDates.GroupMembershipPage);
        internal static readonly ResponseContract RemovedProjectGroupEnvelopeResponse = new(RemovedProjectGroupEnvelope, ManagementResponseUuids.RemovedGroupEnvelope, ManagementResponseDates.RemovedGroupEnvelope);
        internal static readonly ResponseContract ProjectGroupEnvelopeResponse = new(ProjectGroupEnvelope, ManagementResponseUuids.GroupMembershipEnvelope, ManagementResponseDates.GroupMembershipEnvelope);
        internal static readonly ResponseContract ProjectIdentityPageResponse = new(ProjectIdentityPage, ManagementResponseUuids.ProjectIdentityPage, ManagementResponseDates.IdentityMembershipPage);
        internal static readonly ResponseContract ProjectIdentityMutationEnvelopeResponse = new(ProjectIdentityMutationEnvelope, ManagementResponseUuids.IdentityMembershipMutationEnvelope, ManagementResponseDates.IdentityMembershipMutationEnvelope);
        internal static readonly ResponseContract ProjectIdentityEnvelopeResponse = new(ProjectIdentityEnvelope, ManagementResponseUuids.ProjectIdentityEnvelope, ManagementResponseDates.IdentityMembershipEnvelope);
        internal static readonly ResponseContract OrganizationUserMutationEnvelopeResponse = new(OrganizationUserMutationEnvelope, ManagementResponseUuids.OrganizationUserMembershipPage, ManagementResponseDates.UserMembershipMutations);
        internal static readonly ResponseContract OrganizationUserPageResponse = new(OrganizationUserPage, ManagementResponseUuids.OrganizationUserPage, null);
        internal static readonly ResponseContract OrganizationUserEnvelopeResponse = new(OrganizationUserEnvelope, ManagementResponseUuids.OrganizationUserMembershipEnvelope, ManagementResponseDates.OrganizationUserMembershipEnvelope);
        internal static readonly ResponseContract OrganizationIdentityPageResponse = new(OrganizationIdentityPage, ManagementResponseUuids.OrganizationIdentityPage, ManagementResponseDates.OrganizationIdentityPage);
    }

    private static class ProjectTemplates
    {
        internal static readonly Shape Environment = Object(["name", "position", "slug"]);
        internal static readonly Shape Environments = Elements(Environment);
        internal static readonly Shape Group = Object(["groupSlug", "roles"]);
        internal static readonly Shape Groups = Elements(Group);
        internal static readonly Shape Identity = Object(["identityId", "identityName", "roles"]);
        internal static readonly Shape Identities = Elements(Identity);
        internal static readonly Shape ManagedIdentity = Object(["name", "roles"]);
        internal static readonly Shape ManagedIdentities = Elements(ManagedIdentity);
        internal static readonly Shape Role = Object(["name", "permissions", "slug"], ("permissions", Common.Permissions));
        internal static readonly Shape Roles = Elements(Role);
        internal static readonly Shape User = Object(["roles", "username"]);
        internal static readonly Shape Users = Elements(User);
        internal static readonly Shape Template = Object(["createdAt", "description", "environments", "groups", "id", "identities", "name", "orgId", "projectManagedIdentities", "roles", "type", "updatedAt", "users"], ("environments", Environments), ("groups", Groups), ("identities", Identities), ("projectManagedIdentities", ManagedIdentities), ("roles", Roles), ("users", Users));
        internal static readonly Shape Rows = Elements(Template);
        internal static readonly Shape ListEnvelope = Object(["projectTemplates"], ("projectTemplates", Rows));
        internal static readonly Shape Envelope = Object(["projectTemplate"], ("projectTemplate", Template));

        internal static readonly ResponseContract ListEnvelopeResponse = new(ListEnvelope, ManagementResponseUuids.ProjectTemplates, ManagementResponseDates.ProjectTemplates);
        internal static readonly ResponseContract EnvelopeResponse = new(Envelope, ManagementResponseUuids.ProjectTemplate, ManagementResponseDates.ProjectTemplate);
    }

    private static class Projects
    {
        internal static readonly Shape DeletingIdentity = Object(["id", "name", "type"]);
        internal static readonly Shape DeletingUser = Object(["email", "firstName", "id", "lastName", "type", "username"]);
        internal static readonly Shape DeletingActor = Branch("type", ("identity", DeletingIdentity), ("user", DeletingUser));
        internal static readonly Shape DeletedEnvironment = Object(["deleteAfter", "deletedBy", "id", "name", "slug", "softDeletedAt"], ("deletedBy", DeletingActor));
        internal static readonly Shape DeletedEnvironments = Elements(DeletedEnvironment);
        internal static readonly Shape Role = Object(["createdAt", "description", "id", "name", "permissions", "projectId", "slug", "updatedAt", "version"]);
        internal static readonly Shape Roles = Elements(Role);
        internal static readonly Shape InventoryProject = Object(["_id", "auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "deletedEnvironments", "description", "enforceEncryptedSecretManagerSecretMetadata", "environments", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "roles", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"], ("deletedEnvironments", DeletedEnvironments), ("environments", Common.NamedSlugs), ("roles", Roles));
        internal static readonly Shape InventoryRows = Elements(InventoryProject);
        internal static readonly Shape ListEnvelope = Object(["projects"], ("projects", InventoryRows));
        internal static readonly Shape DetailedProject = Object(["_id", "auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "deletedEnvironments", "description", "enforceEncryptedSecretManagerSecretMetadata", "environments", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"], ("deletedEnvironments", DeletedEnvironments), ("environments", Common.NamedSlugs));
        internal static readonly Shape DetailEnvelope = Object(["project"], ("project", DetailedProject));
        internal static readonly Shape MutatedProject = Object(["auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "description", "enforceEncryptedSecretManagerSecretMetadata", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"]);
        internal static readonly Shape MutationEnvelope = Object(["project"], ("project", MutatedProject));
        internal static readonly Shape Authorization = Object(["accountId", "createdAt", "id", "integration", "metadata", "namespace", "projectId", "teamId", "updatedAt", "url"]);
        internal static readonly Shape AuthorizationRows = Elements(Authorization);
        internal static readonly Shape AuthorizationEnvelope = Object(["authorizations"], ("authorizations", AuthorizationRows));
        internal static readonly Shape Environment = Object(["createdAt", "deleteAfter", "deletedByIdentityId", "deletedByUserId", "id", "name", "position", "projectId", "slug", "softDeletedAt", "updatedAt"]);
        internal static readonly Shape EnvironmentMutationEnvelope = Object(["environment", "message", "projectId"], ("environment", Environment));
        internal static readonly Shape EnvironmentEnvelope = Object(["environment"], ("environment", Environment));
        internal static readonly Shape Integration = Object(["app", "appId", "createdAt", "envId", "environment", "id", "integration", "integrationAuthId", "isActive", "isSynced", "lastSyncJobId", "lastUsed", "metadata", "owner", "path", "region", "scope", "secretPath", "syncMessage", "targetEnvironment", "targetEnvironmentId", "targetService", "targetServiceId", "updatedAt", "url"], ("environment", Common.NamedSlug));
        internal static readonly Shape IntegrationRows = Elements(Integration);
        internal static readonly Shape IntegrationEnvelope = Object(["integrations"], ("integrations", IntegrationRows));

        internal static readonly ResponseContract ListEnvelopeResponse = new(ListEnvelope, ManagementResponseUuids.ProjectPage, ManagementResponseDates.ProjectPage);
        internal static readonly ResponseContract DetailEnvelopeResponse = new(DetailEnvelope, ManagementResponseUuids.ProjectEnvelope, ManagementResponseDates.ProjectEnvelope);
        internal static readonly ResponseContract MutationEnvelopeResponse = new(MutationEnvelope, ManagementResponseUuids.ProjectEnvelope, ManagementResponseDates.ProjectMutationEnvelope);
        internal static readonly ResponseContract AuthorizationEnvelopeResponse = new(AuthorizationEnvelope, ManagementResponseUuids.Authorizations, ManagementResponseDates.Authorizations);
        internal static readonly ResponseContract EnvironmentMutationEnvelopeResponse = new(EnvironmentMutationEnvelope, ManagementResponseUuids.EnvironmentEnvelope, ManagementResponseDates.EnvironmentEnvelope);
        internal static readonly ResponseContract EnvironmentEnvelopeResponse = new(EnvironmentEnvelope, ManagementResponseUuids.EnvironmentEnvelope, ManagementResponseDates.EnvironmentEnvelope);
        internal static readonly ResponseContract IntegrationEnvelopeResponse = new(IntegrationEnvelope, ManagementResponseUuids.Integrations, ManagementResponseDates.Integrations);
        internal static readonly ResponseContract DetailedProjectResponse = new(DetailedProject, ManagementResponseUuids.Project, ManagementResponseDates.DetailedProject);
    }

    private static class ProjectRoles
    {
        internal static readonly Shape InventoryRole = Object(["createdAt", "description", "id", "name", "projectId", "slug", "updatedAt"]);
        internal static readonly Shape InventoryRows = Elements(InventoryRole);
        internal static readonly Shape InventoryEnvelope = Object(["roles"], ("roles", InventoryRows));
        internal static readonly Shape Role = Object(["createdAt", "description", "id", "name", "permissions", "projectId", "slug", "updatedAt"], ("permissions", Common.Permissions));
        internal static readonly Shape Envelope = Object(["role"], ("role", Role));

        internal static readonly ResponseContract InventoryEnvelopeResponse = new(InventoryEnvelope, ManagementResponseUuids.ProjectRoles, null);
        internal static readonly ResponseContract EnvelopeResponse = new(Envelope, ManagementResponseUuids.ProjectRole, null);
    }

    private static class Tags
    {
        internal static readonly Shape Tag = Object(["color", "createdAt", "createdBy", "createdByActorType", "id", "projectId", "slug", "updatedAt"]);
        internal static readonly Shape Rows = Elements(Tag);
        internal static readonly Shape ListEnvelope = Object(["tags"], ("tags", Rows));
        internal static readonly Shape Envelope = Object(["tag"], ("tag", Tag));
        internal static readonly Shape DetailedTag = Object(["color", "createdAt", "createdBy", "createdByActorType", "id", "name", "projectId", "slug", "updatedAt"]);
        internal static readonly Shape DetailEnvelope = Object(["tag"], ("tag", DetailedTag));

        internal static readonly ResponseContract ListEnvelopeResponse = new(ListEnvelope, ManagementResponseUuids.TagPage, ManagementResponseDates.Tags);
        internal static readonly ResponseContract EnvelopeResponse = new(Envelope, ManagementResponseUuids.TagEnvelope, ManagementResponseDates.TagEnvelope);
        internal static readonly ResponseContract DetailEnvelopeResponse = new(DetailEnvelope, ManagementResponseUuids.TagEnvelope, ManagementResponseDates.TagEnvelope);
    }

    private static class Sharing
    {
        internal static readonly Shape Metadata = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "type", "updatedAt", "userId"]);
        internal static readonly Shape Rows = Elements(Metadata);
        internal static readonly Shape ListPage = Object(["secrets", "totalCount"], ("secrets", Rows));
        internal static readonly Shape Created = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "sharedSecretLink", "type", "updatedAt", "userId"]);
        internal static readonly Shape Details = Object(["accessType", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "isAuthorizedUser", "isPasswordProtected", "lastViewedAt", "name", "orgId", "type", "updatedAt", "userId"]);
        internal static readonly Shape Accessed = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "orgName", "secretValue", "type", "updatedAt", "userId"]);

        internal static readonly ResponseContract ListPageResponse = new(ListPage, ManagementResponseUuids.SharePage, ManagementResponseDates.SharePage);
        internal static readonly ResponseContract CreatedResponse = new(Created, ManagementResponseUuids.Share, ManagementResponseDates.Share);
        internal static readonly ResponseContract MetadataResponse = new(Metadata, ManagementResponseUuids.Share, ManagementResponseDates.Share);
        internal static readonly ResponseContract DetailsResponse = new(Details, ManagementResponseUuids.Share, ManagementResponseDates.Share);
        internal static readonly ResponseContract AccessedResponse = new(Accessed, ManagementResponseUuids.Share, ManagementResponseDates.Share);
    }

    private static class IdentitySearch
    {
        internal static readonly Shape Project = Object(["id", "name", "slug", "type"]);
        internal static readonly Shape Role = Object(["customRoleDescription", "customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange"]);
        internal static readonly Shape Roles = Elements(Role);
        internal static readonly Shape Membership = Object(["createdAt", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "project", "projectId", "roles", "scope", "updatedAt"], ("identity", Identities.LockoutIdentity), ("project", Project), ("roles", Roles));
        internal static readonly Shape Rows = Elements(Membership);
        internal static readonly Shape Page = Object(["identities", "totalCount"], ("identities", Rows));
        internal static readonly Shape Counts = Object(["organization", "project"]);
        internal static readonly Shape CountEnvelope = Object(["counts"], ("counts", Counts));

        internal static readonly ResponseContract PageResponse = new(Page, ManagementResponseUuids.IdentitySearchPage, ManagementResponseDates.IdentitySearchPage);
        internal static readonly ResponseContract CountEnvelopeResponse = new(CountEnvelope, null, null);
    }

    internal static void Validate(string operationId, JsonElement value)
    {
        ResponseContract? contract = operationId switch
        {
            "infisical.delete.v1.additional.privilege.identity" => IdentityPrivileges.MembershipPrivilegeEnvelopeResponse,
            "infisical.get.v1.additional.privilege.identity" => IdentityPrivileges.MembershipPrivilegePageResponse,
            "infisical.patch.v1.additional.privilege.identity" => IdentityPrivileges.MembershipPrivilegeEnvelopeResponse,
            "infisical.get.v1.additional.privilege.identity.by.privilegeSlug" => IdentityPrivileges.MembershipPrivilegeEnvelopeResponse,
            "infisical.post.v1.additional.privilege.identity.permanent" => IdentityPrivileges.MembershipPrivilegeEnvelopeResponse,
            "infisical.post.v1.additional.privilege.identity.temporary" => IdentityPrivileges.MembershipPrivilegeEnvelopeResponse,
            "infisical.get.v1.groups" => Groups.InventoryRowsResponse,
            "infisical.post.v1.groups" => Groups.MutationGroupResponse,
            "infisical.delete.v1.groups.by.id" => Groups.MutationGroupResponse,
            "infisical.get.v1.groups.by.id" => Groups.DetailGroupResponse,
            "infisical.patch.v1.groups.by.id" => Groups.MutationGroupResponse,
            "infisical.get.v1.groups.by.id.machine.identities" => Groups.MachineIdentityPageResponse,
            "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId" => Groups.MachineIdentityMutationResponse,
            "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" => Groups.MachineIdentityMutationResponse,
            "infisical.get.v1.groups.by.id.members" => Groups.MemberPageResponse,
            "infisical.get.v1.groups.by.id.projects" => Groups.ProjectPageResponse,
            "infisical.get.v1.groups.by.id.users" => Groups.UserPageResponse,
            "infisical.delete.v1.groups.by.id.users.by.username" => Groups.UserMutationResponse,
            "infisical.post.v1.groups.by.id.users.by.username" => Groups.UserMutationResponse,
            "infisical.get.v1.identities" => Identities.ListPageResponse,
            "infisical.post.v1.identities" => Identities.CreatedEnvelopeResponse,
            "infisical.delete.v1.identities.by.identityId" => Identities.DeletedEnvelopeResponse,
            "infisical.get.v1.identities.by.identityId" => Identities.DetailEnvelopeResponse,
            "infisical.patch.v1.identities.by.identityId" => Identities.UpdatedEnvelopeResponse,
            "infisical.get.v1.identities.details" => Identities.DetailsEnvelopeResponse,
            "infisical.get.v1.identity.templates" => IdentityTemplates.RowsResponse,
            "infisical.post.v1.identity.templates" => IdentityTemplates.AuthMethodResponse,
            "infisical.delete.v1.identity.templates.by.templateId" => IdentityTemplates.DeleteResponse,
            "infisical.get.v1.identity.templates.by.templateId" => IdentityTemplates.AuthMethodResponse,
            "infisical.patch.v1.identity.templates.by.templateId" => IdentityTemplates.AuthMethodResponse,
            "infisical.post.v1.identity.templates.by.templateId.delete.usage" => IdentityTemplates.DeletedUsageRowsResponse,
            "infisical.get.v1.identity.templates.by.templateId.usage" => IdentityTemplates.UsageRowsResponse,
            "infisical.get.v1.identity.templates.search" => IdentityTemplates.SearchPageResponse,
            "infisical.get.v1.organization.audit.log.settings" => Audit.SettingsEnvelopeResponse,
            "infisical.put.v1.organization.audit.log.settings" => Audit.SettingsEnvelopeResponse,
            "infisical.get.v1.organization.audit.logs" => Audit.EnvelopeResponse,
            "infisical.get.v1.organization.available.groups" => OrganizationAccess.AvailableGroupsResponse,
            "infisical.get.v1.organization.available.identities" => OrganizationAccess.AvailableIdentitiesResponse,
            "infisical.get.v1.organization.roles" => OrganizationRoles.InventoryEnvelopeResponse,
            "infisical.post.v1.organization.roles" => OrganizationRoles.EnvelopeResponse,
            "infisical.delete.v1.organization.roles.by.roleId" => OrganizationRoles.EnvelopeResponse,
            "infisical.get.v1.organization.roles.by.roleId" => OrganizationRoles.EnvelopeResponse,
            "infisical.patch.v1.organization.roles.by.roleId" => OrganizationRoles.EnvelopeResponse,
            "infisical.get.v1.organization.roles.slug.by.roleSlug" => OrganizationRoles.EnvelopeResponse,
            "infisical.get.v1.organizations.memberships.groups" => Memberships.OrganizationGroupPageResponse,
            "infisical.delete.v1.organizations.memberships.groups.by.groupId" => Memberships.RemovedOrganizationGroupEnvelopeResponse,
            "infisical.get.v1.organizations.memberships.groups.by.groupId" => Memberships.OrganizationGroupEnvelopeResponse,
            "infisical.patch.v1.organizations.memberships.groups.by.groupId" => Memberships.OrganizationGroupEnvelopeResponse,
            "infisical.post.v1.organizations.memberships.groups.by.groupId" => Memberships.OrganizationGroupEnvelopeResponse,
            "infisical.get.v1.project.templates" => ProjectTemplates.ListEnvelopeResponse,
            "infisical.post.v1.project.templates" => ProjectTemplates.EnvelopeResponse,
            "infisical.delete.v1.project.templates.by.templateId" => ProjectTemplates.EnvelopeResponse,
            "infisical.get.v1.project.templates.by.templateId" => ProjectTemplates.EnvelopeResponse,
            "infisical.patch.v1.project.templates.by.templateId" => ProjectTemplates.EnvelopeResponse,
            "infisical.get.v1.projects" => Projects.ListEnvelopeResponse,
            "infisical.post.v1.projects" => Projects.DetailEnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId" => Projects.MutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId" => Projects.DetailEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId" => Projects.MutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.audit.log.settings" => Audit.SettingsEnvelopeResponse,
            "infisical.put.v1.projects.by.projectId.audit.log.settings" => Audit.SettingsEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.authorizations" => Projects.AuthorizationEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.environments" => Projects.EnvironmentMutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.environments.by.envId" => Projects.EnvironmentEnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId.environments.by.id" => Projects.EnvironmentMutationEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.environments.by.id" => Projects.EnvironmentMutationEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.environments.by.id.restore" => Projects.EnvironmentMutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug" => Projects.EnvironmentEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.identities" => Identities.ProjectListPageResponse,
            "infisical.post.v1.projects.by.projectId.identities" => Identities.ProjectEnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => Identities.ProjectEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => Identities.ProjectEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => Identities.ProjectEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.integrations" => Projects.IntegrationEnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId.memberships" => Memberships.ProjectUserMutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships" => Memberships.ProjectUserEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.memberships" => Memberships.ProjectUserMutationEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId" => Memberships.UpdatedRolesEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships.available.identities" => OrganizationAccess.AvailableIdentitiesResponse,
            "infisical.post.v1.projects.by.projectId.memberships.details" => Memberships.ProjectUserDetailsEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships.groups" => Memberships.ProjectGroupListResponse,
            "infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId" => Memberships.RemovedProjectGroupEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId" => Memberships.ProjectGroupEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId" => Memberships.UpdatedRolesEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId" => Memberships.ProjectGroupEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships.identities" => Memberships.ProjectIdentityPageResponse,
            "infisical.delete.v1.projects.by.projectId.memberships.identities.by.identityId" => Memberships.ProjectIdentityMutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId" => Memberships.ProjectIdentityEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId" => Memberships.ProjectIdentityMutationEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId" => Memberships.ProjectIdentityMutationEnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.roles" => ProjectRoles.InventoryEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.roles" => ProjectRoles.EnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId" => ProjectRoles.EnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.roles.by.roleId" => ProjectRoles.EnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug" => ProjectRoles.EnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.tags" => Tags.ListEnvelopeResponse,
            "infisical.post.v1.projects.by.projectId.tags" => Tags.EnvelopeResponse,
            "infisical.delete.v1.projects.by.projectId.tags.by.tagId" => Tags.EnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.tags.by.tagId" => Tags.DetailEnvelopeResponse,
            "infisical.patch.v1.projects.by.projectId.tags.by.tagId" => Tags.EnvelopeResponse,
            "infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug" => Tags.DetailEnvelopeResponse,
            "infisical.get.v1.projects.roles.by.roleId" => ProjectRoles.EnvelopeResponse,
            "infisical.get.v1.projects.slug.by.slug" => Projects.DetailedProjectResponse,
            "infisical.get.v1.shared.secrets" => Sharing.ListPageResponse,
            "infisical.post.v1.shared.secrets" => Sharing.CreatedResponse,
            "infisical.delete.v1.shared.secrets.by.id" => Sharing.MetadataResponse,
            "infisical.get.v1.shared.secrets.by.id" => Sharing.DetailsResponse,
            "infisical.post.v1.shared.secrets.by.id.access" => Sharing.AccessedResponse,
            "infisical.post.v2.identities.search" => IdentitySearch.PageResponse,
            "infisical.post.v2.identities.search.count" => IdentitySearch.CountEnvelopeResponse,
            "infisical.get.v2.identity.project.additional.privilege" => IdentityPrivileges.ProjectPrivilegePageResponse,
            "infisical.post.v2.identity.project.additional.privilege" => IdentityPrivileges.ProjectPrivilegeEnvelopeResponse,
            "infisical.delete.v2.identity.project.additional.privilege.by.id" => IdentityPrivileges.ProjectPrivilegeEnvelopeResponse,
            "infisical.get.v2.identity.project.additional.privilege.by.id" => IdentityPrivileges.ProjectPrivilegeEnvelopeResponse,
            "infisical.patch.v2.identity.project.additional.privilege.by.id" => IdentityPrivileges.ProjectPrivilegeEnvelopeResponse,
            "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug" => IdentityPrivileges.ProjectPrivilegeEnvelopeResponse,
            "infisical.delete.v2.organizations.by.organizationId.memberships" => Memberships.OrganizationUserMutationEnvelopeResponse,
            "infisical.get.v2.organizations.by.organizationId.memberships" => Memberships.OrganizationUserPageResponse,
            "infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId" => Memberships.OrganizationUserEnvelopeResponse,
            "infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId" => Memberships.OrganizationUserEnvelopeResponse,
            "infisical.get.v2.organizations.by.orgId.identity.memberships" => Memberships.OrganizationIdentityPageResponse,
            _ => null
        };
        if (contract is null) return;
        Validate(value, contract.Closure, 0);
        if (contract.Uuids is { } uuids) ManagementResponseUuids.Validate(value, uuids, 0);
        if (contract.Dates is { } dates) ManagementResponseDates.Validate(value, dates, 0);
    }

    // Audit rows are isolated by their typed parser before the envelope is validated.
    internal static ResponseContract AuditRow => Audit.RowResponse;

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, AuditRow.Closure, 0);

    private static void Validate(JsonElement value, Shape shape, int depth)
    {
        if (depth > 64) throw new ManagementContractException(SecretStatus.Unknown);
        // Presence and nullability belong to the endpoint's existing typed parser.
        if (value.ValueKind == JsonValueKind.Null) return;
        if (shape.Discriminator is { } discriminator)
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(discriminator, out var tag) ||
                tag.ValueKind != JsonValueKind.String) return;
            foreach (var branch in shape.Branches!)
                if (string.Equals(tag.GetString(), branch.Name, StringComparison.Ordinal))
                {
                    Validate(value, branch.Value, depth + 1);
                    return;
                }
            // The unestablished alternative has no invented closed member set.
            return;
        }
        if (shape.Element is { } element)
        {
            if (value.ValueKind != JsonValueKind.Array) throw new ManagementContractException(SecretStatus.Unknown);
            foreach (var item in value.EnumerateArray()) Validate(item, element, depth + 1);
            return;
        }
        if (value.ValueKind != JsonValueKind.Object) throw new ManagementContractException(SecretStatus.Unknown);
        if (shape.Members is { } members)
            foreach (var property in value.EnumerateObject())
                if (!members.Contains(property.Name, StringComparer.Ordinal))
                    throw new ManagementContractException(SecretStatus.Unknown);
        foreach (var child in shape.Children)
            if (value.TryGetProperty(child.Name, out var nested)) Validate(nested, child.Value, depth + 1);
    }
}
