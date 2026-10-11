using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

// Closed member sets from the admitted public response field contracts in
// docs/internal/providers/infisical-operations.json. No runtime manifest loading.
internal static class ManagementResponseContracts
{
    private sealed record Shape(string[]? Members, (string Name, Shape Value)[] Children,
        Shape? Element = null, string? Discriminator = null, (string Name, Shape Value)[]? Branches = null);

    private static Shape Object(string[]? members, params (string Name, Shape Value)[] children) => new(members, children);
    private static Shape Elements(Shape element) => new(null, [], element);
    private static Shape Branch(string discriminator, params (string Name, Shape Value)[] branches) =>
        new(null, [], Discriminator: discriminator, Branches: branches);

    private static readonly Shape Shape0 = Object(["action", "conditions", "inverted", "subject"]);
    private static readonly Shape Shape1 = Elements(Shape0);
    private static readonly Shape Shape2 = Object(["createdAt", "id", "isTemporary", "permissions", "projectMembershipId", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"], ("permissions", Shape1));
    private static readonly Shape Shape3 = Object(["privilege"], ("privilege", Shape2));
    private static readonly Shape Shape4 = Elements(Shape2);
    private static readonly Shape Shape5 = Object(["privileges"], ("privileges", Shape4));
    private static readonly Shape Shape6 = Object(["createdAt", "id", "name", "orgId", "role", "roleId", "slug", "updatedAt"]);
    private static readonly Shape Shape7 = Elements(Shape6);
    private static readonly Shape Shape8 = Object(["createdAt", "id", "name", "orgId", "slug", "updatedAt"]);
    private static readonly Shape Shape9 = Object(["createdAt", "customRoleSlug", "id", "name", "orgId", "role", "roleId", "slug", "updatedAt"]);
    private static readonly Shape Shape10 = Object(["id", "isPartOfGroup", "joinedGroupAt", "name"]);
    private static readonly Shape Shape11 = Elements(Shape10);
    private static readonly Shape Shape12 = Object(["machineIdentities", "totalCount"], ("machineIdentities", Shape11));
    private static readonly Shape Shape13 = Object(["id"]);
    private static readonly Shape Shape14 = Object(["id", "name"]);
    private static readonly Shape Shape15 = Object(["id", "joinedGroupAt", "machineIdentity", "type"], ("machineIdentity", Shape14));
    private static readonly Shape Shape16 = Object(["email", "firstName", "id", "lastName", "username"]);
    private static readonly Shape Shape17 = Object(["id", "joinedGroupAt", "type", "user"], ("user", Shape16));
    private static readonly Shape Shape18 = Branch("type", ("machineIdentity", Shape15), ("user", Shape17));
    private static readonly Shape Shape19 = Elements(Shape18);
    private static readonly Shape Shape20 = Object(["members", "totalCount"], ("members", Shape19));
    private static readonly Shape Shape21 = Object(["description", "id", "joinedGroupAt", "name", "slug", "type"]);
    private static readonly Shape Shape22 = Elements(Shape21);
    private static readonly Shape Shape23 = Object(["projects", "totalCount"], ("projects", Shape22));
    private static readonly Shape Shape24 = Object(["email", "firstName", "id", "isPartOfGroup", "joinedGroupAt", "lastName", "username"]);
    private static readonly Shape Shape25 = Elements(Shape24);
    private static readonly Shape Shape26 = Object(["totalCount", "users"], ("users", Shape25));
    private static readonly Shape Shape27 = Object(["description", "id", "name", "permissions", "slug"]);
    private static readonly Shape Shape28 = Object(["authMethods", "hasDeleteProtection", "id", "name"]);
    private static readonly Shape Shape29 = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "role", "roleId", "updatedAt"], ("customRole", Shape27), ("identity", Shape28));
    private static readonly Shape Shape30 = Elements(Shape29);
    private static readonly Shape Shape31 = Object(["identities", "totalCount"], ("identities", Shape30));
    private static readonly Shape Shape32 = Object(["id", "key", "value"]);
    private static readonly Shape Shape33 = Elements(Shape32);
    private static readonly Shape Shape34 = Object(["authMethod", "authMethods", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Shape33));
    private static readonly Shape Shape35 = Object(["identity"], ("identity", Shape34));
    private static readonly Shape Shape36 = Object(["authMethod", "createdAt", "hasDeleteProtection", "id", "name", "orgId", "projectId", "updatedAt"]);
    private static readonly Shape Shape37 = Object(["identity"], ("identity", Shape36));
    private static readonly Shape Shape38 = Object(["activeLockoutAuthMethods", "authMethods", "hasDeleteProtection", "id", "name", "orgId"]);
    private static readonly Shape Shape39 = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "metadata", "orgId", "role", "roleId", "updatedAt"], ("customRole", Shape27), ("identity", Shape38), ("metadata", Shape33));
    private static readonly Shape Shape40 = Object(["identity"], ("identity", Shape39));
    private static readonly Shape Shape41 = Object(["authMethod", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Shape33));
    private static readonly Shape Shape42 = Object(["identity"], ("identity", Shape41));
    private static readonly Shape Shape43 = Object(["id", "name", "slug"]);
    private static readonly Shape Shape44 = Object(["organization"], ("organization", Shape43));
    private static readonly Shape Shape45 = Object(["identityDetails"], ("identityDetails", Shape44));
    private static readonly Shape Shape46 = Object(["allowedAudience", "caCert", "gatewayId", "gatewayPoolId", "hasTokenReviewerJwt", "kubernetesHost", "tokenReviewMode", "verifyTlsCertificate"]);
    private static readonly Shape Shape47 = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", Shape46));
    private static readonly Shape Shape48 = Object(["bindDN", "hasBindPass", "ldapCaCertificate", "searchBase", "url"]);
    private static readonly Shape Shape49 = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", Shape48));
    private static readonly Shape Shape50 = Object(["boundAudiences", "boundIssuer", "caCert", "oidcDiscoveryUrl"]);
    private static readonly Shape Shape51 = Object(["authMethod", "createdAt", "id", "name", "orgId", "templateFields", "updatedAt"], ("templateFields", Shape50));
    private static readonly Shape Shape52 = Branch("authMethod", ("kubernetes", Shape47), ("ldap", Shape49), ("oidc", Shape51));
    private static readonly Shape Shape53 = Elements(Shape52);
    private static readonly Shape Shape54 = Object(["message"]);
    private static readonly Shape Shape55 = Object(["authId", "identityId", "identityName"]);
    private static readonly Shape Shape56 = Elements(Shape55);
    private static readonly Shape Shape57 = Object(["identityId", "identityName"]);
    private static readonly Shape Shape58 = Elements(Shape57);
    private static readonly Shape Shape59 = Object(["templates", "totalCount"], ("templates", Shape53));
    private static readonly Shape Shape60 = Object(["eventClass", "isEnabled"]);
    private static readonly Shape Shape61 = Elements(Shape60);
    private static readonly Shape Shape62 = Object(["eventClasses", "shouldUseNewPrivilegeSystem"], ("eventClasses", Shape61));
    private static readonly Shape Shape63 = Object(["auditLogSettings"], ("auditLogSettings", Shape62));
    private static readonly Shape Shape64 = Object(["auditLogs"]);
    private static readonly Shape Shape65 = Elements(Shape43);
    private static readonly Shape Shape66 = Object(["groups"], ("groups", Shape65));
    private static readonly Shape Shape67 = Elements(Shape14);
    private static readonly Shape Shape68 = Object(["identities"], ("identities", Shape67));
    private static readonly Shape Shape69 = Object(["createdAt", "description", "id", "name", "orgId", "slug", "updatedAt"]);
    private static readonly Shape Shape70 = Elements(Shape69);
    private static readonly Shape Shape71 = Object(["roles"], ("roles", Shape70));
    private static readonly Shape Shape72 = Object(["createdAt", "description", "id", "name", "orgId", "permissions", "slug", "updatedAt"], ("permissions", Shape1));
    private static readonly Shape Shape73 = Object(["role"], ("role", Shape72));
    private static readonly Shape Shape74 = Object(["id", "name", "orgId", "slug"]);
    private static readonly Shape Shape75 = Object(["createdAt", "customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
    private static readonly Shape Shape76 = Elements(Shape75);
    private static readonly Shape Shape77 = Object(["createdAt", "group", "groupId", "id", "roles", "updatedAt"], ("group", Shape74), ("roles", Shape76));
    private static readonly Shape Shape78 = Elements(Shape77);
    private static readonly Shape Shape79 = Object(["groupMemberships", "totalCount"], ("groupMemberships", Shape78));
    private static readonly Shape Shape80 = Object(["createdAt", "groupId", "id", "orgId", "updatedAt"]);
    private static readonly Shape Shape81 = Object(["groupMembership"], ("groupMembership", Shape80));
    private static readonly Shape Shape82 = Object(["groupMembership"], ("groupMembership", Shape77));
    private static readonly Shape Shape83 = Object(["name", "position", "slug"]);
    private static readonly Shape Shape84 = Elements(Shape83);
    private static readonly Shape Shape85 = Object(["groupSlug", "roles"]);
    private static readonly Shape Shape86 = Elements(Shape85);
    private static readonly Shape Shape87 = Object(["identityId", "identityName", "roles"]);
    private static readonly Shape Shape88 = Elements(Shape87);
    private static readonly Shape Shape89 = Object(["name", "roles"]);
    private static readonly Shape Shape90 = Elements(Shape89);
    private static readonly Shape Shape91 = Object(["name", "permissions", "slug"], ("permissions", Shape1));
    private static readonly Shape Shape92 = Elements(Shape91);
    private static readonly Shape Shape93 = Object(["roles", "username"]);
    private static readonly Shape Shape94 = Elements(Shape93);
    private static readonly Shape Shape95 = Object(["createdAt", "description", "environments", "groups", "id", "identities", "name", "orgId", "projectManagedIdentities", "roles", "type", "updatedAt", "users"], ("environments", Shape84), ("groups", Shape86), ("identities", Shape88), ("projectManagedIdentities", Shape90), ("roles", Shape92), ("users", Shape94));
    private static readonly Shape Shape96 = Elements(Shape95);
    private static readonly Shape Shape97 = Object(["projectTemplates"], ("projectTemplates", Shape96));
    private static readonly Shape Shape98 = Object(["projectTemplate"], ("projectTemplate", Shape95));
    private static readonly Shape Shape99 = Object(["id", "name", "type"]);
    private static readonly Shape Shape100 = Object(["email", "firstName", "id", "lastName", "type", "username"]);
    private static readonly Shape Shape101 = Branch("type", ("identity", Shape99), ("user", Shape100));
    private static readonly Shape Shape102 = Object(["deleteAfter", "deletedBy", "id", "name", "slug", "softDeletedAt"], ("deletedBy", Shape101));
    private static readonly Shape Shape103 = Elements(Shape102);
    private static readonly Shape Shape104 = Object(["createdAt", "description", "id", "name", "permissions", "projectId", "slug", "updatedAt", "version"]);
    private static readonly Shape Shape105 = Elements(Shape104);
    private static readonly Shape Shape106 = Object(["_id", "auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "deletedEnvironments", "description", "enforceEncryptedSecretManagerSecretMetadata", "environments", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "roles", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"], ("deletedEnvironments", Shape103), ("environments", Shape65), ("roles", Shape105));
    private static readonly Shape Shape107 = Elements(Shape106);
    private static readonly Shape Shape108 = Object(["projects"], ("projects", Shape107));
    private static readonly Shape Shape109 = Object(["_id", "auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "deletedEnvironments", "description", "enforceEncryptedSecretManagerSecretMetadata", "environments", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"], ("deletedEnvironments", Shape103), ("environments", Shape65));
    private static readonly Shape Shape110 = Object(["project"], ("project", Shape109));
    private static readonly Shape Shape111 = Object(["auditLogsRetentionDays", "autoCapitalization", "createdAt", "defaultProduct", "description", "enforceEncryptedSecretManagerSecretMetadata", "hasDeleteProtection", "id", "isLegacyAdditionalPrivilegesEnabled", "kmsCertificateKeyId", "kmsSecretManagerKeyId", "name", "orgId", "pitVersionLimit", "secretBlindIndexEnabled", "secretDetectionIgnoreValues", "secretSharing", "showSnapshotsLegacy", "slug", "type", "updatedAt", "upgradeStatus", "version"]);
    private static readonly Shape Shape112 = Object(["project"], ("project", Shape111));
    private static readonly Shape Shape113 = Object(["accountId", "createdAt", "id", "integration", "metadata", "namespace", "projectId", "teamId", "updatedAt", "url"]);
    private static readonly Shape Shape114 = Elements(Shape113);
    private static readonly Shape Shape115 = Object(["authorizations"], ("authorizations", Shape114));
    private static readonly Shape Shape116 = Object(["createdAt", "deleteAfter", "deletedByIdentityId", "deletedByUserId", "id", "name", "position", "projectId", "slug", "softDeletedAt", "updatedAt"]);
    private static readonly Shape Shape117 = Object(["environment", "message", "projectId"], ("environment", Shape116));
    private static readonly Shape Shape118 = Object(["environment"], ("environment", Shape116));
    private static readonly Shape Shape119 = Object(["activeLockoutAuthMethods", "authMethods", "createdAt", "hasDeleteProtection", "id", "metadata", "name", "orgId", "projectId", "updatedAt"], ("metadata", Shape33));
    private static readonly Shape Shape120 = Elements(Shape119);
    private static readonly Shape Shape121 = Object(["identities", "totalCount"], ("identities", Shape120));
    private static readonly Shape Shape122 = Object(["identity"], ("identity", Shape119));
    private static readonly Shape Shape123 = Object(["app", "appId", "createdAt", "envId", "environment", "id", "integration", "integrationAuthId", "isActive", "isSynced", "lastSyncJobId", "lastUsed", "metadata", "owner", "path", "region", "scope", "secretPath", "syncMessage", "targetEnvironment", "targetEnvironmentId", "targetService", "targetServiceId", "updatedAt", "url"], ("environment", Shape43));
    private static readonly Shape Shape124 = Elements(Shape123);
    private static readonly Shape Shape125 = Object(["integrations"], ("integrations", Shape124));
    private static readonly Shape Shape126 = Object(["createdAt", "id", "projectId", "updatedAt", "userId"]);
    private static readonly Shape Shape127 = Elements(Shape126);
    private static readonly Shape Shape128 = Object(["memberships"], ("memberships", Shape127));
    private static readonly Shape Shape129 = Object(["customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange"]);
    private static readonly Shape Shape130 = Elements(Shape129);
    private static readonly Shape Shape131 = Object(["authMethods", "email", "firstName", "id", "isEmailVerified", "lastName", "publicKey", "username"]);
    private static readonly Shape Shape132 = Object(["createdAt", "id", "projectId", "roles", "user", "userId"], ("roles", Shape130), ("user", Shape131));
    private static readonly Shape Shape133 = Elements(Shape132);
    private static readonly Shape Shape134 = Object(["memberships"], ("memberships", Shape133));
    private static readonly Shape Shape135 = Object(["createdAt", "customRoleId", "id", "isTemporary", "projectMembershipId", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
    private static readonly Shape Shape136 = Elements(Shape135);
    private static readonly Shape Shape137 = Object(["roles"], ("roles", Shape136));
    private static readonly Shape Shape138 = Object(["id", "projectId", "roles", "user", "userId"], ("roles", Shape130), ("user", Shape131));
    private static readonly Shape Shape139 = Object(["membership"], ("membership", Shape138));
    private static readonly Shape Shape140 = Object(["createdAt", "group", "groupId", "id", "projectId", "roles", "updatedAt"], ("group", Shape74), ("roles", Shape76));
    private static readonly Shape Shape141 = Elements(Shape140);
    private static readonly Shape Shape142 = Object(["groupMemberships"], ("groupMemberships", Shape141));
    private static readonly Shape Shape143 = Object(["createdAt", "groupId", "id", "projectId", "updatedAt"]);
    private static readonly Shape Shape144 = Object(["groupMembership"], ("groupMembership", Shape143));
    private static readonly Shape Shape145 = Object(["groupMembership"], ("groupMembership", Shape140));
    private static readonly Shape Shape146 = Object(["activeLockoutAuthMethods", "authMethods", "id", "name", "orgId", "projectId"]);
    private static readonly Shape Shape147 = Object(["createdAt", "id", "identity", "identityId", "roles", "updatedAt"], ("identity", Shape146), ("roles", Shape130));
    private static readonly Shape Shape148 = Elements(Shape147);
    private static readonly Shape Shape149 = Object(["identityMemberships", "totalCount"], ("identityMemberships", Shape148));
    private static readonly Shape Shape150 = Object(["createdAt", "id", "identityId", "projectId", "updatedAt"]);
    private static readonly Shape Shape151 = Object(["identityMembership"], ("identityMembership", Shape150));
    private static readonly Shape Shape152 = Object(["authMethods", "id", "metadata", "name", "orgId", "projectId"], ("metadata", Shape33));
    private static readonly Shape Shape153 = Object(["createdAt", "id", "identity", "lastLoginAuthMethod", "lastLoginTime", "roles", "updatedAt"], ("identity", Shape152), ("roles", Shape130));
    private static readonly Shape Shape154 = Object(["identityMembership"], ("identityMembership", Shape153));
    private static readonly Shape Shape155 = Object(["createdAt", "description", "id", "name", "projectId", "slug", "updatedAt"]);
    private static readonly Shape Shape156 = Elements(Shape155);
    private static readonly Shape Shape157 = Object(["roles"], ("roles", Shape156));
    private static readonly Shape Shape158 = Object(["createdAt", "description", "id", "name", "permissions", "projectId", "slug", "updatedAt"], ("permissions", Shape1));
    private static readonly Shape Shape159 = Object(["role"], ("role", Shape158));
    private static readonly Shape Shape160 = Object(["color", "createdAt", "createdBy", "createdByActorType", "id", "projectId", "slug", "updatedAt"]);
    private static readonly Shape Shape161 = Elements(Shape160);
    private static readonly Shape Shape162 = Object(["tags"], ("tags", Shape161));
    private static readonly Shape Shape163 = Object(["tag"], ("tag", Shape160));
    private static readonly Shape Shape164 = Object(["color", "createdAt", "createdBy", "createdByActorType", "id", "name", "projectId", "slug", "updatedAt"]);
    private static readonly Shape Shape165 = Object(["tag"], ("tag", Shape164));
    private static readonly Shape Shape166 = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "type", "updatedAt", "userId"]);
    private static readonly Shape Shape167 = Elements(Shape166);
    private static readonly Shape Shape168 = Object(["secrets", "totalCount"], ("secrets", Shape167));
    private static readonly Shape Shape169 = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "sharedSecretLink", "type", "updatedAt", "userId"]);
    private static readonly Shape Shape170 = Object(["accessType", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "isAuthorizedUser", "isPasswordProtected", "lastViewedAt", "name", "orgId", "type", "updatedAt", "userId"]);
    private static readonly Shape Shape171 = Object(["accessType", "allowExternalEmails", "authorizedEmails", "createdAt", "expiresAfterViews", "expiresAt", "id", "identityId", "lastViewedAt", "name", "orgId", "orgName", "secretValue", "type", "updatedAt", "userId"]);
    private static readonly Shape Shape172 = Object(["id", "name", "slug", "type"]);
    private static readonly Shape Shape173 = Object(["customRoleDescription", "customRoleId", "customRoleName", "customRoleSlug", "id", "isTemporary", "role", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange"]);
    private static readonly Shape Shape174 = Elements(Shape173);
    private static readonly Shape Shape175 = Object(["createdAt", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "project", "projectId", "roles", "scope", "updatedAt"], ("identity", Shape38), ("project", Shape172), ("roles", Shape174));
    private static readonly Shape Shape176 = Elements(Shape175);
    private static readonly Shape Shape177 = Object(["identities", "totalCount"], ("identities", Shape176));
    private static readonly Shape Shape178 = Object(["organization", "project"]);
    private static readonly Shape Shape179 = Object(["counts"], ("counts", Shape178));
    private static readonly Shape Shape180 = Object(["createdAt", "id", "isTemporary", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"]);
    private static readonly Shape Shape181 = Elements(Shape180);
    private static readonly Shape Shape182 = Object(["privileges"], ("privileges", Shape181));
    private static readonly Shape Shape183 = Object(["createdAt", "id", "isTemporary", "permissions", "slug", "temporaryAccessEndTime", "temporaryAccessStartTime", "temporaryMode", "temporaryRange", "updatedAt"], ("permissions", Shape1));
    private static readonly Shape Shape184 = Object(["privilege"], ("privilege", Shape183));
    private static readonly Shape Shape185 = Object(["createdAt", "id", "inviteEmail", "isActive", "lastInvitedAt", "lastLoginAuthMethod", "lastLoginTime", "orgId", "projectFavorites", "role", "roleId", "status", "updatedAt", "userId"]);
    private static readonly Shape Shape186 = Elements(Shape185);
    private static readonly Shape Shape187 = Object(["memberships"], ("memberships", Shape186));
    private static readonly Shape Shape188 = Object(["id", "inviteEmail", "isActive", "lastInvitedAt", "lastLoginAuthMethod", "lastLoginTime", "orgId", "projectFavorites", "role", "roleId", "status", "user", "userId"], ("user", Shape131));
    private static readonly Shape Shape189 = Elements(Shape188);
    private static readonly Shape Shape190 = Object(["users"], ("users", Shape189));
    private static readonly Shape Shape191 = Object(["membership"], ("membership", Shape185));
    private static readonly Shape Shape192 = Object(["authMethods", "id", "name", "orgId"]);
    private static readonly Shape Shape193 = Object(["createdAt", "customRole", "id", "identity", "identityId", "lastLoginAuthMethod", "lastLoginTime", "orgId", "role", "roleId", "updatedAt"], ("customRole", Shape27), ("identity", Shape192));
    private static readonly Shape Shape194 = Elements(Shape193);
    private static readonly Shape Shape195 = Object(["identityMemberships", "totalCount"], ("identityMemberships", Shape194));
    private static readonly Shape Shape196 = Object(["metadata", "type"]);
    private static readonly Shape Shape197 = Object(["class", "metadata", "type"]);
    private static readonly Shape Shape198 = Object(["actor", "createdAt", "event", "expiresAt", "id", "ipAddress", "orgId", "projectId", "projectName", "updatedAt", "userAgent", "userAgentType"], ("actor", Shape196), ("event", Shape197));

    internal static void Validate(string operationId, JsonElement value)
    {
        Shape? shape = operationId switch
        {
            "infisical.delete.v1.additional.privilege.identity" => Shape3,
            "infisical.get.v1.additional.privilege.identity" => Shape5,
            "infisical.patch.v1.additional.privilege.identity" => Shape3,
            "infisical.get.v1.additional.privilege.identity.by.privilegeSlug" => Shape3,
            "infisical.post.v1.additional.privilege.identity.permanent" => Shape3,
            "infisical.post.v1.additional.privilege.identity.temporary" => Shape3,
            "infisical.get.v1.groups" => Shape7,
            "infisical.post.v1.groups" => Shape8,
            "infisical.delete.v1.groups.by.id" => Shape8,
            "infisical.get.v1.groups.by.id" => Shape9,
            "infisical.patch.v1.groups.by.id" => Shape8,
            "infisical.get.v1.groups.by.id.machine.identities" => Shape12,
            "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId" => Shape13,
            "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" => Shape13,
            "infisical.get.v1.groups.by.id.members" => Shape20,
            "infisical.get.v1.groups.by.id.projects" => Shape23,
            "infisical.get.v1.groups.by.id.users" => Shape26,
            "infisical.delete.v1.groups.by.id.users.by.username" => Shape16,
            "infisical.post.v1.groups.by.id.users.by.username" => Shape16,
            "infisical.get.v1.identities" => Shape31,
            "infisical.post.v1.identities" => Shape35,
            "infisical.delete.v1.identities.by.identityId" => Shape37,
            "infisical.get.v1.identities.by.identityId" => Shape40,
            "infisical.patch.v1.identities.by.identityId" => Shape42,
            "infisical.get.v1.identities.details" => Shape45,
            "infisical.get.v1.identity.templates" => Shape53,
            "infisical.post.v1.identity.templates" => Shape52,
            "infisical.delete.v1.identity.templates.by.templateId" => Shape54,
            "infisical.get.v1.identity.templates.by.templateId" => Shape52,
            "infisical.patch.v1.identity.templates.by.templateId" => Shape52,
            "infisical.post.v1.identity.templates.by.templateId.delete.usage" => Shape56,
            "infisical.get.v1.identity.templates.by.templateId.usage" => Shape58,
            "infisical.get.v1.identity.templates.search" => Shape59,
            "infisical.get.v1.organization.audit.log.settings" => Shape63,
            "infisical.put.v1.organization.audit.log.settings" => Shape63,
            "infisical.get.v1.organization.audit.logs" => Shape64,
            "infisical.get.v1.organization.available.groups" => Shape66,
            "infisical.get.v1.organization.available.identities" => Shape68,
            "infisical.get.v1.organization.roles" => Shape71,
            "infisical.post.v1.organization.roles" => Shape73,
            "infisical.delete.v1.organization.roles.by.roleId" => Shape73,
            "infisical.get.v1.organization.roles.by.roleId" => Shape73,
            "infisical.patch.v1.organization.roles.by.roleId" => Shape73,
            "infisical.get.v1.organization.roles.slug.by.roleSlug" => Shape73,
            "infisical.get.v1.organizations.memberships.groups" => Shape79,
            "infisical.delete.v1.organizations.memberships.groups.by.groupId" => Shape81,
            "infisical.get.v1.organizations.memberships.groups.by.groupId" => Shape82,
            "infisical.patch.v1.organizations.memberships.groups.by.groupId" => Shape82,
            "infisical.post.v1.organizations.memberships.groups.by.groupId" => Shape82,
            "infisical.get.v1.project.templates" => Shape97,
            "infisical.post.v1.project.templates" => Shape98,
            "infisical.delete.v1.project.templates.by.templateId" => Shape98,
            "infisical.get.v1.project.templates.by.templateId" => Shape98,
            "infisical.patch.v1.project.templates.by.templateId" => Shape98,
            "infisical.get.v1.projects" => Shape108,
            "infisical.post.v1.projects" => Shape110,
            "infisical.delete.v1.projects.by.projectId" => Shape112,
            "infisical.get.v1.projects.by.projectId" => Shape110,
            "infisical.patch.v1.projects.by.projectId" => Shape112,
            "infisical.get.v1.projects.by.projectId.audit.log.settings" => Shape63,
            "infisical.put.v1.projects.by.projectId.audit.log.settings" => Shape63,
            "infisical.get.v1.projects.by.projectId.authorizations" => Shape115,
            "infisical.post.v1.projects.by.projectId.environments" => Shape117,
            "infisical.get.v1.projects.by.projectId.environments.by.envId" => Shape118,
            "infisical.delete.v1.projects.by.projectId.environments.by.id" => Shape117,
            "infisical.patch.v1.projects.by.projectId.environments.by.id" => Shape117,
            "infisical.post.v1.projects.by.projectId.environments.by.id.restore" => Shape117,
            "infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug" => Shape118,
            "infisical.get.v1.projects.by.projectId.identities" => Shape121,
            "infisical.post.v1.projects.by.projectId.identities" => Shape122,
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => Shape122,
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => Shape122,
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => Shape122,
            "infisical.get.v1.projects.by.projectId.integrations" => Shape125,
            "infisical.delete.v1.projects.by.projectId.memberships" => Shape128,
            "infisical.get.v1.projects.by.projectId.memberships" => Shape134,
            "infisical.post.v1.projects.by.projectId.memberships" => Shape128,
            "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId" => Shape137,
            "infisical.get.v1.projects.by.projectId.memberships.available.identities" => Shape68,
            "infisical.post.v1.projects.by.projectId.memberships.details" => Shape139,
            "infisical.get.v1.projects.by.projectId.memberships.groups" => Shape142,
            "infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape144,
            "infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape145,
            "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape137,
            "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId" => Shape145,
            "infisical.get.v1.projects.by.projectId.memberships.identities" => Shape149,
            "infisical.delete.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape151,
            "infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape154,
            "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape151,
            "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId" => Shape151,
            "infisical.get.v1.projects.by.projectId.roles" => Shape157,
            "infisical.post.v1.projects.by.projectId.roles" => Shape159,
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId" => Shape159,
            "infisical.patch.v1.projects.by.projectId.roles.by.roleId" => Shape159,
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug" => Shape159,
            "infisical.get.v1.projects.by.projectId.tags" => Shape162,
            "infisical.post.v1.projects.by.projectId.tags" => Shape163,
            "infisical.delete.v1.projects.by.projectId.tags.by.tagId" => Shape163,
            "infisical.get.v1.projects.by.projectId.tags.by.tagId" => Shape165,
            "infisical.patch.v1.projects.by.projectId.tags.by.tagId" => Shape163,
            "infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug" => Shape165,
            "infisical.get.v1.projects.roles.by.roleId" => Shape159,
            "infisical.get.v1.projects.slug.by.slug" => Shape109,
            "infisical.get.v1.shared.secrets" => Shape168,
            "infisical.post.v1.shared.secrets" => Shape169,
            "infisical.delete.v1.shared.secrets.by.id" => Shape166,
            "infisical.get.v1.shared.secrets.by.id" => Shape170,
            "infisical.post.v1.shared.secrets.by.id.access" => Shape171,
            "infisical.post.v2.identities.search" => Shape177,
            "infisical.post.v2.identities.search.count" => Shape179,
            "infisical.get.v2.identity.project.additional.privilege" => Shape182,
            "infisical.post.v2.identity.project.additional.privilege" => Shape184,
            "infisical.delete.v2.identity.project.additional.privilege.by.id" => Shape184,
            "infisical.get.v2.identity.project.additional.privilege.by.id" => Shape184,
            "infisical.patch.v2.identity.project.additional.privilege.by.id" => Shape184,
            "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug" => Shape184,
            "infisical.delete.v2.organizations.by.organizationId.memberships" => Shape187,
            "infisical.get.v2.organizations.by.organizationId.memberships" => Shape190,
            "infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape191,
            "infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId" => Shape191,
            "infisical.get.v2.organizations.by.orgId.identity.memberships" => Shape195,
            _ => null
        };
        if (shape is not null) Validate(value, shape, 0);
    }

    internal static void ValidateAuditRow(JsonElement value) => Validate(value, Shape198, 0);

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
