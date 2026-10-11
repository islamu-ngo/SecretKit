using Refit;

namespace SecretKit.Infisical.Management;

// Handwritten, fixed native endpoints. HttpContent contains only a bounded body
// built by an internal typed factory; no caller can construct these interfaces.
// Refit builds requests only; the controlled client owns dispatch and bounded responses.
internal interface IGroupAdministrationApi
{
    [Get("/api/v1/groups/{group}/members")]
    Task<HttpRequestMessage> Members(string group, int offset, int limit, string orderBy,
        string orderDirection, string? search, [Query(CollectionFormat.Multi)] string[]? memberTypeFilter, CancellationToken cancellationToken);
    [Get("/api/v1/groups/{group}/projects")]
    Task<HttpRequestMessage> Projects(string group, int offset, int limit, string orderBy,
        string orderDirection, string? search, string? filter, CancellationToken cancellationToken);
    [Get("/api/v1/groups")]
    Task<HttpRequestMessage> List(CancellationToken cancellationToken);
    [Post("/api/v1/groups")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/groups/{id}")]
    Task<HttpRequestMessage> Get(string id, CancellationToken cancellationToken);
    [Patch("/api/v1/groups/{id}")]
    Task<HttpRequestMessage> Update(string id, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/groups/{id}")]
    Task<HttpRequestMessage> Delete(string id, CancellationToken cancellationToken);
    [Get("/api/v1/groups/{id}/machine-identities")]
    Task<HttpRequestMessage> Identities(string id, int offset, int limit, string? filter, string? search, CancellationToken cancellationToken);
    [Post("/api/v1/groups/{id}/machine-identities/{identity}")]
    Task<HttpRequestMessage> AddIdentity(string id, string identity, CancellationToken cancellationToken);
    [Delete("/api/v1/groups/{id}/machine-identities/{identity}")]
    Task<HttpRequestMessage> RemoveIdentity(string id, string identity, CancellationToken cancellationToken);
    [Get("/api/v1/groups/{id}/users")]
    Task<HttpRequestMessage> Users(string id, int offset, int limit, string? filter, string? search, string? username, CancellationToken cancellationToken);
    [Post("/api/v1/groups/{id}/users/{username}")]
    Task<HttpRequestMessage> AddUser(string id, string username, CancellationToken cancellationToken);
    [Delete("/api/v1/groups/{id}/users/{username}")]
    Task<HttpRequestMessage> RemoveUser(string id, string username, CancellationToken cancellationToken);
    [Get("/api/v1/organization/available-groups")]
    Task<HttpRequestMessage> AvailableGroups(CancellationToken cancellationToken);
    [Get("/api/v1/organization/available-identities")]
    Task<HttpRequestMessage> AvailableIdentities(int offset, int limit, string? identityName, CancellationToken cancellationToken);
    [Get("/api/v1/organization/roles")]
    Task<HttpRequestMessage> Roles(CancellationToken cancellationToken);
    [Post("/api/v1/organization/roles")]
    Task<HttpRequestMessage> CreateRole([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/organization/roles/{roleId}")]
    Task<HttpRequestMessage> UpdateRole(string roleId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/organization/roles/{id}")]
    Task<HttpRequestMessage> Role(string id, CancellationToken cancellationToken);
    [Get("/api/v1/organization/roles/slug/{slug}")]
    Task<HttpRequestMessage> RoleBySlug(string slug, CancellationToken cancellationToken);
    [Delete("/api/v1/organization/roles/{id}")]
    Task<HttpRequestMessage> DeleteRole(string id, CancellationToken cancellationToken);
}

internal interface IProjectAdministrationApi
{
    [Get("/api/v1/projects")]
    Task<HttpRequestMessage> List(string? type, string? includeRoles, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}")]
    Task<HttpRequestMessage> Get(string project, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/authorizations")]
    Task<HttpRequestMessage> Authorizations(string project, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/integrations")]
    Task<HttpRequestMessage> Integrations(string project, CancellationToken cancellationToken);
    [Get("/api/v1/projects/slug/{slug}")]
    Task<HttpRequestMessage> GetBySlug(string slug, CancellationToken cancellationToken);
    [Post("/api/v1/projects")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}")]
    Task<HttpRequestMessage> Update(string project, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}")]
    Task<HttpRequestMessage> Delete(string project, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/environments")]
    Task<HttpRequestMessage> CreateEnvironment(string project, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/environments/{id}")]
    Task<HttpRequestMessage> Environment(string project, string id, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/environments/slug/{slug}")]
    Task<HttpRequestMessage> EnvironmentBySlug(string project, string slug, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/environments/{id}")]
    Task<HttpRequestMessage> UpdateEnvironment(string project, string id, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/environments/{id}")]
    Task<HttpRequestMessage> DeleteEnvironment(string project, string id, string hardDelete, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/environments/{id}/restore")]
    Task<HttpRequestMessage> RestoreEnvironment(string project, string id, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/tags")]
    Task<HttpRequestMessage> Tags(string project, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/tags/{id}")]
    Task<HttpRequestMessage> Tag(string project, string id, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/tags/slug/{slug}")]
    Task<HttpRequestMessage> TagBySlug(string project, string slug, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/tags")]
    Task<HttpRequestMessage> CreateTag(string project, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/tags/{id}")]
    Task<HttpRequestMessage> UpdateTag(string project, string id, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/tags/{id}")]
    Task<HttpRequestMessage> DeleteTag(string project, string id, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/roles")]
    Task<HttpRequestMessage> Roles(string project, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{projectId}/roles")]
    Task<HttpRequestMessage> CreateRole(string projectId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{projectId}/roles/{roleId}")]
    Task<HttpRequestMessage> UpdateRole(string projectId, string roleId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/projects/roles/{id}")]
    Task<HttpRequestMessage> Role(string id, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/roles/slug/{slug}")]
    Task<HttpRequestMessage> RoleBySlug(string project, string slug, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/roles/{id}")]
    Task<HttpRequestMessage> DeleteRole(string project, string id, CancellationToken cancellationToken);
}

internal interface IProjectTemplateAdministrationApi
{
    [Get("/api/v1/project-templates")]
    Task<HttpRequestMessage> List(string? type, CancellationToken cancellationToken);
    [Get("/api/v1/project-templates/{templateId}")]
    Task<HttpRequestMessage> Get(string templateId, CancellationToken cancellationToken);
    [Post("/api/v1/project-templates")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/project-templates/{templateId}")]
    Task<HttpRequestMessage> Update(string templateId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/project-templates/{templateId}")]
    Task<HttpRequestMessage> Delete(string templateId, CancellationToken cancellationToken);
}

internal interface IIdentityTemplateAdministrationApi
{
    [Get("/api/v1/identity-templates")]
    Task<HttpRequestMessage> List(string authMethod, CancellationToken cancellationToken);
    [Get("/api/v1/identity-templates/search")]
    Task<HttpRequestMessage> Search(int offset, int limit, string? search, CancellationToken cancellationToken);
    [Get("/api/v1/identity-templates/{templateId}")]
    Task<HttpRequestMessage> Get(string templateId, CancellationToken cancellationToken);
    [Post("/api/v1/identity-templates")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/identity-templates/{templateId}")]
    Task<HttpRequestMessage> Update(string templateId, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/identity-templates/{templateId}")]
    Task<HttpRequestMessage> Delete(string templateId, CancellationToken cancellationToken);
    [Get("/api/v1/identity-templates/{templateId}/usage")]
    Task<HttpRequestMessage> Usage(string templateId, CancellationToken cancellationToken);
    [Post("/api/v1/identity-templates/{templateId}/delete-usage")]
    Task<HttpRequestMessage> DeleteUsage(string templateId, [Body] HttpContent body, CancellationToken cancellationToken);
}

internal interface IIdentityAdministrationApi
{
    [Get("/api/v1/identities")]
    Task<HttpRequestMessage> List(string orgId, CancellationToken cancellationToken);
    [Get("/api/v1/identities/{identity}")]
    Task<HttpRequestMessage> Get(string identity, CancellationToken cancellationToken);
    [Post("/api/v1/identities")]
    Task<HttpRequestMessage> Create([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/identities/{identity}")]
    Task<HttpRequestMessage> Update(string identity, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/identities/{identity}")]
    Task<HttpRequestMessage> Delete(string identity, CancellationToken cancellationToken);
    [Get("/api/v1/identities/details")]
    Task<HttpRequestMessage> Organization(CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/identities")]
    Task<HttpRequestMessage> ProjectIdentities(string project, int offset, int limit, string? search, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/identities/{identity}")]
    Task<HttpRequestMessage> ProjectIdentity(string project, string identity, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/identities")]
    Task<HttpRequestMessage> CreateProjectIdentity(string project, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/identities/{identity}")]
    Task<HttpRequestMessage> UpdateProjectIdentity(string project, string identity, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/identities/{identity}")]
    Task<HttpRequestMessage> DeleteProjectIdentity(string project, string identity, CancellationToken cancellationToken);
}

internal interface IMembershipAdministrationApi
{
    [Post("/api/v1/projects/{project}/memberships")]
    Task<HttpRequestMessage> InviteProjectMembers(string project, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/memberships")]
    Task<HttpRequestMessage> RemoveProjectMembers(string project, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Delete("/api/v2/organizations/{organizationId}/memberships")]
    Task<HttpRequestMessage> DeleteOrganizationMemberships(string organizationId, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships")]
    Task<HttpRequestMessage> ProjectMemberships(string project, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/memberships/{membership}")]
    Task<HttpRequestMessage> UpdateProjectMembership(string project, string membership,
        [Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/memberships/details")]
    Task<HttpRequestMessage> ProjectMembershipDetails(string project, [Body] HttpContent body,
        CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships/available-identities")]
    Task<HttpRequestMessage> AvailableProjectIdentities(string project, int offset, int limit,
        string? identityName, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships/identities")]
    Task<HttpRequestMessage> ProjectIdentityMemberships(string project, int offset, int limit,
        string? identityName, string? roles, CancellationToken cancellationToken);
    [Get("/api/v2/organizations/{organizationId}/memberships")]
    Task<HttpRequestMessage> OrganizationMemberships(string organizationId, CancellationToken cancellationToken);
    [Patch("/api/v2/organizations/{organizationId}/memberships/{membershipId}")]
    Task<HttpRequestMessage> UpdateOrganizationMembership(string organizationId, string membershipId,
        [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v2/organizations/{organizationId}/memberships/{membershipId}")]
    Task<HttpRequestMessage> DeleteOrganizationMembership(string organizationId, string membershipId,
        CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/memberships/identities/{identity}")]
    Task<HttpRequestMessage> AddIdentity(string project, string identity, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/memberships/identities/{identity}")]
    Task<HttpRequestMessage> UpdateIdentity(string project, string identity, [Body] HttpContent body, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/memberships/identities/{identity}")]
    Task<HttpRequestMessage> RemoveIdentity(string project, string identity, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships/identities/{identity}")]
    Task<HttpRequestMessage> Identity(string project, string identity, CancellationToken cancellationToken);
    [Delete("/api/v1/projects/{project}/memberships/groups/{group}")]
    Task<HttpRequestMessage> RemoveGroup(string project, string group, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships/groups/{group}")]
    Task<HttpRequestMessage> Group(string project, string group, CancellationToken cancellationToken);
    [Post("/api/v1/projects/{project}/memberships/groups/{group}")]
    Task<HttpRequestMessage> AddGroup(string project, string group, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/projects/{project}/memberships/groups/{group}")]
    Task<HttpRequestMessage> UpdateGroup(string project, string group, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/memberships/groups")]
    Task<HttpRequestMessage> Groups(string project, CancellationToken cancellationToken);
    [Delete("/api/v1/organizations/memberships/groups/{group}")]
    Task<HttpRequestMessage> RemoveOrganizationGroup(string group, CancellationToken cancellationToken);
    [Get("/api/v1/organizations/memberships/groups/{group}")]
    Task<HttpRequestMessage> OrganizationGroup(string group, CancellationToken cancellationToken);
    [Post("/api/v1/organizations/memberships/groups/{group}")]
    Task<HttpRequestMessage> AddOrganizationGroup(string group, [Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v1/organizations/memberships/groups/{group}")]
    Task<HttpRequestMessage> UpdateOrganizationGroup(string group, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/organizations/memberships/groups")]
    Task<HttpRequestMessage> OrganizationGroups(int offset, int limit, string? orderBy, string? orderDirection,
        string? search, [Query(CollectionFormat.Multi)] string[]? roles, CancellationToken cancellationToken);
}

internal interface IGovernanceAdministrationApi
{
    [Get("/api/v1/organization/audit-log-settings")]
    Task<HttpRequestMessage> OrganizationAuditSettings(CancellationToken cancellationToken);
    [Put("/api/v1/organization/audit-log-settings")]
    Task<HttpRequestMessage> SetOrganizationAuditSettings([Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/projects/{project}/audit-log-settings")]
    Task<HttpRequestMessage> ProjectAuditSettings(string project, CancellationToken cancellationToken);
    [Put("/api/v1/projects/{project}/audit-log-settings")]
    Task<HttpRequestMessage> SetProjectAuditSettings(string project, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v1/organization/audit-logs")]
    Task<HttpRequestMessage> Audit(int offset, int limit, string startDate, string endDate, string? projectId,
        string? actor, string? actorType, string? environment,
        [Query(CollectionFormat.Multi)] string[]? eventClass, string? eventMetadata,
        [Query(CollectionFormat.Multi)] string[]? eventType, string? secretKey, string? secretPath,
        string? userAgentType, CancellationToken cancellationToken);
    [Get("/api/v1/shared-secrets")]
    Task<HttpRequestMessage> Shares(int offset, int limit, CancellationToken cancellationToken);
    [Get("/api/v1/shared-secrets/{id}")]
    Task<HttpRequestMessage> Share(string id, CancellationToken cancellationToken);
    [Delete("/api/v1/shared-secrets/{id}")]
    Task<HttpRequestMessage> DeleteShare(string id, CancellationToken cancellationToken);
    [Post("/api/v1/shared-secrets")]
    Task<HttpRequestMessage> CreateShare([Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v1/shared-secrets/{id}/access")]
    Task<HttpRequestMessage> AccessShare(string id, [Body] HttpContent body, CancellationToken cancellationToken);
}

internal interface IPrivilegeAdministrationApi
{
    [Get("/api/v2/identity-project-additional-privilege")]
    Task<HttpRequestMessage> List(string projectId, string identityId, CancellationToken cancellationToken);
    [Get("/api/v2/identity-project-additional-privilege/{id}")]
    Task<HttpRequestMessage> Get(string id, CancellationToken cancellationToken);
    [Delete("/api/v2/identity-project-additional-privilege/{id}")]
    Task<HttpRequestMessage> Delete(string id, CancellationToken cancellationToken);
}

internal interface IIdentityPrivilegeChangeApi
{
    [Patch("/api/v1/additional-privilege/identity")]
    Task<HttpRequestMessage> UpdateLegacy([Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v1/additional-privilege/identity/permanent")]
    Task<HttpRequestMessage> CreatePermanentLegacy([Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v1/additional-privilege/identity/temporary")]
    Task<HttpRequestMessage> CreateTemporaryLegacy([Body] HttpContent body, CancellationToken cancellationToken);
    [Post("/api/v2/identity-project-additional-privilege")]
    Task<HttpRequestMessage> CreateProject([Body] HttpContent body, CancellationToken cancellationToken);
    [Patch("/api/v2/identity-project-additional-privilege/{id}")]
    Task<HttpRequestMessage> UpdateProject(string id, [Body] HttpContent body, CancellationToken cancellationToken);
    [Get("/api/v2/identity-project-additional-privilege/slug/{privilegeSlug}")]
    Task<HttpRequestMessage> GetProjectBySlug(string privilegeSlug, [AliasAs("identityId")] string identityId,
        [AliasAs("projectSlug")] string projectSlug, CancellationToken cancellationToken);
}
