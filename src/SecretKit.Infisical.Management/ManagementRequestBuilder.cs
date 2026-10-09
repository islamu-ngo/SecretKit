using System.Globalization;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management;

/// <summary>Fixed dispatch table over handwritten Refit request builders, never a raw route executor.</summary>
internal sealed class ManagementRequestBuilder
{
    private readonly IGroupAdministrationApi _groups;
    private readonly IProjectAdministrationApi _projects;
    private readonly IProjectTemplateAdministrationApi _templates;
    private readonly IIdentityAdministrationApi _identities;
    private readonly IMembershipAdministrationApi _memberships;
    private readonly IGovernanceAdministrationApi _governance;
    private readonly IPrivilegeAdministrationApi _privileges;
    private readonly Uri _origin;

    internal ManagementRequestBuilder(HttpClient client)
    {
        _origin = client.BaseAddress!;
        var settings = new RefitSettings
        {
            // Builders do not receive responses. Also prevent a future interface
            // return-type change from creating payload-bearing ApiExceptions.
            ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null)
        };
        _groups = RestService.For<IGroupAdministrationApi>(client, settings);
        _projects = RestService.For<IProjectAdministrationApi>(client, settings);
        _templates = RestService.For<IProjectTemplateAdministrationApi>(client, settings);
        _identities = RestService.For<IIdentityAdministrationApi>(client, settings);
        _memberships = RestService.For<IMembershipAdministrationApi>(client, settings);
        _governance = RestService.For<IGovernanceAdministrationApi>(client, settings);
        _privileges = RestService.For<IPrivilegeAdministrationApi>(client, settings);
    }

    internal async Task<HttpRequestMessage> BuildAsync<T>(ManagementRequest<T> request,
        HttpContent? body, CancellationToken cancellationToken) where T : notnull
    {
        Uri expected = new(_origin, request.Path);
        Dictionary<string, string> query = Query(expected);
        string resource = request.Target.ResourceId!;
        string secondary = request.Target.SecondaryId!;
        string project = request.Target.ProjectId!;
        int offset = query.TryGetValue("offset", out string? offsetText) ? int.Parse(offsetText, CultureInfo.InvariantCulture) : 0;
        int limit = query.TryGetValue("limit", out string? limitText) ? int.Parse(limitText, CultureInfo.InvariantCulture) : 100;
        HttpRequestMessage message = await (request.OperationId switch
        {
            "infisical.get.v1.groups" => _groups.List(cancellationToken),
            "infisical.get.v1.groups.by.id.members" => _groups.Members(resource, offset, limit,
                query["orderBy"], query["orderDirection"], query.GetValueOrDefault("search"),
                query.GetValueOrDefault("memberTypeFilter"), cancellationToken),
            "infisical.get.v1.groups.by.id.projects" => _groups.Projects(resource, offset, limit,
                query["orderBy"], query["orderDirection"], query.GetValueOrDefault("search"),
                query.GetValueOrDefault("filter"), cancellationToken),
            "infisical.get.v1.groups.by.id" => _groups.Get(resource, cancellationToken),
            "infisical.post.v1.groups" => _groups.Create(body!, cancellationToken),
            "infisical.patch.v1.groups.by.id" => _groups.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.groups.by.id" => _groups.Delete(resource, cancellationToken),
            "infisical.get.v1.groups.by.id.machine.identities" => _groups.Identities(resource, offset, limit, cancellationToken),
            "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" => _groups.AddIdentity(resource, secondary, cancellationToken),
            "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId" => _groups.RemoveIdentity(resource, secondary, cancellationToken),
            "infisical.get.v1.groups.by.id.users" => _groups.Users(resource, offset, limit, cancellationToken),
            "infisical.post.v1.groups.by.id.users.by.username" => _groups.AddUser(resource, secondary, cancellationToken),
            "infisical.delete.v1.groups.by.id.users.by.username" => _groups.RemoveUser(resource, secondary, cancellationToken),
            "infisical.get.v1.organization.available.groups" => _groups.AvailableGroups(cancellationToken),
            "infisical.get.v1.organization.available.identities" => _groups.AvailableIdentities(offset, limit, cancellationToken),
            "infisical.get.v1.organization.roles" => _groups.Roles(cancellationToken),
            "infisical.get.v1.organization.roles.by.roleId" => _groups.Role(resource, cancellationToken),
            "infisical.get.v1.organization.roles.slug.by.roleSlug" => _groups.RoleBySlug(resource, cancellationToken),
            "infisical.delete.v1.organization.roles.by.roleId" => _groups.DeleteRole(resource, cancellationToken),

            "infisical.get.v1.projects" => _projects.List(cancellationToken),
            "infisical.get.v1.projects.by.projectId" => _projects.Get(project, cancellationToken),
            "infisical.get.v1.projects.slug.by.slug" => _projects.GetBySlug(resource, cancellationToken),
            "infisical.post.v1.projects" => _projects.Create(body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId" => _projects.Update(project, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId" => _projects.Delete(project, cancellationToken),
            "infisical.post.v1.projects.by.projectId.environments" => _projects.CreateEnvironment(project, body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.environments.by.envId" => _projects.Environment(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.environments.slug.by.envSlug" => _projects.EnvironmentBySlug(project, resource, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.environments.by.id" => _projects.UpdateEnvironment(project, resource, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.environments.by.id" => _projects.DeleteEnvironment(project, resource, query["hardDelete"], cancellationToken),
            "infisical.post.v1.projects.by.projectId.environments.by.id.restore" => _projects.RestoreEnvironment(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.tags" => _projects.Tags(project, cancellationToken),
            "infisical.get.v1.projects.by.projectId.tags.by.tagId" => _projects.Tag(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.tags.slug.by.tagSlug" => _projects.TagBySlug(project, resource, cancellationToken),
            "infisical.post.v1.projects.by.projectId.tags" => _projects.CreateTag(project, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.tags.by.tagId" => _projects.UpdateTag(project, resource, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.tags.by.tagId" => _projects.DeleteTag(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.roles" => _projects.Roles(project, cancellationToken),
            "infisical.get.v1.projects.roles.by.roleId" => _projects.Role(resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug" => _projects.RoleBySlug(project, resource, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId" => _projects.DeleteRole(project, resource, cancellationToken),

            "infisical.get.v1.project.templates" => _templates.List(query["type"], cancellationToken),
            "infisical.get.v1.project.templates.by.templateId" => _templates.Get(resource, cancellationToken),
            "infisical.post.v1.project.templates" => _templates.Create(body!, cancellationToken),
            "infisical.patch.v1.project.templates.by.templateId" => _templates.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.project.templates.by.templateId" => _templates.Delete(resource, cancellationToken),

            "infisical.get.v1.identities" => _identities.List(request.Target.OrganizationId, cancellationToken),
            "infisical.get.v1.identities.by.identityId" => _identities.Get(resource, cancellationToken),
            "infisical.post.v1.identities" => _identities.Create(body!, cancellationToken),
            "infisical.patch.v1.identities.by.identityId" => _identities.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.identities.by.identityId" => _identities.Delete(resource, cancellationToken),
            "infisical.get.v1.identities.details" => _identities.Organization(cancellationToken),
            "infisical.get.v1.projects.by.projectId.identities" => _identities.ProjectIdentities(project, offset, limit, cancellationToken),
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => _identities.ProjectIdentity(project, resource, cancellationToken),
            "infisical.post.v1.projects.by.projectId.identities" => _identities.CreateProjectIdentity(project, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => _identities.UpdateProjectIdentity(project, resource, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => _identities.DeleteProjectIdentity(project, resource, cancellationToken),

            "infisical.get.v2.organizations.by.organizationId.memberships" => _memberships.OrganizationMemberships(request.Target.OrganizationId, cancellationToken),
            "infisical.patch.v2.organizations.by.organizationId.memberships.by.membershipId" => _memberships.UpdateOrganizationMembership(request.Target.OrganizationId, resource, body!, cancellationToken),
            "infisical.delete.v2.organizations.by.organizationId.memberships.by.membershipId" => _memberships.DeleteOrganizationMembership(request.Target.OrganizationId, resource, cancellationToken),
            "infisical.post.v1.projects.by.projectId.memberships.identities.by.identityId" => _memberships.AddIdentity(project, resource, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.memberships.identities.by.identityId" => _memberships.UpdateIdentity(project, resource, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.memberships.identities.by.identityId" => _memberships.RemoveIdentity(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships.identities.by.identityId" => _memberships.Identity(project, resource, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.memberships.groups.by.groupId" => _memberships.RemoveGroup(project, resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships.groups.by.groupId" => _memberships.Group(project, resource, cancellationToken),
            "infisical.post.v1.projects.by.projectId.memberships.groups.by.groupId" => _memberships.AddGroup(project, resource, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.memberships.groups.by.groupId" => _memberships.UpdateGroup(project, resource, body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships.groups" => _memberships.Groups(project, cancellationToken),
            "infisical.delete.v1.organizations.memberships.groups.by.groupId" => _memberships.RemoveOrganizationGroup(resource, cancellationToken),
            "infisical.get.v1.organizations.memberships.groups.by.groupId" => _memberships.OrganizationGroup(resource, cancellationToken),
            "infisical.post.v1.organizations.memberships.groups.by.groupId" => _memberships.AddOrganizationGroup(resource, body!, cancellationToken),
            "infisical.patch.v1.organizations.memberships.groups.by.groupId" => _memberships.UpdateOrganizationGroup(resource, body!, cancellationToken),
            "infisical.get.v1.organizations.memberships.groups" => _memberships.OrganizationGroups(offset, limit, cancellationToken),

            "infisical.get.v1.organization.audit.log.settings" => _governance.OrganizationAuditSettings(cancellationToken),
            "infisical.put.v1.organization.audit.log.settings" => _governance.SetOrganizationAuditSettings(body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.audit.log.settings" => _governance.ProjectAuditSettings(project, cancellationToken),
            "infisical.put.v1.projects.by.projectId.audit.log.settings" => _governance.SetProjectAuditSettings(project, body!, cancellationToken),
            "infisical.get.v1.organization.audit.logs" => _governance.Audit(offset, limit, query["startDate"], query["endDate"], request.Target.ProjectId, cancellationToken),
            "infisical.get.v1.shared.secrets" => _governance.Shares(offset, limit, cancellationToken),
            "infisical.get.v1.shared.secrets.by.id" => _governance.Share(resource, cancellationToken),
            "infisical.delete.v1.shared.secrets.by.id" => _governance.DeleteShare(resource, cancellationToken),
            "infisical.post.v1.shared.secrets" => _governance.CreateShare(body!, cancellationToken),
            "infisical.post.v1.shared.secrets.by.id.access" => _governance.AccessShare(resource, body!, cancellationToken),

            "infisical.get.v2.identity.project.additional.privilege" => _privileges.List(project, resource, cancellationToken),
            "infisical.get.v2.identity.project.additional.privilege.by.id" => _privileges.Get(secondary, cancellationToken),
            "infisical.delete.v2.identity.project.additional.privilege.by.id" => _privileges.Delete(secondary, cancellationToken),
            _ => throw new ManagementContractException(SecretStatus.ContractNotEstablished)
        }).ConfigureAwait(false);

        // Protect the authorization boundary against a mismapped builder, changed
        // parameter escaping, or an unexpected future Refit behavior.
        Uri? actual = message.RequestUri;
        if (actual is not null && !actual.IsAbsoluteUri)
        {
            actual = new Uri(_origin, actual);
            message.RequestUri = actual;
        }
        if (actual is null || actual.Scheme != expected.Scheme ||
            actual.Authority != expected.Authority || actual.AbsolutePath != expected.AbsolutePath ||
            actual.Fragment.Length != 0 || message.Method != request.Method ||
            !Query(actual).OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .SequenceEqual(query.OrderBy(pair => pair.Key, StringComparer.Ordinal)))
        {
            message.Dispose();
            throw new ManagementContractException(SecretStatus.Invalid);
        }
        return message;
    }

    private static Dictionary<string, string> Query(Uri uri)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string component in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = component.Split('=', 2);
            string key = Uri.UnescapeDataString(pair[0]);
            string value = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
            if (!values.TryAdd(key, value)) throw new ManagementContractException(SecretStatus.Invalid);
        }
        return values;
    }
}
