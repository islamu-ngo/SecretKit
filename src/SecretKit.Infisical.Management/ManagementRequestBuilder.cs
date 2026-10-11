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
    private readonly IIdentityTemplateAdministrationApi _identityTemplates;
    private readonly IOrganizationIdentityMembershipApi _organizationIdentityMemberships;
    private readonly IIdentityAdministrationApi _identities;
    private readonly IIdentitySearchApi _identitySearch;
    private readonly IMembershipAdministrationApi _memberships;
    private readonly IGovernanceAdministrationApi _governance;
    private readonly IPrivilegeAdministrationApi _privileges;
    private readonly ILegacyIdentityPrivilegeApi _legacyPrivileges;
    private readonly IIdentityPrivilegeChangeApi _privilegeChanges;
    private readonly IIdentityAuthenticationAdministrationApi _identityAuthentication;
    private readonly IWorkloadIdentityAuthenticationApi _workloadIdentityAuthentication;
    private readonly ICloudIdentityAuthenticationApi _cloudIdentityAuthentication;
    private readonly IExternalIdentityAuthenticationApi _externalIdentityAuthentication;
    private readonly IPostgresSecretRotationApi _postgresRotations;
    private readonly IGatewayAdministrationApi _gateways;
    private readonly IProxiedServiceAdministrationApi _proxiedServices;
    private readonly IMySqlSecretRotationApi _mySqlRotations;
    private readonly IMsSqlSecretRotationApi _msSqlRotations;
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
        _identityTemplates = RestService.For<IIdentityTemplateAdministrationApi>(client, settings);
        _organizationIdentityMemberships = RestService.For<IOrganizationIdentityMembershipApi>(client, settings);
        _identities = RestService.For<IIdentityAdministrationApi>(client, settings);
        _identitySearch = RestService.For<IIdentitySearchApi>(client, settings);
        _memberships = RestService.For<IMembershipAdministrationApi>(client, settings);
        _governance = RestService.For<IGovernanceAdministrationApi>(client, settings);
        _privileges = RestService.For<IPrivilegeAdministrationApi>(client, settings);
        _legacyPrivileges = RestService.For<ILegacyIdentityPrivilegeApi>(client, settings);
        _privilegeChanges = RestService.For<IIdentityPrivilegeChangeApi>(client, settings);
        _identityAuthentication = RestService.For<IIdentityAuthenticationAdministrationApi>(client, settings);
        _workloadIdentityAuthentication = RestService.For<IWorkloadIdentityAuthenticationApi>(client, settings);
        _cloudIdentityAuthentication = RestService.For<ICloudIdentityAuthenticationApi>(client, settings);
        _externalIdentityAuthentication = RestService.For<IExternalIdentityAuthenticationApi>(client, settings);
        _postgresRotations = RestService.For<IPostgresSecretRotationApi>(client, settings);
        _gateways = RestService.For<IGatewayAdministrationApi>(client, settings);
        _proxiedServices = RestService.For<IProxiedServiceAdministrationApi>(client, settings);
        _mySqlRotations = RestService.For<IMySqlSecretRotationApi>(client, settings);
        _msSqlRotations = RestService.For<IMsSqlSecretRotationApi>(client, settings);
    }

    internal async Task<HttpRequestMessage> BuildAsync<T>(ManagementRequest<T> request,
        HttpContent? body, CancellationToken cancellationToken) where T : notnull
    {
        Uri expected = new(_origin, request.Path);
        Dictionary<string, List<string>>? repeatedValues = request.OperationId switch
        {
            "infisical.get.v1.organizations.memberships.groups" => new(StringComparer.Ordinal) { ["roles"] = [] },
            "infisical.get.v1.groups.by.id.members" => new(StringComparer.Ordinal) { ["memberTypeFilter"] = [] },
            "infisical.get.v1.organization.audit.logs" => new(StringComparer.Ordinal) { ["eventClass"] = [], ["eventType"] = [] },
            _ => null
        };
        Dictionary<string, string> query = Query(expected, repeatedValues);
        string resource = request.Target.ResourceId!;
        string secondary = request.Target.SecondaryId!;
        string project = request.Target.ProjectId!;
        int offset = query.TryGetValue("offset", out string? offsetText) ? int.Parse(offsetText, CultureInfo.InvariantCulture) : 0;
        int limit = query.TryGetValue("limit", out string? limitText) ? int.Parse(limitText, CultureInfo.InvariantCulture) : 100;
        HttpRequestMessage message = await (request.OperationId switch
        {
            "infisical.get.v2.secret.rotations.mssql.credentials" =>
                _msSqlRotations.List(query["projectId"], cancellationToken),
            "infisical.post.v2.secret.rotations.mssql.credentials" =>
                _msSqlRotations.Create(body!, cancellationToken),
            "infisical.get.v2.secret.rotations.mssql.credentials.by.rotationId" =>
                _msSqlRotations.Get(resource, cancellationToken),
            "infisical.patch.v2.secret.rotations.mssql.credentials.by.rotationId" =>
                _msSqlRotations.Update(resource, body!, cancellationToken),
            "infisical.delete.v2.secret.rotations.mssql.credentials.by.rotationId" =>
                _msSqlRotations.Delete(resource, query.GetValueOrDefault("deleteSecrets"),
                    query.GetValueOrDefault("revokeGeneratedCredentials"), cancellationToken),
            "infisical.post.v2.secret.rotations.mssql.credentials.by.rotationId.check.credentials" =>
                _msSqlRotations.CheckCredentials(resource, cancellationToken),
            "infisical.get.v2.secret.rotations.mssql.credentials.by.rotationId.generated.credentials" =>
                _msSqlRotations.GeneratedCredentials(resource, cancellationToken),
            "infisical.post.v2.secret.rotations.mssql.credentials.by.rotationId.move" =>
                _msSqlRotations.Move(resource, body!, cancellationToken),
            "infisical.get.v2.secret.rotations.mssql.credentials.rotation.name.by.rotationName" =>
                _msSqlRotations.GetByName(resource, query["projectId"], query["environment"], query["secretPath"], cancellationToken),
            "infisical.get.v2.secret.rotations.mysql.credentials" =>
                _mySqlRotations.List(query["projectId"], cancellationToken),
            "infisical.post.v2.secret.rotations.mysql.credentials" =>
                _mySqlRotations.Create(body!, cancellationToken),
            "infisical.get.v2.secret.rotations.mysql.credentials.by.rotationId" =>
                _mySqlRotations.Get(resource, cancellationToken),
            "infisical.get.v2.secret.rotations.mysql.credentials.rotation.name.by.rotationName" =>
                _mySqlRotations.GetByName(resource, query["projectId"], query["environment"], query["secretPath"], cancellationToken),
            "infisical.patch.v2.secret.rotations.mysql.credentials.by.rotationId" =>
                _mySqlRotations.Update(resource, body!, cancellationToken),
            "infisical.delete.v2.secret.rotations.mysql.credentials.by.rotationId" =>
                _mySqlRotations.Delete(resource, query.GetValueOrDefault("deleteSecrets"),
                    query.GetValueOrDefault("revokeGeneratedCredentials"), cancellationToken),
            "infisical.post.v2.secret.rotations.mysql.credentials.by.rotationId.check.credentials" =>
                _mySqlRotations.CheckCredentials(resource, cancellationToken),
            "infisical.get.v2.secret.rotations.mysql.credentials.by.rotationId.generated.credentials" =>
                _mySqlRotations.GeneratedCredentials(resource, cancellationToken),
            "infisical.post.v2.secret.rotations.mysql.credentials.by.rotationId.move" =>
                _mySqlRotations.Move(resource, body!, cancellationToken),
            "infisical.post.v3.gateways" => _gateways.Create(body!, cancellationToken),
            "infisical.get.v3.gateways.by.gatewayId" => _gateways.Get(resource, cancellationToken),
            "infisical.patch.v3.gateways.by.gatewayId" => _gateways.Update(resource, body!, cancellationToken),
            "infisical.post.v3.gateways.by.gatewayId.token.auth.generate.enrollment.token" =>
                _gateways.GenerateEnrollmentToken(resource, cancellationToken),
            "infisical.get.v1.proxied.services" =>
                _proxiedServices.List(query["projectId"], query["environment"], query.GetValueOrDefault("secretPath"), cancellationToken),
            "infisical.post.v1.proxied.services" => _proxiedServices.Create(body!, cancellationToken),
            "infisical.get.v1.proxied.services.by.serviceId" => _proxiedServices.Get(resource, cancellationToken),
            "infisical.patch.v1.proxied.services.by.serviceId" => _proxiedServices.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.proxied.services.by.serviceId" => _proxiedServices.Delete(resource, cancellationToken),
            "infisical.get.v1.proxied.services.slug.by.name" =>
                _proxiedServices.GetByName(resource, query["projectId"], query["environment"],
                    query.GetValueOrDefault("secretPath"), cancellationToken),
            "infisical.get.v2.secret.rotations.postgres.credentials" =>
                _postgresRotations.List(query["projectId"], cancellationToken),
            "infisical.post.v2.secret.rotations.postgres.credentials" =>
                _postgresRotations.Create(body!, cancellationToken),
            "infisical.get.v2.secret.rotations.postgres.credentials.by.rotationId" =>
                _postgresRotations.Get(resource, cancellationToken),
            "infisical.get.v2.secret.rotations.postgres.credentials.rotation.name.by.rotationName" =>
                _postgresRotations.GetByName(resource, query["projectId"], query["environment"], query["secretPath"], cancellationToken),
            "infisical.patch.v2.secret.rotations.postgres.credentials.by.rotationId" =>
                _postgresRotations.Update(resource, body!, cancellationToken),
            "infisical.delete.v2.secret.rotations.postgres.credentials.by.rotationId" =>
                _postgresRotations.Delete(resource, query.GetValueOrDefault("deleteSecrets"),
                    query.GetValueOrDefault("revokeGeneratedCredentials"), cancellationToken),
            "infisical.post.v2.secret.rotations.postgres.credentials.by.rotationId.check.credentials" =>
                _postgresRotations.CheckCredentials(resource, cancellationToken),
            "infisical.get.v2.secret.rotations.postgres.credentials.by.rotationId.generated.credentials" =>
                _postgresRotations.GeneratedCredentials(resource, cancellationToken),
            "infisical.post.v2.secret.rotations.postgres.credentials.by.rotationId.move" =>
                _postgresRotations.Move(resource, body!, cancellationToken),
            "infisical.get.v2.secret.rotations" =>
                _postgresRotations.ListCatalog(query["projectId"], cancellationToken),
            "infisical.get.v2.secret.rotations.options" =>
                _postgresRotations.Options(cancellationToken),
            "infisical.get.v1.auth.aws.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.GetAws(resource, cancellationToken),
            "infisical.post.v1.auth.aws.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.AttachAws(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.aws.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.UpdateAws(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.aws.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.DeleteAws(resource, cancellationToken),
            "infisical.get.v1.auth.azure.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.GetAzure(resource, cancellationToken),
            "infisical.post.v1.auth.azure.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.AttachAzure(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.azure.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.UpdateAzure(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.azure.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.DeleteAzure(resource, cancellationToken),
            "infisical.get.v1.auth.gcp.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.GetGcp(resource, cancellationToken),
            "infisical.post.v1.auth.gcp.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.AttachGcp(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.gcp.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.UpdateGcp(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.gcp.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.DeleteGcp(resource, cancellationToken),
            "infisical.get.v1.auth.alicloud.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.GetAliCloud(resource, cancellationToken),
            "infisical.post.v1.auth.alicloud.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.AttachAliCloud(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.alicloud.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.UpdateAliCloud(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.alicloud.auth.identities.by.identityId" =>
                _cloudIdentityAuthentication.DeleteAliCloud(resource, cancellationToken),
            "infisical.get.v1.auth.ldap.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.GetLdap(resource, cancellationToken),
            "infisical.post.v1.auth.ldap.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.AttachLdap(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.ldap.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.UpdateLdap(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.ldap.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.DeleteLdap(resource, cancellationToken),
            "infisical.post.v1.auth.ldap.auth.identities.by.identityId.clear.lockouts" =>
                _externalIdentityAuthentication.ClearLdapLockouts(resource, cancellationToken),
            "infisical.get.v1.auth.oci.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.GetOci(resource, cancellationToken),
            "infisical.post.v1.auth.oci.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.AttachOci(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.oci.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.UpdateOci(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.oci.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.DeleteOci(resource, cancellationToken),
            "infisical.get.v1.auth.spiffe.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.GetSpiffe(resource, cancellationToken),
            "infisical.post.v1.auth.spiffe.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.AttachSpiffe(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.spiffe.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.UpdateSpiffe(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.spiffe.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.DeleteSpiffe(resource, cancellationToken),
            "infisical.post.v1.auth.spiffe.auth.identities.by.identityId.refresh.bundle" =>
                _externalIdentityAuthentication.RefreshSpiffeBundle(resource, cancellationToken),
            "infisical.get.v1.auth.tls.cert.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.GetTlsCert(resource, cancellationToken),
            "infisical.post.v1.auth.tls.cert.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.AttachTlsCert(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.tls.cert.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.UpdateTlsCert(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.tls.cert.auth.identities.by.identityId" =>
                _externalIdentityAuthentication.DeleteTlsCert(resource, cancellationToken),
            "infisical.get.v1.auth.jwt.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.GetJwt(resource, cancellationToken),
            "infisical.post.v1.auth.jwt.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.AttachJwt(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.jwt.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.UpdateJwt(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.jwt.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.DeleteJwt(resource, cancellationToken),
            "infisical.get.v1.auth.oidc.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.GetOidc(resource, cancellationToken),
            "infisical.post.v1.auth.oidc.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.AttachOidc(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.oidc.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.UpdateOidc(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.oidc.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.DeleteOidc(resource, cancellationToken),
            "infisical.get.v1.auth.kubernetes.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.GetKubernetes(resource, cancellationToken),
            "infisical.post.v1.auth.kubernetes.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.AttachKubernetes(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.kubernetes.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.UpdateKubernetes(resource, body!, cancellationToken),
            "infisical.delete.v1.auth.kubernetes.auth.identities.by.identityId" =>
                _workloadIdentityAuthentication.DeleteKubernetes(resource, cancellationToken),
            "infisical.post.v1.auth.universal.auth.identities.by.identityId" =>
                _identityAuthentication.AttachUniversal(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.universal.auth.identities.by.identityId" =>
                _identityAuthentication.UpdateUniversal(resource, body!, cancellationToken),
            "infisical.get.v1.auth.universal.auth.identities.by.identityId" =>
                _identityAuthentication.Universal(resource, cancellationToken),
            "infisical.delete.v1.auth.universal.auth.identities.by.identityId" =>
                _identityAuthentication.DeleteUniversal(resource, cancellationToken),
            "infisical.post.v1.auth.universal.auth.identities.by.identityId.client.secrets" =>
                _identityAuthentication.CreateSecret(resource, body!, cancellationToken),
            "infisical.get.v1.auth.universal.auth.identities.by.identityId.client.secrets" =>
                _identityAuthentication.Secrets(resource, cancellationToken),
            "infisical.get.v1.auth.universal.auth.identities.by.identityId.client.secrets.by.clientSecretId" =>
                _identityAuthentication.Secret(resource, secondary, cancellationToken),
            "infisical.post.v1.auth.universal.auth.identities.by.identityId.client.secrets.by.clientSecretId.revoke" =>
                _identityAuthentication.RevokeSecret(resource, secondary, cancellationToken),
            "infisical.post.v1.auth.universal.auth.identities.by.identityId.clear.lockouts" =>
                _identityAuthentication.ClearLockouts(resource, cancellationToken),
            "infisical.post.v1.auth.token.auth.identities.by.identityId" =>
                _identityAuthentication.AttachToken(resource, body!, cancellationToken),
            "infisical.patch.v1.auth.token.auth.identities.by.identityId" =>
                _identityAuthentication.UpdateToken(resource, body!, cancellationToken),
            "infisical.get.v1.auth.token.auth.identities.by.identityId" =>
                _identityAuthentication.Token(resource, cancellationToken),
            "infisical.delete.v1.auth.token.auth.identities.by.identityId" =>
                _identityAuthentication.DeleteToken(resource, cancellationToken),
            "infisical.post.v1.auth.token.auth.identities.by.identityId.tokens" =>
                _identityAuthentication.CreateAccessToken(resource, body!, cancellationToken),
            "infisical.get.v1.auth.token.auth.identities.by.identityId.tokens" =>
                _identityAuthentication.AccessTokens(resource, cancellationToken),
            "infisical.get.v1.auth.token.auth.tokens.by.tokenId" =>
                _identityAuthentication.AccessToken(resource, cancellationToken),
            "infisical.patch.v1.auth.token.auth.tokens.by.tokenId" =>
                _identityAuthentication.RenameAccessToken(resource, body!, cancellationToken),
            "infisical.post.v1.auth.token.auth.tokens.by.tokenId.revoke" =>
                _identityAuthentication.RevokeAccessToken(resource, cancellationToken),
            "infisical.get.v1.additional.privilege.identity" =>
                _legacyPrivileges.List(query["identityId"], query["projectSlug"], cancellationToken),
            "infisical.get.v1.additional.privilege.identity.by.privilegeSlug" =>
                _legacyPrivileges.Get(Uri.UnescapeDataString(expected.Segments[^1]),
                    query["identityId"], query["projectSlug"], cancellationToken),
            "infisical.delete.v1.additional.privilege.identity" => _legacyPrivileges.Delete(body!, cancellationToken),
            "infisical.patch.v1.additional.privilege.identity" => _privilegeChanges.UpdateLegacy(body!, cancellationToken),
            "infisical.post.v1.additional.privilege.identity.permanent" => _privilegeChanges.CreatePermanentLegacy(body!, cancellationToken),
            "infisical.post.v1.additional.privilege.identity.temporary" => _privilegeChanges.CreateTemporaryLegacy(body!, cancellationToken),
            "infisical.post.v2.identity.project.additional.privilege" => _privilegeChanges.CreateProject(body!, cancellationToken),
            "infisical.patch.v2.identity.project.additional.privilege.by.id" =>
                _privilegeChanges.UpdateProject(Uri.UnescapeDataString(expected.Segments[^1]), body!, cancellationToken),
            "infisical.get.v2.identity.project.additional.privilege.slug.by.privilegeSlug" =>
                _privilegeChanges.GetProjectBySlug(Uri.UnescapeDataString(expected.Segments[^1]),
                    query["identityId"], query["projectSlug"], cancellationToken),
            "infisical.post.v2.identities.search" => _identitySearch.Search(body!, cancellationToken),
            "infisical.post.v2.identities.search.count" => _identitySearch.Count(body!, cancellationToken),
            "infisical.get.v2.organizations.by.orgId.identity.memberships" =>
                _organizationIdentityMemberships.List(request.Target.OrganizationId, offset, limit,
                    query["orderBy"], query["orderDirection"], query.GetValueOrDefault("search"), cancellationToken),
            "infisical.get.v1.groups" => _groups.List(cancellationToken),
            "infisical.get.v1.groups.by.id.members" => _groups.Members(resource, offset, limit,
                query["orderBy"], query["orderDirection"], query.GetValueOrDefault("search"),
                repeatedValues!["memberTypeFilter"] is { Count: > 0 } members ? members.ToArray() : null, cancellationToken),
            "infisical.get.v1.groups.by.id.projects" => _groups.Projects(resource, offset, limit,
                query["orderBy"], query["orderDirection"], query.GetValueOrDefault("search"),
                query.GetValueOrDefault("filter"), cancellationToken),
            "infisical.get.v1.groups.by.id" => _groups.Get(resource, cancellationToken),
            "infisical.post.v1.groups" => _groups.Create(body!, cancellationToken),
            "infisical.patch.v1.groups.by.id" => _groups.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.groups.by.id" => _groups.Delete(resource, cancellationToken),
            "infisical.get.v1.groups.by.id.machine.identities" => _groups.Identities(resource, offset, limit,
                query.GetValueOrDefault("filter"), query.GetValueOrDefault("search"), cancellationToken),
            "infisical.post.v1.groups.by.id.machine.identities.by.machineIdentityId" => _groups.AddIdentity(resource, secondary, cancellationToken),
            "infisical.delete.v1.groups.by.id.machine.identities.by.machineIdentityId" => _groups.RemoveIdentity(resource, secondary, cancellationToken),
            "infisical.get.v1.groups.by.id.users" => _groups.Users(resource, offset, limit,
                query.GetValueOrDefault("filter"), query.GetValueOrDefault("search"), query.GetValueOrDefault("username"), cancellationToken),
            "infisical.post.v1.groups.by.id.users.by.username" => _groups.AddUser(resource, secondary, cancellationToken),
            "infisical.delete.v1.groups.by.id.users.by.username" => _groups.RemoveUser(resource, secondary, cancellationToken),
            "infisical.get.v1.organization.available.groups" => _groups.AvailableGroups(cancellationToken),
            "infisical.get.v1.organization.available.identities" => _groups.AvailableIdentities(offset, limit, query.GetValueOrDefault("identityName"), cancellationToken),
            "infisical.get.v1.organization.roles" => _groups.Roles(cancellationToken),
            "infisical.post.v1.organization.roles" => _groups.CreateRole(body!, cancellationToken),
            "infisical.patch.v1.organization.roles.by.roleId" => _groups.UpdateRole(resource, body!, cancellationToken),
            "infisical.get.v1.organization.roles.by.roleId" => _groups.Role(resource, cancellationToken),
            "infisical.get.v1.organization.roles.slug.by.roleSlug" => _groups.RoleBySlug(resource, cancellationToken),
            "infisical.delete.v1.organization.roles.by.roleId" => _groups.DeleteRole(resource, cancellationToken),

            "infisical.get.v1.projects" => _projects.List(query.GetValueOrDefault("type"),
                query.GetValueOrDefault("includeRoles"), cancellationToken),
            "infisical.get.v1.projects.by.projectId" => _projects.Get(project, cancellationToken),
            "infisical.get.v1.projects.by.projectId.authorizations" => _projects.Authorizations(project, cancellationToken),
            "infisical.get.v1.projects.by.projectId.integrations" => _projects.Integrations(project, cancellationToken),
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
            "infisical.post.v1.projects.by.projectId.roles" => _projects.CreateRole(project, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.roles.by.roleId" => _projects.UpdateRole(project, resource, body!, cancellationToken),
            "infisical.get.v1.projects.roles.by.roleId" => _projects.Role(resource, cancellationToken),
            "infisical.get.v1.projects.by.projectId.roles.slug.by.roleSlug" => _projects.RoleBySlug(project, resource, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.roles.by.roleId" => _projects.DeleteRole(project, resource, cancellationToken),

            "infisical.get.v1.project.templates" => _templates.List(query.GetValueOrDefault("type"), cancellationToken),
            "infisical.get.v1.project.templates.by.templateId" => _templates.Get(resource, cancellationToken),
            "infisical.post.v1.project.templates" => _templates.Create(body!, cancellationToken),
            "infisical.patch.v1.project.templates.by.templateId" => _templates.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.project.templates.by.templateId" => _templates.Delete(resource, cancellationToken),

            "infisical.get.v1.identity.templates" => _identityTemplates.List(query["authMethod"], cancellationToken),
            "infisical.get.v1.identity.templates.search" => _identityTemplates.Search(offset, limit, query.GetValueOrDefault("search"), cancellationToken),
            "infisical.get.v1.identity.templates.by.templateId" => _identityTemplates.Get(resource, cancellationToken),
            "infisical.post.v1.identity.templates" => _identityTemplates.Create(body!, cancellationToken),
            "infisical.patch.v1.identity.templates.by.templateId" => _identityTemplates.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.identity.templates.by.templateId" => _identityTemplates.Delete(resource, cancellationToken),
            "infisical.get.v1.identity.templates.by.templateId.usage" => _identityTemplates.Usage(resource, cancellationToken),
            "infisical.post.v1.identity.templates.by.templateId.delete.usage" => _identityTemplates.DeleteUsage(resource, body!, cancellationToken),

            "infisical.get.v1.identities" => _identities.List(request.Target.OrganizationId, cancellationToken),
            "infisical.get.v1.identities.by.identityId" => _identities.Get(resource, cancellationToken),
            "infisical.post.v1.identities" => _identities.Create(body!, cancellationToken),
            "infisical.patch.v1.identities.by.identityId" => _identities.Update(resource, body!, cancellationToken),
            "infisical.delete.v1.identities.by.identityId" => _identities.Delete(resource, cancellationToken),
            "infisical.get.v1.identities.details" => _identities.Organization(cancellationToken),
            "infisical.get.v1.projects.by.projectId.identities" => _identities.ProjectIdentities(project, offset, limit, query.GetValueOrDefault("search"), cancellationToken),
            "infisical.get.v1.projects.by.projectId.identities.by.identityId" => _identities.ProjectIdentity(project, resource, cancellationToken),
            "infisical.post.v1.projects.by.projectId.identities" => _identities.CreateProjectIdentity(project, body!, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.identities.by.identityId" => _identities.UpdateProjectIdentity(project, resource, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.identities.by.identityId" => _identities.DeleteProjectIdentity(project, resource, cancellationToken),

            "infisical.post.v1.projects.by.projectId.memberships" => _memberships.InviteProjectMembers(project, body!, cancellationToken),
            "infisical.delete.v1.projects.by.projectId.memberships" => _memberships.RemoveProjectMembers(project, body!, cancellationToken),
            "infisical.delete.v2.organizations.by.organizationId.memberships" => _memberships.DeleteOrganizationMemberships(request.Target.OrganizationId, body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships" => _memberships.ProjectMemberships(project, cancellationToken),
            "infisical.patch.v1.projects.by.projectId.memberships.by.membershipId" => _memberships.UpdateProjectMembership(project, resource, body!, cancellationToken),
            "infisical.post.v1.projects.by.projectId.memberships.details" => _memberships.ProjectMembershipDetails(project, body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships.available.identities" => _memberships.AvailableProjectIdentities(project, offset, limit, query.GetValueOrDefault("identityName"), cancellationToken),
            "infisical.get.v1.projects.by.projectId.memberships.identities" => _memberships.ProjectIdentityMemberships(project, offset, limit, query.GetValueOrDefault("identityName"), query.GetValueOrDefault("roles"), cancellationToken),
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
            "infisical.get.v1.organizations.memberships.groups" => _memberships.OrganizationGroups(offset, limit,
                query.GetValueOrDefault("orderBy"), query.GetValueOrDefault("orderDirection"),
                query.GetValueOrDefault("search"), repeatedValues!["roles"] is { Count: > 0 } roles ? roles.ToArray() : null, cancellationToken),

            "infisical.get.v1.organization.audit.log.settings" => _governance.OrganizationAuditSettings(cancellationToken),
            "infisical.put.v1.organization.audit.log.settings" => _governance.SetOrganizationAuditSettings(body!, cancellationToken),
            "infisical.get.v1.projects.by.projectId.audit.log.settings" => _governance.ProjectAuditSettings(project, cancellationToken),
            "infisical.put.v1.projects.by.projectId.audit.log.settings" => _governance.SetProjectAuditSettings(project, body!, cancellationToken),
            "infisical.get.v1.organization.audit.logs" => _governance.Audit(offset, limit, query["startDate"], query["endDate"],
                request.Target.ProjectId, query.GetValueOrDefault("actor"), query.GetValueOrDefault("actorType"),
                query.GetValueOrDefault("environment"),
                repeatedValues!["eventClass"] is { Count: > 0 } classes ? classes.ToArray() : null,
                query.GetValueOrDefault("eventMetadata"),
                repeatedValues!["eventType"] is { Count: > 0 } types ? types.ToArray() : null,
                query.GetValueOrDefault("secretKey"), query.GetValueOrDefault("secretPath"),
                query.GetValueOrDefault("userAgentType"), cancellationToken),
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
        Dictionary<string, List<string>>? actualRepeatedValues = repeatedValues?.ToDictionary(
            pair => pair.Key, _ => new List<string>(), StringComparer.Ordinal);
        if (actual is null || actual.Scheme != expected.Scheme ||
            actual.Authority != expected.Authority || actual.AbsolutePath != expected.AbsolutePath ||
            actual.Fragment.Length != 0 || message.Method != request.Method ||
            !Query(actual, actualRepeatedValues).OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .SequenceEqual(query.OrderBy(pair => pair.Key, StringComparer.Ordinal)) ||
            repeatedValues is not null && repeatedValues.Any(pair => !pair.Value.SequenceEqual(actualRepeatedValues![pair.Key])))
        {
            message.Dispose();
            throw new ManagementContractException(SecretStatus.Invalid);
        }
        return message;
    }

    private static Dictionary<string, string> Query(Uri uri, Dictionary<string, List<string>>? repeatedValues)
    {
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string component in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] pair = component.Split('=', 2);
            string key = Uri.UnescapeDataString(pair[0]);
            string value = pair.Length == 2 ? Uri.UnescapeDataString(pair[1]) : "";
            if (repeatedValues is not null && repeatedValues.TryGetValue(key, out List<string>? repeated))
            {
                repeated.Add(value);
                continue;
            }
            if (!values.TryAdd(key, value)) throw new ManagementContractException(SecretStatus.Invalid);
        }
        return values;
    }
}
