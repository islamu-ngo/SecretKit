using System.Net;
using System.Net.Http.Headers;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class RefitRouteTests
{
    private const string Group = "22222222-2222-4222-8222-222222222222";
    private const string Role = "33333333-3333-4333-8333-333333333333";
    private const string AuditProject = "44444444-4444-4444-8444-444444444444";

    [Test]
    public async Task EveryCallableFactoryBuildsItsNativeRequestWithoutNetworkOrCredentials()
    {
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024, null, false, new NoNetwork());
        await Verify(transport, ScopedAccessOperations.ListGroups("org"), "GET", "/api/v1/groups");
        await Verify(transport, ScopedAccessOperations.GetGroup("org", "group"), "GET", "/api/v1/groups/group");
        await Verify(transport, ScopedAccessOperations.CreateGroup("org", "Group", "group"), "POST", "/api/v1/groups");
        await Verify(transport, ScopedAccessOperations.UpdateGroup("org", "group", name: "New"), "PATCH", "/api/v1/groups/group");
        await Verify(transport, ScopedAccessOperations.DeleteGroup("org", "group"), "DELETE", "/api/v1/groups/group");
        await Verify(transport, ScopedAccessOperations.ListGroupIdentities("org", "group"), "GET", "/api/v1/groups/group/machine-identities");
        await Verify(transport, ScopedAccessOperations.AddGroupIdentity("org", "group", "identity"), "POST", "/api/v1/groups/group/machine-identities/identity");
        await Verify(transport, ScopedAccessOperations.RemoveGroupIdentity("org", "group", "identity"), "DELETE", "/api/v1/groups/group/machine-identities/identity");
        await Verify(transport, ScopedAccessOperations.ListGroupUsers("org", "group"), "GET", "/api/v1/groups/group/users");
        await Verify(transport, ScopedAccessOperations.AddGroupUser("org", "group", "username"), "POST", "/api/v1/groups/group/users/username");
        await Verify(transport, ScopedAccessOperations.RemoveGroupUser("org", "group", "username"), "DELETE", "/api/v1/groups/group/users/username");
        await Verify(transport, ScopedAccessOperations.AvailableGroups("org"), "GET", "/api/v1/organization/available-groups");
        await Verify(transport, ScopedAccessOperations.AvailableIdentities("org"), "GET", "/api/v1/organization/available-identities");
        await Verify(transport, ScopedAccessOperations.ListOrganizationRoles("org"), "GET", "/api/v1/organization/roles");
        await Verify(transport, ScopedAccessOperations.GetOrganizationRole("org", "role"), "GET", "/api/v1/organization/roles/role");
        await Verify(transport, ScopedAccessOperations.GetOrganizationRoleBySlug("org", "role-slug"), "GET", "/api/v1/organization/roles/slug/role-slug");
        await Verify(transport, ScopedAccessOperations.DeleteOrganizationRole("org", "role"), "DELETE", "/api/v1/organization/roles/role");

        await Verify(transport, ProjectOperations.ListProjects("org"), "GET", "/api/v1/projects");
        await Verify(transport, ProjectOperations.GetProject("org", "project"), "GET", "/api/v1/projects/project");
        await Verify(transport, ProjectOperations.GetProjectBySlug("org", "project-slug"), "GET", "/api/v1/projects/slug/project-slug");
        await Verify(transport, ProjectOperations.CreateProject("org", "Project", "project-slug"), "POST", "/api/v1/projects");
        await Verify(transport, ProjectOperations.UpdateProject("org", "project", name: "New"), "PATCH", "/api/v1/projects/project");
        await Verify(transport, ProjectOperations.DeleteProject("org", "project"), "DELETE", "/api/v1/projects/project");
        await Verify(transport, ProjectOperations.CreateEnvironment("org", "project", "Production", "prod"), "POST", "/api/v1/projects/project/environments");
        await Verify(transport, ProjectOperations.GetEnvironment("org", "project", "environment"), "GET", "/api/v1/projects/project/environments/environment");
        await Verify(transport, ProjectOperations.GetEnvironmentBySlug("org", "project", "prod"), "GET", "/api/v1/projects/project/environments/slug/prod");
        await Verify(transport, ProjectOperations.UpdateEnvironment("org", "project", "environment", name: "New"), "PATCH", "/api/v1/projects/project/environments/environment");
        await Verify(transport, ProjectOperations.DeleteEnvironment("org", "project", "environment"), "DELETE", "/api/v1/projects/project/environments/environment");
        await Verify(transport, ProjectOperations.RestoreEnvironment("org", "project", "environment"), "POST", "/api/v1/projects/project/environments/environment/restore");
        await Verify(transport, ProjectOperations.ListTags("org", "project"), "GET", "/api/v1/projects/project/tags");
        await Verify(transport, ProjectOperations.GetTag("org", "project", "tag"), "GET", "/api/v1/projects/project/tags/tag");
        await Verify(transport, ProjectOperations.GetTagBySlug("org", "project", "slug"), "GET", "/api/v1/projects/project/tags/slug/slug");
        await Verify(transport, ProjectOperations.CreateTag("org", "project", "slug", "blue"), "POST", "/api/v1/projects/project/tags");
        await Verify(transport, ProjectOperations.UpdateTag("org", "project", "tag", "slug", "blue"), "PATCH", "/api/v1/projects/project/tags/tag");
        await Verify(transport, ProjectOperations.DeleteTag("org", "project", "tag"), "DELETE", "/api/v1/projects/project/tags/tag");
        await Verify(transport, ProjectOperations.ListProjectRoles("org", "project"), "GET", "/api/v1/projects/project/roles");
        await Verify(transport, ProjectOperations.GetProjectRole("org", "project", Role), "GET", "/api/v1/projects/roles/" + Role);
        await Verify(transport, ProjectOperations.GetProjectRoleBySlug("org", "project", "role-slug"), "GET", "/api/v1/projects/project/roles/slug/role-slug");
        await Verify(transport, ProjectOperations.DeleteProjectRole("org", "project", "role"), "DELETE", "/api/v1/projects/project/roles/role");

        MembershipRole[] roles = [new("member")];
        await Verify(transport, IdentityOperations.ListOrganizationIdentities("org"), "GET", "/api/v1/identities");
        await Verify(transport, IdentityOperations.GetOrganizationIdentity("org", "identity"), "GET", "/api/v1/identities/identity");
        await Verify(transport, IdentityOperations.CreateOrganizationIdentity("org", "Identity", "member"), "POST", "/api/v1/identities");
        await Verify(transport, IdentityOperations.UpdateOrganizationIdentity("org", "identity", name: "New"), "PATCH", "/api/v1/identities/identity");
        await Verify(transport, IdentityOperations.DeleteOrganizationIdentity("org", "identity"), "DELETE", "/api/v1/identities/identity");
        await Verify(transport, IdentityOperations.GetSelectedIdentityOrganization("org"), "GET", "/api/v1/identities/details");
        await Verify(transport, IdentityOperations.ListProjectIdentities("org", "project"), "GET", "/api/v1/projects/project/identities");
        await Verify(transport, IdentityOperations.GetProjectIdentity("org", "project", "identity"), "GET", "/api/v1/projects/project/identities/identity");
        await Verify(transport, IdentityOperations.CreateProjectIdentity("org", "project", "Identity", roles), "POST", "/api/v1/projects/project/identities");
        await Verify(transport, IdentityOperations.UpdateProjectIdentity("org", "project", "identity", name: "New"), "PATCH", "/api/v1/projects/project/identities/identity");
        await Verify(transport, IdentityOperations.DeleteProjectIdentity("org", "project", "identity"), "DELETE", "/api/v1/projects/project/identities/identity");
        await Verify(transport, MembershipOperations.AddProjectIdentity("org", "project", "identity", roles), "POST", "/api/v1/projects/project/memberships/identities/identity");
        await Verify(transport, MembershipOperations.UpdateProjectIdentityRoles("org", "project", "identity", roles), "PATCH", "/api/v1/projects/project/memberships/identities/identity");
        await Verify(transport, MembershipOperations.RemoveProjectIdentity("org", "project", "identity"), "DELETE", "/api/v1/projects/project/memberships/identities/identity");
        await Verify(transport, MembershipOperations.GetProjectIdentityMembership("org", "project", "identity"), "GET", "/api/v1/projects/project/memberships/identities/identity");
        await Verify(transport, MembershipOperations.RemoveProjectGroup("org", "project", Group), "DELETE", "/api/v1/projects/project/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.GetProjectGroup("org", "project", Group), "GET", "/api/v1/projects/project/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.AddProjectGroup("org", "project", Group, roles), "POST", "/api/v1/projects/project/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.ListProjectGroups("org", "project"), "GET", "/api/v1/projects/project/memberships/groups");
        await Verify(transport, MembershipOperations.RemoveOrganizationGroup("org", Group), "DELETE", "/api/v1/organizations/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.GetOrganizationGroup("org", Group), "GET", "/api/v1/organizations/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.AddOrganizationGroup("org", Group, roles), "POST", "/api/v1/organizations/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.UpdateOrganizationGroupRoles("org", Group, roles), "PATCH", "/api/v1/organizations/memberships/groups/" + Group);
        await Verify(transport, MembershipOperations.ListOrganizationGroups("org"), "GET", "/api/v1/organizations/memberships/groups");

        AuditClassSetting[] settings = [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authorization, false)];
        await Verify(transport, GovernanceOperations.GetOrganizationAuditSettings("org"), "GET", "/api/v1/organization/audit-log-settings");
        await Verify(transport, GovernanceOperations.SetOrganizationAuditSettings("org", settings), "PUT", "/api/v1/organization/audit-log-settings");
        await Verify(transport, GovernanceOperations.GetProjectAuditSettings("org", AuditProject), "GET", "/api/v1/projects/" + AuditProject + "/audit-log-settings");
        await Verify(transport, GovernanceOperations.SetProjectAuditSettings("org", AuditProject, settings), "PUT", "/api/v1/projects/" + AuditProject + "/audit-log-settings");
        await Verify(transport, GovernanceOperations.ReadAudit("org", DateTimeOffset.UnixEpoch, DateTimeOffset.UnixEpoch.AddDays(1)), "GET", "/api/v1/organization/audit-logs");
        await Verify(transport, SharingOperations.ListShares("org"), "GET", "/api/v1/shared-secrets");
        await Verify(transport, SharingOperations.GetShare("org", "share"), "GET", "/api/v1/shared-secrets/share");
        await Verify(transport, SharingOperations.DeleteShare("org", "share"), "DELETE", "/api/v1/shared-secrets/share");
        using SecretMaterial value = SecretMaterial.FromText(Guid.NewGuid().ToString());
        await Verify(transport, SharingOperations.CreateShare("org", "Share", value, 5, ShareAudience.Organization), "POST", "/api/v1/shared-secrets");
        await Verify(transport, SharingOperations.AccessShare("org", "share"), "POST", "/api/v1/shared-secrets/share/access");
        await Verify(transport, IdentityPrivilegeOperations.ListProjectPrivileges("org", "project", "identity"), "GET", "/api/v2/identity-project-additional-privilege");
        await Verify(transport, IdentityPrivilegeOperations.GetProjectPrivilege("org", "project", "identity", "privilege"), "GET", "/api/v2/identity-project-additional-privilege/privilege");
        await Verify(transport, IdentityPrivilegeOperations.DeleteProjectPrivilege("org", "project", "identity", "privilege"), "DELETE", "/api/v2/identity-project-additional-privilege/privilege");
    }

    private static async Task Verify<T>(ManagementTransport transport, ManagementRequest<T> request,
        string method, string path) where T : notnull
    {
        using (request)
        {
            byte[]? bytes = request.CopyBody();
            try
            {
                using var body = bytes is null ? null : new ByteArrayContent(bytes);
                if (body is not null) body.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                using HttpRequestMessage wire = await transport.BuildAsync(request, body, CancellationToken.None);
                await Assert.That(wire.Method.Method).IsEqualTo(method);
                await Assert.That(wire.RequestUri!.AbsolutePath).IsEqualTo(path);
                await Assert.That(wire.RequestUri.Authority).IsEqualTo("management.test");
                await Assert.That(wire.Headers.Authorization is null).IsTrue();
                if (bytes is not null)
                {
                    byte[] actual = await wire.Content!.ReadAsByteArrayAsync();
                    await Assert.That(actual.SequenceEqual(bytes)).IsTrue();
                    Array.Clear(actual);
                }
            }
            finally { if (bytes is not null) Array.Clear(bytes); }
        }
    }

    private sealed class NoNetwork : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Refit request construction must not perform I/O.");
    }
}
