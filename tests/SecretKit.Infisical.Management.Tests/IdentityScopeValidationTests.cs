namespace SecretKit.Infisical.Management.Tests;

public sealed class IdentityScopeValidationTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Project = "22222222-2222-4222-8222-222222222222";
    private const string Identity = "33333333-3333-4333-8333-333333333333";

    [Test]
    [Arguments("organization-update-id")]
    [Arguments("project-update-id")]
    [Arguments("project-update-project")]
    [Arguments("organization-target-id")]
    [Arguments("project-target-id")]
    [Arguments("project-target-project")]
    [Arguments("project-list-target")]
    [Arguments("project-create-target")]
    public async Task MissingRequiredCoordinatesCannotSelectAnotherScopeOrAction(string operation)
    {
        Action create = operation switch
        {
            "organization-update-id" => () =>
                IdentityOperations.UpdateOrganizationIdentity(Org, null!, name: "changed-name").Dispose(),
            "project-update-id" => () =>
                IdentityOperations.UpdateProjectIdentity(Org, Project, null!, name: "changed-name").Dispose(),
            "project-update-project" => () =>
                IdentityOperations.UpdateProjectIdentity(Org, null!, Identity, name: "changed-name").Dispose(),
            "organization-target-id" => () =>
                IdentityOperations.OrganizationIdentityUpdateTarget(Org, null!, name: "changed-name"),
            "project-target-id" => () =>
                IdentityOperations.ProjectIdentityUpdateTarget(Org, Project, null!, name: "changed-name"),
            "project-target-project" => () =>
                IdentityOperations.ProjectIdentityUpdateTarget(Org, null!, Identity, name: "changed-name"),
            "project-list-target" => () => IdentityOperations.ProjectIdentityListTarget(Org, null!),
            _ => () => IdentityOperations.ProjectIdentityCreateTarget(Org, null!, "new-name")
        };

        await Assert.That(create).Throws<ArgumentException>();
    }

    [Test]
    public async Task ExplicitCreationAndValidUpdatesRetainTheirDeclaredActionsAndScopes()
    {
        using var create = IdentityOperations.CreateOrganizationIdentity(Org, "new-name", "member");
        using var organization = IdentityOperations.UpdateOrganizationIdentity(Org, Identity, name: "changed-name");
        using var project = IdentityOperations.UpdateProjectIdentity(Org, Project, Identity, name: "changed-name");

        await Assert.That(create.OperationId).IsEqualTo("infisical.post.v1.identities");
        await Assert.That(organization.OperationId).IsEqualTo("infisical.patch.v1.identities.by.identityId");
        await Assert.That(project.OperationId).IsEqualTo("infisical.patch.v1.projects.by.projectId.identities.by.identityId");
        await Assert.That(organization.Target.ProjectId).IsNull();
        await Assert.That(project.Target.ProjectId).IsEqualTo(Project);
        await Assert.That(organization.Target.ResourceId).IsEqualTo(Identity);
        await Assert.That(project.Target.ResourceId).IsEqualTo(Identity);
        await Assert.That(IdentityOperations.OrganizationIdentityUpdateTarget(Org, Identity, name: "changed-name")
            .SameTarget(organization.Target)).IsTrue();
        await Assert.That(IdentityOperations.ProjectIdentityUpdateTarget(Org, Project, Identity, name: "changed-name")
            .SameTarget(project.Target)).IsTrue();
    }
}
