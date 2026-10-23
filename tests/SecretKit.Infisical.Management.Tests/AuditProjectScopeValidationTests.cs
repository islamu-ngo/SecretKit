namespace SecretKit.Infisical.Management.Tests;

public sealed class AuditProjectScopeValidationTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task MissingProjectCannotSelectOrganizationAuditScope(bool write)
    {
        await Assert.That(() =>
        {
            using var request = write ?
                GovernanceOperations.SetProjectAuditSettings("org", null!,
                    [new(AuditEventClass.Authentication, false), new(AuditEventClass.Authorization, false)]) :
                GovernanceOperations.GetProjectAuditSettings("org", null!);
        }).Throws<ArgumentNullException>();
    }
}
