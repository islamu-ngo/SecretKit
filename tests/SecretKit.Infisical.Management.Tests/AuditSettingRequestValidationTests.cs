namespace SecretKit.Infisical.Management.Tests;

public sealed class AuditSettingRequestValidationTests
{
    private const string Org = "11111111-1111-4111-8111-111111111111";
    private const string Project = "22222222-2222-4222-8222-222222222222";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task WritesAndIntentTargetsRejectInvalidMutableClassSets(int route)
    {
        AuditClassSetting[][] invalid =
        [
            [new(AuditEventClass.Management, true), new(AuditEventClass.Authorization, false)],
            [new(AuditEventClass.Authentication, true), new(AuditEventClass.DataAccess, false)],
            [new(AuditEventClass.Authorization, true)],
            [new(AuditEventClass.Authentication, true)],
            [new(AuditEventClass.Management, true), new(AuditEventClass.Authentication, true),
                new(AuditEventClass.Authorization, false), new(AuditEventClass.DataAccess, true)],
            [new(AuditEventClass.Authentication, true), new(AuditEventClass.Authentication, false)],
            [new(AuditEventClass.Authorization, true), new(AuditEventClass.Authorization, false)],
            []
        ];
        foreach (AuditClassSetting[] settings in invalid)
            await Assert.That(() => Build(route, settings)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task NullWriteSettingsCannotBecomeReadRequests(int route)
    {
        await Assert.That(() => Build(route, null!)).Throws<ArgumentNullException>();
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(0, true)]
    [Arguments(1, false)]
    [Arguments(1, true)]
    [Arguments(2, false)]
    [Arguments(2, true)]
    [Arguments(3, false)]
    [Arguments(3, true)]
    public void BothOrdersAndEveryBooleanPairRemainValid(int route, bool reverse)
    {
        foreach (bool authentication in new[] { false, true })
            foreach (bool authorization in new[] { false, true })
            {
                AuditClassSetting[] settings =
                    [new(AuditEventClass.Authentication, authentication), new(AuditEventClass.Authorization, authorization)];
                if (reverse) Array.Reverse(settings);
                Build(route, settings);
            }
    }

    private static void Build(int route, AuditClassSetting[] settings)
    {
        if (route == 0)
        {
            using var request = GovernanceOperations.SetOrganizationAuditSettings(Org, settings);
        }
        else if (route == 1)
        {
            using var request = GovernanceOperations.SetProjectAuditSettings(Org, Project, settings);
        }
        else
        {
            _ = GovernanceOperations.AuditSettingsTarget(Org, settings, route == 2 ? null : Project);
        }
    }
}
