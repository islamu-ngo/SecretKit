using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class ContractAvailabilityTests
{
    [Test]
    [Arguments(InfisicalUnestablishedContract.ApprovalAdministration)]
    [Arguments(InfisicalUnestablishedContract.AccessRequests)]
    [Arguments(InfisicalUnestablishedContract.PointInTimeRecovery)]
    [Arguments(InfisicalUnestablishedContract.Insights)]
    [Arguments(InfisicalUnestablishedContract.WebhookAdministration)]
    public async Task UnestablishedContractNeverImpliesPermissionOrImplementedSupport(InfisicalUnestablishedContract contract)
    {
        SecretCapabilityEvidence evidence = InfisicalContractAvailability.Describe(contract);

        await Assert.That(evidence.Availability).IsEqualTo(CapabilityAvailability.ContractNotEstablished);
        await Assert.That(evidence.Permission).IsEqualTo(PermissionEvidence.NotChecked);
        await Assert.That(evidence.RemotelyVerified).IsFalse();
    }
}
