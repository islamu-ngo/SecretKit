using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class ManagementOperationFixtureRelease
{
    internal static async ValueTask ReleaseAsync(OwnedManagementObserver service, FixtureSelector selector,
        LeaseFacts? known, NativeCaseProbe probe, OwnedAzureEnvironment env, NativeCaseDefinition definition)
    {
        try
        {
            var measured = await service.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "operation/release", selector, CancellationToken.None).ConfigureAwait(false);
            RoleFixtureRelease.Validate(measured, selector, known);
            env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
        }
        catch (Exception)
        {
            env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
            probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
}
