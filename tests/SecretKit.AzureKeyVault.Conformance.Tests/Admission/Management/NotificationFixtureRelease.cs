using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class NotificationFixtureRelease
{
    internal static async ValueTask ReleaseAsync(OwnedManagementObserver service, FixtureSelector selector,
        LeaseFacts? known, NativeCaseProbe probe, OwnedAzureEnvironment env, NativeCaseDefinition definition)
    {
        try
        {
            // The original selector owns release even when Prepare has no usable
            // reply. The observer bounds this request independently of caller cancellation.
            var measured = await service.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
                "notification/release", selector, CancellationToken.None).ConfigureAwait(false);
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
