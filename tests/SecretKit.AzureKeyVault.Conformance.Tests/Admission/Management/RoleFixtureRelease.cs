using System.Text.Json.Serialization;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

internal static class RoleFixtureRelease
{
    internal sealed record Measurement(FixtureSelector Selector, [property: JsonRequired] bool Closing,
        [property: JsonRequired] int ActiveDispatches, string[] OwnedResourceIds, string[] BorrowedResourceIds,
        string[] AbsentResourceIds, string[] RemainingResourceIds)
    {
        public override string ToString() => "[RoleReleaseMeasurement]";
    }

    internal static void Validate(Measurement measured, FixtureSelector selector, LeaseFacts? known)
    {
        ManagementAdmission.Require(measured.Selector == selector && measured.Closing &&
            measured.ActiveDispatches == 0 && measured.OwnedResourceIds is not null &&
            measured.BorrowedResourceIds is not null && measured.AbsentResourceIds is not null &&
            measured.RemainingResourceIds is { Length: 0 }, NativeFailure.CleanupIncomplete);
        string[][] sets = [measured.OwnedResourceIds!, measured.BorrowedResourceIds!, measured.AbsentResourceIds!];
        ManagementAdmission.Require(sets[0].Length + (long)sets[1].Length <= 24 &&
            sets.All(rows => rows.Length <= 24 &&
            rows.All(r => !string.IsNullOrWhiteSpace(r) && r.Length <= 2048 &&
                r.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase)) &&
            rows.Distinct(StringComparer.OrdinalIgnoreCase).Count() == rows.Length) &&
            !sets[0].Intersect(sets[1], StringComparer.OrdinalIgnoreCase).Any() &&
            sets[0].ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(sets[2]) &&
            (known is null || known.Nonce == selector.Nonce &&
                known.OwnedResourceIds.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(sets[0])),
            NativeFailure.CleanupIncomplete);
    }

    internal static async ValueTask ReleaseAsync(OwnedManagementObserver service, FixtureSelector selector,
        LeaseFacts? known, NativeCaseProbe probe, OwnedAzureEnvironment? env = null,
        NativeCaseDefinition? definition = null)
    {
        try
        {
            // Authenticated service owner + original selector, never returned
            // lease coordinates. Cleanup has its own bounded uncancelled request.
            Measurement measured = await service.PostAsync<FixtureSelector, Measurement>("role/release",
                selector, CancellationToken.None).ConfigureAwait(false);
            Validate(measured, selector, known);
            if (env is not null && definition is not null)
                env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Matched);
        }
        catch (Exception)
        {
            if (env is not null && definition is not null)
                env.ConfirmPrerequisite(definition.Key.Scope, "approved-sandbox-cleanup", NativeObservation.Mismatched);
            probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
}
