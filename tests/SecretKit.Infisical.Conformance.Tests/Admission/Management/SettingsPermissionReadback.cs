using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Only the observer reads. Complete storage evidence owns fields absent from the
// SDK; absence is not silently converted into a baseline value or a success echo.
internal static class SettingsPermissionReadback
{
    internal static async ValueTask CheckAsync(NativeEnvironment env, SettingsPermissionRoot root,
        SettingsPermissionState[] states, CancellationToken token)
    {
        var client = env.CreateManagementClient();
        foreach (var state in states)
        {
            using var get = ProjectOperations.GetProject(root.Organization, state.Id);
            var authority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization, state.Id);
            var read = await client.ExecuteAsync(get, authority, authority.IssueGrant(get.OperationId, get.Target), cancellationToken: token);
            SettingsPermissionContract.Require(read.IsSuccess, "effect-mismatch"); Match(read.Value, state, true);
            using var slug = ProjectOperations.GetProjectBySlug(root.Organization, state.Slug);
            var slugAuthority = new ManagementAuthority(client.Authority, env.Tokens(NativeIdentityRole.Observer), root.Organization);
            var bySlug = await client.ExecuteAsync(slug, slugAuthority, slugAuthority.IssueGrant(slug.OperationId, slug.Target), cancellationToken: token);
            SettingsPermissionContract.Require(bySlug.IsSuccess, "effect-mismatch"); Match(bySlug.Value, state, true);
        }
    }
    private static bool Field(ProjectField<string> field, string? expected) => !field.IsPresent ||
        (expected is null ? field.IsNull : !field.IsNull && field.Value == expected);
    internal static void Match(ProjectSummary value, SettingsPermissionState state, bool detail)
    {
        var f = state.Fixed;
        SettingsPermissionContract.Require(value.Id == state.Id && value.Name == state.Name && value.Slug == state.Slug &&
            value.DescriptionField.IsPresent && !value.DescriptionField.IsNull && value.Description == state.Description && value.Type == state.Type &&
            value.CreatedAt.Value == state.CreatedAt && value.UpdatedAt.Value == state.UpdatedAt &&
            (!value.HasDeleteProtection.IsPresent || !value.HasDeleteProtection.IsNull && value.HasDeleteProtection.Value == f.DeleteProtection) &&
            (!value.AutoCapitalization.IsPresent || !value.AutoCapitalization.IsNull && value.AutoCapitalization.Value == f.AutoCapitalization) &&
            (!value.EnforceEncryptedSecretManagerSecretMetadata.IsPresent || !value.EnforceEncryptedSecretManagerSecretMetadata.IsNull && value.EnforceEncryptedSecretManagerSecretMetadata.Value == f.EncryptedMetadata) &&
            (!value.SecretSharing.IsPresent || !value.SecretSharing.IsNull && value.SecretSharing.Value == f.SecretSharing) &&
            (!value.IsLegacyAdditionalPrivilegesEnabled.IsPresent || !value.IsLegacyAdditionalPrivilegesEnabled.IsNull && value.IsLegacyAdditionalPrivilegesEnabled.Value == f.LegacyPrivileges) &&
            (!value.SecretBlindIndexEnabled.IsPresent || !value.SecretBlindIndexEnabled.IsNull && value.SecretBlindIndexEnabled.Value == f.BlindIndex) &&
            (!value.ShowSnapshotsLegacy.IsPresent || !value.ShowSnapshotsLegacy.IsNull && value.ShowSnapshotsLegacy.Value == f.LegacySnapshots) &&
            (!value.AuditLogsRetentionDays.IsPresent || !value.AuditLogsRetentionDays.IsNull && value.AuditLogsRetentionDays.Value == f.AuditRetention) &&
            (!value.PitVersionLimit.IsPresent || !value.PitVersionLimit.IsNull && value.PitVersionLimit.Value == f.PitLimit) &&
            (!value.Version.IsPresent || !value.Version.IsNull && value.Version.Value == f.ProjectVersion) &&
            (!value.DefaultProduct.IsPresent || !value.DefaultProduct.IsNull && value.DefaultProduct.Value == f.DefaultProduct) &&
            Field(value.UpgradeStatus, f.UpgradeStatus) &&
            Field(value.KmsCertificateKeyId, f.CertificateKey) &&
            Field(value.KmsSecretManagerKeyId, f.SecretManagerKey) &&
            (!value.SecretDetectionIgnoreValues.IsPresent || !value.SecretDetectionIgnoreValues.IsNull && SettingsPermissionContract.Hash(value.SecretDetectionIgnoreValues.Value) == f.IgnoreValuesHash), "effect-mismatch");
        if (detail) SettingsPermissionContract.Require(value.NativeId.IsPresent && value.NativeId.Value == state.Id &&
            value.Environments.IsPresent && value.Environments.Value.Count == 1 && value.Environments.Value[0].Id == f.Environment &&
            value.Environments.Value[0].Name == f.EnvironmentName && value.Environments.Value[0].Slug == f.EnvironmentSlug &&
            value.DeletedEnvironments.IsPresent && value.DeletedEnvironments.Value.Count == 0, "effect-mismatch");
    }
}
