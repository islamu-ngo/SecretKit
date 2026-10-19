using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

internal static partial class AzureNativeCases
{
    static partial void RegisterFamilies(NativeCaseRegistry registry, OwnedAzureEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        AzureKeyVaultClientEffects.Register(registry, environment, expected);
        AzureNativeLifecycleEffects.Register(registry, environment, expected);
        Admission.Management.AzureManagementFamilies.Register(registry, environment, expected);
    }
}
