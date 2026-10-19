using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static partial class InfisicalNativeCases
{
    static partial void RegisterFamilies(NativeCaseRegistry registry, NativeEnvironment environment,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        InfisicalStaticFamilies.Register(registry, environment, expected);
        InfisicalProjectFamilies.Register(registry, environment, expected,
            rotationPermissionRuntime: environment.RotationPermissionRuntime);
        InfisicalAuthenticationFamilies.Register(registry, environment, expected);
        InfisicalImportPolicyFamilies.Register(registry, environment, expected);
        InfisicalLifecycleFamilies.Register(registry, environment, expected);
        InfisicalGovernanceFamilies.Register(registry, environment, expected,
            new GovernanceObservers { RotationPermissionRuntime = environment.RotationPermissionRuntime });
        InfisicalIdentityFamilies.Register(registry, environment, expected);
        InfisicalPermissionFamilies.Register(registry, environment, expected,
            rotationPermissionRuntime: environment.RotationPermissionRuntime);
        InfisicalDatabaseFamilies.Register(registry, environment, expected);
        InfisicalIdentityAuthenticationFamilies.Register(registry, environment, expected);
    }
}
