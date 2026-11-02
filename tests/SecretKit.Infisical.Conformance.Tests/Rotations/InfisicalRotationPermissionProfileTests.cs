using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationPermissionProfileTests
{
    public static IEnumerable<(string Operation, string Variant, string Boundary, int Profile, bool Generic)> Cases() =>
        from c in InfisicalRotationPermissionGateTests.Cases()
        from profile in new[] { InfisicalRotationProfile.MysqlCredentials, InfisicalRotationProfile.MssqlCredentials }
        from generic in new[] { false, true }
        select (c.Operation, c.Variant, c.Boundary, (int)profile, generic);
    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task OriginalRoutesRequireSelectedSqlProfile(string operation, string variant, string boundary,
        int profile, bool generic)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(profile: (InfisicalRotationProfile)profile);
        using var env = fixture.Environment(InfisicalRotationPermissionGateTests.Action(variant));
        var d = generic ?
            new NativeCaseDefinition(new("Infisical", InfisicalRotationPermissionGateTests.Execute,
                "factory." + operation, "local", boundary),
                InfisicalGovernanceFamilies.Bindings[InfisicalRotationPermissionGateTests.Execute].Member) :
            InfisicalRotationPermissionGateTests.Definition(operation, variant, boundary);
        var registry = new NativeCaseRegistry();
        var source = fixture.Source.CreateClient();
        if (generic)
            InfisicalGovernanceFamilies.Register(registry, env, [d],
                new GovernanceObservers { RotationPermissions = source, RotationPermissionRuntime = fixture.Runtime });
        else if (InfisicalPermissionFamilies.Owns(operation))
            InfisicalPermissionFamilies.Register(registry, env, [d], rotationPermissions: source,
                rotationPermissionRuntime: fixture.Runtime);
        else
            InfisicalProjectFamilies.Register(registry, env, [d], rotationPermissions: source,
                rotationPermissionRuntime: fixture.Runtime);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsTrue().Because(result.ReasonCode);
        await Assert.That(result.Variant).IsEqualTo(generic ? "factory." + operation : variant);
        await Assert.That(fixture.Opens).IsEqualTo(1);
        await Assert.That(fixture.Originals).IsEqualTo(boundary == "cancellation-boundary" ? 0 : 1);
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
    }

    public static IEnumerable<(int Profile, string Fault)> Faults() =>
        from profile in new[] { InfisicalRotationProfile.MysqlCredentials, InfisicalRotationProfile.MssqlCredentials }
        from fault in new[] { "ignored-config", "ignored-rotation", "wrong-material", "backend-permission",
            "forged-journal", "profile-mismatch" }
        select ((int)profile, fault);
    [Test]
    [MethodDataSource(nameof(Faults))]
    public async Task ProfileConfigurationMaterialBackendAndJournalFaultsCannotPass(int profile, string fault)
    {
        await using var fixture = new InfisicalRotationPermissionFixture(fault, (InfisicalRotationProfile)profile);
        using var env = fixture.Environment(RotationPermissionAction.Edit);
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = InfisicalRotationPermissionGateTests.Definition(operation,
            "permission.SecretRotation.edit", "independent-effect");
        var registry = new NativeCaseRegistry();
        InfisicalPermissionFamilies.Register(registry, env, [d], rotationPermissions: fixture.Source.CreateClient(),
            rotationPermissionRuntime: fixture.Runtime);
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
        if (fault == "profile-mismatch") await Assert.That(fixture.Originals).IsEqualTo(0);
    }
}
