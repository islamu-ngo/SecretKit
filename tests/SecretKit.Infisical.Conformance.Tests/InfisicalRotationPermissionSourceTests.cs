using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationPermissionSourceTests
{
    [Test]
    public async Task OutOfOrderAndDuplicateReserveCannotPreventOriginalRootRecovery()
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        var root = fixture.Root("i.management.RoleChangeOperations.UpdateProjectRole", RotationPermissionAction.Edit, "independent-effect");
        var source = fixture.Source.CreateClient();
        RotationPermissionTrial? retained = null;
        using var capability = SecretMaterial.FromText("rotation-capability");
        try
        {
            _ = await RotationPermissionTrial.OpenAsync(source, root, capability, t => retained = t, CancellationToken.None);
            bool failed = false;
            try { await source.StepAsync(root, RotationPermissionStep.Settle, null, CancellationToken.None); }
            catch (NativeCaseFailureException) { failed = true; }
            await Assert.That(failed).IsTrue();
            failed = false;
            try { await source.StepAsync(root, RotationPermissionStep.Reserve, capability, CancellationToken.None); }
            catch (NativeCaseFailureException) { failed = true; }
            await Assert.That(failed).IsTrue();
        }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await InfisicalRotationPermissionEffectTests.CleanAsync(fixture);
    }
    [Test]
    public async Task PinsRequireDistinctP256AuthoritiesAndCoordinatorCannotSupplyThem()
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        var pins = fixture.Profile.Pins.ToArray();
        pins[1] = pins[1] with { Spki = pins[0].Spki };
        bool failed = false;
        try { RotationPermissionContract.Validate(fixture.Profile with { Pins = pins }); }
        catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
        using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        pins = fixture.Profile.Pins.ToArray();
        pins[0] = pins[0] with { Spki = Convert.ToBase64String(wrongCurve.ExportSubjectPublicKeyInfo()) };
        failed = false;
        try { RotationPermissionContract.Validate(fixture.Profile with { Pins = pins }); }
        catch (NativeCaseFailureException) { failed = true; }
        await Assert.That(failed).IsTrue();
        await Assert.That(fixture.Opens).IsEqualTo(0);
    }
    [Test]
    [Arguments((int)InfisicalRotationProfile.MongodbCredentials)]
    [Arguments((int)InfisicalRotationProfile.OracledbCredentials)]
    public async Task UnimplementedProfilesRemainUnavailableWithoutOpeningAnything(int profile)
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        using var env = fixture.Environment(RotationPermissionAction.ReadGeneratedCredentials, (InfisicalRotationProfile)profile);
        const string operation = "i.management.RoleChangeOperations.UpdateProjectRole";
        var d = InfisicalRotationPermissionGateTests.Definition(operation, "permission.SecretRotation.read-generated-credentials", "independent-effect");
        var registry = new NativeCaseRegistry();
        registry.Add(new(d, async (probe, token) =>
        {
            probe.Contract(true, NativeFailure.ContractMismatch);
            var context = new ProjectFamilyContext(env, "RoleChanges", d, probe);
            try { await RotationPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), token, fixture.Runtime); }
            finally { await context.CleanupAsync(); }
        }));
        var result = (await NativeCaseRunner.RunAsync(registry, [d], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.EffectObserved).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
    }
    [Test]
    public async Task MissingHostOwnedRuntimeTransportCannotBootstrapAnyTrial()
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        using var env = fixture.Environment(RotationPermissionAction.Edit);
        var d = InfisicalRotationPermissionGateTests.Definition("i.management.RoleChangeOperations.UpdateProjectRole",
            "permission.SecretRotation.edit", "independent-effect");
        var probe = new NativeCaseProbe();
        var context = new ProjectFamilyContext(env, "RoleChanges", d, probe);
        bool unavailable = false;
        try { await RotationPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), CancellationToken.None); }
        catch (NativeCaseFailureException error) { unavailable = error.Message == "observer-unavailable"; }
        finally { await context.CleanupAsync(); }
        await Assert.That(unavailable).IsTrue();
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
    }
    [Test]
    public async Task NativeHostOwnsRuntimeTransportAndDisposesItWithTheEnvironment()
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        var env = fixture.Environment(RotationPermissionAction.Edit);
        var runtime = env.RotationPermissionRuntime;
        try { await Assert.That(runtime.Origin).IsEqualTo(env.Origin); }
        finally { env.Dispose(); }
        using var request = new HttpRequestMessage(HttpMethod.Get, runtime.Origin);
        await Assert.That(async () =>
        {
            using var response = await runtime.Transport.SendAsync(request);
        }).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task NonHttpsHostTransportCannotBootstrapAnyTrial()
    {
        await using var fixture = new InfisicalRotationPermissionFixture();
        using var env = fixture.Environment(RotationPermissionAction.Edit);
        var d = InfisicalRotationPermissionGateTests.Definition("i.management.RoleChangeOperations.UpdateProjectRole",
            "permission.SecretRotation.edit", "independent-effect");
        var context = new ProjectFamilyContext(env, "RoleChanges", d, new NativeCaseProbe());
        bool unavailable = false;
        try
        {
            await RotationPermissionEffects.ExecuteAsync(context, fixture.Source.CreateClient(), CancellationToken.None,
                env.RotationPermissionRuntime);
        }
        catch (NativeCaseFailureException error) { unavailable = error.Message == "observer-unavailable"; }
        finally { await context.CleanupAsync(); }
        await Assert.That(unavailable).IsTrue();
        await Assert.That(fixture.Opens).IsEqualTo(0);
        await Assert.That(fixture.Remaining).IsEqualTo(0);
    }
}
