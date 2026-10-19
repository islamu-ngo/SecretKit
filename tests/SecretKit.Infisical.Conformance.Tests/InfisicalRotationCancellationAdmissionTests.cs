using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationCancellationAdmissionTests
{
    [Test]
    [Arguments("RotateSecretsAsync", "profile.PostgresCredentials", true)]
    [Arguments("RotateSecretsAsync", "profile.MysqlCredentials", true)]
    [Arguments("RotateSecretsAsync", "profile.MssqlCredentials", true)]
    [Arguments("SetAutomaticRotationAsync", "enabled.true", true)]
    [Arguments("SetAutomaticRotationAsync", "enabled.false", true)]
    [Arguments("GetAsync", "profile.PostgresCredentials", false)]
    [Arguments("ListAsync", "profile.PostgresCredentials", false)]
    [Arguments("RotateSecretsAsync", "precondition.RequireCompareAndSwap.rejected", false)]
    [Arguments("SetAutomaticRotationAsync", "precondition.RequireIdempotency.rejected", false)]
    public async Task NativeMutationCancellationNeedsCompletionEvidenceBeforeOwnership(
        string method, string variant, bool needsCompletion)
    {
        // Given: native transport with no server-completion witness.
        var profile = variant.EndsWith("MysqlCredentials", StringComparison.Ordinal) ?
            InfisicalRotationProfile.MysqlCredentials :
            variant.EndsWith("MssqlCredentials", StringComparison.Ordinal) ?
                InfisicalRotationProfile.MssqlCredentials : InfisicalRotationProfile.PostgresCredentials;
        var input = new InfisicalRotationClientEffects.RotationInput(
            new("project", "project-slug", "env", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "/owned"),
            "organization", profile, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            new(profile, "backend.invalid", 5432, "database", "account"),
            "account-a", "account-b", null, 1, false, 128, ["select"], ["write"]);
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a =>
            a.Operation == "i.runtime.InfisicalRotationClient." + method);
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, variant,
            "owned-cancellation", "cancellation-boundary"), admission.Member);
        var options = new JsonSerializerOptions(InfisicalLifecycleFamilies.Options)
        {
            IgnoreReadOnlyProperties = false
        };
        using var env = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = "https://rotation.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new JsonObject
            {
                [InfisicalRotationClientEffects.Family] = new JsonObject
                {
                    ["scopes"] = new JsonObject
                    {
                        [row.Key.Scope] = new JsonObject
                        {
                            [row.Key.Operation] = new JsonObject
                            {
                                [row.Key.Variant] = new JsonObject
                                {
                                    [row.Key.Case] = JsonSerializer.SerializeToNode(input, options)
                                }
                            }
                        }
                    }
                }
            }
        }, options));
        var owner = new OwnershipTripwire();
        var registry = new NativeCaseRegistry();
        InfisicalRotationClientEffects.Register(registry, env, [row], factory: owner);

        // When: the native cancellation scenario is admitted.
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();

        // Then: no ownership or provider dispatch can precede the missing witness.
        await Assert.That(result.ReasonCode).IsEqualTo(needsCompletion ? "observer-unavailable" : "missing-prerequisite");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(owner.Reached).IsEqualTo(!needsCompletion);
    }

    private sealed class OwnershipTripwire : IInfisicalRotationFixtureFactory
    {
        internal bool Reached { get; private set; }

        public ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
            InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token)
        {
            Reached = true;
            // A wrong admission path cannot accidentally reach a native service.
            throw new NativeCaseFailureException("missing-prerequisite");
        }
    }
}
