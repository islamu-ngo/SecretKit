using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalSqlRotationPatchTests
{
    public static IEnumerable<(string Profile, string Variant, string Boundary)> Cases()
    {
        foreach (string profile in new[] { "Postgres", "MySql", "MsSql" })
        {
            var binding = InfisicalDatabaseFamilies.Bindings[$"i.management.{profile}SecretRotationOperations.Update"];
            foreach (string variant in binding.Variants)
                foreach (string boundary in new[] { "selected-contract", "independent-effect", "denied-authority",
                    "cancellation-boundary", "lost-response-no-replay" })
                    yield return (profile, variant, boundary);
        }
    }

    [Test]
    [MethodDataSource(nameof(Cases))]
    public async Task PopulatedSiblingContrastsUseUnchangedRequiredMembersAndIndependentCompletion(
        string profile, string variant, string boundary)
    {
        await using var fixture = new InfisicalSqlRotationPatchFixture();
        var result = await fixture.RunAsync(InfisicalSqlRotationPatchFixture.Definition(profile, variant, boundary));
        await Assert.That(result.Passed).IsTrue().Because($"{profile}/{variant}/{boundary}: {result.ReasonCode}");
        await Assert.That(fixture.SetupParameters.Single().ContainsKey("passwordRequirements")).IsTrue();
        await Assert.That(fixture.SetupParameters.Single().ContainsKey("rotationStatement")).IsTrue();
        await Assert.That(fixture.SetupParameters.Single()["passwordRequirements"]!["allowedSymbols"]!.GetValue<string>()).IsEqualTo("!@");
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Projects.Count).IsEqualTo(0);
        await Assert.That(fixture.BorrowedIntact).IsTrue();
        var source = fixture.Sources.Single();
        await Assert.That(source.CompletedCallbacks).IsEqualTo(1);
        await Assert.That(source.CallerReceipt).IsEqualTo(boundary switch
        {
            "lost-response-no-replay" => DispatchEvidence.PossiblyDispatched,
            "cancellation-boundary" => DispatchEvidence.NotDispatched,
            "denied-authority" => DispatchEvidence.Rejected,
            _ => DispatchEvidence.Applied
        });
        await Assert.That(source.Registrations).IsEqualTo(0);
        await Assert.That(source.RecoveryRoots.Distinct().Count()).IsEqualTo(1);
        if (variant == "patch.empty" && boundary is "selected-contract" or "independent-effect" or "lost-response-no-replay")
            await Assert.That(fixture.Patches.Single().Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("Postgres", "PostgresRotationParameters.passwordRequirements.omitted")]
    [Arguments("MySql", "MySqlRotationParameters.rotationStatement.omitted")]
    [Arguments("MsSql", "MsSqlRotationPasswordRequirements.allowedSymbols.omitted")]
    public async Task RecursiveMergeCannotCertifyReplacementOfPopulatedSiblings(string profile, string variant)
    {
        await using var fixture = new InfisicalSqlRotationPatchFixture("deep-merge");
        var result = await fixture.RunAsync(InfisicalSqlRotationPatchFixture.Definition(profile, variant));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.BorrowedIntact).IsTrue();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("case")]
    [Arguments("root")]
    [Arguments("version")]
    [Arguments("deployment")]
    [Arguments("source")]
    [Arguments("clock")]
    [Arguments("epoch")]
    [Arguments("ignored-patch")]
    [Arguments("echo-only")]
    public async Task SubstitutedSourceAndUnchangedStorageCannotQualify(string mode)
    {
        await using var fixture = new InfisicalSqlRotationPatchFixture(mode);
        var result = await fixture.RunAsync(InfisicalSqlRotationPatchFixture.Definition("Postgres",
            "PostgresSecretRotationUpdate.name.value"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Sources.Single().Registrations).IsEqualTo(0);
        await Assert.That(fixture.Sources.Single().RecoveryRoots.Distinct().Count()).IsEqualTo(1);
    }

    [Test]
    [Arguments("arm-loss")]
    [Arguments("bootstrap-loss")]
    public async Task LostBootstrapRepliesRecoverOnlyTheOriginalRoot(string mode)
    {
        await using var fixture = new InfisicalSqlRotationPatchFixture(mode);
        var result = await fixture.RunAsync(InfisicalSqlRotationPatchFixture.Definition("MySql", "patch.empty"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(fixture.Residual).IsEqualTo(0);
        await Assert.That(fixture.Patches.Count).IsEqualTo(0);
        await Assert.That(fixture.Sources.Single().Registrations).IsEqualTo(0);
        await Assert.That(fixture.Sources.Single().RecoveryRoots.Distinct().Count()).IsEqualTo(1);
        await Assert.That(fixture.BorrowedIntact).IsTrue();
    }

    [Test]
    [Arguments("unsettled")]
    [Arguments("borrowed-damage")]
    public async Task UnsettledWorkOrBorrowedDamageCannotBeForceCleaned(string mode)
    {
        await using var fixture = new InfisicalSqlRotationPatchFixture(mode);
        var result = await fixture.RunAsync(InfisicalSqlRotationPatchFixture.Definition("MsSql", "patch.empty",
            "lost-response-no-replay"));
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(fixture.Patches.Count).IsEqualTo(1);
        await Assert.That(fixture.Residual).IsGreaterThan(0);
    }
}
