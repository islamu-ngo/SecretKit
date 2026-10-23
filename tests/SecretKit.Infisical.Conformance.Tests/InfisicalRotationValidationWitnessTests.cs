using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationValidationWitnessTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private const string ConnectionId = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    private const string ExternalId = "cccccccc-cccc-cccc-cccc-cccccccccccc";
    private const string Password32 = "aaaaaaaaAAAAAAAA11111111!!!!!!!!";
    private const string Policy24 = "abcdefghijklmnopqr_-.~!1";
    private const string Policy32 = "abcdefghijklmnopqrstuvwxyz_-.~!1";
    private static readonly JsonSerializerOptions Options = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "SecretRotations.MysqlCredentials", "selected-contract", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "SecretRotations.MssqlCredentials", "selected-contract", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "isActive.true", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "isActive.true", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "isActive.false", "independent-effect", "inactive")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "isActive.false", "independent-effect", "inactive")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "SecretRotations.MysqlCredentials", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "SecretRotations.MssqlCredentials", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "isActive.true", "independent-effect", "activate")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "isActive.true", "independent-effect", "activate")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "isActive.false", "independent-effect", "deactivate")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "isActive.false", "independent-effect", "deactivate")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "GetValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "GetValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ListValidationRulesAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ListValidationRulesAsync", "kind.SecretRotations", "independent-effect", "active")]
    public async Task SqlRuleTransitionsRequireMeasuredTwoCycleCredentials(InfisicalRotationProfile profile,
        string method, string variant, string boundary, string transition)
        => await RuleTransitionAsync(method, variant, boundary, transition, profile);

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "bare-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "bare-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "no-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "no-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "combined", "inactive", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "combined", "inactive", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "prefix", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "prefix", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "suffix", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "suffix", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "no-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "no-regex", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "combined", "activate", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "combined", "activate", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "combined", "deactivate", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "combined", "deactivate", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "GetValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "GetValidationRuleAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ListValidationRulesAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ListValidationRulesAsync", "combined", "active", "independent-effect")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "combined", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "combined", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "combined", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "combined", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "CreateValidationRuleAsync", "combined", "active", "lost-response-no-replay")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "CreateValidationRuleAsync", "combined", "active", "lost-response-no-replay")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "regex", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "regex", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "prefix", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "prefix", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "UpdateValidationRuleAsync", "suffix", "active", "lost-response-no-replay")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "UpdateValidationRuleAsync", "suffix", "active", "lost-response-no-replay")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "denied-authority")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "cancellation-boundary")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "lost-response-no-replay")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "DeleteValidationRuleAsync", "combined", "active", "lost-response-no-replay")]
    public async Task SqlRegexAndAffixesIgnoreGenerationBounds(InfisicalRotationProfile profile,
        string method, string shape, string transition, string boundary)
        => await RegexTransitionAsync(method, transition == "inactive" || transition == "deactivate" ?
            "isActive.false" : transition == "activate" ? "isActive.true" : "kind.SecretRotations",
            shape, transition, boundary, profile);

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-account-host")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "user-substitute")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "identity-database")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "missing-identity")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-identity-branch")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "connecting-login")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "execution-login")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "database-user")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "original-sid")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "execution-sid")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "database-sid")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "identity-database")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "missing-identity")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-identity-branch")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "rekey-sids")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-credentials")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-credentials")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "previous-invalidated")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "previous-invalidated")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-actions")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-actions")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "config-changed")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "config-changed")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "config-enabled")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "config-enabled")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ignored-rule")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ignored-rule")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-length")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-length")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-alphabet")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-alphabet")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-authenticated-user")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-authenticated-user")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrong-coordinate")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrong-coordinate")]
    public async Task SqlCredentialIdentityCannotBeInferredFromSuppliedUsername(InfisicalRotationProfile profile, string mode)
    {
        await using var wire = new RotationValidationWire(mode, profile);
        var input = Input("UpdateValidationRuleAsync", profile: profile);
        if (mode == "ignored-rule")
        {
            // A post-update closed32 fallback must differ from the selected rule.
            // Ignoring an exact32 rule would otherwise generate a legal password.
            input["seed"]!["passwordConstraints"]!["minimumLength"] = 32;
            input["seed"]!["passwordConstraints"]!["maximumLength"] = 32;
            input["change"]!["passwordConstraints"]!["minimumLength"] = 24;
            input["change"]!["passwordConstraints"]!["maximumLength"] = 24;
        }
        var result = await RunAsync(wire, "UpdateValidationRuleAsync", input: input);
        var captured = wire.Issued.ToArray();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(captured.Length).IsEqualTo(2);
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.OwnerDisposals).IsEqualTo(1);
        await Assert.That(wire.RotationCreates).IsEqualTo(1);
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsTrue();
        await Assert.That(wire.FinalInventoryExactCompleteAndBound).IsTrue();
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "catalog-incomplete")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "catalog-unbound")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "catalog-duplicate")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "catalog-other-host")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "policy-incompatible")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "policy-incomplete")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-incomplete")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-unbound")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-duplicate")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-cross-mapped")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-contained")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-server-incomplete")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "catalog-database-incomplete")]
    public async Task SqlInitialCatalogMustQualifyBeforeRotationCreation(InfisicalRotationProfile profile, string mode)
    {
        await using var wire = new RotationValidationWire(mode, profile);
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: Input("CreateValidationRuleAsync", profile: profile));
        var captured = wire.Issued.ToArray();
        // This injected factory already claimed the pair. Persistent unbound or
        // incomplete final evidence cannot certify compensation after admission fails.
        string reason = mode is "catalog-incomplete" or "catalog-unbound" or "catalog-server-incomplete" or
            "catalog-database-incomplete" or "catalog-other-host" or "policy-incomplete" or "policy-incompatible" ?
            "cleanup-incomplete" : "observer-unavailable";
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.CatalogReads).IsGreaterThan(0);
        await Assert.That(wire.RotationCreates + wire.ManualRotations + wire.RuntimeMutations).IsEqualTo(0);
        await Assert.That(captured.Length).IsEqualTo(0);
        await Assert.That(wire.OwnerCreates).IsEqualTo(wire.OwnerDisposals);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    [Test]
    [Arguments("good", "observed")]
    [Arguments("catalog-other-host", "cleanup-incomplete")]
    [Arguments("policy-incompatible", "cleanup-incomplete")]
    public async Task NativeMysqlCatalogParticipatesInOriginalRotationWitness(string mode, string reason)
    {
        await using var wire = new RotationValidationWire(mode, InfisicalRotationProfile.MysqlCredentials)
        {
            NativeMysqlCatalog = true
        };

        var result = await RunAsync(wire, "CreateValidationRuleAsync",
            input: Input("CreateValidationRuleAsync", profile: InfisicalRotationProfile.MysqlCredentials));

        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.CatalogReads).IsGreaterThan(0);
        await Assert.That(wire.OwnerCreates).IsEqualTo(wire.OwnerDisposals);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
        if (mode != "good") await Assert.That(wire.RotationCreates + wire.ManualRotations).IsEqualTo(0);
        else await Assert.That(wire.ManualRotations).IsEqualTo(2);
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ignored-regex", "regex")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ignored-regex", "regex")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "wrongcase", "regex")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "wrongcase", "regex")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "missing-prefix", "prefix")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "missing-prefix", "prefix")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "missing-suffix", "suffix")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "missing-suffix", "suffix")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "swapped-affixes", "combined")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "swapped-affixes", "combined")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "bounds-overriding-regex", "combined")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "bounds-overriding-regex", "combined")]
    public async Task SqlMetadataCannotHideMiddleAndAffixFaults(InfisicalRotationProfile profile, string mode, string shape)
    {
        await using var wire = new RotationValidationWire(mode, profile);
        var result = await RunAsync(wire, "UpdateValidationRuleAsync",
            input: ShapedInput("UpdateValidationRuleAsync", shape, profile: profile));
        var captured = wire.Issued.ToArray();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(captured.Length).IsEqualTo(2);
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsTrue();
        await Assert.That(wire.FinalInventoryExactCompleteAndBound).IsTrue();
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    [Arguments(InfisicalRotationProfile.OracledbCredentials)]
    public async Task SqlProfileProviderMismatchRemainsUnavailableBeforeOwnerWork(InfisicalRotationProfile profile)
    {
        await using var wire = new RotationValidationWire(profile: profile);
        var input = Input("CreateValidationRuleAsync", profile: profile);
        foreach (string stage in new[] { "seed", "change" })
            input[stage]!["providers"] = JsonSerializer.SerializeToNode(new[] { InfisicalValidationProvider.PostgresCredentials }, Options);
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: input);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates + wire.ProviderMutations + wire.ManualRotations).IsEqualTo(0);
    }

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "retain-other-host")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "policy-changed")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-server-only")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-database-only")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "ack-only-absence")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "ack-only-absence")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "bad-rejection-user")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "bad-rejection-user")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "bad-rejection-identity")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "bad-rejection-identity")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "retain-config")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-config")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "retain-secrets")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-secrets")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "retain-credentials")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-credentials")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "retain-roles")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "retain-roles")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "password-ignored")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "password-ignored")]
    public async Task SqlCleanupRequiresRejectedPairsAndCompleteIndependentAbsence(InfisicalRotationProfile profile, string mode)
    {
        await using var wire = new RotationValidationWire(mode, profile);
        var result = await RunAsync(wire, "UpdateValidationRuleAsync", input: Input("UpdateValidationRuleAsync", profile: profile));
        var captured = wire.Issued.ToArray();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(captured.Length).IsEqualTo(2);
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.OwnerDisposals).IsEqualTo(1);
        await Assert.That(wire.BothCleanupFlags).IsTrue();
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    [Test]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments("CreateValidationRuleAsync", "SecretRotations.PostgresCredentials", "selected-contract", "active")]
    [Arguments("CreateValidationRuleAsync", "isActive.true", "independent-effect", "active")]
    [Arguments("CreateValidationRuleAsync", "isActive.false", "independent-effect", "inactive")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments("UpdateValidationRuleAsync", "SecretRotations.PostgresCredentials", "independent-effect", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments("UpdateValidationRuleAsync", "isActive.true", "independent-effect", "activate")]
    [Arguments("UpdateValidationRuleAsync", "isActive.false", "independent-effect", "deactivate")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "denied-authority", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "cancellation-boundary", "active")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "lost-response-no-replay", "active")]
    [Arguments("GetValidationRuleAsync", "kind.SecretRotations", "independent-effect", "active")]
    [Arguments("ListValidationRulesAsync", "kind.SecretRotations", "independent-effect", "active")]
    public async Task RuleTransitionRequiresTwoManualRotationsAndActualRetainedCredentials(
        string method, string variant, string boundary, string transition)
        => await RuleTransitionAsync(method, variant, boundary, transition, InfisicalRotationProfile.PostgresCredentials);

    private static async Task RuleTransitionAsync(string method, string variant, string boundary, string transition,
        InfisicalRotationProfile profile)
    {
        // Given a borrowed connection, two locally owned roles and independent native stores.
        await using var wire = new RotationValidationWire(profile: profile);
        bool applied = boundary is not "denied-authority" and not "cancellation-boundary";
        var input = Input(method, applied, transition, profile);
        // When the public rule operation is bracketed by exactly one manual rotation on each side.
        var result = await RunAsync(wire, method, variant, boundary, input);
        var captured = wire.Issued.ToArray();
        // Then rule metadata alone cannot certify the resulting database passwords.
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        bool mutation = method is "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" or "DeleteValidationRuleAsync";
        await Assert.That(wire.RuntimeMutations).IsEqualTo(mutation && applied ? 1 : 0);
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.OwnerDisposals).IsEqualTo(1);
        await Assert.That(wire.RotationCreates).IsEqualTo(1);
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(wire.Issued.Count).IsEqualTo(2);
        await Assert.That(captured.Length).IsEqualTo(2);
        await Assert.That(captured[0].Password == Password32 || captured[0].Password == Policy24).IsTrue();
        await Assert.That(captured[1].Password == Password32 || captured[1].Password == Policy24 ||
            captured[1].Password == Policy32).IsTrue();
        await Assert.That(wire.Issued[0].Password.Length).IsEqualTo(
            method == "CreateValidationRuleAsync" || transition == "activate" ? 32 : 24);
        int after = method switch
        {
            "CreateValidationRuleAsync" => applied && transition != "inactive" ? 24 : 32,
            "UpdateValidationRuleAsync" => transition == "activate" ? 24 :
                transition == "deactivate" || applied ? 32 : 24,
            "DeleteValidationRuleAsync" => applied ? 32 : 24,
            _ => 24
        };
        await Assert.That(wire.Issued[1].Password.Length).IsEqualTo(after);
        await Assert.That(wire.Issued[0].User == wire.Issued[1].User).IsFalse();
        await Assert.That(wire.Issued.All(pair => wire.Accepted.Contains(pair) &&
            wire.WrongPasswordRejected.Contains(pair) && wire.AcceptedAgain.Contains(pair) &&
            wire.RejectedAfterCleanup.Contains(pair))).IsTrue();
        await Assert.That(wire.PreviousActiveAcceptedAfterSecondRotation).IsTrue();
        await Assert.That(wire.RuntimeMappedReads).IsEqualTo(4);
        await Assert.That(wire.ProjectInventoryBeforeOwnership).IsTrue();
        await Assert.That(wire.ProjectInventoriesOnly).IsTrue();
        await Assert.That(wire.AdminManualRotationsOnly).IsTrue();
        await Assert.That(wire.BothCleanupFlags).IsTrue();
        await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsTrue();
        await Assert.That(wire.FinalInventoryExactCompleteAndBound).IsTrue();
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
        await Assert.That(wire.RecordCount).IsEqualTo(0);
        await Assert.That(wire.OwnedRoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "combined", "active", "independent-effect")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "bare-regex", "active", "independent-effect")]
    [Arguments("CreateValidationRuleAsync", "SecretRotations.PostgresCredentials", "no-regex", "active", "independent-effect")]
    [Arguments("CreateValidationRuleAsync", "isActive.false", "combined", "inactive", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "regex", "active", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "SecretRotations.PostgresCredentials", "prefix", "active", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "suffix", "active", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "combined", "active", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "no-regex", "active", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "isActive.true", "combined", "activate", "independent-effect")]
    [Arguments("UpdateValidationRuleAsync", "isActive.false", "combined", "deactivate", "independent-effect")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "combined", "active", "independent-effect")]
    [Arguments("GetValidationRuleAsync", "kind.SecretRotations", "combined", "active", "independent-effect")]
    [Arguments("ListValidationRulesAsync", "kind.SecretRotations", "combined", "active", "independent-effect")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "combined", "active", "denied-authority")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "combined", "active", "cancellation-boundary")]
    [Arguments("CreateValidationRuleAsync", "kind.SecretRotations", "combined", "active", "lost-response-no-replay")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "regex", "active", "denied-authority")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "prefix", "active", "cancellation-boundary")]
    [Arguments("UpdateValidationRuleAsync", "kind.SecretRotations", "suffix", "active", "lost-response-no-replay")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "combined", "active", "denied-authority")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "combined", "active", "cancellation-boundary")]
    [Arguments("DeleteValidationRuleAsync", "kind.SecretRotations", "combined", "active", "lost-response-no-replay")]
    public async Task RegexMiddleAndAffixesDriveMeasuredCredentialsWithoutChangingRotation(
        string method, string variant, string shape, string transition, string boundary)
        => await RegexTransitionAsync(method, variant, shape, transition, boundary, InfisicalRotationProfile.PostgresCredentials);

    private static async Task RegexTransitionAsync(string method, string variant, string shape, string transition,
        string boundary, InfisicalRotationProfile profile)
    {
        await using var wire = new RotationValidationWire(profile: profile);
        bool applied = boundary is not "denied-authority" and not "cancellation-boundary";
        var result = await RunAsync(wire, method, variant, boundary, ShapedInput(method, shape, applied, transition, profile));
        var captured = wire.Issued.ToArray();
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(captured.Length).IsEqualTo(2);
        bool baselineActive = method != "CreateValidationRuleAsync" && transition != "activate";
        bool afterActive = method switch
        {
            "CreateValidationRuleAsync" => applied && transition != "inactive",
            "DeleteValidationRuleAsync" => !applied,
            "UpdateValidationRuleAsync" => applied ? transition != "deactivate" : baselineActive,
            _ => baselineActive
        };
        string before = baselineActive ? ShapedPassword(shape, false) : Password32;
        bool changed = applied && method is "CreateValidationRuleAsync" or "UpdateValidationRuleAsync";
        string after = afterActive ? ShapedPassword(shape, changed) : Password32;
        await Assert.That(wire.Issued[0].Password).IsEqualTo(before);
        await Assert.That(wire.Issued[1].Password).IsEqualTo(after);
        await Assert.That(wire.Issued[0].User == wire.Issued[1].User).IsFalse();
        await Assert.That(wire.Issued.All(pair => wire.Accepted.Contains(pair) &&
            wire.WrongPasswordRejected.Contains(pair) && wire.AcceptedAgain.Contains(pair) &&
            wire.RejectedAfterCleanup.Contains(pair))).IsTrue();
        await Assert.That(wire.PreviousActiveAcceptedAfterSecondRotation).IsTrue();
        await Assert.That(wire.RuntimeMappedReads).IsEqualTo(4);
        await Assert.That(wire.RuntimeMutations).IsEqualTo(
            applied && method is "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" or "DeleteValidationRuleAsync" ? 1 : 0);
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.OwnerDisposals).IsEqualTo(1);
        await Assert.That(wire.RotationCreates).IsEqualTo(1);
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.AdminManualRotationsOnly && wire.BothCleanupFlags).IsTrue();
        await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsTrue();
        await Assert.That(wire.FinalInventoryExactCompleteAndBound).IsTrue();
        await Assert.That(wire.ProjectInventoryBeforeOwnership && wire.ProjectInventoriesOnly).IsTrue();
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
        await Assert.That(wire.RecordCount + wire.OwnedRoleCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ignored-regex", "regex")]
    [Arguments("wrongcase", "regex")]
    [Arguments("missing-prefix", "prefix")]
    [Arguments("missing-suffix", "suffix")]
    [Arguments("swapped-affixes", "combined")]
    [Arguments("bounds-overriding-regex", "combined")]
    public async Task MetadataCannotHideRegexOrAffixGenerationFaults(string mode, string shape)
    {
        await using var wire = new RotationValidationWire(mode);
        var result = await RunAsync(wire, "UpdateValidationRuleAsync",
            input: ShapedInput("UpdateValidationRuleAsync", shape));
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.ManualRotations).IsEqualTo(2);
        await Assert.That(wire.RuntimeMutations).IsEqualTo(1);
        await Assert.That(wire.RotationUpdates).IsEqualTo(0);
        await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsTrue();
        await Assert.That(wire.FinalInventoryExactCompleteAndBound).IsTrue();
        await Assert.That(wire.RecordCount + wire.OwnedRoleCount).IsEqualTo(0);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    [Test]
    [Arguments("regexPattern", "^safe")]
    [Arguments("regexPattern", "^[A-Z]{32}$")]
    [Arguments("regexPattern", "^[a-z]{24}$.*")]
    [Arguments("requiredPrefix", "safe_")]
    [Arguments("requiredSuffix", "_B_")]
    [Arguments("uniqueAcrossLastVersions", "2")]
    [Arguments("uniqueWithinScope", "true")]
    public async Task UnsupportedRegexAffixesAndReuseRemainUnavailableBeforeOwnership(string field, string value)
    {
        await using var wire = new RotationValidationWire();
        var input = ShapedInput("CreateValidationRuleAsync", "combined");
        var constraints = input["change"]!["passwordConstraints"]!;
        constraints[field] = field switch
        {
            "uniqueAcrossLastVersions" => JsonValue.Create(int.Parse(value)),
            "uniqueWithinScope" => JsonValue.Create(bool.Parse(value)),
            _ => JsonValue.Create(value)
        };
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: input);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates + wire.ProviderMutations + wire.ManualRotations).IsEqualTo(0);
        await Assert.That(wire.RecordCount + wire.OwnedRoleCount).IsEqualTo(0);
    }

    [Test]
    public async Task RegexCancellationStillRequiresInjectedOfflineCompletion()
    {
        await using var wire = new RotationValidationWire();
        var result = await RunAsync(wire, "UpdateValidationRuleAsync", boundary: "cancellation-boundary",
            input: ShapedInput("UpdateValidationRuleAsync", "regex", false), supplyOfflineTransport: false);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates + wire.ProviderMutations).IsEqualTo(0);
    }

    [Test]
    [Arguments("ignored-rule", "effect-mismatch")]
    [Arguments("wrong-length", "effect-mismatch")]
    [Arguments("wrong-alphabet", "effect-mismatch")]
    [Arguments("wrong-credentials", "effect-mismatch")]
    // A password-ignoring route also prevents proving revocation before role removal.
    [Arguments("password-ignored", "cleanup-incomplete")]
    [Arguments("wrong-authenticated-user", "effect-mismatch")]
    [Arguments("wrong-coordinate", "effect-mismatch")]
    [Arguments("wrong-actions", "effect-mismatch")]
    [Arguments("previous-invalidated", "effect-mismatch")]
    [Arguments("config-changed", "effect-mismatch")]
    [Arguments("config-enabled", "effect-mismatch")]
    [Arguments("unavailable", "observer-unavailable")]
    [Arguments("retain-config", "cleanup-incomplete")]
    [Arguments("retain-secrets", "cleanup-incomplete")]
    [Arguments("retain-credentials", "cleanup-incomplete")]
    [Arguments("retain-roles", "cleanup-incomplete")]
    public async Task NativeAcknowledgementsCannotHideCredentialConfigurationOrCleanupFaults(
        string mode, string reason)
    {
        // Given metadata-correct rules and one independently injected downstream fault.
        await using var wire = new RotationValidationWire(mode);
        // When an active rule changes 24 to 32 without editing rotation parameters.
        var result = await RunAsync(wire, "UpdateValidationRuleAsync");
        // Then measured credentials, unchanged configuration and independently observed absence decide.
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates).IsEqualTo(1);
        await Assert.That(wire.RotationCreates).IsEqualTo(1);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
        if (mode == "retain-roles") await Assert.That(wire.OwnedRoleCount).IsEqualTo(2);
        else await Assert.That(wire.OwnedRoleCount).IsEqualTo(0);
        if (mode == "retain-credentials")
            await Assert.That(wire.CredentialsRejectedBeforeOwnerDisposal).IsFalse();
        if (mode == "retain-config") await Assert.That(wire.RotationCount).IsEqualTo(1);
        if (mode == "retain-secrets") await Assert.That(wire.MappedSecretCount).IsEqualTo(2);
    }

    [Test]
    [Arguments("other-active", "missing-prerequisite")]
    [Arguments("other-inactive", "missing-prerequisite")]
    [Arguments("missing-project", "observer-unavailable")]
    [Arguments("incomplete-project", "observer-unavailable")]
    [Arguments("unbound-project", "observer-unavailable")]
    [Arguments("missing-owner", "observer-unavailable")]
    [Arguments("missing-observer", "observer-unavailable")]
    [Arguments("missing-trial", "missing-input")]
    [Arguments("bad-budget", "missing-input")]
    [Arguments("bad-port", "missing-input")]
    [Arguments("bad-connection", "missing-input")]
    [Arguments("unsupported-provider", "observer-unavailable")]
    [Arguments("unsupported-constraint", "observer-unavailable")]
    [Arguments("unscoped-rule", "observer-unavailable")]
    [Arguments("wrong-owner-coordinate", "observer-unavailable")]
    [Arguments("duplicate-owner-names", "observer-unavailable")]
    public async Task AdmissionMustPrecedeOwnershipAndRejectUnrelatedProjectRules(string mode, string reason)
    {
        // Given a missing prerequisite, invalid input or unusable owned account fixture.
        await using var wire = new RotationValidationWire(mode);
        var input = Input("CreateValidationRuleAsync");
        switch (mode)
        {
            case "missing-trial": input["rotationTrial"] = null; break;
            case "bad-budget": input["maximumItems"] = 0; break;
            case "bad-port": input["rotationTrial"]!["port"] = 0; break;
            case "bad-connection": input["rotationTrial"]!["connectionId"] = "not-a-uuid"; break;
            case "unsupported-provider": input["change"]!["providers"] = new JsonArray("MysqlCredentials"); break;
            case "unsupported-constraint": input["change"]!["passwordConstraints"]!["regexPattern"] = "^safe"; break;
            case "unscoped-rule": input["change"]!["supplyEnvironment"] = false; break;
        }
        // When the registered family attempts admission, not adoption of external resources.
        var result = await RunAsync(wire, "CreateValidationRuleAsync", input: input,
            supplyOwner: mode != "missing-owner", supplyObserver: mode != "missing-observer");
        // Then prerequisites fail before provider work; only malformed owner output requires ownership.
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.RotationCreates).IsEqualTo(0);
        bool badOwner = mode is "wrong-owner-coordinate" or "duplicate-owner-names";
        await Assert.That(wire.OwnerCreates).IsEqualTo(badOwner ? 1 : 0);
        if (!badOwner) await Assert.That(wire.ProviderMutations).IsEqualTo(0);
        await Assert.That(wire.OwnedRoleCount).IsEqualTo(0);
        await Assert.That(wire.UnrelatedRuleCount).IsEqualTo(mode.StartsWith("other-", StringComparison.Ordinal) ? 1 : 0);
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    [Test]
    public async Task NativeCancellationCannotQualifyWithoutBoundProviderCompletion()
    {
        await using var wire = new RotationValidationWire();
        var result = await RunAsync(wire, "UpdateValidationRuleAsync",
            boundary: "cancellation-boundary", supplyOfflineTransport: false);
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnerCreates).IsEqualTo(0);
        await Assert.That(wire.ProviderMutations).IsEqualTo(0);
    }

    [Test]
    public async Task FixturePublicSchemasDriveTwoCyclesAndRevocationDoesNotDeleteOwnedRoles()
        => await FixturePublicSchemasAsync("plain");

    [Test]
    [Arguments("regex")]
    [Arguments("bare-regex")]
    [Arguments("prefix")]
    [Arguments("suffix")]
    [Arguments("combined")]
    [Arguments("no-regex")]
    public async Task IndependentPublicTransportGeneratesRegexMiddleThenWrapsAffixes(string shape)
        => await FixturePublicSchemasAsync(shape);

    [Test]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "plain")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "plain")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "regex")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "regex")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "bare-regex")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "bare-regex")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "prefix")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "prefix")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "suffix")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "suffix")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "combined")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "combined")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "no-regex")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "no-regex")]
    public async Task SqlFixturePublicSchemasDriveActualMappedCredentials(InfisicalRotationProfile profile, string shape)
        => await FixturePublicSchemasAsync(shape, profile);

    private static async Task FixturePublicSchemasAsync(string shape,
        InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
    {
        // Given the same TCP/native transport and independent role store used by the Red witnesses.
        await using var wire = new RotationValidationWire(profile: profile);
        var configured = shape == "plain" ? Input("CreateValidationRuleAsync", profile: profile) :
            ShapedInput("CreateValidationRuleAsync", shape, profile: profile);
        using var env = Environment(wire, Row("CreateValidationRuleAsync"), configured);
        var input = configured.Deserialize<ValidationPoliciesEffects.PolicyInput>(Options)!;
        await using var folder = new StaticOwnedFixture(env, input.Fixture, new NativeCaseProbe(), "offline");
        await folder.InitializeAsync(CancellationToken.None);
        var accounts = await wire.CreateAsync("project", input.RotationTrial!, CancellationToken.None);
        RotationIdentityCatalogFacts? initialCatalog = profile == InfisicalRotationProfile.PostgresCredentials ? null :
            await wire.InspectIdentityCatalogAsync(accounts.Coordinate, wire.OwnedNames, CancellationToken.None);
        try
        {
            var management = env.CreateManagementClient();
            string id = await CreateFixtureRotationAsync(env, management, accounts, folder.Folder, profile);
            var address = new InfisicalRotationAddress("project", "env", folder.Folder, profile, id);
            var a0 = wire.Active;
            await using var runtime = env.CreateRuntimeClient();
            using var http = new HttpClient(wire, disposeHandler: false);
            var authority = new SecretAuthority();
            var client = new InfisicalRotationClient(new UriBuilder(wire.Origin) { Scheme = "https" }.Uri,
                http, authority, new(authority, env.Tokens(NativeIdentityRole.Administrative), "project"));
            var target = new SecretReference(authority, address);
            var first = await client.RotateSecretsAsync(target, new(target, InfisicalRotationAction.RotateSecrets));
            await Assert.That(first.IsSuccess).IsTrue();
            var b1 = await ReadPairAsync(runtime, folder.Folder, "fixture-user", "fixture-password");
            await Assert.That(b1.Password).IsEqualTo(Password32);
            await Assert.That((await MeasureAsync(wire, accounts.Coordinate, a0)).Authentication).IsEqualTo(BackendAuthentication.Accepted);
            var ruleTarget = new SecretReference(folder.Setup.Authority,
                new InfisicalValidationAddress("project", InfisicalValidationKind.SecretRotations,
                    environment: "env", secretPath: folder.Folder));
            var seeded = await folder.Setup.CreateValidationRuleAsync(ruleTarget,
                input.Change.Build("fixture-rule", folder, true),
                new(folder.Setup.Authority, env.Tokens(NativeIdentityRole.Setup), "project"),
                new(ruleTarget));
            await Assert.That(seeded.IsSuccess).IsTrue();
            var second = await client.RotateSecretsAsync(target, new(target, InfisicalRotationAction.RotateSecrets));
            await Assert.That(second.IsSuccess).IsTrue();
            var a2 = await ReadPairAsync(runtime, folder.Folder, "fixture-user", "fixture-password");
            var actualIdentity = await MeasureAsync(wire, accounts.Coordinate, a2);
            await Assert.That(a2.User).IsEqualTo(a0.User);
            await Assert.That(a2.Password).IsEqualTo(shape == "plain" ? Policy24 : ShapedPassword(shape, true));
            await Assert.That((await MeasureAsync(wire, accounts.Coordinate, a0)).Authentication).IsEqualTo(BackendAuthentication.Rejected);
            await Assert.That((await MeasureAsync(wire, accounts.Coordinate, b1)).Authentication).IsEqualTo(BackendAuthentication.Accepted);
            using var wrong = SecretMaterial.FromText("deliberately-wrong");
            using var user = SecretMaterial.FromText(a2.User);
            await Assert.That((await wire.MeasureCredentialsAsync(accounts.Coordinate, user, wrong, CancellationToken.None)).Authentication)
                .IsEqualTo(BackendAuthentication.Rejected);
            await Assert.That((await MeasureAsync(wire, accounts.Coordinate, a2)).AuthenticatedUsername).IsEqualTo(a2.User);
            if (profile == InfisicalRotationProfile.MysqlCredentials)
            {
                await Assert.That(actualIdentity.Identity!.Mysql!.CurrentUser).IsEqualTo(a2.User + "@%");
                await Assert.That(actualIdentity.Identity.Mysql.Database).IsEqualTo("database");
                await Assert.That(actualIdentity.Identity.Mssql is null).IsTrue();
                await Assert.That(initialCatalog!.Mysql!.Accounts.Select(a => a.Host).ToArray()).IsEquivalentTo(new[] { "%", "%" });
            }
            if (profile == InfisicalRotationProfile.MssqlCredentials)
            {
                var measured = actualIdentity.Identity!.Mssql!;
                var login = initialCatalog!.Mssql!.ServerPrincipals.Single(a => a.Name == a2.User);
                var databaseUser = initialCatalog.Mssql.DatabasePrincipals.Single(a => a.Name == a2.User);
                await Assert.That(measured.OriginalLogin).IsEqualTo(a2.User);
                await Assert.That(measured.ExecutionLogin).IsEqualTo(a2.User);
                await Assert.That(measured.DatabaseUser).IsEqualTo(a2.User);
                await Assert.That(measured.Database).IsEqualTo("database");
                await Assert.That(measured.OriginalLoginSid.SequenceEqual(login.Sid)).IsTrue();
                await Assert.That(measured.ExecutionLoginSid.SequenceEqual(login.Sid)).IsTrue();
                await Assert.That(measured.DatabaseUserSid.SequenceEqual(databaseUser.Sid)).IsTrue();
                await Assert.That(login.Sid.SequenceEqual(databaseUser.Sid)).IsTrue();
                await Assert.That(ReferenceEquals(login.Sid, databaseUser.Sid)).IsFalse();
                await Assert.That(ReferenceEquals(measured.OriginalLoginSid, measured.ExecutionLoginSid)).IsFalse();
                await Assert.That(actualIdentity.Identity.Mysql is null).IsTrue();
            }
            await RemoveFixtureRotationAsync(env, management, address);
            foreach (var pair in new[] { a0, b1, a2 })
            {
                var rejection = await MeasureAsync(wire, accounts.Coordinate, pair);
                await Assert.That(rejection.Authentication).IsEqualTo(BackendAuthentication.Rejected);
                await Assert.That(rejection.AuthenticatedUsername is null && rejection.Identity is null).IsTrue();
            }
            foreach (string key in new[] { "fixture-user", "fixture-password" })
                await Assert.That((await runtime.ReadAsync(new(runtime.Authority,
                    new InfisicalSecretAddress("project", "env", folder.Folder, key)))).Status).IsEqualTo(SecretStatus.Absent);
            await Assert.That(wire.OwnedRoleCount).IsEqualTo(2);
            await Assert.That(wire.RotationCount + wire.MappedSecretCount).IsEqualTo(0);
            var ownedRule = new SecretReference(folder.Administrative.Authority,
                new InfisicalValidationAddress("project", InfisicalValidationKind.SecretRotations, seeded.Value.Id,
                    "env", folder.Folder));
            var deletedRule = await folder.Administrative.DeleteValidationRuleAsync(ownedRule,
                new(folder.Administrative.Authority, env.Tokens(NativeIdentityRole.Administrative), "project"), new(ownedRule));
            await Assert.That(deletedRule.IsSuccess).IsTrue();
        }
        finally { await accounts.DisposeAsync(); }
        if (profile == InfisicalRotationProfile.PostgresCredentials)
        {
            var inventory = await wire.InspectUsernamesAsync(new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database"),
                wire.OwnedNames, CancellationToken.None);
            await Assert.That(inventory.IsComplete).IsTrue();
            await Assert.That(inventory.ExistingUsernames.Length).IsEqualTo(0);
        }
        else
        {
            var inventory = await wire.InspectIdentityCatalogAsync(accounts.Coordinate, wire.OwnedNames, CancellationToken.None);
            await Assert.That(inventory.RequestedUsernames).IsEquivalentTo(wire.OwnedNames);
            if (profile == InfisicalRotationProfile.MysqlCredentials)
            {
                await Assert.That(inventory.Mysql!.AllHostsComplete).IsTrue();
                await Assert.That(inventory.Mysql.Accounts.Length).IsEqualTo(0);
                await Assert.That(inventory.Mysql.PasswordPolicy.Policy).IsEqualTo(0);
            }
            else
            {
                await Assert.That(inventory.Mssql!.ServerPrincipalsComplete && inventory.Mssql.DatabasePrincipalsComplete).IsTrue();
                await Assert.That(inventory.Mssql.ServerPrincipals.Length + inventory.Mssql.DatabasePrincipals.Length).IsEqualTo(0);
            }
        }
        await Assert.That(wire.BorrowedConnectionRetained && wire.UnownedRoleRetained).IsTrue();
    }

    private static async Task<string> CreateFixtureRotationAsync(NativeEnvironment env, ManagementClient management,
        IInfisicalRotationValidationAccounts accounts, string folder, InfisicalRotationProfile profile)
    {
        if (profile == InfisicalRotationProfile.MysqlCredentials)
        {
            using var parameters = new MySqlRotationParameters(accounts.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!"));
            using var request = MySqlSecretRotationOperations.Create("organization", new("fixture", "project", "env",
                folder, ConnectionId, 1, parameters, new("fixture-user", "fixture-password"), isAutoRotationEnabled: false));
            var result = await ExecuteAsync(env, management, request, NativeIdentityRole.Setup, true);
            await Assert.That(result.IsSuccess).IsTrue();
            using var config = result.Value;
            await Assert.That(config.ConnectionId).IsEqualTo(ConnectionId);
            await Assert.That(config.Parameters.PasswordRequirements!.Length).IsEqualTo(32);
            await Assert.That(config.Parameters.PasswordRequirements.Digits).IsEqualTo(8);
            await Assert.That(config.IsAutoRotationEnabled).IsFalse();
            return config.Id;
        }
        if (profile == InfisicalRotationProfile.MssqlCredentials)
        {
            using var parameters = new MsSqlRotationParameters(accounts.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!"));
            using var request = MsSqlSecretRotationOperations.Create("organization", new("fixture", "project", "env",
                folder, ConnectionId, 1, parameters, new("fixture-user", "fixture-password"), isAutoRotationEnabled: false));
            var result = await ExecuteAsync(env, management, request, NativeIdentityRole.Setup, true);
            await Assert.That(result.IsSuccess).IsTrue();
            using var config = result.Value;
            await Assert.That(config.ConnectionId).IsEqualTo(ConnectionId);
            await Assert.That(config.Parameters.PasswordRequirements!.Length).IsEqualTo(32);
            await Assert.That(config.Parameters.PasswordRequirements.Digits).IsEqualTo(8);
            await Assert.That(config.IsAutoRotationEnabled).IsFalse();
            return config.Id;
        }
        using var pg = new PostgresRotationParameters(accounts.Username1, accounts.Username2, new(32, 8, 8, 8, 8, "!"));
        using var create = PostgresSecretRotationOperations.Create("organization", new("fixture", "project", "env",
            folder, ConnectionId, 1, pg, new("fixture-user", "fixture-password"), isAutoRotationEnabled: false));
        var created = await ExecuteAsync(env, management, create, NativeIdentityRole.Setup, true);
        await Assert.That(created.IsSuccess).IsTrue();
        using var value = created.Value;
        await Assert.That(value.ConnectionId).IsEqualTo(ConnectionId);
        await Assert.That(value.Parameters.PasswordRequirements!.Length).IsEqualTo(32);
        await Assert.That(value.Parameters.PasswordRequirements.Digits).IsEqualTo(8);
        await Assert.That(value.IsAutoRotationEnabled).IsFalse();
        return value.Id;
    }

    private static async Task RemoveFixtureRotationAsync(NativeEnvironment env, ManagementClient management,
        InfisicalRotationAddress address)
    {
        if (address.Profile == InfisicalRotationProfile.MysqlCredentials)
        {
            using var remove = MySqlSecretRotationOperations.Delete("organization", address, true, true);
            var result = await ExecuteAsync(env, management, remove, NativeIdentityRole.Administrative, true);
            await Assert.That(result.IsSuccess).IsTrue();
            result.Value.Dispose();
            using var get = MySqlSecretRotationOperations.Get("organization", address);
            await Assert.That((await ExecuteAsync(env, management, get, NativeIdentityRole.Observer, false)).Status).IsEqualTo(SecretStatus.Absent);
        }
        else if (address.Profile == InfisicalRotationProfile.MssqlCredentials)
        {
            using var remove = MsSqlSecretRotationOperations.Delete("organization", address, true, true);
            var result = await ExecuteAsync(env, management, remove, NativeIdentityRole.Administrative, true);
            await Assert.That(result.IsSuccess).IsTrue();
            result.Value.Dispose();
            using var get = MsSqlSecretRotationOperations.Get("organization", address);
            await Assert.That((await ExecuteAsync(env, management, get, NativeIdentityRole.Observer, false)).Status).IsEqualTo(SecretStatus.Absent);
        }
        else
        {
            using var remove = PostgresSecretRotationOperations.Delete("organization", address, true, true);
            var result = await ExecuteAsync(env, management, remove, NativeIdentityRole.Administrative, true);
            await Assert.That(result.IsSuccess).IsTrue();
            result.Value.Dispose();
            using var get = PostgresSecretRotationOperations.Get("organization", address);
            await Assert.That((await ExecuteAsync(env, management, get, NativeIdentityRole.Observer, false)).Status).IsEqualTo(SecretStatus.Absent);
        }
    }

    private static async ValueTask<SecretOutcome<T>> ExecuteAsync<T>(NativeEnvironment env, ManagementClient client,
        ManagementRequest<T> request, NativeIdentityRole role, bool mutation) where T : notnull
    {
        var authority = env.CreateManagementAuthority(client, role, "organization", "project");
        return await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            mutation ? client.CreateReceipt(request) : null);
    }

    private static async Task<Pair> ReadPairAsync(InfisicalClient client, string folder, string usernameKey, string passwordKey)
    {
        var user = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress("project", "env", folder, usernameKey)));
        var password = await client.ReadAsync(new(client.Authority, new InfisicalSecretAddress("project", "env", folder, passwordKey)));
        using var u = user.Value;
        using var p = password.Value;
        return new(u.Material.Reveal(), p.Material.Reveal());
    }

    private static async ValueTask<RotationCredentialFacts> MeasureAsync(RotationValidationWire wire,
        RotationBackendCoordinate coordinate, Pair pair)
    {
        using var user = SecretMaterial.FromText(pair.User);
        using var password = SecretMaterial.FromText(pair.Password);
        return await wire.MeasureCredentialsAsync(coordinate, user, password, CancellationToken.None);
    }

    private static JsonObject Input(string method, bool applied = true, string transition = "active",
        InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
    {
        var provider = profile switch
        {
            InfisicalRotationProfile.MysqlCredentials => InfisicalValidationProvider.MysqlCredentials,
            InfisicalRotationProfile.MssqlCredentials => InfisicalValidationProvider.MssqlCredentials,
            _ => InfisicalValidationProvider.PostgresCredentials
        };
        ValidationPoliciesEffects.RuleInput Rule(int length, bool active) => new(null, null, active,
            null, null, new(length, length, null, null, null, null, null),
            [provider], true, true, false, false, false, false);
        var seed = Rule(24, transition != "activate");
        var change = method == "UpdateValidationRuleAsync" && transition == "active" ? Rule(32, true) :
            Rule(24, transition is not "inactive" and not "deactivate");
        return JsonSerializer.SerializeToNode(new ValidationPoliciesEffects.PolicyInput(
            new("project", "env", EnvironmentId, "/owned", [], StaticApiRevision.SecretsV4FoldersV2),
            InfisicalValidationKind.SecretRotations, seed, change, [], [],
            1000, false, applied, true, RotationTrial:
            new("organization", ConnectionId, "backend.invalid", 5432, "database", 1, ["select"], ["write"], profile)), Options)!.AsObject();
    }

    private static NativeCaseDefinition Row(string method, string variant = "kind.SecretRotations",
        string boundary = "independent-effect")
    {
        string member = method switch
        {
            "CreateValidationRuleAsync" or "UpdateValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalValidationInput,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            "DeleteValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalNativeAuthority,SecretKit.Core.MutationReceipt,System.Threading.CancellationToken)",
            "GetValidationRuleAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            "ListValidationRulesAsync" =>
                $"SecretKit.Infisical.InfisicalClient.{method}(SecretKit.Core.SecretReference,System.Int32,System.Boolean,System.Threading.CancellationToken)",
            _ => throw new ArgumentOutOfRangeException(nameof(method))
        };
        return new(new("Infisical", "i.runtime.InfisicalClient." + method, variant, "offline", boundary), member);
    }

    private static JsonObject ShapedInput(string method, string shape, bool applied = true, string transition = "active",
        InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
    {
        var input = Input(method, applied, transition, profile);
        foreach (string stage in new[] { "seed", "change" })
        {
            bool changed = stage == "change";
            int length = shape == "combined" || shape == "no-regex" && changed ? 32 : 24;
            input[stage]!["passwordConstraints"] = new JsonObject
            {
                ["minimumLength"] = length,
                ["maximumLength"] = length,
                ["regexPattern"] = shape == "no-regex" ? null :
                    shape == "regex" && !changed ? "^[A-Z]{24}$" : "^[a-z]{24}$",
                ["requiredPrefix"] = shape == "bare-regex" ? null : shape == "prefix" && changed ? "B_" : "A_",
                ["requiredSuffix"] = shape == "bare-regex" ? null : shape == "suffix" && changed ? "_B" : "_A",
                ["uniqueAcrossLastVersions"] = null,
                ["uniqueWithinScope"] = null
            };
        }
        return input;
    }

    private static string ShapedPassword(string shape, bool changed) =>
        (shape == "bare-regex" ? "" : shape == "prefix" && changed ? "B_" : "A_") +
        (shape == "no-regex" ? new string('*', changed ? 28 : 20) :
            new string(shape == "regex" && !changed ? 'A' : 'a', 24)) +
        (shape == "bare-regex" ? "" : shape == "suffix" && changed ? "_B" : "_A");

    private static NativeEnvironment Environment(RotationValidationWire wire, NativeCaseDefinition row, JsonObject input) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = wire.Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new JsonObject
            {
                ["C08-IR-ValidationPolicies"] = new JsonObject
                {
                    ["scopes"] = new JsonObject
                    {
                        [row.Key.Scope] = new JsonObject
                        {
                            [row.Key.Operation] = new JsonObject
                            {
                                [row.Key.Variant] = new JsonObject { [row.Key.Case] = input }
                            }
                        }
                    }
                }
            }
        }, Options));

    private static async Task<NativeCaseResult> RunAsync(RotationValidationWire wire, string method,
        string variant = "kind.SecretRotations", string boundary = "independent-effect",
        JsonObject? input = null, bool supplyOwner = true, bool supplyObserver = true, bool supplyOfflineTransport = true)
    {
        var row = Row(method, variant, boundary);
        using var env = Environment(wire, row, input ?? Input(method,
            boundary is not "denied-authority" and not "cancellation-boundary"));
        var registry = new NativeCaseRegistry();
        ValidationPoliciesEffects.Register(registry, env, [row],
            rotationFactory: supplyOwner ? wire : null, rotationBackend: supplyObserver ? wire : null,
            offlineRotationTransport: supplyOfflineTransport ? wire : null);
        return (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
    }

    private sealed record Pair(string User, string Password)
    {
        public override string ToString() => "[RotationPair]";
    }

    // Native metadata, mapped secrets and database roles are distinct stores.
    // Neither deleting a native record nor returning a successful HTTP response authenticates a pair.
    private sealed class RotationValidationWire : HttpMessageHandler, IAsyncDisposable,
        IInfisicalRotationValidationAccountFactory, IInfisicalRotationCredentialObserver,
        IInfisicalDynamicUsernameObserver, IInfisicalRotationIdentityCatalogObserver
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<string, JsonObject> rules = [];
        private readonly Dictionary<string, JsonObject> rotations = [];
        private readonly Dictionary<(string Folder, string Key), string> secrets = [];
        private readonly Dictionary<string, string> roles = new() { ["borrowed-unrelated-role"] = "unrelated-password" };
        private readonly Dictionary<(string User, string Host), string> mysqlAccounts = [];
        private readonly Dictionary<string, MssqlRotationLoginFacts> serverLogins = [];
        private readonly Dictionary<string, MssqlRotationUserFacts> databaseUsers = [];
        private readonly Dictionary<string, RotationCredentialIdentity> measuredIdentities = [];
        private MysqlPasswordPolicyFacts mysqlPolicy = new(true, ["validate_password"], [], 0, 8, false, 0, 0, 0, "", null);
        private readonly InfisicalRotationProfile profile;
        private string App => profile switch
        {
            InfisicalRotationProfile.MysqlCredentials => "mysql",
            InfisicalRotationProfile.MssqlCredentials => "mssql",
            _ => "postgres"
        };
        private string ProfilePath => App + "-credentials";
        private RotationBackendCoordinate Coordinate => new(profile, "backend.invalid", 5432, "database", OwnedNames[0]);
        private readonly HashSet<string> borrowedConnections = [ConnectionId];
        private readonly string mode;
        private readonly Task accept;
        private Pair active = new("", "");
        private bool ownerDisposed;
        private int generation;
        internal Uri Origin { get; }
        internal string[] OwnedNames { get; private set; } = [];
        internal Pair Active { get { lock (folders) return active; } }
        internal List<Pair> Issued { get; } = [];
        internal HashSet<Pair> Accepted { get; } = [];
        internal HashSet<Pair> WrongPasswordRejected { get; } = [];
        internal HashSet<Pair> AcceptedAgain { get; } = [];
        internal HashSet<Pair> RejectedAfterCleanup { get; } = [];
        internal int ProviderMutations { get; private set; }
        internal int RuntimeMutations { get; private set; }
        internal int OwnerCreates { get; private set; }
        internal int OwnerDisposals { get; private set; }
        internal int RotationCreates { get; private set; }
        internal int RotationUpdates { get; private set; }
        internal int ManualRotations { get; private set; }
        internal int RuntimeMappedReads { get; private set; }
        internal int CatalogReads { get; private set; }
        internal bool NativeMysqlCatalog { get; init; }
        internal bool ProjectInventoryBeforeOwnership { get; private set; }
        internal bool ProjectInventoriesOnly { get; private set; } = true;
        internal bool AdminManualRotationsOnly { get; private set; } = true;
        internal bool BothCleanupFlags { get; private set; }
        internal bool CredentialsRejectedBeforeOwnerDisposal { get; private set; }
        internal bool PreviousActiveAcceptedAfterSecondRotation { get; private set; }
        internal bool FinalInventoryExactCompleteAndBound { get; private set; }
        internal bool BorrowedConnectionRetained => borrowedConnections.Contains(ConnectionId);
        internal bool UnownedRoleRetained => roles.ContainsKey("borrowed-unrelated-role");
        internal int UnrelatedRuleCount => rules.ContainsKey(ExternalId) ? 1 : 0;
        internal int OwnedRoleCount { get { lock (folders) return OwnedNames.Count(roles.ContainsKey); } }
        internal int RotationCount { get { lock (folders) return rotations.Count; } }
        internal int MappedSecretCount { get { lock (folders) return secrets.Count; } }
        internal int RecordCount { get { lock (folders) return folders.Count + rules.Count + rotations.Count + secrets.Count; } }

        internal RotationValidationWire(string mode = "good",
            InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
        {
            this.mode = mode;
            this.profile = profile;
            if (mode is "other-active" or "other-inactive")
                rules[ExternalId] = ExternalRule(ExternalId, "project", mode == "other-active");
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            using (var budget = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token))
            {
                budget.CancelAfter(TimeSpan.FromSeconds(15));
                try
                {
                    var stream = socket.GetStream();
                    var headers = new List<byte>();
                    byte[] one = new byte[1];
                    while (headers.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, budget.Token) == 0) return;
                        headers.Add(one[0]);
                        if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    if (headers.Count == 32768) throw new InvalidOperationException("fixture-header-budget");
                    string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string principal = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                        .Split(' ').Last() ?? "";
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                        .Split(':')[1] ?? "0");
                    if (length is < 0 or > 1048576) throw new InvalidOperationException("fixture-body-budget");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, budget.Token);
                    var json = JsonNode.Parse(length == 0 ? "{}"u8.ToArray() : body)!.AsObject();
                    (int Status, object Payload) result;
                    lock (folders) result = Handle(request[0], new(Origin, request[1]), principal, json);
                    byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                        budget.Token);
                    await stream.WriteAsync(response, budget.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }

        private static string Text(JsonObject body, string field) => body[field]?.GetValue<string>() ?? "";
        private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&')
            .Where(p => p.StartsWith(key + "=", StringComparison.Ordinal))
            .Select(p => Uri.UnescapeDataString(p[(key.Length + 1)..])).SingleOrDefault() ?? "";
        private static object Response(string key, JsonObject value) => new JsonObject { [key] = value.DeepClone() };

        private (int, object) Handle(string method, Uri uri, string principal, JsonObject body)
        {
            if (principal == "denied") return (403, new { });
            if (method is "POST" or "PATCH" or "DELETE") ProviderMutations++;
            string path = uri.AbsolutePath;
            if (path.StartsWith("/api/v1/secret-validation-rules", StringComparison.Ordinal))
                return RuleState(method, uri, principal, body);
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString("D");
                    folders[id] = (Text(body, "name"), Text(body, "path").TrimEnd('/') + "/" + Text(body, "name"));
                    return (200, new { folder = Folder(id) });
                }
                if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
                string selector = Uri.UnescapeDataString(path.Split('/').Last());
                string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
                if (found is null) return (404, new { });
                object folder = Folder(found);
                // Folder deletion never erases SQL roles, rotations or orphaned mapped secrets.
                if (method == "DELETE") folders.Remove(found);
                return (200, new { folder });
            }
            if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
            {
                string key = Uri.UnescapeDataString(path.Split('/').Last());
                string folder = method == "GET" ? Query(uri, "secretPath") : Text(body, "secretPath");
                if (method == "POST")
                {
                    secrets[(folder, key)] = Text(body, "secretValue");
                    return (200, new { secret = new { secretKey = key, workspace = "project", environment = "env", type = "shared", version = 1 } });
                }
                if (principal == "runtime" && secrets.ContainsKey((folder, key))) RuntimeMappedReads++;
                return secrets.TryGetValue((folder, key), out string? value) ?
                    (200, new { secret = new { secretKey = key, secretValue = value, secretValueHidden = false, version = generation + 1 } }) :
                    (404, new { });
            }
            if (path.StartsWith("/api/v2/secret-rotations", StringComparison.Ordinal))
                return RotationState(method, uri, principal, body);
            // The borrowed connection has no owned deletion authority.
            if (path.StartsWith("/api/v1/app-connections", StringComparison.Ordinal))
            {
                if (method != "GET") throw new InvalidOperationException("fixture-borrowed-connection-mutation");
                return (200, new { appConnection = new { id = ConnectionId, app = App, name = "borrowed" } });
            }
            return (404, new { });
        }

        private (int, object) RuleState(string method, Uri uri, string principal, JsonObject body)
        {
            const string collection = "/api/v1/secret-validation-rules/secret-rotations";
            if (method == "GET" && uri.AbsolutePath == collection)
            {
                bool bound = Query(uri, "projectId") == "project" &&
                    Query(uri, "environment") == "" && Query(uri, "secretPath") == "";
                ProjectInventoriesOnly &= bound;
                if (ProviderMutations == 0 && OwnerCreates == 0 && bound) ProjectInventoryBeforeOwnership = true;
                if (mode == "missing-project") return (403, new { });
                if (mode == "unbound-project")
                    return (200, new { secretValidationRules = new[] { ExternalRule(ExternalId, "other", false) } });
                if (mode == "incomplete-project")
                    return (200, new
                    {
                        secretValidationRules = Enumerable.Range(1, 1001).Select(n =>
                            ExternalRule(new Guid(n, 0, 0, new byte[8]).ToString("D"), "project", false)).ToArray()
                    });
                return (200, new JsonObject
                {
                    ["secretValidationRules"] = new JsonArray(rules.Values.Select(r => r.DeepClone()).ToArray())
                });
            }
            if (principal == "runtime" && method is "POST" or "PATCH" or "DELETE") RuntimeMutations++;
            if (method == "POST")
            {
                string id = Guid.NewGuid().ToString("D");
                var rule = new JsonObject
                {
                    ["id"] = id,
                    ["type"] = "secret-rotations",
                    ["projectId"] = "project",
                    ["createdAt"] = Epoch,
                    ["updatedAt"] = Epoch
                };
                ReplaceRule(rule, body);
                rules.Add(id, rule);
                return (200, Response("secretValidationRule", rule));
            }
            string selector = uri.AbsolutePath.Split('/').Last();
            if (!rules.TryGetValue(selector, out var found)) return (404, new { });
            if (selector == ExternalId && method != "GET") throw new InvalidOperationException("fixture-external-rule-mutation");
            if (method == "PATCH") ReplaceRule(found, body);
            var result = Response("secretValidationRule", found);
            if (method == "DELETE") rules.Remove(selector);
            return (200, result);
        }

        private static void ReplaceRule(JsonObject rule, JsonObject body)
        {
            foreach (var field in body)
                rule[field.Key] = field.Key == "environment" && field.Value is not null ?
                    new JsonObject { ["id"] = EnvironmentId, ["name"] = "Env", ["slug"] = field.Value.DeepClone() } :
                    field.Value?.DeepClone();
        }

        private static JsonObject ExternalRule(string id, string project, bool active) => new()
        {
            ["id"] = id,
            ["name"] = "external-" + id,
            ["type"] = "secret-rotations",
            ["projectId"] = project,
            ["isActive"] = active,
            ["environment"] = new JsonObject { ["id"] = EnvironmentId, ["name"] = "Other", ["slug"] = "elsewhere" },
            ["secretPath"] = "/elsewhere",
            ["providers"] = new JsonArray("postgres-credentials"),
            ["passwordConstraints"] = new JsonObject { ["minLength"] = 24, ["maxLength"] = 24 },
            ["createdAt"] = Epoch,
            ["updatedAt"] = Epoch
        };

        private object Folder(string id) => new
        {
            id,
            envId = EnvironmentId,
            name = folders[id].Name,
            path = folders[id].Path,
            projectId = "project",
            environment = new { envSlug = "env" },
            createdAt = Epoch,
            updatedAt = Epoch
        };

        private (int, object) RotationState(string method, Uri uri, string principal, JsonObject body)
        {
            string collection = "/api/v2/secret-rotations/" + ProfilePath;
            if (method == "GET" && (uri.AbsolutePath == collection || uri.AbsolutePath == "/api/v2/secret-rotations"))
                return (200, new JsonObject { ["secretRotations"] = new JsonArray(rotations.Values.Select(r => r.DeepClone()).ToArray()) });
            if (method == "POST" && uri.AbsolutePath == collection)
            {
                if (Text(body, "projectId") != "project" || Text(body, "environment") != "env" ||
                    Text(body, "connectionId") != ConnectionId || body["isAutoRotationEnabled"]?.GetValue<bool>() != false ||
                    body["rotationInterval"]?.GetValue<double>() != 1 || Text(body, "name").Length == 0 ||
                    body["parameters"] is not JsonObject parameters ||
                    Text(parameters, "username1") != OwnedNames[0] || Text(parameters, "username2") != OwnedNames[1] ||
                    parameters["rotationStatement"] is not null ||
                    parameters["passwordRequirements"] is not JsonObject requirements ||
                    requirements["length"]?.GetValue<double>() != 32 || Text(requirements, "allowedSymbols") != "!" ||
                    requirements["required"] is not JsonObject required ||
                    new[] { "digits", "lowercase", "symbols", "uppercase" }.Any(k => required[k]?.GetValue<double>() != 8))
                    throw new InvalidOperationException("fixture-rotation-construction");
                string folderPath = Text(body, "secretPath");
                string folderId = folders.Single(f => f.Value.Path == folderPath).Key;
                var mapping = body["secretsMapping"]!.AsObject();
                if (Text(mapping, "username") == Text(mapping, "password") ||
                    new[] { Text(mapping, "username"), Text(mapping, "password") }.Any(k =>
                        string.IsNullOrWhiteSpace(k) || secrets.ContainsKey((folderPath, k))))
                    throw new InvalidOperationException("fixture-fresh-mapping");
                var rotation = body.DeepClone().AsObject();
                rotation.Remove("secretPath");
                rotation["id"] = Guid.NewGuid().ToString("D");
                rotation["type"] = ProfilePath;
                rotation["connection"] = new JsonObject { ["id"] = ConnectionId, ["app"] = App, ["name"] = "borrowed" };
                rotation["environment"] = new JsonObject { ["id"] = EnvironmentId, ["name"] = "Env", ["slug"] = "env" };
                rotation["folderId"] = folderId;
                rotation["folder"] = new JsonObject { ["id"] = folderId, ["path"] = folderPath };
                foreach (string field in new[] { "createdAt", "updatedAt", "lastRotatedAt", "lastRotationAttemptedAt" })
                    rotation[field] = Epoch;
                rotation["rotationStatus"] = "success";
                rotation["description"] ??= null;
                rotation["lastRotationJobId"] = null;
                rotation["lastRotationMessage"] = null;
                rotation["nextRotationAt"] = null;
                rotation["rotateAtUtc"] ??= new JsonObject { ["hours"] = 0, ["minutes"] = 0 };
                rotation["activeIndex"] = 0;
                rotations.Add(Text(rotation, "id"), rotation);
                SetMappedPair(rotation, active);
                RotationCreates++;
                return (200, Response("secretRotation", rotation));
            }
            string selector = Uri.UnescapeDataString(uri.AbsolutePath.Split('/').Last());
            var found = uri.AbsolutePath.Contains("/rotation-name/", StringComparison.Ordinal) ?
                rotations.Values.SingleOrDefault(r => Text(r, "name") == selector) : rotations.GetValueOrDefault(selector);
            if (found is null) return (404, new { });
            if (method == "PATCH") RotationUpdates++;
            var result = Response("secretRotation", found);
            if (method == "DELETE")
            {
                BothCleanupFlags = Query(uri, "deleteSecrets") == "true" && Query(uri, "revokeGeneratedCredentials") == "true";
                if (!BothCleanupFlags || principal != "administrative")
                    throw new InvalidOperationException("fixture-cleanup-authority");
                if (mode == "retain-other-host")
                    foreach (string name in OwnedNames)
                        mysqlAccounts.Add((name, "localhost"), "mysql_native_password");
                if (mode != "retain-config") rotations.Remove(Text(found, "id"));
                if (mode != "retain-secrets")
                {
                    string path = Text(found["folder"]!.AsObject(), "path");
                    secrets.Remove((path, Text(found["secretsMapping"]!.AsObject(), "username")));
                    secrets.Remove((path, Text(found["secretsMapping"]!.AsObject(), "password")));
                }
                // Revocation changes passwords; only the account owner can drop roles.
                if (mode != "retain-credentials")
                    foreach (string name in OwnedNames) if (roles.ContainsKey(name)) roles[name] = "revoked-" + Guid.NewGuid().ToString("N");
            }
            return (200, result);
        }

        private void SetMappedPair(JsonObject rotation, Pair pair)
        {
            string path = Text(rotation["folder"]!.AsObject(), "path");
            var mapping = rotation["secretsMapping"]!.AsObject();
            secrets[(path, Text(mapping, "username"))] = pair.User;
            secrets[(path, Text(mapping, "password"))] = pair.Password;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                var uri = request.RequestUri!;
                if (uri.Scheme != "https" || uri.Host != Origin.Host || uri.Port != Origin.Port)
                    throw new InvalidOperationException("fixture-offline-rotation-origin");
                string id = uri.AbsolutePath.Split('/')[5];
                if (!rotations.TryGetValue(id, out var rotation))
                    return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") });
                if (request.Method == HttpMethod.Post && uri.AbsolutePath ==
                    "/api/v2/secret-rotations/" + ProfilePath + "/" + id + "/rotate-secrets")
                {
                    AdminManualRotationsOnly &= request.Headers.Authorization?.Parameter == "administrative";
                    if (!AdminManualRotationsOnly) throw new InvalidOperationException("fixture-manual-authority");
                    var before = active;
                    string next = active.User == OwnedNames[0] ? OwnedNames[1] : OwnedNames[0];
                    var rule = rules.Values.SingleOrDefault(r => Text(r, "projectId") == "project" &&
                        r["environment"]?["slug"]?.GetValue<string>() == "env" &&
                        Text(r, "secretPath") == Text(rotation["folder"]!.AsObject(), "path") &&
                        r["isActive"]?.GetValue<bool>() == true &&
                        r["providers"]?.AsArray().Any(p => p?.GetValue<string>() == ProfilePath) == true);
                    var constraints = rule?["passwordConstraints"]?.AsObject();
                    // SQL mutation faults follow a valid baseline so the selected
                    // rule transition, not setup, is the operation being challenged.
                    bool fault = profile == InfisicalRotationProfile.PostgresCredentials || ManualRotations > 0;
                    string password = mode == "ignored-rule" && fault || constraints is null ?
                        Password32 : GeneratePassword(constraints);
                    if (ManualRotations > 0)
                    {
                        if (mode == "wrong-length") password = password[..^1];
                        if (mode == "wrong-alphabet") password = password[..^1] + "?";
                    }
                    roles[next] = password;
                    if (mode == "rekey-sids" && ManualRotations == 1)
                        foreach (string name in OwnedNames)
                        {
                            byte[] replacement = [serverLogins[name].Sid[0], 88, 77, 66];
                            serverLogins[name] = serverLogins[name] with { Sid = replacement.ToArray() };
                            databaseUsers[name] = databaseUsers[name] with { Sid = replacement.ToArray() };
                        }
                    if (mode == "policy-changed" && ManualRotations == 1)
                        mysqlPolicy = mysqlPolicy with { Policy = 2, MinimumLength = 32 };
                    if (mode == "previous-invalidated" && ManualRotations > 0) roles[before.User] = "prematurely-invalidated";
                    active = new(next, password);
                    generation++;
                    ManualRotations++;
                    var delivered = mode == "wrong-credentials" && ManualRotations > 1 ? active with { Password = "uninstalled-password" } : active;
                    Issued.Add(delivered);
                    SetMappedPair(rotation, delivered);
                    rotation["activeIndex"] = next == OwnedNames[0] ? 0 : 1;
                    if (ManualRotations > 1 && mode == "config-changed") rotation["parameters"]!["passwordRequirements"]!["length"] = 24;
                    if (ManualRotations > 1 && mode == "config-enabled") rotation["isAutoRotationEnabled"] = true;
                }
                else if (request.Method != HttpMethod.Get || uri.AbsolutePath !=
                    "/api/v2/secret-rotations/" + ProfilePath + "/" + id)
                    throw new InvalidOperationException("fixture-offline-rotation-route");
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(Response("secretRotation", rotation)))
                });
            }
        }

        public ValueTask<IInfisicalRotationValidationAccounts> CreateAsync(string projectId,
            ValidationPoliciesEffects.RotationValidationInput input, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                if (projectId != "project" || input.ConnectionId != ConnectionId || OwnerCreates != 0 || input.Profile != profile)
                    throw new InvalidOperationException("fixture-owner-input");
                OwnerCreates++;
                string nonce = Guid.NewGuid().ToString("N");
                OwnedNames = ["sk_rv_" + nonce[..16] + "_a", "sk_rv_" + nonce[..16] + "_b"];
                foreach (string name in OwnedNames) roles.Add(name, Password32);
                for (int n = 0; n < OwnedNames.Length; n++)
                {
                    string name = OwnedNames[n];
                    if (profile == InfisicalRotationProfile.MysqlCredentials)
                    {
                        mysqlAccounts.Add((name, "%"), "caching_sha2_password");
                        if (mode == "catalog-other-host")
                            mysqlAccounts.Add((name, "localhost"), "mysql_native_password");
                    }
                    if (profile == InfisicalRotationProfile.MssqlCredentials)
                    {
                        byte[] sid = [(byte)(n + 1), 17, 42, 99];
                        serverLogins.Add(name, new(name, sid.ToArray(), "SQL_LOGIN", false, false, false));
                        databaseUsers.Add(name, new(name, sid.ToArray(), "SQL_USER", "INSTANCE"));
                    }
                }
                if (mode == "catalog-cross-mapped")
                    (databaseUsers[OwnedNames[0]], databaseUsers[OwnedNames[1]]) =
                        (databaseUsers[OwnedNames[0]] with { Sid = serverLogins[OwnedNames[1]].Sid.ToArray() },
                         databaseUsers[OwnedNames[1]] with { Sid = serverLogins[OwnedNames[0]].Sid.ToArray() });
                if (mode == "catalog-contained")
                    databaseUsers[OwnedNames[0]] = databaseUsers[OwnedNames[0]] with { AuthenticationTypeDescription = "DATABASE" };
                active = new(OwnedNames[0], Password32);
                var coordinate = Coordinate;
                return ValueTask.FromResult<IInfisicalRotationValidationAccounts>(new Accounts(this,
                    mode == "wrong-owner-coordinate" ? coordinate with { Database = "other" } : coordinate));
            }
        }

        // Independent pinned-provider model: generate a middle, then wrap it.
        // Regex generation ignores the ordinary generation length bounds.
        private string GeneratePassword(JsonObject constraints)
        {
            int length = constraints["minLength"]!.GetValue<int>();
            string pattern = Text(constraints, "regexPattern");
            string prefix = Text(constraints, "requiredPrefix");
            string suffix = Text(constraints, "requiredSuffix");
            string middle = pattern switch
            {
                "^[A-Z]{24}$" => new string('A', 24),
                "^[a-z]{24}$" => new string('a', 24),
                "" when prefix.Length + suffix.Length == 0 => length == 24 ? Policy24 : Policy32,
                "" => new string('*', length - prefix.Length - suffix.Length),
                _ => throw new InvalidOperationException("fixture-unsupported-pattern")
            };
            if (ManualRotations > 0)
            {
                if (mode == "ignored-regex") middle = Policy24;
                if (mode == "wrongcase") middle = pattern == "^[a-z]{24}$" ? new string('A', 24) : new string('a', 24);
                if (mode == "missing-prefix") prefix = "";
                if (mode == "missing-suffix") suffix = "";
                if (mode == "swapped-affixes") (prefix, suffix) = (suffix, prefix);
                if (mode == "bounds-overriding-regex")
                    middle = new string(pattern == "^[A-Z]{24}$" ? 'A' : 'a', length - prefix.Length - suffix.Length);
            }
            return prefix + middle + suffix;
        }

        private sealed class Accounts(RotationValidationWire owner, RotationBackendCoordinate coordinate)
            : IInfisicalRotationValidationAccounts
        {
            private bool disposed;
            public string Username1 => owner.OwnedNames[0];
            public string Username2 => owner.mode == "duplicate-owner-names" ? owner.OwnedNames[0] : owner.OwnedNames[1];
            public RotationBackendCoordinate Coordinate => coordinate;
            public ValueTask DisposeAsync()
            {
                lock (owner.folders)
                {
                    if (!disposed)
                    {
                        disposed = true;
                        owner.CredentialsRejectedBeforeOwnerDisposal = owner.Issued.Count > 0 &&
                            owner.Issued.All(p => !owner.roles.TryGetValue(p.User, out string? password) || password != p.Password);
                        if (owner.mode != "retain-roles")
                            foreach (string name in owner.OwnedNames)
                            {
                                owner.roles.Remove(name);
                                if (owner.mode != "ack-only-absence") owner.mysqlAccounts.Remove((name, "%"));
                                if (owner.mode is not "retain-server-only" and not "ack-only-absence") owner.serverLogins.Remove(name);
                                if (owner.mode is not "retain-database-only" and not "ack-only-absence") owner.databaseUsers.Remove(name);
                            }
                        owner.OwnerDisposals++;
                        owner.ownerDisposed = true;
                    }
                }
                return ValueTask.CompletedTask;
            }
        }

        public ValueTask<RotationCredentialFacts> MeasureCredentialsAsync(RotationBackendCoordinate coordinate,
            SecretMaterial username, SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                var pair = new Pair(username.Reveal(), password.Reveal());
                bool bound = coordinate == Coordinate;
                bool present = roles.TryGetValue(pair.User, out string? installed);
                bool valid = present && installed == pair.Password;
                bool principalPresent = profile switch
                {
                    InfisicalRotationProfile.MysqlCredentials => mysqlAccounts.ContainsKey((pair.User, "%")),
                    InfisicalRotationProfile.MssqlCredentials => serverLogins.ContainsKey(pair.User) && databaseUsers.ContainsKey(pair.User),
                    _ => true
                };
                bool fault = profile == InfisicalRotationProfile.PostgresCredentials || ManualRotations >= 2;
                bool accepted = bound && present && principalPresent && (valid || mode == "password-ignored" && fault);
                var identity = accepted ? Identity(pair.User) : null;
                if (identity is not null) measuredIdentities[pair.User] = identity;
                if (Issued.Contains(pair))
                {
                    if (accepted)
                    {
                        Accepted.Add(pair);
                        if (WrongPasswordRejected.Contains(pair)) AcceptedAgain.Add(pair);
                        if (ManualRotations == 2 && pair == Issued[0]) PreviousActiveAcceptedAfterSecondRotation = true;
                    }
                    else if (BothCleanupFlags) RejectedAfterCleanup.Add(pair);
                }
                else if (!accepted && present)
                    foreach (var issued in Issued.Where(p => p.User == pair.User && p.Password == installed))
                        WrongPasswordRejected.Add(issued);
                return ValueTask.FromResult(new RotationCredentialFacts(
                    mode == "wrong-coordinate" && accepted && fault ? coordinate with { Database = "other" } : coordinate,
                    mode == "unavailable" && valid ? BackendAuthentication.Unavailable :
                        accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                    accepted ? mode == "wrong-authenticated-user" && fault ? "borrowed-unrelated-role" : pair.User :
                        BothCleanupFlags && mode == "bad-rejection-user" ? pair.User : null,
                    accepted ? mode == "wrong-actions" && fault ? ["insert"] : ["select"] : [],
                    accepted ? ["write"] : [], accepted ? identity :
                        BothCleanupFlags && mode == "bad-rejection-identity" ? measuredIdentities.GetValueOrDefault(pair.User) : null));
            }
        }

        private RotationCredentialIdentity? Identity(string username)
        {
            bool fault = ManualRotations == 2 && !BothCleanupFlags;
            if (fault && mode == "missing-identity") return null;
            if (profile == InfisicalRotationProfile.MysqlCredentials)
            {
                var account = mysqlAccounts.Single(a => a.Key.User == username && a.Key.Host == "%");
                string currentUser = account.Key.User + "@" + account.Key.Host;
                if (fault && mode == "wrong-account-host") currentUser = account.Key.User + "@localhost";
                // USER() identifies the supplied connection name/peer, not the admitted CURRENT_USER() account.
                if (fault && mode == "user-substitute") currentUser = username + "@client.invalid";
                if (fault && mode == "wrong-identity-branch")
                    return new(null, new(username, [1], username, [1], username, [1], "database"));
                return new(new(currentUser, fault && mode == "identity-database" ? "other" : "database"), null);
            }
            if (profile == InfisicalRotationProfile.MssqlCredentials)
            {
                var login = serverLogins[username];
                var user = databaseUsers[username];
                if (fault && mode == "wrong-identity-branch") return new(new(username + "@%", "database"), null);
                return new(null, new(fault && mode == "connecting-login" ? "borrowed-unrelated-role" : login.Name,
                    fault && mode == "original-sid" ? [99, 98] : login.Sid.ToArray(),
                    fault && mode == "execution-login" ? "borrowed-unrelated-role" : login.Name,
                    fault && mode == "execution-sid" ? [99, 98] : login.Sid.ToArray(),
                    fault && mode == "database-user" ? "dbo" : user.Name,
                    fault && mode == "database-sid" ? [99, 98] : user.Sid.ToArray(),
                    fault && mode == "identity-database" ? "other" : "database"));
            }
            return null;
        }

        public ValueTask<RotationIdentityCatalogFacts> InspectIdentityCatalogAsync(RotationBackendCoordinate coordinate,
            IReadOnlyList<string> usernames, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                CatalogReads++;
                if (mode == "policy-incompatible") mysqlPolicy = mysqlPolicy with { Policy = 2 };
                if (mode == "policy-incomplete") mysqlPolicy = mysqlPolicy with { IsComplete = false };
                bool complete = mode != "catalog-incomplete" && !(ownerDisposed && mode == "ack-only-absence");
                var mysql = profile == InfisicalRotationProfile.MysqlCredentials ? new MysqlRotationCatalogFacts(
                    "database", complete, mysqlAccounts.Where(a => usernames.Contains(a.Key.User))
                        .Select(a => new MysqlRotationAccountFacts(a.Key.User, a.Key.Host, a.Value)).ToArray(), mysqlPolicy) : null;
                var mssql = profile == InfisicalRotationProfile.MssqlCredentials ? new MssqlRotationCatalogFacts(
                    "database", complete && mode != "catalog-server-incomplete",
                    complete && mode != "catalog-database-incomplete", serverLogins.Values.Where(a => usernames.Contains(a.Name))
                        .Select(a => a with { Sid = a.Sid.ToArray() }).ToArray(),
                    databaseUsers.Values.Where(a => usernames.Contains(a.Name))
                        .Select(a => a with { Sid = a.Sid.ToArray() }).ToArray()) : null;
                if (mode == "catalog-duplicate")
                {
                    if (mysql is { Accounts.Length: > 0 }) mysql = mysql with { Accounts = [.. mysql.Accounts, mysql.Accounts[0]] };
                    if (mssql is { ServerPrincipals.Length: > 0 })
                        mssql = mssql with { ServerPrincipals = [.. mssql.ServerPrincipals, mssql.ServerPrincipals[0]] };
                }
                if (ownerDisposed && mode == "ack-only-absence")
                {
                    if (mysql is not null) mysql = mysql with { Accounts = [] };
                    if (mssql is not null) mssql = mssql with { ServerPrincipals = [], DatabasePrincipals = [] };
                }
                var observedCoordinate = mode == "catalog-unbound" ? coordinate with { Account = "borrowed-unrelated-role" } : coordinate;
                FinalInventoryExactCompleteAndBound = ownerDisposed && OwnedNames.Length == 2 && observedCoordinate == Coordinate && complete &&
                    usernames.SequenceEqual(OwnedNames) &&
                    (mysql is { Accounts.Length: 0 } ||
                        mssql is { ServerPrincipals.Length: 0, DatabasePrincipals.Length: 0 });
                if (NativeMysqlCatalog)
                {
                    using JsonDocument selected = JsonDocument.Parse(JsonSerializer.Serialize(new
                    {
                        host = Coordinate.Host,
                        port = Coordinate.Port,
                        database = Coordinate.Database,
                        username = "catalog",
                        password = "private-catalog-password",
                        principal = "catalog@%",
                        rootCertificate = Path.Combine(Path.GetTempPath(), "selected-ca.pem"),
                        timeoutSeconds = 10
                    }));
                    MysqlPasswordPolicyFacts policy = mysql!.PasswordPolicy;
                    var variables = new[]
                    {
                        new { name = "validate_password_policy", value = policy.Policy!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                        new { name = "validate_password_length", value = policy.MinimumLength!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                        new { name = "validate_password_check_user_name", value = policy.CheckUserName == true ? "ON" : "OFF" },
                        new { name = "validate_password_mixed_case_count", value = policy.MixedCaseCount!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                        new { name = "validate_password_number_count", value = policy.NumberCount!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                        new { name = "validate_password_special_char_count", value = policy.SpecialCharCount!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture) },
                        new { name = "validate_password_dictionary_file", value = policy.DictionaryFile! }
                    };
                    string output = JsonSerializer.Serialize(new
                    {
                        principal = "catalog@%",
                        database = mysql.Database,
                        accounts = mysql.Accounts,
                        plugins = policy.ActiveValidationPlugins,
                        components = policy.InstalledValidationComponents,
                        variables
                    }, Options);
                    var native = new InfisicalMysqlIdentityCatalog(selected.RootElement,
                        (_, _, _, _) => Task.FromResult((0, output)));
                    return native.InspectIdentityCatalogAsync(coordinate, usernames, token);
                }
                return ValueTask.FromResult(new RotationIdentityCatalogFacts(observedCoordinate, usernames.ToArray(), mysql, mssql));
            }
        }

        public ValueTask<DynamicUsernameFacts> InspectUsernamesAsync(DynamicUsernameCoordinate coordinate,
            IReadOnlyList<string> usernames, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                bool bound = coordinate == new DynamicUsernameCoordinate(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database");
                bool exact = usernames.Count == 2 && usernames.Distinct(StringComparer.Ordinal).Count() == 2 &&
                    usernames.Order(StringComparer.Ordinal).SequenceEqual(OwnedNames.Order(StringComparer.Ordinal));
                string[] remaining = usernames.Where(roles.ContainsKey).ToArray();
                FinalInventoryExactCompleteAndBound = ownerDisposed && bound && exact && remaining.Length == 0;
                return ValueTask.FromResult(new DynamicUsernameFacts(coordinate, usernames.ToArray(), remaining, bound && exact));
            }
        }

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            await accept;
            listener.Stop();
            await Task.WhenAll(connections).WaitAsync(TimeSpan.FromSeconds(15));
            shutdown.Dispose();
            Dispose();
        }
    }
}
