using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureRuntimeFamilyTests
{
    [Test]
    [Arguments(SecretStatus.Denied, DispatchEvidence.Rejected, true)]
    [Arguments(SecretStatus.Unknown, DispatchEvidence.PossiblyDispatched, true)]
    [Arguments(SecretStatus.Denied, DispatchEvidence.Applied, false)]
    [Arguments(SecretStatus.Denied, DispatchEvidence.NotDispatched, false)]
    [Arguments(SecretStatus.Denied, DispatchEvidence.PossiblyDispatched, false)]
    [Arguments(SecretStatus.Unknown, DispatchEvidence.Applied, false)]
    [Arguments(SecretStatus.Unknown, DispatchEvidence.Rejected, false)]
    [Arguments(SecretStatus.Unknown, DispatchEvidence.NotDispatched, false)]
    public async Task DeniedMutationEvidenceMustMatchDefinitiveOrUncertainOutcome(
        SecretStatus status, DispatchEvidence evidence, bool expected)
    {
        await Assert.That(AzureKeyVaultClientEffects.DeniedMutationMatches(status, 403, evidence)).IsEqualTo(expected);
        await Assert.That(AzureKeyVaultClientEffects.DeniedMutationMatches(status, 200, evidence)).IsFalse();
    }

    [Test]
    [Arguments(true, false, false, true)]
    [Arguments(true, true, false, false)]
    [Arguments(false, true, false, false)]
    [Arguments(false, false, false, true)]
    [Arguments(true, false, true, false)]
    public async Task InventoryRequiresUniqueCoordinatesAndCompleteSetEquality(
        bool complete, bool duplicate, bool duplicatedObserver, bool expected)
    {
        (string Name, string Version)[] observed = duplicatedObserver ?
            [("owned-a", "v1"), ("owned-a", "v1")] : [("owned-a", "v1"), ("owned-b", "v2")];
        (string Name, string Version)[] actual = duplicate ?
            [("owned-a", "v1"), ("owned-a", "v1")] : complete ? observed : [("owned-a", "v1")];
        await Assert.That(AzureKeyVaultClientEffects.InventoryMatches(actual, observed, complete)).IsEqualTo(expected);
    }

    [Test]
    [Arguments("GetDeletedSecretAsync", "SecretKit.Core.SecretReference")]
    [Arguments("GetDeletedSecretsAsync", "SecretKit.AzureKeyVault.AzureInventoryScope")]
    [Arguments("StartDeleteSecretAsync", "SecretKit.Core.SecretReference,SecretKit.Core.MutationReceipt")]
    [Arguments("StartRecoverDeletedSecretAsync", "SecretKit.Core.SecretReference,SecretKit.Core.MutationReceipt")]
    [Arguments("PurgeDeletedSecretAsync", "SecretKit.Core.SecretReference,SecretKit.Core.MutationReceipt")]
    [Arguments("BackupSecretAsync", "SecretKit.Core.SecretReference")]
    [Arguments("RestoreSecretBackupAsync", "SecretKit.AzureKeyVault.AzureRestoreSecretRequest,SecretKit.Core.MutationReceipt")]
    [Arguments("CheckLifecycleStatusAsync", "SecretKit.AzureKeyVault.AzureLifecycleOperation")]
    public async Task NativeLifecycleInvalidSandboxFailsBeforeProviderWork(string method, string argument)
    {
        using OwnedAzureEnvironment environment = EnvironmentWith("""
            {"C08-AR-AzureNativeLifecycle":{"namespace":"","statusNamespace":""}}
            """);
        var definition = new NativeCaseDefinition(new("AzureKeyVault",
            "a.runtime.AzureKeyVaultClient." + method, method == "CheckLifecycleStatusAsync" ? "kind.Delete.Pending" :
                method == "RestoreSecretBackupAsync" ? "precondition.None" :
                method == "BackupSecretAsync" || method.StartsWith("Get", StringComparison.Ordinal) ?
                    "selector.exact" : "input.target", "owned", "selected-contract"),
            "SecretKit.AzureKeyVault.AzureKeyVaultClient." + method + "(" + argument +
            ",System.Threading.CancellationToken)");
        var registry = new NativeCaseRegistry();
        AzureNativeCases.Register(registry, environment, [definition]);
        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.EffectObserved).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
    }

    [Test]
    [Arguments("tags.omitted")]
    [Arguments("tags.nonempty")]
    [Arguments("tags.empty.clear")]
    [Arguments("AzureUpdatePropertiesRequest.enabled.false")]
    [Arguments("AzureUpdatePropertiesRequest.enabled.true")]
    [Arguments("AzureUpdatePropertiesRequest.notBefore.value")]
    [Arguments("AzureUpdatePropertiesRequest.expiresOn.value")]
    [Arguments("AzureUpdatePropertiesRequest.contentType.value")]
    [Arguments("precondition.CreateOnly.rejected")]
    [Arguments("precondition.MatchVersion.rejected")]
    [Arguments("precondition.None")]
    [Arguments("AzureUpdatePropertiesRequest.precondition.None")]
    [Arguments("AzureUpdatePropertiesRequest.precondition.CreateOnly")]
    [Arguments("AzureUpdatePropertiesRequest.precondition.MatchVersion")]
    [Arguments("AzureUpdatePropertiesRequest.enabled.omitted")]
    [Arguments("AzureUpdatePropertiesRequest.notBefore.omitted")]
    [Arguments("AzureUpdatePropertiesRequest.expiresOn.omitted")]
    [Arguments("AzureUpdatePropertiesRequest.contentType.omitted")]
    public async Task MetadataPatchRetainsExactSelectorAndSelectedFields(string variant)
    {
        using OwnedAzureEnvironment environment = EnvironmentWith("{}", trustedOrigin: true);
        AzureKeyVaultClient client = environment.CreateClient(NativeIdentityRole.Runtime);
        var target = new SecretReference(client.Authority,
            new AzureSecretAddress("owned-name", "11111111111111111111111111111111"));
        DateTimeOffset now = DateTimeOffset.FromUnixTimeSeconds(2000000000);
        AzureUpdatePropertiesRequest patch = AzureNativeLifecycleEffects.Patch(target, variant, now);
        await Assert.That(ReferenceEquals(patch.Target, target)).IsTrue();
        await Assert.That(patch.Enabled).IsEqualTo(variant switch
        {
            "AzureUpdatePropertiesRequest.enabled.false" => (bool?)false,
            "AzureUpdatePropertiesRequest.enabled.true" => true,
            _ => null
        });
        await Assert.That(patch.Tags?.Count).IsEqualTo(variant switch
        {
            "tags.nonempty" => (int?)1,
            "tags.empty.clear" => 0,
            _ => null
        });
        await Assert.That(patch.NotBefore).IsEqualTo(variant == "AzureUpdatePropertiesRequest.notBefore.value" ?
            now.AddDays(-2) : (DateTimeOffset?)null);
        await Assert.That(patch.ExpiresOn).IsEqualTo(variant == "AzureUpdatePropertiesRequest.expiresOn.value" ?
            now.AddDays(3) : (DateTimeOffset?)null);
        await Assert.That(patch.ContentType).IsEqualTo(variant is "AzureUpdatePropertiesRequest.contentType.value" or
            "precondition.None" or "AzureUpdatePropertiesRequest.precondition.None" ? "patched" : null);
        await Assert.That(patch.Precondition).IsEqualTo(variant switch
        {
            "precondition.CreateOnly.rejected" or "AzureUpdatePropertiesRequest.precondition.CreateOnly" =>
                AzureSetSecretPrecondition.CreateOnly,
            "precondition.MatchVersion.rejected" or "AzureUpdatePropertiesRequest.precondition.MatchVersion" =>
                AzureSetSecretPrecondition.MatchVersion,
            _ => AzureSetSecretPrecondition.None
        });
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InvalidSandboxFailsBeforeProviderWork(bool lifecycle)
    {
        using OwnedAzureEnvironment environment = EnvironmentWith("""
            {"C08-AR-AzureKeyVaultClient":{"namespace":""},"C08-AR-AzureNativeLifecycle":{"namespace":""}}
            """);
        string method = lifecycle ? "GetSecretVersionAsync" : "ReadAsync";
        var definition = new NativeCaseDefinition(new("AzureKeyVault", "a.runtime.AzureKeyVaultClient." + method,
            lifecycle ? "version.exact.valid" : "version.latest", "owned", "selected-contract"),
            "SecretKit.AzureKeyVault.AzureKeyVaultClient." + method + "(SecretKit.Core.SecretReference,System.Threading.CancellationToken)");
        var registry = new NativeCaseRegistry();
        AzureNativeCases.Register(registry, environment, [definition]);

        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];

        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.EffectObserved).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task WrongFullMemberCannotExecuteFamily(bool lifecycle)
    {
        using OwnedAzureEnvironment environment = EnvironmentWith("{}");
        var definition = new NativeCaseDefinition(new("AzureKeyVault", lifecycle ?
            "a.runtime.AzureKeyVaultClient.GetSecretVersionAsync" : "a.runtime.AzureKeyVaultClient.ReadAsync",
            "version.latest", "owned", "selected-contract"), "Wrong.ReadAsync()");
        var registry = new NativeCaseRegistry();
        AzureNativeCases.Register(registry, environment, [definition]);

        NativeCaseResult result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None))[0];

        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.EffectObserved).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
    }

    private static OwnedAzureEnvironment EnvironmentWith(string families, bool trustedOrigin = false)
    {
        // This origin cannot reach a real vault. Both counterexamples must fail before SDK construction.
        using JsonDocument settings = JsonDocument.Parse("""
            {"vaultUri":"https://invalid.example/","setup":{"token":"setup","expiresAt":"2099-01-01T00:00:00Z"},
            "runtime":{"token":"runtime","expiresAt":"2099-01-01T00:00:00Z"},
            "denied":{"token":"denied","expiresAt":"2099-01-01T00:00:00Z"},
            "administrative":{"token":"admin","expiresAt":"2099-01-01T00:00:00Z"},
            "observer":{"token":"observer","expiresAt":"2099-01-01T00:00:00Z"},"families":
            """ + families + "}");
        if (!trustedOrigin) return OwnedAzureEnvironment.Create(settings.RootElement);
        // Patch construction never dispatches; use a syntactically trusted owned selector.
        using JsonDocument trusted = JsonDocument.Parse(settings.RootElement.GetRawText()
            .Replace("https://invalid.example/", "https://native-patch-fixture.vault.azure.net/", StringComparison.Ordinal));
        return OwnedAzureEnvironment.Create(trusted.RootElement);
    }
}
