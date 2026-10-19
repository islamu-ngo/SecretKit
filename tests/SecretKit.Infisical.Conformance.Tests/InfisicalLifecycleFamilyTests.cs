using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalLifecycleFamilyTests
{
    private static readonly DateTimeOffset Epoch = new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private const string EnvironmentId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    private static readonly JsonSerializerOptions InputOptions = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    public async Task CompleteInventoryHasExactRegistrationAndMissingInputRows()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var inventory = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var createVariants = inventory.RootElement.GetProperty("operations").EnumerateArray().Single(o =>
            o.GetProperty("id").GetString() == "i.runtime.InfisicalDynamicClient.CreateDefinitionAsync")
            .GetProperty("variants").EnumerateArray().Select(v => v.GetString()!).ToArray();
        await Assert.That(createVariants.Length).IsEqualTo(302);
        await Assert.That(createVariants.All(InfisicalDynamicClientEffects.ExecutableVariant)).IsTrue()
            .Because(string.Join(", ", createVariants.Where(v => !InfisicalDynamicClientEffects.ExecutableVariant(v))));
        var dynamicVariants = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => o.GetProperty("id").GetString()!.StartsWith("i.runtime.InfisicalDynamicClient.", StringComparison.Ordinal))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().Select(v => v.GetString()!)).ToArray();
        await Assert.That(dynamicVariants.Length).IsEqualTo(868);
        await Assert.That(dynamicVariants.All(InfisicalDynamicClientEffects.ExecutableVariant)).IsTrue()
            .Because(string.Join(", ", dynamicVariants.Where(v => !InfisicalDynamicClientEffects.ExecutableVariant(v))));
        var expected = inventory.RootElement.GetProperty("operations").EnumerateArray()
            .Where(o => InfisicalLifecycleFamilies.Catalog.Any(a => a.Operation == o.GetProperty("id").GetString()))
            .SelectMany(o => o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                    new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "offline", c.GetString()!),
                    o.GetProperty("member").GetString()!)))).ToArray();
        using var env = Environment(new("http://127.0.0.1:1/"), new JsonObject());
        var registry = new NativeCaseRegistry();
        InfisicalLifecycleFamilies.Register(registry, env, expected);
        var results = await NativeCaseRunner.RunAsync(registry, expected, CancellationToken.None);
        await Assert.That(results.Count).IsEqualTo(4870);
        await Assert.That(results.Count(r => r.Operation.StartsWith("i.runtime.InfisicalDynamicClient."))).IsEqualTo(4224);
        await Assert.That(results.Count(r => r.Operation.StartsWith("i.runtime.InfisicalPeriodicTokenSession."))).IsEqualTo(58);
        await Assert.That(results.Count(r => r.Operation.StartsWith("i.runtime.InfisicalRotationClient."))).IsEqualTo(588);
        await Assert.That(results.All(r => !r.Passed && r.ReasonCode == "missing-input")).IsTrue();
    }

    [Test]
    [Arguments("member")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task IncorrectMachineContractFailsBeforeConstructingAnyFixture(string changed)
    {
        var definition = Row("InfisicalDynamicClient", "AcquireDatabaseAsync", "ttl.value");
        definition = changed switch
        {
            "member" => definition with { Member = definition.Member + ".wrong" },
            "variant" => definition with { Key = definition.Key with { Variant = "profile.Invented" } },
            _ => definition with { Key = definition.Key with { Case = "invented-case" } }
        };
        using var env = Environment(new("http://127.0.0.1:1/"), new JsonObject());
        var registry = new NativeCaseRegistry();
        InfisicalLifecycleFamilies.Register(registry, env, [definition]);
        var result = (await NativeCaseRunner.RunAsync(registry, [definition], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("contract-mismatch");
    }

    [Test]
    [Arguments("CreateDefinitionAsync")]
    [Arguments("UpdateDefinitionAsync")]
    [Arguments("UpdateDefinitionPolicyAsync")]
    [Arguments("InspectDefinitionAsync")]
    [Arguments("ListDefinitionsAsync")]
    [Arguments("AcquireDatabaseAsync")]
    [Arguments("InspectLeaseAsync")]
    [Arguments("ListLeasesAsync")]
    [Arguments("RenewAsync")]
    [Arguments("RenewLeaseAsync")]
    [Arguments("RevokeAsync")]
    [Arguments("RevokeLeaseAsync")]
    [Arguments("DeleteDefinitionAsync")]
    public async Task EveryDynamicSdkMethodRequiresIndependentBackendStateAndCleansOwnedRecords(string method)
    {
        await using var wire = new OfflineLifecycleWire();
        string variant = method is "AcquireDatabaseAsync" or "RenewAsync" ? "ttl.value" :
            method == "RevokeAsync" ? "forceRecordRemoval.false" : "profile.SqlDatabase";
        var row = Row("InfisicalDynamicClient", method, variant);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("CreateDefinitionAsync", "independent-effect", 1)]
    [Arguments("UpdateDefinitionAsync", "independent-effect", 1)]
    [Arguments("UpdateDefinitionPolicyAsync", "independent-effect", 1)]
    [Arguments("InspectDefinitionAsync", "independent-effect", 1)]
    [Arguments("ListDefinitionsAsync", "independent-effect", 1)]
    [Arguments("DeleteDefinitionAsync", "independent-effect", 1)]
    [Arguments("CreateDefinitionAsync", "denied-authority", 0)]
    [Arguments("CreateDefinitionAsync", "cancellation-boundary", 0)]
    [Arguments("CreateDefinitionAsync", "lost-response-no-replay", 1)]
    [Arguments("UpdateDefinitionAsync", "denied-authority", 0)]
    [Arguments("UpdateDefinitionAsync", "cancellation-boundary", 0)]
    [Arguments("UpdateDefinitionAsync", "lost-response-no-replay", 1)]
    [Arguments("DeleteDefinitionAsync", "denied-authority", 0)]
    [Arguments("DeleteDefinitionAsync", "cancellation-boundary", 0)]
    [Arguments("DeleteDefinitionAsync", "lost-response-no-replay", 1)]
    public async Task NonSqlDefinitionsExecuteTypedSdkButNeverCertifyBackendEffects(
        string method, string caseName, int requests)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", method, "profile.Ssh", caseName);
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        input["nonSqlProfile"] = JsonSerializer.SerializeToNode(
            new InfisicalDynamicProfileInput(Ssh: new(["owned-principal"])), InputOptions);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Clickhouse)]
    [Arguments(InfisicalDynamicProvider.Cassandra)]
    [Arguments(InfisicalDynamicProvider.SapAse)]
    [Arguments(InfisicalDynamicProvider.SapHana)]
    [Arguments(InfisicalDynamicProvider.Redis)]
    [Arguments(InfisicalDynamicProvider.Vertica)]
    [Arguments(InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments(InfisicalDynamicProvider.Snowflake)]
    [Arguments(InfisicalDynamicProvider.AwsIam)]
    [Arguments(InfisicalDynamicProvider.AwsElasticache)]
    [Arguments(InfisicalDynamicProvider.AwsMemorydb)]
    [Arguments(InfisicalDynamicProvider.AzureEntraId)]
    [Arguments(InfisicalDynamicProvider.GcpIam)]
    [Arguments(InfisicalDynamicProvider.Github)]
    [Arguments(InfisicalDynamicProvider.Milvus)]
    [Arguments(InfisicalDynamicProvider.MongoDb)]
    [Arguments(InfisicalDynamicProvider.ElasticSearch)]
    [Arguments(InfisicalDynamicProvider.RabbitMq)]
    [Arguments(InfisicalDynamicProvider.Kubernetes)]
    [Arguments(InfisicalDynamicProvider.Ldap)]
    [Arguments(InfisicalDynamicProvider.Totp)]
    [Arguments(InfisicalDynamicProvider.Ssh)]
    [Arguments(InfisicalDynamicProvider.IbmApiConnect)]
    [Arguments(InfisicalDynamicProvider.Oauth2)]
    [Arguments(InfisicalDynamicProvider.Tailscale)]
    [Arguments(InfisicalDynamicProvider.Couchbase)]
    [Arguments(InfisicalDynamicProvider.MongoDbAtlas)]
    public async Task EveryNonSqlProfileDispatchesThroughRegisteredOwnedDefinitionScenario(InfisicalDynamicProvider provider)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
        using var expected = sample.Profile;
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "profile." + provider);
        var input = DynamicInput() with { Profile = null, NonSqlProfile = sample.Input };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("access-key", NativeAwsCredentialKind.IamUser, "independent-effect", 1)]
    [Arguments("access-key", NativeAwsCredentialKind.Temporary, "independent-effect", 1)]
    [Arguments("assume-role", NativeAwsCredentialKind.IamUser, "independent-effect", 1)]
    [Arguments("assume-role", NativeAwsCredentialKind.Temporary, "independent-effect", 1)]
    [Arguments("irsa", NativeAwsCredentialKind.IamUser, "independent-effect", 1)]
    [Arguments("irsa", NativeAwsCredentialKind.Temporary, "independent-effect", 1)]
    [Arguments("assume-role", NativeAwsCredentialKind.IamUser, "denied-authority", 0)]
    [Arguments("assume-role", NativeAwsCredentialKind.IamUser, "cancellation-boundary", 0)]
    [Arguments("assume-role", NativeAwsCredentialKind.IamUser, "lost-response-no-replay", 1)]
    public async Task AwsAuthenticationVariantsUseExplicitTypedInputsWithoutCertifyingCloudEffects(
        string authentication, NativeAwsCredentialKind kind, string caseName, int requests)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "UpdateDefinitionAsync", "AwsIam." + authentication + "." + kind, caseName);
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.AwsIam, false);
        using var expected = sample.Profile;
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        input["nonSqlProfile"] = JsonSerializer.SerializeToNode(sample.Input, InputOptions);
        var aws = input["nonSqlProfile"]!["awsIam"]!;
        aws["authentication"] = authentication switch
        {
            "assume-role" => "AssumeRole",
            "irsa" => "Irsa",
            _ => "AccessKey"
        };
        aws["credentialKind"] = kind.ToString();
        aws["roleArn"] = authentication == "assume-role" ? "owned-role" : null;
        if (authentication != "access-key")
        {
            aws["accessKey"] = null;
            aws["secretAccessKey"] = null;
        }
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    [Arguments("AwsIam.assume-role.IamUser")]
    [Arguments("AwsIam.irsa.IamUser")]
    [Arguments("AwsIam.access-key.Temporary")]
    public async Task AwsVariantCannotSilentlySelectAnotherAuthenticationOrCredentialKind(string variant)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", variant);
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.AwsIam, false);
        using var expected = sample.Profile;
        var input = DynamicInput() with { Profile = null, NonSqlProfile = sample.Input };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("ElasticSearch.api-key", "independent-effect", 1)]
    [Arguments("Kubernetes.static-account", "independent-effect", 1)]
    [Arguments("Ldap.static-account", "independent-effect", 1)]
    [Arguments("Totp.manual.Sha1", "independent-effect", 1)]
    [Arguments("Totp.manual.Sha256", "independent-effect", 1)]
    [Arguments("Totp.manual.Sha512", "independent-effect", 1)]
    [Arguments("Tailscale.auth_keys.oauth", "independent-effect", 1)]
    [Arguments("Tailscale.federated_keys.api_key", "independent-effect", 1)]
    [Arguments("Tailscale.federated_keys.oauth", "independent-effect", 1)]
    [Arguments("Tailscale.oauth_keys.api_key", "independent-effect", 1)]
    [Arguments("Tailscale.oauth_keys.oauth", "independent-effect", 1)]
    [Arguments("Tailscale.oauth_keys.oauth", "denied-authority", 0)]
    [Arguments("Tailscale.oauth_keys.oauth", "cancellation-boundary", 0)]
    [Arguments("Tailscale.oauth_keys.oauth", "lost-response-no-replay", 1)]
    public async Task AlternativeFactoriesExecuteOwnedDefinitionsWithoutCertifyingEffects(
        string variant, string caseName, int requests)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "UpdateDefinitionAsync", variant, caseName);
        var sample = InfisicalDynamicAlternativeProfileInputTests.Sample(variant, 1);
        using var expected = sample.Profile;
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        input["alternativeProfile"] = JsonSerializer.SerializeToNode(sample.Input, InputOptions);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AlternativeScenarioRequiresOneExplicitEnvelopeBeforeDispatch(bool conflicting)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "Totp.manual.Sha1");
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        if (conflicting)
        {
            input["nonSqlProfile"] = JsonSerializer.SerializeToNode(
                new InfisicalDynamicProfileInput(Ssh: new(["owned-principal"])), InputOptions);
            input["alternativeProfile"] = JsonSerializer.SerializeToNode(
                new InfisicalDynamicAlternativeProfileInput(TotpManualSecret: new("owned-secret")), InputOptions);
        }
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    public async Task EveryTypedOptionVariantDispatchesWithoutCertifyingProtectedInputEffects()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var admission = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var operation = admission.RootElement.GetProperty("operations").EnumerateArray().Single(o =>
            o.GetProperty("id").GetString() == "i.runtime.InfisicalDynamicClient.CreateDefinitionAsync");
        int executed = 0;
        foreach (string variant in operation.GetProperty("variants").EnumerateArray().Select(v => v.GetString()!))
        {
            if (!InfisicalDynamicProfileVariants.TryProvider(variant, out var provider)) continue;
            var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
            using var expected = sample.Profile;
            await using var wire = new OfflineLifecycleWire();
            var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", variant);
            var profileInput = sample.Input;
            if (variant == "Couchbase.buckets.text")
                profileInput = profileInput with
                {
                    Couchbase = (profileInput.Couchbase ?? throw new InvalidOperationException()) with
                    {
                        Buckets = new(Text: "owned-bucket")
                    }
                };
            var input = DynamicInput() with { Profile = null, NonSqlProfile = profileInput };
            using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
            var registry = new NativeCaseRegistry();
            InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
            var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(result.Passed).IsFalse();
            await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
            await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
            await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
            executed++;
        }
        await Assert.That(executed).IsEqualTo(151);
    }

    [Test]
    [Arguments("denied-authority", 0)]
    [Arguments("cancellation-boundary", 0)]
    [Arguments("lost-response-no-replay", 1)]
    public async Task TypedOptionUpdatesRetainAuthorityAndUncertainDispatchBoundaries(string caseName, int requests)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "UpdateDefinitionAsync", "NativeMongoDefinitionProfile.clearPort.true", caseName);
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.MongoDb, true);
        using var expected = sample.Profile;
        var input = DynamicInput() with { Profile = null, NonSqlProfile = sample.Input };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    public async Task MissingSelectedOptionFailsBeforeOwningAnyProviderFixture()
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "NativeClickhouseDefinitionProfile.renewal.value");
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.Clickhouse, false);
        using var expected = sample.Profile;
        var input = DynamicInput() with { Profile = null, NonSqlProfile = sample.Input };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    public async Task EveryNestedVariantUsesExplicitProviderAndFactoryWithoutCertifyingEffects()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var admission = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var operation = admission.RootElement.GetProperty("operations").EnumerateArray().Single(o =>
            o.GetProperty("id").GetString() == "i.runtime.InfisicalDynamicClient.CreateDefinitionAsync");
        int executed = 0;
        foreach (string variant in operation.GetProperty("variants").EnumerateArray().Select(v => v.GetString()!))
        {
            if (!InfisicalDynamicNestedProfileOptions.Supports(variant)) continue;
            await using var wire = new OfflineLifecycleWire();
            var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", variant);
            var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
            input["profile"] = null;
            if (variant.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal))
            {
                string alternative = variant.StartsWith("NativeTailscaleOptions.audience.", StringComparison.Ordinal) ?
                    "Tailscale.federated_keys.oauth" : "Tailscale.auth_keys.oauth";
                var sample = InfisicalDynamicAlternativeProfileInputTests.Sample(alternative, 1);
                using var expected = sample.Profile;
                input["optionProvider"] = "Tailscale";
                input["alternativeVariant"] = alternative;
                input["alternativeProfile"] = JsonSerializer.SerializeToNode(sample.Input, InputOptions);
            }
            else
            {
                var provider = InfisicalDynamicNestedProfileOptionTests.Provider(variant);
                input["optionProvider"] = provider.ToString();
                input["nonSqlProfile"] = JsonSerializer.SerializeToNode(
                    InfisicalDynamicNestedProfileOptionTests.Sample(provider), InputOptions);
            }
            using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
            var registry = new NativeCaseRegistry();
            InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
            var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
            await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
            await Assert.That(result.Passed).IsFalse();
            await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
            await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
            await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
            executed++;
        }
        await Assert.That(executed).IsEqualTo(59);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NestedOptionsRequireExplicitMatchingProviderBeforeFixtureCreation(bool wrong)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "NativeGatewayOptions.gatewayId.value");
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        input["nonSqlProfile"] = JsonSerializer.SerializeToNode(
            InfisicalDynamicNestedProfileOptionTests.Sample(InfisicalDynamicProvider.Clickhouse), InputOptions);
        if (wrong) input["optionProvider"] = "AwsIam";
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("denied-authority", 0)]
    [Arguments("cancellation-boundary", 0)]
    [Arguments("lost-response-no-replay", 1)]
    public async Task NestedSessionPolicyUpdatesKeepDispatchBoundaries(string caseName, int requests)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "UpdateDefinitionAsync", "AwsIam.assume-role.sessionPolicyArns", caseName);
        var input = JsonSerializer.SerializeToNode(DynamicInput(), InputOptions)!.AsObject();
        input["profile"] = null;
        input["optionProvider"] = "AwsIam";
        input["nonSqlProfile"] = JsonSerializer.SerializeToNode(
            InfisicalDynamicNestedProfileOptionTests.Sample(InfisicalDynamicProvider.AwsIam), InputOptions);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("wrong-definition-provider", "effect-mismatch")]
    public async Task NonSqlDefinitionUnavailableEffectsStillRequireIndependentStateAndCleanup(
        string mode, string reason)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "profile.Ssh");
        var input = DynamicInput() with
        {
            Profile = null,
            NonSqlProfile = new(Ssh: new(["owned-principal"]))
        };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
        if (mode != "cleanup") await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("denied-authority", "observed")]
    [Arguments("cancellation-boundary", "observed")]
    [Arguments("lost-response-no-replay", "observed")]
    public async Task DynamicRenewalRetainsBoundaryReceiptAndNeverReplays(string caseName, string reason)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "RenewAsync", "ttl.value", caseName);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RuntimeRequests).IsEqualTo(caseName == "lost-response-no-replay" ? 1 : 0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("independent-effect", "good", "observed", 1)]
    [Arguments("denied-authority", "good", "observed", 0)]
    [Arguments("cancellation-boundary", "good", "observed", 0)]
    [Arguments("lost-response-no-replay", "good", "observed", 1)]
    [Arguments("independent-effect", "rename-id-mismatch", "contract-mismatch", 1)]
    [Arguments("independent-effect", "cleanup", "cleanup-incomplete", 1)]
    public async Task RenameReconcilesBothOwnedNamesWithoutReplayOrForcedCleanup(
        string caseName, string mode, string reason, int requests)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalDynamicClient", "UpdateDefinitionAsync", "newName.value", caseName);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RuntimeRequests).IsEqualTo(requests);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
        if (mode != "cleanup")
        {
            await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
            await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
        }
    }

    [Test]
    [Arguments("RenewAsync", "no-op-renew", "observer-unavailable")]
    [Arguments("RenewLeaseAsync", "no-op-renew", "observer-unavailable")]
    [Arguments("RenewAsync", "renewal-echo-mismatch", "effect-mismatch")]
    [Arguments("RenewLeaseAsync", "renewal-echo-mismatch", "effect-mismatch")]
    public async Task RenewalRequiresChangedIndependentExpiryAndMatchingReturnedObservation(
        string method, string mode, string reason)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalDynamicClient", method, "ttl.value");
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("renewalStatement.omitted", "renewStatement", false)]
    [Arguments("renewalStatement.value", "renewStatement", true)]
    [Arguments("ca.omitted", "ca", false)]
    [Arguments("ca.value", "ca", true)]
    [Arguments("sslEnabled.omitted", "sslEnabled", false)]
    [Arguments("sslEnabled.false", "sslEnabled", true)]
    [Arguments("sslEnabled.true", "sslEnabled", true)]
    [Arguments("gatewayId.omitted", "gatewayId", false)]
    [Arguments("gatewayId.value", "gatewayId", true)]
    [Arguments("gatewayPoolId.omitted", "gatewayPoolId", false)]
    [Arguments("gatewayPoolId.value", "gatewayPoolId", true)]
    [Arguments("passwordRequirements.omitted", "passwordRequirements", false)]
    [Arguments("passwordRequirements.value", "passwordRequirements", true)]
    public async Task SqlConstructorVariantsExecuteSdkFieldsWithoutInventingNativeEffects(string field, string key, bool present)
    {
        await using var wire = new OfflineLifecycleWire("good");
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "NativeSqlDefinitionProfile." + field);
        var input = DynamicInput();
        input = input with
        {
            Profile = (input.Profile ?? throw new InvalidOperationException("Missing SQL test profile.")) with
            {
                Ca = "fixture-ca",
                GatewayId = Guid.NewGuid().ToString(),
                GatewayPoolId = Guid.NewGuid().ToString(),
                PasswordRequirements = new(16, 2, 2, 2, 1, "!")
            }
        };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row]);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None))[0];
        await Assert.That(wire.LastCreatedInputs.HasValue).IsTrue();
        await Assert.That(wire.LastCreatedInputs!.Value.TryGetProperty(key, out _)).IsEqualTo(present);
        if (field == "passwordRequirements.value")
        {
            JsonElement password = wire.LastCreatedInputs.Value.GetProperty(key);
            await Assert.That(password.GetProperty("length").GetInt32()).IsEqualTo(16);
            await Assert.That(password.GetProperty("allowedSymbols").GetString()).IsEqualTo("!");
        }
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("observer", "observer-unavailable")]
    [Arguments("cleanup", "cleanup-incomplete")]
    [Arguments("bad-revoke", "cleanup-incomplete")]
    public async Task MissingOracleOrFailedCleanupCannotBePromotedFromAcknowledgements(string mode, string reason)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalDynamicClient", "RevokeAsync", "forceRecordRemoval.false");
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], mode == "observer" ? null : wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
        await Assert.That(wire.ForcedCleanupRequests).IsEqualTo(0);
    }

    [Test]
    public async Task MissingTypedNonSqlConfigurationRemainsRegisteredAndDoesNotBecomeSql()
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "CreateDefinitionAsync", "profile.Oauth2");
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row]);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("missing-input");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("lost-response-no-replay")]
    [Arguments("cancellation-boundary")]
    public async Task UncertainAcquisitionCannotInventMaterialAndCleansObservedOrphans(string caseName)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "AcquireDatabaseAsync", "ttl.value", caseName);
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(caseName == "lost-response-no-replay" ? 1 : 0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
    }

    [Test]
    public async Task ForcedRecordRemovalNeverClaimsRevocationAndRetainedBackendCredentialsFailCleanup()
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalDynamicClient", "RevokeAsync", "forceRecordRemoval.true");
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, DynamicInput()));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("cleanup-incomplete");
    }

    [Test]
    [Arguments("bad-expiry")]
    [Arguments("backend-rejects")]
    [Arguments("wrong-rights")]
    public async Task IssuanceAcknowledgementCannotSubstituteForMeasuredBackendFacts(string mode)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalDynamicClient", "AcquireDatabaseAsync", "ttl.value");
        var input = DynamicInput();
        if (mode == "wrong-rights") input = input with { AllowedActions = ["insert"] };
        using var env = Environment(wire.Origin, Family(InfisicalDynamicClientEffects.Family, row, input));
        var registry = new NativeCaseRegistry();
        InfisicalDynamicClientEffects.Register(registry, env, [row], wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(wire.RuntimeRequests).IsEqualTo(1);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
        await Assert.That(wire.BackendCredentialCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("GetTokenAsync")]
    [Arguments("RenewAsync")]
    public async Task ExpiredSessionUsesAnInjectedExpirySignalAndExposesNoUsableToken(string method)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalPeriodicTokenSession", method, "session.expired");
        using var env = Environment(wire.Origin, Family(InfisicalPeriodicTokenSessionEffects.Family, row,
            SessionInput("session.expired")));
        var registry = new NativeCaseRegistry();
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, [row], wire.Clock, wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observed");
        await Assert.That(wire.RenewalCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("lifetime.Finite", false)]
    [Arguments("lifetime.Periodic.no-absolute-limit", false)]
    [Arguments("lifetime.Periodic.absolute-limit", false)]
    [Arguments("lifetime.Unknown.recovery-required", true)]
    [Arguments("session.recovery-required", true)]
    public async Task SessionOwnedCopyAndLifetimeUseInjectedTimeWithoutRenewing(string variant, bool recovery)
    {
        var clock = new ManualClock(Epoch);
        using var env = Environment(new("http://127.0.0.1:1/"), new JsonObject());
        using var material = SecretMaterial.FromText("owned-token");
        var input = SessionInput(variant);
        await using var session = InfisicalPeriodicTokenSessionEffects.CreateSession(env, input, material, clock);
        var result = await session.GetTokenAsync(CancellationToken.None);
        await Assert.That(result.Status).IsEqualTo(recovery ? SecretStatus.RecoveryRequired : SecretStatus.Success);
        await Assert.That(session.LastRenewal).IsNull();
        if (!recovery)
        {
            using var first = result.Value;
            using var second = (await session.GetTokenAsync(CancellationToken.None)).Value;
            first.Dispose();
            await Assert.That(second.Material.Reveal()).IsEqualTo("owned-token");
            clock.Advance(TimeSpan.FromSeconds(60));
            await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.Expired);
            await Assert.That((await session.GetTokenAsync(CancellationToken.None)).IsSuccess).IsFalse();
        }
    }

    [Test]
    [Arguments("GetTokenAsync", "independent-effect", "observed")]
    [Arguments("GetTokenAsync", "denied-authority", "observed")]
    [Arguments("GetTokenAsync", "cancellation-boundary", "observed")]
    [Arguments("RenewAsync", "independent-effect", "observed")]
    [Arguments("RenewAsync", "denied-authority", "observed")]
    [Arguments("RenewAsync", "lost-response-no-replay", "observer-unavailable")]
    [Arguments("RenewAsync", "cancellation-boundary", "observer-unavailable")]
    public async Task ActualSessionUsesProtectedConsumerAndExactRenewalBoundary(string method, string caseName, string reason)
    {
        await using var wire = new OfflineLifecycleWire();
        var row = Row("InfisicalPeriodicTokenSession", method, "lifetime.Finite", caseName);
        using var env = Environment(wire.Origin, Family(InfisicalPeriodicTokenSessionEffects.Family, row,
            SessionInput("lifetime.Finite")));
        var registry = new NativeCaseRegistry();
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, [row], wire.Clock, wire);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo(reason);
        await Assert.That(wire.RenewalCount).IsEqualTo(method == "RenewAsync" &&
            caseName is not ("cancellation-boundary" or "denied-authority") ? 1 : 0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("cancellation-boundary", "session-expiry")]
    [Arguments("cancellation-boundary", "session-period")]
    [Arguments("cancellation-boundary", "session-absolute")]
    [Arguments("lost-response-no-replay", "session-expiry")]
    [Arguments("lost-response-no-replay", "session-period")]
    [Arguments("lost-response-no-replay", "session-absolute")]
    public async Task InterruptedRenewalCannotPassFromUnsettledLifetimeSnapshot(string boundary, string mode)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalPeriodicTokenSession", "RenewAsync", "lifetime.Finite", boundary);
        using var env = Environment(wire.Origin, Family(InfisicalPeriodicTokenSessionEffects.Family, row,
            SessionInput("lifetime.Finite")));
        var registry = new NativeCaseRegistry();
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, [row], wire.Clock, wire);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("session-expiry")]
    [Arguments("session-period")]
    [Arguments("session-absolute")]
    public async Task RejectedRenewalPreservesEveryIndependentLifetimeField(string mode)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var row = Row("InfisicalPeriodicTokenSession", "RenewAsync", "lifetime.Finite", "denied-authority");
        using var env = Environment(wire.Origin, Family(InfisicalPeriodicTokenSessionEffects.Family, row,
            SessionInput("lifetime.Finite")));
        var registry = new NativeCaseRegistry();
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, [row], wire.Clock, wire);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var result = (await NativeCaseRunner.RunAsync(registry, [row], deadline.Token)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("effect-mismatch");
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(wire.RenewalCount).IsEqualTo(0);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments("GetAsync", "selector.exact", "independent-effect")]
    [Arguments("ListAsync", "collection.bounded", "independent-effect")]
    [Arguments("RotateSecretsAsync", "precondition.None", "independent-effect")]
    [Arguments("SetAutomaticRotationAsync", "enabled.true", "independent-effect")]
    [Arguments("RotateSecretsAsync", "precondition.None", "lost-response-no-replay")]
    [Arguments("RotateSecretsAsync", "precondition.None", "cancellation-boundary")]
    [Arguments("RotateSecretsAsync", "precondition.RequireCompareAndSwap.rejected", "selected-contract")]
    [Arguments("RotateSecretsAsync", "precondition.RequireIdempotency.rejected", "selected-contract")]
    [Arguments("RotateSecretsAsync", "precondition.None", "denied-authority")]
    public async Task RotationRunsActualSdkButCannotPassWithoutPasswordAndRightsOracle(string method, string variant, string caseName)
    {
        using var wire = new RotationWire();
        var factory = new RotationFactory(wire);
        var row = Row("InfisicalRotationClient", method, variant, caseName);
        using var env = Environment(new("https://offline.invalid/"), Family(InfisicalRotationClientEffects.Family,
            row, RotationInput()));
        var registry = new NativeCaseRegistry();
        InfisicalRotationClientEffects.Register(registry, env, [row], factory, offlineTransport: wire);
        await Assert.That(factory.Created).IsEqualTo(0);
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();
        await Assert.That(result.ReasonCode).IsEqualTo("observer-unavailable");
        await Assert.That(factory.Created).IsEqualTo(1);
        await Assert.That(factory.Disposed).IsEqualTo(1);
        await Assert.That(wire.Mutations).IsEqualTo(method is "RotateSecretsAsync" or "SetAutomaticRotationAsync" &&
            !variant.EndsWith(".rejected", StringComparison.Ordinal) &&
            caseName is not ("denied-authority" or "cancellation-boundary") ? 1 : 0);
    }

    [Test]
    [Arguments(InfisicalRotationProfile.PostgresCredentials)]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task DefaultDatabaseRotationFixtureUsesTypedManagementAndRemovesOwnedConfiguration(
        InfisicalRotationProfile profile)
    {
        await using var wire = new OfflineLifecycleWire();
        var input = RotationInput() with { Profile = profile, Backend = RotationInput().Backend with { Profile = profile } };
        var row = Row("InfisicalRotationClient", "GetAsync", "profile." + profile);
        using var env = Environment(wire.Origin, Family(InfisicalRotationClientEffects.Family, row, input));
        await using (var fixture = await InfisicalRotationClientEffects.DatabaseRotationFixture.CreateAsync(
            env, input, new NativeCaseProbe(), "offline", CancellationToken.None))
        {
            await Assert.That(fixture.Address.Profile).IsEqualTo(profile);
        }
        await Assert.That(wire.CreatedRotationType).IsEqualTo(profile switch
        {
            InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
            InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
            _ => "mssql-credentials"
        });
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(0);
    }

    [Test]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, "rotation-observer", "observer-unavailable")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "rotation-observer", "observer-unavailable")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "rotation-observer", "observer-unavailable")]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, "rotation-cleanup", "cleanup-incomplete")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "rotation-cleanup", "cleanup-incomplete")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "rotation-cleanup", "cleanup-incomplete")]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, "rotation-admin-absent", "cleanup-incomplete")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, "rotation-admin-absent", "cleanup-incomplete")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, "rotation-admin-absent", "cleanup-incomplete")]
    public async Task DefaultDatabaseRotationFixtureRejectsIndependentMismatchAndFailedCleanup(
        InfisicalRotationProfile profile, string mode, string expected)
    {
        await using var wire = new OfflineLifecycleWire(mode);
        var input = RotationInput() with { Profile = profile, Backend = RotationInput().Backend with { Profile = profile } };
        using var env = Environment(wire.Origin, new JsonObject());
        string? reason = null;
        try
        {
            await using var fixture = await InfisicalRotationClientEffects.DatabaseRotationFixture.CreateAsync(
                env, input, new NativeCaseProbe(), "offline", CancellationToken.None);
        }
        catch (NativeCaseFailureException error) { reason = error.Message; }
        await Assert.That(reason).IsEqualTo(expected);
        await Assert.That(wire.OwnedRecordCount).IsEqualTo(mode == "rotation-observer" ? 0 : 1);
    }

    private static NativeCaseDefinition Row(string type, string method, string variant,
        string caseName = "independent-effect")
    {
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a => a.Operation == "i.runtime." + type + "." + method);
        return new(new("Infisical", admission.Operation, variant, "offline", caseName), admission.Member);
    }
    private static LifecycleSandbox Sandbox() => new("project", "project-slug", "env", EnvironmentId, "/owned");
    private static InfisicalDynamicClientEffects.DynamicInput DynamicInput() => new(Sandbox(),
        new(NativeSqlEngine.Postgres, "backend.invalid", 5432, "database", "administrator", "private-password",
            "create-owned-role", "revoke-owned-role", "renew-owned-role", null, false, null, null),
        60, 300, 120, null, [], ["select"], ["write"]);
    private static InfisicalPeriodicTokenSessionEffects.SessionInput SessionInput(string variant)
    {
        bool periodic = variant.StartsWith("lifetime.Periodic.", StringComparison.Ordinal);
        var evidence = new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = Epoch,
            ExpiresAt = Epoch.AddSeconds(60),
            Lifetime = variant == "lifetime.Unknown.recovery-required" ? InfisicalTokenLifetime.Unknown :
                periodic ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
            ReportedMaximumTtl = periodic ? TimeSpan.Zero : TimeSpan.FromSeconds(120),
            Period = periodic ? TimeSpan.FromSeconds(60) : null,
            AbsoluteLifetimeLimit = variant == "lifetime.Periodic.absolute-limit" ? Epoch.AddSeconds(120) : null
        };
        return new(Sandbox(), evidence, 10, 5, variant == "session.recovery-required", "protected-value");
    }
    private static InfisicalRotationClientEffects.RotationInput RotationInput() => new(Sandbox(), "organization",
        InfisicalRotationProfile.PostgresCredentials, Guid.NewGuid().ToString("D"),
        new(InfisicalRotationProfile.PostgresCredentials, "backend.invalid", 5432, "database", "owned"),
        "owned-one", "owned-two", null, 1, true, 128, ["select"], ["write"]);

    private static JsonObject Family<T>(string name, NativeCaseDefinition row, T input) => new()
    {
        [name] = new JsonObject
        {
            ["scopes"] = new JsonObject
            {
                [row.Key.Scope] = new JsonObject
                {
                    [row.Key.Operation] = new JsonObject
                    {
                        [row.Key.Variant] = new JsonObject
                        {
                            [row.Key.Case] = JsonSerializer.SerializeToNode(input, InputOptions)
                        }
                    }
                }
            }
        }
    };
    private static NativeEnvironment Environment(Uri origin, JsonObject families) => NativeEnvironment.Create(
        JsonSerializer.SerializeToElement(new
        {
            origin = origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families
        }, InputOptions));

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset current = now;
        public override DateTimeOffset GetUtcNow() => current;
        internal void Advance(TimeSpan elapsed) => current += elapsed;
    }

    // Stateful offline native wire and a separate downstream credential store. No row from
    // this fixture is remote conformance evidence. Credential checks read backend state,
    // not the SDK response, and deliberately diverge in bad-revoke mode.
    private sealed class OfflineLifecycleWire : IAsyncDisposable, IInfisicalDynamicBackendObserver,
        IInfisicalSessionLifetimeObserver
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly ConcurrentBag<Task> connections = [];
        private readonly Dictionary<string, (string Name, string Path)> folders = [];
        private readonly Dictionary<string, Definition> definitions = [];
        private readonly Dictionary<Guid, Lease> leases = [];
        private readonly Dictionary<string, (string Password, DateTimeOffset Expires)> backendCredentials = [];
        private readonly Dictionary<(string Folder, string Key), string> secrets = [];
        private readonly Dictionary<string, JsonObject> rotations = [];
        private readonly Task accept;
        private readonly string mode;
        internal ManualClock Clock { get; } = new(Epoch);
        internal Uri Origin { get; }
        internal int RuntimeRequests { get; private set; }
        internal int ForcedCleanupRequests { get; private set; }
        internal JsonElement? LastCreatedInputs { get; private set; }
        internal string? CreatedRotationType { get; private set; }
        internal int RenewalCount { get; private set; }
        internal int OwnedRecordCount { get { lock (folders) return folders.Count + definitions.Count + leases.Count + rotations.Count; } }
        internal int BackendCredentialCount { get { lock (folders) return backendCredentials.Count; } }
        internal OfflineLifecycleWire(string mode = "normal")
        {
            this.mode = mode;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }
        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                {
                    var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                    connections.Add(ServeAsync(socket));
                }
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }
        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            {
                try
                {
                    var stream = socket.GetStream();
                    var headers = new List<byte>();
                    byte[] one = new byte[1];
                    while (headers.Count < 32768)
                    {
                        if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                        headers.Add(one[0]);
                        if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    string role = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?
                        .Split(' ').Last() ?? "";
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                        .Split(':')[1] ?? "0");
                    if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("offline-budget");
                    byte[] body = new byte[length];
                    await stream.ReadExactlyAsync(body, shutdown.Token);
                    using var json = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                    (int Status, object Payload) result;
                    lock (folders) result = Handle(request[0], new(Origin, request[1]), role, json.RootElement);
                    byte[] response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(
                        $"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"),
                        shutdown.Token);
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            }
        }
        private (int, object) Handle(string method, Uri uri, string suppliedRole, JsonElement body)
        {
            string role = suppliedRole == "renewed-runtime" ? "runtime" : suppliedRole;
            if (uri.AbsolutePath == "/api/v1/auth/token/renew")
            {
                if (body.GetProperty("accessToken").GetString() == "denied") return (403, new { });
                RenewalCount++;
                return (200, new { accessToken = "renewed-runtime", accessTokenMaxTTL = 120, expiresIn = 60, tokenType = "Bearer" });
            }
            if (role == "denied") return (403, new { });
            string path = uri.AbsolutePath;
            if (path.StartsWith("/api/v2/folders", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string id = Guid.NewGuid().ToString("D");
                    folders[id] = (body.GetProperty("name").GetString()!,
                        body.GetProperty("path").GetString()!.TrimEnd('/') + "/" + body.GetProperty("name").GetString());
                    return (200, new { folder = Folder(id) });
                }
                if (path == "/api/v2/folders") return (200, new { folders = folders.Keys.Select(Folder).ToArray() });
                string selector = Uri.UnescapeDataString(path.Split('/').Last());
                string? found = folders.Keys.SingleOrDefault(id => id == selector || folders[id].Name == selector);
                if (found is null) return (404, new { });
                object folder = Folder(found);
                if (method == "DELETE")
                {
                    folders.Remove(found);
                    definitions.Clear();
                    leases.Clear();
                    backendCredentials.Clear();
                    secrets.Clear();
                }
                return (200, new { folder });
            }
            if (path.StartsWith("/api/v4/secrets", StringComparison.Ordinal))
            {
                string key = Uri.UnescapeDataString(path.Split('/').Last());
                string folder = method == "GET" ? Query(uri, "secretPath") : body.GetProperty("secretPath").GetString()!;
                if (method == "POST")
                {
                    secrets[(folder, key)] = body.GetProperty("secretValue").GetString()!;
                    return (200, new { secret = new { secretKey = key, workspace = "project", environment = "env", type = "shared", version = 1 } });
                }
                return secrets.TryGetValue((folder, key), out string? value) ?
                    (200, new { secret = new { secretKey = key, secretValue = value, secretValueHidden = false, version = 1 } }) : (404, new { });
            }
            if (path.StartsWith("/api/v2/secret-rotations", StringComparison.Ordinal))
            {
                if (method == "POST")
                {
                    string type = path.Split('/').Last();
                    var rotation = JsonNode.Parse(body.GetRawText())!.AsObject();
                    string folderId = folders.Single(f => f.Value.Path == rotation["secretPath"]!.GetValue<string>()).Key;
                    rotation.Remove("secretPath");
                    rotation["id"] = Guid.NewGuid().ToString("D");
                    rotation["type"] = type;
                    rotation["connection"] = new JsonObject
                    {
                        ["id"] = rotation["connectionId"]!.DeepClone(),
                        ["app"] = type.Split('-')[0],
                        ["name"] = "owned-connection"
                    };
                    rotation["environment"] = new JsonObject { ["id"] = EnvironmentId, ["name"] = "env", ["slug"] = "env" };
                    rotation["folderId"] = folderId;
                    rotation["folder"] = new JsonObject { ["id"] = folderId, ["path"] = folders[folderId].Path };
                    foreach (string field in new[] { "createdAt", "updatedAt", "lastRotatedAt", "lastRotationAttemptedAt" })
                        rotation[field] = Epoch;
                    rotation["rotationStatus"] = "success";
                    rotation["rotateAtUtc"] = new JsonObject { ["hours"] = 0, ["minutes"] = 0 };
                    rotations[rotation["id"]!.GetValue<string>()] = rotation;
                    CreatedRotationType = type;
                    return (200, new { secretRotation = rotation });
                }
                string id = path.Split('/').Last();
                var found = path.Contains("/rotation-name/", StringComparison.Ordinal) ?
                    rotations.Values.SingleOrDefault(r => r["name"]!.GetValue<string>() == id) :
                    rotations.GetValueOrDefault(id);
                if (found is null) return (404, new { });
                if (method == "GET" && role == "administrative" && mode == "rotation-admin-absent") return (404, new { });
                if (method == "DELETE" && mode == "rotation-cleanup") return (403, new { });
                if (method == "GET" && role == "observer" && mode == "rotation-observer")
                {
                    var mismatched = found.DeepClone().AsObject();
                    mismatched["parameters"]!["username1"] = "wrong-account";
                    return (200, new { secretRotation = mismatched });
                }
                if (method == "DELETE") rotations.Remove(found["id"]!.GetValue<string>());
                return (200, new { secretRotation = found });
            }
            if (!path.StartsWith("/api/v1/dynamic-secrets", StringComparison.Ordinal)) return (404, new { });
            if (role == "runtime") RuntimeRequests++;
            if (path == "/api/v1/dynamic-secrets")
            {
                if (method == "GET") return (200, new { dynamicSecrets = definitions.Values.Select(DefinitionJson).ToArray() });
                LastCreatedInputs = body.GetProperty("provider").GetProperty("inputs").Clone();
                string name = body.GetProperty("name").GetString()!;
                string selectedPath = body.GetProperty("path").GetString()!;
                var definition = new Definition(Guid.NewGuid(), name, folders.Single(f => f.Value.Path == selectedPath).Key,
                    body.GetProperty("defaultTTL").GetString()!,
                    body.TryGetProperty("maxTTL", out var maximum) ? maximum.GetString() : null, 1,
                    body.GetProperty("provider").GetProperty("type").GetString()!);
                definitions[name] = definition;
                return (200, new { dynamicSecret = DefinitionJson(definition) });
            }
            if (path == "/api/v1/dynamic-secrets/leases")
            {
                string name = body.GetProperty("dynamicSecretName").GetString()!;
                var definition = definitions[name];
                Guid id = Guid.NewGuid();
                string user = "user-" + id.ToString("N");
                string password = "password-" + id.ToString("N");
                var lease = new Lease(id, definition.Id, user, password, Epoch.AddSeconds(1),
                    Epoch.AddSeconds(121), 1);
                leases[id] = lease;
                backendCredentials[user] = (mode == "backend-rejects" ? "different-backend-password" : password,
                    mode == "bad-expiry" ? lease.ExpiresAt.AddSeconds(1) : lease.ExpiresAt);
                return (200, new
                {
                    dynamicSecret = DefinitionJson(definition),
                    lease = LeaseJson(lease),
                    data = new { DB_USERNAME = user, DB_PASSWORD = password }
                });
            }
            string[] segments = path.Split('/');
            if (segments[4] == "leases")
            {
                Guid id = Guid.Parse(segments[5]);
                if (!leases.TryGetValue(id, out var lease)) return (404, new { });
                object observed = LeaseJson(lease);
                if (method == "DELETE")
                {
                    bool forced = body.GetProperty("isForced").GetBoolean();
                    if (forced && role == "administrative") ForcedCleanupRequests++;
                    if (mode == "cleanup" && role == "administrative" && !forced) return (403, new { });
                    leases.Remove(id);
                    if (!forced && !(mode == "bad-revoke" && role == "runtime")) backendCredentials.Remove(lease.Username);
                    return (200, new { lease = observed });
                }
                if (method == "POST")
                {
                    if (mode == "no-op-renew") return (200, new { lease = LeaseJson(lease) });
                    lease = lease with { ExpiresAt = Epoch.AddSeconds(181), Version = lease.Version + 1 };
                    leases[id] = lease;
                    backendCredentials[lease.Username] = (lease.Password, lease.ExpiresAt);
                    if (mode == "renewal-echo-mismatch")
                        return (200, new { lease = LeaseJson(lease with { ExpiresAt = lease.ExpiresAt.AddSeconds(60) }) });
                    return (200, new { lease = LeaseJson(lease) });
                }
                var definition = definitions.Values.Single(d => d.Id == lease.DefinitionId);
                return (200, new { lease = LeaseWithDefinition(lease, definition) });
            }
            string selectedName = Uri.UnescapeDataString(segments[4]);
            if (!definitions.TryGetValue(selectedName, out var selected)) return (404, new { });
            if (segments.Length > 5) return (200, new { leases = leases.Values.Where(l => l.DefinitionId == selected.Id).Select(LeaseJson).ToArray() });
            if (method == "PATCH")
            {
                var data = body.GetProperty("data");
                selected = selected with
                {
                    Name = data.TryGetProperty("newName", out var newName) ? newName.GetString()! : selected.Name,
                    DefaultTtl = data.TryGetProperty("defaultTTL", out var ttl) ? ttl.GetString()! : selected.DefaultTtl,
                    MaximumTtl = data.TryGetProperty("maxTTL", out var maximum) ? maximum.GetString() : selected.MaximumTtl,
                    Version = selected.Version + 1
                };
                definitions.Remove(selectedName);
                definitions[selected.Name] = selected;
            }
            object projected = DefinitionJson(method == "PATCH" && mode == "rename-id-mismatch" ?
                selected with { Id = Guid.NewGuid() } : selected);
            if (role == "observer" && mode == "wrong-definition-provider")
                projected = DefinitionJson(selected with { Provider = "sql-database" });
            if (method == "DELETE")
            {
                if (role == "administrative" && body.GetProperty("isForced").GetBoolean()) ForcedCleanupRequests++;
                if (mode == "cleanup" && role == "administrative" && !body.GetProperty("isForced").GetBoolean())
                    return (403, new { });
                foreach (var lease in leases.Values.Where(l => l.DefinitionId == selected.Id).ToArray())
                {
                    leases.Remove(lease.Id);
                    if (!body.GetProperty("isForced").GetBoolean()) backendCredentials.Remove(lease.Username);
                }
                definitions.Remove(selectedName);
            }
            return (200, new { dynamicSecret = projected });
        }
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
        private static object DefinitionJson(Definition d) => new
        {
            id = d.Id,
            name = d.Name,
            folderId = d.FolderId,
            type = d.Provider,
            defaultTTL = d.DefaultTtl,
            maxTTL = d.MaximumTtl,
            version = d.Version,
            createdAt = Epoch,
            updatedAt = Epoch,
            status = (string?)null
        };
        private static object LeaseJson(Lease l) => new
        {
            id = l.Id,
            dynamicSecretId = l.DefinitionId,
            createdAt = l.CreatedAt,
            expireAt = l.ExpiresAt,
            updatedAt = l.CreatedAt,
            version = l.Version,
            externalEntityId = l.Username,
            status = (string?)null
        };
        private static object LeaseWithDefinition(Lease l, Definition d) => new
        {
            id = l.Id,
            dynamicSecretId = l.DefinitionId,
            createdAt = l.CreatedAt,
            expireAt = l.ExpiresAt,
            updatedAt = l.CreatedAt,
            version = l.Version,
            externalEntityId = l.Username,
            status = (string?)null,
            dynamicSecret = DefinitionJson(d)
        };
        private static string Query(Uri uri, string key) => uri.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
            .Where(p => p.Length == 2 && p[0] == key).Select(p => Uri.UnescapeDataString(p[1])).Single();
        public ValueTask<DynamicBackendFacts> MeasureAsync(DynamicBackendCoordinate coordinate, SecretMaterial user,
            SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (folders)
            {
                bool accepted = backendCredentials.TryGetValue(user.Reveal(), out var credential) &&
                    credential.Password == password.Reveal();
                return ValueTask.FromResult(new DynamicBackendFacts(coordinate,
                    accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected,
                    accepted ? ["select"] : [], accepted ? ["write"] : [], accepted ? credential.Expires : null));
            }
        }
        public ValueTask<SessionLifetimeFacts> MeasureAsync(SecretMaterial token, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new SessionLifetimeFacts(Epoch, Epoch.AddSeconds(60),
                InfisicalTokenLifetime.Finite, TimeSpan.FromSeconds(120), null, null) with
            {
                ExpiresAt = mode == "session-expiry" ? Epoch.AddSeconds(90) : Epoch.AddSeconds(60),
                Period = mode == "session-period" ? TimeSpan.FromSeconds(30) : null,
                AbsoluteLifetimeLimit = mode == "session-absolute" ? Epoch.AddSeconds(100) : null
            });
        }
        public ValueTask ExpiredAsync(SecretMaterial token, InfisicalTokenLifetimeEvidence previous, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Clock.Advance(previous.ExpiresAt - Clock.GetUtcNow());
            return ValueTask.CompletedTask;
        }
        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            try { await accept; }
            finally { listener.Stop(); }
            await Task.WhenAll(connections);
            shutdown.Dispose();
        }
        private sealed record Definition(Guid Id, string Name, string FolderId, string DefaultTtl,
            string? MaximumTtl, int Version, string Provider);
        private sealed record Lease(Guid Id, Guid DefinitionId, string Username, string Password,
            DateTimeOffset CreatedAt, DateTimeOffset ExpiresAt, int Version);
    }

    private sealed class RotationFactory(RotationWire wire) : IInfisicalRotationFixtureFactory
    {
        internal int Created { get; private set; }
        internal int Disposed { get; private set; }
        public ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
            InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Created++;
            wire.Address = new(input.Sandbox.ProjectId, input.Sandbox.Environment,
                input.Sandbox.Parent + "/fresh-" + Guid.NewGuid().ToString("N"), input.Profile, Guid.NewGuid().ToString("D"));
            return ValueTask.FromResult<IInfisicalRotationOwnedFixture>(new RotationFixture(wire.Address, input.Backend, () => Disposed++));
        }
        private sealed class RotationFixture(InfisicalRotationAddress address, RotationBackendCoordinate coordinate,
            Action dispose) : IInfisicalRotationOwnedFixture
        {
            public InfisicalRotationAddress Address => address;
            public RotationBackendCoordinate Coordinate => coordinate;
            public string UsernameKey => "owned-user";
            public string PasswordKey => "owned-password";
            public ValueTask DisposeAsync() { dispose(); return ValueTask.CompletedTask; }
        }
    }
    private sealed class RotationWire : HttpMessageHandler
    {
        internal InfisicalRotationAddress? Address { get; set; }
        internal int Mutations { get; private set; }
        private bool enabled;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (request.Headers.Authorization?.Parameter == "denied")
                return new(HttpStatusCode.Forbidden) { Content = new StringContent("{}") };
            if (request.Method != HttpMethod.Get)
            {
                Mutations++;
                if (request.Method == HttpMethod.Patch)
                {
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
                    enabled = body.RootElement.GetProperty("isAutoRotationEnabled").GetBoolean();
                }
            }
            var projection = new
            {
                id = Address!.RotationId,
                projectId = Address.ProjectId,
                type = "postgres-credentials",
                environment = new { slug = Address.Environment },
                folder = new { path = Address.Folder },
                rotationStatus = Mutations > 0 ? "pending" : "success",
                lastRotationAttemptedAt = Epoch,
                lastRotatedAt = Epoch,
                nextRotationAt = Epoch.AddHours(1),
                isAutoRotationEnabled = enabled
            };
            object payload = request.RequestUri!.AbsolutePath == "/api/v2/secret-rotations" ?
                new { secretRotations = new[] { projection } } : new { secretRotation = projection };
            return new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(payload)) };
        }
    }
}
