using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class DynamicDefinitionTests
{
    [Test]
    public async Task EveryAdmittedProfileCreatesTypedProtectedNativeDefinitionWithoutIssuance()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        string material = DynamicWireFixture.Material();
        InfisicalDynamicProfile[] profiles =
        [
            new NativeSqlDefinitionProfile(NativeSqlEngine.Postgres, "db.test", 5432, material, material, "db", "create\n", "revoke\n"),
            new NativeClickhouseDefinitionProfile("db.test", 8123, material, material, "db", "create", "revoke"),
            new NativeCassandraDefinitionProfile("db.test", 9042, material, material, "local", "create", "revoke"),
            new NativeSapAseDefinitionProfile("db.test", 5000, material, material, "db", "create", "revoke"),
            new NativeAwsIamDefinitionProfile(material, material, "region"),
            new NativeRedisDefinitionProfile("db.test", 6379, material, "create", "revoke", material),
            new NativeSapHanaDefinitionProfile("db.test", 30015, material, material, "create", "revoke"),
            new NativeAwsElasticacheDefinitionProfile(material, material, "region", "cluster", "create", "revoke"),
            new NativeAwsMemorydbDefinitionProfile(material, material, "region", "cluster", "create", "revoke"),
            new NativeAtlasDefinitionProfile(material, material, "group", [new("db", "role")], [new("scope", "type")]),
            new NativeElasticsearchDefinitionProfile("db.test", 9200, material, material, ["role"]),
            new NativeMongoDefinitionProfile("db.test", material, material, "db", ["role"]),
            new NativeRabbitDefinitionProfile("db.test", 5672, material, material, "vhost", "configure", "write", "read"),
            new NativeAzureEntraDefinitionProfile("tenant", "application", material, "user", "email"),
            new NativeAzureSqlDefinitionProfile("db.test", 1433, material, material, "db", "create", "masterCreate", "revoke"),
            new NativeLdapDefinitionProfile("ldaps://directory.test", "bind", material, "create", "revoke"),
            new NativeSnowflakeDefinitionProfile("account", "org", material, material, "create", "revoke"),
            new NativeTotpDefinitionProfile("otpauth://totp/fixture?secret=" + material),
            new NativeKubernetesDefinitionProfile("namespace", "role", true, ["audience"], material, "https://cluster.test"),
            new NativeVerticaDefinitionProfile("db.test", 5433, material, material, "db", "create", "revoke"),
            new NativeGcpIamDefinitionProfile("account@example.test"),
            new NativeGithubDefinitionProfile(1, 2, material),
            new NativeCouchbaseDefinitionProfile("https://couchbase.test", material, "org", "project", "cluster", ["role"]),
            new NativeMilvusDefinitionProfile("db.test", 19530, material, material),
            new NativeSshDefinitionProfile(["principal"]),
            new NativeIbmApiDefinitionProfile(material, "app", "client", material, "org", "catalog", "consumer", "https://ibm.test"),
            new NativeTailscaleDefinitionProfile(material),
            new NativeOauthDefinitionProfile("client", material, NativeOauthClientAuthentication.Basic, "https://oauth.test/token", "https://oauth.test/revoke")
        ];
        try
        {
            var supported = new HashSet<InfisicalDynamicProvider>();
            foreach (InfisicalDynamicProfile profile in profiles)
            {
                InfisicalDynamicTarget target = client.Definition("definition-" + supported.Count);
                var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
                InfisicalDynamicDefinition result = (await client.CreateDefinitionAsync(target, profile,
                    new(TimeSpan.FromMinutes(1)), new(TimeSpan.FromMinutes(2)), receipt)).Value;
                await Assert.That(result.Provider).IsEqualTo(profile.Provider);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That(supported.Add(result.Provider)).IsTrue();
                await Assert.That((await client.InspectDefinitionAsync(target)).Value.Id).IsEqualTo(result.Id);
                await Assert.That((await client.ListLeasesAsync(result)).Value.Items.Count).IsEqualTo(0);
                await Assert.That(JsonSerializer.Serialize(profile).Contains(material, StringComparison.Ordinal)).IsFalse();
                if (profile.Provider != InfisicalDynamicProvider.SqlDatabase)
                {
                    var acquire = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.Acquire);
                    await Assert.That((await client.AcquireDatabaseAsync(result, acquire)).Status).IsEqualTo(SecretStatus.ContractNotEstablished);
                    await Assert.That(acquire.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
                }
            }
            await Assert.That(supported.Count).IsEqualTo(28);
            await Assert.That((await client.ListDefinitionsAsync()).Value.Items.Count).IsEqualTo(28);
            await Assert.That(wire.LeaseCount).IsEqualTo(0);
            JsonElement sql = wire.Inputs("definition-0");
            await Assert.That(sql.GetProperty("creationStatement").GetString()).IsEqualTo("create\n");
            await Assert.That(sql.GetProperty("username").GetString()).IsEqualTo(material);
            JsonElement rabbit = wire.Inputs("definition-12");
            await Assert.That(rabbit.GetProperty("virtualHost").GetProperty("permissions").GetProperty("read").GetString()).IsEqualTo("read");
            JsonElement oauth = wire.Inputs("definition-27");
            await Assert.That(oauth.GetProperty("clientAuth").GetProperty("clientSecret").GetString()).IsEqualTo(material);
        }
        finally
        {
            foreach (InfisicalDynamicProfile profile in profiles) { profile.Dispose(); }
        }
    }

    [Test]
    public async Task PolicyUpdateAndDefinitionDeletionAreDistinctScopedMutations()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition definition = await wire.CreateDatabaseAsync(client);
        var update = new InfisicalDynamicMutationReceipt(definition.Target, InfisicalDynamicOperation.UpdateDefinition);
        InfisicalDynamicDefinition updated = (await client.UpdateDefinitionPolicyAsync(definition,
            new(TimeSpan.FromSeconds(30)), new(TimeSpan.FromSeconds(90)), update)).Value;
        await Assert.That(updated.DefaultTtl.Duration).IsEqualTo(TimeSpan.FromSeconds(30));
        await Assert.That(updated.MaximumTtl!.Duration).IsEqualTo(TimeSpan.FromSeconds(90));
        await Assert.That(updated.Version).IsEqualTo(2);
        using InfisicalDatabaseLease lease = (await client.AcquireDatabaseAsync(updated,
            new(updated.Target, InfisicalDynamicOperation.Acquire))).Value;
        var delete = new InfisicalDynamicMutationReceipt(updated.Target, InfisicalDynamicOperation.DeleteDefinition);
        InfisicalDynamicDeletion result = (await client.DeleteDefinitionAsync(updated, delete)).Value;
        await Assert.That(result.ExternalRevocationVerified).IsFalse();
        await Assert.That((await client.InspectDefinitionAsync(updated.Target)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
        await Assert.That(delete.Evidence).IsEqualTo(DispatchEvidence.Applied);
    }

    [Test]
    public async Task NativeProfileAuthenticationAlternativesPreserveDeclaredDiscriminators()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        string material = DynamicWireFixture.Material();
        (InfisicalDynamicProfile Profile, string Field, string Expected)[] alternatives =
        [
            (NativeAwsIamDefinitionProfile.ForAssumeRole("role", "region"), "method", "assume-role"),
            (NativeAwsIamDefinitionProfile.ForIrsa("region"), "method", "irsa"),
            (NativeElasticsearchDefinitionProfile.ForApiKey("db.test", 9200, material, material, ["role"]), "auth.type", "api-key"),
            (NativeKubernetesDefinitionProfile.ForStaticAccount("ns", "account", ["audience"], material, "https://cluster.test"), "credentialType", "static"),
            (NativeLdapDefinitionProfile.ForStaticAccount("ldaps://directory.test", "bind", material, "rotate"), "credentialType", "static"),
            (NativeTotpDefinitionProfile.ForManualSecret(material, NativeTotpAlgorithm.Sha512, 6, 30), "algorithm", "sha512"),
            (NativeTailscaleDefinitionProfile.ForOAuthAuthority("client", material), "auth.method", "oauth"),
            (NativeTailscaleDefinitionProfile.ForFederatedApiKey(material, "issuer", "subject", ["scope"]), "authType", "federated_keys"),
            (NativeTailscaleDefinitionProfile.ForFederatedOAuth("client", material, "issuer", "subject", ["scope"]), "auth.method", "oauth"),
            (NativeTailscaleDefinitionProfile.ForOAuthKeyApiKey(material, ["scope"]), "authType", "oauth_keys"),
            (NativeTailscaleDefinitionProfile.ForOAuthKeyOAuth("client", material, ["scope"]), "auth.method", "oauth"),
            (new NativeOauthDefinitionProfile("client", material, NativeOauthClientAuthentication.Post, "https://oauth.test/token", "https://oauth.test/revoke"), "clientAuth.method", "client_secret_post")
        ];
        try
        {
            for (int index = 0; index < alternatives.Length; index++)
            {
                (InfisicalDynamicProfile profile, string field, string expected) = alternatives[index];
                InfisicalDynamicTarget target = client.Definition("alternative-" + index);
                await Assert.That((await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromMinutes(1)),
                    null, new(target, InfisicalDynamicOperation.CreateDefinition))).IsSuccess).IsTrue();
                JsonElement input = wire.Inputs(target.Name);
                foreach (string part in field.Split('.')) { input = input.GetProperty(part); }
                await Assert.That(input.GetString()).IsEqualTo(expected);
                await Assert.That(JsonSerializer.Serialize(profile).Contains(material, StringComparison.Ordinal)).IsFalse();
            }
            await Assert.That(wire.LeaseCount).IsEqualTo(0);
        }
        finally
        {
            foreach ((InfisicalDynamicProfile profile, _, _) in alternatives) { profile.Dispose(); }
        }
    }

    [Test]
    public async Task TypedInputPatchRenameAndExplicitPolicyClearingRetainExactDefinitionIdentity()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicDefinition original = await wire.CreateDatabaseAsync(client);
        string material = DynamicWireFixture.Material();
        using var replacement = new NativeSqlDefinitionProfile(NativeSqlEngine.Mysql, "changed.test", 3306,
            material, material, "changed", "create", "revoke");
        var patch = new NativeDynamicDefinitionPatch(clearMaximumTtl: true, inputs: replacement, newName: "renamed",
            options: new NativeDynamicDefinitionOptions(metadata: [new(material, material)]), clearUsernameTemplate: true);
        var receipt = new InfisicalDynamicMutationReceipt(original.Target, InfisicalDynamicOperation.UpdateDefinition);
        InfisicalDynamicDefinition updated = (await client.UpdateDefinitionAsync(original, patch, receipt)).Value;
        await Assert.That(updated.Id).IsEqualTo(original.Id);
        await Assert.That(updated.Target.Name).IsEqualTo("renamed");
        await Assert.That(updated.MaximumTtl is null).IsTrue();
        await Assert.That((await client.InspectDefinitionAsync(original.Target)).Status).IsEqualTo(SecretStatus.Absent);
        await Assert.That(wire.Inputs("renamed").GetProperty("password").GetString()).IsEqualTo(material);
        await Assert.That(JsonSerializer.Serialize(patch).Contains(material, StringComparison.Ordinal)).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
    }

    [Test]
    public async Task InputResponseBytesDepthCountsAndDuplicateKeysFailClosedWithoutLeaking()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client(maximumBytes: 1024);
        InfisicalDynamicTarget target = client.Definition("bounded");
        using var profile = new NativeSqlDefinitionProfile(NativeSqlEngine.Postgres, "db.test", 5432,
            DynamicWireFixture.Material(), DynamicWireFixture.Material(), "db", new string('x', 2048), "revoke");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That(async () => await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromSeconds(60)), null, receipt)).Throws<ArgumentException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
        foreach (string raw in new[]
        {
            new string('x', 2048),
            "{\"dynamicSecrets\":[],\"dynamicSecrets\":[]}",
            new string('[', 33) + "0" + new string(']', 33),
            "{\"dynamicSecrets\":[" + string.Join(',', Enumerable.Repeat("{}", 129)) + "]}"
        })
        {
            wire.RawNextResponse = raw;
            await Assert.That((await client.ListDefinitionsAsync()).Status).IsEqualTo(SecretStatus.Invalid);
        }
        string error = DynamicWireFixture.Material();
        wire.RawNextResponse = error;
        wire.StatusNextResponse = System.Net.HttpStatusCode.Forbidden;
        SecretOutcome<InfisicalDynamicDefinition> denied = await client.InspectDefinitionAsync(target);
        await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((denied + JsonSerializer.Serialize(denied)).Contains(error, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task ProfileConstraintsAndDisposedInputsCannotDispatchDefinition()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        await Assert.That(() => new NativeSqlDefinitionProfile((NativeSqlEngine)100, "db.test", 5432,
            DynamicWireFixture.Material(), DynamicWireFixture.Material(), "db", "create", "revoke")).Throws<ArgumentException>();
        await Assert.That(() => new NativeSshDefinitionProfile([])).Throws<ArgumentException>();
        await Assert.That(() => new NativeOauthDefinitionProfile("client", new string('x', 4097),
            NativeOauthClientAuthentication.Basic, "https://oauth.test", "https://oauth.test")).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalLeaseDuration(TimeSpan.Zero)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalDynamicClient(new Uri("https://dynamic.test/escape"),
            new FailingSource(), client.Scope)).Throws<ArgumentException>();
        using var profile = new NativeGithubDefinitionProfile(1, 2, DynamicWireFixture.Material());
        profile.Dispose();
        InfisicalDynamicTarget target = client.Definition("disposed");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That(async () => await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromSeconds(60)), null, receipt)).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
    }

    [Test]
    public async Task RefitRequestBuilderRetainsBoundedStreamingWithoutResponseBuffering()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client(maximumBytes: 1024);
        wire.NextStreamingResponse = new StreamingContent("{\"dynamicSecrets\":[]}");
        await Assert.That((await client.ListDefinitionsAsync()).Value.Items.Count).IsEqualTo(0);
        wire.NextStreamingResponse = new StreamingContent(new string('x', 2048));
        await Assert.That((await client.ListDefinitionsAsync()).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
    }

    private sealed class StreamingContent : HttpContent
    {
        private readonly byte[] _bytes;
        internal StreamingContent(string text) => _bytes = System.Text.Encoding.UTF8.GetBytes(text);
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, System.Net.TransportContext? context) =>
            throw new InvalidOperationException("Native responses must not be automatically buffered.");
        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new MemoryStream(_bytes, writable: false));
    }

    private sealed class FailingSource : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            throw new InvalidOperationException("An invalid origin must never acquire a token.");
    }
}
