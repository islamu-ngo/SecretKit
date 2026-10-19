using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicProfileVariantTests
{
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task CouchbaseRepresentationAliasRequiresTheConfiguredTypedForm(bool text)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.Couchbase, true);
        using var baseline = sample.Profile;
        var couchbase = sample.Input.Couchbase ?? throw new InvalidOperationException();
        var input = text ? sample.Input with
        {
            Couchbase = couchbase with { Buckets = new(Text: "owned-bucket") }
        } : sample.Input;
        string variant = text ? "Couchbase.buckets.text" : "Couchbase.buckets.objects";
        string wrongVariant = text ? "Couchbase.buckets.objects" : "Couchbase.buckets.text";
        var selected = InfisicalDynamicProfileVariants.Select(variant, input);
        using var profile = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Couchbase, selected);
        var wire = (await Capture(profile)).GetProperty("inputs").GetProperty("buckets");
        await Assert.That(wire.ValueKind).IsEqualTo(text ? JsonValueKind.String : JsonValueKind.Array);
        if (text) await Assert.That(wire.GetString()).IsEqualTo("owned-bucket");
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(wrongVariant, input)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("NativeClickhouseDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.Clickhouse, "renewStatement", "omit")]
    [Arguments("NativeClickhouseDefinitionProfile.renewal.value", InfisicalDynamicProvider.Clickhouse, "renewStatement", "keep")]
    [Arguments("NativeClickhouseDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Clickhouse, "ca", "omit")]
    [Arguments("NativeClickhouseDefinitionProfile.ca.value", InfisicalDynamicProvider.Clickhouse, "ca", "keep")]
    [Arguments("NativeClickhouseDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.Clickhouse, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeClickhouseDefinitionProfile.gateway.value", InfisicalDynamicProvider.Clickhouse, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeClickhouseDefinitionProfile.passwordRequirements.omitted", InfisicalDynamicProvider.Clickhouse, "passwordRequirements", "omit")]
    [Arguments("NativeClickhouseDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Clickhouse, "passwordRequirements", "keep")]
    [Arguments("NativeCassandraDefinitionProfile.keyspace.omitted", InfisicalDynamicProvider.Cassandra, "keyspace", "omit")]
    [Arguments("NativeCassandraDefinitionProfile.keyspace.value", InfisicalDynamicProvider.Cassandra, "keyspace", "keep")]
    [Arguments("NativeCassandraDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.Cassandra, "renewStatement", "omit")]
    [Arguments("NativeCassandraDefinitionProfile.renewal.value", InfisicalDynamicProvider.Cassandra, "renewStatement", "keep")]
    [Arguments("NativeCassandraDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Cassandra, "ca", "omit")]
    [Arguments("NativeCassandraDefinitionProfile.ca.value", InfisicalDynamicProvider.Cassandra, "ca", "keep")]
    [Arguments("NativeSapHanaDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.SapHana, "renewStatement", "omit")]
    [Arguments("NativeSapHanaDefinitionProfile.renewal.value", InfisicalDynamicProvider.SapHana, "renewStatement", "keep")]
    [Arguments("NativeSapHanaDefinitionProfile.ca.omitted", InfisicalDynamicProvider.SapHana, "ca", "omit")]
    [Arguments("NativeSapHanaDefinitionProfile.ca.value", InfisicalDynamicProvider.SapHana, "ca", "keep")]
    [Arguments("NativeRedisDefinitionProfile.password.omitted", InfisicalDynamicProvider.Redis, "password", "omit")]
    [Arguments("NativeRedisDefinitionProfile.password.value", InfisicalDynamicProvider.Redis, "password", "keep")]
    [Arguments("NativeRedisDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.Redis, "renewStatement", "omit")]
    [Arguments("NativeRedisDefinitionProfile.renewal.value", InfisicalDynamicProvider.Redis, "renewStatement", "keep")]
    [Arguments("NativeRedisDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Redis, "ca", "omit")]
    [Arguments("NativeRedisDefinitionProfile.ca.value", InfisicalDynamicProvider.Redis, "ca", "keep")]
    [Arguments("NativeVerticaDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.Vertica, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeVerticaDefinitionProfile.gateway.value", InfisicalDynamicProvider.Vertica, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeVerticaDefinitionProfile.passwordRequirements.omitted", InfisicalDynamicProvider.Vertica, "passwordRequirements", "omit")]
    [Arguments("NativeVerticaDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Vertica, "passwordRequirements", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.masterDatabase.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "masterDatabase", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.masterDatabase.value", InfisicalDynamicProvider.AzureSqlDatabase, "masterDatabase", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "renewStatement", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.renewal.value", InfisicalDynamicProvider.AzureSqlDatabase, "renewStatement", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.ca.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "ca", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.ca.value", InfisicalDynamicProvider.AzureSqlDatabase, "ca", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.gateway.value", InfisicalDynamicProvider.AzureSqlDatabase, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.passwordRequirements.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "passwordRequirements", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.AzureSqlDatabase, "passwordRequirements", "keep")]
    [Arguments("NativeAzureSqlDefinitionProfile.sslEnabled.omitted", InfisicalDynamicProvider.AzureSqlDatabase, "sslEnabled", "omit")]
    [Arguments("NativeAzureSqlDefinitionProfile.sslEnabled.false", InfisicalDynamicProvider.AzureSqlDatabase, "sslEnabled", "false")]
    [Arguments("NativeAzureSqlDefinitionProfile.sslEnabled.true", InfisicalDynamicProvider.AzureSqlDatabase, "sslEnabled", "true")]
    [Arguments("NativeSnowflakeDefinitionProfile.renewal.omitted", InfisicalDynamicProvider.Snowflake, "renewStatement", "omit")]
    [Arguments("NativeSnowflakeDefinitionProfile.renewal.value", InfisicalDynamicProvider.Snowflake, "renewStatement", "keep")]
    [Arguments("NativeAwsIamDefinitionProfile.credentialKind.IamUser", InfisicalDynamicProvider.AwsIam, "credentialType", "\"iam-user\"")]
    [Arguments("NativeAwsIamDefinitionProfile.credentialKind.Temporary", InfisicalDynamicProvider.AwsIam, "credentialType", "\"temporary-credentials\"")]
    [Arguments("NativeAwsIamDefinitionProfile.options.omitted", InfisicalDynamicProvider.AwsIam, "awsPath|permissionBoundaryPolicyArn|policyArns|policyDocument|userGroups|tags", "omit")]
    [Arguments("NativeAwsIamDefinitionProfile.options.value", InfisicalDynamicProvider.AwsIam, "awsPath|permissionBoundaryPolicyArn|policyArns|policyDocument|userGroups|tags", "keep")]
    [Arguments("NativeGcpIamDefinitionProfile.tokenScopes.omitted", InfisicalDynamicProvider.GcpIam, "tokenScopes", "omit")]
    [Arguments("NativeGcpIamDefinitionProfile.tokenScopes.value", InfisicalDynamicProvider.GcpIam, "tokenScopes", "keep")]
    [Arguments("NativeMilvusDefinitionProfile.database.omitted", InfisicalDynamicProvider.Milvus, "database", "omit")]
    [Arguments("NativeMilvusDefinitionProfile.database.value", InfisicalDynamicProvider.Milvus, "database", "keep")]
    [Arguments("NativeMilvusDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Milvus, "ca", "omit")]
    [Arguments("NativeMilvusDefinitionProfile.ca.value", InfisicalDynamicProvider.Milvus, "ca", "keep")]
    [Arguments("NativeMilvusDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.Milvus, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeMilvusDefinitionProfile.gateway.value", InfisicalDynamicProvider.Milvus, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeMilvusDefinitionProfile.privileges.omitted", InfisicalDynamicProvider.Milvus, "privileges", "omit")]
    [Arguments("NativeMilvusDefinitionProfile.privileges.value", InfisicalDynamicProvider.Milvus, "privileges", "keep")]
    [Arguments("NativeMongoDefinitionProfile.port.omitted", InfisicalDynamicProvider.MongoDb, "port", "omit")]
    [Arguments("NativeMongoDefinitionProfile.port.value", InfisicalDynamicProvider.MongoDb, "port", "keep")]
    [Arguments("NativeMongoDefinitionProfile.ca.omitted", InfisicalDynamicProvider.MongoDb, "ca", "omit")]
    [Arguments("NativeMongoDefinitionProfile.ca.value", InfisicalDynamicProvider.MongoDb, "ca", "keep")]
    [Arguments("NativeMongoDefinitionProfile.clearPort.false", InfisicalDynamicProvider.MongoDb, "port", "keep")]
    [Arguments("NativeMongoDefinitionProfile.clearPort.true", InfisicalDynamicProvider.MongoDb, "port", "null")]
    [Arguments("NativeMongoDefinitionProfile.clearCa.false", InfisicalDynamicProvider.MongoDb, "ca", "keep")]
    [Arguments("NativeMongoDefinitionProfile.clearCa.true", InfisicalDynamicProvider.MongoDb, "ca", "null")]
    [Arguments("NativeElasticsearchDefinitionProfile.ca.omitted", InfisicalDynamicProvider.ElasticSearch, "ca", "omit")]
    [Arguments("NativeElasticsearchDefinitionProfile.ca.value", InfisicalDynamicProvider.ElasticSearch, "ca", "keep")]
    [Arguments("NativeRabbitDefinitionProfile.tags.omitted", InfisicalDynamicProvider.RabbitMq, "tags", "omit")]
    [Arguments("NativeRabbitDefinitionProfile.tags.value", InfisicalDynamicProvider.RabbitMq, "tags", "keep")]
    [Arguments("NativeRabbitDefinitionProfile.ca.omitted", InfisicalDynamicProvider.RabbitMq, "ca", "omit")]
    [Arguments("NativeRabbitDefinitionProfile.ca.value", InfisicalDynamicProvider.RabbitMq, "ca", "keep")]
    [Arguments("NativeKubernetesDefinitionProfile.clusterToken.omitted", InfisicalDynamicProvider.Kubernetes, "clusterToken", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.clusterToken.value", InfisicalDynamicProvider.Kubernetes, "clusterToken", "keep")]
    [Arguments("NativeKubernetesDefinitionProfile.url.omitted", InfisicalDynamicProvider.Kubernetes, "url", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.url.value", InfisicalDynamicProvider.Kubernetes, "url", "keep")]
    [Arguments("NativeKubernetesDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Kubernetes, "ca", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.ca.value", InfisicalDynamicProvider.Kubernetes, "ca", "keep")]
    [Arguments("NativeKubernetesDefinitionProfile.authentication.Api", InfisicalDynamicProvider.Kubernetes, "authMethod", "\"api\"")]
    [Arguments("NativeKubernetesDefinitionProfile.authentication.Gateway", InfisicalDynamicProvider.Kubernetes, "authMethod", "\"gateway\"")]
    [Arguments("NativeKubernetesDefinitionProfile.authentication.omitted", InfisicalDynamicProvider.Kubernetes, "authMethod", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.Kubernetes, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.gateway.value", InfisicalDynamicProvider.Kubernetes, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeKubernetesDefinitionProfile.sslEnabled.omitted", InfisicalDynamicProvider.Kubernetes, "sslEnabled", "omit")]
    [Arguments("NativeKubernetesDefinitionProfile.sslEnabled.false", InfisicalDynamicProvider.Kubernetes, "sslEnabled", "false")]
    [Arguments("NativeKubernetesDefinitionProfile.sslEnabled.true", InfisicalDynamicProvider.Kubernetes, "sslEnabled", "true")]
    [Arguments("NativeLdapDefinitionProfile.rollbackLdif.omitted", InfisicalDynamicProvider.Ldap, "rollbackLdif", "omit")]
    [Arguments("NativeLdapDefinitionProfile.rollbackLdif.value", InfisicalDynamicProvider.Ldap, "rollbackLdif", "keep")]
    [Arguments("NativeLdapDefinitionProfile.ca.omitted", InfisicalDynamicProvider.Ldap, "ca", "omit")]
    [Arguments("NativeLdapDefinitionProfile.ca.value", InfisicalDynamicProvider.Ldap, "ca", "keep")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.Rsa2048", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"RSA_2048\"")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.Rsa4096", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"RSA_4096\"")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.EcPrime256v1", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"EC_prime256v1\"")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.EcSecp384r1", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"EC_secp384r1\"")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.Ed25519", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"ED25519\"")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.omitted", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "omit")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.Rsa2048", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"RSA_2048\"")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.Rsa4096", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"RSA_4096\"")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.EcPrime256v1", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"EC_prime256v1\"")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.EcSecp384r1", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"EC_secp384r1\"")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.Ed25519", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"ED25519\"")]
    [Arguments("NativeSshDefinitionProfile.caKeyAlgorithm.omitted", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "omit")]
    [Arguments("NativeIbmApiDefinitionProfile.gateway.omitted", InfisicalDynamicProvider.IbmApiConnect, "gatewayId|gatewayPoolId", "omit")]
    [Arguments("NativeIbmApiDefinitionProfile.gateway.value", InfisicalDynamicProvider.IbmApiConnect, "gatewayId|gatewayPoolId", "keep")]
    [Arguments("NativeOauthDefinitionProfile.scope.omitted", InfisicalDynamicProvider.Oauth2, "scope", "omit")]
    [Arguments("NativeOauthDefinitionProfile.scope.value", InfisicalDynamicProvider.Oauth2, "scope", "keep")]
    [Arguments("NativeOauthDefinitionProfile.extraParameters.omitted", InfisicalDynamicProvider.Oauth2, "extraParams", "omit")]
    [Arguments("NativeOauthDefinitionProfile.extraParameters.value", InfisicalDynamicProvider.Oauth2, "extraParams", "keep")]
    [Arguments("NativeTailscaleDefinitionProfile.tailnet.omitted", InfisicalDynamicProvider.Tailscale, "tailnet", "omit")]
    [Arguments("NativeTailscaleDefinitionProfile.tailnet.value", InfisicalDynamicProvider.Tailscale, "tailnet", "keep")]
    [Arguments("NativeTailscaleDefinitionProfile.reusable.false", InfisicalDynamicProvider.Tailscale, "reusable", "false")]
    [Arguments("NativeTailscaleDefinitionProfile.reusable.true", InfisicalDynamicProvider.Tailscale, "reusable", "true")]
    [Arguments("NativeTailscaleDefinitionProfile.preauthorized.false", InfisicalDynamicProvider.Tailscale, "preauthorized", "false")]
    [Arguments("NativeTailscaleDefinitionProfile.preauthorized.true", InfisicalDynamicProvider.Tailscale, "preauthorized", "true")]
    [Arguments("NativeTailscaleDefinitionProfile.tags.omitted", InfisicalDynamicProvider.Tailscale, "tags", "omit")]
    [Arguments("NativeTailscaleDefinitionProfile.tags.value", InfisicalDynamicProvider.Tailscale, "tags", "keep")]
    [Arguments("NativeTailscaleDefinitionProfile.description.omitted", InfisicalDynamicProvider.Tailscale, "description", "omit")]
    [Arguments("NativeTailscaleDefinitionProfile.description.value", InfisicalDynamicProvider.Tailscale, "description", "keep")]
    [Arguments("NativeCouchbaseDefinitionProfile.buckets.omitted", InfisicalDynamicProvider.Couchbase, "buckets", "omit")]
    [Arguments("NativeCouchbaseDefinitionProfile.buckets.value", InfisicalDynamicProvider.Couchbase, "buckets", "keep")]
    [Arguments("NativeCouchbaseDefinitionProfile.passwordRequirements.omitted", InfisicalDynamicProvider.Couchbase, "passwordRequirements", "omit")]
    [Arguments("NativeCouchbaseDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Couchbase, "passwordRequirements", "keep")]
    [Arguments("Ssh.keyAlgorithm.Rsa2048", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"RSA_2048\"")]
    [Arguments("Ssh.keyAlgorithm.Rsa4096", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"RSA_4096\"")]
    [Arguments("Ssh.keyAlgorithm.EcPrime256v1", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"EC_prime256v1\"")]
    [Arguments("Ssh.keyAlgorithm.EcSecp384r1", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"EC_secp384r1\"")]
    [Arguments("Ssh.keyAlgorithm.Ed25519", InfisicalDynamicProvider.Ssh, "keyAlgorithm", "\"ED25519\"")]
    [Arguments("Ssh.caKeyAlgorithm.Rsa2048", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"RSA_2048\"")]
    [Arguments("Ssh.caKeyAlgorithm.Rsa4096", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"RSA_4096\"")]
    [Arguments("Ssh.caKeyAlgorithm.EcPrime256v1", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"EC_prime256v1\"")]
    [Arguments("Ssh.caKeyAlgorithm.EcSecp384r1", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"EC_secp384r1\"")]
    [Arguments("Ssh.caKeyAlgorithm.Ed25519", InfisicalDynamicProvider.Ssh, "caKeyAlgorithm", "\"ED25519\"")]
    [Arguments("Ssh.algorithms.omitted", InfisicalDynamicProvider.Ssh, "keyAlgorithm|caKeyAlgorithm", "omit")]
    [Arguments("MongoDb.port.omitted", InfisicalDynamicProvider.MongoDb, "port", "omit")]
    [Arguments("MongoDb.port.null", InfisicalDynamicProvider.MongoDb, "port", "null")]
    [Arguments("MongoDb.port.value", InfisicalDynamicProvider.MongoDb, "port", "keep")]
    [Arguments("MongoDb.ca.omitted", InfisicalDynamicProvider.MongoDb, "ca", "omit")]
    [Arguments("MongoDb.ca.null", InfisicalDynamicProvider.MongoDb, "ca", "null")]
    [Arguments("MongoDb.ca.value", InfisicalDynamicProvider.MongoDb, "ca", "keep")]
    [Arguments("Oauth2.Basic", InfisicalDynamicProvider.Oauth2, "clientAuth.method", "\"client_secret_basic\"")]
    [Arguments("Oauth2.Post", InfisicalDynamicProvider.Oauth2, "clientAuth.method", "\"client_secret_post\"")]
    [Arguments("Kubernetes.dynamic-role", InfisicalDynamicProvider.Kubernetes, "roleType", "\"role\"")]
    [Arguments("Kubernetes.dynamic-cluster-role", InfisicalDynamicProvider.Kubernetes, "roleType", "\"cluster-role\"")]
    [Arguments("Kubernetes.auth.omitted", InfisicalDynamicProvider.Kubernetes, "authMethod", "omit")]
    [Arguments("Kubernetes.auth.Api", InfisicalDynamicProvider.Kubernetes, "authMethod", "\"api\"")]
    [Arguments("Kubernetes.auth.Gateway", InfisicalDynamicProvider.Kubernetes, "authMethod", "\"gateway\"")]
    [Arguments("ElasticSearch.user", InfisicalDynamicProvider.ElasticSearch, "", "keep")]
    [Arguments("Ldap.dynamic", InfisicalDynamicProvider.Ldap, "", "keep")]
    [Arguments("Totp.url", InfisicalDynamicProvider.Totp, "", "keep")]
    [Arguments("Tailscale.auth_keys.api_key", InfisicalDynamicProvider.Tailscale, "", "keep")]
    public async Task SelectedVariantHasExactPublicTransportEffect(string variant,
        InfisicalDynamicProvider provider, string fields, string effect)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
        using var expectedProfile = sample.Profile;
        var expected = JsonNode.Parse((await Capture(expectedProfile)).GetRawText())!;
        string before = JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options);
        await Assert.That(InfisicalDynamicProfileVariants.TryProvider(variant, out var selectedProvider)).IsTrue();
        await Assert.That(selectedProvider).IsEqualTo(provider);
        await Assert.That(InfisicalDynamicProfileVariants.TryProvider(variant.ToLowerInvariant(), out _)).IsFalse();
        await Assert.That(InfisicalDynamicProfileVariants.TryProvider(variant + ".unknown", out _)).IsFalse();
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(variant, new())).Throws<ArgumentException>();
        var wrong = provider == InfisicalDynamicProvider.Ssh ?
            new InfisicalDynamicProfileInput(Totp: new("https://totp.test")) :
            new InfisicalDynamicProfileInput(Ssh: new(["principal-canary"]));
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(variant, wrong)).Throws<ArgumentException>();
        var multiple = provider == InfisicalDynamicProvider.Ssh ?
            sample.Input with { Totp = new("https://totp.test") } :
            sample.Input with { Ssh = new(["principal-canary"]) };
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(variant, multiple)).Throws<ArgumentException>();
        var selected = InfisicalDynamicProfileVariants.Select(variant, sample.Input);
        await Assert.That(ReferenceEquals(selected, sample.Input)).IsFalse();
        foreach (string field in fields.Split('|', StringSplitOptions.RemoveEmptyEntries))
        {
            string[] path = field.Split('.');
            JsonObject parent = (path.Length == 1 ? expected["inputs"] : expected["inputs"]![path[0]])!.AsObject();
            string key = path[^1];
            if (effect == "omit")
            {
                await Assert.That(parent.ContainsKey(key)).IsTrue();
                parent.Remove(key);
            }
            else if (effect == "keep") await Assert.That(parent.ContainsKey(key)).IsTrue();
            else parent[key] = JsonNode.Parse(effect);
        }
        using var actualProfile = InfisicalDynamicProfileInputs.Create(provider, selected);
        JsonElement actual = await Capture(actualProfile);
        await Assert.That(JsonElement.DeepEquals(actual, JsonSerializer.SerializeToElement(expected))).IsTrue();
        await Assert.That(JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options)).IsEqualTo(before);
        await Assert.That(selected.ToString()).IsEqualTo("[InfisicalDynamicProfileInput]");
        await Assert.That(actualProfile.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        actualProfile.Dispose();
        // Disposing one SDK-owned copy must not dispose a sibling made from the snapshot.
        using var sibling = InfisicalDynamicProfileInputs.Create(provider, selected);
        await Assert.That(JsonElement.DeepEquals(actual, await Capture(sibling))).IsTrue();
    }

    [Test]
    public async Task EveryAdmittedProfileFieldAndLegacyAliasIsSelectedExactly()
    {
        string root = FindRoot();
        using var admission = JsonDocument.Parse(File.ReadAllText(Path.Combine(root,
            "docs/internal/releases/admission/infisical.json")));
        var operation = admission.RootElement.GetProperty("operations").EnumerateArray().Single(row =>
            row.GetProperty("id").GetString() == "i.runtime.InfisicalDynamicClient.CreateDefinitionAsync");
        string[] native = operation.GetProperty("variants").EnumerateArray().Select(v => v.GetString()!)
            .Where(v => v.StartsWith("Native", StringComparison.Ordinal) && v.Contains("DefinitionProfile.", StringComparison.Ordinal)
                && !v.StartsWith("NativeSqlDefinitionProfile.", StringComparison.Ordinal)).ToArray();
        await Assert.That(native.Length).IsEqualTo(121);
        string[] aliases =
        [
            "Ssh.keyAlgorithm.Rsa2048",
            "Ssh.keyAlgorithm.Rsa4096",
            "Ssh.keyAlgorithm.EcPrime256v1",
            "Ssh.keyAlgorithm.EcSecp384r1",
            "Ssh.keyAlgorithm.Ed25519",
            "Ssh.caKeyAlgorithm.Rsa2048",
            "Ssh.caKeyAlgorithm.Rsa4096",
            "Ssh.caKeyAlgorithm.EcPrime256v1",
            "Ssh.caKeyAlgorithm.EcSecp384r1",
            "Ssh.caKeyAlgorithm.Ed25519",
            "Ssh.algorithms.omitted",
            "MongoDb.port.omitted",
            "MongoDb.port.null",
            "MongoDb.port.value",
            "MongoDb.ca.omitted",
            "MongoDb.ca.null",
            "MongoDb.ca.value",
            "Oauth2.Basic",
            "Oauth2.Post",
            "Kubernetes.dynamic-role",
            "Kubernetes.dynamic-cluster-role",
            "Kubernetes.auth.omitted",
            "Kubernetes.auth.Api",
            "Kubernetes.auth.Gateway",
            "ElasticSearch.user",
            "Ldap.dynamic",
            "Totp.url",
            "Tailscale.auth_keys.api_key",
            "Couchbase.buckets.text",
            "Couchbase.buckets.objects",
        ];
        foreach (string variant in native.Concat(aliases))
        {
            await Assert.That(operation.GetProperty("variants").EnumerateArray().Any(v => v.GetString() == variant)).IsTrue();
            await Assert.That(InfisicalDynamicProfileVariants.TryProvider(variant, out var provider)).IsTrue();
            var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
            using var baseline = sample.Profile;
            var input = sample.Input;
            if (variant == "Couchbase.buckets.text")
                input = input with
                {
                    Couchbase = (input.Couchbase ?? throw new InvalidOperationException()) with
                    {
                        Buckets = new(Text: "owned-bucket")
                    }
                };
            using var profile = InfisicalDynamicProfileInputs.Create(provider,
                InfisicalDynamicProfileVariants.Select(variant, input));
            await Assert.That(profile.Provider).IsEqualTo(provider);
        }
        await Assert.That(native.Concat(aliases).Distinct(StringComparer.Ordinal).Count()).IsEqualTo(151);
    }

    [Test]
    [Arguments("nativeSshDefinitionProfile.keyAlgorithm.Ed25519")]
    [Arguments("NativeSshDefinitionProfile.keyAlgorithm.ed25519")]
    [Arguments("NativeSshDefinitionProfile.unknown.value")]
    [Arguments("NativeMongoDefinitionProfile.port.null")]
    [Arguments("NativeSqlDefinitionProfile.ca.value")]
    [Arguments("NativeGatewayOptions.gatewayId.value")]
    [Arguments("NativeAwsIamOptions.awsPath.value")]
    [Arguments("ElasticSearch.api-key")]
    [Arguments("Kubernetes.static-account")]
    [Arguments("Ldap.static-account")]
    [Arguments("Totp.manual.Sha1")]
    [Arguments("Tailscale.auth_keys.oauth")]
    [Arguments("AwsIam.irsa.Temporary")]
    [Arguments("Ssh.keyAlgorithm.Ed25519 ")]
    [Arguments("")]
    public async Task UnknownAndOutOfScopeSpellingsFailClosed(string variant)
    {
        await Assert.That(InfisicalDynamicProfileVariants.TryProvider(variant, out _)).IsFalse();
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(variant, new())).Throws<ArgumentException>();
    }

    [Test]
    public async Task MissingMismatchedMultipleAndNullInputsFailClosed()
    {
        var ssh = new InfisicalDynamicProfileInput(Ssh: new(["principal-canary"]));
        var multiple = ssh with { Totp = new("https://totp.test") };
        foreach (var input in new[] { new InfisicalDynamicProfileInput(), ssh, multiple })
            await Assert.That(() => InfisicalDynamicProfileVariants.Select("Totp.url", input)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicProfileVariants.Select("Totp.url", null!)).Throws<ArgumentNullException>();
        await Assert.That(InfisicalDynamicProfileVariants.TryProvider(null!, out _)).IsFalse();
    }

    [Test]
    [Arguments("NativeClickhouseDefinitionProfile.renewal.value", InfisicalDynamicProvider.Clickhouse)]
    [Arguments("NativeClickhouseDefinitionProfile.ca.value", InfisicalDynamicProvider.Clickhouse)]
    [Arguments("NativeClickhouseDefinitionProfile.gateway.value", InfisicalDynamicProvider.Clickhouse)]
    [Arguments("NativeClickhouseDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Clickhouse)]
    [Arguments("NativeCassandraDefinitionProfile.keyspace.value", InfisicalDynamicProvider.Cassandra)]
    [Arguments("NativeCassandraDefinitionProfile.renewal.value", InfisicalDynamicProvider.Cassandra)]
    [Arguments("NativeCassandraDefinitionProfile.ca.value", InfisicalDynamicProvider.Cassandra)]
    [Arguments("NativeSapHanaDefinitionProfile.renewal.value", InfisicalDynamicProvider.SapHana)]
    [Arguments("NativeSapHanaDefinitionProfile.ca.value", InfisicalDynamicProvider.SapHana)]
    [Arguments("NativeRedisDefinitionProfile.password.value", InfisicalDynamicProvider.Redis)]
    [Arguments("NativeRedisDefinitionProfile.renewal.value", InfisicalDynamicProvider.Redis)]
    [Arguments("NativeRedisDefinitionProfile.ca.value", InfisicalDynamicProvider.Redis)]
    [Arguments("NativeVerticaDefinitionProfile.gateway.value", InfisicalDynamicProvider.Vertica)]
    [Arguments("NativeVerticaDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Vertica)]
    [Arguments("NativeAzureSqlDefinitionProfile.masterDatabase.value", InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments("NativeAzureSqlDefinitionProfile.renewal.value", InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments("NativeAzureSqlDefinitionProfile.ca.value", InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments("NativeAzureSqlDefinitionProfile.gateway.value", InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments("NativeAzureSqlDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments("NativeSnowflakeDefinitionProfile.renewal.value", InfisicalDynamicProvider.Snowflake)]
    [Arguments("NativeAwsIamDefinitionProfile.options.value", InfisicalDynamicProvider.AwsIam)]
    [Arguments("NativeGcpIamDefinitionProfile.tokenScopes.value", InfisicalDynamicProvider.GcpIam)]
    [Arguments("NativeMilvusDefinitionProfile.database.value", InfisicalDynamicProvider.Milvus)]
    [Arguments("NativeMilvusDefinitionProfile.ca.value", InfisicalDynamicProvider.Milvus)]
    [Arguments("NativeMilvusDefinitionProfile.gateway.value", InfisicalDynamicProvider.Milvus)]
    [Arguments("NativeMilvusDefinitionProfile.privileges.value", InfisicalDynamicProvider.Milvus)]
    [Arguments("NativeMongoDefinitionProfile.port.value", InfisicalDynamicProvider.MongoDb)]
    [Arguments("NativeMongoDefinitionProfile.ca.value", InfisicalDynamicProvider.MongoDb)]
    [Arguments("NativeElasticsearchDefinitionProfile.ca.value", InfisicalDynamicProvider.ElasticSearch)]
    [Arguments("NativeRabbitDefinitionProfile.tags.value", InfisicalDynamicProvider.RabbitMq)]
    [Arguments("NativeRabbitDefinitionProfile.ca.value", InfisicalDynamicProvider.RabbitMq)]
    [Arguments("NativeKubernetesDefinitionProfile.clusterToken.value", InfisicalDynamicProvider.Kubernetes)]
    [Arguments("NativeKubernetesDefinitionProfile.url.value", InfisicalDynamicProvider.Kubernetes)]
    [Arguments("NativeKubernetesDefinitionProfile.ca.value", InfisicalDynamicProvider.Kubernetes)]
    [Arguments("NativeKubernetesDefinitionProfile.gateway.value", InfisicalDynamicProvider.Kubernetes)]
    [Arguments("NativeLdapDefinitionProfile.rollbackLdif.value", InfisicalDynamicProvider.Ldap)]
    [Arguments("NativeLdapDefinitionProfile.ca.value", InfisicalDynamicProvider.Ldap)]
    [Arguments("NativeIbmApiDefinitionProfile.gateway.value", InfisicalDynamicProvider.IbmApiConnect)]
    [Arguments("NativeOauthDefinitionProfile.scope.value", InfisicalDynamicProvider.Oauth2)]
    [Arguments("NativeOauthDefinitionProfile.extraParameters.value", InfisicalDynamicProvider.Oauth2)]
    [Arguments("NativeTailscaleDefinitionProfile.tailnet.value", InfisicalDynamicProvider.Tailscale)]
    [Arguments("NativeTailscaleDefinitionProfile.tags.value", InfisicalDynamicProvider.Tailscale)]
    [Arguments("NativeTailscaleDefinitionProfile.description.value", InfisicalDynamicProvider.Tailscale)]
    [Arguments("NativeCouchbaseDefinitionProfile.buckets.value", InfisicalDynamicProvider.Couchbase)]
    [Arguments("NativeCouchbaseDefinitionProfile.passwordRequirements.value", InfisicalDynamicProvider.Couchbase)]
    [Arguments("MongoDb.port.value", InfisicalDynamicProvider.MongoDb)]
    [Arguments("MongoDb.ca.value", InfisicalDynamicProvider.MongoDb)]
    public async Task ValueRequiresTheSelectedConfiguredOptional(string variant, InfisicalDynamicProvider provider)
    {
        var absent = InfisicalDynamicProfileInputTests.Sample(provider, false);
        using var profile = absent.Profile;
        await Assert.That(() => InfisicalDynamicProfileVariants.Select(variant, absent.Input)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("NativeAwsIamDefinitionProfile.options.value", InfisicalDynamicProvider.AwsIam)]
    [Arguments("NativeGcpIamDefinitionProfile.tokenScopes.value", InfisicalDynamicProvider.GcpIam)]
    [Arguments("NativeMilvusDefinitionProfile.privileges.value", InfisicalDynamicProvider.Milvus)]
    [Arguments("NativeMongoDefinitionProfile.port.value", InfisicalDynamicProvider.MongoDb)]
    [Arguments("ElasticSearch.user", InfisicalDynamicProvider.ElasticSearch)]
    [Arguments("NativeRabbitDefinitionProfile.tags.value", InfisicalDynamicProvider.RabbitMq)]
    [Arguments("Kubernetes.dynamic-role", InfisicalDynamicProvider.Kubernetes)]
    [Arguments("Ssh.keyAlgorithm.Ed25519", InfisicalDynamicProvider.Ssh)]
    [Arguments("NativeOauthDefinitionProfile.extraParameters.value", InfisicalDynamicProvider.Oauth2)]
    [Arguments("Tailscale.auth_keys.api_key", InfisicalDynamicProvider.Tailscale)]
    public async Task SnapshotCopiesEachMutableProviderContainer(string variant, InfisicalDynamicProvider provider)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
        using var baseline = sample.Profile;
        var selected = InfisicalDynamicProfileVariants.Select(variant, sample.Input);
        using var before = InfisicalDynamicProfileInputs.Create(provider, selected);
        JsonElement expected = await Capture(before);
        switch (provider)
        {
            case InfisicalDynamicProvider.AwsIam:
                sample.Input.AwsIam!.Options!.Tags![0] = new("changed-key", "changed-value");
                break;
            case InfisicalDynamicProvider.GcpIam:
                sample.Input.GcpIam!.TokenScopes![0] = "changed-scope";
                break;
            case InfisicalDynamicProvider.Milvus:
                sample.Input.Milvus!.Privileges![0] = new("changed-object", "changed-privilege");
                break;
            case InfisicalDynamicProvider.MongoDb:
                sample.Input.MongoDb!.Roles[0] = "changed-role";
                break;
            case InfisicalDynamicProvider.ElasticSearch:
                sample.Input.ElasticSearch!.Roles[0] = "changed-role";
                break;
            case InfisicalDynamicProvider.RabbitMq:
                sample.Input.RabbitMq!.Tags![0] = "changed-tag";
                break;
            case InfisicalDynamicProvider.Kubernetes:
                sample.Input.Kubernetes!.Audiences[0] = "changed-audience";
                break;
            case InfisicalDynamicProvider.Ssh:
                sample.Input.Ssh!.Principals[0] = "changed-principal";
                break;
            case InfisicalDynamicProvider.Oauth2:
                sample.Input.Oauth2!.ExtraParameters![0] = new("changed-key", "changed-value");
                break;
            case InfisicalDynamicProvider.Tailscale:
                sample.Input.Tailscale!.Tags![0] = "changed-tag";
                break;
            default:
                throw new ArgumentException("Unexpected mutable profile.");
        }
        using var actual = InfisicalDynamicProfileInputs.Create(provider, selected);
        await Assert.That(JsonElement.DeepEquals(await Capture(actual), expected)).IsTrue();
    }

    [Test]
    public async Task SnapshotCopiesMutableNestedInputsBeforeCallerMutation()
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.Couchbase, true);
        using var expected = sample.Profile;
        var selected = InfisicalDynamicProfileVariants.Select("NativeCouchbaseDefinitionProfile.buckets.value", sample.Input);
        sample.Input.Couchbase!.Roles[0] = "changed-role";
        sample.Input.Couchbase.Buckets!.Buckets![0].Scopes![0].Collections![0] = "changed-collection";
        using var actual = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Couchbase, selected);
        await Assert.That(JsonElement.DeepEquals(await Capture(actual), await Capture(expected))).IsTrue();
    }

    [Test]
    [Arguments("NativeMongoDefinitionProfile.port.omitted", true)]
    [Arguments("NativeMongoDefinitionProfile.ca.omitted", false)]
    public async Task MongoOmissionOverridesExplicitNullSelection(string variant, bool port)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.MongoDb, true);
        using var baseline = sample.Profile;
        var input = sample.Input with
        {
            MongoDb = port ? sample.Input.MongoDb! with { Port = null, ClearPort = true } :
                sample.Input.MongoDb! with { Ca = null, ClearCa = true }
        };
        var selected = InfisicalDynamicProfileVariants.Select(variant, input);
        using var actual = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.MongoDb, selected);
        var wire = await Capture(actual);
        await Assert.That(wire.GetProperty("inputs").TryGetProperty(port ? "port" : "ca", out _)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(input, InfisicalLifecycleFamilies.Options))
            .IsEqualTo(JsonSerializer.Serialize(port ?
                sample.Input with { MongoDb = sample.Input.MongoDb! with { Port = null, ClearPort = true } } :
                sample.Input with { MongoDb = sample.Input.MongoDb! with { Ca = null, ClearCa = true } },
                InfisicalLifecycleFamilies.Options));
    }

    [Test]
    public async Task MongoFalseClearingPreservesConfiguredValues()
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(InfisicalDynamicProvider.MongoDb, true);
        using var expected = sample.Profile;
        var input = sample.Input with { MongoDb = sample.Input.MongoDb! with { ClearPort = true, ClearCa = true } };
        var port = InfisicalDynamicProfileVariants.Select("NativeMongoDefinitionProfile.clearPort.false", input);
        await Assert.That(port.MongoDb!.Port).IsEqualTo(1234);
        await Assert.That(port.MongoDb.ClearPort).IsFalse();
        await Assert.That(port.MongoDb.ClearCa).IsTrue();
        var ca = InfisicalDynamicProfileVariants.Select("NativeMongoDefinitionProfile.clearCa.false", port);
        await Assert.That(ca.MongoDb!.Ca).IsEqualTo("ca-canary");
        using var actual = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.MongoDb, ca);
        await Assert.That(JsonElement.DeepEquals(await Capture(actual), await Capture(expected))).IsTrue();
    }

    private static string FindRoot()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
            if (File.Exists(Path.Combine(directory.FullName, "SecretKit.slnx"))) return directory.FullName;
        throw new InvalidOperationException("Repository admission fixture is required.");
    }

    private static async Task<JsonElement> Capture(InfisicalDynamicProfile profile)
    {
        using var transport = new CaptureTransport();
        await using var client = new InfisicalDynamicClient(new("https://dynamic.test"), new Tokens(),
            new("project", "environment", "/folder", CaptureTransport.FolderId), transport: transport);
        var target = client.Definition("offline");
        var outcome = await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), new(target, InfisicalDynamicOperation.CreateDefinition));
        await Assert.That(outcome.IsSuccess).IsTrue();
        return transport.Provider!.Value;
    }

    private sealed class CaptureTransport : HttpMessageHandler
    {
        internal static readonly Guid FolderId = new("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        internal JsonElement? Provider { get; private set; }
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            await Assert.That(request.Method).IsEqualTo(HttpMethod.Post);
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://dynamic.test/api/v1/dynamic-secrets");
            using var document = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            JsonElement body = document.RootElement;
            Provider = body.GetProperty("provider").Clone();
            return new(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    dynamicSecret = new
                    {
                        id = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                        name = body.GetProperty("name").GetString(),
                        type = Provider.Value.GetProperty("type").GetString(),
                        folderId = FolderId,
                        defaultTTL = body.GetProperty("defaultTTL").GetString(),
                        maxTTL = body.GetProperty("maxTTL").GetString(),
                        createdAt = "2026-01-01T00:00:00Z",
                        updatedAt = "2026-01-01T00:00:00Z",
                        version = 1,
                        status = (string?)null
                    }
                }), Encoding.UTF8, "application/json")
            };
        }
    }

    private sealed class Tokens : IInfisicalTokenSource
    {
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
}
