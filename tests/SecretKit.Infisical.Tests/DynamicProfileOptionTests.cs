using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class DynamicProfileOptionTests
{
    [Test]
    [Arguments("clickhouse", "omitted")]
    [Arguments("clickhouse", "selected")]
    [Arguments("clickhouse", "cleared")]
    [Arguments("vertica", "omitted")]
    [Arguments("vertica", "selected")]
    [Arguments("vertica", "cleared")]
    [Arguments("azure", "omitted")]
    [Arguments("azure", "selected")]
    [Arguments("azure", "cleared")]
    [Arguments("milvus", "omitted")]
    [Arguments("milvus", "selected")]
    [Arguments("milvus", "cleared")]
    [Arguments("ibm", "omitted")]
    [Arguments("ibm", "selected")]
    [Arguments("ibm", "cleared")]
    public async Task GatewayAndPasswordFieldsPreserveOmissionSelectionAndClearing(string kind, string mode)
    {
        using var gateway = new NativeGatewayOptions(mode == "selected" ? "gateway" : null,
            mode == "selected" ? "pool" : null, mode == "cleared", mode == "cleared");
        using var password = mode == "selected" ? new NativePasswordRequirements(24, 4, 4, 4, 4, "") : null;
        using InfisicalDynamicProfile profile = kind switch
        {
            "clickhouse" => new NativeClickhouseDefinitionProfile("db.test", 8123, "user", "password",
                "db", "", "", gateway: gateway, passwordRequirements: password),
            "vertica" => new NativeVerticaDefinitionProfile("db.test", 5433, "user", "password",
                "db", "", "", gateway, password),
            "azure" => new NativeAzureSqlDefinitionProfile("db.test", 1433, "user", "password",
                "db", "", "", "", gateway: gateway, passwordRequirements: password,
                sslEnabled: mode == "selected" ? false : null),
            "milvus" => new NativeMilvusDefinitionProfile("db.test", 19530, "user", "password", gateway: gateway),
            _ => new NativeIbmApiDefinitionProfile("key", "app", "client", "secret",
                "org", "catalog", "consumer", "https://ibm.test", gateway)
        };
        gateway.Dispose(); password?.Dispose();
        JsonElement inputs = await Create(profile);
        foreach (string field in new[] { "gatewayId", "gatewayPoolId" })
        {
            if (mode == "omitted") await Assert.That(inputs.TryGetProperty(field, out _)).IsFalse();
            else if (mode == "cleared") await Assert.That(inputs.GetProperty(field).ValueKind).IsEqualTo(JsonValueKind.Null);
            else await Assert.That(inputs.GetProperty(field).GetString()).IsEqualTo(field == "gatewayId" ? "gateway" : "pool");
        }
        if (kind is "clickhouse" or "vertica" or "azure")
        {
            if (mode == "selected")
            {
                JsonElement requirements = inputs.GetProperty("passwordRequirements");
                await Assert.That(requirements.GetProperty("length").GetInt32()).IsEqualTo(24);
                foreach (string field in new[] { "lowercase", "uppercase", "digits", "symbols" })
                    await Assert.That(requirements.GetProperty("required").GetProperty(field).GetInt32()).IsEqualTo(4);
                await Assert.That(requirements.GetProperty("allowedSymbols").GetString()).IsEqualTo("");
            }
            else await Assert.That(inputs.TryGetProperty("passwordRequirements", out _)).IsFalse();
        }
        if (kind == "azure")
        {
            if (mode == "selected") await Assert.That(inputs.GetProperty("sslEnabled").GetBoolean()).IsFalse();
            else await Assert.That(inputs.TryGetProperty("sslEnabled", out _)).IsFalse();
        }
        await Assert.That(inputs.TryGetProperty("sslRejectUnauthorized", out _)).IsFalse();
    }

    [Test]
    [Arguments("access-key")]
    [Arguments("assume-role")]
    [Arguments("irsa")]
    public async Task AwsPoliciesGroupsAndTagsUseExactStringAndArrayContracts(string method)
    {
        string secret = DynamicWireFixture.Material();
        using var tag = new NativeAwsTag(secret, "");
        using var absentTag = new NativeAwsTag("absent");
        NativeAwsTag[] tags = [tag, absentTag];
        using var options = new NativeAwsIamOptions("", secret, secret, secret, "",
            tags, method == "assume-role" ? secret : null, method == "assume-role" ? "" : null);
        using NativeAwsIamDefinitionProfile profile = method switch
        {
            "access-key" => new(secret, secret, "region", options: options),
            "assume-role" => NativeAwsIamDefinitionProfile.ForAssumeRole("role", "region", options: options),
            _ => NativeAwsIamDefinitionProfile.ForIrsa("region", options: options)
        };
        tag.Dispose(); absentTag.Dispose(); options.Dispose(); tags[0] = absentTag;
        await Assert.That(JsonSerializer.Serialize(options)).IsEqualTo("{}");
        JsonElement inputs = await Create(profile);
        foreach (string field in new[] { "permissionBoundaryPolicyArn", "policyArns", "policyDocument" })
            await Assert.That(inputs.GetProperty(field).GetString() == secret).IsTrue();
        await Assert.That(inputs.GetProperty("awsPath").GetString()).IsEqualTo("");
        await Assert.That(inputs.GetProperty("userGroups").GetString()).IsEqualTo("");
        await Assert.That(inputs.GetProperty("tags")[0].GetProperty("key").GetString() == secret).IsTrue();
        await Assert.That(inputs.GetProperty("tags")[0].GetProperty("value").GetString()).IsEqualTo("");
        await Assert.That(inputs.GetProperty("tags")[1].TryGetProperty("value", out _)).IsFalse();
        if (method == "assume-role")
        {
            await Assert.That(inputs.GetProperty("sessionPolicyArns").GetString() == secret).IsTrue();
            await Assert.That(inputs.GetProperty("sessionPolicyDocument").GetString()).IsEqualTo("");
        }
        else
        {
            await Assert.That(inputs.TryGetProperty("sessionPolicyArns", out _)).IsFalse();
            await Assert.That(inputs.TryGetProperty("sessionPolicyDocument", out _)).IsFalse();
        }
    }

    [Test]
    [Arguments("elastic-ca")]
    [Arguments("mongo-null")]
    [Arguments("kube-dynamic")]
    [Arguments("kube-static")]
    [Arguments("milvus-privileges")]
    [Arguments("couch-text")]
    [Arguments("couch-structured")]
    [Arguments("couch-empty")]
    [Arguments("ssh-rsa2048")]
    [Arguments("ssh-rsa4096")]
    [Arguments("ssh-p256")]
    [Arguments("ssh-p384")]
    [Arguments("ssh-ed25519")]
    [Arguments("tailscale-auth")]
    [Arguments("tailscale-federated-api")]
    [Arguments("tailscale-federated-oauth")]
    [Arguments("tailscale-oauth-api")]
    [Arguments("tailscale-oauth-oauth")]
    [Arguments("oauth-extra")]
    public async Task TypedOptionalAlternativesAreCopiedAndWrittenAtPublicRequestSeam(string kind)
    {
        string secret = DynamicWireFixture.Material();
        using var gateway = new NativeGatewayOptions(clearGatewayId: true, clearGatewayPoolId: true);
        using var privilege = new NativeMilvusPrivilege(secret, secret, secret, secret);
        using var minimalPrivilege = new NativeMilvusPrivilege("Global", "All");
        using var scope = new NativeCouchbaseScope(secret, [secret]);
        using var bucket = new NativeCouchbaseBucket(secret, [scope]);
        using var minimalBucket = new NativeCouchbaseBucket("minimal");
        using var buckets = kind == "couch-text" ? NativeCouchbaseBuckets.FromText(secret) :
            NativeCouchbaseBuckets.FromBuckets(kind == "couch-empty" ? [] : [bucket, minimalBucket]);
        using var tailscale = new NativeTailscaleOptions(secret, [], "",
            kind.StartsWith("tailscale-federated", StringComparison.Ordinal) ? "" : null,
            kind == "tailscale-auth" ? false : null, kind == "tailscale-auth" ? false : null);
        using var parameter = new NativeOauthExtraParameter(secret, secret);
        using var password = new NativePasswordRequirements(16, 2, 2, 2, 2, "");
        var algorithms = new Dictionary<string, (NativeSshKeyAlgorithm Algorithm, string Wire)>
        {
            ["ssh-rsa2048"] = (NativeSshKeyAlgorithm.Rsa2048, "RSA_2048"),
            ["ssh-rsa4096"] = (NativeSshKeyAlgorithm.Rsa4096, "RSA_4096"),
            ["ssh-p256"] = (NativeSshKeyAlgorithm.EcPrime256v1, "EC_prime256v1"),
            ["ssh-p384"] = (NativeSshKeyAlgorithm.EcSecp384r1, "EC_secp384r1"),
            ["ssh-ed25519"] = (NativeSshKeyAlgorithm.Ed25519, "ED25519")
        };
        using InfisicalDynamicProfile profile = kind switch
        {
            "elastic-ca" => NativeElasticsearchDefinitionProfile.ForApiKey("db.test", 9200, secret, secret, ["role"], secret),
            "mongo-null" => new NativeMongoDefinitionProfile("db.test", secret, secret, "db", ["role"], clearPort: true, clearCa: true),
            "kube-dynamic" => new NativeKubernetesDefinitionProfile("namespace", "role", false, [],
                authentication: NativeKubernetesAuthentication.Gateway, gateway: gateway, sslEnabled: false),
            "kube-static" => NativeKubernetesDefinitionProfile.ForStaticAccount("namespace", "account", [],
                authentication: NativeKubernetesAuthentication.Gateway, gateway: gateway, sslEnabled: false),
            "milvus-privileges" => new NativeMilvusDefinitionProfile("db.test", 19530, secret, secret,
                privileges: [privilege, minimalPrivilege]),
            "couch-text" or "couch-structured" or "couch-empty" => new NativeCouchbaseDefinitionProfile(
                "https://couchbase.test", secret, "org", "project", "cluster", ["role"], buckets,
                password),
            "tailscale-auth" => NativeTailscaleDefinitionProfile.ForOAuthAuthority("client", secret, tailscale),
            "tailscale-federated-api" => NativeTailscaleDefinitionProfile.ForFederatedApiKey(secret, "issuer", "subject", ["scope"], tailscale),
            "tailscale-federated-oauth" => NativeTailscaleDefinitionProfile.ForFederatedOAuth("client", secret, "issuer", "subject", ["scope"], tailscale),
            "tailscale-oauth-api" => NativeTailscaleDefinitionProfile.ForOAuthKeyApiKey(secret, ["scope"], tailscale),
            "tailscale-oauth-oauth" => NativeTailscaleDefinitionProfile.ForOAuthKeyOAuth("client", secret, ["scope"], tailscale),
            "oauth-extra" => new NativeOauthDefinitionProfile("client", secret, NativeOauthClientAuthentication.Post,
                "https://oauth.test/token", "https://oauth.test/revoke", extraParameters: [parameter]),
            _ => new NativeSshDefinitionProfile(["principal"], algorithms[kind].Algorithm, algorithms[kind].Algorithm)
        };
        gateway.Dispose(); privilege.Dispose(); minimalPrivilege.Dispose(); scope.Dispose(); bucket.Dispose();
        minimalBucket.Dispose(); buckets.Dispose(); tailscale.Dispose(); parameter.Dispose(); password.Dispose();
        await Assert.That(JsonSerializer.Serialize(profile).Contains(secret, StringComparison.Ordinal)).IsFalse();
        JsonElement inputs = await Create(profile);
        switch (kind)
        {
            case "elastic-ca":
                await Assert.That(inputs.GetProperty("ca").GetString() == secret).IsTrue();
                break;
            case "mongo-null":
                await Assert.That(inputs.GetProperty("port").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(inputs.GetProperty("ca").ValueKind).IsEqualTo(JsonValueKind.Null);
                break;
            case "kube-dynamic":
            case "kube-static":
                await Assert.That(inputs.GetProperty("authMethod").GetString()).IsEqualTo("gateway");
                await Assert.That(inputs.GetProperty("sslEnabled").GetBoolean()).IsFalse();
                await Assert.That(inputs.GetProperty("gatewayId").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(inputs.GetProperty("gatewayPoolId").ValueKind).IsEqualTo(JsonValueKind.Null);
                await Assert.That(inputs.TryGetProperty("url", out _)).IsFalse();
                await Assert.That(inputs.TryGetProperty("clusterToken", out _)).IsFalse();
                await Assert.That(inputs.GetProperty("sslRejectUnauthorized").GetBoolean()).IsTrue();
                break;
            case "milvus-privileges":
                foreach (string field in new[] { "objectType", "objectName", "privilege", "dbName" })
                    await Assert.That(inputs.GetProperty("privileges")[0].GetProperty(field).GetString() == secret).IsTrue();
                await Assert.That(inputs.GetProperty("privileges")[1].TryGetProperty("objectName", out _)).IsFalse();
                await Assert.That(inputs.GetProperty("privileges")[1].TryGetProperty("dbName", out _)).IsFalse();
                break;
            case "couch-text":
                await Assert.That(inputs.GetProperty("buckets").GetString() == secret).IsTrue();
                await Assert.That(inputs.GetProperty("passwordRequirements").GetProperty("length").GetInt32()).IsEqualTo(16);
                break;
            case "couch-structured":
                JsonElement first = inputs.GetProperty("buckets")[0];
                await Assert.That(first.GetProperty("name").GetString() == secret).IsTrue();
                await Assert.That(first.GetProperty("scopes")[0].GetProperty("name").GetString() == secret).IsTrue();
                await Assert.That(first.GetProperty("scopes")[0].GetProperty("collections")[0].GetString() == secret).IsTrue();
                await Assert.That(inputs.GetProperty("buckets")[1].TryGetProperty("scopes", out _)).IsFalse();
                break;
            case "couch-empty":
                await Assert.That(inputs.GetProperty("buckets").GetArrayLength()).IsEqualTo(0);
                break;
            case "oauth-extra":
                await Assert.That(inputs.GetProperty("extraParams")[0].GetProperty("key").GetString() == secret).IsTrue();
                await Assert.That(inputs.GetProperty("extraParams")[0].GetProperty("value").GetString() == secret).IsTrue();
                break;
            default:
                if (algorithms.TryGetValue(kind, out var algorithm))
                {
                    await Assert.That(inputs.GetProperty("keyAlgorithm").GetString()).IsEqualTo(algorithm.Wire);
                    await Assert.That(inputs.GetProperty("caKeyAlgorithm").GetString()).IsEqualTo(algorithm.Wire);
                }
                else
                {
                    await Assert.That(inputs.GetProperty("tailnet").GetString() == secret).IsTrue();
                    await Assert.That(inputs.GetProperty("tags").GetArrayLength()).IsEqualTo(0);
                    await Assert.That(inputs.GetProperty("description").GetString()).IsEqualTo("");
                    if (kind == "tailscale-auth")
                    {
                        await Assert.That(inputs.GetProperty("reusable").GetBoolean()).IsFalse();
                        await Assert.That(inputs.GetProperty("preauthorized").GetBoolean()).IsFalse();
                    }
                    else
                    {
                        await Assert.That(inputs.TryGetProperty("reusable", out _)).IsFalse();
                        await Assert.That(inputs.TryGetProperty("preauthorized", out _)).IsFalse();
                    }
                    if (kind.StartsWith("tailscale-federated", StringComparison.Ordinal))
                        await Assert.That(inputs.GetProperty("audience").GetString()).IsEqualTo("");
                    else await Assert.That(inputs.TryGetProperty("audience", out _)).IsFalse();
                }
                break;
        }
    }

    [Test]
    [Arguments("gateway-id")]
    [Arguments("gateway-pool")]
    [Arguments("mongo-port")]
    [Arguments("mongo-ca")]
    [Arguments("aws-key-session")]
    [Arguments("aws-irsa-session")]
    [Arguments("tailscale-auth-audience")]
    [Arguments("tailscale-oauth-audience")]
    [Arguments("tailscale-oauth-flags")]
    [Arguments("tailscale-federated-flags")]
    [Arguments("ssh-key")]
    [Arguments("ssh-ca")]
    [Arguments("kube-auth")]
    [Arguments("couch-length-low")]
    [Arguments("couch-length-high")]
    [Arguments("couch-count")]
    [Arguments("oauth-count")]
    [Arguments("oauth-key")]
    [Arguments("oauth-value")]
    [Arguments("oauth-key-length")]
    [Arguments("oauth-value-length")]
    [Arguments("tag-key")]
    [Arguments("tag-value-length")]
    [Arguments("milvus-object")]
    [Arguments("milvus-database")]
    [Arguments("bucket-count")]
    [Arguments("collection-empty")]
    [Arguments("tailnet-empty")]
    [Arguments("description-length")]
    public async Task UnsupportedVariantsAndInvalidBoundsFailWithoutDispatch(string kind)
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        var receipt = new InfisicalDynamicMutationReceipt(client.Definition("invalid"), InfisicalDynamicOperation.CreateDefinition);
        using var session = new NativeAwsIamOptions(sessionPolicyDocument: "");
        using var audience = new NativeTailscaleOptions(audience: "");
        using var flags = new NativeTailscaleOptions(reusable: false);
        using var parameter = new NativeOauthExtraParameter("key", "value");
        using var bucket = new NativeCouchbaseBucket("bucket");
        using var password = kind == "couch-length-low" ? new NativePasswordRequirements(7, 1, 1, 1, 1) :
            kind == "couch-length-high" ? new NativePasswordRequirements(129, 1, 1, 1, 1) :
            new NativePasswordRequirements(16, 0, 1, 1, 1);
        Action construct = kind switch
        {
            "gateway-id" => () => _ = new NativeGatewayOptions(gatewayId: "", clearGatewayId: true),
            "gateway-pool" => () => _ = new NativeGatewayOptions(gatewayPoolId: "", clearGatewayPoolId: true),
            "mongo-port" => () => _ = new NativeMongoDefinitionProfile("db", "u", "p", "db", ["role"], port: 1, clearPort: true),
            "mongo-ca" => () => _ = new NativeMongoDefinitionProfile("db", "u", "p", "db", ["role"], ca: "", clearCa: true),
            "aws-key-session" => () => _ = new NativeAwsIamDefinitionProfile("key", "secret", "region", options: session),
            "aws-irsa-session" => () => _ = NativeAwsIamDefinitionProfile.ForIrsa("region", options: session),
            "tailscale-auth-audience" => () => _ = NativeTailscaleDefinitionProfile.ForOAuthAuthority("client", "secret", audience),
            "tailscale-oauth-audience" => () => _ = NativeTailscaleDefinitionProfile.ForOAuthKeyApiKey("key", ["scope"], audience),
            "tailscale-oauth-flags" => () => _ = NativeTailscaleDefinitionProfile.ForOAuthKeyOAuth("client", "secret", ["scope"], flags),
            "tailscale-federated-flags" => () => _ = NativeTailscaleDefinitionProfile.ForFederatedApiKey("key", "issuer", "subject", ["scope"], flags),
            "ssh-key" => () => _ = new NativeSshDefinitionProfile(["principal"], (NativeSshKeyAlgorithm)99),
            "ssh-ca" => () => _ = new NativeSshDefinitionProfile(["principal"], caKeyAlgorithm: (NativeSshKeyAlgorithm)99),
            "kube-auth" => () => _ = new NativeKubernetesDefinitionProfile("ns", "role", true, [],
                authentication: (NativeKubernetesAuthentication)99),
            "couch-length-low" or "couch-length-high" or "couch-count" => () => _ = new NativeCouchbaseDefinitionProfile(
                "https://couch.test", "key", "org", "project", "cluster", ["role"], passwordRequirements: password),
            "oauth-count" => () => _ = new NativeOauthDefinitionProfile("client", "secret", NativeOauthClientAuthentication.Basic,
                "https://oauth.test", "https://oauth.test", extraParameters: Enumerable.Repeat(parameter, 21).ToArray()),
            "oauth-key" => () => _ = new NativeOauthExtraParameter("", "value"),
            "oauth-value" => () => _ = new NativeOauthExtraParameter("key", ""),
            "oauth-key-length" => () => _ = new NativeOauthExtraParameter(new string('x', 129), "value"),
            "oauth-value-length" => () => _ = new NativeOauthExtraParameter("key", new string('x', 2049)),
            "tag-key" => () => _ = new NativeAwsTag(""),
            "tag-value-length" => () => _ = new NativeAwsTag("key", new string('x', 1021)),
            "milvus-object" => () => _ = new NativeMilvusPrivilege("", "privilege"),
            "milvus-database" => () => _ = new NativeMilvusPrivilege("object", "privilege", dbName: ""),
            "bucket-count" => () => _ = NativeCouchbaseBuckets.FromBuckets(Enumerable.Repeat(bucket, 129).ToArray()),
            "collection-empty" => () => _ = new NativeCouchbaseScope("scope", [""]),
            "tailnet-empty" => () => _ = new NativeTailscaleOptions(tailnet: ""),
            _ => () => _ = new NativeTailscaleOptions(description: new string('x', 51))
        };
        await Assert.That(construct).Throws<ArgumentException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.DefinitionCount).IsEqualTo(0);
    }

    [Test]
    public async Task DisposedOptionsRejectNewOwnersButIndependentProfilesRemainUsable()
    {
        string secret = DynamicWireFixture.Material();
        using var tag = new NativeAwsTag(secret, secret);
        using var options = new NativeAwsIamOptions(tags: [tag]);
        using var first = new NativeAwsIamDefinitionProfile("key", "secret", "region", options: options);
        using var second = new NativeAwsIamDefinitionProfile("key", "secret", "region", options: options);
        tag.Dispose(); options.Dispose(); first.Dispose();
        JsonElement inputs = await Create(second);
        await Assert.That(inputs.GetProperty("tags")[0].GetProperty("key").GetString() == secret).IsTrue();
        await Assert.That(() => new NativeAwsIamOptions(tags: [tag])).Throws<ObjectDisposedException>();
        await Assert.That(() => new NativeAwsIamDefinitionProfile("key", "secret", "region", options: options))
            .Throws<ObjectDisposedException>();
        using var policy = new NativePasswordRequirements(16, 1, 1, 1, 1, secret);
        using var sql = new NativeSqlDefinitionProfile(NativeSqlEngine.Postgres, "db.test", 5432, "user", "password",
            "db", "", "", passwordRequirements: policy);
        policy.Dispose();
        await Assert.That((await Create(sql)).GetProperty("passwordRequirements").GetProperty("allowedSymbols").GetString() == secret).IsTrue();
        await Assert.That(() => policy.AllowedSymbols).Throws<ObjectDisposedException>();
        await Assert.That(() => new NativeClickhouseDefinitionProfile("db", 8123, "u", "p", "db", "", "",
            passwordRequirements: policy)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task EmptyOptionalArraysAndNestedOmissionRemainDistinctFromAbsentFields()
    {
        using var tag = new NativeAwsTag(new string('x', 255), new string('v', 1020));
        using var emptyAws = new NativeAwsIamOptions(tags: []);
        using var maxAws = new NativeAwsIamOptions(tags: [tag]);
        using var aws = NativeAwsIamDefinitionProfile.ForIrsa("region", options: emptyAws);
        await Assert.That((await Create(aws)).GetProperty("tags").GetArrayLength()).IsEqualTo(0);
        using var awsBound = new NativeAwsIamDefinitionProfile("key", "secret", "region", options: maxAws);
        await Assert.That((await Create(awsBound)).GetProperty("tags")[0].GetProperty("key").GetString()!.Length).IsEqualTo(255);
        using var oauth = new NativeOauthDefinitionProfile("client", "secret", NativeOauthClientAuthentication.Basic,
            "https://oauth.test", "https://oauth.test", extraParameters: []);
        await Assert.That((await Create(oauth)).GetProperty("extraParams").GetArrayLength()).IsEqualTo(0);
        using var milvus = new NativeMilvusDefinitionProfile("db", 19530, "u", "p", privileges: []);
        await Assert.That((await Create(milvus)).GetProperty("privileges").GetArrayLength()).IsEqualTo(0);
        using var emptyScope = new NativeCouchbaseScope("empty", []);
        using var absentScope = new NativeCouchbaseScope("absent");
        using var scopedBucket = new NativeCouchbaseBucket("scoped", [emptyScope, absentScope]);
        using var emptyBucket = new NativeCouchbaseBucket("empty", []);
        using var buckets = NativeCouchbaseBuckets.FromBuckets([scopedBucket, emptyBucket]);
        using var couch = new NativeCouchbaseDefinitionProfile("https://couch.test", "key", "org", "project", "cluster", ["role"], buckets);
        JsonElement inputs = await Create(couch);
        await Assert.That(inputs.GetProperty("buckets")[0].GetProperty("scopes")[0].GetProperty("collections").GetArrayLength()).IsEqualTo(0);
        await Assert.That(inputs.GetProperty("buckets")[0].GetProperty("scopes")[1].TryGetProperty("collections", out _)).IsFalse();
        await Assert.That(inputs.GetProperty("buckets")[1].GetProperty("scopes").GetArrayLength()).IsEqualTo(0);
    }

    [Test]
    public async Task TypedOptionsUseSameDefinitionUpdateSeamAndDisposedProfilesDoNotDispatch()
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        using var first = new NativeMongoDefinitionProfile("db", "u", "p", "db", ["role"], port: 27017, ca: "ca");
        var target = client.Definition("mongo-options");
        var create = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        var definition = (await client.CreateDefinitionAsync(target, first, new(TimeSpan.FromMinutes(1)), null, create)).Value;
        using var cleared = new NativeMongoDefinitionProfile("db", "u", "p", "db", ["role"], clearPort: true, clearCa: true);
        var update = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.UpdateDefinition);
        await Assert.That((await client.UpdateDefinitionAsync(definition, new(inputs: cleared), update)).IsSuccess).IsTrue();
        await Assert.That(update.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.Inputs(target.Name).GetProperty("ca").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(wire.Inputs(target.Name).GetProperty("port").ValueKind).IsEqualTo(JsonValueKind.Null);
        cleared.Dispose();
        var disposed = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.UpdateDefinition);
        await Assert.That(async () => await client.UpdateDefinitionAsync(definition, new(inputs: cleared), disposed))
            .Throws<ObjectDisposedException>();
        await Assert.That(disposed.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
    }

    private static async Task<JsonElement> Create(InfisicalDynamicProfile profile)
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        InfisicalDynamicTarget target = client.Definition("profile-options");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That((await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromMinutes(1)), null, receipt)).IsSuccess).IsTrue();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
        return wire.Inputs(target.Name).Clone();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task KubernetesPublicOptionalUrlAndTokenCanBeOmitted(bool staticAccount)
    {
        using var wire = new DynamicWireFixture();
        await using InfisicalDynamicClient client = wire.Client();
        using NativeKubernetesDefinitionProfile profile = staticAccount
            ? NativeKubernetesDefinitionProfile.ForStaticAccount("namespace", "account", [], null!, null!)
            : new("namespace", "role", true, [], null!, null!);
        InfisicalDynamicTarget target = client.Definition("optional-cluster");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That((await client.CreateDefinitionAsync(target, profile,
            new(TimeSpan.FromMinutes(1)), null, receipt)).IsSuccess).IsTrue();
        JsonElement inputs = wire.Inputs(target.Name);
        await Assert.That(inputs.TryGetProperty("url", out _)).IsFalse();
        await Assert.That(inputs.TryGetProperty("clusterToken", out _)).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.LeaseCount).IsEqualTo(0);
    }
}
