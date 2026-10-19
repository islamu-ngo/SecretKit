using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicProfileInputTests
{
    [Test]
    [Arguments(true, NativeAwsCredentialKind.IamUser)]
    [Arguments(true, NativeAwsCredentialKind.Temporary)]
    [Arguments(false, NativeAwsCredentialKind.IamUser)]
    [Arguments(false, NativeAwsCredentialKind.Temporary)]
    public async Task AwsRoleInputsUsePublicAlternativeConstructorsWithoutAccessKeys(
        bool assumeRole, NativeAwsCredentialKind kind)
    {
        var sample = Sample(InfisicalDynamicProvider.AwsIam, false);
        using var sampled = sample.Profile;
        var json = JsonSerializer.SerializeToNode(sample.Input, InfisicalLifecycleFamilies.Options)!;
        json["awsIam"]!["accessKey"] = null;
        json["awsIam"]!["secretAccessKey"] = null;
        json["awsIam"]!["authentication"] = assumeRole ? "AssumeRole" : "Irsa";
        json["awsIam"]!["roleArn"] = assumeRole ? "role-canary" : null;
        json["awsIam"]!["credentialKind"] = kind.ToString();
        var input = JsonSerializer.Deserialize<InfisicalDynamicProfileInput>(json.ToJsonString(),
            InfisicalLifecycleFamilies.Options)!;
        using var actual = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.AwsIam, input);
        using var expected = assumeRole ?
            NativeAwsIamDefinitionProfile.ForAssumeRole("role-canary", "region-canary", kind) :
            NativeAwsIamDefinitionProfile.ForIrsa("region-canary", kind);
        await Assert.That(JsonElement.DeepEquals(await Capture(actual), await Capture(expected))).IsTrue();
    }

    [Test]
    public async Task AwsAuthenticationRejectsMissingAndConflictingInputs()
    {
        DynamicAwsIamInput[] invalid =
        [
            new(null, null, "region"),
            new("access", "secret", "region", Authentication: DynamicAwsAuthentication.AssumeRole, RoleArn: "role"),
            new(null, null, "region", Authentication: DynamicAwsAuthentication.AssumeRole),
            new(null, null, "region", Authentication: DynamicAwsAuthentication.Irsa, RoleArn: "role"),
            new(null, null, "region", Authentication: (DynamicAwsAuthentication)999)
        ];
        foreach (var input in invalid)
            await Assert.That(() => InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.AwsIam,
                new(AwsIam: input))).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Clickhouse, false)]
    [Arguments(InfisicalDynamicProvider.Clickhouse, true)]
    [Arguments(InfisicalDynamicProvider.Cassandra, false)]
    [Arguments(InfisicalDynamicProvider.Cassandra, true)]
    [Arguments(InfisicalDynamicProvider.SapAse, false)]
    [Arguments(InfisicalDynamicProvider.SapAse, true)]
    [Arguments(InfisicalDynamicProvider.SapHana, false)]
    [Arguments(InfisicalDynamicProvider.SapHana, true)]
    [Arguments(InfisicalDynamicProvider.Redis, false)]
    [Arguments(InfisicalDynamicProvider.Redis, true)]
    [Arguments(InfisicalDynamicProvider.Vertica, false)]
    [Arguments(InfisicalDynamicProvider.Vertica, true)]
    [Arguments(InfisicalDynamicProvider.AzureSqlDatabase, false)]
    [Arguments(InfisicalDynamicProvider.AzureSqlDatabase, true)]
    [Arguments(InfisicalDynamicProvider.Snowflake, false)]
    [Arguments(InfisicalDynamicProvider.Snowflake, true)]
    [Arguments(InfisicalDynamicProvider.AwsIam, false)]
    [Arguments(InfisicalDynamicProvider.AwsIam, true)]
    [Arguments(InfisicalDynamicProvider.AwsElasticache, false)]
    [Arguments(InfisicalDynamicProvider.AwsElasticache, true)]
    [Arguments(InfisicalDynamicProvider.AwsMemorydb, false)]
    [Arguments(InfisicalDynamicProvider.AwsMemorydb, true)]
    [Arguments(InfisicalDynamicProvider.AzureEntraId, false)]
    [Arguments(InfisicalDynamicProvider.AzureEntraId, true)]
    [Arguments(InfisicalDynamicProvider.GcpIam, false)]
    [Arguments(InfisicalDynamicProvider.GcpIam, true)]
    [Arguments(InfisicalDynamicProvider.Github, false)]
    [Arguments(InfisicalDynamicProvider.Github, true)]
    [Arguments(InfisicalDynamicProvider.Milvus, false)]
    [Arguments(InfisicalDynamicProvider.Milvus, true)]
    [Arguments(InfisicalDynamicProvider.MongoDb, false)]
    [Arguments(InfisicalDynamicProvider.MongoDb, true)]
    [Arguments(InfisicalDynamicProvider.ElasticSearch, false)]
    [Arguments(InfisicalDynamicProvider.ElasticSearch, true)]
    [Arguments(InfisicalDynamicProvider.RabbitMq, false)]
    [Arguments(InfisicalDynamicProvider.RabbitMq, true)]
    [Arguments(InfisicalDynamicProvider.Kubernetes, false)]
    [Arguments(InfisicalDynamicProvider.Kubernetes, true)]
    [Arguments(InfisicalDynamicProvider.Ldap, false)]
    [Arguments(InfisicalDynamicProvider.Ldap, true)]
    [Arguments(InfisicalDynamicProvider.Totp, false)]
    [Arguments(InfisicalDynamicProvider.Totp, true)]
    [Arguments(InfisicalDynamicProvider.Ssh, false)]
    [Arguments(InfisicalDynamicProvider.Ssh, true)]
    [Arguments(InfisicalDynamicProvider.IbmApiConnect, false)]
    [Arguments(InfisicalDynamicProvider.IbmApiConnect, true)]
    [Arguments(InfisicalDynamicProvider.Oauth2, false)]
    [Arguments(InfisicalDynamicProvider.Oauth2, true)]
    [Arguments(InfisicalDynamicProvider.Tailscale, false)]
    [Arguments(InfisicalDynamicProvider.Tailscale, true)]
    [Arguments(InfisicalDynamicProvider.Couchbase, false)]
    [Arguments(InfisicalDynamicProvider.Couchbase, true)]
    [Arguments(InfisicalDynamicProvider.MongoDbAtlas, false)]
    [Arguments(InfisicalDynamicProvider.MongoDbAtlas, true)]
    public async Task EveryTypedConstructorPreservesActualDefinitionWire(InfisicalDynamicProvider provider, bool selected)
    {
        var sample = Sample(provider, selected);
        using var expected = sample.Profile;
        string json = JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options);
        var input = JsonSerializer.Deserialize<InfisicalDynamicProfileInput>(json, InfisicalLifecycleFamilies.Options)!;
        using var actual = InfisicalDynamicProfileInputs.Create(provider, input);
        await Assert.That(actual.Provider).IsEqualTo(provider);
        JsonElement actualWire = await Capture(actual);
        JsonElement expectedWire = await Capture(expected);
        await Assert.That(JsonElement.DeepEquals(actualWire, expectedWire)).IsTrue();
        await Assert.That(input.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(actual.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
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
    public async Task MissingAndWrongTypedInputsFailClosed(InfisicalDynamicProvider provider)
    {
        var wrong = provider == InfisicalDynamicProvider.Ssh ?
            new InfisicalDynamicProfileInput(Totp: new("https://totp.test")) :
            new InfisicalDynamicProfileInput(Ssh: new(["principal-canary"]));
        await Assert.That(() => InfisicalDynamicProfileInputs.Create(provider, new())).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicProfileInputs.Create(provider, wrong)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicProfileInputs.Create(provider, null!)).Throws<ArgumentNullException>();
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
    public async Task StrictPrivateInputRequiresConstructorFieldsAndRejectsUnknownFields(InfisicalDynamicProvider provider)
    {
        var sample = Sample(provider, false);
        using var expected = sample.Profile;
        var root = JsonNode.Parse(JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options))!;
        string selection = JsonNamingPolicy.CamelCase.ConvertName(provider.ToString());
        var profile = root[selection]!.AsObject();
        profile.Remove(sample.RequiredField);
        await Assert.That(() => JsonSerializer.Deserialize<InfisicalDynamicProfileInput>(root.ToJsonString(),
            InfisicalLifecycleFamilies.Options)).Throws<JsonException>();
        root = JsonNode.Parse(JsonSerializer.Serialize(sample.Input, InfisicalLifecycleFamilies.Options))!;
        root[selection]!["arbitraryField"] = "canary";
        await Assert.That(() => JsonSerializer.Deserialize<InfisicalDynamicProfileInput>(root.ToJsonString(),
            InfisicalLifecycleFamilies.Options)).Throws<JsonException>();
    }

    [Test]
    public async Task FactoryCopiesNestedProtectedInputsBeforeReturningIndependentOwners()
    {
        var privilege = new DynamicMilvusPrivilegeInput("object-canary", "privilege-canary", "name-canary", "db-canary");
        DynamicMilvusPrivilegeInput[] privileges = [privilege];
        var input = new InfisicalDynamicProfileInput(Milvus: new("host-canary", 1234, "user-canary", "password-canary",
            Gateway: new(ClearGatewayId: true, ClearGatewayPoolId: true), Privileges: privileges));
        using var first = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Milvus, input);
        using var second = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Milvus, input);
        privileges[0] = new("changed", "changed");
        first.Dispose();
        JsonElement wire = await Capture(second);
        var inputs = wire.GetProperty("inputs");
        await Assert.That(inputs.GetProperty("privileges")[0].GetProperty("objectName").GetString() == "name-canary").IsTrue();
        await Assert.That(inputs.GetProperty("gatewayId").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(inputs.GetProperty("gatewayPoolId").ValueKind).IsEqualTo(JsonValueKind.Null);
        await Assert.That(privilege.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        await Assert.That(input.Milvus!.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
        second.Dispose();
        using var handler = new CaptureTransport();
        await using var client = Client(handler);
        var target = client.Definition("offline");
        var receipt = new InfisicalDynamicMutationReceipt(target, InfisicalDynamicOperation.CreateDefinition);
        await Assert.That(async () => await client.CreateDefinitionAsync(target, second, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), receipt)).Throws<ObjectDisposedException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(handler.Provider).IsNull();
    }

    [Test]
    public async Task MultipleSelectionsSqlAndUndefinedProvidersAreRejected()
    {
        var input = new InfisicalDynamicProfileInput(Ssh: new(["principal"]), Totp: new("https://totp.test"));
        await Assert.That(() => InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Ssh, input)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.SqlDatabase, input)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicProfileInputs.Create((InfisicalDynamicProvider)999, input)).Throws<ArgumentException>();
    }

    internal static (InfisicalDynamicProfileInput Input, InfisicalDynamicProfile Profile, string RequiredField)
        Sample(InfisicalDynamicProvider provider, bool selected)
    {
        using var gateway = new NativeGatewayOptions("gateway-canary", "pool-canary");
        using var password = new NativePasswordRequirements(24, 2, 3, 4, 5, "symbols-canary");
        using var tag = new NativeAwsTag("key-canary", "value-canary");
        using var absentTag = new NativeAwsTag("absent-canary");
        using var aws = new NativeAwsIamOptions("path-canary", "boundary-canary", "policies-canary", "document-canary",
            "groups-canary", [tag, absentTag]);
        using var privilege = new NativeMilvusPrivilege("object-canary", "privilege-canary", "name-canary", "database-canary");
        using var minimalPrivilege = new NativeMilvusPrivilege("minimal-object", "minimal-privilege");
        NativeMilvusPrivilege[] privileges = [privilege, minimalPrivilege];
        using var parameter = new NativeOauthExtraParameter("key-canary", "value-canary");
        NativeOauthExtraParameter[] parameters = [parameter];
        using var scope = new NativeCouchbaseScope("scope-canary", ["collection-canary"]);
        using var absentScope = new NativeCouchbaseScope("absent-scope");
        using var bucket = new NativeCouchbaseBucket("bucket-canary", [scope, absentScope]);
        using var emptyBucket = new NativeCouchbaseBucket("empty-bucket", []);
        using var buckets = NativeCouchbaseBuckets.FromBuckets([bucket, emptyBucket]);
        NativeAtlasRole[] roles = [new("database-canary", "role-canary", "collection-canary"), new("db-minimal", "role-minimal")];
        NativeAtlasScope[] scopes = [new("scope-canary", "type-canary")];
        return provider switch
        {
            InfisicalDynamicProvider.Clickhouse => (new(Clickhouse: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "database-canary",
                "creation-canary",
                "revocation-canary",
                selected ? "renewal-canary" : null,
                selected ? "ca-canary" : null,
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null,
                selected ? new DynamicPasswordInput(24, 2, 3, 4, 5, "symbols-canary") : null)),
                new NativeClickhouseDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "database-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? "renewal-canary" : null,
                    selected ? "ca-canary" : null,
                    selected ? gateway : null,
                    selected ? password : null), "host"),
            InfisicalDynamicProvider.Cassandra => (new(Cassandra: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "localDataCenter-canary",
                "creation-canary",
                "revocation-canary",
                selected ? "keyspace-canary" : null,
                selected ? "renewal-canary" : null,
                selected ? "ca-canary" : null)),
                new NativeCassandraDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "localDataCenter-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? "keyspace-canary" : null,
                    selected ? "renewal-canary" : null,
                    selected ? "ca-canary" : null), "host"),
            InfisicalDynamicProvider.SapAse => (new(SapAse: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "database-canary",
                "creation-canary",
                "revocation-canary")),
                new NativeSapAseDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "database-canary",
                    "creation-canary",
                    "revocation-canary"), "host"),
            InfisicalDynamicProvider.SapHana => (new(SapHana: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "creation-canary",
                "revocation-canary",
                selected ? "renewal-canary" : null,
                selected ? "ca-canary" : null)),
                new NativeSapHanaDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? "renewal-canary" : null,
                    selected ? "ca-canary" : null), "host"),
            InfisicalDynamicProvider.Redis => (new(Redis: new(
                "host-canary",
                1234,
                "username-canary",
                "creation-canary",
                "revocation-canary",
                selected ? "password-canary" : null,
                selected ? "renewal-canary" : null,
                selected ? "ca-canary" : null)),
                new NativeRedisDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? "password-canary" : null,
                    selected ? "renewal-canary" : null,
                    selected ? "ca-canary" : null), "host"),
            InfisicalDynamicProvider.Vertica => (new(Vertica: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "database-canary",
                "creation-canary",
                "revocation-canary",
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null,
                selected ? new DynamicPasswordInput(24, 2, 3, 4, 5, "symbols-canary") : null)),
                new NativeVerticaDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "database-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? gateway : null,
                    selected ? password : null), "host"),
            InfisicalDynamicProvider.AzureSqlDatabase => (new(AzureSqlDatabase: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "database-canary",
                "creation-canary",
                "masterCreation-canary",
                "revocation-canary",
                selected ? "masterDatabase-canary" : null,
                selected ? "renewal-canary" : null,
                selected ? "ca-canary" : null,
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null,
                selected ? new DynamicPasswordInput(24, 2, 3, 4, 5, "symbols-canary") : null,
                selected ? true : null)),
                new NativeAzureSqlDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "database-canary",
                    "creation-canary",
                    "masterCreation-canary",
                    "revocation-canary",
                    selected ? "masterDatabase-canary" : null,
                    selected ? "renewal-canary" : null,
                    selected ? "ca-canary" : null,
                    selected ? gateway : null,
                    selected ? password : null,
                    selected ? true : null), "host"),
            InfisicalDynamicProvider.Snowflake => (new(Snowflake: new(
                "accountId-canary",
                "organizationId-canary",
                "username-canary",
                "password-canary",
                "creation-canary",
                "revocation-canary",
                selected ? "renewal-canary" : null)),
                new NativeSnowflakeDefinitionProfile(
                    "accountId-canary",
                    "organizationId-canary",
                    "username-canary",
                    "password-canary",
                    "creation-canary",
                    "revocation-canary",
                    selected ? "renewal-canary" : null), "accountId"),
            InfisicalDynamicProvider.AwsIam => (new(AwsIam: new(
                "accessKey-canary",
                "secretAccessKey-canary",
                "region-canary",
                selected ? NativeAwsCredentialKind.Temporary : NativeAwsCredentialKind.IamUser,
                selected ? new DynamicAwsIamOptionsInput("path-canary", "boundary-canary", "policies-canary", "document-canary", "groups-canary", [new("key-canary", "value-canary"), new("absent-canary")]) : null)),
                new NativeAwsIamDefinitionProfile(
                    "accessKey-canary",
                    "secretAccessKey-canary",
                    "region-canary",
                    selected ? NativeAwsCredentialKind.Temporary : NativeAwsCredentialKind.IamUser,
                    selected ? aws : null), "accessKey"),
            InfisicalDynamicProvider.AwsElasticache => (new(AwsElasticache: new(
                "accessKeyId-canary",
                "secretAccessKey-canary",
                "region-canary",
                "clusterName-canary",
                "creation-canary",
                "revocation-canary")),
                new NativeAwsElasticacheDefinitionProfile(
                    "accessKeyId-canary",
                    "secretAccessKey-canary",
                    "region-canary",
                    "clusterName-canary",
                    "creation-canary",
                    "revocation-canary"), "accessKeyId"),
            InfisicalDynamicProvider.AwsMemorydb => (new(AwsMemorydb: new(
                "accessKeyId-canary",
                "secretAccessKey-canary",
                "region-canary",
                "clusterName-canary",
                "creation-canary",
                "revocation-canary")),
                new NativeAwsMemorydbDefinitionProfile(
                    "accessKeyId-canary",
                    "secretAccessKey-canary",
                    "region-canary",
                    "clusterName-canary",
                    "creation-canary",
                    "revocation-canary"), "accessKeyId"),
            InfisicalDynamicProvider.AzureEntraId => (new(AzureEntraId: new(
                "tenantId-canary",
                "applicationId-canary",
                "clientSecret-canary",
                "userId-canary",
                "email-canary")),
                new NativeAzureEntraDefinitionProfile(
                    "tenantId-canary",
                    "applicationId-canary",
                    "clientSecret-canary",
                    "userId-canary",
                    "email-canary"), "tenantId"),
            InfisicalDynamicProvider.GcpIam => (new(GcpIam: new(
                "account@offline.test",
                selected ? ["tokenScopes-one", "tokenScopes-two"] : null)),
                new NativeGcpIamDefinitionProfile(
                    "account@offline.test",
                    selected ? ["tokenScopes-one", "tokenScopes-two"] : null), "serviceAccountEmail"),
            InfisicalDynamicProvider.Github => (new(Github: new(
                123L,
                456L,
                "privateKey-canary")),
                new NativeGithubDefinitionProfile(
                    123L,
                    456L,
                    "privateKey-canary"), "applicationId"),
            InfisicalDynamicProvider.Milvus => (new(Milvus: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                selected ? "database-canary" : null,
                selected ? "ca-canary" : null,
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null,
                selected ? [new DynamicMilvusPrivilegeInput("object-canary", "privilege-canary", "name-canary", "database-canary"), new("minimal-object", "minimal-privilege")] : null)),
                new NativeMilvusDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    selected ? "database-canary" : null,
                    selected ? "ca-canary" : null,
                    selected ? gateway : null,
                    selected ? privileges : null), "host"),
            InfisicalDynamicProvider.MongoDb => (new(MongoDb: new(
                "host-canary",
                "username-canary",
                "password-canary",
                "database-canary",
                ["roles-one", "roles-two"],
                selected ? 1234 : null,
                selected ? "ca-canary" : null,
                false,
                false)),
                new NativeMongoDefinitionProfile(
                    "host-canary",
                    "username-canary",
                    "password-canary",
                    "database-canary",
                    ["roles-one", "roles-two"],
                    selected ? 1234 : null,
                    selected ? "ca-canary" : null,
                    false,
                    false), "host"),
            InfisicalDynamicProvider.ElasticSearch => (new(ElasticSearch: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                ["roles-one", "roles-two"],
                selected ? "ca-canary" : null)),
                new NativeElasticsearchDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    ["roles-one", "roles-two"],
                    selected ? "ca-canary" : null), "host"),
            InfisicalDynamicProvider.RabbitMq => (new(RabbitMq: new(
                "host-canary",
                1234,
                "username-canary",
                "password-canary",
                "virtualHost-canary",
                "configurePermission-canary",
                "writePermission-canary",
                "readPermission-canary",
                selected ? ["tags-one", "tags-two"] : null,
                selected ? "ca-canary" : null)),
                new NativeRabbitDefinitionProfile(
                    "host-canary",
                    1234,
                    "username-canary",
                    "password-canary",
                    "virtualHost-canary",
                    "configurePermission-canary",
                    "writePermission-canary",
                    "readPermission-canary",
                    selected ? ["tags-one", "tags-two"] : null,
                    selected ? "ca-canary" : null), "host"),
            InfisicalDynamicProvider.Kubernetes => (new(Kubernetes: new(
                "nameSpace-canary",
                "role-canary",
                true,
                ["audiences-one", "audiences-two"],
                selected ? "clusterToken-canary" : null,
                selected ? "https://url.test/path" : null,
                selected ? "ca-canary" : null,
                selected ? NativeKubernetesAuthentication.Gateway : null,
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null,
                selected ? true : null)),
                new NativeKubernetesDefinitionProfile(
                    "nameSpace-canary",
                    "role-canary",
                    true,
                    ["audiences-one", "audiences-two"],
                    selected ? "clusterToken-canary" : null,
                    selected ? "https://url.test/path" : null,
                    selected ? "ca-canary" : null,
                    selected ? NativeKubernetesAuthentication.Gateway : null,
                    selected ? gateway : null,
                    selected ? true : null), "nameSpace"),
            InfisicalDynamicProvider.Ldap => (new(Ldap: new(
                "https://url.test/path",
                "bindDn-canary",
                "bindPassword-canary",
                "creationLdif-canary",
                "revocationLdif-canary",
                selected ? "rollbackLdif-canary" : null,
                selected ? "ca-canary" : null)),
                new NativeLdapDefinitionProfile(
                    "https://url.test/path",
                    "bindDn-canary",
                    "bindPassword-canary",
                    "creationLdif-canary",
                    "revocationLdif-canary",
                    selected ? "rollbackLdif-canary" : null,
                    selected ? "ca-canary" : null), "url"),
            InfisicalDynamicProvider.Totp => (new(Totp: new(
                "https://provisioningurl.test/path")),
                new NativeTotpDefinitionProfile(
                    "https://provisioningurl.test/path"), "provisioningUrl"),
            InfisicalDynamicProvider.Ssh => (new(Ssh: new(
                ["principals-one", "principals-two"],
                selected ? NativeSshKeyAlgorithm.Ed25519 : null,
                selected ? NativeSshKeyAlgorithm.Rsa4096 : null)),
                new NativeSshDefinitionProfile(
                    ["principals-one", "principals-two"],
                    selected ? NativeSshKeyAlgorithm.Ed25519 : null,
                    selected ? NativeSshKeyAlgorithm.Rsa4096 : null), "principals"),
            InfisicalDynamicProvider.IbmApiConnect => (new(IbmApiConnect: new(
                "apiKey-canary",
                "applicationId-canary",
                "clientId-canary",
                "clientSecret-canary",
                "organizationId-canary",
                "catalogId-canary",
                "consumerOrganizationId-canary",
                "https://instanceurl.test/path",
                selected ? new DynamicGatewayInput("gateway-canary", "pool-canary") : null)),
                new NativeIbmApiDefinitionProfile(
                    "apiKey-canary",
                    "applicationId-canary",
                    "clientId-canary",
                    "clientSecret-canary",
                    "organizationId-canary",
                    "catalogId-canary",
                    "consumerOrganizationId-canary",
                    "https://instanceurl.test/path",
                    selected ? gateway : null), "apiKey"),
            InfisicalDynamicProvider.Oauth2 => (new(Oauth2: new(
                "clientId-canary",
                "clientSecret-canary",
                NativeOauthClientAuthentication.Post,
                "https://tokenurl.test/path",
                "https://revocationurl.test/path",
                selected ? "scope-canary" : null,
                selected ? [new DynamicOauthExtraParameterInput("key-canary", "value-canary")] : null)),
                new NativeOauthDefinitionProfile(
                    "clientId-canary",
                    "clientSecret-canary",
                    NativeOauthClientAuthentication.Post,
                    "https://tokenurl.test/path",
                    "https://revocationurl.test/path",
                    selected ? "scope-canary" : null,
                    selected ? parameters : null), "clientId"),
            InfisicalDynamicProvider.Tailscale => (new(Tailscale: new(
                "apiKey-canary",
                selected ? "tailnet-canary" : null,
                selected ? true : false,
                selected ? true : false,
                selected ? ["tags-one", "tags-two"] : null,
                selected ? "description-canary" : null)),
                new NativeTailscaleDefinitionProfile(
                    "apiKey-canary",
                    selected ? "tailnet-canary" : null,
                    selected ? true : false,
                    selected ? true : false,
                    selected ? ["tags-one", "tags-two"] : null,
                    selected ? "description-canary" : null), "apiKey"),
            InfisicalDynamicProvider.Couchbase => (new(Couchbase: new(
                "https://url.test/path",
                "apiKey-canary",
                "organizationId-canary",
                "projectId-canary",
                "clusterId-canary",
                ["roles-one", "roles-two"],
                selected ? new DynamicCouchbaseBucketsInput(Buckets: [new("bucket-canary", [new("scope-canary", ["collection-canary"]), new("absent-scope")]), new("empty-bucket", [])]) : null,
                selected ? new DynamicPasswordInput(24, 2, 3, 4, 5, "symbols-canary") : null)),
                new NativeCouchbaseDefinitionProfile(
                    "https://url.test/path",
                    "apiKey-canary",
                    "organizationId-canary",
                    "projectId-canary",
                    "clusterId-canary",
                    ["roles-one", "roles-two"],
                    selected ? buckets : null,
                    selected ? password : null), "url"),
            InfisicalDynamicProvider.MongoDbAtlas => (new(MongoDbAtlas: new(
                "adminPublicKey-canary",
                "adminPrivateKey-canary",
                "groupId-canary",
                [new DynamicAtlasRoleInput("database-canary", "role-canary", "collection-canary"), new("db-minimal", "role-minimal")],
                [new DynamicAtlasScopeInput("scope-canary", "type-canary")])),
                new NativeAtlasDefinitionProfile(
                    "adminPublicKey-canary",
                    "adminPrivateKey-canary",
                    "groupId-canary",
                    roles,
                    scopes), "adminPublicKey"),
            _ => throw new ArgumentException()
        };
    }

    private static InfisicalDynamicClient Client(CaptureTransport handler) => new(new("https://dynamic.test"),
        new Tokens(), new("project", "environment", "/folder", CaptureTransport.FolderId), transport: handler);

    private static async Task<JsonElement> Capture(InfisicalDynamicProfile profile)
    {
        using var handler = new CaptureTransport();
        await using var client = Client(handler);
        var target = client.Definition("offline");
        var result = await client.CreateDefinitionAsync(target, profile, new(TimeSpan.FromSeconds(60)),
            new(TimeSpan.FromSeconds(120)), new(target, InfisicalDynamicOperation.CreateDefinition));
        await Assert.That(result.IsSuccess).IsTrue();
        return handler.Provider!.Value;
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
