using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalDynamicNestedProfileOptionTests
{
    [Test]
    [Arguments("NativeGatewayOptions.gatewayId.omitted", "gatewayId", "omitted")]
    [Arguments("NativeGatewayOptions.gatewayId.value", "gatewayId", "value")]
    [Arguments("NativeGatewayOptions.gatewayPoolId.omitted", "gatewayPoolId", "omitted")]
    [Arguments("NativeGatewayOptions.gatewayPoolId.value", "gatewayPoolId", "value")]
    [Arguments("NativeGatewayOptions.clearGatewayId.false", "gatewayId", "value")]
    [Arguments("NativeGatewayOptions.clearGatewayId.true", "gatewayId", "null")]
    [Arguments("NativeGatewayOptions.clearGatewayPoolId.false", "gatewayPoolId", "value")]
    [Arguments("NativeGatewayOptions.clearGatewayPoolId.true", "gatewayPoolId", "null")]
    [Arguments("NativeAwsIamOptions.awsPath.omitted", "awsPath", "omitted")]
    [Arguments("NativeAwsIamOptions.awsPath.value", "awsPath", "value")]
    [Arguments("NativeAwsIamOptions.permissionBoundaryPolicyArn.omitted", "permissionBoundaryPolicyArn", "omitted")]
    [Arguments("NativeAwsIamOptions.permissionBoundaryPolicyArn.value", "permissionBoundaryPolicyArn", "value")]
    [Arguments("NativeAwsIamOptions.policyArns.omitted", "policyArns", "omitted")]
    [Arguments("NativeAwsIamOptions.policyArns.value", "policyArns", "value")]
    [Arguments("NativeAwsIamOptions.policyDocument.omitted", "policyDocument", "omitted")]
    [Arguments("NativeAwsIamOptions.policyDocument.value", "policyDocument", "value")]
    [Arguments("NativeAwsIamOptions.userGroups.omitted", "userGroups", "omitted")]
    [Arguments("NativeAwsIamOptions.userGroups.value", "userGroups", "value")]
    [Arguments("NativeAwsIamOptions.tags.omitted", "tags", "omitted")]
    [Arguments("NativeAwsIamOptions.tags.value", "tags", "value")]
    [Arguments("NativeAwsIamOptions.sessionPolicyArns.omitted", "sessionPolicyArns", "omitted")]
    [Arguments("NativeAwsIamOptions.sessionPolicyArns.value", "sessionPolicyArns", "value")]
    [Arguments("NativeAwsIamOptions.sessionPolicyDocument.omitted", "sessionPolicyDocument", "omitted")]
    [Arguments("NativeAwsIamOptions.sessionPolicyDocument.value", "sessionPolicyDocument", "value")]
    [Arguments("NativeMilvusPrivilege.objectName.omitted", "objectName", "omitted")]
    [Arguments("NativeMilvusPrivilege.objectName.value", "objectName", "value")]
    [Arguments("NativeMilvusPrivilege.dbName.omitted", "dbName", "omitted")]
    [Arguments("NativeMilvusPrivilege.dbName.value", "dbName", "value")]
    [Arguments("NativeCouchbaseScope.collections.omitted", "collections", "omitted")]
    [Arguments("NativeCouchbaseScope.collections.value", "collections", "value")]
    [Arguments("NativeCouchbaseBucket.scopes.omitted", "scopes", "omitted")]
    [Arguments("NativeCouchbaseBucket.scopes.value", "scopes", "value")]
    [Arguments("NativeTailscaleOptions.tailnet.omitted", "tailnet", "omitted")]
    [Arguments("NativeTailscaleOptions.tailnet.value", "tailnet", "value")]
    [Arguments("NativeTailscaleOptions.tags.omitted", "tags", "omitted")]
    [Arguments("NativeTailscaleOptions.tags.value", "tags", "value")]
    [Arguments("NativeTailscaleOptions.description.omitted", "description", "omitted")]
    [Arguments("NativeTailscaleOptions.description.value", "description", "value")]
    [Arguments("NativeTailscaleOptions.audience.omitted", "audience", "omitted")]
    [Arguments("NativeTailscaleOptions.audience.value", "audience", "value")]
    [Arguments("NativeTailscaleOptions.reusable.omitted", "reusable", "omitted")]
    [Arguments("NativeTailscaleOptions.reusable.false", "reusable", "false")]
    [Arguments("NativeTailscaleOptions.reusable.true", "reusable", "true")]
    [Arguments("NativeTailscaleOptions.preauthorized.omitted", "preauthorized", "omitted")]
    [Arguments("NativeTailscaleOptions.preauthorized.false", "preauthorized", "false")]
    [Arguments("NativeTailscaleOptions.preauthorized.true", "preauthorized", "true")]
    [Arguments("AwsIam.assume-role.sessionPolicyArns", "sessionPolicyArns", "value")]
    [Arguments("AwsIam.assume-role.sessionPolicyDocument", "sessionPolicyDocument", "value")]
    [Arguments("RabbitMq.tags.empty", "tags", "empty")]
    [Arguments("RabbitMq.tags.values", "tags", "values")]
    [Arguments("GcpIam.tokenScopes.omitted", "tokenScopes", "omitted")]
    [Arguments("GcpIam.tokenScopes.values", "tokenScopes", "values")]
    [Arguments("Atlas.role.collectionName.omitted", "collectionName", "omitted")]
    [Arguments("Atlas.role.collectionName.value", "collectionName", "value")]
    [Arguments("Atlas.scopes.empty", "scopes", "empty")]
    [Arguments("Atlas.scopes.values", "scopes", "values")]
    [Arguments("Oauth2.extraParams.omitted", "extraParams", "omitted")]
    [Arguments("Oauth2.extraParams.empty", "extraParams", "empty")]
    [Arguments("Oauth2.extraParams.values", "extraParams", "values")]
    public async Task NamedVariantsDispatchExactFieldsWithoutChangingOtherInputs(string variant, string field, string effect)
    {
        await Assert.That(InfisicalDynamicNestedProfileOptions.Supports(variant)).IsTrue();
        if (variant.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal))
        {
            string alternative = field == "audience" ? "Tailscale.federated_keys.oauth" : "Tailscale.auth_keys.oauth";
            await VerifyAlternative(variant, alternative, field, effect);
            return;
        }
        InfisicalDynamicProvider provider = Provider(variant);
        var input = Sample(provider);
        string original = JsonSerializer.Serialize(input);
        using var baseline = InfisicalDynamicProfileInputs.Create(provider, input);
        var expected = JsonNode.Parse((await Capture(baseline)).GetRawText())!;
        ChangeExpected(expected["inputs"]!, variant, field, effect);
        var selected = InfisicalDynamicNestedProfileOptions.Select(variant, provider, input);
        using var first = InfisicalDynamicProfileInputs.Create(provider, selected);
        using var second = InfisicalDynamicProfileInputs.Create(provider, selected);
        first.Dispose();
        await Assert.That(JsonElement.DeepEquals(await Capture(second), JsonSerializer.SerializeToElement(expected))).IsTrue();
        await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo(original);
        await Assert.That(selected.ToString()).IsEqualTo("[InfisicalDynamicProfileInput]");
        await Assert.That(second.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(InfisicalDynamicProvider.Clickhouse)]
    [Arguments(InfisicalDynamicProvider.Vertica)]
    [Arguments(InfisicalDynamicProvider.AzureSqlDatabase)]
    [Arguments(InfisicalDynamicProvider.Milvus)]
    [Arguments(InfisicalDynamicProvider.Kubernetes)]
    [Arguments(InfisicalDynamicProvider.IbmApiConnect)]
    public async Task GatewayRowsDispatchThroughEveryCompatibleConstructor(InfisicalDynamicProvider provider)
    {
        foreach (string variant in Admitted().Where(v => v.StartsWith("NativeGatewayOptions.", StringComparison.Ordinal)))
        {
            var input = Sample(provider);
            using var baseline = InfisicalDynamicProfileInputs.Create(provider, input);
            var expected = JsonNode.Parse((await Capture(baseline)).GetRawText())!;
            var (field, effect) = GatewayEffect(variant);
            ChangeExpected(expected["inputs"]!, variant, field, effect);
            using var profile = InfisicalDynamicProfileInputs.Create(provider,
                InfisicalDynamicNestedProfileOptions.Select(variant, provider, input));
            await Assert.That(JsonElement.DeepEquals(await Capture(profile), JsonSerializer.SerializeToElement(expected))).IsTrue();
            await VerifyAlternative(variant, "Kubernetes.static-account", field, effect);
        }
    }

    [Test]
    [Arguments("Tailscale.auth_keys.oauth")]
    [Arguments("Tailscale.federated_keys.api_key")]
    [Arguments("Tailscale.federated_keys.oauth")]
    [Arguments("Tailscale.oauth_keys.api_key")]
    [Arguments("Tailscale.oauth_keys.oauth")]
    public async Task TailscaleFactoryMatrixAcceptsOnlyCompatibleOptionBranches(string alternative)
    {
        foreach (string variant in Admitted().Where(v => v.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal)))
        {
            string[] parts = variant.Split('.');
            string field = parts[1], effect = parts[2];
            bool compatible = field switch
            {
                "audience" => effect == "omitted" || alternative.StartsWith("Tailscale.federated_keys.", StringComparison.Ordinal),
                "reusable" or "preauthorized" => effect == "omitted" || alternative == "Tailscale.auth_keys.oauth",
                _ => true
            };
            if (compatible) await VerifyAlternative(variant, alternative, field, effect);
            else
            {
                var sample = InfisicalDynamicAlternativeProfileInputTests.Sample(alternative, 1);
                using var baseline = sample.Profile;
                await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative(variant, alternative, sample.Input))
                    .Throws<ArgumentException>();
            }
        }
    }

    [Test]
    public async Task AdmissionCoverageIsCompleteAndExact()
    {
        string[] variants = Admitted();
        await Assert.That(variants.Length).IsEqualTo(59);
        foreach (string variant in variants)
            await Assert.That(InfisicalDynamicNestedProfileOptions.Supports(variant)).IsTrue();
        foreach (string variant in new[] { "", "NativeGatewayOptions.gatewayId.VALUE", "NativeGatewayOptions.gatewayId.value ",
            "NativeTailscaleOptions.unknown.omitted", "RabbitMq.tags.omitted", "NativeSqlDefinitionProfile.ca.value",
            "NativeAwsTag.value.value", "Tailscale.auth_keys.oauth", "NativeCouchbaseBucket.scopes.empty" })
        {
            await Assert.That(InfisicalDynamicNestedProfileOptions.Supports(variant)).IsFalse();
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, InfisicalDynamicProvider.Clickhouse,
                Sample(InfisicalDynamicProvider.Clickhouse))).Throws<ArgumentException>();
        }
        await Assert.That(InfisicalDynamicNestedProfileOptions.Supports(null!)).IsFalse();
    }

    [Test]
    public async Task MissingValuesArraysAndExplicitSelectionsFailClosed()
    {
        foreach (string variant in Admitted().Where(v => !v.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal)))
        {
            var provider = Provider(variant);
            var input = Sample(provider);
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, provider, new())).Throws<ArgumentException>();
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, InfisicalDynamicProvider.SqlDatabase, input))
                .Throws<ArgumentException>();
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, provider,
                input with { Ssh = new(["principal"]) })).Throws<ArgumentException>();
            if (variant.EndsWith(".value", StringComparison.Ordinal) || variant.EndsWith(".values", StringComparison.Ordinal) ||
                variant.StartsWith("AwsIam.assume-role.", StringComparison.Ordinal))
            {
                var absent = InfisicalDynamicProfileInputTests.Sample(provider, false);
                using var absentProfile = absent.Profile;
                var missing = absent.Input;
                if (provider == InfisicalDynamicProvider.MongoDbAtlas)
                    missing = missing with { MongoDbAtlas = missing.MongoDbAtlas! with { Roles = [], Scopes = [] } };
                await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, provider, missing)).Throws<ArgumentException>();
            }
        }
        var couchbase = Sample(InfisicalDynamicProvider.Couchbase);
        foreach (var buckets in new DynamicCouchbaseBucketsInput?[] { null, new(Text: "owned-text"), new(Buckets: []),
            new(Buckets: [new("bucket")]), new(Buckets: [new("bucket", [])]) })
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("NativeCouchbaseScope.collections.omitted",
                InfisicalDynamicProvider.Couchbase, couchbase with { Couchbase = couchbase.Couchbase! with { Buckets = buckets } }))
                .Throws<ArgumentException>();
        var milvus = Sample(InfisicalDynamicProvider.Milvus);
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("NativeMilvusPrivilege.objectName.omitted",
            InfisicalDynamicProvider.Milvus, milvus with { Milvus = milvus.Milvus! with { Privileges = null } })).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("RabbitMq.tags.empty", InfisicalDynamicProvider.RabbitMq, null!))
            .Throws<ArgumentNullException>();
    }

    [Test]
    public async Task SessionPolicySelectionNeverChangesAuthorityAndRequiresValidRoleArn()
    {
        foreach (string variant in new[] { "AwsIam.assume-role.sessionPolicyArns", "AwsIam.assume-role.sessionPolicyDocument",
            "NativeAwsIamOptions.sessionPolicyArns.value", "NativeAwsIamOptions.sessionPolicyDocument.value" })
        {
            var input = Sample(InfisicalDynamicProvider.AwsIam);
            foreach (var authority in new DynamicAwsIamInput[]
            {
                input.AwsIam! with { Authentication = DynamicAwsAuthentication.AccessKey, AccessKey = "key", SecretAccessKey = "secret", RoleArn = null },
                input.AwsIam! with { Authentication = DynamicAwsAuthentication.Irsa, RoleArn = null },
                input.AwsIam! with { RoleArn = "not-an-arn" },
                input.AwsIam! with { RoleArn = "arn:aws:iam::123456789012:user/caller" },
                input.AwsIam! with { RoleArn = "arn:aws:iam::123:role/caller" },
                input.AwsIam! with { AccessKey = "conflicting-key" }
            })
                await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, InfisicalDynamicProvider.AwsIam,
                    input with { AwsIam = authority })).Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task AlternativeSelectionRejectsUnknownMismatchedAndMultipleFactories()
    {
        var sample = InfisicalDynamicAlternativeProfileInputTests.Sample("Tailscale.auth_keys.oauth", 1);
        using var baseline = sample.Profile;
        foreach (string alternative in new[] { "Tailscale.auth_keys.api_key", "Tailscale.auth_keys.oauth ", "Kubernetes.static-account",
            "Tailscale.federated_keys.oauth", "unknown" })
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative("NativeTailscaleOptions.tailnet.value",
                alternative, sample.Input)).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative("NativeTailscaleOptions.tailnet.value",
            "Tailscale.auth_keys.oauth", sample.Input with { TotpManualSecret = new("secret") })).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative("NativeTailscaleOptions.tailnet.value",
            "Tailscale.auth_keys.oauth", new())).Throws<ArgumentException>();
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative("NativeTailscaleOptions.tailnet.value",
            "Tailscale.auth_keys.oauth", null!)).Throws<ArgumentNullException>();
        foreach (string variant in Admitted().Where(v => v.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal)))
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select(variant, InfisicalDynamicProvider.Tailscale,
                Sample(InfisicalDynamicProvider.Tailscale))).Throws<ArgumentException>();
        foreach (string variant in new[] { "NativeTailscaleOptions.tailnet.value", "NativeTailscaleOptions.tags.value",
            "NativeTailscaleOptions.description.value", "NativeTailscaleOptions.audience.value" })
        {
            var absent = InfisicalDynamicAlternativeProfileInputTests.Sample("Tailscale.federated_keys.oauth", 0);
            using var absentProfile = absent.Profile;
            await Assert.That(() => InfisicalDynamicNestedProfileOptions.SelectAlternative(variant,
                "Tailscale.federated_keys.oauth", absent.Input)).Throws<ArgumentException>();
        }
    }

    [Test]
    public async Task SnapshotsCopyEveryMutableNestedContainerBeforeCallerMutation()
    {
        foreach (var (variant, provider) in new (string, InfisicalDynamicProvider)[]
        {
            ("NativeAwsIamOptions.tags.value", InfisicalDynamicProvider.AwsIam),
            ("NativeMilvusPrivilege.objectName.value", InfisicalDynamicProvider.Milvus),
            ("NativeCouchbaseScope.collections.value", InfisicalDynamicProvider.Couchbase),
            ("Atlas.role.collectionName.value", InfisicalDynamicProvider.MongoDbAtlas),
            ("RabbitMq.tags.values", InfisicalDynamicProvider.RabbitMq),
            ("GcpIam.tokenScopes.values", InfisicalDynamicProvider.GcpIam),
            ("Oauth2.extraParams.values", InfisicalDynamicProvider.Oauth2),
            ("NativeGatewayOptions.gatewayId.value", InfisicalDynamicProvider.Kubernetes)
        })
        {
            var input = Sample(provider);
            var selected = InfisicalDynamicNestedProfileOptions.Select(variant, provider, input);
            using var before = InfisicalDynamicProfileInputs.Create(provider, selected);
            var expected = await Capture(before);
            switch (provider)
            {
                case InfisicalDynamicProvider.AwsIam: input.AwsIam!.Options!.Tags![0] = new("changed"); break;
                case InfisicalDynamicProvider.Milvus: input.Milvus!.Privileges![0] = new("changed", "changed"); break;
                case InfisicalDynamicProvider.Couchbase:
                    input.Couchbase!.Roles[0] = "changed";
                    input.Couchbase.Buckets!.Buckets![0].Scopes![0].Collections![0] = "changed";
                    input.Couchbase.Buckets.Buckets[1] = new("changed");
                    break;
                case InfisicalDynamicProvider.MongoDbAtlas:
                    input.MongoDbAtlas!.Roles[0] = new("changed", "changed");
                    input.MongoDbAtlas.Scopes[0] = new("changed", "changed"); break;
                case InfisicalDynamicProvider.RabbitMq: input.RabbitMq!.Tags![0] = "changed"; break;
                case InfisicalDynamicProvider.GcpIam: input.GcpIam!.TokenScopes![0] = "changed"; break;
                case InfisicalDynamicProvider.Oauth2: input.Oauth2!.ExtraParameters![0] = new("changed", "changed"); break;
                case InfisicalDynamicProvider.Kubernetes: input.Kubernetes!.Audiences[0] = "changed"; break;
            }
            using var after = InfisicalDynamicProfileInputs.Create(provider, selected);
            await Assert.That(JsonElement.DeepEquals(await Capture(after), expected)).IsTrue();
        }
        var alternative = InfisicalDynamicAlternativeProfileInputTests.Sample("Tailscale.federated_keys.oauth", 1);
        using var original = alternative.Profile;
        var snapshot = InfisicalDynamicNestedProfileOptions.SelectAlternative("NativeTailscaleOptions.tags.value",
            "Tailscale.federated_keys.oauth", alternative.Input);
        using var tailBefore = InfisicalDynamicAlternativeProfileInputs.Create("Tailscale.federated_keys.oauth", snapshot);
        var tailExpected = await Capture(tailBefore);
        alternative.Input.TailscaleFederatedOAuth!.Scopes[0] = "changed";
        alternative.Input.TailscaleFederatedOAuth.Options!.Tags![0] = "changed";
        using var tailAfter = InfisicalDynamicAlternativeProfileInputs.Create("Tailscale.federated_keys.oauth", snapshot);
        tailBefore.Dispose();
        await Assert.That(JsonElement.DeepEquals(await Capture(tailAfter), tailExpected)).IsTrue();
    }

    [Test]
    public async Task ClearFalsePreservesConfiguredCoordinatesAndOtherOptions()
    {
        var input = Sample(InfisicalDynamicProvider.Clickhouse);
        foreach (bool pool in new[] { false, true })
        {
            var gateway = input.Clickhouse!.Gateway! with { ClearGatewayId = !pool, ClearGatewayPoolId = pool };
            var configured = input with { Clickhouse = input.Clickhouse with { Gateway = gateway } };
            string variant = pool ? "NativeGatewayOptions.clearGatewayPoolId.false" : "NativeGatewayOptions.clearGatewayId.false";
            var selected = InfisicalDynamicNestedProfileOptions.Select(variant, InfisicalDynamicProvider.Clickhouse, configured);
            using var expected = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Clickhouse, input);
            using var actual = InfisicalDynamicProfileInputs.Create(InfisicalDynamicProvider.Clickhouse, selected);
            await Assert.That(JsonElement.DeepEquals(await Capture(actual), await Capture(expected))).IsTrue();
            await Assert.That(configured.Clickhouse!.Gateway!.ClearGatewayId).IsEqualTo(!pool);
            await Assert.That(configured.Clickhouse.Gateway.ClearGatewayPoolId).IsEqualTo(pool);
        }
    }

    [Test]
    public async Task EveryOwnedArrayElementRequiresItsSelectedValue()
    {
        var milvus = Sample(InfisicalDynamicProvider.Milvus);
        var privileges = milvus.Milvus!.Privileges!.ToArray();
        privileges[1] = privileges[1] with { ObjectName = null };
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("NativeMilvusPrivilege.objectName.value",
            InfisicalDynamicProvider.Milvus, milvus with { Milvus = milvus.Milvus with { Privileges = privileges } })).Throws<ArgumentException>();
        var atlas = Sample(InfisicalDynamicProvider.MongoDbAtlas);
        var roles = atlas.MongoDbAtlas!.Roles.ToArray();
        roles[1] = roles[1] with { CollectionName = null };
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("Atlas.role.collectionName.value",
            InfisicalDynamicProvider.MongoDbAtlas, atlas with { MongoDbAtlas = atlas.MongoDbAtlas with { Roles = roles } })).Throws<ArgumentException>();
        var couchbase = Sample(InfisicalDynamicProvider.Couchbase);
        var buckets = couchbase.Couchbase!.Buckets!.Buckets!.ToArray();
        buckets[1] = buckets[1] with { Scopes = [new("scope-without-collections")] };
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("NativeCouchbaseScope.collections.value",
            InfisicalDynamicProvider.Couchbase, couchbase with
            { Couchbase = couchbase.Couchbase with { Buckets = new(Buckets: buckets) } })).Throws<ArgumentException>();
        privileges[1] = null!;
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("NativeMilvusPrivilege.dbName.omitted",
            InfisicalDynamicProvider.Milvus, milvus with { Milvus = milvus.Milvus with { Privileges = privileges } })).Throws<ArgumentException>();
        var rabbit = Sample(InfisicalDynamicProvider.RabbitMq);
        await Assert.That(() => InfisicalDynamicNestedProfileOptions.Select("RabbitMq.tags.values",
            InfisicalDynamicProvider.RabbitMq, rabbit with { RabbitMq = rabbit.RabbitMq! with { Tags = [] } })).Throws<ArgumentException>();
    }

    internal static InfisicalDynamicProfileInput Sample(InfisicalDynamicProvider provider)
    {
        var sample = InfisicalDynamicProfileInputTests.Sample(provider, true);
        using var baseline = sample.Profile;
        var input = sample.Input;
        return provider switch
        {
            InfisicalDynamicProvider.AwsIam => input with
            {
                AwsIam = input.AwsIam! with
                {
                    AccessKey = null,
                    SecretAccessKey = null,
                    Authentication = DynamicAwsAuthentication.AssumeRole,
                    RoleArn = "arn:aws:iam::123456789012:role/owned-role",
                    Options = input.AwsIam.Options! with
                    {
                        SessionPolicyArns = "arn:aws:iam::123456789012:policy/owned-policy",
                        SessionPolicyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
                    }
                }
            },
            InfisicalDynamicProvider.Milvus => input with { Milvus = input.Milvus! with { Privileges = [new("Collection", "Search", "first", "db-first"), new("Collection", "Query", "second", "db-second")] } },
            InfisicalDynamicProvider.Couchbase => input with
            {
                Couchbase = input.Couchbase! with
                {
                    Buckets = new(Buckets: [new("bucket-first", [new("scope-first", ["collection-first"]), new("scope-second", ["collection-second"])]),
                        new("bucket-second", [new("scope-third", ["collection-third"])])])
                }
            },
            InfisicalDynamicProvider.MongoDbAtlas => input with { MongoDbAtlas = input.MongoDbAtlas! with { Roles = [new("db-first", "read", "collection-first"), new("db-second", "readWrite", "collection-second")] } },
            _ => input
        };
    }

    internal static InfisicalDynamicProvider Provider(string variant) => variant.Split('.')[0] switch
    {
        "NativeGatewayOptions" => InfisicalDynamicProvider.Clickhouse,
        "NativeAwsIamOptions" or "AwsIam" => InfisicalDynamicProvider.AwsIam,
        "NativeMilvusPrivilege" => InfisicalDynamicProvider.Milvus,
        "NativeCouchbaseScope" or "NativeCouchbaseBucket" => InfisicalDynamicProvider.Couchbase,
        "RabbitMq" => InfisicalDynamicProvider.RabbitMq,
        "GcpIam" => InfisicalDynamicProvider.GcpIam,
        "Atlas" => InfisicalDynamicProvider.MongoDbAtlas,
        "Oauth2" => InfisicalDynamicProvider.Oauth2,
        _ => throw new ArgumentException()
    };

    private static (string Field, string Effect) GatewayEffect(string variant)
    {
        string[] parts = variant.Split('.');
        return parts[1] switch
        {
            "clearGatewayId" => ("gatewayId", parts[2] == "true" ? "null" : "value"),
            "clearGatewayPoolId" => ("gatewayPoolId", parts[2] == "true" ? "null" : "value"),
            _ => (parts[1], parts[2])
        };
    }

    private static void ChangeExpected(JsonNode inputs, string variant, string field, string effect)
    {
        IEnumerable<JsonObject> parents = variant.Split('.')[0] switch
        {
            "NativeMilvusPrivilege" => inputs["privileges"]!.AsArray().Select(v => v!.AsObject()),
            "NativeCouchbaseBucket" => inputs["buckets"]!.AsArray().Select(v => v!.AsObject()),
            "NativeCouchbaseScope" => inputs["buckets"]!.AsArray().SelectMany(b => b!["scopes"]!.AsArray()).Select(v => v!.AsObject()),
            "Atlas" when field == "collectionName" => inputs["roles"]!.AsArray().Select(v => v!.AsObject()),
            _ => [inputs.AsObject()]
        };
        foreach (JsonObject parent in parents)
        {
            switch (effect)
            {
                case "omitted": parent.Remove(field); break;
                case "empty": parent[field] = new JsonArray(); break;
                case "null": parent[field] = null; break;
                case "true": parent[field] = true; break;
                case "false": parent[field] = false; break;
                case "value" or "values":
                    if (parent[field] is null) throw new InvalidOperationException("Configured wire value required.");
                    break;
                default: throw new ArgumentException();
            }
        }
    }

    private static async Task VerifyAlternative(string variant, string alternative, string field, string effect)
    {
        var sample = InfisicalDynamicAlternativeProfileInputTests.Sample(alternative, 1);
        using var baseline = sample.Profile;
        string original = JsonSerializer.Serialize(sample.Input);
        var expected = JsonNode.Parse((await Capture(baseline)).GetRawText())!;
        ChangeExpected(expected["inputs"]!, variant, field, effect);
        var selected = InfisicalDynamicNestedProfileOptions.SelectAlternative(variant, alternative, sample.Input);
        using var first = InfisicalDynamicAlternativeProfileInputs.Create(alternative, selected);
        using var second = InfisicalDynamicAlternativeProfileInputs.Create(alternative, selected);
        first.Dispose();
        await Assert.That(JsonElement.DeepEquals(await Capture(second), JsonSerializer.SerializeToElement(expected))).IsTrue();
        await Assert.That(JsonSerializer.Serialize(sample.Input)).IsEqualTo(original);
        await Assert.That(selected.ToString()).IsEqualTo("[InfisicalDynamicAlternativeProfileInput]");
    }

    private static string[] Admitted()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SecretKit.slnx"))) directory = directory.Parent;
        if (directory is null) throw new InvalidOperationException("Repository admission fixture required.");
        using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory.FullName, "docs/internal/releases/admission/infisical.json")));
        var operation = document.RootElement.GetProperty("operations").EnumerateArray().Single(v =>
            v.GetProperty("id").GetString() == "i.runtime.InfisicalDynamicClient.CreateDefinitionAsync");
        string[] aliases = ["AwsIam.assume-role.sessionPolicyArns", "AwsIam.assume-role.sessionPolicyDocument", "RabbitMq.tags.empty",
            "RabbitMq.tags.values", "GcpIam.tokenScopes.omitted", "GcpIam.tokenScopes.values", "Atlas.role.collectionName.omitted",
            "Atlas.role.collectionName.value", "Atlas.scopes.empty", "Atlas.scopes.values", "Oauth2.extraParams.omitted",
            "Oauth2.extraParams.empty", "Oauth2.extraParams.values"];
        return operation.GetProperty("variants").EnumerateArray().Select(v => v.GetString()!).Where(v =>
            v.StartsWith("NativeGatewayOptions.", StringComparison.Ordinal) || v.StartsWith("NativeAwsIamOptions.", StringComparison.Ordinal) ||
            v.StartsWith("NativeMilvusPrivilege.", StringComparison.Ordinal) || v.StartsWith("NativeCouchbaseScope.", StringComparison.Ordinal) ||
            v.StartsWith("NativeCouchbaseBucket.", StringComparison.Ordinal) || v.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal) ||
            aliases.Contains(v, StringComparer.Ordinal)).ToArray();
    }

    private static async Task<JsonElement> Capture(InfisicalDynamicProfile profile)
    {
        using var transport = new CaptureTransport();
        await using var client = new InfisicalDynamicClient(new("https://dynamic.test"), new Tokens(),
            new("project", "environment", "/folder", CaptureTransport.FolderId),
            new() { Transport = InfisicalTransportOptions.HostControlled(transport) });
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
