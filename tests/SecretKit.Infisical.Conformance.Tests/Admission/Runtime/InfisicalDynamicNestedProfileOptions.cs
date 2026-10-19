namespace SecretKit.Infisical.Conformance.Tests;

// Closed private admission selection. Only the public factories construct protected SDK profiles.
internal static class InfisicalDynamicNestedProfileOptions
{
    internal static bool Supports(string variant) => variant switch
    {
        "NativeGatewayOptions.gatewayId.omitted" or
        "NativeGatewayOptions.gatewayId.value" or
        "NativeGatewayOptions.gatewayPoolId.omitted" or
        "NativeGatewayOptions.gatewayPoolId.value" or
        "NativeGatewayOptions.clearGatewayId.false" or
        "NativeGatewayOptions.clearGatewayId.true" or
        "NativeGatewayOptions.clearGatewayPoolId.false" or
        "NativeGatewayOptions.clearGatewayPoolId.true" or
        "NativeAwsIamOptions.awsPath.omitted" or
        "NativeAwsIamOptions.awsPath.value" or
        "NativeAwsIamOptions.permissionBoundaryPolicyArn.omitted" or
        "NativeAwsIamOptions.permissionBoundaryPolicyArn.value" or
        "NativeAwsIamOptions.policyArns.omitted" or
        "NativeAwsIamOptions.policyArns.value" or
        "NativeAwsIamOptions.policyDocument.omitted" or
        "NativeAwsIamOptions.policyDocument.value" or
        "NativeAwsIamOptions.userGroups.omitted" or
        "NativeAwsIamOptions.userGroups.value" or
        "NativeAwsIamOptions.tags.omitted" or
        "NativeAwsIamOptions.tags.value" or
        "NativeAwsIamOptions.sessionPolicyArns.omitted" or
        "NativeAwsIamOptions.sessionPolicyArns.value" or
        "NativeAwsIamOptions.sessionPolicyDocument.omitted" or
        "NativeAwsIamOptions.sessionPolicyDocument.value" or
        "NativeMilvusPrivilege.objectName.omitted" or
        "NativeMilvusPrivilege.objectName.value" or
        "NativeMilvusPrivilege.dbName.omitted" or
        "NativeMilvusPrivilege.dbName.value" or
        "NativeCouchbaseScope.collections.omitted" or
        "NativeCouchbaseScope.collections.value" or
        "NativeCouchbaseBucket.scopes.omitted" or
        "NativeCouchbaseBucket.scopes.value" or
        "NativeTailscaleOptions.tailnet.omitted" or
        "NativeTailscaleOptions.tailnet.value" or
        "NativeTailscaleOptions.tags.omitted" or
        "NativeTailscaleOptions.tags.value" or
        "NativeTailscaleOptions.description.omitted" or
        "NativeTailscaleOptions.description.value" or
        "NativeTailscaleOptions.audience.omitted" or
        "NativeTailscaleOptions.audience.value" or
        "NativeTailscaleOptions.reusable.omitted" or
        "NativeTailscaleOptions.reusable.false" or
        "NativeTailscaleOptions.reusable.true" or
        "NativeTailscaleOptions.preauthorized.omitted" or
        "NativeTailscaleOptions.preauthorized.false" or
        "NativeTailscaleOptions.preauthorized.true" or
        "AwsIam.assume-role.sessionPolicyArns" or
        "AwsIam.assume-role.sessionPolicyDocument" or
        "RabbitMq.tags.empty" or
        "RabbitMq.tags.values" or
        "GcpIam.tokenScopes.omitted" or
        "GcpIam.tokenScopes.values" or
        "Atlas.role.collectionName.omitted" or
        "Atlas.role.collectionName.value" or
        "Atlas.scopes.empty" or
        "Atlas.scopes.values" or
        "Oauth2.extraParams.omitted" or
        "Oauth2.extraParams.empty" or
        "Oauth2.extraParams.values" => true,
        _ => false
    };

    internal static InfisicalDynamicProfileInput Select(string variant, InfisicalDynamicProvider provider,
        InfisicalDynamicProfileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!Supports(variant)) throw new ArgumentException("Unknown nested option variant.");
        InfisicalDynamicProfileInput selected;
        if (variant.StartsWith("NativeGatewayOptions.", StringComparison.Ordinal))
        {
            selected = provider switch
            {
                InfisicalDynamicProvider.Clickhouse when input.Clickhouse is { } p =>
                    input with { Clickhouse = p with { Gateway = Gateway(variant, p.Gateway) } },
                InfisicalDynamicProvider.Vertica when input.Vertica is { } p =>
                    input with { Vertica = p with { Gateway = Gateway(variant, p.Gateway) } },
                InfisicalDynamicProvider.AzureSqlDatabase when input.AzureSqlDatabase is { } p =>
                    input with { AzureSqlDatabase = p with { Gateway = Gateway(variant, p.Gateway) } },
                InfisicalDynamicProvider.Milvus when input.Milvus is { } p =>
                    input with { Milvus = p with { Gateway = Gateway(variant, p.Gateway), Privileges = Privileges(p.Privileges) } },
                InfisicalDynamicProvider.Kubernetes when input.Kubernetes is { } p =>
                    input with { Kubernetes = p with { Gateway = Gateway(variant, p.Gateway), Audiences = Required(p.Audiences).ToArray() } },
                InfisicalDynamicProvider.IbmApiConnect when input.IbmApiConnect is { } p =>
                    input with { IbmApiConnect = p with { Gateway = Gateway(variant, p.Gateway) } },
                _ => throw new ArgumentException("The explicit provider does not accept native gateway options.")
            };
        }
        else if (variant.StartsWith("NativeAwsIamOptions.", StringComparison.Ordinal) ||
            variant.StartsWith("AwsIam.assume-role.", StringComparison.Ordinal))
        {
            if (provider != InfisicalDynamicProvider.AwsIam) throw new ArgumentException("Mismatched nested option provider.");
            var p = Required(input.AwsIam);
            if (variant.Contains(".sessionPolicy", StringComparison.Ordinal)) RequireAssumeRole(p);
            selected = input with { AwsIam = p with { Options = Aws(variant, p.Options) } };
        }
        else if (variant.StartsWith("NativeMilvusPrivilege.", StringComparison.Ordinal))
        {
            if (provider != InfisicalDynamicProvider.Milvus) throw new ArgumentException("Mismatched nested option provider.");
            var p = Required(input.Milvus);
            var privileges = Items(p.Privileges).Select(v =>
            {
                var item = Required(v);
                return variant switch
                {
                    "NativeMilvusPrivilege.objectName.omitted" => item with { ObjectName = null },
                    "NativeMilvusPrivilege.objectName.value" => item with { ObjectName = Value(item.ObjectName) },
                    "NativeMilvusPrivilege.dbName.omitted" => item with { DbName = null },
                    "NativeMilvusPrivilege.dbName.value" => item with { DbName = Value(item.DbName) },
                    _ => throw new ArgumentException("Unknown privilege variant.")
                };
            }).ToArray();
            selected = input with { Milvus = p with { Privileges = privileges } };
        }
        else if (variant.StartsWith("NativeCouchbaseScope.", StringComparison.Ordinal) ||
            variant.StartsWith("NativeCouchbaseBucket.", StringComparison.Ordinal))
        {
            if (provider != InfisicalDynamicProvider.Couchbase) throw new ArgumentException("Mismatched nested option provider.");
            var p = Required(input.Couchbase);
            var buckets = Required(p.Buckets);
            if (buckets.Text is not null) throw new ArgumentException("Owned typed buckets are required.");
            var selectedBuckets = Items(buckets.Buckets).Select(v =>
            {
                var bucket = Required(v);
                return variant switch
                {
                    "NativeCouchbaseBucket.scopes.omitted" => bucket with { Scopes = null },
                    "NativeCouchbaseBucket.scopes.value" => bucket with { Scopes = Scopes(Items(bucket.Scopes)) },
                    "NativeCouchbaseScope.collections.omitted" => bucket with
                    {
                        Scopes = Items(bucket.Scopes).Select(s => Required(s) with { Collections = null }).ToArray()
                    },
                    "NativeCouchbaseScope.collections.value" => bucket with
                    {
                        Scopes = Items(bucket.Scopes).Select(s =>
                        {
                            var scope = Required(s);
                            return scope with { Collections = Items(scope.Collections).ToArray() };
                        }).ToArray()
                    },
                    _ => throw new ArgumentException("Unknown bucket variant.")
                };
            }).ToArray();
            selected = input with { Couchbase = p with { Roles = Required(p.Roles).ToArray(), Buckets = buckets with { Buckets = selectedBuckets } } };
        }
        else
        {
            selected = variant switch
            {
                "RabbitMq.tags.empty" when provider == InfisicalDynamicProvider.RabbitMq && input.RabbitMq is { } p =>
                    input with { RabbitMq = p with { Tags = [] } },
                "RabbitMq.tags.values" when provider == InfisicalDynamicProvider.RabbitMq && input.RabbitMq is { } p =>
                    input with { RabbitMq = p with { Tags = Items(p.Tags).ToArray() } },
                "GcpIam.tokenScopes.omitted" when provider == InfisicalDynamicProvider.GcpIam && input.GcpIam is { } p =>
                    input with { GcpIam = p with { TokenScopes = null } },
                "GcpIam.tokenScopes.values" when provider == InfisicalDynamicProvider.GcpIam && input.GcpIam is { } p =>
                    input with { GcpIam = p with { TokenScopes = Items(p.TokenScopes).ToArray() } },
                "Atlas.role.collectionName.omitted" when provider == InfisicalDynamicProvider.MongoDbAtlas && input.MongoDbAtlas is { } p =>
                    input with { MongoDbAtlas = p with { Roles = Items(p.Roles).Select(v => Required(v) with { CollectionName = null }).ToArray(), Scopes = AtlasScopes(p.Scopes) } },
                "Atlas.role.collectionName.value" when provider == InfisicalDynamicProvider.MongoDbAtlas && input.MongoDbAtlas is { } p =>
                    input with
                    {
                        MongoDbAtlas = p with
                        {
                            Roles = Items(p.Roles).Select(v =>
                            {
                                var role = Required(v);
                                return role with { CollectionName = Value(role.CollectionName) };
                            }).ToArray(),
                            Scopes = AtlasScopes(p.Scopes)
                        }
                    },
                "Atlas.scopes.empty" when provider == InfisicalDynamicProvider.MongoDbAtlas && input.MongoDbAtlas is { } p =>
                    input with { MongoDbAtlas = p with { Roles = AtlasRoles(p.Roles), Scopes = [] } },
                "Atlas.scopes.values" when provider == InfisicalDynamicProvider.MongoDbAtlas && input.MongoDbAtlas is { } p =>
                    input with { MongoDbAtlas = p with { Roles = AtlasRoles(p.Roles), Scopes = AtlasScopes(Items(p.Scopes)) } },
                "Oauth2.extraParams.omitted" when provider == InfisicalDynamicProvider.Oauth2 && input.Oauth2 is { } p =>
                    input with { Oauth2 = p with { ExtraParameters = null } },
                "Oauth2.extraParams.empty" when provider == InfisicalDynamicProvider.Oauth2 && input.Oauth2 is { } p =>
                    input with { Oauth2 = p with { ExtraParameters = [] } },
                "Oauth2.extraParams.values" when provider == InfisicalDynamicProvider.Oauth2 && input.Oauth2 is { } p =>
                    input with { Oauth2 = p with { ExtraParameters = Items(p.ExtraParameters).Select(v => Required(v) with { }).ToArray() } },
                _ => throw new ArgumentException("The variant requires its explicit typed provider or alternative factory.")
            };
        }
        // The actual public constructor enforces required inputs, selection cardinality and conflicting options.
        using var validated = InfisicalDynamicProfileInputs.Create(provider, selected);
        return selected;
    }

    internal static InfisicalDynamicAlternativeProfileInput SelectAlternative(string variant, string alternativeVariant,
        InfisicalDynamicAlternativeProfileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!Supports(variant) || !InfisicalDynamicAlternativeProfileInputs.TryProvider(alternativeVariant, out _))
            throw new ArgumentException("Unknown nested option or alternative factory variant.");
        InfisicalDynamicAlternativeProfileInput selected;
        if (variant.StartsWith("NativeGatewayOptions.", StringComparison.Ordinal) &&
            alternativeVariant == "Kubernetes.static-account" && input.KubernetesStaticAccount is { } k)
            selected = input with { KubernetesStaticAccount = k with { Gateway = Gateway(variant, k.Gateway), Audiences = Required(k.Audiences).ToArray() } };
        else if (variant.StartsWith("NativeTailscaleOptions.", StringComparison.Ordinal))
            selected = alternativeVariant switch
            {
                "Tailscale.auth_keys.oauth" when input.TailscaleOAuthAuthority is { } p =>
                    input with { TailscaleOAuthAuthority = p with { Options = Tailscale(variant, alternativeVariant, p.Options) } },
                "Tailscale.federated_keys.api_key" when input.TailscaleFederatedApiKey is { } p =>
                    input with { TailscaleFederatedApiKey = p with { Scopes = Required(p.Scopes).ToArray(), Options = Tailscale(variant, alternativeVariant, p.Options) } },
                "Tailscale.federated_keys.oauth" when input.TailscaleFederatedOAuth is { } p =>
                    input with { TailscaleFederatedOAuth = p with { Scopes = Required(p.Scopes).ToArray(), Options = Tailscale(variant, alternativeVariant, p.Options) } },
                "Tailscale.oauth_keys.api_key" when input.TailscaleOAuthKeyApiKey is { } p =>
                    input with { TailscaleOAuthKeyApiKey = p with { Scopes = Required(p.Scopes).ToArray(), Options = Tailscale(variant, alternativeVariant, p.Options) } },
                "Tailscale.oauth_keys.oauth" when input.TailscaleOAuthKeyOAuth is { } p =>
                    input with { TailscaleOAuthKeyOAuth = p with { Scopes = Required(p.Scopes).ToArray(), Options = Tailscale(variant, alternativeVariant, p.Options) } },
                _ => throw new ArgumentException("The alternative factory and typed input must match.")
            };
        else throw new ArgumentException("Unsupported nested option and alternative factory combination.");
        using var validated = InfisicalDynamicAlternativeProfileInputs.Create(alternativeVariant, selected);
        return selected;
    }

    private static DynamicGatewayInput Gateway(string variant, DynamicGatewayInput? input)
    {
        var p = input ?? new();
        return variant switch
        {
            "NativeGatewayOptions.gatewayId.omitted" => p with { GatewayId = null, ClearGatewayId = false },
            "NativeGatewayOptions.gatewayId.value" => p with { GatewayId = Value(p.GatewayId), ClearGatewayId = false },
            "NativeGatewayOptions.gatewayPoolId.omitted" => p with { GatewayPoolId = null, ClearGatewayPoolId = false },
            "NativeGatewayOptions.gatewayPoolId.value" => p with { GatewayPoolId = Value(p.GatewayPoolId), ClearGatewayPoolId = false },
            "NativeGatewayOptions.clearGatewayId.false" => p with { GatewayId = p.GatewayId, ClearGatewayId = false },
            "NativeGatewayOptions.clearGatewayId.true" => p with { GatewayId = null, ClearGatewayId = true },
            "NativeGatewayOptions.clearGatewayPoolId.false" => p with { GatewayPoolId = p.GatewayPoolId, ClearGatewayPoolId = false },
            "NativeGatewayOptions.clearGatewayPoolId.true" => p with { GatewayPoolId = null, ClearGatewayPoolId = true },
            _ => throw new ArgumentException("Unknown gateway variant.")
        };
    }

    private static DynamicAwsIamOptionsInput Aws(string variant, DynamicAwsIamOptionsInput? input)
    {
        var p = input ?? new();
        p = p with { Tags = p.Tags?.Select(v => Required(v) with { }).ToArray() };
        return variant switch
        {
            "NativeAwsIamOptions.awsPath.omitted" => p with { AwsPath = null },
            "NativeAwsIamOptions.awsPath.value" => p with { AwsPath = Value(p.AwsPath) },
            "NativeAwsIamOptions.permissionBoundaryPolicyArn.omitted" => p with { PermissionBoundaryPolicyArn = null },
            "NativeAwsIamOptions.permissionBoundaryPolicyArn.value" => p with { PermissionBoundaryPolicyArn = Value(p.PermissionBoundaryPolicyArn) },
            "NativeAwsIamOptions.policyArns.omitted" => p with { PolicyArns = null },
            "NativeAwsIamOptions.policyArns.value" => p with { PolicyArns = Value(p.PolicyArns) },
            "NativeAwsIamOptions.policyDocument.omitted" => p with { PolicyDocument = null },
            "NativeAwsIamOptions.policyDocument.value" => p with { PolicyDocument = Value(p.PolicyDocument) },
            "NativeAwsIamOptions.userGroups.omitted" => p with { UserGroups = null },
            "NativeAwsIamOptions.userGroups.value" => p with { UserGroups = Value(p.UserGroups) },
            "NativeAwsIamOptions.tags.omitted" => p with { Tags = null },
            "NativeAwsIamOptions.tags.value" => p with { Tags = Items(p.Tags).Select(v => Required(v) with { }).ToArray() },
            "NativeAwsIamOptions.sessionPolicyArns.omitted" => p with { SessionPolicyArns = null },
            "NativeAwsIamOptions.sessionPolicyArns.value" => p with { SessionPolicyArns = Value(p.SessionPolicyArns) },
            "NativeAwsIamOptions.sessionPolicyDocument.omitted" => p with { SessionPolicyDocument = null },
            "NativeAwsIamOptions.sessionPolicyDocument.value" => p with { SessionPolicyDocument = Value(p.SessionPolicyDocument) },
            "AwsIam.assume-role.sessionPolicyArns" => p with { SessionPolicyArns = Value(p.SessionPolicyArns) },
            "AwsIam.assume-role.sessionPolicyDocument" => p with { SessionPolicyDocument = Value(p.SessionPolicyDocument) },
            _ => throw new ArgumentException("Unknown AWS option variant.")
        };
    }

    private static void RequireAssumeRole(DynamicAwsIamInput input)
    {
        string[]? arn = input.RoleArn?.Split(':', 6);
        if (input.Authentication != DynamicAwsAuthentication.AssumeRole || input.AccessKey is not null ||
            input.SecretAccessKey is not null || arn is not { Length: 6 } || arn[0] != "arn" ||
            arn[1] is not ("aws" or "aws-cn" or "aws-us-gov") || arn[2] != "iam" || arn[3].Length != 0 ||
            arn[4].Length != 12 || arn[4].Any(c => c is < '0' or > '9') ||
            !arn[5].StartsWith("role/", StringComparison.Ordinal) || arn[5].Length <= 5 ||
            arn[5].Any(char.IsWhiteSpace))
            throw new ArgumentException("Session policy variants require explicitly selected assume-role authority and a valid role ARN.");
    }

    private static DynamicTailscaleOptionsInput Tailscale(string variant, string alternativeVariant, DynamicTailscaleOptionsInput? input)
    {
        bool flags = variant.StartsWith("NativeTailscaleOptions.reusable.", StringComparison.Ordinal) ||
            variant.StartsWith("NativeTailscaleOptions.preauthorized.", StringComparison.Ordinal);
        if (flags && !variant.EndsWith(".omitted", StringComparison.Ordinal) && alternativeVariant != "Tailscale.auth_keys.oauth" ||
            variant == "NativeTailscaleOptions.audience.value" &&
            alternativeVariant is not ("Tailscale.federated_keys.api_key" or "Tailscale.federated_keys.oauth"))
            throw new ArgumentException("Unsupported native Tailscale branch options.");
        var p = input ?? new();
        p = p with { Tags = p.Tags?.ToArray() };
        return variant switch
        {
            "NativeTailscaleOptions.tailnet.omitted" => p with { Tailnet = null },
            "NativeTailscaleOptions.tailnet.value" => p with { Tailnet = Value(p.Tailnet) },
            "NativeTailscaleOptions.tags.omitted" => p with { Tags = null },
            "NativeTailscaleOptions.tags.value" => p with { Tags = Items(p.Tags).ToArray() },
            "NativeTailscaleOptions.description.omitted" => p with { Description = null },
            "NativeTailscaleOptions.description.value" => p with { Description = Value(p.Description) },
            "NativeTailscaleOptions.audience.omitted" => p with { Audience = null },
            "NativeTailscaleOptions.audience.value" => p with { Audience = Value(p.Audience) },
            "NativeTailscaleOptions.reusable.omitted" => p with { Reusable = null },
            "NativeTailscaleOptions.reusable.false" => p with { Reusable = false },
            "NativeTailscaleOptions.reusable.true" => p with { Reusable = true },
            "NativeTailscaleOptions.preauthorized.omitted" => p with { Preauthorized = null },
            "NativeTailscaleOptions.preauthorized.false" => p with { Preauthorized = false },
            "NativeTailscaleOptions.preauthorized.true" => p with { Preauthorized = true },
            _ => throw new ArgumentException("Unknown Tailscale option variant.")
        };
    }

    private static DynamicMilvusPrivilegeInput[]? Privileges(DynamicMilvusPrivilegeInput[]? values) =>
        values?.Select(v => Required(v) with { }).ToArray();

    private static DynamicCouchbaseScopeInput[] Scopes(DynamicCouchbaseScopeInput[] values) =>
        values.Select(v =>
        {
            var scope = Required(v);
            return scope with { Collections = scope.Collections?.ToArray() };
        }).ToArray();

    private static DynamicAtlasRoleInput[] AtlasRoles(DynamicAtlasRoleInput[] values) =>
        Required(values).Select(v => Required(v) with { }).ToArray();

    private static DynamicAtlasScopeInput[] AtlasScopes(DynamicAtlasScopeInput[] values) =>
        Required(values).Select(v => Required(v) with { }).ToArray();

    private static T Required<T>(T? value) where T : class => value ?? throw new ArgumentException("Missing typed nested input.");
    private static string Value(string? value) => !string.IsNullOrEmpty(value) ? value :
        throw new ArgumentException("The selected option requires a configured value.");
    private static T[] Items<T>(T[]? values) => values is { Length: > 0 } ? values :
        throw new ArgumentException("The selected option requires caller-owned nonempty values.");
}
