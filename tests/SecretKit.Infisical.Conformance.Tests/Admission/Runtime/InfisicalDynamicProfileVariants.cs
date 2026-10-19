namespace SecretKit.Infisical.Conformance.Tests;

// Closed admission selectors only; construction and transport remain in the public SDK.
internal static class InfisicalDynamicProfileVariants
{
    internal static bool TryProvider(string variant, out InfisicalDynamicProvider provider)
    {
        InfisicalDynamicProvider? selected = variant switch
        {
            "NativeClickhouseDefinitionProfile.renewal.omitted" or
            "NativeClickhouseDefinitionProfile.renewal.value" or
            "NativeClickhouseDefinitionProfile.ca.omitted" or
            "NativeClickhouseDefinitionProfile.ca.value" or
            "NativeClickhouseDefinitionProfile.gateway.omitted" or
            "NativeClickhouseDefinitionProfile.gateway.value" or
            "NativeClickhouseDefinitionProfile.passwordRequirements.omitted" or
            "NativeClickhouseDefinitionProfile.passwordRequirements.value" => InfisicalDynamicProvider.Clickhouse,
            "NativeCassandraDefinitionProfile.keyspace.omitted" or
            "NativeCassandraDefinitionProfile.keyspace.value" or
            "NativeCassandraDefinitionProfile.renewal.omitted" or
            "NativeCassandraDefinitionProfile.renewal.value" or
            "NativeCassandraDefinitionProfile.ca.omitted" or
            "NativeCassandraDefinitionProfile.ca.value" => InfisicalDynamicProvider.Cassandra,
            "NativeSapHanaDefinitionProfile.renewal.omitted" or
            "NativeSapHanaDefinitionProfile.renewal.value" or
            "NativeSapHanaDefinitionProfile.ca.omitted" or
            "NativeSapHanaDefinitionProfile.ca.value" => InfisicalDynamicProvider.SapHana,
            "NativeRedisDefinitionProfile.password.omitted" or
            "NativeRedisDefinitionProfile.password.value" or
            "NativeRedisDefinitionProfile.renewal.omitted" or
            "NativeRedisDefinitionProfile.renewal.value" or
            "NativeRedisDefinitionProfile.ca.omitted" or
            "NativeRedisDefinitionProfile.ca.value" => InfisicalDynamicProvider.Redis,
            "NativeVerticaDefinitionProfile.gateway.omitted" or
            "NativeVerticaDefinitionProfile.gateway.value" or
            "NativeVerticaDefinitionProfile.passwordRequirements.omitted" or
            "NativeVerticaDefinitionProfile.passwordRequirements.value" => InfisicalDynamicProvider.Vertica,
            "NativeAzureSqlDefinitionProfile.masterDatabase.omitted" or
            "NativeAzureSqlDefinitionProfile.masterDatabase.value" or
            "NativeAzureSqlDefinitionProfile.renewal.omitted" or
            "NativeAzureSqlDefinitionProfile.renewal.value" or
            "NativeAzureSqlDefinitionProfile.ca.omitted" or
            "NativeAzureSqlDefinitionProfile.ca.value" or
            "NativeAzureSqlDefinitionProfile.gateway.omitted" or
            "NativeAzureSqlDefinitionProfile.gateway.value" or
            "NativeAzureSqlDefinitionProfile.passwordRequirements.omitted" or
            "NativeAzureSqlDefinitionProfile.passwordRequirements.value" or
            "NativeAzureSqlDefinitionProfile.sslEnabled.omitted" or
            "NativeAzureSqlDefinitionProfile.sslEnabled.false" or
            "NativeAzureSqlDefinitionProfile.sslEnabled.true" => InfisicalDynamicProvider.AzureSqlDatabase,
            "NativeSnowflakeDefinitionProfile.renewal.omitted" or
            "NativeSnowflakeDefinitionProfile.renewal.value" => InfisicalDynamicProvider.Snowflake,
            "NativeAwsIamDefinitionProfile.credentialKind.IamUser" or
            "NativeAwsIamDefinitionProfile.credentialKind.Temporary" or
            "NativeAwsIamDefinitionProfile.options.omitted" or
            "NativeAwsIamDefinitionProfile.options.value" => InfisicalDynamicProvider.AwsIam,
            "NativeGcpIamDefinitionProfile.tokenScopes.omitted" or
            "NativeGcpIamDefinitionProfile.tokenScopes.value" => InfisicalDynamicProvider.GcpIam,
            "NativeMilvusDefinitionProfile.database.omitted" or
            "NativeMilvusDefinitionProfile.database.value" or
            "NativeMilvusDefinitionProfile.ca.omitted" or
            "NativeMilvusDefinitionProfile.ca.value" or
            "NativeMilvusDefinitionProfile.gateway.omitted" or
            "NativeMilvusDefinitionProfile.gateway.value" or
            "NativeMilvusDefinitionProfile.privileges.omitted" or
            "NativeMilvusDefinitionProfile.privileges.value" => InfisicalDynamicProvider.Milvus,
            "NativeMongoDefinitionProfile.port.omitted" or
            "NativeMongoDefinitionProfile.port.value" or
            "NativeMongoDefinitionProfile.ca.omitted" or
            "NativeMongoDefinitionProfile.ca.value" or
            "NativeMongoDefinitionProfile.clearPort.false" or
            "NativeMongoDefinitionProfile.clearPort.true" or
            "NativeMongoDefinitionProfile.clearCa.false" or
            "NativeMongoDefinitionProfile.clearCa.true" or
            "MongoDb.port.omitted" or
            "MongoDb.port.null" or
            "MongoDb.port.value" or
            "MongoDb.ca.omitted" or
            "MongoDb.ca.null" or
            "MongoDb.ca.value" => InfisicalDynamicProvider.MongoDb,
            "NativeElasticsearchDefinitionProfile.ca.omitted" or
            "NativeElasticsearchDefinitionProfile.ca.value" or
            "ElasticSearch.user" => InfisicalDynamicProvider.ElasticSearch,
            "NativeRabbitDefinitionProfile.tags.omitted" or
            "NativeRabbitDefinitionProfile.tags.value" or
            "NativeRabbitDefinitionProfile.ca.omitted" or
            "NativeRabbitDefinitionProfile.ca.value" => InfisicalDynamicProvider.RabbitMq,
            "NativeKubernetesDefinitionProfile.clusterToken.omitted" or
            "NativeKubernetesDefinitionProfile.clusterToken.value" or
            "NativeKubernetesDefinitionProfile.url.omitted" or
            "NativeKubernetesDefinitionProfile.url.value" or
            "NativeKubernetesDefinitionProfile.ca.omitted" or
            "NativeKubernetesDefinitionProfile.ca.value" or
            "NativeKubernetesDefinitionProfile.authentication.Api" or
            "NativeKubernetesDefinitionProfile.authentication.Gateway" or
            "NativeKubernetesDefinitionProfile.authentication.omitted" or
            "NativeKubernetesDefinitionProfile.gateway.omitted" or
            "NativeKubernetesDefinitionProfile.gateway.value" or
            "NativeKubernetesDefinitionProfile.sslEnabled.omitted" or
            "NativeKubernetesDefinitionProfile.sslEnabled.false" or
            "NativeKubernetesDefinitionProfile.sslEnabled.true" or
            "Kubernetes.dynamic-role" or
            "Kubernetes.dynamic-cluster-role" or
            "Kubernetes.auth.omitted" or
            "Kubernetes.auth.Api" or
            "Kubernetes.auth.Gateway" => InfisicalDynamicProvider.Kubernetes,
            "NativeLdapDefinitionProfile.rollbackLdif.omitted" or
            "NativeLdapDefinitionProfile.rollbackLdif.value" or
            "NativeLdapDefinitionProfile.ca.omitted" or
            "NativeLdapDefinitionProfile.ca.value" or
            "Ldap.dynamic" => InfisicalDynamicProvider.Ldap,
            "NativeSshDefinitionProfile.keyAlgorithm.Rsa2048" or
            "NativeSshDefinitionProfile.keyAlgorithm.Rsa4096" or
            "NativeSshDefinitionProfile.keyAlgorithm.EcPrime256v1" or
            "NativeSshDefinitionProfile.keyAlgorithm.EcSecp384r1" or
            "NativeSshDefinitionProfile.keyAlgorithm.Ed25519" or
            "NativeSshDefinitionProfile.keyAlgorithm.omitted" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa2048" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa4096" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.EcPrime256v1" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.EcSecp384r1" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.Ed25519" or
            "NativeSshDefinitionProfile.caKeyAlgorithm.omitted" or
            "Ssh.keyAlgorithm.Rsa2048" or
            "Ssh.keyAlgorithm.Rsa4096" or
            "Ssh.keyAlgorithm.EcPrime256v1" or
            "Ssh.keyAlgorithm.EcSecp384r1" or
            "Ssh.keyAlgorithm.Ed25519" or
            "Ssh.caKeyAlgorithm.Rsa2048" or
            "Ssh.caKeyAlgorithm.Rsa4096" or
            "Ssh.caKeyAlgorithm.EcPrime256v1" or
            "Ssh.caKeyAlgorithm.EcSecp384r1" or
            "Ssh.caKeyAlgorithm.Ed25519" or
            "Ssh.algorithms.omitted" => InfisicalDynamicProvider.Ssh,
            "NativeIbmApiDefinitionProfile.gateway.omitted" or
            "NativeIbmApiDefinitionProfile.gateway.value" => InfisicalDynamicProvider.IbmApiConnect,
            "NativeOauthDefinitionProfile.scope.omitted" or
            "NativeOauthDefinitionProfile.scope.value" or
            "NativeOauthDefinitionProfile.extraParameters.omitted" or
            "NativeOauthDefinitionProfile.extraParameters.value" or
            "Oauth2.Basic" or
            "Oauth2.Post" => InfisicalDynamicProvider.Oauth2,
            "NativeTailscaleDefinitionProfile.tailnet.omitted" or
            "NativeTailscaleDefinitionProfile.tailnet.value" or
            "NativeTailscaleDefinitionProfile.reusable.false" or
            "NativeTailscaleDefinitionProfile.reusable.true" or
            "NativeTailscaleDefinitionProfile.preauthorized.false" or
            "NativeTailscaleDefinitionProfile.preauthorized.true" or
            "NativeTailscaleDefinitionProfile.tags.omitted" or
            "NativeTailscaleDefinitionProfile.tags.value" or
            "NativeTailscaleDefinitionProfile.description.omitted" or
            "NativeTailscaleDefinitionProfile.description.value" or
            "Tailscale.auth_keys.api_key" => InfisicalDynamicProvider.Tailscale,
            "NativeCouchbaseDefinitionProfile.buckets.omitted" or
            "NativeCouchbaseDefinitionProfile.buckets.value" or
            "Couchbase.buckets.text" or "Couchbase.buckets.objects" or
            "NativeCouchbaseDefinitionProfile.passwordRequirements.omitted" or
            "NativeCouchbaseDefinitionProfile.passwordRequirements.value" => InfisicalDynamicProvider.Couchbase,
            "Totp.url" => InfisicalDynamicProvider.Totp,
            _ => null
        };
        provider = selected.GetValueOrDefault();
        return selected.HasValue;
    }

    internal static InfisicalDynamicProfileInput Select(string variant, InfisicalDynamicProfileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!TryProvider(variant, out var provider)) throw new ArgumentException("Unknown profile variant.");
        int selections =
            (input.Clickhouse is null ? 0 : 1) +
            (input.Cassandra is null ? 0 : 1) +
            (input.SapAse is null ? 0 : 1) +
            (input.SapHana is null ? 0 : 1) +
            (input.Redis is null ? 0 : 1) +
            (input.Vertica is null ? 0 : 1) +
            (input.AzureSqlDatabase is null ? 0 : 1) +
            (input.Snowflake is null ? 0 : 1) +
            (input.AwsIam is null ? 0 : 1) +
            (input.AwsElasticache is null ? 0 : 1) +
            (input.AwsMemorydb is null ? 0 : 1) +
            (input.AzureEntraId is null ? 0 : 1) +
            (input.GcpIam is null ? 0 : 1) +
            (input.Github is null ? 0 : 1) +
            (input.Milvus is null ? 0 : 1) +
            (input.MongoDb is null ? 0 : 1) +
            (input.ElasticSearch is null ? 0 : 1) +
            (input.RabbitMq is null ? 0 : 1) +
            (input.Kubernetes is null ? 0 : 1) +
            (input.Ldap is null ? 0 : 1) +
            (input.Totp is null ? 0 : 1) +
            (input.Ssh is null ? 0 : 1) +
            (input.IbmApiConnect is null ? 0 : 1) +
            (input.Oauth2 is null ? 0 : 1) +
            (input.Tailscale is null ? 0 : 1) +
            (input.Couchbase is null ? 0 : 1) +
            (input.MongoDbAtlas is null ? 0 : 1);
        if (selections != 1) throw new ArgumentException("Exactly one typed profile input is required.");
        // Copy mutable containers at the selection boundary, before any SDK construction.
        var snapshot = provider switch
        {
            InfisicalDynamicProvider.Clickhouse when input.Clickhouse is { } p =>
                input with { Clickhouse = p with { } },
            InfisicalDynamicProvider.Cassandra when input.Cassandra is { } p =>
                input with { Cassandra = p with { } },
            InfisicalDynamicProvider.SapHana when input.SapHana is { } p =>
                input with { SapHana = p with { } },
            InfisicalDynamicProvider.Redis when input.Redis is { } p =>
                input with { Redis = p with { } },
            InfisicalDynamicProvider.Vertica when input.Vertica is { } p =>
                input with { Vertica = p with { } },
            InfisicalDynamicProvider.AzureSqlDatabase when input.AzureSqlDatabase is { } p =>
                input with { AzureSqlDatabase = p with { } },
            InfisicalDynamicProvider.Snowflake when input.Snowflake is { } p =>
                input with { Snowflake = p with { } },
            InfisicalDynamicProvider.AwsIam when input.AwsIam is { } p =>
                input with { AwsIam = p with { Options = p.Options is null ? null : p.Options with { Tags = p.Options.Tags?.Select(v => v with { }).ToArray() } } },
            InfisicalDynamicProvider.GcpIam when input.GcpIam is { } p =>
                input with { GcpIam = p with { TokenScopes = p.TokenScopes?.ToArray() } },
            InfisicalDynamicProvider.Milvus when input.Milvus is { } p =>
                input with { Milvus = p with { Privileges = p.Privileges?.Select(v => v with { }).ToArray() } },
            InfisicalDynamicProvider.MongoDb when input.MongoDb is { } p =>
                input with { MongoDb = p with { Roles = p.Roles.ToArray() } },
            InfisicalDynamicProvider.ElasticSearch when input.ElasticSearch is { } p =>
                input with { ElasticSearch = p with { Roles = p.Roles.ToArray() } },
            InfisicalDynamicProvider.RabbitMq when input.RabbitMq is { } p =>
                input with { RabbitMq = p with { Tags = p.Tags?.ToArray() } },
            InfisicalDynamicProvider.Kubernetes when input.Kubernetes is { } p =>
                input with { Kubernetes = p with { Audiences = p.Audiences.ToArray() } },
            InfisicalDynamicProvider.Ldap when input.Ldap is { } p =>
                input with { Ldap = p with { } },
            InfisicalDynamicProvider.Ssh when input.Ssh is { } p =>
                input with { Ssh = p with { Principals = p.Principals.ToArray() } },
            InfisicalDynamicProvider.IbmApiConnect when input.IbmApiConnect is { } p =>
                input with { IbmApiConnect = p with { } },
            InfisicalDynamicProvider.Oauth2 when input.Oauth2 is { } p =>
                input with { Oauth2 = p with { ExtraParameters = p.ExtraParameters?.Select(v => v with { }).ToArray() } },
            InfisicalDynamicProvider.Tailscale when input.Tailscale is { } p =>
                input with { Tailscale = p with { Tags = p.Tags?.ToArray() } },
            InfisicalDynamicProvider.Couchbase when input.Couchbase is { } p =>
                input with
                {
                    Couchbase = p with
                    {
                        Roles = p.Roles.ToArray(),
                        Buckets = p.Buckets is null ? null : p.Buckets with
                        {
                            Buckets = p.Buckets.Buckets?.Select(b => b with
                            {
                                Scopes = b.Scopes?.Select(s => s with { Collections = s.Collections?.ToArray() }).ToArray()
                            }).ToArray()
                        }
                    }
                },
            InfisicalDynamicProvider.Totp when input.Totp is { } p =>
                input with { Totp = p with { } },
            _ => throw new ArgumentException("Missing or mismatched typed profile input.")
        };
        return variant switch
        {
            "NativeClickhouseDefinitionProfile.renewal.omitted" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Renewal = null }
            },
            "NativeClickhouseDefinitionProfile.renewal.value" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Renewal = snapshot.Clickhouse!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeClickhouseDefinitionProfile.ca.omitted" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Ca = null }
            },
            "NativeClickhouseDefinitionProfile.ca.value" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Ca = snapshot.Clickhouse!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeClickhouseDefinitionProfile.gateway.omitted" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Gateway = null }
            },
            "NativeClickhouseDefinitionProfile.gateway.value" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { Gateway = snapshot.Clickhouse!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeClickhouseDefinitionProfile.passwordRequirements.omitted" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { PasswordRequirements = null }
            },
            "NativeClickhouseDefinitionProfile.passwordRequirements.value" => snapshot with
            {
                Clickhouse = snapshot.Clickhouse! with { PasswordRequirements = snapshot.Clickhouse!.PasswordRequirements ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeCassandraDefinitionProfile.keyspace.omitted" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Keyspace = null }
            },
            "NativeCassandraDefinitionProfile.keyspace.value" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Keyspace = snapshot.Cassandra!.Keyspace ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeCassandraDefinitionProfile.renewal.omitted" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Renewal = null }
            },
            "NativeCassandraDefinitionProfile.renewal.value" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Renewal = snapshot.Cassandra!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeCassandraDefinitionProfile.ca.omitted" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Ca = null }
            },
            "NativeCassandraDefinitionProfile.ca.value" => snapshot with
            {
                Cassandra = snapshot.Cassandra! with { Ca = snapshot.Cassandra!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeSapHanaDefinitionProfile.renewal.omitted" => snapshot with
            {
                SapHana = snapshot.SapHana! with { Renewal = null }
            },
            "NativeSapHanaDefinitionProfile.renewal.value" => snapshot with
            {
                SapHana = snapshot.SapHana! with { Renewal = snapshot.SapHana!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeSapHanaDefinitionProfile.ca.omitted" => snapshot with
            {
                SapHana = snapshot.SapHana! with { Ca = null }
            },
            "NativeSapHanaDefinitionProfile.ca.value" => snapshot with
            {
                SapHana = snapshot.SapHana! with { Ca = snapshot.SapHana!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeRedisDefinitionProfile.password.omitted" => snapshot with
            {
                Redis = snapshot.Redis! with { Password = null }
            },
            "NativeRedisDefinitionProfile.password.value" => snapshot with
            {
                Redis = snapshot.Redis! with { Password = snapshot.Redis!.Password ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeRedisDefinitionProfile.renewal.omitted" => snapshot with
            {
                Redis = snapshot.Redis! with { Renewal = null }
            },
            "NativeRedisDefinitionProfile.renewal.value" => snapshot with
            {
                Redis = snapshot.Redis! with { Renewal = snapshot.Redis!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeRedisDefinitionProfile.ca.omitted" => snapshot with
            {
                Redis = snapshot.Redis! with { Ca = null }
            },
            "NativeRedisDefinitionProfile.ca.value" => snapshot with
            {
                Redis = snapshot.Redis! with { Ca = snapshot.Redis!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeVerticaDefinitionProfile.gateway.omitted" => snapshot with
            {
                Vertica = snapshot.Vertica! with { Gateway = null }
            },
            "NativeVerticaDefinitionProfile.gateway.value" => snapshot with
            {
                Vertica = snapshot.Vertica! with { Gateway = snapshot.Vertica!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeVerticaDefinitionProfile.passwordRequirements.omitted" => snapshot with
            {
                Vertica = snapshot.Vertica! with { PasswordRequirements = null }
            },
            "NativeVerticaDefinitionProfile.passwordRequirements.value" => snapshot with
            {
                Vertica = snapshot.Vertica! with { PasswordRequirements = snapshot.Vertica!.PasswordRequirements ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.masterDatabase.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { MasterDatabase = null }
            },
            "NativeAzureSqlDefinitionProfile.masterDatabase.value" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { MasterDatabase = snapshot.AzureSqlDatabase!.MasterDatabase ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.renewal.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Renewal = null }
            },
            "NativeAzureSqlDefinitionProfile.renewal.value" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Renewal = snapshot.AzureSqlDatabase!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.ca.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Ca = null }
            },
            "NativeAzureSqlDefinitionProfile.ca.value" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Ca = snapshot.AzureSqlDatabase!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.gateway.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Gateway = null }
            },
            "NativeAzureSqlDefinitionProfile.gateway.value" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { Gateway = snapshot.AzureSqlDatabase!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.passwordRequirements.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { PasswordRequirements = null }
            },
            "NativeAzureSqlDefinitionProfile.passwordRequirements.value" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { PasswordRequirements = snapshot.AzureSqlDatabase!.PasswordRequirements ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAzureSqlDefinitionProfile.sslEnabled.omitted" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { SslEnabled = null }
            },
            "NativeAzureSqlDefinitionProfile.sslEnabled.false" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { SslEnabled = false }
            },
            "NativeAzureSqlDefinitionProfile.sslEnabled.true" => snapshot with
            {
                AzureSqlDatabase = snapshot.AzureSqlDatabase! with { SslEnabled = true }
            },
            "NativeSnowflakeDefinitionProfile.renewal.omitted" => snapshot with
            {
                Snowflake = snapshot.Snowflake! with { Renewal = null }
            },
            "NativeSnowflakeDefinitionProfile.renewal.value" => snapshot with
            {
                Snowflake = snapshot.Snowflake! with { Renewal = snapshot.Snowflake!.Renewal ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeAwsIamDefinitionProfile.credentialKind.IamUser" => snapshot with
            {
                AwsIam = snapshot.AwsIam! with { CredentialKind = NativeAwsCredentialKind.IamUser }
            },
            "NativeAwsIamDefinitionProfile.credentialKind.Temporary" => snapshot with
            {
                AwsIam = snapshot.AwsIam! with { CredentialKind = NativeAwsCredentialKind.Temporary }
            },
            "NativeAwsIamDefinitionProfile.options.omitted" => snapshot with
            {
                AwsIam = snapshot.AwsIam! with { Options = null }
            },
            "NativeAwsIamDefinitionProfile.options.value" => snapshot with
            {
                AwsIam = snapshot.AwsIam! with { Options = snapshot.AwsIam!.Options ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeGcpIamDefinitionProfile.tokenScopes.omitted" => snapshot with
            {
                GcpIam = snapshot.GcpIam! with { TokenScopes = null }
            },
            "NativeGcpIamDefinitionProfile.tokenScopes.value" => snapshot with
            {
                GcpIam = snapshot.GcpIam! with { TokenScopes = snapshot.GcpIam!.TokenScopes ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeMilvusDefinitionProfile.database.omitted" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Database = null }
            },
            "NativeMilvusDefinitionProfile.database.value" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Database = snapshot.Milvus!.Database ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeMilvusDefinitionProfile.ca.omitted" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Ca = null }
            },
            "NativeMilvusDefinitionProfile.ca.value" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Ca = snapshot.Milvus!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeMilvusDefinitionProfile.gateway.omitted" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Gateway = null }
            },
            "NativeMilvusDefinitionProfile.gateway.value" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Gateway = snapshot.Milvus!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeMilvusDefinitionProfile.privileges.omitted" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Privileges = null }
            },
            "NativeMilvusDefinitionProfile.privileges.value" => snapshot with
            {
                Milvus = snapshot.Milvus! with { Privileges = snapshot.Milvus!.Privileges ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeMongoDefinitionProfile.port.omitted" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Port = null, ClearPort = false }
            },
            "NativeMongoDefinitionProfile.port.value" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Port = snapshot.MongoDb!.Port ?? throw new ArgumentException("Selected optional value is required."), ClearPort = false }
            },
            "NativeMongoDefinitionProfile.ca.omitted" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Ca = null, ClearCa = false }
            },
            "NativeMongoDefinitionProfile.ca.value" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Ca = snapshot.MongoDb!.Ca ?? throw new ArgumentException("Selected optional value is required."), ClearCa = false }
            },
            "NativeMongoDefinitionProfile.clearPort.false" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { ClearPort = false }
            },
            "NativeMongoDefinitionProfile.clearPort.true" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { ClearPort = true, Port = null }
            },
            "NativeMongoDefinitionProfile.clearCa.false" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { ClearCa = false }
            },
            "NativeMongoDefinitionProfile.clearCa.true" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { ClearCa = true, Ca = null }
            },
            "NativeElasticsearchDefinitionProfile.ca.omitted" => snapshot with
            {
                ElasticSearch = snapshot.ElasticSearch! with { Ca = null }
            },
            "NativeElasticsearchDefinitionProfile.ca.value" => snapshot with
            {
                ElasticSearch = snapshot.ElasticSearch! with { Ca = snapshot.ElasticSearch!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeRabbitDefinitionProfile.tags.omitted" => snapshot with
            {
                RabbitMq = snapshot.RabbitMq! with { Tags = null }
            },
            "NativeRabbitDefinitionProfile.tags.value" => snapshot with
            {
                RabbitMq = snapshot.RabbitMq! with { Tags = snapshot.RabbitMq!.Tags ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeRabbitDefinitionProfile.ca.omitted" => snapshot with
            {
                RabbitMq = snapshot.RabbitMq! with { Ca = null }
            },
            "NativeRabbitDefinitionProfile.ca.value" => snapshot with
            {
                RabbitMq = snapshot.RabbitMq! with { Ca = snapshot.RabbitMq!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeKubernetesDefinitionProfile.clusterToken.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { ClusterToken = null }
            },
            "NativeKubernetesDefinitionProfile.clusterToken.value" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { ClusterToken = snapshot.Kubernetes!.ClusterToken ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeKubernetesDefinitionProfile.url.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Url = null }
            },
            "NativeKubernetesDefinitionProfile.url.value" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Url = snapshot.Kubernetes!.Url ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeKubernetesDefinitionProfile.ca.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Ca = null }
            },
            "NativeKubernetesDefinitionProfile.ca.value" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Ca = snapshot.Kubernetes!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeKubernetesDefinitionProfile.authentication.Api" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = NativeKubernetesAuthentication.Api }
            },
            "NativeKubernetesDefinitionProfile.authentication.Gateway" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = NativeKubernetesAuthentication.Gateway }
            },
            "NativeKubernetesDefinitionProfile.authentication.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = null }
            },
            "NativeKubernetesDefinitionProfile.gateway.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Gateway = null }
            },
            "NativeKubernetesDefinitionProfile.gateway.value" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Gateway = snapshot.Kubernetes!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeKubernetesDefinitionProfile.sslEnabled.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { SslEnabled = null }
            },
            "NativeKubernetesDefinitionProfile.sslEnabled.false" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { SslEnabled = false }
            },
            "NativeKubernetesDefinitionProfile.sslEnabled.true" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { SslEnabled = true }
            },
            "NativeLdapDefinitionProfile.rollbackLdif.omitted" => snapshot with
            {
                Ldap = snapshot.Ldap! with { RollbackLdif = null }
            },
            "NativeLdapDefinitionProfile.rollbackLdif.value" => snapshot with
            {
                Ldap = snapshot.Ldap! with { RollbackLdif = snapshot.Ldap!.RollbackLdif ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeLdapDefinitionProfile.ca.omitted" => snapshot with
            {
                Ldap = snapshot.Ldap! with { Ca = null }
            },
            "NativeLdapDefinitionProfile.ca.value" => snapshot with
            {
                Ldap = snapshot.Ldap! with { Ca = snapshot.Ldap!.Ca ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.Rsa2048" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Rsa2048 }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.Rsa4096" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Rsa4096 }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.EcPrime256v1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.EcPrime256v1 }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.EcSecp384r1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.EcSecp384r1 }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.Ed25519" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Ed25519 }
            },
            "NativeSshDefinitionProfile.keyAlgorithm.omitted" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = null }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa2048" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Rsa2048 }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa4096" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Rsa4096 }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.EcPrime256v1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.EcPrime256v1 }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.EcSecp384r1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.EcSecp384r1 }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.Ed25519" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Ed25519 }
            },
            "NativeSshDefinitionProfile.caKeyAlgorithm.omitted" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = null }
            },
            "NativeIbmApiDefinitionProfile.gateway.omitted" => snapshot with
            {
                IbmApiConnect = snapshot.IbmApiConnect! with { Gateway = null }
            },
            "NativeIbmApiDefinitionProfile.gateway.value" => snapshot with
            {
                IbmApiConnect = snapshot.IbmApiConnect! with { Gateway = snapshot.IbmApiConnect!.Gateway ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeOauthDefinitionProfile.scope.omitted" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { Scope = null }
            },
            "NativeOauthDefinitionProfile.scope.value" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { Scope = snapshot.Oauth2!.Scope ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeOauthDefinitionProfile.extraParameters.omitted" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { ExtraParameters = null }
            },
            "NativeOauthDefinitionProfile.extraParameters.value" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { ExtraParameters = snapshot.Oauth2!.ExtraParameters ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeTailscaleDefinitionProfile.tailnet.omitted" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Tailnet = null }
            },
            "NativeTailscaleDefinitionProfile.tailnet.value" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Tailnet = snapshot.Tailscale!.Tailnet ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeTailscaleDefinitionProfile.reusable.false" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Reusable = false }
            },
            "NativeTailscaleDefinitionProfile.reusable.true" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Reusable = true }
            },
            "NativeTailscaleDefinitionProfile.preauthorized.false" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Preauthorized = false }
            },
            "NativeTailscaleDefinitionProfile.preauthorized.true" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Preauthorized = true }
            },
            "NativeTailscaleDefinitionProfile.tags.omitted" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Tags = null }
            },
            "NativeTailscaleDefinitionProfile.tags.value" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Tags = snapshot.Tailscale!.Tags ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeTailscaleDefinitionProfile.description.omitted" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Description = null }
            },
            "NativeTailscaleDefinitionProfile.description.value" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { Description = snapshot.Tailscale!.Description ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "NativeCouchbaseDefinitionProfile.buckets.omitted" => snapshot with
            {
                Couchbase = snapshot.Couchbase! with { Buckets = null }
            },
            "NativeCouchbaseDefinitionProfile.buckets.value" => snapshot with
            {
                Couchbase = snapshot.Couchbase! with { Buckets = snapshot.Couchbase!.Buckets ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "Couchbase.buckets.text" when snapshot.Couchbase!.Buckets is { Text: not null, Buckets: null } => snapshot,
            "Couchbase.buckets.objects" when snapshot.Couchbase!.Buckets is { Text: null, Buckets: not null } => snapshot,
            "NativeCouchbaseDefinitionProfile.passwordRequirements.omitted" => snapshot with
            {
                Couchbase = snapshot.Couchbase! with { PasswordRequirements = null }
            },
            "NativeCouchbaseDefinitionProfile.passwordRequirements.value" => snapshot with
            {
                Couchbase = snapshot.Couchbase! with { PasswordRequirements = snapshot.Couchbase!.PasswordRequirements ?? throw new ArgumentException("Selected optional value is required.") }
            },
            "Ssh.keyAlgorithm.Rsa2048" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Rsa2048 }
            },
            "Ssh.keyAlgorithm.Rsa4096" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Rsa4096 }
            },
            "Ssh.keyAlgorithm.EcPrime256v1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.EcPrime256v1 }
            },
            "Ssh.keyAlgorithm.EcSecp384r1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.EcSecp384r1 }
            },
            "Ssh.keyAlgorithm.Ed25519" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = NativeSshKeyAlgorithm.Ed25519 }
            },
            "Ssh.caKeyAlgorithm.Rsa2048" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Rsa2048 }
            },
            "Ssh.caKeyAlgorithm.Rsa4096" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Rsa4096 }
            },
            "Ssh.caKeyAlgorithm.EcPrime256v1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.EcPrime256v1 }
            },
            "Ssh.caKeyAlgorithm.EcSecp384r1" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.EcSecp384r1 }
            },
            "Ssh.caKeyAlgorithm.Ed25519" => snapshot with
            {
                Ssh = snapshot.Ssh! with { CaKeyAlgorithm = NativeSshKeyAlgorithm.Ed25519 }
            },
            "Ssh.algorithms.omitted" => snapshot with
            {
                Ssh = snapshot.Ssh! with { KeyAlgorithm = null, CaKeyAlgorithm = null }
            },
            "MongoDb.port.omitted" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Port = null, ClearPort = false }
            },
            "MongoDb.port.null" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Port = null, ClearPort = true }
            },
            "MongoDb.port.value" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Port = snapshot.MongoDb!.Port ?? throw new ArgumentException("Selected optional value is required."), ClearPort = false }
            },
            "MongoDb.ca.omitted" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Ca = null, ClearCa = false }
            },
            "MongoDb.ca.null" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Ca = null, ClearCa = true }
            },
            "MongoDb.ca.value" => snapshot with
            {
                MongoDb = snapshot.MongoDb! with { Ca = snapshot.MongoDb!.Ca ?? throw new ArgumentException("Selected optional value is required."), ClearCa = false }
            },
            "Oauth2.Basic" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { Method = NativeOauthClientAuthentication.Basic }
            },
            "Oauth2.Post" => snapshot with
            {
                Oauth2 = snapshot.Oauth2! with { Method = NativeOauthClientAuthentication.Post }
            },
            "Kubernetes.dynamic-role" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { ClusterRole = false }
            },
            "Kubernetes.dynamic-cluster-role" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { ClusterRole = true }
            },
            "Kubernetes.auth.omitted" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = null }
            },
            "Kubernetes.auth.Api" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = NativeKubernetesAuthentication.Api }
            },
            "Kubernetes.auth.Gateway" => snapshot with
            {
                Kubernetes = snapshot.Kubernetes! with { Authentication = NativeKubernetesAuthentication.Gateway }
            },
            "ElasticSearch.user" => snapshot with
            {
                ElasticSearch = snapshot.ElasticSearch! with { }
            },
            "Ldap.dynamic" => snapshot with
            {
                Ldap = snapshot.Ldap! with { }
            },
            "Totp.url" => snapshot with
            {
                Totp = snapshot.Totp! with { }
            },
            "Tailscale.auth_keys.api_key" => snapshot with
            {
                Tailscale = snapshot.Tailscale! with { }
            },
            _ => throw new ArgumentException("Unknown profile variant.")
        };
    }
}
