using System.Diagnostics.Tracing;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static partial class InfisicalLifecycleFamilies
{
    internal static LifecycleAdmission[] Catalog { get; } =
    [
        new("i.runtime.InfisicalDynamicClient.AcquireDatabaseAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.AcquireDatabaseAsync(SecretKit.Infisical.InfisicalDynamicDefinition,SecretKit.Infisical.InfisicalDynamicMutationReceipt,SecretKit.Infisical.InfisicalLeaseDuration,System.Threading.CancellationToken)",
            [
                "ttl.omitted",
                "ttl.value",
                "SqlDatabase.engine.Postgres",
                "SqlDatabase.engine.Mysql",
                "SqlDatabase.engine.Oracle",
                "SqlDatabase.engine.SqlServer",
                "SqlDatabase.engine.SapAse",
                "SqlDatabase.engine.Vertica",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.CreateDefinitionAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.CreateDefinitionAsync(SecretKit.Infisical.InfisicalDynamicTarget,SecretKit.Infisical.InfisicalDynamicProfile,SecretKit.Infisical.InfisicalLeaseDuration,SecretKit.Infisical.InfisicalLeaseDuration,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Threading.CancellationToken,SecretKit.Infisical.NativeDynamicDefinitionOptions)",
            [
                "options.omitted",
                "options.value",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
                "SqlDatabase.engine.Postgres",
                "SqlDatabase.engine.Mysql",
                "SqlDatabase.engine.Oracle",
                "SqlDatabase.engine.SqlServer",
                "SqlDatabase.engine.SapAse",
                "SqlDatabase.engine.Vertica",
                "AwsIam.access-key.IamUser",
                "AwsIam.access-key.Temporary",
                "AwsIam.assume-role.IamUser",
                "AwsIam.assume-role.Temporary",
                "AwsIam.irsa.IamUser",
                "AwsIam.irsa.Temporary",
                "ElasticSearch.user",
                "ElasticSearch.api-key",
                "Kubernetes.static-account",
                "Kubernetes.dynamic-role",
                "Kubernetes.dynamic-cluster-role",
                "Kubernetes.auth.omitted",
                "Kubernetes.auth.Api",
                "Kubernetes.auth.Gateway",
                "Ldap.static-account",
                "Ldap.dynamic",
                "Totp.url",
                "Totp.manual.Sha1",
                "Totp.manual.Sha256",
                "Totp.manual.Sha512",
                "Tailscale.auth_keys.api_key",
                "Tailscale.auth_keys.oauth",
                "Tailscale.oauth_keys.api_key",
                "Tailscale.oauth_keys.oauth",
                "Tailscale.federated_keys.api_key",
                "Tailscale.federated_keys.oauth",
                "Oauth2.Basic",
                "Oauth2.Post",
                "Couchbase.buckets.text",
                "Couchbase.buckets.objects",
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
                "maximumTtl.omitted",
                "maximumTtl.value",
                "usernameTemplate.omitted",
                "usernameTemplate.value",
                "metadata.omitted",
                "metadata.empty",
                "metadata.value",
                "gatewayId.omitted",
                "gatewayId.value",
                "gatewayId.null",
                "gatewayPoolId.omitted",
                "gatewayPoolId.value",
                "gatewayPoolId.null",
                "MongoDb.port.omitted",
                "MongoDb.port.null",
                "MongoDb.port.value",
                "MongoDb.ca.omitted",
                "MongoDb.ca.null",
                "MongoDb.ca.value",
                "sql.sslEnabled.omitted",
                "sql.sslEnabled.false",
                "sql.sslEnabled.true",
                "sql.ca.omitted",
                "sql.ca.value",
                "sql.renewStatement.omitted",
                "sql.renewStatement.value",
                "passwordRequirements.omitted",
                "passwordRequirements.value",
                "NativeSqlDefinitionProfile.renewalStatement.omitted",
                "NativeSqlDefinitionProfile.renewalStatement.value",
                "NativeSqlDefinitionProfile.ca.omitted",
                "NativeSqlDefinitionProfile.ca.value",
                "NativeSqlDefinitionProfile.sslEnabled.omitted",
                "NativeSqlDefinitionProfile.sslEnabled.false",
                "NativeSqlDefinitionProfile.sslEnabled.true",
                "NativeSqlDefinitionProfile.gatewayId.omitted",
                "NativeSqlDefinitionProfile.gatewayId.value",
                "NativeSqlDefinitionProfile.gatewayPoolId.omitted",
                "NativeSqlDefinitionProfile.gatewayPoolId.value",
                "NativeSqlDefinitionProfile.passwordRequirements.omitted",
                "NativeSqlDefinitionProfile.passwordRequirements.value",
                "NativeSqlDefinitionProfile.clearGatewayId.false",
                "NativeSqlDefinitionProfile.clearGatewayId.true",
                "NativeSqlDefinitionProfile.clearGatewayPoolId.false",
                "NativeSqlDefinitionProfile.clearGatewayPoolId.true",
                "NativeClickhouseDefinitionProfile.renewal.omitted",
                "NativeClickhouseDefinitionProfile.renewal.value",
                "NativeClickhouseDefinitionProfile.ca.omitted",
                "NativeClickhouseDefinitionProfile.ca.value",
                "NativeClickhouseDefinitionProfile.gateway.omitted",
                "NativeClickhouseDefinitionProfile.gateway.value",
                "NativeClickhouseDefinitionProfile.passwordRequirements.omitted",
                "NativeClickhouseDefinitionProfile.passwordRequirements.value",
                "NativeCassandraDefinitionProfile.keyspace.omitted",
                "NativeCassandraDefinitionProfile.keyspace.value",
                "NativeCassandraDefinitionProfile.renewal.omitted",
                "NativeCassandraDefinitionProfile.renewal.value",
                "NativeCassandraDefinitionProfile.ca.omitted",
                "NativeCassandraDefinitionProfile.ca.value",
                "NativeSapHanaDefinitionProfile.renewal.omitted",
                "NativeSapHanaDefinitionProfile.renewal.value",
                "NativeSapHanaDefinitionProfile.ca.omitted",
                "NativeSapHanaDefinitionProfile.ca.value",
                "NativeRedisDefinitionProfile.password.omitted",
                "NativeRedisDefinitionProfile.password.value",
                "NativeRedisDefinitionProfile.renewal.omitted",
                "NativeRedisDefinitionProfile.renewal.value",
                "NativeRedisDefinitionProfile.ca.omitted",
                "NativeRedisDefinitionProfile.ca.value",
                "NativeVerticaDefinitionProfile.gateway.omitted",
                "NativeVerticaDefinitionProfile.gateway.value",
                "NativeVerticaDefinitionProfile.passwordRequirements.omitted",
                "NativeVerticaDefinitionProfile.passwordRequirements.value",
                "NativeAzureSqlDefinitionProfile.masterDatabase.omitted",
                "NativeAzureSqlDefinitionProfile.masterDatabase.value",
                "NativeAzureSqlDefinitionProfile.renewal.omitted",
                "NativeAzureSqlDefinitionProfile.renewal.value",
                "NativeAzureSqlDefinitionProfile.ca.omitted",
                "NativeAzureSqlDefinitionProfile.ca.value",
                "NativeAzureSqlDefinitionProfile.gateway.omitted",
                "NativeAzureSqlDefinitionProfile.gateway.value",
                "NativeAzureSqlDefinitionProfile.passwordRequirements.omitted",
                "NativeAzureSqlDefinitionProfile.passwordRequirements.value",
                "NativeAzureSqlDefinitionProfile.sslEnabled.omitted",
                "NativeAzureSqlDefinitionProfile.sslEnabled.false",
                "NativeAzureSqlDefinitionProfile.sslEnabled.true",
                "NativeSnowflakeDefinitionProfile.renewal.omitted",
                "NativeSnowflakeDefinitionProfile.renewal.value",
                "NativeAwsIamDefinitionProfile.credentialKind.IamUser",
                "NativeAwsIamDefinitionProfile.credentialKind.Temporary",
                "NativeAwsIamDefinitionProfile.options.omitted",
                "NativeAwsIamDefinitionProfile.options.value",
                "NativeGcpIamDefinitionProfile.tokenScopes.omitted",
                "NativeGcpIamDefinitionProfile.tokenScopes.value",
                "NativeMilvusDefinitionProfile.database.omitted",
                "NativeMilvusDefinitionProfile.database.value",
                "NativeMilvusDefinitionProfile.ca.omitted",
                "NativeMilvusDefinitionProfile.ca.value",
                "NativeMilvusDefinitionProfile.gateway.omitted",
                "NativeMilvusDefinitionProfile.gateway.value",
                "NativeMilvusDefinitionProfile.privileges.omitted",
                "NativeMilvusDefinitionProfile.privileges.value",
                "NativeMongoDefinitionProfile.port.omitted",
                "NativeMongoDefinitionProfile.port.value",
                "NativeMongoDefinitionProfile.ca.omitted",
                "NativeMongoDefinitionProfile.ca.value",
                "NativeMongoDefinitionProfile.clearPort.false",
                "NativeMongoDefinitionProfile.clearPort.true",
                "NativeMongoDefinitionProfile.clearCa.false",
                "NativeMongoDefinitionProfile.clearCa.true",
                "NativeElasticsearchDefinitionProfile.ca.omitted",
                "NativeElasticsearchDefinitionProfile.ca.value",
                "NativeRabbitDefinitionProfile.tags.omitted",
                "NativeRabbitDefinitionProfile.tags.value",
                "NativeRabbitDefinitionProfile.ca.omitted",
                "NativeRabbitDefinitionProfile.ca.value",
                "NativeKubernetesDefinitionProfile.clusterToken.omitted",
                "NativeKubernetesDefinitionProfile.clusterToken.value",
                "NativeKubernetesDefinitionProfile.url.omitted",
                "NativeKubernetesDefinitionProfile.url.value",
                "NativeKubernetesDefinitionProfile.ca.omitted",
                "NativeKubernetesDefinitionProfile.ca.value",
                "NativeKubernetesDefinitionProfile.authentication.Api",
                "NativeKubernetesDefinitionProfile.authentication.Gateway",
                "NativeKubernetesDefinitionProfile.authentication.omitted",
                "NativeKubernetesDefinitionProfile.gateway.omitted",
                "NativeKubernetesDefinitionProfile.gateway.value",
                "NativeKubernetesDefinitionProfile.sslEnabled.omitted",
                "NativeKubernetesDefinitionProfile.sslEnabled.false",
                "NativeKubernetesDefinitionProfile.sslEnabled.true",
                "NativeLdapDefinitionProfile.rollbackLdif.omitted",
                "NativeLdapDefinitionProfile.rollbackLdif.value",
                "NativeLdapDefinitionProfile.ca.omitted",
                "NativeLdapDefinitionProfile.ca.value",
                "NativeSshDefinitionProfile.keyAlgorithm.Rsa2048",
                "NativeSshDefinitionProfile.keyAlgorithm.Rsa4096",
                "NativeSshDefinitionProfile.keyAlgorithm.EcPrime256v1",
                "NativeSshDefinitionProfile.keyAlgorithm.EcSecp384r1",
                "NativeSshDefinitionProfile.keyAlgorithm.Ed25519",
                "NativeSshDefinitionProfile.keyAlgorithm.omitted",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa2048",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa4096",
                "NativeSshDefinitionProfile.caKeyAlgorithm.EcPrime256v1",
                "NativeSshDefinitionProfile.caKeyAlgorithm.EcSecp384r1",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Ed25519",
                "NativeSshDefinitionProfile.caKeyAlgorithm.omitted",
                "NativeIbmApiDefinitionProfile.gateway.omitted",
                "NativeIbmApiDefinitionProfile.gateway.value",
                "NativeOauthDefinitionProfile.scope.omitted",
                "NativeOauthDefinitionProfile.scope.value",
                "NativeOauthDefinitionProfile.extraParameters.omitted",
                "NativeOauthDefinitionProfile.extraParameters.value",
                "NativeTailscaleDefinitionProfile.tailnet.omitted",
                "NativeTailscaleDefinitionProfile.tailnet.value",
                "NativeTailscaleDefinitionProfile.reusable.false",
                "NativeTailscaleDefinitionProfile.reusable.true",
                "NativeTailscaleDefinitionProfile.preauthorized.false",
                "NativeTailscaleDefinitionProfile.preauthorized.true",
                "NativeTailscaleDefinitionProfile.tags.omitted",
                "NativeTailscaleDefinitionProfile.tags.value",
                "NativeTailscaleDefinitionProfile.description.omitted",
                "NativeTailscaleDefinitionProfile.description.value",
                "NativeCouchbaseDefinitionProfile.buckets.omitted",
                "NativeCouchbaseDefinitionProfile.buckets.value",
                "NativeCouchbaseDefinitionProfile.passwordRequirements.omitted",
                "NativeCouchbaseDefinitionProfile.passwordRequirements.value",
                "NativeGatewayOptions.gatewayId.omitted",
                "NativeGatewayOptions.gatewayId.value",
                "NativeGatewayOptions.gatewayPoolId.omitted",
                "NativeGatewayOptions.gatewayPoolId.value",
                "NativeGatewayOptions.clearGatewayId.false",
                "NativeGatewayOptions.clearGatewayId.true",
                "NativeGatewayOptions.clearGatewayPoolId.false",
                "NativeGatewayOptions.clearGatewayPoolId.true",
                "NativeAwsIamOptions.awsPath.omitted",
                "NativeAwsIamOptions.awsPath.value",
                "NativeAwsIamOptions.permissionBoundaryPolicyArn.omitted",
                "NativeAwsIamOptions.permissionBoundaryPolicyArn.value",
                "NativeAwsIamOptions.policyArns.omitted",
                "NativeAwsIamOptions.policyArns.value",
                "NativeAwsIamOptions.policyDocument.omitted",
                "NativeAwsIamOptions.policyDocument.value",
                "NativeAwsIamOptions.userGroups.omitted",
                "NativeAwsIamOptions.userGroups.value",
                "NativeAwsIamOptions.tags.omitted",
                "NativeAwsIamOptions.tags.value",
                "NativeAwsIamOptions.sessionPolicyArns.omitted",
                "NativeAwsIamOptions.sessionPolicyArns.value",
                "NativeAwsIamOptions.sessionPolicyDocument.omitted",
                "NativeAwsIamOptions.sessionPolicyDocument.value",
                "NativeMilvusPrivilege.objectName.omitted",
                "NativeMilvusPrivilege.objectName.value",
                "NativeMilvusPrivilege.dbName.omitted",
                "NativeMilvusPrivilege.dbName.value",
                "NativeCouchbaseScope.collections.omitted",
                "NativeCouchbaseScope.collections.value",
                "NativeCouchbaseBucket.scopes.omitted",
                "NativeCouchbaseBucket.scopes.value",
                "NativeTailscaleOptions.tailnet.omitted",
                "NativeTailscaleOptions.tailnet.value",
                "NativeTailscaleOptions.tags.omitted",
                "NativeTailscaleOptions.tags.value",
                "NativeTailscaleOptions.description.omitted",
                "NativeTailscaleOptions.description.value",
                "NativeTailscaleOptions.audience.omitted",
                "NativeTailscaleOptions.audience.value",
                "NativeTailscaleOptions.reusable.omitted",
                "NativeTailscaleOptions.reusable.false",
                "NativeTailscaleOptions.reusable.true",
                "NativeTailscaleOptions.preauthorized.omitted",
                "NativeTailscaleOptions.preauthorized.false",
                "NativeTailscaleOptions.preauthorized.true",
                "AwsIam.assume-role.sessionPolicyArns",
                "AwsIam.assume-role.sessionPolicyDocument",
                "RabbitMq.tags.empty",
                "RabbitMq.tags.values",
                "GcpIam.tokenScopes.omitted",
                "GcpIam.tokenScopes.values",
                "Atlas.role.collectionName.omitted",
                "Atlas.role.collectionName.value",
                "Atlas.scopes.empty",
                "Atlas.scopes.values",
                "Oauth2.extraParams.omitted",
                "Oauth2.extraParams.empty",
                "Oauth2.extraParams.values",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.DeleteDefinitionAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.DeleteDefinitionAsync(SecretKit.Infisical.InfisicalDynamicDefinition,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Boolean,System.Threading.CancellationToken)",
            [
                "forceRecordRemoval.false",
                "forceRecordRemoval.true",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.InspectDefinitionAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.InspectDefinitionAsync(SecretKit.Infisical.InfisicalDynamicTarget,System.Threading.CancellationToken)",
            [
                "selector.exact",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalDynamicClient.InspectLeaseAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.InspectLeaseAsync(SecretKit.Infisical.InfisicalLeaseReference,System.Threading.CancellationToken)",
            [
                "selector.exact",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalDynamicClient.ListDefinitionsAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.ListDefinitionsAsync(System.Threading.CancellationToken)",
            [
                "collection.bounded",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalDynamicClient.ListLeasesAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.ListLeasesAsync(SecretKit.Infisical.InfisicalDynamicDefinition,System.Threading.CancellationToken)",
            [
                "collection.bounded",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalDynamicClient.RenewAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.RenewAsync(SecretKit.Infisical.InfisicalDatabaseLease,SecretKit.Infisical.InfisicalDynamicMutationReceipt,SecretKit.Infisical.InfisicalLeaseDuration,System.Threading.CancellationToken)",
            [
                "ttl.omitted",
                "ttl.value",
                "SqlDatabase.engine.Postgres",
                "SqlDatabase.engine.Mysql",
                "SqlDatabase.engine.Oracle",
                "SqlDatabase.engine.SqlServer",
                "SqlDatabase.engine.SapAse",
                "SqlDatabase.engine.Vertica",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.RenewLeaseAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.RenewLeaseAsync(SecretKit.Infisical.InfisicalLeaseObservation,SecretKit.Infisical.InfisicalDynamicMutationReceipt,SecretKit.Infisical.InfisicalLeaseDuration,System.Threading.CancellationToken)",
            [
                "ttl.omitted",
                "ttl.value",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.RevokeAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.RevokeAsync(SecretKit.Infisical.InfisicalDatabaseLease,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Boolean,System.Threading.CancellationToken)",
            [
                "forceRecordRemoval.false",
                "forceRecordRemoval.true",
                "SqlDatabase.engine.Postgres",
                "SqlDatabase.engine.Mysql",
                "SqlDatabase.engine.Oracle",
                "SqlDatabase.engine.SqlServer",
                "SqlDatabase.engine.SapAse",
                "SqlDatabase.engine.Vertica",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.RevokeLeaseAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.RevokeLeaseAsync(SecretKit.Infisical.InfisicalLeaseReference,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Boolean,System.Threading.CancellationToken)",
            [
                "forceRecordRemoval.false",
                "forceRecordRemoval.true",
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.UpdateDefinitionAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.UpdateDefinitionAsync(SecretKit.Infisical.InfisicalDynamicDefinition,SecretKit.Infisical.NativeDynamicDefinitionPatch,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Threading.CancellationToken)",
            [
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
                "SqlDatabase.engine.Postgres",
                "SqlDatabase.engine.Mysql",
                "SqlDatabase.engine.Oracle",
                "SqlDatabase.engine.SqlServer",
                "SqlDatabase.engine.SapAse",
                "SqlDatabase.engine.Vertica",
                "AwsIam.access-key.IamUser",
                "AwsIam.access-key.Temporary",
                "AwsIam.assume-role.IamUser",
                "AwsIam.assume-role.Temporary",
                "AwsIam.irsa.IamUser",
                "AwsIam.irsa.Temporary",
                "ElasticSearch.user",
                "ElasticSearch.api-key",
                "Kubernetes.static-account",
                "Kubernetes.dynamic-role",
                "Kubernetes.dynamic-cluster-role",
                "Kubernetes.auth.omitted",
                "Kubernetes.auth.Api",
                "Kubernetes.auth.Gateway",
                "Ldap.static-account",
                "Ldap.dynamic",
                "Totp.url",
                "Totp.manual.Sha1",
                "Totp.manual.Sha256",
                "Totp.manual.Sha512",
                "Tailscale.auth_keys.api_key",
                "Tailscale.auth_keys.oauth",
                "Tailscale.oauth_keys.api_key",
                "Tailscale.oauth_keys.oauth",
                "Tailscale.federated_keys.api_key",
                "Tailscale.federated_keys.oauth",
                "Oauth2.Basic",
                "Oauth2.Post",
                "Couchbase.buckets.text",
                "Couchbase.buckets.objects",
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
                "maximumTtl.omitted",
                "maximumTtl.value",
                "usernameTemplate.omitted",
                "usernameTemplate.value",
                "metadata.omitted",
                "metadata.empty",
                "metadata.value",
                "gatewayId.omitted",
                "gatewayId.value",
                "gatewayId.null",
                "gatewayPoolId.omitted",
                "gatewayPoolId.value",
                "gatewayPoolId.null",
                "MongoDb.port.omitted",
                "MongoDb.port.null",
                "MongoDb.port.value",
                "MongoDb.ca.omitted",
                "MongoDb.ca.null",
                "MongoDb.ca.value",
                "sql.sslEnabled.omitted",
                "sql.sslEnabled.false",
                "sql.sslEnabled.true",
                "sql.ca.omitted",
                "sql.ca.value",
                "sql.renewStatement.omitted",
                "sql.renewStatement.value",
                "passwordRequirements.omitted",
                "passwordRequirements.value",
                "maximumTtl.null",
                "usernameTemplate.null",
                "newName.omitted",
                "newName.value",
                "inputs.omitted",
                "inputs.same-provider",
                "NativeSqlDefinitionProfile.renewalStatement.omitted",
                "NativeSqlDefinitionProfile.renewalStatement.value",
                "NativeSqlDefinitionProfile.ca.omitted",
                "NativeSqlDefinitionProfile.ca.value",
                "NativeSqlDefinitionProfile.sslEnabled.omitted",
                "NativeSqlDefinitionProfile.sslEnabled.false",
                "NativeSqlDefinitionProfile.sslEnabled.true",
                "NativeSqlDefinitionProfile.gatewayId.omitted",
                "NativeSqlDefinitionProfile.gatewayId.value",
                "NativeSqlDefinitionProfile.gatewayPoolId.omitted",
                "NativeSqlDefinitionProfile.gatewayPoolId.value",
                "NativeSqlDefinitionProfile.passwordRequirements.omitted",
                "NativeSqlDefinitionProfile.passwordRequirements.value",
                "NativeSqlDefinitionProfile.clearGatewayId.false",
                "NativeSqlDefinitionProfile.clearGatewayId.true",
                "NativeSqlDefinitionProfile.clearGatewayPoolId.false",
                "NativeSqlDefinitionProfile.clearGatewayPoolId.true",
                "NativeClickhouseDefinitionProfile.renewal.omitted",
                "NativeClickhouseDefinitionProfile.renewal.value",
                "NativeClickhouseDefinitionProfile.ca.omitted",
                "NativeClickhouseDefinitionProfile.ca.value",
                "NativeClickhouseDefinitionProfile.gateway.omitted",
                "NativeClickhouseDefinitionProfile.gateway.value",
                "NativeClickhouseDefinitionProfile.passwordRequirements.omitted",
                "NativeClickhouseDefinitionProfile.passwordRequirements.value",
                "NativeCassandraDefinitionProfile.keyspace.omitted",
                "NativeCassandraDefinitionProfile.keyspace.value",
                "NativeCassandraDefinitionProfile.renewal.omitted",
                "NativeCassandraDefinitionProfile.renewal.value",
                "NativeCassandraDefinitionProfile.ca.omitted",
                "NativeCassandraDefinitionProfile.ca.value",
                "NativeSapHanaDefinitionProfile.renewal.omitted",
                "NativeSapHanaDefinitionProfile.renewal.value",
                "NativeSapHanaDefinitionProfile.ca.omitted",
                "NativeSapHanaDefinitionProfile.ca.value",
                "NativeRedisDefinitionProfile.password.omitted",
                "NativeRedisDefinitionProfile.password.value",
                "NativeRedisDefinitionProfile.renewal.omitted",
                "NativeRedisDefinitionProfile.renewal.value",
                "NativeRedisDefinitionProfile.ca.omitted",
                "NativeRedisDefinitionProfile.ca.value",
                "NativeVerticaDefinitionProfile.gateway.omitted",
                "NativeVerticaDefinitionProfile.gateway.value",
                "NativeVerticaDefinitionProfile.passwordRequirements.omitted",
                "NativeVerticaDefinitionProfile.passwordRequirements.value",
                "NativeAzureSqlDefinitionProfile.masterDatabase.omitted",
                "NativeAzureSqlDefinitionProfile.masterDatabase.value",
                "NativeAzureSqlDefinitionProfile.renewal.omitted",
                "NativeAzureSqlDefinitionProfile.renewal.value",
                "NativeAzureSqlDefinitionProfile.ca.omitted",
                "NativeAzureSqlDefinitionProfile.ca.value",
                "NativeAzureSqlDefinitionProfile.gateway.omitted",
                "NativeAzureSqlDefinitionProfile.gateway.value",
                "NativeAzureSqlDefinitionProfile.passwordRequirements.omitted",
                "NativeAzureSqlDefinitionProfile.passwordRequirements.value",
                "NativeAzureSqlDefinitionProfile.sslEnabled.omitted",
                "NativeAzureSqlDefinitionProfile.sslEnabled.false",
                "NativeAzureSqlDefinitionProfile.sslEnabled.true",
                "NativeSnowflakeDefinitionProfile.renewal.omitted",
                "NativeSnowflakeDefinitionProfile.renewal.value",
                "NativeAwsIamDefinitionProfile.credentialKind.IamUser",
                "NativeAwsIamDefinitionProfile.credentialKind.Temporary",
                "NativeAwsIamDefinitionProfile.options.omitted",
                "NativeAwsIamDefinitionProfile.options.value",
                "NativeGcpIamDefinitionProfile.tokenScopes.omitted",
                "NativeGcpIamDefinitionProfile.tokenScopes.value",
                "NativeMilvusDefinitionProfile.database.omitted",
                "NativeMilvusDefinitionProfile.database.value",
                "NativeMilvusDefinitionProfile.ca.omitted",
                "NativeMilvusDefinitionProfile.ca.value",
                "NativeMilvusDefinitionProfile.gateway.omitted",
                "NativeMilvusDefinitionProfile.gateway.value",
                "NativeMilvusDefinitionProfile.privileges.omitted",
                "NativeMilvusDefinitionProfile.privileges.value",
                "NativeMongoDefinitionProfile.port.omitted",
                "NativeMongoDefinitionProfile.port.value",
                "NativeMongoDefinitionProfile.ca.omitted",
                "NativeMongoDefinitionProfile.ca.value",
                "NativeMongoDefinitionProfile.clearPort.false",
                "NativeMongoDefinitionProfile.clearPort.true",
                "NativeMongoDefinitionProfile.clearCa.false",
                "NativeMongoDefinitionProfile.clearCa.true",
                "NativeElasticsearchDefinitionProfile.ca.omitted",
                "NativeElasticsearchDefinitionProfile.ca.value",
                "NativeRabbitDefinitionProfile.tags.omitted",
                "NativeRabbitDefinitionProfile.tags.value",
                "NativeRabbitDefinitionProfile.ca.omitted",
                "NativeRabbitDefinitionProfile.ca.value",
                "NativeKubernetesDefinitionProfile.clusterToken.omitted",
                "NativeKubernetesDefinitionProfile.clusterToken.value",
                "NativeKubernetesDefinitionProfile.url.omitted",
                "NativeKubernetesDefinitionProfile.url.value",
                "NativeKubernetesDefinitionProfile.ca.omitted",
                "NativeKubernetesDefinitionProfile.ca.value",
                "NativeKubernetesDefinitionProfile.authentication.Api",
                "NativeKubernetesDefinitionProfile.authentication.Gateway",
                "NativeKubernetesDefinitionProfile.authentication.omitted",
                "NativeKubernetesDefinitionProfile.gateway.omitted",
                "NativeKubernetesDefinitionProfile.gateway.value",
                "NativeKubernetesDefinitionProfile.sslEnabled.omitted",
                "NativeKubernetesDefinitionProfile.sslEnabled.false",
                "NativeKubernetesDefinitionProfile.sslEnabled.true",
                "NativeLdapDefinitionProfile.rollbackLdif.omitted",
                "NativeLdapDefinitionProfile.rollbackLdif.value",
                "NativeLdapDefinitionProfile.ca.omitted",
                "NativeLdapDefinitionProfile.ca.value",
                "NativeSshDefinitionProfile.keyAlgorithm.Rsa2048",
                "NativeSshDefinitionProfile.keyAlgorithm.Rsa4096",
                "NativeSshDefinitionProfile.keyAlgorithm.EcPrime256v1",
                "NativeSshDefinitionProfile.keyAlgorithm.EcSecp384r1",
                "NativeSshDefinitionProfile.keyAlgorithm.Ed25519",
                "NativeSshDefinitionProfile.keyAlgorithm.omitted",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa2048",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Rsa4096",
                "NativeSshDefinitionProfile.caKeyAlgorithm.EcPrime256v1",
                "NativeSshDefinitionProfile.caKeyAlgorithm.EcSecp384r1",
                "NativeSshDefinitionProfile.caKeyAlgorithm.Ed25519",
                "NativeSshDefinitionProfile.caKeyAlgorithm.omitted",
                "NativeIbmApiDefinitionProfile.gateway.omitted",
                "NativeIbmApiDefinitionProfile.gateway.value",
                "NativeOauthDefinitionProfile.scope.omitted",
                "NativeOauthDefinitionProfile.scope.value",
                "NativeOauthDefinitionProfile.extraParameters.omitted",
                "NativeOauthDefinitionProfile.extraParameters.value",
                "NativeTailscaleDefinitionProfile.tailnet.omitted",
                "NativeTailscaleDefinitionProfile.tailnet.value",
                "NativeTailscaleDefinitionProfile.reusable.false",
                "NativeTailscaleDefinitionProfile.reusable.true",
                "NativeTailscaleDefinitionProfile.preauthorized.false",
                "NativeTailscaleDefinitionProfile.preauthorized.true",
                "NativeTailscaleDefinitionProfile.tags.omitted",
                "NativeTailscaleDefinitionProfile.tags.value",
                "NativeTailscaleDefinitionProfile.description.omitted",
                "NativeTailscaleDefinitionProfile.description.value",
                "NativeCouchbaseDefinitionProfile.buckets.omitted",
                "NativeCouchbaseDefinitionProfile.buckets.value",
                "NativeCouchbaseDefinitionProfile.passwordRequirements.omitted",
                "NativeCouchbaseDefinitionProfile.passwordRequirements.value",
                "NativeGatewayOptions.gatewayId.omitted",
                "NativeGatewayOptions.gatewayId.value",
                "NativeGatewayOptions.gatewayPoolId.omitted",
                "NativeGatewayOptions.gatewayPoolId.value",
                "NativeGatewayOptions.clearGatewayId.false",
                "NativeGatewayOptions.clearGatewayId.true",
                "NativeGatewayOptions.clearGatewayPoolId.false",
                "NativeGatewayOptions.clearGatewayPoolId.true",
                "NativeAwsIamOptions.awsPath.omitted",
                "NativeAwsIamOptions.awsPath.value",
                "NativeAwsIamOptions.permissionBoundaryPolicyArn.omitted",
                "NativeAwsIamOptions.permissionBoundaryPolicyArn.value",
                "NativeAwsIamOptions.policyArns.omitted",
                "NativeAwsIamOptions.policyArns.value",
                "NativeAwsIamOptions.policyDocument.omitted",
                "NativeAwsIamOptions.policyDocument.value",
                "NativeAwsIamOptions.userGroups.omitted",
                "NativeAwsIamOptions.userGroups.value",
                "NativeAwsIamOptions.tags.omitted",
                "NativeAwsIamOptions.tags.value",
                "NativeAwsIamOptions.sessionPolicyArns.omitted",
                "NativeAwsIamOptions.sessionPolicyArns.value",
                "NativeAwsIamOptions.sessionPolicyDocument.omitted",
                "NativeAwsIamOptions.sessionPolicyDocument.value",
                "NativeMilvusPrivilege.objectName.omitted",
                "NativeMilvusPrivilege.objectName.value",
                "NativeMilvusPrivilege.dbName.omitted",
                "NativeMilvusPrivilege.dbName.value",
                "NativeCouchbaseScope.collections.omitted",
                "NativeCouchbaseScope.collections.value",
                "NativeCouchbaseBucket.scopes.omitted",
                "NativeCouchbaseBucket.scopes.value",
                "NativeTailscaleOptions.tailnet.omitted",
                "NativeTailscaleOptions.tailnet.value",
                "NativeTailscaleOptions.tags.omitted",
                "NativeTailscaleOptions.tags.value",
                "NativeTailscaleOptions.description.omitted",
                "NativeTailscaleOptions.description.value",
                "NativeTailscaleOptions.audience.omitted",
                "NativeTailscaleOptions.audience.value",
                "NativeTailscaleOptions.reusable.omitted",
                "NativeTailscaleOptions.reusable.false",
                "NativeTailscaleOptions.reusable.true",
                "NativeTailscaleOptions.preauthorized.omitted",
                "NativeTailscaleOptions.preauthorized.false",
                "NativeTailscaleOptions.preauthorized.true",
                "AwsIam.assume-role.sessionPolicyArns",
                "AwsIam.assume-role.sessionPolicyDocument",
                "RabbitMq.tags.empty",
                "RabbitMq.tags.values",
                "GcpIam.tokenScopes.omitted",
                "GcpIam.tokenScopes.values",
                "Atlas.role.collectionName.omitted",
                "Atlas.role.collectionName.value",
                "Atlas.scopes.empty",
                "Atlas.scopes.values",
                "Oauth2.extraParams.omitted",
                "Oauth2.extraParams.empty",
                "Oauth2.extraParams.values",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalDynamicClient.UpdateDefinitionPolicyAsync",
            "SecretKit.Infisical.InfisicalDynamicClient.UpdateDefinitionPolicyAsync(SecretKit.Infisical.InfisicalDynamicDefinition,SecretKit.Infisical.InfisicalLeaseDuration,SecretKit.Infisical.InfisicalLeaseDuration,SecretKit.Infisical.InfisicalDynamicMutationReceipt,System.Threading.CancellationToken)",
            [
                "profile.SqlDatabase",
                "profile.Clickhouse",
                "profile.Cassandra",
                "profile.SapAse",
                "profile.AwsIam",
                "profile.Redis",
                "profile.SapHana",
                "profile.AwsElasticache",
                "profile.AwsMemorydb",
                "profile.MongoDbAtlas",
                "profile.ElasticSearch",
                "profile.MongoDb",
                "profile.RabbitMq",
                "profile.AzureEntraId",
                "profile.AzureSqlDatabase",
                "profile.Ldap",
                "profile.Snowflake",
                "profile.Totp",
                "profile.Kubernetes",
                "profile.Vertica",
                "profile.GcpIam",
                "profile.Github",
                "profile.Couchbase",
                "profile.Milvus",
                "profile.Ssh",
                "profile.IbmApiConnect",
                "profile.Tailscale",
                "profile.Oauth2",
                "maximumTtl.null",
                "maximumTtl.value",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalPeriodicTokenSession.GetTokenAsync",
            "SecretKit.Infisical.InfisicalPeriodicTokenSession.GetTokenAsync(System.Threading.CancellationToken)",
            [
                "selector.exact",
                "lifetime.Finite",
                "lifetime.Periodic.no-absolute-limit",
                "lifetime.Periodic.absolute-limit",
                "lifetime.Unknown.recovery-required",
                "session.expired",
                "session.recovery-required",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalPeriodicTokenSession.RenewAsync",
            "SecretKit.Infisical.InfisicalPeriodicTokenSession.RenewAsync(System.Threading.CancellationToken)",
            [
                "lifetime.Finite",
                "lifetime.Periodic.no-absolute-limit",
                "lifetime.Periodic.absolute-limit",
                "lifetime.Unknown.recovery-required",
                "session.expired",
                "session.recovery-required",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalRotationClient.GetAsync",
            "SecretKit.Infisical.InfisicalRotationClient.GetAsync(SecretKit.Core.SecretReference,System.Threading.CancellationToken)",
            [
                "selector.exact",
                "profile.Auth0ClientSecret",
                "profile.AwsIamUserSecret",
                "profile.AzureClientSecret",
                "profile.CloudflareApiToken",
                "profile.CloudflareR2AccessKey",
                "profile.ConvexAccessKey",
                "profile.DatabricksServicePrincipalSecret",
                "profile.DatadogApiKey",
                "profile.DatadogApplicationKeySecret",
                "profile.DbtServiceToken",
                "profile.FireworksApiKey",
                "profile.GcpServiceAccountKey",
                "profile.HpIloLocalAccount",
                "profile.LdapPassword",
                "profile.LitellmApiKey",
                "profile.MongodbCredentials",
                "profile.MssqlCredentials",
                "profile.MysqlCredentials",
                "profile.OktaClientSecret",
                "profile.OpenRouterApiKey",
                "profile.OpenaiServiceAccount",
                "profile.OracledbCredentials",
                "profile.PostgresCredentials",
                "profile.RedisCredentials",
                "profile.SalesforceOauthCredentials",
                "profile.SnowflakeUserKeyPair",
                "profile.StripeApiKey",
                "profile.SupabaseApiKey",
                "profile.UnixLinuxLocalAccount",
                "profile.WindowsLocalAccount",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalRotationClient.ListAsync",
            "SecretKit.Infisical.InfisicalRotationClient.ListAsync(SecretKit.Core.SecretReference,System.Int32,System.Threading.CancellationToken)",
            [
                "collection.bounded",
                "profile.Auth0ClientSecret",
                "profile.AwsIamUserSecret",
                "profile.AzureClientSecret",
                "profile.CloudflareApiToken",
                "profile.CloudflareR2AccessKey",
                "profile.ConvexAccessKey",
                "profile.DatabricksServicePrincipalSecret",
                "profile.DatadogApiKey",
                "profile.DatadogApplicationKeySecret",
                "profile.DbtServiceToken",
                "profile.FireworksApiKey",
                "profile.GcpServiceAccountKey",
                "profile.HpIloLocalAccount",
                "profile.LdapPassword",
                "profile.LitellmApiKey",
                "profile.MongodbCredentials",
                "profile.MssqlCredentials",
                "profile.MysqlCredentials",
                "profile.OktaClientSecret",
                "profile.OpenRouterApiKey",
                "profile.OpenaiServiceAccount",
                "profile.OracledbCredentials",
                "profile.PostgresCredentials",
                "profile.RedisCredentials",
                "profile.SalesforceOauthCredentials",
                "profile.SnowflakeUserKeyPair",
                "profile.StripeApiKey",
                "profile.SupabaseApiKey",
                "profile.UnixLinuxLocalAccount",
                "profile.WindowsLocalAccount",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect"]),
        new("i.runtime.InfisicalRotationClient.RotateSecretsAsync",
            "SecretKit.Infisical.InfisicalRotationClient.RotateSecretsAsync(SecretKit.Core.SecretReference,SecretKit.Infisical.InfisicalRotationReceipt,SecretKit.Infisical.InfisicalRotationPrecondition,System.Threading.CancellationToken)",
            [
                "precondition.None",
                "precondition.RequireCompareAndSwap.rejected",
                "precondition.RequireIdempotency.rejected",
                "profile.Auth0ClientSecret",
                "profile.AwsIamUserSecret",
                "profile.AzureClientSecret",
                "profile.CloudflareApiToken",
                "profile.CloudflareR2AccessKey",
                "profile.ConvexAccessKey",
                "profile.DatabricksServicePrincipalSecret",
                "profile.DatadogApiKey",
                "profile.DatadogApplicationKeySecret",
                "profile.DbtServiceToken",
                "profile.FireworksApiKey",
                "profile.GcpServiceAccountKey",
                "profile.HpIloLocalAccount",
                "profile.LdapPassword",
                "profile.LitellmApiKey",
                "profile.MongodbCredentials",
                "profile.MssqlCredentials",
                "profile.MysqlCredentials",
                "profile.OktaClientSecret",
                "profile.OpenRouterApiKey",
                "profile.OpenaiServiceAccount",
                "profile.OracledbCredentials",
                "profile.PostgresCredentials",
                "profile.RedisCredentials",
                "profile.SalesforceOauthCredentials",
                "profile.SnowflakeUserKeyPair",
                "profile.StripeApiKey",
                "profile.SupabaseApiKey",
                "profile.UnixLinuxLocalAccount",
                "profile.WindowsLocalAccount",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
        new("i.runtime.InfisicalRotationClient.SetAutomaticRotationAsync",
            "SecretKit.Infisical.InfisicalRotationClient.SetAutomaticRotationAsync(SecretKit.Core.SecretReference,System.Boolean,SecretKit.Infisical.InfisicalRotationReceipt,SecretKit.Infisical.InfisicalRotationPrecondition,System.Threading.CancellationToken)",
            [
                "enabled.false",
                "enabled.true",
                "precondition.None",
                "precondition.RequireCompareAndSwap.rejected",
                "precondition.RequireIdempotency.rejected",
                "profile.Auth0ClientSecret",
                "profile.AwsIamUserSecret",
                "profile.AzureClientSecret",
                "profile.CloudflareApiToken",
                "profile.CloudflareR2AccessKey",
                "profile.ConvexAccessKey",
                "profile.DatabricksServicePrincipalSecret",
                "profile.DatadogApiKey",
                "profile.DatadogApplicationKeySecret",
                "profile.DbtServiceToken",
                "profile.FireworksApiKey",
                "profile.GcpServiceAccountKey",
                "profile.HpIloLocalAccount",
                "profile.LdapPassword",
                "profile.LitellmApiKey",
                "profile.MongodbCredentials",
                "profile.MssqlCredentials",
                "profile.MysqlCredentials",
                "profile.OktaClientSecret",
                "profile.OpenRouterApiKey",
                "profile.OpenaiServiceAccount",
                "profile.OracledbCredentials",
                "profile.PostgresCredentials",
                "profile.RedisCredentials",
                "profile.SalesforceOauthCredentials",
                "profile.SnowflakeUserKeyPair",
                "profile.StripeApiKey",
                "profile.SupabaseApiKey",
                "profile.UnixLinuxLocalAccount",
                "profile.WindowsLocalAccount",
            ],
            ["selected-contract", "denied-authority", "cancellation-boundary", "independent-effect", "lost-response-no-replay"]),
    ];
    public static void Register(NativeCaseRegistry registry, NativeEnvironment env,
        IReadOnlyList<NativeCaseDefinition> expected)
    {
        InfisicalDynamicClientEffects.Register(registry, env, expected);
        InfisicalPeriodicTokenSessionEffects.Register(registry, env, expected);
        InfisicalRotationClientEffects.Register(registry, env, expected);
    }

    internal static JsonSerializerOptions Options { get; } = new(NativeRunProtocol.JsonOptions)
    {
        Converters = { new JsonStringEnumConverter() }
    };

    internal static T Input<T>(NativeEnvironment env, string family, NativeCaseDefinition definition)
    {
        try
        {
            return env.RequireFamilyInput(family).GetProperty("scopes").GetProperty(definition.Key.Scope)
                .GetProperty(definition.Key.Operation).GetProperty(definition.Key.Variant)
                .GetProperty(definition.Key.Case).Deserialize<T>(Options)
                ?? throw new NativeCaseFailureException("missing-input");
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException)
        {
            throw new NativeCaseFailureException("missing-input");
        }
    }

    internal static async ValueTask BoundedAsync(NativeCaseProbe probe, CancellationToken token,
        Func<CancellationToken, ValueTask> execute, Func<int>? timeoutSeconds = null)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            int seconds = timeoutSeconds?.Invoke() ?? 40;
            if (seconds is < 1 or > 900) throw new NativeCaseFailureException("missing-input");
            deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
            await execute(deadline.Token);
        }
        catch (NativeCaseFailureException error)
        {
            probe.Contract(false, error.Message switch
            {
                "missing-input" => NativeFailure.MissingInput,
                "missing-prerequisite" => NativeFailure.MissingPrerequisite,
                "observer-unavailable" => NativeFailure.ObserverUnavailable,
                "contract-mismatch" => NativeFailure.ContractMismatch,
                "effect-mismatch" => NativeFailure.EffectMismatch,
                "cleanup-incomplete" => NativeFailure.CleanupIncomplete,
                _ => NativeFailure.UnexpectedFailure
            });
        }
        catch (OperationCanceledException)
        {
            probe.Contract(false, token.IsCancellationRequested ?
                NativeFailure.UnexpectedCancellation : NativeFailure.DeadlineExceeded);
        }
        catch (Exception error) when (error is ArgumentException or JsonException or KeyNotFoundException)
        {
            probe.Contract(false, NativeFailure.MissingInput);
        }
    }

    internal static LifecycleAdmission Admission(NativeCaseDefinition definition, NativeCaseProbe probe)
    {
        LifecycleAdmission? admission = Catalog.SingleOrDefault(a => a.Operation == definition.Key.Operation);
        probe.Contract(admission is not null && admission.Member == definition.Member &&
            admission.Variants.Contains(definition.Key.Variant, StringComparer.Ordinal) &&
            admission.Cases.Contains(definition.Key.Case, StringComparer.Ordinal), NativeFailure.ContractMismatch);
        return admission!;
    }
}

internal sealed record LifecycleAdmission(string Operation, string Member, string[] Variants, string[] Cases);

internal sealed class LifecycleSelectedTokens(NativeEnvironment env, NativeIdentityRole role) : IInfisicalTokenSource
{
    internal NativeIdentityRole Role { get; set; } = role;
    public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token) =>
        env.Tokens(Role).GetTokenAsync(token);
    public override string ToString() => "[LifecycleSelectedTokens]";
}

internal sealed record LifecycleSandbox(string ProjectId, string ProjectSlug, string Environment,
    string EnvironmentId, string Parent)
{
    public override string ToString() => "[LifecycleSandbox]";
}

// Only folder-v2 setup and cleanup; all family operations still go through their actual SDK seam.
// Register never creates this fixture. Each Execute creates a fresh, non-reused namespace.
internal sealed class LifecycleOwnedFolder : IAsyncDisposable
{
    private readonly NativeEnvironment env;
    private readonly NativeCaseProbe probe;
    private readonly LifecycleSandbox input;
    private readonly string scope;
    private readonly string name = "sk-life-" + Guid.NewGuid().ToString("N");
    private readonly InfisicalClient setup;
    private readonly InfisicalClient administrative;
    private readonly InfisicalClient observer;
    private bool attempted;
    private string? id;
    internal string Path => input.Parent.TrimEnd('/') + "/" + name;
    internal Guid FolderId => Guid.Parse(id!);

    internal LifecycleOwnedFolder(NativeEnvironment env, LifecycleSandbox input, NativeCaseProbe probe, string scope)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (string.IsNullOrWhiteSpace(input.Parent) || input.Parent == "/" || !input.Parent.StartsWith('/') ||
            !Guid.TryParse(input.EnvironmentId, out _) || input.Parent.Split('/').Any(p => p is "." or ".."))
            throw new NativeCaseFailureException("missing-input");
        this.env = env;
        this.input = input;
        this.probe = probe;
        this.scope = scope;
        setup = env.CreateClient(NativeIdentityRole.Setup);
        administrative = env.CreateClient(NativeIdentityRole.Administrative);
        observer = env.CreateObserverClient();
    }

    private SecretReference Target(InfisicalClient client) => new(client.Authority,
        new InfisicalFolderAddress(input.ProjectId, input.Environment, input.EnvironmentId,
            input.Parent, id, name));

    private InfisicalNativeAuthority Authority(InfisicalClient client, NativeIdentityRole role) =>
        new(client.Authority, env.Tokens(role), input.ProjectId, input.Environment, input.Parent);

    internal async ValueTask InitializeAsync(CancellationToken token)
    {
        SecretReference target = Target(setup);
        var receipt = new MutationReceipt(target);
        attempted = true;
        var created = await setup.CreateFolderAsync(target, Authority(setup, NativeIdentityRole.Setup),
            receipt, cancellationToken: token);
        probe.Contract(created.IsSuccess && receipt.Evidence == DispatchEvidence.Applied,
            NativeFailure.MissingPrerequisite);
        id = created.Value.Id;
        var observed = await observer.GetFolderAsync(Target(observer), token);
        probe.Contract(observed.IsSuccess && observed.Value.Id == id &&
            observed.Value.Path == Path, NativeFailure.ObserverUnavailable);
    }

    public async ValueTask DisposeAsync()
    {
        bool clean = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        try
        {
            if (attempted)
            {
                SecretReference target = Target(administrative);
                var result = await administrative.DeleteFolderAsync(target,
                    Authority(administrative, NativeIdentityRole.Administrative), new(target),
                    forceDelete: true, cancellationToken: deadline.Token);
                var remaining = await observer.ListFoldersAsync(new(observer.Authority,
                    new InfisicalFolderAddress(input.ProjectId, input.Environment, input.EnvironmentId,
                        input.Parent)), cancellationToken: deadline.Token);
                clean = (result.IsSuccess || result.Status == SecretStatus.Absent) &&
                    remaining.IsSuccess && remaining.Value.IsComplete &&
                    !remaining.Value.Items.Any(f => f.Name == name);
            }
        }
        catch (Exception) { clean = false; }
        finally
        {
            foreach (var client in new[] { setup, administrative, observer })
            {
                try { await client.DisposeAsync(); }
                catch (Exception) { clean = false; }
            }
            if (attempted)
                env.ConfirmPrerequisite(scope, "approved-sandbox-cleanup",
                    clean ? NativeObservation.Matched : NativeObservation.Mismatched);
            if (!clean) probe.Contract(false, NativeFailure.CleanupIncomplete);
        }
    }
}

// A host transport forwards only requests constructed by the SDK. It never builds provider requests.
// The caller subscribes before invoking the SDK. Loss occurs after upstream headers; cancellation
// occurs at this exact transport send, not after a guessed delay.
internal sealed class LifecycleTransport : HttpMessageHandler
{
    private readonly HttpMessageInvoker upstream;
    private readonly string? caseName;
    private bool armed;
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal LifecycleTransport(string? caseName = null, HttpMessageHandler? transport = null)
    {
        this.caseName = caseName;
        upstream = new(transport ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null
        }, transport is null);
    }
    internal void Arm() => armed = true;
    internal void Disarm() => armed = false;
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        if (armed && caseName == "cancellation-boundary")
        {
            Reached.TrySetResult();
            await new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously).Task.WaitAsync(token);
        }
        HttpResponseMessage response = await upstream.SendAsync(request, token);
        if (armed && caseName == "lost-response-no-replay")
        {
            response.Dispose();
            Reached.TrySetResult();
            throw new HttpRequestException("lifecycle-response-withheld");
        }
        return response;
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) upstream.Dispose();
        base.Dispose(disposing);
    }
}

// Sessions publicly accept only a SocketsHttpHandler. Correlation stays within the exact
// async execution and token-renew path; no reflection or replacement renewal implementation.
internal sealed class LifecycleSessionBoundary : EventListener
{
    private static readonly AsyncLocal<LifecycleSessionBoundary?> Current = new();
    private readonly LifecycleSessionBoundary? previous;
    private readonly Uri? origin;
    private readonly CancellationTokenSource? cancellation;
    private readonly bool loseResponse;
    private readonly Action? stop;
    private bool selected;
    internal TaskCompletionSource Reached { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal LifecycleSessionBoundary(Uri origin, CancellationTokenSource cancellation, bool loseResponse, Action? stop = null)
    {
        this.origin = origin;
        this.cancellation = cancellation;
        this.loseResponse = loseResponse;
        this.stop = stop;
        previous = Current.Value;
        Current.Value = this;
    }
    protected override void OnEventSourceCreated(EventSource source)
    {
        if (source.Name == "System.Net.Http") EnableEvents(source, EventLevel.Verbose, EventKeywords.All);
    }
    protected override void OnEventWritten(EventWrittenEventArgs value)
    {
        if (origin is null || cancellation is null || !ReferenceEquals(Current.Value, this)) return;
        if (value.EventName == "RequestStart" && value.Payload is { Count: >= 4 } fields &&
            fields[0] is string scheme && scheme == origin.Scheme &&
            fields[1] is string host && host == origin.Host &&
            fields[2] is int port && port == origin.Port &&
            fields[3] is string path && path == "/api/v1/auth/token/renew") selected = true;
        if (selected && value.EventName == (loseResponse ? "ResponseHeadersStop" : "RequestHeadersStart") &&
            Reached.TrySetResult())
        {
            cancellation.Cancel();
            stop?.Invoke();
        }
    }
    public override void Dispose()
    {
        if (ReferenceEquals(Current.Value, this)) Current.Value = previous;
        base.Dispose();
    }
}
