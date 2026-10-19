namespace SecretKit.Infisical.Conformance.Tests;

internal sealed record InfisicalDynamicProfileInput(
    DynamicClickhouseInput? Clickhouse = null,
    DynamicCassandraInput? Cassandra = null,
    DynamicSapAseInput? SapAse = null,
    DynamicSapHanaInput? SapHana = null,
    DynamicRedisInput? Redis = null,
    DynamicVerticaInput? Vertica = null,
    DynamicAzureSqlDatabaseInput? AzureSqlDatabase = null,
    DynamicSnowflakeInput? Snowflake = null,
    DynamicAwsIamInput? AwsIam = null,
    DynamicAwsElasticacheInput? AwsElasticache = null,
    DynamicAwsMemorydbInput? AwsMemorydb = null,
    DynamicAzureEntraIdInput? AzureEntraId = null,
    DynamicGcpIamInput? GcpIam = null,
    DynamicGithubInput? Github = null,
    DynamicMilvusInput? Milvus = null,
    DynamicMongoDbInput? MongoDb = null,
    DynamicElasticSearchInput? ElasticSearch = null,
    DynamicRabbitMqInput? RabbitMq = null,
    DynamicKubernetesInput? Kubernetes = null,
    DynamicLdapInput? Ldap = null,
    DynamicTotpInput? Totp = null,
    DynamicSshInput? Ssh = null,
    DynamicIbmApiConnectInput? IbmApiConnect = null,
    DynamicOauth2Input? Oauth2 = null,
    DynamicTailscaleInput? Tailscale = null,
    DynamicCouchbaseInput? Couchbase = null,
    DynamicMongoDbAtlasInput? MongoDbAtlas = null)
{
    public override string ToString() => "[InfisicalDynamicProfileInput]";
}

internal sealed record DynamicClickhouseInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string Database,
    string Creation,
    string Revocation,
    string? Renewal = null,
    string? Ca = null,
    DynamicGatewayInput? Gateway = null,
    DynamicPasswordInput? PasswordRequirements = null)
{
    public override string ToString() => "[DynamicClickhouseInput]";
}

internal sealed record DynamicCassandraInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string LocalDataCenter,
    string Creation,
    string Revocation,
    string? Keyspace = null,
    string? Renewal = null,
    string? Ca = null)
{
    public override string ToString() => "[DynamicCassandraInput]";
}

internal sealed record DynamicSapAseInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string Database,
    string Creation,
    string Revocation)
{
    public override string ToString() => "[DynamicSapAseInput]";
}

internal sealed record DynamicSapHanaInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string Creation,
    string Revocation,
    string? Renewal = null,
    string? Ca = null)
{
    public override string ToString() => "[DynamicSapHanaInput]";
}

internal sealed record DynamicRedisInput(
    string Host,
    int Port,
    string Username,
    string Creation,
    string Revocation,
    string? Password = null,
    string? Renewal = null,
    string? Ca = null)
{
    public override string ToString() => "[DynamicRedisInput]";
}

internal sealed record DynamicVerticaInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string Database,
    string Creation,
    string Revocation,
    DynamicGatewayInput? Gateway = null,
    DynamicPasswordInput? PasswordRequirements = null)
{
    public override string ToString() => "[DynamicVerticaInput]";
}

internal sealed record DynamicAzureSqlDatabaseInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string Database,
    string Creation,
    string MasterCreation,
    string Revocation,
    string? MasterDatabase = null,
    string? Renewal = null,
    string? Ca = null,
    DynamicGatewayInput? Gateway = null,
    DynamicPasswordInput? PasswordRequirements = null,
    bool? SslEnabled = null)
{
    public override string ToString() => "[DynamicAzureSqlDatabaseInput]";
}

internal sealed record DynamicSnowflakeInput(
    string AccountId,
    string OrganizationId,
    string Username,
    string Password,
    string Creation,
    string Revocation,
    string? Renewal = null)
{
    public override string ToString() => "[DynamicSnowflakeInput]";
}

internal enum DynamicAwsAuthentication { AccessKey, AssumeRole, Irsa }

internal sealed record DynamicAwsIamInput(
    string? AccessKey,
    string? SecretAccessKey,
    string Region,
    NativeAwsCredentialKind CredentialKind = NativeAwsCredentialKind.IamUser,
    DynamicAwsIamOptionsInput? Options = null,
    DynamicAwsAuthentication Authentication = DynamicAwsAuthentication.AccessKey,
    string? RoleArn = null)
{
    public override string ToString() => "[DynamicAwsIamInput]";
}

internal sealed record DynamicAwsElasticacheInput(
    string AccessKeyId,
    string SecretAccessKey,
    string Region,
    string ClusterName,
    string Creation,
    string Revocation)
{
    public override string ToString() => "[DynamicAwsElasticacheInput]";
}

internal sealed record DynamicAwsMemorydbInput(
    string AccessKeyId,
    string SecretAccessKey,
    string Region,
    string ClusterName,
    string Creation,
    string Revocation)
{
    public override string ToString() => "[DynamicAwsMemorydbInput]";
}

internal sealed record DynamicAzureEntraIdInput(
    string TenantId,
    string ApplicationId,
    string ClientSecret,
    string UserId,
    string Email)
{
    public override string ToString() => "[DynamicAzureEntraIdInput]";
}

internal sealed record DynamicGcpIamInput(
    string ServiceAccountEmail,
    string[]? TokenScopes = null)
{
    public override string ToString() => "[DynamicGcpIamInput]";
}

internal sealed record DynamicGithubInput(
    long ApplicationId,
    long InstallationId,
    string PrivateKey)
{
    public override string ToString() => "[DynamicGithubInput]";
}

internal sealed record DynamicMilvusInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string? Database = null,
    string? Ca = null,
    DynamicGatewayInput? Gateway = null,
    DynamicMilvusPrivilegeInput[]? Privileges = null)
{
    public override string ToString() => "[DynamicMilvusInput]";
}

internal sealed record DynamicMongoDbInput(
    string Host,
    string Username,
    string Password,
    string Database,
    string[] Roles,
    int? Port = null,
    string? Ca = null,
    bool ClearPort = false,
    bool ClearCa = false)
{
    public override string ToString() => "[DynamicMongoDbInput]";
}

internal sealed record DynamicElasticSearchInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string[] Roles,
    string? Ca = null)
{
    public override string ToString() => "[DynamicElasticSearchInput]";
}

internal sealed record DynamicRabbitMqInput(
    string Host,
    int Port,
    string Username,
    string Password,
    string VirtualHost,
    string ConfigurePermission,
    string WritePermission,
    string ReadPermission,
    string[]? Tags = null,
    string? Ca = null)
{
    public override string ToString() => "[DynamicRabbitMqInput]";
}

internal sealed record DynamicKubernetesInput(
    string NameSpace,
    string Role,
    bool ClusterRole,
    string[] Audiences,
    string? ClusterToken = null,
    string? Url = null,
    string? Ca = null,
    NativeKubernetesAuthentication? Authentication = null,
    DynamicGatewayInput? Gateway = null,
    bool? SslEnabled = null)
{
    public override string ToString() => "[DynamicKubernetesInput]";
}

internal sealed record DynamicLdapInput(
    string Url,
    string BindDn,
    string BindPassword,
    string CreationLdif,
    string RevocationLdif,
    string? RollbackLdif = null,
    string? Ca = null)
{
    public override string ToString() => "[DynamicLdapInput]";
}

internal sealed record DynamicTotpInput(
    string ProvisioningUrl)
{
    public override string ToString() => "[DynamicTotpInput]";
}

internal sealed record DynamicSshInput(
    string[] Principals,
    NativeSshKeyAlgorithm? KeyAlgorithm = null,
    NativeSshKeyAlgorithm? CaKeyAlgorithm = null)
{
    public override string ToString() => "[DynamicSshInput]";
}

internal sealed record DynamicIbmApiConnectInput(
    string ApiKey,
    string ApplicationId,
    string ClientId,
    string ClientSecret,
    string OrganizationId,
    string CatalogId,
    string ConsumerOrganizationId,
    string InstanceUrl,
    DynamicGatewayInput? Gateway = null)
{
    public override string ToString() => "[DynamicIbmApiConnectInput]";
}

internal sealed record DynamicOauth2Input(
    string ClientId,
    string ClientSecret,
    NativeOauthClientAuthentication Method,
    string TokenUrl,
    string RevocationUrl,
    string? Scope = null,
    DynamicOauthExtraParameterInput[]? ExtraParameters = null)
{
    public override string ToString() => "[DynamicOauth2Input]";
}

internal sealed record DynamicTailscaleInput(
    string ApiKey,
    string? Tailnet = null,
    bool Reusable = false,
    bool Preauthorized = false,
    string[]? Tags = null,
    string? Description = null)
{
    public override string ToString() => "[DynamicTailscaleInput]";
}

internal sealed record DynamicCouchbaseInput(
    string Url,
    string ApiKey,
    string OrganizationId,
    string ProjectId,
    string ClusterId,
    string[] Roles,
    DynamicCouchbaseBucketsInput? Buckets = null,
    DynamicPasswordInput? PasswordRequirements = null)
{
    public override string ToString() => "[DynamicCouchbaseInput]";
}

internal sealed record DynamicMongoDbAtlasInput(
    string AdminPublicKey,
    string AdminPrivateKey,
    string GroupId,
    DynamicAtlasRoleInput[] Roles,
    DynamicAtlasScopeInput[] Scopes)
{
    public override string ToString() => "[DynamicMongoDbAtlasInput]";
}

internal sealed record DynamicGatewayInput(
    string? GatewayId = null,
    string? GatewayPoolId = null,
    bool ClearGatewayId = false,
    bool ClearGatewayPoolId = false)
{
    public override string ToString() => "[DynamicGatewayInput]";
}

internal sealed record DynamicAwsTagInput(
    string Key,
    string? Value = null)
{
    public override string ToString() => "[DynamicAwsTagInput]";
}

internal sealed record DynamicAwsIamOptionsInput(
    string? AwsPath = null,
    string? PermissionBoundaryPolicyArn = null,
    string? PolicyArns = null,
    string? PolicyDocument = null,
    string? UserGroups = null,
    DynamicAwsTagInput[]? Tags = null,
    string? SessionPolicyArns = null,
    string? SessionPolicyDocument = null)
{
    public override string ToString() => "[DynamicAwsIamOptionsInput]";
}

internal sealed record DynamicMilvusPrivilegeInput(
    string ObjectType,
    string Privilege,
    string? ObjectName = null,
    string? DbName = null)
{
    public override string ToString() => "[DynamicMilvusPrivilegeInput]";
}

internal sealed record DynamicOauthExtraParameterInput(
    string Key,
    string Value)
{
    public override string ToString() => "[DynamicOauthExtraParameterInput]";
}

internal sealed record DynamicCouchbaseScopeInput(
    string Name,
    string[]? Collections = null)
{
    public override string ToString() => "[DynamicCouchbaseScopeInput]";
}

internal sealed record DynamicCouchbaseBucketInput(
    string Name,
    DynamicCouchbaseScopeInput[]? Scopes = null)
{
    public override string ToString() => "[DynamicCouchbaseBucketInput]";
}

internal sealed record DynamicCouchbaseBucketsInput(
    string? Text = null,
    DynamicCouchbaseBucketInput[]? Buckets = null)
{
    public override string ToString() => "[DynamicCouchbaseBucketsInput]";
}

internal sealed record DynamicAtlasRoleInput(
    string DatabaseName,
    string RoleName,
    string? CollectionName = null)
{
    public override string ToString() => "[DynamicAtlasRoleInput]";
}

internal sealed record DynamicAtlasScopeInput(
    string Name,
    string Type)
{
    public override string ToString() => "[DynamicAtlasScopeInput]";
}

// Private host input is deliberately separate from SDK request serialization.
// Only the selected public constructor exports material, through the SDK transport.
internal static class InfisicalDynamicProfileInputs
{
    internal static InfisicalDynamicProfile Create(InfisicalDynamicProvider provider, InfisicalDynamicProfileInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
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
        using var owned = new OwnedOptions();
        return provider switch
        {
            InfisicalDynamicProvider.Clickhouse when input.Clickhouse is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Database is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeClickhouseDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Creation,
                    p.Revocation,
                    p.Renewal,
                    p.Ca,
                    Gateway(p.Gateway, owned),
                    Password(p.PasswordRequirements, owned)),
            InfisicalDynamicProvider.Cassandra when input.Cassandra is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.LocalDataCenter is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeCassandraDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.LocalDataCenter,
                    p.Creation,
                    p.Revocation,
                    p.Keyspace,
                    p.Renewal,
                    p.Ca),
            InfisicalDynamicProvider.SapAse when input.SapAse is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Database is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeSapAseDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Creation,
                    p.Revocation),
            InfisicalDynamicProvider.SapHana when input.SapHana is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeSapHanaDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Creation,
                    p.Revocation,
                    p.Renewal,
                    p.Ca),
            InfisicalDynamicProvider.Redis when input.Redis is { } p &&
                p.Host is not null && p.Username is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeRedisDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Creation,
                    p.Revocation,
                    p.Password,
                    p.Renewal,
                    p.Ca),
            InfisicalDynamicProvider.Vertica when input.Vertica is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Database is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeVerticaDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Creation,
                    p.Revocation,
                    Gateway(p.Gateway, owned),
                    Password(p.PasswordRequirements, owned)),
            InfisicalDynamicProvider.AzureSqlDatabase when input.AzureSqlDatabase is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Database is not null && p.Creation is not null && p.MasterCreation is not null && p.Revocation is not null =>
                new NativeAzureSqlDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Creation,
                    p.MasterCreation,
                    p.Revocation,
                    p.MasterDatabase,
                    p.Renewal,
                    p.Ca,
                    Gateway(p.Gateway, owned),
                    Password(p.PasswordRequirements, owned),
                    p.SslEnabled),
            InfisicalDynamicProvider.Snowflake when input.Snowflake is { } p &&
                p.AccountId is not null && p.OrganizationId is not null && p.Username is not null && p.Password is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeSnowflakeDefinitionProfile(
                    p.AccountId,
                    p.OrganizationId,
                    p.Username,
                    p.Password,
                    p.Creation,
                    p.Revocation,
                    p.Renewal),
            InfisicalDynamicProvider.AwsIam when input.AwsIam is { } p &&
                p.Region is not null => p.Authentication switch
                {
                    DynamicAwsAuthentication.AccessKey when p.AccessKey is not null &&
                        p.SecretAccessKey is not null && p.RoleArn is null =>
                        new NativeAwsIamDefinitionProfile(p.AccessKey, p.SecretAccessKey, p.Region,
                            p.CredentialKind, Aws(p.Options, owned)),
                    DynamicAwsAuthentication.AssumeRole when p.RoleArn is not null &&
                        p.AccessKey is null && p.SecretAccessKey is null =>
                        NativeAwsIamDefinitionProfile.ForAssumeRole(p.RoleArn, p.Region,
                            p.CredentialKind, Aws(p.Options, owned)),
                    DynamicAwsAuthentication.Irsa when p.RoleArn is null &&
                        p.AccessKey is null && p.SecretAccessKey is null =>
                        NativeAwsIamDefinitionProfile.ForIrsa(p.Region, p.CredentialKind, Aws(p.Options, owned)),
                    _ => throw new ArgumentException("Missing or conflicting AWS authentication input.")
                },
            InfisicalDynamicProvider.AwsElasticache when input.AwsElasticache is { } p &&
                p.AccessKeyId is not null && p.SecretAccessKey is not null && p.Region is not null && p.ClusterName is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeAwsElasticacheDefinitionProfile(
                    p.AccessKeyId,
                    p.SecretAccessKey,
                    p.Region,
                    p.ClusterName,
                    p.Creation,
                    p.Revocation),
            InfisicalDynamicProvider.AwsMemorydb when input.AwsMemorydb is { } p &&
                p.AccessKeyId is not null && p.SecretAccessKey is not null && p.Region is not null && p.ClusterName is not null && p.Creation is not null && p.Revocation is not null =>
                new NativeAwsMemorydbDefinitionProfile(
                    p.AccessKeyId,
                    p.SecretAccessKey,
                    p.Region,
                    p.ClusterName,
                    p.Creation,
                    p.Revocation),
            InfisicalDynamicProvider.AzureEntraId when input.AzureEntraId is { } p &&
                p.TenantId is not null && p.ApplicationId is not null && p.ClientSecret is not null && p.UserId is not null && p.Email is not null =>
                new NativeAzureEntraDefinitionProfile(
                    p.TenantId,
                    p.ApplicationId,
                    p.ClientSecret,
                    p.UserId,
                    p.Email),
            InfisicalDynamicProvider.GcpIam when input.GcpIam is { } p &&
                p.ServiceAccountEmail is not null =>
                new NativeGcpIamDefinitionProfile(
                    p.ServiceAccountEmail,
                    p.TokenScopes),
            InfisicalDynamicProvider.Github when input.Github is { } p &&
                p.PrivateKey is not null =>
                new NativeGithubDefinitionProfile(
                    p.ApplicationId,
                    p.InstallationId,
                    p.PrivateKey),
            InfisicalDynamicProvider.Milvus when input.Milvus is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null =>
                new NativeMilvusDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Ca,
                    Gateway(p.Gateway, owned),
                    p.Privileges?.Select(v => v is null ? throw new ArgumentException("Missing typed privilege.") :
                    owned.Add(new NativeMilvusPrivilege(v.ObjectType, v.Privilege, v.ObjectName, v.DbName))).ToArray()),
            InfisicalDynamicProvider.MongoDb when input.MongoDb is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Database is not null && p.Roles is not null =>
                new NativeMongoDefinitionProfile(
                    p.Host,
                    p.Username,
                    p.Password,
                    p.Database,
                    p.Roles,
                    p.Port,
                    p.Ca,
                    p.ClearPort,
                    p.ClearCa),
            InfisicalDynamicProvider.ElasticSearch when input.ElasticSearch is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.Roles is not null =>
                new NativeElasticsearchDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.Roles,
                    p.Ca),
            InfisicalDynamicProvider.RabbitMq when input.RabbitMq is { } p &&
                p.Host is not null && p.Username is not null && p.Password is not null && p.VirtualHost is not null && p.ConfigurePermission is not null && p.WritePermission is not null && p.ReadPermission is not null =>
                new NativeRabbitDefinitionProfile(
                    p.Host,
                    p.Port,
                    p.Username,
                    p.Password,
                    p.VirtualHost,
                    p.ConfigurePermission,
                    p.WritePermission,
                    p.ReadPermission,
                    p.Tags,
                    p.Ca),
            InfisicalDynamicProvider.Kubernetes when input.Kubernetes is { } p &&
                p.NameSpace is not null && p.Role is not null && p.Audiences is not null =>
                new NativeKubernetesDefinitionProfile(
                    p.NameSpace,
                    p.Role,
                    p.ClusterRole,
                    p.Audiences,
                    p.ClusterToken,
                    p.Url,
                    p.Ca,
                    p.Authentication,
                    Gateway(p.Gateway, owned),
                    p.SslEnabled),
            InfisicalDynamicProvider.Ldap when input.Ldap is { } p &&
                p.Url is not null && p.BindDn is not null && p.BindPassword is not null && p.CreationLdif is not null && p.RevocationLdif is not null =>
                new NativeLdapDefinitionProfile(
                    p.Url,
                    p.BindDn,
                    p.BindPassword,
                    p.CreationLdif,
                    p.RevocationLdif,
                    p.RollbackLdif,
                    p.Ca),
            InfisicalDynamicProvider.Totp when input.Totp is { } p &&
                p.ProvisioningUrl is not null =>
                new NativeTotpDefinitionProfile(
                    p.ProvisioningUrl),
            InfisicalDynamicProvider.Ssh when input.Ssh is { } p &&
                p.Principals is not null =>
                new NativeSshDefinitionProfile(
                    p.Principals,
                    p.KeyAlgorithm,
                    p.CaKeyAlgorithm),
            InfisicalDynamicProvider.IbmApiConnect when input.IbmApiConnect is { } p &&
                p.ApiKey is not null && p.ApplicationId is not null && p.ClientId is not null && p.ClientSecret is not null && p.OrganizationId is not null && p.CatalogId is not null && p.ConsumerOrganizationId is not null && p.InstanceUrl is not null =>
                new NativeIbmApiDefinitionProfile(
                    p.ApiKey,
                    p.ApplicationId,
                    p.ClientId,
                    p.ClientSecret,
                    p.OrganizationId,
                    p.CatalogId,
                    p.ConsumerOrganizationId,
                    p.InstanceUrl,
                    Gateway(p.Gateway, owned)),
            InfisicalDynamicProvider.Oauth2 when input.Oauth2 is { } p &&
                p.ClientId is not null && p.ClientSecret is not null && p.TokenUrl is not null && p.RevocationUrl is not null =>
                new NativeOauthDefinitionProfile(
                    p.ClientId,
                    p.ClientSecret,
                    p.Method,
                    p.TokenUrl,
                    p.RevocationUrl,
                    p.Scope,
                    p.ExtraParameters?.Select(v => v is null ? throw new ArgumentException("Missing typed parameter.") :
                    owned.Add(new NativeOauthExtraParameter(v.Key, v.Value))).ToArray()),
            InfisicalDynamicProvider.Tailscale when input.Tailscale is { } p &&
                p.ApiKey is not null =>
                new NativeTailscaleDefinitionProfile(
                    p.ApiKey,
                    p.Tailnet,
                    p.Reusable,
                    p.Preauthorized,
                    p.Tags,
                    p.Description),
            InfisicalDynamicProvider.Couchbase when input.Couchbase is { } p &&
                p.Url is not null && p.ApiKey is not null && p.OrganizationId is not null && p.ProjectId is not null && p.ClusterId is not null && p.Roles is not null =>
                new NativeCouchbaseDefinitionProfile(
                    p.Url,
                    p.ApiKey,
                    p.OrganizationId,
                    p.ProjectId,
                    p.ClusterId,
                    p.Roles,
                    Buckets(p.Buckets, owned),
                    Password(p.PasswordRequirements, owned)),
            InfisicalDynamicProvider.MongoDbAtlas when input.MongoDbAtlas is { } p &&
                p.AdminPublicKey is not null && p.AdminPrivateKey is not null && p.GroupId is not null && p.Roles is not null && p.Scopes is not null =>
                new NativeAtlasDefinitionProfile(
                    p.AdminPublicKey,
                    p.AdminPrivateKey,
                    p.GroupId,
                    p.Roles.Select(v => v is null ? throw new ArgumentException("Missing typed role.") :
                    new NativeAtlasRole(v.DatabaseName, v.RoleName, v.CollectionName)).ToArray(),
                    p.Scopes.Select(v => v is null ? throw new ArgumentException("Missing typed scope.") :
                    new NativeAtlasScope(v.Name, v.Type)).ToArray()),
            _ => throw new ArgumentException("Missing or mismatched typed profile input.")
        };
    }

    private static NativeGatewayOptions? Gateway(DynamicGatewayInput? input, OwnedOptions owned) =>
        input is null ? null : owned.Add(new NativeGatewayOptions(input.GatewayId, input.GatewayPoolId,
            input.ClearGatewayId, input.ClearGatewayPoolId));

    private static NativePasswordRequirements? Password(DynamicPasswordInput? input, OwnedOptions owned) =>
        input is null ? null : owned.Add(new NativePasswordRequirements(input.Length, input.Lowercase,
            input.Uppercase, input.Digits, input.Symbols, input.AllowedSymbols));

    private static NativeAwsIamOptions? Aws(DynamicAwsIamOptionsInput? input, OwnedOptions owned) =>
        input is null ? null : owned.Add(new NativeAwsIamOptions(input.AwsPath, input.PermissionBoundaryPolicyArn,
            input.PolicyArns, input.PolicyDocument, input.UserGroups,
            input.Tags?.Select(v => v is null ? throw new ArgumentException("Missing typed tag.") :
                owned.Add(new NativeAwsTag(v.Key, v.Value))).ToArray(),
            input.SessionPolicyArns, input.SessionPolicyDocument));

    private static NativeCouchbaseBuckets? Buckets(DynamicCouchbaseBucketsInput? input, OwnedOptions owned)
    {
        if (input is null) return null;
        if ((input.Text is null) == (input.Buckets is null))
            throw new ArgumentException("Exactly one typed bucket representation is required.");
        if (input.Text is { } text) return owned.Add(NativeCouchbaseBuckets.FromText(text));
        var buckets = input.Buckets!.Select(bucket => bucket is null ?
            throw new ArgumentException("Missing typed bucket.") : owned.Add(new NativeCouchbaseBucket(bucket.Name,
                bucket.Scopes?.Select(scope => scope is null ? throw new ArgumentException("Missing typed bucket scope.") :
                    owned.Add(new NativeCouchbaseScope(scope.Name, scope.Collections))).ToArray()))).ToArray();
        return owned.Add(NativeCouchbaseBuckets.FromBuckets(buckets));
    }

    // Register each allocation immediately so later construction failures still erase copies.
    // SDK constructors take independent copies before this scope disposes in reverse order.
    private sealed class OwnedOptions : IDisposable
    {
        private readonly List<IDisposable> values = [];
        internal T Add<T>(T value) where T : IDisposable
        {
            values.Add(value);
            return value;
        }
        public void Dispose()
        {
            for (int i = values.Count - 1; i >= 0; i--) values[i].Dispose();
        }
    }
}
