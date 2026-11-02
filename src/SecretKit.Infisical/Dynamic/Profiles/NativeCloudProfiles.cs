namespace SecretKit.Infisical.Dynamic;

/// <summary>The native AWS credential shape requested by an IAM definition.</summary>
public enum NativeAwsCredentialKind { /** <summary>IAM user credentials.</summary> */ IamUser, /** <summary>Temporary credentials.</summary> */ Temporary }
/// <summary>Owned AWS IAM definition inputs with explicit access-key, assume-role or IRSA authority selection.</summary>
public sealed class NativeAwsIamDefinitionProfile : InfisicalDynamicProfile
{
    private enum RoleMethod { AssumeRole, Irsa }
    private NativeAwsIamDefinitionProfile(RoleMethod method, string region, string? roleArn,
        NativeAwsCredentialKind credentialKind, NativeAwsIamOptions? options) : base(InfisicalDynamicProvider.AwsIam)
    {
        if (method != RoleMethod.AssumeRole && options?.HasSessionPolicy == true)
            throw new ArgumentException("Session policies require native assume-role authentication.");
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentException("Unknown native AWS credential kind.");
        }
        Text("method", method == RoleMethod.AssumeRole ? "assume-role" : "irsa"); Text("region", region);
        if (method == RoleMethod.AssumeRole) { Text("roleArn", roleArn!); }
        Text("credentialType", credentialKind == NativeAwsCredentialKind.IamUser ? "iam-user" : "temporary-credentials");
        Options(options);
    }
    /// <summary>Copies assume-role selectors and optional session policy; does not assume a role locally.</summary>
    public static NativeAwsIamDefinitionProfile ForAssumeRole(string roleArn, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null) =>
        new(RoleMethod.AssumeRole, region, roleArn, credentialKind, options);
    /// <summary>Selects provider-side IRSA with copied region/options; session policy inputs are not admitted on this branch.</summary>
    public static NativeAwsIamDefinitionProfile ForIrsa(string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null) =>
        new(RoleMethod.Irsa, region, null, credentialKind, options);
    /// <summary>Copies explicit access-key credentials and native options; session policies require the assume-role branch.</summary>
    public NativeAwsIamDefinitionProfile(string accessKey, string secretAccessKey, string region,
        NativeAwsCredentialKind credentialKind = NativeAwsCredentialKind.IamUser, NativeAwsIamOptions? options = null)
        : base(InfisicalDynamicProvider.AwsIam)
    {
        if (options?.HasSessionPolicy == true)
            throw new ArgumentException("Session policies require native assume-role authentication.");
        if (!Enum.IsDefined(credentialKind))
        {
            throw new ArgumentException("Unknown native AWS credential kind.");
        }
        Text("method", "access-key"); Text("accessKey", accessKey); Text("secretAccessKey", secretAccessKey);
        Text("region", region); Text("credentialType", credentialKind switch
        {
            NativeAwsCredentialKind.IamUser => "iam-user",
            NativeAwsCredentialKind.Temporary => "temporary-credentials",
            _ => throw new ArgumentException("Unknown native AWS credential kind.")
        });
        Options(options);
    }
}
/// <summary>Owned AWS ElastiCache credentials, cluster selectors and native lifecycle statements.</summary>
public sealed class NativeAwsElasticacheDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies AWS credentials and explicit cluster/statement inputs without acquiring a remote lease.</summary>
    public NativeAwsElasticacheDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsElasticache)
    {
        Text("accessKeyId", accessKeyId); Text("secretAccessKey", secretAccessKey); Text("region", region);
        Text("clusterName", clusterName); Text("creationStatement", creation, allowEmpty: true);
        Text("revocationStatement", revocation, allowEmpty: true);
    }
}
/// <summary>Owned AWS MemoryDB definition inputs using the native IAM authentication shape.</summary>
public sealed class NativeAwsMemorydbDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies IAM keys, region, cluster and lifecycle statements without provider I/O.</summary>
    public NativeAwsMemorydbDefinitionProfile(string accessKeyId, string secretAccessKey, string region,
        string clusterName, string creation, string revocation) : base(InfisicalDynamicProvider.AwsMemorydb)
    {
        Text("auth.type", "iam"); Text("auth.accessKeyId", accessKeyId); Text("auth.secretAccessKey", secretAccessKey);
        Text("region", region); Text("clusterName", clusterName);
        Text("creationStatement", creation, allowEmpty: true); Text("revocationStatement", revocation, allowEmpty: true);
    }
}
/// <summary>Owned native Entra ID definition inputs with explicit application and user coordinates.</summary>
public sealed class NativeAzureEntraDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies tenant/application credentials and user/email selectors; does not run an identity flow.</summary>
    public NativeAzureEntraDefinitionProfile(string tenantId, string applicationId, string clientSecret,
        string userId, string email) : base(InfisicalDynamicProvider.AzureEntraId)
    {
        Text("tenantId", tenantId); Text("applicationId", applicationId); Text("clientSecret", clientSecret);
        Text("userId", userId); Text("email", email);
    }
}
/// <summary>Owned GCP IAM definition selectors; no host credential discovery is performed.</summary>
public sealed class NativeGcpIamDefinitionProfile : InfisicalDynamicProfile
{
    /// <summary>Copies service-account email and optional token scopes for provider-side execution.</summary>
    public NativeGcpIamDefinitionProfile(string serviceAccountEmail, IReadOnlyList<string>? tokenScopes = null)
        : base(InfisicalDynamicProvider.GcpIam)
    {
        if (!serviceAccountEmail.Contains('@'))
        {
            throw new ArgumentException("A native service-account email is required.");
        }
        Text("serviceAccountEmail", serviceAccountEmail, 128);
        if (tokenScopes is not null) { Strings("tokenScopes", tokenScopes); }
    }
}
