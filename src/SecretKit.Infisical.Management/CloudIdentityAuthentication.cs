using System.Text.Json;

namespace SecretKit.Infisical.Management;

/// <summary>Host-selected configuration administration with whole-body intent grants.</summary>
public static class CloudIdentityAuthenticationOperations
{
    public static ManagementTarget AwsAuthConfigurationTarget(string organizationId, string identityId,
        AwsAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "aws", update, input.Write);
    }
    public static ManagementTarget AzureAuthConfigurationTarget(string organizationId, string identityId,
        AzureAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "azure", update, input.Write);
    }
    public static ManagementTarget GcpAuthConfigurationTarget(string organizationId, string identityId,
        GcpAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "gcp", update, input.Write);
    }
    public static ManagementTarget AliCloudAuthConfigurationTarget(string organizationId, string identityId,
        AliCloudAuthConfigurationInput input, bool update = false)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (!update) input.ValidateAttach();
        return Intent(organizationId, identityId, "alicloud", update, input.Write);
    }

    public static ManagementRequest<AwsAuthConfiguration> AttachAwsAuth(string organizationId, string identityId,
        AwsAuthConfigurationInput input) => Configuration("aws", HttpMethod.Post, identityId,
            AwsAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new AwsAuthConfiguration(ManagementJson.Object(root, "identityAwsAuth"), identityId));
    public static ManagementRequest<AwsAuthConfiguration> UpdateAwsAuth(string organizationId, string identityId,
        AwsAuthConfigurationInput input) => Configuration("aws", HttpMethod.Patch, identityId,
            AwsAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new AwsAuthConfiguration(ManagementJson.Object(root, "identityAwsAuth"), identityId));
    public static ManagementRequest<AwsAuthConfiguration> GetAwsAuth(string organizationId, string identityId) =>
        Configuration("aws", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new AwsAuthConfiguration(ManagementJson.Object(root, "identityAwsAuth"), identityId));
    public static ManagementRequest<AwsAuthConfiguration> DeleteAwsAuth(string organizationId, string identityId) =>
        Configuration("aws", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new AwsAuthConfiguration(ManagementJson.Object(root, "identityAwsAuth"), identityId));

    public static ManagementRequest<AzureAuthConfiguration> AttachAzureAuth(string organizationId, string identityId,
        AzureAuthConfigurationInput input) => Configuration("azure", HttpMethod.Post, identityId,
            AzureAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new AzureAuthConfiguration(ManagementJson.Object(root, "identityAzureAuth"), identityId));
    public static ManagementRequest<AzureAuthConfiguration> UpdateAzureAuth(string organizationId, string identityId,
        AzureAuthConfigurationInput input) => Configuration("azure", HttpMethod.Patch, identityId,
            AzureAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new AzureAuthConfiguration(ManagementJson.Object(root, "identityAzureAuth"), identityId));
    public static ManagementRequest<AzureAuthConfiguration> GetAzureAuth(string organizationId, string identityId) =>
        Configuration("azure", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new AzureAuthConfiguration(ManagementJson.Object(root, "identityAzureAuth"), identityId));
    public static ManagementRequest<AzureAuthConfiguration> DeleteAzureAuth(string organizationId, string identityId) =>
        Configuration("azure", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new AzureAuthConfiguration(ManagementJson.Object(root, "identityAzureAuth"), identityId));

    public static ManagementRequest<GcpAuthConfiguration> AttachGcpAuth(string organizationId, string identityId,
        GcpAuthConfigurationInput input) => Configuration("gcp", HttpMethod.Post, identityId,
            GcpAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new GcpAuthConfiguration(ManagementJson.Object(root, "identityGcpAuth"), identityId));
    public static ManagementRequest<GcpAuthConfiguration> UpdateGcpAuth(string organizationId, string identityId,
        GcpAuthConfigurationInput input) => Configuration("gcp", HttpMethod.Patch, identityId,
            GcpAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new GcpAuthConfiguration(ManagementJson.Object(root, "identityGcpAuth"), identityId));
    public static ManagementRequest<GcpAuthConfiguration> GetGcpAuth(string organizationId, string identityId) =>
        Configuration("gcp", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new GcpAuthConfiguration(ManagementJson.Object(root, "identityGcpAuth"), identityId));
    public static ManagementRequest<GcpAuthConfiguration> DeleteGcpAuth(string organizationId, string identityId) =>
        Configuration("gcp", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new GcpAuthConfiguration(ManagementJson.Object(root, "identityGcpAuth"), identityId));

    public static ManagementRequest<AliCloudAuthConfiguration> AttachAliCloudAuth(string organizationId, string identityId,
        AliCloudAuthConfigurationInput input) => Configuration("alicloud", HttpMethod.Post, identityId,
            AliCloudAuthConfigurationTarget(organizationId, identityId, input), input.Write,
            root => new AliCloudAuthConfiguration(ManagementJson.Object(root, "identityAliCloudAuth"), identityId));
    public static ManagementRequest<AliCloudAuthConfiguration> UpdateAliCloudAuth(string organizationId, string identityId,
        AliCloudAuthConfigurationInput input) => Configuration("alicloud", HttpMethod.Patch, identityId,
            AliCloudAuthConfigurationTarget(organizationId, identityId, input, true), input.Write,
            root => new AliCloudAuthConfiguration(ManagementJson.Object(root, "identityAliCloudAuth"), identityId));
    public static ManagementRequest<AliCloudAuthConfiguration> GetAliCloudAuth(string organizationId, string identityId) =>
        Configuration("alicloud", HttpMethod.Get, identityId, new(organizationId, resourceId: identityId), null,
            root => new AliCloudAuthConfiguration(ManagementJson.Object(root, "identityAliCloudAuth"), identityId));
    public static ManagementRequest<AliCloudAuthConfiguration> DeleteAliCloudAuth(string organizationId, string identityId) =>
        Configuration("alicloud", HttpMethod.Delete, identityId, new(organizationId, resourceId: identityId), null,
            root => new AliCloudAuthConfiguration(ManagementJson.Object(root, "identityAliCloudAuth"), identityId));

    private static ManagementTarget Intent(string organizationId, string identityId, string strategy, bool update,
        Action<Utf8JsonWriter> fields) => AuthenticationJson.Intent(organizationId, identityId,
            (update ? "patch-" : "attach-") + strategy, writer => Write(writer, fields));
    private static ManagementRequest<T> Configuration<T>(string strategy, HttpMethod method, string identityId,
        ManagementTarget target, Action<Utf8JsonWriter>? fields, Func<JsonElement, T> parse) where T : notnull =>
        new($"infisical.{method.Method.ToLowerInvariant()}.v1.auth.{strategy}.auth.identities.by.identityId",
            method, $"/api/v1/auth/{strategy}-auth/identities/" + ManagementJson.Escape(identityId), target,
            fields is null ? null : writer => Write(writer, fields), root =>
            {
                string envelope = strategy switch
                {
                    "aws" => "identityAwsAuth",
                    "azure" => "identityAzureAuth",
                    "gcp" => "identityGcpAuth",
                    _ => "identityAliCloudAuth"
                };
                AuthenticationJson.ClosedObject(root, envelope);
                string[] members = strategy switch
                {
                    "aws" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "allowedAccountIds", "allowedPrincipalArns", "stsEndpoint", "type"],
                    "azure" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "allowedServicePrincipalIds", "resource", "tenantId"],
                    "gcp" => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenPeriod", "accessTokenTrustedIps", "accessTokenTTL",
                        "allowedProjects", "allowedServiceAccounts", "allowedZones", "type"],
                    _ => ["id", "identityId", "createdAt", "updatedAt", "accessTokenMaxTTL",
                        "accessTokenNumUsesLimit", "accessTokenTrustedIps", "accessTokenTTL", "allowedArns", "type"]
                };
                AuthenticationJson.ClosedObject(ManagementJson.Object(root, envelope), members);
                return parse(root);
            }, method != HttpMethod.Get);
    private static void Write(Utf8JsonWriter writer, Action<Utf8JsonWriter> fields)
    {
        writer.WriteStartObject();
        fields(writer);
        writer.WriteEndObject();
    }
}
