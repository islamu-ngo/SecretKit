using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class CloudIdentityAuthenticationEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition d) => null;

    internal static async ValueTask ExecuteAsync(IdentityAuthContext c, CancellationToken token)
    {
        if (c.Variant.EndsWith(".rejected", StringComparison.Ordinal))
        {
            await c.EnsureIdentityAsync(token);
            if (c.Operation.Contains("Azure", StringComparison.Ordinal))
                await c.RejectionAsync(() =>
                {
                    using var rejected = CloudIdentityAuthenticationOperations.AttachAzureAuth(c.OrganizationId, c.IdentityId,
                        new(c.Variant.Contains("tenantId", StringComparison.Ordinal) ? null : "owned-tenant",
                            c.Variant.Contains("resource", StringComparison.Ordinal) ? null : "owned-resource"));
                }, () => CloudIdentityAuthenticationOperations.GetAzureAuth(c.OrganizationId, c.IdentityId), token);
            else
                await c.RejectionAsync(() =>
                {
                    using var rejected = CloudIdentityAuthenticationOperations.AttachGcpAuth(c.OrganizationId, c.IdentityId, new());
                }, () => CloudIdentityAuthenticationOperations.GetGcpAuth(c.OrganizationId, c.IdentityId), token);
            return;
        }
        string mechanism = c.Operation.Contains("AliCloud", StringComparison.Ordinal) ? "alicloud" :
            c.Operation.Contains("Aws", StringComparison.Ordinal) ? "aws" :
            c.Operation.Contains("Azure", StringComparison.Ordinal) ? "azure" : "gcp";
        c.RequireIssuer(mechanism);
        await c.EnsureIdentityAsync(token);
        string org = c.OrganizationId, id = c.IdentityId;
        bool seed = !c.Operation.StartsWith("Attach", StringComparison.Ordinal);
        WorkloadAuthTokenPolicy baseline = c.Policy(true), selected = c.Policy();
        bool Match(WorkloadAuthConfiguration value, bool changed) =>
            c.PolicyMatches(value, changed ? selected : baseline);
        if (mechanism == "alicloud")
        {
            string arns = c.Setting("allowedArns");
            var initial = new AliCloudAuthConfigurationInput(arns, seed ? baseline : selected);
            var update = new AliCloudAuthConfigurationInput(arns, selected);
            await c.ConfigurationAsync(
                () => CloudIdentityAuthenticationOperations.AttachAliCloudAuth(org, id, initial),
                () => CloudIdentityAuthenticationOperations.GetAliCloudAuth(org, id),
                () => CloudIdentityAuthenticationOperations.UpdateAliCloudAuth(org, id, update),
                () => CloudIdentityAuthenticationOperations.DeleteAliCloudAuth(org, id),
                (v, changed) => Match(v, changed) && v.AllowedArns == arns, mechanism, token);
        }
        else if (mechanism == "aws")
        {
            AwsAuthConfigurationInput Input(bool before) => new(c.TextInput("allowedPrincipalArns", before),
                c.TextInput("allowedAccountIds", before), c.TextInput("stsEndpoint", before), before ? baseline : selected);
            AwsAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Fields(AwsAuthConfiguration v, bool changed)
            {
                AwsAuthConfigurationInput input = changed ? update : initial;
                return Match(v, changed) && v.AllowedPrincipalArns == c.ExpectedText("allowedPrincipalArns", input.AllowedPrincipalArns) &&
                    v.AllowedAccountIds == c.ExpectedText("allowedAccountIds", input.AllowedAccountIds) &&
                    v.StsEndpoint == c.ExpectedText("stsEndpoint", input.StsEndpoint);
            }
            await c.ConfigurationAsync(
                () => CloudIdentityAuthenticationOperations.AttachAwsAuth(org, id, initial),
                () => CloudIdentityAuthenticationOperations.GetAwsAuth(org, id),
                () => CloudIdentityAuthenticationOperations.UpdateAwsAuth(org, id, update),
                () => CloudIdentityAuthenticationOperations.DeleteAwsAuth(org, id), Fields, mechanism, token);
        }
        else if (mechanism == "azure")
        {
            AzureAuthConfigurationInput Input(bool before) => new(c.TextInput("tenantId", before),
                c.TextInput("resource", before), c.TextInput("allowedServicePrincipalIds", before), before ? baseline : selected);
            AzureAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Fields(AzureAuthConfiguration v, bool changed)
            {
                AzureAuthConfigurationInput input = changed ? update : initial;
                return Match(v, changed) && v.TenantId == c.ExpectedText("tenantId", input.TenantId) &&
                    v.Resource == c.ExpectedText("resource", input.Resource) &&
                    v.AllowedServicePrincipalIds == c.ExpectedText("allowedServicePrincipalIds", input.AllowedServicePrincipalIds);
            }
            await c.ConfigurationAsync(
                () => CloudIdentityAuthenticationOperations.AttachAzureAuth(org, id, initial),
                () => CloudIdentityAuthenticationOperations.GetAzureAuth(org, id),
                () => CloudIdentityAuthenticationOperations.UpdateAzureAuth(org, id, update),
                () => CloudIdentityAuthenticationOperations.DeleteAzureAuth(org, id), Fields, mechanism, token);
        }
        else
        {
            GcpAuthConfigurationType type = c.Variant.EndsWith(".Gce", StringComparison.Ordinal) ?
                GcpAuthConfigurationType.Gce : GcpAuthConfigurationType.Iam;
            GcpAuthConfigurationType initialType = type;
            if (c.Operation.StartsWith("Update", StringComparison.Ordinal) &&
                (c.Variant.EndsWith(".type.Iam", StringComparison.Ordinal) ||
                    c.Variant.EndsWith(".type.Gce", StringComparison.Ordinal)))
                initialType = c.BaselineSetting("type", type == GcpAuthConfigurationType.Iam ? "iam" : "gce") switch
                {
                    "iam" => GcpAuthConfigurationType.Iam,
                    "gce" => GcpAuthConfigurationType.Gce,
                    _ => throw new NativeCaseFailureException("missing-input")
                };
            GcpAuthConfigurationInput Input(bool before) => new(
                !before && c.Variant.EndsWith("type.omitted", StringComparison.Ordinal) ? null : before ? initialType : type,
                c.TextInput("allowedServiceAccounts", before), c.TextInput("allowedProjects", before),
                c.TextInput("allowedZones", before), before ? baseline : selected);
            GcpAuthConfigurationInput initial = Input(seed), update = Input(false);
            bool Field(ProjectField<string> field, string name, string? input) =>
                field.IsPresent && !field.IsNull && field.Value == c.ExpectedText(name, input);
            bool Fields(GcpAuthConfiguration v, bool changed)
            {
                GcpAuthConfigurationInput input = changed ? update : initial;
                GcpAuthConfigurationType expectedType = input.Type ?? initialType;
                return Match(v, changed) && v.Type == (expectedType == GcpAuthConfigurationType.Iam ? "iam" : "gce") &&
                    Field(v.AllowedServiceAccounts, "allowedServiceAccounts", input.AllowedServiceAccounts) &&
                    Field(v.AllowedProjects, "allowedProjects", input.AllowedProjects) &&
                    Field(v.AllowedZones, "allowedZones", input.AllowedZones);
            }
            await c.ConfigurationAsync(
                () => CloudIdentityAuthenticationOperations.AttachGcpAuth(org, id, initial),
                () => CloudIdentityAuthenticationOperations.GetGcpAuth(org, id),
                () => CloudIdentityAuthenticationOperations.UpdateGcpAuth(org, id, update),
                () => CloudIdentityAuthenticationOperations.DeleteGcpAuth(org, id), Fields, mechanism, token);
        }
    }
}
