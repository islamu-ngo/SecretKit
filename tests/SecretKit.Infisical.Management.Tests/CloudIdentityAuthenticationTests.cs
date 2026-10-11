using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class CloudIdentityAuthenticationTests
{
    private const string IdentityId = "11111111-1111-4111-8111-111111111111";
    private const string ConfigurationId = "22222222-2222-4222-8222-222222222222";
    private const string ForeignIdentityId = "33333333-3333-4333-8333-333333333333";

    [Test]
    [Arguments("aws", "GET")]
    [Arguments("aws", "POST")]
    [Arguments("aws", "PATCH")]
    [Arguments("aws", "DELETE")]
    [Arguments("azure", "GET")]
    [Arguments("azure", "POST")]
    [Arguments("azure", "PATCH")]
    [Arguments("azure", "DELETE")]
    [Arguments("gcp", "GET")]
    [Arguments("gcp", "POST")]
    [Arguments("gcp", "PATCH")]
    [Arguments("gcp", "DELETE")]
    [Arguments("alicloud", "GET")]
    [Arguments("alicloud", "POST")]
    [Arguments("alicloud", "PATCH")]
    [Arguments("alicloud", "DELETE")]
    public async Task ConfigurationBindingUsesControlledManagementSeam(string strategy, string method)
    {
        switch (strategy)
        {
            case "aws":
                using (var request = Aws(method)) await Binding(request, strategy, method, Approved(strategy, method));
                break;
            case "azure":
                using (var request = Azure(method)) await Binding(request, strategy, method, Approved(strategy, method));
                break;
            case "gcp":
                using (var request = Gcp(method)) await Binding(request, strategy, method, Approved(strategy, method));
                break;
            default:
                using (var request = AliCloud(method)) await Binding(request, strategy, method, Approved(strategy, method));
                break;
        }
    }

    private static async Task Binding<T>(ManagementRequest<T> request, string strategy, string method,
        ManagementTarget target) where T : notnull
    {
        var wire = new Wire(Response(strategy));
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(wire.Observed).IsTrue();
        await Assert.That(wire.Method).IsEqualTo(method);
        await Assert.That(wire.Path).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}");
        if (receipt is not null) await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        foreach (bool nested in new[] { false, true })
        {
            var response = JsonNode.Parse(Response(strategy))!.AsObject();
            var selected = nested ? response.First().Value!.AsObject() : response;
            selected["notDeclared"] = "private-extra";
            using var malformedTransport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
                null, false, new Wire(response.ToJsonString()));
            var malformedClient = new ManagementClient(malformedTransport);
            var malformedAuthority = new ManagementAuthority(malformedClient.Authority, new Tokens(), "org");
            var malformedReceipt = request.IsMutation ? malformedClient.CreateReceipt(request) : null;
            var malformed = await malformedClient.ExecuteAsync(request, malformedAuthority,
                malformedAuthority.IssueGrant(request.OperationId, target), malformedReceipt);
            await Assert.That(malformed.Status).IsEqualTo(SecretStatus.Unknown);
            if (malformedReceipt is not null)
                await Assert.That(malformedReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        var invalidUuid = JsonNode.Parse(Response(strategy))!.AsObject();
        invalidUuid.First().Value!["id"] = "not-a-uuid";
        using var uuidTransport = new ManagementTransport(new("https://management.test"), 1024 * 1024,
            null, false, new Wire(invalidUuid.ToJsonString()));
        var uuidClient = new ManagementClient(uuidTransport);
        var uuidAuthority = new ManagementAuthority(uuidClient.Authority, new Tokens(), "org");
        var uuidReceipt = request.IsMutation ? uuidClient.CreateReceipt(request) : null;
        var uuidResult = await uuidClient.ExecuteAsync(request, uuidAuthority,
            uuidAuthority.IssueGrant(request.OperationId, target), uuidReceipt);
        await Assert.That(uuidResult.Status).IsEqualTo(SecretStatus.Unknown);
        if (uuidReceipt is not null)
            await Assert.That(uuidReceipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments("identity")]
    [Arguments("{11111111-1111-4111-8111-111111111111}")]
    [Arguments("11111111111141118111111111111111")]
    public async Task MatchingHostIdentityDoesNotReplaceDeclaredUuidValidation(string identity)
    {
        var root = JsonNode.Parse(Response("aws"))!.AsObject();
        root.First().Value!["identityId"] = identity;
        using var request = CloudIdentityAuthenticationOperations.GetAwsAuth("org", identity);
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false,
            new Wire(root.ToJsonString()));
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), "org");
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId,
            new("org", resourceId: identity)));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
    }

    [Test]
    [Arguments("GET")]
    [Arguments("POST")]
    [Arguments("PATCH")]
    [Arguments("DELETE")]
    public async Task EveryKnownResultFieldIsProjectedWithoutRequestInference(string method)
    {
        using var aws = Aws(method);
        using var azure = Azure(method);
        using var gcp = Gcp(method);
        using var ali = AliCloud(method);
        using var awsDocument = JsonDocument.Parse(Response("aws"));
        using var azureDocument = JsonDocument.Parse(Response("azure"));
        using var gcpDocument = JsonDocument.Parse(Response("gcp"));
        using var aliDocument = JsonDocument.Parse(Response("alicloud"));
        var awsResult = aws.Parse(awsDocument.RootElement);
        var azureResult = azure.Parse(azureDocument.RootElement);
        var gcpResult = gcp.Parse(gcpDocument.RootElement);
        var aliResult = ali.Parse(aliDocument.RootElement);
        await Assert.That(awsResult.Type).IsEqualTo("returned-aws");
        await Assert.That(awsResult.AllowedAccountIds).IsEqualTo("");
        await Assert.That(awsResult.AllowedPrincipalArns).IsEqualTo("returned-principals");
        await Assert.That(awsResult.StsEndpoint).IsEqualTo("");
        await Assert.That(awsResult.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(azureResult.TenantId).IsEqualTo("");
        await Assert.That(azureResult.Resource).IsEqualTo("returned-resource");
        await Assert.That(azureResult.AllowedServicePrincipalIds).IsEqualTo("");
        await Assert.That(azureResult.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(gcpResult.Type).IsEqualTo("returned-gcp"); // No response enum is declared.
        await Assert.That(gcpResult.AllowedProjects.IsNull).IsTrue();
        await Assert.That(gcpResult.AllowedServiceAccounts.Value).IsEqualTo("");
        await Assert.That(gcpResult.AllowedZones.IsPresent).IsFalse();
        await Assert.That(gcpResult.AccessTokenPeriod).IsEqualTo(1.25d);
        await Assert.That(aliResult.Type).IsEqualTo("returned-ali");
        await Assert.That(aliResult.AllowedArns).IsEqualTo("");
        foreach (var result in new WorkloadAuthConfiguration[] { awsResult, azureResult, gcpResult, aliResult })
        {
            await Assert.That(result.Id).IsEqualTo(ConfigurationId);
            await Assert.That(result.IdentityId).IsEqualTo(IdentityId);
            await Assert.That(result.CreatedAt).IsEqualTo(DateTimeOffset.Parse("2026-10-10T00:00:00Z"));
            await Assert.That(result.UpdatedAt).IsEqualTo(DateTimeOffset.Parse("2026-10-11T00:00:00Z"));
            await Assert.That(result.AccessTokenTTL).IsEqualTo(0.5d);
            await Assert.That(result.AccessTokenMaxTTL).IsEqualTo(1.5d);
            await Assert.That(result.AccessTokenNumUsesLimit).IsEqualTo(0d);
            await Assert.That(result.HasUnestablishedTrustedIpProjection).IsTrue();
            await Assert.That(JsonSerializer.Serialize(result, result.GetType())).IsEqualTo("{}");
            await Assert.That(result.ToString()!.Contains("returned", StringComparison.Ordinal)).IsFalse();
        }
        await Descriptor(aws, "aws", method);
        await Descriptor(azure, "azure", method);
        await Descriptor(gcp, "gcp", method);
        await Descriptor(ali, "alicloud", method);
    }

    private static async Task Descriptor<T>(ManagementRequest<T> request, string strategy, string method) where T : notnull
    {
        await Assert.That(request.OperationId).IsEqualTo($"infisical.{method.ToLowerInvariant()}.v1.auth.{strategy}.auth.identities.by.identityId");
        await Assert.That(request.IsMutation).IsEqualTo(method != "GET");
        var bytes = request.CopyBody();
        await Assert.That(bytes is null).IsEqualTo(method is "GET" or "DELETE");
        if (bytes is not null) Array.Clear(bytes);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task EveryRequestFieldAndCopiedPolicyRetainsExplicitValues(bool update)
    {
        var ips = new List<IdentityTrustedIp> { new("127.0.0.1/32") };
        var policy = new WorkloadAuthTokenPolicy(0, update ? 0 : 1, 0, ips);
        var awsInput = new AwsAuthConfigurationInput("", "", "endpoint-canary", policy);
        var azureInput = new AzureAuthConfigurationInput("", "", "", policy);
        var gcpInput = new GcpAuthConfigurationInput(GcpAuthConfigurationType.Gce, "", "", "", policy);
        var aliInput = new AliCloudAuthConfigurationInput("arn-canary", policy);
        using var aws = update ? CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId, awsInput)
            : CloudIdentityAuthenticationOperations.AttachAwsAuth("org", IdentityId, awsInput);
        using var azure = update ? CloudIdentityAuthenticationOperations.UpdateAzureAuth("org", IdentityId, azureInput)
            : CloudIdentityAuthenticationOperations.AttachAzureAuth("org", IdentityId, azureInput);
        using var gcp = update ? CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, gcpInput)
            : CloudIdentityAuthenticationOperations.AttachGcpAuth("org", IdentityId, gcpInput);
        using var ali = update ? CloudIdentityAuthenticationOperations.UpdateAliCloudAuth("org", IdentityId, aliInput)
            : CloudIdentityAuthenticationOperations.AttachAliCloudAuth("org", IdentityId, aliInput);
        ips.Clear();
        using var a = Body(aws);
        using var z = Body(azure);
        using var g = Body(gcp);
        using var c = Body(ali);
        await Assert.That(a.RootElement.EnumerateObject().Count()).IsEqualTo(7);
        await Assert.That(z.RootElement.EnumerateObject().Count()).IsEqualTo(7);
        await Assert.That(g.RootElement.EnumerateObject().Count()).IsEqualTo(8);
        await Assert.That(c.RootElement.EnumerateObject().Count()).IsEqualTo(5);
        foreach (var body in new[] { a.RootElement, z.RootElement, g.RootElement, c.RootElement })
        {
            await Assert.That(body.GetProperty("accessTokenTTL").GetInt32()).IsEqualTo(0);
            await Assert.That(body.GetProperty("accessTokenMaxTTL").GetInt32()).IsEqualTo(update ? 0 : 1);
            await Assert.That(body.GetProperty("accessTokenNumUsesLimit").GetInt64()).IsEqualTo(0L);
            await Assert.That(body.GetProperty("accessTokenTrustedIps")[0].GetProperty("ipAddress").GetString()).IsEqualTo("127.0.0.1/32");
        }
        await Assert.That(a.RootElement.GetProperty("allowedPrincipalArns").GetString()).IsEqualTo("");
        await Assert.That(a.RootElement.GetProperty("allowedAccountIds").GetString()).IsEqualTo("");
        await Assert.That(a.RootElement.GetProperty("stsEndpoint").GetString()).IsEqualTo("endpoint-canary");
        foreach (string field in new[] { "tenantId", "resource", "allowedServicePrincipalIds" })
            await Assert.That(z.RootElement.GetProperty(field).GetString()).IsEqualTo("");
        foreach (string field in new[] { "allowedProjects", "allowedServiceAccounts", "allowedZones" })
            await Assert.That(g.RootElement.GetProperty(field).GetString()).IsEqualTo("");
        await Assert.That(g.RootElement.GetProperty("type").GetString()).IsEqualTo("gce");
        await Assert.That(c.RootElement.GetProperty("allowedArns").GetString()).IsEqualTo("arn-canary");
        await Assert.That(aws.Target.SecondaryId).IsEqualTo(CloudIdentityAuthenticationOperations.AwsAuthConfigurationTarget("org", IdentityId, awsInput, update).SecondaryId);
        await Assert.That(azure.Target.SecondaryId).IsEqualTo(CloudIdentityAuthenticationOperations.AzureAuthConfigurationTarget("org", IdentityId, azureInput, update).SecondaryId);
        await Assert.That(gcp.Target.SecondaryId).IsEqualTo(CloudIdentityAuthenticationOperations.GcpAuthConfigurationTarget("org", IdentityId, gcpInput, update).SecondaryId);
        await Assert.That(ali.Target.SecondaryId).IsEqualTo(CloudIdentityAuthenticationOperations.AliCloudAuthConfigurationTarget("org", IdentityId, aliInput, update).SecondaryId);
        foreach (var input in new object[] { awsInput, azureInput, gcpInput, aliInput, policy })
        {
            await Assert.That(JsonSerializer.Serialize(input)).IsEqualTo("{}");
            await Assert.That(input.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
        var copy = aws.CopyBody()!;
        Array.Clear(copy);
        using var intact = Body(aws);
        await Assert.That(intact.RootElement.GetProperty("stsEndpoint").GetString()).IsEqualTo("endpoint-canary");
    }

    [Test]
    [Arguments(GcpAuthConfigurationType.Iam)]
    [Arguments(GcpAuthConfigurationType.Gce)]
    public async Task GcpDiscriminatorsAllowAllEstablishedFieldsOnBothMethods(GcpAuthConfigurationType type)
    {
        var input = new GcpAuthConfigurationInput(type, "accounts", "projects", "zones");
        using var attach = CloudIdentityAuthenticationOperations.AttachGcpAuth("org", IdentityId, input);
        using var update = CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, input);
        foreach (var request in new[] { attach, update })
        {
            using var body = Body(request);
            await Assert.That(body.RootElement.GetProperty("type").GetString()).IsEqualTo(type == GcpAuthConfigurationType.Iam ? "iam" : "gce");
            await Assert.That(body.RootElement.GetProperty("allowedProjects").GetString()).IsEqualTo("projects");
            await Assert.That(body.RootElement.GetProperty("allowedZones").GetString()).IsEqualTo("zones");
            await Assert.That(body.RootElement.GetProperty("allowedServiceAccounts").GetString()).IsEqualTo("accounts");
        }
        await Assert.That(attach.Target.SecondaryId == update.Target.SecondaryId).IsFalse();
    }

    [Test]
    public async Task OmittedPatchAndEmptyPolicyHaveDistinctWholeIntentWithoutDefaults()
    {
        using var aws = CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId, new());
        using var azure = CloudIdentityAuthenticationOperations.UpdateAzureAuth("org", IdentityId, new());
        using var gcp = CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, new());
        using var a = Body(aws);
        using var z = Body(azure);
        using var g = Body(gcp);
        foreach (var document in new[] { a, z, g }) await Assert.That(document.RootElement.EnumerateObject().Count()).IsEqualTo(0);
        // Current packet permits []; frozen registry's older minItems=1 is not inferred into current contracts.
        using var explicitEmpty = CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId,
            new(allowedAccountIds: "", policy: new(accessTokenTrustedIps: [])));
        using var body = Body(explicitEmpty);
        await Assert.That(body.RootElement.GetProperty("accessTokenTrustedIps").GetArrayLength()).IsEqualTo(0);
        await Assert.That(body.RootElement.GetProperty("allowedAccountIds").GetString()).IsEqualTo("");
        await Assert.That(aws.Target.SecondaryId == explicitEmpty.Target.SecondaryId).IsFalse();
        using var ali = CloudIdentityAuthenticationOperations.UpdateAliCloudAuth("org", IdentityId, new("arns"));
        using var aliBody = Body(ali);
        await Assert.That(aliBody.RootElement.EnumerateObject().Count()).IsEqualTo(1);
    }

    [Test]
    public async Task InvalidBranchesAndNativeBoundsFailBeforeDispatch()
    {
        await Assert.That(() => new AwsAuthConfigurationInput(stsEndpoint: "")).Throws<ArgumentException>();
        await Assert.That(() => new AwsAuthConfigurationInput(allowedAccountIds: new string('a', 4097))).Throws<ArgumentException>();
        await Assert.That(() => new AwsAuthConfigurationInput(allowedPrincipalArns: new string('a', 4097))).Throws<ArgumentException>();
        await Assert.That(() => new AliCloudAuthConfigurationInput("")).Throws<ArgumentException>();
        await Assert.That(() => new AliCloudAuthConfigurationInput(new string('a', 501))).Throws<ArgumentException>();
        await Assert.That(() => new AliCloudAuthConfigurationInput(null!)).Throws<ArgumentNullException>();
        await Assert.That(() => new GcpAuthConfigurationInput((GcpAuthConfigurationType)9)).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AttachGcpAuth("org", IdentityId, new())).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AttachAzureAuth("org", IdentityId, new())).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AttachAzureAuth("org", IdentityId, new(tenantId: ""))).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AttachAwsAuth("org", IdentityId, new(policy: new(accessTokenMaxTTL: 0)))).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AttachAliCloudAuth("org", IdentityId, new("arns", new(accessTokenMaxTTL: 0)))).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(-1)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenMaxTTL: 315360001)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenNumUsesLimit: -1)).Throws<ArgumentException>();
        await Assert.That(() => new WorkloadAuthTokenPolicy(accessTokenTrustedIps: [null!])).Throws<ArgumentException>();
        await Assert.That(() => CloudIdentityAuthenticationOperations.AwsAuthConfigurationTarget("org", IdentityId, null!)).Throws<ArgumentNullException>();
        using var maximum = CloudIdentityAuthenticationOperations.AttachAliCloudAuth("org", IdentityId,
            new(new string('a', 500), new(315360000, 315360000, long.MaxValue)));
        using var body = Body(maximum);
        await Assert.That(body.RootElement.GetProperty("accessTokenNumUsesLimit").GetInt64()).IsEqualTo(long.MaxValue);
        await Assert.That(body.RootElement.GetProperty("accessTokenTTL").GetInt32()).IsEqualTo(315360000);
    }

    [Test]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("alicloud")]
    public async Task ChangedWholeIntentIsDeniedBeforeTokenAcquisition(string strategy)
    {
        var tokens = new Tokens();
        var wire = new Wire("{}");
        using var transport = new ManagementTransport(new("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, tokens, "org");
        switch (strategy)
        {
            case "aws":
                using (var request = CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId, new(allowedAccountIds: "")))
                    await Denied(client, authority, request, Approved(strategy, "PATCH"));
                break;
            case "azure":
                using (var request = CloudIdentityAuthenticationOperations.UpdateAzureAuth("org", IdentityId, new(resource: "")))
                    await Denied(client, authority, request, Approved(strategy, "PATCH"));
                break;
            case "gcp":
                using (var request = CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, new(allowedZones: "")))
                    await Denied(client, authority, request, Approved(strategy, "PATCH"));
                break;
            default:
                using (var request = CloudIdentityAuthenticationOperations.UpdateAliCloudAuth("org", IdentityId, new("other")))
                    await Denied(client, authority, request, Approved(strategy, "PATCH"));
                break;
        }
        await Assert.That(() => authority.IssueGrant("operation", new("foreign", resourceId: IdentityId))).Throws<ArgumentException>();
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Observed).IsFalse();
    }

    private static async Task Denied<T>(ManagementClient client, ManagementAuthority authority,
        ManagementRequest<T> request, ManagementTarget target) where T : notnull
    {
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
    }

    [Test]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("alicloud")]
    public async Task KnownMalformedFieldsFailWhileUnknownNodesRemainFlags(string strategy)
    {
        foreach (string response in new[]
        {
            Response(strategy).Replace($"\"identityId\":\"{IdentityId}\"", $"\"identityId\":\"{ForeignIdentityId}\"", StringComparison.Ordinal),
            Response(strategy).Replace("\"accessTokenTTL\":0.5", "\"accessTokenTTL\":null", StringComparison.Ordinal),
            Response(strategy).Replace("\"createdAt\":\"2026-10-10T00:00:00Z\",", "", StringComparison.Ordinal),
            Response(strategy).Replace("\"updatedAt\":\"2026-10-11T00:00:00Z\"", "\"updatedAt\":false", StringComparison.Ordinal)
        })
        {
            using var document = JsonDocument.Parse(response);
            await Assert.That(() => Parse(strategy, document.RootElement)).Throws<ManagementContractException>();
        }
        string valid = Response(strategy);
        using var absent = JsonDocument.Parse(valid.Replace("\"accessTokenTrustedIps\":false,", "", StringComparison.Ordinal)
            .Replace("\"accessTokenTTL\":0.5,", "", StringComparison.Ordinal)
            .Replace("\"accessTokenMaxTTL\":1.5,", "", StringComparison.Ordinal)
            .Replace("\"accessTokenNumUsesLimit\":0,", "", StringComparison.Ordinal));
        var result = Parse(strategy, absent.RootElement);
        await Assert.That(result.HasUnestablishedTrustedIpProjection).IsFalse();
        await Assert.That(result.AccessTokenTTL is null).IsTrue();
        await Assert.That(result.AccessTokenMaxTTL is null).IsTrue();
        await Assert.That(result.AccessTokenNumUsesLimit is null).IsTrue();
        foreach (string unknown in new[] { "null", "[]", "{}", "\"opaque\"", "42" })
        {
            using var document = JsonDocument.Parse(valid.Replace("\"accessTokenTrustedIps\":false", "\"accessTokenTrustedIps\":" + unknown, StringComparison.Ordinal));
            await Assert.That(Parse(strategy, document.RootElement).HasUnestablishedTrustedIpProjection).IsTrue();
        }
    }

    [Test]
    public async Task NullableGcpFieldsRetainAbsenceNullAndEmptyIndependently()
    {
        using var request = Gcp("GET");
        foreach (string field in new[] { "allowedProjects", "allowedServiceAccounts", "allowedZones" })
            foreach (string node in new[] { "", ",\"" + field + "\":null", ",\"" + field + "\":\"\"" })
            {
                using var document = JsonDocument.Parse("{\"identityGcpAuth\":{" + Common + ",\"type\":\"gce\"" + node + "}}");
                var result = request.Parse(document.RootElement);
                var value = field == "allowedProjects" ? result.AllowedProjects : field == "allowedServiceAccounts" ? result.AllowedServiceAccounts : result.AllowedZones;
                await Assert.That(value.IsPresent).IsEqualTo(node.Length != 0);
                if (node.EndsWith("null", StringComparison.Ordinal)) await Assert.That(value.IsNull).IsTrue();
                if (node.EndsWith("\"\"", StringComparison.Ordinal)) await Assert.That(value.Value).IsEqualTo("");
            }
    }

    [Test]
    [Arguments("aws")]
    [Arguments("azure")]
    [Arguments("gcp")]
    [Arguments("alicloud")]
    public async Task EveryStrategySpecificKnownPrimitiveIsValidated(string strategy)
    {
        using var original = JsonDocument.Parse(Response(strategy));
        var inner = original.RootElement.EnumerateObject().Single().Value;
        string[] fields = strategy switch
        {
            "aws" => ["type", "allowedPrincipalArns", "allowedAccountIds", "stsEndpoint", "accessTokenPeriod"],
            "azure" => ["tenantId", "resource", "allowedServicePrincipalIds", "accessTokenPeriod"],
            "gcp" => ["type", "allowedProjects", "allowedServiceAccounts", "accessTokenPeriod"],
            _ => ["type", "allowedArns"]
        };
        foreach (string field in fields)
        {
            string old = "\"" + field + "\":" + inner.GetProperty(field).GetRawText();
            using var malformed = JsonDocument.Parse(Response(strategy).Replace(old, "\"" + field + "\":false", StringComparison.Ordinal));
            await Assert.That(() => Parse(strategy, malformed.RootElement)).Throws<ManagementContractException>();
        }
        if (strategy != "alicloud")
        {
            using var absent = JsonDocument.Parse(Response(strategy).Replace(",\"accessTokenPeriod\":1.25", "", StringComparison.Ordinal));
            var result = Parse(strategy, absent.RootElement);
            double? period = result switch
            {
                AwsAuthConfiguration aws => aws.AccessTokenPeriod,
                AzureAuthConfiguration azure => azure.AccessTokenPeriod,
                GcpAuthConfiguration gcp => gcp.AccessTokenPeriod,
                _ => throw new InvalidOperationException()
            };
            await Assert.That(period is null).IsTrue();
        }
    }

    [Test]
    [Arguments("aws", "GET")]
    [Arguments("aws", "POST")]
    [Arguments("aws", "PATCH")]
    [Arguments("aws", "DELETE")]
    [Arguments("azure", "GET")]
    [Arguments("azure", "POST")]
    [Arguments("azure", "PATCH")]
    [Arguments("azure", "DELETE")]
    [Arguments("gcp", "GET")]
    [Arguments("gcp", "POST")]
    [Arguments("gcp", "PATCH")]
    [Arguments("gcp", "DELETE")]
    [Arguments("alicloud", "GET")]
    [Arguments("alicloud", "POST")]
    [Arguments("alicloud", "PATCH")]
    [Arguments("alicloud", "DELETE")]
    public async Task HandwrittenRefitRoutesConstructWithoutDispatch(string strategy, string method)
    {
        var wire = new Wire("{}");
        using var client = new HttpClient(wire) { BaseAddress = new("https://management.test") };
        var api = RestService.For<ICloudIdentityAuthenticationApi>(client,
            new RefitSettings { ExceptionFactory = _ => ValueTask.FromResult<Exception?>(null) });
        using var body = new StringContent("""{"canary":false}""", Encoding.UTF8, "application/json");
        using var request = await ((strategy, method) switch
        {
            ("aws", "GET") => api.GetAws(IdentityId, default),
            ("aws", "POST") => api.AttachAws(IdentityId, body, default),
            ("aws", "PATCH") => api.UpdateAws(IdentityId, body, default),
            ("aws", "DELETE") => api.DeleteAws(IdentityId, default),
            ("azure", "GET") => api.GetAzure(IdentityId, default),
            ("azure", "POST") => api.AttachAzure(IdentityId, body, default),
            ("azure", "PATCH") => api.UpdateAzure(IdentityId, body, default),
            ("azure", "DELETE") => api.DeleteAzure(IdentityId, default),
            ("gcp", "GET") => api.GetGcp(IdentityId, default),
            ("gcp", "POST") => api.AttachGcp(IdentityId, body, default),
            ("gcp", "PATCH") => api.UpdateGcp(IdentityId, body, default),
            ("gcp", "DELETE") => api.DeleteGcp(IdentityId, default),
            ("alicloud", "GET") => api.GetAliCloud(IdentityId, default),
            ("alicloud", "POST") => api.AttachAliCloud(IdentityId, body, default),
            ("alicloud", "PATCH") => api.UpdateAliCloud(IdentityId, body, default),
            _ => api.DeleteAliCloud(IdentityId, default)
        });
        await Assert.That(request.Method.Method).IsEqualTo(method);
        await Assert.That(new Uri(client.BaseAddress, request.RequestUri!).AbsolutePath).IsEqualTo($"/api/v1/auth/{strategy}-auth/identities/{IdentityId}");
        if (method is "POST" or "PATCH")
            await Assert.That(await request.Content!.ReadAsStringAsync()).IsEqualTo("""{"canary":false}""");
        else await Assert.That(request.Content is null).IsTrue();
        await Assert.That(wire.Observed).IsFalse();
    }

    private static ManagementRequest<AwsAuthConfiguration> Aws(string method) => method switch
    {
        "POST" => CloudIdentityAuthenticationOperations.AttachAwsAuth("org", IdentityId, new()),
        "PATCH" => CloudIdentityAuthenticationOperations.UpdateAwsAuth("org", IdentityId, new()),
        "GET" => CloudIdentityAuthenticationOperations.GetAwsAuth("org", IdentityId),
        _ => CloudIdentityAuthenticationOperations.DeleteAwsAuth("org", IdentityId)
    };
    private static ManagementRequest<AzureAuthConfiguration> Azure(string method) => method switch
    {
        "POST" => CloudIdentityAuthenticationOperations.AttachAzureAuth("org", IdentityId, new("", "")),
        "PATCH" => CloudIdentityAuthenticationOperations.UpdateAzureAuth("org", IdentityId, new("", "")),
        "GET" => CloudIdentityAuthenticationOperations.GetAzureAuth("org", IdentityId),
        _ => CloudIdentityAuthenticationOperations.DeleteAzureAuth("org", IdentityId)
    };
    private static ManagementRequest<GcpAuthConfiguration> Gcp(string method) => method switch
    {
        "POST" => CloudIdentityAuthenticationOperations.AttachGcpAuth("org", IdentityId, new(GcpAuthConfigurationType.Iam)),
        "PATCH" => CloudIdentityAuthenticationOperations.UpdateGcpAuth("org", IdentityId, new(GcpAuthConfigurationType.Iam)),
        "GET" => CloudIdentityAuthenticationOperations.GetGcpAuth("org", IdentityId),
        _ => CloudIdentityAuthenticationOperations.DeleteGcpAuth("org", IdentityId)
    };
    private static ManagementRequest<AliCloudAuthConfiguration> AliCloud(string method) => method switch
    {
        "POST" => CloudIdentityAuthenticationOperations.AttachAliCloudAuth("org", IdentityId, new("arns")),
        "PATCH" => CloudIdentityAuthenticationOperations.UpdateAliCloudAuth("org", IdentityId, new("arns")),
        "GET" => CloudIdentityAuthenticationOperations.GetAliCloudAuth("org", IdentityId),
        _ => CloudIdentityAuthenticationOperations.DeleteAliCloudAuth("org", IdentityId)
    };
    private static ManagementTarget Approved(string strategy, string method) => method is "GET" or "DELETE"
        ? new("org", resourceId: IdentityId) : strategy switch
        {
            "aws" => CloudIdentityAuthenticationOperations.AwsAuthConfigurationTarget("org", IdentityId, new(), method == "PATCH"),
            "azure" => CloudIdentityAuthenticationOperations.AzureAuthConfigurationTarget("org", IdentityId, new("", ""), method == "PATCH"),
            "gcp" => CloudIdentityAuthenticationOperations.GcpAuthConfigurationTarget("org", IdentityId, new(GcpAuthConfigurationType.Iam), method == "PATCH"),
            _ => CloudIdentityAuthenticationOperations.AliCloudAuthConfigurationTarget("org", IdentityId, new("arns"), method == "PATCH")
        };
    private static WorkloadAuthConfiguration Parse(string strategy, JsonElement root)
    {
        switch (strategy)
        {
            case "aws": using (var request = Aws("GET")) return request.Parse(root);
            case "azure": using (var request = Azure("GET")) return request.Parse(root);
            case "gcp": using (var request = Gcp("GET")) return request.Parse(root);
            default: using (var request = AliCloud("GET")) return request.Parse(root);
        }
    }
    private static JsonDocument Body<T>(ManagementRequest<T> request) where T : notnull
    {
        byte[] bytes = request.CopyBody()!;
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            return JsonDocument.Parse(stream);
        }
        finally { Array.Clear(bytes); }
    }
    private const string Common = $$"""
        "id":"{{ConfigurationId}}","identityId":"{{IdentityId}}","createdAt":"2026-10-10T00:00:00Z","updatedAt":"2026-10-11T00:00:00Z",
        "accessTokenTTL":0.5,"accessTokenMaxTTL":1.5,"accessTokenNumUsesLimit":0,"accessTokenTrustedIps":false
        """;
    private static string Response(string strategy) => "{\"" + (strategy switch
    {
        "aws" => "identityAwsAuth",
        "azure" => "identityAzureAuth",
        "gcp" => "identityGcpAuth",
        _ => "identityAliCloudAuth"
    }) + "\":{" + Common + "," + (strategy switch
    {
        "aws" => "\"type\":\"returned-aws\",\"allowedPrincipalArns\":\"returned-principals\",\"allowedAccountIds\":\"\",\"stsEndpoint\":\"\",\"accessTokenPeriod\":1.25",
        "azure" => "\"tenantId\":\"\",\"resource\":\"returned-resource\",\"allowedServicePrincipalIds\":\"\",\"accessTokenPeriod\":1.25",
        "gcp" => "\"type\":\"returned-gcp\",\"allowedProjects\":null,\"allowedServiceAccounts\":\"\",\"accessTokenPeriod\":1.25",
        _ => "\"type\":\"returned-ali\",\"allowedArns\":\"\""
    }) + "}}";

    private sealed class Tokens : IInfisicalTokenSource
    {
        internal bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("admin-canary"))));
        }
    }

    private sealed class Wire(string response) : HttpMessageHandler
    {
        internal bool Observed { get; private set; }
        internal string? Method { get; private set; }
        internal string? Path { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Observed = true;
            Method = request.Method.Method;
            Path = request.RequestUri!.AbsolutePath;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response, Encoding.UTF8, "application/json")
            });
        }
    }
}
