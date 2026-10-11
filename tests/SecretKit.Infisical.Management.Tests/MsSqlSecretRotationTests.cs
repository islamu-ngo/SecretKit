using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class MsSqlSecretRotationTests
{
    private const string Org = "b4193215-cd74-4dd6-aec9-b2f3e07eddeb";
    private const string Project = "project-private";
    private const string Id = "7b15ac64-78ee-4fa5-a7b4-eb2da9ac5796";
    private const string Prefix = "infisical.";
    private const string Path = "/api/v2/secret-rotations/mssql-credentials";

    [Test]
    [Arguments("root")]
    [Arguments("summary")]
    [Arguments("connection")]
    [Arguments("environment")]
    [Arguments("folder")]
    [Arguments("parameters")]
    [Arguments("secretsMapping")]
    [Arguments("rotateAtUtc")]
    [Arguments("passwordRequirements")]
    [Arguments("required")]
    public async Task ContractMetadataRejectsUnlistedMembersAtEveryClosedObject(string branch)
    {
        var value = Metadata();
        value["parameters"]!["passwordRequirements"] = JsonNode.Parse("""
            {"length":20,"required":{"digits":1,"lowercase":1,"symbols":1,"uppercase":1}}
            """);
        var root = new JsonObject { ["secretRotation"] = value };
        JsonNode selected = branch switch
        {
            "root" => root,
            "summary" => value,
            "passwordRequirements" => value["parameters"]!["passwordRequirements"]!,
            "required" => value["parameters"]!["passwordRequirements"]!["required"]!,
            _ => value[branch]!
        };
        selected["unlisted"] = "withheld-private";
        using var document = JsonDocument.Parse(root.ToJsonString());
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("name")]
    [Arguments("connection")]
    [Arguments("connection.id")]
    [Arguments("connection.app")]
    [Arguments("connection.name")]
    [Arguments("environment.id")]
    [Arguments("environment.name")]
    [Arguments("environment.slug")]
    [Arguments("folder.id")]
    [Arguments("folder.path")]
    [Arguments("updatedAt")]
    [Arguments("lastRotatedAt")]
    [Arguments("lastRotationAttemptedAt")]
    [Arguments("rotationInterval")]
    [Arguments("parameters.username1")]
    [Arguments("parameters.username2")]
    [Arguments("secretsMapping.username")]
    [Arguments("secretsMapping.password")]
    [Arguments("rotateAtUtc.hours")]
    [Arguments("rotateAtUtc.minutes")]
    public async Task ContractEveryRemainingRequiredSummaryFieldFailsClosedWhenMissing(string field)
    {
        var value = Metadata();
        var parts = field.Split('.');
        if (parts.Length == 1) value.Remove(field);
        else value[parts[0]]!.AsObject().Remove(parts[1]);
        using var document = JsonDocument.Parse(new JsonObject { ["secretRotation"] = value }.ToJsonString());
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("root")]
    [Arguments("option")]
    [Arguments("template")]
    [Arguments("mapping")]
    [Arguments("name")]
    [Arguments("connection")]
    [Arguments("createUserStatement")]
    [Arguments("rotationStatement")]
    [Arguments("username")]
    [Arguments("password")]
    public async Task ContractOptionRequiredBranchesAndClosedDiscriminatorsFailClosed(string defect)
    {
        var value = Options();
        var option = value["secretRotationOptions"]![1]!;
        var template = option["template"]!;
        switch (defect)
        {
            case "root": value["unlisted"] = true; break;
            case "option": option["unlisted"] = true; break;
            case "template": template["unlisted"] = true; break;
            case "mapping": template["secretsMapping"]!["unlisted"] = true; break;
            case "name": option["name"] = "MySQL Credentials"; break;
            case "connection": option["connection"] = "mysql"; break;
            case "username": case "password": template["secretsMapping"]!.AsObject().Remove(defect); break;
            default: template.AsObject().Remove(defect); break;
        }
        using var document = JsonDocument.Parse(value.ToJsonString());
        using var request = MsSqlSecretRotationOperations.MsSqlOptionsSubset(Org);
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    public async Task ActualCredentialCheckRejects200WithoutReadingMaterialOrApplyingReceipt()
    {
        using var wire = new Wire(HttpMethod.Post, Path + "/" + Id + "/check-credentials")
        { UnreadableSuccess = true };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var request = MsSqlSecretRotationOperations.CheckCredentials(Org, Address());
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, MsSqlSecretRotationOperations.SelectionTarget(Org, Address())), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(wire.Dispatched).IsTrue();
        await Assert.That(wire.ResponseBodyReads).IsEqualTo(0);
    }

    [Test]
    public async Task ContractClosedOptionRejectsUnknownMemberThroughPublicTransport()
    {
        var response = Options();
        response["secretRotationOptions"]![1]!["unexpected"] = "withheld-private";
        using var wire = new Wire(HttpMethod.Get, "/api/v2/secret-rotations/options")
        { ResponseOverride = response };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org);
        using var request = MsSqlSecretRotationOperations.MsSqlOptionsSubset(Org);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, new(Org, secondaryId: "mssql-credentials-subset")));
        (result.IsSuccess ? result.Value : null)?.Dispose();
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Dispatched).IsTrue();
    }

    [Test]
    public async Task EmptyCheckAcknowledgementDoesNotReadAResponseBody()
    {
        using var wire = new Wire(HttpMethod.Post, Path + "/" + Id + "/check-credentials")
        { ResponseStatus = HttpStatusCode.NoContent };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var request = MsSqlSecretRotationOperations.CheckCredentials(Org, Address());
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, MsSqlSecretRotationOperations.SelectionTarget(Org, Address())), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(wire.ResponseBodyReads).IsEqualTo(0);
    }

    [Test]
    public async Task EmptyCheckStatusDoesNotAuthorizeOtherOperations()
    {
        using var wire = new Wire(HttpMethod.Delete, Path + "/" + Id)
        { ResponseStatus = HttpStatusCode.NoContent };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var request = MsSqlSecretRotationOperations.Delete(Org, Address());
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, MsSqlSecretRotationOperations.DeletionTarget(Org, Address())), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task ActualManagementBindingDispatchesEstablishedRoute(int route)
    {
        if (route == 8)
        {
            using var wire = new NativeWire();
            using var http = new HttpClient(wire);
            var clientAuthority = new SecretAuthority();
            var native = new InfisicalRotationClient(new Uri("https://management.test"), http,
                clientAuthority, new(clientAuthority, new Tokens(), Project, "dev", "/"));
            var target = new SecretReference(clientAuthority, Address());
            var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
            var outcome = await native.RotateSecretsAsync(target, receipt);
            await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
            await Assert.That(receipt.Effect).IsEqualTo(InfisicalRotationEffect.AcceptedPending);
            await Assert.That(outcome.Value.ConsumerDeliveryVerified).IsFalse();
            await Assert.That(outcome.Value.FleetConvergenceVerified).IsFalse();
            await Assert.That((await native.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(wire.Commits).IsEqualTo(1);
            return;
        }
        var (operation, method, path) = Route(route);
        using var parameters = new MsSqlRotationParameters("first-private", "second-private");
        var creation = Creation(parameters);
        var update = new MsSqlSecretRotationUpdate();
        var move = new MsSqlSecretRotationMove("next", "/next");
        switch (route)
        {
            case 0:
                await Execute(MsSqlSecretRotationOperations.List(Org, Project), new(Org, Project)); break;
            case 1:
                await Execute(MsSqlSecretRotationOperations.Create(Org, creation),
                MsSqlSecretRotationOperations.CreationTarget(Org, Creation(parameters))); break;
            case 2:
                await Execute(MsSqlSecretRotationOperations.Delete(Org, Address()),
                MsSqlSecretRotationOperations.DeletionTarget(Org, Address())); break;
            case 3:
                await Execute(MsSqlSecretRotationOperations.Get(Org, Address()),
                MsSqlSecretRotationOperations.SelectionTarget(Org, Address())); break;
            case 4:
                await Execute(MsSqlSecretRotationOperations.Update(Org, Address(), update),
                MsSqlSecretRotationOperations.UpdateTarget(Org, Address(), new())); break;
            case 5:
                await Execute(MsSqlSecretRotationOperations.CheckCredentials(Org, Address()),
                MsSqlSecretRotationOperations.SelectionTarget(Org, Address())); break;
            case 6:
                await Execute(MsSqlSecretRotationOperations.GetGeneratedCredentials(Org, Address()),
                MsSqlSecretRotationOperations.SelectionTarget(Org, Address())); break;
            case 7:
                await Execute(MsSqlSecretRotationOperations.Move(Org, Address(), move),
                MsSqlSecretRotationOperations.MoveTarget(Org, Address(), new("next", "/next"))); break;
            case 9:
                await Execute(MsSqlSecretRotationOperations.GetByName(Org, Project, "dev", "/", "rotation-private"),
                MsSqlSecretRotationOperations.NameTarget(Org, Project, "dev", "/", "rotation-private")); break;
            case 10:
                await Execute(MsSqlSecretRotationOperations.ListMsSqlSubset(Org, Project),
                new(Org, Project, secondaryId: "mssql-credentials-subset")); break;
            default:
                await Execute(MsSqlSecretRotationOperations.MsSqlOptionsSubset(Org),
                new(Org, secondaryId: "mssql-credentials-subset")); break;
        }

        async Task Execute<T>(ManagementRequest<T> request, ManagementTarget independent) where T : notnull
        {
            using var owned = request;
            var wire = new Wire(method, path) { RouteNumber = route };
            using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024,
                null, false, wire);
            var client = new ManagementClient(transport);
            var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, independent.ProjectId);
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(operation, independent), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            (result.Value as IDisposable)?.Dispose();
            await Assert.That(wire.Dispatched).IsTrue();
            if (receipt is not null)
            {
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                if (route == 1) await Assert.That(wire.Stored!["connectionId"]!.GetValue<string>()).IsEqualTo(Id);
                if (route == 4) await Assert.That(wire.Stored!.Count).IsEqualTo(0);
                if (route == 7) await Assert.That(wire.Stored!["destinationEnvironment"]!.GetValue<string>()).IsEqualTo("next");
                await Assert.That((await client.ExecuteAsync(request, authority,
                    authority.IssueGrant(operation, independent), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
                await Assert.That(wire.Commits).IsEqualTo(1);
            }
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task ContractCreationAndPatchPreserveEveryEstablishedAlternative(int variant)
    {
        using var statement = SecretMaterial.FromText("statement-private");
        using var parameters = new MsSqlRotationParameters("first-private", "second-private",
            variant == 0 ? null : new(20.5, 0.5, 1.5, 2.5, 3.5, variant == 1 ? null : "!"),
            variant == 0 ? null : statement);
        statement.Dispose();
        MsSqlRotationNullableText? description = variant switch
        { 0 => null, 1 => new(null), 2 => new(""), _ => new("description-private") };
        var time = variant == 0 ? null : new MsSqlRotationTime(1.5, 2.5);
        bool? enabled = variant == 0 ? null : variant == 3;
        var creation = new MsSqlSecretRotationCreation("rotation-private", Project, "dev", "/", Id, 1.5, parameters,
            new("USERNAME", "PASSWORD"), time, description, enabled);
        var update = new MsSqlSecretRotationUpdate("rotation-private", description, enabled, 1.5,
            parameters, new("USERNAME", "PASSWORD"), time);
        using var create = MsSqlSecretRotationOperations.Create(Org, creation);
        using var patch = MsSqlSecretRotationOperations.Update(Org, Address(), update);
        var createTarget = MsSqlSecretRotationOperations.CreationTarget(Org, creation);
        var patchTarget = MsSqlSecretRotationOperations.UpdateTarget(Org, Address(), update);
        await Assert.That(create.Target.SecondaryId).IsEqualTo(createTarget.SecondaryId);
        await Assert.That(patch.Target.SecondaryId).IsEqualTo(patchTarget.SecondaryId);
        parameters.Dispose();
        foreach (var request in new[] { create, patch })
        {
            byte[] body = request.CopyBody()!;
            try
            {
                using var json = JsonDocument.Parse(body);
                var root = json.RootElement;
                await Assert.That(root.GetProperty("rotationInterval").GetDouble()).IsEqualTo(1.5);
                await Assert.That(root.GetProperty("secretsMapping").GetProperty("password").GetString()).IsEqualTo("PASSWORD");
                await Assert.That(root.GetProperty("parameters").GetProperty("username1").GetString()).IsEqualTo("first-private");
                await Assert.That(root.GetProperty("parameters").GetProperty("username2").GetString()).IsEqualTo("second-private");
                await Assert.That(root.TryGetProperty("description", out var desc)).IsEqualTo(variant != 0);
                await Assert.That(root.TryGetProperty("rotateAtUtc", out var utc)).IsEqualTo(variant != 0);
                await Assert.That(root.TryGetProperty("isAutoRotationEnabled", out var flag)).IsEqualTo(variant != 0);
                await Assert.That(root.GetProperty("parameters").TryGetProperty("rotationStatement", out var stmt)).IsEqualTo(variant != 0);
                await Assert.That(root.GetProperty("parameters").TryGetProperty("passwordRequirements", out var requirements)).IsEqualTo(variant != 0);
                if (variant != 0)
                {
                    await Assert.That(flag.GetBoolean()).IsEqualTo(variant == 3);
                    await Assert.That(utc.GetProperty("hours").GetDouble()).IsEqualTo(1.5);
                    await Assert.That(utc.GetProperty("minutes").GetDouble()).IsEqualTo(2.5);
                    await Assert.That(stmt.GetString()).IsEqualTo("statement-private");
                    await Assert.That(requirements.GetProperty("length").GetDouble()).IsEqualTo(20.5);
                    await Assert.That(requirements.GetProperty("required").GetProperty("digits").GetDouble()).IsEqualTo(0.5);
                    await Assert.That(requirements.GetProperty("required").GetProperty("lowercase").GetDouble()).IsEqualTo(1.5);
                    await Assert.That(requirements.GetProperty("required").GetProperty("symbols").GetDouble()).IsEqualTo(2.5);
                    await Assert.That(requirements.GetProperty("required").GetProperty("uppercase").GetDouble()).IsEqualTo(3.5);
                    await Assert.That(requirements.TryGetProperty("allowedSymbols", out _)).IsEqualTo(variant >= 2);
                    await Assert.That(desc.ValueKind).IsEqualTo(variant == 1 ? JsonValueKind.Null : JsonValueKind.String);
                    if (variant == 2) await Assert.That(desc.GetString()).IsEqualTo("");
                }
                await Assert.That(root.TryGetProperty("projectId", out _)).IsEqualTo(ReferenceEquals(request, create));
                if (ReferenceEquals(request, create))
                {
                    await Assert.That(root.GetProperty("environment").GetString()).IsEqualTo("dev");
                    await Assert.That(root.GetProperty("secretPath").GetString()).IsEqualTo("/");
                    await Assert.That(root.GetProperty("connectionId").GetString()).IsEqualTo(Id);
                }
            }
            finally { Array.Clear(body); }
        }
        foreach (var value in new object[] { create, patch, creation, update, parameters, createTarget })
        {
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task ContractEmptyUpdateAndRequestDisposalHaveNoDefaults()
    {
        using var request = MsSqlSecretRotationOperations.Update(Org, Address(), new());
        byte[] body = request.CopyBody()!;
        try { await Assert.That(Encoding.UTF8.GetString(body)).IsEqualTo("{}"); }
        finally { Array.Clear(body); }
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
        using var parameters = new MsSqlRotationParameters("one", "two");
        parameters.Dispose();
        await Assert.That(() => MsSqlSecretRotationOperations.Create(Org, Creation(parameters))).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task ContractDeletionAndMovePreserveOmittedFalseTrueIntents(int variant)
    {
        bool? flag = variant == 0 ? null : variant == 2;
        using var deletion = MsSqlSecretRotationOperations.Delete(Org, Address(), flag, flag);
        await Assert.That(deletion.Path).IsEqualTo(Path + "/" + Id + (variant == 0 ? "" :
            "?deleteSecrets=" + (flag == true ? "true" : "false") + "&revokeGeneratedCredentials=" + (flag == true ? "true" : "false")));
        var move = new MsSqlSecretRotationMove("next", "/next", flag);
        using var request = MsSqlSecretRotationOperations.Move(Org, Address(), move);
        byte[] body = request.CopyBody()!;
        try
        {
            using var json = JsonDocument.Parse(body);
            await Assert.That(json.RootElement.GetProperty("destinationEnvironment").GetString()).IsEqualTo("next");
            await Assert.That(json.RootElement.GetProperty("destinationSecretPath").GetString()).IsEqualTo("/next");
            await Assert.That(json.RootElement.TryGetProperty("overwriteDestination", out var overwrite)).IsEqualTo(variant != 0);
            if (variant != 0) await Assert.That(overwrite.GetBoolean()).IsEqualTo(flag == true);
        }
        finally { Array.Clear(body); }
        await Assert.That(request.Target.SecondaryId).IsEqualTo(MsSqlSecretRotationOperations.MoveTarget(Org, Address(), new("next", "/next", flag)).SecondaryId);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task ContractMetadataMapsAllServerFieldsWithoutSynthesizedDefaults(int variant)
    {
        JsonObject value = Metadata();
        if (variant != 0)
        {
            value["activeIndex"] = 1.5;
            value["isAutoRotationEnabled"] = false;
            value["isLastRotationManual"] = true;
            value["description"] = variant == 1 ? null : "";
            value["lastRotationJobId"] = variant == 1 ? null : "job-private";
            value["lastRotationMessage"] = variant == 1 ? null : "message-private";
            value["nextRotationAt"] = variant == 1 ? null : "2026-10-11T00:00:00Z";
            value["parameters"]!["rotationStatement"] = "statement-private";
            value["parameters"]!["passwordRequirements"] = JsonNode.Parse("""
                {"length":20.5,"required":{"digits":0.5,"lowercase":1.5,"symbols":2.5,"uppercase":3.5},"allowedSymbols":"!"}
                """);
        }
        using var document = JsonDocument.Parse(new JsonObject { ["secretRotation"] = value }.ToJsonString());
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        using var result = request.Parse(document.RootElement);
        await Assert.That(result.Id).IsEqualTo(Id);
        await Assert.That(result.ProjectId).IsEqualTo(Project);
        await Assert.That(result.Name).IsEqualTo("rotation-private");
        await Assert.That(result.ConnectionId).IsEqualTo(Id);
        await Assert.That(result.ConnectionName).IsEqualTo("mssql-private");
        await Assert.That(result.EnvironmentId).IsEqualTo(Id);
        await Assert.That(result.EnvironmentName).IsEqualTo("Development");
        await Assert.That(result.Environment).IsEqualTo("dev");
        await Assert.That(result.FolderId).IsEqualTo(Id);
        await Assert.That(result.SecretPath).IsEqualTo("/");
        foreach (var timestamp in new[] { result.CreatedAt, result.UpdatedAt, result.LastRotatedAt, result.LastRotationAttemptedAt })
            await Assert.That(timestamp).IsEqualTo("2026-10-10T00:00:00Z");
        await Assert.That(result.RotationStatus).IsEqualTo("future-provider-state");
        await Assert.That(result.ActiveIndex).IsEqualTo(variant == 0 ? (double?)null : 1.5);
        await Assert.That(result.IsAutoRotationEnabled).IsEqualTo(variant == 0 ? (bool?)null : false);
        await Assert.That(result.IsLastRotationManual).IsEqualTo(variant == 0 ? (bool?)null : true);
        await Assert.That(result.HasDescription).IsEqualTo(variant != 0);
        await Assert.That(result.HasLastRotationJobId).IsEqualTo(variant != 0);
        await Assert.That(result.HasLastRotationMessage).IsEqualTo(variant != 0);
        await Assert.That(result.HasNextRotationAt).IsEqualTo(variant != 0);
        await Assert.That(result.Description).IsEqualTo(variant == 2 ? "" : null);
        await Assert.That(result.LastRotationJobId).IsEqualTo(variant == 2 ? "job-private" : null);
        await Assert.That(result.LastRotationMessage).IsEqualTo(variant == 2 ? "message-private" : null);
        await Assert.That(result.NextRotationAt).IsEqualTo(variant == 2 ? "2026-10-11T00:00:00Z" : null);
        await Assert.That(result.RotateAtUtc.Hours).IsEqualTo(1.5);
        await Assert.That(result.RotateAtUtc.Minutes).IsEqualTo(2.5);
        await Assert.That(result.RotationInterval).IsEqualTo(2.5);
        await Assert.That(result.SecretsMapping.Username).IsEqualTo("USERNAME");
        await Assert.That(result.SecretsMapping.Password).IsEqualTo("PASSWORD");
        await Assert.That(result.Parameters.Username1).IsEqualTo("first-private");
        await Assert.That(result.Parameters.Username2).IsEqualTo("second-private");
        if (variant != 0)
        {
            await Assert.That(result.Parameters.RotationStatement!.Reveal()).IsEqualTo("statement-private");
            await Assert.That(result.Parameters.PasswordRequirements!.Length).IsEqualTo(20.5);
        }
        await Assert.That(JsonSerializer.Serialize(result).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task ContractGeneratedMaterialIsCopiedDisposableAndAllowsEmptyValues(int count)
    {
        JsonObject value = Generated(count);
        using var request = MsSqlSecretRotationOperations.GetGeneratedCredentials(Org, Address());
        MsSqlGeneratedCredentials result;
        using (var document = JsonDocument.Parse(value.ToJsonString())) result = request.Parse(document.RootElement);
        await Assert.That(result.RotationId).IsEqualTo(Id);
        await Assert.That(result.ActiveIndex).IsEqualTo(1.5);
        await Assert.That(result.Items.Count).IsEqualTo(count);
        await Assert.That(result.Items[0].Password.Reveal()).IsEqualTo("");
        await Assert.That(result.Items[0].Username.Reveal()).IsEqualTo("");
        if (count == 2) await Assert.That(result.Items[1].Password.Reveal()).IsEqualTo("password-private");
        await Assert.That(JsonSerializer.Serialize(result).Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(result.Items[0])).IsEqualTo("{}");
        var material = result.Items[^1].Password;
        result.Dispose();
        await Assert.That(() => material.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(3)]
    public async Task ContractGeneratedMaterialRejectsUnestablishedArrayBounds(int count)
    {
        using var request = MsSqlSecretRotationOperations.GetGeneratedCredentials(Org, Address());
        using var document = JsonDocument.Parse(Generated(count).ToJsonString());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    public async Task ContractMixedCatalogsRemainMsSqlSubsetsAndProtectTemplateMaterial()
    {
        using var request = MsSqlSecretRotationOperations.ListMsSqlSubset(Org, Project);
        using var document = JsonDocument.Parse(new JsonObject
        {
            ["secretRotations"] =
            new JsonArray(new JsonObject { ["type"] = "redis-credentials" }, Metadata())
        }.ToJsonString());
        using var result = request.Parse(document.RootElement);
        await Assert.That(result.Items.Count).IsEqualTo(1);
        await Assert.That(result.IsComplete).IsFalse();
        using var options = MsSqlSecretRotationOperations.MsSqlOptionsSubset(Org);
        using var optionDocument = JsonDocument.Parse(Options().ToJsonString());
        using var optionResult = options.Parse(optionDocument.RootElement);
        await Assert.That(optionResult.IsComplete).IsFalse();
        await Assert.That(optionResult.Items.Count).IsEqualTo(1);
        var option = optionResult.Items.Single();
        await Assert.That(option.CreateUserStatement.Reveal()).IsEqualTo("create-private");
        await Assert.That(option.RotationStatement.Reveal()).IsEqualTo("rotate-private");
        await Assert.That(option.SecretsMapping.Username).IsEqualTo("");
        await Assert.That(option.SecretsMapping.Password).IsEqualTo("");
        await Assert.That(JsonSerializer.Serialize(option)).IsEqualTo("{}");
        optionResult.Dispose();
        await Assert.That(() => option.CreateUserStatement.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("projectId")]
    [Arguments("id")]
    [Arguments("connectionId")]
    [Arguments("folderId")]
    [Arguments("type")]
    [Arguments("environment")]
    [Arguments("folder")]
    [Arguments("createdAt")]
    [Arguments("parameters")]
    [Arguments("secretsMapping")]
    [Arguments("rotateAtUtc")]
    [Arguments("rotationStatus")]
    public async Task ContractMetadataRejectsWrongCoordinatesAndMalformedRequiredFields(string field)
    {
        JsonObject value = Metadata();
        value[field] = null;
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        using var document = JsonDocument.Parse(new JsonObject { ["secretRotation"] = value }.ToJsonString());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("statement")]
    [Arguments("username")]
    [Arguments("requirements")]
    [Arguments("enabled")]
    [Arguments("active")]
    [Arguments("date")]
    public async Task ContractOptionalNonnullableMetadataRejectsExplicitNull(string field)
    {
        JsonObject value = Metadata();
        if (field == "statement") value["parameters"]!["rotationStatement"] = null;
        if (field == "username") value["parameters"]!["username1"] = "";
        if (field == "requirements") value["parameters"]!["passwordRequirements"] = null;
        if (field == "enabled") value["isAutoRotationEnabled"] = null;
        if (field == "active") value["activeIndex"] = null;
        if (field == "date") value["nextRotationAt"] = "";
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        using var document = JsonDocument.Parse(new JsonObject { ["secretRotation"] = value }.ToJsonString());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    public async Task ContractInputBoundsRemainExplicit(int defect)
    {
        using var parameters = new MsSqlRotationParameters("one", "two");
        Action action = defect switch
        {
            0 => () => new MsSqlRotationTime(24, 0),
            1 => () => new MsSqlRotationTime(0, 60),
            2 => () => new MsSqlRotationPasswordRequirements(251, 0, 0, 0, 0),
            3 => () => new MsSqlRotationPasswordRequirements(1, -1, 0, 0, 0),
            4 => () => new MsSqlRotationPasswordRequirements(1, 0, 0, 0, 0, ""),
            5 => () => new MsSqlSecretRotationUpdate(rotationInterval: double.NaN),
            6 => () => new MsSqlSecretRotationUpdate(description: new(new string('x', 257))),
            _ => () => new MsSqlSecretRotationCreation("x", Project, "dev", "/", "not-uuid", 1, parameters, new("U", "P"))
        };
        await Assert.That(action).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("organization")]
    [Arguments("project")]
    [Arguments("resource")]
    [Arguments("body")]
    [Arguments("environment")]
    [Arguments("operation")]
    public async Task ContractIndependentIntentMismatchFailsBeforeTokensOrDispatch(string mismatch)
    {
        using var parameters = new MsSqlRotationParameters("one", "two");
        var update = new MsSqlSecretRotationUpdate(name: "selected");
        using var request = MsSqlSecretRotationOperations.Update(Org, Address(), update);
        var independent = MsSqlSecretRotationOperations.UpdateTarget(Org,
            Address(mismatch == "environment" ? "other" : "dev"), new(name: mismatch == "body" ? "other" : "selected"));
        independent = new(mismatch == "organization" ? "other" : Org,
            mismatch == "project" ? "other" : Project, mismatch == "resource" ? "other" : Id, independent.SecondaryId);
        using var wire = new Wire(HttpMethod.Patch, Path + "/" + Id);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024,
            null, false, wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, independent.OrganizationId, independent.ProjectId);
        var result = await client.ExecuteAsync(request, authority,
            authority.IssueGrant(mismatch == "operation" ? "other-operation" : request.OperationId, independent), client.CreateReceipt(request));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsFalse();
    }

    [Test]
    public async Task ContractHandwrittenApiBuildsExactEscapedQueriesWithoutDispatch()
    {
        using var handler = new BuildOnly();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://management.test") };
        var api = RestService.For<IMsSqlSecretRotationApi>(http);
        using var byName = await api.GetByName("name?private", Project, "dev&private", "/private?x", default);
        await Assert.That(byName.RequestUri!.ToString().Contains("environment=dev%26private", StringComparison.Ordinal)).IsTrue();
        using var deletion = await api.Delete(Id, "false", "true", default);
        await Assert.That(deletion.RequestUri!.ToString().EndsWith("?deleteSecrets=false&revokeGeneratedCredentials=true", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task ContractCredentialCheckRequiresExactEmptyAcknowledgement()
    {
        using var request = MsSqlSecretRotationOperations.CheckCredentials(Org, Address());
        using var empty = JsonDocument.Parse("\"\"");
        await Assert.That(request.Parse(empty.RootElement)).IsNotNull();
        using var wrong = JsonDocument.Parse("{}");
        await Assert.That(() => request.Parse(wrong.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments("loss")]
    [Arguments("pending")]
    [Arguments("denied")]
    public async Task ActualManagementReceiptPreservesCommittedLossPendingAndRejection(string scenario)
    {
        using var request = MsSqlSecretRotationOperations.Update(Org, Address(), new(name: "selected-private"));
        var wire = new Wire(HttpMethod.Patch, Path + "/" + Id)
        {
            Lost = scenario == "loss",
            ResponseStatus = scenario == "pending" ? HttpStatusCode.Accepted :
                scenario == "denied" ? HttpStatusCode.Forbidden : HttpStatusCode.OK
        };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        var grant = authority.IssueGrant(request.OperationId,
            MsSqlSecretRotationOperations.UpdateTarget(Org, Address(), new(name: "selected-private")));
        var receipt = client.CreateReceipt(request);
        var outcome = await client.ExecuteAsync(request, authority, grant, receipt);
        await Assert.That(outcome.Status).IsEqualTo(scenario switch
        { "loss" => SecretStatus.Unknown, "pending" => SecretStatus.Pending, _ => SecretStatus.Denied });
        await Assert.That(receipt.Evidence).IsEqualTo(scenario switch
        { "loss" => DispatchEvidence.PossiblyDispatched, "pending" => DispatchEvidence.Pending, _ => DispatchEvidence.Rejected });
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Commits).IsEqualTo(scenario == "denied" ? 0 : 1);
        if (scenario != "denied") await Assert.That(wire.Stored!["name"]!.GetValue<string>()).IsEqualTo("selected-private");
    }

    [Test]
    public async Task ActualManagementCancellationAfterCommitRetainsUnknownWithoutReplay()
    {
        using var request = MsSqlSecretRotationOperations.Move(Org, Address(), new("next", "/next"));
        var wire = new Wire(HttpMethod.Post, Path + "/" + Id + "/move") { HoldAfterCommit = true };
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        var grant = authority.IssueGrant(request.OperationId, MsSqlSecretRotationOperations.MoveTarget(Org, Address(), new("next", "/next")));
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        Task committed = wire.Committed.Task;
        var dispatch = client.ExecuteAsync(request, authority, grant, receipt, cancellation.Token).AsTask();
        Task first = await Task.WhenAny(committed, dispatch).WaitAsync(TimeSpan.FromSeconds(5));
        // Completion before the exact commit barrier means construction/authorization failed.
        await Assert.That(ReferenceEquals(first, committed)).IsTrue();
        cancellation.Cancel();
        await Assert.That(async () => await dispatch).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Commits).IsEqualTo(1);
    }

    [Test]
    public async Task ContractCancellationBeforeDispatchKeepsReceiptNotDispatched()
    {
        using var request = MsSqlSecretRotationOperations.Delete(Org, Address());
        using var wire = new Wire(HttpMethod.Delete, Path + "/" + Id);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority,
            authority.IssueGrant(request.OperationId, MsSqlSecretRotationOperations.DeletionTarget(Org, Address())),
            receipt, cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsFalse();
    }


    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(8)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task ContractEveryPatchMemberBindsIndependentWholeBodyIntent(int member)
    {
        using var originalParameters = new MsSqlRotationParameters("one", "two");
        using var changedParameters = new MsSqlRotationParameters("one", member == 6 ? "other" : "two",
            member == 7 ? new(20, 1, 2, 3, 4, "!") : null);
        using var statement = SecretMaterial.FromText("statement-private");
        using var statementParameters = new MsSqlRotationParameters("one", "two", rotationStatement: statement);
        var original = new MsSqlSecretRotationUpdate("selected", new(null), false, 1,
            originalParameters, new("U", "P"), new(0, 0));
        var changed = new MsSqlSecretRotationUpdate(member == 0 ? "other" : "selected",
            member == 1 ? new("") : new(null), member == 2, member == 3 ? 2 : 1,
            member == 8 ? statementParameters : changedParameters,
            new(member == 4 ? "OTHER" : "U", member == 5 ? "OTHER" : "P"),
            new(member == 9 ? 1 : 0, member == 10 ? 1 : 0));
        using var request = MsSqlSecretRotationOperations.Update(Org, Address(), original);
        var target = MsSqlSecretRotationOperations.UpdateTarget(Org,
            member == 11 ? new(Project, "dev", "/other", InfisicalRotationProfile.MssqlCredentials, Id) : Address(), changed);
        using var wire = new Wire(HttpMethod.Patch, Path + "/" + Id);
        using var transport = new ManagementTransport(new Uri("https://management.test"), 1024 * 1024, null, false, wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        var receipt = client.CreateReceipt(request);
        var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Dispatched).IsFalse();
    }

    [Test]
    [Arguments("type")]
    [Arguments("rotationId")]
    [Arguments("activeIndex")]
    [Arguments("password")]
    [Arguments("username")]
    public async Task ContractGeneratedResponseRejectsWrongScopeAndPrimitiveVariants(string field)
    {
        var value = Generated(1);
        if (field is "username" or "password") value["generatedCredentials"]![0]![field] = null;
        else value[field] = field == "type" ? "postgres-credentials" : field == "rotationId" ?
            "bb4b7959-a8ef-493f-a2c1-807b3be3aa71" : null;
        using var document = JsonDocument.Parse(value.ToJsonString());
        using var request = MsSqlSecretRotationOperations.GetGeneratedCredentials(Org, Address());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    [Arguments(6)]
    [Arguments(7)]
    [Arguments(9)]
    [Arguments(10)]
    [Arguments(11)]
    public async Task ContractEveryHandwrittenApiBuildsExactMethodAndPath(int route)
    {
        using var handler = new BuildOnly();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://management.test") };
        var api = RestService.For<IMsSqlSecretRotationApi>(http);
        using var body = new StringContent("{}");
        using var request = route switch
        {
            0 => await api.List(Project, default),
            1 => await api.Create(body, default),
            2 => await api.Delete(Id, null, null, default),
            3 => await api.Get(Id, default),
            4 => await api.Update(Id, body, default),
            5 => await api.CheckCredentials(Id, default),
            6 => await api.GeneratedCredentials(Id, default),
            7 => await api.Move(Id, body, default),
            9 => await api.GetByName("rotation-private", Project, "dev", "/", default),
            10 => await api.ListCatalog(Project, default),
            _ => await api.Options(default)
        };
        var (_, method, path) = Route(route);
        await Assert.That(request.Method).IsEqualTo(method);
        await Assert.That(new Uri(http.BaseAddress!, request.RequestUri!).PathAndQuery).IsEqualTo(path);
    }

    [Test]
    public async Task ContractWrongNativeProfileCannotConstructMsSqlManagementRequest()
    {
        var wrong = new InfisicalRotationAddress(Project, "dev", "/", InfisicalRotationProfile.PostgresCredentials, Id);
        await Assert.That(() => MsSqlSecretRotationOperations.Get(Org, wrong)).Throws<ArgumentException>();
        await Assert.That(() => MsSqlSecretRotationOperations.CheckCredentials(Org, wrong)).Throws<ArgumentException>();
        await Assert.That(() => MsSqlSecretRotationOperations.UpdateTarget(Org, wrong, new())).Throws<ArgumentException>();
    }

    [Test]
    [Arguments("connection")]
    [Arguments("environment")]
    [Arguments("folder")]
    public async Task ContractMetadataRejectsNestedCoordinateMismatch(string field)
    {
        var value = Metadata();
        value[field]![field == "environment" ? "slug" : field == "folder" ? "path" : "id"] =
            field == "connection" ? "bb4b7959-a8ef-493f-a2c1-807b3be3aa71" : "other";
        using var document = JsonDocument.Parse(new JsonObject { ["secretRotation"] = value }.ToJsonString());
        using var request = MsSqlSecretRotationOperations.Get(Org, Address());
        await Assert.That(() => request.Parse(document.RootElement)).Throws<ManagementContractException>();
    }

    private static (string Operation, HttpMethod Method, string Path) Route(int route) => route switch
    {
        0 => (Prefix + "get.v2.secret.rotations.mssql.credentials", HttpMethod.Get, Path + "?projectId=" + Project),
        1 => (Prefix + "post.v2.secret.rotations.mssql.credentials", HttpMethod.Post, Path),
        2 => (Prefix + "delete.v2.secret.rotations.mssql.credentials.by.rotationId", HttpMethod.Delete, Path + "/" + Id),
        3 => (Prefix + "get.v2.secret.rotations.mssql.credentials.by.rotationId", HttpMethod.Get, Path + "/" + Id),
        4 => (Prefix + "patch.v2.secret.rotations.mssql.credentials.by.rotationId", HttpMethod.Patch, Path + "/" + Id),
        5 => (Prefix + "post.v2.secret.rotations.mssql.credentials.by.rotationId.check.credentials", HttpMethod.Post, Path + "/" + Id + "/check-credentials"),
        6 => (Prefix + "get.v2.secret.rotations.mssql.credentials.by.rotationId.generated.credentials", HttpMethod.Get, Path + "/" + Id + "/generated-credentials"),
        7 => (Prefix + "post.v2.secret.rotations.mssql.credentials.by.rotationId.move", HttpMethod.Post, Path + "/" + Id + "/move"),
        8 => (Prefix + "post.v2.secret.rotations.mssql.credentials.by.rotationId.rotate.secrets", HttpMethod.Post, Path + "/" + Id + "/rotate-secrets"),
        9 => (Prefix + "get.v2.secret.rotations.mssql.credentials.rotation.name.by.rotationName", HttpMethod.Get,
            Path + "/rotation-name/rotation-private?projectId=" + Project + "&environment=dev&secretPath=%2F"),
        10 => (Prefix + "get.v2.secret.rotations", HttpMethod.Get, "/api/v2/secret-rotations?projectId=" + Project),
        _ => (Prefix + "get.v2.secret.rotations.options", HttpMethod.Get, "/api/v2/secret-rotations/options")
    };

    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken) =>
            Token();
        private ValueTask<SecretOutcome<InfisicalAccessToken>> Token()
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }

    private sealed class Wire(HttpMethod method, string path) : HttpMessageHandler
    {
        public int RouteNumber { get; init; }
        public JsonObject? ResponseOverride { get; init; }
        public bool UnreadableSuccess { get; init; }
        public int ResponseBodyReads { get; private set; }
        public bool Dispatched { get; private set; }
        public int Commits { get; private set; }
        public JsonObject? Stored { get; private set; }
        public bool Lost { get; init; }
        public bool HoldAfterCommit { get; init; }
        public HttpStatusCode ResponseStatus { get; init; } = HttpStatusCode.OK;
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Dispatched = true;
            if (request.Method != method || request.RequestUri!.PathAndQuery != path)
                return new(HttpStatusCode.NotFound);
            if (ResponseStatus == HttpStatusCode.Forbidden)
                return new(ResponseStatus) { Content = new UnreadableContent(() => ResponseBodyReads++) };
            if (ResponseStatus == HttpStatusCode.NoContent)
                return new(ResponseStatus) { Content = new UnreadableContent(() => ResponseBodyReads++) };
            if (request.Content is not null) Stored = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            if (method != HttpMethod.Get) Commits++;
            Committed.TrySetResult();
            if (HoldAfterCommit) await Release.Task.WaitAsync(cancellationToken);
            if (Lost) throw new IOException("Lost response.");
            if (ResponseStatus != HttpStatusCode.OK) return new(ResponseStatus);
            if (UnreadableSuccess) return new(HttpStatusCode.OK) { Content = new UnreadableContent(() => ResponseBodyReads++) };
            if (RouteNumber == 5) return new(HttpStatusCode.NoContent);
            JsonObject response = ResponseOverride ?? (RouteNumber switch
            {
                0 or 10 => new() { ["secretRotations"] = new JsonArray(Metadata()) },
                6 => Generated(2),
                11 => Options(),
                _ => new() { ["secretRotation"] = Metadata(RouteNumber == 7 ? "next" : "dev", RouteNumber == 7 ? "/next" : "/") }
            });
            return new(HttpStatusCode.OK) { Content = new StringContent(response.ToJsonString()) };
        }
    }

    private sealed class UnreadableContent(Action read) : HttpContent
    {
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            read();
            throw new InvalidOperationException("Error bodies must remain withheld.");
        }
        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            read();
            throw new InvalidOperationException("Error bodies must remain withheld.");
        }
    }

    private sealed class BuildOnly : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Request construction must not dispatch.");
    }
    private sealed class NativeWire : HttpMessageHandler
    {
        public int Commits { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method != HttpMethod.Post || request.RequestUri!.AbsolutePath != Path + "/" + Id + "/rotate-secrets")
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
            Commits++;
            JsonObject metadata = Metadata();
            metadata["rotationStatus"] = "pending";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(new JsonObject { ["secretRotation"] = metadata }.ToJsonString()) });
        }
    }
    private static InfisicalRotationAddress Address(string environment = "dev") =>
        new(Project, environment, "/", InfisicalRotationProfile.MssqlCredentials, Id);
    private static MsSqlSecretRotationCreation Creation(MsSqlRotationParameters parameters) =>
        new("rotation-private", Project, "dev", "/", Id, 1.5, parameters, new("USERNAME", "PASSWORD"));
    private static JsonObject Generated(int count) => new()
    {
        ["type"] = "mssql-credentials",
        ["rotationId"] = Id,
        ["activeIndex"] = 1.5,
        ["generatedCredentials"] = new JsonArray(Enumerable.Range(0, count).Select(index =>
            (JsonNode)new JsonObject
            {
                ["username"] = index == 0 ? "" : "user-private",
                ["password"] = index == 0 ? "" : "password-private"
            }).ToArray())
    };
    private static JsonObject Options() => JsonNode.Parse("""
        {"secretRotationOptions":[{"type":"redis-credentials"},{"type":"mssql-credentials","connection":"mssql",
        "name":"Microsoft SQL Server Credentials","template":{"createUserStatement":"create-private","rotationStatement":"rotate-private",
        "secretsMapping":{"username":"","password":""}}}]}
        """)!.AsObject();
    private static JsonObject Metadata(string environment = "dev", string secretPath = "/") => new()
    {
        ["id"] = Id,
        ["projectId"] = Project,
        ["name"] = "rotation-private",
        ["type"] = "mssql-credentials",
        ["connectionId"] = Id,
        ["connection"] = new JsonObject { ["id"] = Id, ["app"] = "mssql", ["name"] = "mssql-private" },
        ["environment"] = new JsonObject { ["id"] = Id, ["slug"] = environment, ["name"] = "Development" },
        ["folderId"] = Id,
        ["folder"] = new JsonObject { ["id"] = Id, ["path"] = secretPath },
        ["createdAt"] = "2026-10-10T00:00:00Z",
        ["updatedAt"] = "2026-10-10T00:00:00Z",
        ["lastRotatedAt"] = "2026-10-10T00:00:00Z",
        ["lastRotationAttemptedAt"] = "2026-10-10T00:00:00Z",
        ["rotationStatus"] = "future-provider-state",
        ["rotationInterval"] = 2.5,
        ["rotateAtUtc"] = new JsonObject { ["hours"] = 1.5, ["minutes"] = 2.5 },
        ["secretsMapping"] = new JsonObject { ["username"] = "USERNAME", ["password"] = "PASSWORD" },
        ["parameters"] = new JsonObject { ["username1"] = "first-private", ["username2"] = "second-private" }
    };
}
