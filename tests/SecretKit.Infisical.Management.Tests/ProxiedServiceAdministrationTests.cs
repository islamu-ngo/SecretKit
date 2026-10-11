using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Refit;
using SecretKit.Core;

namespace SecretKit.Infisical.Management.Tests;

public sealed class ProxiedServiceAdministrationTests
{
    private const string Org = "org-private";
    private const string Project = "project-private";
    private const string EnvironmentName = "env-private";
    private const string Id = "7b15ac64-78ee-4fa5-a7b4-eb2da9ac5796";
    private const string Name = "service-private";

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task ActualManagementBindingsReturnEstablishedContracts(int route)
    {
        using var wire = new Wire(Response(route));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var credential = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.HeaderRewrite);
        using var creation = new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private", [credential]);
        using var update = new ProxiedServiceUpdate(isEnabled: false);
        if (route == 0)
        {
            using var request = ProxiedServiceAdministrationOperations.List(Org, Project, EnvironmentName);
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(
                "infisical.get.v1.proxied.services", ProxiedServiceAdministrationOperations.ListTarget(Org, Project, EnvironmentName)));
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            using var value = result.Value;
            await Assert.That(value.Services.Single().CanProxy).IsTrue();
            await Assert.That(wire.Path).IsEqualTo("/api/v1/proxied-services?projectId=" + Project + "&environment=" + EnvironmentName);
        }
        else
        {
            using var request = Request(route, creation, update);
            var target = Target(route, creation, update);
            var receipt = request.IsMutation ? client.CreateReceipt(request) : null;
            var result = await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
            using var value = result.Value;
            await Assert.That(value.Id).IsEqualTo(Id);
            await Assert.That(value.HasCredentials).IsEqualTo(route != 4);
            if (route == 1)
            {
                await Assert.That(wire.Stored!["projectId"]!.GetValue<string>()).IsEqualTo(Project);
                await Assert.That(wire.Stored["environment"]!.GetValue<string>()).IsEqualTo(EnvironmentName);
                await Assert.That(wire.Stored["credentials"]![0]!["role"]!.GetValue<string>()).IsEqualTo("header-rewrite");
            }
            if (route == 3) await Assert.That(wire.Stored!["isEnabled"]!.GetValue<bool>()).IsFalse();
            if (receipt is not null)
            {
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That((await client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target), receipt)).Status).IsEqualTo(SecretStatus.Invalid);
                await Assert.That(wire.Revision).IsEqualTo(1);
            }
        }
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task HandwrittenBuildersKeepNativeRoutesAndOmission(int route)
    {
        using var http = new HttpClient { BaseAddress = new("https://management.test") };
        var api = RestService.For<IProxiedServiceAdministrationApi>(http);
        using var body = new StringContent("{}");
        using var message = await (route switch
        {
            0 => api.List(Project, EnvironmentName, null, default),
            1 => api.Create(body, default),
            2 => api.Get(Id, default),
            3 => api.Update(Id, body, default),
            4 => api.Delete(Id, default),
            _ => api.GetByName(Name, Project, EnvironmentName, "", default)
        });
        await Assert.That(message.Method).IsEqualTo(route switch { 1 => HttpMethod.Post, 3 => HttpMethod.Patch, 4 => HttpMethod.Delete, _ => HttpMethod.Get });
        await Assert.That(new Uri(http.BaseAddress!, message.RequestUri!).PathAndQuery).IsEqualTo(route switch
        {
            0 => "/api/v1/proxied-services?projectId=" + Project + "&environment=" + EnvironmentName,
            1 => "/api/v1/proxied-services",
            5 => "/api/v1/proxied-services/slug/" + Name + "?projectId=" + Project + "&environment=" + EnvironmentName + "&secretPath=",
            _ => "/api/v1/proxied-services/" + Id
        });
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(5)]
    public async Task EachSuccessShapeOwnsProtectedNativeMetadata(int route)
    {
        using var credential = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.HeaderRewrite);
        using var creation = new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private", [credential]);
        using var update = new ProxiedServiceUpdate();
        using var json = JsonDocument.Parse(Response(route));
        ProxiedServiceList? list = null;
        ProxiedServiceSummary service;
        if (route == 0)
        {
            using var request = ProxiedServiceAdministrationOperations.List(Org, Project, EnvironmentName);
            list = request.Parse(json.RootElement);
            service = list.Services.Single();
            await Assert.That(list.ProjectSlug).IsEqualTo("slug-private");
        }
        else
        {
            using var request = Request(route, creation, update);
            service = request.Parse(json.RootElement);
        }
        using var owned = service;
        using var ownedList = list;
        json.Dispose();
        await Assert.That(service.Id).IsEqualTo(Id);
        await Assert.That(service.HasLastUsedAt).IsTrue();
        await Assert.That(service.LastUsedAt).IsNull();
        await Assert.That(service.HasIsEnabled).IsFalse();
        await Assert.That(service.IsEnabled).IsNull();
        await Assert.That(service.HasCredentials).IsEqualTo(route != 4);
        await Assert.That(service.CanProxy).IsEqualTo(route is 0 or 2 or 5 ? true : null);
        if (route != 4)
        {
            var metadata = service.Credentials.Single();
            await Assert.That(metadata.Role).IsEqualTo("future-role");
            await Assert.That(metadata.HeaderPurpose).IsEqualTo("future-purpose");
            await Assert.That(metadata.SubstitutionSurfaces!.Single()).IsEqualTo("future-surface");
            await Assert.That(metadata.HasDynamicSecretName).IsTrue();
            await Assert.That(metadata.DynamicSecretName).IsNull();
            await Assert.That(metadata.HasSecretKey).IsFalse();
            await Assert.That(metadata.PlaceholderValue!.Reveal()).IsEqualTo("placeholder-private");
            await Assert.That(metadata.CallerCanLease).IsEqualTo(route is 0 or 2 or 5 ? false : null);
            await Assert.That(JsonSerializer.Serialize(metadata)).IsEqualTo("{}");
            await Assert.That(metadata.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
            service.Dispose();
            await Assert.That(() => metadata.PlaceholderValue.Reveal()).Throws<ObjectDisposedException>();
        }
        await Assert.That(JsonSerializer.Serialize(service)).IsEqualTo("{}");
        await Assert.That(service.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public async Task CredentialAlternativesCopyArraysSecretsAndPreserveOmission(int variant)
    {
        using var placeholder = SecretMaterial.FromText("placeholder-private");
        var surfaces = new[] { ProxiedServiceSubstitutionSurface.Header, ProxiedServiceSubstitutionSurface.Path,
            ProxiedServiceSubstitutionSurface.Query, ProxiedServiceSubstitutionSurface.Body };
        using var credential = Credential(variant, placeholder, surfaces);
        placeholder.Dispose();
        using var creation = new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private", [credential], variant == 0 ? null : "", variant == 0 ? null : false);
        using var update = new ProxiedServiceUpdate(Name, "host-private", variant == 0 ? null : false, [credential]);
        credential.Dispose();
        Array.Fill(surfaces, (ProxiedServiceSubstitutionSurface)99);
        using var request = ProxiedServiceAdministrationOperations.Create(Org, creation);
        using var independentValue = SecretMaterial.FromText("placeholder-private");
        using var independent = Credential(variant, independentValue, [ProxiedServiceSubstitutionSurface.Header,
            ProxiedServiceSubstitutionSurface.Path, ProxiedServiceSubstitutionSurface.Query, ProxiedServiceSubstitutionSurface.Body]);
        using var selection = new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private", [independent], variant == 0 ? null : "", variant == 0 ? null : false);
        await Assert.That(request.Target.SecondaryId).IsEqualTo(ProxiedServiceAdministrationOperations.CreationTarget(Org, selection).SecondaryId);
        using var patch = ProxiedServiceAdministrationOperations.Update(Org, Project, Id, update);
        using var independentlySelectedPatch = new ProxiedServiceUpdate(Name, "host-private", variant == 0 ? null : false, [independent]);
        await Assert.That(patch.Target.SecondaryId).IsEqualTo(ProxiedServiceAdministrationOperations.UpdateTarget(Org, Project, Id, independentlySelectedPatch).SecondaryId);
        creation.Dispose();
        update.Dispose();
        byte[] bytes = request.CopyBody()!;
        try
        {
            using var json = JsonDocument.Parse(bytes);
            JsonElement root = json.RootElement, material = root.GetProperty("credentials")[0];
            await Assert.That(root.TryGetProperty("secretPath", out _)).IsEqualTo(variant != 0);
            await Assert.That(root.TryGetProperty("isEnabled", out _)).IsEqualTo(variant != 0);
            await Assert.That(material.GetProperty("role").GetString()).IsEqualTo(variant % 2 == 0 ? "header-rewrite" : "credential-substitution");
            await Assert.That(material.TryGetProperty("placeholderValue", out _)).IsEqualTo(variant >= 2);
            if (variant >= 2)
            {
                await Assert.That(material.GetProperty("placeholderValue").GetString()).IsEqualTo("placeholder-private");
                await Assert.That(material.GetProperty("substitutionSurfaces").GetArrayLength()).IsEqualTo(4);
                await Assert.That(material.GetProperty("headerPrefix").GetString()).IsEqualTo("");
                await Assert.That(material.GetProperty("headerPurpose").GetString()).IsEqualTo(variant == 2 ? "username" : "password");
            }
        }
        finally { Array.Clear(bytes); }
        foreach (object value in new object[] { independent, selection, independentlySelectedPatch, request })
        {
            await Assert.That(JsonSerializer.Serialize(value).Contains("private", StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains("private", StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(() => ProxiedServiceAdministrationOperations.Create(Org, creation)).Throws<ObjectDisposedException>();
        await Assert.That(() => ProxiedServiceAdministrationOperations.Update(Org, Project, Id, update)).Throws<ObjectDisposedException>();
        request.Dispose();
        await Assert.That(() => request.CopyBody()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task ReadSelectionHashesDistinguishEnvironmentPathOmissionEmptyAndName()
    {
        var omitted = ProxiedServiceAdministrationOperations.ListTarget(Org, Project, EnvironmentName);
        var empty = ProxiedServiceAdministrationOperations.ListTarget(Org, Project, EnvironmentName, "");
        var root = ProxiedServiceAdministrationOperations.ListTarget(Org, Project, EnvironmentName, "/");
        await Assert.That(omitted.SecondaryId == empty.SecondaryId).IsFalse();
        await Assert.That(empty.SecondaryId == root.SecondaryId).IsFalse();
        await Assert.That(root.SecondaryId == ProxiedServiceAdministrationOperations.ListTarget(Org, Project, "another-private", "/").SecondaryId).IsFalse();
        var byName = ProxiedServiceAdministrationOperations.NameTarget(Org, Project, EnvironmentName, Name, "/");
        await Assert.That(byName.ResourceId).IsEqualTo(Name);
        await Assert.That(byName.SecondaryId).IsEqualTo(root.SecondaryId);
        using var request = ProxiedServiceAdministrationOperations.GetByName(Org, Project, EnvironmentName, "name/private", "");
        await Assert.That(request.Path).IsEqualTo("/api/v1/proxied-services/slug/name%2Fprivate?projectId=" + Project + "&environment=" + EnvironmentName + "&secretPath=");
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task OptionalCredentialMetadataKeepsEachNullAndOmission(int variant)
    {
        var service = Metadata(true, true);
        var credential = service["credentials"]![0]!.AsObject();
        string[] fields = ["dynamicSecretField", "dynamicSecretName", "headerName", "headerPrefix", "headerPurpose",
            "placeholderKey", "placeholderValue", "secretKey", "substitutionSurfaces"];
        foreach (string field in fields)
        {
            credential.Remove(field);
            if (variant > 0) credential[field] = variant == 1 ? null :
                field == "substitutionSurfaces" ? new JsonArray() : JsonValue.Create("");
        }
        using var request = ProxiedServiceAdministrationOperations.Get(Org, Project, Id);
        using var json = JsonDocument.Parse(new JsonObject { ["service"] = service }.ToJsonString());
        using var result = request.Parse(json.RootElement);
        var value = result.Credentials.Single();
        foreach (bool present in new[] { value.HasDynamicSecretField, value.HasDynamicSecretName, value.HasHeaderName,
            value.HasHeaderPrefix, value.HasHeaderPurpose, value.HasPlaceholderKey, value.HasPlaceholderValue,
            value.HasSecretKey, value.HasSubstitutionSurfaces }) await Assert.That(present).IsEqualTo(variant > 0);
        await Assert.That(value.SubstitutionSurfaces?.Count).IsEqualTo(variant == 2 ? 0 : null);
        await Assert.That(value.PlaceholderValue?.Reveal()).IsEqualTo(variant == 2 ? "" : null);
    }

    [Test]
    public async Task EmptyPatchNonemptyCredentialAndResponseBudgetsStayIndependent()
    {
        using var update = new ProxiedServiceUpdate();
        using var request = ProxiedServiceAdministrationOperations.Update(Org, Project, Id, update);
        byte[] bytes = request.CopyBody()!;
        try { await Assert.That(Encoding.UTF8.GetString(bytes)).IsEqualTo("{}"); }
        finally { Array.Clear(bytes); }
        await Assert.That(() => new ProxiedServiceUpdate(credentials: [])).Throws<ArgumentException>();
        using var input = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.CredentialSubstitution,
            dynamicSecretField: new string('x', 255), dynamicSecretName: new string('x', 255), headerName: new string('x', 255),
            headerPrefix: new string('x', 255), placeholderKey: new string('x', 255), secretKey: new string('x', 255));
        await Assert.That(() => new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private",
            Enumerable.Repeat(input, 1001))).Throws<ArgumentException>();
        await Assert.That(() => new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private",
            Enumerable.Repeat(input, 100))).Throws<ArgumentException>();
        var root = new JsonObject
        {
            ["projectSlug"] = "slug-private",
            ["services"] = new JsonArray(
                Enumerable.Range(0, 1001).Select(_ => (JsonNode)Metadata(true, true)).ToArray())
        };
        using var list = ProxiedServiceAdministrationOperations.List(Org, Project, EnvironmentName);
        using var json = JsonDocument.Parse(root.ToJsonString());
        await Assert.That(() => list.Parse(json.RootElement)).Throws<ManagementContractException>();
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
    public async Task InvalidPublishedInputsFailBeforeAcquisition(int defect)
    {
        Action action = () =>
        {
            using var value = SecretMaterial.FromText(defect == 6 ? new string('x', 256) : "value-private");
            using var credential = defect switch
            {
                0 => new ProxiedServiceCredentialInput((ProxiedServiceCredentialRole)99),
                1 => new(ProxiedServiceCredentialRole.HeaderRewrite, headerName: ""),
                2 => new(ProxiedServiceCredentialRole.HeaderRewrite, headerPrefix: new string('x', 256)),
                3 => new(ProxiedServiceCredentialRole.HeaderRewrite, headerPurpose: (ProxiedServiceHeaderPurpose)99),
                4 => new(ProxiedServiceCredentialRole.HeaderRewrite, substitutionSurfaces: []),
                5 => new(ProxiedServiceCredentialRole.HeaderRewrite, substitutionSurfaces: [(ProxiedServiceSubstitutionSurface)99]),
                6 => new(ProxiedServiceCredentialRole.HeaderRewrite, placeholderValue: value),
                _ => new(ProxiedServiceCredentialRole.HeaderRewrite)
            };
            using var creation = new ProxiedServiceCreation(Project, EnvironmentName,
                defect == 7 ? "" : Name, defect == 8 ? new string('x', 256) : "host-private", defect == 9 ? [] : [credential]);
            if (defect == 10) _ = ProxiedServiceAdministrationOperations.Get(Org, Project, "invalid-private");
            if (defect == 11) _ = ProxiedServiceAdministrationOperations.List(Org, Project, "");
        };
        await Assert.That(action).Throws<ArgumentException>();
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
    public async Task IndependentResponseFailuresDoNotWeakenPublishedShapes(int defect)
    {
        var service = Metadata(true, true);
        switch (defect)
        {
            case 0: service.Remove("canProxy"); break;
            case 1: service.Remove("credentials"); break;
            case 2: service["folderId"] = "invalid-private"; break;
            case 3: service["isEnabled"] = null; break;
            case 4: service["lastUsedAt"] = "invalid-private"; break;
            case 5: service["credentials"]![0]!["serviceId"] = "00000000-0000-0000-0000-000000000000"; break;
            case 6: service["credentials"]![0]!["callerCanLease"] = null; break;
            case 7: service["credentials"]![0]!["substitutionSurfaces"] = new JsonArray(1); break;
        }
        using var request = ProxiedServiceAdministrationOperations.Get(Org, Project, Id);
        using var json = JsonDocument.Parse(new JsonObject { ["service"] = service }.ToJsonString());
        await Assert.That(() => request.Parse(json.RootElement)).Throws<ManagementContractException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    [Arguments(4)]
    public async Task IndependentGrantsRejectOriginProjectResourceOperationAndFullBody(int defect)
    {
        using var credential = new ProxiedServiceCredentialInput(ProxiedServiceCredentialRole.HeaderRewrite);
        using var creation = new ProxiedServiceCreation(Project, EnvironmentName, Name, "host-private", [credential]);
        using var request = ProxiedServiceAdministrationOperations.Create(Org, creation);
        using var wire = new Wire(Response(1));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        using var selected = new ProxiedServiceCreation(Project, EnvironmentName, Name, defect == 4 ? "other-private" : "host-private", [credential]);
        var target = ProxiedServiceAdministrationOperations.CreationTarget(Org, selected);
        if (defect == 2) target = new(Org, Project, "another-private", target.SecondaryId);
        var issuer = defect == 0 ? new ManagementAuthority(new(), tokens, Org, Project) :
            defect == 1 ? new ManagementAuthority(client.Authority, tokens, Org, "another-private") : authority;
        if (defect == 1) target = new(Org, "another-private", Name, target.SecondaryId);
        var grant = issuer.IssueGrant(defect == 3 ? "infisical.patch.v1.proxied.services.by.serviceId" : request.OperationId, target);
        await Assert.That((await client.ExecuteAsync(request, authority, grant, client.CreateReceipt(request))).Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    public async Task PreCancellationAndMissingReceiptNeverDispatch()
    {
        using var wire = new Wire(Response(4));
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var tokens = new Tokens();
        var authority = new ManagementAuthority(client.Authority, tokens, Org, Project);
        using var request = ProxiedServiceAdministrationOperations.Delete(Org, Project, Id);
        var grant = authority.IssueGrant(request.OperationId, new(Org, Project, Id));
        var receipt = client.CreateReceipt(request);
        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        await Assert.That(async () => await client.ExecuteAsync(request, authority, grant, receipt, cancel.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(tokens.Acquired).IsFalse();
        await Assert.That(wire.Revision).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CommittedLossAndCancellationNeverReplay(bool cancel)
    {
        using var wire = new Wire(Response(4)) { Lost = !cancel, Hold = cancel };
        using var transport = Transport(wire);
        var client = new ManagementClient(transport);
        var authority = new ManagementAuthority(client.Authority, new Tokens(), Org, Project);
        using var request = ProxiedServiceAdministrationOperations.Delete(Org, Project, Id);
        var grant = authority.IssueGrant(request.OperationId, new(Org, Project, Id));
        var receipt = client.CreateReceipt(request);
        using var cancellation = new CancellationTokenSource();
        if (cancel)
        {
            Task committed = wire.Committed.Task;
            Task result = client.ExecuteAsync(request, authority, grant, receipt, cancellation.Token).AsTask();
            await Task.WhenAny(committed, result).WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(committed.IsCompletedSuccessfully).IsTrue();
            await committed.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await Assert.That(async () => await result).Throws<OperationCanceledException>();
        }
        else await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That((await client.ExecuteAsync(request, authority, grant, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Revision).IsEqualTo(1);
    }

    private static ManagementRequest<ProxiedServiceSummary> Request(int route, ProxiedServiceCreation creation, ProxiedServiceUpdate update) => route switch
    {
        1 => ProxiedServiceAdministrationOperations.Create(Org, creation),
        2 => ProxiedServiceAdministrationOperations.Get(Org, Project, Id),
        3 => ProxiedServiceAdministrationOperations.Update(Org, Project, Id, update),
        4 => ProxiedServiceAdministrationOperations.Delete(Org, Project, Id),
        _ => ProxiedServiceAdministrationOperations.GetByName(Org, Project, EnvironmentName, Name)
    };
    private static ManagementTarget Target(int route, ProxiedServiceCreation creation, ProxiedServiceUpdate update) => route switch
    {
        1 => ProxiedServiceAdministrationOperations.CreationTarget(Org, creation),
        3 => ProxiedServiceAdministrationOperations.UpdateTarget(Org, Project, Id, update),
        5 => ProxiedServiceAdministrationOperations.NameTarget(Org, Project, EnvironmentName, Name),
        _ => new(Org, Project, Id)
    };
    private static ProxiedServiceCredentialInput Credential(int variant, SecretMaterial value, IEnumerable<ProxiedServiceSubstitutionSurface> surfaces) =>
        new(variant % 2 == 0 ? ProxiedServiceCredentialRole.HeaderRewrite : ProxiedServiceCredentialRole.CredentialSubstitution,
            variant >= 2 ? "field-private" : null, variant >= 2 ? "dynamic-private" : null,
            variant >= 2 ? "header-private" : null, variant >= 2 ? "" : null,
            variant < 2 ? null : variant == 2 ? ProxiedServiceHeaderPurpose.Username : ProxiedServiceHeaderPurpose.Password,
            variant >= 2 ? "key-private" : null, variant >= 2 ? value : null, variant >= 2 ? "secret-private" : null,
            variant >= 2 ? surfaces : null);

    private static string Response(int route)
    {
        JsonObject service = Metadata(route != 4, route is 0 or 2 or 5);
        return (route == 0 ? new JsonObject { ["projectSlug"] = "slug-private", ["services"] = new JsonArray(service) } :
            new JsonObject { ["service"] = service }).ToJsonString();
    }
    private static JsonObject Metadata(bool credentials, bool access)
    {
        var service = new JsonObject
        {
            ["id"] = Id,
            ["name"] = Name,
            ["folderId"] = Id,
            ["hostPattern"] = "host-private",
            ["createdAt"] = "2026-10-10T00:00:00Z",
            ["updatedAt"] = "2026-10-10T00:00:00Z",
            ["lastUsedAt"] = null
        };
        if (access) service["canProxy"] = true;
        if (credentials)
        {
            var credential = new JsonObject
            {
                ["id"] = Id,
                ["serviceId"] = Id,
                ["role"] = "future-role",
                ["headerPurpose"] = "future-purpose",
                ["dynamicSecretName"] = null,
                ["placeholderValue"] = "placeholder-private",
                ["substitutionSurfaces"] = new JsonArray("future-surface")
            };
            if (access) credential["callerCanLease"] = false;
            service["credentials"] = new JsonArray(credential);
        }
        return service;
    }
    private static ManagementTransport Transport(Wire wire) => new(new("https://management.test"), 65536, null, false, wire);
    private sealed class Tokens : IInfisicalTokenSource
    {
        public bool Acquired { get; private set; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            Acquired = true;
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(SecretMaterial.FromText("offline-token"))));
        }
    }
    private sealed class Wire(string response) : HttpMessageHandler
    {
        public string? Path { get; private set; }
        public JsonObject? Stored { get; private set; }
        public int Revision { get; private set; }
        public bool Lost { get; init; }
        public bool Hold { get; init; }
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Path = request.RequestUri!.PathAndQuery;
            if (request.RequestUri.GetLeftPart(UriPartial.Authority) != "https://management.test" ||
                request.Headers.Authorization?.Scheme != "Bearer") return new(HttpStatusCode.Unauthorized);
            if (request.Content is not null) Stored = JsonNode.Parse(await request.Content.ReadAsStringAsync(cancellationToken))!.AsObject();
            if (request.Method != HttpMethod.Get) Revision++;
            Committed.TrySetResult();
            if (Hold) await Release.Task.WaitAsync(cancellationToken);
            if (Lost) throw new IOException("Lost response.");
            return new(HttpStatusCode.OK) { Content = new StringContent(response, Encoding.UTF8, "application/json") };
        }
    }
}
