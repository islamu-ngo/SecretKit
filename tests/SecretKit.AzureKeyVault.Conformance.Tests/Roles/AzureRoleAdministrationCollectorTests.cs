using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleAdministrationCollectorTests
{
    private static readonly Guid SubscriptionId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid AssignmentId = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly Guid DefinitionId = Guid.Parse("44444444-4444-4444-4444-444444444444");
    private static readonly Guid PrincipalId = Guid.Parse("55555555-5555-5555-5555-555555555555");
    private static readonly Guid OtherId = Guid.Parse("66666666-6666-6666-6666-666666666666");
    private const string Version = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Material = "controlled-only-collector-canary";
    private const string ArmOrigin = "https://management.azure.com";
    private static string SubscriptionPath => $"/subscriptions/{SubscriptionId:D}";
    private static VaultScope Vault() => new(new(new(SubscriptionId), "collector-group"), "collector-vault");
    private static string AssignmentPath => Vault().ExportResourceId() + "/providers/Microsoft.Authorization/roleAssignments";
    private static string DefinitionPath => SubscriptionPath + "/providers/Microsoft.Authorization/roleDefinitions";
    private static string SecretId => $"https://collector-vault.vault.azure.net/secrets/canary/{Version}";

    [Test]
    public async Task NativePagesRetainInheritedMetadataAndPermissionMultiplicity()
    {
        using var fixture = new Fixture();
        fixture.Arm.Respond = (request, _) =>
        {
            bool second = request.RequestUri!.Query.Contains("skiptoken", StringComparison.Ordinal);
            bool definitions = request.RequestUri.AbsolutePath == DefinitionPath;
            string row = definitions ? Definition(second ? OtherId : DefinitionId) :
                Assignment(second ? OtherId : AssignmentId, second ? SubscriptionPath : null);
            return Task.FromResult(Json(200, Page(row, second ? null : Next(definitions))));
        };
        var collector = fixture.Collector();
        var binding = Binding();
        var window = collector.Arm(binding);
        var result = await collector.CollectAsync(window, binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsTrue();
        await Assert.That(result.Assignments.Count).IsEqualTo(2);
        await Assert.That(result.Assignments[1].ParentResourceId).IsEqualTo(SubscriptionPath);
        await Assert.That(result.Assignments[0].Description).IsEqualTo("protected-description");
        await Assert.That(result.Assignments[0].PrincipalType).IsEqualTo("ServicePrincipal");
        await Assert.That(result.Assignments[0].Condition).IsEqualTo("protected-condition");
        await Assert.That(result.Assignments[0].ConditionVersion).IsEqualTo("2.0");
        await Assert.That(result.Definitions.Count).IsEqualTo(2);
        await Assert.That(result.Definitions[0].Name).IsEqualTo("protected-role");
        await Assert.That(result.Definitions[0].RoleType).IsEqualTo("CustomRole");
        await Assert.That(result.Definitions[0].Description).IsEqualTo("protected-description");
        await Assert.That(result.Definitions[0].Permissions.Length).IsEqualTo(2);
        await Assert.That(result.Definitions[0].Permissions[0].Actions).IsEquivalentTo(["read", "read"]);
        await Assert.That(result.Definitions[0].Permissions[0].NotActions).IsEquivalentTo(["write"]);
        await Assert.That(result.Definitions[0].Permissions[0].DataActions).IsEquivalentTo(["get"]);
        await Assert.That(result.Definitions[0].Permissions[0].NotDataActions).IsEquivalentTo(["set"]);
        await Assert.That(result.Definitions[0].AssignableScopes).IsEquivalentTo([SubscriptionPath, SubscriptionPath]);
        await Assert.That(result.TargetPresent).IsTrue();
        await Assert.That(result.Intended.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(result.Intended.Sha256).IsEqualTo(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Material))));
        await Assert.That(result.Intended.NativeRequestId).IsEqualTo("intended-final");
        await Assert.That(result.Denied.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(result.Denied.Sha256).IsNull();
        await Assert.That(result.Denied.NativeRequestId).IsEqualTo("denied-final");
        await Assert.That(result.Observer.NativeRequestId).IsEqualTo("observer-final");
        await Assert.That(fixture.Arm.Requests.All(r => r.Method == HttpMethod.Get && r.Token == "arm")).IsTrue();
        await Assert.That(fixture.Intended.Requests.All(r => r.Token is null or "intended")).IsTrue();
        await Assert.That(fixture.Denied.Requests.All(r => r.Token is null or "denied")).IsTrue();
        await Assert.That(fixture.Observer.Requests.All(r => r.Token is null or "observer")).IsTrue();
    }

    [Test]
    [Arguments("foreign-assignment")]
    [Arguments("foreign-definition")]
    [Arguments("foreign-scope")]
    [Arguments("malformed-guid")]
    [Arguments("duplicate-row")]
    [Arguments("missing-permissions")]
    [Arguments("missing-array")]
    [Arguments("duplicate-property")]
    [Arguments("foreign-link")]
    [Arguments("wrong-revision")]
    [Arguments("duplicate-revision")]
    [Arguments("changed-filter")]
    [Arguments("path-traversal")]
    [Arguments("relative-link")]
    [Arguments("duplicate-link")]
    [Arguments("disagreeing-links")]
    [Arguments("empty-next")]
    [Arguments("empty-page")]
    [Arguments("missing-list")]
    [Arguments("null-list")]
    [Arguments("truncated-body")]
    [Arguments("foreign-definition-row")]
    [Arguments("duplicate-definition")]
    [Arguments("malformed-definition")]
    [Arguments("fragment")]
    [Arguments("other-operation")]
    [Arguments("wrong-name")]
    [Arguments("wrong-type")]
    [Arguments("encoded-foreign-link")]
    [Arguments("truncated-json")]
    public async Task InvalidMetadataNeverProvesAbsence(string fault)
    {
        using var fixture = new Fixture();
        fixture.Arm.Respond = (request, _) =>
        {
            bool definitions = request.RequestUri!.AbsolutePath == DefinitionPath;
            string row = definitions ? Definition(DefinitionId) : Assignment(AssignmentId);
            if (!definitions)
            {
                row = fault switch
                {
                    "foreign-assignment" => row.Replace(AssignmentPath, AssignmentPath.Replace("collector-vault", "foreign-vault"), StringComparison.Ordinal),
                    "foreign-definition" => row.Replace(DefinitionPath, DefinitionPath.Replace(SubscriptionId.ToString(), OtherId.ToString()), StringComparison.Ordinal),
                    "foreign-scope" => row.Replace("\"scope\":\"" + Vault().ExportResourceId(), "\"scope\":\"" + SubscriptionPath, StringComparison.Ordinal),
                    "malformed-guid" => row.Replace(AssignmentId.ToString(), "invalid-guid", StringComparison.Ordinal),
                    "duplicate-row" => row + "," + row,
                    "duplicate-property" => row.Replace("\"principalType\":", "\"principalId\":\"" + OtherId + "\",\"principalType\":", StringComparison.Ordinal),
                    "wrong-name" => row.Replace("\"name\":\"" + AssignmentId, "\"name\":\"" + OtherId, StringComparison.Ordinal),
                    "wrong-type" => row.Replace("\"type\":\"Microsoft.Authorization/roleAssignments\"", "\"type\":\"Microsoft.Authorization/roleDefinitions\"", StringComparison.Ordinal),
                    _ => row
                };
            }
            else
            {
                if (fault == "missing-permissions") row = row.Replace("\"permissions\":", "\"omitted\":", StringComparison.Ordinal);
                if (fault == "missing-array") row = row.Replace("\"notDataActions\":", "\"omitted\":", StringComparison.Ordinal);
                if (fault == "foreign-definition-row") row = row.Replace(SubscriptionId.ToString(), OtherId.ToString(), StringComparison.Ordinal);
                if (fault == "duplicate-definition") row += "," + row;
                if (fault == "malformed-definition") row = row.Replace(DefinitionId.ToString(), "invalid-guid", StringComparison.Ordinal);
            }
            string? next = !definitions ? fault switch
            {
                "foreign-link" => Next(false).Replace("management.azure.com", "foreign.invalid", StringComparison.Ordinal),
                "wrong-revision" => Next(false).Replace("2022-04-01", "2021-01-01", StringComparison.Ordinal),
                "duplicate-revision" => Next(false) + "&api-version=2022-04-01",
                "changed-filter" => Next(false) + "&$filter=principalId%20eq%20%27other%27",
                "path-traversal" => Next(false).Replace("/subscriptions/", "/other/../subscriptions/", StringComparison.Ordinal),
                "relative-link" => "/relative",
                "duplicate-link" => Next(false),
                "empty-next" => "",
                "empty-page" => Next(false),
                "fragment" => Next(false) + "#",
                "other-operation" => Next(true),
                "encoded-foreign-link" => Next(false).Replace("/roleAssignments?", "/role%41ssignments?", StringComparison.Ordinal),
                _ => null
            } : null;
            string body = fault switch
            {
                "truncated-json" => "{\"value\":[",
                "missing-list" => "{}",
                "null-list" => "{\"value\":null}",
                "empty-page" when !definitions => Page("", next),
                "disagreeing-links" when !definitions => Page(row, Next(false))[..^1] + ",\"nextLink\":" + JsonSerializer.Serialize(Next(true)) + "}",
                _ => Page(row, next)
            };
            var response = Json(200, body);
            if (fault == "truncated-body") response.Content.Headers.ContentLength = Encoding.UTF8.GetByteCount(body) + 1;
            return Task.FromResult(response);
        };
        var collector = fixture.Collector();
        var binding = Binding();
        var result = await collector.CollectAsync(collector.Arm(binding), binding, RoleAdministrationCollector.Phase.After);
        await Assert.That(result.Complete).IsFalse();
        await Assert.That(result.TargetPresent).IsNull();
        await Assert.That(result.Assignments.Count).IsEqualTo(0);
        await Assert.That(result.Definitions.Count).IsEqualTo(0);
        await Assert.That(result.Failure).IsNotEqualTo(RoleAdministrationCollector.Failure.None);
        await Assert.That(fixture.Arm.Requests.All(r => r.Uri.Host == "management.azure.com")).IsTrue();
    }

    private static RoleAdministrationCollector.Binding Binding() =>
        new(new(Guid.NewGuid(), "collector-scope", "role-operation", "scope.vault", "independent-effect"),
            Guid.NewGuid(), Vault(), new(Vault(), AssignmentId), DefinitionId, "canary", Version, []);

    private static string Next(bool definitions) => ArmOrigin + (definitions ? DefinitionPath : AssignmentPath) +
        "?api-version=2022-04-01&$skiptoken=page2";
    private static string Page(string rows, string? next = null) =>
        "{\"value\":[" + rows + "]" + (next is null ? "" : ",\"nextLink\":" + JsonSerializer.Serialize(next)) + "}";
    private static string Assignment(Guid id, string? parent = null) => JsonSerializer.Serialize(new
    {
        id = (parent ?? Vault().ExportResourceId()) + $"/providers/Microsoft.Authorization/roleAssignments/{id:D}",
        name = id.ToString("D"),
        type = "Microsoft.Authorization/roleAssignments",
        properties = new
        {
            scope = parent ?? Vault().ExportResourceId(),
            roleDefinitionId = DefinitionPath + "/" + DefinitionId,
            principalId = PrincipalId,
            principalType = "ServicePrincipal",
            description = "protected-description",
            condition = "protected-condition",
            conditionVersion = "2.0"
        }
    });
    private static string Definition(Guid id) => JsonSerializer.Serialize(new
    {
        id = DefinitionPath + "/" + id,
        name = id.ToString("D"),
        type = "Microsoft.Authorization/roleDefinitions",
        properties = new
        {
            roleName = "protected-role",
            description = "protected-description",
            type = "CustomRole",
            assignableScopes = new[] { SubscriptionPath, SubscriptionPath },
            permissions = Enumerable.Range(0, 2).Select(_ => new
            {
                actions = new[] { "read", "read" },
                notActions = new[] { "write" },
                dataActions = new[] { "get" },
                notDataActions = new[] { "set" }
            }).ToArray()
        }
    });
    private static HttpResponseMessage Json(int status, string body, string id = "arm-final")
    {
        var response = new HttpResponseMessage((HttpStatusCode)status)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json")
        };
        response.Headers.Add("x-ms-request-id", id);
        return response;
    }

    private sealed class Fixture : IDisposable
    {
        internal readonly Backend Arm = new("arm");
        internal readonly Backend Intended = new("intended");
        internal readonly Backend Denied = new("denied");
        internal readonly Backend Observer = new("observer");
        internal readonly Credential ArmCredential = new("arm", "https://management.azure.com/.default");
        internal readonly Credential IntendedCredential = new("intended", "https://vault.azure.net/.default");
        internal readonly Credential DeniedCredential = new("denied", "https://vault.azure.net/.default");
        internal readonly Credential ObserverCredential = new("observer", "https://vault.azure.net/.default");
        private readonly HttpClient[] clients;
        internal readonly HttpClientTransport[] Transports;

        internal Fixture()
        {
            clients = [new(Arm), new(Intended), new(Denied), new(Observer)];
            Transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            Arm.Respond = (request, _) => Task.FromResult(Json(200,
                Page(request.RequestUri!.AbsolutePath == DefinitionPath ? Definition(DefinitionId) : Assignment(AssignmentId))));
            foreach (var backend in new[] { Intended, Denied, Observer })
                backend.Respond = (request, _) =>
                {
                    if (request.Headers.Authorization is null)
                    {
                        var challenge = Json(401, "{}", "challenge-not-final");
                        challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                            "Bearer authorization=\"https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222\", resource=\"https://vault.azure.net\"");
                        return Task.FromResult(challenge);
                    }
                    return Task.FromResult(backend == Denied
                        ? Json(403, """{"error":{"code":"Forbidden","message":"private-native-error"}}""", "denied-final")
                        : Json(200, JsonSerializer.Serialize(new { id = SecretId, value = Material, attributes = new { enabled = true } }),
                            backend == Intended ? "intended-final" : "observer-final"));
                };
        }

        internal RoleAdministrationCollector Collector(RoleAdministrationCollector.Limits? limits = null, TimeProvider? time = null) =>
            new(new("arm", ArmCredential, Transports[0]), new("intended", IntendedCredential, Transports[1]),
                new("denied", DeniedCredential, Transports[2]), new("observer", ObserverCredential, Transports[3]),
                limits ?? new(4, 100, 64 * 1024, TimeSpan.FromSeconds(10)), time);

        public void Dispose()
        {
            foreach (var client in clients) client.Dispose();
        }
    }

    private sealed class Backend(string role) : HttpMessageHandler
    {
        internal Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Respond = null!;
        internal readonly List<(HttpMethod Method, Uri Uri, string? Token)> Requests = [];
        internal bool Disposed;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method, request.RequestUri!, request.Headers.Authorization?.Parameter));
            if (request.Method != HttpMethod.Get) throw new InvalidOperationException("collector-write");
            if (request.Headers.Authorization is { } authorization && authorization.Parameter != role)
                throw new InvalidOperationException("collector-authority");
            return Respond(request, cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class Credential(string token, string audience) : TokenCredential, IDisposable
    {
        internal bool Disposed;
        internal int Uses;
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Disposed || context.Scopes.Length != 1 || context.Scopes[0] != audience)
                throw new InvalidOperationException("collector-credential");
            Uses++;
            return new(token, DateTimeOffset.MaxValue);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken) =>
            ValueTask.FromResult(GetToken(context, cancellationToken));
        public void Dispose() => Disposed = true;
    }
}
