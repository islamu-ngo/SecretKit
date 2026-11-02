using System.Net;
using System.Text;
using System.Text.Json;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    private sealed class WireState
    {
        internal string? VaultId;
        internal string? VaultName;
        internal string? AssignmentPath;
        internal string? Nonce;
        internal string? Secret;
        internal bool Rbac;
        internal bool PurgeProtection;
        internal Guid Principal;
        internal string? Definition;
        internal bool VaultExists;
        internal bool DeletedVaultExists;
        internal bool BeforeSendPersisted = true;
        internal string VaultState = "Succeeded";
        internal string? CreateFault;
        internal string? DeleteFault;
        internal string? PurgeFault;
        internal bool AsyncPurge;
        internal bool IncludeBorrowedRows;
        internal bool SelectedAssignmentNoOp;
        internal string? SelectedDeleteFault;
        internal int SelectedDeleteStatus = 204;
        internal string SelectedDeleteBody = "";
        internal string? SelectedDeleteHeader;
        internal string? MissingAssignmentBody;
        internal Action<System.Text.Json.Nodes.JsonObject>? AssignmentTransform;
        internal string PurgeState = "InProgress";
        internal string? PurgeStatusOrigin;
        internal bool SecretDenied;
        internal bool ForeignDeleted;
        internal bool ObservationDenied;
        internal bool Oversized;
        internal Action<string> BeforeMutation = null!;
        internal TaskCompletionSource? Applied;
        internal TaskCompletionSource? Terminate;
        internal TaskCompletionSource? SelectedApplied, SelectedTerminate;
        internal TaskCompletionSource? SetupAssignmentApplied, SetupAssignmentTerminate;

        internal async Task<HttpResponseMessage> Respond(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (role.StartsWith("observe", StringComparison.Ordinal) && request.Method != HttpMethod.Get)
                throw new InvalidOperationException("controlled-observer-write");
            if (request.Headers.Authorization is null && role.EndsWith("secret", StringComparison.Ordinal))
            {
                var challenge = Json(401, "{}");
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    $"Bearer authorization=\"https://login.microsoftonline.com/{Tenant:D}\", resource=\"https://vault.azure.net\"");
                return challenge;
            }
            if (request.Headers.Authorization?.Parameter != role) throw new InvalidOperationException("controlled-authority");
            if (role == "denied-arm") return Json(403, """{"error":{"code":"Forbidden"}}""");
            if (role.StartsWith("observe", StringComparison.Ordinal) && ObservationDenied)
                return Json(403, """{"error":{"code":"Forbidden","message":"protected-server-message"}}""");
            if (Oversized) return Json(200, "{\"padding\":\"" + new string('x', 70000) + "\"}");
            if (path.Contains("/operationResults/", StringComparison.Ordinal))
            {
                if (request.Method != HttpMethod.Get) throw new InvalidOperationException("controlled-status-write");
                if (CreateFault == "status-denied")
                    return Json(403, """{"error":{"code":"Forbidden"}}""");
                if (PurgeState == "Succeeded")
                {
                    DeletedVaultExists = false;
                    Secret = null;
                }
                return Json(200, JsonSerializer.Serialize(new { status = PurgeState }));
            }
            if (path.StartsWith("/secrets/", StringComparison.Ordinal))
            {
                if (request.Method == HttpMethod.Put)
                {
                    BeforeMutation(VaultId + "/secrets/canary");
                    if (SecretDenied) return Json(403, """{"error":{"code":"Forbidden","message":"private-secret-diagnostic"}}""");
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                    Secret = body.RootElement.GetProperty("value").GetString();
                }
                if (role == "denied-secret" || role == "intended-secret" && AssignmentPath is null)
                    return Json(403, """{"error":{"code":"Forbidden"}}""");
                return Secret is null ? Missing() : Json(200, JsonSerializer.Serialize(new
                {
                    id = $"https://{VaultName}.vault.azure.net/secrets/canary/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    value = Secret,
                    attributes = new { enabled = true }
                }));
            }
            if (path == SubscriptionPath + "/providers/Microsoft.Authorization/roleDefinitions")
            {
                using var rowRequest = new HttpRequestMessage(HttpMethod.Get,
                    "https://management.azure.com" + DefinitionPath + "?api-version=2022-04-01");
                rowRequest.Headers.Authorization = request.Headers.Authorization;
                using var row = await Respond(rowRequest, role, token);
                return Json(200, "{\"value\":[" + await row.Content!.ReadAsStringAsync(token) + "]}");
            }
            if (path == VaultId + "/providers/Microsoft.Authorization/roleAssignments")
            {
                string[] rows = AssignmentPath is null ? [] : [Assignment(AssignmentPath)];
                if (IncludeBorrowedRows) rows = [.. rows, Assignment(GroupAssignmentPath), Assignment(SubscriptionAssignmentPath)];
                return Json(200, "{\"value\":[" + string.Join(',', rows) + "]}");
            }
            if (path.Contains("/roleDefinitions/", StringComparison.Ordinal))
            {
                return Json(200, JsonSerializer.Serialize(new
                {
                    id = path,
                    name = path[(path.LastIndexOf('/') + 1)..],
                    type = "Microsoft.Authorization/roleDefinitions",
                    properties = new
                    {
                        roleName = "controlled-role",
                        type = "CustomRole",
                        description = "protected-role-metadata",
                        assignableScopes = new[] { SubscriptionPath },
                        permissions = new[] { new { actions = Array.Empty<string>(), notActions = Array.Empty<string>(),
                            dataActions = new[] { "Microsoft.KeyVault/vaults/secrets/getSecret/action" }, notDataActions = Array.Empty<string>() } }
                    }
                }));
            }
            if (path.Contains("/roleAssignments/", StringComparison.Ordinal))
            {
                if (path == GroupAssignmentPath || path == SubscriptionAssignmentPath)
                {
                    if (request.Method != HttpMethod.Get) throw new InvalidOperationException("controlled-borrowed-write");
                    return Json(200, Assignment(path));
                }
                if (request.Method == HttpMethod.Put)
                {
                    BeforeMutation(path);
                    using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                    var properties = body.RootElement.GetProperty("properties");
                    Principal = properties.GetProperty("principalId").GetGuid();
                    if (role == "administrative-arm")
                    {
                        SelectedApplied?.TrySetResult();
                        if (SelectedTerminate is not null) await SelectedTerminate.Task;
                        token.ThrowIfCancellationRequested();
                    }
                    Definition = properties.GetProperty("roleDefinitionId").GetString();
                    if (role != "administrative-arm" || !SelectedAssignmentNoOp) AssignmentPath = path;
                    if (role == "setup-arm")
                    {
                        SetupAssignmentApplied?.TrySetResult();
                        if (SetupAssignmentTerminate is not null) await SetupAssignmentTerminate.Task;
                        token.ThrowIfCancellationRequested();
                    }
                    return Json(201, Assignment(path));
                }
                if (request.Method == HttpMethod.Delete)
                {
                    BeforeMutation(path);
                    if (role != "administrative-arm" || SelectedDeleteFault != "no-op") AssignmentPath = null;
                    if (role == "administrative-arm")
                    {
                        SelectedApplied?.TrySetResult();
                        if (SelectedTerminate is not null) await SelectedTerminate.Task;
                        token.ThrowIfCancellationRequested();
                        if (SelectedDeleteFault == "lost") throw new IOException("controlled-selected-role-delete-loss");
                    }
                    var response = Json(role == "administrative-arm" ? SelectedDeleteStatus : 204,
                        role == "administrative-arm" ? SelectedDeleteBody : "");
                    if (role == "administrative-arm" && SelectedDeleteHeader is { } header)
                        response.Headers.TryAddWithoutValidation(header,
                            header == "Retry-After" ? "1" : request.RequestUri.AbsoluteUri);
                    return response;
                }
                return AssignmentPath == path ? Json(200, Assignment(path)) :
                    MissingAssignmentBody is { } missing ? Json(404, missing) : Missing();
            }
            if (path.EndsWith("/purge", StringComparison.Ordinal))
            {
                if (request.Method != HttpMethod.Post) throw new InvalidOperationException("controlled-purge-method");
                BeforeMutation(path[..^6]);
                if (PurgeFault == "denied") return Json(403, """{"error":{"code":"Forbidden"}}""");
                if (AsyncPurge)
                {
                    var pending = Json(202, "");
                    pending.Headers.TryAddWithoutValidation("Azure-AsyncOperation",
                        (PurgeStatusOrigin ?? "https://management.azure.com") + SubscriptionPath +
                        "/providers/Microsoft.KeyVault/locations/eastus/operationResults/11111111-2222-3333-4444-555555555555?api-version=2026-02-01");
                    return pending;
                }
                if (PurgeFault != "no-op")
                {
                    DeletedVaultExists = false;
                    Secret = null;
                }
                if (PurgeFault == "lost") throw new IOException("private-purge-token-coordinate");
                return Json(200, "");
            }
            if (path.Contains("/deletedVaults/", StringComparison.Ordinal))
            {
                return DeletedVaultExists ? Json(200, JsonSerializer.Serialize(new
                {
                    id = path,
                    name = VaultName,
                    type = "Microsoft.KeyVault/deletedVaults",
                    properties = new
                    {
                        vaultId = ForeignDeleted ? GroupPath + "/providers/Microsoft.KeyVault/vaults/borrowed" : VaultId,
                        location = "eastus",
                        tags = new Dictionary<string, string?> { ["secretkit-fixture"] = Nonce },
                        purgeProtectionEnabled = PurgeProtection,
                        deletionDate = "2026-10-14T00:00:00Z",
                        scheduledPurgeDate = "2026-10-21T00:00:00Z"
                    }
                })) : Missing();
            }
            if (request.Method == HttpMethod.Put)
            {
                BeforeMutation(path);
                if (CreateFault == "denied") return Json(403, """{"error":{"code":"Forbidden","message":"protected-create-message"}}""");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                VaultId = path;
                VaultName = path[(path.LastIndexOf('/') + 1)..];
                Nonce = body.RootElement.GetProperty("tags").GetProperty("secretkit-fixture").GetString();
                var properties = body.RootElement.GetProperty("properties");
                Rbac = properties.GetProperty("enableRbacAuthorization").GetBoolean();
                PurgeProtection = properties.GetProperty("enablePurgeProtection").GetBoolean();
                VaultExists = CreateFault != "no-op";
                Applied?.TrySetResult();
                if (Terminate is not null) await Terminate.Task.ConfigureAwait(false);
                if (CreateFault == "lost") throw new IOException("private-create-token-coordinate");
                if (CreateFault == "status-denied")
                {
                    VaultState = "Updating";
                    var pending = Json(202, Vault());
                    pending.Headers.TryAddWithoutValidation("Azure-AsyncOperation",
                        "https://management.azure.com" + SubscriptionPath +
                        "/providers/Microsoft.KeyVault/locations/eastus/operationResults/11111111-2222-3333-4444-555555555555?api-version=2026-02-01");
                    return pending;
                }
                return Json(200, Vault());
            }
            if (request.Method == HttpMethod.Delete)
            {
                BeforeMutation(path);
                if (DeleteFault == "denied") return Json(403, """{"error":{"code":"Forbidden"}}""");
                if (DeleteFault != "no-op")
                {
                    VaultExists = false;
                    DeletedVaultExists = true;
                }
                if (DeleteFault == "lost") throw new IOException("private-delete-token-coordinate");
                return Json(204, "");
            }
            return VaultExists ? Json(200, Vault()) : Missing();
        }

        private string Vault() => JsonSerializer.Serialize(new
        {
            id = VaultId,
            name = VaultName,
            type = "Microsoft.KeyVault/vaults",
            location = "eastus",
            tags = new Dictionary<string, string?> { ["secretkit-fixture"] = Nonce },
            properties = new
            {
                tenantId = Tenant,
                sku = new { family = "A", name = "standard" },
                vaultUri = $"https://{VaultName}.vault.azure.net",
                provisioningState = VaultState,
                enableRbacAuthorization = Rbac,
                enableSoftDelete = true,
                enablePurgeProtection = PurgeProtection
            }
        });

        private string Assignment(string path)
        {
            var json = JsonSerializer.Serialize(new
            {
                id = path,
                name = path[(path.LastIndexOf('/') + 1)..],
                type = "Microsoft.Authorization/roleAssignments",
                properties = new
                {
                    scope = path[..path.LastIndexOf("/providers/", StringComparison.Ordinal)],
                    roleDefinitionId = DefinitionPath,
                    principalId = path == GroupAssignmentPath || path == SubscriptionAssignmentPath
                    ? Guid.Parse("88888888-8888-8888-8888-888888888888") : PrincipalId,
                    principalType = "ServicePrincipal",
                    description = "protected-assignment-metadata"
                }
            });
            if (AssignmentTransform is null) return json;
            var body = System.Text.Json.Nodes.JsonNode.Parse(json)!.AsObject();
            AssignmentTransform(body);
            return body.ToJsonString();
        }
    }

    private sealed class Backend(string role, WireState state) : HttpMessageHandler
    {
        internal string Role { get; } = role;
        internal readonly List<(HttpMethod Method, string Path)> Requests = [];
        internal bool Disposed;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method, request.RequestUri!.AbsolutePath));
            return state.Respond(request, Role, cancellationToken);
        }
        protected override void Dispose(bool disposing)
        {
            Disposed = true;
            base.Dispose(disposing);
        }
    }

    private static HttpResponseMessage Missing() => Json(404, """{"error":{"code":"ResourceNotFound"}}""");
    private static HttpResponseMessage Json(int status, string body)
    {
        var response = new HttpResponseMessage((HttpStatusCode)status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        response.Headers.Add("x-ms-request-id", "controlled-native-receipt");
        return response;
    }
}
