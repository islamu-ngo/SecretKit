using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;
using SecretKit.Samples.OperatorWorkflow;

using var provider = new OfflineProvider();
return await OperatorWorkflow.RunAsync(provider, Console.Out);

namespace SecretKit.Samples.OperatorWorkflow
{
    // All coordinates and material in this executable are synthetic. It cannot contact a provider.
    public static class OperatorWorkflow
    {
        public static readonly Uri Origin = new("https://operator.invalid");
        public const string Organization = "11111111-1111-4111-8111-111111111111";
        public const string FolderId = "22222222-2222-4222-8222-222222222222";
        public const string EnvironmentId = "33333333-3333-4333-8333-333333333333";
        public static InfisicalNetworkOptions Network(HttpMessageHandler handler) =>
            new() { Transport = InfisicalTransportOptions.HostControlled(handler) };

        public static async Task<int> RunAsync(HttpMessageHandler provider, TextWriter output,
            TimeProvider? timeProvider = null, CancellationToken cancellationToken = default)
        {
            using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            budget.CancelAfter(TimeSpan.FromSeconds(20));
            CancellationToken token = budget.Token;
            var network = Network(provider);
            using var authentication = new InfisicalUniversalAuthentication(Origin, network);
            using var bootstrap = SecretMaterial.FromText("offline-bootstrap");
            var attempt = authentication.CreateReceipt(); // Retained before login, including on cancellation.
            var acquired = await authentication.LoginAsync("offline-client", bootstrap, attempt, cancellationToken: token);
            if (!acquired.IsSuccess)
            {
                await output.WriteLineAsync($"LOGIN_{acquired.Status}_{attempt.Evidence}");
                return 1;
            }
            using var login = acquired.Value;
            using var runtimeTokens = new InfisicalSuppliedTokenSource(login.Token.Material, login.Token.ExpiresAt);
            // Management/apply authority is selected separately, never a fallback from a failed runtime read.
            using var adminMaterial = SecretMaterial.FromText("operator-admin");
            using var adminTokens = new InfisicalSuppliedTokenSource(adminMaterial);
            await using var client = new InfisicalClient(Origin, runtimeTokens, network);
            using var managementTransport = new ManagementTransport(Origin, network);
            var management = new ManagementClient(managementTransport);
            var admin = new ManagementAuthority(management.Authority, adminTokens, Organization, "project");
            using var revoker = new InfisicalProofAuthentication(Origin, network);
            var signoutReceipt = revoker.CreateRevocationReceipt();
            int result;
            try
            {
                result = await RunReviewedAsync();
            }
            catch (OperationCanceledException)
            {
                await output.WriteLineAsync("CANCELED");
                result = 1;
            }
            finally
            {
                // Sign-out has a separate deadline even when workflow cancellation occurred; never replay uncertainty.
                using var signoutBudget = new CancellationTokenSource(TimeSpan.FromSeconds(5), timeProvider ?? TimeProvider.System);
                try
                {
                    await revoker.RevokeTokenAsync(login.Token.Material, signoutReceipt, signoutBudget.Token);
                }
                catch (OperationCanceledException) when (signoutBudget.IsCancellationRequested)
                {
                    result = 1;
                }
                finally
                {
                    await output.WriteLineAsync($"SIGNOUT_{signoutReceipt.Evidence}");
                }
            }
            return signoutReceipt.Evidence == DispatchEvidence.Applied ? result : 1;

            async Task<int> RunReviewedAsync()
            {
                using var request = ProjectOperations.GetProject(Organization, "project");
                var policy = await management.ExecuteAsync(request, admin,
                    admin.IssueGrant(request.OperationId, new(Organization, "project")), cancellationToken: token);
                if (!policy.IsSuccess || !policy.Value.AutoCapitalization.IsPresent || policy.Value.AutoCapitalization.IsNull)
                    return await StopAsync("POLICY_UNESTABLISHED");

                var selection = new InfisicalInventorySelection(client.Authority, "project", "dev", "/",
                    includeImports: true, maximumItems: 10, maximumRequests: 4, timeout: TimeSpan.FromSeconds(5));
                var observed = await client.InspectNativeAsync(selection, token);
                if (!observed.IsSuccess) return await StopAsync($"INVENTORY_{observed.Status}");
                if (!observed.Value.IsComplete) return await StopAsync("INVENTORY_INCOMPLETE");
                var entries = observed.Value.Entries;
                if (entries.Count != 2 || entries.Any(entry => entry.Origin != InfisicalInventoryOrigin.Direct ||
                    entry.IsRotatedSecret != false || entry.Revision is null || entry.Reference is null))
                    return await StopAsync("PREFLIGHT_BLOCKED");
                // Exact keys are prepared for human review. This offline host approves only its fixed demonstration intent.
                string[] reviewed = ["FIRST", "SECOND"];
                if (!entries.Select(entry => entry.Key).Order(StringComparer.Ordinal).SequenceEqual(reviewed) ||
                    policy.Value.AutoCapitalization.Value && reviewed.Any(key => key != key.ToUpperInvariant()))
                    return await StopAsync("PREFLIGHT_BLOCKED");
                foreach (var entry in entries)
                {
                    var readiness = await client.ReadAsync(entry.Reference!, token);
                    if (!readiness.IsSuccess) return await StopAsync($"READINESS_{readiness.Status}");
                    readiness.Value.Dispose();
                }
                await output.WriteLineAsync("REVIEWED_TWO_UPDATES");
                // Immediate metadata recheck detects observed changes only: it is not CAS or a rotation lock.
                var fresh = await client.InspectNativeAsync(selection, token);
                if (!fresh.IsSuccess || !fresh.Value.IsComplete || fresh.Value.Entries.Count != entries.Count ||
                    fresh.Value.Entries.Any(entry => entry.Origin != InfisicalInventoryOrigin.Direct ||
                        entry.IsRotatedSecret != false || !entries.Any(old => old.Key == entry.Key && old.Revision == entry.Revision)))
                    return await StopAsync("REVIEW_CHANGED");
                using var replacement = SecretMaterial.FromText("replacement");
                InfisicalBulkSecret[] updates = reviewed.Select(key => new InfisicalBulkSecret(key, replacement)).ToArray();
                var target = new SecretReference(client.Authority, new InfisicalBulkAddress("project", "dev", "/", FolderId));
                var authority = new InfisicalNativeAuthority(client.Authority, adminTokens, "project", "dev", "/");
                var receipt = new InfisicalBulkReceipt(client, target, updates, InfisicalBulkOperation.Update);
                SecretOutcome<InfisicalBulkObservation> applied;
                try
                {
                    applied = await client.UpdateSecretsAsync(target, updates, authority, receipt, cancellationToken: token);
                }
                finally { await output.WriteLineAsync($"APPLY_{receipt.Evidence}"); }
                // Receipt survives failure; never turn Pending, partial application or response loss into success or replay.
                if (!applied.IsSuccess || !applied.Value.AllApplied || applied.Value.ApprovalPending)
                    return 1;
                foreach (var entry in entries)
                {
                    var delivered = await client.ReadAsync(entry.Reference!, token);
                    if (!delivered.IsSuccess) return await StopAsync($"READINESS_{delivered.Status}");
                    delivered.Value.Dispose();
                }
                await output.WriteLineAsync("READY");
                return 0;
            }

            async Task<int> StopAsync(string reason)
            {
                await output.WriteLineAsync(reason);
                return 1;
            }
        }
    }

    // Deterministic wire fixtures model provider state, not operator policy. No real endpoint is contacted.
    public sealed class OfflineProvider : HttpMessageHandler
    {
        public string Fault { get; init; } = "";
        public Dictionary<string, string> Values { get; } = new() { ["FIRST"] = "original", ["SECOND"] = "original" };
        public int ApplyAttempts { get; private set; }
        public int RuntimeReads { get; private set; }
        public int SignOuts { get; private set; }
        public TaskCompletionSource SignoutEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource SignoutRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ApplyEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ApplyRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _inventories;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            string path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/universal-auth/login", StringComparison.Ordinal))
                return Json(new { accessToken = "operator-runtime", accessTokenMaxTTL = 3600, expiresIn = 3600, tokenType = "Bearer" });
            if (path.EndsWith("/token/revoke", StringComparison.Ordinal))
            {
                SignOuts++;
                SignoutEntered.TrySetResult();
                if (Fault == "hold-signout") await SignoutRelease.Task.WaitAsync(token);
                if (Fault == "signout-loss") throw new HttpRequestException("private-signout-detail");
                return Json(new { message = "revoked" });
            }
            if (path.Contains("/projects/", StringComparison.Ordinal))
            {
                var project = new Dictionary<string, object?>
                {
                    ["id"] = "project",
                    ["orgId"] = OperatorWorkflow.Organization,
                    ["type"] = "secret-manager",
                    ["name"] = "private-project",
                    ["slug"] = "project",
                    ["createdAt"] = "2026-11-01T00:00:00Z",
                    ["updatedAt"] = "2026-11-01T00:00:00Z"
                };
                if (Fault != "unknown-policy") project["autoCapitalization"] = Fault == "null-policy" ? null : Fault != "lowercase-policy";
                return Json(new { project });
            }
            if (request.Method == HttpMethod.Get && path == "/api/v4/secrets")
            {
                _inventories++;
                if (Fault is "concealed" or "missing-route") return Json(new { }, HttpStatusCode.NotFound);
                object[] rows = [Row(Fault == "noncanonical" ? "first" : "FIRST"), Row("SECOND")];
                if (Fault == "incomplete") ((Dictionary<string, object?>)rows[0]).Remove("version");
                object[] imports = Fault == "imported"
                    ? [new { environment = "upstream", secretPath = "/source", secrets = new[] { Row("IMPORTED", "/source", "upstream") } }]
                    : [];
                return Json(new { secrets = rows, imports });
            }
            if (request.Method == HttpMethod.Get && path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
            {
                if (request.Headers.Authorization?.Parameter != "operator-runtime")
                    return Json(new { }, HttpStatusCode.Forbidden);
                RuntimeReads++;
                return Fault == "read-denied" ? Json(new { }, HttpStatusCode.Forbidden)
                    : Json(new { secret = Row(Uri.UnescapeDataString(path.Split('/')[^1])) });
            }
            if (request.Method == HttpMethod.Patch && path.EndsWith("/batch", StringComparison.Ordinal))
            {
                ApplyAttempts++;
                if (request.Headers.Authorization?.Parameter != "operator-admin" || Fault == "apply-denied")
                    return Json(new { }, HttpStatusCode.Forbidden);
                if (Fault == "pending")
                    return Json(new
                    {
                        approval = new
                        {
                            id = "44444444-4444-4444-8444-444444444444",
                            folderId = OperatorWorkflow.FolderId,
                            policyId = "55555555-5555-4555-8555-555555555555",
                            hasMerged = false
                        }
                    });
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                var changed = new List<object>();
                foreach (var item in body.RootElement.GetProperty("secrets").EnumerateArray())
                {
                    string key = item.GetProperty("secretKey").GetString()!;
                    Values[key] = item.GetProperty("secretValue").GetString()!;
                    changed.Add(Row(key));
                    if (Fault == "partial") break;
                }
                ApplyEntered.TrySetResult();
                if (Fault == "hold-apply") await ApplyRelease.Task.WaitAsync(token);
                if (Fault == "lost-response") throw new HttpRequestException("private-provider-detail");
                return Json(new { secrets = changed });
            }
            return Json(new { }, HttpStatusCode.NotFound);
        }

        private Dictionary<string, object?> Row(string key, string path = "/", string environment = "dev") => new()
        {
            ["id"] = key,
            ["workspace"] = "project",
            ["environment"] = environment,
            ["secretPath"] = path,
            ["type"] = "shared",
            ["secretKey"] = key,
            ["version"] = Fault == "changed-revision" && _inventories > 1 ? 2 : 1,
            ["secretValue"] = Values.GetValueOrDefault(key, "private-value"),
            ["secretValueHidden"] = false,
            ["secretComment"] = "private-comment",
            ["isRotatedSecret"] = Fault == "unknown-rotation" ? null : Fault == "managed",
            ["updatedAt"] = "2026-11-01T00:00:00Z"
        };
        private static HttpResponseMessage Json(object value, HttpStatusCode status = HttpStatusCode.OK) =>
            new(status) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
    }
}
