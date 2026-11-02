using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Provider-owned storage and an independently provisioned TokenReview destination
// inventory. The witness channel cannot apply SDK updates.
internal sealed class InfisicalGatewayPatchEffectFixture : IAsyncDisposable, IGatewayAgentObserver, IGatewayPatchObserver
{
    internal const string Organization = "00000000-0000-0000-0000-000000000001";
    internal const string Attachment = "00000000-0000-0000-0000-000000000011";
    internal const string Pool = "00000000-0000-0000-0000-000000000012";
    internal const string SelectedAttachment = "00000000-0000-0000-0000-000000000021";
    internal const string SelectedPool = "00000000-0000-0000-0000-000000000022";
    internal const string Identity = "00000000-0000-0000-0000-000000000013";
    internal const string Date = "2040-01-01T00:00:00Z";
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accepting;
    private readonly Dictionary<string, JsonObject> gateways = [];
    private readonly Dictionary<string, (string Ca, string Reviewer)> destinations = new()
    {
        ["https://cluster-one.invalid"] = ("CA-one", "reviewer-one"),
        ["https://cluster-two.invalid"] = ("CA-two", "reviewer-two")
    };
    private readonly HashSet<string> owned = [];
    private readonly Dictionary<string, string> ownedIdentities = [];
    private readonly Dictionary<string, JsonObject> projects = [];
    private readonly List<SecretMaterial> privateCopies = [];
    private readonly IGatewayPatchObserver patchObserver;
    internal object Gate { get; } = new();
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal InfisicalGatewayPatchEffectSource Source { get; }
    internal ManagementClient Client { get; private set; } = null!;
    internal long Sequence { get; private set; }
    internal long Tick() => ++Sequence;
    internal DateTimeOffset Now => DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture).AddTicks(Sequence);
    internal List<RequestEvent> Requests { get; } = [];
    internal List<AuthenticationEvent> Authentications { get; } = [];
    internal int ResidualCount => gateways.Count + projects.Count + owned.Count;
    internal int GatewayCount => gateways.Count;
    internal bool BorrowedPreserved => destinations.Count == 2 &&
        destinations.GetValueOrDefault("https://cluster-one.invalid") == ("CA-one", "reviewer-one") &&
        destinations.GetValueOrDefault("https://cluster-two.invalid") == ("CA-two", "reviewer-two");
    internal bool Destroyed => privateCopies.All(m =>
    {
        try { m.Reveal(); return false; }
        catch (ObjectDisposedException) { return true; }
    });

    internal InfisicalGatewayPatchEffectFixture(string fault = "good")
    {
        Fault = fault;
        if (fault == "borrowed-damage") destinations.Remove("https://cluster-two.invalid");
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        patchObserver = Source.CreateObserver();
        accepting = AcceptAsync();
    }

    internal static GatewayPatchAuthenticationInput Baseline(string variant) => variant switch
    {
        "response.auth.Identity" => new(GatewayAuthenticationMethod.Identity),
        _ when variant.Contains("Aws", StringComparison.Ordinal) =>
            new(GatewayAuthenticationMethod.Aws, AllowedAccountIds: "111111111111", AllowedPrincipalArns: "arn:baseline"),
        _ when variant.Contains("Gcp", StringComparison.Ordinal) =>
            new(GatewayAuthenticationMethod.Gcp, AllowedProjects: "baseline-project",
                AllowedServiceAccounts: "baseline-account", AllowedZones: "baseline-zone",
                GcpType: variant == "auth.Gcp.Iam" ? GatewayGcpType.Gce : GatewayGcpType.Iam),
        _ => new(GatewayAuthenticationMethod.Kubernetes, AllowedNames: "baseline-workload",
            AllowedNamespaces: "baseline-namespace", AllowedAudience: "baseline-audience",
            CaCertificate: "CA-one", KubernetesHost: "https://cluster-one.invalid",
            TokenReviewerJwt: "reviewer-one", TokenReviewMode: variant == "auth.Kubernetes.review-omitted" ?
                GatewayTokenReviewMode.Gateway : GatewayTokenReviewMode.Api,
            VerifyTlsCertificate: variant == "verifyTlsCertificate.false", GatewayId: Attachment, GatewayPoolId: Pool)
    };

    internal static GatewayPatchAuthenticationInput Selected(string variant) =>
        GatewayPatchEffects.Select(variant, new(GatewayAuthenticationMethod.Kubernetes,
            AllowedAccountIds: "222222222222", AllowedPrincipalArns: "arn:selected",
            AllowedProjects: "selected-project", AllowedServiceAccounts: "selected-account", AllowedZones: "selected-zone",
            AllowedNames: "selected-workload", AllowedNamespaces: "selected-namespace",
            CaCertificate: variant == "Kubernetes.kubernetesHost.value" ? "CA-two" :
                variant == "Kubernetes.caCertificate.value" ? "CA-one-selected" : "CA-one",
            KubernetesHost: variant == "Kubernetes.kubernetesHost.value" ? "https://cluster-two.invalid" : "https://cluster-one.invalid",
            TokenReviewerJwt: variant == "Kubernetes.kubernetesHost.value" ? "reviewer-two" :
                variant == "Kubernetes.tokenReviewerJwt.value" ? "reviewer-one-selected" : "reviewer-one",
            VerifyTlsCertificate: variant == "Kubernetes.caCertificate.empty" ? false : null,
            GatewayId: variant == "gatewayId.value" ? SelectedAttachment : Attachment,
            GatewayPoolId: variant == "gatewayPoolId.value" ? SelectedPool : Pool));

    internal NativeEnvironment Environment(string variant, GatewayPatchAuthenticationInput? baseline = null,
        GatewayPatchAuthenticationInput? selected = null)
    {
        var input = new JsonObject
        {
            ["organizationId"] = Organization,
            ["administrativeIdentityId"] = Identity,
            ["observerIdentityId"] = "00000000-0000-0000-0000-000000000014",
            ["gatewayPatchWitness"] = JsonSerializer.SerializeToNode(new GatewayPatchWitnessInput(
                "controlled-gateway", "controlled-fixture", Guid.NewGuid().ToString("D"), 15,
                baseline ?? Baseline(variant), selected ?? Selected(variant)), InfisicalGatewayPatchEffectTests.Options)
        };
        var environment = NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup-token",
            administrative = "administrative-token",
            observer = "observer-token",
            runtime = "runtime-token",
            denied = "denied-token",
            families = new Dictionary<string, object>
            {
                ["C08-IM-GatewayAdministration"] = new { scopes = new Dictionary<string, object> { ["local"] = input } }
            }
        }, InfisicalGatewayPatchEffectTests.Options));
        Client = environment.CreateManagementClient();
        return environment;
    }

    internal JsonObject? Storage(string id) => gateways.GetValueOrDefault(id)?.DeepClone().AsObject();
    internal void RegisterRoot(GatewayPatchRootAttempt root, GatewayPatchAuthenticationInput baseline)
    {
        if (!owned.Add(root.Id)) throw new NativeCaseFailureException("observer-unavailable");
        if (baseline.Method == GatewayAuthenticationMethod.Identity)
        {
            string id = Guid.NewGuid().ToString("D");
            gateways.Add(id, Metadata(id, root.OriginalName, new()
            {
                ["method"] = "identity",
                ["config"] = new JsonObject { ["identityId"] = Identity, ["identityName"] = "owned-identity" }
            }));
            ownedIdentities.Add(root.Id, id);
        }
    }
    internal void RemoveRoot(string rootId, bool settled)
    {
        // Only the response-only Identity baseline is source-created. This also
        // recovers a lost Open before the SDK owner can register its cleanup.
        if (ownedIdentities.Remove(rootId, out string? id) && settled) gateways.Remove(id);
        owned.Remove(rootId);
    }
    internal void Erase()
    {
        foreach (var item in Requests) { item.Before?.Clear(); item.After?.Clear(); }
        foreach (var copy in privateCopies) copy.Dispose();
    }
    internal bool DestinationValid(JsonObject auth)
    {
        if (auth["method"]!.GetValue<string>() != "kubernetes") return true;
        var config = auth["config"]!.AsObject();
        if (Text(config, "gatewayId") is { } gateway && gateway != Attachment && gateway != SelectedAttachment ||
            Text(config, "gatewayPoolId") is { } pool && pool != Pool && pool != SelectedPool) return false;
        string host = Text(config, "kubernetesHost") ?? "";
        if (!destinations.TryGetValue(host, out var destination)) return false;
        if (config["verifyTlsCertificate"]!.GetValue<bool>() && Text(config, "caCertificate") != destination.Ca &&
            Text(config, "caCertificate") != destination.Ca + "-selected") return false;
        string? reviewer = Text(config, "tokenReviewerJwt");
        return reviewer is null or "" || reviewer == destination.Reviewer || reviewer == destination.Reviewer + "-selected";
    }
    internal AuthenticationEvent Authenticate(string id, bool denied, JsonObject expected)
    {
        var stored = gateways[id]["authMethod"]!.AsObject();
        var config = stored["config"]!.AsObject();
        string method = stored["method"]!.GetValue<string>();
        bool review = method != "kubernetes" || DestinationValid(stored) &&
            Text(config, "tokenReviewerJwt") is { Length: > 0 } reviewer &&
            (reviewer == destinations[Text(config, "kubernetesHost")!].Reviewer ||
                reviewer == destinations[Text(config, "kubernetesHost")!].Reviewer + "-selected");
        var claims = expected["config"]!.AsObject();
        bool Permits(string field)
        {
            string list = Text(config, field) ?? "";
            string claim = (Text(claims, field) ?? "").Split(',')[0].Trim();
            return list.Length == 0 || list.Split(',').Select(s => s.Trim()).Contains(claim);
        }
        bool credentials = method switch
        {
            "aws" => Permits("allowedAccountIds") && Permits("allowedPrincipalArns"),
            "gcp" => Permits("allowedProjects") && Permits("allowedServiceAccounts") && Permits("allowedZones"),
            "kubernetes" => Permits("allowedNames") && Permits("allowedNamespaces") &&
                Text(config, "allowedAudience") == Text(claims, "allowedAudience"),
            "identity" => Text(config, "identityId") == Identity,
            "token" => true,
            _ => false
        };
        bool allowed = !denied && credentials && review;
        if (Fault == "wrong-runtime") allowed = !allowed;
        if (Fault == "denied-accepted" && denied) allowed = true;
        var result = new AuthenticationEvent(Tick(), id, Guid.NewGuid().ToString("D"), denied, allowed, review, method);
        Authentications.Add(result);
        return result;
    }

    // Independent service application: omission is resolved from stored native
    // configuration, not from the source's expected profile.
    private JsonObject ApplyAuthentication(JsonObject input, JsonObject? prior)
    {
        string method = Text(input, "method")!;
        var config = new JsonObject();
        bool same = Text(prior, "method") == method;
        JsonObject? old = same ? prior!["config"]!.AsObject() : null;
        if (method is "aws" or "gcp" or "kubernetes")
        {
            config["id"] = Guid.NewGuid().ToString("D");
            config["createdAt"] = Date; config["updatedAt"] = Date;
        }
        if (method == "aws")
            foreach (string field in new[] { "allowedAccountIds", "allowedPrincipalArns" })
                config[field] = input[field]?.DeepClone() ?? JsonValue.Create("");
        if (method == "gcp")
        {
            foreach (string field in new[] { "allowedProjects", "allowedServiceAccounts", "allowedZones" })
                config[field] = input[field]?.DeepClone() ?? JsonValue.Create("");
            config["type"] = input["type"]?.DeepClone() ?? JsonValue.Create("gce");
        }
        if (method == "kubernetes")
        {
            foreach (string field in new[] { "allowedNames", "allowedNamespaces" }) config[field] = input[field]!.DeepClone();
            config["allowedAudience"] = input["allowedAudience"]?.DeepClone() ?? JsonValue.Create("");
            config["tokenReviewMode"] = input["tokenReviewMode"]?.DeepClone() ?? JsonValue.Create("api");
            config["verifyTlsCertificate"] = input["verifyTlsCertificate"]?.DeepClone() ?? JsonValue.Create(true);
            config["gatewayId"] = input["gatewayId"]?.DeepClone();
            config["gatewayPoolId"] = input["gatewayPoolId"]?.DeepClone();
            config["kubernetesHost"] = input["kubernetesHost"]?.DeepClone() ?? old?["kubernetesHost"]?.DeepClone();
            config["caCertificate"] = input["caCertificate"]?.DeepClone() ?? old?["caCertificate"]?.DeepClone() ?? JsonValue.Create("");
            bool destinationSame = old is not null && new[] { "kubernetesHost", "tokenReviewMode", "gatewayId", "gatewayPoolId" }
                .All(field => JsonNode.DeepEquals(config[field], old[field]));
            config["tokenReviewerJwt"] = input["tokenReviewerJwt"]?.DeepClone() ??
                (destinationSame ? old?["tokenReviewerJwt"]?.DeepClone() : null);
            if (Text(config, "tokenReviewerJwt") is { } jwt) privateCopies.Add(SecretMaterial.FromText(jwt));
            if (Text(config, "caCertificate") is { } ca) privateCopies.Add(SecretMaterial.FromText(ca));
        }
        return new() { ["method"] = method, ["config"] = config };
    }
    private static JsonObject Metadata(string id, string name, JsonObject auth) => new()
    {
        ["id"] = id,
        ["name"] = name,
        ["createdAt"] = Date,
        ["updatedAt"] = Date,
        ["canRevoke"] = true,
        ["heartbeat"] = Date,
        ["identityId"] = Identity,
        ["authMethod"] = auth
    };
    private static JsonObject Public(JsonObject stored)
    {
        var result = stored.DeepClone().AsObject();
        var config = result["authMethod"]!["config"]!.AsObject();
        if (config.ContainsKey("tokenReviewerJwt"))
        {
            config["hasTokenReviewerJwt"] = Text(config, "tokenReviewerJwt") is { Length: > 0 };
            config.Remove("tokenReviewerJwt");
        }
        return result;
    }
    private (int, JsonObject) Respond(string method, Uri uri, string actor, JsonObject body)
    {
        string[] path = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (!path.Contains("gateways")) return ProjectResponse(method, path, body);
        if (method == "GET")
        {
            string id = path[^1];
            return gateways.TryGetValue(id, out var stored) ? (200, Public(stored)) : (404, new());
        }
        bool create = method == "POST";
        string gatewayId = create ? Guid.NewGuid().ToString("D") : path[^1];
        var before = gateways.GetValueOrDefault(gatewayId)?.DeepClone().AsObject();
        string requestId = Guid.NewGuid().ToString("D");
        long cursor = Tick();
        bool authApplied = false, nameApplied = false;
        int status = 200;
        if (actor == "denied-token") status = 403;
        else if (!create && before is null) status = 404;
        else
        {
            var current = before?.DeepClone().AsObject() ?? Metadata(gatewayId, Text(body, "name")!, new());
            JsonObject? authentication = body["authMethod"]?.AsObject();
            JsonObject candidate = authentication is null ? current["authMethod"]!.AsObject() :
                ApplyAuthentication(authentication, before?["authMethod"]?.AsObject());
            if (!DestinationValid(candidate)) status = 400;
            else
            {
                if (authentication is not null && (create || Fault != "ignored-auth"))
                { current["authMethod"] = candidate.DeepClone(); authApplied = true; }
                if (Fault == "retained-optionals" && !create && before is not null)
                    current["authMethod"] = before["authMethod"]!.DeepClone();
                if (Fault != "auth-only" || create)
                {
                    if (body["name"] is not null && (create || Fault != "ignored-name"))
                    { current["name"] = body["name"]!.DeepClone(); nameApplied = true; }
                }
                if (Fault == "noncommitted" && !create) { authApplied = false; nameApplied = false; }
                else gateways[gatewayId] = current;
            }
        }
        Requests.Add(new(cursor, requestId, gatewayId, actor, before, Storage(gatewayId),
            authApplied, nameApplied, create || Fault != "late", Fault == "replay" && !create ? 2 : 1, status));
        return (status, status == 200 ? Public(gateways.GetValueOrDefault(gatewayId) ?? before!) : new());
    }

    private (int, JsonObject) ProjectResponse(string method, string[] path, JsonObject body)
    {
        if (path[2] == "projects" && path.Length == 3 && method == "POST")
        {
            string id = Guid.NewGuid().ToString("D");
            var project = new JsonObject
            {
                ["id"] = id,
                ["_id"] = id,
                ["orgId"] = Organization,
                ["name"] = body["projectName"]!.DeepClone(),
                ["slug"] = body["slug"]!.DeepClone(),
                ["type"] = "secret-manager",
                ["hasDeleteProtection"] = false,
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["environments"] = new JsonArray(),
                ["deletedEnvironments"] = new JsonArray(),
                ["description"] = null,
                ["auditLogsRetentionDays"] = 30,
                ["secretSharing"] = false,
                ["autoCapitalization"] = false,
                ["enforceEncryptedSecretManagerSecretMetadata"] = false,
                ["pitVersionLimit"] = 10,
                ["showSnapshotsLegacy"] = false,
                ["secretDetectionIgnoreValues"] = new JsonArray()
            };
            projects.Add(id, project);
            return (200, new() { ["project"] = project.DeepClone() });
        }
        if (path[2] == "identities" || path.Contains("memberships"))
            return (200, new()
            {
                ["identityMembership"] = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString("D"),
                    ["identityId"] = path[^1],
                    ["projectId"] = Text(body, "projectId") ?? path[3],
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                }
            });
        string? key = path[3] == "slug" ?
            projects.Keys.SingleOrDefault(k => Text(projects[k], "slug") == path[4]) : path[3];
        if (key is null || !projects.TryGetValue(key, out var saved)) return (404, new());
        var result = saved.DeepClone().AsObject();
        result.Remove("_id"); result.Remove("environments"); result.Remove("deletedEnvironments");
        if (method == "DELETE") { projects.Remove(key); return (200, new() { ["project"] = result }); }
        return path[3] == "slug" ? (200, result) : (200, new() { ["project"] = saved.DeepClone() });
    }

    public async ValueTask<SecretOutcome<GatewaySummary>> FindOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource observer, CancellationToken token)
    {
        string? id;
        lock (Gate) id = gateways.Keys.SingleOrDefault(k => Text(gateways[k], "name") == name);
        if (id is null) return SecretOutcome<GatewaySummary>.Failure(SecretStatus.Absent);
        using var request = GatewayAdministrationOperations.Get(organizationId, id);
        var authority = new ManagementAuthority(Client.Authority, observer, organizationId);
        return await Client.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, request.Target),
            cancellationToken: token);
    }
    public async ValueTask<SecretStatus> RemoveOwnedAsync(string organizationId, string name,
        IInfisicalTokenSource setup, CancellationToken token)
    {
        using var identity = (await setup.GetTokenAsync(token)).Value;
        if (identity.Material.Reveal() != "setup-token") return SecretStatus.Denied;
        lock (Gate)
        {
            string? id = gateways.Keys.SingleOrDefault(k => Text(gateways[k], "name") == name);
            if (id is null) return SecretStatus.Absent;
            gateways.Remove(id);
            Tick();
            return SecretStatus.Success;
        }
    }
    public ValueTask<GatewayAgentFacts> AuthenticateAsync(string organizationId, GatewaySummary gateway,
        IInfisicalTokenSource runtime, CancellationToken token)
    {
        lock (Gate)
        {
            var result = Authenticate(gateway.Id, false, gateways[gateway.Id]["authMethod"]!.AsObject());
            return ValueTask.FromResult(new GatewayAgentFacts(gateway.Id, Identity, gateway.Authentication.Method,
                Now, result.Accepted ? 1 : 0));
        }
    }
    public ValueTask<GatewayAgentFacts> EnrollAsync(string organizationId, GatewaySummary gateway,
        SecretMaterial enrollmentToken, IInfisicalTokenSource runtime, CancellationToken token) =>
        throw new NativeCaseFailureException("observer-unavailable");
    public ValueTask<GatewayEnrollmentFacts> ObserveEnrollmentAsync(string gatewayId, CancellationToken token) =>
        throw new NativeCaseFailureException("observer-unavailable");
    // The existing Gateway injection slot carries the private PATCH source for
    // independent Red. Parent can route it without changing the tests or SDK.
    public ValueTask<GatewayPatchBinding> OpenAsync(GatewayPatchRootAttempt root, GatewayPatchAuthenticationInput baseline,
        GatewayPatchAuthenticationInput selected, CancellationToken token) =>
        patchObserver.OpenAsync(root, baseline, selected, token);
    public ValueTask<GatewayPatchArm> ArmAsync(GatewayPatchBinding binding, string attemptId, string operation,
        string variant, string boundary, string? id, CancellationToken token) =>
        patchObserver.ArmAsync(binding, attemptId, operation, variant, boundary, id, token);
    public ValueTask<GatewayPatchFence> CompleteAsync(GatewayPatchArm arm, DispatchEvidence receipt, CancellationToken token) =>
        patchObserver.CompleteAsync(arm, receipt, token);
    public ValueTask<GatewayPatchObservation> ObserveAsync(GatewayPatchBinding binding, GatewayPatchFence fence, CancellationToken token) =>
        patchObserver.ObserveAsync(binding, fence, token);
    public ValueTask<GatewayPatchCleanup> CloseAsync(GatewayPatchRootAttempt root, CancellationToken token) =>
        patchObserver.CloseAsync(root, token);
    internal static string? Text(JsonObject? value, string field) => value?[field]?.GetValue<string>();

    private async Task AcceptAsync()
    {
        try
        {
            while (!stop.IsCancellationRequested) connections.Add(HandleAsync(await listener.AcceptTcpClientAsync(stop.Token)));
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        catch (SocketException) when (stop.IsCancellationRequested) { }
    }
    private async Task HandleAsync(TcpClient connection)
    {
        using (connection)
        {
            try
            {
                var stream = connection.GetStream();
                var header = new List<byte>();
                byte[] one = new byte[1];
                while (header.Count < 65536)
                {
                    if (await stream.ReadAsync(one, stop.Token) == 0) return;
                    header.Add(one[0]);
                    if (header.Count >= 4 && header[^4] == 13 && header[^3] == 10 && header[^2] == 13 && header[^1] == 10) break;
                }
                string[] lines = Encoding.ASCII.GetString(header.ToArray()).Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
                string[] first = lines[0].Split(' ');
                var headers = lines.Skip(1).Select(line => line.Split(':', 2)).ToDictionary(
                    p => p[0], p => p[1].Trim(), StringComparer.OrdinalIgnoreCase);
                int length = headers.TryGetValue("Content-Length", out var size) ? int.Parse(size, CultureInfo.InvariantCulture) : 0;
                byte[] bytes = new byte[length];
                JsonObject body;
                try { await stream.ReadExactlyAsync(bytes, stop.Token); body = length == 0 ? new() : JsonNode.Parse(bytes)!.AsObject(); }
                finally { Array.Clear(bytes); }
                (int Status, JsonObject Body) reply;
                lock (Gate) reply = Respond(first[0], new(Origin, first[1]),
                    headers["Authorization"].Replace("Bearer ", "", StringComparison.Ordinal), body);
                byte[] response = Encoding.UTF8.GetBytes(reply.Body.ToJsonString());
                try
                {
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {reply.Status} Response\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), stop.Token);
                    await stream.WriteAsync(response, stop.Token);
                }
                finally { Array.Clear(response); body.Clear(); reply.Body.Clear(); }
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }
    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop();
        await accepting; await Task.WhenAll(connections);
        Erase();
        stop.Dispose();
    }
    internal sealed record RequestEvent(long Sequence, string Id, string GatewayId, string Actor,
        JsonObject? Before, JsonObject? After, bool AuthApplied, bool NameApplied, bool Settled, int Count, int Status);
    internal sealed record AuthenticationEvent(long Sequence, string GatewayId, string Challenge,
        bool Denied, bool Accepted, bool TokenReview, string Method);
}
