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

// The service owns storage, reference authority, and backend delivery journals.
// Source Open/Arm cannot save a service or manufacture a delivery.
internal sealed class InfisicalProxyPatchEffectFixture : IAsyncDisposable, IProxyBackendObserver
{
    internal const string OrganizationId = "00000000-0000-0000-0000-000000000001";
    internal const string ProjectId = "00000000-0000-0000-0000-000000000010";
    internal const string Date = "2040-01-01T00:00:00.000Z";
    internal static readonly string[] OptionalFields =
    [
        "dynamicSecretField", "dynamicSecretName", "headerName", "headerPrefix",
        "headerPurpose", "placeholderKey", "placeholderValue", "secretKey", "substitutionSurfaces"
    ];
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource stop = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accepting;
    private readonly Dictionary<string, JsonObject> projects = [];
    private readonly Dictionary<string, JsonObject> services = [];
    private readonly Dictionary<string, Reference> references = [];
    private readonly Dictionary<string, string[]> ownedReferences = [];
    private readonly List<SecretMaterial> copies = [];
    private readonly string borrowed = "borrowed-root-and-authority";
    internal object Gate { get; } = new();
    internal string Mode { get; }
    internal Uri Origin { get; }
    internal InfisicalProxyPatchEffectSource Source { get; }
    internal List<PatchEvent> Patches { get; } = [];
    internal List<CommitEvent> Commits { get; } = [];
    private readonly HashSet<string> pendingActions = [];
    internal List<ReferenceEvent> Validations { get; } = [];
    internal List<DeliveryEvent> Deliveries { get; } = [];
    internal long Sequence { get; private set; }
    internal DateTimeOffset Now => DateTimeOffset.Parse(Date, CultureInfo.InvariantCulture).AddTicks(Sequence);
    internal int ResidualCount => services.Count + projects.Count + references.Count + ownedReferences.Count;
    internal int ServiceCount => services.Count;
    internal int ReferenceCount => references.Count;
    internal bool BorrowedStatePreserved => borrowed == "borrowed-root-and-authority" && Mode != "borrowed-damage";
    internal bool PrivateCopiesDestroyed => copies.All(c =>
    {
        try { c.Reveal(); return false; }
        catch (ObjectDisposedException) { return true; }
    });
    internal int PendingActions => pendingActions.Count;
    internal long Tick() => ++Sequence;

    internal InfisicalProxyPatchEffectFixture(string mode = "good")
    {
        Mode = mode;
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        if (mode == "cleanup-pending") pendingActions.Add("cleanup");
        accepting = AcceptAsync();
    }

    internal GovernanceObservers Observers
    {
        get
        {
            return new GovernanceObservers { Proxy = this, ProxyPatch = Source.CreateObserver() };
        }
    }

    internal JsonObject Input() => new()
    {
        ["organizationId"] = OrganizationId,
        ["administrativeIdentityId"] = "00000000-0000-0000-0000-000000000002",
        ["observerIdentityId"] = "00000000-0000-0000-0000-000000000003",
        ["runtimeIdentityId"] = "00000000-0000-0000-0000-000000000004",
        ["proxyPatchWitness"] = JsonSerializer.SerializeToNode(new ProxyPatchWitnessInput(
            "controlled-proxy", "controlled-fixture", Guid.NewGuid().ToString("N"), 15),
            InfisicalProxyPatchEffectTests.Options)
    };

    internal NativeEnvironment Environment()
    {
        var family = new JsonObject { ["scopes"] = new JsonObject { ["local"] = Input() } };
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup-token",
            administrative = "administrative-token",
            observer = "observer-token",
            runtime = "runtime-token",
            denied = "denied-token",
            families = new Dictionary<string, JsonObject> { ["C08-IM-ProxiedServiceAdministration"] = family }
        }, InfisicalProxyPatchEffectTests.Options));
    }

    public async ValueTask<ProxyCredentialFixture> PrepareAsync(string organizationId, string projectId,
        string environment, string ownedName, IInfisicalTokenSource setup, CancellationToken token)
    {
        using var identity = (await setup.GetTokenAsync(token)).Value;
        if (identity.Material.Reveal() != "setup-token") throw new NativeCaseFailureException("missing-input");
        lock (Gate)
        {
            string key = ownedName + "-static", dynamic = ownedName + "-dynamic";
            string value = "private-" + Guid.NewGuid().ToString("N");
            references.Add(key, new(value, false, true, true, "password"));
            references.Add(dynamic, new(value, true, true, true, "password"));
            ownedReferences.Add(ownedName, [key, dynamic]);
            SecretMaterial material = SecretMaterial.FromText(value);
            copies.Add(material);
            return new(key, dynamic, "password", ownedName.EndsWith("-selected", StringComparison.Ordinal) ?
                "selected.invalid" : "baseline.invalid", material);
        }
    }

    public async ValueTask<SecretStatus> RemoveFixtureAsync(string projectId, string ownedName,
        IInfisicalTokenSource setup, CancellationToken token)
    {
        using var identity = (await setup.GetTokenAsync(token)).Value;
        if (identity.Material.Reveal() != "setup-token") return SecretStatus.Denied;
        lock (Gate)
        {
            if (!ownedReferences.Remove(ownedName, out var names)) return SecretStatus.Absent;
            foreach (string name in names) references.Remove(name);
            return SecretStatus.Success;
        }
    }

    public async ValueTask<ProxyBackendFacts> SendThroughAsync(string serviceId, string challenge,
        ProxiedServiceCredentialRole role, ProxiedServiceSubstitutionSurface surface,
        IInfisicalTokenSource selectedIdentity, CancellationToken token)
    {
        using var identity = (await selectedIdentity.GetTokenAsync(token)).Value;
        string selected = identity.Material.Reveal();
        lock (Gate)
        {
            bool exists = services.TryGetValue(serviceId, out var service);
            bool allowed = selected == "runtime-token" && exists && service!["isEnabled"]!.GetValue<bool>();
            bool updated = Patches.Any(p => p.Before.Count > 0);
            if (Mode == "denied-delivered" && updated && selected == "denied-token") allowed = exists;
            string requestedRole = role == ProxiedServiceCredentialRole.HeaderRewrite ? "header-rewrite" : "credential-substitution";
            string requestedSurface = surface.ToString().ToLowerInvariant();
            JsonObject? row = exists ? service!["credentials"]!.AsArray().Cast<JsonObject>().FirstOrDefault(r =>
                Text(r, "role") == requestedRole &&
                (r["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header") == requestedSurface) : null;
            string? key = Text(row, "secretKey") ?? Text(row, "dynamicSecretName");
            bool valid = key is not null && references.TryGetValue(key, out var resolved) && resolved.Allowed;
            string? actual = allowed && valid ? references[key!].Value : null;
            if (actual is not null) actual = (Text(row, "headerPrefix") ?? "") + actual;
            if (Mode == "wrong-actual-substitution" && updated && actual is not null) actual = "wrong-private-value";
            int count = actual is null ? 0 : 1;
            var status = actual is not null ? SecretStatus.Success : exists ? SecretStatus.Denied : SecretStatus.Absent;
            string actualRole = Text(row, "role") ?? "header-rewrite";
            string actualSurface = row?["substitutionSurfaces"]?[0]?.GetValue<string>() ?? "header";
            SecretMaterial? material = actual is null ? null : SecretMaterial.FromText(actual);
            if (material is not null) copies.Add(material);
            Deliveries.Add(new(Tick(), serviceId, challenge, selected, count, actual, actualRole, actualSurface));
            return new(serviceId, challenge, status, count, material,
                actualRole == "header-rewrite" ? ProxiedServiceCredentialRole.HeaderRewrite :
                    ProxiedServiceCredentialRole.CredentialSubstitution,
                Enum.Parse<ProxiedServiceSubstitutionSurface>(actualSurface, true), Text(row, "headerName"));
        }
    }

    internal JsonObject? Storage(string id) => services.GetValueOrDefault(id)?.DeepClone().AsObject();
    internal string[] Keys(string ownedName) => ownedReferences[ownedName];
    internal string? ReferenceValue(string? key) => key is not null &&
        references.GetValueOrDefault(key) is { Allowed: true } reference ? reference.Value : null;
    internal void RevokeReferences()
    {
        foreach (var key in references.Keys.ToArray()) references[key] = references[key] with { Allowed = false };
    }

    internal void DestroyJournalCopies()
    {
        foreach (var patch in Patches) { patch.Before.Clear(); patch.Candidate.Clear(); }
        for (int i = 0; i < Deliveries.Count; i++) Deliveries[i] = Deliveries[i] with { Value = null };
    }

    private bool Validate(JsonArray rows, string serviceId, string actor, string action)
    {
        bool valid = true;
        foreach (JsonObject row in rows.Cast<JsonObject>())
        {
            string?[] keys = [Text(row, "secretKey"), Text(row, "dynamicSecretName")];
            foreach (string? key in keys.Where(k => k is not null).DefaultIfEmpty())
            {
                Reference? reference = key is null ? null : references.GetValueOrDefault(key);
                bool accepted = key is null || reference is not null && reference.Allowed &&
                    (!reference.Dynamic || reference.Brokerable && reference.Entitled &&
                        (Text(row, "dynamicSecretField") is null || Text(row, "dynamicSecretField") == reference.Field));
                if (Mode == "new-refs-not-validated" && action == "Edit") continue;
                Validations.Add(new(Tick(), serviceId, key, actor, action,
                    key is null ? "None" : reference?.Dynamic == true ? "Lease" : "ReadValue", accepted,
                    reference?.Brokerable ?? false, reference?.Entitled ?? false));
                valid &= accepted;
            }
        }
        return valid;
    }

    private (int Status, JsonObject Body) Respond(string method, Uri uri, string actor, JsonObject body)
    {
        string[] p = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (p.Length < 3) return (404, new());
        if (p[2] != "proxied-services") return ProjectResponse(method, p, body, actor);
        string? id = p.Length > 3 ? p[3] : null;
        if (method == "POST")
        {
            if (actor == "denied-token") return (403, new());
            id = Guid.NewGuid().ToString();
            var rows = Rows(body["credentials"]!.AsArray(), id);
            if (!Validate(rows, id, actor, "Create")) return (403, new());
            services.Add(id, new()
            {
                ["id"] = id,
                ["folderId"] = Guid.NewGuid().ToString(),
                ["name"] = body["name"]!.DeepClone(),
                ["hostPattern"] = body["hostPattern"]!.DeepClone(),
                ["isEnabled"] = body["isEnabled"]?.DeepClone() ?? JsonValue.Create(true),
                ["createdAt"] = Date,
                ["updatedAt"] = Date,
                ["canProxy"] = true,
                ["credentials"] = rows
            });
            string createEvent = Guid.NewGuid().ToString("N");
            Commits.Add(new(Tick(), createEvent, id));
            Patches.Add(new(Tick(), createEvent, id, actor, new(),
                services[id].DeepClone().AsObject(), true, true, true, true, true, 1));
            return (200, ServiceReply(services[id]));
        }
        if (method == "PATCH")
        {
            if (id is null || !services.TryGetValue(id, out var saved)) return (404, new());
            JsonObject before = saved.DeepClone().AsObject();
            JsonObject candidate = saved.DeepClone().AsObject();
            foreach (string field in new[] { "name", "hostPattern", "isEnabled" })
                if (body.ContainsKey(field)) candidate[field] = body[field]?.DeepClone();
            if (body["credentials"] is JsonArray supplied)
            {
                var rows = Rows(supplied, id);
                if (Mode == "ignored-selected-row") rows = before["credentials"]!.DeepClone().AsArray();
                if (Mode == "retained-removed-row") rows.Add(before["credentials"]![1]!.DeepClone());
                if (Mode == "optional-retained-ignored")
                    foreach (string field in OptionalFields)
                        if (!supplied[0]!.AsObject().ContainsKey(field)) rows[0]![field] = before["credentials"]![0]![field]?.DeepClone();
                candidate["credentials"] = rows;
            }
            bool authority = actor != "denied-token";
            bool validated = Validate(candidate["credentials"]!.AsArray(), id, actor, "Edit");
            bool applied = authority && validated && Mode != "noncommitted";
            string eventId = Guid.NewGuid().ToString("N");
            if (applied)
            {
                services[id] = candidate;
                Commits.Add(new(Tick(), eventId, id));
                if (Mode == "replay")
                {
                    services[id] = candidate.DeepClone().AsObject();
                    Commits.Add(new(Tick(), eventId, id));
                }
            }
            if (Mode == "late") pendingActions.Add(eventId);
            Patches.Add(new(Tick(), eventId, id, actor, before,
                candidate.DeepClone().AsObject(), body.ContainsKey("credentials"), applied, validated,
                !pendingActions.Contains(eventId), Commits.Count(c => c.RequestEventId == eventId) <= 1, 1));
            return (!authority || !validated ? 403 : 200, ServiceReply(candidate));
        }
        if (actor == "denied-token") return (403, new());
        if (p.Length == 3)
        {
            string projectId = Query(uri)["projectId"];
            return (200, new()
            {
                ["projectSlug"] = projects[projectId]["slug"]!.DeepClone(),
                ["services"] = new JsonArray(services.Values.Select(s => s.DeepClone()).ToArray())
            });
        }
        if (id == "slug") id = services.Keys.SingleOrDefault(k => Text(services[k], "name") == p[4]);
        if (id is null || !services.TryGetValue(id, out var service)) return (404, new());
        JsonObject result = service.DeepClone().AsObject();
        if (method == "DELETE") { services.Remove(id); result.Remove("credentials"); Tick(); }
        return (200, ServiceReply(result));
    }

    private (int, JsonObject) ProjectResponse(string method, string[] p, JsonObject body, string actor)
    {
        if (actor == "denied-token") return (403, new());
        if (p[2] == "projects" && p.Length == 3 && method == "POST")
        {
            string id = Guid.NewGuid().ToString();
            var project = new JsonObject
            {
                ["id"] = id,
                ["_id"] = id,
                ["orgId"] = OrganizationId,
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
        if (p[2] == "identities" || p.Contains("memberships"))
        {
            string id = p[2] == "identities" ? Text(body, "projectId")! : p[3];
            return (200, new()
            {
                ["identityMembership"] = new JsonObject
                {
                    ["id"] = Guid.NewGuid().ToString(),
                    ["identityId"] = p[^1],
                    ["projectId"] = id,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date
                }
            });
        }
        if (p[2] != "projects") return (404, new());
        string? key = p[3] == "slug" ? projects.Keys.SingleOrDefault(k => Text(projects[k], "slug") == p[4]) : p[3];
        if (key is null || !projects.TryGetValue(key, out var saved)) return (404, new());
        if (p.Length > 4 && p[4] == "environments")
        {
            string id = Guid.NewGuid().ToString();
            return (200, new()
            {
                ["projectId"] = key,
                ["environment"] = new JsonObject
                {
                    ["id"] = id,
                    ["projectId"] = key,
                    ["name"] = body["name"]!.DeepClone(),
                    ["slug"] = body["slug"]!.DeepClone(),
                    ["position"] = 1,
                    ["createdAt"] = Date,
                    ["updatedAt"] = Date,
                    ["softDeletedAt"] = null,
                    ["deleteAfter"] = null
                }
            });
        }
        var result = saved.DeepClone().AsObject();
        if (method == "DELETE" || p[3] == "slug")
        {
            result.Remove("_id"); result.Remove("environments"); result.Remove("deletedEnvironments");
            if (method == "DELETE")
            {
                projects.Remove(key);
                return (200, new() { ["project"] = result });
            }
            return (200, result);
        }
        return (200, new() { ["project"] = result });
    }

    private static JsonArray Rows(JsonArray supplied, string id) => new(supplied.Select(value =>
    {
        var row = value!.DeepClone().AsObject();
        foreach (string field in OptionalFields) if (!row.ContainsKey(field)) row[field] = null;
        row["id"] = Guid.NewGuid().ToString(); row["serviceId"] = id; row["callerCanLease"] = true;
        return (JsonNode)row;
    }).ToArray());
    private static JsonObject ServiceReply(JsonObject service) => new() { ["service"] = service.DeepClone() };
    internal static string? Text(JsonObject? body, string key) => body?[key]?.GetValue<string>();
    private static Dictionary<string, string> Query(Uri uri) => uri.Query.TrimStart('?').Split('&')
        .Select(q => q.Split('=', 2)).ToDictionary(q => Uri.UnescapeDataString(q[0]), q => Uri.UnescapeDataString(q[1]));

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
                var headers = lines.Skip(1).Select(line => line.Split(':', 2))
                    .ToDictionary(parts => parts[0], parts => parts[1].Trim(), StringComparer.OrdinalIgnoreCase);
                int length = headers.TryGetValue("Content-Length", out var size) ? int.Parse(size, CultureInfo.InvariantCulture) : 0;
                byte[] bytes = new byte[length];
                await stream.ReadExactlyAsync(bytes, stop.Token);
                var body = length == 0 ? new JsonObject() : JsonNode.Parse(bytes)!.AsObject();
                Array.Clear(bytes);
                (int Status, JsonObject Body) reply;
                lock (Gate) reply = Respond(first[0], new(Origin, first[1]),
                    headers["Authorization"].Replace("Bearer ", "", StringComparison.Ordinal), body);
                byte[] response = Encoding.UTF8.GetBytes(reply.Body.ToJsonString());
                byte[] responseHeader = Encoding.ASCII.GetBytes($"HTTP/1.1 {reply.Status} Response\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(responseHeader, stop.Token);
                await stream.WriteAsync(response, stop.Token);
                Array.Clear(response);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
    }

    public async ValueTask DisposeAsync()
    {
        stop.Cancel(); listener.Stop();
        await accepting; await Task.WhenAll(connections);
        foreach (var copy in copies) copy.Dispose();
        stop.Dispose();
    }

    internal sealed record PatchEvent(long Sequence, string EventId, string ServiceId, string Actor,
        JsonObject Before, JsonObject Candidate, bool SuppliedArray, bool Applied, bool Validated,
        bool Settled, bool NoReplay, int Requests);
    internal sealed record CommitEvent(long Sequence, string RequestEventId, string ServiceId);
    internal sealed record ReferenceEvent(long Sequence, string ServiceId, string? Reference, string Actor,
        string Action, string Privilege, bool Accepted, bool Brokerable, bool Entitled);
    internal sealed record DeliveryEvent(long Sequence, string ServiceId, string Challenge, string Actor,
        int Requests, string? Value, string Role, string Surface);
    private sealed record Reference(string Value, bool Dynamic, bool Allowed, bool Brokerable, string Field,
        bool Entitled = true);
}
