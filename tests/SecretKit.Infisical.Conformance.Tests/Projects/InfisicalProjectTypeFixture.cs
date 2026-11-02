using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled provider: real SDK HTTP, independent typed provider storage and
// policy, no effect predicate in request handling or issuance.
internal sealed class InfisicalProjectTypeFixture : IAsyncDisposable
{
    internal const string Org = "10000000-0000-0000-0000-000000000001";
    internal const string Date = "2040-01-01T00:00:00Z";
    internal static ProjectTypeAuthorities Authorities { get; } =
        new("setup-principal", "runtime-principal", "denied-principal", "admin-principal", "observer-principal");
    internal object Gate { get; } = new();
    internal Uri Origin { get; }
    internal string Fault { get; }
    internal InfisicalProjectTypeFixtureSource Source { get; }
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<string, ProjectTypeState> projects = [];
    private readonly Dictionary<string, string> roles = [];
    private readonly Dictionary<string, ProjectTypeRoot> owners = [];
    private readonly Dictionary<string, List<ProjectTypeResource>> issuance = [];
    private readonly HashSet<(string, string)> creationFences = [];
    private readonly HashSet<string> dispatchFences = [];
    private readonly Dictionary<string, string> windows = [];
    private readonly HashSet<string> armed = [];
    private readonly Dictionary<string, int> used = [];
    private readonly ProjectTypeBorrowed[] borrowedBaseline;
    internal List<(string Root, ProjectTypeResource Resource)> IssuanceJournal { get; } = [];
    internal List<(string Root, ProjectTypeOriginal Request)> RequestJournal { get; } = [];
    internal List<(string Root, string Phase, ProjectTypeAccess Access)> AccessJournal { get; } = [];
    internal List<(string Root, string Phase, ProjectTypeState[] Rows)> StorageJournal { get; } = [];
    internal List<(string Root, ProjectTypeResource Resource)> CleanupJournal { get; } = [];
    internal List<string> LateRejections { get; } = [];

    internal InfisicalProjectTypeFixture(string fault = "")
    {
        Fault = fault;
        foreach (string type in new[] { "secret-manager", "kms" })
        {
            string id = Guid.NewGuid().ToString(), role = Guid.NewGuid().ToString();
            projects.Add(id, Row(id, role, "borrowed-" + type, type));
            roles.Add(role, id);
        }
        borrowedBaseline = Borrowed();
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal NativeEnvironment Environment(object families) => NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
    {
        origin = Origin.AbsoluteUri,
        allowLoopbackDevelopmentHttp = true,
        setup = "setup",
        runtime = "runtime",
        denied = "denied",
        administrative = "administrative",
        observer = "observer",
        families
    }, ProjectTypeContract.Options));
    private static ProjectTypeState Row(string id, string role, string name, string type) =>
        new(Org, id, name, name, type, "description-" + name, Date, Date, id, type, 2, false,
            new(null, null, null, null, 10, false, true, false, true, true, false, ["metadata-only"], 0, 0),
            [new(role, "Read inventory", "inventory-reader", "Metadata only", Date, Date, 1)]);
    internal int Remaining { get { lock (Gate) return projects.Count + roles.Count - borrowedBaseline.Length; } }
    internal ProjectTypeBorrowed[] Borrowed() =>
        projects.Values.Where(p => !issuance.Values.Any(items => items.Any(r => r.Kind == "project" && r.Id == p.Id)))
            .SelectMany(p => new[] { new ProjectTypeBorrowed("project", p.Id,
                JsonSerializer.Serialize(p, ProjectTypeContract.Options)) }.Concat(p.Roles.Select(r =>
                    new ProjectTypeBorrowed("role", r.Id, roles.GetValueOrDefault(r.Id) ?? "missing")))).ToArray();
    internal bool BorrowedPreserved => ProjectTypeContract.BorrowedEqual(Borrowed(), borrowedBaseline);
    internal void Reserve(ProjectTypeRoot root)
    {
        if (Fault == "collision" || owners.ContainsKey(root.Id) || owners.Values.Any(r => r.Nonce == root.Nonce) ||
            creationFences.Contains((root.Id, root.Nonce))) throw new NativeCaseFailureException("observer-unavailable");
        owners.Add(root.Id, root); issuance.Add(root.Id, []);
    }
    private void Enroll(ProjectTypeRoot root, string kind, string id)
    {
        if (!owners.TryGetValue(root.Id, out var owner) || owner != root ||
            creationFences.Contains((root.Id, root.Nonce)))
        { LateRejections.Add(root.Id); throw new NativeCaseFailureException("observer-unavailable"); }
        var resource = new ProjectTypeResource(root.Id, root.Nonce, kind, id);
        issuance[root.Id].Add(resource);
        IssuanceJournal.Add((root.Id, resource)); // Same lock, BEFORE storage creation.
    }
    internal ProjectTypeState[] Issue(ProjectTypeRoot root)
    {
        var result = new List<ProjectTypeState>();
        // Literal provider vocabulary is deliberately separate from effect query mapping.
        foreach (string type in new[] { "secret-manager", "cert-manager", "kms", "secret-scanning", "pam", "agent-vault" })
            for (int slot = 0; slot < 2; slot++)
            {
                string id = Guid.NewGuid().ToString(), role = Guid.NewGuid().ToString();
                var row = Row(id, role, "owned-" + Guid.NewGuid().ToString("N"), type);
                Enroll(root, "project", id);
                var stored = Fault == "storage-wrong-type" && result.Count == 0 ? row with { Type = "kms" } : row;
                projects.Add(id, stored with { Roles = [] });
                if (Fault == "partial-open" && result.Count == 0)
                    throw new NativeCaseFailureException("observer-unavailable");
                Enroll(root, "role", role); roles.Add(role, id);
                projects[id] = stored;
                result.Add(row);
            }
        return result.ToArray();
    }
    internal ProjectTypeResource[] Inventory(ProjectTypeRoot root) =>
        owners.TryGetValue(root.Id, out var owner) && owner == root ? issuance[root.Id].ToArray() : [];
    internal ProjectTypeState[] State(ProjectTypeRoot root, string phase)
    {
        var result = projects.Values.Where(p => p.OrganizationId == root.OrganizationId).ToArray();
        StorageJournal.Add((root.Id, phase, result));
        return result;
    }
    internal void Begin(ProjectTypeRoot root, string phase) => windows.Add(root.Id, phase);
    internal void End(ProjectTypeRoot root) => windows.Remove(root.Id);
    internal void Arm(ProjectTypeRoot root)
    {
        if (dispatchFences.Contains(root.Id) || !armed.Add(root.Id))
            throw new NativeCaseFailureException("observer-unavailable");
        used.Add(root.Id, 0);
    }
    internal void SealCreation(ProjectTypeRoot root) => creationFences.Add((root.Id, root.Nonce));
    internal void Fence(ProjectTypeRoot root)
    {
        if (owners.TryGetValue(root.Id, out var owner) && owner == root) dispatchFences.Add(root.Id);
    }
    internal ProjectTypeResource[] Close(ProjectTypeRoot root)
    {
        SealCreation(root);
        if (!owners.TryGetValue(root.Id, out var owner) || owner != root) return [];
        Fence(root);
        var all = Inventory(root);
        foreach (var resource in all.Reverse())
        {
            if (Fault == "cleanup-residual" && resource.Kind == "project") continue;
            if (resource.Kind == "project") projects.Remove(resource.Id);
            else roles.Remove(resource.Id);
            CleanupJournal.Add((root.Id, resource));
        }
        windows.Remove(root.Id);
        return all; // Keep original-root tombstones and enrolled IDs for recovery.
    }
    internal ProjectTypeResource[] RemainingInventory(ProjectTypeRoot root) =>
        Inventory(root).Where(r => r.Kind == "project" ? projects.ContainsKey(r.Id) : roles.ContainsKey(r.Id)).ToArray();

    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
                connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            byte[]? response = null;
            try
            {
                var stream = socket.GetStream();
                var headers = new List<byte>();
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                string bearer = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))
                    .Split(' ').Last();
                (int Status, object Payload) result;
                lock (Gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally { if (response is not null) CryptographicOperations.ZeroMemory(response); }
        }
    }
    private (int, object) Handle(string method, Uri uri, string bearer)
    {
        if (method != "GET" || uri.AbsolutePath != "/api/v1/projects") return (404, new { });
        string actor = bearer switch
        {
            "setup" => Authorities.Setup,
            "runtime" => Authorities.Runtime,
            "denied" => Authorities.Denied,
            "administrative" => Authorities.Administrative,
            "observer" => Authorities.Observer,
            _ => "unknown"
        };
        var fields = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(v => v.Split('=', 2)).ToDictionary(v => v[0], v => Uri.UnescapeDataString(v[1]));
        string? type = fields.GetValueOrDefault("type");
        SecretKit.Infisical.Management.ProjectType? kind = type switch
        {
            null => null,
            "secret-manager" => SecretKit.Infisical.Management.ProjectType.SecretManager,
            "cert-manager" => SecretKit.Infisical.Management.ProjectType.CertificateManager,
            "kms" => SecretKit.Infisical.Management.ProjectType.Kms,
            "secret-scanning" => SecretKit.Infisical.Management.ProjectType.SecretScanning,
            "pam" => SecretKit.Infisical.Management.ProjectType.Pam,
            "agent-vault" => SecretKit.Infisical.Management.ProjectType.AgentVault,
            _ => throw new InvalidOperationException("fixture-query")
        };
        bool? includeRoles = fields.TryGetValue("includeRoles", out var roleValue) ? bool.Parse(roleValue) : null;
        var query = new ProjectTypeQuery(kind, includeRoles);
        bool allowed = actor is "setup-principal" or "runtime-principal" or "admin-principal" or "observer-principal" ||
            Fault == "denied-accepted" && actor == Authorities.Denied;
        var window = windows.SingleOrDefault();
        if (window.Key is not null)
            AccessJournal.Add((window.Key, window.Value, new(Guid.NewGuid().ToString(), actor, Org, query, allowed)));
        else
        {
            var owner = owners.Values.LastOrDefault(r => armed.Contains(r.Id));
            if (owner is not null)
            {
                if (dispatchFences.Contains(owner.Id)) { LateRejections.Add(owner.Id); return (409, new { }); }
                var original = new ProjectTypeOriginal(Guid.NewGuid().ToString(), actor, Org, method, uri.AbsolutePath, query);
                RequestJournal.Add((owner.Id, original));
                if (used[owner.Id]++ != 0) return (409, new { });
            }
        }
        if (!allowed) return (403, new { });
        var rows = projects.Values.Where(p => Fault == "ignored-filter" || type is null || p.Type == type).ToList();
        if (Fault is "missing-positive" or "incomplete-list" && rows.Count > 0) rows.RemoveAt(rows.Count - 1);
        if (Fault == "empty-positive") rows.Clear();
        if (Fault == "singleton-positive") rows = rows.Take(1).ToList();
        if (Fault == "duplicate" && rows.Count > 0) rows.Add(rows[0]);
        if (Fault == "borrowed-mutated")
        {
            string id = borrowedBaseline.First(b => b.Kind == "project").Id;
            projects[id] = projects[id] with { Description = "damaged-borrowed-project" };
        }
        return (200, new { projects = rows.Select(p => Wire(p, includeRoles == true || Fault == "ignored-roles-filter")).ToArray() });
    }
    private object Wire(ProjectTypeState p, bool includeRoles)
    {
        var row = new Dictionary<string, object?>
        {
            ["orgId"] = Fault == "wrong-scope" ? "other-organization" : p.OrganizationId,
            ["id"] = p.Id,
            ["name"] = p.Name,
            ["slug"] = p.Slug,
            ["type"] = p.Type,
            ["description"] = p.Description,
            ["createdAt"] = p.CreatedAt,
            ["updatedAt"] = p.UpdatedAt,
            ["_id"] = p.NativeId,
            ["defaultProduct"] = p.DefaultProduct,
            ["version"] = p.Version,
            ["hasDeleteProtection"] = p.DeleteProtection,
            ["environments"] = Array.Empty<object>(),
            ["deletedEnvironments"] = Array.Empty<object>(),
            ["upgradeStatus"] = p.Metadata.UpgradeStatus,
            ["kmsCertificateKeyId"] = p.Metadata.KmsCertificateKeyId,
            ["kmsSecretManagerKeyId"] = p.Metadata.KmsSecretManagerKeyId,
            ["auditLogsRetentionDays"] = p.Metadata.AuditLogsRetentionDays,
            ["pitVersionLimit"] = p.Metadata.PitVersionLimit,
            ["autoCapitalization"] = p.Metadata.AutoCapitalization,
            ["enforceEncryptedSecretManagerSecretMetadata"] = p.Metadata.EncryptedMetadata,
            ["isLegacyAdditionalPrivilegesEnabled"] = p.Metadata.LegacyAdditionalPrivileges,
            ["secretBlindIndexEnabled"] = p.Metadata.SecretBlindIndexEnabled,
            ["secretSharing"] = p.Metadata.SecretSharing,
            ["showSnapshotsLegacy"] = p.Metadata.ShowSnapshotsLegacy,
            ["secretDetectionIgnoreValues"] = p.Metadata.IgnoreValues
        };
        if (Fault == "field-mismatch") row["description"] = "invented-description";
        if (Fault == "missing-field") row.Remove("createdAt");
        if (Fault == "metadata-mismatch") row["secretSharing"] = !p.Metadata.SecretSharing;
        if (Fault == "metadata-omitted") row.Remove("auditLogsRetentionDays");
        if (includeRoles && Fault != "roles-omitted")
            row["roles"] = p.Roles.Select(r => new
            {
                id = r.Id,
                name = r.Name,
                slug = r.Slug,
                projectId = Fault == "roles-wrong-project" ? "other-project" : p.Id,
                description = r.Description,
                createdAt = r.CreatedAt,
                updatedAt = r.UpdatedAt,
                version = r.Version,
                permissions = "unprojected-native-permissions"
            }).ToArray();
        return row;
    }
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); listener.Stop();
        await accept; await Task.WhenAll(connections);
        shutdown.Dispose();
    }
}
