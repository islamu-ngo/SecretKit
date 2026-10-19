using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent controlled HTTP provider. No effect/trial predicate determines
// authorization, creates commits, or populates its issuer/access journals.
internal sealed class InfisicalOrganizationUserFixture : IAsyncDisposable
{
    internal const string Org = "10000000-0000-0000-0000-000000000001";
    internal const string BorrowedUser = "20000000-0000-0000-0000-000000000001";
    private const string BorrowedMember = "30000000-0000-0000-0000-000000000001";
    private const string BorrowedGroup = "40000000-0000-0000-0000-000000000001";
    private const string Date = "2040-01-01T00:00:00Z";
    internal static OrganizationUserAuthorities Authorities { get; } = new(
        "setup-principal", "runtime-principal", "denied-principal", "admin-principal", "observer-principal");
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<string, UserRow> users = [];
    private readonly Dictionary<string, CredentialRow> credentials = [];
    private readonly Dictionary<string, MemberRow> memberships = [];
    private readonly Dictionary<string, GroupRow> groups = [];
    private readonly Dictionary<string, RoleRow> roles = [];
    private readonly Dictionary<string, OrganizationUserRoot> reservations = [];
    private readonly HashSet<(string Id, string Nonce)> creationFences = [];
    private readonly HashSet<string> dispatchFences = [];
    private readonly Dictionary<string, OrganizationUserIntent> armed = [];
    private readonly Dictionary<string, int> requestsUsed = [];
    private readonly Dictionary<string, string> windows = [];
    private readonly Dictionary<string, List<OrganizationUserResource>> issuance = [];
    internal object Gate { get; } = new();
    internal Uri Origin { get; }
    internal string Fault { get; }
    internal InfisicalOrganizationUserFixtureSource Source { get; }
    internal List<(string Root, string User, string Credential, string Hash)> UserIssuerJournal { get; } = [];
    internal List<Original> RequestJournal { get; } = [];
    internal List<(string Root, string Request, string Membership)> MembershipJournal { get; } = [];
    internal List<(string Root, string Phase, OrganizationUserAccess Access)> AccessJournal { get; } = [];
    internal List<(string Root, OrganizationUserResource Resource)> CleanupJournal { get; } = [];
    internal List<(string Root, string Phase, OrganizationUserState[] Rows)> StorageJournal { get; } = [];
    internal List<string> LateRejections { get; } = [];
    internal TaskCompletionSource ResponseRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Remaining
    {
        get
        {
            lock (Gate) return users.Count - 1 + credentials.Count +
                memberships.Count - 1 + groups.Count - 1 + roles.Count - 1;
        }
    }
    internal sealed record Original(string Id, string Root, string Actor, string Method,
        string[] MembershipIds, string? Role, bool? Active);
    private sealed record UserRow(string Id, string Username);
    private sealed record CredentialRow(string Id, string UserId, byte[] Bytes);
    private sealed record MemberRow(string Id, string UserId, string Role, bool Active);
    private sealed record GroupRow(string Id, string Name);
    private sealed record RoleRow(string Id, string Slug, bool Read);

    internal InfisicalOrganizationUserFixture(string fault = "")
    {
        Fault = fault;
        users.Add(BorrowedUser, new(BorrowedUser, "borrowed-user"));
        memberships.Add(BorrowedMember, new(BorrowedMember, BorrowedUser, "borrowed-role", true));
        groups.Add(BorrowedGroup, new(BorrowedGroup, "borrowed-group"));
        roles.Add("borrowed-role-id", new("borrowed-role-id", "borrowed-role", false));
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
    }, OrganizationUserContract.Options));
    internal OrganizationUserBorrowed[] Borrowed() =>
        [new("user", BorrowedUser, users.GetValueOrDefault(BorrowedUser)?.Username ?? "missing"),
        new("membership", BorrowedMember, memberships.GetValueOrDefault(BorrowedMember) is { } m ?
            $"{m.UserId}/{m.Role}/{m.Active}" : "missing"),
        new("group", BorrowedGroup, groups.GetValueOrDefault(BorrowedGroup)?.Name ?? "missing"),
        new("role", "borrowed-role-id", roles.GetValueOrDefault("borrowed-role-id") is { } role ?
            $"{role.Slug}/{role.Read}" : "missing")];
    internal bool BorrowedPreserved => users.GetValueOrDefault(BorrowedUser)?.Username == "borrowed-user" &&
        memberships.GetValueOrDefault(BorrowedMember) == new MemberRow(BorrowedMember, BorrowedUser, "borrowed-role", true) &&
        groups.GetValueOrDefault(BorrowedGroup)?.Name == "borrowed-group" &&
        roles.GetValueOrDefault("borrowed-role-id") == new RoleRow("borrowed-role-id", "borrowed-role", false);
    internal void Reserve(OrganizationUserRoot root)
    {
        if (Fault == "collision" || reservations.ContainsKey(root.Id) ||
            creationFences.Contains((root.Id, root.Nonce)) ||
            reservations.Values.Any(r => r.Nonce == root.Nonce))
            throw new NativeCaseFailureException("observer-unavailable");
        // The root and enrollment journal exist before the first resource write.
        reservations.Add(root.Id, root);
        issuance.Add(root.Id, []);
    }
    private void Enroll(OrganizationUserRoot root, string kind, string id)
    {
        if (!reservations.TryGetValue(root.Id, out var owned) || owned != root ||
            creationFences.Contains((root.Id, root.Nonce)))
        {
            LateRejections.Add(root.Id);
            throw new NativeCaseFailureException("observer-unavailable");
        }
        // Called under Gate in the same critical section as its resource write.
        // A native implementation needs durable transaction/coordinator semantics.
        issuance[root.Id].Add(new(root.Id, root.Nonce, kind, id));
    }
    internal OrganizationUserIssuance Issue(OrganizationUserRoot root, OrganizationUserStamp stamp, int stopAfter = int.MaxValue)
    {
        string allow = "role-" + Guid.NewGuid().ToString("N"), deny = "role-" + Guid.NewGuid().ToString("N");
        string allowId = Guid.NewGuid().ToString(), denyId = Guid.NewGuid().ToString();
        string canary = Guid.NewGuid().ToString(), name = "canary-" + Guid.NewGuid().ToString("N");
        void Added()
        {
            if (issuance[root.Id].Count == stopAfter) throw new NativeCaseFailureException("observer-unavailable");
        }
        Enroll(root, "role", allowId); roles.Add(allowId, new(allowId, allow, true)); Added();
        Enroll(root, "role", denyId); roles.Add(denyId, new(denyId, deny, false)); Added();
        Enroll(root, "group", canary); groups.Add(canary, new(canary, name)); Added();
        int targets = root.Operation.EndsWith(".DeleteOrganizationMemberships", StringComparison.Ordinal) ? 2 : 1;
        var principals = new List<OrganizationUserPrincipal>();
        try
        {
            for (int slot = 0; slot <= targets; slot++)
            {
                string user = Guid.NewGuid().ToString(), member = Guid.NewGuid().ToString(),
                    credential = Guid.NewGuid().ToString(), username = "fresh-" + Guid.NewGuid().ToString("N");
                Enroll(root, "user", user); users.Add(user, new(user, username)); Added();
                byte[] bytes = Encoding.UTF8.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
                string hash = Convert.ToHexString(SHA256.HashData(bytes));
                Enroll(root, "credential", credential); credentials.Add(hash, new(credential, user, bytes));
                UserIssuerJournal.Add((root.Id, user, credential, hash)); Added();
                bool granted = slot < targets && root.Variant is not ("role.value" or "isActive.omitted");
                bool active = slot == targets || root.Variant != "isActive.true";
                Enroll(root, "membership", member);
                memberships.Add(member, new(member, user, granted ? allow : deny, active)); Added();
                principals.Add(new(slot, user, username, member, credential, hash, bytes.ToArray()));
            }
            return new(stamp, principals.ToArray(), allow, deny, allowId, denyId,
                canary, name, true, true, true, Inventory(root));
        }
        catch { foreach (var p in principals) p.Erase(); throw; }
    }
    internal OrganizationUserResource[] Inventory(OrganizationUserRoot root) =>
        reservations.TryGetValue(root.Id, out var selected) && selected == root ? issuance[root.Id].ToArray() : [];
    internal OrganizationUserState[] State(OrganizationUserRoot root, string phase)
    {
        var ids = Inventory(root).Where(r => r.Kind == "membership").Select(r => r.Id).ToHashSet();
        var rows = memberships.Values.Where(m => ids.Contains(m.Id))
            .Select(m => new OrganizationUserState(m.UserId, m.Id, users[m.UserId].Username,
                m.Role, m.Active, "accepted")).ToArray();
        StorageJournal.Add((root.Id, phase, rows));
        return rows;
    }
    internal void Begin(OrganizationUserRoot root, string phase) => windows.Add(root.Id, phase);
    internal void End(OrganizationUserRoot root) => windows.Remove(root.Id);
    internal void Arm(OrganizationUserRoot root, OrganizationUserIntent intent)
    {
        if (dispatchFences.Contains(root.Id) || armed.ContainsKey(root.Id)) throw new NativeCaseFailureException("observer-unavailable");
        armed.Add(root.Id, intent); requestsUsed.Add(root.Id, 0);
    }
    internal void Fence(OrganizationUserRoot root) => dispatchFences.Add(root.Id);
    internal OrganizationUserResource[] Close(OrganizationUserRoot root)
    {
        creationFences.Add((root.Id, root.Nonce));
        // A conflicting owner is borrowed. Never follow returned or guessed IDs.
        if (!reservations.TryGetValue(root.Id, out var owner) || owner != root) return [];
        Fence(root);
        var all = Inventory(root);
        foreach (var resource in all.Reverse())
        {
            if (Fault == "cleanup-residual" && resource.Kind == "user") continue;
            switch (resource.Kind)
            {
                case "membership": memberships.Remove(resource.Id); break;
                case "user": users.Remove(resource.Id); break;
                case "group": groups.Remove(resource.Id); break;
                case "role": roles.Remove(resource.Id); break;
                case "credential":
                    foreach (var pair in credentials.Where(p => p.Value.Id == resource.Id).ToArray())
                    {
                        CryptographicOperations.ZeroMemory(pair.Value.Bytes);
                        credentials.Remove(pair.Key);
                    }
                    break;
            }
            CleanupJournal.Add((root.Id, resource));
        }
        windows.Remove(root.Id); armed.Remove(root.Id);
        // Keep reservation and issuance tombstones; recovery and late work use
        // the original root after all provider records and replies disappear.
        return all;
    }
    internal OrganizationUserResource[] RemainingInventory(OrganizationUserRoot root) => Inventory(root).Where(r => r.Kind switch
    {
        "user" => users.ContainsKey(r.Id),
        "credential" => credentials.Values.Any(c => c.Id == r.Id),
        "membership" => memberships.ContainsKey(r.Id),
        "role" => roles.ContainsKey(r.Id),
        "group" => groups.ContainsKey(r.Id),
        _ => true
    }).ToArray();

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
            byte[]? body = null, response = null;
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
                int length = int.Parse(lines.FirstOrDefault(l =>
                    l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1] ?? "0");
                if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("fixture-input");
                body = new byte[length];
                await stream.ReadExactlyAsync(body, shutdown.Token);
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Payload, bool Original) result;
                lock (Gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Payload);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                if (result.Original && Source.LoseResponse)
                    await ResponseRelease.Task.WaitAsync(shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                if (body is not null) CryptographicOperations.ZeroMemory(body);
                if (response is not null) CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private (int, object, bool) Handle(string method, Uri uri, string bearer, JsonElement body)
    {
        byte[] tokenBytes = Encoding.UTF8.GetBytes(bearer);
        string hash;
        try { hash = Convert.ToHexString(SHA256.HashData(tokenBytes)); }
        finally { CryptographicOperations.ZeroMemory(tokenBytes); }
        credentials.TryGetValue(hash, out var credential);
        string actor = credential?.UserId ?? bearer switch
        {
            "setup" => Authorities.Setup,
            "runtime" => Authorities.Runtime,
            "denied" => Authorities.Denied,
            "administrative" => Authorities.Administrative,
            "observer" => Authorities.Observer,
            _ => "unknown"
        };
        string[] parts = uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 4 && parts[2] == "groups" && method == "GET")
        {
            string id = parts[3];
            var resourceRoot = issuance.FirstOrDefault(p => p.Value.Any(r => r.Kind == "group" && r.Id == id)).Key;
            bool allowed = actor is "setup-principal" or "observer-principal" ||
                memberships.Values.Any(m => m.UserId == actor && m.Active &&
                    roles.Values.Any(role => role.Slug == m.Role && role.Read));
            if (Fault == "access-ignores-role" && credential is not null) allowed = true;
            if (Fault == "wrong-user-accepted" && credential is not null && memberships.Values.Any(m =>
                m.UserId == actor && roles.Values.Any(role => role.Slug == m.Role && !role.Read))) allowed = true;
            if (Fault == "denied-accepted" && actor == Authorities.Denied) allowed = true;
            if (Fault == "valid-recheck-denied" && credential is not null && AccessJournal.Any(a =>
                a.Root == resourceRoot && a.Phase == windows.GetValueOrDefault(resourceRoot ?? "") &&
                a.Access.CredentialId == credential.Id)) allowed = false;
            if (resourceRoot is not null && windows.TryGetValue(resourceRoot, out string? phase))
                AccessJournal.Add((resourceRoot, phase, new(Guid.NewGuid().ToString(), actor,
                    credential?.Id, hash, id, allowed)));
            if (!allowed) return (403, new { }, false);
            if (!groups.TryGetValue(id, out var g)) return (404, new { }, false);
            return (200, new
            {
                id = g.Id,
                orgId = Org,
                name = g.Name,
                slug = g.Name,
                role = "member",
                customRoleSlug = (string?)null,
                createdAt = Date,
                updatedAt = Date
            }, false);
        }
        if (parts.Length is < 5 or > 6 || parts[2] != "organizations" || parts[3] != Org || parts[4] != "memberships")
            return (404, new { }, false);
        string[] ids = parts.Length == 6 ? [parts[5]] : method == "DELETE" ?
            body.GetProperty("membershipIds").EnumerateArray().Select(v => v.GetString()!).ToArray() : [];
        string? role = body.TryGetProperty("role", out var roleValue) ? roleValue.GetString() : null;
        bool? active = body.TryGetProperty("isActive", out var activeValue) ? activeValue.GetBoolean() : null;
        var owner = reservations.Values.SingleOrDefault(r => armed.ContainsKey(r.Id) &&
            (ids.Length == 0 ? method == "GET" && actor != Authorities.Observer :
                ids.Any(id => issuance[r.Id].Any(x => x.Kind == "membership" && x.Id == id))));
        bool original = owner is not null;
        string requestId = Guid.NewGuid().ToString();
        if (owner is not null)
        {
            if (dispatchFences.Contains(owner.Id))
            {
                LateRejections.Add(owner.Id); return (409, new { }, true);
            }
            RequestJournal.Add(new(requestId, owner.Id, actor, method, ids, role, active));
            if (requestsUsed[owner.Id]++ != 0) return (409, new { }, true);
        }
        if (actor is not ("setup-principal" or "admin-principal" or "observer-principal") &&
            !(Fault == "denied-accepted" && actor == Authorities.Denied))
            return (403, new { }, original);
        if (method == "GET")
        {
            var rows = memberships.Values.Select(m => Wire(m, true)).ToList();
            if (Fault == "list-duplicate" && rows.Count > 0) rows.Add(rows[0]);
            if (Fault == "list-missing" && rows.Count > 1) rows.RemoveAt(rows.Count - 1);
            return (200, new { users = rows }, original);
        }
        if (actor == Authorities.Observer) return (403, new { }, original);
        var responses = new List<object>();
        foreach (string id in ids)
        {
            if (!memberships.TryGetValue(id, out var before)) return (404, new { }, original);
            bool apply = Fault is not ("ignored-mutation" or "lost-nonapplied") &&
                !(Fault == "lost-partial" && responses.Count > 0);
            if (apply)
            {
                if (method == "PATCH") memberships[id] = before with { Role = role ?? before.Role, Active = active ?? before.Active };
                else if (method == "DELETE") memberships.Remove(id);
                else return (405, new { }, original);
                if (owner is not null) MembershipJournal.Add((owner.Id, requestId, id));
            }
            var responseRow = method == "PATCH" ? before with { Role = role ?? before.Role, Active = active ?? before.Active } : before;
            responses.Add(Wire(responseRow, false)); // May honestly or falsely echo; storage is separate.
        }
        if (Fault == "borrowed-mutated") memberships[BorrowedMember] = memberships[BorrowedMember] with { Active = false };
        return parts.Length == 6 ? (200, new { membership = responses.Single() }, original) :
            (200, new { memberships = responses }, original);
    }
    private object Wire(MemberRow m, bool list)
    {
        var result = new Dictionary<string, object?>
        {
            ["id"] = m.Id,
            ["orgId"] = Org,
            ["userId"] = m.UserId,
            ["role"] = m.Role,
            ["isActive"] = m.Active,
            ["status"] = "accepted"
        };
        if (list) result["user"] = new { id = m.UserId, username = users[m.UserId].Username };
        else { result["createdAt"] = Date; result["updatedAt"] = Date; }
        return result;
    }
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); ResponseRelease.TrySetResult(); listener.Stop();
        await accept; await Task.WhenAll(connections);
        foreach (var credential in credentials.Values) CryptographicOperations.ZeroMemory(credential.Bytes);
        shutdown.Dispose();
    }
}
