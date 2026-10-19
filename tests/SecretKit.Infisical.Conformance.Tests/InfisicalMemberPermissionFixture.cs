using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled provider only. Authentication reads actual bearer bytes; authorization
// reads persisted wire policies and membership assignments, never the effect oracle,
// source action label, caller outcome or row.Control.
internal sealed class InfisicalMemberPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities { get; } = new(
        "20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
        "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
        "20000000-0000-0000-0000-000000000005");
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<MemberPermissionJournal, InfisicalMemberPermissionWriter> writers = [];
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly Dictionary<string, MemberPermissionCredential> tokens = [];
    private readonly List<MemberPermissionCredential> credentials = [];
    private readonly List<MemberPermissionResource> enrolled = [];
    private readonly Dictionary<string, MemberPermissionResource> resources = [];
    private readonly Dictionary<string, MemberPermissionState> members = [];
    private readonly List<MemberPermissionJoin> joins = [];
    private readonly List<MemberPermissionIngress> ingress = [];
    private readonly List<MemberPermissionCommit> commits = [];
    private readonly List<MemberPermissionAccess> decisions = [];
    private readonly List<MemberPermissionChange> changes = [];
    private readonly List<byte[]> privateCredentials = [];
    private readonly MemberPermissionBorrowed[] borrowed;
    private MemberPermissionRoot? root;
    private MemberPermissionIssued? issued;
    private MemberPermissionPolicy? policy, copiedPolicy;
    private string revision = "policy-1", window = "";
    private int stage, attempt;
    private bool closed, closing, armed, settled, assigned, copied;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal MemberPermissionProfile Profile { get; }
    internal InfisicalMemberPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Originals { get; private set; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count + members.Count + credentials.Count + joins.Count +
        (policy is null ? 0 : 1) + (copiedPolicy is null ? 0 : 1);
    internal bool BorrowedPreserved => borrowed.SequenceEqual(Borrowed());
    internal InfisicalMemberPermissionFixture(string fault = "")
    {
        Fault = fault;
        foreach (var journal in Enum.GetValues<MemberPermissionJournal>()) writers.Add(journal, new(journal));
        Profile = new("controlled-member", "controlled-epoch", "controlled-v1", writers.Values.Select(w => w.Pin).ToArray());
        borrowed = Borrowed();
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal MemberPermissionInput Input(string operation, MemberPermissionAction action) =>
        new(new(new("https://member-source.invalid/"), "coordinator-token", "member-coordinator", 30), "member-capability",
            Profile, MemberPermissionContract.Scope(operation), MemberPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, MemberPermissionAction action, bool configured = true)
    {
        var scope = JsonSerializer.SerializeToNode(new
        {
            scopes = new
            {
                local = new
                {
                    organizationId = Organization,
                    setupIdentityId = Authorities.Setup,
                    runtimeIdentityId = Authorities.Runtime,
                    deniedIdentityId = Authorities.Denied,
                    administrativeIdentityId = Authorities.Administrative,
                    observerIdentityId = Authorities.Observer,
                    memberPermission = Input(operation, action)
                }
            }
        }, MemberPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("memberPermission");
        return NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new Dictionary<string, object>
            {
                ["C08-IM-IdentityPrivilegeChanges"] = scope,
                ["C08-IM-RoleChanges"] = scope,
                ["C08-IM-ProjectTemplates"] = scope,
                ["C08-IM-ManagementClient"] = scope
            }
        }, MemberPermissionContract.Options));
    }
    internal MemberPermissionRoot Root(string operation, MemberPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            MemberPermissionContract.Variant(action), boundary, "local", "member-coordinator", MemberPermissionSourceKind.ControlledFixture,
            MemberPermissionContract.Scope(operation), MemberPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p =>
        new MemberPermissionBorrowed("host-credential", p.Key, MemberPermissionContract.Hash(p.Value))).Concat(
            writers.Values.Select(w => new MemberPermissionBorrowed("host-key", w.Pin.Writer, MemberPermissionContract.Hash(w.Pin.Spki)))).ToArray();
    private void Enroll(string kind, string id)
    {
        MemberPermissionContract.Require(root is not null && !closed &&
            !enrolled.Any(e => e.Kind == kind && e.Id == id) && !borrowed.Any(b => b.Kind == kind && b.Id == id));
        enrolled.Add(new(kind, id, root!.Id, root.Nonce));
    }
    private void Create(string kind, string id)
    {
        MemberPermissionContract.Require(!closed && !closing);
        resources.Add(kind + "/" + id, enrolled.Single(e => e.Kind == kind && e.Id == id));
    }
    private static string Id() => Guid.NewGuid().ToString();
    private (string Id, string Hash, byte[] Bytes) PlanCredential(string principal)
    {
        string id = Id();
        Enroll("credential", id);
        // Inert owned buffer; it is not registered as a usable credential until Open.
        byte[] bytes = Encoding.ASCII.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        privateCredentials.Add(bytes); Copies.Add(bytes);
        return (id, MemberPermissionContract.RawHash(bytes), bytes);
    }
    private MemberPermissionPrincipal PlanPrincipal(MemberPermissionActorKind kind, string? machine = null)
    {
        bool owned = kind == MemberPermissionActorKind.User;
        string id = owned ? Id() : machine!, username = owned ? "user-" + id : "machine-" + id;
        string org = Id(), project = Id(), copy = Id();
        foreach (string membership in new[] { org, project, copy }) Enroll("membership", membership);
        if (!owned)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(hostTokens[id]);
            try { return new(id, kind, username, "host-" + id, MemberPermissionContract.RawHash(bytes), [], false, org, project, copy); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        Enroll("user", id);
        var credential = PlanCredential(id);
        return new(id, kind, username, credential.Id, credential.Hash, credential.Bytes, true, org, project, copy);
    }
    private void Reserve(MemberPermissionRoot selected)
    {
        MemberPermissionContract.Require(root is null && selected.Origin == Origin.AbsoluteUri &&
            selected.Organization == Organization && selected.Authorities == Authorities &&
            MemberPermissionContract.Hash(Profile) == MemberPermissionContract.Hash(selected.Profile));
        root = selected;
        if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
        var actors = selected.ActorKind == MemberPermissionActorKind.Machine ?
            new[] { PlanPrincipal(MemberPermissionActorKind.Machine, Authorities.Runtime),
                PlanPrincipal(MemberPermissionActorKind.Machine, Authorities.Denied), PlanPrincipal(MemberPermissionActorKind.User) } :
            [PlanPrincipal(MemberPermissionActorKind.User), PlanPrincipal(MemberPermissionActorKind.User),
                PlanPrincipal(MemberPermissionActorKind.Machine, Authorities.Runtime)];
        string project = Id(), otherProject = Id(), copyProject = Id(), otherOrganization = Id();
        var rows = new List<MemberPermissionRow>();
        MemberPermissionAction[] actions = selected.ScopeProfile == MemberPermissionScope.Project ?
            [MemberPermissionAction.Read, MemberPermissionAction.Create, MemberPermissionAction.Delete, MemberPermissionAction.AssignRole] :
            [MemberPermissionAction.Read, MemberPermissionAction.Edit, MemberPermissionAction.Delete, MemberPermissionAction.GrantPrivileges];
        foreach (string phase in new[] { "before", "after", "copy" })
            foreach (var action in actions)
                foreach (string control in action == MemberPermissionAction.AssignRole ?
                    new[] { "selected", "scope", "actor", "kind", "credential", "member" } : ["selected", "scope", "actor", "kind", "credential"])
                {
                    string user = Id(), membership = Id(), username = "affected-" + user;
                    Enroll("user", user); Enroll("membership", membership);
                    var credential = PlanCredential(user);
                    rows.Add(new(Id(), phase, control, action,
                        control == "scope" && selected.ScopeProfile == MemberPermissionScope.Organization ? otherOrganization : Organization,
                        selected.ScopeProfile == MemberPermissionScope.Organization ? "" :
                            control == "scope" ? otherProject : phase == "copy" ? copyProject : project,
                        membership, new(user, username, username + "@example.invalid", credential.Id, credential.Hash),
                        control is "actor" or "credential" ? 1 : control == "kind" ? 2 : 0));
                }
        issued = new(project, "project-" + selected.Id, otherProject, otherOrganization, copyProject, "copy-" + selected.Id,
            Id(), "policy-" + selected.Id, Id(), "member-reader", revision, actors, rows.ToArray());
        foreach (string id in new[] { project, otherProject, copyProject }) Enroll("project", id);
        Enroll("organization", otherOrganization); Enroll("policy", issued.PolicyId); Enroll("template", issued.TemplateId);
        Enroll("role", issued.AssignedRole); Enroll("issuer-work", selected.Id); Enroll("dispatch-work", selected.Id);
        Enroll("registration", selected.Id); Enroll("canary", selected.Id);
        assigned = !selected.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    }
    internal MemberPermissionPacket Step(MemberPermissionRoot selected, MemberPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == MemberPermissionStep.Reserve)
            {
                MemberPermissionContract.Require(capability == "member-capability");
                Reserve(selected);
            }
            MemberPermissionContract.Require(root is not null && MemberPermissionContract.Hash(root) == MemberPermissionContract.Hash(selected) &&
                !closed && (step == MemberPermissionStep.Close || stage == (int)step));
            if (step != MemberPermissionStep.Close) stage++;
            switch (step)
            {
                case MemberPermissionStep.Open:
                    Opens++;
                    foreach (var entry in enrolled.Where(e => e.Kind is not ("policy" or "template" or "membership") &&
                        e.Id != issued!.CopyProject))
                    {
                        Create(entry.Kind, entry.Id);
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    foreach (var actor in issued!.Principals)
                    {
                        var c = new MemberPermissionCredential(actor.CredentialId, actor.Id, actor.Kind, actor.CredentialHash, actor.Owned);
                        credentials.Add(c);
                        if (actor.Owned) tokens.Add(Encoding.UTF8.GetString(actor.Credential), c);
                        string membership = root!.ScopeProfile == MemberPermissionScope.Organization ? actor.OrganizationMembership : actor.ProjectMembership;
                        Create("membership", membership);
                        joins.Add(new(actor.Id, actor.Kind, Organization,
                            root.ScopeProfile == MemberPermissionScope.Organization ? "" : issued.Project, membership, actor == issued.Principals[0] && assigned));
                    }
                    foreach (var row in issued.Rows)
                    {
                        var credential = new MemberPermissionCredential(row.User.CredentialId, row.User.Id,
                            MemberPermissionActorKind.User, row.User.CredentialHash, true);
                        credentials.Add(credential);
                        tokens.Add(Encoding.UTF8.GetString(privateCredentials.Single(b =>
                            MemberPermissionContract.RawHash(b) == credential.Hash)), credential);
                        if (row.Window != "copy") Bootstrap(row);
                    }
                    if (!root!.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal))
                    {
                        string[] supported = root.ScopeProfile == MemberPermissionScope.Project ?
                            ["read", "create", "delete", "assign-role"] : ["read", "edit", "delete", "grant-privileges"];
                        string selectedAction = MemberPermissionContract.Wire(root.Action);
                        string baseline = supported[(Array.IndexOf(supported, selectedAction) + 1) % supported.Length];
                        policy = new(root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal) ? issued.TemplateId : issued.PolicyId,
                            revision, issued.Principals[0].Id, issued.Principals[0].Kind, Organization,
                            root.ScopeProfile == MemberPermissionScope.Organization ? "" : issued.Project, "member", [baseline],
                            baseline == "assign-role" ? issued.Rows.Where(r => r.Control == "selected").Select(r => r.User.Email).ToArray() : [],
                            baseline == "assign-role" ? issued.AssignedRole : "");
                        Create(root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal) ? "template" : "policy", policy.Resource);
                    }
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                    break;
                case MemberPermissionStep.Before: Clear(); window = "before"; break;
                case MemberPermissionStep.Arm: Clear(); window = ""; armed = true; break;
                case MemberPermissionStep.Settle: settled = true; break;
                case MemberPermissionStep.After:
                    ingress.RemoveAll(i => i.Phase != "activation");
                    commits.RemoveAll(c => !ingress.Any(i => i.Request == c.Request));
                    decisions.Clear(); changes.Clear(); attempt = 0; window = "after";
                    break;
                case MemberPermissionStep.ObserveBefore:
                case MemberPermissionStep.ObserveAfter: window = ""; break;
                case MemberPermissionStep.Close:
                    Closes++; closed = closing = settled = true; armed = false; window = "";
                    resources.Clear(); members.Clear(); credentials.Clear(); tokens.Clear(); joins.Clear();
                    if (Fault != "policy-cleanup") policy = copiedPolicy = null;
                    if (Fault == "cleanup") resources.Add("residual", enrolled.First());
                    if (Fault == "borrowed-change") hostTokens[Authorities.Runtime] = "changed";
                    foreach (var bytes in privateCredentials) CryptographicOperations.ZeroMemory(bytes);
                    issued?.Erase();
                    break;
            }
            return Packet(step);
        }
    }
    private void Bootstrap(MemberPermissionRow row)
    {
        joins.Add(new(row.User.Id, MemberPermissionActorKind.User, row.Organization, row.Project, row.Membership, false));
        if (row.Action == MemberPermissionAction.Create) return;
        Create("membership", row.Membership);
        members.Add(row.Membership, new(row.Membership, row.User.Id, row.Organization, row.Project, row.User.Username, "no-access", true, 1));
    }
    private void Clear() { ingress.Clear(); commits.Clear(); decisions.Clear(); changes.Clear(); attempt = 0; }
    private MemberPermissionSigned<T> Sign<T>(MemberPermissionStep step, MemberPermissionJournal journal, T value) =>
        writers[journal].Sign(root!, step, value);
    private MemberPermissionPacket Packet(MemberPermissionStep step)
    {
        bool opened = step == MemberPermissionStep.Open, observe = step is MemberPermissionStep.ObserveBefore or MemberPermissionStep.ObserveAfter;
        var issuer = credentials.ToArray();
        var membership = joins.ToArray();
        if (opened && Fault == "credential-wrong-user")
            issuer[0] = issuer[0] with { Principal = Id() };
        if (opened && Fault == "membership-wrong-user")
            membership[0] = membership[0] with { Principal = Id() };
        if (opened && Fault == "actor-kind")
            issuer[0] = issuer[0] with
            {
                Kind = issuer[0].Kind == MemberPermissionActorKind.User ?
                MemberPermissionActorKind.Machine : MemberPermissionActorKind.User
            };
        var inventory = members.Values.OrderBy(s => s.Membership).ToArray();
        if (opened && Fault == "missing-inventory") inventory = inventory.Skip(1).ToArray();
        var policies = new[] { policy, copiedPolicy }.OfType<MemberPermissionPolicy>().OrderBy(p => p.Resource).ToArray();
        var committed = observe || step == MemberPermissionStep.Settle ? commits.ToArray() : [];
        if (step == MemberPermissionStep.Settle && Fault == "wrong-policy-target" && committed.Length == 1)
        {
            var unrelated = committed[0].Policy with { Resource = Id() };
            committed[0] = committed[0] with { Policy = unrelated };
            policies = [unrelated];
        }
        var packet = new MemberPermissionPacket(
            Sign(step, MemberPermissionJournal.Ownership, new MemberPermissionOwner(true, true, true,
                settled || closed, settled || closed, Fault == "pending-issuer" && opened ? 1 : 0, closed ? 0 : 1,
                opened ? issued : null, enrolled.ToArray(), resources.Values.ToArray(), Borrowed())),
            Sign(step, MemberPermissionJournal.Ingress, observe || step == MemberPermissionStep.Settle ? ingress.ToArray() : []),
            Sign(step, MemberPermissionJournal.Policy, new MemberPermissionPolicies(policies, committed)),
            Sign(step, MemberPermissionJournal.Storage, new MemberPermissionStorage(inventory, observe ? changes.ToArray() : [])),
            Sign(step, MemberPermissionJournal.Issuer, issuer),
            Sign(step, MemberPermissionJournal.Membership, membership),
            Sign(step, MemberPermissionJournal.Access, observe ? decisions.ToArray() : []), []);
        var seals = new List<MemberPermissionSigned<MemberPermissionSeal>>();
        Add(MemberPermissionJournal.Ownership, packet.Owner.Payload);
        Add(MemberPermissionJournal.Ingress, packet.Ingress.Payload);
        Add(MemberPermissionJournal.Policy, packet.Policy.Payload);
        Add(MemberPermissionJournal.Storage, packet.Storage.Payload);
        Add(MemberPermissionJournal.Issuer, packet.Issuer.Payload);
        Add(MemberPermissionJournal.Membership, packet.Membership.Payload);
        Add(MemberPermissionJournal.Access, packet.Access.Payload);
        return packet with { Seals = Fault == "missing-seal" && opened ? seals.Skip(1).ToArray() : seals.ToArray() };
        void Add<T>(MemberPermissionJournal journal, T payload) => seals.Add(Sign(step, journal,
            new MemberPermissionSeal(MemberPermissionContract.Hash(payload), !(Fault == "nonterminal" && opened), 0, 1)));
    }
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
            byte[] header = new byte[32768], body = [], response = [];
            Copies.Add(header);
            try
            {
                var stream = socket.GetStream(); int count = 0;
                while (count < header.Length)
                {
                    if (await stream.ReadAsync(header.AsMemory(count, 1), shutdown.Token) == 0) return;
                    count++;
                    if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                }
                string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                string[] request = lines[0].Split(' ');
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?
                    .Split(':')[1].Trim() ?? "0");
                MemberPermissionContract.Require(length is >= 0 and <= 131072);
                body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, shutdown.Token);
                string bearer = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "";
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Body) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement, body);
                response = JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body); CryptographicOperations.ZeroMemory(response);
            }
        }
    }
    private MemberPermissionCredential Authenticate(string bearer)
    {
        if (tokens.TryGetValue(bearer, out var owned)) return owned;
        string id = hostTokens.SingleOrDefault(p => p.Value == bearer).Key ?? "unknown";
        byte[] bytes = Encoding.UTF8.GetBytes(bearer);
        try { return new("host-" + id, id, MemberPermissionActorKind.Machine, MemberPermissionContract.RawHash(bytes), false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Record(string request, MemberPermissionCredential actor, string method, string path,
        byte[] body, string intent, bool allowed, string phase) =>
        ingress.Add(new(request, actor.Principal, actor.Kind, actor.Hash, method, path,
            MemberPermissionContract.RawHash(body), intent, allowed, phase));
    private (int, object) Handle(string method, Uri uri, string bearer, JsonElement body, byte[] bytes)
    {
        if (root is null || issued is null || closed || closing) return (403, new { });
        var actor = Authenticate(bearer);
        string path = uri.AbsolutePath;
        bool template = root.Operation.Contains("ProjectTemplate", StringComparison.Ordinal);
        bool organization = root.Operation.EndsWith("OrganizationRole", StringComparison.Ordinal);
        bool privilege = root.Operation.Contains("IdentityPrivilegeChange", StringComparison.Ordinal);
        bool create = root.Operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
        string originalPath = (template ? "/api/v1/project-templates" : organization ? "/api/v1/organization/roles" :
            privilege ? "/api/v2/identity-project-additional-privilege" : "/api/v1/projects/" + issued.Project + "/roles") +
            (create ? "" : "/" + (template ? issued.TemplateId : issued.PolicyId));
        if (path == originalPath && method == (create ? "POST" : "PATCH"))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++;
            string request = Id(), intent = MemberPermissionContract.RawHash(bytes);
            if (privilege) intent = WireHash(new object?[] { issued.ProjectSlug, issued.Principals[0].ProjectMembership,
                create ? null : issued.PolicyId, body });
            bool authorized = actor.Principal == Authorities.Administrative && actor.Kind == MemberPermissionActorKind.Machine;
            Record(request, actor, method, path, bytes, intent, authorized, "original");
            if (!authorized) return (403, new { });
            JsonElement permissions = template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
            var permission = permissions.EnumerateArray().Single();
            string[] actions = permission.GetProperty("action").ValueKind == JsonValueKind.Array ?
                permission.GetProperty("action").EnumerateArray().Select(v => v.GetString()!).ToArray() : [permission.GetProperty("action").GetString()!];
            string principal = privilege && create ? body.GetProperty("identityId").GetString()! :
                template ? issued.Principals.Single(p => p.Username == body.GetProperty("users")[0].GetProperty("username").GetString()).Id :
                issued.Principals[0].Id;
            string[] emails = permission.TryGetProperty("conditions", out var conditions) ?
                conditions.GetProperty("userEmail").GetProperty("$in").EnumerateArray().Select(e => e.GetString()!).ToArray() : [];
            string role = conditions.ValueKind == JsonValueKind.Object ? conditions.GetProperty("assignableRole").GetString()! : "";
            if (Fault is not ("ignored-policy" or "lost-nonapplied"))
            {
                string old = revision; revision = "policy-2";
                policy = new(template ? issued.TemplateId : issued.PolicyId, revision, principal, issued.Principals[0].Kind,
                    Organization, organization ? "" : issued.Project, permission.GetProperty("subject").GetString()!,
                    Fault == "partial" ? [] : actions, emails, role);
                string kind = template ? "template" : "policy";
                if (!resources.ContainsKey(kind + "/" + policy.Resource)) Create(kind, policy.Resource);
                commits.Add(new(request, old, policy));
                if (privilege)
                {
                    assigned = true;
                    int index = joins.FindIndex(j => j.Principal == issued.Principals[0].Id && j.Project == issued.Project);
                    joins[index] = joins[index] with { Assigned = true };
                }
            }
            var row = new JsonObject
            {
                ["id"] = template ? issued.TemplateId : issued.PolicyId,
                ["slug"] = issued.PolicySlug,
                ["createdAt"] = "2026-01-01T00:00:00Z",
                ["updatedAt"] = "2026-01-01T00:00:01Z",
                ["permissions"] = JsonNode.Parse(permissions.GetRawText())
            };
            if (template)
            {
                row.Remove("slug"); row.Remove("permissions"); row["name"] = issued.PolicySlug;
                row["orgId"] = Organization; row["type"] = "secret-manager";
                row["groups"] = new JsonArray(); row["identities"] = new JsonArray(); row["projectManagedIdentities"] = new JsonArray();
                foreach (string property in new[] { "roles", "environments", "users" })
                    row[property] = JsonNode.Parse(body.GetProperty(property).GetRawText());
            }
            else if (privilege) row["isTemporary"] = false;
            else { row["name"] = issued.PolicySlug; row[organization ? "orgId" : "projectId"] = organization ? Organization : issued.Project; }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = row });
        }
        if (settled && actor.Principal == Authorities.Setup && actor.Kind == MemberPermissionActorKind.Machine &&
            policy is not null && (path == "/api/v1/projects" ||
                path.EndsWith("/" + issued.Principals[0].ProjectMembership, StringComparison.Ordinal) ||
                path.EndsWith("/" + issued.Principals[0].OrganizationMembership, StringComparison.Ordinal)))
            return Activate(actor, method, path, body, bytes);
        return MemberAction(actor, method, path, body, bytes);
    }
    private (int, object) Activate(MemberPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        string request = Id();
        bool template = path == "/api/v1/projects";
        if (template)
        {
            if (copied || method != "POST" || body.GetProperty("template").GetString() != issued!.PolicySlug ||
                body.GetProperty("slug").GetString() != issued.CopySlug) return (403, new { });
            copied = true; assigned = true;
            Create("project", issued.CopyProject);
            var principal = issued.Principals[0]; Create("membership", principal.CopyMembership);
            joins.Add(new(principal.Id, principal.Kind, Organization, issued.CopyProject, principal.CopyMembership, true));
            foreach (var row in issued.Rows.Where(r => r.Window == "copy")) Bootstrap(row);
            copiedPolicy = Fault == "template-echo" ? policy! with { Actions = [] } :
                policy! with { Resource = issued.CopyProject, Project = issued.CopyProject };
            Record(request, actor, method, path, bytes, MemberPermissionContract.RawHash(bytes), true, "activation");
            commits.Add(new(request, revision, copiedPolicy));
            return (200, new
            {
                project = new
                {
                    id = issued.CopyProject,
                    _id = issued.CopyProject,
                    orgId = Organization,
                    name = issued.CopySlug,
                    slug = issued.CopySlug,
                    type = "secret-manager",
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:00Z",
                    environments = Array.Empty<object>(),
                    deletedEnvironments = Array.Empty<object>()
                }
            });
        }
        if (assigned || method != "PATCH") return (403, new { });
        bool organization = path.StartsWith("/api/v2/organizations/", StringComparison.Ordinal);
        string role = organization ? body.GetProperty("role").GetString()! : body.GetProperty("roles")[0].GetProperty("role").GetString()!;
        if (role != issued!.PolicySlug) return (403, new { });
        assigned = Fault != "assignment-echo";
        int index = joins.FindIndex(j => j.Principal == issued.Principals[0].Id && j.Project == (organization ? "" : issued.Project));
        joins[index] = joins[index] with { Assigned = assigned };
        Record(request, actor, method, path, bytes, organization ? MemberPermissionContract.RawHash(bytes) :
            WireHash(new object?[] { null, body }), true, "activation");
        commits.Add(new(request, revision, policy!));
        return organization ? (200, new
        {
            membership = OrgRow(new(issued.Principals[0].OrganizationMembership,
            issued.Principals[0].Id, Organization, "", issued.Principals[0].Username, role, true, 1))
        }) :
            (200, new { roles = new[] { Role(issued.Principals[0].ProjectMembership, role) } });
    }
    private (int, object) MemberAction(MemberPermissionCredential actor, string method, string path, JsonElement body, byte[] bytes)
    {
        if (window is not ("before" or "after")) return (403, new { });
        bool organization = path.StartsWith("/api/v2/organizations/", StringComparison.Ordinal);
        string[] segments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length < 5 || segments[4] != "memberships") return (404, new { });
        string org = organization ? segments[3] : Organization, project = organization ? "" : segments[3];
        MemberPermissionAction action = method switch
        {
            "GET" => MemberPermissionAction.Read,
            "POST" => path.EndsWith("/details", StringComparison.Ordinal) ? MemberPermissionAction.Read : MemberPermissionAction.Create,
            "DELETE" => MemberPermissionAction.Delete,
            "PATCH" => organization ? body.TryGetProperty("role", out _) ? MemberPermissionAction.GrantPrivileges :
                MemberPermissionAction.Edit : MemberPermissionAction.AssignRole,
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        var rows = issued!.Rows.Where(r => r.Window == (window == "after" && copied ? "copy" : window)).ToArray();
        if (attempt >= rows.Length) return (409, new { });
        // Row order supplies only an observation correlation for organization list.
        // Other targets are independently resolved from native selectors.
        var expectedRow = rows[attempt++];
        MemberPermissionRow? row = organization && action == MemberPermissionAction.Read ? expectedRow :
            organization || action == MemberPermissionAction.AssignRole ?
                issued.Rows.SingleOrDefault(r => r.Membership == segments.Last()) :
            action == MemberPermissionAction.Read ? issued.Rows.SingleOrDefault(r => r.Project == project &&
                r.User.Username == body.GetProperty("username").GetString()) :
                issued.Rows.SingleOrDefault(r => r.Project == project &&
                    r.User.Username == body.GetProperty("usernames")[0].GetString());
        if (row is null) return (404, new { });
        var effective = project == issued.CopyProject ? copiedPolicy : policy;
        string wire = action switch
        {
            MemberPermissionAction.Read => "read",
            MemberPermissionAction.Create => "create",
            MemberPermissionAction.Delete => "delete",
            MemberPermissionAction.Edit => "edit",
            MemberPermissionAction.AssignRole => "assign-role",
            _ => "grant-privileges"
        };
        string selectedRole = action == MemberPermissionAction.AssignRole ? body.GetProperty("roles")[0].GetProperty("role").GetString()! : "";
        bool allowed = assigned && effective is not null && effective.Subject == "member" &&
            effective.ActorId == actor.Principal && effective.ActorKind == actor.Kind &&
            effective.Organization == org && effective.Project == project && effective.Actions.Contains(wire) &&
            (action != MemberPermissionAction.AssignRole || effective.Emails.Contains(row.User.Email) && effective.AssignedRole == selectedRole);
        if (Fault == "action-leak" && revision == "policy-2" && actor.Principal == issued.Principals[0].Id &&
            org == Organization && project == (organization ? "" : copied ? issued.CopyProject : issued.Project)) allowed = true;
        if (Fault == "scope-leak" && revision == "policy-2" && actor.Principal == issued.Principals[0].Id &&
            policy?.Actions.Contains(wire) == true) allowed = true;
        var recordedActor = Fault == "wrong-actor" ? actor with { Principal = Authorities.Observer } : actor;
        if (Fault == "wrong-credential") recordedActor = actor with { Hash = "wrong" };
        string request = Id();
        Record(request, recordedActor, method, path, bytes, "", allowed, "action");
        bool list = organization && action == MemberPermissionAction.Read;
        decisions.Add(new(request, recordedActor.Principal, recordedActor.Kind, recordedActor.Id, recordedActor.Hash,
            org, project, list ? null : row.User.Id, list ? null : row.Membership, revision, action, allowed));
        var previous = members.GetValueOrDefault(row.Membership);
        object response = new { };
        if (allowed)
        {
            switch (action)
            {
                case MemberPermissionAction.Create:
                    Create("membership", row.Membership);
                    members.Add(row.Membership, new(row.Membership, row.User.Id, org, project, row.User.Username,
                        body.GetProperty("roleSlugs")[0].GetString()!, true, 1));
                    response = new { memberships = new[] { ProjectMutation(members[row.Membership]) } }; break;
                case MemberPermissionAction.Delete:
                    response = organization ? new { membership = OrgRow(previous!) } :
                        new { memberships = new[] { ProjectMutation(previous!) } };
                    members.Remove(row.Membership); resources.Remove("membership/" + row.Membership); break;
                case MemberPermissionAction.Edit:
                    members[row.Membership] = previous! with { Active = body.GetProperty("isActive").GetBoolean(), Version = previous.Version + 1 };
                    response = new { membership = OrgRow(members[row.Membership]) }; break;
                case MemberPermissionAction.GrantPrivileges:
                    members[row.Membership] = previous! with { Role = body.GetProperty("role").GetString()!, Version = previous.Version + 1 };
                    response = new { membership = OrgRow(members[row.Membership]) }; break;
                case MemberPermissionAction.AssignRole:
                    members[row.Membership] = previous! with { Role = selectedRole, Version = previous.Version + 1 };
                    response = new { roles = new[] { Role(row.Membership, selectedRole) } }; break;
                case MemberPermissionAction.Read:
                    response = list ? new { users = members.Values.Where(m => m.Organization == org).Select(m => OrgRow(m, true)).ToArray() } :
                        new { membership = ProjectRow(previous!) }; break;
            }
            if (Fault == "wrong-member" && previous is not null)
                members[row.Membership] = (members.GetValueOrDefault(row.Membership) ?? previous) with { User = Id() };
        }
        changes.Add(new(request, row.Membership, previous, members.GetValueOrDefault(row.Membership)));
        return (allowed ? 200 : 403, response);
    }
    private static object Role(string membership, string role) => new
    {
        id = membership,
        projectMembershipId = membership,
        role,
        isTemporary = false,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static object ProjectRow(MemberPermissionState value) => new
    {
        id = value.Membership,
        userId = value.User,
        projectId = value.Project,
        user = new { id = value.User, username = value.Username, email = value.Username + "@example.invalid" },
        roles = new[] { new { id = value.Membership, role = value.Role, isTemporary = false } }
    };
    private static object ProjectMutation(MemberPermissionState value) => new
    {
        id = value.Membership,
        userId = value.User,
        projectId = value.Project,
        createdAt = "2026-01-01T00:00:00Z",
        updatedAt = "2026-01-01T00:00:01Z"
    };
    private static object OrgRow(MemberPermissionState value, bool list = false)
    {
        var row = new Dictionary<string, object>
        {
            ["id"] = value.Membership,
            ["userId"] = value.User,
            ["orgId"] = value.Organization,
            ["role"] = value.Role,
            ["isActive"] = value.Active,
            ["status"] = "accepted"
        };
        if (list) row["user"] = new { id = value.User, username = value.Username, email = value.Username + "@example.invalid" };
        else { row["createdAt"] = "2026-01-01T00:00:00Z"; row["updatedAt"] = "2026-01-01T00:00:01Z"; }
        return row;
    }
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return MemberPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; settled = true; armed = false; }
        await Task.WhenAll(connections);
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult();
        shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var bytes in privateCredentials) CryptographicOperations.ZeroMemory(bytes);
        Source.Dispose();
        foreach (var writer in writers.Values) writer.Dispose();
        shutdown.Dispose();
    }
}
