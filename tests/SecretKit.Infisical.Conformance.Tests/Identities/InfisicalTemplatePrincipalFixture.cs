using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Independent provider model. HTTP body -> template storage -> copy membership
// and policy -> authenticated secret access. No trial/effect predicate authorizes
// requests, copies principals or generates evidence. Six fixture keys represent
// distinct trusted writers, NOT native independently deployed services.
internal sealed class InfisicalTemplatePrincipalFixture : IAsyncDisposable
{
    internal const string Org = "10000000-0000-0000-0000-000000000001";
    private const string BorrowedProject = "10000000-0000-0000-0000-000000000002";
    private const string Date = "2040-01-01T00:00:00Z";
    internal static TemplatePrincipalAuthorities Authorities { get; } =
        new("20000000-0000-0000-0000-000000000001", "20000000-0000-0000-0000-000000000002",
            "20000000-0000-0000-0000-000000000003", "20000000-0000-0000-0000-000000000004",
            "20000000-0000-0000-0000-000000000005");
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly ConcurrentBag<List<byte>> headerBuffers = [];
    private readonly Task accept;
    private readonly object gate = new();
    private readonly Dictionary<TemplatePrincipalJournal, ECDsa> keys = [];
    private readonly Dictionary<TemplatePrincipalJournal, long> sequences = [];
    private readonly Dictionary<string, TemplateRow> templates = [];
    private readonly Dictionary<string, string> users = [];
    private readonly Dictionary<string, CredentialRow> credentials = [];
    private readonly Dictionary<string, string> groups = [];
    private readonly Dictionary<string, string> groupMembers = [];
    private readonly HashSet<string> managed = [];
    private readonly HashSet<string> auth = [];
    private readonly Dictionary<string, ProjectRow> projects = [];
    private readonly Dictionary<string, byte[]> secrets = [];
    private readonly Dictionary<string, string> secretIds = [];
    private readonly Dictionary<string, string> environmentIds = [];
    private readonly Dictionary<string, string> roleIds = [];
    private readonly Dictionary<string, string> membershipIds = [];
    private readonly Dictionary<string, string> organizationMemberships = [];
    private readonly Dictionary<string, (string Subject, string Action, string Environment, string Path)> policies = [];
    private readonly List<TemplatePrincipalResource> enrolled = [];
    private readonly List<TemplatePrincipalResource> resources = [];
    private readonly List<TemplatePrincipalIngress> ingress = [];
    private readonly List<TemplatePrincipalCommit> commits = [];
    private readonly List<TemplatePrincipalIssuer> issuers = [];
    private readonly List<TemplatePrincipalMembership> memberships = [];
    private readonly List<TemplatePrincipalAccess> access = [];
    private TemplatePrincipalRoot? root;
    private TemplatePrincipalIssued? issued;
    private string intent = "", window = "";
    private int stage, originals;
    private int pendingIssuers;
    private TaskCompletionSource? issuerDrained;
    private bool closed, armed, fenced;
    private readonly TaskCompletionSource responseRelease = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    private readonly List<byte[]> privateCopies = [];
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal InfisicalTemplatePrincipalFixtureSource Source { get; }
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int Remaining => resources.Count;
    internal int Originals => originals;
    internal IReadOnlyList<TemplatePrincipalCommit> Commits => commits;
    internal IReadOnlyList<TemplatePrincipalIngress> Ingress => ingress;
    internal IReadOnlyList<TemplatePrincipalIssuer> Issuers => issuers;
    internal IReadOnlyList<TemplatePrincipalMembership> Memberships => memberships;
    internal IReadOnlyList<TemplatePrincipalAccess> Access => access;
    internal List<(string Method, string Path, int Status)> HttpJournal { get; } = [];
    internal bool BorrowedPreserved => projects.GetValueOrDefault(BorrowedProject) ==
        new ProjectRow(BorrowedProject, "borrowed-project", "", "borrowed-1", "borrowed-policy") && hostTokens.SequenceEqual(
        new[] { "setup", "runtime", "denied", "administrative", "observer" });
    private readonly string[] hostTokens = ["setup", "runtime", "denied", "administrative", "observer"];
    private sealed record CredentialRow(string Principal, string Id, byte[] Bytes, string Kind, string Project);
    private sealed record TemplateRow(string Id, string Name, string Revision, JsonElement Configuration);
    private sealed record ProjectRow(string Id, string Slug, string Template, string Revision, string ConfigurationHash);

    internal InfisicalTemplatePrincipalFixture(string fault = "")
    {
        Fault = fault;
        foreach (var j in Enum.GetValues<TemplatePrincipalJournal>())
            keys.Add(j, ECDsa.Create(ECCurve.NamedCurves.nistP256));
        projects.Add(BorrowedProject, new(BorrowedProject, "borrowed-project", "", "borrowed-1", "borrowed-policy"));
        listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this);
        accept = AcceptAsync();
    }
    internal TemplatePrincipalInput Input(TemplatePrincipalShape shape = TemplatePrincipalShape.Values) =>
        new(new(new("https://template-source.invalid/"), "coordinator-token", "principal-coordinator", 20),
            "private-user-capability", new("controlled-deployment", "controlled-epoch", "controlled-template-v1",
                keys.Select(k => new TemplatePrincipalPin(k.Key, "writer-" + k.Key, "channel-" + k.Key,
                    "principal-v1-" + k.Key, Convert.ToBase64String(k.Value.ExportSubjectPublicKeyInfo()))).ToArray()),
            shape, 20);
    internal object Families(TemplatePrincipalShape shape = TemplatePrincipalShape.Values)
    {
        var scope = new
        {
            scopes = new
            {
                local = new
                {
                    organizationId = Org,
                    setupIdentityId = Authorities.Setup,
                    runtimeIdentityId = Authorities.Runtime,
                    deniedIdentityId = Authorities.Denied,
                    administrativeIdentityId = Authorities.Administrative,
                    observerIdentityId = Authorities.Observer,
                    apiRevision = "AuthV1IdentitiesV1SecretsV4",
                    templatePrincipal = Input(shape)
                }
            }
        };
        return new Dictionary<string, object> { ["C08-IM-ProjectTemplates"] = scope, ["C08-IM-ManagementClient"] = scope };
    }
    internal NativeEnvironment Environment(TemplatePrincipalShape shape = TemplatePrincipalShape.Values) =>
        NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
        {
            origin = Origin.AbsoluteUri,
            allowLoopbackDevelopmentHttp = true,
            setup = hostTokens[0],
            runtime = hostTokens[1],
            denied = hostTokens[2],
            administrative = hostTokens[3],
            observer = hostTokens[4],
            families = Families(shape)
        }, TemplatePrincipalContract.Options));
    internal TemplatePrincipalRoot Root(string operation, string variant, string boundary,
        TemplatePrincipalShape shape = TemplatePrincipalShape.Values) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Org, operation,
            variant, boundary, "local", "principal-coordinator", TemplatePrincipalKind.ControlledFixture,
            shape, Authorities, Input(shape).Profile);
    private static string Id() => Guid.NewGuid().ToString();
    private byte[] NewMaterial()
    {
        Span<byte> random = stackalloc byte[32];
        RandomNumberGenerator.Fill(random);
        try
        {
            byte[] bytes = Encoding.UTF8.GetBytes(Convert.ToHexString(random));
            Copies.Add(bytes); privateCopies.Add(bytes);
            return bytes;
        }
        finally { CryptographicOperations.ZeroMemory(random); }
    }
    private static string TokenHash(string token)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(token);
        try { return TemplatePrincipalContract.HashBytes(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private TemplatePrincipalBorrowed[] Borrowed() =>
        [new("project", BorrowedProject, TemplatePrincipalContract.Hash(projects[BorrowedProject])),
            .. Authorities.All.Select((id, index) => new TemplatePrincipalBorrowed("host-token", id,
                TokenHash(hostTokens[index])))];
    private void Enroll(string kind, string id)
    {
        TemplatePrincipalContract.Require(root is not null && !closed);
        var entry = new TemplatePrincipalResource(root!.Id, root.Nonce, kind, id);
        TemplatePrincipalContract.Require(!enrolled.Contains(entry));
        enrolled.Add(entry); // durable model enrollment precedes existence
    }
    private void Create(string kind, string id)
    {
        TemplatePrincipalContract.Require(root is not null && !closed);
        var entry = enrolled.SingleOrDefault(e => e.Kind == kind && e.Id == id);
        TemplatePrincipalContract.Require(entry is not null && !resources.Contains(entry));
        resources.Add(entry!);
    }
    private void Reserve(TemplatePrincipalRoot selected)
    {
        TemplatePrincipalContract.Require(root is null && !closed && Fault != "collision");
        root = selected;
        string prefix = "tp" + selected.Id;
        var freshUsers = Enumerable.Range(0, 3).Select(n =>
        {
            string actor = Id(), credential = Id(), username = prefix + n;
            Enroll("user", actor); Enroll("credential", credential);
            string membership = Id(); Enroll("organization-membership", membership);
            organizationMemberships.Add(actor, membership);
            byte[] bytes = NewMaterial();
            return new TemplatePrincipalCredential(actor, username, "user", "", credential,
                TemplatePrincipalContract.HashBytes(bytes), bytes);
        }).ToArray();
        byte[] value = NewMaterial();
        issued = new(Id(), prefix, Id(), "seed" + selected.Id, Id(), "group" + selected.Id, "managed" + selected.Id,
            Id(), Id(), "before" + selected.Id, "after" + selected.Id, Id(), Id(), "read" + selected.Id,
            "mark" + selected.Id, "CANARY", TemplatePrincipalContract.HashBytes(value), value, freshUsers);
        Enroll("template", issued.TemplateId);
        if (selected.Operation == TemplatePrincipalContract.Create) Enroll("template", issued.SeedId);
        Enroll("group", issued.GroupId); Enroll("group-member", issued.Users[1].Principal);
        foreach (string project in new[] { issued.BeforeProject, issued.AfterProject })
        {
            Enroll("project", project);
            foreach (string role in new[] { issued.ReaderRole, issued.MarkerRole })
            {
                string id = Id(); roleIds.Add(project + "/" + role, id); Enroll("role", id);
            }
            foreach (string environment in new[] { "baseline", "witness", "outside" })
            {
                string environmentId = Id(); environmentIds.Add(project + "/" + environment, environmentId);
                Enroll("environment", environmentId);
                string id = Id(); secretIds.Add(project + "/" + environment + "/" + issued.Key, id); Enroll("secret", id);
            }
            foreach (string kind in new[] { "user", "group", "managed" })
            {
                string id = Id(); membershipIds.Add(project + "/" + kind, id); Enroll("membership", id);
            }
        }
        foreach (string identity in new[] { issued.BeforeManaged, issued.AfterManaged })
        { Enroll("managed", identity); Enroll("auth", identity); }
    }
    internal async ValueTask<TemplatePrincipalPacket> StepAsync(TemplatePrincipalRoot selected,
        TemplatePrincipalStep step, string? capability, TemplatePrincipalReceipt? receipt, CancellationToken token)
    {
        lock (gate)
        {
            if (step == TemplatePrincipalStep.Reserve)
            {
                TemplatePrincipalContract.Require(capability == "private-user-capability");
                Reserve(selected);
            }
            // Close uses the original root even if Reserve/Open reply was lost.
            if (step == TemplatePrincipalStep.Close && root is null)
            {
                root = selected; closed = fenced = true; Closes++;
                return Packet(step);
            }
            TemplatePrincipalContract.Require(root is not null &&
                TemplatePrincipalContract.Hash(root) == TemplatePrincipalContract.Hash(selected) &&
                !closed && (step == TemplatePrincipalStep.Close || (int)step == stage));
            if (step != TemplatePrincipalStep.Close) stage++;
            switch (step)
            {
                case TemplatePrincipalStep.Open:
                    Opens++;
                    pendingIssuers++;
                    issuerDrained = new(TaskCreationOptions.RunContinuationsAsynchronously);
                    break;
                case TemplatePrincipalStep.Before: window = "before"; access.Clear(); break;
                case TemplatePrincipalStep.After: window = "after"; access.Clear(); break;
                case TemplatePrincipalStep.ObserveBefore:
                case TemplatePrincipalStep.ObserveAfter: window = ""; break;
                case TemplatePrincipalStep.Arm:
                    intent = receipt?.IntentHash ?? "";
                    TemplatePrincipalContract.Require(intent.Length == 64 && !armed);
                    armed = true; break;
                case TemplatePrincipalStep.Settle:
                    fenced = true; responseRelease.TrySetResult(); break;
                case TemplatePrincipalStep.Close:
                    Closes++; closed = fenced = true; armed = false; window = "";
                    OpenRelease.TrySetResult(); responseRelease.TrySetResult();
                    // Transport buffers remain owned by their active request/content.
                    // Clearing the current coordinator input here would corrupt Close.
                    foreach (var bytes in privateCopies)
                        if (Fault != "cleanup" || !credentials.Values.Any(c => ReferenceEquals(c.Bytes, bytes)))
                            CryptographicOperations.ZeroMemory(bytes);
                    foreach (var r in resources.ToArray())
                        if (Fault != "cleanup" || r.Kind != "credential") resources.Remove(r);
                    if (Fault != "cleanup") credentials.Clear();
                    templates.Clear(); users.Clear(); groups.Clear(); groupMembers.Clear(); organizationMemberships.Clear();
                    managed.Clear(); auth.Clear(); secrets.Clear(); policies.Clear();
                    foreach (var project in enrolled.Where(e => e.Kind == "project")) projects.Remove(project.Id);
                    if (Fault == "borrowed-change") projects[BorrowedProject] = projects[BorrowedProject] with { Revision = "changed" };
                    break;
            }
        }
        if (step == TemplatePrincipalStep.Open)
        {
            try
            {
                lock (gate)
                {
                    foreach (var c in issued!.Users)
                    {
                        Create("user", c.Principal); users.Add(c.Principal, c.Username);
                        Create("organization-membership", organizationMemberships[c.Principal]);
                        Create("credential", c.CredentialId);
                        byte[] bytes = c.Bytes.ToArray(); Copies.Add(bytes); privateCopies.Add(bytes);
                        credentials.Add(c.Hash, new(c.Principal, c.CredentialId, bytes, "user", ""));
                        issuers.Add(new(Id(), c.Principal, c.CredentialId, c.Hash, "user", "", organizationMemberships[c.Principal]));
                        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
                    }
                    if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                }
                if (Fault == "blocked-open")
                {
                    OpenEntered.TrySetResult();
                    await OpenRelease.Task.WaitAsync(token);
                    lock (gate) TemplatePrincipalContract.Require(!closed);
                }
            }
            finally
            {
                lock (gate) { pendingIssuers--; issuerDrained!.TrySetResult(); }
            }
        }
        if (step is TemplatePrincipalStep.Close or TemplatePrincipalStep.Settle)
        {
            if (step == TemplatePrincipalStep.Close && issuerDrained is not null)
                await issuerDrained.Task.WaitAsync(token);
            // Response release precedes the exact connection drain. No body or
            // late dispatch worker survives a terminal source fence.
            await Task.WhenAll(connections.ToArray()).WaitAsync(token);
        }
        lock (gate) return Packet(step);
    }
    private TemplatePrincipalSigned<T> Sign<T>(TemplatePrincipalJournal journal, TemplatePrincipalStep step, T value)
    {
        var pin = root!.Profile.Pins.Single(p => p.Journal == journal);
        long sequence = sequences.GetValueOrDefault(journal) + 1; sequences[journal] = sequence;
        var envelope = new TemplatePrincipalEnvelope<T>(TemplatePrincipalContract.Hash(root), journal, pin.Writer,
            pin.Channel, pin.Schema, step.ToString(), sequence, true, 0, value);
        byte[] bytes = TemplatePrincipalContract.Bytes(envelope);
        try
        {
            return new(envelope, Convert.ToBase64String(keys[journal].SignData(bytes,
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private TemplatePrincipalPacket Packet(TemplatePrincipalStep step)
    {
        TemplatePrincipalIssued? exported = null;
        if (step == TemplatePrincipalStep.Open)
        {
            exported = issued! with
            {
                Value = issued.Value.ToArray(),
                Users = issued.Users.Select(c => c with { Bytes = c.Bytes.ToArray() }).ToArray()
            };
            Copies.Add(exported.Value);
            privateCopies.Add(exported.Value);
            foreach (var credential in exported.Users) { Copies.Add(credential.Bytes); privateCopies.Add(credential.Bytes); }
        }
        bool sample = step is TemplatePrincipalStep.ObserveBefore or TemplatePrincipalStep.ObserveAfter;
        string project = step == TemplatePrincipalStep.ObserveBefore ? issued!.BeforeProject : issued?.AfterProject ?? "";
        var owner = new TemplatePrincipalOwner(Fault != "collision", true, true, closed, pendingIssuers, 0,
            Registrations, closed && privateCopies.All(b => b.All(x => x == 0)) &&
                headerBuffers.All(b => b.All(x => x == 0)), exported,
            enrolled.ToArray(), resources.ToArray(), Borrowed());
        var packet = new TemplatePrincipalPacket(Sign(TemplatePrincipalJournal.Ownership, step, owner),
            Sign(TemplatePrincipalJournal.Ingress, step, ingress.ToArray()),
            Sign(TemplatePrincipalJournal.Template, step, commits.ToArray()),
            Sign(TemplatePrincipalJournal.Issuer, step, issuers.ToArray()),
            Sign(TemplatePrincipalJournal.Membership, step, sample ? memberships.Where(m => m.Project == project).ToArray() : []),
            Sign(TemplatePrincipalJournal.Access, step, sample ? access.ToArray() : []));
        if (Fault == "source-echo" && sample)
            packet = packet with
            {
                Memberships = Sign(TemplatePrincipalJournal.Membership, step,
                    memberships.Where(m => m.Project == project).Select(m => m with { CopyRequest = "", Revision = "" }).ToArray())
            };
        if (Fault == "content-tamper" && step == TemplatePrincipalStep.Settle && packet.Templates.Payload.Content.Length != 0)
        {
            var rows = packet.Templates.Payload.Content.ToArray();
            rows[0] = rows[0] with { ConfigurationHash = "tampered" };
            packet = packet with
            {
                Templates = packet.Templates with { Payload = packet.Templates.Payload with { Content = rows } }
            };
        }
        return packet;
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
            byte[]? body = null, response = null;
            List<byte>? headers = null;
            try
            {
                var stream = socket.GetStream();
                headers = [];
                headerBuffers.Add(headers);
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    if (await stream.ReadAsync(one, shutdown.Token) == 0) return;
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                byte[] headerBytes = headers.ToArray(); Copies.Add(headerBytes);
                string[] lines;
                try { lines = Encoding.ASCII.GetString(headerBytes).Split("\r\n"); }
                finally { CryptographicOperations.ZeroMemory(headerBytes); }
                string[] request = lines[0].Split(' ');
                string bearer = lines.Single(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)).Split(' ').Last();
                int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
                    ?.Split(':')[1] ?? "0");
                if (length is < 0 or > 1024 * 1024) throw new InvalidOperationException("fixture-input");
                body = new byte[length]; Copies.Add(body);
                await stream.ReadExactlyAsync(body, shutdown.Token);
                using var document = JsonDocument.Parse(length == 0 ? "{}"u8.ToArray() : body);
                (int Status, object Payload, bool Original) result;
                lock (gate) result = Handle(request[0], new Uri(Origin, request[1]), bearer, document.RootElement,
                    TemplatePrincipalContract.HashBytes(body));
                lock (gate) HttpJournal.Add((request[0], new Uri(Origin, request[1]).AbsolutePath, result.Status));
                response = JsonSerializer.SerializeToUtf8Bytes(result.Payload); Copies.Add(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\nConnection: close\r\n\r\n"), shutdown.Token);
                if (result.Original && root!.Boundary == "lost-response-no-replay")
                    await responseRelease.Task.WaitAsync(shutdown.Token);
                await stream.WriteAsync(response, shutdown.Token);
            }
            catch (IOException) { }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
            finally
            {
                if (body is not null) CryptographicOperations.ZeroMemory(body);
                if (response is not null) CryptographicOperations.ZeroMemory(response);
                if (headers is not null) CryptographicOperations.ZeroMemory(CollectionsMarshal.AsSpan(headers));
            }
        }
    }
    private (int, object, bool) Handle(string method, Uri uri, string bearer, JsonElement body, string bodyHash)
    {
        if (closed && method != "GET") return (409, new { }, false);
        byte[] tokenBytes = Encoding.UTF8.GetBytes(bearer);
        string tokenHash;
        try { tokenHash = TemplatePrincipalContract.HashBytes(tokenBytes); }
        finally { CryptographicOperations.ZeroMemory(tokenBytes); }
        credentials.TryGetValue(tokenHash, out var credential);
        string actor = credential?.Principal ?? bearer switch
        {
            "setup" => Authorities.Setup,
            "runtime" => Authorities.Runtime,
            "denied" => Authorities.Denied,
            "administrative" => Authorities.Administrative,
            "observer" => Authorities.Observer,
            _ => "unknown"
        };
        string path = uri.AbsolutePath;
        bool setup = actor == Authorities.Setup;
        if (path == "/api/v1/groups" && method == "POST")
        {
            if (!setup || issued is null) return (403, new { }, false);
            string slug = body.GetProperty("slug").GetString()!;
            if (slug != issued.GroupSlug) return (400, new { }, false);
            Create("group", issued.GroupId); groups.Add(issued.GroupId, slug);
            return (200, new
            {
                id = issued.GroupId,
                orgId = Org,
                name = slug,
                slug,
                createdAt = Date,
                updatedAt = Date
            }, false);
        }
        if (issued is not null && path.StartsWith("/api/v1/groups/" + issued.GroupId + "/users/", StringComparison.Ordinal))
        {
            if (!setup) return (403, new { }, false);
            string username = Uri.UnescapeDataString(path.Split('/').Last());
            string user = users.Single(p => p.Value == username).Key;
            Create("group-member", user);
            groupMembers.Add(issued.GroupId, Fault == "wrong-group-membership" ? issued.Users[2].Principal : user);
            return (200, new { id = user, username }, false);
        }
        if (path.StartsWith("/api/v1/auth/token-auth/identities/", StringComparison.Ordinal))
        {
            if (!setup) return (403, new { }, false);
            string identity = path.Split('/')[6];
            if (!managed.Contains(identity)) return (404, new { }, false);
            if (!path.EndsWith("/tokens", StringComparison.Ordinal))
            {
                Create("auth", identity); auth.Add(identity);
                return (200, new
                {
                    identityTokenAuth = new
                    {
                        id = identity,
                        identityId = identity,
                        createdAt = Date,
                        updatedAt = Date,
                        accessTokenTTL = 600,
                        accessTokenMaxTTL = 600
                    }
                }, false);
            }
            if (!auth.Contains(identity)) return (403, new { }, false);
            string id = Id(), project = memberships.Single(m => m.Principal == identity).Project;
            Enroll("credential", id);
            byte[] bytes = NewMaterial();
            string hash = TemplatePrincipalContract.HashBytes(bytes);
            Create("credential", id);
            credentials.Add(hash, new(identity, id, bytes, "managed", project));
            issuers.Add(new(Id(), identity, id, hash, "managed", project, memberships.Single(m => m.Principal == identity).Id));
            return (200, new
            {
                tokenData = new
                {
                    id,
                    identityId = identity,
                    authMethod = "token-auth",
                    createdAt = Date,
                    updatedAt = Date
                },
                accessToken = Encoding.UTF8.GetString(bytes),
                tokenType = "Bearer",
                expiresIn = 600,
                accessTokenMaxTTL = 600
            }, false);
        }
        if (path.StartsWith("/api/v1/project-templates", StringComparison.Ordinal) && method is "POST" or "PATCH")
        {
            if (issued is null) return (403, new { }, false);
            bool original = armed && actor != Authorities.Setup;
            string request = Id();
            string id = path == "/api/v1/project-templates" ?
                body.GetProperty("name").GetString() == issued.SeedName ? issued.SeedId : issued.TemplateId :
                path.Split('/').Last();
            if (original)
            {
                if (fenced || originals != 0 || bodyHash != intent) return (409, new { }, true);
                originals++;
                ingress.Add(new(request, actor, method, path, bodyHash, actor == Authorities.Administrative));
            }
            if (!setup && actor != Authorities.Administrative) return (403, new { }, original);
            JsonElement configuration;
            string name;
            string previous = "";
            if (method == "PATCH")
            {
                if (!templates.TryGetValue(id, out var prior)) return (404, new { }, original);
                previous = prior.Revision; name = prior.Name;
                var merged = prior.Configuration.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone());
                foreach (var property in body.EnumerateObject())
                    if (Fault != "ignored-principal-update" || property.Name != TemplatePrincipalContract.Field(root!.Variant))
                        merged[property.Name] = property.Value.Clone();
                configuration = JsonSerializer.SerializeToElement(merged);
            }
            else { configuration = body.Clone(); name = body.GetProperty("name").GetString()!; }
            string revision = original ? "original-1" : "baseline-1";
            bool apply = !original || Fault != "lost-nonapplied";
            if (apply)
            {
                if (!templates.ContainsKey(id)) Create("template", id);
                if (original && Fault == "lost-partial" && templates.TryGetValue(id, out var partial))
                {
                    var fields = partial.Configuration.EnumerateObject().ToDictionary(p => p.Name, p => p.Value.Clone());
                    fields["roles"] = body.GetProperty("roles").Clone();
                    configuration = JsonSerializer.SerializeToElement(fields);
                }
                templates[id] = new(id, name, revision, configuration);
                if (original)
                    foreach (var field in new[] { "roles", "users", "groups", "projectManagedIdentities" })
                        if (body.TryGetProperty(field, out _) && (Fault != "lost-partial" || field == "roles"))
                            commits.Add(new(request, id, previous, revision,
                                TemplatePrincipalContract.Hash(configuration), field));
            }
            return (200, new { projectTemplate = TemplateWire(new(id, name, revision, configuration)) }, original);
        }
        if (path == "/api/v1/projects" && method == "POST")
        {
            if (!setup || issued is null) return (403, new { }, false);
            string templateName = body.GetProperty("template").GetString()!;
            var template = templates.Values.SingleOrDefault(t => t.Name == templateName);
            if (template is null) return (404, new { }, false);
            string slug = body.GetProperty("slug").GetString()!;
            string project = slug == issued.BeforeSlug ? issued.BeforeProject : slug == issued.AfterSlug ? issued.AfterProject : "";
            if (project.Length == 0) return (400, new { }, false);
            Create("project", project);
            string request = Id(), hash = TemplatePrincipalContract.Hash(template.Configuration);
            projects.Add(project, new(project, slug, template.Id, template.Revision, hash));
            Copy(template, project, request, hash);
            return (200, new
            {
                project = new
                {
                    id = project,
                    orgId = Org,
                    name = slug,
                    slug,
                    type = "secret-manager",
                    createdAt = Date,
                    updatedAt = Date,
                    _id = project,
                    environments = new[]
                    {
                        new { id = environmentIds[project + "/baseline"], name = "Baseline", slug = "baseline" },
                        new { id = environmentIds[project + "/witness"], name = "Witness", slug = "witness" },
                        new { id = environmentIds[project + "/outside"], name = "Outside", slug = "outside" }
                    },
                    deletedEnvironments = Array.Empty<object>()
                }
            }, false);
        }
        if (path.StartsWith("/api/v4/secrets/", StringComparison.Ordinal))
        {
            var query = uri.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
                .ToDictionary(p => p[0], p => Uri.UnescapeDataString(p.Length == 2 ? p[1] : ""));
            string project = method == "GET" ? query["projectId"] : body.GetProperty("projectId").GetString()!;
            string environment = method == "GET" ? query["environment"] : body.GetProperty("environment").GetString()!;
            string key = Uri.UnescapeDataString(path.Split('/').Last());
            string coordinate = project + "/" + environment + "/" + key;
            if (method == "POST")
            {
                if (!setup) return (403, new { }, false);
                byte[] value = Encoding.UTF8.GetBytes(body.GetProperty("secretValue").GetString()!);
                Copies.Add(value); privateCopies.Add(value);
                Create("secret", secretIds[coordinate]); secrets.Add(coordinate, value);
                return (200, new
                {
                    secret = new
                    {
                        id = secretIds[coordinate],
                        secretKey = key,
                        secretValue = Encoding.UTF8.GetString(value),
                        secretValueHidden = false,
                        version = 1,
                        type = "shared",
                        environment,
                        secretPath = "/",
                        workspace = project
                    }
                }, false);
            }
            bool allowed = actor == Authorities.Observer || setup;
            var matches = memberships.Where(m => m.Project == project &&
                (m.Principal == actor || m.GroupMember == actor)).ToArray();
            foreach (var membership in matches)
            {
                var policy = policies[membership.Id];
                allowed |= policy.Subject == "secrets" && policy.Action == "read" &&
                    policy.Environment == environment && policy.Path == query["secretPath"];
            }
            if (Fault == "wrong-principal" && credential is not null && issued!.Users[2].Principal == actor) allowed = true;
            if (Fault == "denied-accepted" && actor == Authorities.Denied) allowed = true;
            if (Fault == "valid-recheck-denied" && credential is not null &&
                access.Any(a => a.Credential == credential.Id && a.Allowed)) allowed = false;
            if (Fault == "host-runtime-access" && actor == Authorities.Runtime) allowed = true;
            if (window.Length != 0)
                access.Add(new(Id(), actor, credential?.Id ?? "host", tokenHash, project,
                    projects[project].Revision, key, environment, allowed,
                    allowed && secrets.TryGetValue(coordinate, out var stored) ? TemplatePrincipalContract.HashBytes(stored) : null));
            if (!allowed) return (403, new { }, false);
            if (!secrets.TryGetValue(coordinate, out var bytes)) return (404, new { }, false);
            return (200, new
            {
                secret = new
                {
                    id = secretIds[coordinate],
                    secretKey = key,
                    secretValue = Encoding.UTF8.GetString(bytes),
                    secretValueHidden = false,
                    version = 1,
                    type = "shared",
                    environment,
                    secretPath = "/",
                    workspace = project
                }
            }, false);
        }
        return (404, new { }, false);
    }
    private void Copy(TemplateRow template, string project, string request, string configurationHash)
    {
        bool after = project == issued!.AfterProject;
        foreach (string environment in new[] { "baseline", "witness", "outside" })
            Create("environment", environmentIds[project + "/" + environment]);
        foreach (string role in new[] { issued.ReaderRole, issued.MarkerRole }) Create("role", roleIds[project + "/" + role]);
        if (after && Fault == "ignored-copy") return;
        string policyEnvironment = template.Configuration.GetProperty("roles")[0].GetProperty("permissions")[0]
            .GetProperty("conditions").GetProperty("environment").GetString()!;
        var permission = template.Configuration.GetProperty("roles")[0].GetProperty("permissions")[0];
        if (after && Fault == "unchanged-copied-roles") policyEnvironment = "baseline";
        string policyHash = TemplatePrincipalContract.Hash(new[] { "secrets", "read", policyEnvironment, "/" });
        foreach (string field in new[] { "users", "groups", "projectManagedIdentities" })
        {
            if (!template.Configuration.TryGetProperty(field, out var values) || values.ValueKind == JsonValueKind.Null) continue;
            foreach (var value in values.EnumerateArray())
            {
                string kind, principal;
                string? group = null, member = null;
                if (field == "users")
                {
                    kind = "user";
                    principal = users.Single(p => p.Value == value.GetProperty("username").GetString()).Key;
                    if (after && Fault == "copied-wrong-user") principal = issued.Users[2].Principal;
                }
                else if (field == "groups")
                {
                    kind = "group";
                    principal = groups.Single(p => p.Value == value.GetProperty("groupSlug").GetString()).Key;
                    group = principal; member = groupMembers.GetValueOrDefault(principal);
                }
                else
                {
                    kind = "managed"; principal = after ? issued.AfterManaged : issued.BeforeManaged;
                    Create("managed", principal); managed.Add(principal);
                }
                string[] roles = value.GetProperty("roles").EnumerateArray().Select(r => r.GetString()!).ToArray();
                if (after && Fault == "unchanged-copied-roles") roles = [issued.ReaderRole];
                if (after && Fault == "extra-copied-role") roles = [.. roles, "admin"];
                string membershipId = membershipIds[project + "/" + kind];
                Create("membership", membershipId);
                policies.Add(membershipId, (permission.GetProperty("subject").GetString()!,
                    permission.GetProperty("action").GetString()!, policyEnvironment,
                    permission.GetProperty("conditions").GetProperty("secretPath").GetString()!));
                memberships.Add(new(membershipId, request, template.Id, template.Revision, configurationHash, project, principal, kind,
                    roles, policyHash, group, member));
            }
        }
    }
    private object TemplateWire(TemplateRow row)
    {
        var fields = row.Configuration.EnumerateObject().ToDictionary(p => p.Name, p => (object?)p.Value);
        fields["id"] = row.Id; fields["orgId"] = Org; fields["name"] = row.Name; fields["type"] = "secret-manager";
        fields["createdAt"] = Date; fields["updatedAt"] = Date;
        foreach (string field in new[] { "users", "groups", "identities", "projectManagedIdentities" })
            fields.TryAdd(field, Array.Empty<object>());
        return fields;
    }
    public async ValueTask DisposeAsync()
    {
        shutdown.Cancel(); responseRelease.TrySetResult(); OpenRelease.TrySetResult(); listener.Stop();
        await accept; await Task.WhenAll(connections);
        foreach (var bytes in Copies) CryptographicOperations.ZeroMemory(bytes);
        foreach (var key in keys.Values) key.Dispose();
        Source.Dispose(); shutdown.Dispose();
    }
}
