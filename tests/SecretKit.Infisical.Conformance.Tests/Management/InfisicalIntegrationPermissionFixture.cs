using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// The HTTP provider, not the source coordinator, captures authenticated requests.
// A single case owns one bounded root. The commit lock serializes synchronous
// native taps; admitted asynchronous issuer/dispatch work is separately drained.
internal sealed class InfisicalIntegrationPermissionFixture : IAsyncDisposable
{
    internal const string Organization = "10000000-0000-0000-0000-000000000001";
    internal static MemberPermissionAuthorities Authorities => InfisicalMemberPermissionFixture.Authorities;
    private readonly object gate = new();
    private readonly TcpListener listener = new(IPAddress.Loopback, 0);
    private readonly CancellationTokenSource shutdown = new(), ingressStop = new();
    private readonly ConcurrentBag<Task> connections = [];
    private readonly Task accept;
    private readonly Dictionary<string, string> hostTokens = new()
    {
        [Authorities.Setup] = "setup",
        [Authorities.Runtime] = "runtime",
        [Authorities.Denied] = "denied",
        [Authorities.Administrative] = "administrative",
        [Authorities.Observer] = "observer"
    };
    private readonly InfisicalIntegrationPermissionStorage storage;
    private readonly InfisicalIntegrationPermissionIssuer issuer;
    private readonly InfisicalIntegrationPermissionOwnership ownership;
    private readonly InfisicalIntegrationPermissionIngress ingress;
    private readonly InfisicalIntegrationPermissionPolicy policy;
    private readonly InfisicalIntegrationPermissionMembership membership = new();
    private readonly InfisicalIntegrationPermissionAccess access;
    private readonly InfisicalIntegrationPermissionCollection collection;
    private readonly InfisicalIntegrationPermissionJournal[] journals;
    private readonly MemberPermissionBorrowed[] borrowed;
    private IntegrationPermissionRoot? root;
    private IntegrationPermissionPlan? plan;
    private IntegrationPermissionActor[] actors = [];
    private int stage;
    private bool closing, closed, armed, settled, acceptingReads;
    private Task? delayedIssuer;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal IntegrationPermissionProfile Profile { get; }
    internal InfisicalIntegrationPermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Originals { get; private set; }
    internal int Generated => storage.Bindings.Length;
    internal int Remaining => storage.Remaining;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int ConnectionCount => connections.Count;
    internal IntegrationPermissionPacket? ClosedPacket { get; private set; }
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal string Progress => $"stage={stage};opens={Opens};originals={Originals};closes={Closes};remaining={Remaining}";
    internal InfisicalIntegrationPermissionFixture(string fault = "")
    {
        Fault = fault; storage = new(fault); issuer = new(storage); storage.ObserveIssuer(issuer);
        ownership = new(storage); ingress = new(issuer); policy = new(storage, ingress, fault);
        access = new(ingress, policy, membership, fault); collection = new(storage, access, fault);
        journals = [ownership, issuer, storage, policy, membership, ingress, access, collection];
        Profile = new("controlled-integrations", "controlled-epoch", "history-v1", journals.Select(j => j.Pin).ToArray());
        borrowed = Borrowed(); listener.Start();
        Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/"); Source = new(this); accept = AcceptAsync();
    }
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key,
        IntegrationPermissionContract.Hash(p.Value))).Concat(journals.Select(j => new MemberPermissionBorrowed("host-key", j.Pin.Writer,
            IntegrationPermissionContract.Hash(j.Pin.Spki)))).Concat([new MemberPermissionBorrowed("borrowed-project",
                "30000000-0000-0000-0000-000000000001", "unchanged-borrowed-state")]).ToArray();
    internal IntegrationPermissionInput Input(string operation, IntegrationPermissionAction action) =>
        new(new(new("https://integration-source.invalid/"), "coordinator-token", "integration-coordinator", 30),
            "integration-capability", Profile, IntegrationPermissionScope.Project, IntegrationPermissionContract.ActorKind(operation), action, 30);
    internal NativeEnvironment Environment(string operation, IntegrationPermissionAction action, bool configured = true)
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
                    integrationPermission = Input(operation, action)
                }
            }
        }, IntegrationPermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("integrationPermission");
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
        }, IntegrationPermissionContract.Options));
    }
    internal IntegrationPermissionRoot Root(string operation, IntegrationPermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            IntegrationPermissionContract.Variant(action), boundary, "local", "integration-coordinator", MemberPermissionSourceKind.ControlledFixture,
            IntegrationPermissionScope.Project, IntegrationPermissionContract.ActorKind(operation), action, Authorities, Profile);
    private IntegrationPermissionIssued Issued => new(storage.Bindings, actors);
    private string Id(string key) => storage.Id(key);
    internal IntegrationPermissionPacket Step(IntegrationPermissionRoot selected, IntegrationPermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == IntegrationPermissionStep.Reserve)
            {
                IntegrationPermissionContract.Require(root is null && capability == "integration-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && IntegrationPermissionVerifier.Same(selected.Profile, Profile));
                root = selected; plan = new(selected);
                foreach (var journal in journals) journal.Enroll(selected);
                ownership.Reserve(Borrowed());
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            IntegrationPermissionContract.Require(root is not null && IntegrationPermissionVerifier.Same(root, selected) && !closed &&
                (step == IntegrationPermissionStep.Close || stage == (int)step));
            if (step != IntegrationPermissionStep.Close) stage++;
            switch (step)
            {
                case IntegrationPermissionStep.Open: Open(); break;
                case IntegrationPermissionStep.Before:
                case IntegrationPermissionStep.After: acceptingReads = true; break;
                case IntegrationPermissionStep.ObserveBefore:
                case IntegrationPermissionStep.ObserveAfter: acceptingReads = false; break;
                case IntegrationPermissionStep.Arm: armed = true; break;
                case IntegrationPermissionStep.Settle: settled = true; armed = false; break;
                case IntegrationPermissionStep.Close:
                    IntegrationPermissionContract.Require(closing && (delayedIssuer is null || delayedIssuer.IsCompletedSuccessfully));
                    Closes++;
                    foreach (var journal in journals) journal.Fence();
                    policy.Clear(); membership.Clear(); storage.Clear();
                    if (Fault == "borrowed-change") hostTokens[Authorities.Observer] = "changed";
                    ownership.Close(Borrowed());
                    foreach (var actor in actors) actor.Erase();
                    closed = true; acceptingReads = armed = false;
                    break;
            }
            var packet = new IntegrationPermissionPacket(journals.Select(j => j.Publish(selected, step)).ToArray(),
                step == IntegrationPermissionStep.Open ? actors : []);
            if (step == IntegrationPermissionStep.Close)
            {
                ClosedPacket = packet;
                foreach (var journal in journals)
                    foreach (var bytes in journal.ReleaseCaptures()) Copies.Add(bytes);
            }
            return packet;
        }
    }
    private void Open()
    {
        Opens++; storage.Create(IntegrationPermissionPlan.Project);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        storage.Create(IntegrationPermissionPlan.OtherProject);
        foreach (var host in hostTokens) issuer.Host(host.Key, host.Value);
        actors = Enumerable.Range(0, 3).Select(i =>
        {
            if (plan!.ActorKey(i).StartsWith('@')) return new IntegrationPermissionActor(issuer.Host(Id(plan.ActorKey(i)), hostTokens[Id(plan.ActorKey(i))]), []);
            storage.Create(plan.ActorKey(i)); var actor = issuer.Issue(i); Copies.Add(actor.Credential); return actor;
        }).ToArray();
        policy.Bootstrap(actors[0]);
        for (int i = 0; i < 3; i++)
        {
            var b = storage.Create("member-" + i); var actor = actors[i].Identity;
            bool assigned = i == 0 && !IntegrationPermissionContract.Create(root!.Operation) && !IntegrationPermissionContract.Template(root.Operation);
            string assignment = assigned && actor.Kind == MemberPermissionActorKind.User ? storage.Create("assignment").CanonicalId : "";
            membership.Assign("bootstrap", new(b.CanonicalId, actor.Principal, actor.Kind, Organization, Id(IntegrationPermissionPlan.Project),
                assigned ? Id(plan!.PolicyKey) : "", assigned ? plan!.Slug : "no-access", true, "accepted", assignment));
        }
        storage.Seed(IntegrationPermissionPlan.Project); storage.Seed(IntegrationPermissionPlan.OtherProject);
        if (Fault == "delayed-issuer")
        {
            delayedIssuer = DelayedIssuerAsync(); throw new NativeCaseFailureException("observer-unavailable");
        }
        if (Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
    }
    private async Task DelayedIssuerAsync()
    {
        using var admitted = issuer.AdmitProvisioning();
        IssuerEntered.TrySetResult(); await IssuerRelease.Task.WaitAsync(shutdown.Token);
        lock (gate) storage.Create("deferred"); // Admitted before closing; drain precedes fencing and deletion.
    }
    private async Task AcceptAsync()
    {
        try
        {
            while (!shutdown.IsCancellationRequested)
            {
                var socket = await listener.AcceptTcpClientAsync(shutdown.Token);
                connections.Add(ServeAsync(socket));
            }
        }
        catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
    }
    private async Task ServeAsync(TcpClient socket)
    {
        using (socket)
        {
            var stream = socket.GetStream();
            while (!ingressStop.IsCancellationRequested)
            {
                byte[] header = new byte[32768], body = [], credential = [], response = []; Copies.Add(header);
                try
                {
                    int count = 0;
                    while (count < header.Length)
                    {
                        if (await stream.ReadAsync(header.AsMemory(count, 1), ingressStop.Token) == 0) return;
                        count++;
                        if (count >= 4 && header.AsSpan(count - 4, 4).SequenceEqual("\r\n\r\n"u8)) break;
                    }
                    string[] lines = Encoding.ASCII.GetString(header, 0, count).Split("\r\n");
                    string[] request = lines[0].Split(' ');
                    int length = int.Parse(lines.FirstOrDefault(l => l.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))?.Split(':')[1].Trim() ?? "0",
                        System.Globalization.CultureInfo.InvariantCulture);
                    IntegrationPermissionContract.Require(length is >= 0 and <= 131072);
                    body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, ingressStop.Token);
                    credential = Encoding.ASCII.GetBytes(lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "");
                    Copies.Add(credential);
                    bool admitted; IDisposable? work;
                    lock (gate)
                    {
                        admitted = !closing && !closed && (request[0] != "GET" || acceptingReads);
                        work = admitted ? ingress.AdmitDispatch() : null;
                    }
                    using var admission = work;
                    if (admitted && Fault == "delayed-dispatch" && request[0] == "GET")
                    {
                        DispatchEntered.TrySetResult(); await DispatchRelease.Task.WaitAsync(shutdown.Token);
                    }
                    (int Status, object Body) result;
                    lock (gate)
                    {
                        result = Handle(request[0], new Uri(Origin, request[1]).AbsolutePath, credential, body, admitted);
                        // Capture completion precedes the response becoming
                        // observable. Transport draining is a separate boundary.
                        work?.Dispose();
                    }
                    // There is no denial payload in this bounded protocol. A zero
                    // length response also avoids asynchronous error-body drains
                    // opening fresh sockets between sequential denied probes.
                    response = result.Status == 403 ? [] : JsonSerializer.SerializeToUtf8Bytes(result.Body); Copies.Add(response);
                    await stream.WriteAsync(Encoding.ASCII.GetBytes($"HTTP/1.1 {result.Status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {response.Length}\r\n\r\n"), shutdown.Token);
                    await stream.WriteAsync(response, shutdown.Token);
                }
                catch (IOException) { return; }
                catch (OperationCanceledException) when (shutdown.IsCancellationRequested || ingressStop.IsCancellationRequested) { return; }
                finally
                {
                    CryptographicOperations.ZeroMemory(header); CryptographicOperations.ZeroMemory(body);
                    CryptographicOperations.ZeroMemory(credential); CryptographicOperations.ZeroMemory(response);
                }
            }
        }
    }
    private (int, object) Handle(string method, string path, byte[] bearer, byte[] bytes, bool admitted)
    {
        if (root is null || plan is null || actors.Length == 0 || closed || closing && !admitted) return (403, new { });
        bool template = IntegrationPermissionContract.Template(root.Operation), create = IntegrationPermissionContract.Create(root.Operation),
            privilege = root.ActorKind == MemberPermissionActorKind.Machine;
        if (path == IntegrationPermissionEffects.OriginalPath(root, plan, Issued) && method == (create ? "POST" : "PATCH"))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++;
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            string intent = IntegrationPermissionContract.RawHash(bytes);
            if (privilege) intent = WireHash(new object?[] { plan.ProjectSlug, Id("member-0"), create ? null : Id(plan.PolicyKey), body });
            var r = ingress.Capture(bearer, method, path, bytes, intent, "original");
            var d = access.Decide(r, Id(IntegrationPermissionPlan.Project));
            if (!d.Allowed) return (403, new { });
            policy.Apply(r, bytes, actors[0]);
            if (privilege && policy.Inventory.Any(p => p.Actions.Contains("read"))) Assign(r.Id);
            var permissions = template ? body.GetProperty("roles")[0].GetProperty("permissions") : body.GetProperty("permissions");
            var result = new JsonObject
            {
                ["id"] = Id(plan.PolicyKey).Length == 0 ? Guid.NewGuid().ToString() : Id(plan.PolicyKey),
                ["slug"] = plan.Slug,
                ["createdAt"] = "2026-01-01T00:00:00Z",
                ["updatedAt"] = "2026-01-01T00:00:01Z",
                ["permissions"] = JsonNode.Parse(permissions.GetRawText())
            };
            if (template)
            {
                result.Remove("slug"); result.Remove("permissions"); result["name"] = plan.Slug; result["orgId"] = Organization; result["type"] = "secret-manager";
                result["groups"] = new JsonArray(); result["identities"] = new JsonArray(); result["projectManagedIdentities"] = new JsonArray();
                foreach (string key in new[] { "roles", "environments", "users" }) result[key] = JsonNode.Parse(body.GetProperty(key).GetRawText());
            }
            else if (privilege) result["isTemporary"] = false;
            else { result["name"] = plan.Slug; result["projectId"] = Id(IntegrationPermissionPlan.Project); }
            return (200, new JsonObject { [template ? "projectTemplate" : privilege ? "privilege" : "role"] = result });
        }
        if (settled && (path == "/api/v1/projects" && method == "POST" ||
            path == "/api/v1/projects/" + Id(IntegrationPermissionPlan.Project) + "/memberships/" + Id("member-0") && method == "PATCH"))
        {
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            var r = ingress.Capture(bearer, method, path, bytes, template ? IntegrationPermissionContract.RawHash(bytes) : WireHash(new object?[] { null, body }), "activation");
            var d = access.Decide(r, Id(IntegrationPermissionPlan.Project));
            if (!d.Allowed) return (403, new { });
            if (template)
            {
                IntegrationPermissionContract.Require(body.GetProperty("template").GetString() == plan.Slug && body.GetProperty("slug").GetString() == plan.CopySlug &&
                    !body.GetProperty("shouldCreateDefaultEnvs").GetBoolean());
                storage.Copy(r, policy.Inventory.Single(), policy.Configuration, policy, membership, actors[0]);
                return (200, new
                {
                    project = new
                    {
                        id = Id(IntegrationPermissionPlan.CopyProject),
                        _id = Id(IntegrationPermissionPlan.CopyProject),
                        orgId = Organization,
                        name = plan.CopySlug,
                        slug = plan.CopySlug,
                        type = "secret-manager",
                        createdAt = "2026-01-01T00:00:00Z",
                        updatedAt = "2026-01-01T00:00:00Z",
                        environments = Array.Empty<object>(),
                        deletedEnvironments = Array.Empty<object>()
                    }
                });
            }
            IntegrationPermissionContract.Require(body.GetProperty("roles")[0].GetProperty("role").GetString() == plan.Slug);
            if (Fault != "assignment-echo")
            {
                storage.Create("assignment", r.Id, r.BodyHash);
                Assign(r.Id);
            }
            return (200, new
            {
                roles = new[] { new { id = Id("assignment").Length == 0 ? Guid.NewGuid().ToString() : Id("assignment"), projectMembershipId = Id("member-0"), role = plan.Slug, isTemporary = false,
                    createdAt = "2026-01-01T00:00:00Z", updatedAt = "2026-01-01T00:00:01Z" } }
            });
        }
        if (method == "GET" && path.StartsWith("/api/v1/projects/", StringComparison.Ordinal) && path.EndsWith("/integrations", StringComparison.Ordinal))
        {
            if (!acceptingReads && !admitted) return (403, new { });
            string project = path.Split('/')[4];
            var r = ingress.Capture(bearer, method, path, bytes, "", "read");
            var d = access.Decide(r, project); var result = collection.Read(d);
            return (d.Allowed ? 200 : 403, d.Allowed ? new { integrations = result.Rows.Select(Wire).ToArray() } : new object());
        }
        return (404, new { });
    }
    private void Assign(string request)
    {
        var old = membership.Inventory.Single(m => m.Id == Id("member-0"));
        membership.Assign(request, old with
        {
            Role = Id(plan!.PolicyKey),
            Slug = plan.Slug,
            Assignment = old.Kind == MemberPermissionActorKind.User ? Id("assignment") : ""
        });
    }
    private static object Wire(IntegrationPermissionMetadata m)
    {
        var value = JsonSerializer.SerializeToNode(new
        {
            id = m.Id,
            isActive = m.IsActive,
            integration = m.Integration,
            integrationAuthId = m.AuthorizationId,
            envId = m.EnvironmentId,
            environment = new { id = m.EnvironmentId, name = m.EnvironmentName, slug = m.EnvironmentSlug },
            createdAt = m.CreatedAt,
            updatedAt = m.UpdatedAt,
            url = m.Url,
            app = m.App,
            appId = m.AppId,
            targetEnvironment = m.TargetEnvironment,
            targetEnvironmentId = m.TargetEnvironmentId,
            targetService = m.TargetService,
            targetServiceId = m.TargetServiceId,
            owner = m.Owner,
            path = m.Path,
            region = m.Region,
            scope = m.Scope,
            secretPath = m.SecretPath,
            lastUsed = m.LastUsed,
            lastSyncJobId = m.LastSyncJobId,
            isSynced = m.IsSynced
        })!;
        // This optional SDK field allows absence, not an explicit JSON null.
        if (m.SecretPath is null) value.AsObject().Remove("secretPath");
        return value;
    }
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return IntegrationPermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal async Task SealAndDrainAsync()
    {
        lock (gate) { closing = true; CloseEntered.TrySetResult(); }
        // New issuer work and dispatch are rejected by closing under the same
        // admission lock. Cancel partial transports, drain previously admitted
        // work, THEN fence each synchronous store and delete only enrolled IDs.
        ingressStop.Cancel();
        if (delayedIssuer is not null) await delayedIssuer;
        await Task.WhenAll(connections);
    }
    internal Task DrainAsync() => Task.WhenAll(connections);
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); DispatchRelease.TrySetResult();
        if (delayedIssuer is not null) await delayedIssuer;
        ingressStop.Cancel(); shutdown.Cancel(); listener.Stop();
        try { await accept; } catch (SocketException) when (shutdown.IsCancellationRequested) { }
        await Task.WhenAll(connections);
        foreach (var actor in actors) actor.Erase();
        foreach (var journal in journals) journal.Dispose();
        Source.Dispose(); ingressStop.Dispose(); shutdown.Dispose();
        foreach (var bytes in Copies) CryptographicOperations.ZeroMemory(bytes);
        Copies.Clear(); connections.Clear(); actors = []; root = null; plan = null; ClosedPacket = null;
    }
}
