using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// One owned loopback provider with independently captured subsystems. The source
// coordinator never authors snapshots for those writers to sign.
internal sealed class InfisicalAuthTemplatePermissionFixture : IAsyncDisposable
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
    private readonly InfisicalAuthTemplatePermissionStorage storage;
    private readonly InfisicalAuthTemplatePermissionIssuer issuer;
    private readonly InfisicalAuthTemplatePermissionOwnership ownership;
    private readonly InfisicalAuthTemplatePermissionIngress ingress;
    private readonly InfisicalAuthTemplatePermissionPolicy policy;
    private readonly InfisicalAuthTemplatePermissionMembership membership = new();
    private readonly InfisicalAuthTemplatePermissionAccess access;
    private readonly InfisicalAuthTemplatePermissionCollection collection;
    private readonly InfisicalAuthTemplatePermissionJournal[] journals;
    private readonly MemberPermissionBorrowed[] borrowed;
    private AuthTemplatePermissionRoot? root;
    private AuthTemplatePermissionPlan? plan;
    private AuthTemplatePermissionActor[] actors = [];
    private int stage;
    private bool closing, closed, armed, settled, acceptingPatches;
    private Task? delayedIssuer;
    internal string Fault { get; }
    internal Uri Origin { get; }
    internal AuthTemplatePermissionProfile Profile { get; }
    internal InfisicalAuthTemplatePermissionFixtureSource Source { get; }
    internal ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource OpenEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource OpenRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DispatchRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource StorageEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource StorageRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource CloseEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Originals { get; private set; }
    internal int Generated => storage.Bindings.Length;
    internal int Remaining => storage.Remaining;
    internal int Registrations => root is not null && !closed ? 1 : 0;
    internal int ConnectionCount => connections.Count;
    internal AuthTemplatePermissionPacket? ClosedPacket { get; private set; }
    internal bool BorrowedPreserved => Borrowed().SequenceEqual(borrowed);
    internal InfisicalAuthTemplatePermissionFixture(string fault = "")
    {
        Fault = fault; storage = new(fault); issuer = new(storage); storage.ObserveIssuer(issuer);
        ownership = new(storage); ingress = new(issuer); policy = new(storage, ingress, fault);
        access = new(ingress, policy, membership, fault); collection = new(storage, ingress, access, fault);
        journals = [ownership, issuer, storage, policy, membership, ingress, access, collection];
        Profile = new("controlled-auth-template", "controlled-epoch", "history-v1", journals.Select(j => j.Pin).ToArray());
        borrowed = Borrowed(); listener.Start(); Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        Source = new(this); accept = AcceptAsync();
    }
    private MemberPermissionBorrowed[] Borrowed() => hostTokens.Select(p => new MemberPermissionBorrowed("host-credential", p.Key,
        AuthTemplatePermissionContract.Hash(p.Value))).Concat(journals.Select(j => new MemberPermissionBorrowed("host-key", j.Pin.Writer,
            AuthTemplatePermissionContract.Hash(j.Pin.Spki)))).Concat([new MemberPermissionBorrowed("borrowed-template",
                "30000000-0000-0000-0000-000000000001", "unchanged-borrowed-state")]).ToArray();
    internal AuthTemplatePermissionInput Input(string operation, AuthTemplatePermissionAction action) =>
        new(new(new("https://auth-template-source.invalid/"), "coordinator-token", "auth-template-coordinator", 30),
            "auth-template-capability", Profile, action, 30);
    internal NativeEnvironment Environment(string operation, AuthTemplatePermissionAction action, bool configured = true)
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
                    authTemplatePermission = Input(operation, action)
                }
            }
        }, AuthTemplatePermissionContract.Options)!;
        if (!configured) scope["scopes"]!["local"]!.AsObject().Remove("authTemplatePermission");
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
            { ["C08-IM-RoleChanges"] = scope, ["C08-IM-ManagementClient"] = scope }
        }, AuthTemplatePermissionContract.Options));
    }
    internal AuthTemplatePermissionRoot Root(string operation, AuthTemplatePermissionAction action, string boundary) =>
        new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"), Origin.AbsoluteUri, Organization, operation,
            AuthTemplatePermissionContract.Variant(action), boundary, "local", "auth-template-coordinator", MemberPermissionSourceKind.ControlledFixture,
            action, Authorities, Profile);
    private AuthTemplatePermissionIssued Issued => new(storage.Bindings, actors);
    private string Id(string key) => storage.Id(key);
    internal AuthTemplatePermissionPacket Step(AuthTemplatePermissionRoot selected, AuthTemplatePermissionStep step, string? capability)
    {
        lock (gate)
        {
            if (step == AuthTemplatePermissionStep.Reserve)
            {
                AuthTemplatePermissionContract.Require(root is null && capability == "auth-template-capability" && selected.Origin == Origin.AbsoluteUri &&
                    selected.Organization == Organization && selected.Authorities == Authorities && selected.Kind == MemberPermissionSourceKind.ControlledFixture &&
                    selected.Source == "auth-template-coordinator" && AuthTemplatePermissionVerifier.Same(selected.Profile, Profile));
                root = selected; plan = new(selected);
                foreach (var journal in journals) journal.Enroll(selected);
                ownership.Reserve(Borrowed());
                if (Fault == "collision") throw new NativeCaseFailureException("observer-unavailable");
            }
            AuthTemplatePermissionContract.Require(root is not null && AuthTemplatePermissionVerifier.Same(root, selected) && !closed &&
                (step == AuthTemplatePermissionStep.Close || stage == (int)step));
            if (step != AuthTemplatePermissionStep.Close) stage++;
            switch (step)
            {
                case AuthTemplatePermissionStep.Open: Open(); break;
                case AuthTemplatePermissionStep.Before:
                case AuthTemplatePermissionStep.After: acceptingPatches = true; break;
                case AuthTemplatePermissionStep.ObserveBefore:
                case AuthTemplatePermissionStep.ObserveAfter: acceptingPatches = false; break;
                case AuthTemplatePermissionStep.Arm: armed = true; break;
                case AuthTemplatePermissionStep.Settle: settled = true; armed = false; break;
                case AuthTemplatePermissionStep.Close:
                    AuthTemplatePermissionContract.Require(closing && (delayedIssuer is null || delayedIssuer.IsCompletedSuccessfully));
                    Closes++;
                    foreach (var journal in journals) journal.Fence();
                    policy.Clear(); membership.Clear(); storage.Clear();
                    if (Fault == "borrowed-change") hostTokens[Authorities.Observer] = "changed";
                    ownership.Close(Borrowed()); foreach (var actor in actors) actor.Erase();
                    closed = true; acceptingPatches = armed = false; break;
            }
            var packet = new AuthTemplatePermissionPacket(journals.Select(j => j.Publish(selected, step)).ToArray(), step == AuthTemplatePermissionStep.Open ? actors : []);
            if (step == AuthTemplatePermissionStep.Close)
            {
                ClosedPacket = packet;
                foreach (var journal in journals) foreach (var bytes in journal.ReleaseCaptures()) Copies.Add(bytes);
            }
            return packet;
        }
    }
    private void Open()
    {
        Opens++; storage.Create(AuthTemplatePermissionPlan.OtherOrganization);
        if (Fault == "partial-open") throw new NativeCaseFailureException("observer-unavailable");
        foreach (var host in hostTokens) issuer.Host(host.Key, host.Value);
        actors = Enumerable.Range(0, 5).Select(i =>
        { storage.Create(plan!.ActorKey(i)); var actor = issuer.Issue(i); Copies.Add(actor.Credential); return actor; }).ToArray();
        policy.Bootstrap(actors[0]);
        for (int i = 0; i < 5; i++)
        {
            var b = storage.Create("member-" + i); var actor = actors[i].Identity;
            membership.Assign("bootstrap", new(b.CanonicalId, actor.Principal, actor.Kind, actor.Organization, "", "no-access", true, "accepted", ""));
        }
        storage.Seed(AuthTemplatePermissionPlan.Selected); storage.Seed(AuthTemplatePermissionPlan.Peer); storage.Seed("foreign");
        if (Fault == "delayed-issuer") { delayedIssuer = DelayedIssuerAsync(); throw new NativeCaseFailureException("observer-unavailable"); }
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
                    AuthTemplatePermissionContract.Require(length is >= 0 and <= 131072);
                    body = new byte[length]; Copies.Add(body); await stream.ReadExactlyAsync(body, ingressStop.Token);
                    credential = Encoding.ASCII.GetBytes(lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase))?.Split(' ').Last() ?? "");
                    Copies.Add(credential);
                    bool admitted, delayStorage; IDisposable? work;
                    lock (gate)
                    {
                        admitted = !closing && !closed;
                        delayStorage = Fault == "delayed-storage" && settled;
                        work = admitted ? ingress.AdmitDispatch() : null;
                    }
                    using var admission = work;
                    if (admitted && Fault == "delayed-dispatch" && request[0] != "GET" && request[1].StartsWith(AuthTemplatePermissionContract.Path, StringComparison.Ordinal))
                    {
                        DispatchEntered.TrySetResult(); await DispatchRelease.Task.WaitAsync(shutdown.Token);
                    }
                    using var storageWork = admitted && request[0] != "GET" && request[1].StartsWith(AuthTemplatePermissionContract.Path, StringComparison.Ordinal) ? storage.AdmitStorage() : null;
                    if (storageWork is not null && delayStorage)
                    {
                        StorageEntered.TrySetResult(); await StorageRelease.Task.WaitAsync(shutdown.Token);
                    }
                    (int Status, object Body) result;
                    lock (gate)
                    {
                        result = Handle(request[0], new Uri(Origin, request[1]).PathAndQuery, credential, body, admitted);
                        // Capture completion precedes the response becoming
                        // observable. Transport draining is a separate boundary.
                        storageWork?.Dispose(); work?.Dispose();
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
        bool create = AuthTemplatePermissionContract.Create(root.Operation);
        if (path == AuthTemplatePermissionEffects.OriginalPath(root, Issued) && method == (create ? "POST" : "PATCH"))
        {
            if (!armed || settled || Originals != 0) return (409, new { });
            Originals++; using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            var request = ingress.Capture(bearer, method, path, bytes, AuthTemplatePermissionContract.RawHash(bytes), "original");
            var decision = access.Decide(request, "original"); if (!decision.Allowed) return (403, new { });
            policy.Apply(request, bytes, actors[0]);
            return (200, new
            {
                role = new
                {
                    id = Id(AuthTemplatePermissionPlan.Policy).Length == 0 ? Guid.NewGuid().ToString() : Id(AuthTemplatePermissionPlan.Policy),
                    orgId = Organization,
                    name = plan.Slug,
                    slug = plan.Slug,
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:01Z",
                    permissions = body.GetProperty("permissions").Clone()
                }
            });
        }
        if (settled && method == "PATCH" && path == "/api/v2/organizations/" + Organization + "/memberships/" + Id("member-0"))
        {
            using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
            var request = ingress.Capture(bearer, method, path, bytes, AuthTemplatePermissionContract.RawHash(bytes), "activation");
            var decision = access.Decide(request, "activation"); if (!decision.Allowed) return (403, new { });
            AuthTemplatePermissionContract.Require(body.GetProperty("role").GetString() == plan.Slug);
            var old = membership.Inventory.Single(m => m.Id == Id("member-0"));
            if (Fault != "assignment-echo")
            {
                var assignment = storage.Create("assignment", request.Id, request.BodyHash);
                membership.Assign(request.Id, old with { Role = Id(AuthTemplatePermissionPlan.Policy), Slug = plan.Slug, Assignment = assignment.CanonicalId });
            }
            return (200, new
            {
                membership = new
                {
                    id = old.Id,
                    orgId = Organization,
                    role = plan.Slug,
                    roleId = Id(AuthTemplatePermissionPlan.Policy),
                    userId = old.Principal,
                    status = "accepted",
                    isActive = true,
                    createdAt = "2026-01-01T00:00:00Z",
                    updatedAt = "2026-01-01T00:00:01Z"
                }
            });
        }
        if (!path.StartsWith(AuthTemplatePermissionContract.Path, StringComparison.Ordinal)) return (404, new { });
        bool individual = method == "GET" && path.StartsWith(AuthTemplatePermissionContract.Path + "/", StringComparison.Ordinal) &&
            !path.StartsWith(AuthTemplatePermissionContract.Path + "/search?", StringComparison.Ordinal);
        bool observer = individual && issuer.Authenticate(bearer).Principal == Authorities.Observer;
        if (!observer && !acceptingPatches && !admitted) return (403, new { });
        string action = method == "POST" ? "create-templates" : method == "PATCH" ? "edit-templates" : method == "DELETE" ? "delete-templates" :
            path.Contains("?authMethod=", StringComparison.Ordinal) ? "attach-templates" : "list-templates";
        string intent = method is "POST" or "PATCH" ? TemplateIntent(bytes, method == "POST") : "";
        string phase = observer ? "observer" : individual ? path.EndsWith("/usage", StringComparison.Ordinal) ? "template-usage" : "template-get" : "template";
        var r = ingress.Capture(bearer, method, path, bytes, intent, phase); var d = access.Decide(r, action);
        if (method == "GET")
        {
            var rows = collection.Read(r, d);
            if (!d.Allowed) return (403, new { });
            // No link is seeded or created by this unit. Usage is an actual empty
            // association collection for an existing selected, owned template.
            if (phase == "template-usage") return rows.Length == 0 ? (404, new { }) : (200, Array.Empty<object>());
            if (phase == "template-get") return rows.Length == 0 ? (404, new { }) : (200, Wire(rows.Single()));
            if (observer) return rows.Length == 0 ? (404, new { }) : (200, Wire(rows.Single()));
            return path.Contains("/search?", StringComparison.Ordinal) ? (200, new { templates = rows.Select(Wire).ToArray(), totalCount = rows.Length }) : (200, rows.Select(Wire).ToArray());
        }
        var stored = storage.Apply(r, d, ingress, access, bytes);
        if (!d.Allowed) return (403, new { });
        return method == "DELETE" ? (200, new { message = "Template deleted" }) : (200, Wire(stored!));
    }
    private static string TemplateIntent(byte[] bytes, bool create)
    {
        using var document = JsonDocument.Parse(bytes);
        return WireHash(new object?[] { "kubernetes", document.RootElement });
    }
    private static object Wire(AuthTemplatePermissionState state) => new
    {
        id = state.Id,
        orgId = state.Organization,
        name = state.Name,
        authMethod = state.Method,
        createdAt = state.CreatedAt,
        updatedAt = state.UpdatedAt,
        templateFields = new
        {
            tokenReviewMode = state.Configuration.Mode,
            kubernetesHost = state.Configuration.Host,
            caCert = state.Configuration.Ca,
            verifyTlsCertificate = state.Configuration.VerifyTls,
            allowedAudience = state.Configuration.Audience,
            hasTokenReviewerJwt = state.Configuration.HasCredential
        }
    };
    private static string WireHash(object value)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        try { return AuthTemplatePermissionContract.RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
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
    internal Task DrainAsync()
    {
        // Unconfigured original factories can still open a transport without
        // enrolling a source root. Close that read boundary explicitly instead
        // of waiting for the client's connection-pool idle timer.
        if (root is null) ingressStop.Cancel();
        return Task.WhenAll(connections);
    }
    public async ValueTask DisposeAsync()
    {
        OpenRelease.TrySetResult(); IssuerRelease.TrySetResult(); DispatchRelease.TrySetResult(); StorageRelease.TrySetResult();
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
