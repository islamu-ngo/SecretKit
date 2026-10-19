using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private control service, separate from the native list endpoint. No expected
// native page/result is sent to this source. Measurements use provider journals.
internal sealed class InfisicalProjectTypeFixtureSource(InfisicalProjectTypeFixture provider) : IProjectTypeSource
{
    public ProjectTypeSourceKind Kind => ProjectTypeSourceKind.ControlledFixture;
    public string Identity => "controlled-project-type-source";
    private readonly Dictionary<string, Session> sessions = [];
    private readonly HashSet<string> consumed = [];
    private long sequence;
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Observations { get; private set; }
    internal int Registrations => sessions.Values.Count(s => !s.Closed);
    internal List<ProjectTypeFence> Fences { get; } = [];
    internal List<ProjectTypeCleanup> Cleanups { get; } = [];
    internal List<(string Root, string State)> IssuerWorkJournal { get; } = [];
    internal System.Collections.Concurrent.ConcurrentBag<byte[]> Copies { get; } = [];
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal bool PauseIssuer { get; set; }
    private sealed class Session(ProjectTypeRoot root)
    {
        internal ProjectTypeRoot Root { get; } = root;
        internal string Registration { get; } = Guid.NewGuid().ToString();
        internal int Stage { get; set; }
        internal bool Closed { get; set; }
        internal bool Pending { get; set; }
        internal CancellationTokenSource Abort { get; } = new();
        internal TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal ProjectTypeWindow? Window { get; set; }
        internal ProjectTypeArm? Arm { get; set; }
    }
    internal IProjectTypeSource CreateClient() => new InfisicalProjectTypeSource(new(new(
        new("https://project-source.invalid/"), "source-capability-token", Identity, 15), new Channel(this)), Identity, Kind);
    private sealed class Channel(InfisicalProjectTypeFixtureSource source) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            source.Copies.Add(bytes);
            try
            {
                if (request.Headers.Authorization?.Parameter != "source-capability-token") return new(HttpStatusCode.Forbidden);
                if (!request.RequestUri!.AbsolutePath.StartsWith("/project-type/", StringComparison.Ordinal))
                    return new(HttpStatusCode.NotFound);
                using var document = JsonDocument.Parse(bytes);
                NativeRunProtocol.RejectDuplicates(document.RootElement);
                var command = document.RootElement;
                var root = command.GetProperty("root").Deserialize<ProjectTypeRoot>(ProjectTypeContract.Options)!;
                object facts = request.RequestUri!.Segments.Last() switch
                {
                    "reserve" => await Reserve(),
                    "open" => await source.OpenAsync(root, token),
                    "begin" => await source.BeginAsync(root, command.GetProperty("phase").GetString()!, token),
                    "observe" => await source.ObserveAsync(root, command.GetProperty("phase").GetString()!, token),
                    "arm" => await source.ArmAsync(root, token),
                    "settle" => await source.SettleAsync(root, token),
                    "close" => await source.CloseAsync(root, token),
                    _ => throw new NativeCaseFailureException("observer-unavailable")
                };
                var reply = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    nonce = command.GetProperty("nonce").GetString(),
                    observerIdentity = source.Identity,
                    observedAt = DateTimeOffset.UtcNow,
                    facts
                }, ProjectTypeContract.Options);
                source.Copies.Add(reply);
                return new(HttpStatusCode.OK) { Content = new PrivateContent(reply) };
                async ValueTask<ProjectTypeReservation> Reserve()
                {
                    using var capability = SecretMaterial.FromText(command.GetProperty("capability").GetString()!);
                    return await source.ReserveAsync(root, capability, token);
                }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    private sealed class PrivateContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal PrivateContent(byte[] bytes) : base(bytes) { this.bytes = bytes; }
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
            base.Dispose(disposing);
        }
    }
    private Session Enter(ProjectTypeRoot root, int stage)
    {
        if (!sessions.TryGetValue(root.Id, out var session) || session.Root != root || session.Closed ||
            session.Stage != stage || !consumed.Add(root.Id + "/" + stage))
            throw new NativeCaseFailureException("observer-unavailable");
        session.Stage++;
        return session;
    }
    private ProjectTypeClock Clock(ProjectTypeRoot root) =>
        new(root.Deployment, root.Epoch, "provider-application-clock", ++sequence,
            new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private ProjectTypeStamp Stamp(Session session)
    {
        var stamp = new ProjectTypeStamp(session.Root, session.Registration, Guid.NewGuid().ToString(), Clock(session.Root));
        if (session.Stage >= 2) stamp = provider.Fault switch
        {
            "wrong-epoch" => stamp with { Clock = stamp.Clock with { Epoch = "other-epoch" } },
            "wrong-deployment" => stamp with { Clock = stamp.Clock with { Deployment = "other-deployment" } },
            "wrong-clock" => stamp with { Clock = stamp.Clock with { Authority = "host-wall-clock" } },
            "stale-sequence" => stamp with { Clock = stamp.Clock with { Sequence = 1 } },
            "wrong-root" => stamp with { Root = stamp.Root with { Nonce = "other-nonce" } },
            "wrong-revision" => stamp with { Root = stamp.Root with { ProviderRevision = "other-revision" } },
            "wrong-registration" => stamp with { Registration = "other-registration" },
            "wrong-source" => stamp with { Root = stamp.Root with { SourceIdentity = "other-source" } },
            "duplicate-event" => stamp with { Event = "repeated-event" },
            _ => stamp
        };
        return stamp;
    }
    public ValueTask<ProjectTypeReservation> ReserveAsync(ProjectTypeRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            ProjectTypeContract.Require(root.Source == Kind && root.SourceIdentity == Identity &&
                root.Authorities == InfisicalProjectTypeFixture.Authorities &&
                root.OrganizationId == InfisicalProjectTypeFixture.Org && root.Origin == provider.Origin.AbsoluteUri &&
                root.Deployment == "controlled-deployment" && root.Epoch == "controlled-epoch" &&
                root.ProviderRevision == "controlled-project-v1" && root.Scope == "local" &&
                root.Operation == ProjectTypeContract.Operation && ProjectTypeContract.Cases.Contains(root.Case) &&
                capability.Reveal() == "private-project-type-capability" && !sessions.ContainsKey(root.Id), "missing-input");
            var session = new Session(root); sessions.Add(root.Id, session);
            Enter(root, 0); provider.Reserve(root);
            if (provider.Fault == "lost-reserve") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(new ProjectTypeReservation(Stamp(session), true, true,
                provider.Fault != "unqualified-issuance", true, [], provider.Borrowed()));
        }
    }
    public async ValueTask<ProjectTypeIssuance> OpenAsync(ProjectTypeRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Session session;
        lock (provider.Gate)
        {
            session = Enter(root, 1); Opens++; session.Pending = true;
            IssuerWorkJournal.Add((root.Id, "enrolled"));
        }
        try
        {
            if (PauseIssuer)
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.Abort.Token);
                IssuerEntered.TrySetResult();
                await IssuerRelease.Task.WaitAsync(linked.Token);
            }
            lock (provider.Gate)
            {
                var rows = provider.Issue(root);
                if (provider.Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                var inventory = provider.Inventory(root);
                if (provider.Fault == "inventory-missing") inventory = inventory[..^1];
                return new(Stamp(session), true, true, rows, inventory);
            }
        }
        catch (OperationCanceledException) when (session.Abort.IsCancellationRequested)
        { throw new NativeCaseFailureException("observer-unavailable"); }
        finally
        {
            lock (provider.Gate)
            {
                session.Pending = false;
                IssuerWorkJournal.Add((root.Id, session.Abort.IsCancellationRequested ? "aborted" : "terminal"));
                session.Finished.TrySetResult();
            }
        }
    }
    public ValueTask<ProjectTypeWindow> BeginAsync(ProjectTypeRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 2 : 6);
            ProjectTypeContract.Require(phase is "before" or "after");
            provider.Begin(root, phase);
            session.Window = new(Stamp(session), phase, true, provider.Fault != "unheld-window");
            return ValueTask.FromResult(session.Window);
        }
    }
    public ValueTask<ProjectTypeObservation> ObserveAsync(ProjectTypeRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 3 : 7); Observations++;
            var rows = provider.State(root, phase);
            var access = provider.AccessJournal.Where(a => a.Root == root.Id && a.Phase == phase).Select(a => a.Access).ToArray();
            provider.End(root);
            if (provider.Fault == "storage-incomplete") rows = rows[..^1];
            if (provider.Fault == "access-wrong-actor" && access.Length > 0)
                access[0] = access[0] with { Actor = "other-actor" };
            if (provider.Fault == "access-wrong-query" && access.Length > 0)
                access[0] = access[0] with { Query = new(SecretKit.Infisical.Management.ProjectType.Pam, null) };
            if (provider.Fault == "access-replay" && access.Length > 1)
                access[1] = access[1] with { RequestId = access[0].RequestId };
            return ValueTask.FromResult(new ProjectTypeObservation(Stamp(session), session.Window!.Stamp.Event, phase,
                provider.Fault != "incomplete-inventory", provider.Fault != "source-echo",
                provider.Fault != "source-echo", provider.Fault != "unqualified-access", rows, access, provider.Borrowed()));
        }
    }
    public ValueTask<ProjectTypeArm> ArmAsync(ProjectTypeRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 4); provider.Arm(root);
            session.Arm = new(Stamp(session), true, provider.Fault != "unexclusive-ingress", 1);
            return ValueTask.FromResult(session.Arm);
        }
    }
    public ValueTask<ProjectTypeFence> SettleAsync(ProjectTypeRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 5); provider.Fence(root);
            var requests = provider.RequestJournal.Where(r => r.Root == root.Id).Select(r => r.Request).ToArray();
            if (provider.Fault == "wrong-original-actor" && requests.Length > 0)
                requests[0] = requests[0] with { Actor = root.Authorities.Runtime };
            if (provider.Fault == "wrong-original-query" && requests.Length > 0)
                requests[0] = requests[0] with { Query = new(null, null) };
            if (provider.Fault == "replayed-original" && requests.Length > 0) requests = [.. requests, requests[0]];
            var result = new ProjectTypeFence(Stamp(session), session.Arm!.Stamp.Event,
                provider.Fault != "nonterminal", provider.Fault != "late-work", true, 0, requests);
            Fences.Add(result);
            return ValueTask.FromResult(result);
        }
    }
    public async ValueTask<ProjectTypeCleanup> CloseAsync(ProjectTypeRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Session session;
        bool pending;
        lock (provider.Gate)
        {
            ProjectTypeContract.Require(sessions.TryGetValue(root.Id, out var found) && found.Root == root && !found.Closed);
            session = found!; session.Closed = true; Closes++;
            provider.SealCreation(root); provider.Fence(root); pending = session.Pending;
            session.Abort.Cancel();
        }
        if (pending) await session.Finished.Task.WaitAsync(token);
        lock (provider.Gate)
        {
            var issued = provider.Close(root);
            var result = new ProjectTypeCleanup(root, Identity, Clock(root), true, true, true, true,
                0, 0, 0, issued, provider.RemainingInventory(root), provider.Borrowed(), provider.BorrowedPreserved);
            Cleanups.Add(result);
            return result;
        }
    }
}
