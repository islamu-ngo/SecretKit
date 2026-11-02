using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalWorkloadTransitionFixtureSource(InfisicalWorkloadTransitionFixture provider) : IWorkloadTransitionSource
{
    public string Identity => "controlled-workload-source";
    public WorkloadTransitionSourceKind Kind => WorkloadTransitionSourceKind.ControlledFixture;
    private readonly Dictionary<string, Session> sessions = [];
    private long sequence;
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations => sessions.Values.Count(s => !s.Closed);
    internal List<WorkloadTransitionFence> Fences { get; } = [];
    internal List<WorkloadTransitionCleanup> Cleanups { get; } = [];
    internal bool PauseIssuer { get; set; }
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal List<string> IssuerWork { get; } = [];
    private System.Collections.Concurrent.ConcurrentBag<byte[]> Copies => provider.Copies;
    private sealed class Session(WorkloadTransitionRoot root)
    {
        internal WorkloadTransitionRoot Root { get; } = root;
        internal string Registration { get; } = Guid.NewGuid().ToString();
        internal int Stage;
        internal bool Closed, Pending;
        internal CancellationTokenSource Abort { get; } = new();
        internal TaskCompletionSource Finished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal WorkloadTransitionIssuance? Issued;
        internal WorkloadTransitionWindow? Window;
        internal WorkloadTransitionArm? Arm;
    }
    internal IWorkloadTransitionSource CreateClient() => new InfisicalWorkloadTransitionSource(new(new(
        new("https://workload-source.invalid/"), "source-channel-token", Identity, 15), new Channel(this), length =>
        {
            byte[] bytes = new byte[length]; provider.Copies.Add(bytes); return bytes;
        }), Identity, Kind);
    private sealed class Channel(InfisicalWorkloadTransitionFixtureSource source) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            source.Copies.Add(bytes);
            try
            {
                if (request.Headers.Authorization?.Parameter != "source-channel-token") return new(HttpStatusCode.Forbidden);
                if (!request.RequestUri!.AbsolutePath.StartsWith("/workload-transition/", StringComparison.Ordinal))
                    return new(HttpStatusCode.NotFound);
                using var document = JsonDocument.Parse(bytes);
                NativeRunProtocol.RejectDuplicates(document.RootElement);
                var command = document.RootElement;
                var root = command.GetProperty("root").Deserialize<WorkloadTransitionRoot>(WorkloadTransitionContract.Options)!;
                object facts = request.RequestUri.Segments.Last() switch
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
                byte[] reply = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    nonce = command.GetProperty("nonce").GetString(),
                    observerIdentity = source.Identity,
                    observedAt = DateTimeOffset.UtcNow,
                    facts
                }, WorkloadTransitionContract.Options);
                source.Copies.Add(reply);
                return new(HttpStatusCode.OK) { Content = new PrivateContent(reply) };
                async ValueTask<WorkloadTransitionReservation> Reserve()
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
    private Session Enter(WorkloadTransitionRoot root, int stage)
    {
        WorkloadTransitionContract.Require(sessions.TryGetValue(root.Id, out var session) &&
            WorkloadTransitionContract.SameRoot(session.Root, root) && !session.Closed && !session.Pending && session.Stage == stage);
        session!.Stage++; return session;
    }
    private WorkloadTransitionStamp Stamp(Session session) => new(session.Root, session.Registration,
        Guid.NewGuid().ToString(), ++sequence, new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
    public ValueTask<WorkloadTransitionReservation> ReserveAsync(WorkloadTransitionRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            WorkloadTransitionContract.Require(root.Source == Identity && root.Kind == Kind &&
                root.Origin == provider.Origin.AbsoluteUri && root.Organization == InfisicalWorkloadTransitionFixture.Organization &&
                root.Authorities == InfisicalWorkloadTransitionFixture.Authorities &&
                root.Profile.Revision == "controlled-workload-v1" && root.Profile.Deployment == "controlled-deployment" &&
                root.Profile.Epoch == "controlled-epoch" && capability.Reveal() == "workload-capability" &&
                !sessions.ContainsKey(root.Id), "missing-input");
            var session = new Session(root); sessions.Add(root.Id, session); Enter(root, 0);
            provider.Reserve(root);
            if (provider.Fault == "lost-reserve") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(new WorkloadTransitionReservation(Stamp(session), true, true,
                provider.Fault != "unenrolled", provider.Borrowed));
        }
    }
    public async ValueTask<WorkloadTransitionIssuance> OpenAsync(WorkloadTransitionRoot root, CancellationToken token)
    {
        Session session;
        lock (provider.Gate)
        {
            session = Enter(root, 1); session.Pending = true; Opens++;
            // Work enrollment precedes the pause as well as all resource creation.
            provider.Enroll("issuer-work", root.Id);
            IssuerWork.Add("enrolled:" + root.Id);
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
                session.Abort.Token.ThrowIfCancellationRequested();
                session.Issued = provider.Bootstrap(Stamp(session));
                if (provider.Fault == "lost-open") throw new NativeCaseFailureException("observer-unavailable");
                return session.Issued;
            }
        }
        finally
        {
            lock (provider.Gate)
            {
                session.Pending = false; IssuerWork.Add("terminal:" + root.Id); session.Finished.TrySetResult();
            }
        }
    }
    public ValueTask<WorkloadTransitionWindow> BeginAsync(WorkloadTransitionRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 2 : 6);
            session.Window = new(Stamp(session), phase, true, provider.Fault != "unheld-window");
            provider.Begin(session.Window.Stamp.Event);
            return ValueTask.FromResult(session.Window);
        }
    }
    public ValueTask<WorkloadTransitionObservation> ObserveAsync(WorkloadTransitionRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 3 : 7);
            string window = session.Window!.Stamp.Event;
            var snapshots = provider.Snapshot(window);
            var ingress = provider.Ingress.Where(i => i.Event.Window == window).ToArray();
            var reviews = provider.Reviews.Where(r => r.Event.Window == window).ToArray();
            var tokens = provider.IssuedTokens.Where(t => t.Event.Window == window).ToArray();
            var access = provider.Access.Where(a => a.Event.Window == window).ToArray();
            // Faults alter one independent journal, never the effect predicate.
            if (provider.Fault == "review-revision") reviews = reviews.Select(r =>
                r with { ConfigurationRevision = "unrelated-revision" }).ToArray();
            if (provider.Fault == "review-duplicate" && reviews.Length > 0) reviews = [.. reviews, reviews[0]];
            if (provider.Fault == "access-principal") access = access.Select(a =>
                a with { Identity = root.Authorities.Runtime }).ToArray();
            if (provider.Fault == "wrong-epoch") ingress = ingress.Select(i =>
                i with { Event = i.Event with { Epoch = "different-epoch" } }).ToArray();
            if (provider.Fault == "wrong-deployment") ingress = ingress.Select(i =>
                i with { Event = i.Event with { Deployment = "different-deployment" } }).ToArray();
            if (provider.Fault == "journal-schema") ingress = ingress.Select(i =>
                i with { Event = i.Event with { Schema = "unqualified-v2" } }).ToArray();
            if (provider.Fault == "duplicate-request" && ingress.Length > 1)
                ingress[1] = ingress[1] with { RequestId = ingress[0].RequestId };
            provider.End();
            return ValueTask.FromResult(new WorkloadTransitionObservation(Stamp(session), window, phase, true,
                provider.Target, provider.Control, snapshots, ingress, reviews, tokens, access, provider.Borrowed));
        }
    }
    public ValueTask<WorkloadTransitionArm> ArmAsync(WorkloadTransitionRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 4);
            session.Arm = new(Stamp(session), WorkloadTransitionContract.Intent(root, session.Issued!), true, 1);
            provider.Arm(session.Arm.Stamp.Event);
            if (provider.Fault == "lost-arm") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(session.Arm);
        }
    }
    public ValueTask<WorkloadTransitionFence> SettleAsync(WorkloadTransitionRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 5); provider.SealDispatch();
            string arm = session.Arm!.Stamp.Event;
            var commits = provider.Storage.Where(s => s.Event.Window == arm).ToArray();
            if (provider.Fault == "source-echo")
            {
                // A lying coordinator upgrades the SDK echo to invented storage
                // lineage, including plausible writer labels. Actual after-login
                // validation and fresh access MUST still disprove this assertion.
                var writer = root.Profile.Journals.Single(j => j.Kind == "storage");
                commits = [new(new(root.Id, root.Nonce, root.Profile.Deployment, root.Profile.Epoch,
                    root.Profile.Revision, "storage", writer.Writer, writer.Schema, Guid.NewGuid().ToString(),
                    provider.Storage.Max(s => s.Event.Sequence) + 1, arm),
                    provider.Ingress.Single(i => i.Event.Window == arm).RequestId, session.Issued!.Target.Identity,
                    session.Issued.Baseline.Revision,
                    WorkloadTransitionContract.Expected(root, session.Issued) with { Revision = "invented-echo" })];
            }
            if (provider.Fault == "commit-cause") commits = commits.Select(c => c with { CauseRequest = "unrelated-ingress" }).ToArray();
            if (provider.Fault == "commit-predecessor") commits = commits.Select(c => c with { PreviousRevision = "unrelated" }).ToArray();
            var facts = new WorkloadTransitionFence(Stamp(session), arm, provider.Fault != "unterminated",
                true, provider.Fault != "replay", 0,
                provider.Ingress.Where(i => i.Event.Window == arm).ToArray(), commits);
            Fences.Add(facts); return ValueTask.FromResult(facts);
        }
    }
    public async ValueTask<WorkloadTransitionCleanup> CloseAsync(WorkloadTransitionRoot root, CancellationToken token)
    {
        Session session;
        Task? pending;
        lock (provider.Gate)
        {
            WorkloadTransitionContract.Require(sessions.TryGetValue(root.Id, out var found) &&
                WorkloadTransitionContract.SameRoot(found.Root, root) && !found.Closed);
            session = found!; session.Closed = true; Closes++;
            if (provider.Owns(root)) { provider.SealCreation(); provider.SealDispatch(); }
            session.Abort.Cancel();
            pending = session.Pending ? session.Finished.Task : null;
        }
        if (pending is not null) await pending.WaitAsync(token);
        await provider.DrainAsync(token);
        lock (provider.Gate)
        {
            bool owns = provider.Owns(root);
            if (owns) provider.Close();
            var facts = new WorkloadTransitionCleanup(Stamp(session), true, true,
                provider.Fault != "cleanup-incomplete-inventory", 0, session.Closed ? 0 : 1,
                owns ? provider.Inventory.Where(r => provider.Fault != "cleanup-token-inventory" || r.Kind != "token").ToArray() : [],
                owns ? provider.RemainingInventory : [], provider.Borrowed);
            Cleanups.Add(facts); return facts;
        }
    }
}
