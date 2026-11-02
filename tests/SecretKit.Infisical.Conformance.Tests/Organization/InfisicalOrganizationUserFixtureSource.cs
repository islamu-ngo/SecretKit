using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Separate source service model. Measurements read independent issuer, provider
// storage, request, access and cleanup journals, never the SDK response.
internal sealed class InfisicalOrganizationUserFixtureSource(InfisicalOrganizationUserFixture provider)
    : IOrganizationUserSource
{
    public OrganizationUserSourceKind Kind => OrganizationUserSourceKind.ControlledFixture;
    public string Identity => "controlled-organization-user-source";
    private readonly Dictionary<string, Session> sessions = [];
    private readonly HashSet<string> consumed = [];
    private long sequence;
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Observations { get; private set; }
    internal int Registrations => sessions.Values.Count(s => !s.Closed);
    internal bool LoseResponse { get; set; }
    internal List<OrganizationUserFence> Fences { get; } = [];
    internal List<OrganizationUserCleanup> Cleanups { get; } = [];
    internal List<(string Root, string State)> IssuerWorkJournal { get; } = [];
    internal int IssuerAborts { get; private set; }
    internal System.Collections.Concurrent.ConcurrentBag<byte[]> PrivateCopies { get; } = [];
    internal TaskCompletionSource IssuerEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource IssuerRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal bool PauseIssuer { get; set; }
    private sealed class Session(OrganizationUserRoot root, string registration)
    {
        internal OrganizationUserRoot Root { get; } = root;
        internal string Registration { get; } = registration;
        internal int Stage { get; set; }
        internal bool Closed { get; set; }
        internal OrganizationUserIssuance? Issued { get; set; }
        internal OrganizationUserWindow? Window { get; set; }
        internal OrganizationUserArm? Arm { get; set; }
        internal OrganizationUserIntent? Intent { get; set; }
        internal bool IssuerPending { get; set; }
        internal CancellationTokenSource IssuerAbort { get; } = new();
        internal TaskCompletionSource IssuerFinished { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }
    internal IOrganizationUserSource CreateClient(Func<int, byte[]>? allocate = null) =>
        new InfisicalOrganizationUserSource(new(new(new("https://organization-source.invalid/"),
            "source-capability-token", Identity, 15), new Channel(this), allocate), Identity, Kind);

    private sealed class Channel(InfisicalOrganizationUserFixtureSource source) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(token);
            source.PrivateCopies.Add(bytes);
            try
            {
                if (request.Headers.Authorization?.Parameter != "source-capability-token") return new(HttpStatusCode.Forbidden);
                using var document = JsonDocument.Parse(bytes);
                var command = document.RootElement;
                T Read<T>(string field) => command.GetProperty(field).Deserialize<T>(OrganizationUserContract.Options)!;
                var root = Read<OrganizationUserRoot>("root");
                object facts;
                switch (request.RequestUri!.Segments.Last())
                {
                    case "reserve":
                        using (var capability = SecretMaterial.FromText(command.GetProperty("capability").GetString()!))
                            facts = await source.ReserveAsync(root, capability, token);
                        break;
                    case "open": facts = await source.OpenAsync(root, token); break;
                    case "begin": facts = await source.BeginAsync(root, Read<string>("phase"), token); break;
                    case "observe": facts = await source.ObserveAsync(root, Read<string>("phase"), token); break;
                    case "arm": facts = await source.ArmAsync(root, Read<OrganizationUserIntent>("intent"), token); break;
                    case "settle": facts = await source.SettleAsync(root, Read<OrganizationUserReceipt>("receipt"), token); break;
                    case "close": facts = await source.CloseAsync(root, token); break;
                    default: throw new NativeCaseFailureException("observer-unavailable");
                }
                try
                {
                    byte[] reply = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schemaVersion = 1,
                        nonce = command.GetProperty("nonce").GetString(),
                        observerIdentity = source.Identity,
                        observedAt = DateTimeOffset.UtcNow,
                        facts
                    }, OrganizationUserContract.Options);
                    source.PrivateCopies.Add(reply);
                    return new(HttpStatusCode.OK) { Content = new PrivateContent(reply) };
                }
                finally { if (facts is OrganizationUserIssuance issuance) issuance.Erase(); }
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
    private Session Enter(OrganizationUserRoot root, int stage)
    {
        if (!sessions.TryGetValue(root.Id, out var session) || session.Root != root ||
            session.Closed || session.Stage != stage || !consumed.Add(root.Id + "/" + stage))
            throw new NativeCaseFailureException("observer-unavailable");
        session.Stage++;
        return session;
    }
    private OrganizationUserScopeClock Clock(OrganizationUserRoot root) => new(root.Deployment,
        "provider-application-clock", root.Epoch, ++sequence, new(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
    private OrganizationUserStamp Stamp(Session session)
    {
        var stamp = new OrganizationUserStamp(session.Root, session.Registration,
            Guid.NewGuid().ToString(), Clock(session.Root));
        if (provider.Fault == "duplicate-event") stamp = stamp with { Event = "repeated-event" };
        if (session.Stage >= 2)
            stamp = provider.Fault switch
            {
                "wrong-epoch" => stamp with { Clock = stamp.Clock with { Epoch = "other-epoch" } },
                "wrong-deployment" => stamp with { Clock = stamp.Clock with { Deployment = "other-deployment" } },
                "wrong-clock" => stamp with { Clock = stamp.Clock with { Authority = "host-wall-clock" } },
                "stale-sequence" => stamp with { Clock = stamp.Clock with { Sequence = 1 } },
                "regressed-time" => stamp with { Clock = stamp.Clock with { At = stamp.Clock.At.AddSeconds(-1) } },
                "non-utc" => stamp with { Clock = stamp.Clock with { At = stamp.Clock.At.ToOffset(TimeSpan.FromHours(1)) } },
                "wrong-registration" => stamp with { Registration = "other-registration" },
                "wrong-root" => stamp with { Root = stamp.Root with { Nonce = "other-nonce" } },
                _ => stamp
            };
        return stamp;
    }
    public ValueTask<OrganizationUserReservation> ReserveAsync(OrganizationUserRoot root,
        SecretMaterial capability, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            if (root.Source != Kind || root.SourceIdentity != Identity || root.Authorities != InfisicalOrganizationUserFixture.Authorities ||
                root.OrganizationId != InfisicalOrganizationUserFixture.Org || root.Origin != provider.Origin.AbsoluteUri ||
                capability.Reveal() != "private-user-issuer-capability" || sessions.ContainsKey(root.Id))
                throw new NativeCaseFailureException("missing-input");
            var session = new Session(root, Guid.NewGuid().ToString());
            sessions.Add(root.Id, session);
            Enter(root, 0);
            provider.Reserve(root);
            if (provider.Fault == "lost-reserve") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(new OrganizationUserReservation(Stamp(session), true, true,
                provider.Fault != "unqualified-issuance", true, [], provider.Borrowed()));
        }
    }
    public async ValueTask<OrganizationUserIssuance> OpenAsync(OrganizationUserRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Session session;
        lock (provider.Gate)
        {
            session = Enter(root, 1); Opens++;
            session.IssuerPending = true;
            IssuerWorkJournal.Add((root.Id, "enrolled"));
        }
        try
        {
            if (PauseIssuer)
            {
                using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, session.IssuerAbort.Token);
                IssuerEntered.TrySetResult();
                await IssuerRelease.Task.WaitAsync(linked.Token);
            }
            lock (provider.Gate)
            {
                int partial = provider.Fault.StartsWith("lost-open-", StringComparison.Ordinal) ?
                    int.Parse(provider.Fault["lost-open-".Length..]) : int.MaxValue;
                var result = provider.Issue(root, Stamp(session), partial);
                session.Issued = result with
                { Principals = result.Principals.Select(p => p with { Credential = [] }).ToArray() };
                if (provider.Fault == "lost-open") { result.Erase(); throw new NativeCaseFailureException("observer-unavailable"); }
                if (provider.Fault == "credential-wrong-user")
                {
                    var selected = result.Principals[0];
                    selected.Erase();
                    var wrong = result.Principals[^1];
                    result.Principals[0] = selected with { Credential = wrong.Credential.ToArray(), CredentialHash = wrong.CredentialHash };
                }
                if (provider.Fault == "credential-unbound")
                    result.Principals[0] = result.Principals[0] with { CredentialId = "unissued-id" };
                if (provider.Fault == "membership-wrong-user")
                    result.Principals[0] = result.Principals[0] with { UserId = InfisicalOrganizationUserFixture.BorrowedUser };
                if (provider.Fault == "inventory-missing") result = result with { Inventory = result.Inventory[..^1] };
                return result;
            }
        }
        catch (OperationCanceledException) when (session.IssuerAbort.IsCancellationRequested)
        { throw new NativeCaseFailureException("observer-unavailable"); }
        finally
        {
            lock (provider.Gate)
            {
                session.IssuerPending = false;
                IssuerWorkJournal.Add((root.Id, session.IssuerAbort.IsCancellationRequested ? "aborted" : "terminal"));
                session.IssuerFinished.TrySetResult();
            }
        }
    }
    public ValueTask<OrganizationUserWindow> BeginAsync(OrganizationUserRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 2 : 6);
            if (phase is not ("before" or "after")) throw new NativeCaseFailureException("observer-unavailable");
            provider.Begin(root, phase);
            session.Window = new(Stamp(session), phase, true, provider.Fault != "unheld-window");
            return ValueTask.FromResult(session.Window);
        }
    }
    public ValueTask<OrganizationUserObservation> ObserveAsync(OrganizationUserRoot root, string phase, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, phase == "before" ? 3 : 7);
            Observations++;
            var access = provider.AccessJournal.Where(a => a.Root == root.Id && a.Phase == phase)
                .Select(a => a.Access).ToArray();
            var rows = provider.State(root, phase);
            provider.End(root);
            if (provider.Fault == "storage-wrong-role" && phase == "after" && rows.Length > 0)
                rows[0] = rows[0] with { Role = "invented-role" };
            if (provider.Fault == "access-wrong-principal" && access.Length > 0)
                access[0] = access[0] with { PrincipalId = "other-principal" };
            if (provider.Fault == "access-wrong-credential" && access.Length > 0)
                access[0] = access[0] with { CredentialId = "other-credential" };
            if (provider.Fault == "access-replayed" && access.Length > 1)
                access[1] = access[1] with { RequestId = access[0].RequestId };
            return ValueTask.FromResult(new OrganizationUserObservation(Stamp(session), session.Window!.Stamp.Event,
                phase, provider.Fault != "incomplete-inventory", provider.Fault != "metadata-echo",
                provider.Fault != "unqualified-access", provider.Fault != "credential-reissued",
                rows, access, provider.Borrowed()));
        }
    }
    public ValueTask<OrganizationUserArm> ArmAsync(OrganizationUserRoot root, OrganizationUserIntent intent,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 4);
            session.Intent = intent;
            provider.Arm(root, intent);
            session.Arm = new(Stamp(session), true, provider.Fault != "unexclusive-ingress", 1);
            return ValueTask.FromResult(session.Arm);
        }
    }
    public ValueTask<OrganizationUserFence> SettleAsync(OrganizationUserRoot root, OrganizationUserReceipt receipt,
        CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var session = Enter(root, 5);
            provider.Fence(root); // Real terminal gate in the controlled provider.
            var requests = provider.RequestJournal.Where(r => r.Root == root.Id).ToArray();
            var commits = provider.MembershipJournal.Where(r => r.Root == root.Id).ToArray();
            var intent = session.Intent!;
            bool exact = requests.All(r => r.Actor == root.Authorities.Selected(root.Case) &&
                r.Method == intent.Method && r.MembershipIds.SequenceEqual(intent.MembershipIds) &&
                r.Role == intent.Role && r.Active == intent.Active) &&
                commits.All(c => requests.Any(r => r.Id == c.Request));
            var outcome = commits.Length == 0 ? OrganizationUserOutcome.NonApplied :
                commits.Length == intent.MembershipIds.Length ? OrganizationUserOutcome.Applied : OrganizationUserOutcome.Partial;
            var result = new OrganizationUserFence(Stamp(session), session.Arm!.Stamp.Event, receipt,
                requests.Select(r => r.Id).ToArray(), commits.Select(c => c.Membership).ToArray(), outcome,
                exact && provider.Fault != "wrong-original-actor", provider.Fault != "nonterminal",
                provider.Fault != "late-work", requests.Length <= 1 && provider.Fault != "replayed-original", 0);
            if (provider.Fault == "receipt-substituted")
                result = result with { Receipt = receipt with { Evidence = DispatchEvidence.Applied } };
            if (provider.Fault == "extra-original") result = result with { RequestIds = ["first", "second"] };
            Fences.Add(result);
            if (provider.Fault == "lost-settle") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(result);
        }
    }
    public async ValueTask<OrganizationUserCleanup> CloseAsync(OrganizationUserRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        Session session;
        OrganizationUserResource[] issued;
        Task? issuer = null;
        lock (provider.Gate)
        {
            if (!sessions.TryGetValue(root.Id, out var selected) || selected.Root != root || selected.Closed)
                throw new NativeCaseFailureException("cleanup-incomplete");
            session = selected;
            session.Closed = true;
            Closes++;
            issued = provider.Close(root); // durable creation/dispatch fences precede abort/drain
            if (session.IssuerPending)
            {
                IssuerAborts++;
                issuer = session.IssuerFinished.Task; // subscribe before cancellation
                session.IssuerAbort.Cancel();
            }
        }
        if (issuer is not null) await issuer.WaitAsync(token);
        lock (provider.Gate)
        {
            var result = new OrganizationUserCleanup(root, Identity, Clock(root), true,
                provider.Fault != "cleanup-creation-fence", provider.Fault != "cleanup-dispatch-fence",
                provider.Fault != "cleanup-terminal", true, session.IssuerPending ? 1 : 0, 0, 0, issued,
                provider.RemainingInventory(root), provider.Borrowed(), provider.BorrowedPreserved);
            if (provider.Fault == "cleanup-inventory") result = result with { CompleteIssuanceInventory = false };
            if (provider.Fault == "cleanup-pending-issuer") result = result with { PendingIssuers = 1 };
            if (provider.Fault == "cleanup-pending-dispatch") result = result with { PendingDispatches = 1 };
            if (provider.Fault == "cleanup-registration") result = result with { Registrations = 1 };
            if (provider.Fault == "cleanup-copies") result = result with { PrivateCopiesReleased = false };
            if (provider.Fault == "cleanup-epoch") result = result with { Clock = result.Clock with { Epoch = "other" } };
            if (provider.Fault == "cleanup-root") result = result with { Root = root with { Nonce = "other" } };
            Cleanups.Add(result);
            session.IssuerAbort.Dispose();
            return result;
        }
    }
}
