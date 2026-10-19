using System.Net;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Measures the independent provider's committed encrypted storage and journals.
// It cannot create effects from an expected row or the returned SDK metadata.
internal sealed class InfisicalBulkAuxiliaryFixtureSource(InfisicalBulkAuxiliaryFixture provider) : IBulkAuxiliarySource
{
    public BulkAuxiliarySourceKind Kind => BulkAuxiliarySourceKind.ControlledFixture;
    public string Identity => "controlled-bulk-storage";
    internal int Opens { get; private set; }
    internal int Observations { get; private set; }
    internal int Registrations => sessions.Count;
    internal bool LoseResponse { get; set; }
    internal TaskCompletionSource ResponseRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal List<BulkAuxiliaryFence> Fences { get; } = [];
    private readonly Dictionary<string, BulkAuxiliaryBinding> sessions = [];
    private readonly Dictionary<string, BulkAuxiliaryFence> fences = [];
    internal IBulkAuxiliarySource CreateObserver(Func<int, byte[]>? allocate = null) =>
        new InfisicalBulkAuxiliarySource(new(new(new("https://bulk-source.invalid/"),
            "private-source-token", Identity, 15), new Channel(this), allocate), Identity, Kind);

    // The source protocol transport is host-owned, distinct from provider HTTP.
    // Only private typed fixture commands are decoded here.
    private sealed class Channel(InfisicalBulkAuxiliaryFixtureSource source) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            using var owned = new PrivateBytes(bytes);
            using var document = JsonDocument.Parse(bytes);
            if (request.Headers.Authorization?.Parameter != "private-source-token") return new(HttpStatusCode.Forbidden);
            var command = document.RootElement;
            T Read<T>(string name) => command.GetProperty(name).Deserialize<T>(InfisicalStaticFamilies.Options)!;
            var root = Read<BulkAuxiliaryRoot>("root");
            object facts;
            switch (request.RequestUri!.AbsolutePath.Split('/').Last())
            {
                case "open":
                    var baseline = Read<BulkAuxiliaryRow[]>("baseline");
                    try { facts = await source.OpenAsync(root, baseline, token); }
                    finally { foreach (var row in baseline) row.Erase(); }
                    break;
                case "complete":
                    facts = await source.CompleteAsync(root, Read<DispatchEvidence>("receipt"), token); break;
                case "observe":
                    facts = await source.ObserveAsync(root, token); break;
                case "close":
                    facts = await source.CloseAsync(root, token); break;
                default: throw new NativeCaseFailureException("observer-unavailable");
            }
            try
            {
                return new(HttpStatusCode.OK)
                {
                    Content = new PrivateContent(JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schemaVersion = 1,
                        nonce = command.GetProperty("nonce").GetString(),
                        observerIdentity = source.Identity,
                        observedAt = DateTimeOffset.UtcNow,
                        facts
                    }, BulkAuxiliaryContract.Options))
                };
            }
            finally
            {
                if (facts is BulkAuxiliaryBinding binding) foreach (var row in binding.Baseline) row.Erase();
                if (facts is BulkAuxiliarySnapshot snapshot) foreach (var row in snapshot.Rows) row.Erase();
            }
        }
    }
    private sealed class PrivateBytes(byte[] bytes) : IDisposable
    {
        public void Dispose() => System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
    }
    private sealed class PrivateContent : ByteArrayContent
    {
        private readonly byte[] owned;
        internal PrivateContent(byte[] bytes) : base(bytes) { owned = bytes; }
        protected override void Dispose(bool disposing)
        {
            if (disposing) System.Security.Cryptography.CryptographicOperations.ZeroMemory(owned);
            base.Dispose(disposing);
        }
    }

    public ValueTask<BulkAuxiliaryBinding> OpenAsync(BulkAuxiliaryRoot root,
        BulkAuxiliaryRow[] baseline, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            Opens++;
            provider.Open(root, baseline);
            var binding = new BulkAuxiliaryBinding(root, Guid.NewGuid().ToString("D"), Identity,
                "provider-application-clock", "controlled-epoch", provider.Tick(), provider.Now,
                true, true, provider.Fault != "unqualified", true, provider.BorrowedPreserved, provider.Storage(root));
            sessions.Add(root.Id, binding with { Baseline = [] });
            if (provider.Fault == "lost-open")
            {
                foreach (var row in binding.Baseline) row.Erase();
                throw new NativeCaseFailureException("observer-unavailable");
            }
            return ValueTask.FromResult(binding);
        }
    }
    public ValueTask<BulkAuxiliaryFence> CompleteAsync(BulkAuxiliaryRoot root,
        DispatchEvidence receipt, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var binding = Get(root);
            BulkAuxiliaryContract.Require(!fences.ContainsKey(root.Id));
            var requests = provider.Requests.Where(r => r.Root == root.Id).ToArray();
            var original = requests.FirstOrDefault();
            bool exact = requests.All(r => r.Method == root.Method && r.Shape == root.Shape &&
                r.Project == root.ProjectId && r.Environment == root.Environment &&
                r.Folder == root.Folder && r.Role == root.Role);
            bool settled = provider.Fault is not ("late" or "replay");
            provider.Seal(root); // Future original deliveries cannot apply.
            var fence = new BulkAuxiliaryFence(root, binding.Registration, Guid.NewGuid().ToString("D"),
                original?.Id, requests.Sum(r => r.Count), provider.Commits.Where(c => c.Root == root.Id).Sum(c => c.Rows),
                provider.Tick(), provider.Now, receipt, exact && provider.Fault != "wrong-shape",
                settled, settled, requests.Sum(r => r.Count) <= 1);
            fences.Add(root.Id, fence); Fences.Add(fence);
            if (provider.Fault == "lost-complete") throw new NativeCaseFailureException("observer-unavailable");
            return ValueTask.FromResult(fence);
        }
    }
    public ValueTask<BulkAuxiliarySnapshot> ObserveAsync(BulkAuxiliaryRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            var binding = Get(root);
            var fence = fences[root.Id];
            Observations++;
            var rows = provider.Fault == "metadata-echo" ? [] : provider.Storage(root);
            if (provider.Fault == "extra-row")
                rows = [.. rows, new("EXTRA", "extra"u8.ToArray(), [], [], [], [], false, null, null, 1)];
            if (provider.Fault == "wrong-plaintext" && rows.Length > 0)
            {
                rows[0].Erase();
                rows[0] = rows[0] with { Material = "incorrect"u8.ToArray() };
            }
            return ValueTask.FromResult(new BulkAuxiliarySnapshot(root, binding.Registration,
                fence.EventId, Guid.NewGuid().ToString("D"), provider.Tick(), provider.Now,
                provider.Fault != "incomplete-inventory", provider.Fault != "metadata-echo",
                provider.BorrowedPreserved, rows));
        }
    }
    public ValueTask<BulkAuxiliaryCleanup> CloseAsync(BulkAuxiliaryRoot root, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        lock (provider.Gate)
        {
            bool registered = sessions.Remove(root.Id);
            bool terminal = fences.TryGetValue(root.Id, out var fence) ?
                fence.Settled && fence.NoReplay && fence.LateWorkExcluded :
                provider.Fault is not ("late" or "replay") &&
                    provider.Requests.Where(r => r.Root == root.Id).Sum(r => r.Count) <= 1;
            provider.Seal(root);
            // An Open without a returned binding has no original SDK dispatch.
            // A terminality failure is quarantined, never repaired by deletion.
            bool removed = registered && provider.Close(root, terminal);
            fences.Remove(root.Id);
            return ValueTask.FromResult(new BulkAuxiliaryCleanup(root, terminal, terminal,
                removed, removed, provider.BorrowedPreserved, removed, sessions.Count, 0));
        }
    }
    private BulkAuxiliaryBinding Get(BulkAuxiliaryRoot root)
    {
        BulkAuxiliaryContract.Require(sessions.TryGetValue(root.Id, out var binding) && binding.Root == root);
        return binding!;
    }
}
