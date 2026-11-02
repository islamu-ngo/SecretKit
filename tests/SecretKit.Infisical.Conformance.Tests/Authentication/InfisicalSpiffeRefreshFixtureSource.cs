using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalSpiffeRefreshFixtureSource(InfisicalSpiffeRefreshFixture fixture) : HttpMessageHandler
{
    private SpiffeRefreshRoot? root;
    private SpiffeRefreshBinding? binding;
    private SpiffeRefreshArm? arm;
    private SecretMaterial? capability;
    private readonly HashSet<int> measuredLogins = [];
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations { get; private set; }
    internal bool CopiesDestroyed => capability is null;
    internal List<byte[]> Buffers { get; } = [];
    internal string? LostReply { get; set; }
    internal InfisicalSpiffeRefreshSource Client() => new(new(new(
        new("https://source.invalid/private/"), "channel", "refresh-source", 20), this,
        size => { byte[] bytes = new byte[size]; Buffers.Add(bytes); return bytes; }),
        "refresh-source", SpiffeRefreshSourceKind.ControlledFixture);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        if (request.Headers.Authorization?.Parameter != "channel") return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            JsonElement body = document.RootElement;
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            object facts;
            switch (route)
            {
                case "open":
                    if (root is not null) throw new InvalidOperationException("fixture-open-replay");
                    root = body.GetProperty("root").Deserialize<SpiffeRefreshRoot>(InfisicalSpiffeRefreshFixture.Json)!;
                    if (body.GetProperty("capability").GetString() != "exclusive-capability")
                        throw new InvalidOperationException("fixture-capability");
                    capability = SecretMaterial.FromText(body.GetProperty("capability").GetString()!);
                    fixture.SelectIdentity(root.IdentityId);
                    Opens++;
                    Registrations++;
                    facts = binding = new(root, Guid.NewGuid().ToString("N"), "old", "new", "wrong", true, true,
                        fixture.BorrowedPreserved);
                    break;
                case "arm":
                    Check(body);
                    if (arm is not null) throw new InvalidOperationException("fixture-arm-replay");
                    string window = Guid.NewGuid().ToString("N");
                    fixture.PublishAndArm(window);
                    facts = arm = new(binding!, window, "overlap", true, true, fixture.HasKey("old"));
                    break;
                case "settle":
                    CheckArm(body);
                    var receipt = body.GetProperty("receipt").Deserialize<SpiffeRefreshReceipt>(InfisicalSpiffeRefreshFixture.Json)!;
                    await fixture.FenceAsync(token);
                    facts = new SpiffeRefreshSettlement(arm!, receipt, fixture.Requests.Count,
                        fixture.Bundles.Count(b => b.Window == arm!.Window),
                        fixture.Cache.Count(c => c.Window == arm!.Window), fixture.ForeignRequests, fixture.Pending,
                        fixture.Terminals.Count == fixture.Requests.Count, fixture.Fenced,
                        fixture.Requests.Count <= 1, true, fixture.HasKey("old"), fixture.HasKey("new"),
                        fixture.HasKey("wrong"), fixture.BorrowedPreserved);
                    break;
                case "proof":
                    Check(body);
                    if (body.GetProperty("arm").ValueKind != JsonValueKind.Null) CheckArm(body);
                    string jwt = body.GetProperty("jwt").GetString()!;
                    string phase = body.GetProperty("phase").GetString()!;
                    string proof = body.GetProperty("proof").GetString()!;
                    string digest = InfisicalSpiffeRefreshFixture.Digest(jwt);
                    int index = fixture.Logins.FindLastIndex(l => l.Digest == digest);
                    if (index < 0 || !measuredLogins.Add(index) ||
                        !fixture.Issuer.Any(i => i.Digest == digest && i.Proof == proof) ||
                        (phase == "before" ? arm is not null : phase != "after" || arm is null || !fixture.Fenced))
                        throw new InvalidOperationException("fixture-proof-join");
                    var observed = fixture.Logins[index];
                    facts = new SpiffeRefreshProofFacts(arm, binding!.Registration,
                        phase, proof,
                        observed.Allowed, observed.TokenId is null ? 0 : 1, true);
                    break;
                case "close":
                    if (body.GetProperty("root").Deserialize<SpiffeRefreshRoot>(InfisicalSpiffeRefreshFixture.Json) != root)
                        throw new InvalidOperationException("fixture-root-substitution");
                    Closes++;
                    await fixture.FenceAsync(token);
                    fixture.CloseOwned();
                    capability?.Dispose();
                    capability = null;
                    Registrations = 0;
                    facts = new SpiffeRefreshCleanup(root!, fixture.Terminals.Count == fixture.Requests.Count,
                        fixture.Fenced && fixture.ForeignRequests == 0, fixture.OwnedAbsent, fixture.BorrowedPreserved,
                        CopiesDestroyed, Registrations, fixture.Pending);
                    break;
                default: throw new InvalidOperationException("fixture-source-route");
            }
            if (route == LostReply) throw new HttpRequestException("controlled-reply-withheld");
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "refresh-source",
                observedAt = DateTimeOffset.UtcNow,
                facts
            }, InfisicalSpiffeRefreshFixture.Json);
            Buffers.Add(response);
            return new(HttpStatusCode.OK) { Content = new PrivateContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private void Check(JsonElement body)
    {
        if (body.GetProperty("binding").Deserialize<SpiffeRefreshBinding>(InfisicalSpiffeRefreshFixture.Json) != binding)
            throw new InvalidOperationException("fixture-binding-substitution");
    }
    private void CheckArm(JsonElement body)
    {
        if (body.GetProperty("arm").Deserialize<SpiffeRefreshArm>(InfisicalSpiffeRefreshFixture.Json) != arm)
            throw new InvalidOperationException("fixture-arm-substitution");
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { capability?.Dispose(); capability = null; }
        base.Dispose(disposing);
    }
    private sealed class PrivateContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal PrivateContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
            base.Dispose(disposing);
        }
    }
}
