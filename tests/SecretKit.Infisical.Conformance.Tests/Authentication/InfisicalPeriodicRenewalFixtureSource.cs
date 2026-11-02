using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalPeriodicRenewalFixtureSource(InfisicalPeriodicRenewalFixture fixture) : HttpMessageHandler
{
    private PeriodicRenewalRoot? root;
    private PeriodicRenewalBinding? binding;
    private PeriodicRenewalArm? arm;
    private SecretMaterial? copy;
    private long sequence;
    private string registration = "";
    internal int Opens { get; private set; }
    internal int Closes { get; private set; }
    internal int Deliveries { get; private set; }
    internal int Registrations { get; private set; }
    internal bool CopiesDestroyed => copy is null;
    internal PeriodicRenewalRoot? ClosedRoot { get; private set; }
    internal PeriodicRenewalSettlement? Settlement { get; private set; }
    internal List<byte[]> Buffers { get; } = [];
    internal Action<string, JsonObject>? Change { get; set; }
    internal InfisicalPeriodicRenewalSource Client() => new(new(
        new(new("https://source.invalid/private/"), "private-channel-token", "periodic-original-source", 15),
        this, length => { var bytes = new byte[length]; Buffers.Add(bytes); return bytes; }),
        "periodic-original-source", PeriodicRenewalSourceKind.ControlledFixture);

    private PeriodicRenewalStamp Stamp() => new(root!, registration, "event-" + ++sequence,
        sequence, fixture.Clock.GetUtcNow(), "provider-application-clock");

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        if (request.Headers.Authorization?.Parameter != "private-channel-token")
            return new(HttpStatusCode.Forbidden);
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            var body = document.RootElement;
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            object facts = route switch
            {
                "open" => Open(body),
                "expire" => Expire(body),
                "arm" => Arm(body),
                "boundary" => await Boundary(body, token),
                "settle" => await Settle(body, token),
                "delivery" => Delivery(body),
                "close" => await Close(body, token),
                _ => throw new InvalidOperationException("fixture-source-route")
            };
            if (fixture.Mode == "lost-" + route) throw new HttpRequestException("controlled-reply-withheld");
            var node = JsonSerializer.SerializeToNode(facts, InfisicalPeriodicRenewalFixture.Json)!.AsObject();
            Change?.Invoke(route, node);
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "periodic-original-source",
                observedAt = DateTimeOffset.UtcNow,
                facts = node
            }, InfisicalPeriodicRenewalFixture.Json);
            Buffers.Add(response);
            return new(HttpStatusCode.OK) { Content = new PrivateContent(response) };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private PeriodicRenewalBinding Open(JsonElement body)
    {
        root = body.GetProperty("root").Deserialize<PeriodicRenewalRoot>(InfisicalPeriodicRenewalFixture.Json)!;
        Opens++;
        var credential = fixture.Open(root, body.GetProperty("borrowed").GetString()!,
            body.GetProperty("capability").GetString()!);
        copy = credential.Material.Copy();
        registration = Guid.NewGuid().ToString("N");
        Registrations++;
        return binding = new(Stamp(), credential.Handle, credential.Lifetime, true,
            fixture.Mode != "echo-source", fixture.BorrowedPreserved);
    }

    private PeriodicRenewalExpiry Expire(JsonElement body)
    {
        CheckBinding(body);
        fixture.Clock.AdvanceTo(binding!.Lifetime.ExpiresAt);
        return new(Stamp(), fixture.Current, true, fixture.BorrowedPreserved, true);
    }

    private PeriodicRenewalArm Arm(JsonElement body)
    {
        CheckBinding(body);
        return arm = new(Stamp(), binding!, fixture.Arm(), true, true, fixture.PendingWork);
    }

    private async ValueTask<PeriodicRenewalArrival> Boundary(JsonElement body, CancellationToken token)
    {
        CheckArm(body);
        await fixture.Arrived.Task.WaitAsync(token);
        var request = fixture.Requests.Single();
        return new(Stamp(), request.Window, request.RequestId, request.CredentialHandle, root!.Boundary, true);
    }

    private async ValueTask<PeriodicRenewalSettlement> Settle(JsonElement body, CancellationToken token)
    {
        CheckArm(body);
        var receipt = body.GetProperty("receipt").Deserialize<PeriodicRenewalReceipt>(InfisicalPeriodicRenewalFixture.Json)!;
        await fixture.FenceAsync(token);
        var captured = fixture.Captured;
        var outcome = fixture.Commits.Count == 0 ? PeriodicRenewalOutcome.NonApplied :
            fixture.Mode == "partial" ? PeriodicRenewalOutcome.Partial : PeriodicRenewalOutcome.Applied;
        return Settlement = new(Stamp(), arm!, receipt, fixture.RequestId, fixture.SelectedHandle, outcome,
            fixture.Requests.Count, fixture.Commits.Count, fixture.ForeignRequests, fixture.PendingWork, 0,
            fixture.OriginalTerminal, fixture.Fenced, true, fixture.Requests.Count <= 1,
            fixture.BorrowedPreserved, fixture.Current, captured?.Lifetime, captured?.Row, captured?.Handle);
    }

    private PeriodicRenewalDelivery Delivery(JsonElement body)
    {
        CheckArm(body);
        Deliveries++;
        var credential = fixture.Find(body.GetProperty("actual").GetString()!);
        return new(Stamp(), fixture.Window, credential?.Row ?? "", credential?.Handle ?? "",
            credential?.Lifetime ?? fixture.Baseline, credential is not null);
    }

    private async ValueTask<PeriodicRenewalCleanup> Close(JsonElement body, CancellationToken token)
    {
        var closing = body.GetProperty("root").Deserialize<PeriodicRenewalRoot>(InfisicalPeriodicRenewalFixture.Json)!;
        if (closing != root) throw new InvalidOperationException("fixture-close-root");
        Closes++;
        ClosedRoot = closing;
        await fixture.FenceAsync(token);
        var before = fixture.Current;
        bool ownedAbsent = fixture.CloseOwned();
        copy?.Dispose();
        copy = null;
        Registrations = 0;
        return new(closing, fixture.OriginalTerminal, fixture.Fenced && fixture.ForeignRequests == 0,
            true, fixture.BorrowedPreserved, fixture.Current == before,
            ownedAbsent && fixture.CapturedResources == 0, CopiesDestroyed,
            Registrations, fixture.PendingWork, 0);
    }

    private void CheckBinding(JsonElement body)
    {
        if (body.GetProperty("binding").Deserialize<PeriodicRenewalBinding>(InfisicalPeriodicRenewalFixture.Json) != binding)
            throw new InvalidOperationException("fixture-binding-substitution");
    }
    private void CheckArm(JsonElement body)
    {
        if (body.GetProperty("arm").Deserialize<PeriodicRenewalArm>(InfisicalPeriodicRenewalFixture.Json) != arm)
            throw new InvalidOperationException("fixture-arm-substitution");
    }
    protected override void Dispose(bool disposing)
    {
        if (disposing) { copy?.Dispose(); copy = null; }
        base.Dispose(disposing);
    }
    private sealed class PrivateContent : ByteArrayContent
    {
        private readonly byte[] owned;
        internal PrivateContent(byte[] bytes) : base(bytes) => owned = bytes;
        protected override void Dispose(bool disposing)
        {
            if (disposing) CryptographicOperations.ZeroMemory(owned);
            base.Dispose(disposing);
        }
    }
}
