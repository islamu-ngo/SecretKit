using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SecretKit.Infisical.Conformance.Tests;

// A private source service for the controlled unit. Source state and provider
// journals are independent of the effect handler and owned host trial.
internal sealed class InfisicalRotationMutationFixtureSource(InfisicalRotationMutationFixture fixture)
    : HttpMessageHandler
{
    private RotationMutationRoot? root;
    private RotationMutationBinding? binding;
    private RotationMutationArm? arm;
    private string registration = "";
    private long sequence;
    internal List<byte[]> Buffers { get; } = [];
    internal int Opens { get; private set; }
    internal int Arms { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations { get; private set; }
    internal RotationMutationRoot? OriginalRoot => root;
    internal RotationMutationRoot? ClosedRoot { get; private set; }
    internal RotationMutationSettlement? Settlement { get; private set; }
    internal Action<string, JsonObject>? Change { get; set; }
    internal InfisicalRotationMutationSource Client() => new(new(
        new(new("https://source.invalid/private/"), "mutation-source-token", "rotation-mutation-source", 15),
        this, length => { byte[] bytes = new byte[length]; Buffers.Add(bytes); return bytes; }),
        "rotation-mutation-source", RotationMaterialSource.ControlledFixture);
    private RotationMutationStamp Stamp() => new(root!, registration, "mutation-event-" + ++sequence,
        sequence, InfisicalRotationMutationFixture.Clock.AddTicks(sequence), "provider-application-clock");

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        RotationMaterialTrial.Require(request.Headers.Authorization?.Parameter == "mutation-source-token");
        byte[] bodyBytes = await request.Content!.ReadAsByteArrayAsync(token);
        try
        {
            using var document = JsonDocument.Parse(bodyBytes);
            var body = document.RootElement;
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            object facts = route switch
            {
                "open" => Open(body),
                "arm" => Arm(body),
                "settle" => await Settle(body, token),
                "authenticate" => Authenticate(body),
                "close" => await Close(body, token),
                _ => throw new InvalidOperationException("fixture-route")
            };
            if (fixture.Mode == "lost-" + route) throw new HttpRequestException("controlled-source-response-withheld");
            var node = JsonSerializer.SerializeToNode(facts, InfisicalRotationMutationFixture.Json)!.AsObject();
            Change?.Invoke(route, node);
            byte[] response = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                nonce = body.GetProperty("nonce").GetString(),
                observerIdentity = "rotation-mutation-source",
                observedAt = DateTimeOffset.UtcNow,
                facts = node
            }, InfisicalRotationMutationFixture.Json);
            Buffers.Add(response);
            return new(HttpStatusCode.OK)
            {
                Content = new PrivateContent(response)
            };
        }
        finally { CryptographicOperations.ZeroMemory(bodyBytes); }
    }

    private RotationMutationBinding Open(JsonElement body)
    {
        root = body.GetProperty("root").Deserialize<RotationMutationRoot>(InfisicalRotationMutationFixture.Json)!;
        Opens++;
        fixture.Provision(root, body.GetProperty("baseline"), body.GetProperty("setupCapability").GetString()!);
        registration = "mutation-root-registration";
        Registrations++;
        return binding = new(Stamp(), true, true, true, true, fixture.IdentityInventoryQualified,
            fixture.Mode != "echo-source", fixture.SetupAuthenticationJournal[0],
            !fixture.SetupAuthenticationJournal[1], fixture.SetupAuthenticationJournal[2]);
    }

    private RotationMutationArm Arm(JsonElement body)
    {
        var selected = body.GetProperty("binding").Deserialize<RotationMutationBinding>(InfisicalRotationMutationFixture.Json)!;
        RotationMaterialTrial.Require(selected == binding);
        fixture.Arm(root!);
        Arms++;
        registration = "original-attempt-registration";
        Registrations++;
        return arm = new(Stamp(), selected, true, true);
    }

    private async ValueTask<RotationMutationSettlement> Settle(JsonElement body, CancellationToken token)
    {
        var selected = body.GetProperty("arm").Deserialize<RotationMutationArm>(InfisicalRotationMutationFixture.Json)!;
        var receipt = body.GetProperty("receipt").Deserialize<RotationMutationReceipt>(InfisicalRotationMutationFixture.Json)!;
        RotationMaterialTrial.Require(selected == arm && receipt.AttemptId == root!.AttemptId && receipt.Action == root.Action);
        await fixture.SettleOriginalAsync(root!, token);
        var outcome = fixture.Mode is "unknown-partial" or "partial-setting" ? RotationMutationOutcome.Partial :
            fixture.OriginalCommits == 0 ? RotationMutationOutcome.NonApplied : RotationMutationOutcome.Applied;
        bool applied = outcome == RotationMutationOutcome.Applied;
        bool manual = root!.Action == InfisicalRotationAction.RotateSecrets;
        bool configuration = manual || fixture.Enabled == (root.Action == InfisicalRotationAction.EnableAutomaticRotation);
        return Settlement = new(Stamp(), selected, receipt, outcome, fixture.RequestJournal.Count,
            fixture.OriginalCommits, fixture.OriginalDeliveries, fixture.OriginalTerminal,
            fixture.ExcludesLateWork, true, fixture.RequestJournal.Count <= 1 && fixture.Mode != "replay",
            fixture.Pending, 0, configuration || !applied, true, fixture.Enabled,
            applied || fixture.OriginalDeliveries > 0 ? manual ? RotationMutationEvent.OriginalManual : RotationMutationEvent.ScheduledOpportunity :
                RotationMutationEvent.None,
            fixture.AttributedAttempt, fixture.SchedulerJournal.Count == 1,
            fixture.Mode != "native-clock", fixture.OriginalTerminal && fixture.Pending == 0,
            fixture.QueuedDeliveries, fixture.OpportunityBaseline, fixture.Generation, fixture.Fields(fixture.Generation),
            fixture.HistoryComplete, fixture.PreviousAccepted, fixture.OverwrittenRetired, fixture.IdentityInventoryQualified);
    }

    private RotationMutationAuthentication Authenticate(JsonElement body)
    {
        var selected = body.GetProperty("arm").Deserialize<RotationMutationArm>(InfisicalRotationMutationFixture.Json)!;
        RotationMaterialTrial.Require(selected == arm && Settlement is not null);
        var actual = body.GetProperty("actual");
        bool valid = fixture.Authenticate(actual, false);
        bool wrong = fixture.Authenticate(body.GetProperty("wrong"), true);
        bool recheck = fixture.Authenticate(actual, false);
        bool allowed = fixture.Authenticate(actual, false, "read");
        bool denied = !fixture.Authenticate(actual, false, "write");
        return new(Stamp(), selected, fixture.Generation, fixture.Exact(actual, fixture.Generation),
            fixture.Generation == Settlement!.Generation, true, true, Auth(valid), Auth(wrong), Auth(recheck),
            allowed ? ["read"] : [], denied ? ["write"] : []);
    }

    private async ValueTask<RotationMutationCleanup> Close(JsonElement body, CancellationToken token)
    {
        var original = body.GetProperty("root").Deserialize<RotationMutationRoot>(InfisicalRotationMutationFixture.Json)!;
        RotationMaterialTrial.Require(original == root, "cleanup-incomplete");
        Closes++;
        ClosedRoot = original;
        var result = await fixture.CleanupAsync(original, token);
        Registrations = 0;
        return result;
    }

    private static BackendAuthentication Auth(bool accepted) => accepted ? BackendAuthentication.Accepted : BackendAuthentication.Rejected;

    // Settlement contains private material. The source owns its serialized
    // response as well as the channel's clearable received/request capacities.
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
