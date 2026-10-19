using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Independently measures the fixture's journals. The private channel remains the
// same concrete source client used by a selected native service.
internal sealed class InfisicalRotationMaterialFixtureSource : HttpMessageHandler
{
    private readonly InfisicalRotationMaterialFixture fixture;
    private RotationMaterialRoot? root;
    private RotationMaterialBinding? binding;
    private RotationMaterialArm? arm;
    private string registration = "";
    private long sequence;
    private long baselineGeneration;
    private int baselineReads;
    private int baselineMappings;
    private long baselineConfiguration;
    private long baselineMappingRevision;
    private bool fenced;
    private bool privateDestroyed;
    internal List<byte[]> Buffers { get; } = [];
    internal int Opens { get; private set; }
    internal int Arms { get; private set; }
    internal int Measurements { get; private set; }
    internal int Closes { get; private set; }
    internal int Registrations { get; private set; }
    internal RotationMaterialRoot? OriginalRoot => root;
    internal RotationMaterialRoot? ClosedRoot { get; private set; }
    internal bool PrivateDestroyed => privateDestroyed;
    internal Action<string, JsonObject>? Change { get; set; }

    internal InfisicalRotationMaterialFixtureSource(InfisicalRotationMaterialFixture fixture) => this.fixture = fixture;
    internal InfisicalRotationMaterialSource Client() => new(new(
        new(new("https://source.invalid/private/"), "source-channel-token", "rotation-material-source", 15),
        this, length => { byte[] bytes = new byte[length]; Buffers.Add(bytes); return bytes; }),
        "rotation-material-source", RotationMaterialSource.ControlledFixture);

    private RotationMaterialStamp Stamp() => new(root!, registration, "provider-application-clock",
        "event-" + ++sequence, sequence, InfisicalRotationMaterialFixture.Clock.AddTicks(sequence));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
        try
        {
            using var document = JsonDocument.Parse(bytes);
            JsonElement body = document.RootElement;
            string route = request.RequestUri!.AbsolutePath.Split('/').Last();
            object facts = route switch
            {
                "open" => Open(body),
                "arm" => Arm(body),
                "authenticate" => Authenticate(body),
                "complete" => Complete(body),
                "close" => Close(body),
                _ => throw new InvalidOperationException("fixture-route")
            };
            if (fixture.Mode == "lost-" + route)
                throw new HttpRequestException("controlled-source-response-withheld");
            var node = JsonSerializer.SerializeToNode(facts, InfisicalRotationMaterialFixture.Json)!.AsObject();
            Change?.Invoke(route, node);
            return new(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(JsonSerializer.SerializeToUtf8Bytes(new
                {
                    schemaVersion = 1,
                    nonce = body.GetProperty("nonce").GetString(),
                    observerIdentity = "rotation-material-source",
                    observedAt = DateTimeOffset.UtcNow,
                    facts = node
                }, InfisicalRotationMaterialFixture.Json))
            };
        }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private RotationMaterialBinding Open(JsonElement body)
    {
        root = body.GetProperty("root").Deserialize<RotationMaterialRoot>(InfisicalRotationMaterialFixture.Json)!;
        Opens++;
        fixture.Provision(root, body.GetProperty("material"), body.GetProperty("setupCapability").GetString()!);
        registration = "root-registration";
        Registrations++;
        return binding = new(Stamp(), true, true, true, true, true, true,
            fixture.Mode != "echo-source", true, true, true);
    }

    private RotationMaterialArm Arm(JsonElement body)
    {
        var selected = body.GetProperty("binding").Deserialize<RotationMaterialBinding>(InfisicalRotationMaterialFixture.Json)!;
        RotationMaterialTrial.Require(selected == binding && !fenced);
        Arms++;
        registration = "read-registration";
        Registrations++;
        baselineGeneration = fixture.Generation;
        baselineReads = fixture.MetadataReads;
        baselineMappings = fixture.MappedCount;
        baselineConfiguration = fixture.ConfigurationRevision;
        baselineMappingRevision = fixture.MappingRevision;
        return arm = new(Stamp(), selected, true);
    }

    private RotationMaterialAuthentication Authenticate(JsonElement body)
    {
        Measurements++;
        var selected = body.GetProperty("arm").Deserialize<RotationMaterialArm>(InfisicalRotationMaterialFixture.Json)!;
        RotationMaterialTrial.Require(selected == arm);
        var actual = body.GetProperty("actual");
        var wrong = body.GetProperty("wrong");
        bool valid = fixture.BackendAuthenticate(actual, false);
        bool rejected = !fixture.BackendAuthenticate(wrong, true);
        bool recheck = fixture.BackendAuthenticate(actual, false);
        bool allowed = fixture.BackendAuthenticate(actual, false, "read");
        bool denied = !fixture.BackendAuthenticate(actual, false, "write");
        return new(Stamp(), selected, fixture.Exact(actual),
            fixture.Generation == baselineGeneration, Auth(valid), Auth(!rejected), Auth(recheck),
            allowed ? ["read"] : [], denied ? ["write"] : [], true, true);
    }

    private RotationMaterialWindow Complete(JsonElement body)
    {
        var selected = body.GetProperty("arm").Deserialize<RotationMaterialArm>(InfisicalRotationMaterialFixture.Json)!;
        var status = body.GetProperty("status").Deserialize<SecretStatus>(InfisicalRotationMaterialFixture.Json);
        RotationMaterialTrial.Require(selected == arm);
        fenced = fixture.Mode != "late-work";
        return new(Stamp(), selected, status, fixture.MetadataReads - baselineReads, true, fenced,
            fixture.ConfigurationRevision == baselineConfiguration,
            fixture.MappingRevision == baselineMappingRevision && fixture.MappedCount == baselineMappings,
            fixture.Generation == baselineGeneration, fixture.Residual == baselineMappings + 2,
            true, fixture.MetadataReads - baselineReads <= 1, 0, fixture.Mode == "pending-work" ? 1 : 0);
    }

    private RotationMaterialCleanup Close(JsonElement body)
    {
        var original = body.GetProperty("root").Deserialize<RotationMaterialRoot>(InfisicalRotationMaterialFixture.Json)!;
        RotationMaterialTrial.Require(original == root, "cleanup-incomplete");
        Closes++;
        ClosedRoot = original;
        var cleanup = fixture.Cleanup(original);
        Registrations = 0;
        privateDestroyed = fixture.PrivateDestroyed;
        // Closure fences even unknown Open/arm. A forced fault keeps the terminal
        // failure visible rather than silently treating source disposal as proof.
        return new(original, true, fixture.Mode != "late-work", cleanup.Setup, cleanup.Secrets,
            cleanup.Backend, cleanup.Retired, fixture.BorrowedPreserved, privateDestroyed, true, Registrations,
            fixture.Mode == "pending-delivery" ? 1 : 0, fixture.Mode == "pending-work" ? 1 : 0);
    }

    private static BackendAuthentication Auth(bool value) => value ? BackendAuthentication.Accepted : BackendAuthentication.Rejected;
}
