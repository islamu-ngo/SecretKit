using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalShareObserverTests
{
    private const string Organization = "51000000-0000-0000-0000-000000000001";
    private static readonly JsonSerializerOptions Json = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new("https://observer.invalid/owned/"), "service-token", "independent-service", 30);
    private static readonly DateTimeOffset Expiry = DateTimeOffset.UnixEpoch.AddMinutes(5);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ShareSelectsOnlyExplicitGovernanceObserver(bool configured)
    {
        var family = new JsonObject();
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, Json);
        using JsonDocument settings = JsonDocument.Parse(new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject { ["C08-IM-Governance"] = family }
        }.ToJsonString());
        using var environment = NativeEnvironment.Create(settings.RootElement);
        await Assert.That(InfisicalShareObserver.FromInputs(environment) is not null).IsEqualTo(configured);
    }

    [Test]
    public async Task ShareUsesTypedSdkMetadataAndMeasuredRecipientViewsAndExpiry()
    {
        await using var sdk = new SdkBackend();
        using var transport = new ManagementTransport(sdk.Origin, new() { AllowLoopbackDevelopmentHttp = true });
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("service-token");
            object facts;
            switch (request.RequestUri!.AbsolutePath.Split('/').Last())
            {
                case "find":
                    await Assert.That(body["ownedName"]!.GetValue<string>()).IsEqualTo("owned");
                    await Assert.That(body["observerToken"]!.GetValue<string>()).IsEqualTo("observer");
                    facts = new { organizationId = Organization, ownedName = "owned", status = SecretStatus.Success, shareId = "share" };
                    break;
                case "views":
                    facts = new { shareId = "share", consumedViews = 2 };
                    break;
                default:
                    await Assert.That(body["runtimeToken"]!.GetValue<string>()).IsEqualTo("runtime");
                    await Assert.That(body["deniedToken"]!.GetValue<string>()).IsEqualTo("denied");
                    await Assert.That(body["password"]!.GetValue<string>()).IsEqualTo("owned-proof");
                    facts = Delivery();
                    break;
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalShareObserver(new(Settings, handler), new(transport));
        var measured = new Source("observer");
        var runtime = new Source("runtime");
        var denied = new Source("denied");
        var metadata = await observer.FindOwnedAsync(Organization, "owned", measured, CancellationToken.None);
        await Assert.That(sdk.Path).IsEqualTo("/api/v1/shared-secrets/share");
        await Assert.That(metadata.IsSuccess).IsTrue().Because(metadata.Status.ToString());
        await Assert.That(metadata.Value.Id).IsEqualTo("share");
        await Assert.That((await observer.ObserveViewsAsync("share", measured, CancellationToken.None)).ConsumedViews).IsEqualTo(2);
        using var proof = SecretMaterial.FromText("owned-proof");
        using ShareDeliveryFacts delivered = await observer.DeliverAsync(Organization, "share", proof, runtime, denied, CancellationToken.None);
        await Assert.That(delivered.Material!.Reveal()).IsEqualTo("owned-offline-material");
        await Assert.That(delivered.ViewsAfter).IsEqualTo(delivered.ViewsBefore + 1);
        await Assert.That(delivered.ExpiredObservationTime).IsEqualTo(Expiry);
        await Assert.That(delivered.ExpiredStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(delivered.ViewLimit).IsNotNull();
        await Assert.That(delivered.ViewLimit!.MaximumViews).IsEqualTo(4);
        await Assert.That(delivered.ViewLimit.ViewsBeforeExhaustedAccess).IsEqualTo(4);
        await Assert.That(delivered.ViewLimit.ViewsAfterExhaustedAccess).IsEqualTo(4);
        await Assert.That(delivered.ViewLimit.ExhaustedStatus).IsEqualTo(SecretStatus.Denied);
        await Assert.That(delivered.ViewLimit.MaterialReturned).IsFalse();
        delivered.Dispose();
        await Assert.That(() => delivered.Material!.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(proof.Reveal()).IsEqualTo("owned-proof");
        foreach (SecretMaterial copy in new[] { measured, runtime, denied }.SelectMany(s => s.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("organization")]
    [Arguments("share")]
    [Arguments("recipient")]
    [Arguments("denied")]
    [Arguments("views")]
    [Arguments("expiry")]
    [Arguments("expired-status")]
    [Arguments("material")]
    [Arguments("missing")]
    public async Task ShareDeliveryRejectsSubstitutedOrIncompleteMeasurements(string mode)
    {
        using var transport = new ManagementTransport(new("https://infisical.invalid/"));
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            JsonObject facts = JsonSerializer.SerializeToNode(Delivery(), Json)!.AsObject();
            switch (mode)
            {
                case "organization": facts["organizationId"] = "other"; break;
                case "share": facts["shareId"] = "other"; break;
                case "recipient": facts["recipientStatus"] = (int)SecretStatus.Denied; break;
                case "denied": facts["deniedStatus"] = (int)SecretStatus.Success; break;
                case "views": facts["viewsAfter"] = 2; break;
                case "expiry": facts["expiredObservationTime"] = Expiry.AddSeconds(-1); break;
                case "expired-status": facts["expiredStatus"] = (int)SecretStatus.Success; break;
                case "material": facts["material"] = null; break;
                default: facts.Remove("viewsAfter"); break;
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalShareObserver(new(Settings, handler), new(transport));
        var runtime = new Source("runtime");
        var denied = new Source("denied");
        await Assert.That(async () =>
        {
            using var result = await observer.DeliverAsync(Organization, "share", null, runtime, denied, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        foreach (SecretMaterial copy in runtime.Issued.Concat(denied.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments("missing-limit")]
    [Arguments("null-limit")]
    [Arguments("zero-maximum")]
    [Arguments("negative-maximum")]
    [Arguments("substituted-maximum")]
    [Arguments("before")]
    [Arguments("after")]
    [Arguments("negative-before")]
    [Arguments("negative-after")]
    [Arguments("success")]
    [Arguments("unknown")]
    [Arguments("undefined-status")]
    [Arguments("material")]
    [Arguments("default-time")]
    [Arguments("expiry-time")]
    [Arguments("after-expiry-time")]
    [Arguments("missing-maximumViews")]
    [Arguments("missing-viewsBeforeExhaustedAccess")]
    [Arguments("missing-viewsAfterExhaustedAccess")]
    [Arguments("missing-exhaustedStatus")]
    [Arguments("missing-materialReturned")]
    [Arguments("missing-exhaustedObservationTime")]
    [Arguments("null-maximumViews")]
    [Arguments("null-viewsBeforeExhaustedAccess")]
    [Arguments("null-viewsAfterExhaustedAccess")]
    [Arguments("null-exhaustedStatus")]
    [Arguments("null-materialReturned")]
    [Arguments("null-exhaustedObservationTime")]
    public async Task FiniteShareRejectsMissingOrFalseExhaustion(string mode)
    {
        using var transport = new ManagementTransport(new("https://infisical.invalid/"));
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            JsonObject facts = JsonSerializer.SerializeToNode(Delivery(), Json)!.AsObject();
            JsonObject exhausted = facts["viewLimit"]!.AsObject();
            if (mode.StartsWith("missing-", StringComparison.Ordinal) && mode != "missing-limit")
                exhausted.Remove(mode["missing-".Length..]);
            else if (mode.StartsWith("null-", StringComparison.Ordinal) && mode != "null-limit")
                exhausted[mode["null-".Length..]] = null;
            else switch (mode)
                {
                    case "missing-limit": facts.Remove("viewLimit"); break;
                    case "null-limit": facts["viewLimit"] = null; break;
                    case "zero-maximum":
                        facts["maximumViews"] = 0;
                        exhausted["maximumViews"] = 0;
                        break;
                    case "negative-maximum":
                        facts["maximumViews"] = -1;
                        exhausted["maximumViews"] = -1;
                        break;
                    case "substituted-maximum": exhausted["maximumViews"] = 5; break;
                    case "before": exhausted["viewsBeforeExhaustedAccess"] = 3; break;
                    case "after": exhausted["viewsAfterExhaustedAccess"] = 5; break;
                    case "negative-before": exhausted["viewsBeforeExhaustedAccess"] = -1; break;
                    case "negative-after": exhausted["viewsAfterExhaustedAccess"] = -1; break;
                    case "success": exhausted["exhaustedStatus"] = (int)SecretStatus.Success; break;
                    case "unknown": exhausted["exhaustedStatus"] = (int)SecretStatus.Unknown; break;
                    case "undefined-status": exhausted["exhaustedStatus"] = int.MaxValue; break;
                    case "material": exhausted["materialReturned"] = true; break;
                    case "default-time": exhausted["exhaustedObservationTime"] = default(DateTimeOffset); break;
                    case "expiry-time": exhausted["exhaustedObservationTime"] = Expiry; break;
                    case "after-expiry-time": exhausted["exhaustedObservationTime"] = Expiry.AddSeconds(1); break;
                }
            return Reply(body, facts);
        });
        var observer = new InfisicalShareObserver(new(Settings, handler), new(transport));
        var runtime = new Source("runtime");
        var denied = new Source("denied");
        await Assert.That(async () =>
        {
            using var result = await observer.DeliverAsync(Organization, "share", null, runtime, denied, CancellationToken.None);
        }).Throws<NativeCaseFailureException>();
        foreach (SecretMaterial copy in runtime.Issued.Concat(denied.Issued))
            await Assert.That(() => copy.Reveal()).Throws<ObjectDisposedException>();
    }

    [Test]
    [Arguments(1, SecretStatus.Denied, false)]
    [Arguments(4, SecretStatus.Absent, false)]
    [Arguments(int.MaxValue, SecretStatus.Denied, false)]
    [Arguments(null, SecretStatus.Denied, false)]
    [Arguments(null, SecretStatus.Denied, true)]
    public async Task ShareDeliveryPreservesExplicitFiniteOrUnlimitedMeasurements(int? maximumViews, SecretStatus status,
        bool nullViewLimit)
    {
        using var transport = new ManagementTransport(new("https://infisical.invalid/"));
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!.AsObject();
            await Assert.That(request.RequestUri!.Scheme).IsEqualTo("https");
            await Assert.That(body["runtimeToken"]!.GetValue<string>()).IsEqualTo("runtime");
            await Assert.That(body["deniedToken"]!.GetValue<string>()).IsEqualTo("denied");
            JsonObject facts = JsonSerializer.SerializeToNode(Delivery(), Json)!.AsObject();
            facts["maximumViews"] = maximumViews;
            facts["viewsBefore"] = 0;
            facts["viewsAfter"] = 1;
            if (maximumViews is null)
            {
                if (nullViewLimit) facts["viewLimit"] = null;
                else facts.Remove("viewLimit");
            }
            else
            {
                JsonObject exhausted = facts["viewLimit"]!.AsObject();
                exhausted["maximumViews"] = maximumViews;
                exhausted["viewsBeforeExhaustedAccess"] = maximumViews;
                exhausted["viewsAfterExhaustedAccess"] = maximumViews;
                exhausted["exhaustedStatus"] = (int)status;
            }
            return Reply(body, facts);
        });
        var observer = new InfisicalShareObserver(new(Settings, handler), new(transport));
        using var delivered = await observer.DeliverAsync(Organization, "share", null,
            new Source("runtime"), new Source("denied"), CancellationToken.None);
        await Assert.That(delivered.MaximumViews).IsEqualTo(maximumViews);
        if (maximumViews is { } limit)
        {
            await Assert.That(delivered.ViewLimit).IsNotNull();
            await Assert.That(delivered.ViewLimit!.MaximumViews).IsEqualTo(limit);
            await Assert.That(delivered.ViewLimit.ViewsBeforeExhaustedAccess).IsEqualTo(limit);
            await Assert.That(delivered.ViewLimit.ViewsAfterExhaustedAccess).IsEqualTo(limit);
            await Assert.That(delivered.ViewLimit.ExhaustedObservationTime).IsEqualTo(Expiry.AddSeconds(-1));
            await Assert.That(delivered.ViewLimit.ExhaustedStatus).IsEqualTo(status);
            await Assert.That(delivered.ViewLimit.MaterialReturned).IsFalse();
        }
        else await Assert.That(delivered.ViewLimit).IsNull();
        await Assert.That(delivered.Material!.Reveal()).IsEqualTo("owned-offline-material");
    }

    private static object Delivery() => new
    {
        organizationId = Organization,
        shareId = "share",
        recipientStatus = SecretStatus.Success,
        deniedStatus = SecretStatus.Denied,
        viewsBefore = 2,
        viewsAfter = 3,
        expiresAt = Expiry,
        expiredObservationTime = Expiry,
        expiredStatus = SecretStatus.Denied,
        material = "owned-offline-material",
        audience = ShareAudience.Organization,
        maximumViews = (int?)4,
        allowExternalEmails = (bool?)false,
        authorizedEmails = new[] { "recipient@example.invalid" },
        viewLimit = new
        {
            maximumViews = 4,
            viewsBeforeExhaustedAccess = 4,
            viewsAfterExhaustedAccess = 4,
            exhaustedStatus = SecretStatus.Denied,
            materialReturned = false,
            exhaustedObservationTime = Expiry.AddSeconds(-1)
        }
    };
    private static HttpResponseMessage Reply(JsonObject request, object facts) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(new
        {
            schemaVersion = 1,
            nonce = request["nonce"]!.GetValue<string>(),
            observerIdentity = Settings.Identity,
            observedAt = DateTimeOffset.UtcNow,
            facts
        }, Json))
    };
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) =>
            send(request, token);
    }
    private sealed class Source(string token) : IInfisicalTokenSource
    {
        internal List<SecretMaterial> Issued { get; } = [];
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var copy = SecretMaterial.FromText(token);
            Issued.Add(copy);
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(copy)));
        }
    }
    private sealed class SdkBackend : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stop = new(TimeSpan.FromSeconds(10));
        private readonly Task serving;
        internal Uri Origin { get; }
        internal string? Path { get; private set; }
        internal SdkBackend()
        {
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            serving = ServeAsync();
        }
        private async Task ServeAsync()
        {
            try
            {
                using TcpClient socket = await listener.AcceptTcpClientAsync(stop.Token);
                using var reader = new StreamReader(socket.GetStream(), Encoding.ASCII, leaveOpen: true);
                Path = (await reader.ReadLineAsync(stop.Token))!.Split(' ')[1];
                while (!string.IsNullOrEmpty(await reader.ReadLineAsync(stop.Token))) { }
                byte[] body = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    id = "share",
                    name = "owned",
                    orgId = Organization,
                    expiresAt = Expiry,
                    createdAt = DateTimeOffset.UnixEpoch,
                    updatedAt = DateTimeOffset.UnixEpoch,
                    isAuthorizedUser = true,
                    isPasswordProtected = true
                });
                byte[] header = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\nConnection: close\r\n\r\n");
                await socket.GetStream().WriteAsync(header, stop.Token);
                await socket.GetStream().WriteAsync(body, stop.Token);
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
        }
        public async ValueTask DisposeAsync()
        {
            await stop.CancelAsync();
            try { await serving; }
            finally { listener.Stop(); stop.Dispose(); }
        }
    }
}
