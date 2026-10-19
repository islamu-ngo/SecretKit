using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalLifecycleObserverTests
{
    private static readonly JsonSerializerOptions ServiceJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };
    private static readonly InfisicalLifecycleObservers.Settings Settings =
        new(new Uri("https://observer.invalid/owned/"), "fixture-observer", "independent-service", 30);

    private static DynamicBackendCoordinate Coordinate() =>
        new(NativeSqlEngine.Postgres, "database.invalid", 5432, "owned", Guid.NewGuid(), Guid.NewGuid());

    private static DynamicBackendFacts Facts(DynamicBackendCoordinate coordinate) =>
        new(coordinate, BackendAuthentication.Accepted, ["select"], ["write"], DateTimeOffset.UtcNow.AddMinutes(1));

    [Test]
    [Arguments("pending")]
    [Arguments("flush")]
    [Arguments("growth")]
    [Arguments("allocation")]
    public async Task SerializationFailureClearsAllOwnedStorage(string mode)
    {
        var buffers = new List<byte[]>();
        byte[] Allocate(int length)
        {
            if (mode == "allocation" && buffers.Count != 0) throw new InvalidOperationException();
            byte[] buffer = new byte[length];
            buffers.Add(buffer);
            return buffer;
        }
        using var handler = new Handler((_, _) => throw new InvalidOperationException());
        var observer = new InfisicalLifecycleObservers(Settings, handler, Allocate);
        byte[] key = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        bool populated = false;
        bool pending = false;
        bool retiredCleared = false;
        try
        {
            await Assert.That(async () => await observer.PostAsync<int>("private", writer =>
            {
                writer.WriteBase64String("privateKey", key);
                pending = writer.BytesPending > 0;
                populated = buffers.Any(buffer => ContainsEncodedKey(buffer, key));
                if (mode != "pending") writer.Flush();
                if (mode is "growth" or "allocation")
                {
                    writer.WriteString("padding", new string('x', 8192));
                    retiredCleared = buffers.Take(buffers.Count - 1).All(AllZero);
                }
                throw new InvalidOperationException();
            }, CancellationToken.None)).Throws<InvalidOperationException>();
            await Assert.That(populated).IsTrue();
            await Assert.That(pending).IsTrue();
            await Assert.That(buffers.Count).IsEqualTo(mode == "growth" ? 2 : 1);
            if (mode == "growth") await Assert.That(retiredCleared).IsTrue();
            await Assert.That(buffers.All(AllZero)).IsTrue();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Test]
    public async Task OwnedBufferClearsUncommittedTailAndGrowthCopies()
    {
        var buffers = new List<byte[]>();
        using (var body = new InfisicalLifecycleObservers.OwnedJsonBuffer(length =>
        {
            byte[] buffer = new byte[length];
            buffers.Add(buffer);
            return buffer;
        }))
        {
            body.GetSpan(256).Fill(0xa5);
            body.Advance(32);
            body.GetMemory(4096);
            await Assert.That(buffers.Count).IsEqualTo(2);
            await Assert.That(AllZero(buffers[0])).IsTrue();
            await Assert.That(buffers[1].Take(32).Count(value => value != 0)).IsEqualTo(32);
            body.GetSpan().Fill(0xa5);
        }
        await Assert.That(buffers.All(AllZero)).IsTrue();
    }

    [Test]
    [Arguments("request")]
    [Arguments("transport")]
    public async Task SetupFailureAfterSerializationClearsOwnedStorage(string mode)
    {
        var buffers = new List<byte[]>();
        using var handler = new HttpClientHandler();
        handler.Dispose();
        var observer = new InfisicalLifecycleObservers(Settings, handler, length =>
        {
            byte[] buffer = new byte[length];
            buffers.Add(buffer);
            return buffer;
        });
        byte[] key = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        bool serialized = false;
        try
        {
            async Task Send() => _ = await observer.PostAsync<int>(
                mode == "request" ? "https://[" : "private", writer =>
                {
                    writer.WriteBase64String("privateKey", key);
                    serialized = true;
                }, CancellationToken.None);
            if (mode == "request") await Assert.That(Send).Throws<UriFormatException>();
            else await Assert.That(Send).Throws<ObjectDisposedException>();
            await Assert.That(serialized).IsTrue();
            await Assert.That(buffers.Count).IsEqualTo(1);
            await Assert.That(buffers.All(AllZero)).IsTrue();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    [Test]
    [Arguments("success")]
    [Arguments("success-growth")]
    [Arguments("cancel")]
    [Arguments("pre-cancel")]
    [Arguments("http")]
    [Arguments("status")]
    [Arguments("json")]
    [Arguments("binding")]
    [Arguments("duplicate")]
    [Arguments("size")]
    public async Task HttpExitsClearTheActualSerializedBackingBuffer(string mode)
    {
        var buffers = new List<byte[]>();
        using var cancellation = new CancellationTokenSource();
        bool dispatched = false;
        bool backingMatches = false;
        bool populated = false;
        bool wireMatches = false;
        using var handler = new Handler(async (request, token) =>
        {
            token.ThrowIfCancellationRequested();
            dispatched = true;
            using var capture = new BufferCaptureStream();
            await request.Content!.CopyToAsync(capture, token);
            ArraySegment<byte> backing = capture.Buffer;
            backingMatches = ReferenceEquals(backing.Array, buffers[^1]);
            populated = backing.AsSpan().ContainsAnyExcept((byte)0);
            using JsonDocument body = JsonDocument.Parse(backing.AsMemory());
            byte[] decoded = body.RootElement.GetProperty("privateKey").GetBytesFromBase64();
            try { wireMatches = decoded.Length == 32 && decoded.All(value => value == 0xa5); }
            finally { CryptographicOperations.ZeroMemory(decoded); }
            if (mode == "cancel")
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
            }
            if (mode == "http") throw new HttpRequestException();
            if (mode == "status") return new(HttpStatusCode.ServiceUnavailable);
            if (mode == "json") return new(HttpStatusCode.OK) { Content = new StringContent("{") };
            if (mode == "size")
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(new byte[1024 * 1024 + 1]) };
            JsonObject response = Envelope(new JsonObject
            {
                ["nonce"] = body.RootElement.GetProperty("nonce").GetString()
            }, 42);
            if (mode == "binding") response["nonce"] = "other-request";
            if (mode == "duplicate") return new(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString().Replace("\"schemaVersion\":1",
                    "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal))
            };
            return Reply(response);
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler, length =>
        {
            byte[] buffer = new byte[length];
            buffers.Add(buffer);
            return buffer;
        });
        byte[] key = Enumerable.Repeat((byte)0xa5, 32).ToArray();
        try
        {
            if (mode == "pre-cancel") cancellation.Cancel();
            async Task<int> Send() => await observer.PostAsync<int>("private", writer =>
            {
                writer.WriteBase64String("privateKey", key);
                if (mode == "success-growth") writer.WriteString("padding", new string('x', 8192));
            }, cancellation.Token);
            if (mode is "success" or "success-growth") await Assert.That(await Send()).IsEqualTo(42);
            else if (mode is "cancel" or "pre-cancel")
                await Assert.That(Send).Throws<OperationCanceledException>();
            else await Assert.That(Send).Throws<NativeCaseFailureException>();
            await Assert.That(dispatched).IsEqualTo(mode != "pre-cancel");
            if (dispatched)
            {
                await Assert.That(backingMatches).IsTrue();
                await Assert.That(populated).IsTrue();
                await Assert.That(wireMatches).IsTrue();
            }
            await Assert.That(buffers.Count).IsEqualTo(mode == "success-growth" ? 2 : 1);
            await Assert.That(buffers.All(AllZero)).IsTrue();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static bool AllZero(byte[] buffer) => buffer.All(value => value == 0);

    private static bool ContainsEncodedKey(byte[] buffer, byte[] key)
    {
        Span<byte> encoded = stackalloc byte[44];
        try
        {
            System.Buffers.Text.Base64.EncodeToUtf8(key, encoded, out _, out int written);
            return buffer.AsSpan().IndexOf(encoded[..written]) >= 0;
        }
        finally { CryptographicOperations.ZeroMemory(encoded); }
    }

    private sealed class BufferCaptureStream : Stream
    {
        internal ArraySegment<byte> Buffer { get; private set; }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => Buffer = new(buffer, offset, count);
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!MemoryMarshal.TryGetArray(buffer, out ArraySegment<byte> backing)) throw new InvalidOperationException();
            Buffer = backing;
            return ValueTask.CompletedTask;
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PrivateFamilyInputsSelectOnlyExplicitObserver(bool configured)
    {
        var family = new JsonObject();
        if (configured) family["observer"] = JsonSerializer.SerializeToNode(Settings, ServiceJson);
        var settings = new JsonObject
        {
            ["origin"] = "https://infisical.invalid",
            ["setup"] = "setup",
            ["runtime"] = "runtime",
            ["denied"] = "denied",
            ["administrative"] = "administrative",
            ["observer"] = "observer",
            ["families"] = new JsonObject { [InfisicalDynamicClientEffects.Family] = family }
        };
        using JsonDocument document = JsonDocument.Parse(settings.ToJsonString());
        using NativeEnvironment environment = NativeEnvironment.Create(document.RootElement);
        InfisicalLifecycleObservers? observer = InfisicalLifecycleObservers.FromInputs(environment,
            InfisicalDynamicClientEffects.Family);
        await Assert.That(observer is not null).IsEqualTo(configured);
    }

    [Test]
    [Arguments("http://observer.invalid/")]
    [Arguments("https://user@observer.invalid/")]
    [Arguments("https://observer.invalid/?token=value")]
    [Arguments("https://observer.invalid/#token")]
    [Arguments("https://observer.invalid/no-trailing-slash")]
    public async Task InvalidObserverOriginFailsBeforeCredentialForwarding(string endpoint)
    {
        await Assert.That(() => new InfisicalLifecycleObservers(Settings with { Endpoint = new(endpoint) }))
            .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("identity")]
    [Arguments("schema")]
    [Arguments("stale")]
    [Arguments("future")]
    [Arguments("null-facts")]
    public async Task UnboundMeasurementCannotBecomeAnEffect(string mode)
    {
        DynamicBackendCoordinate coordinate = Coordinate();
        int requests = 0;
        using var handler = new Handler(async (request, token) =>
        {
            requests++;
            JsonObject body = await Body(request, token);
            JsonObject response = Envelope(body, Facts(coordinate));
            switch (mode)
            {
                case "nonce": response["nonce"] = "other-request"; break;
                case "identity": response["observerIdentity"] = "wrong-service"; break;
                case "schema": response["schemaVersion"] = 2; break;
                case "stale": response["observedAt"] = DateTimeOffset.UnixEpoch; break;
                case "future": response["observedAt"] = DateTimeOffset.UtcNow.AddDays(1); break;
                case "null-facts": response["facts"] = null; break;
            }
            return Reply(response);
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var username = SecretMaterial.FromText("owned-user");
        using var password = SecretMaterial.FromText("owned-password");
        await Assert.That(async () => await observer.MeasureAsync(coordinate, username, password, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
        await Assert.That(requests).IsEqualTo(1);
    }

    [Test]
    public async Task DynamicMeasurementUsesExplicitServiceAndActualReturnedFacts()
    {
        DynamicBackendCoordinate coordinate = Coordinate();
        DynamicBackendFacts expected = Facts(coordinate);
        using var handler = new Handler(async (request, token) =>
        {
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://observer.invalid/owned/dynamic/measure");
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("fixture-observer");
            JsonObject body = await Body(request, token);
            await Assert.That(body["username"]!.GetValue<string>()).IsEqualTo("owned-user");
            await Assert.That(body["password"]!.GetValue<string>()).IsEqualTo("owned-password");
            return Reply(Envelope(body, expected));
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var username = SecretMaterial.FromText("owned-user");
        using var password = SecretMaterial.FromText("owned-password");
        DynamicBackendFacts measured = await observer.MeasureAsync(coordinate, username, password, CancellationToken.None);
        await Assert.That(measured.Coordinate).IsEqualTo(coordinate);
        await Assert.That(measured.Authentication).IsEqualTo(BackendAuthentication.Accepted);
        await Assert.That(measured.ExpiresAt).IsEqualTo(expected.ExpiresAt);
    }

    [Test]
    [Arguments("good")]
    [Arguments("incomplete")]
    [Arguments("coordinate")]
    [Arguments("requested")]
    [Arguments("duplicate")]
    [Arguments("foreign")]
    [Arguments("missing-complete")]
    [Arguments("missing-existing")]
    public async Task UsernameInventoryRequiresCompleteBoundClusterFacts(string mode)
    {
        var coordinate = new DynamicUsernameCoordinate(NativeSqlEngine.Postgres, "database.invalid", 5432, "owned");
        string[] names = ["sk_u_0123456789abcdef_a", "sk_u_0123456789abcdef_b"];
        using var handler = new Handler(async (request, token) =>
        {
            await Assert.That(request.RequestUri!.AbsoluteUri).IsEqualTo("https://observer.invalid/owned/dynamic/usernames");
            await Assert.That(request.Headers.Authorization!.Parameter).IsEqualTo("fixture-observer");
            JsonObject body = await Body(request, token);
            await Assert.That(body["usernames"]!.AsArray().Select(item => item!.GetValue<string>()).ToArray())
                .IsEquivalentTo(names);
            await Assert.That(body.ContainsKey("password")).IsFalse();
            JsonObject response = Envelope(body, new DynamicUsernameFacts(coordinate, names, [names[0]], true));
            JsonObject facts = response["facts"]!.AsObject();
            switch (mode)
            {
                case "incomplete": facts["isComplete"] = false; break;
                case "coordinate": facts["coordinate"]!["database"] = "foreign"; break;
                case "requested": facts["requestedUsernames"] = new JsonArray(names[1], names[0]); break;
                case "duplicate": facts["existingUsernames"] = new JsonArray(names[0], names[0]); break;
                case "foreign": facts["existingUsernames"] = new JsonArray("foreign-role"); break;
                case "missing-complete": facts.Remove("isComplete"); break;
                case "missing-existing": facts.Remove("existingUsernames"); break;
            }
            return Reply(response);
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        if (mode == "good")
        {
            var facts = await observer.InspectUsernamesAsync(coordinate, names, CancellationToken.None);
            await Assert.That(facts.ExistingUsernames).IsEquivalentTo(new[] { names[0] });
        }
        else
            await Assert.That(async () => await observer.InspectUsernamesAsync(coordinate, names, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
    }

    [Test]
    [Arguments("Accepted", false)]
    [Arguments("Rejected", true)]
    public async Task ExpiryRequiresRejectionAndAnActualElapsedLifetime(string authentication, bool future)
    {
        DateTimeOffset expiry = future ? DateTimeOffset.UtcNow.AddDays(1) : DateTimeOffset.UnixEpoch;
        using var handler = new Handler(async (request, token) => Reply(Envelope(await Body(request, token),
            new { authentication = Enum.Parse<BackendAuthentication>(authentication), expiresAt = expiry })));
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var issued = SecretMaterial.FromText("owned-token");
        var previous = new InfisicalTokenLifetimeEvidence
        {
            OriginalIssuedAt = expiry.AddMinutes(-1),
            ExpiresAt = expiry,
            Lifetime = InfisicalTokenLifetime.Finite,
            ReportedMaximumTtl = TimeSpan.FromMinutes(1)
        };
        string? reason = null;
        try { await observer.ExpiredAsync(issued, previous, CancellationToken.None); }
        catch (NativeCaseFailureException error) { reason = error.Message; }
        await Assert.That(reason).IsEqualTo("effect-mismatch");
    }

    [Test]
    [Arguments("bound")]
    [Arguments("missing")]
    [Arguments("legacy")]
    public async Task RotationMeasurementRequiresExplicitPreviousActiveCredentialField(string mode)
    {
        var coordinate = new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
            "database.invalid", 5432, "owned", "owned-account");
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject response = Envelope(await Body(request, token),
                new RotationBackendFacts(coordinate, 1, BackendAuthentication.Accepted, BackendAuthentication.Accepted,
                    ["select"], ["write"], RotationBackendEvent.ManualCredentialChange, DateTimeOffset.UtcNow));
            if (mode != "bound")
                response["facts"]!.AsObject().Remove("previousActiveCredentialAuthentication");
            if (mode == "legacy")
                response["facts"]!["previousCredentialAuthentication"] = "Rejected";
            return Reply(response);
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        if (mode == "bound")
            await Assert.That((await observer.MeasureAsync(coordinate, CancellationToken.None))
                .PreviousActiveCredentialAuthentication).IsEqualTo(BackendAuthentication.Accepted);
        else
            await Assert.That(async () => await observer.MeasureAsync(coordinate, CancellationToken.None))
                .Throws<NativeCaseFailureException>();
    }

    [Test]
    public async Task RotationSubscriptionIsArmedBeforeTriggerAndReleasedAfterObservation()
    {
        var coordinate = new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
            "database.invalid", 5432, "owned", "owned-account");
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var trigger = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        bool armed = false;
        int disarmed = 0;
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = await Body(request, token);
            if (request.RequestUri!.AbsolutePath.EndsWith("/arm", StringComparison.Ordinal))
            {
                armed = true;
                return Reply(Envelope(body, new { id = "owned-subscription", coordinate, remainingRegistrations = 1 }));
            }
            if (request.RequestUri.AbsolutePath.EndsWith("/observe", StringComparison.Ordinal))
            {
                await Assert.That(armed).IsTrue();
                entered.TrySetResult();
                await trigger.Task.WaitAsync(token);
                return Reply(Envelope(body, new RotationBackendFacts(coordinate, 2, BackendAuthentication.Accepted,
                    BackendAuthentication.Accepted, ["select"], ["write"],
                    RotationBackendEvent.ManualCredentialChange, DateTimeOffset.UtcNow)));
            }
            await Assert.That(request.RequestUri.AbsolutePath.EndsWith("/disarm", StringComparison.Ordinal)).IsTrue();
            disarmed++;
            return Reply(Envelope(body, new { id = "owned-subscription", remainingRegistrations = 0 }));
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        IInfisicalRotationBackendSubscription subscription = await observer.SubscribeAsync(coordinate, CancellationToken.None);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(subscription.Observed.IsCompleted).IsFalse();
            trigger.TrySetResult();
            RotationBackendFacts measured = await subscription.Observed.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(measured.PasswordGeneration).IsEqualTo(2);
            await Assert.That(measured.Coordinate).IsEqualTo(coordinate);
            await Assert.That(measured.PreviousActiveCredentialAuthentication).IsEqualTo(BackendAuthentication.Accepted);
        }
        finally
        {
            trigger.TrySetResult();
            await subscription.DisposeAsync();
        }
        await Assert.That(disarmed).IsEqualTo(1);
    }

    [Test]
    public async Task FailedEventStillReleasesOwnedSubscription()
    {
        var coordinate = new RotationBackendCoordinate(InfisicalRotationProfile.PostgresCredentials,
            "database.invalid", 5432, "owned", "owned-account");
        int disarmed = 0;
        using var handler = new Handler(async (request, token) =>
        {
            JsonObject body = await Body(request, token);
            if (request.RequestUri!.AbsolutePath.EndsWith("/arm", StringComparison.Ordinal))
                return Reply(Envelope(body, new { id = "owned-subscription", coordinate, remainingRegistrations = 1 }));
            if (request.RequestUri.AbsolutePath.EndsWith("/observe", StringComparison.Ordinal))
                return new(HttpStatusCode.ServiceUnavailable);
            disarmed++;
            return Reply(Envelope(body, new { id = "owned-subscription", remainingRegistrations = 0 }));
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        IInfisicalRotationBackendSubscription subscription = await observer.SubscribeAsync(coordinate, CancellationToken.None);
        await Assert.That(async () => await subscription.DisposeAsync()).Throws<NativeCaseFailureException>();
        await Assert.That(disarmed).IsEqualTo(1);
    }

    private static async Task<JsonObject> Body(HttpRequestMessage request, CancellationToken token) =>
        (JsonObject)JsonNode.Parse(await request.Content!.ReadAsByteArrayAsync(token))!;

    [Test]
    public async Task DuplicateResponseKeysCannotOverrideObserverBinding()
    {
        DynamicBackendCoordinate coordinate = Coordinate();
        using var handler = new Handler(async (request, token) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(Envelope(await Body(request, token), Facts(coordinate)).ToJsonString()
                .Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal))
        });
        var observer = new InfisicalLifecycleObservers(Settings, handler);
        using var username = SecretMaterial.FromText("owned-user");
        using var password = SecretMaterial.FromText("owned-password");
        await Assert.That(async () => await observer.MeasureAsync(coordinate, username, password, CancellationToken.None))
            .Throws<NativeCaseFailureException>();
    }

    private static JsonObject Envelope<T>(JsonObject body, T facts) => new()
    {
        ["schemaVersion"] = 1,
        ["nonce"] = body["nonce"]!.DeepClone(),
        ["observerIdentity"] = Settings.Identity,
        ["observedAt"] = DateTimeOffset.UtcNow,
        ["facts"] = JsonSerializer.SerializeToNode(facts, ServiceJson)
    };

    private static HttpResponseMessage Reply(JsonObject body) =>
        new(HttpStatusCode.OK) { Content = new StringContent(body.ToJsonString()) };

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
