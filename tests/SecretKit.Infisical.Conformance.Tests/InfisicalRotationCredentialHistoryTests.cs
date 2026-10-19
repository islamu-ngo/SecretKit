using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalRotationCredentialHistoryTests
{
    private static readonly JsonSerializerOptions InputJson = new(InfisicalLifecycleFamilies.Options)
    {
        IgnoreReadOnlyProperties = false
    };

    [Test]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, false, 1, "observed")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, false, 1, "observed")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, false, 1, "observed")]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, true, 1, "effect-mismatch")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, true, 1, "effect-mismatch")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, true, 1, "effect-mismatch")]
    [Arguments(InfisicalRotationProfile.PostgresCredentials, false, 2, "effect-mismatch")]
    [Arguments(InfisicalRotationProfile.MysqlCredentials, false, 2, "effect-mismatch")]
    [Arguments(InfisicalRotationProfile.MssqlCredentials, false, 2, "effect-mismatch")]
    public async Task ManualRotationRequiresRetainedPreviousActivePairAndExactlyOneGeneration(
        InfisicalRotationProfile profile, bool revokePrevious, int generationStep, string expectedReason)
    {
        // Given: independent account passwords, an owned rotation, and a real public static client.
        var input = Input(profile);
        var store = new CredentialStore(input.Backend, input.Username1, input.Username2);
        using var wire = new RotationWire(store, revokePrevious, generationStep);
        await using var reads = new StaticReadBackend(store, wire);
        var admission = InfisicalLifecycleFamilies.Catalog.Single(a =>
            a.Operation == "i.runtime.InfisicalRotationClient.RotateSecretsAsync");
        var row = new NativeCaseDefinition(new("Infisical", admission.Operation, "profile." + profile,
            "owned-history", "independent-effect"), admission.Member);
        using var env = Environment(row, input);
        var registry = new NativeCaseRegistry();
        InfisicalRotationClientEffects.Register(registry, env, [row], new RotationFactory(wire, store),
            store, wire, selected => new InfisicalClient(reads.Origin, selected.Tokens(NativeIdentityRole.Runtime),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true }));

        // When: the registered native family performs the manual rotation.
        var result = (await NativeCaseRunner.RunAsync(registry, [row], CancellationToken.None)).Single();

        // Then: cleanup and independent facts survive even a failed effect contract.
        await Assert.That(store.LiveAccounts).IsEqualTo(0);
        await Assert.That(store.Mutations).IsEqualTo(1);
        await Assert.That(store.Subscriptions).IsEqualTo(0);
        await Assert.That(result.ReasonCode).IsEqualTo(expectedReason);
        await Assert.That(result.Passed).IsEqualTo(expectedReason == "observed");
        if (expectedReason == "observed")
        {
            await reads.Delivered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(reads.CompletedReads).IsEqualTo(2);
            await Assert.That(store.ConsumerAuthentications).IsEqualTo(1);
        }
    }

    [Test]
    [Arguments(InfisicalRotationProfile.PostgresCredentials)]
    [Arguments(InfisicalRotationProfile.MysqlCredentials)]
    [Arguments(InfisicalRotationProfile.MssqlCredentials)]
    public async Task FixtureOnlyTwoCyclesOverwriteInactiveAccountRatherThanPreviousActivePair(
        InfisicalRotationProfile profile)
    {
        // Given: this characterizes the fixture, not a core overwritten-history check.
        var input = Input(profile);
        var store = new CredentialStore(input.Backend, input.Username1, input.Username2);
        var a0 = store.Active;
        using var a0User = SecretMaterial.FromText(a0.User);
        using var a0Password = SecretMaterial.FromText(a0.Password);
        try
        {
            // When: A0 -> B1 -> A2, retaining the immediately previous active account.
            await using var first = await store.SubscribeAsync(input.Backend, CancellationToken.None);
            store.Rotate(false, 1);
            await first.Observed.WaitAsync(TimeSpan.FromSeconds(5));
            await Assert.That(await store.AuthenticateAsync(input.Backend, a0User, a0Password, CancellationToken.None))
                .IsEqualTo(BackendAuthentication.Accepted);
            var b1 = store.Active;
            using var b1User = SecretMaterial.FromText(b1.User);
            using var b1Password = SecretMaterial.FromText(b1.Password);
            await using var second = await store.SubscribeAsync(input.Backend, CancellationToken.None);
            store.Rotate(false, 1);
            await second.Observed.WaitAsync(TimeSpan.FromSeconds(5));

            // Then: the overwritten A0 pair fails; B1 still authenticates.
            await Assert.That(await store.AuthenticateAsync(input.Backend, a0User, a0Password, CancellationToken.None))
                .IsEqualTo(BackendAuthentication.Rejected);
            await Assert.That(await store.AuthenticateAsync(input.Backend, b1User, b1Password, CancellationToken.None))
                .IsEqualTo(BackendAuthentication.Accepted);
            await Assert.That(store.Active.User).IsEqualTo(a0.User);
            await Assert.That(store.Generation).IsEqualTo(2);
        }
        finally { store.RevokeAll(); }
        await Assert.That((await store.MeasureAsync(input.Backend, CancellationToken.None)).Authentication)
            .IsEqualTo(BackendAuthentication.Rejected);
        await Assert.That(store.LiveAccounts).IsEqualTo(0);
    }

    private static InfisicalRotationClientEffects.RotationInput Input(InfisicalRotationProfile profile) =>
        new(new("project", "project-slug", "env", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "/owned"),
            "organization", profile, Guid.NewGuid().ToString("D"),
            new(profile, "owned-backend.invalid", 5432, "owned-database", "owned-account"),
            "owned-a", "owned-b", null, 1, false, 128, ["select"], ["write"]);

    private static NativeEnvironment Environment(NativeCaseDefinition row,
        InfisicalRotationClientEffects.RotationInput input) => NativeEnvironment.Create(
        JsonSerializer.SerializeToElement(new
        {
            origin = "https://rotation.invalid/",
            setup = "setup",
            runtime = "runtime",
            denied = "denied",
            administrative = "administrative",
            observer = "observer",
            families = new JsonObject
            {
                [InfisicalRotationClientEffects.Family] = new JsonObject
                {
                    ["scopes"] = new JsonObject
                    {
                        [row.Key.Scope] = new JsonObject
                        {
                            [row.Key.Operation] = new JsonObject
                            {
                                [row.Key.Variant] = new JsonObject
                                {
                                    [row.Key.Case] = JsonSerializer.SerializeToNode(input, InputJson)
                                }
                            }
                        }
                    }
                }
            }
        }, InputJson));

    private sealed class CredentialStore(RotationBackendCoordinate coordinate, string accountA, string accountB)
        : IInfisicalRotationBackendObserver
    {
        private readonly Dictionary<string, string> accounts = new()
        {
            [accountA] = "owned-a-password-0",
            [accountB] = "owned-b-password-0"
        };
        private readonly object gate = new();
        private (string User, string Password) active = (accountA, "owned-a-password-0");
        private Subscription? subscription;
        private long generation;
        internal (string User, string Password) Active { get { lock (gate) return active; } }
        internal long Generation { get { lock (gate) return generation; } }
        internal int LiveAccounts { get { lock (gate) return accounts.Count; } }
        internal int Mutations { get; private set; }
        internal int Subscriptions { get; private set; }
        internal int ConsumerAuthentications { get; private set; }

        private BackendAuthentication Authenticate((string User, string Password) pair) =>
            accounts.TryGetValue(pair.User, out var password) && password == pair.Password ?
                BackendAuthentication.Accepted : BackendAuthentication.Rejected;

        internal void Rotate(bool revokePrevious, int generationStep)
        {
            lock (gate)
            {
                var armed = subscription ?? throw new InvalidOperationException("fixture-subscription-not-armed");
                var previousActive = active;
                string nextUser = active.User == accountA ? accountB : accountA;
                generation += generationStep;
                string nextPassword = "owned-password-" + generation;
                accounts[nextUser] = nextPassword;
                if (revokePrevious) accounts.Remove(previousActive.User);
                active = (nextUser, nextPassword);
                Mutations++;
                armed.Signal(new(coordinate, generation, Authenticate(active), Authenticate(previousActive),
                    ["select"], ["write"], RotationBackendEvent.ManualCredentialChange, DateTimeOffset.UtcNow));
            }
        }

        internal void RevokeAll() { lock (gate) accounts.Clear(); }
        public ValueTask<RotationBackendFacts> MeasureAsync(RotationBackendCoordinate requested, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (requested != coordinate) throw new InvalidOperationException("fixture-coordinate");
                return ValueTask.FromResult(new RotationBackendFacts(coordinate, generation, Authenticate(active),
                    BackendAuthentication.Rejected, ["select"], ["write"], RotationBackendEvent.Snapshot, DateTimeOffset.UtcNow));
            }
        }

        public ValueTask<BackendAuthentication> AuthenticateAsync(RotationBackendCoordinate requested,
            SecretMaterial username, SecretMaterial password, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (requested != coordinate) throw new InvalidOperationException("fixture-coordinate");
                ConsumerAuthentications++;
                return ValueTask.FromResult(Authenticate((username.Reveal(), password.Reveal())));
            }
        }

        public ValueTask<IInfisicalRotationBackendSubscription> SubscribeAsync(
            RotationBackendCoordinate requested, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            lock (gate)
            {
                if (requested != coordinate || subscription is { Pending: true })
                    throw new InvalidOperationException("fixture-subscription");
                Subscriptions++;
                subscription = new Subscription(() => { lock (gate) Subscriptions--; });
                return ValueTask.FromResult<IInfisicalRotationBackendSubscription>(subscription);
            }
        }

        private sealed class Subscription(Action disarm) : IInfisicalRotationBackendSubscription
        {
            private readonly TaskCompletionSource<RotationBackendFacts> signal =
                new(TaskCreationOptions.RunContinuationsAsynchronously);
            private bool disposed;
            public Task<RotationBackendFacts> Observed => signal.Task;
            internal bool Pending => !signal.Task.IsCompleted;
            internal void Signal(RotationBackendFacts facts) => signal.SetResult(facts);
            public ValueTask DisposeAsync()
            {
                if (!disposed) { disposed = true; disarm(); }
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class RotationFactory(RotationWire wire, CredentialStore store) : IInfisicalRotationFixtureFactory
    {
        public ValueTask<IInfisicalRotationOwnedFixture> CreateAsync(NativeEnvironment env,
            InfisicalRotationClientEffects.RotationInput input, NativeCaseProbe probe, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            wire.Address = new(input.Sandbox.ProjectId, input.Sandbox.Environment,
                input.Sandbox.Parent + "/history-" + Guid.NewGuid().ToString("N"), input.Profile, Guid.NewGuid().ToString("D"));
            return ValueTask.FromResult<IInfisicalRotationOwnedFixture>(new OwnedFixture(wire.Address, input.Backend, store));
        }

        private sealed class OwnedFixture(InfisicalRotationAddress address, RotationBackendCoordinate coordinate,
            CredentialStore store) : IInfisicalRotationOwnedFixture
        {
            public InfisicalRotationAddress Address => address;
            public RotationBackendCoordinate Coordinate => coordinate;
            public string UsernameKey => "owned-user";
            public string PasswordKey => "owned-password";
            public ValueTask DisposeAsync() { store.RevokeAll(); return ValueTask.CompletedTask; }
        }
    }

    private sealed class RotationWire(CredentialStore store, bool revokePrevious, int generationStep) : HttpMessageHandler
    {
        internal InfisicalRotationAddress? Address { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            var address = Address ?? throw new InvalidOperationException("fixture-address");
            string type = address.Profile switch
            {
                InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
                InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
                InfisicalRotationProfile.MssqlCredentials => "mssql-credentials",
                _ => throw new InvalidOperationException("fixture-profile")
            };
            string path = "/api/v2/secret-rotations/" + type + "/" + address.RotationId;
            if (request.RequestUri!.Scheme != "https" || request.RequestUri.Host != "rotation.invalid" ||
                request.RequestUri.AbsolutePath != path && request.RequestUri.AbsolutePath != path + "/rotate-secrets")
                throw new InvalidOperationException("fixture-rotation-route");
            if (request.Method == HttpMethod.Post && request.RequestUri.AbsolutePath == path + "/rotate-secrets")
                store.Rotate(revokePrevious, generationStep);
            else if (request.Method != HttpMethod.Get || request.RequestUri.AbsolutePath != path)
                throw new InvalidOperationException("fixture-rotation-method");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(new
                {
                    secretRotation = new
                    {
                        id = address.RotationId,
                        projectId = address.ProjectId,
                        type,
                        environment = new { slug = address.Environment },
                        folder = new { path = address.Folder },
                        rotationStatus = store.Mutations == 0 ? "success" : "pending",
                        lastRotationAttemptedAt = DateTimeOffset.UnixEpoch,
                        lastRotatedAt = DateTimeOffset.UnixEpoch,
                        isAutoRotationEnabled = false
                    }
                }))
            });
        }
    }

    private sealed class StaticReadBackend : IAsyncDisposable
    {
        private readonly CredentialStore store;
        private readonly RotationWire wire;
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource shutdown = new();
        private readonly List<Task> connections = [];
        private readonly Task accept;
        internal Uri Origin { get; }
        private int completedReads;
        internal int CompletedReads => Volatile.Read(ref completedReads);
        internal TaskCompletionSource Delivered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal StaticReadBackend(CredentialStore store, RotationWire wire)
        {
            this.store = store;
            this.wire = wire;
            listener.Start();
            Origin = new($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
            accept = AcceptAsync();
        }

        private async Task AcceptAsync()
        {
            try
            {
                while (!shutdown.IsCancellationRequested)
                    connections.Add(ServeAsync(await listener.AcceptTcpClientAsync(shutdown.Token)));
            }
            catch (OperationCanceledException) when (shutdown.IsCancellationRequested) { }
        }

        private async Task ServeAsync(TcpClient socket)
        {
            using (socket)
            using (var budget = CancellationTokenSource.CreateLinkedTokenSource(shutdown.Token))
            {
                budget.CancelAfter(TimeSpan.FromSeconds(15));
                var stream = socket.GetStream();
                var headers = new List<byte>();
                byte[] one = new byte[1];
                while (headers.Count < 32768)
                {
                    await stream.ReadExactlyAsync(one, budget.Token);
                    headers.Add(one[0]);
                    if (headers.Count >= 4 && headers.TakeLast(4).SequenceEqual("\r\n\r\n"u8.ToArray())) break;
                }
                if (headers.Count == 32768) throw new InvalidOperationException("fixture-header-budget");
                string[] lines = Encoding.ASCII.GetString(headers.ToArray()).Split("\r\n");
                string[] request = lines[0].Split(' ');
                var uri = new Uri(Origin, request[1]);
                var address = wire.Address ?? throw new InvalidOperationException("fixture-address");
                var query = uri.Query.TrimStart('?').Split('&').Select(p => p.Split('=', 2))
                    .ToDictionary(p => Uri.UnescapeDataString(p[0]), p => Uri.UnescapeDataString(p[1]));
                if (request[0] != "GET" || !lines.Any(l => l.Equals("Authorization: Bearer runtime",
                    StringComparison.OrdinalIgnoreCase)) || query["projectId"] != address.ProjectId ||
                    query["environment"] != address.Environment || query["secretPath"] != address.Folder)
                    throw new InvalidOperationException("fixture-static-scope");
                var active = store.Active;
                string key = uri.AbsolutePath switch
                {
                    "/api/v4/secrets/owned-user" => "owned-user",
                    "/api/v4/secrets/owned-password" => "owned-password",
                    _ => throw new InvalidOperationException("fixture-static-key")
                };
                byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
                {
                    secret = new
                    {
                        secretKey = key,
                        secretValue = key == "owned-user" ? active.User : active.Password,
                        secretValueHidden = false,
                        version = store.Generation + 1
                    }
                });
                byte[] responseHeaders = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 200 Fixture\r\nContent-Type: application/json\r\nContent-Length: {payload.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(responseHeaders, budget.Token);
                await stream.WriteAsync(payload, budget.Token);
                if (Interlocked.Increment(ref completedReads) == 2) Delivered.SetResult();
            }
        }

        public async ValueTask DisposeAsync()
        {
            await shutdown.CancelAsync();
            await accept;
            listener.Stop();
            await Task.WhenAll(connections).WaitAsync(TimeSpan.FromSeconds(15));
            shutdown.Dispose();
        }
    }
}
