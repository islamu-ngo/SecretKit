using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Effects = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationEffects;
using ReadSource = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultReadFixtureObserverService;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ImmutableNameSnapshotStaysLiveUntilActualSdkBorrowerDrains(bool observer)
    {
        await using var f = new NameReadFixture();
        var lease = observer ? await f.PrepareAndArm() : await f.PrepareAndBaseline();
        f.Fault = observer ? "stateful-observer" : "stateful-request";
        f.Barrier = observer ? "observer-sdk" : "sdk";
        Task borrowed = observer ? f.Baseline(lease).AsTask() : f.Start(lease);
        Task disposal = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(f.BorrowedNameBuffers.Count > 0).IsTrue();
            await Assert.That(f.BorrowedNameBuffers.All(bytes => bytes.Any(b => b != 0))).IsTrue();
            disposal = f.Source.DisposeAsync().AsTask();
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(f.BorrowedNameBuffers.All(bytes => bytes.Any(b => b != 0))).IsTrue();
        }
        finally { f.Resume.TrySetResult(); }
        if (observer)
            await Assert.That(async () => await borrowed.WaitAsync(TimeSpan.FromSeconds(10))).Throws<NativeCaseFailureException>();
        else
            await Assert.That(async () => await borrowed.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await disposal.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.BorrowedNameBuffers.All(bytes => bytes.All(b => b == 0))).IsTrue();
        await Assert.That(f.ForeignQueries).IsEqualTo(0);
    }

    [Test]
    public async Task StatefulNameContentCannotChangeTheActuallyDispatchedOwnedName()
    {
        await using var f = new NameReadFixture { Fault = "stateful-request" };
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.ForeignQueries).IsEqualTo(0);
        await Assert.That(f.SelectedQueries).IsEqualTo(1);
    }

    [Test]
    public async Task StatefulObserverContentCannotChangeTheActuallyDispatchedOwnedName()
    {
        await using var f = new NameReadFixture { Fault = "stateful-observer" };
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.ForeignQueries).IsEqualTo(0);
    }

    [Test]
    [Arguments("selected-contract")]
    [Arguments("independent-effect")]
    [Arguments("denied-authority")]
    [Arguments("cancellation-boundary")]
    [Arguments("lost-response-no-replay")]
    public async Task OriginalNameQueryJoinsActualReadPostAndIndependentOwnedNameWitness(string boundary)
    {
        await using var f = new NameReadFixture(boundary);
        await Assert.That((await f.RunOriginal()).Passed).IsTrue();
        await Assert.That(f.SelectedQueries).IsEqualTo(1);
        await Assert.That(f.MetadataQueries >= 2).IsTrue();
        await Assert.That(f.Native.Read().Resources.Length).IsEqualTo(3);
        await Assert.That(f.Native.Read().Resources.Any(r => r.SelectedAttempted)).IsFalse();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments("selected-malformed")]
    [Arguments("selected-oversized")]
    [Arguments("selected-null")]
    [Arguments("selected-true")]
    [Arguments("metadata-true")]
    [Arguments("post-true")]
    public async Task NameQueryCannotQualifyUnprovenNativeBoolean(string fault)
    {
        await using var f = new NameReadFixture { Fault = fault };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedQueries <= 1).IsTrue();
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task ExceptionOnlyDenialCannotQualifyOriginalNameQuery()
    {
        await using var f = new NameReadFixture("denied-authority") { Fault = "denial-without-response" };
        await Assert.That((await f.RunOriginal()).Passed).IsFalse();
        await Assert.That(f.SelectedQueries).IsEqualTo(1);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task NameQueryTimerFailureCannotStrandOriginalLoan()
    {
        var clock = new ReadTimer();
        await using var f = new NameReadFixture(time: clock);
        var lease = await f.PrepareAndBaseline();
        clock.Fail = true;
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        clock.Fail = false;
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedQueries).IsEqualTo(0);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task OriginalNameQueryCannotReplaySelectedInvocation()
    {
        await using var f = new NameReadFixture();
        var lease = await f.PrepareAndBaseline();
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(async () => await f.Start(lease)).Throws<InvalidOperationException>();
        await Assert.That(f.SelectedQueries).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ForeignNameQueryCoordinatesCannotConsumeOriginalAdmission(bool subscription)
    {
        await using var f = new NameReadFixture();
        var lease = await f.PrepareAndBaseline();
        var client = new VaultAdministration(new Credential("selected-arm"), f.Source.SelectedTransport);
        await Assert.That(async () => await f.Source.RunCheckNameAvailabilityAsync(f.Native.Selector, client,
            new(subscription ? Guid.NewGuid() : Subscription), subscription ? lease.VaultName : "foreign-name-vault", default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.SelectedQueries).IsEqualTo(0);
        await Assert.That((await f.Start(lease)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.SelectedQueries).IsEqualTo(1);
        RoleFixtureRelease.Validate(await f.Release(), f.Native.Selector, lease.Facts);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RestartedNameReadServiceOnlyRecoversCleanupCoordinates(bool selected)
    {
        await using var f = new NameReadFixture();
        var lease = await f.PrepareAndBaseline();
        if (selected) await f.Start(lease);
        await f.Source.DisposeAsync();
        await using var restarted = f.Reopen();
        using var observer = f.ObserverFor(restarted);
        RoleFixtureRelease.Validate(await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>(
            "vault/release", f.Native.Selector, default), f.Native.Selector, lease.Facts);
        await Assert.That(f.SelectedQueries).IsEqualTo(selected ? 1 : 0);
        await Assert.That(f.Native.Read().Released).IsTrue();
    }

    [Test]
    [Arguments(false, "credential")]
    [Arguments(true, "credential")]
    [Arguments(false, "transport")]
    [Arguments(true, "transport")]
    [Arguments(false, "body")]
    [Arguments(true, "body")]
    [Arguments(false, "sdk")]
    [Arguments(true, "sdk")]
    public async Task NameQueryClosureDrainsActualSelectedBorrower(bool dispose, string barrier)
    {
        await using var f = new NameReadFixture();
        var lease = await f.PrepareAndBaseline();
        f.Barrier = barrier;
        var selected = f.Start(lease);
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await selected.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedQueries).IsEqualTo(barrier == "credential" ? 0 : 1);
    }

    [Test]
    [Arguments(false, "observer-credential")]
    [Arguments(true, "observer-credential")]
    [Arguments(false, "observer-transport")]
    [Arguments(true, "observer-transport")]
    [Arguments(false, "observer-body")]
    [Arguments(true, "observer-body")]
    public async Task NameQueryClosureDrainsActualIndependentBorrower(bool dispose, string barrier)
    {
        await using var f = new NameReadFixture();
        var lease = await f.PrepareAndArm();
        f.Barrier = barrier;
        var observed = f.Baseline(lease).AsTask();
        Task closing = Task.CompletedTask;
        try
        {
            await f.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            closing = dispose ? f.Source.DisposeAsync().AsTask() : f.Release().AsTask();
            await Assert.That(f.Native.Read().Closing).IsTrue();
            await Assert.That(closing.IsCompleted).IsFalse();
        }
        finally { f.Resume.TrySetResult(); }
        await Assert.That(async () => await observed.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<NativeCaseFailureException>();
        await closing.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Read().Idle).IsTrue();
        await Assert.That(f.SelectedQueries).IsEqualTo(0);
    }

    private sealed class NameReadFixture : IAsyncDisposable
    {
        private const string Capability = "private-name-read-capability";
        private static readonly Uri Origin = new("https://vault-name-read.invalid/");
        internal readonly Fixture Native = new(allowPurge: true);
        internal readonly ReadSource Source;
        internal readonly OwnedManagementObserver Observer;
        private readonly VaultFixtureProvisioner provisioner;
        private readonly SecretMaterial capability = SecretMaterial.FromText(Capability);
        private readonly List<HttpClient> clients = [];
        private readonly HttpPipelineTransport metadataTransport, selectedTransport;
        private ObservationSubscription? subscription;
        internal string? Fault, Barrier;
        internal int SelectedQueries, MetadataQueries, ForeignQueries;
        internal Request? MetadataRequest;
        internal readonly List<byte[]> BorrowedNameBuffers = [];
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();

        internal NameReadFixture(string boundary = "selected-contract", TimeProvider? time = null)
        {
            Native.Selector = Native.Selector with
            {
                Operation = Effects.Members.Single(m => m.Operation.EndsWith(".CheckNameAvailabilityAsync", StringComparison.Ordinal)).Operation,
                Variant = "selector.exact",
                Case = boundary
            };
            HttpPipelineTransport Transport(string role)
            {
                var client = new HttpClient(new VaultForwarder((request, token) => Send(request, role, token)));
                clients.Add(client);
                var transport = new HttpClientTransport(client);
                return role == "read-name-metadata-arm" ? new NameMetadataTrace(transport, this) : transport;
            }
            provisioner = new(Native.Journal, new(Subscription, "fixture-group", "eastus", Tenant, true, true), Native.Baseline,
                new("setup-arm", new Credential("setup-arm"), Transport("setup-arm")),
                new("setup-secret", new Credential("setup-secret"), Transport("setup-secret")),
                new("read-arm", new Credential("read-arm"), Transport("read-arm")),
                new("read-secret", new Credential("read-secret"), Transport("read-secret")),
                new(65536, TimeSpan.FromSeconds(20)));
            metadataTransport = Transport("read-name-metadata-arm");
            selectedTransport = Transport("selected-arm");
            Source = Reopen(time);
            Observer = ObserverFor(Source);
        }
        internal ReadSource Reopen(TimeProvider? time = null) => new(Origin, Owner, "name-read-source", capability,
            new(Subscription, "fixture-group", "eastus", Tenant, true, true), provisioner,
            new("name-metadata", new NameReadCredential(this, true), metadataTransport), selectedTransport,
            new(2, 32, 65536, 8192, TimeSpan.FromSeconds(20)),
            new(65536, 65536, TimeSpan.FromSeconds(20)), time);
        internal OwnedManagementObserver ObserverFor(ReadSource source) =>
            new(new(Origin, Capability, TimeSpan.FromSeconds(20)), new VaultForwarder(source.DispatchAsync));
        internal Effects.Prepare PrepareRequest() => new(Native.Selector, Subscription, "fixture-group",
            Native.Baseline, [new(Tenant, Principal, [SecretPermission.Get], null)], Guid.Empty);
        internal async Task<Effects.Lease> PrepareAndArm()
        {
            var lease = await Observer.PostAsync<Effects.Prepare, Effects.Lease>("vault/prepare", PrepareRequest(), default);
            subscription = await Observer.SubscribeAsync("vault", lease.Facts, default);
            return lease;
        }
        internal async Task<Effects.Lease> PrepareAndBaseline()
        {
            var lease = await PrepareAndArm();
            await Baseline(lease);
            return lease;
        }
        internal ValueTask<Effects.Measurement> Baseline(Effects.Lease lease) =>
            Observer.PostAsync<ObserveLease, Effects.Measurement>("vault/observe",
                new(lease.Facts.LeaseId, lease.Facts.Nonce, "baseline-before-dispatch", subscription!.SubscriptionId), default);
        internal Task<SecretOutcome<VaultNameAvailability>> Start(Effects.Lease lease) =>
            Source.RunCheckNameAvailabilityAsync(Native.Selector,
                new VaultAdministration(new NameReadCredential(this, false), new NameReadSdk(Source.SelectedTransport, this)),
                new(Subscription), lease.VaultName, default).AsTask();
        internal ValueTask<RoleFixtureRelease.Measurement> Release() =>
            Observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("vault/release", Native.Selector, default);
        internal async Task<NativeCaseResult> RunOriginal()
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            AudienceToken Arm(string role) => new(role, DateTimeOffset.MaxValue, "https://management.azure.com/.default");
            using var json = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://controlled.vault.azure.net",
                setup = Runtime("setup-secret"),
                runtime = Runtime("runtime-secret"),
                denied = Runtime("denied-secret"),
                administrative = Runtime("admin-secret"),
                observer = Runtime("observer-secret"),
                families = new Dictionary<string, object>
                {
                    ["VaultAdministration"] = new Effects.Input(new(Origin, Capability, TimeSpan.FromSeconds(20)),
                        new(Arm("setup-arm"), Arm("selected-arm"), Arm("denied-arm"), Arm("observer-arm")),
                        Subscription, "fixture-group", Native.Baseline, PrepareRequest().IntendedPolicies,
                        Guid.Empty, 2, 32, TimeSpan.FromSeconds(20))
                }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(json.RootElement);
            var member = Effects.Members.Single(m => m.Operation == Native.Selector.Operation);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", member.Operation, "selector.exact",
                "controlled", Native.Selector.Case), member.Member);
            var registry = new NativeCaseRegistry();
            Effects.Register(registry, environment, [definition], endpoint => new(endpoint,
                new VaultForwarder(async (request, token) =>
                {
                    if (request.RequestUri!.AbsolutePath == "/vault/prepare")
                        Native.Selector = JsonSerializer.Deserialize<Effects.Prepare>(
                            await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!.Selection;
                    return await Source.DispatchAsync(request, token);
                })), selectedTransport: new NameReadSdk(Source.SelectedTransport, this), readSelectedInvocation: Source);
            return (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
        }
        private async Task<HttpResponseMessage> Send(HttpRequestMessage request, string role, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (Native.Wire.VaultId.Length == 0 && path.Contains("/vaults/", StringComparison.Ordinal))
            {
                Native.Wire.VaultId = path;
                Native.Wire.VaultName = path[(path.LastIndexOf('/') + 1)..];
            }
            if (path.EndsWith("/checkNameAvailability", StringComparison.Ordinal))
            {
                if (request.RequestUri.Host != "management.azure.com" || request.Method != HttpMethod.Post ||
                    path != $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/checkNameAvailability" ||
                    request.RequestUri.Query != "?api-version=2026-02-01" || request.Content is null ||
                    request.Headers.Authorization?.Parameter is not ("selected-arm" or "denied-arm" or "read-name-metadata-arm"))
                    throw new InvalidOperationException("unexpected-name-query");
                using var body = JsonDocument.Parse(await request.Content.ReadAsByteArrayAsync(token));
                if (body.RootElement.GetProperty("name").GetString() != Native.Wire.VaultName)
                {
                    ForeignQueries++;
                    if (Fault is not ("stateful-request" or "stateful-observer")) throw new InvalidOperationException("unexpected-query-name");
                }
                if (body.RootElement.EnumerateObject().Count() != 2 ||
                    body.RootElement.GetProperty("type").GetString() != "Microsoft.KeyVault/vaults")
                    throw new InvalidOperationException("unexpected-query-body");
                bool selected = role == "selected-arm";
                if (selected) SelectedQueries++;
                else MetadataQueries++;
                if (selected && Barrier == "transport" || !selected && Barrier == "observer-transport")
                {
                    Entered.TrySetResult();
                    await Resume.Task;
                }
                if (selected && Fault == "denial-without-response") throw new Azure.RequestFailedException(403, "controlled-no-response");
                if (request.Headers.Authorization?.Parameter == "denied-arm") return Reply(403, "{\"error\":{\"code\":\"Forbidden\"}}");
                string payload = selected && Fault == "selected-malformed" ? "{" :
                    selected && Fault == "selected-oversized" ? "{\"padding\":\"" + new string('x', 70000) + "\"}" :
                    selected && Fault == "selected-null" ? "{\"nameAvailable\":null}" :
                    selected && Fault == "selected-true" || !selected && Fault == "metadata-true" ||
                        !selected && Fault == "post-true" && SelectedQueries > 0
                    ? "{\"nameAvailable\":true}" : "{\"nameAvailable\":false}";
                var response = Reply(200, payload);
                if (selected && Barrier == "body" || !selected && Barrier == "observer-body")
                {
                    response.Content!.Dispose();
                    response.Content = new StreamContent(new NameReadBody(Encoding.UTF8.GetBytes(payload), this));
                    response.Content.Headers.ContentType = new("application/json");
                }
                return response;
            }
            return await Native.Wire.Respond(request, role, token);
        }
        private static HttpResponseMessage Reply(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.Add("x-ms-request-id", "controlled-name-read");
            return response;
        }
        public async ValueTask DisposeAsync()
        {
            Resume.TrySetResult();
            try { await Source.DisposeAsync(); }
            finally
            {
                try { await provisioner.DisposeAsync(); }
                finally
                {
                    Observer.Dispose();
                    foreach (var client in clients) client.Dispose();
                    capability.Dispose();
                    Native.Dispose();
                }
            }
        }
    }
    private sealed class NameReadCredential(NameReadFixture fixture, bool observer) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext,
            CancellationToken cancellationToken)
        {
            if (observer && fixture.Fault == "stateful-observer")
                fixture.MetadataRequest!.Content = new StatefulNameContent(fixture.MetadataRequest.Content!, fixture);
            if (fixture.Barrier == (observer ? "observer-credential" : "credential"))
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(observer ? "read-name-metadata-arm" : "selected-arm", DateTimeOffset.MaxValue);
        }
    }
    private sealed class NameMetadataTrace(HttpPipelineTransport inner, NameReadFixture fixture) : HttpPipelineTransport
    {
        public override Request CreateRequest() => fixture.MetadataRequest = inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            if (fixture.Barrier == "observer-sdk")
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
        }
    }
    private sealed class NameReadBody(byte[] bytes, NameReadFixture fixture) : MemoryStream(bytes)
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            fixture.Entered.TrySetResult();
            await fixture.Resume.Task;
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }
    private sealed class NameReadSdk(HttpPipelineTransport inner, NameReadFixture fixture) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            if (fixture.Fault == "stateful-request")
                message.Request.Content = new StatefulNameContent(message.Request.Content!, fixture);
            await inner.ProcessAsync(message);
            if (fixture.Barrier == "sdk")
            {
                fixture.Entered.TrySetResult();
                await fixture.Resume.Task;
            }
        }
    }
    private sealed class StatefulNameContent(RequestContent original, NameReadFixture fixture) : RequestContent
    {
        private int writes;
        private byte[] Foreign() => Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        {
            name = (fixture.Native.Wire.VaultName[0] == 'x' ? "y" : "x") + fixture.Native.Wire.VaultName[1..],
            type = "Microsoft.KeyVault/vaults"
        }));
        public override void WriteTo(Stream stream, CancellationToken cancellation)
        {
            Capture(stream);
            if (++writes == (fixture.Fault == "stateful-observer" ? 4 : 3)) stream.Write(Foreign());
            else original.WriteTo(stream, cancellation);
        }
        public override async Task WriteToAsync(Stream stream, CancellationToken cancellation)
        {
            Capture(stream);
            if (++writes == (fixture.Fault == "stateful-observer" ? 4 : 3)) await stream.WriteAsync(Foreign(), cancellation);
            else await original.WriteToAsync(stream, cancellation);
        }
        public override bool TryComputeLength(out long length) => original.TryComputeLength(out length);
        public override void Dispose() => original.Dispose();
        private void Capture(Stream stream)
        {
            if (stream is MemoryStream memory && memory.TryGetBuffer(out var buffer) && buffer.Array is { } bytes)
                fixture.BorrowedNameBuffers.Add(bytes);
        }
    }
}
