using System.Net;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed partial class AzureRoleFixtureProvisionerTests
{
    [Test]
    public async Task OriginalObserverClientPreparesMeasuresAndReleasesOverActualPinnedHttps()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest("CN=localhost", key, HashAlgorithmName.SHA256);
        var names = new SubjectAlternativeNameBuilder();
        names.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(names.Build());
        using var certificate = request.CreateSelfSigned(new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new(2099, 1, 1, 0, 0, 0, TimeSpan.Zero));
        RoleFixtureObserverService? service = null;
        await using var host = RoleFixtureObserverHost.Start(certificate, new(IPAddress.Loopback, 0),
            (message, token) => service!.DispatchAsync(message, token));
        await using var fixture = new ServiceFixture(host.Origin);
        service = fixture.Service;
        byte[] pin = certificate.GetCertHash(HashAlgorithmName.SHA256);
        using var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (_, peer, _, errors) => peer is not null &&
                (errors & SslPolicyErrors.RemoteCertificateNameMismatch) == 0 &&
                CryptographicOperations.FixedTimeEquals(peer.GetCertHash(HashAlgorithmName.SHA256), pin)
        };
        using var observer = new OwnedManagementObserver(
            new(host.Origin, "private-owner-capability", TimeSpan.FromSeconds(10)), handler);
        var lease = await observer.PostAsync<RoleAdministrationEffects.Prepare, RoleAdministrationEffects.Lease>(
            "role/prepare", fixture.Input, CancellationToken.None);
        var arm = new ObserveLease(lease.Facts.LeaseId, fixture.Native.Selector.Nonce, "subscribe-before-trigger");
        var window = await observer.PostAsync<ObserveLease, ObservationSubscription>("role/arm", arm, CancellationToken.None);
        await fixture.ReadSelected();
        var measured = await observer.PostAsync<ObserveLease, RoleAdministrationEffects.Measurement>(
            "role/observe", arm with { Phase = "assignment-and-effective-permission", SubscriptionId = window.SubscriptionId }, CancellationToken.None);
        RoleAdministrationEffects.ValidateReads(measured, SecretStatus.Success, lease.RuntimeSecretSha256);
        var released = await observer.PostAsync<FixtureSelector, RoleFixtureRelease.Measurement>("role/release",
            fixture.Native.Selector, CancellationToken.None);
        RoleFixtureRelease.Validate(released, fixture.Native.Selector, lease.Facts);
        await Assert.That(certificate.HasPrivateKey).IsTrue();
        await Assert.That(fixture.Native.State.VaultExists || fixture.Native.State.DeletedVaultExists).IsFalse();
    }

    [Test]
    public async Task AuthenticatedSourceRoutesCollectNativeStateRatherThanOperationAcknowledgements()
    {
        await using var fixture = new ServiceFixture();
        var lease = await fixture.Prepare();
        var selector = fixture.Native.Selector;
        var arm = new ObserveLease(lease.Facts.LeaseId, selector.Nonce, "subscribe-before-trigger");
        using var armedResponse = await fixture.Send("role/arm", arm);
        var armed = await fixture.Read<ObservationSubscription>(armedResponse);
        using var beforeResponse = await fixture.Send("role/observe",
            arm with { Phase = "assignment-baseline-before-dispatch", SubscriptionId = armed.SubscriptionId });
        var before = await fixture.Read<RoleAdministrationEffects.Measurement>(beforeResponse);
        var vault = new VaultScope(new ResourceGroupScope(new(Subscription), "fixture-group"), lease.VaultName);
        var target = new RoleAssignmentScope(vault, lease.AssignmentId);
        RoleAdministrationEffects.ValidateMeasurement(before, lease, armed, selector, vault, target, DefinitionId,
            RoleAdministrationCollector.Phase.Baseline);
        RoleAdministrationEffects.ValidateReads(before, SecretStatus.Success, lease.RuntimeSecretSha256);
        await fixture.ReadSelected();
        // An acknowledgement cannot change this separately held persisted state.
        await Assert.That(before.TargetPresent).IsTrue();
        fixture.Native.State.AssignmentPath = null;
        using var afterResponse = await fixture.Send("role/observe",
            arm with { Phase = "assignment-and-effective-permission", SubscriptionId = armed.SubscriptionId });
        var after = await fixture.Read<RoleAdministrationEffects.Measurement>(afterResponse);
        RoleAdministrationEffects.ValidateMeasurement(after, lease, armed, selector, vault, target, DefinitionId,
            RoleAdministrationCollector.Phase.After, before.Sequence);
        RoleAdministrationEffects.ValidateReads(after, SecretStatus.Denied, lease.RuntimeSecretSha256);
        await Assert.That(after.TargetPresent).IsFalse();
        using var releasedResponse = await fixture.Send("role/release", selector);
        var released = await fixture.Read<RoleFixtureRelease.Measurement>(releasedResponse);
        RoleFixtureRelease.Validate(released, selector, lease.Facts);
        await Assert.That(fixture.Native.State.VaultExists || fixture.Native.State.DeletedVaultExists).IsFalse();
    }

    [Test]
    [Arguments("capability")]
    [Arguments("origin")]
    [Arguments("method")]
    [Arguments("route")]
    [Arguments("scope")]
    [Arguments("duplicate-json")]
    public async Task SourceRejectsUntrustedRequestsBeforeNativeEnrollment(string fault)
    {
        await using var fixture = new ServiceFixture();
        using var request = fixture.Request("role/prepare", fixture.Input);
        if (fault == "capability") request.Headers.Authorization = new("Bearer", "wrong");
        if (fault == "origin") request.RequestUri = new("https://foreign.invalid/role/prepare");
        if (fault == "method") request.Method = HttpMethod.Get;
        if (fault == "route") request.RequestUri = new("https://fixture.invalid/arbitrary");
        if (fault == "scope")
            request.Content = fixture.Content(fixture.Input with { SubscriptionId = Guid.NewGuid() });
        if (fault == "duplicate-json")
            request.Content = new StringContent("{\"selection\":{},\"selection\":{}}");
        using var response = await fixture.Service.DispatchAsync(request, CancellationToken.None);
        await Assert.That(response.IsSuccessStatusCode).IsFalse();
        await Assert.That(fixture.Native.WriteCount).IsEqualTo(0);
        await Assert.That(Directory.EnumerateFiles(fixture.Native.DirectoryPath).Any()).IsFalse();
        await Assert.That(fixture.Backends.SelectMany(b => b.Requests).Any()).IsFalse();
    }

    [Test]
    public async Task SourceReleaseBeforePreparePreventsDelayedNativeEnrollment()
    {
        await using var fixture = new ServiceFixture();
        using var release = await fixture.Send("role/release", fixture.Native.Selector);
        RoleFixtureRelease.Validate(await fixture.Read<RoleFixtureRelease.Measurement>(release),
            fixture.Native.Selector, null);
        using var prepare = await fixture.Send("role/prepare", fixture.Input);
        await Assert.That(prepare.IsSuccessStatusCode).IsFalse();
        await Assert.That(fixture.Native.WriteCount).IsEqualTo(0);
        await Assert.That(fixture.Native.Read().Released).IsTrue();
    }

    [Test]
    public async Task SourcePhaseReplayAndForeignWindowCannotCollectAgain()
    {
        await using var fixture = new ServiceFixture();
        var lease = await fixture.Prepare();
        var arm = new ObserveLease(lease.Facts.LeaseId, fixture.Native.Selector.Nonce, "subscribe-before-trigger");
        using var armedResponse = await fixture.Send("role/arm", arm);
        var armed = await fixture.Read<ObservationSubscription>(armedResponse);
        using var foreign = await fixture.Send("role/observe", arm with { SubscriptionId = Guid.NewGuid() });
        await Assert.That(foreign.IsSuccessStatusCode).IsFalse();
        await fixture.ReadSelected();
        using var measured = await fixture.Send("role/observe",
            arm with { Phase = "assignment-and-effective-permission", SubscriptionId = armed.SubscriptionId });
        await fixture.Read<RoleAdministrationEffects.Measurement>(measured);
        int reads = fixture.Backends.Sum(b => b.Requests.Count);
        using var replay = await fixture.Send("role/observe",
            arm with { Phase = "assignment-and-effective-permission", SubscriptionId = armed.SubscriptionId });
        await Assert.That(replay.IsSuccessStatusCode).IsFalse();
        await Assert.That(fixture.Backends.Sum(b => b.Requests.Count)).IsEqualTo(reads);
        using var release = await fixture.Send("role/release", fixture.Native.Selector);
        RoleFixtureRelease.Validate(await fixture.Read<RoleFixtureRelease.Measurement>(release),
            fixture.Native.Selector, lease.Facts);
    }

    [Test]
    public async Task SourceDisposalDoesNotDisposeBorrowedAuthorityOrPerformProviderWrites()
    {
        await using var fixture = new ServiceFixture();
        await fixture.Prepare();
        int writes = fixture.Native.WriteCount;
        await fixture.Service.DisposeAsync();
        await Assert.That(fixture.Native.WriteCount).IsEqualTo(writes);
        await Assert.That(fixture.Native.Credentials.Concat(fixture.Credentials).All(c => !c.Disposed)).IsTrue();
        char[] exported = fixture.Capability.ExportCharacters();
        Array.Clear(exported);
        var observed = await fixture.Native.Source.ObserveAsync("owner", fixture.Native.Selector);
        await Assert.That(observed.State).IsEqualTo(RoleFixtureProvisioner.State.Ready);
        await fixture.Native.Source.ReleaseAsync("owner", fixture.Native.Selector, purge: true);
    }

    [Test]
    public async Task SourceDisposalWaitsForActualNativeInvocationTermination()
    {
        await using var fixture = new ServiceFixture();
        fixture.Native.State.Applied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Native.State.Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<HttpResponseMessage> preparing = fixture.Send("role/prepare", fixture.Input);
        await fixture.Native.State.Applied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Task draining = fixture.Service.DisposeAsync().AsTask();
        try
        {
            await Assert.That(draining.IsCompleted).IsFalse();
            await Assert.That(fixture.Native.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
        finally { fixture.Native.State.Terminate.TrySetResult(); }
        await Assert.That(async () => { using var response = await preparing; }).Throws<OperationCanceledException>();
        await draining.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(fixture.Native.Read().Released).IsFalse();
        await Assert.That(fixture.Native.Credentials.All(c => !c.Disposed)).IsTrue();
    }

    [Test]
    public async Task UnconfiguredSelectedIngressCannotEnrollOrProvision()
    {
        await using var fixture = new ServiceFixture(configureSelected: false);
        using var response = await fixture.Send("role/prepare", fixture.Input);
        await Assert.That(response.IsSuccessStatusCode).IsFalse();
        await Assert.That(fixture.Native.WriteCount).IsEqualTo(0);
        await Assert.That(Directory.EnumerateFiles(fixture.Native.DirectoryPath).Any()).IsFalse();
    }

    [Test]
    public async Task ClosingFencesLateSelectedMutationAndRetainsActualInFlightNativeWrite()
    {
        await using var fixture = new ServiceFixture(operation: "CreateRoleAssignmentAsync");
        var lease = await fixture.Prepare();
        using var armResponse = await fixture.Send("role/arm",
            new ObserveLease(lease.Facts.LeaseId, fixture.Native.Selector.Nonce, "subscribe-before-trigger"));
        await fixture.Read<ObservationSubscription>(armResponse);
        fixture.Native.State.SelectedApplied = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Native.State.SelectedTerminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        var creating = fixture.CreateSelected(lease).AsTask();
        await fixture.Native.State.SelectedApplied.Task.WaitAsync(TimeSpan.FromSeconds(10));
        try
        {
            using var closingResponse = await fixture.Send("role/release", fixture.Native.Selector);
            var closing = await fixture.Read<RoleFixtureRelease.Measurement>(closingResponse);
            await Assert.That(closing.ActiveDispatches > 0).IsTrue();
            await Assert.That(fixture.Native.State.VaultExists).IsTrue();
            await Assert.That(() => RoleFixtureRelease.Validate(closing, fixture.Native.Selector, lease.Facts))
                .Throws<NativeCaseFailureException>();
            int requests = fixture.SelectedBackend.Requests;
            var late = await fixture.CreateSelected(lease);
            await Assert.That(late.IsSuccess).IsFalse();
            await Assert.That(fixture.SelectedBackend.Requests).IsEqualTo(requests);
        }
        finally { fixture.Native.State.SelectedTerminate.TrySetResult(); }
        await Assert.That((await creating).IsSuccess).IsTrue();
        using var releasedResponse = await fixture.Send("role/release", fixture.Native.Selector);
        RoleFixtureRelease.Validate(await fixture.Read<RoleFixtureRelease.Measurement>(releasedResponse),
            fixture.Native.Selector, lease.Facts);
        await Assert.That(fixture.Native.Read().Released).IsTrue();
    }

    private sealed class ServiceFixture : IAsyncDisposable
    {
        internal readonly Fixture Native;
        internal readonly Backend[] Backends;
        internal readonly Credential[] Credentials;
        private readonly HttpClient[] clients;
        private readonly HttpClient selectedHttp;
        private readonly Credential selectedCredential = new("administrative-arm");
        internal readonly OriginalNativeBackend SelectedBackend;
        internal readonly HttpPipelineTransport SelectedTransport;
        internal readonly SecretMaterial Capability = SecretMaterial.FromText("private-owner-capability");
        internal readonly RoleFixtureObserverService Service;
        internal readonly RoleAdministrationEffects.Prepare Input;
        private readonly Uri origin;
        internal ServiceFixture(Uri? origin = null, bool borrowed = false,
            string operation = "GetRoleDefinitionAsync", bool configureSelected = true)
        {
            this.origin = origin ?? new("https://fixture.invalid/");
            var member = RoleAdministrationEffects.Members.Single(m => m.Operation.EndsWith("." + operation, StringComparison.Ordinal));
            var selector = new FixtureSelector(Guid.NewGuid(), "owned-source", member.Operation, member.Variants[0], "selected-contract");
            Native = new(true, selector);
            Native.State.IncludeBorrowedRows = borrowed;
            Backends = new[] { "observer-arm", "intended-secret", "denied-secret", "observer-secret" }
                .Select(r => new Backend(r, Native.State)).ToArray();
            Credentials = Backends.Select(b => new Credential(b.Role)).ToArray();
            clients = Backends.Select(b => new HttpClient(b)).ToArray();
            var transports = clients.Select(c => new HttpClientTransport(c)).ToArray();
            var clock = new ServiceClock();
            var collector = new RoleAdministrationCollector(new("arm", Credentials[0], transports[0]),
                new("intended", Credentials[1], transports[1]), new("denied", Credentials[2], transports[2]),
                new("observer", Credentials[3], transports[3]), new(10, 100, 64 * 1024, TimeSpan.FromSeconds(10)),
                clock);
            Service = new(this.origin, "owner", "independent-observer", Capability,
                new(Subscription, "fixture-group", "eastus", Tenant, PrincipalId, DefinitionId, true, true),
                borrowed ? [new(new ResourceGroupScope(new(Subscription), "fixture-group"), GroupAssignment),
                    new(new SubscriptionScope(Subscription), SubscriptionAssignment)] : [],
                Native.Source, collector, clock);
            SelectedBackend = new(Native.State, secret: false);
            selectedHttp = new(SelectedBackend);
            var native = new HttpClientTransport(selectedHttp);
            SelectedTransport = configureSelected ? Service.CreateSelectedTransport(native, () => Native.Selector) : native;
            Input = new(selector, Subscription, "fixture-group", "eastus", Tenant, DefinitionId, PrincipalId);
        }
        internal ByteArrayContent Content<T>(T value) =>
            new(JsonSerializer.SerializeToUtf8Bytes(value, ManagementAdmission.Json));
        internal HttpRequestMessage Request<T>(string route, T value)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, new Uri(origin, route)) { Content = Content(value) };
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "private-owner-capability");
            return request;
        }
        internal async Task<HttpResponseMessage> Send<T>(string route, T value)
        {
            using var request = Request(route, value);
            return await Service.DispatchAsync(request, CancellationToken.None);
        }
        internal async Task<T> Read<T>(HttpResponseMessage response)
        {
            await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
            return JsonSerializer.Deserialize<T>(await response.Content!.ReadAsByteArrayAsync(), ManagementAdmission.Json)!;
        }
        internal async Task<RoleAdministrationEffects.Lease> Prepare()
        {
            using var response = await Send("role/prepare", Input);
            return await Read<RoleAdministrationEffects.Lease>(response);
        }
        internal async Task ReadSelected()
        {
            var client = new VaultAdministration(selectedCredential, SelectedTransport);
            var result = await client.GetRoleDefinitionAsync(new(new SubscriptionScope(Subscription), DefinitionId));
            await Assert.That(result.IsSuccess).IsTrue();
        }
        internal ValueTask<SecretOutcome<RoleAssignmentObservation>> CreateSelected(RoleAdministrationEffects.Lease lease)
        {
            var client = new VaultAdministration(selectedCredential, SelectedTransport);
            var vault = new VaultScope(new ResourceGroupScope(new(Subscription), "fixture-group"), lease.VaultName);
            var target = new RoleAssignmentScope(vault, lease.AssignmentId);
            var receipt = client.PrepareReceipt(target, ManagementMutation.CreateRoleAssignment);
            return client.CreateRoleAssignmentAsync(target,
                new(new SubscriptionScope(Subscription), DefinitionId), PrincipalId, receipt);
        }
        public async ValueTask DisposeAsync()
        {
            await Service.DisposeAsync();
            foreach (var client in clients) client.Dispose();
            selectedHttp.Dispose();
            selectedCredential.Dispose();
            Capability.Dispose();
            Native.Dispose();
        }
    }
    private sealed class ServiceClock : TimeProvider
    {
        private readonly DateTimeOffset epoch = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => epoch;
    }
}
