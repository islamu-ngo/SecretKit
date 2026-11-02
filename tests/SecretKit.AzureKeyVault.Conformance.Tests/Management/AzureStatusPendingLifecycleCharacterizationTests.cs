using System.Net;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using SecretKit.TestFixtures;
using Op = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationEffects;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Original-handler and installed-native lifetime characterization only.
// This observer is not a source-owned fixture admission or live qualification.
public sealed class AzureStatusPendingLifecycleCharacterizationTests
{
    [Test]
    public async Task PendingDisposedSelectedCredentialCannotIssueAnotherToken()
    {
        const string audience = "https://management.azure.com/.default";
        using var credential = new SelectedAudienceCredential(new("controlled-disposal-token",
            DateTimeOffset.UtcNow.AddHours(1), audience));
        var context = new TokenRequestContext([audience]);
        await credential.GetTokenAsync(context, default);
        credential.Dispose();
        await Assert.That(async () => await credential.GetTokenAsync(context, default)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task PendingOriginalHandlerClaimsChallengeCannotBorrowCleanupAuthority()
    {
        using var probe = new PendingProbe(expireBeforeCleanup: false, challengeCleanup: true);
        var result = await probe.Run();
        await Assert.That(probe.SelectedStatus).IsEqualTo(SecretStatus.Pending);
        await Assert.That(probe.CleanupStatus == SecretStatus.Success).IsFalse();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(probe.SelectedPosts).IsEqualTo(1);
        await Assert.That(probe.SelectedGets).IsEqualTo(2);
        await Assert.That(probe.ObserverStatusGets).IsEqualTo(1);
        await Assert.That(probe.Remaining.Contains(probe.DeletedId)).IsTrue();
        await Assert.That(probe.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
    }

    [Test]
    public async Task PendingOriginalHandlerCanCompleteItsSameHandleAfterCredentialOwnerDisposal()
    {
        using var probe = new PendingProbe(expireBeforeCleanup: false);
        var result = await probe.Run();
        await Assert.That(result.Passed).IsTrue();
        await Assert.That(probe.SelectedStatus).IsEqualTo(SecretStatus.Pending);
        await Assert.That(probe.SelectedState).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(probe.CleanupStatus).IsEqualTo(SecretStatus.Success);
        await Assert.That(probe.Handle!.State).IsEqualTo(NativeProvisioningState.Succeeded);
        await Assert.That(probe.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(probe.SelectedPosts).IsEqualTo(1);
        await Assert.That(probe.SelectedGets).IsEqualTo(3);
        await Assert.That(probe.ObserverStatusGets).IsEqualTo(1);
        await Assert.That(probe.Remaining.Length).IsEqualTo(0);
        await Assert.That(probe.StartTask!.Result.Value == probe.Handle).IsTrue();
        await Assert.That(probe.SelectedTask!.IsCompletedSuccessfully && probe.CleanupTask!.IsCompletedSuccessfully).IsTrue();
        await Assert.That(probe.Transport.Frames.All(f => ReferenceEquals(f.Task, probe.Owner(f.Phase)) &&
            f.Task!.IsCompletedSuccessfully && f.Custody.Complete && !f.Custody.Invalid)).IsTrue();
        probe.Transport.Erase();
        await Assert.That(probe.Transport.Frames.All(f => f.Body.Span.IndexOfAnyExcept((byte)0) < 0)).IsTrue();
    }

    [Test]
    public async Task PendingOriginalHandlerCannotRefreshExpiredSelectedAuthorityDuringCleanup()
    {
        using var probe = new PendingProbe(expireBeforeCleanup: true);
        var result = await probe.Run();
        await Assert.That(probe.SelectedStatus).IsEqualTo(SecretStatus.Pending);
        await Assert.That(probe.SelectedState).IsEqualTo(NativeProvisioningState.Pending);
        await Assert.That(probe.CleanupStatus == SecretStatus.Success).IsFalse();
        await Assert.That(result.Passed).IsFalse();
        await Assert.That(probe.SelectedPosts).IsEqualTo(1);
        await Assert.That(probe.SelectedGets).IsEqualTo(1);
        await Assert.That(probe.ObserverStatusGets).IsEqualTo(1);
        await Assert.That(probe.Remaining.Contains(probe.DeletedId)).IsTrue();
        await Assert.That(probe.Receipt!.Evidence).IsEqualTo(DispatchEvidence.Pending);
        await Assert.That(probe.CleanupTask!.IsCompletedSuccessfully).IsTrue();
    }

    [Test]
    [Arguments("response")]
    [Arguments("stream")]
    [Arguments("missing")]
    public async Task PendingOriginalHandlerCustodyRejectsSelectedResponseSubstitution(string fault)
    {
        using var probe = new PendingProbe(expireBeforeCleanup: false, substitution: fault);
        await probe.Run();
        await Assert.That(probe.SelectedPosts).IsEqualTo(1);
        await Assert.That(probe.Transport.Frames.Any(f => f.Phase == Phase.Selected &&
            (f.Custody.Invalid || !f.Custody.Complete))).IsTrue();
        await Assert.That(probe.StartTask!.IsCompletedSuccessfully).IsTrue();
        probe.Transport.Erase();
        await Assert.That(probe.Transport.Frames.All(f => f.Body.Span.IndexOfAnyExcept((byte)0) < 0)).IsTrue();
    }

    private enum Phase { Start, Selected, Cleanup }

    private sealed class PendingProbe : Op.SelectedInvocation, IDisposable
    {
        private static readonly Guid Subscription = Guid.Parse("11111111-1111-1111-1111-111111111111");
        private static readonly Guid Tenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
        private const string Audience = "https://management.azure.com/.default";
        private const string Target = "https://management.azure.com/subscriptions/11111111-1111-1111-1111-111111111111/providers/Microsoft.KeyVault/locations/eastus/operations/55555555-5555-5555-5555-555555555555?api-version=2026-02-01";
        private readonly bool expireBeforeCleanup;
        private readonly bool challengeCleanup;
        private readonly DateTimeOffset selectedExpiry;
        private readonly TaskCompletionSource expired = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly ITimer? expiryTimer;
        private readonly Op.Input input;
        private readonly SelectedAudienceCredential observerCredential;
        private readonly VaultAdministration observer;
        private readonly HttpClient observerStatus;
        private readonly HttpClient observerHttp;
        private readonly HttpClient selectedHttp;
        private FixtureSelector? selector;
        private Op.Lease? lease;
        private Guid subscriptionId;
        private bool terminal;
        private bool absent;
        internal readonly CaptureTransport Transport;
        internal Task<SecretOutcome<ManagementOperation>>? StartTask;
        internal Task<SecretStatus>? SelectedTask, CleanupTask;
        internal ManagementOperation? Handle;
        internal ManagementReceipt? Receipt;
        internal SecretStatus SelectedStatus = SecretStatus.Unknown, CleanupStatus = SecretStatus.Unknown;
        internal NativeProvisioningState SelectedState;
        internal int SelectedPosts, SelectedGets, ObserverStatusGets;
        internal string[] Remaining = [];
        private string VaultName => "skv-" + selector!.Nonce.ToString("N")[..20];
        private string VaultId => $"/subscriptions/{Subscription:D}/resourceGroups/pending-group/providers/Microsoft.KeyVault/vaults/{VaultName}";
        internal string DeletedId => $"/subscriptions/{Subscription:D}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/{VaultName}";
        private DeletedVaultScope DeletedScope => new(new(Subscription), "eastus", VaultName);

        internal PendingProbe(bool expireBeforeCleanup, string? substitution = null, bool challengeCleanup = false)
        {
            this.expireBeforeCleanup = expireBeforeCleanup;
            this.challengeCleanup = challengeCleanup;
            selectedExpiry = expireBeforeCleanup ? DateTimeOffset.UtcNow.AddMinutes(1) : DateTimeOffset.Parse("2099-01-01T00:00:00Z");
            var longExpiry = DateTimeOffset.Parse("2099-01-01T00:00:00Z");
            input = new(new(new("https://pending-characterization.example/"), "controlled-observer", TimeSpan.FromMinutes(2)),
                new(new("controlled-setup", longExpiry, Audience), new("controlled-selected", selectedExpiry, Audience),
                    new("controlled-denied", longExpiry, Audience), new("controlled-observer", longExpiry, Audience)),
                Subscription, "pending-group", "eastus", Tenant, VaultSku.Premium, 23,
                ManagementMutation.PurgeDeletedVault, "https://pending-characterization.example/webhook", Guid.Empty);
            if (expireBeforeCleanup)
            {
                // Expiry is the behavior under test. Subscribe before the original
                // handler starts; no polling or synchronization sleep is involved.
                expiryTimer = TimeProvider.System.CreateTimer(_ => expired.TrySetResult(), null,
                    selectedExpiry - DateTimeOffset.UtcNow + TimeSpan.FromSeconds(1), Timeout.InfiniteTimeSpan);
            }
            selectedHttp = new(new Forwarder(Backend));
            Transport = new(new HttpClientTransport(selectedHttp), this, substitution);
            observerCredential = new(input.Arm.Observer);
            observerStatus = new(new Forwarder(Backend));
            observerStatus.DefaultRequestHeaders.Authorization = new("Bearer", input.Arm.Observer.Token);
            observerHttp = new(new Forwarder(Backend));
            observer = new(observerCredential, new HttpClientTransport(observerHttp));
        }

        internal Task? Owner(Phase phase) => phase switch
        {
            Phase.Start => StartTask,
            Phase.Selected => SelectedTask,
            _ => CleanupTask
        };

        internal async Task<NativeCaseResult> Run()
        {
            object Runtime(string role) => new { token = role, expiresAt = "2099-01-01T00:00:00Z" };
            using var document = JsonDocument.Parse(JsonSerializer.Serialize(new
            {
                vaultUri = "https://pending-characterization.vault.azure.net",
                setup = Runtime("controlled-runtime-setup"), runtime = Runtime("controlled-runtime"),
                denied = Runtime("controlled-runtime-denied"), administrative = Runtime("controlled-runtime-admin"),
                observer = Runtime("controlled-runtime-observer"),
                families = new Dictionary<string, object> { ["ManagementOperation"] = input }
            }, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
            using var environment = OwnedAzureEnvironment.Create(document.RootElement);
            var definition = new NativeCaseDefinition(new("AzureKeyVault", Op.Members[0].Operation,
                "status.Pending", "controlled", "selected-contract"), Op.Members[0].Member);
            var registry = new NativeCaseRegistry();
            Op.Register(registry, environment, [definition], endpoint => new(endpoint, new Forwarder(Observe)),
                selectedTransport: Transport, selectedInvocation: this);
            foreach (var assembly in new[] { typeof(TokenCredential).Assembly, typeof(Azure.ResourceManager.ArmClient).Assembly,
                typeof(Azure.ResourceManager.KeyVault.KeyVaultResource).Assembly })
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    Assembly = assembly.GetName().Name, Version = assembly.GetName().Version?.ToString(),
                    Informational = assembly.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
                        .Cast<System.Reflection.AssemblyInformationalVersionAttribute>().SingleOrDefault()?.InformationalVersion
                }));
            var result = (await NativeCaseRunner.RunAsync(registry, [definition], default)).Single();
            Console.WriteLine(JsonSerializer.Serialize(new { result.Passed, result.ReasonCode, SelectedPosts, SelectedGets,
                ObserverStatusGets, SelectedStatus, CleanupStatus, SelectedState }));
            return result;
        }

        public async ValueTask<SecretOutcome<ManagementOperation>> RunStartAsync(FixtureSelector selected,
            VaultAdministration client, ManagementScope scope, ManagementMutation operation, Op.Input originalInput,
            ManagementReceipt receipt, CancellationToken token)
        {
            Transport.Current = Phase.Start;
            Receipt = receipt;
            if (operation != ManagementMutation.PurgeDeletedVault || scope is not DeletedVaultScope deleted)
                throw new InvalidOperationException("unexpected-original-operation");
            StartTask = client.PurgeDeletedVaultAsync(deleted, receipt, token).AsTask();
            Transport.Assign(Phase.Start, StartTask);
            var result = await StartTask;
            Handle = result.Value;
            return result;
        }

        public async ValueTask<SecretStatus> RunCheckStatusAsync(FixtureSelector selected, ManagementOperation handle,
            CancellationToken token)
        {
            if (!ReferenceEquals(handle, Handle)) throw new InvalidOperationException("foreign-original-handle");
            Transport.Current = Phase.Selected;
            SelectedTask = handle.CheckStatusAsync(token).AsTask();
            Transport.Assign(Phase.Selected, SelectedTask);
            SelectedStatus = await SelectedTask;
            SelectedState = handle.State;
            return SelectedStatus;
        }

        private async Task<HttpResponseMessage> Observe(HttpRequestMessage request, CancellationToken token)
        {
            string path = request.RequestUri!.AbsolutePath;
            if (path == "/operation/prepare")
            {
                var prepared = JsonSerializer.Deserialize<Op.Prepare>(await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!;
                selector = prepared.Selection;
                lease = new(new(selector.Nonce, Guid.NewGuid(), "controlled-independent-reader",
                    "https://management.azure.com", "2026-02-01", DateTimeOffset.UtcNow, [VaultId, DeletedId]),
                    VaultName, null, null, null, prepared.Operation, NativeProvisioningState.Pending);
                return Json(lease);
            }
            if (path == "/operation/arm")
            {
                subscriptionId = Guid.NewGuid();
                return Json(new ObservationSubscription(lease!.Facts.LeaseId, selector!.Nonce, subscriptionId, DateTimeOffset.UtcNow));
            }
            if (path == "/operation/observe")
            {
                var phase = JsonSerializer.Deserialize<ObserveLease>(await request.Content!.ReadAsByteArrayAsync(token), ManagementAdmission.Json)!;
                var read = await observer.GetDeletedVaultAsync(DeletedScope, token);
                var state = NativeProvisioningState.Pending;
                if (phase.Phase == "selected-state")
                {
                    using var response = await observerStatus.GetAsync(Target, token);
                    using var status = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(token));
                    if (!response.IsSuccessStatusCode || status.RootElement.GetProperty("status").GetString() != "InProgress")
                        throw new InvalidOperationException("unexpected-independent-status");
                }
                return Json(new Op.Measurement(lease!.Facts.LeaseId, selector!.Nonce, lease.Facts.ObserverIdentity,
                    DateTimeOffset.UtcNow, ManagementMutation.PurgeDeletedVault, state, DeletedId,
                    read.Status, null, null, null));
            }
            if (path == "/operation/release")
            {
                if (Handle is not null)
                {
                    if (expireBeforeCleanup) await expired.Task.WaitAsync(TimeSpan.FromSeconds(90), token);
                    terminal = true;
                    Transport.Current = Phase.Cleanup;
                    CleanupTask = Handle.CheckStatusAsync(CancellationToken.None).AsTask();
                    Transport.Assign(Phase.Cleanup, CleanupTask);
                    CleanupStatus = await CleanupTask;
                }
                var deleted = await observer.GetDeletedVaultAsync(DeletedScope, token);
                var vault = await observer.GetVaultAsync(new(new(new(Subscription), "pending-group"), VaultName), token);
                var missing = new List<string>();
                if (deleted.Status == SecretStatus.Absent) missing.Add(DeletedId);
                if (vault.Status == SecretStatus.Absent) missing.Add(VaultId);
                Remaining = lease!.Facts.OwnedResourceIds.Except(missing).ToArray();
                return Json(new RoleFixtureRelease.Measurement(selector!, true,
                    CleanupStatus == SecretStatus.Success ? 0 : 1, lease.Facts.OwnedResourceIds, [], missing.ToArray(), Remaining));
            }
            throw new InvalidOperationException("unexpected-characterization-observer-request");
        }

        private Task<HttpResponseMessage> Backend(HttpRequestMessage request, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            string identity = request.Headers.Authorization?.Parameter ?? "";
            if (request.RequestUri!.AbsoluteUri == Target)
            {
                if (identity == input.Arm.Observer.Token) ObserverStatusGets++;
                else if (identity == input.Arm.Administrative.Token) SelectedGets++;
                else throw new InvalidOperationException("unexpected-status-principal");
                if (terminal && identity == input.Arm.Administrative.Token && challengeCleanup)
                {
                    var response = Raw(401, """{"error":{"code":"InvalidAuthenticationToken"}}""");
                    string claims = Convert.ToBase64String(Encoding.UTF8.GetBytes(
                        """{"access_token":{"xms_cc":{"values":["cp1"]}}}"""));
                    response.Headers.TryAddWithoutValidation("WWW-Authenticate",
                        $"Bearer error=\"insufficient_claims\", claims=\"{claims}\"");
                    return Task.FromResult(response);
                }
                if (terminal && identity == input.Arm.Administrative.Token) absent = true;
                return Task.FromResult(Raw(200, terminal && identity == input.Arm.Administrative.Token
                    ? """{"status":"Succeeded"}""" : """{"status":"InProgress"}"""));
            }
            if (request.Method == HttpMethod.Post && request.RequestUri.AbsolutePath == DeletedId + "/purge")
            {
                if (identity != input.Arm.Administrative.Token) throw new InvalidOperationException("unexpected-purge-principal");
                SelectedPosts++;
                var response = Raw(202, """{"status":"InProgress"}""");
                response.Headers.TryAddWithoutValidation("Location", Target);
                response.Headers.TryAddWithoutValidation("Azure-AsyncOperation", Target);
                return Task.FromResult(response);
            }
            if (identity != input.Arm.Observer.Token || request.Method != HttpMethod.Get)
                throw new InvalidOperationException("unexpected-resource-principal");
            if (request.RequestUri.AbsolutePath == VaultId || absent)
                return Task.FromResult(Raw(404, """{"error":{"code":"ResourceNotFound"}}"""));
            if (request.RequestUri.AbsolutePath != DeletedId) throw new InvalidOperationException("foreign-resource-read");
            return Task.FromResult(Raw(200, JsonSerializer.Serialize(new
            {
                id = DeletedId, name = VaultName, type = "Microsoft.KeyVault/deletedVaults",
                properties = new { vaultId = VaultId, location = "eastus", purgeProtectionEnabled = false }
            })));
        }

        private static HttpResponseMessage Json<T>(T value) => Raw(200,
            JsonSerializer.Serialize(value, new JsonSerializerOptions(ManagementAdmission.Json) { IgnoreReadOnlyProperties = false }));
        private static HttpResponseMessage Raw(int status, string body)
        {
            var response = new HttpResponseMessage((HttpStatusCode)status)
            { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.TryAddWithoutValidation("x-ms-request-id", Guid.NewGuid().ToString("D"));
            return response;
        }
        public void Dispose()
        {
            expiryTimer?.Dispose();
            Transport.Erase();
            observerCredential.Dispose();
            observerStatus.Dispose();
            observerHttp.Dispose();
            selectedHttp.Dispose();
        }
    }

    private sealed class CaptureTransport(HttpPipelineTransport inner, PendingProbe owner, string? substitution) : HttpPipelineTransport
    {
        internal sealed class Frame(Phase phase, ReadOnlyMemory<byte> body, OwnedArmResponse.Storage storage,
            OwnedArmResponse.ParserCustody custody, Task? task)
        {
            internal Phase Phase = phase;
            internal ReadOnlyMemory<byte> Body = body;
            internal OwnedArmResponse.Storage Storage = storage;
            internal OwnedArmResponse.ParserCustody Custody = custody;
            internal Task? Task = task;
        }
        internal Phase Current;
        internal readonly List<Frame> Frames = [];
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("async-only-characterization");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            await inner.ProcessAsync(message);
            var storage = new OwnedArmResponse.Storage();
            var snapshot = await OwnedArmResponse.CaptureAsync(message, 65536, storage,
                allowContinuation: Current == Phase.Start);
            int phaseOrdinal = Frames.Count(f => f.Phase == Current);
            var custody = OwnedArmResponse.ParserCustody.Install(message, snapshot.Response, snapshot.Bytes, storage,
                requireRebuffer: true, requireDownstreamRead: Current != Phase.Start && !(Current == Phase.Cleanup && phaseOrdinal == 1));
            Frames.Add(new(Current, snapshot.Bytes, storage, custody, owner.Owner(Current)));
            if (Current == Phase.Selected && substitution is not null)
            {
                byte[] replacement = snapshot.Bytes.ToArray();
                storage.Own(replacement);
                var stream = new MemoryStream(replacement, false);
                storage.Own(stream);
                if (substitution == "response")
                    message.Response = new OwnedArmResponse(snapshot.Response.Status, snapshot.Response.ReasonPhrase,
                        snapshot.Response.ClientRequestId, snapshot.Response.Headers.ToArray(), stream);
                else message.Response.ContentStream = substitution == "stream" ? stream : null;
            }
        }
        internal void Assign(Phase phase, Task task)
        {
            foreach (var frame in Frames.Where(f => f.Phase == phase)) frame.Task = task;
        }
        internal void Erase()
        {
            foreach (var frame in Frames) frame.Storage.Dispose();
        }
    }

    private sealed class Forwarder(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            send(request, cancellationToken);
    }
}
