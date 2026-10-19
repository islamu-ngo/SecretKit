using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using RuntimeCapture = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.NotificationRuntimeTriggerCapture;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

// Reuses only the private native fixture; the runtime PUT below creates an
// actual fresh version in its state, never the fixture's prepared Version.
public sealed partial class AzureVaultFixtureProvisionerTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NotificationOriginalRuntimeWriteNormalizesColdAndWarmEnvelopes(bool warm)
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Seam.Warm = warm;
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var receipt = new MutationReceipt(target);
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), receipt, default);
        var measurement = f.Source.Read(window, f.Binding);
        f.Source.ValidateMeasurement(f.Fixture.Journal, Owner, window, f.Binding, measurement);

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(((AzureSecretAddress)result.Value!.Reference.Address).Version).IsEqualTo(NotificationCaptureScope.FreshVersion);
        await Assert.That(f.Fixture.Wire.Secret).IsEqualTo(NotificationCaptureScope.Value);
        await Assert.That(f.Native.Version).IsEqualTo(NotificationCaptureScope.FreshVersion);
        await Assert.That(f.Native.Sends).IsEqualTo(1);
        await Assert.That(f.Native.Body).IsEqualTo("{\"value\":\"notification-original-value\"}");
        await Assert.That(f.Native.Authorization).IsEqualTo("Bearer source-runtime");
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(measurement.Version).IsEqualTo(NotificationCaptureScope.FreshVersion);
        await Assert.That(measurement.NativeRequestId).IsEqualTo("native-original-write");
        await Assert.That(measurement.MaterialSha256).IsEqualTo(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(NotificationCaptureScope.Value))));
        await Assert.That(measurement.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(measurement.TaskDrained && measurement.NativeAcknowledged && measurement.NativeSettled).IsTrue();
        await Assert.That(measurement.EmissionEstablished).IsFalse();
        await Assert.That(ReferenceEquals(measurement, f.Source.Read(window, f.Binding))).IsTrue();
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Prejournaled).IsTrue();
    }

    [Test]
    public async Task NotificationFrozenBodyWinsOverCredentialCallbackMutation()
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Seam.Warm = true;
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        f.Credential.Callback = () =>
            f.Seam.Message!.Request.Content = RequestContent.Create(Encoding.UTF8.GetBytes("{\"value\":\"foreign\"}"));
        var target = f.Target();
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material),
            new(target), default);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Native.Body).IsEqualTo("{\"value\":\"notification-original-value\"}");
        await Assert.That(f.Source.Read(window, f.Binding).NativeSettled).IsTrue();
    }

    [Test]
    public async Task NotificationOriginalTaskMustDrainAfterNativeAcknowledgement()
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Seam.HoldAfterNative = true;
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var task = f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default).AsTask();
        try
        {
            await f.Seam.AfterNative.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(task.IsCompleted).IsFalse();
            await Assert.That(() => f.Source.Read(window, f.Binding)).Throws<InvalidOperationException>();
            await Assert.That(f.Fixture.Read().Resources.Single(r => r.Id.EndsWith("/secrets/canary",
                StringComparison.Ordinal)).ActiveDispatch != Guid.Empty).IsTrue();
        }
        finally { f.Seam.Resume.TrySetResult(); }
        await Assert.That((await task).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.Read(window, f.Binding).NativeSettled).IsTrue();
    }

    [Test]
    public async Task NotificationRawProofSurvivesOuterSdkCancellationButNotBeforeDrain()
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Seam.HoldAfterNative = true;
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        using var cancellation = new CancellationTokenSource();
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var task = f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material),
            new(target), cancellation.Token).AsTask();
        try
        {
            await f.Seam.AfterNative.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await Assert.That(() => f.Source.Read(window, f.Binding)).Throws<InvalidOperationException>();
        }
        finally { f.Seam.Resume.TrySetResult(); }
        await Assert.That(async () => await task).Throws<OperationCanceledException>();
        var measurement = f.Source.Read(window, f.Binding);
        await Assert.That(measurement.Status).IsNull();
        await Assert.That(measurement.NativeAcknowledged && measurement.NativeSettled && measurement.TaskDrained).IsTrue();
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments("credential")]
    [Arguments("request-body")]
    [Arguments("body")]
    [Arguments("sdk")]
    public async Task NotificationDisposalJoinsEveryOriginalBorrower(string barrier)
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Credential.Block = barrier == "credential";
        f.Seam.Warm = f.Seam.BlockRequestBody = barrier == "request-body";
        f.Native.BlockBody = barrier == "body";
        f.Seam.HoldAfterNative = barrier == "sdk";
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var task = f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default).AsTask();
        Task? disposal = null;
        try
        {
            await (barrier switch
            {
                "credential" => f.Credential.Entered.Task,
                "request-body" => f.Seam.BodyEntered.Task,
                "body" => f.Native.BodyEntered.Task,
                _ => f.Seam.AfterNative.Task
            }).WaitAsync(TimeSpan.FromSeconds(10));
            var canceled = Signal();
            using var cancellation = f.Seam.Message!.CancellationToken.Register(() => canceled.TrySetResult());
            disposal = f.Source.DisposeAsync().AsTask();
            // CancelAsync propagates linked-token callbacks asynchronously.
            // Observe cancellation before releasing the original SDK borrower.
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(task.IsCompleted).IsFalse();
            await Assert.That(disposal.IsCompleted).IsFalse();
            await Assert.That(() => f.Source.Read(window, f.Binding)).Throws<InvalidOperationException>();
            await Assert.That(f.Fixture.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
        }
        finally
        {
            f.Credential.Resume.TrySetResult();
            f.Seam.BodyResume.TrySetResult();
            f.Native.BodyResume.TrySetResult();
            f.Seam.Resume.TrySetResult();
        }
        await Assert.That(async () => await task).Throws<OperationCanceledException>();
        await disposal!.WaitAsync(TimeSpan.FromSeconds(10));
        var measurement = f.Source.Read(window, f.Binding);
        await Assert.That(measurement.TaskDrained).IsTrue();
        await Assert.That(measurement.NativeSettled).IsEqualTo(barrier == "sdk");
        await Assert.That(f.Native.Sends).IsEqualTo(barrier is "credential" or "request-body" ? 0 : 1);
        await Assert.That(f.Credential.Disposed || f.Native.Disposed).IsFalse();
    }

    [Test]
    [Arguments("foreign")]
    [Arguments("old-version")]
    [Arguments("malformed")]
    [Arguments("duplicate")]
    [Arguments("oversized")]
    [Arguments("async")]
    [Arguments("async-header")]
    [Arguments("redirect")]
    [Arguments("redirect-header")]
    [Arguments("missing-request-id")]
    [Arguments("wrong-value")]
    [Arguments("deep")]
    [Arguments("nodes")]
    [Arguments("headers")]
    [Arguments("lost")]
    public async Task NotificationUnprovenNativeWritesRetainTheirOriginalFence(string fault)
    {
        await using var f = await NotificationCaptureScope.Create(fault);
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default);
        var measurement = f.Source.Read(window, f.Binding);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(f.Native.Sends).IsEqualTo(1);
        await Assert.That(f.Fixture.Wire.Secret).IsEqualTo(NotificationCaptureScope.Value);
        await Assert.That(measurement.TaskDrained).IsTrue();
        await Assert.That(measurement.NativeAcknowledged || measurement.NativeSettled || measurement.EmissionEstablished).IsFalse();
        var row = f.Fixture.Read().Resources.Single(r => r.Id.EndsWith("/secrets/canary", StringComparison.Ordinal));
        await Assert.That(row.ActiveDispatch != Guid.Empty && row.InvocationTerminated).IsTrue();
        f.Fixture.Journal.Close(Owner, f.Binding.Selector);
        await Assert.That(() => f.Fixture.Journal.BeginDispatch(Owner, f.Binding.Selector, row.Id, true))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task NotificationOriginalInvalidReceiptCanClearOnlyPredispatchReservation()
    {
        await using var f = await NotificationCaptureScope.Create();
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var wrongReceipt = new MutationReceipt(f.Target()); // Equal coordinates, DIFFERENT reference.
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), wrongReceipt, default);
        var measurement = f.Source.Read(window, f.Binding);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wrongReceipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(f.Native.Sends).IsEqualTo(0);
        await Assert.That(f.Credential.Calls).IsEqualTo(0);
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(measurement.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(measurement.NativeAcknowledged || measurement.NativeSettled).IsFalse();
    }

    [Test]
    public async Task NotificationCredentialExceptionIsNotPredispatchRejectionProof()
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Credential.Callback = () => throw new ObjectDisposedException("controlled");
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        _ = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default);
        await Assert.That(f.Native.Sends).IsEqualTo(0);
        await Assert.That(f.Source.Read(window, f.Binding).NativeSettled).IsFalse();
        await Assert.That(f.Fixture.Read().Resources.Any(r => r.ActiveDispatch != Guid.Empty)).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NotificationOnlyValidatedNativeDenialSettlesWithoutAcknowledgingCreation(bool malformed)
    {
        await using var f = await NotificationCaptureScope.Create(malformed ? "denied-malformed" : "denied");
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        var result = await f.Source.RunSetAsync(f.Binding.Selector, f.Client, new(target, material), new(target), default);
        var measurement = f.Source.Read(window, f.Binding);
        // Core preserves Unknown for a dispatched SDK RequestFailedException.
        // Native rejection settlement must not rewrite that actual SDK status.
        await Assert.That(measurement.Status).IsEqualTo(result.Status);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(measurement.Version).IsNull();
        await Assert.That(measurement.NativeAcknowledged || measurement.EmissionEstablished).IsFalse();
        await Assert.That(measurement.NativeSettled).IsEqualTo(!malformed);
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsEqualTo(!malformed);
        await Assert.That(f.Fixture.Wire.Secret).IsEqualTo(Material);
        await Assert.That(f.Native.Sends).IsEqualTo(1);
    }

    [Test]
    public async Task NotificationWindowsMeasurementsAndOriginalInvocationCannotBeReusedOrForged()
    {
        await using var f = await NotificationCaptureScope.Create();
        await using var other = await NotificationCaptureScope.Create();
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var otherWindow = other.Source.Arm(other.Binding, material);
        await Assert.That(() => f.Source.Read(new RuntimeCapture.Window(), f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Read(window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.Arm(f.Binding, material)).Throws<InvalidOperationException>();
        var target = f.Target();
        var request = new AzureSetSecretRequest(target, material);
        var receipt = new MutationReceipt(target);
        await f.Source.RunSetAsync(f.Binding.Selector, f.Client, request, receipt, default);
        var otherTarget = other.Target();
        await other.Source.RunSetAsync(other.Binding.Selector, other.Client, new(otherTarget, material), new(otherTarget), default);
        var measurement = f.Source.Read(window, f.Binding);
        var foreign = other.Source.Read(otherWindow, other.Binding);
        await Assert.That(() => f.Source.ValidateMeasurement(f.Fixture.Journal, Owner, window, f.Binding, foreign))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.ValidateMeasurement(other.Fixture.Journal, Owner, window, f.Binding, measurement))
            .Throws<InvalidOperationException>();
        var reopenedJournal = new RoleFixtureJournal(Path.GetDirectoryName(f.Fixture.JournalPath)!);
        await Assert.That(() => f.Source.ValidateMeasurement(reopenedJournal, Owner, window, f.Binding, measurement))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.ValidateMeasurement(f.Fixture.Journal, "other-owner", window, f.Binding, measurement))
            .Throws<InvalidOperationException>();
        await Assert.That(() => f.Source.ValidateMeasurement(f.Fixture.Journal, Owner, otherWindow, f.Binding, measurement))
            .Throws<InvalidOperationException>();
        foreach (var changed in new[]
        {
            f.Binding with { Selector = f.Binding.Selector with { Case = "independent-effect" } },
            f.Binding with { LeaseId = Guid.NewGuid() }, f.Binding with { ObservationId = Guid.NewGuid() },
            f.Binding with { AzureSubscriptionId = Guid.NewGuid() }, f.Binding with { ResourceGroup = "another-group" },
            f.Binding with { VaultName = "another-vault" }, f.Binding with { RuntimeSecretName = "another-secret" },
            f.Binding with { PreparedVersion = NotificationCaptureScope.FreshVersion }
        })
        {
            await Assert.That(() => f.Source.Read(window, changed)).Throws<InvalidOperationException>();
            await Assert.That(() => f.Source.ValidateMeasurement(f.Fixture.Journal, Owner, window, changed, measurement))
                .Throws<InvalidOperationException>();
        }
        await Assert.That(async () => await f.Source.RunSetAsync(f.Binding.Selector, f.Client, request, receipt, default))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Sends).IsEqualTo(1);
    }

    [Test]
    [Arguments("close")]
    [Arguments("dispatch")]
    [Arguments("selected")]
    [Arguments("lease")]
    [Arguments("absent")]
    public async Task NotificationArmRejectsUnpreparedOrBusyOriginalRoots(string fault)
    {
        await using var f = await NotificationCaptureScope.Create();
        var binding = f.Binding;
        string secret = f.Fixture.Read().Resources.Single(r => r.Id.EndsWith("/secrets/canary", StringComparison.Ordinal)).Id;
        if (fault == "close") f.Fixture.Journal.Close(Owner, binding.Selector);
        if (fault is "dispatch" or "selected")
        {
            Guid dispatch = f.Fixture.Journal.BeginSelectedUpdate(Owner, binding.Selector, secret);
            if (fault == "selected") f.Fixture.Journal.EndDispatch(Owner, binding.Selector, secret, dispatch);
        }
        if (fault == "lease") binding = binding with { LeaseId = Guid.NewGuid() };
        if (fault == "absent") binding = binding with { RuntimeSecretName = "unprepared" };
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        await Assert.That(() => f.Source.Arm(binding, material)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Sends).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task NotificationArmRechecksRootAndSourceAfterClockCallback(bool dispose)
    {
        await using var f = await NotificationCaptureScope.Create();
        Task? disposal = null;
        f.Clock.Callback = () =>
        {
            if (dispose) disposal = f.Source.DisposeAsync().AsTask();
            else f.Fixture.Journal.Close(Owner, f.Binding.Selector);
        };
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        await Assert.That(() => f.Source.Arm(f.Binding, material)).Throws<InvalidOperationException>();
        if (disposal is not null) await disposal.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Sends).IsEqualTo(0);
    }

    [Test]
    [Arguments("absent")]
    [Arguments("deleted")]
    [Arguments("cleanup")]
    public async Task NotificationArmRequiresNativePreparedActiveVaultAndRuntimeSecret(string state)
    {
        var preparation = state switch
        {
            "absent" => VaultFixtureProvisioner.Preparation.Absent,
            "deleted" => VaultFixtureProvisioner.Preparation.Deleted,
            _ => VaultFixtureProvisioner.Preparation.Active
        };
        await using var f = await NotificationCaptureScope.Create(preparation: preparation, seedCanary: state != "cleanup");
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        await Assert.That(() => f.Source.Arm(f.Binding, material)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Sends).IsEqualTo(0);
    }

    [Test]
    public async Task NotificationWindowExpirationUsesInjectedClockWithoutWaiting()
    {
        await using var f = await NotificationCaptureScope.Create();
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        f.Source.Arm(f.Binding, material);
        f.Clock.Elapsed = TimeSpan.FromMinutes(3);
        var target = f.Target();
        await Assert.That(async () => await f.Source.RunSetAsync(f.Binding.Selector, f.Client,
            new(target, material), new(target), default)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Sends).IsEqualTo(0);
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task NotificationRejectsDifferentOriginalMaterialWithoutWriting()
    {
        await using var f = await NotificationCaptureScope.Create();
        using var expected = SecretMaterial.FromText(NotificationCaptureScope.Value);
        using var different = SecretMaterial.FromText("different-original");
        f.Source.Arm(f.Binding, expected);
        var target = f.Target();
        await Assert.That(async () => await f.Source.RunSetAsync(f.Binding.Selector, f.Client,
            new(target, different), new(target), default)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Sends).IsEqualTo(0);
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
    }

    [Test]
    public async Task NotificationThrowingResponseDisposalStillClearsStorageAndDrains()
    {
        await using var f = await NotificationCaptureScope.Create();
        f.Tracking.ThrowOnDispose = true;
        using var material = SecretMaterial.FromText(NotificationCaptureScope.Value);
        var window = f.Source.Arm(f.Binding, material);
        var target = f.Target();
        await Assert.That(async () => await f.Source.RunSetAsync(f.Binding.Selector, f.Client,
            new(target, material), new(target), default)).Throws<InvalidOperationException>();
        await f.Source.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Tracking.DisposeAttempts > 0).IsTrue();
        await Assert.That(f.Tracking.ResponseBuffer).IsNotNull();
        await Assert.That(f.Tracking.ResponseBuffer!.All(b => b == 0)).IsTrue();
        using var captured = new MemoryStream();
        f.Tracking.RequestContent!.WriteTo(captured, default);
        await Assert.That(captured.ToArray().All(b => b == 0)).IsTrue();
        await Assert.That(f.Source.Read(window, f.Binding).TaskDrained).IsTrue();
        await Assert.That(f.Fixture.Read().Resources.All(r => r.ActiveDispatch == Guid.Empty)).IsTrue();
        await Assert.That(f.Native.Disposed || f.Credential.Disposed).IsFalse();
    }

    private sealed class NotificationCaptureScope : IAsyncDisposable
    {
        internal const string Value = "notification-original-value";
        internal const string FreshVersion = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        internal readonly Fixture Fixture;
        internal readonly NotificationRuntimeBackend Native;
        internal readonly NotificationRuntimeCredential Credential = new();
        internal readonly NotificationRuntimeClock Clock = new();
        internal readonly NotificationResponseTransport Tracking;
        internal readonly RuntimeCapture Source;
        internal readonly RuntimeCapture.Binding Binding;
        internal readonly NotificationRuntimeSeam Seam;
        internal readonly AzureKeyVaultClient Client;
        private readonly HttpClient http;

        private NotificationCaptureScope(Fixture fixture, string fault)
        {
            Fixture = fixture;
            Native = new(fixture, fault);
            http = new(Native);
            Tracking = new(new HttpClientTransport(http));
            Source = new(fixture.Journal, Owner, new(Credential, Tracking),
                new(4096, 4096, 32768, 64, 8, TimeSpan.FromMinutes(2)), Clock);
            Binding = new(fixture.Selector, fixture.Read().LeaseId, Guid.NewGuid(), Subscription,
                "fixture-group", fixture.Wire.VaultName, "canary", Version);
            Seam = new(Source.RuntimeTransport);
            Client = new(new Uri("https://" + Binding.VaultName + ".vault.azure.net"),
                new Credential("runtime-secret"), Seam);
        }

        internal static async Task<NotificationCaptureScope> Create(string fault = "",
            VaultFixtureProvisioner.Preparation preparation = VaultFixtureProvisioner.Preparation.Active,
            bool seedCanary = true, string[]? notifications = null, bool allowPurge = false)
        {
            var fixture = new Fixture(allowPurge: allowPurge);
            try
            {
                fixture.Selector = fixture.Selector with
                {
                    Operation = "a.management.VaultAdministration.CreateOrUpdateNotificationAsync",
                    Variant = "event.SecretNewVersionCreated"
                };
                bool seed = seedCanary && preparation != VaultFixtureProvisioner.Preparation.Absent;
                var plan = fixture.Plan(preparation, seedCanary: seed, notifications: notifications);
                using var material = SecretMaterial.FromText(Material);
                var prepared = await fixture.Source.ProvisionAsync(plan, material);
                if (prepared.State != VaultFixtureProvisioner.State.Ready ||
                    preparation == VaultFixtureProvisioner.Preparation.Active && seed && prepared.CanaryVersion != Version)
                    throw new InvalidOperationException("controlled-native-preparation");
                return new(fixture, fault);
            }
            catch { fixture.Dispose(); throw; }
        }

        internal SecretReference Target() => new(Client.Authority, new AzureSecretAddress("canary"));

        public async ValueTask DisposeAsync()
        {
            Credential.Resume.TrySetResult();
            Seam.BodyResume.TrySetResult();
            Native.BodyResume.TrySetResult();
            Seam.Resume.TrySetResult();
            try { await Source.DisposeAsync(); }
            finally { http.Dispose(); Fixture.Dispose(); }
        }
    }

    private sealed class NotificationRuntimeCredential : TokenCredential, IDisposable
    {
        internal readonly TaskCompletionSource Entered = Signal(), Resume = Signal();
        internal bool Block, Disposed;
        internal int Calls;
        internal Action? Callback;
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            if (requestContext.Scopes.Length != 1 || requestContext.Scopes[0] != "https://vault.azure.net/.default")
                throw new InvalidOperationException("controlled-audience");
            Calls++;
            Entered.TrySetResult();
            if (Block) await Resume.Task; // Deliberately ignores cancellation; its actual exit must drain.
            Callback?.Invoke();
            return new("source-runtime", DateTimeOffset.MaxValue);
        }
        public void Dispose() => Disposed = true;
    }

    private sealed class NotificationRuntimeClock : TimeProvider
    {
        internal Action? Callback;
        internal TimeSpan Elapsed;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow()
        {
            var callback = Callback;
            Callback = null;
            callback?.Invoke();
            return new DateTimeOffset(2026, 10, 16, 0, 0, 0, TimeSpan.Zero) + Elapsed;
        }
        public override long GetTimestamp() => Elapsed.Ticks;
    }

    private sealed class NotificationRuntimeSeam(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal readonly TaskCompletionSource AfterNative = Signal(), Resume = Signal();
        internal readonly TaskCompletionSource BodyEntered = Signal(), BodyResume = Signal();
        internal bool Warm, HoldAfterNative, BlockRequestBody;
        internal HttpMessage? Message;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Message = message;
            if (Warm)
            {
                // A warm envelope at the installed SDK seam. Do not seed or
                // mutate the SDK's global challenge cache to obtain this case.
                byte[] bytes = Encoding.UTF8.GetBytes("{\"value\":\"notification-original-value\",\"attributes\":{}}");
                message.Request.Content = BlockRequestBody ? new NotificationHeldContent(bytes, this) :
                    RequestContent.Create(bytes);
                message.Request.Headers.SetValue("Authorization", "Bearer unrelated-cached-token");
            }
            await inner.ProcessAsync(message);
            AfterNative.TrySetResult();
            if (HoldAfterNative) await Resume.Task;
        }
    }

    private sealed class NotificationHeldContent(byte[] bytes, NotificationRuntimeSeam seam) : RequestContent
    {
        public override bool TryComputeLength(out long length) { length = bytes.Length; return true; }
        public override void WriteTo(Stream stream, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("controlled-async-only");
        public override async Task WriteToAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(bytes, cancellationToken);
            seam.BodyEntered.TrySetResult();
            await seam.BodyResume.Task;
            cancellationToken.ThrowIfCancellationRequested();
        }
        public override void Dispose() => CryptographicOperations.ZeroMemory(bytes);
    }

    private sealed class NotificationRuntimeBackend(Fixture fixture, string fault) : HttpMessageHandler
    {
        internal readonly TaskCompletionSource BodyEntered = Signal(), BodyResume = Signal();
        internal bool BlockBody, Prejournaled = true, Disposed;
        internal int Sends;
        internal string? Body, Authorization, Version;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            string path = "/secrets/canary";
            if (request.Method != HttpMethod.Put ||
                request.RequestUri!.AbsoluteUri != "https://" + fixture.Wire.VaultName +
                    ".vault.azure.net" + path + "?api-version=2025-07-01")
                throw new InvalidOperationException("controlled-exact-runtime-route");
            Prejournaled &= fixture.Read().Resources.Any(r =>
                r.Id == fixture.Wire.VaultId + path && r.ActiveDispatch != Guid.Empty && !r.InvocationTerminated);
            Authorization = request.Headers.Authorization?.ToString();
            if (Authorization != "Bearer source-runtime") throw new InvalidOperationException("controlled-runtime-authority");
            Body = await request.Content!.ReadAsStringAsync(cancellationToken);
            using var body = JsonDocument.Parse(Body);
            if (!fault.StartsWith("denied", StringComparison.Ordinal))
            {
                fixture.Wire.Secret = body.RootElement.GetProperty("value").GetString();
                Version = NotificationCaptureScope.FreshVersion;
            }
            if (fault == "lost") throw new HttpRequestException("controlled-native-response-loss");
            string version = fault == "old-version" ? AzureVaultFixtureProvisionerTests.Version : NotificationCaptureScope.FreshVersion;
            string origin = fault == "foreign" ? "https://foreign.vault.azure.net" :
                "https://" + fixture.Wire.VaultName + ".vault.azure.net";
            string json = JsonSerializer.Serialize(new
            {
                id = origin + path + "/" + version,
                value = fault == "wrong-value" ? "foreign" : fixture.Wire.Secret,
                attributes = new { enabled = true }
            });
            if (fault == "malformed") json = "{";
            if (fault == "duplicate") json = json[..^1] + ",\"value\":\"duplicate\"}";
            if (fault == "oversized") json = new string(' ', 4097) + json;
            if (fault == "deep") json = "{\"tags\":" + new string('[', 9) + "0" + new string(']', 9) + "}";
            if (fault == "nodes") json = "{\"tags\":[" + string.Join(',', Enumerable.Repeat("0", 65)) + "]}";
            if (fault == "denied") json = "{\"error\":{\"code\":\"Forbidden\",\"message\":\"controlled\"}}";
            if (fault == "denied-malformed") json = "{\"error\":{\"code\":\"unknown\"}}";
            var response = new HttpResponseMessage(fault.StartsWith("denied", StringComparison.Ordinal) ? HttpStatusCode.Forbidden :
                fault == "async" ? HttpStatusCode.Accepted :
                fault == "redirect" ? HttpStatusCode.TemporaryRedirect : HttpStatusCode.OK)
            {
                Content = new StreamContent(new NotificationRuntimeBody(Encoding.UTF8.GetBytes(json), this))
            };
            response.Content.Headers.ContentType = new("application/json");
            if (fault != "missing-request-id") response.Headers.Add("x-ms-request-id", "native-original-write");
            if (fault is "async" or "async-header") response.Headers.Add("Azure-AsyncOperation", origin + "/operations/selected");
            if (fault is "redirect" or "redirect-header") response.Headers.Location = new Uri(origin + path);
            if (fault == "headers") response.Headers.Add("x-controlled", new string('x', 33000));
            return response;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }

    private sealed class NotificationRuntimeBody(byte[] bytes, NotificationRuntimeBackend backend) : MemoryStream(bytes)
    {
        private bool entered;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (!entered)
            {
                entered = true;
                backend.BodyEntered.TrySetResult();
                if (backend.BlockBody) await backend.BodyResume.Task;
            }
            return await base.ReadAsync(buffer, cancellationToken);
        }
    }

    private sealed class NotificationResponseTransport(HttpPipelineTransport inner) : HttpPipelineTransport
    {
        internal bool ThrowOnDispose;
        internal int DisposeAttempts;
        internal byte[]? ResponseBuffer;
        internal RequestContent? RequestContent;
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            RequestContent = message.Request.Content;
            await inner.ProcessAsync(message);
            message.Response = new NotificationTrackedResponse(message.Response, this);
        }

        private sealed class NotificationTrackedResponse(Response inner, NotificationResponseTransport owner) : Response
        {
            public override int Status => inner.Status;
            public override string ReasonPhrase => inner.ReasonPhrase;
            public override string ClientRequestId { get => inner.ClientRequestId; set => inner.ClientRequestId = value; }
            public override Stream? ContentStream
            {
                get => inner.ContentStream;
                set
                {
                    if (value is MemoryStream memory && memory.TryGetBuffer(out var buffer)) owner.ResponseBuffer = buffer.Array;
                    inner.ContentStream = value;
                }
            }
            public override void Dispose()
            {
                owner.DisposeAttempts++;
                inner.Dispose();
                if (owner.ThrowOnDispose) throw new InvalidOperationException("controlled-response-disposal");
            }
            protected override bool ContainsHeader(string name) => inner.Headers.Contains(name);
            protected override IEnumerable<HttpHeader> EnumerateHeaders() => inner.Headers;
            protected override bool TryGetHeader(string name, [NotNullWhen(true)] out string? value) =>
                inner.Headers.TryGetValue(name, out value);
            protected override bool TryGetHeaderValues(string name, [NotNullWhen(true)] out IEnumerable<string>? values) =>
                inner.Headers.TryGetValues(name, out values);
        }
    }
}
