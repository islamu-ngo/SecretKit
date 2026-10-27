using System.Net;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class RotationOutcomeTests
{
    private const string Id = "bb4b7959-a8ef-493f-a2c1-807b3be3aa71";
    private const string OtherId = "7dd128d5-fedd-445f-aaef-6aec4bb35335";

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task AcquisitionFaultIsSanitizedBeforeAnyDispatch(bool io)
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var tokens = new Tokens
        {
            AcquisitionFault = io
            ? new IOException("protected-acquisition-canary")
            : new HttpRequestException("protected-acquisition-canary")
        };
        using var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That((await client.GetAsync(target)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That((await client.ListAsync(new(client.Authority,
            new InfisicalRotationScope("private-project")))).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task AcquisitionCancellationRemainsCallerCancellation()
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var cancellation = new CancellationTokenSource();
        using var tokens = new Tokens
        {
            OnAcquire = cancellation.Cancel,
            AcquisitionFault = new OperationCanceledException("protected-cancellation-canary")
        };
        using var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        try
        {
            await client.RotateSecretsAsync(target, receipt, cancellationToken: cancellation.Token);
            throw new InvalidOperationException("Expected caller cancellation.");
        }
        catch (OperationCanceledException exception)
        {
            await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
            await Assert.That(exception.ToString().Contains("protected-cancellation-canary", StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    [Arguments("unsuccessful")]
    [Arguments("http")]
    [Arguments("io")]
    public async Task CancellationWinsReleasedAcquisitionFailureWithoutDispatch(string failure)
    {
        foreach (string operation in new[] { "get", "list", "rotate", "automatic" })
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var cancellation = new CancellationTokenSource();
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var acquisition = new TaskCompletionSource<SecretOutcome<InfisicalAccessToken>>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            using var wire = new RotationWire();
            using var http = new HttpClient(wire);
            using var tokens = new Tokens
            {
                OnAcquire = () => entered.TrySetResult(),
                PendingAcquisition = acquisition.Task
            };
            using var client = Client(http, tokens);
            var target = Target(client);
            var receipt = new InfisicalRotationReceipt(target, operation == "automatic" ?
                InfisicalRotationAction.EnableAutomaticRotation : InfisicalRotationAction.RotateSecrets);
            Task pending = operation switch
            {
                "get" => client.GetAsync(target, cancellation.Token).AsTask(),
                "list" => client.ListAsync(new(client.Authority,
                    new InfisicalRotationScope("private-project")), cancellationToken: cancellation.Token).AsTask(),
                "rotate" => client.RotateSecretsAsync(target, receipt, cancellationToken: cancellation.Token).AsTask(),
                _ => client.SetAutomaticRotationAsync(target, true, receipt,
                    cancellationToken: cancellation.Token).AsTask()
            };
            await entered.Task.WaitAsync(deadline.Token);
            cancellation.Cancel();
            if (failure == "unsuccessful")
                acquisition.SetResult(SecretOutcome<InfisicalAccessToken>.Failure(SecretStatus.Denied));
            else
                acquisition.SetException(failure == "http" ?
                    new HttpRequestException("protected-acquisition-canary") :
                    new IOException("protected-acquisition-canary"));
            try
            {
                await pending.WaitAsync(deadline.Token);
                throw new InvalidOperationException("Expected caller cancellation.");
            }
            catch (OperationCanceledException exception)
            {
                await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
                await Assert.That(exception.ToString().Contains("protected-acquisition-canary",
                    StringComparison.Ordinal)).IsFalse();
            }
            await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
            await Assert.That(wire.Requests).IsEqualTo(0);
        }
    }

    [Test]
    public async Task EveryCurrentProfileUsesItsNativeRoutesAndObservedSetting()
    {
        foreach (var profile in Enum.GetValues<InfisicalRotationProfile>())
        {
            using var wire = new RotationWire(profile);
            using var http = new HttpClient(wire);
            using var tokens = new Tokens();
            var client = Client(http, tokens);
            var target = Target(client, profile);
            var initial = (await client.GetAsync(target)).Value;
            await Assert.That(initial.Address.Profile).IsEqualTo(profile);
            var trigger = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
            var pending = (await client.RotateSecretsAsync(target, trigger)).Value;
            await Assert.That(pending.NativeStatus).IsEqualTo("pending");
            await Assert.That(trigger.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseObserved);
            await Assert.That(trigger.Effect).IsEqualTo(InfisicalRotationEffect.AcceptedPending);
            await Assert.That(wire.Rotations).IsEqualTo(1);
            await Assert.That(pending.ConsumerDeliveryVerified).IsFalse();
            await Assert.That(pending.FleetConvergenceVerified).IsFalse();
            await Assert.That((await client.RotateSecretsAsync(target, trigger)).Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(wire.Rotations).IsEqualTo(1);
            foreach (bool enabled in new[] { false, true })
            {
                var receipt = new InfisicalRotationReceipt(target, enabled ?
                    InfisicalRotationAction.EnableAutomaticRotation : InfisicalRotationAction.DisableAutomaticRotation);
                await Assert.That((await client.SetAutomaticRotationAsync(target, enabled, receipt)).Value.AutoRotationEnabled)
                    .IsEqualTo((bool?)enabled);
                await Assert.That(wire.Enabled).IsEqualTo(enabled);
                await Assert.That(receipt.Effect).IsEqualTo(InfisicalRotationEffect.AutomaticRotationSettingApplied);
            }
            await Assert.That(wire.UnexpectedOperation).IsFalse();
        }
    }

    [Test]
    [Arguments("pending")]
    [Arguments("failed")]
    [Arguments("success")]
    [Arguments("future-provider-state")]
    public async Task OpenNativeStatusIsPreservedWithoutInventingCompletionOrAttribution(string status)
    {
        using var wire = new RotationWire { Status = status };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var observed = (await client.GetAsync(target)).Value;
        await Assert.That(observed.NativeStatus).IsEqualTo(status);
        await Assert.That(observed.LastJobId).IsEqualTo("job-private");
        await Assert.That(wire.Rotations).IsEqualTo(0);
        await Assert.That(observed.ConsumerDeliveryVerified).IsFalse();
    }

    [Test]
    public async Task ListIsBoundedSingleObservationWithoutPagingOrMutations()
    {
        using var wire = new RotationWire { ListCount = 2 };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var scope = new SecretReference(client.Authority, new InfisicalRotationScope("private-project"));
        var result = (await client.ListAsync(scope, 1)).Value;
        await Assert.That(result.IsComplete).IsFalse();
        await Assert.That(result.Items.Count).IsEqualTo(1);
        await Assert.That((await client.ListAsync(scope, 2)).Value.IsComplete).IsTrue();
        await Assert.That(wire.Rotations).IsEqualTo(0);
        await Assert.That(wire.Requests).IsEqualTo(2);
        await Assert.That(wire.UnexpectedOperation).IsFalse();
    }

    [Test]
    public async Task ScopeReceiptActionAndMandatoryPreconditionsFailBeforeToken()
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var tokens = new Tokens { Forbidden = true };
        var client = Client(http, tokens);
        var target = Target(client);
        var trigger = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        var sameCoordinates = Target(client);
        await Assert.That((await client.RotateSecretsAsync(sameCoordinates, trigger)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.SetAutomaticRotationAsync(target, false, trigger)).Status).IsEqualTo(SecretStatus.Invalid);
        foreach (var condition in new[] { InfisicalRotationPrecondition.RequireCompareAndSwap,
            InfisicalRotationPrecondition.RequireIdempotency })
        {
            await Assert.That((await client.RotateSecretsAsync(target, trigger, condition)).Status).IsEqualTo(SecretStatus.Unsupported);
        }
        var otherProject = new SecretReference(client.Authority,
            new InfisicalRotationAddress("other-project", "private-env", "/private-path",
                InfisicalRotationProfile.PostgresCredentials, Id));
        await Assert.That((await client.GetAsync(otherProject)).Status).IsEqualTo(SecretStatus.Invalid);
        var otherInstance = new SecretReference(new SecretAuthority(), target.Address);
        await Assert.That((await client.GetAsync(otherInstance)).Status).IsEqualTo(SecretStatus.Invalid);
        var scoped = Client(http, tokens, environment: "different-env", path: "/different-path");
        await Assert.That((await scoped.GetAsync(Target(scoped))).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await scoped.ListAsync(new(scoped.Authority, new InfisicalRotationScope("private-project")))).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.ListAsync(new(client.Authority, new InfisicalRotationScope("private-project")), 0)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That((await client.ListAsync(new(client.Authority, new InfisicalRotationScope("private-project")), 4097)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(trigger.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    [Arguments(400, SecretStatus.Invalid, InfisicalRotationDispatch.Rejected)]
    [Arguments(401, SecretStatus.Denied, InfisicalRotationDispatch.Rejected)]
    [Arguments(403, SecretStatus.Denied, InfisicalRotationDispatch.Rejected)]
    [Arguments(404, SecretStatus.Absent, InfisicalRotationDispatch.Rejected)]
    [Arguments(409, SecretStatus.Conflict, InfisicalRotationDispatch.Rejected)]
    [Arguments(422, SecretStatus.Invalid, InfisicalRotationDispatch.Rejected)]
    [Arguments(429, SecretStatus.Throttled, InfisicalRotationDispatch.ResponseUnknown)]
    [Arguments(500, SecretStatus.Unavailable, InfisicalRotationDispatch.ResponseUnknown)]
    [Arguments(202, SecretStatus.Unknown, InfisicalRotationDispatch.ResponseUnknown)]
    [Arguments(302, SecretStatus.Unknown, InfisicalRotationDispatch.ResponseUnknown)]
    public async Task HttpFailureCannotBecomeProviderApplied(int code, SecretStatus expected,
        InfisicalRotationDispatch dispatch)
    {
        using var wire = new RotationWire { ResponseCode = code };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(expected);
        await Assert.That(receipt.Dispatch).IsEqualTo(dispatch);
        await Assert.That(receipt.Effect).IsEqualTo(InfisicalRotationEffect.Unknown);
        await Assert.That(receipt.ResponseProgress is null).IsTrue();
        await Assert.That(wire.Rotations).IsEqualTo(0);
    }

    [Test]
    [Arguments("projectId", "\"wrong-project\"")]
    [Arguments("id", "\"7dd128d5-fedd-445f-aaef-6aec4bb35335\"")]
    [Arguments("type", "\"redis-credentials\"")]
    [Arguments("environment", "{\"slug\":\"other-env\"}")]
    [Arguments("folder", "{\"path\":\"/other\"}")]
    [Arguments("rotationStatus", "null")]
    [Arguments("lastRotatedAt", "\"not-a-date\"")]
    [Arguments("isAutoRotationEnabled", "\"true\"")]
    public async Task InvalidProgressResponseLeavesCommittedMutationUnknown(string field, string replacement)
    {
        using var wire = new RotationWire { ReplacementField = field, Replacement = replacement };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(wire.Rotations).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task BodyBudgetCoversLengthHeadersAndActualStream(bool knownLength)
    {
        using var wire = new RotationWire { Oversized = true, KnownLength = knownLength };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens, responseLimit: 1024);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Rotations).IsEqualTo(1);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(wire.BodyDisposed).IsTrue();
    }

    [Test]
    [Arguments("{")]
    [Arguments("{\"secretRotation\":{},\"secretRotation\":{}}")]
    [Arguments("[]")]
    public async Task MalformedOrAmbiguousEnvelopeCannotBeObserved(string body)
    {
        using var wire = new RotationWire { RawBody = body };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
    }

    [Test]
    public async Task LostCommittedResponseIsNotReplayedOrReconciledByGet()
    {
        using var wire = new RotationWire { LoseResponse = true };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(wire.Rotations).IsEqualTo(1);
        wire.LoseResponse = false;
        wire.Status = "success";
        await Assert.That((await client.GetAsync(target)).Value.NativeStatus).IsEqualTo("success");
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(receipt.ResponseProgress is null).IsTrue();
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Rotations).IsEqualTo(1);
    }

    [Test]
    public async Task CancellationBeforeAndAfterSendRetainsExactReceiptAndNeverReplays()
    {
        using var wire = new RotationWire { HoldResponse = true };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var before = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        using var alreadyCanceled = new CancellationTokenSource();
        alreadyCanceled.Cancel();
        await Assert.That(async () => await client.RotateSecretsAsync(target, before,
            cancellationToken: alreadyCanceled.Token)).Throws<OperationCanceledException>();
        await Assert.That(before.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(wire.Rotations).IsEqualTo(0);
        var after = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        using var cancellation = new CancellationTokenSource();
        Task operation = client.RotateSecretsAsync(target, after, cancellationToken: cancellation.Token).AsTask();
        await wire.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        cancellation.Cancel();
        await Assert.That(async () => await operation.WaitAsync(TimeSpan.FromSeconds(5))).Throws<OperationCanceledException>();
        await Assert.That(wire.Rotations).IsEqualTo(1);
        await Assert.That(after.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That((await client.RotateSecretsAsync(target, after)).Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task ConcurrentUseOfReceiptCannotDispatchTwice()
    {
        using var wire = new RotationWire { HoldResponse = true };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        var first = client.RotateSecretsAsync(target, receipt).AsTask();
        await wire.Committed.Task.WaitAsync(TimeSpan.FromSeconds(5));
        await Assert.That((await client.RotateSecretsAsync(target, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        wire.Release.TrySetResult();
        await Assert.That((await first.WaitAsync(TimeSpan.FromSeconds(5))).IsSuccess).IsTrue();
        await Assert.That(wire.Rotations).IsEqualTo(1);
    }

    [Test]
    public async Task RedactionOwnedCopiesAndHostTransportSurviveOperation()
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var progress = (await client.GetAsync(target)).Value;
        string serialized = JsonSerializer.Serialize(progress) + JsonSerializer.Serialize(target) +
            JsonSerializer.Serialize(new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets));
        await Assert.That(serialized.Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(serialized.Contains(Id, StringComparison.Ordinal)).IsFalse();
        await Assert.That(progress.ToString().Contains("private", StringComparison.Ordinal)).IsFalse();
        await Assert.That(tokens.Source.Reveal()).IsEqualTo("private-token");
        await Assert.That(() => tokens.LastCopy!.Reveal()).Throws<ObjectDisposedException>();
        await Assert.That(progress.NativeStatus).IsEqualTo("success");
        wire.Status = "failed";
        await Assert.That((await client.GetAsync(target)).Value.NativeStatus).IsEqualTo("failed");
        await Assert.That(progress.NativeStatus).IsEqualTo("success");
        await Assert.That(wire.BodyDisposed).IsTrue();
        await Assert.That(wire.UnexpectedOperation).IsFalse();
    }

    [Test]
    public async Task SettingResponseMustActuallyObserveRequestedBoolean()
    {
        using var wire = new RotationWire { IgnoreSetting = true };
        using var http = new HttpClient(wire);
        using var tokens = new Tokens();
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.DisableAutomaticRotation);
        await Assert.That((await client.SetAutomaticRotationAsync(target, false, receipt)).Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.ResponseUnknown);
        await Assert.That(wire.Enabled).IsTrue();
    }

    [Test]
    public async Task TrustedOriginAndNativeInputBoundsHaveProtectedErrors()
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var tokens = new Tokens { Forbidden = true };
        var authority = new SecretAuthority();
        var admin = new InfisicalNativeAuthority(authority, tokens, "private-project");
        foreach (string invalid in new[]
        {
            "http://rotation.example", "https://private-user:private-pass@rotation.example",
            "https://rotation.example/private-path", "https://rotation.example?private=query"
        })
        {
            await Assert.That(() => new InfisicalRotationClient(new(invalid), authority, admin))
                .Throws<ArgumentException>();
        }
        await Assert.That(() => new InfisicalRotationAddress(new string('p', 1025), "env", "/",
            InfisicalRotationProfile.PostgresCredentials, Id)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalRotationAddress("project", "env", "/private/../path",
            InfisicalRotationProfile.PostgresCredentials, Id)).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalRotationAddress("project", "env", "/",
            InfisicalRotationProfile.PostgresCredentials, "private-invalid-id")).Throws<ArgumentException>();
        await Assert.That(() => new InfisicalRotationAddress("project", "env", "/",
            (InfisicalRotationProfile)999, Id)).Throws<ArgumentException>();
        await Assert.That(wire.Requests).IsEqualTo(0);
    }

    [Test]
    public async Task CancellationAtTokenReturnIsStillPreDispatchAndDisposesCopy()
    {
        using var wire = new RotationWire();
        using var http = new HttpClient(wire);
        using var cancellation = new CancellationTokenSource();
        using var tokens = new Tokens { OnIssued = cancellation.Cancel };
        var client = Client(http, tokens);
        var target = Target(client);
        var receipt = new InfisicalRotationReceipt(target, InfisicalRotationAction.RotateSecrets);
        await Assert.That(async () => await client.RotateSecretsAsync(target, receipt,
            cancellationToken: cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That(receipt.Dispatch).IsEqualTo(InfisicalRotationDispatch.NotDispatched);
        await Assert.That(wire.Rotations).IsEqualTo(0);
        await Assert.That(() => tokens.LastCopy!.Reveal()).Throws<ObjectDisposedException>();
    }

    private static InfisicalRotationClient Client(HttpClient http, Tokens tokens, int responseLimit = 4096,
        string? environment = null, string? path = null)
    {
        var authority = new SecretAuthority();
        return new(new Uri("https://rotation.example"), authority,
            new(authority, tokens, "private-project", environment, path),
            new() { Transport = InfisicalTransportOptions.HostControlled(http), MaximumResponseBytes = responseLimit });
    }

    private static SecretReference Target(InfisicalRotationClient client,
        InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials) =>
        new(client.Authority, new InfisicalRotationAddress("private-project", "private-env", "/private-path", profile, Id));

    private sealed class Tokens : IInfisicalTokenSource, IDisposable
    {
        internal SecretMaterial Source { get; } = SecretMaterial.FromText("private-token");
        internal SecretMaterial? LastCopy { get; private set; }
        internal bool Forbidden { get; init; }
        internal Action? OnIssued { get; init; }
        internal Action? OnAcquire { get; init; }
        internal Exception? AcquisitionFault { get; init; }
        internal Task<SecretOutcome<InfisicalAccessToken>>? PendingAcquisition { get; init; }
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            OnAcquire?.Invoke();
            if (PendingAcquisition is { } pending) return new(pending);
            if (AcquisitionFault is { } fault) throw fault;
            if (Forbidden)
            {
                throw new InvalidOperationException("Forbidden credential acquisition.");
            }
            LastCopy = Source.Copy();
            OnIssued?.Invoke();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(LastCopy)));
        }
        public void Dispose() => Source.Dispose();
    }

    /// <summary>Managed wire fixture with committed provider state and exact event barriers.</summary>
    private sealed class RotationWire(InfisicalRotationProfile profile = InfisicalRotationProfile.PostgresCredentials)
        : HttpMessageHandler
    {
        internal string Status { get; set; } = "success";
        internal bool Enabled { get; private set; } = true;
        internal int Rotations { get; private set; }
        internal int Requests { get; private set; }
        internal bool UnexpectedOperation { get; private set; }
        internal int ResponseCode { get; init; } = 200;
        internal bool LoseResponse { get; set; }
        internal bool HoldResponse { get; init; }
        internal bool Oversized { get; init; }
        internal bool KnownLength { get; init; }
        internal bool IgnoreSetting { get; init; }
        internal bool BodyDisposed { get; private set; }
        internal int ListCount { get; init; } = 1;
        internal string? ReplacementField { get; init; }
        internal string? Replacement { get; init; }
        internal string? RawBody { get; init; }
        internal TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            string collection = "/api/v2/secret-rotations";
            string native = collection + "/" + InfisicalRotationClient.WireProfile(profile) + "/" + Id;
            string? path = request.RequestUri?.AbsolutePath;
            bool list = request.Method == HttpMethod.Get && path == collection &&
                request.RequestUri?.Query == "?projectId=private-project";
            if (request.RequestUri?.GetLeftPart(UriPartial.Authority) != "https://rotation.example" ||
                request.Headers.Authorization?.Parameter != "private-token")
            {
                throw new InvalidOperationException("Unexpected origin or authority.");
            }
            if (ResponseCode != 200)
            {
                return new((HttpStatusCode)ResponseCode) { Content = new StringContent("private-provider-error") };
            }
            if (request.Method == HttpMethod.Post && path == native + "/rotate-secrets")
            {
                if (request.Content is not null &&
                    (await request.Content.ReadAsByteArrayAsync(cancellationToken)).Length != 0)
                {
                    throw new InvalidOperationException("Trigger has no published body.");
                }
                Rotations++;
                Status = "pending";
                Committed.TrySetResult();
                if (LoseResponse)
                {
                    throw new HttpRequestException("private-coordinates-and-credentials");
                }
                if (HoldResponse)
                {
                    await Release.Task.WaitAsync(cancellationToken);
                }
            }
            else if (request.Method == HttpMethod.Patch && path == native)
            {
                using var payload = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(cancellationToken));
                if (payload.RootElement.EnumerateObject().Count() != 1)
                {
                    throw new InvalidOperationException("Only enablement may be changed.");
                }
                bool requested = payload.RootElement.GetProperty("isAutoRotationEnabled").GetBoolean();
                if (!IgnoreSetting)
                {
                    Enabled = requested;
                }
            }
            else if (!(list || (request.Method == HttpMethod.Get && path == native)))
            {
                UnexpectedOperation = true;
                throw new InvalidOperationException("Unexpected operation; no runtime, lease, restart or reconciliation routes.");
            }
            string body = RawBody ?? JsonSerializer.Serialize(list ?
                new Dictionary<string, object>
                {
                    ["secretRotations"] = Enumerable.Range(0, ListCount)
                    .Select(index => Rotation(index == 0 ? Id : OtherId)).ToArray()
                } :
                new Dictionary<string, object> { ["secretRotation"] = Rotation(Id) });
            if (Oversized)
            {
                body += new string(' ', 8192);
            }
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            HttpContent content = new StreamContent(new BodyStream(bodyBytes, () => BodyDisposed = true));
            if (KnownLength)
            {
                content.Headers.ContentLength = bodyBytes.Length;
            }
            content.Headers.ContentType = new("application/json");
            return new(HttpStatusCode.OK) { Content = content };
        }

        private Dictionary<string, object?> Rotation(string id)
        {
            var state = new Dictionary<string, object?>
            {
                ["id"] = id,
                ["projectId"] = "private-project",
                ["type"] = InfisicalRotationClient.WireProfile(profile),
                ["environment"] = new { slug = "private-env", id = OtherId, name = "private-env-name" },
                ["folder"] = new { path = "/private-path", id = OtherId },
                ["rotationStatus"] = Status,
                ["isAutoRotationEnabled"] = Enabled,
                ["isLastRotationManual"] = true,
                ["lastRotationAttemptedAt"] = "2026-10-09T10:00:00Z",
                ["lastRotatedAt"] = "2026-10-08T10:00:00Z",
                ["nextRotationAt"] = null,
                ["lastRotationJobId"] = "job-private",
                ["lastRotationMessage"] = "private-provider-message",
                ["name"] = "private-name",
                ["parameters"] = new { username1 = "private-user", password = "private-config" },
                ["secretsMapping"] = new { password = "private-secret" },
                ["createdAt"] = "2026-10-01T10:00:00Z",
                ["updatedAt"] = "2026-10-09T10:00:00Z",
                ["folderId"] = OtherId,
                ["connectionId"] = OtherId,
                ["connection"] = new { app = "postgres", name = "private-connection", id = OtherId },
                ["rotateAtUtc"] = new { hours = 10, minutes = 0 },
                ["rotationInterval"] = 1
            };
            if (ReplacementField is not null)
            {
                using var replacement = JsonDocument.Parse(Replacement!);
                state[ReplacementField] = replacement.RootElement.Clone();
            }
            return state;
        }
    }

    private sealed class BodyStream(byte[] bytes, Action disposed) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                disposed();
            }
            base.Dispose(disposing);
        }
    }
}
