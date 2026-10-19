using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointNativeCapture;
using Native = SecretKit.AzureKeyVault.Conformance.Tests.AzurePrivateEndpointNativeSdkTests;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzurePrivateEndpointNativeCaptureTests
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Group = "/subscriptions/" + Subscription + "/resourceGroups/endpoint-group";
    private static readonly R.Limits Bounds = new(65536, 32768, 4096, 64, 16, TimeSpan.FromSeconds(20));

    [Test]
    [Arguments(200, false)]
    [Arguments(201, false)]
    [Arguments(201, true)]
    public async Task OnlyOriginalEndpointCreationAndActualCompletionCanIssueProof(int status, bool asynchronous)
    {
        await using var f = new Fixture(status, asynchronous);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(f.Source.OwnsCreationProof(proof!, f.Window, f.Binding, f.Dispatch)).IsTrue();
        await Assert.That(f.Source.OwnsCreationProof(proof!, f.Window, f.Binding, Guid.NewGuid())).IsFalse();
        await Assert.That(f.Source.OwnsCreationProof(proof!, f.Window, f.Binding with { }, f.Dispatch)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Native.Requests.Count).IsEqualTo(asynchronous ? 3 : 1);
        await Assert.That(f.Admissions).IsEqualTo(1);
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("Location")]
    [Arguments("Properties")]
    [Arguments("value")]
    [Arguments("nextLink")]
    [Arguments("error")]
    public async Task OrdinaryNativeTagsDoNotInvalidateOriginalCreationEvidence(string tag)
    {
        await using var f = new Fixture();
        f.Native.AfterReply = async response =>
        {
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
            body["tags"]![tag] = "ordinary-tag";
            response.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        };
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsTrue();
    }

    [Test]
    [Arguments("empty")]
    [Arguments("foreign-resource")]
    [Arguments("pending")]
    [Arguments("failed")]
    [Arguments("relative-target")]
    [Arguments("foreign-target")]
    [Arguments("wrong-revision")]
    [Arguments("ambiguous-target")]
    [Arguments("retry")]
    [Arguments("encoding")]
    [Arguments("status")]
    [Arguments("oversized")]
    public async Task UnqualifiedNativeStartCannotIssueCreationProof(string fault)
    {
        bool asynchronous = fault.EndsWith("target", StringComparison.Ordinal) || fault == "wrong-revision";
        await using var f = new Fixture(asynchronous ? 201 : 200, asynchronous);
        f.Native.AfterReply = async response =>
        {
            if (fault == "empty") response.Content = new StringContent("", Encoding.UTF8, "application/json");
            if (fault == "oversized") response.Content = new StringContent(new string('x', 65537), Encoding.UTF8, "application/json");
            if (fault is "foreign-resource" or "pending" or "failed")
            {
                var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
                if (fault == "foreign-resource") body["id"] = f.Binding.EndpointId + "-foreign";
                else body["properties"]!["provisioningState"] = fault == "pending" ? "Updating" : "Failed";
                response.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
            }
            if (fault is "relative-target" or "foreign-target" or "wrong-revision")
            {
                string target = response.Headers.GetValues("Azure-AsyncOperation").Single();
                response.Headers.Remove("Azure-AsyncOperation");
                response.Headers.Add("Azure-AsyncOperation", fault switch
                {
                    "relative-target" => new Uri(target).PathAndQuery,
                    "foreign-target" => target.Replace("management.azure.com", "foreign.invalid", StringComparison.Ordinal),
                    _ => target.Replace("2026-01-01", "2024-01-01", StringComparison.Ordinal)
                });
            }
            if (fault == "ambiguous-target") response.Headers.Add("Location", "https://foreign.invalid/next");
            if (fault == "retry") response.Headers.Add("Retry-After", "1");
            if (fault == "encoding") response.Content.Headers.ContentEncoding.Add("gzip");
            if (fault == "status") response.StatusCode = HttpStatusCode.Accepted;
        };
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Requests.Count).IsEqualTo(1);
        await Assert.That(f.Admissions).IsEqualTo(1);
    }

    [Test]
    [Arguments("Pending")]
    [Arguments("Failed")]
    [Arguments("future-state")]
    public async Task NonterminalOrFailedNativeStatusCannotBeReplayedIntoCreationProof(string state)
    {
        await using var f = new Fixture(201, true);
        await f.Start();
        f.Native.AfterReply = response =>
        {
            response.Content = new StringContent(JsonSerializer.Serialize(new { status = state }), Encoding.UTF8, "application/json");
            return Task.CompletedTask;
        };
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Unavailable);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Requests.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task OriginalCachedResponseSurvivesStartAndClearsAfterItsFinalReaderOrSeal(bool seal)
    {
        await using var f = new Fixture();
        var buffers = new List<byte[]>();
        f.Native.AfterReply = async response =>
        {
            byte[] bytes = await response.Content.ReadAsByteArrayAsync();
            response.Content = new StreamContent(new ObservedStream(bytes, buffers));
            response.Content.Headers.ContentType = new("application/json");
        };
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(buffers.Any(b => b.Any(v => v != 0))).IsTrue();
        if (seal) await f.Source.SealAsync(f.Window);
        else await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(buffers.All(b => b.All(v => v == 0))).IsTrue();
    }

    [Test]
    public async Task CreationCompletionDoesNotReplaceIndependentOwnerAndDependencyReadback()
    {
        await using var f = new Fixture();
        f.Native.AfterReply = async response =>
        {
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync())!;
            body["tags"]!["fixture-owner"] = "foreign-owner";
            response.Content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        };
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Source.CheckStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsTrue();
        var reader = new P(new("independent-reader", f.Native.Credential, f.Native.Transport), Bounds, f.Clock);
        var observed = await reader.CollectAsync(reader.Arm(f.Binding), f.Binding);
        await Assert.That(observed.ResponseComplete).IsTrue();
        await Assert.That(observed.MatchesDeclaration || observed.OwnershipProven || observed.NativeSettlementProven).IsFalse();
    }

    [Test]
    public async Task DisposingCreationCaptureDoesNotDisposeBorrowedTransportOrCredential()
    {
        await using var f = new Fixture();
        await f.Start();
        await f.Source.DisposeAsync();
        var observed = await f.Native.Client.GetGenericResource(new(f.Binding.EndpointId)).GetAsync();
        await Assert.That(observed.Value.Id.ToString()).IsEqualTo(f.Binding.EndpointId);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task DurableAdmissionPrecedesStartClockCredentialAndTransportCallbacks()
    {
        await using var f = new Fixture();
        bool admitted = false;
        f.Clock.BeforeRead = () =>
        {
            if (!admitted) throw new InvalidOperationException("clock-before-admission");
        };
        var result = await f.Source.StartAsync(f.Window, f.Binding, () =>
        {
            if (f.Native.Credential.Scopes.Count != 0 || f.Native.Requests.Count != 0)
                throw new InvalidOperationException("native-before-admission");
            admitted = true;
            return f.Dispatch;
        });
        await Assert.That(result).IsEqualTo(SecretStatus.Success);
        await Assert.That(admitted).IsTrue();
    }

    [Test]
    public async Task FailedAdmissionConsumesStartWithoutAnyNativeCallbackOrReplay()
    {
        await using var f = new Fixture();
        int calls = 0;
        await Assert.That(async () => await f.Source.StartAsync(f.Window, f.Binding, () =>
        {
            calls++;
            throw new InvalidOperationException("controlled-journal-rejection");
        })).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(calls).IsEqualTo(1);
        await Assert.That(f.Native.Credential.Scopes.Count + f.Native.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task EmptyAdmissionDispatchCannotReachNativeCreation()
    {
        await using var f = new Fixture();
        await Assert.That(async () => await f.Source.StartAsync(f.Window, f.Binding, () => Guid.Empty))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Credential.Scopes.Count + f.Native.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task ForeignWindowOrEqualBindingCannotConsumeOriginalStart()
    {
        await using var f = new Fixture();
        await using var other = new Fixture();
        await Assert.That(async () => await other.Source.StartAsync(f.Window, f.Binding, () => Guid.NewGuid()))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.StartAsync(f.Window, f.Binding with { }, () => Guid.NewGuid()))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Admissions).IsEqualTo(1);
        await Assert.That(other.Native.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task AnotherSourceCannotAdoptCreationProofWithMatchingCoordinates()
    {
        await using var f = new Fixture();
        await using var other = new Fixture();
        await f.Start();
        await f.Source.CheckStatusAsync(f.Window, f.Binding);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(other.Source.OwnsCreationProof(proof!, other.Window, other.Binding, f.Dispatch)).IsFalse();
        await Assert.That(other.Source.OwnsCreationProof(proof!, f.Window, f.Binding, f.Dispatch)).IsFalse();
        await Assert.That(other.Native.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task SealedCreationWindowRevokesProofWithoutMutationReplay()
    {
        await using var f = new Fixture();
        await f.Start();
        await f.Source.CheckStatusAsync(f.Window, f.Binding);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out var proof)).IsTrue();
        await f.Source.SealAsync(f.Window);
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Source.OwnsCreationProof(proof!, f.Window, f.Binding, f.Dispatch)).IsFalse();
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Native.Requests.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CloseDrainsActualUncooperativeCreationBeforeReturning(bool dispose)
    {
        await using var f = new Fixture();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Native.BeforeSend = async token =>
        {
            using var registration = token.Register(() => canceled.TrySetResult());
            entered.TrySetResult();
            await resume.Task;
        };
        var start = f.Start().AsTask();
        Task? close = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            close = dispose ? f.Source.DisposeAsync().AsTask() : f.Source.SealAsync(f.Window).AsTask();
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(start.IsCompleted || close.IsCompleted).IsFalse();
        }
        finally { resume.TrySetResult(); }
        await Assert.That(await start.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Unavailable);
        await close!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task CanceledActualStatusTaskCannotIssueACompletionProof()
    {
        await using var f = new Fixture(201, true);
        await f.Start();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        f.Native.BeforeSend = async token =>
        {
            using var registration = token.Register(() => canceled.TrySetResult());
            entered.TrySetResult();
            await resume.Task;
        };
        using var cancellation = new CancellationTokenSource();
        var check = f.Source.CheckStatusAsync(f.Window, f.Binding, cancellation.Token).AsTask();
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            cancellation.Cancel();
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(check.IsCompleted).IsFalse();
        }
        finally { resume.TrySetResult(); }
        await Assert.That(async () => await check.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task StatusBeforeOriginalStartCannotInventCreationEvidence()
    {
        await using var f = new Fixture();
        await Assert.That(async () => await f.Source.CheckStatusAsync(f.Window, f.Binding)).Throws<InvalidOperationException>();
        await Assert.That(f.Source.TryGetCreationProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Native.Requests.Count).IsEqualTo(0);
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly Native.Fixture Native;
        internal readonly P.Binding Binding = new(new(Guid.NewGuid(), "controlled-endpoint",
            ManagementOperationEffects.Members[0].Operation, "operation.UpdatePrivateConnection", "selected-contract"),
            Guid.NewGuid(),
            Group + "/providers/Microsoft.Network/privateEndpoints/generated-endpoint",
            Group + "/providers/Microsoft.KeyVault/vaults/owned-vault",
            Group + "/providers/Microsoft.Network/virtualNetworks/borrowed-network/subnets/borrowed-subnet",
            Group + "/providers/Microsoft.Network/networkInterfaces/generated-nic",
            "network-side-name", "eastus", "fixture-owner", "controlled-owner");
        internal readonly C Source;
        internal readonly C.Window Window;
        internal readonly Guid Dispatch = Guid.NewGuid();
        internal readonly Clock Clock = new();
        internal int Admissions;
        internal Fixture(int status = 200, bool asynchronous = false)
        {
            Native = new(status, asynchronous);
            Source = new(new("endpoint-setup", Native.Credential, Native.Transport), Bounds, Clock);
            Window = Source.Arm(Binding);
        }
        internal ValueTask<SecretStatus> Start() => Source.StartAsync(Window, Binding, () => { Admissions++; return Dispatch; });
        public async ValueTask DisposeAsync()
        {
            try { await Source.DisposeAsync(); }
            finally { Native.Dispose(); }
        }
    }

    private sealed class Clock : TimeProvider
    {
        internal Action? BeforeRead;
        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override DateTimeOffset GetUtcNow() { BeforeRead?.Invoke(); return new(2026, 10, 16, 0, 0, 0, TimeSpan.Zero); }
        public override long GetTimestamp() { BeforeRead?.Invoke(); return 0; }
    }

    private sealed class ObservedStream(byte[] bytes, List<byte[]> buffers) : MemoryStream(bytes, false)
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment) && segment.Array is { } array)
                buffers.Add(array);
            return base.ReadAsync(buffer, cancellationToken);
        }
    }
}
