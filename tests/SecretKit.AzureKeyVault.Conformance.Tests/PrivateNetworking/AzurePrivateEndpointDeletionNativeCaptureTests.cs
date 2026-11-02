using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.Core;
using C = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointNativeCapture;
using Native = SecretKit.AzureKeyVault.Conformance.Tests.AzurePrivateEndpointNativeSdkTests;
using P = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using R = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzurePrivateEndpointDeletionNativeCaptureTests
{
    private const string Subscription = "11111111-1111-1111-1111-111111111111";
    private const string Group = "/subscriptions/" + Subscription + "/resourceGroups/endpoint-group";
    private static readonly R.Limits Bounds = new(65536, 32768, 4096, 64, 16, TimeSpan.FromSeconds(20));

    [Test]
    [Arguments(204, false)]
    [Arguments(202, true)]
    public async Task OriginalEndpointDeletionNeedsItsActualExplicitNativeCompletion(int status, bool asynchronous)
    {
        await using var f = new Fixture(status, asynchronous);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(f.Source.OwnsDeletionProof(proof!, f.Window, f.Binding, f.Dispatch)).IsTrue();
        await Assert.That(f.Source.OwnsDeletionProof(proof!, f.Window, f.Binding, Guid.NewGuid())).IsFalse();
        await Assert.That(f.Source.OwnsDeletionProof(proof!, f.Window, f.Binding with { }, f.Dispatch)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(proof)).IsEqualTo("{}");
        await Assert.That(f.Native.Requests.Count).IsEqualTo(asynchronous ? 2 : 1);
        await Assert.That(f.Native.Requests[0].Method).IsEqualTo("DELETE");
        await Assert.That(f.Native.Requests.Skip(1).All(r => r.Method == "GET" && r.Path.Contains("/operations/", StringComparison.Ordinal))).IsTrue();
        await Assert.That(f.Native.Requests.Any(r => r.Path == f.Binding.NicId)).IsFalse();
        await Assert.That(f.Admissions).IsEqualTo(1);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DeletionAdmissionPrecedesEveryClockCredentialAndTransportCallback()
    {
        await using var f = new Fixture();
        f.Clock.BeforeRead = () =>
        {
            if (f.Admissions != 1) throw new InvalidOperationException("controlled-premature-clock");
        };
        f.Native.BeforeSend = _ =>
        {
            if (f.Admissions != 1) throw new InvalidOperationException("controlled-premature-send");
            return Task.CompletedTask;
        };
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RejectedOrEmptyDeletionAdmissionCannotSendOrReplay(bool empty)
    {
        await using var f = new Fixture();
        await Assert.That(async () => await f.Source.StartDeleteAsync(f.Window, f.Binding,
            () => empty ? Guid.Empty : throw new InvalidOperationException("controlled-admission")))
            .Throws<InvalidOperationException>();
        await Assert.That(f.Native.Requests.Count).IsEqualTo(0);
        await Assert.That(f.Native.Credential.Scopes.Count).IsEqualTo(0);
        await Assert.That(async () => await f.Start()).Throws<InvalidOperationException>();
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    public async Task MatchingConstructedDeletionCapabilitiesAreNotOriginalAuthority()
    {
        await using var f = new Fixture();
        var window = C.DeleteWindow.Create(f.Binding);
        await Assert.That(async () => await f.Source.StartDeleteAsync(window, f.Binding, () => f.Dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(async () => await f.Source.StartDeleteAsync(f.Window, f.Binding with { }, () => f.Dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        var forged = C.DeletionProof.Create(f.Binding, f.Dispatch);
        await Assert.That(f.Source.OwnsDeletionProof(forged, f.Window, f.Binding, f.Dispatch)).IsFalse();
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out var original)).IsTrue();
        await Assert.That(f.Source.OwnsDeletionProof(original!, f.Window, f.Binding, f.Dispatch)).IsTrue();
    }

    [Test]
    public async Task ForeignDeletionWindowsAndProofsCannotConferCompletion()
    {
        await using var f = new Fixture();
        await using var other = new Fixture();
        await Assert.That(async () => await f.Source.StartDeleteAsync(other.Window, other.Binding, () => f.Dispatch))
            .Throws<InvalidOperationException>();
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
        await Assert.That(await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).IsEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out var proof)).IsTrue();
        await Assert.That(other.Source.OwnsDeletionProof(proof!, other.Window, other.Binding, f.Dispatch)).IsFalse();
        await Assert.That(other.Native.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("nonempty204")]
    [Arguments("unsupported200")]
    [Arguments("missing-target")]
    [Arguments("relative-target")]
    [Arguments("foreign-target")]
    [Arguments("wrong-revision")]
    [Arguments("malformed-status")]
    [Arguments("pending-status")]
    [Arguments("failed-status")]
    public async Task InvalidDeletionProtocolCannotIssueProof(string fault)
    {
        bool asynchronous = fault is not ("nonempty204" or "unsupported200");
        await using var f = new Fixture(fault == "unsupported200" ? 200 : asynchronous ? 202 : 204, asynchronous);
        f.Native.AfterReply = response =>
        {
            if (response.StatusCode == HttpStatusCode.Accepted)
            {
                string target = response.Headers.GetValues("Azure-AsyncOperation").Single();
                response.Headers.Remove("Azure-AsyncOperation");
                target = fault switch
                {
                    "relative-target" => new Uri(target).PathAndQuery,
                    "foreign-target" => target.Replace("management.azure.com", "foreign.invalid", StringComparison.Ordinal),
                    "wrong-revision" => target.Replace("2026-01-01", "2025-01-01", StringComparison.Ordinal),
                    _ => target
                };
                if (fault != "missing-target") response.Headers.Add("Azure-AsyncOperation", target);
            }
            if (fault == "nonempty204") response.Content = new StringContent("unexpected", Encoding.UTF8, "application/json");
            if (response.StatusCode == HttpStatusCode.OK && asynchronous && fault.EndsWith("-status", StringComparison.Ordinal))
                response.Content = new StringContent(fault switch
                {
                    "malformed-status" => "{",
                    "pending-status" => """{"status":"Running"}""",
                    _ => """{"status":"Failed"}"""
                }, Encoding.UTF8, "application/json");
            return Task.CompletedTask;
        };
        var start = await f.Start();
        if (start == SecretStatus.Success)
            await Assert.That(await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding)).IsNotEqualTo(SecretStatus.Success);
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Native.Requests.Count(r => r.Method == "DELETE")).IsLessThanOrEqualTo(1);
    }

    [Test]
    public async Task DisposalRevokesDeletionProofAndPreservesBorrowedNativeHost()
    {
        await using var f = new Fixture();
        await f.Start();
        await f.Source.CheckDeleteStatusAsync(f.Window, f.Binding);
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out var proof)).IsTrue();
        await f.Source.DisposeAsync();
        await Assert.That(f.Source.OwnsDeletionProof(proof!, f.Window, f.Binding, f.Dispatch)).IsFalse();
        var operation = await f.Native.Client.GetGenericResource(new(f.Binding.EndpointId)).DeleteAsync(Azure.WaitUntil.Started);
        await operation.UpdateStatusAsync();
        await Assert.That(operation.HasCompleted).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ClosingDeletionCaptureAwaitsAnActuallyUncooperativeSend(bool dispose)
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
            await Assert.That(close.IsCompleted || start.IsCompleted).IsFalse();
        }
        finally { resume.TrySetResult(); }
        await Assert.That(await start.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Unavailable);
        await close!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
    }

    [Test]
    [Arguments("caller")]
    [Arguments("seal")]
    [Arguments("dispose")]
    public async Task InterruptedDeletionStatusWaitsForTheOriginalUncooperativeStatusTask(string kind)
    {
        await using var f = new Fixture(202, true);
        await Assert.That(await f.Start()).IsEqualTo(SecretStatus.Success);
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
        var status = f.Source.CheckDeleteStatusAsync(f.Window, f.Binding, cancellation.Token).AsTask();
        Task? close = null;
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            if (kind == "caller") cancellation.Cancel();
            else close = kind == "seal" ? f.Source.SealAsync(f.Window).AsTask() : f.Source.DisposeAsync().AsTask();
            await canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(status.IsCompleted || close?.IsCompleted == true).IsFalse();
            await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
        }
        finally { resume.TrySetResult(); }
        if (kind == "caller")
            await Assert.That(async () => await status.WaitAsync(TimeSpan.FromSeconds(10))).Throws<OperationCanceledException>();
        else
        {
            await Assert.That(await status.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Unavailable);
            await close!.WaitAsync(TimeSpan.FromSeconds(10));
        }
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
        await Assert.That(f.Native.Requests.Count(r => r.Method == "DELETE")).IsEqualTo(1);
    }

    [Test]
    public async Task DeletionDisposalWaitsForAnUncooperativeBorrowedCredential()
    {
        var credential = new BarrierCredential();
        await using var f = new Fixture(credential: credential);
        var start = f.Start().AsTask();
        Task? close = null;
        try
        {
            await credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            close = f.Source.DisposeAsync().AsTask();
            await credential.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(start.IsCompleted || close.IsCompleted).IsFalse();
            await Assert.That(f.Native.Requests.Count).IsEqualTo(0);
        }
        finally { credential.Resume.TrySetResult(); }
        await Assert.That(await start.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Unavailable);
        await close!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(f.Native.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task DeletionStatusDisposalKeepsTheActualBodyBufferUntilItsBorrowerDrains()
    {
        await using var f = new Fixture(202, true);
        await f.Start();
        var body = new BarrierStream(Encoding.UTF8.GetBytes("""{"status":"Succeeded"}"""));
        f.Native.AfterReply = response =>
        {
            response.Content = new StreamContent(body);
            response.Content.Headers.ContentType = new("application/json");
            return Task.CompletedTask;
        };
        var status = f.Source.CheckDeleteStatusAsync(f.Window, f.Binding).AsTask();
        Task? close = null;
        try
        {
            await body.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            close = f.Source.DisposeAsync().AsTask();
            await body.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(10));
            await Assert.That(status.IsCompleted || close.IsCompleted).IsFalse();
            await Assert.That(body.Buffer!.Any(b => b != 0)).IsTrue();
        }
        finally { body.Resume.TrySetResult(); }
        await Assert.That(await status.WaitAsync(TimeSpan.FromSeconds(10))).IsEqualTo(SecretStatus.Unavailable);
        await close!.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(body.Buffer!.All(b => b == 0)).IsTrue();
        await Assert.That(f.Source.TryGetDeletionProof(f.Window, f.Binding, out _)).IsFalse();
    }

    private sealed class BarrierCredential : Azure.Core.TokenCredential
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override Azure.Core.AccessToken GetToken(Azure.Core.TokenRequestContext context, CancellationToken token) =>
            throw new InvalidOperationException("controlled-async-only");
        public override async ValueTask<Azure.Core.AccessToken> GetTokenAsync(Azure.Core.TokenRequestContext context, CancellationToken token)
        {
            using var registration = token.Register(() => Canceled.TrySetResult());
            Entered.TrySetResult();
            await Resume.Task;
            return new("controlled-endpoint-credential", DateTimeOffset.MaxValue);
        }
    }

    private sealed class BarrierStream(byte[] bytes) : MemoryStream(bytes, false)
    {
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Canceled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Resume = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal byte[]? Buffer;
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int count = await base.ReadAsync(buffer, CancellationToken.None);
            if (count > 0)
            {
                if (!MemoryMarshal.TryGetArray((ReadOnlyMemory<byte>)buffer, out var segment))
                    throw new InvalidOperationException("controlled-buffer");
                Buffer = segment.Array;
                using var registration = cancellationToken.Register(() => Canceled.TrySetResult());
                Entered.TrySetResult();
                await Resume.Task;
            }
            return count;
        }
    }

    private sealed class Fixture : IAsyncDisposable
    {
        internal readonly Native.Fixture Native;
        internal readonly P.Binding Binding = new(
            new(Guid.NewGuid(), "controlled", ManagementOperationEffects.Members[0].Operation,
                "operation.UpdatePrivateConnection", "selected-contract"), Guid.NewGuid(),
            Group + "/providers/Microsoft.Network/privateEndpoints/generated-endpoint",
            Group + "/providers/Microsoft.KeyVault/vaults/owned-vault",
            Group + "/providers/Microsoft.Network/virtualNetworks/borrowed-network/subnets/borrowed-subnet",
            Group + "/providers/Microsoft.Network/networkInterfaces/generated-nic",
            "network-side-name", "eastus", "fixture-owner", "controlled-owner");
        internal readonly C Source;
        internal readonly C.DeleteWindow Window;
        internal readonly Guid Dispatch = Guid.NewGuid();
        internal readonly Clock Clock = new();
        internal int Admissions;
        internal Fixture(int status = 204, bool asynchronous = false, Azure.Core.TokenCredential? credential = null)
        {
            Native = new(status, asynchronous);
            Source = new(new("endpoint-cleanup", credential ?? Native.Credential, Native.Transport), Bounds, Clock);
            Window = Source.ArmDelete(Binding);
        }
        internal ValueTask<SecretStatus> Start() =>
            Source.StartDeleteAsync(Window, Binding, () => { Admissions++; return Dispatch; });
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
}
