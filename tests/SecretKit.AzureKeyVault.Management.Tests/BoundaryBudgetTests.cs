using System.Net;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Management.Tests;

public sealed class BoundaryBudgetTests
{
    [Test]
    public async Task CredentialFailureHasNoDispatchOrBackendEffect()
    {
        bool changed = false;
        var backend = new WireBackend((_, _) =>
        {
            changed = true;
            return Task.FromResult(WireBackend.Json(204, ""));
        });
        var client = new VaultAdministration(new Credential { Fail = true }, backend);
        var scope = ScopeAuthorityTests.Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteVault);
        var result = await client.DeleteVaultAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(changed).IsFalse();
        await Assert.That(result.ToString().Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(403, DispatchEvidence.Rejected, SecretStatus.Denied)]
    [Arguments(409, DispatchEvidence.Conflict, SecretStatus.Conflict)]
    [Arguments(429, DispatchEvidence.Rejected, SecretStatus.Throttled)]
    public async Task AuthoritativeRejectionIsNotUnknownOrApplied(int status,
        DispatchEvidence evidence, SecretStatus outcome)
    {
        bool exists = true;
        var backend = new WireBackend((_, _) =>
        {
            if (!exists)
            {
                throw new InvalidOperationException("Rejected operation changed backend state.");
            }

            return Task.FromResult(WireBackend.Json(status, """{"error":{"code":"Rejected","message":"canary"}}"""));
        });
        var client = new VaultAdministration(new Credential(), backend);
        var scope = ScopeAuthorityTests.Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.DeleteVault);
        var result = await client.DeleteVaultAsync(scope, receipt);
        await Assert.That(result.Status).IsEqualTo(outcome);
        await Assert.That(receipt.Evidence).IsEqualTo(evidence);
        await Assert.That(exists).IsTrue();
    }

    [Test]
    public async Task ChunkedResponseBudgetIsEnforcedBeforeSdkDeserialization()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamingContent(ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id) + new string(' ', 2048))
        }));
        var result = await new VaultAdministration(new Credential(), backend, maximumResponseBytes: 1024)
            .GetVaultAsync(ScopeAuthorityTests.Scope());
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    public async Task InitialLroResponseSubstitutionCannotPublishPendingHandle()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(201,
            ScopeAuthorityTests.VaultJson(ScopeAuthorityTests.Id.Replace("group-canary", "other-group")))));
        var client = new VaultAdministration(new Credential(), backend);
        var scope = ScopeAuthorityTests.Scope();
        var receipt = client.PrepareReceipt(scope, ManagementMutation.CreateOrUpdateVault);
        var configuration = new VaultConfiguration("eastus",
            Guid.Parse("22222222-2222-2222-2222-222222222222"), VaultSku.Standard, true, true, 7, false);
        var result = await client.CreateOrUpdateVaultAsync(scope, configuration, receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task PrivateConnectionNoContentMeansAbsent()
    {
        var backend = new WireBackend((_, _) => Task.FromResult(WireBackend.Json(204, "")));
        var result = await new VaultAdministration(new Credential(), backend)
            .GetPrivateConnectionAsync(new PrivateConnectionScope(ScopeAuthorityTests.Scope(), "connection-canary"));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Absent);
    }

    [Test]
    public async Task InjectedDeadlineCancelsExactInFlightReadWithoutSleep()
    {
        var time = new ManualTime();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var backend = new WireBackend(async (_, token) =>
        {
            var canceled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = token.Register(() => canceled.TrySetCanceled(token));
            entered.SetResult();
            await canceled.Task;
            return WireBackend.Json(200, "{}");
        });
        var pending = new VaultAdministration(new Credential(), backend, timeProvider: time)
            .GetVaultAsync(ScopeAuthorityTests.Scope()).AsTask();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        time.FireDeadline();
        var result = await pending.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Unavailable);
    }

    private sealed class ManualTime : TimeProvider
    {
        private readonly List<Timer> _timers = [];
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = new Timer(callback, state);
            _timers.Add(timer);
            return timer;
        }

        public void FireDeadline()
        {
            foreach (var timer in _timers.ToArray())
            {
                timer.Fire();
            }
        }

        private sealed class Timer(TimerCallback callback, object? state) : ITimer
        {
            private bool _disposed;
            public bool Change(TimeSpan dueTime, TimeSpan period) => !_disposed;
            public void Fire()
            {
                if (!_disposed)
                {
                    callback(state);
                }
            }

            public void Dispose() => _disposed = true;
            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }

    private sealed class StreamingContent(string text) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult<Stream>(new NonSeekableStream(System.Text.Encoding.UTF8.GetBytes(text)));
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(System.Text.Encoding.UTF8.GetBytes(text)).AsTask();
    }

    private sealed class NonSeekableStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
    }
}
