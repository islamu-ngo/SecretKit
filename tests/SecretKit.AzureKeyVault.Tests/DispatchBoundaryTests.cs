using System.Collections.Concurrent;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

public sealed class DispatchBoundaryTests
{
    [Test]
    [Arguments(403, false)]
    [Arguments(409, false)]
    [Arguments(403, true)]
    [Arguments(409, true)]
    public async Task DefinitiveRejectionSurvivesAnOversizedResponseBody(int status, bool native)
    {
        var vault = new Uri($"https://reject{Guid.NewGuid().ToString("N")[..12]}.vault.azure.net/");
        int authenticated = 0;
        var wire = new WireTransport((request, _) =>
        {
            if (request.Headers.Authorization is null) return Task.FromResult(WireTransport.Challenge());
            authenticated++;
            return Task.FromResult(new HttpResponseMessage((System.Net.HttpStatusCode)status)
            {
                Content = new ByteArrayContent(new byte[2048])
            });
        });
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire, maximumResponseBytes: 1024);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("one"));
        var receipt = client.CreateReceipt(target);
        SecretStatus outcome;
        if (native)
            outcome = (await client.PurgeDeletedSecretAsync(target, receipt)).Status;
        else
        {
            using var material = SecretMaterial.FromText("owned");
            outcome = (await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt)).Status;
        }

        await Assert.That(outcome).IsEqualTo(status == 403 ? SecretStatus.Denied : SecretStatus.Conflict);
        await Assert.That(receipt.Evidence).IsEqualTo(status == 403 ? DispatchEvidence.Rejected : DispatchEvidence.Conflict);
        await Assert.That(authenticated).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task InventoryValidatesContinuationBeforeStoppingAtItsLimit(bool wrongRevision)
    {
        var vault = new Uri($"https://pages{Guid.NewGuid().ToString("N")[..12]}.vault.azure.net/");
        int reads = 0;
        var wire = new WireTransport((_, _) =>
        {
            reads++;
            return Task.FromResult(WireTransport.Json(200, JsonSerializer.Serialize(new
            {
                value = new[] { new { id = $"{vault}secrets/one/{new string('a', 32)}" } },
                nextLink = wrongRevision ? $"{vault}secrets?api-version=incorrect" :
                    "https://foreign.vault.azure.net/secrets?api-version=2025-07-01"
            })));
        });
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);

        var result = await client.InspectAsync(new AzureInventoryScope(client.Authority, maximumPages: 1));

        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(reads).IsEqualTo(1);
    }

    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ContinuationCannotIntroduceMalformedRevisionKeys(bool versions, bool doubledDelimiter)
    {
        var vault = Vault();
        var wire = new WireTransport((request, _) => Task.FromResult(WireTransport.Json(200, JsonSerializer.Serialize(new
        {
            value = Array.Empty<object>(),
            nextLink = doubledDelimiter
                ? request.RequestUri!.AbsoluteUri.Replace("?", "??", StringComparison.Ordinal)
                : request.RequestUri!.AbsoluteUri + "&API-VERSION"
        }))));
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var scope = new AzureInventoryScope(client.Authority, maximumPages: 1);
        var status = versions ? (await client.GetSecretVersionsAsync(new SecretReference(client.Authority,
            new AzureSecretAddress("bound")), scope)).Status : (await client.InspectAsync(scope)).Status;
        await Assert.That(status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(wire.Requests.Count).IsEqualTo(1);
    }

    private static Uri Vault() => new($"https://w{Guid.NewGuid():N}"[..22] + ".vault.azure.net");
    private static TaskCompletionSource Gate() => new(TaskCreationOptions.RunContinuationsAsynchronously);
    private static readonly TimeSpan Guard = TimeSpan.FromSeconds(10);

    [Test]
    public async Task PinnedPipelineCarriesCaptureAcrossColdChallengeButNotIntoCredential()
    {
        var vault = Vault();
        var slot = new AsyncLocal<object?>();
        var marker = new object();
        var transport = new ProbeTransport(slot, marker, vault);
        var credential = new CallbackCredential(() => slot.Value is null);
        var options = new SecretClientOptions { Transport = transport };
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
        options.Retry.MaxRetries = 0;
        options.AddPolicy(new Capture(slot), HttpPipelinePosition.PerCall);
        var sdk = new SecretClient(vault, credential, options);
        slot.Value = marker;
        try
        {
            await sdk.SetSecretAsync("probe", "synthetic");
        }
        finally { slot.Value = null; }
        await Assert.That(transport.Sends.ToArray()).IsEquivalentTo(new[] { (false, false, true), (true, true, true) });
        await Assert.That(credential.Isolated).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DeadlineDistinguishesStalledChallengeFromDispatchedMutation(bool afterDispatch)
    {
        var clock = new ManualDeadline();
        var entered = Gate();
        var released = Gate();
        var wire = new WireTransport(async (request, token) =>
        {
            if (afterDispatch && request.Headers.Authorization is null) return WireTransport.Challenge();
            entered.TrySetResult();
            await released.Task.WaitAsync(token);
            return WireTransport.Json(503, "{}");
        });
        var client = new AzureKeyVaultClient(Vault(), new TestCredential(), wire, clock, operationTimeout: TimeSpan.FromSeconds(1));
        var target = new SecretReference(client.Authority, new AzureSecretAddress("target"));
        using var material = SecretMaterial.FromText("synthetic");
        var receipt = client.CreateReceipt(target);
        var write = client.SetSecretAsync(new(target, material), receipt).AsTask();
        try
        {
            await entered.Task.WaitAsync(Guard);
            clock.Expire();
            var result = await write.WaitAsync(Guard);
            await Assert.That((result.Status, result.Reason, receipt.Evidence)).IsEqualTo((
                afterDispatch ? SecretStatus.Unknown : SecretStatus.Unavailable, SecretFailureReason.DeadlineExceeded,
                afterDispatch ? DispatchEvidence.PossiblyDispatched : DispatchEvidence.NotDispatched));
        }
        finally { released.TrySetResult(); }
    }

    private sealed class ManualDeadline : TimeProvider
    {
        private Action? _expire;
        public void Expire() => _expire?.Invoke();
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            _expire = () => callback(state);
            return new ManualTimer();
        }
        private sealed class ManualTimer : ITimer
        {
            public void Dispose() { }
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
            public bool Change(TimeSpan dueTime, TimeSpan period) => throw new NotSupportedException();
        }
    }

    private sealed class Capture(AsyncLocal<object?> slot) : HttpPipelineSynchronousPolicy
    {
        public override void OnSendingRequest(HttpMessage message)
        {
            message.SetProperty(typeof(Capture), slot.Value!);
            slot.Value = null;
        }
    }

    private sealed class CallbackCredential(Func<bool> isolated) : TokenCredential
    {
        public bool Isolated { get; private set; }
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token) => throw new NotSupportedException();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            Isolated = isolated() && await Task.Run(isolated, token);
            return new AccessToken("synthetic", DateTimeOffset.MaxValue);
        }
    }

    private sealed class ProbeTransport(AsyncLocal<object?> slot, object marker, Uri vault) : HttpPipelineTransport
    {
        private readonly WireTransport _wire = new((req, _) => Task.FromResult(req.Headers.Authorization is null ? WireTransport.Challenge() :
            WireTransport.Json(200, JsonSerializer.Serialize(new { id = $"{vault}secrets/probe/{new string('a', 32)}" }))));
        public List<(bool, bool, bool)> Sends { get; } = [];
        public override Request CreateRequest() => _wire.CreateRequest();
        public override void Process(HttpMessage message) => throw new NotSupportedException();
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            Sends.Add((message.Request.Headers.Contains("Authorization"), message.Request.Content is not null,
                slot.Value is null && message.TryGetProperty(typeof(Capture), out var value) && ReferenceEquals(value, marker)));
            return _wire.ProcessAsync(message);
        }
    }

    [Test]
    [Arguments(400, SecretStatus.Invalid, DispatchEvidence.Rejected)]
    [Arguments(403, SecretStatus.Denied, DispatchEvidence.Rejected)]
    [Arguments(404, SecretStatus.Absent, DispatchEvidence.Rejected)]
    [Arguments(409, SecretStatus.Conflict, DispatchEvidence.Conflict)]
    public async Task ServiceRejectionIsNotAnUncertainWrite(int status, SecretStatus expected, DispatchEvidence evidence)
    {
        var wire = new WireTransport((req, _) => Task.FromResult(req.Headers.Authorization is null ? WireTransport.Challenge() : WireTransport.Json(status, "{}")));
        var client = new AzureKeyVaultClient(Vault(), new TestCredential(), wire);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("target"));
        using var material = SecretMaterial.FromText("synthetic");
        var receipt = client.CreateReceipt(target);
        var result = await client.SetSecretAsync(new(target, material), receipt);
        await Assert.That((result.Status, receipt.Evidence)).IsEqualTo((expected, evidence));
    }

    [Test]
    public async Task EscapedSetBodyOverBudgetIsNeverDispatched()
    {
        var sends = 0;
        var wire = new WireTransport((req, _) =>
        {
            if (req.Headers.Authorization is null) return Task.FromResult(WireTransport.Challenge());
            sends++;
            return Task.FromResult(WireTransport.Json(200, "{}"));
        });
        var client = new AzureKeyVaultClient(Vault(), new TestCredential(), wire, maximumResponseBytes: 1024);
        var target = new SecretReference(client.Authority, new AzureSecretAddress("target"));
        using var material = SecretMaterial.FromText(new string('\n', 600));
        var receipt = client.CreateReceipt(target);
        var result = await client.SetSecretAsync(new(target, material), receipt);
        await Assert.That((result.Status, receipt.Evidence, sends)).IsEqualTo((SecretStatus.Invalid, DispatchEvidence.NotDispatched, 0));
    }

    [Test]
    public async Task FetchedThirdRowCannotEscapeInventoryValidation()
    {
        var vault = Vault();
        var rows = new[] { new { id = $"{vault}secrets/one" }, new { id = $"{vault}secrets/two" }, new { id = "https://other.vault.azure.net/secrets/three" } };
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Json(200, JsonSerializer.Serialize(new { value = rows }))));
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var result = await client.InspectAsync(new AzureInventoryScope(client.Authority, maximumItems: 1));
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Invalid);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task TwoColdWritesNeverShareDispatchOrCancellation(bool cancelSecond)
    {
        var vault = Vault();
        var firstProbe = Gate();
        var secondProbe = Gate();
        var allowFirst = Gate();
        var allowSecond = Gate();
        var committed = new ConcurrentDictionary<string, string>();
        using var cancellation = new CancellationTokenSource();
        var wire = new WireTransport(async (request, token) =>
        {
            var name = request.RequestUri!.AbsolutePath.Trim('/').Split('/')[1];
            if (request.Headers.Authorization is null)
            {
                (name == "one" ? firstProbe : secondProbe).TrySetResult();
                await (name == "one" ? allowFirst : allowSecond).Task.WaitAsync(token);
                return WireTransport.Challenge();
            }
            if (name == "two") return WireTransport.Json(403, "{}");
            using var data = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
            committed.AddOrUpdate(name, data.RootElement.GetProperty("value").GetString()!, (_, _) => "duplicate");
            return WireTransport.Json(200, JsonSerializer.Serialize(new { id = $"{vault}secrets/{name}/{new string('b', 32)}" }));
        });
        var client = new AzureKeyVaultClient(vault, new TestCredential(), wire);
        var one = new SecretReference(client.Authority, new AzureSecretAddress("one"));
        var two = new SecretReference(client.Authority, new AzureSecretAddress("two"));
        using var first = SecretMaterial.FromText("first");
        using var second = SecretMaterial.FromText("second");
        var a = client.CreateReceipt(one);
        var b = client.CreateReceipt(two);
        var writeA = client.SetSecretAsync(new(one, first), a).AsTask();
        await firstProbe.Task.WaitAsync(Guard);
        var writeB = client.SetSecretAsync(new(two, second), b, cancellation.Token).AsTask();
        try
        {
            await secondProbe.Task.WaitAsync(Guard);
            await Assert.That((a.Evidence, b.Evidence)).IsEqualTo((DispatchEvidence.NotDispatched, DispatchEvidence.NotDispatched));
            if (cancelSecond) cancellation.Cancel();
            allowSecond.TrySetResult();
            if (cancelSecond) await Assert.That(async () => await writeB.WaitAsync(Guard)).Throws<OperationCanceledException>();
            else await Assert.That((await writeB.WaitAsync(Guard)).Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(a.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        }
        finally { allowFirst.TrySetResult(); allowSecond.TrySetResult(); }
        await Assert.That((await writeA.WaitAsync(Guard)).Status).IsEqualTo(SecretStatus.Success);
        await Assert.That((a.Evidence, b.Evidence)).IsEqualTo((DispatchEvidence.Applied, cancelSecond ? DispatchEvidence.NotDispatched : DispatchEvidence.Rejected));
        await Assert.That(committed.ToArray()).IsEquivalentTo(new[] { KeyValuePair.Create("one", "first") });
    }
}
