using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using TriggerKind = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.AuditDiagnosticsEffects.TriggerKind;

namespace SecretKit.AzureKeyVault.Conformance.Tests;

public sealed class AzureAuditNativeTriggerCaptureTests
{
    private const string Version = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string Material = "private-trigger-material";

    [Test]
    [Arguments("Get")]
    [Arguments("List")]
    [Arguments("Set")]
    [Arguments("Delete")]
    [Arguments("Recover")]
    [Arguments("Backup")]
    [Arguments("Restore")]
    [Arguments("Purge")]
    [Arguments("UpdateProperties")]
    public async Task InstalledNativeOperationsCaptureActualChallengeAndFinalDispatch(string operation)
    {
        var kind = Enum.Parse<TriggerKind>(operation);
        using var fixture = new Fixture(kind);
        Exception? failure = null;
        try { await fixture.Invoke(); }
        catch (Exception exception) { failure = exception; }
        await Assert.That(failure is RequestFailedException).IsTrue()
            .Because("Native route: " + fixture.LastPathAndQuery + "; failure: " + failure?.GetType().Name);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(ReferenceEquals(capture.Binding, fixture.Binding)).IsTrue();
        await Assert.That(capture.Attempts.Count).IsEqualTo(2);
        await Assert.That(capture.Attempts[0].Authorized).IsFalse();
        await Assert.That(capture.Attempts[0].HttpStatus).IsEqualTo(401);
        await Assert.That(capture.Attempts[1].Authorized).IsTrue();
        await Assert.That(capture.Attempts[1].HttpStatus).IsEqualTo(403);
        await Assert.That(capture.Attempts.All(a => a.TransportTerminated && a.ResponseObserved)).IsTrue();
        await Assert.That(capture.Attempts.Select(a => a.ClientCorrelationId).Distinct().Count()).IsEqualTo(2);
        await Assert.That(capture.Attempts.All(a => a.ClientCorrelationId != Guid.Empty)).IsTrue();
        await Assert.That(fixture.Backend.Observed.Select(r => r.Correlation))
            .IsEquivalentTo(capture.Attempts.Select(a => a.ClientCorrelationId));
        await Assert.That(capture.Attempts.Select(a => a.NativeResponseRequestId))
            .IsEquivalentTo(new string?[] { "native-challenge", "native-final" });
        await Assert.That(fixture.Backend.Observed.All(r => r.Path == ExpectedPath(kind) &&
            r.Method == ExpectedMethod(kind) && r.Query == "?api-version=2025-07-01")).IsTrue();
        await Assert.That(capture.Attempts.All(a => a.Operation == kind && a.NativePath == ExpectedPath(kind) &&
            a.NativeMethod.ToString() == ExpectedMethod(kind))).IsTrue();
        await Assert.That(fixture.Credential.Scopes.Single()).IsEqualTo("https://vault.azure.net/.default");
        await Assert.That(fixture.Backend.Observed.Last().Authorization).IsEqualTo("Bearer borrowed-trigger-token");
        if (kind is TriggerKind.Set or TriggerKind.Restore or TriggerKind.UpdateProperties)
        {
            await Assert.That(capture.Attempts[1].BodySha256).IsEqualTo(
                Convert.ToHexString(SHA256.HashData(fixture.Backend.Observed.Last().Body)));
        }
    }

    [Test]
    public async Task OriginalSecretKitSetPublicPathUsesCapturedBytesAndActualResponse()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.Succeed = true;
        var runtime = new AzureKeyVaultClient(fixture.Origin, fixture.Credential, fixture.Transport);
        var reference = new SecretReference(runtime.Authority, new AzureSecretAddress("selected-secret"));
        using var material = SecretMaterial.FromText(Material);
        var receipt = new MutationReceipt(reference);
        var result = await runtime.SetSecretAsync(new(reference, material), receipt);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Attempts.Last().HttpStatus).IsEqualTo(200);
        await Assert.That(capture.Attempts.Last().NativeResponseRequestId).IsEqualTo("native-final");
        await Assert.That(fixture.Backend.Value).IsEqualTo(Material);
        await Assert.That(fixture.Backend.Applied).IsTrue();
        await Assert.That(capture.Attempts.Last().ClientCorrelationId)
            .IsEqualTo(fixture.Backend.Observed.Last().Correlation);
    }

    [Test]
    [Arguments("origin")]
    [Arguments("scheme")]
    [Arguments("port")]
    [Arguments("userinfo")]
    [Arguments("fragment")]
    [Arguments("path")]
    [Arguments("encoded-path")]
    [Arguments("trailing-path")]
    [Arguments("foreign-version")]
    [Arguments("query")]
    [Arguments("duplicate-revision")]
    [Arguments("foreign-revision")]
    [Arguments("method")]
    public async Task ForeignOrMalformedRequestsNeverReachBorrowedTransport(string fault)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        string uri = fixture.Origin + "secrets/selected-secret?api-version=2025-07-01";
        uri = fault switch
        {
            "origin" => uri.Replace(fixture.Origin.Host, "other.vault.azure.net", StringComparison.Ordinal),
            "scheme" => uri.Replace("https:", "http:", StringComparison.Ordinal),
            "port" => uri.Replace(".net/", ".net:444/", StringComparison.Ordinal),
            "userinfo" => uri.Replace("https://", "https://user@", StringComparison.Ordinal),
            "fragment" => uri + "#foreign",
            "path" => uri.Replace("selected-secret", "foreign-secret", StringComparison.Ordinal),
            "encoded-path" => uri.Replace("selected-secret", "%2fselected-secret", StringComparison.Ordinal),
            "trailing-path" => uri.Replace("selected-secret?", "selected-secret//?", StringComparison.Ordinal),
            "foreign-version" => uri.Replace("selected-secret?", "selected-secret/" + Version + "?", StringComparison.Ordinal),
            "query" => uri + "&other=private",
            "duplicate-revision" => uri + "&api-version=2025-07-01",
            "foreign-revision" => uri.Replace("2025-07-01", "2024-01-01", StringComparison.Ordinal),
            _ => uri
        };
        using var content = RequestContent.Create(Encoding.UTF8.GetBytes("""{"value":"private"}"""));
        await Assert.That(async () => await fixture.Send(uri, content,
            fault == "method" ? RequestMethod.Post : RequestMethod.Put)).Throws<InvalidOperationException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Attempts.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("nonce")]
    [Arguments("scope")]
    [Arguments("operation")]
    [Arguments("variant")]
    [Arguments("case")]
    public async Task SelectedIngressRequiresFullExactSelectorNotOnlyNonce(string field)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        var selected = fixture.Binding.Selector;
        var foreign = field switch
        {
            "nonce" => selected with { Nonce = Guid.NewGuid() },
            "scope" => selected with { Scope = "foreign" },
            "operation" => selected with { Operation = "foreign" },
            "variant" => selected with { Variant = "foreign" },
            _ => selected with { Case = "foreign" }
        };
        await Assert.That(() => fixture.Source.CreateTransport(fixture.Window, foreign)).Throws<InvalidOperationException>();
        await Assert.That(() => fixture.Source.Arm(fixture.Binding)).Throws<InvalidOperationException>();
        using var other = new Fixture(TriggerKind.Set);
        await Assert.That(() => other.Source.CreateTransport(fixture.Window, selected)).Throws<InvalidOperationException>();
        await Assert.That(async () => await other.Source.SealAsync(fixture.Window)).Throws<InvalidOperationException>();
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task LostNativeResponseRetainsUncertaintyWithoutMutationReplay(bool original)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.LoseResponse = true;
        if (original)
        {
            var runtime = new AzureKeyVaultClient(fixture.Origin, fixture.Credential, fixture.Transport);
            var target = new SecretReference(runtime.Authority, new AzureSecretAddress("selected-secret"));
            using var material = SecretMaterial.FromText(Material);
            var receipt = new MutationReceipt(target);
            var result = await runtime.SetSecretAsync(new(target, material), receipt);
            await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        else await Assert.That(async () => await fixture.Invoke()).Throws<IOException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        var final = capture.Attempts.Last();
        await Assert.That(fixture.Backend.Applied).IsTrue();
        await Assert.That(final.ResponseObserved).IsFalse();
        await Assert.That(final.HttpStatus).IsNull();
        await Assert.That(final.NativeResponseRequestId).IsNull();
        await Assert.That(final.TransportTerminated).IsTrue();
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StatefulBodyIsSnapshottedOnceAndHeldUntilActualSendTermination(bool cancel)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.Block = true;
        using var content = new StatefulContent();
        using var cancellation = new CancellationTokenSource();
        var send = fixture.Send(fixture.Origin + "secrets/selected-secret?api-version=2025-07-01",
            content, RequestMethod.Put, cancellation.Token);
        await Task.WhenAny(fixture.Backend.Entered.Task, send).WaitAsync(TimeSpan.FromSeconds(10));
        if (send.IsCompleted) await send;
        await fixture.Backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var seal = fixture.Source.SealAsync(fixture.Window).AsTask();
        if (cancel) cancellation.Cancel();
        await Assert.That(seal.IsCompleted).IsFalse();
        await Assert.That(send.IsCompleted).IsFalse();
        await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0) >= 0).IsTrue();
        await Assert.That(content.Writes).IsEqualTo(1);
        using var late = RequestContent.Create(Encoding.UTF8.GetBytes("{}"));
        await Assert.That(async () => await fixture.Send(
            fixture.Origin + "secrets/selected-secret?api-version=2025-07-01", late, RequestMethod.Put))
            .Throws<InvalidOperationException>();
        fixture.Backend.Terminate.TrySetResult();
        if (cancel) await Assert.That(async () => await send).Throws<OperationCanceledException>();
        else await send;
        var capture = await seal;
        await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        await Assert.That(content.Disposed).IsFalse();
        await Assert.That(fixture.ContentRestored).IsTrue();
        await Assert.That(fixture.Backend.Value).IsEqualTo("first");
        await Assert.That(capture.Attempts.Single().BodySha256).IsEqualTo(
            Convert.ToHexString(SHA256.HashData(fixture.Backend.Observed.Single().Body)));
        await Assert.That(fixture.Backend.Disposed).IsFalse();
    }

    [Test]
    public async Task BorrowedWriterAliasCannotChangeCapturedDispatchBytes()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.BeforeRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Backend.AllowRead = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using var content = new StatefulContent();
        var send = fixture.Send(fixture.Origin + "secrets/selected-secret?api-version=2025-07-01",
            content, RequestMethod.Put);
        try
        {
            await Task.WhenAny(fixture.Backend.BeforeRead.Task, send).WaitAsync(TimeSpan.FromSeconds(10));
            if (send.IsCompleted) await send;
            await fixture.Backend.BeforeRead.Task.WaitAsync(TimeSpan.FromSeconds(10));
            Encoding.UTF8.GetBytes("""{"value":"other"}""").CopyTo(content.Storage.Span);
            fixture.Backend.AllowRead.TrySetResult();
            await send;
            var capture = await fixture.Source.SealAsync(fixture.Window);
            await Assert.That(fixture.Backend.Value).IsEqualTo("first");
            await Assert.That(capture.Attempts.Single().BodySha256).IsEqualTo(
                Convert.ToHexString(SHA256.HashData(fixture.Backend.Observed.Single().Body)));
            await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        }
        finally
        {
            fixture.Backend.AllowRead.TrySetResult();
            await send;
        }
    }

    [Test]
    public async Task ConcurrentReplayIsRejectedWhileFirstSendIsStillActive()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.Block = true;
        using var content = new StatefulContent();
        var send = fixture.Send(fixture.Origin + "secrets/selected-secret?api-version=2025-07-01",
            content, RequestMethod.Put);
        await Task.WhenAny(fixture.Backend.Entered.Task, send).WaitAsync(TimeSpan.FromSeconds(10));
        if (send.IsCompleted) await send;
        using var replay = RequestContent.Create(Encoding.UTF8.GetBytes("{}"));
        await Assert.That(async () => await fixture.Send(
            fixture.Origin + "secrets/selected-secret?api-version=2025-07-01", replay, RequestMethod.Put))
            .Throws<InvalidOperationException>();
        fixture.Backend.Terminate.TrySetResult();
        await send;
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Attempts.Count).IsEqualTo(1);
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(1);
    }

    [Test]
    public async Task SealDuringSnapshotDrainsActualWriterAndRejectsTheNotYetDispatchedSend()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        using var content = new StatefulContent { Block = true };
        var send = fixture.Send(fixture.Origin + "secrets/selected-secret?api-version=2025-07-01",
            content, RequestMethod.Put);
        await Task.WhenAny(content.Entered.Task, send).WaitAsync(TimeSpan.FromSeconds(10));
        if (send.IsCompleted) await send;
        var seal = fixture.Source.SealAsync(fixture.Window).AsTask();
        await Assert.That(seal.IsCompleted).IsFalse();
        await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0) >= 0).IsTrue();
        content.Terminate.TrySetResult();
        await Assert.That(async () => await send).Throws<InvalidOperationException>();
        await Assert.That((await seal).Attempts.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(0);
        await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        await Assert.That(content.Disposed).IsFalse();
    }

    [Test]
    [Arguments("path")]
    [Arguments("method")]
    public async Task BorrowedContentCannotChangeCoordinatesAfterBoundaryValidation(string mutation)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.MutateDuringSnapshot = mutation;
        using var content = new StatefulContent();
        await Assert.That(async () => await fixture.Send(
            fixture.Origin + "secrets/selected-secret?api-version=2025-07-01", content, RequestMethod.Put))
            .Throws<InvalidOperationException>();
        await Assert.That((await fixture.Source.SealAsync(fixture.Window)).Attempts.Count).IsEqualTo(0);
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(0);
        await Assert.That(content.Storage.Span.IndexOfAnyExcept((byte)0)).IsEqualTo(-1);
        await Assert.That(fixture.ContentRestored).IsTrue();
    }

    [Test]
    public async Task SendDrainIsNotSdkInvocationDrainAndSealRejectsLateChallengeContinuation()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Credential.Block = true;
        var invocation = fixture.Invoke();
        await Task.WhenAny(fixture.Credential.Entered.Task, invocation).WaitAsync(TimeSpan.FromSeconds(10));
        if (invocation.IsCompleted) await invocation;
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(invocation.IsCompleted).IsFalse();
        await Assert.That(capture.Attempts.Single().HttpStatus).IsEqualTo(401);
        await Assert.That(capture.Attempts.Single().TransportTerminated).IsTrue();
        fixture.Credential.Continue.TrySetResult();
        await Assert.That(async () => await invocation).Throws<InvalidOperationException>();
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(1);
        await Assert.That((await fixture.Source.SealAsync(fixture.Window)).Attempts.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments("lease")]
    [Arguments("nonce")]
    [Arguments("revision")]
    [Arguments("name")]
    [Arguments("version")]
    [Arguments("list-coordinate")]
    public async Task InvalidBindingCannotArmOrBorrowAnotherLease(string fault)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        var binding = fault switch
        {
            "lease" => fixture.Binding with { LeaseId = Guid.Empty },
            "nonce" => fixture.Binding with { Selector = fixture.Binding.Selector with { Nonce = Guid.Empty } },
            "revision" => fixture.Binding with { ApiRevision = "2024-01-01" },
            "name" => fixture.Binding with { SecretName = "../foreign" },
            "version" => fixture.Binding with { SecretVersion = Version },
            _ => fixture.Binding with { Operation = TriggerKind.List }
        };
        await Assert.That(() => fixture.Source.Arm(binding)).Throws<ArgumentException>();
        await Assert.That(() => fixture.Source.Arm(fixture.Binding with
        {
            Selector = fixture.Binding.Selector with { Nonce = Guid.NewGuid() }
        })).Throws<InvalidOperationException>();
        await Assert.That(fixture.Backend.Observed.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("foreign-challenge")]
    [Arguments("repeated-challenge")]
    public async Task ChallengeVerificationRemainsNativeAndCannotAuthorizeReplay(string fault)
    {
        using var fixture = new Fixture(TriggerKind.Set);
        fixture.Backend.ChallengeResource = fault == "foreign-challenge" ? "https://foreign.example" : "https://vault.azure.net";
        fixture.Backend.RepeatChallenge = fault == "repeated-challenge";
        await Assert.That(async () => await fixture.Invoke()).Throws<Exception>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        await Assert.That(capture.Attempts.Count).IsEqualTo(fault == "foreign-challenge" ? 1 : 2);
        await Assert.That(fixture.Backend.Applied).IsFalse();
        await Assert.That(fixture.Credential.Scopes.Count).IsEqualTo(fault == "foreign-challenge" ? 0 : 1);
    }

    [Test]
    public async Task CancellationBeforeDispatchAndBodyOverflowLeaveNoActualAttempt()
    {
        using var fixture = new Fixture(TriggerKind.Set, maximumBytes: 1024);
        using var content = RequestContent.Create(new byte[1025]);
        await Assert.That(async () => await fixture.Send(
            fixture.Origin + "secrets/selected-secret?api-version=2025-07-01", content, RequestMethod.Put))
            .Throws<InvalidOperationException>();
        await Assert.That((await fixture.Source.SealAsync(fixture.Window)).Attempts.Count).IsEqualTo(0);
        using var other = new Fixture(TriggerKind.Set);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(async () => await other.Invoke(cancellation.Token)).Throws<OperationCanceledException>();
        await Assert.That((await other.Source.SealAsync(other.Window)).Attempts.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CapturesBindingsAndWindowsHaveNoDefaultPlaintextRepresentation()
    {
        using var fixture = new Fixture(TriggerKind.Set);
        await Assert.That(async () => await fixture.Invoke()).Throws<RequestFailedException>();
        var capture = await fixture.Source.SealAsync(fixture.Window);
        foreach (object value in new object[] { fixture.Source, fixture.Window, fixture.Transport, fixture.Binding,
            capture, capture.Attempts[0], capture.Attempts[1] })
        {
            await Assert.That(JsonSerializer.Serialize(value)).IsEqualTo("{}");
            await Assert.That(value.ToString()!.Contains(fixture.Origin.Host, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(Material, StringComparison.Ordinal)).IsFalse();
            await Assert.That(value.ToString()!.Contains(fixture.Binding.Selector.Nonce.ToString(), StringComparison.Ordinal)).IsFalse();
        }
        await Assert.That(fixture.Backend.Disposed).IsFalse();
    }

    private static string ExpectedPath(TriggerKind kind) => kind switch
    {
        TriggerKind.Get or TriggerKind.UpdateProperties => "/secrets/selected-secret/" + Version,
        TriggerKind.List => "/secrets/",
        TriggerKind.Recover => "/deletedsecrets/selected-secret/recover",
        TriggerKind.Purge => "/deletedsecrets/selected-secret",
        TriggerKind.Backup => "/secrets/selected-secret/backup",
        TriggerKind.Restore => "/secrets/restore",
        _ => "/secrets/selected-secret"
    };
    private static string ExpectedMethod(TriggerKind kind) => kind switch
    {
        TriggerKind.Get or TriggerKind.List => "GET",
        TriggerKind.Set => "PUT",
        TriggerKind.Delete or TriggerKind.Purge => "DELETE",
        TriggerKind.UpdateProperties => "PATCH",
        _ => "POST"
    };

    private sealed class Fixture : IDisposable
    {
        internal readonly Backend Backend = new();
        internal readonly Credential Credential = new();
        private readonly HttpClient http;
        internal readonly AuditNativeTriggerCapture Source;
        internal readonly AuditNativeTriggerCapture.Binding Binding;
        internal readonly AuditNativeTriggerCapture.Window Window;
        internal readonly HttpPipelineTransport Transport;
        internal readonly Uri Origin;
        internal bool ContentRestored;
        internal string? MutateDuringSnapshot;
        internal string? LastPathAndQuery;
        internal Fixture(TriggerKind kind, int maximumBytes = 65536)
        {
            var vault = new VaultScope(new(new(Guid.NewGuid()), "capture-group"), "a" + Guid.NewGuid().ToString("N")[..15]);
            Origin = new("https://" + vault.VaultName + ".vault.azure.net/");
            Backend.Origin = Origin;
            Binding = new(new(Guid.NewGuid(), "scope", "operation", "variant", "case"), Guid.NewGuid(),
                vault, kind, kind == TriggerKind.List ? null : "selected-secret",
                kind is TriggerKind.Get or TriggerKind.UpdateProperties ? Version : null, "2025-07-01");
            http = new(Backend);
            Source = new(new HttpClientTransport(http), maximumBytes);
            Window = Source.Arm(Binding);
            Transport = new InspectingTransport(Source.CreateTransport(Window, Binding.Selector),
                uri => LastPathAndQuery = uri.PathAndQuery);
        }
        internal async Task Invoke(CancellationToken token = default)
        {
            var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
            {
                Transport = Transport,
                DisableChallengeResourceVerification = false
            };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var client = new SecretClient(Origin, Credential, options);
            switch (Binding.Operation)
            {
                case TriggerKind.Get: await client.GetSecretAsync("selected-secret", Version, token); break;
                case TriggerKind.List:
                    await foreach (var page in client.GetPropertiesOfSecretsAsync(token).AsPages()) { _ = page; break; }
                    break;
                case TriggerKind.Set: await client.SetSecretAsync("selected-secret", Material, token); break;
                case TriggerKind.Delete: await client.StartDeleteSecretAsync("selected-secret", token); break;
                case TriggerKind.Recover: await client.StartRecoverDeletedSecretAsync("selected-secret", token); break;
                case TriggerKind.Backup: await client.BackupSecretAsync("selected-secret", token); break;
                case TriggerKind.Restore: await client.RestoreSecretBackupAsync(new byte[] { 1, 2, 3 }, token); break;
                case TriggerKind.Purge: await client.PurgeDeletedSecretAsync("selected-secret", token); break;
                case TriggerKind.UpdateProperties:
                    await client.UpdateSecretPropertiesAsync(new SecretProperties(
                        new Uri(Origin, "secrets/selected-secret/" + Version))
                    { Enabled = false }, token);
                    break;
            }
        }
        internal async Task Send(string uri, RequestContent content, RequestMethod method, CancellationToken token = default)
        {
            using var request = Transport.CreateRequest();
            request.Uri.Reset(new Uri(uri));
            request.Method = method;
            request.Headers.SetValue("Authorization", "Bearer borrowed-trigger-token");
            request.Content = content;
            if (content is StatefulContent stateful && MutateDuringSnapshot is { } mutation)
                stateful.AfterWrite = () =>
                {
                    if (mutation == "method") request.Method = RequestMethod.Delete;
                    else request.Uri.Reset(new Uri(Origin, "secrets/foreign?api-version=2025-07-01"));
                };
            using var message = new HttpMessage(request, new ResponseClassifier());
            var options = new SecretClientOptions { Transport = Transport };
            options.Retry.MaxRetries = 0;
            options.Diagnostics.IsLoggingEnabled = false;
            options.Diagnostics.IsLoggingContentEnabled = false;
            options.Diagnostics.IsDistributedTracingEnabled = false;
            var pipeline = HttpPipelineBuilder.Build(options);
            try { await pipeline.SendAsync(message, token); }
            finally
            {
                ContentRestored = ReferenceEquals(content, request.Content);
                // The test owns content separately, like a host retaining a request.
                request.Content = null;
            }
        }
        public void Dispose() => http.Dispose();
    }
    private sealed class InspectingTransport(HttpPipelineTransport inner, Action<Uri> inspect) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw new InvalidOperationException("test-sync");
        public override ValueTask ProcessAsync(HttpMessage message)
        {
            inspect(message.Request.Uri.ToUri());
            return inner.ProcessAsync(message);
        }
    }

    private sealed class StatefulContent : RequestContent
    {
        internal int Writes;
        internal Memory<byte> Storage { get; private set; }
        internal bool Disposed;
        internal bool Block;
        internal Action? AfterWrite;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private byte[] Next(Stream stream)
        {
            if (stream is MemoryStream buffer && buffer.TryGetBuffer(out var bytes)) Storage = bytes.AsMemory();
            return Encoding.UTF8.GetBytes(++Writes == 1 ? """{"value":"first"}""" : """{"value":"foreign"}""");
        }
        public override void WriteTo(Stream stream, CancellationToken cancellationToken) => stream.Write(Next(stream));
        public override async Task WriteToAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteAsync(Next(stream), cancellationToken);
            AfterWrite?.Invoke();
            Entered.TrySetResult();
            if (Block) await Terminate.Task;
        }
        public override bool TryComputeLength(out long length) { length = 0; return false; }
        public override void Dispose() => Disposed = true;
    }

    private sealed class Credential : TokenCredential
    {
        internal readonly List<string> Scopes = [];
        internal bool Block;
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Continue = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            Scopes.AddRange(context.Scopes);
            return new("borrowed-trigger-token", DateTimeOffset.MaxValue);
        }
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken token)
        {
            Entered.TrySetResult();
            if (Block) await Continue.Task.WaitAsync(token);
            return GetToken(context, token);
        }
    }

    private sealed record WireObservation(string Path, string Query, string Method, Guid Correlation, string? Authorization, byte[] Body);
    private sealed class Backend : HttpMessageHandler
    {
        internal Uri Origin = null!;
        internal readonly List<WireObservation> Observed = [];
        internal readonly TaskCompletionSource Entered = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource Terminate = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal bool Succeed, LoseResponse, Block, RepeatChallenge, Applied, Disposed;
        internal TaskCompletionSource? BeforeRead, AllowRead;
        internal string? Value;
        internal string ChallengeResource = "https://vault.azure.net";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            BeforeRead?.TrySetResult();
            if (AllowRead is not null) await AllowRead.Task.ConfigureAwait(false);
            byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
            var uri = request.RequestUri!;
            bool authorized = request.Headers.Authorization is not null;
            Observed.Add(new(uri.AbsolutePath, uri.Query, request.Method.Method,
                Guid.Parse(request.Headers.GetValues("x-ms-client-request-id").Single()),
                request.Headers.Authorization?.ToString(), body));
            if (!authorized || RepeatChallenge)
            {
                var challenge = new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("{}") };
                challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                    $"Bearer authorization=\"https://login.microsoftonline.com/test-tenant\", resource=\"{ChallengeResource}\"");
                challenge.Headers.Add("x-ms-request-id", authorized ? "native-final" : "native-challenge");
                return challenge;
            }
            if (body.Length > 0)
            {
                using var json = JsonDocument.Parse(body);
                if (json.RootElement.TryGetProperty("value", out var value)) Value = value.GetString();
            }
            Applied = Succeed || LoseResponse;
            Entered.TrySetResult();
            if (Block) await Terminate.Task;
            token.ThrowIfCancellationRequested();
            if (LoseResponse) throw new HttpRequestException("private-provider-loss");
            var response = new HttpResponseMessage(Succeed ? HttpStatusCode.OK : HttpStatusCode.Forbidden)
            {
                Content = new StringContent(Succeed
                    ? JsonSerializer.Serialize(new
                    {
                        id = new Uri(Origin, "secrets/selected-secret/" + Version).AbsoluteUri,
                        value = Value,
                        attributes = new { enabled = true }
                    })
                    : """{"error":{"code":"Forbidden","message":"private-provider-error"}}""")
            };
            response.Headers.Add("x-ms-request-id", "native-final");
            return response;
        }
        protected override void Dispose(bool disposing) { Disposed = true; base.Dispose(disposing); }
    }
}
