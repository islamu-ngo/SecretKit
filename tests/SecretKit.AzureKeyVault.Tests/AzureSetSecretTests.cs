using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Tracing;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Tests;

public sealed class AzureSetSecretTests
{
    [Test]
    public async Task CommittedVersionWithLostResponseRemainsUncertainWithoutReplay()
    {
        var backend = new VersionBackend("lost-write") { DropResponse = true };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task AuthenticatedChallengeAfterCommitCannotReplayMutation()
    {
        var backend = new VersionBackend("challenge-write") { ChallengeAfterCommit = true };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        // Warm the SDK's verified challenge before the body-bearing mutation.
        // A later 401 must not be treated as permission to replay that mutation.
        await client.ReadAsync(target);
        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
    }

    [Test]
    public async Task CancellationAfterCommitRetainsPossibleDispatchEvidence()
    {
        var backend = new VersionBackend("cancel-write") { HoldResponse = true };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        using var cancellation = new CancellationTokenSource();

        var pending = client.SetSecretAsync(new AzureSetSecretRequest(target, material),
            receipt, cancellation.Token).AsTask();
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task SuccessReturnsValidatedNewVersionAndSafeIndependentModels()
    {
        var backend = new VersionBackend("success-write");
        var credential = new TestCredential();
        var client = new AzureKeyVaultClient(backend.Vault, credential, backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        var request = new AzureSetSecretRequest(target, material);

        var outcome = await client.SetSecretAsync(request, receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(outcome.Value.Reference.BelongsTo(client.Authority)).IsTrue();
        var address = (AzureSecretAddress)outcome.Value.Reference.Address;
        await Assert.That(address.Name).IsEqualTo("name-canary");
        await Assert.That(address.Version).IsEqualTo(backend.Versions.Single());
        await Assert.That(material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(credential.Scopes.Count > 0).IsTrue();
        await Assert.That(backend.ApiVersions.All(version => version == "?api-version=2025-07-01")).IsTrue();
        foreach (object model in new object[] { request, outcome.Value, outcome.Value.Reference, receipt })
        {
            await Assert.That(JsonSerializer.Serialize(model).Contains("canary")).IsFalse();
            await Assert.That(JsonSerializer.Serialize(model).Contains(address.Version!)).IsFalse();
            await Assert.That(model.ToString()!.Contains("canary")).IsFalse();
            await Assert.That(model.ToString()!.Contains(address.Version!)).IsFalse();
        }

        var reused = await client.SetSecretAsync(request, receipt);
        await Assert.That(reused.Status).IsEqualTo(SecretStatus.Invalid);
        using var read = (await client.ReadAsync(outcome.Value.Reference)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task PreCancelledReceiptSendsNothingAndCannotBeReused()
    {
        var backend = new VersionBackend("precancel-write");
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var request = new AzureSetSecretRequest(target, material);

        await Assert.That(async () => await client.SetSecretAsync(request, receipt, cancellation.Token))
            .Throws<OperationCanceledException>();

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Wire.Requests.Count).IsEqualTo(0);
        await Assert.That((await client.SetSecretAsync(request, receipt)).Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(backend.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments(AzureSetSecretPrecondition.CreateOnly, false)]
    [Arguments(AzureSetSecretPrecondition.MatchVersion, false)]
    [Arguments(AzureSetSecretPrecondition.None, true)]
    public async Task MandatoryUnsupportedConditionsSendNothing(AzureSetSecretPrecondition condition, bool versioned)
    {
        var backend = new VersionBackend("condition-write");
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client, versioned ? new string('a', 32) : null);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material, condition), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task IdentityReceiptAndMaterialValidationPrecedeNetwork()
    {
        var backend = new VersionBackend("invalid-write");
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var foreign = new SecretReference(new SecretAuthority(), new AzureSecretAddress("name-canary"));
        using var material = SecretMaterial.FromText("material-canary");
        var foreignOutcome = await client.SetSecretAsync(new AzureSetSecretRequest(foreign, material),
            new MutationReceipt(foreign));
        var wrongReceipt = await client.SetSecretAsync(new AzureSetSecretRequest(target, material),
            new MutationReceipt(Target(client)));
        using var oversized = SecretMaterial.FromText(new string('x', 25 * 1024 + 1));
        var tooLarge = await client.SetSecretAsync(new AzureSetSecretRequest(target, oversized),
            new MutationReceipt(target));
        using var disposed = material.Copy();
        disposed.Dispose();
        var unavailableMaterial = await client.SetSecretAsync(new AzureSetSecretRequest(target, disposed),
            new MutationReceipt(target));

        foreach (var outcome in new[] { foreignOutcome, wrongReceipt, tooLarge, unavailableMaterial })
        {
            await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
            await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
        }

        await Assert.That(backend.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("https://other.vault.azure.net/secrets/name-canary/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [Arguments("https://malformed-write.vault.azure.net/secrets/other/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [Arguments("https://malformed-write.vault.azure.net/secrets/name-canary/not-a-version")]
    [Arguments("https://malformed-write.vault.azure.net/secrets/name-canary/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?query=canary")]
    public async Task MalformedSuccessNeverClaimsApplied(string returnedId)
    {
        var backend = new VersionBackend("malformed-write") { ReturnedId = returnedId };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
    }

    [Test]
    public async Task ConcurrentUseOfReceiptCannotCreateSecondVersion()
    {
        var backend = new VersionBackend("concurrent-write") { HoldResponse = true };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        var request = new AzureSetSecretRequest(target, material);
        using var cancellation = new CancellationTokenSource();

        var pending = client.SetSecretAsync(request, receipt, cancellation.Token).AsTask();
        await backend.Committed.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var duplicate = await client.SetSecretAsync(request, receipt);
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();

        await Assert.That(duplicate.Status).IsEqualTo(SecretStatus.Invalid);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CredentialFailureNeverMarksMutationDispatched()
    {
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Challenge()));
        var client = new AzureKeyVaultClient(new Uri("https://credential-write.vault.azure.net"),
            new TestCredential { Fail = true }, wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.IsSuccess).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(wire.Authorized.Any(authorized => authorized)).IsFalse();
        await Assert.That(JsonSerializer.Serialize(outcome).Contains("canary")).IsFalse();
    }

    [Test]
    public async Task ForgedChallengeCannotAcquireCredentialOrDispatchMaterial()
    {
        var credential = new TestCredential();
        var wire = new WireTransport((_, _) => Task.FromResult(WireTransport.Challenge("https://evil.example")));
        var client = new AzureKeyVaultClient(new Uri("https://forged-write.vault.azure.net"), credential, wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.IsSuccess).IsFalse();
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(credential.Scopes.Count).IsEqualTo(0);
        await Assert.That(wire.Authorized.Any(authorized => authorized)).IsFalse();
    }

    [Test]
    [Arguments(429)]
    [Arguments(503)]
    public async Task StatusAfterCommitCannotReplayEvenWithRetryAfter(int status)
    {
        var backend = new VersionBackend($"status-{status}-write") { StatusAfterCommit = status };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task CancellationDuringAuthenticationLeavesReceiptNotDispatched()
    {
        var backend = new VersionBackend("authcancel-write");
        var credential = new BlockedCredential();
        var client = new AzureKeyVaultClient(backend.Vault, credential, backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");
        using var cancellation = new CancellationTokenSource();

        var pending = client.SetSecretAsync(new AzureSetSecretRequest(target, material),
            receipt, cancellation.Token).AsTask();
        await credential.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        cancellation.Cancel();
        await Assert.That(async () => await pending.WaitAsync(TimeSpan.FromSeconds(10)))
            .Throws<OperationCanceledException>();

        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Versions.Count).IsEqualTo(0);
    }

    [Test]
    [Arguments("{}")]
    [Arguments("{not-json")]
    public async Task UnparseableCommittedResponseNeverClaimsApplied(string responseBody)
    {
        var backend = new VersionBackend("parse-write") { ResponseBody = responseBody };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    public async Task WriteDiagnosticsExcludeMaterialAndCoordinates()
    {
        using var events = new AzureEvents();
        var activities = new ConcurrentBag<string>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name.StartsWith("Azure.", StringComparison.Ordinal),
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllData,
            ActivityStarted = activity => activities.Add(activity.OperationName)
        };
        ActivitySource.AddActivityListener(listener);
        var backend = new VersionBackend("diagnostics-write");
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material),
            new MutationReceipt(target));

        await Assert.That(outcome.IsSuccess).IsTrue();
        await Assert.That(events.Payloads.Any(text => text.Contains("canary") || text.Contains(".vault"))).IsFalse();
        await Assert.That(activities.Count).IsEqualTo(0);
    }

    [Test]
    public async Task OversizedCommittedResponseRemainsUnknownAndBounded()
    {
        var backend = new VersionBackend("budget-write")
        {
            ResponseBody = JsonSerializer.Serialize(new { value = new string('x', 4096) })
        };
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire,
            maximumResponseBytes: 1024);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        using var read = (await client.ReadAsync(target)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(backend.Versions.Count).IsEqualTo(1);
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task MaterialEncodingAndByteBudgetAreValidatedBeforeSending(bool oversized)
    {
        var backend = new VersionBackend("encoding-write");
        var client = new AzureKeyVaultClient(backend.Vault, new TestCredential(), backend.Wire);
        var target = Target(client);
        var receipt = new MutationReceipt(target);
        using var material = SecretMaterial.FromText(oversized ? new string('\u0800', 10000) : "\ud800");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material), receipt);

        await Assert.That(outcome.Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(backend.Wire.Requests.Count).IsEqualTo(0);
    }

    [Test]
    public async Task CredentialAndHttpTransportRemainHostOwnedAfterWrite()
    {
        var backend = new VersionBackend("ownership-write");
        using var credential = new OwnedCredential();
        using var handler = new OwnedHandler(backend.RespondAsync);
        using var http = new HttpClient(handler);
        var transport = new HttpClientTransport(http);
        var client = new AzureKeyVaultClient(backend.Vault, credential, transport);
        var target = Target(client);
        using var material = SecretMaterial.FromText("material-canary");

        var outcome = await client.SetSecretAsync(new AzureSetSecretRequest(target, material),
            new MutationReceipt(target));

        await Assert.That(outcome.IsSuccess).IsTrue();
        await Assert.That(credential.IsDisposed).IsFalse();
        await Assert.That(handler.IsDisposed).IsFalse();
        using var read = (await client.ReadAsync(outcome.Value.Reference)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
    }

    private static SecretReference Target(AzureKeyVaultClient client, string? version = null) =>
        new(client.Authority, new AzureSecretAddress("name-canary", version));

    private sealed class VersionBackend
    {
        public VersionBackend(string vault)
        {
            Vault = new Uri($"https://{vault}.vault.azure.net");
            Wire = new WireTransport(RespondAsync);
        }

        public Uri Vault { get; }
        public WireTransport Wire { get; }
        public List<string> Versions { get; } = [];
        public bool DropResponse { get; init; }
        public bool ChallengeAfterCommit { get; init; }
        public bool HoldResponse { get; init; }
        public string? ReturnedId { get; init; }
        public int? StatusAfterCommit { get; init; }
        public string? ResponseBody { get; init; }
        public List<string> ApiVersions { get; } = [];
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private string? _value;

        public async Task<HttpResponseMessage> RespondAsync(HttpRequestMessage request, CancellationToken token)
        {
            ApiVersions.Add(request.RequestUri!.Query);
            if (request.Headers.Authorization is null)
            {
                if (request.Method == HttpMethod.Put && request.Content is not null)
                {
                    using var body = JsonDocument.Parse(await request.Content.ReadAsStringAsync(token));
                    if (body.RootElement.TryGetProperty("value", out _))
                    {
                        throw new InvalidOperationException("Unauthenticated mutation body reached fixture.");
                    }
                }

                return WireTransport.Challenge();
            }

            if (request.Method == HttpMethod.Put)
            {
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(token));
                _value = body.RootElement.GetProperty("value").GetString();
                Versions.Add(Versions.Count.ToString("x32"));
                Committed.TrySetResult();
                if (HoldResponse)
                {
                    var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    using var registration = token.Register(() => cancelled.TrySetCanceled(token));
                    await cancelled.Task;
                }

                if (DropResponse)
                {
                    throw new HttpRequestException("Response lost after commit.");
                }

                if (ChallengeAfterCommit && Versions.Count == 1)
                {
                    return WireTransport.Challenge();
                }

                if (StatusAfterCommit is int status)
                {
                    var response = WireTransport.Json(status, """{"error":{"message":"material-canary"}}""");
                    response.Headers.TryAddWithoutValidation("Retry-After", "0");
                    return response;
                }

                if (ResponseBody is not null)
                {
                    return WireTransport.Json(200, ResponseBody);
                }
            }

            return WireTransport.Json(200, JsonSerializer.Serialize(new
            {
                value = _value,
                id = request.Method == HttpMethod.Put && ReturnedId is not null ? ReturnedId :
                    $"{Vault.AbsoluteUri.TrimEnd('/')}/secrets/name-canary/{Versions.LastOrDefault()}",
                attributes = new { enabled = true }
            }));
        }
    }

    private sealed class BlockedCredential : TokenCredential
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Async only.");

        public override async ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            var cancelled = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            using var registration = cancellationToken.Register(() => cancelled.TrySetCanceled(cancellationToken));
            Entered.TrySetResult();
            await cancelled.Task;
            throw new InvalidOperationException("Unreachable.");
        }
    }

    private sealed class OwnedCredential : TokenCredential, IDisposable
    {
        public bool IsDisposed { get; private set; }

        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("Async only.");

        public override ValueTask<AccessToken> GetTokenAsync(
            TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            ObjectDisposedException.ThrowIf(IsDisposed, this);
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(new AccessToken("token-canary", DateTimeOffset.MaxValue));
        }

        public void Dispose() => IsDisposed = true;
    }

    private sealed class OwnedHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public bool IsDisposed { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => respond(request, cancellationToken);

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class AzureEvents : EventListener
    {
        public ConcurrentBag<string> Payloads { get; } = [];

        protected override void OnEventSourceCreated(EventSource eventSource)
        {
            if (eventSource.Name.StartsWith("Azure-", StringComparison.Ordinal))
            {
                EnableEvents(eventSource, EventLevel.Verbose);
            }
        }

        protected override void OnEventWritten(EventWrittenEventArgs eventData)
        {
            if (eventData.Payload is not null)
            {
                Payloads.Add(string.Join(" ", eventData.Payload));
            }
        }
    }
}
