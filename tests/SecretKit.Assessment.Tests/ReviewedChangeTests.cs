using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;

namespace SecretKit.Assessment.Tests;

public sealed class ReviewedChangeTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    [Test]
    public async Task MixedNativeWritesKeepAppliedPendingConflictAndUnknownEvidence()
    {
        await using var fixture = new NativeFixture();
        fixture.InfisicalState["update-canary"] = new("old", 1);
        fixture.InfisicalState["conflict-canary"] = new("preserved", 1);
        using var material = SecretMaterial.FromText("material-canary\n\n");
        ReviewedChange[] selected =
        [
            ReviewedChange.InfisicalCreate(ReviewApproval.Approved, fixture.Infisical,
                fixture.InfisicalTarget("create-canary"), material),
            ReviewedChange.InfisicalUpdateValue(ReviewApproval.Approved, fixture.Infisical,
                fixture.InfisicalTarget("update-canary"), material),
            ReviewedChange.AzureSet(ReviewApproval.Approved, fixture.Azure,
                fixture.AzureTarget("azure-canary"), material),
            ReviewedChange.InfisicalUpdateValue(ReviewApproval.Approved, fixture.Infisical,
                fixture.InfisicalTarget("pending-canary"), material),
            ReviewedChange.InfisicalCreate(ReviewApproval.Approved, fixture.Infisical,
                fixture.InfisicalTarget("conflict-canary"), material),
            ReviewedChange.InfisicalCreate(ReviewApproval.Approved, fixture.Infisical,
                fixture.InfisicalTarget("unknown-canary"), material)
        ];
        var scenario = new ReviewedChangesScenario(selected, 3);
        MutationReceipt[] held = scenario.Results.Select(row => row.Receipt).ToArray();
        await Assert.That(held.All(receipt => receipt.Evidence == DispatchEvidence.NotDispatched)).IsTrue();

        IReadOnlyList<ReviewedChangeResult> results = await scenario.ExecuteAsync().WaitAsync(Deadline);

        DispatchEvidence[] evidence =
        [
            DispatchEvidence.Applied, DispatchEvidence.Applied, DispatchEvidence.Applied,
            DispatchEvidence.Pending, DispatchEvidence.Conflict, DispatchEvidence.PossiblyDispatched
        ];
        SecretStatus[] status =
        [
            SecretStatus.Success, SecretStatus.Success, SecretStatus.Success,
            SecretStatus.Pending, SecretStatus.Conflict, SecretStatus.Unknown
        ];
        for (int index = 0; index < results.Count; index++)
        {
            await Assert.That(results[index].Index).IsEqualTo(index);
            await Assert.That(ReferenceEquals(results[index].Receipt, held[index])).IsTrue();
            await Assert.That(results[index].Evidence).IsEqualTo(evidence[index]);
            await Assert.That(results[index].Status).IsEqualTo(status[index]);
            await Assert.That(results[index].Progress).IsEqualTo(ReviewedChangeProgress.Completed);
        }

        using SecretRead created = (await fixture.Infisical.ReadAsync(fixture.InfisicalTarget("create-canary"))).Value;
        using SecretRead updated = (await fixture.Infisical.ReadAsync(fixture.InfisicalTarget("update-canary"))).Value;
        using SecretRead azure = (await fixture.Azure.ReadAsync(fixture.AzureTarget("azure-canary"))).Value;
        using SecretRead conflict = (await fixture.Infisical.ReadAsync(fixture.InfisicalTarget("conflict-canary"))).Value;
        using SecretRead uncertain = (await fixture.Infisical.ReadAsync(fixture.InfisicalTarget("unknown-canary"))).Value;
        await Assert.That(created.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(updated.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(updated.Observation.Version).IsEqualTo("2");
        await Assert.That(azure.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(conflict.Material.Reveal()).IsEqualTo("preserved");
        await Assert.That(uncertain.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(uncertain.Observation.Version).IsEqualTo("1");
        await Assert.That((await fixture.Infisical.ReadAsync(fixture.InfisicalTarget("pending-canary"))).Status)
            .IsEqualTo(SecretStatus.Absent);
        foreach (object model in selected.Cast<object>().Concat(results).Append(scenario))
        {
            await Assert.That(JsonSerializer.Serialize(model).Contains("canary", StringComparison.Ordinal)).IsFalse();
            await Assert.That(model.ToString()!.Contains("canary", StringComparison.Ordinal)).IsFalse();
        }
    }

    [Test]
    public async Task WorkerQueueBackpressureKeepsCorrelationWhenLaterItemsFinishFirst()
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        string[] names = ["first", "second", "third", "fourth"];
        Gate[] gates = names.Select(fixture.HoldAzure).ToArray();
        var scenario = new ReviewedChangesScenario(names.Select(name =>
            ReviewedChange.AzureSet(ReviewApproval.Approved, fixture.Azure, fixture.AzureTarget(name), material)), 2);

        Task<IReadOnlyList<ReviewedChangeResult>> execution = scenario.ExecuteAsync();
        await Task.WhenAll(gates[0].Entered.Task, gates[1].Entered.Task).WaitAsync(Deadline);
        await Assert.That(scenario.Results[2].Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(scenario.Results[3].Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(fixture.AzureState.ContainsKey("third")).IsFalse();
        await Assert.That(fixture.AzureState.ContainsKey("fourth")).IsFalse();

        gates[1].Release.SetResult();
        await gates[2].Entered.Task.WaitAsync(Deadline);
        await Assert.That(scenario.Results[0].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(scenario.Results[1].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(scenario.Results[3].Evidence).IsEqualTo(DispatchEvidence.NotDispatched);

        gates[2].Release.SetResult();
        await gates[3].Entered.Task.WaitAsync(Deadline);
        await Assert.That(scenario.Results[2].Evidence).IsEqualTo(DispatchEvidence.Applied);
        gates[3].Release.SetResult();
        gates[0].Release.SetResult();
        IReadOnlyList<ReviewedChangeResult> results = await execution.WaitAsync(Deadline);
        for (int index = 0; index < names.Length; index++)
        {
            await Assert.That(results[index].Index).IsEqualTo(index);
            await Assert.That(results[index].Evidence).IsEqualTo(DispatchEvidence.Applied);
            using SecretRead read = (await fixture.Azure.ReadAsync(fixture.AzureTarget(names[index]))).Value;
            await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
            await Assert.That(read.Observation.Version).IsEqualTo(1.ToString("x32"));
        }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task PreCanceledBatchPreservesCallerHeldNotDispatchedReceipts(bool azure)
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        var scenario = new ReviewedChangesScenario(
            [fixture.Selection(azure, "first", material), fixture.Selection(azure, "second", material)], 2);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.That(async () => await scenario.ExecuteAsync(cancellation.Token).WaitAsync(Deadline))
            .Throws<OperationCanceledException>();

        foreach (ReviewedChangeResult row in scenario.Results)
        {
            await Assert.That(row.Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
            await Assert.That(row.Progress).IsEqualTo(ReviewedChangeProgress.Canceled);
            await Assert.That(row.Status).IsNull();
        }

        await Assert.That(fixture.AzureState.IsEmpty).IsTrue();
        await Assert.That(fixture.InfisicalState.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task CancellationKeepsKnownCompletedAndUncertainSentEvidenceAndQueuedWorkUnsent(bool azure)
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        Gate gate = azure ? fixture.HoldAzure("held") : fixture.HoldInfisical("held");
        var scenario = new ReviewedChangesScenario(
        [
            fixture.Selection(azure, "completed", material),
            fixture.Selection(azure, "held", material),
            fixture.Selection(azure, "queued", material)
        ], 1);
        MutationReceipt[] receipts = scenario.Results.Select(row => row.Receipt).ToArray();
        using var cancellation = new CancellationTokenSource();

        Task<IReadOnlyList<ReviewedChangeResult>> execution = scenario.ExecuteAsync(cancellation.Token);
        await gate.Entered.Task.WaitAsync(Deadline);
        cancellation.Cancel();
        await Assert.That(async () => await execution.WaitAsync(Deadline)).Throws<OperationCanceledException>();
        gate.Release.TrySetResult();

        await Assert.That(receipts[0].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(scenario.Results[0].Progress).IsEqualTo(ReviewedChangeProgress.Completed);
        await Assert.That(receipts[1].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(scenario.Results[1].Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(scenario.Results[1].Progress).IsEqualTo(ReviewedChangeProgress.Canceled);
        await Assert.That(receipts[2].Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(scenario.Results[2].Progress).IsEqualTo(ReviewedChangeProgress.Canceled);
        await Assert.That(scenario.Results[2].Status).IsNull();
        ISecretReader reader = azure ? fixture.Azure : fixture.Infisical;
        SecretReference held = azure ? fixture.AzureTarget("held") : fixture.InfisicalTarget("held");
        using SecretRead read = (await reader.ReadAsync(held)).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(read.Observation.Version).IsEqualTo(azure ? 1.ToString("x32") : "1");
        SecretReference queued = azure ? fixture.AzureTarget("queued") : fixture.InfisicalTarget("queued");
        await Assert.That((await reader.ReadAsync(queued)).Status).IsEqualTo(SecretStatus.Absent);
        // The consumer batch is single-run; this does not assert provider parity for unsent receipts.
        await Assert.That(async () => await scenario.ExecuteAsync()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task QueuedPayloadCopiesSurviveCallerDisposalAndNeverExposeSharedOwnership()
    {
        await using var fixture = new NativeFixture();
        using var original = SecretMaterial.FromText("material-canary");
        using SecretMaterial independent = original.Copy();
        Gate gate = fixture.HoldAzure("first");
        var first = fixture.Selection(true, "first", original);
        var second = fixture.Selection(true, "second", original);
        var scenario = new ReviewedChangesScenario([first, second], 1);

        Task<IReadOnlyList<ReviewedChangeResult>> execution = scenario.ExecuteAsync();
        await gate.Entered.Task.WaitAsync(Deadline);
        original.Dispose();
        gate.Release.SetResult();
        await execution.WaitAsync(Deadline);

        using SecretRead read = (await fixture.Azure.ReadAsync(fixture.AzureTarget("second"))).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo(independent.Reveal());
        await Assert.That(scenario.Results.All(row => row.Evidence == DispatchEvidence.Applied)).IsTrue();
        await Assert.That(typeof(ReviewedChange).GetProperties()
            .Any(property => typeof(IDisposable).IsAssignableFrom(property.PropertyType))).IsFalse();
        await Assert.That(JsonSerializer.Serialize(first).Contains("canary", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task UnapprovedInvalidAndUnavailableMaterialItemsDoNotBlockAnApprovedNativeWrite()
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        using SecretMaterial disposed = material.Copy();
        disposed.Dispose();
        var foreign = new SecretReference(new SecretAuthority(), new AzureSecretAddress("foreign"));
        var scenario = new ReviewedChangesScenario(
        [
            ReviewedChange.AzureSet(ReviewApproval.NotApproved, fixture.Azure, fixture.AzureTarget("denied"), material),
            ReviewedChange.AzureSet(ReviewApproval.Approved, fixture.Azure, foreign, material),
            ReviewedChange.AzureSet(ReviewApproval.Approved, fixture.Azure, fixture.AzureTarget("disposed"), disposed),
            ReviewedChange.AzureSet(ReviewApproval.Approved, fixture.Azure,
                new SecretReference(fixture.Azure.Authority, new AzureSecretAddress("pinned", new string('a', 32))), material),
            fixture.Selection(true, "allowed", material)
        ], 1);

        IReadOnlyList<ReviewedChangeResult> results = await scenario.ExecuteAsync().WaitAsync(Deadline);

        await Assert.That(results[0].Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(results[1].Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(results[2].Status).IsEqualTo(SecretStatus.Invalid);
        await Assert.That(results[3].Status).IsEqualTo(SecretStatus.Unsupported);
        await Assert.That(results.Take(4).All(row => row.Evidence == DispatchEvidence.NotDispatched)).IsTrue();
        await Assert.That(results[4].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(fixture.AzureState.Keys.Single()).IsEqualTo("allowed");
        await Assert.That(material.Reveal()).IsEqualTo("material-canary");
    }

    [Test]
    public async Task NativeAzureLostResponseIsUnknownAndDoesNotReplayOrRollbackOtherRows()
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        var scenario = new ReviewedChangesScenario(
            [fixture.Selection(true, "lost", material), fixture.Selection(true, "known", material)], 1);

        IReadOnlyList<ReviewedChangeResult> rows = await scenario.ExecuteAsync().WaitAsync(Deadline);

        await Assert.That(rows[0].Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(rows[0].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(rows[1].Evidence).IsEqualTo(DispatchEvidence.Applied);
        using SecretRead lost = (await fixture.Azure.ReadAsync(fixture.AzureTarget("lost"))).Value;
        using SecretRead known = (await fixture.Azure.ReadAsync(fixture.AzureTarget("known"))).Value;
        await Assert.That(lost.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(lost.Observation.Version).IsEqualTo(1.ToString("x32"));
        await Assert.That(known.Material.Reveal()).IsEqualTo("material-canary");
        await Assert.That(known.Observation.Version).IsEqualTo(1.ToString("x32"));
    }

    [Test]
    [Arguments(0)]
    [Arguments(17)]
    public async Task ConcurrencyBoundsAreValidatedBeforeExecution(int concurrency)
    {
        await Assert.That(() => new ReviewedChangesScenario([], concurrency)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task FiniteInputBoundRejectsOversizedInfiniteEmptyAndNullSelections()
    {
        await using var fixture = new NativeFixture();
        using var material = SecretMaterial.FromText("material-canary");
        ReviewedChange item = fixture.Selection(true, "selected", material);
        IEnumerable<ReviewedChange> Oversized()
        {
            for (int index = 0; index <= ReviewedChangesScenario.MaximumItems; index++)
            {
                yield return item;
            }

            throw new InvalidOperationException("Enumeration must stop at the input bound.");
        }

        await Assert.That(() => new ReviewedChangesScenario(Oversized(), 1)).Throws<ArgumentException>();
        await Assert.That(() => new ReviewedChangesScenario([], 1)).Throws<ArgumentException>();
        await Assert.That(() => new ReviewedChangesScenario([null!], 1)).Throws<ArgumentException>();
        await Assert.That(fixture.AzureState.IsEmpty).IsTrue();
    }

    private sealed class Gate
    {
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    private sealed record StoredSecret(string Value, int Version);

    /// <summary>Public Infisical loopback HTTP and official Azure SDK transport, never native-write mocks.</summary>
    private sealed class NativeFixture : IAsyncDisposable
    {
        private readonly HttpListener _listener = new();
        private readonly CancellationTokenSource _shutdown = new();
        private readonly ConcurrentBag<Task> _requests = [];
        private readonly ConcurrentDictionary<string, Gate> _infisicalGates = new();
        private readonly ConcurrentDictionary<string, Gate> _azureGates = new();
        private readonly HttpClient _azureHttp;
        private readonly Task _accept;
        public ConcurrentDictionary<string, StoredSecret> InfisicalState { get; } = new();
        public ConcurrentDictionary<string, StoredSecret> AzureState { get; } = new();
        public InfisicalClient Infisical { get; }
        public AzureKeyVaultClient Azure { get; }
        private Uri Vault { get; } = new($"https://r{Guid.NewGuid().ToString("N")[..16]}.vault.azure.net/");

        public NativeFixture()
        {
            // OS-selected loopback port; the native client explicitly opts into development HTTP.
            using var reservation = new TcpListener(IPAddress.Loopback, 0);
            reservation.Start();
            int port = ((IPEndPoint)reservation.LocalEndpoint).Port;
            reservation.Stop();
            var origin = new Uri($"http://127.0.0.1:{port}/");
            _listener.Prefixes.Add(origin.AbsoluteUri);
            _listener.Start();
            Infisical = new InfisicalClient(origin, new Tokens(),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            _azureHttp = new HttpClient(new AzureHandler(this));
            Azure = new AzureKeyVaultClient(Vault, new Credential(), new HttpClientTransport(_azureHttp));
            _accept = AcceptAsync();
        }

        public SecretReference InfisicalTarget(string name) =>
            new(Infisical.Authority, new InfisicalSecretAddress("project-canary", "env-canary", "/folder-canary", name));
        public SecretReference AzureTarget(string name) => new(Azure.Authority, new AzureSecretAddress(name));
        public ReviewedChange Selection(bool azure, string name, SecretMaterial material) => azure
            ? ReviewedChange.AzureSet(ReviewApproval.Approved, Azure, AzureTarget(name), material)
            : ReviewedChange.InfisicalCreate(ReviewApproval.Approved, Infisical, InfisicalTarget(name), material);
        public Gate HoldAzure(string name) => _azureGates.GetOrAdd(name, _ => new Gate());
        public Gate HoldInfisical(string name) => _infisicalGates.GetOrAdd(name, _ => new Gate());

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    HttpListenerContext context = await _listener.GetContextAsync().WaitAsync(_shutdown.Token);
                    _requests.Add(ServeAsync(context));
                }
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (HttpListenerException) when (_shutdown.IsCancellationRequested)
            {
            }
        }

        private async Task ServeAsync(HttpListenerContext context)
        {
            try
            {
                string key = Uri.UnescapeDataString(context.Request.Url!.AbsolutePath.Split('/').Last());
                using var body = new MemoryStream();
                await context.Request.InputStream.CopyToAsync(body, _shutdown.Token);
                using HttpResponseMessage response = await RespondAsync(false, key,
                    context.Request.HttpMethod, body.ToArray(), _shutdown.Token);
                context.Response.StatusCode = (int)response.StatusCode;
                context.Response.ContentType = "application/json";
                byte[] bytes = await response.Content!.ReadAsByteArrayAsync(_shutdown.Token);
                context.Response.ContentLength64 = bytes.Length;
                await context.Response.OutputStream.WriteAsync(bytes, _shutdown.Token);
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (HttpListenerException)
            {
                // A canceled native HTTP caller may close the socket while its fixture reply is held.
            }
            finally
            {
                context.Response.Close();
            }
        }

        private async Task<HttpResponseMessage> RespondAsync(bool azure, string key, string method,
            byte[] body, CancellationToken token)
        {
            ConcurrentDictionary<string, StoredSecret> state = azure ? AzureState : InfisicalState;
            if (method != "GET")
            {
                using JsonDocument document = JsonDocument.Parse(body);
                JsonElement payload = document.RootElement;
                if (!azure && (payload.GetProperty("projectId").GetString() != "project-canary" ||
                    payload.GetProperty("environment").GetString() != "env-canary" ||
                    payload.GetProperty("secretPath").GetString() != "/folder-canary" ||
                    payload.GetProperty("type").GetString() != "shared" ||
                    !payload.GetProperty("skipMultilineEncoding").GetBoolean()))
                {
                    return Json(400, new { });
                }

                if (!azure && key == "pending-canary")
                {
                    return Json(200, new { approval = new { id = Guid.NewGuid(), hasMerged = false } });
                }

                string value = payload.GetProperty(azure ? "value" : "secretValue").GetString()!;
                if (!azure && method == "POST")
                {
                    if (!state.TryAdd(key, new(value, 1)))
                    {
                        return Json(409, new { });
                    }
                }
                else if (!azure && !state.ContainsKey(key))
                {
                    return Json(404, new { });
                }
                else
                {
                    state.AddOrUpdate(key, new StoredSecret(value, 1), (_, previous) => new(value, previous.Version + 1));
                }

                if ((azure ? _azureGates : _infisicalGates).TryGetValue(key, out Gate? gate))
                {
                    gate.Entered.TrySetResult();
                    await gate.Release.Task.WaitAsync(token);
                }

                if (azure && key == "lost")
                {
                    throw new HttpRequestException("Fixture response lost after commit.");
                }

                if (!azure && key == "unknown-canary")
                {
                    return Json(200, new { });
                }
            }

            if (!state.TryGetValue(key, out StoredSecret? stored))
            {
                return Json(404, new { });
            }

            return azure
                ? Json(200, new
                {
                    value = stored.Value,
                    id = $"{Vault.AbsoluteUri}secrets/{key}/{stored.Version:x32}",
                    attributes = new { enabled = true }
                })
                : Json(200, new
                {
                    secret = new
                    {
                        secretKey = key,
                        secretValue = stored.Value,
                        secretValueHidden = false,
                        workspace = "project-canary",
                        environment = "env-canary",
                        version = stored.Version
                    }
                });
        }

        private static HttpResponseMessage Json<T>(int status, T body) => new((HttpStatusCode)status)
        {
            Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json")
        };

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            foreach (Gate gate in _azureGates.Values.Concat(_infisicalGates.Values))
            {
                gate.Release.TrySetResult();
            }

            await Infisical.DisposeAsync();
            _listener.Stop();
            await _accept.WaitAsync(Deadline);
            await Task.WhenAll(_requests).WaitAsync(Deadline);
            _listener.Close();
            _azureHttp.Dispose();
            _shutdown.Dispose();
        }

        private sealed class AzureHandler(NativeFixture fixture) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
            {
                if (request.Headers.Authorization is null)
                {
                    var challenge = Json(401, new { });
                    challenge.Headers.TryAddWithoutValidation("WWW-Authenticate",
                        "Bearer authorization=\"https://login.microsoftonline.com/test-tenant\", resource=\"https://vault.azure.net\"");
                    return challenge;
                }

                string key = request.RequestUri!.AbsolutePath.Split('/')[2];
                byte[] body = request.Content is null ? [] : await request.Content.ReadAsByteArrayAsync(token);
                return await fixture.RespondAsync(true, key, request.Method.Method, body, token);
            }
        }

        private sealed class Credential : TokenCredential
        {
            public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) =>
                throw new InvalidOperationException("Async only.");
            public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(new AccessToken("token-canary", DateTimeOffset.MaxValue));
            }
        }

        private sealed class Tokens : IInfisicalTokenSource
        {
            public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
            {
                cancellationToken.ThrowIfCancellationRequested();
                return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(
                    new InfisicalAccessToken(SecretMaterial.FromText("token-canary"))));
            }
        }
    }
}
