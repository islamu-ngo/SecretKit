using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;

namespace SecretKit.Assessment.Tests;

public sealed class MutationTranslationTests
{
    private static readonly TimeSpan Deadline = TimeSpan.FromSeconds(10);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConsumerKeepsNativeDispositionAlongsideAppliedPendingRejectedAndUnknownEvidence(bool update)
    {
        await using var fixture = new Fixture(update);
        using var material = SecretMaterial.FromText("material-canary\n\n");
        string[] keys = ["applied", "pending", "rejected", "unknown"];
        if (update)
        {
            foreach (string key in keys)
            {
                fixture.State[key] = new("previous-material", 1);
            }
        }

        var scenario = new ReviewedChangesScenario(keys.Select(key =>
            fixture.Selection(key, material, update)), 1);
        MutationReceipt[] held = scenario.Results.Select(row => row.Receipt).ToArray();

        IReadOnlyList<ReviewedChangeResult> rows = await scenario.ExecuteAsync().WaitAsync(Deadline);

        SecretStatus[] statuses = [SecretStatus.Success, SecretStatus.Pending, SecretStatus.Denied, SecretStatus.Unknown];
        DispatchEvidence[] evidence =
        [
            DispatchEvidence.Applied, DispatchEvidence.Pending,
            DispatchEvidence.Rejected, DispatchEvidence.PossiblyDispatched
        ];
        for (int index = 0; index < keys.Length; index++)
        {
            await Assert.That(ReferenceEquals(rows[index].Receipt, held[index])).IsTrue();
            await Assert.That(rows[index].Status).IsEqualTo(statuses[index]);
            await Assert.That(rows[index].Evidence).IsEqualTo(evidence[index]);
            await Assert.That(rows[index].Progress).IsEqualTo(ReviewedChangeProgress.Completed);
        }

        foreach (string key in new[] { "applied", "unknown" })
        {
            using SecretRead read = (await fixture.Client.ReadAsync(fixture.Target(key))).Value;
            await Assert.That(read.Material.Reveal()).IsEqualTo(material.Reveal());
            await Assert.That(read.Observation.Version).IsEqualTo(update ? "2" : "1");
        }

        foreach (string key in new[] { "pending", "rejected" })
        {
            SecretOutcome<SecretRead> read = await fixture.Client.ReadAsync(fixture.Target(key));
            if (update)
            {
                using SecretRead unchanged = read.Value;
                await Assert.That(unchanged.Material.Reveal()).IsEqualTo("previous-material");
                await Assert.That(unchanged.Observation.Version).IsEqualTo("1");
            }
            else
            {
                await Assert.That(read.Status).IsEqualTo(SecretStatus.Absent);
            }
        }

        await AssertNativeDispositionAsync(rows[0], InfisicalChangeDisposition.Applied);
        await AssertNativeDispositionAsync(rows[1], InfisicalChangeDisposition.SubmittedForApproval);
        await Assert.That(rows[0].InfisicalChange!.Version).IsEqualTo(update ? "2" : "1");
        await Assert.That(rows[0].InfisicalChange!.ApprovalId).IsNull();
        await Assert.That(rows[1].InfisicalChange!.Version).IsNull();
        await Assert.That(rows[1].InfisicalChange!.ApprovalId).IsEqualTo("a0000000-0000-0000-0000-000000000001");
        await Assert.That(rows[2].InfisicalChange).IsNull();
        await Assert.That(rows[3].InfisicalChange).IsNull();
        await Assert.That(async () => await scenario.ExecuteAsync()).Throws<InvalidOperationException>();
        await Assert.That(fixture.State["applied"].Version).IsEqualTo(update ? 2 : 1);
        await Assert.That(fixture.State["unknown"].Version).IsEqualTo(update ? 2 : 1);
    }

    [Test]
    public async Task CallerHeldReceiptsSurviveCancellationAfterCommitWithoutReplayingQueuedWork()
    {
        await using var fixture = new Fixture();
        using var material = SecretMaterial.FromText("material-canary");
        var scenario = new ReviewedChangesScenario(
        [
            fixture.Selection("applied", material),
            fixture.Selection("held", material),
            fixture.Selection("queued", material)
        ], 1);
        MutationReceipt[] held = scenario.Results.Select(row => row.Receipt).ToArray();
        using var cancellation = new CancellationTokenSource();

        Task<IReadOnlyList<ReviewedChangeResult>> execution = scenario.ExecuteAsync(cancellation.Token);
        await fixture.Committed.Task.WaitAsync(Deadline);
        cancellation.Cancel();

        await Assert.That(async () => await execution.WaitAsync(Deadline)).Throws<OperationCanceledException>();
        for (int index = 0; index < held.Length; index++)
        {
            await Assert.That(ReferenceEquals(scenario.Results[index].Receipt, held[index])).IsTrue();
        }

        await Assert.That(held[0].Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(scenario.Results[0].Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(scenario.Results[0].Progress).IsEqualTo(ReviewedChangeProgress.Completed);
        await Assert.That(scenario.Results[0].InfisicalChange!.Disposition).IsEqualTo(InfisicalChangeDisposition.Applied);
        await Assert.That(scenario.Results[0].InfisicalChange!.Version).IsEqualTo("1");
        await Assert.That(held[1].Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        await Assert.That(scenario.Results[1].Status).IsEqualTo(SecretStatus.Unknown);
        await Assert.That(scenario.Results[1].Progress).IsEqualTo(ReviewedChangeProgress.Canceled);
        await Assert.That(scenario.Results[1].InfisicalChange).IsNull();
        await Assert.That(held[2].Evidence).IsEqualTo(DispatchEvidence.NotDispatched);
        await Assert.That(scenario.Results[2].Status).IsNull();
        await Assert.That(scenario.Results[2].Progress).IsEqualTo(ReviewedChangeProgress.Canceled);
        using SecretRead committed = (await fixture.Client.ReadAsync(fixture.Target("held"))).Value;
        await Assert.That(committed.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(committed.Observation.Version).IsEqualTo("1");
        await Assert.That(fixture.State.ContainsKey("queued")).IsFalse();
        await Assert.That(async () => await scenario.ExecuteAsync()).Throws<InvalidOperationException>();
        await Assert.That(fixture.State["held"].Version).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task FailedConsumerInvalidationCannotEraseConfirmedWriteOrReexecuteSource(bool cancel)
    {
        await using var fixture = new Fixture();
        using var material = SecretMaterial.FromText("material-canary");
        SecretReference target = fixture.Target("applied");
        var scenario = new ReviewedChangesScenario(
            [ReviewedChange.InfisicalCreate(ReviewApproval.Approved, fixture.Client, target, material)], 1);
        ReviewedChangeResult held = scenario.Results[0];
        bool invalidationStarted = false;

        async Task WriteThenInvalidateAsync()
        {
            await scenario.ExecuteAsync().WaitAsync(Deadline);
            invalidationStarted = true;
            if (cancel)
            {
                throw new OperationCanceledException();
            }

            throw new InvalidOperationException("Consumer invalidation failed.");
        }

        if (cancel)
        {
            await Assert.That(WriteThenInvalidateAsync).Throws<OperationCanceledException>();
        }
        else
        {
            await Assert.That(WriteThenInvalidateAsync).Throws<InvalidOperationException>();
        }

        await Assert.That(invalidationStarted).IsTrue();
        await Assert.That(ReferenceEquals(held, scenario.Results[0])).IsTrue();
        await Assert.That(held.Evidence).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(held.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(held.Progress).IsEqualTo(ReviewedChangeProgress.Completed);
        await Assert.That(held.InfisicalChange!.Disposition).IsEqualTo(InfisicalChangeDisposition.Applied);
        await Assert.That(held.InfisicalChange!.Version).IsEqualTo("1");
        await Assert.That(async () => await scenario.ExecuteAsync()).Throws<InvalidOperationException>();
        SecretOutcome<InfisicalStaticChange> replay = await fixture.Client.CreateAsync(target, material, held.Receipt);
        await Assert.That(replay.Status).IsEqualTo(SecretStatus.Invalid);
        using SecretRead read = (await fixture.Client.ReadAsync(fixture.Target("applied"))).Value;
        await Assert.That(read.Material.Reveal()).IsEqualTo(material.Reveal());
        await Assert.That(read.Observation.Version).IsEqualTo("1");
    }

    private static async Task AssertNativeDispositionAsync(ReviewedChangeResult row, InfisicalChangeDisposition expected)
    {
        using JsonDocument report = JsonDocument.Parse(JsonSerializer.Serialize(row));
        bool retained = report.RootElement.TryGetProperty("InfisicalChange", out JsonElement native);
        await Assert.That(retained).IsTrue();
        await Assert.That(native.GetProperty("Disposition").GetInt32()).IsEqualTo((int)expected);
        await Assert.That(native.TryGetProperty("Version", out _)).IsFalse();
        await Assert.That(native.TryGetProperty("ApprovalId", out _)).IsFalse();
    }

    private sealed record Stored(string Value, int Version);

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly TcpListener _listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource _shutdown = new();
        private readonly ConcurrentBag<Task> _requests = [];
        private readonly Task _accept;
        private readonly string _mutationMethod;
        public ConcurrentDictionary<string, Stored> State { get; } = new();
        public TaskCompletionSource Committed { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public InfisicalClient Client { get; }

        public Fixture(bool update = false)
        {
            _mutationMethod = update ? "PATCH" : "POST";
            _listener.Start();
            int port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            var origin = new Uri($"http://127.0.0.1:{port}/");
            Client = new InfisicalClient(origin, new Tokens(),
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            _accept = AcceptAsync();
        }

        public SecretReference Target(string key) =>
            new(Client.Authority, new InfisicalSecretAddress("project", "env", "/", key));

        public ReviewedChange Selection(string key, SecretMaterial material, bool update = false) => update
            ? ReviewedChange.InfisicalUpdateValue(ReviewApproval.Approved, Client, Target(key), material)
            : ReviewedChange.InfisicalCreate(ReviewApproval.Approved, Client, Target(key), material);

        private async Task AcceptAsync()
        {
            try
            {
                while (true)
                {
                    TcpClient connection = await _listener.AcceptTcpClientAsync(_shutdown.Token);
                    _requests.Add(ServeAsync(connection));
                }
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (SocketException) when (_shutdown.IsCancellationRequested)
            {
            }
        }

        private async Task ServeAsync(TcpClient connection)
        {
            using var ownedConnection = connection;
            try
            {
                using NetworkStream stream = connection.GetStream();
                using var request = new StreamReader(stream, System.Text.Encoding.UTF8, leaveOpen: true);
                string[] first = (await request.ReadLineAsync(_shutdown.Token))!.Split(' ');
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                string? line;
                while (!string.IsNullOrEmpty(line = await request.ReadLineAsync(_shutdown.Token)))
                {
                    int colon = line.IndexOf(':');
                    headers.Add(line[..colon], line[(colon + 1)..].Trim());
                }
                string key = Uri.UnescapeDataString(new Uri(new Uri("http://127.0.0.1"), first[1]).AbsolutePath.Split('/').Last());
                object response = new { };
                int status = 200;
                if (first[0] != "GET")
                {
                    int length = int.Parse(headers["Content-Length"], System.Globalization.CultureInfo.InvariantCulture);
                    char[] payload = new char[length];
                    int received = 0;
                    while (received < payload.Length)
                    {
                        int count = await request.ReadAsync(payload.AsMemory(received), _shutdown.Token);
                        if (count == 0) throw new EndOfStreamException();
                        received += count;
                    }
                    using JsonDocument document = JsonDocument.Parse(new string(payload));
                    JsonElement body = document.RootElement;
                    if (first[0] != _mutationMethod ||
                        headers["Authorization"] != "Bearer token-canary" ||
                        body.GetProperty("projectId").GetString() != "project" ||
                        body.GetProperty("environment").GetString() != "env" ||
                        body.GetProperty("secretPath").GetString() != "/" ||
                        body.GetProperty("type").GetString() != "shared" ||
                        !body.GetProperty("skipMultilineEncoding").GetBoolean())
                    {
                        status = 400;
                    }
                    else if (key == "rejected")
                    {
                        status = 403;
                    }
                    else if (key == "pending")
                    {
                        response = new { approval = new { id = "a0000000-0000-0000-0000-000000000001", hasMerged = false } };
                    }
                    else
                    {
                        string value = body.GetProperty("secretValue").GetString()!;
                        State.AddOrUpdate(key, new Stored(value, 1), (_, previous) => new(value, previous.Version + 1));
                        if (key == "held")
                        {
                            Committed.TrySetResult();
                            var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                            await release.Task.WaitAsync(_shutdown.Token);
                        }

                        if (key != "unknown")
                        {
                            response = ReadResponse(key);
                        }
                    }
                }
                else if (State.ContainsKey(key))
                {
                    response = ReadResponse(key);
                }
                else
                {
                    status = 404;
                }

                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(response);
                byte[] head = System.Text.Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(head, _shutdown.Token);
                await stream.WriteAsync(bytes, _shutdown.Token);
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }
            catch (IOException)
            {
                // A canceled native caller may close its socket before the held reply.
            }
        }

        private object ReadResponse(string key) => new
        {
            secret = new
            {
                id = $"resource-{key}",
                secretKey = key,
                workspace = "project",
                environment = "env",
                secretPath = "/",
                secretValue = State[key].Value,
                secretValueHidden = false,
                version = State[key].Version
            }
        };

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            await Client.DisposeAsync();
            _listener.Stop();
            await _accept.WaitAsync(Deadline);
            await Task.WhenAll(_requests).WaitAsync(Deadline);
            _shutdown.Dispose();
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
