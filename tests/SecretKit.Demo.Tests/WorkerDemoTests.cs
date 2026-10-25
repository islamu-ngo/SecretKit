using System.Text.Json;

namespace SecretKit.Demo.Tests;

public sealed class WorkerDemoTests
{
    private const string Canary = "worker-private-canary-4f83";

    [Test]
    public async Task MalformedProtectedInputNeverLeaksThroughHostFailure()
    {
        DemoResult result = await new DemoProcess().WorkerAsync(Canary + "\n", ["run"]);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("invalid");
    }

    [Test]
    public async Task AdmissionPrecedesActualHostedWorkAndBoundedStop()
    {
        await using var server = new ControlledInfisicalServer(_ => new(200, Secret()));
        DemoResult result = await new DemoProcess().WorkerAsync(() => Input(server.Origin) + "\n",
            ["run"], WorkThenStop);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("prepared,started,success,stopped");
        await Assert.That(server.Requests.Select(request => request.Method).ToArray())
            .IsEquivalentTo(["GET", "GET"]);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task HelpDoesNotReadInputOrStartHost()
    {
        DemoResult result = await new DemoProcess().WorkerAsync("", ["--help"]);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("help");
    }

    [Test]
    [Arguments("unknown", false, false)]
    [Arguments("finite", true, false)]
    [Arguments("finite", false, true)]
    public async Task UnknownOrExpiredEvidenceRequiresRecoveryBeforeHostStart(string lifetime, bool expired,
        bool lost)
    {
        await using var server = new ControlledInfisicalServer(_ =>
            throw new InvalidOperationException("No provider operation is authorized."));
        DemoResult result = await new DemoProcess().WorkerAsync(
            () => Input(server.Origin, lifetime, expired, lost: lost) + "\nwork\nstop\n", ["run", "--maintain"]);
        await Assert.That(result.ExitCode).IsEqualTo(4);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("recovery-required");
        await Assert.That(server.Requests.Count).IsEqualTo(0);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task FailedAdmissionNeverConstructsDependentWorkOrEmitsHostException()
    {
        await using var server = new ControlledInfisicalServer(_ =>
            new(403, JsonSerializer.Serialize(new { message = Canary })));
        DemoResult result = await new DemoProcess().WorkerAsync(() => Input(server.Origin) + "\nwork\nstop\n",
            ["run", "--maintain"]);
        await Assert.That(result.ExitCode).IsEqualTo(4);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("denied");
        await Assert.That(server.Requests.Count).IsEqualTo(1);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task StartedHostSchedulesRenewalAndNeverReplaysUnknownOutcome(bool loseResponse)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var server = new ControlledInfisicalServer(request =>
        {
            if (request.Target == "/api/v1/auth/token/renew")
            {
                entered.TrySetResult();
                return new(200, JsonSerializer.Serialize(new
                {
                    accessToken = Canary + "-renewed",
                    tokenType = "Bearer",
                    expiresIn = 120,
                    accessTokenMaxTTL = 600
                }), Drop: loseResponse, Release: release.Task);
            }
            return new(200, Secret());
        });
        int recoveryEvents = 0;
        DemoResult result = await new DemoProcess().WorkerAsync(() => Input(server.Origin, nearDue: true) + "\n",
            ["run", "--maintain"], async (line, stdin) =>
            {
                string outcome = Outcome(line);
                if (outcome == "started")
                {
                    // The scheduled host renewal must enter before the explicit join command.
                    await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                    await stdin.WriteLineAsync("renew");
                    await stdin.FlushAsync();
                }
                else if (outcome == "renewal-awaiting")
                    release.TrySetResult();
                else if (outcome == "renewed")
                {
                    await stdin.WriteLineAsync("work");
                    await stdin.FlushAsync();
                }
                else if (outcome == "success")
                {
                    await stdin.WriteLineAsync("stop");
                    await stdin.FlushAsync();
                }
                else if (outcome == "recovery-required")
                {
                    await stdin.WriteLineAsync(++recoveryEvents == 1 ? "renew" : "stop");
                    await stdin.FlushAsync();
                }
            });
        await Assert.That(result.ExitCode).IsEqualTo(loseResponse ? 4 : 0);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo(loseResponse
            ? "prepared,started,renewal-awaiting,recovery-required,recovery-required"
            : "prepared,started,renewal-awaiting,renewed,success,stopped");
        DemoRequest[] requests = server.Requests.ToArray();
        await Assert.That(string.Join(',', requests.Select(request => request.Method)))
            .IsEqualTo(loseResponse ? "GET,POST" : "GET,POST,GET");
        using JsonDocument renewal = JsonDocument.Parse(requests[1].Body);
        await Assert.That(renewal.RootElement.GetProperty("accessToken").GetString()).IsEqualTo(Canary);
        if (!loseResponse)
            await Assert.That(requests[2].Headers["Authorization"]).IsEqualTo("Bearer " + Canary + "-renewed");
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task MaintenanceRequiresExplicitOptInEvenForDueSession()
    {
        await using var server = new ControlledInfisicalServer(_ => new(200, Secret()));
        DemoResult result = await new DemoProcess().WorkerAsync(() => Input(server.Origin, nearDue: true) +
            "\n", ["run"], WorkThenStop);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(server.Requests.All(request => request.Method == "GET")).IsTrue();
        await Assert.That(server.Requests.Count).IsEqualTo(2);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ExplicitStopCancelsAndDrainsHeldReadOrScheduledRenewal(bool renewal)
    {
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int reads = 0;
        await using var server = new ControlledInfisicalServer(request =>
        {
            if (request.Method == "POST" || Interlocked.Increment(ref reads) == 2)
            {
                entered.TrySetResult();
                return new(200, "", Hold: true);
            }
            return new(200, Secret());
        });
        DemoResult result = await new DemoProcess().WorkerAsync(() => Input(server.Origin, nearDue: renewal) + "\n",
            renewal ? ["run", "--maintain"] : ["run"], async (line, stdin) =>
            {
                if (Outcome(line) != "started") return;
                if (!renewal)
                {
                    await stdin.WriteLineAsync("work");
                    await stdin.FlushAsync();
                }
                await entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
                await stdin.WriteLineAsync("stop");
                await stdin.FlushAsync();
            });
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("prepared,started,stopped");
        await Assert.That(server.Requests.Count).IsEqualTo(2);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    private static async Task WorkThenStop(string line, StreamWriter stdin)
    {
        string outcome = Outcome(line);
        if (outcome is not ("started" or "success")) return;
        await stdin.WriteLineAsync(outcome == "started" ? "work" : "stop");
        await stdin.FlushAsync();
    }

    [Test]
    [Arguments("{\"token\":\"worker-private-canary-4f83\",\"token\":\"duplicate\"}")]
    [Arguments("{\"unknown\":\"worker-private-canary-4f83\"}")]
    [Arguments("[]")]
    public async Task StrictFramesFailWithoutDefaultHostDiagnosticOutput(string frame)
    {
        DemoResult result = await new DemoProcess().WorkerAsync(frame + "\n", ["run"]);
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(string.Join(',', Outcomes(result))).IsEqualTo("invalid");
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    private static string[] Outcomes(DemoResult result) => result.Output.Split('\n',
        StringSplitOptions.RemoveEmptyEntries).Select(line =>
        {
            using JsonDocument document = JsonDocument.Parse(line);
            return document.RootElement.GetProperty("outcome").GetString()!;
        }).ToArray();

    private static string Outcome(string line)
    {
        using JsonDocument document = JsonDocument.Parse(line);
        return document.RootElement.GetProperty("outcome").GetString()!;
    }

    private static string Input(Uri origin, string lifetime = "finite", bool expired = false,
        bool nearDue = false, bool lost = false) => JsonSerializer.Serialize(new
        {
            origin = origin.AbsoluteUri,
            project = "project",
            environment = "env",
            folder = "/",
            key = "key",
            token = lost ? null : Canary,
            allowLoopbackDevelopmentHttp = true,
            originalIssuedAt = DateTimeOffset.UtcNow.AddMinutes(-1),
            expiresAt = expired ? DateTimeOffset.UtcNow.AddSeconds(-1)
                : nearDue ? DateTimeOffset.UtcNow.AddSeconds(25) : DateTimeOffset.UtcNow.AddMinutes(1),
            lifetime,
            maximumTtlSeconds = 600
        });

    private static string Secret() => JsonSerializer.Serialize(new
    {
        secret = new
        {
            secretKey = "key",
            secretValue = Canary,
            secretValueHidden = false,
            workspace = "project",
            environment = "env",
            secretPath = "/",
            version = 1
        }
    });
}
