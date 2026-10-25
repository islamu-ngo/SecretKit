using System.Net;
using System.Text.Json;
using System.Threading.Channels;

namespace SecretKit.Demo.Tests;

public sealed class WebDemoTests
{
    private const string Token = "synthetic-web-token-canary-7c42";
    private const string Value = "synthetic-web-value-canary-3f65";
    private const string Coordinate = "synthetic-web-coordinate-canary-9c61";
    private const string Hostile = "synthetic-web-exception-canary-8e22";

    [Test]
    public async Task HttpFailureAndDefaultHostOutputDoNotDiscloseProtectedInput()
    {
        await using var provider = new ControlledInfisicalServer(_ => new(403,
            JsonSerializer.Serialize(new { message = Hostile })));
        string captured = "";
        DemoResult result = await new DemoProcess().WebAsync(() => Input(provider.Origin),
            ["serve"], async (line, controls) =>
            {
                using JsonDocument report = JsonDocument.Parse(line);
                if (report.RootElement.GetProperty("outcome").GetString() != "listening") return;
                using var client = new HttpClient();
                using var response = await client.GetAsync(new Uri(
                    new Uri(report.RootElement.GetProperty("address").GetString()!), "work"));
                captured = await response.Content.ReadAsStringAsync();
                await controls.WriteLineAsync("stop");
                await controls.FlushAsync();
            });
        foreach (string canary in new[] { Token, Value, Coordinate, Hostile })
            await Assert.That((result.Output + result.Error + captured).Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.ExitCode).IsEqualTo(4);
        await Assert.That(result.Output.Contains("\"listening\"", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task HelpDoesNotReadInputOrStartAListener()
    {
        DemoResult result = await new DemoProcess().WebAsync(() => "", ["--help"]);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("help");
    }

    [Test]
    [Arguments("http://example.invalid/")]
    [Arguments("http://127.0.0.1/protected")]
    [Arguments("http://synthetic-user:synthetic-password@127.0.0.1/")]
    public async Task UnselectedDownstreamOriginFailsBeforeProviderAccess(string downstream)
    {
        await using var provider = new ControlledInfisicalServer(_ => Secret(Value));
        DemoResult result = await new DemoProcess().WebAsync(
            () => Input(provider.Origin, new Uri(downstream)), ["serve"]);
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(provider.Requests.Count).IsEqualTo(0);
        await Assert.That((result.Output + result.Error).Contains(downstream, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task HeldRequestPinsOldClientWhileOnlyExplicitEnablePublishesReplacement()
    {
        string value = Value;
        var held = Signal();
        var release = Signal();
        int calls = 0;
        await using var provider = new ControlledInfisicalServer(_ => Secret(Volatile.Read(ref value)));
        await using var downstream = new ControlledInfisicalServer(request =>
        {
            if (Interlocked.Increment(ref calls) == 1)
            {
                held.TrySetResult();
                return new(202, "{}", Release: release.Task);
            }
            return new(202, "{}");
        });
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            Task<WebReply> old = session.WorkAsync();
            try
            {
                await held.Task.WaitAsync(session.Token);
                Volatile.Write(ref value, Value + "-replacement");
                await session.CommandAsync("check", "checked");
                WebReply checkedWork = await session.WorkAsync();
                await Assert.That(checkedWork.Revision).IsEqualTo(1);
                await session.CommandAsync("enable", "enabled");
                WebReply replacement = await session.WorkAsync();
                await Assert.That(replacement.Status).IsEqualTo(HttpStatusCode.OK);
                await Assert.That(replacement.Revision).IsEqualTo(3);
                release.TrySetResult();
                WebReply completed = await old;
                await Assert.That(completed.Revision).IsEqualTo(1);
                await Assert.That(completed.Status).IsEqualTo(HttpStatusCode.OK);
                string[] credentials = downstream.Requests.Select(r => r.Headers["Authorization"]).ToArray();
                await Assert.That(credentials.SequenceEqual(["Bearer " + Value, "Bearer " + Value,
                    "Bearer " + Value + "-replacement"])).IsTrue();
                await Assert.That(downstream.Requests.All(r => r.Method == "POST" && r.Target == "/jobs" &&
                    r.Body == "{\"operation\":\"reconcile\"}")).IsTrue();
                await Assert.That((await session.GetAsync("admin")).Status).IsEqualTo(HttpStatusCode.NotFound);
                await Assert.That((await session.GetAsync("work")).Status).IsEqualTo(HttpStatusCode.NotFound);
            }
            finally { release.TrySetResult(); await old; }
        });
        await CleanAsync(result);
    }

    [Test]
    public async Task LateCandidateCannotOverwriteDisableAndHealthSeparatesLiveness()
    {
        var entered = Signal();
        var release = Signal();
        int reads = 0;
        await using var provider = new ControlledInfisicalServer(_ =>
        {
            DemoResponse response = Secret(Value);
            if (Interlocked.Increment(ref reads) != 2) return response;
            entered.TrySetResult();
            return response with { Release = release.Task };
        });
        await using var downstream = new ControlledInfisicalServer(_ => new(202, "{}"));
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            await session.SendAsync("enable");
            await entered.Task.WaitAsync(session.Token);
            await session.CommandAsync("disable", "disabled");
            await Assert.That((await session.GetAsync("health/live")).Status).IsEqualTo(HttpStatusCode.OK);
            await Assert.That((await session.GetAsync("health/ready")).Status).IsEqualTo(HttpStatusCode.ServiceUnavailable);
            release.TrySetResult();
            JsonElement late = await session.EventAsync("enabled");
            await Assert.That(late.GetProperty("active").GetBoolean()).IsFalse();
            await Assert.That((await session.WorkAsync()).Status).IsEqualTo(HttpStatusCode.ServiceUnavailable);
            await session.CommandAsync("enable", "enabled");
            await Assert.That((await session.WorkAsync()).Revision).IsEqualTo(4);
        });
        release.TrySetResult();
        await CleanAsync(result);
    }

    [Test]
    public async Task OptionalFailureAndRejectedReplacementPreserveRequiredWork()
    {
        bool reject = false;
        await using var provider = new ControlledInfisicalServer(request =>
            request.Target.Contains("optional", StringComparison.Ordinal) ? new(404, Hostile) :
            Volatile.Read(ref reject) ? new(403, Hostile) : Secret(Value));
        await using var downstream = new ControlledInfisicalServer(_ => new(202, "{}"));
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            await Assert.That((await session.WorkAsync(optional: true)).Status).IsEqualTo(HttpStatusCode.ServiceUnavailable);
            Volatile.Write(ref reject, true);
            JsonElement rejected = await session.CommandAsync("enable", "enabled");
            await Assert.That(rejected.GetProperty("status").GetString()).IsEqualTo("Denied".ToLowerInvariant());
            await Assert.That((await session.GetAsync("health/ready")).Status).IsEqualTo(HttpStatusCode.OK);
            WebReply work = await session.WorkAsync();
            await Assert.That(work.Status).IsEqualTo(HttpStatusCode.OK);
            await Assert.That(work.Revision).IsEqualTo(1);
        }, optional: true);
        await CleanAsync(result);
    }

    [Test]
    public async Task HeldOptionalAdmissionCannotBlockRequiredReadinessOrWork()
    {
        var optionalEntered = Signal();
        var releaseOptional = Signal();
        await using var provider = new ControlledInfisicalServer(request =>
        {
            if (!request.Target.Contains("optional", StringComparison.Ordinal)) return Secret(Value);
            optionalEntered.TrySetResult();
            return Secret(Value) with { Release = releaseOptional.Task };
        });
        await using var downstream = new ControlledInfisicalServer(_ => new(202, "{}"));
        try
        {
            DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
            {
                await optionalEntered.Task.WaitAsync(session.Token);
                await Assert.That((await session.GetAsync("health/ready")).Status).IsEqualTo(HttpStatusCode.OK);
                await Assert.That((await session.WorkAsync()).Status).IsEqualTo(HttpStatusCode.OK);
                await Assert.That((await session.WorkAsync(optional: true)).Status)
                    .IsEqualTo(HttpStatusCode.ServiceUnavailable);
                // Stop cancels and drains the held optional preparation; it does not wait for this fixture release.
            }, optional: true);
            await CleanAsync(result);
        }
        finally { releaseOptional.TrySetResult(); }
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task DownstreamErrorsAndCancellationKeepHttpAndShutdownOutputMaterialFree(bool cancel)
    {
        var entered = Signal();
        var release = Signal();
        await using var provider = new ControlledInfisicalServer(_ => Secret(Value));
        await using var downstream = new ControlledInfisicalServer(_ =>
        {
            entered.TrySetResult();
            return new(500, Hostile, Release: cancel ? release.Task : null);
        });
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            using var cancellation = new CancellationTokenSource();
            Task<WebReply> request = session.WorkAsync(cancellation.Token);
            await entered.Task.WaitAsync(session.Token);
            if (cancel)
            {
                cancellation.Cancel();
                try { await request; }
                catch (OperationCanceledException) { }
                release.TrySetResult();
                await Assert.That((await session.GetAsync("health/ready")).Status).IsEqualTo(HttpStatusCode.OK);
            }
            else
            {
                WebReply response = await request;
                await Assert.That(response.Status).IsEqualTo(HttpStatusCode.BadGateway);
                await Assert.That(response.Body.Contains(Hostile, StringComparison.Ordinal)).IsFalse();
            }
        });
        release.TrySetResult();
        await CleanAsync(result);
    }

    [Test]
    public async Task ShutdownDrainsAHeldRequestBeforeExiting()
    {
        var entered = Signal();
        var release = Signal();
        await using var provider = new ControlledInfisicalServer(_ => Secret(Value));
        await using var downstream = new ControlledInfisicalServer(_ =>
        {
            entered.TrySetResult();
            return new(202, "{}", Release: release.Task);
        });
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            Task<WebReply> work = session.WorkAsync();
            await entered.Task.WaitAsync(session.Token);
            await session.SendAsync("stop");
            await session.EventAsync("stopping");
            // Stop is accepted while this real downstream request still owns its generation.
            release.TrySetResult();
            await Assert.That((await work).Status).IsEqualTo(HttpStatusCode.OK);
        });
        await CleanAsync(result);
    }

    [Test]
    public async Task ShutdownTimeoutIsNotReportedAsSuccessfulDrain()
    {
        var entered = Signal();
        var release = Signal();
        await using var provider = new ControlledInfisicalServer(_ => Secret(Value));
        await using var downstream = new ControlledInfisicalServer(_ =>
        {
            entered.TrySetResult();
            return new(202, "{}", Release: release.Task);
        });
        DemoResult result = await ExerciseAsync(provider.Origin, downstream.Origin, async session =>
        {
            Task<WebReply> work = session.WorkAsync();
            await entered.Task.WaitAsync(session.Token);
            await session.SendAsync("stop");
            await session.EventAsync("stopping");
            // The real host's five-second grace period is the behavior under test.
            // No timed release: Kestrel must cancel the operation and observe its lease.
            try { await work; }
            catch (HttpRequestException) { }
            catch (OperationCanceledException) { }
        });
        release.TrySetResult();
        await Assert.That(result.ExitCode).IsEqualTo(4);
        await Assert.That(result.Output.Contains("\"stop-timeout\"", StringComparison.Ordinal)).IsTrue();
        foreach (string canary in new[] { Token, Value, Coordinate, Hostile })
            await Assert.That((result.Output + result.Error).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    private static async Task CleanAsync(DemoResult result)
    {
        await Assert.That(result.ExitCode).IsEqualTo(0);
        foreach (string canary in new[] { Token, Value, Coordinate, Hostile })
            await Assert.That((result.Output + result.Error).Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(result.Error).IsEqualTo("");
    }

    private static DemoResponse Secret(string value) => new(200, JsonSerializer.Serialize(new
    {
        secret = new
        {
            id = "11111111-1111-1111-1111-111111111111",
            secretKey = "key",
            secretValue = value,
            secretValueHidden = false,
            workspace = Coordinate,
            environment = "env",
            secretPath = "/",
            version = 1
        }
    }));

    private static TaskCompletionSource Signal() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static async Task<DemoResult> ExerciseAsync(Uri provider, Uri downstream,
        Func<WebSession, Task> exercise, bool optional = false)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        var ready = new TaskCompletionSource<(Uri, StreamWriter)>(TaskCreationOptions.RunContinuationsAsynchronously);
        var events = Channel.CreateUnbounded<JsonElement>();
        Task<DemoResult> process = new DemoProcess().WebAsync(() => Input(provider, downstream, optional),
            ["serve"], (line, writer) =>
            {
                using JsonDocument report = JsonDocument.Parse(line);
                JsonElement item = report.RootElement.Clone();
                if (item.GetProperty("outcome").GetString() == "listening")
                    ready.TrySetResult((new Uri(item.GetProperty("address").GetString()!), writer));
                else events.Writer.TryWrite(item);
                return Task.CompletedTask;
            });
        await Task.WhenAny(ready.Task, process).WaitAsync(deadline.Token);
        if (!ready.Task.IsCompleted)
        {
            DemoResult failed = await process;
            throw new InvalidOperationException("Web listener was not admitted: " + failed.Output + failed.Error);
        }
        var (address, controls) = await ready.Task;
        using var session = new WebSession(address, controls, events.Reader, deadline.Token);
        try { await exercise(session); }
        finally
        {
            if (!process.IsCompleted && !session.StopRequested) await session.SendAsync("stop");
            await process.WaitAsync(deadline.Token);
        }
        return await process;
    }

    private static string Input(Uri provider, Uri? downstream = null, bool optional = false)
    {
        var selection = new Dictionary<string, string>
        {
            ["downstream"] = (downstream ?? new Uri("http://127.0.0.1:1/")).AbsoluteUri
        };
        if (optional) selection["optionalKey"] = "optional";
        return JsonSerializer.Serialize(new
        {
            origin = provider.AbsoluteUri,
            project = Coordinate,
            environment = "env",
            folder = "/",
            key = "key",
            token = Token,
            allowLoopbackDevelopmentHttp = true
        }) + "\n" + JsonSerializer.Serialize(selection) + "\n";
    }

    private sealed class WebSession(Uri address, StreamWriter controls, ChannelReader<JsonElement> events,
        CancellationToken token) : IDisposable
    {
        private readonly HttpClient _http = new() { BaseAddress = address };
        internal CancellationToken Token => token;
        internal bool StopRequested { get; private set; }
        internal Task SendAsync(string command) => SendCoreAsync(command);
        private async Task SendCoreAsync(string command)
        {
            if (command == "stop") StopRequested = true;
            await controls.WriteLineAsync(command.AsMemory(), token);
            await controls.FlushAsync(token);
        }
        internal async Task<JsonElement> CommandAsync(string command, string expected)
        {
            await SendAsync(command);
            return await EventAsync(expected);
        }
        internal async Task<JsonElement> EventAsync(string expected)
        {
            while (await events.WaitToReadAsync(token))
                while (events.TryRead(out JsonElement item))
                    if (item.GetProperty("outcome").GetString() == expected) return item;
            throw new InvalidOperationException("Missing web control result.");
        }
        internal async Task<WebReply> WorkAsync(CancellationToken cancellation = default, bool optional = false)
        {
            using var combined = CancellationTokenSource.CreateLinkedTokenSource(token, cancellation);
            using var response = await _http.PostAsync(optional ? "work?optional=true" : "work", null, combined.Token);
            return await ReplyAsync(response, combined.Token);
        }
        internal async Task<WebReply> GetAsync(string path)
        {
            using var response = await _http.GetAsync(path, token);
            return await ReplyAsync(response, token);
        }
        private static async Task<WebReply> ReplyAsync(HttpResponseMessage response, CancellationToken cancellation)
        {
            string body = await response.Content.ReadAsStringAsync(cancellation);
            foreach (string canary in new[] { WebDemoTests.Token, Value, Coordinate, Hostile })
                await Assert.That(body.Contains(canary, StringComparison.Ordinal)).IsFalse();
            using JsonDocument document = JsonDocument.Parse(body);
            long? revision = document.RootElement.TryGetProperty("revision", out var value) ? value.GetInt64() : null;
            return new(response.StatusCode, revision, body);
        }
        public void Dispose() => _http.Dispose();
    }

    private sealed record WebReply(HttpStatusCode Status, long? Revision, string Body);
}
