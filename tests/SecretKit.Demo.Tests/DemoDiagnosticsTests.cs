using System.Net;
using System.Text.Json;

namespace SecretKit.Demo.Tests;

public sealed class DemoDiagnosticsTests
{
    [Test]
    [Arguments("Console", 200)]
    [Arguments("Console", 403)]
    [Arguments("Worker", 200)]
    [Arguments("Worker", 403)]
    [Arguments("Web", 200)]
    [Arguments("Web", 403)]
    public async Task InstalledAppDefaultTelemetryAndErrorsDoNotDiscloseProtectedInput(string kind, int status)
    {
        string canary = "synthetic-diagnostic-" + Guid.NewGuid().ToString("N");
        await using var provider = new ControlledInfisicalServer(_ => new(status,
            status == 200 ? Secret(canary) : JsonSerializer.Serialize(new { message = canary })));
        await using var downstream = new ControlledInfisicalServer(_ => new(500, canary));
        string capture = CapturePath();
        string http = "";
        var driver = new DemoProcess(capture);
        DemoResult result = kind switch
        {
            "Console" => await driver.ConsoleAsync(Input(provider.Origin, canary), "read"),
            "Worker" => await driver.WorkerAsync(() => Input(provider.Origin, canary, worker: true) + "\n",
                ["run"], async (line, controls) =>
                {
                    string? outcome = Outcome(line);
                    if (outcome == "started") await SendAsync(controls, "work");
                    if (outcome == "success") await SendAsync(controls, "stop");
                }),
            _ => await driver.WebAsync(() => Input(provider.Origin, canary) + "\n" +
                JsonSerializer.Serialize(new { downstream = downstream.Origin.AbsoluteUri }) + "\n",
                ["serve"], async (line, controls) =>
                {
                    using JsonDocument report = JsonDocument.Parse(line);
                    if (report.RootElement.GetProperty("outcome").GetString() != "listening") return;
                    using var client = new HttpClient();
                    using var response = await client.PostAsync(new Uri(
                        new Uri(report.RootElement.GetProperty("address").GetString()!), "work"), null);
                    http = await response.Content.ReadAsStringAsync();
                    await Assert.That(response.StatusCode).IsEqualTo(HttpStatusCode.BadGateway);
                    await SendAsync(controls, "stop");
                })
        };
        await Assert.That(result.ExitCode).IsEqualTo(status == 200 ? 0 : 4);
        await AssertCaptureAsync(capture, result.Output + result.Error + http, canary, provider.Origin);
    }

    [Test]
    [Arguments("Console")]
    [Arguments("Worker")]
    [Arguments("Web")]
    public async Task MalformedProtectedBootstrapInputCannotEscapeThroughStartupDiagnostics(string kind)
    {
        string canary = "synthetic-bootstrap-" + Guid.NewGuid().ToString("N");
        string capture = CapturePath();
        string input = JsonSerializer.Serialize(new { token = canary, bootstrapCredential = canary });
        var driver = new DemoProcess(capture);
        DemoResult result = kind switch
        {
            "Console" => await driver.ConsoleAsync(input, "read"),
            "Worker" => await driver.WorkerAsync(input + "\n", ["run"]),
            _ => await driver.WebAsync(() => input + "\n", ["serve"])
        };
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await AssertCaptureAsync(capture, result.Output + result.Error, canary);
    }

    private static async Task AssertCaptureAsync(string path, string output, string canary, Uri? origin = null)
    {
        string[] lines = await File.ReadAllLinesAsync(path);
        var surfaces = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in lines)
        {
            using JsonDocument entry = JsonDocument.Parse(line);
            surfaces.Add(entry.RootElement.GetProperty("surface").GetString()!);
            await Assert.That(entry.RootElement.GetProperty("surface").GetString()).IsNotEqualTo("overflow");
            await Assert.That(line.Contains(canary, StringComparison.Ordinal)).IsFalse();
            if (origin is not null)
                await Assert.That(line.Contains(origin.AbsoluteUri, StringComparison.Ordinal)).IsFalse();
        }
        foreach (string surface in new[] { "activity", "metric", "trace", "ready" })
            await Assert.That(surfaces.Contains(surface)).IsTrue();
        await Assert.That(output.Contains(canary, StringComparison.Ordinal)).IsFalse();
        if (origin is not null)
            await Assert.That(output.Contains(origin.AbsoluteUri, StringComparison.Ordinal)).IsFalse();
    }

    private static string CapturePath()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string directory = Path.Combine(root, "artifacts/runtime-adoption-hardening/diagnostic-captures");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, Guid.NewGuid().ToString("N") + ".jsonl");
    }

    private static string? Outcome(string line)
    {
        using JsonDocument report = JsonDocument.Parse(line);
        return report.RootElement.GetProperty("outcome").GetString();
    }

    private static async Task SendAsync(StreamWriter controls, string command)
    {
        await controls.WriteLineAsync(command);
        await controls.FlushAsync();
    }

    private static string Input(Uri origin, string canary, bool worker = false)
    {
        var fields = new Dictionary<string, object>
        {
            ["origin"] = origin.AbsoluteUri,
            ["project"] = canary,
            ["environment"] = canary,
            ["folder"] = "/" + canary,
            ["key"] = canary,
            ["token"] = canary,
            ["allowLoopbackDevelopmentHttp"] = true
        };
        if (worker)
        {
            fields["originalIssuedAt"] = DateTimeOffset.UtcNow.AddMinutes(-1);
            fields["expiresAt"] = DateTimeOffset.UtcNow.AddMinutes(1);
            fields["lifetime"] = "finite";
            fields["maximumTtlSeconds"] = 600;
        }
        return JsonSerializer.Serialize(fields);
    }

    private static string Secret(string canary) => JsonSerializer.Serialize(new
    {
        secret = new
        {
            id = "11111111-1111-1111-1111-111111111111",
            workspace = canary,
            environment = canary,
            secretPath = "/" + canary,
            secretKey = canary,
            secretValue = canary,
            secretValueHidden = false,
            version = 1
        }
    });
}
