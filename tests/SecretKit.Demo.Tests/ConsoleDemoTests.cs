using System.Text.Json;

namespace SecretKit.Demo.Tests;

public sealed class ConsoleDemoTests
{
    private const string Canary = "synthetic-credential-output-canary-62b7";

    [Test]
    public async Task HelpDoesNotRequireCredentialsOrContactProvider()
    {
        DemoResult result = await new DemoProcess().ConsoleAsync("", "--help");
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("help");
    }

    [Test]
    [Arguments("read")]
    [Arguments("create")]
    [Arguments("update")]
    public async Task InvalidInputFailsBeforeWorkWithoutDisclosingProtectedFields(string operation)
    {
        const string canary = "synthetic-protected-input-8a92";
        string input = JsonSerializer.Serialize(new { token = canary, unexpected = canary });
        DemoResult result = await new DemoProcess().ConsoleAsync(input, operation);
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(result.ExitCode).IsEqualTo(2);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("invalid");
        await Assert.That((result.Output + result.Error).Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("read", 200, "success", 0)]
    [Arguments("read", 403, "denied", 4)]
    [Arguments("read", 404, "absent", 4)]
    [Arguments("create", 200, "applied", 0)]
    [Arguments("update", 200, "applied", 0)]
    [Arguments("create", 403, "denied", 4)]
    [Arguments("update", 409, "conflict", 4)]
    [Arguments("update", 202, "pending", 3)]
    public async Task SelectedOperationsPreserveNativeOutcomeWithoutDisclosure(
        string operation, int status, string outcome, int exit)
    {
        string? observedValue = null;
        await using var server = new ControlledInfisicalServer(request =>
        {
            if (request.Method != "GET")
            {
                using var body = JsonDocument.Parse(request.Body);
                observedValue = body.RootElement.GetProperty("secretValue").GetString();
            }
            string response = status == 202
                ? JsonSerializer.Serialize(new { approval = new { id = Guid.NewGuid(), hasMerged = false } })
                : status != 200 ? JsonSerializer.Serialize(new { message = Canary })
                : JsonSerializer.Serialize(new
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
            return new(status, response);
        });
        DemoResult result = await new DemoProcess().ConsoleAsync(Input(server.Origin, operation), operation);
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(result.ExitCode).IsEqualTo(exit);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo(outcome);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(server.Requests.Count).IsEqualTo(1);
        DemoRequest sent = server.Requests.Single();
        await Assert.That(sent.Headers["Authorization"]).IsEqualTo("Bearer " + Canary);
        await Assert.That(sent.Method).IsEqualTo(operation switch { "read" => "GET", "create" => "POST", _ => "PATCH" });
        if (operation != "read")
            await Assert.That(observedValue).IsEqualTo(Canary);
        if (outcome == "pending")
            await Assert.That(report.RootElement.GetProperty("evidence").GetString()).IsEqualTo("Pending");
    }

    [Test]
    public async Task LostWriteAcknowledgementRetainsUncertaintyWithoutReplay()
    {
        string? committed = null;
        await using var server = new ControlledInfisicalServer(request =>
        {
            using var body = JsonDocument.Parse(request.Body);
            committed = body.RootElement.GetProperty("secretValue").GetString();
            return new(200, "", Drop: true);
        });
        DemoResult result = await new DemoProcess().ConsoleAsync(Input(server.Origin, "create"), "create");
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(result.ExitCode).IsEqualTo(4);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("unknown");
        await Assert.That(report.RootElement.GetProperty("evidence").GetString()).IsEqualTo("PossiblyDispatched");
        await Assert.That(committed).IsEqualTo(Canary);
        await Assert.That(server.Requests.Count).IsEqualTo(1);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }

    private static string Input(Uri origin, string operation)
    {
        var fields = new Dictionary<string, object>
        {
            ["origin"] = origin.AbsoluteUri,
            ["project"] = "project",
            ["environment"] = "env",
            ["folder"] = "/",
            ["key"] = "key",
            ["token"] = Canary,
            ["allowLoopbackDevelopmentHttp"] = true
        };
        if (operation != "read") fields["value"] = Canary;
        return JsonSerializer.Serialize(fields);
    }

    [Test]
    public async Task OperationDeadlineAfterDispatchRetainsReceiptWithoutReplay()
    {
        // The app's real whole-operation deadline is the behavior under test.
        // The server holds the acknowledgement by event, never by a timed sleep.
        string? committed = null;
        await using var server = new ControlledInfisicalServer(request =>
        {
            using var body = JsonDocument.Parse(request.Body);
            committed = body.RootElement.GetProperty("secretValue").GetString();
            return new(200, "", Hold: true);
        });
        DemoResult result = await new DemoProcess().ConsoleAsync(Input(server.Origin, "create"), "create");
        using JsonDocument report = JsonDocument.Parse(result.Output);
        await Assert.That(result.ExitCode).IsEqualTo(5);
        await Assert.That(report.RootElement.GetProperty("outcome").GetString()).IsEqualTo("cancelled");
        await Assert.That(report.RootElement.GetProperty("evidence").GetString()).IsEqualTo("PossiblyDispatched");
        await Assert.That(committed).IsEqualTo(Canary);
        await Assert.That(server.Requests.Count).IsEqualTo(1);
        await Assert.That((result.Output + result.Error).Contains(Canary, StringComparison.Ordinal)).IsFalse();
    }
}
