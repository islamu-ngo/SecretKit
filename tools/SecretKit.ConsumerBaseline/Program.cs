using System.Diagnostics;
using System.Text.Json;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault;
using SecretKit.ConsumerBaseline;
using SecretKit.Core;
using SecretKit.Infisical;

if (args is ["live-infisical"])
{
    await LiveInfisical.RunAsync();
    return;
}

const int warmups = 5;
const int samples = 30;
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
var fixture = new Fixture();
using var azureHttp = new HttpClient(new AzureFixtureHandler(fixture));
using var transport = new HttpClientTransport(azureHttp);
var credential = new GeneratedCredential();
var setup = Stopwatch.StartNew();
var azure = new AzureKeyVaultClient(Fixture.Vault, credential, transport);
var azureAdmin = new AzureKeyVaultClient(Fixture.Vault, credential, transport);
var azurePath = new KitPath("secretkit-azure", azure, azureAdmin,
    key => new SecretReference(azure.Authority, new AzureSecretAddress(key)),
    new AzureInventoryScope(azureAdmin.Authority, maximumPages: 1, maximumItems: 2));
var directPath = new DirectAzurePath(credential, transport);
await using var wire = new InfisicalFixtureWire(fixture, deadline.Token);
await using var infisical = new InfisicalClient(wire.Origin, new GeneratedTokens(),
    new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
await using var infisicalAdmin = new InfisicalClient(wire.Origin, new GeneratedTokens(),
    new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
var infisicalPath = new KitPath("secretkit-infisical", infisical, infisicalAdmin,
    key => new SecretReference(infisical.Authority,
        new InfisicalSecretAddress("fixture-project", "fixture", "/", key)),
    new InfisicalInventoryScope(infisicalAdmin.Authority, "fixture-project", "fixture", "/", maximumItems: 2));
setup.Stop();
IConsumerPath[] paths = [azurePath, directPath, infisicalPath];
var measurements = new List<Measurement>();

foreach (string scenario in new[] { "ready", "absent", "denied", "unavailable", "indirect", "not-checked" })
{
    fixture.Scenario = scenario;
    foreach (string workflow in new[] { "bootstrap", "assessment" })
    {
        if (workflow == "bootstrap" && scenario is "indirect" or "not-checked")
            continue;
        SafeResult? matched = null;
        foreach (IConsumerPath path in paths)
        {
            async Task<SafeResult> Operation()
            {
                SafeResult result = workflow == "bootstrap"
                    ? await path.BootstrapAsync(fixture.Value, deadline.Token)
                    : await path.AssessAsync(scenario, deadline.Token);
                Require(result == Expected(workflow, scenario));
                return result;
            }

            long first = Stopwatch.GetTimestamp();
            SafeResult output = await Operation();
            first = Stopwatch.GetTimestamp() - first;
            Require(matched is null || matched == output);
            matched = output;
            for (int i = 0; i < warmups; i++)
                await Operation();
            var ticks = new long[samples];
            for (int i = 0; i < samples; i++)
            {
                long started = Stopwatch.GetTimestamp();
                await Operation();
                ticks[i] = Stopwatch.GetTimestamp() - started;
            }

            measurements.Add(new(path.Name, workflow, scenario, output, first, ticks));
        }
    }
}

// A fresh consumer check observes changed material without restarting the client.
fixture.Scenario = "ready";
foreach (IConsumerPath path in paths)
{
    string previous = fixture.Value;
    Require((await path.BootstrapAsync(previous, deadline.Token)).Ready);
    fixture.Rotate();
    Require(fixture.Value != previous);
    Require((await path.BootstrapAsync(fixture.Value, deadline.Token)).Ready);
}

// Validate pre-dispatch cancellation; no timing luck or network authentication.
using var canceled = new CancellationTokenSource();
canceled.Cancel();
foreach (IConsumerPath path in paths)
{
    bool propagated = false;
    try { await path.BootstrapAsync(fixture.Value, canceled.Token); }
    catch (OperationCanceledException) { propagated = true; }
    Require(propagated);
}

Console.WriteLine(JsonSerializer.Serialize(new
{
    Schema = 1,
    Evidence = "offline-only",
    Runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
    Platform = System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier,
    StopwatchFrequency = Stopwatch.Frequency,
    SetupElapsedTicks = setup.ElapsedTicks,
    WarmupsPerCell = warmups,
    SamplesPerCell = samples,
    Measurements = measurements,
    AzureWireRequests = fixture.AzureRequests,
    InfisicalWireRequests = wire.Requests,
    MatchedOutputs = true,
    FreshChecks = true,
    PreDispatchCancellation = true,
    LiveAdopterGate = "OPEN",
    HumanIntegrationHours = (double?)null,
    DiagnosisHours = (double?)null,
    ThirdAdapterHours = (double?)null,
    ExternalMaintainerAdoption = "UNKNOWN"
}, new JsonSerializerOptions { WriteIndented = true }));

static SafeResult Expected(string workflow, string scenario) => workflow == "bootstrap"
    ? new(scenario == "ready", scenario switch
    {
        "ready" => "Success",
        "absent" => "Absent",
        "denied" => "Denied",
        _ => "Unavailable"
    }, 0)
    : new(scenario == "ready", scenario switch
    {
        "ready" => "Ready",
        "absent" => "Absent",
        "denied" => "Denied",
        "indirect" => "Indirect",
        _ => "Unverified"
    }, 2);

static void Require(bool condition)
{
    if (!condition)
        throw new InvalidOperationException("Offline baseline contract failed.");
}

namespace SecretKit.ConsumerBaseline
{
    internal sealed record SafeResult(bool Ready, string State, int AdminVisible);
    internal sealed record Measurement(string Path, string Workflow, string Scenario,
        SafeResult Output, long FirstInvocationTicks, long[] WarmSampleTicks);
}
