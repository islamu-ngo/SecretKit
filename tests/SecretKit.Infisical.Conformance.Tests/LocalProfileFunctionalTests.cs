using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using SecretKit.Core;

namespace SecretKit.Infisical.Conformance.Tests;

// Live only: authority and protected inputs remain admitted by the existing host.
public sealed class LocalProfileFunctionalTests
{
    [Test]
    public async Task InstalledOwnedLocalProfileHasRequiredFunctionalObservations()
    {
        string root = RequiredPath("SECRETKIT_LOCAL_SOURCE");
        string originals = RequiredPath("SECRETKIT_LOCAL_ORIGINALS");
        string records = RequiredPath("SECRETKIT_LOCAL_RECORD");
        LocalNativeBinding expected = LocalProfileConformance.Freeze(root, originals, records);
        LocalNativeReport report = await LocalProfileConformance.RunFromEnvironmentAsync();
        // RunFromEnvironmentAsync returns only after its owned-resource cleanup.
        NativeWorkflow.Require(LocalProfileConformance.SameBinding(expected,
            LocalProfileConformance.Freeze(root, originals, records)));
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, expected)).IsTrue();
    }

    private static string RequiredPath(string name)
    {
        string value = Environment.GetEnvironmentVariable(name) is { Length: > 0 } selected ?
            selected : throw new InvalidOperationException("local-native-authority-or-input-missing");
        NativeWorkflow.Require(Path.IsPathFullyQualified(value));
        return value;
    }
}

public sealed class LocalProfileUpdateWitnessTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RevisionAdvanceRequiresObservedReplacementValue(bool retainCreatedValue)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var origin = new Uri($"http://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}/");
        var request = LocalProfileAdmissionTests.Request();
        request["settings"]!["origin"] = origin.AbsoluteUri;
        request["settings"]!["authentication"] = null;
        LocalNativeInput input = NativeWorkflow.Parse(JsonSerializer.SerializeToUtf8Bytes(request, NativeWorkflow.JsonOptions));
        LocalNativeSettings settings = input.Settings;
        LocalNativeReport report = NativeWorkflow.EmptyReport(input);
        string createdValue = "";
        string currentValue = "";
        int writtenVersion = 1;
        Task serving = ServeAsync();
        try
        {
            await NativeWorkflow.ExecuteAsync(input, report, deadline.Token, () => Task.CompletedTask);
            await Assert.That(report.Cases.Single(c => c.Id == "create").Status).IsEqualTo("passed");
            await Assert.That(report.Cases.Single(c => c.Id == "update-value").Status)
                .IsEqualTo(retainCreatedValue ? "failed" : "passed");
        }
        finally
        {
            await deadline.CancelAsync();
            listener.Stop();
            try { await serving; }
            catch (OperationCanceledException) when (deadline.IsCancellationRequested) { }
            catch (SocketException) when (deadline.IsCancellationRequested) { }
        }

        async Task ServeAsync()
        {
            while (!deadline.IsCancellationRequested)
            {
                using TcpClient connection = await listener.AcceptTcpClientAsync(deadline.Token);
                await using NetworkStream stream = connection.GetStream();
                using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
                string[] line = (await reader.ReadLineAsync(deadline.Token))!.Split(' ');
                var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                while (await reader.ReadLineAsync(deadline.Token) is { Length: > 0 } header)
                {
                    string[] pair = header.Split(':', 2);
                    headers.Add(pair[0], pair[1].Trim());
                }
                int length = headers.TryGetValue("Content-Length", out string? size) ? int.Parse(size) : 0;
                char[] body = new char[length];
                if (length > 0) await reader.ReadBlockAsync(body.AsMemory(), deadline.Token);
                string path = new Uri(origin, line[1]).AbsolutePath;
                bool writeKey = path.EndsWith(settings.WriteKey, StringComparison.Ordinal);
                bool denied = headers.GetValueOrDefault("Authorization") == "Bearer " + settings.Denied.Token ||
                    line[0] == "PATCH" &&
                    headers.GetValueOrDefault("Authorization") == "Bearer " + settings.Runtime.Token;
                int status = denied ? 403 : 200;
                if (!denied && line[0] is "POST" or "PATCH")
                {
                    using JsonDocument change = JsonDocument.Parse(new string(body));
                    string replacement = change.RootElement.GetProperty("secretValue").GetString()!;
                    if (line[0] == "POST") createdValue = currentValue = replacement;
                    else
                    {
                        writtenVersion++;
                        currentValue = retainCreatedValue ? createdValue : replacement;
                    }
                }
                object Secret(string key, string value, int version) => new
                {
                    id = key,
                    workspace = settings.ProjectId,
                    environment = settings.Environment,
                    secretPath = settings.Folder,
                    type = "shared",
                    secretKey = key,
                    version,
                    secretValue = value,
                    secretValueHidden = false
                };
                object response = denied ? new { } :
                    path == "/api/v4/secrets"
                        ? new { secrets = new[] { Secret(settings.ReadKey, "existing-value", 1) } }
                        : new
                        {
                            secret = Secret(writeKey ? settings.WriteKey : settings.ReadKey,
                                writeKey ? currentValue : "existing-value", writeKey ? writtenVersion : 1)
                        };
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(response);
                await stream.WriteAsync(Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {bytes.Length}\r\nConnection: close\r\n\r\n"), deadline.Token);
                await stream.WriteAsync(bytes, deadline.Token);
            }
        }
    }
}

public sealed class LocalProfileFunctionalAdmissionTests
{
    // Independent plan oracles: do not obtain IDs, reasons or expected bytes from
    // the acceptance helper, NativeWorkflow.CaseIds, or the report being checked.
    private static LocalNativeBinding Expected => new("0.1.0-local.20261024.1",
        new string('a', 64), new string('b', 64), new string('c', 64),
        [
            new("SecretKit.Core", new string('d', 64)),
            new("SecretKit.Infisical", new string('e', 64)),
            new("SecretKit.Extensions.Configuration", new string('f', 64)),
            new("SecretKit.Extensions.Hosting", new string('0', 64))
        ]);

    private static LocalNativeReport SuccessfulReport() =>
        new(1, "local-native-observation-not-public-approval", Expected, "0.166.3", "v4", "oss", "linux-x64",
        [
            new("read", "passed", "observed"),
            new("read-native", "passed", "observed"),
            new("inspect", "passed", "observed"),
            new("repeat-revision", "passed", "observed"),
            new("selected-revision", "passed", "observed"),
            new("denied-read", "passed", "observed"),
            new("runtime-write-denied", "passed", "observed"),
            new("create", "passed", "observed"),
            new("update-value", "passed", "observed"),
            new("pending-approval", "unavailable", "not-observed"),
            new("recreation", "passed", "observed"),
            new("universal-login", "passed", "observed"),
            new("get-token", "passed", "observed"),
            new("renew-token", "passed", "observed"),
            new("expired-token", "passed", "observed"),
            new("explicit-recovery", "passed", "observed"),
            new("network", "passed", "selected-origin-system-trust-and-proxy"),
            new("cleanup", "passed", "owned-resource-cleanup"),
            new("deployment-binding", "unavailable", "authoritative-proof-unavailable"),
            new("actor-binding", "unavailable", "authoritative-proof-unavailable"),
            new("policy-binding", "unavailable", "authoritative-proof-unavailable")
        ])
        { CreateEffect = DispatchEvidence.Applied };

    [Test]
    public async Task FunctionalSuccessRetainsCompleteUnqualifiedReport()
    {
        LocalNativeReport report = SuccessfulReport();
        string before = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsTrue();
        await Assert.That(report.Cases.Length).IsEqualTo(21);
        await Assert.That(report.Cases.Count(c => c.Status == "passed")).IsEqualTo(17);
        await Assert.That(report.Cases.All(c => c.Status == "passed")).IsFalse();
        await Assert.That(report.Kind).IsEqualTo("local-native-observation-not-public-approval");
        await Assert.That(JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions)).IsEqualTo(before);
    }

    [Test]
    [Arguments("read")]
    [Arguments("read-native")]
    [Arguments("inspect")]
    [Arguments("repeat-revision")]
    [Arguments("selected-revision")]
    [Arguments("denied-read")]
    [Arguments("runtime-write-denied")]
    [Arguments("create")]
    [Arguments("update-value")]
    [Arguments("recreation")]
    [Arguments("universal-login")]
    [Arguments("get-token")]
    [Arguments("renew-token")]
    [Arguments("expired-token")]
    [Arguments("explicit-recovery")]
    [Arguments("network")]
    [Arguments("cleanup")]
    public async Task EveryRequiredCaseMustPass(string id)
    {
        foreach (string status in new[] { "failed", "unavailable" })
        {
            LocalNativeReport report = SuccessfulReport();
            int index = Array.FindIndex(report.Cases, c => c.Id == id);
            report.Cases[index] = report.Cases[index] with { Status = status };
            LocalProfileConformance.ValidateReport(report, Expected);
            await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
        }
    }

    [Test]
    [Arguments(DispatchEvidence.NotDispatched)]
    [Arguments(DispatchEvidence.PossiblyDispatched)]
    [Arguments(DispatchEvidence.Pending)]
    [Arguments(DispatchEvidence.Rejected)]
    [Arguments(DispatchEvidence.Conflict)]
    public async Task PassedStatusesCannotReplaceAppliedCreateEvidence(DispatchEvidence effect)
    {
        LocalNativeReport report = SuccessfulReport();
        report.CreateEffect = effect;
        LocalProfileConformance.ValidateReport(report, Expected);
        await Assert.That(report.Cases.Count(c => c.Status == "passed")).IsEqualTo(17);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
    }

    [Test]
    public async Task PassedCleanupWithoutObservedRemovalCannotSucceed()
    {
        LocalNativeReport report = SuccessfulReport();
        report.Cases[17] = new("cleanup", "passed", "not-observed");
        LocalProfileConformance.ValidateReport(report, Expected);
        await Assert.That(report.Cases.Count(c => c.Status == "passed")).IsEqualTo(17);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
    }

    [Test]
    [Arguments("read", "observed")]
    [Arguments("read-native", "observed")]
    [Arguments("inspect", "observed")]
    [Arguments("repeat-revision", "observed")]
    [Arguments("selected-revision", "observed")]
    [Arguments("denied-read", "observed")]
    [Arguments("runtime-write-denied", "observed")]
    [Arguments("create", "observed")]
    [Arguments("update-value", "observed")]
    [Arguments("pending-approval", "not-observed")]
    [Arguments("recreation", "observed")]
    [Arguments("universal-login", "observed")]
    [Arguments("get-token", "observed")]
    [Arguments("renew-token", "observed")]
    [Arguments("expired-token", "observed")]
    [Arguments("explicit-recovery", "observed")]
    [Arguments("network", "selected-origin-system-trust-and-proxy")]
    [Arguments("cleanup", "owned-resource-cleanup")]
    [Arguments("deployment-binding", "authoritative-proof-unavailable")]
    [Arguments("actor-binding", "authoritative-proof-unavailable")]
    [Arguments("policy-binding", "authoritative-proof-unavailable")]
    public async Task KnownReasonInWrongCaseIsNotEvidence(string id, string expectedReason)
    {
        string[] reasons = ["not-observed", "observed", "deadline-or-cancellation",
            "observation-unavailable", "execution-incomplete", "selected-origin-system-trust-and-proxy",
            "owned-resource-cleanup", "cleanup-unconfirmed", "authoritative-proof-unavailable"];
        foreach (string reason in reasons.Where(r => r != expectedReason))
        {
            LocalNativeReport report = SuccessfulReport();
            int index = Array.FindIndex(report.Cases, c => c.Id == id);
            report.Cases[index] = report.Cases[index] with { Reason = reason };
            LocalProfileConformance.ValidateReport(report, Expected);
            await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
        }
    }

    [Test]
    [Arguments("passed")]
    [Arguments("failed")]
    public async Task NoApprovalPilotCannotInventAnApprovalObservation(string status)
    {
        LocalNativeReport report = SuccessfulReport();
        report.Cases[9] = new("pending-approval", status, "observed");
        LocalProfileConformance.ValidateReport(report, Expected);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
    }

    [Test]
    [Arguments("deployment-binding")]
    [Arguments("actor-binding")]
    [Arguments("policy-binding")]
    public async Task BindingProofCannotBePromotedToPassed(string id)
    {
        LocalNativeReport report = SuccessfulReport();
        int index = Array.FindIndex(report.Cases, c => c.Id == id);
        report.Cases[index] = new(id, "passed", "observed");
        await Assert.That(() => LocalProfileFunctionalAcceptance.Accepts(report, Expected))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("version")]
    [Arguments("profile")]
    [Arguments("source")]
    [Arguments("record")]
    [Arguments("core")]
    [Arguments("infisical")]
    [Arguments("configuration")]
    [Arguments("hosting")]
    [Arguments("missing-package")]
    [Arguments("duplicate-package")]
    [Arguments("foreign-package")]
    public async Task ReportCannotSubstituteIndependentlyExpectedArtifacts(string fault)
    {
        LocalNativeReport report = SuccessfulReport() with { Binding = AlterBinding(Expected, fault) };
        await Assert.That(() => LocalProfileFunctionalAcceptance.Accepts(report, Expected))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("version")]
    [Arguments("profile")]
    [Arguments("source")]
    [Arguments("record")]
    [Arguments("core")]
    [Arguments("infisical")]
    [Arguments("configuration")]
    [Arguments("hosting")]
    public async Task DifferentIndependentExpectationRejectsOtherwiseSuccessfulReport(string fault)
    {
        await Assert.That(() => LocalProfileFunctionalAcceptance.Accepts(
            SuccessfulReport(), AlterBinding(Expected, fault))).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("version")]
    [Arguments("missing-package")]
    [Arguments("duplicate-package")]
    [Arguments("foreign-package")]
    [Arguments("invalid-hash")]
    public async Task SharedMalformedBindingDoesNotValidateItself(string fault)
    {
        LocalNativeBinding invalid = AlterBinding(Expected, fault);
        LocalNativeReport report = SuccessfulReport() with { Binding = AlterBinding(Expected, fault) };
        await Assert.That(() => LocalProfileFunctionalAcceptance.Accepts(report, invalid))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PackageOrderDoesNotChangeArtifactIdentity()
    {
        LocalNativeReport report = SuccessfulReport();
        Array.Reverse(report.Binding.Packages);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsTrue();
    }

    [Test]
    [Arguments("missing")]
    [Arguments("duplicate")]
    [Arguments("unknown")]
    [Arguments("reordered")]
    [Arguments("schema")]
    [Arguments("native-promotion")]
    [Arguments("release-promotion")]
    [Arguments("public-promotion")]
    [Arguments("unknown-status")]
    [Arguments("undefined-effect")]
    [Arguments("raw-diagnostic")]
    [Arguments("material-canary")]
    public async Task InvalidEvidenceFailsWithBoundedDiagnostics(string fault)
    {
        const string canary = "protected-material-canary";
        LocalNativeReport report = SuccessfulReport();
        report = fault switch
        {
            "missing" => report with { Cases = report.Cases[..^1] },
            "duplicate" => report with { Cases = [report.Cases[0], .. report.Cases[..^1]] },
            "unknown" => report with { Cases = [new("unknown", "passed", "observed"), .. report.Cases[1..]] },
            "reordered" => report with { Cases = [report.Cases[1], report.Cases[0], .. report.Cases[2..]] },
            "schema" => report with { SchemaVersion = 2 },
            "native-promotion" => report with { Kind = "complete-live" },
            "release-promotion" => report with { Kind = "release-observation" },
            "public-promotion" => report with { Kind = "public-approval" },
            "raw-diagnostic" => report with { Cases = [new("read", "passed", canary), .. report.Cases[1..]] },
            "material-canary" => report with { DeclaredServerVersion = canary },
            "unknown-status" => report with { Cases = [new("read", canary, "observed"), .. report.Cases[1..]] },
            "undefined-effect" => report,
            _ => throw new InvalidOperationException()
        };
        if (fault == "undefined-effect") report.CreateEffect = (DispatchEvidence)int.MaxValue;
        InvalidOperationException? rejection = null;
        try { _ = LocalProfileFunctionalAcceptance.Accepts(report, Expected); }
        catch (InvalidOperationException error) { rejection = error; }
        await Assert.That(rejection is not null).IsTrue();
        await Assert.That(rejection!.Message).IsEqualTo("local-native-contract");
        await Assert.That(rejection.ToString().Contains(canary, StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task IncompleteReportRemainsValidEvidenceButNotFunctionalSuccess()
    {
        LocalNativeReport report = SuccessfulReport() with
        {
            Cases = SuccessfulReport().Cases.Select(c => c with { Status = "unavailable" }).ToArray()
        };
        report.CreateEffect = DispatchEvidence.NotDispatched;
        LocalProfileConformance.ValidateReport(report, Expected);
        await Assert.That(LocalProfileFunctionalAcceptance.Accepts(report, Expected)).IsFalse();
    }

    private static LocalNativeBinding AlterBinding(LocalNativeBinding binding, string fault)
    {
        string changed = new('1', 64);
        switch (fault)
        {
            case "version": return binding with { Version = "0.1.0-local.20261023.2" };
            case "profile": return binding with { ProfileSha256 = changed };
            case "source": return binding with { SourceSha256 = changed };
            case "record": return binding with { RecordSha256 = changed };
            case "invalid-hash": return binding with { ProfileSha256 = "not-a-hash" };
            case "missing-package": return binding with { Packages = binding.Packages[..^1] };
            case "duplicate-package":
                return binding with { Packages = [binding.Packages[0], .. binding.Packages[..^1]] };
            case "foreign-package":
                binding.Packages[0] = new("SecretKit.AzureKeyVault", changed);
                return binding;
            default:
                int index = fault switch
                {
                    "core" => 0,
                    "infisical" => 1,
                    "configuration" => 2,
                    "hosting" => 3,
                    _ => throw new InvalidOperationException()
                };
                binding.Packages[index] = binding.Packages[index] with { Sha256 = changed };
                return binding;
        }
    }
}
