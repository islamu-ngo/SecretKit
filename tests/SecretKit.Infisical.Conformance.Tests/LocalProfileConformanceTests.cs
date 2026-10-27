using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SecretKit.Core;
using SecretKit.Release;

namespace SecretKit.Infisical.Conformance.Tests;

// Never select this class for an offline run. Missing authority is a failure, not a skip.
public sealed class LocalProfileConformanceTests
{
    [Test]
    public async Task InstalledOwnedLocalProfileHasEveryNativeObservation()
    {
        LocalNativeReport report = await LocalProfileConformance.RunCausalFromEnvironmentAsync();
        await Assert.That(report.Cases.Length).IsEqualTo(21);
        await Assert.That(report.Cases.All(c => c.Status == "passed")).IsTrue();
        await Assert.That(report.SupplementalCases.Length).IsEqualTo(6);
        await Assert.That(report.SupplementalCases.All(c => c.Status == "passed")).IsTrue();
        await Assert.That(report.ProducerCleanup.Status).IsEqualTo("complete");
        await Assert.That(report.CreateEffect).IsEqualTo(DispatchEvidence.Applied);
    }
}

public sealed class LocalProfileAdmissionTests
{
    internal static LocalNativeBinding Binding => new("0.1.0-local.20261024.1",
        new string('a', 64), new string('b', 64), new string('c', 64),
        LocalQualification.PackageIds.Select(id => new LocalNativePackage(id, new string('d', 64))).ToArray());

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ConfirmedCreateSurvivesFailedWitnessAndInterruption(bool interrupted)
    {
        LocalNativeReport report = NativeWorkflow.EmptyReport(LocalProfileConformance.Admit(Bytes(Request()), Binding));
        var reference = new SecretReference(new SecretAuthority(), new InfisicalSecretAddress(
            "project", "environment", "/", "key"));
        var receipt = new MutationReceipt(reference);
        string? durable = null;
        int removals = 0;
        Task Persist()
        {
            durable = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
            return Task.CompletedTask;
        }
        try
        {
            await NativeWorkflow.CaptureCreateAsync(report, receipt, () =>
            {
                receipt.BeginDispatch(reference);
                receipt.Record(DispatchEvidence.Applied);
                return Task.FromResult(true);
            }, Persist);
            // The durable witness precedes any independent observer work.
            await Assert.That(JsonSerializer.Deserialize<LocalNativeReport>(durable!,
                NativeWorkflow.JsonOptions)!.CreateEffect).IsEqualTo(DispatchEvidence.Applied);
            int create = Array.IndexOf(NativeWorkflow.CaseIds, "create");
            report.Cases[create] = new("create", interrupted ? "unavailable" : "failed",
                interrupted ? "deadline-or-cancellation" : "observed");
            if (interrupted) throw new OperationCanceledException();
        }
        catch (OperationCanceledException) when (interrupted) { }
        finally
        {
            // The real host uses this same finalization after failed child/control execution.
            report = JsonSerializer.Deserialize<LocalNativeReport>(
                JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions), NativeWorkflow.JsonOptions)!;
            await LocalProfileConformance.ReconcileCleanupAsync(report, () =>
            {
                removals++;
                return Task.FromResult(true);
            }, Persist);
        }
        await Assert.That(removals).IsEqualTo(1);
        await Assert.That(report.CreateEffect).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(report.Cases.Single(c => c.Id == "create").Status)
            .IsEqualTo(interrupted ? "unavailable" : "failed");
        await Assert.That(report.Cases.Single(c => c.Id == "cleanup").Status).IsEqualTo("passed");
        LocalProfileConformance.ValidateReport(report, Binding);
    }

    [Test]
    [Arguments(DispatchEvidence.NotDispatched)]
    [Arguments(DispatchEvidence.PossiblyDispatched)]
    [Arguments(DispatchEvidence.Pending)]
    [Arguments(DispatchEvidence.Rejected)]
    [Arguments(DispatchEvidence.Conflict)]
    public async Task UnacknowledgedCreateNeverGrantsCleanupAuthority(DispatchEvidence effect)
    {
        LocalNativeReport report = NativeWorkflow.EmptyReport(LocalProfileConformance.Admit(Bytes(Request()), Binding));
        report.CreateEffect = effect;
        int removals = 0;
        bool persisted = false;
        await LocalProfileConformance.ReconcileCleanupAsync(report, () =>
        {
            removals++;
            return Task.FromResult(true);
        }, () => { persisted = true; return Task.CompletedTask; });
        await Assert.That(removals).IsEqualTo(0);
        await Assert.That(persisted).IsTrue();
        await Assert.That(report.CreateEffect).IsEqualTo(effect);
        await Assert.That(report.Cases.Single(c => c.Id == "cleanup").Status).IsEqualTo("unavailable");
    }

    [Test]
    public async Task CleanupFailureRetainsAppliedEffectAndPersistsUncertainty()
    {
        LocalNativeReport report = NativeWorkflow.EmptyReport(LocalProfileConformance.Admit(Bytes(Request()), Binding));
        report.CreateEffect = DispatchEvidence.Applied;
        bool persisted = false;
        await LocalProfileConformance.ReconcileCleanupAsync(report,
            () => throw new OperationCanceledException(),
            () => { persisted = true; return Task.CompletedTask; });
        await Assert.That(persisted).IsTrue();
        await Assert.That(report.CreateEffect).IsEqualTo(DispatchEvidence.Applied);
        await Assert.That(report.Cases.Single(c => c.Id == "cleanup").Reason).IsEqualTo("cleanup-unconfirmed");
    }

    [Test]
    public async Task ExplicitLocalSelectionKeepsFiveIndependentOwnedActors()
    {
        LocalNativeInput input = LocalProfileConformance.Admit(Bytes(Request()), Binding);
        await Assert.That(input.Settings.Runtime.Id).IsEqualTo("10000000-0000-0000-0000-000000000002");
        await Assert.That(input.Settings.Denied.Id).IsEqualTo("10000000-0000-0000-0000-000000000003");
        await Assert.That(input.Settings.Folder).IsEqualTo("/secretkit-sdk-12345678");
        await Assert.That(LocalProfileConformance.SameBinding(input.Binding, Binding)).IsTrue();
    }

    [Test]
    public async Task ExplicitHostReadTransportAdmitsDeliberatePolicyWithoutCredentialUse()
    {
        using var tokens = new LocalNativeTokens("offline-token-canary");
        using var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ActivityHeadersPropagator = null,
            SslOptions = new() { RemoteCertificateValidationCallback = (_, _, _, _) => true }
        };
        tokens.Dispose();
        await using var client = new InfisicalClient(new Uri("https://provider.invalid"), tokens,
            new() { Transport = InfisicalTransportOptions.HostControlled(handler) });
        await Assert.That(client.Authority).IsNotNull();
    }

    [Test]
    [Arguments("authority")]
    [Arguments("profile")]
    [Arguments("schema")]
    [Arguments("public-mode")]
    [Arguments("unknown")]
    [Arguments("credential-alias")]
    [Arguments("actor-alias")]
    [Arguments("blank-token")]
    [Arguments("token-control")]
    [Arguments("foreign-folder")]
    [Arguments("traversal")]
    [Arguments("foreign-key")]
    [Arguments("duplicate-key")]
    [Arguments("owner")]
    [Arguments("organization")]
    [Arguments("project")]
    [Arguments("origin-path")]
    [Arguments("origin-user")]
    [Arguments("remote-http")]
    [Arguments("localhost")]
    [Arguments("tls-bypass")]
    [Arguments("zero-version")]
    [Arguments("null-actor")]
    [Arguments("auth-actor")]
    [Arguments("periodic-inference")]
    [Arguments("periodic-without-period")]
    [Arguments("recovery-replay")]
    public async Task InvalidInputsFailBeforeAnyDispatch(string fault)
    {
        JsonObject request = Request();
        JsonNode settings = request["settings"]!;
        switch (fault)
        {
            case "authority": request["authority"] = "not-authorized"; break;
            case "profile": request["profileId"] = "complete-live"; break;
            case "schema": request["schemaVersion"] = 2; break;
            case "public-mode": request["kind"] = "release-observation"; break;
            case "unknown": request["publisher"] = "not-authority"; break;
            case "credential-alias": settings["denied"]!["token"] = settings["runtime"]!["token"]!.DeepClone(); break;
            case "actor-alias": settings["observer"]!["id"] = settings["runtime"]!["id"]!.DeepClone(); break;
            case "blank-token": settings["writer"]!["token"] = ""; break;
            case "token-control": settings["runtime"]!["token"] = "canary\n"; break;
            case "foreign-folder": settings["folder"] = "/production"; break;
            case "traversal": settings["folder"] = "/secretkit-sdk-12345678/../production"; break;
            case "foreign-key": settings["readKey"] = "FOREIGN"; break;
            case "duplicate-key": settings["writeKey"] = settings["readKey"]!.DeepClone(); break;
            case "owner": settings["owner"] = "secretkit-sdk-1234567z"; break;
            case "organization": settings["organizationId"] = "not-generated"; break;
            case "project": settings["projectId"] = "not-generated"; break;
            case "origin-path": settings["origin"] = "https://provider.invalid/secrets"; break;
            case "origin-user": settings["origin"] = "https://user:credential@provider.invalid"; break;
            case "remote-http": settings["origin"] = "http://provider.invalid:12345"; break;
            case "localhost": settings["origin"] = "http://localhost:12345"; break;
            case "tls-bypass": settings["allowInvalidCertificates"] = true; break;
            case "zero-version": settings["selectedVersion"] = 0; break;
            case "null-actor": settings["runtime"] = null; break;
            case "auth-actor":
                settings["authentication"]!["actorId"] = settings["writer"]!["id"]!.DeepClone(); break;
            case "periodic-inference": settings["authentication"]!["periodic"] = true; break;
            case "periodic-without-period": settings["authentication"]!["lifetime"] = "periodic"; break;
            case "recovery-replay":
                settings["authentication"]!["recoveryClientSecret"] = settings["authentication"]!["clientSecret"]!.DeepClone();
                break;
            default: throw new InvalidOperationException();
        }
        await Assert.That(() => LocalProfileConformance.Admit(Bytes(request), Binding))
            .Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("profileSha256")]
    [Arguments("sourceSha256")]
    [Arguments("recordSha256")]
    [Arguments("version")]
    [Arguments("package-hash")]
    [Arguments("package-family")]
    [Arguments("package-duplicate")]
    public async Task LaunchMustMatchEveryFrozenWitness(string fault)
    {
        JsonObject request = Request();
        JsonNode binding = request["binding"]!;
        switch (fault)
        {
            case "package-hash": binding["packages"]![0]!["sha256"] = new string('e', 64); break;
            case "package-family": binding["packages"]![0]!["id"] = "SecretKit.AzureKeyVault"; break;
            case "package-duplicate":
                binding["packages"]![1]!["id"] = binding["packages"]![0]!["id"]!.DeepClone(); break;
            case "version": binding["version"] = "0.2.0"; break;
            default: binding[fault] = new string('e', 64); break;
        }
        await Assert.That(() => LocalProfileConformance.Admit(Bytes(request), Binding))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task DuplicatePropertiesAndOversizedInputsAreRejectedWithoutProtectedDiagnostics()
    {
        string json = Encoding.UTF8.GetString(Bytes(Request()));
        byte[] duplicate = Encoding.UTF8.GetBytes(json.Replace("\"schemaVersion\":1",
            "\"schemaVersion\":1,\"schemaVersion\":1", StringComparison.Ordinal));
        await Assert.That(() => NativeWorkflow.Parse(duplicate)).Throws<InvalidOperationException>();
        await Assert.That(() => NativeWorkflow.Parse(new byte[131073])).Throws<InvalidOperationException>();
        await using var stream = new MemoryStream(new byte[131073]);
        await Assert.That(async () => await NativeWorkflow.ReadBoundedAsync(stream, CancellationToken.None))
            .Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ProtectedInputRejectsLinksAndSharedUnixPermissions()
    {
        string directory = Path.Combine(Path.GetTempPath(), "secretkit-p7-input-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string input = Path.Combine(directory, "input.json");
        try
        {
            File.WriteAllBytes(input, Bytes(Request()));
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(input, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                await Assert.That(LocalProfileConformance.ReadProtectedInput(input).Length > 0).IsTrue();
                File.SetUnixFileMode(input, UnixFileMode.UserRead | UnixFileMode.GroupRead);
                await Assert.That(() => LocalProfileConformance.ReadProtectedInput(input)).Throws<InvalidOperationException>();
                File.SetUnixFileMode(input, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                string link = Path.Combine(directory, "link.json");
                File.CreateSymbolicLink(link, input);
                await Assert.That(() => LocalProfileConformance.ReadProtectedInput(link)).Throws<Exception>();
            }
            await Assert.That(() => LocalProfileConformance.ReadProtectedInput("relative.json"))
                .Throws<InvalidOperationException>();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    public async Task AdmissionAndPreDispatchReportNeverExportProtectedInputs()
    {
        LocalNativeInput input = LocalProfileConformance.Admit(Bytes(Request()), Binding);
        LocalNativeReport report = NativeWorkflow.EmptyReport(input);
        LocalProfileConformance.ValidateReport(report, Binding);
        await Assert.That(JsonSerializer.Serialize(input, NativeWorkflow.JsonOptions)).IsEqualTo("{}");
        string serialized = JsonSerializer.Serialize(report, NativeWorkflow.JsonOptions);
        foreach (string canary in new[] { "secretkit-sdk-12345678", "SDK_12345678_READ", "bootstrap-canary",
            "runtime-token-canary", "provider.invalid", "sensitive-environment", input.Settings.ProjectId })
            await Assert.That(serialized.Contains(canary, StringComparison.Ordinal)).IsFalse();
        await Assert.That(report.Cases.Length).IsEqualTo(21);
        await Assert.That(report.Cases.All(c => c.Status == "unavailable")).IsTrue();
    }

    [Test]
    [Arguments("missing-case")]
    [Arguments("duplicate-case")]
    [Arguments("invented-success")]
    [Arguments("raw-diagnostic")]
    [Arguments("stale-binding")]
    [Arguments("protected-metadata")]
    [Arguments("unproven-actor-binding")]
    public async Task ReportsCannotHideUnavailableCasesOrIntroduceDiagnostics(string fault)
    {
        LocalNativeReport report = NativeWorkflow.EmptyReport(LocalProfileConformance.Admit(Bytes(Request()), Binding));
        report = fault switch
        {
            "missing-case" => report with { Cases = report.Cases[1..] },
            "duplicate-case" => report with { Cases = [report.Cases[0], .. report.Cases[..^1]] },
            "invented-success" => report with { Cases = report.Cases.Select(c => c with { Status = "mock-pass" }).ToArray() },
            "raw-diagnostic" => report with { Cases = report.Cases.Select(c => c with { Reason = "credential-canary" }).ToArray() },
            "stale-binding" => report with { Binding = Binding with { SourceSha256 = new string('e', 64) } },
            "protected-metadata" => report with { DeclaredServerVersion = "credential-canary" },
            "unproven-actor-binding" => report with
            {
                Cases = report.Cases.Select(c => c.Id == "actor-binding" ? c with { Status = "passed" } : c).ToArray()
            },
            _ => throw new InvalidOperationException()
        };
        await Assert.That(() => LocalProfileConformance.ValidateReport(report, Binding)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("source")]
    [Arguments("profile")]
    [Arguments("original")]
    [Arguments("record")]
    public async Task FrozenLaunchReopensActualSourceProfileOriginalAndRecordBytes(string fault)
    {
        using var fixture = new FrozenFixture();
        LocalNativeBinding before = LocalProfileConformance.Freeze(fixture.Source, fixture.Originals, fixture.Record);
        string path = fault switch
        {
            "source" => Path.Combine(fixture.Source, "input.cs"),
            "profile" => Path.Combine(fixture.Source, "docs/internal/local/infisical-runtime.json"),
            "original" => Path.Combine(fixture.Originals, $"SecretKit.Core.{before.Version}.nupkg"),
            "record" => Path.Combine(fixture.Record, LocalQualification.RecordFile),
            _ => throw new InvalidOperationException()
        };
        File.AppendAllText(path, "changed-bytes");
        await Assert.That(() => LocalProfileConformance.Freeze(fixture.Source, fixture.Originals, fixture.Record))
            .Throws<Exception>();
    }

    private static byte[] Bytes(JsonObject request) => JsonSerializer.SerializeToUtf8Bytes(request, NativeWorkflow.JsonOptions);
    internal static JsonObject Request()
    {
        LocalNativeActor Actor(int id, string role) => new($"10000000-0000-0000-0000-{id:D12}", role + "-token-canary");
        var settings = new LocalNativeSettings("http://127.0.0.1:12345", true, "secretkit-sdk-12345678",
            "20000000-0000-0000-0000-000000000001", "30000000-0000-0000-0000-000000000001",
            "sensitive-environment", "/secretkit-sdk-12345678", "SDK_12345678_READ", "SDK_12345678_WRITE",
            null, 1, "0.166.3", "oss", false, Actor(1, "setup"), Actor(2, "runtime"), Actor(3, "denied"),
            Actor(4, "writer"), Actor(5, "observer"), new("10000000-0000-0000-0000-000000000002",
                "client-canary", "bootstrap-canary", new string('f', 64), "finite", null, null, false));
        return JsonSerializer.SerializeToNode(new LocalNativeWire(1, "local-native-run", "infisical-runtime",
            "owned-local-native-execution", Binding, JsonSerializer.SerializeToElement(settings, NativeWorkflow.JsonOptions)),
            NativeWorkflow.JsonOptions)!.AsObject();
    }

    private sealed class FrozenFixture : IDisposable
    {
        private readonly string root = Path.Combine(Path.GetTempPath(), "secretkit-p7-" + Guid.NewGuid().ToString("N"));
        internal string Source => Path.Combine(root, "source");
        internal string Originals => Path.Combine(root, "originals");
        internal string Record => Path.Combine(root, "record");
        internal FrozenFixture()
        {
            string profile = Path.Combine(Source, "docs/internal/local/infisical-runtime.json");
            Directory.CreateDirectory(Path.GetDirectoryName(profile)!);
            Directory.CreateDirectory(Originals);
            DirectoryInfo? checkout = new(AppContext.BaseDirectory);
            while (checkout is not null && !File.Exists(Path.Combine(checkout.FullName, "SecretKit.slnx")))
                checkout = checkout.Parent;
            File.Copy(Path.Combine(checkout!.FullName, "docs/internal/local/infisical-runtime.json"), profile);
            File.WriteAllText(Path.Combine(Source, "input.cs"), "controlled source");
            File.WriteAllText(Path.Combine(Source, "THIRD-PARTY-NOTICES.md"), "controlled notices");
            foreach (string id in LocalQualification.PackageIds)
            {
                string[] dependencies = id switch
                {
                    "SecretKit.Core" => [],
                    "SecretKit.Infisical" => ["SecretKit.Core", "Refit"],
                    "SecretKit.Extensions.Configuration" => ["SecretKit.Core", "Microsoft.Extensions.Configuration"],
                    _ => ["SecretKit.Core", "SecretKit.Infisical", "Microsoft.Extensions.Hosting.Abstractions",
                        "Microsoft.Extensions.Diagnostics.HealthChecks.Abstractions"]
                };
                string entries = string.Concat(dependencies.Select(d =>
                    $"""<dependency id="{d}" version="{(d.StartsWith("SecretKit.", StringComparison.Ordinal) ? "[" + Binding.Version + "]" : "1.0.0")}" />"""));
                using var zip = ZipFile.Open(Path.Combine(Originals, $"{id}.{Binding.Version}.nupkg"), ZipArchiveMode.Create);
                Write(id + ".nuspec", $"""
                    <package><metadata><id>{id}</id><version>{Binding.Version}</version>
                    <license type="expression">MIT</license>
                    <repository type="git" url="{Manifest.Repository}" commit="{new string('a', 40)}"/>
                    <dependencies><group targetFramework="net10.0">{entries}</group></dependencies>
                    </metadata></package>
                    """);
                Write("README.md", "controlled");
                Write("THIRD-PARTY-NOTICES.md", "controlled notices");
                void Write(string name, string content)
                {
                    using var stream = new StreamWriter(zip.CreateEntry(name).Open());
                    stream.Write(content);
                }
            }
            _ = LocalQualification.Prepare(Source, Originals, Record);
        }
        public void Dispose() => Directory.Delete(root, recursive: true);
    }
}
