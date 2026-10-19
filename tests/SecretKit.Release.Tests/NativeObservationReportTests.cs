using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Release.Tests;

public sealed class NativeObservationReportTests
{
    private static readonly DateTimeOffset Started = new(2026, 10, 12, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Completed = Started.AddMinutes(1);

    private static (NativeRunRequest Request, NativeReportContext Context, NativeRunResult Result,
        InstallationObservation Installation) Fixture()
    {
        var selected = new NativeProviderScope("owned", "AzureKeyVault", "owned-deployment", "selected-api",
            "runtime", "observer", "setup", "denied", "administrative");
        var definition = new NativeCaseDefinition(new("AzureKeyVault", "read", "selected", "owned", "selected-contract"),
            "Client.ReadAsync(Input,CancellationToken)");
        var scope = new ReleaseScope("0.1.0-preview.1", new('a', 40), PackageCandidate.PackageIds,
            [new("AzureKeyVault", "read", "selected", "owned", "complete")],
            ["linux-x64-net10.0", "windows-x64-net10.0"],
            [new("azure-key-vault.json", new('b', 64)), new("infisical.json", new('c', 64))],
            "complete-live", [new(selected.Label, selected.Provider, selected.Deployment, selected.ApiVersion,
                selected.RuntimeIdentity, selected.ObserverIdentity, selected.SetupIdentity, selected.DeniedIdentity,
                selected.AdministrativeIdentity)]);
        var request = new NativeRunRequest("development-observation", "AzureKeyVault", "native-operations",
            "linux-x64-net10.0", scope.Version, scope.SourceCommit,
            Manifest.Hash(JsonSerializer.SerializeToUtf8Bytes(scope, Manifest.JsonOptions)),
            0, 0, 0, [selected], [definition], [new("AzureKeyVault", "owned", "backend-observer")]);
        PackageRecord[] packages = PackageCandidate.PackageIds.Select(id =>
            new PackageRecord(id, $"{id}.{scope.Version}.nupkg", new('d', 64))).ToArray();
        var context = new NativeReportContext(scope, packages, []);
        var result = new NativeRunResult(request.Provider, request.Kind, request.Platform, request.Version,
            request.SourceCommit, request.ScopeSha256, Started, Completed,
            [new("AzureKeyVault", "read", "selected", "owned", "selected-contract", true, true, "observed")],
            [new("AzureKeyVault", "owned", "backend-observer", true)], new("linux", "x64", "net10.0"));
        return (request, context, result, new("linux", "x64", "net10.0", 0, 0, true, "candidate-only"));
    }

    [Test]
    public async Task MeasuredCompletionCreatesCanonicalNonqualifyingDevelopmentReport()
    {
        var f = Fixture();
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context, f.Result, f.Installation,
            Started, Completed, 0);
        await Assert.That(report.SchemaVersion).IsEqualTo(2);
        await Assert.That(report.Discovered).IsEqualTo(1);
        await Assert.That(report.Failed).IsEqualTo(0);
        await Assert.That(report.ExitCode).IsEqualTo(0);
        await Assert.That(report.Purpose).IsEqualTo("development-observation");
        await Assert.That(report.RunId).IsEqualTo(0);
        await Assert.That(report.JobId).IsEqualTo(0);
        await Assert.That(report.NativeCases.Single().EffectObserved).IsTrue();
        await Assert.That(report.Checks.Single().Key).IsEqualTo(f.Context.Scope.NativeOperations.Single().Key);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report, Manifest.JsonOptions);
        await Assert.That(Manifest.Parse<MachineReport>(bytes).Installation).IsEqualTo(f.Installation);
    }

    [Test]
    [Arguments("provider")]
    [Arguments("variant")]
    [Arguments("scope")]
    [Arguments("source")]
    [Arguments("version")]
    [Arguments("duplicate")]
    public async Task SubstitutedChildBindingOrCaseFails(string change)
    {
        var f = Fixture();
        NativeRunResult result = change switch
        {
            "provider" => f.Result with { Provider = "Infisical" },
            "variant" => f.Result with { Cases = [f.Result.Cases[0] with { Variant = "substituted" }] },
            "scope" => f.Result with { Cases = [f.Result.Cases[0] with { Scope = "substituted" }] },
            "source" => f.Result with { SourceCommit = new('f', 40) },
            "version" => f.Result with { Version = "0.2.0" },
            _ => f.Result with { Cases = [f.Result.Cases[0], f.Result.Cases[0]] }
        };
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context, result, f.Installation,
            Started, Completed, 0);
        await Assert.That(report.Failed).IsEqualTo(1);
        await Assert.That(report.NativeCases.Single().ReasonCode).IsEqualTo("substituted-result");
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task MissingOutputOrUnfinishedRowFailsExpectedDenominator(bool missingOutput)
    {
        var f = Fixture();
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context,
            missingOutput ? null : f.Result with { Cases = [] }, f.Installation, Started, Completed, 0);
        await Assert.That(report.Discovered).IsEqualTo(1);
        await Assert.That(report.Failed).IsEqualTo(1);
        await Assert.That(report.NativeCases.Single().ReasonCode).IsEqualTo("incomplete-execution");
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task MissingOrUnconfirmedPrerequisiteCannotPass(bool missing)
    {
        var f = Fixture();
        var result = f.Result with
        {
            Prerequisites = missing ? [] : [f.Result.Prerequisites[0] with { Confirmed = false }]
        };
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context, result, f.Installation,
            Started, Completed, 0);
        await Assert.That(report.Failed).IsEqualTo(1);
        await Assert.That(report.Prerequisites.Single().Confirmed).IsFalse();
        await Assert.That(report.NativeCases.Single().ReasonCode).IsEqualTo("missing-prerequisite");
    }

    [Test]
    public async Task PrerequisiteCollectorStartsFalseAndRetainsObservedFailure()
    {
        var f = Fixture();
        var collector = new NativePrerequisiteObservations();
        await Assert.That(collector.Results(f.Request.Prerequisites).Single().Confirmed).IsFalse();
        collector.Confirm("AzureKeyVault", "owned", "backend-observer", NativeObservation.Matched);
        await Assert.That(collector.Results(f.Request.Prerequisites).Single().Confirmed).IsTrue();
        collector.Confirm("AzureKeyVault", "owned", "backend-observer", NativeObservation.Unavailable);
        collector.Confirm("AzureKeyVault", "owned", "backend-observer", NativeObservation.Matched);
        await Assert.That(collector.Results(f.Request.Prerequisites).Single().Confirmed).IsFalse();
    }

    [Test]
    [Arguments("process-exit")]
    [Arguments("deadline-exceeded")]
    [Arguments("unexpected-cancellation")]
    public async Task ProcessOutcomeInvalidatesSuccessfulChildRows(string failure)
    {
        var f = Fixture();
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context, f.Result,
            f.Installation with { ProcessExitCode = 7 }, Started, Completed, 7,
            failure == "process-exit" ? null : failure);
        await Assert.That(report.ExitCode).IsEqualTo(7);
        await Assert.That(report.Failed).IsEqualTo(1);
        await Assert.That(report.NativeCases.Single().ReasonCode).IsEqualTo(failure);
    }

    [Test]
    [Arguments("effect")]
    [Arguments("cleanup")]
    [Arguments("reason")]
    [Arguments("gap")]
    [Arguments("installation")]
    public async Task MissingEffectCleanupOrContractGapCannotPass(string change)
    {
        var f = Fixture();
        NativeRunResult result = change switch
        {
            "effect" => f.Result with { Cases = [f.Result.Cases[0] with { EffectObserved = false }] },
            "cleanup" => f.Result with
            { Cases = [f.Result.Cases[0] with { Passed = false, ReasonCode = "cleanup-incomplete" }] },
            "reason" => f.Result with { Cases = [f.Result.Cases[0] with { ReasonCode = "protected-raw-input" }] },
            _ => f.Result
        };
        MachineReport report = NativeObservationReport.Create(f.Request,
            change == "gap" ? f.Context with { ContractGaps = ["read"] } : f.Context, result,
            change == "installation" ? f.Installation with { ProjectReferences = 1 } : f.Installation,
            Started, Completed, 0);
        await Assert.That(report.Failed).IsEqualTo(1);
        if (change == "cleanup")
            await Assert.That(report.NativeCases.Single().ReasonCode).IsEqualTo("cleanup-incomplete");
        await Assert.That(JsonSerializer.Serialize(report).Contains("protected-raw-input", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    [Arguments("setup")]
    [Arguments("runtime")]
    [Arguments("denied")]
    [Arguments("administrative")]
    [Arguments("observer")]
    [Arguments("duplicate")]
    public async Task EveryDistinctRoleLabelIsRequired(string role)
    {
        var f = Fixture();
        NativeProviderScope scope = role switch
        {
            "setup" => f.Request.Scopes[0] with { SetupIdentity = "" },
            "runtime" => f.Request.Scopes[0] with { RuntimeIdentity = "" },
            "denied" => f.Request.Scopes[0] with { DeniedIdentity = "" },
            "administrative" => f.Request.Scopes[0] with { AdministrativeIdentity = "" },
            "observer" => f.Request.Scopes[0] with { ObserverIdentity = "" },
            _ => f.Request.Scopes[0] with { ObserverIdentity = "runtime" }
        };
        await Assert.That(() => (f.Request with { Scopes = [scope] }).Validate()).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task ReleasePurposeRequiresRealProducerIdentifiers()
    {
        var f = Fixture();
        await Assert.That(() => (f.Request with { Purpose = "release-observation" }).Validate())
            .Throws<InvalidOperationException>();
        await Assert.That(() => (f.Request with { RunId = 1 }).Validate()).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments(6)]
    [Arguments(8)]
    public async Task IncorrectOriginalPackageCountIsRejected(int count)
    {
        var f = Fixture();
        PackageRecord[] packages = count == 6 ? f.Context.Packages[..6] :
            [.. f.Context.Packages, f.Context.Packages[0]];
        await Assert.That(() => NativeObservationReport.Create(f.Request, f.Context with { Packages = packages },
            f.Result, f.Installation, Started, Completed, 0)).Throws<InvalidOperationException>();
    }

    [Test]
    public async Task PrivateSettingsSerializeOnlyInStdinEnvelope()
    {
        var f = Fixture();
        var request = f.Request with { FixtureSettings = JsonSerializer.SerializeToElement(new { token = "fixture-private-token" }) };
        await Assert.That(JsonSerializer.Serialize(request, NativeRunProtocol.JsonOptions)
            .Contains("fixture-private-token", StringComparison.Ordinal)).IsFalse();
        byte[] stdin = JsonSerializer.SerializeToUtf8Bytes(new NativeRunEnvelope(request, request.FixtureSettings),
            NativeRunProtocol.JsonOptions);
        NativeRunEnvelope parsed = NativeRunProtocol.Parse<NativeRunEnvelope>(stdin);
        parsed.Request.Validate();
        await Assert.That(parsed.FixtureSettings.GetProperty("token").GetString()).IsEqualTo("fixture-private-token");
        await Assert.That(request.ToString()).IsEqualTo("[NativeRunRequest]");
    }

    [Test]
    public async Task ReportUsesCreateNewAndEnforcesByteBudget()
    {
        var f = Fixture();
        MachineReport report = NativeObservationReport.Create(f.Request, f.Context, f.Result, f.Installation,
            Started, Completed, 0);
        string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "report.json");
        try
        {
            await NativeObservationReport.WriteAsync(path, report, CancellationToken.None);
            await Assert.That(() => NativeObservationReport.WriteAsync(path, report, CancellationToken.None)).Throws<IOException>();
            await Assert.That(() => NativeObservationReport.WriteAsync(Path.Combine(directory, "oversized.json"),
                report with { Environment = new('x', EvidenceLimits.ReportBytes) }, CancellationToken.None))
                .Throws<InvalidOperationException>();
        }
        finally { Directory.Delete(directory, recursive: true); }
    }

    [Test]
    public async Task DirectProcessExecutionUsesRealExitAndCancellation()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        await Assert.That(await NativeConsumerLauncher.ProcessAsync(root, ["--version"], null, CancellationToken.None)).IsEqualTo(0);
        await Assert.That(await NativeConsumerLauncher.ProcessAsync(root, ["secretkit-nonexistent-command"], null, CancellationToken.None))
            .IsNotEqualTo(0);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.That(() => NativeConsumerLauncher.ProcessAsync(root, ["--version"], null, cancellation.Token))
            .Throws<OperationCanceledException>();
    }

    [Test]
    public async Task InstalledNativeEntryPointReportsMissingOwnedInputWithoutRemoteCalls()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        PackageCandidate candidate = PackageCandidate.FromEnvironment(root);
        var f = Fixture();
        NativeRunRequest request = f.Request with { Version = candidate.Version };
        string outputs = Path.Combine(root, "artifacts", "native-fixture-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputs);
        ConsumerInstallation installation = candidate.PrepareConsumer(outputs);
        string project = Path.Combine(root, "tests/fixtures/SecretKit.PackageConsumer/SecretKit.PackageConsumer.csproj");
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        await Assert.That(await NativeConsumerLauncher.ProcessAsync(root,
            ["restore", project, "--configfile", installation.Configuration, .. installation.Properties],
            null, deadline.Token)).IsEqualTo(0);
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"), installation.Packages);
        await Assert.That(await NativeConsumerLauncher.ProcessAsync(root,
            ["build", project, "--no-restore", "-c", "Release", .. installation.Properties],
            null, deadline.Token)).IsEqualTo(0);
        string destination = Path.Combine(outputs, "native-result.json");
        byte[] stdin = JsonSerializer.SerializeToUtf8Bytes(new NativeRunEnvelope(request,
            JsonSerializer.SerializeToElement(new { })), NativeRunProtocol.JsonOptions);
        int exit = await NativeConsumerLauncher.ProcessAsync(root,
            [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.PackageConsumer.dll"),
                "native", "AzureKeyVault", destination], stdin, deadline.Token);
        await Assert.That(exit).IsEqualTo(1);
        NativeRunResult result = NativeRunProtocol.Parse<NativeRunResult>(await File.ReadAllBytesAsync(destination, deadline.Token));
        await Assert.That(result.Cases.Length).IsEqualTo(request.Expected.Length);
        await Assert.That(result.Cases.Single().ReasonCode).IsEqualTo("missing-input");
        await Assert.That(result.Cases.Single().Passed).IsFalse();
        await Assert.That(result.Prerequisites.Single().Confirmed).IsFalse();
        await Assert.That(result.Installation.Framework).IsEqualTo("net10.0");
    }

    [Test]
    [Arguments("AzureKeyVault")]
    [Arguments("Infisical")]
    public async Task ProducerInputsKeepOriginalRunAndSelectedRoles(string provider)
    {
        var f = Fixture();
        ReleaseManifest manifest = new(2, "SecretKit", f.Context.Scope.Version, f.Context.Scope.SourceCommit,
            Manifest.Repository, 17, "publisher", "owner", "SecretKit.", "release", new('e', 64),
            new("scope.json", f.Request.ScopeSha256), f.Context.Packages, []);
        var inputs = new CandidateInputs(1, "candidate-inputs-not-approved", 3, manifest);

        NativeHostInputs result = NativeConsumerLauncher.ProducerInputs(inputs, f.Context.Scope,
            provider, "native-operations", "linux-x64-net10.0", 29);

        await Assert.That(result.Provider).IsEqualTo(provider);
        await Assert.That(result.Purpose).IsEqualTo("release-observation");
        await Assert.That(result.SourceCommit).IsEqualTo(manifest.SourceCommit);
        await Assert.That(result.RunId).IsEqualTo(17);
        await Assert.That(result.RunAttempt).IsEqualTo(3);
        await Assert.That(result.JobId).IsEqualTo(29);
        await Assert.That(result.Scopes[0]).IsEqualTo(f.Request.Scopes[0]);
        await Assert.That(result.Operations.Length).IsEqualTo(0);
    }

    [Test]
    [Arguments("source")]
    [Arguments("version")]
    [Arguments("attempt")]
    [Arguments("job")]
    public async Task ProducerInputsRejectSubstitutedBinding(string changed)
    {
        var f = Fixture();
        ReleaseManifest manifest = new(2, "SecretKit", f.Context.Scope.Version, f.Context.Scope.SourceCommit,
            Manifest.Repository, 17, "publisher", "owner", "SecretKit.", "release", new('e', 64),
            new("scope.json", f.Request.ScopeSha256), f.Context.Packages, []);
        if (changed == "source") manifest = manifest with { SourceCommit = new('f', 40) };
        if (changed == "version") manifest = manifest with { Version = "different" };
        var inputs = new CandidateInputs(1, "candidate-inputs-not-approved", changed == "attempt" ? 0 : 3, manifest);

        await Assert.That(() => NativeConsumerLauncher.ProducerInputs(inputs, f.Context.Scope, "AzureKeyVault",
            "native-operations", "linux-x64-net10.0", changed == "job" ? 0 : 29)).Throws<InvalidOperationException>();
    }

    [Test]
    [Arguments("AzureKeyVault", "azure-key-vault.json")]
    [Arguments("Infisical", "infisical.json")]
    public async Task CompleteCurrentAdmissionFitsBoundedPrivateProtocol(string provider, string file)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(Manifest.ReadFile(
            Path.Combine(root, "docs/internal/releases/admission"), file, 4 * 1024 * 1024));
        var f = Fixture();
        NativeCaseDefinition[] expected = inventory.Operations.SelectMany(o => o.Variants.SelectMany(v =>
            o.RequiredCases.Select(c => new NativeCaseDefinition(new(provider, o.Id, v, "owned", c), o.Member)))).ToArray();
        NativeRunRequest request = f.Request with
        {
            Provider = provider,
            Scopes = [f.Request.Scopes[0] with { Provider = provider }],
            Expected = expected,
            Prerequisites = inventory.Operations.SelectMany(o => o.Prerequisites).Distinct()
                .Select(p => new NativePrerequisiteKey(provider, "owned", p)).ToArray()
        };
        request.Validate();
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new NativeRunEnvelope(request,
            JsonSerializer.SerializeToElement(new { })), NativeRunProtocol.JsonOptions);
        await Assert.That(bytes.Length).IsLessThan(NativeRunProtocol.MaximumBytes);
        await Assert.That(NativeRunProtocol.Parse<NativeRunEnvelope>(bytes).Request.Expected.Length).IsEqualTo(expected.Length);
    }
}
