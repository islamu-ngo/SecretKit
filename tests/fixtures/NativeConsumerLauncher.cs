using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecretKit.Release;

namespace SecretKit.TestFixtures;

internal sealed record NativeHostInputs(string Purpose, string Provider, string Kind, string Platform,
    string SourceCommit, long RunId, int RunAttempt, long JobId, NativeProviderScope[] Scopes,
    string[] Operations);

internal static class NativeConsumerLauncher
{
    internal static async Task<MachineReport> RunFromEnvironmentAsync(string root, string provider, CancellationToken token)
    {
        bool producer = Environment.GetEnvironmentVariable("SECRETKIT_NATIVE_REQUEST") is null;
        string reportPath = RequiredPath("SECRETKIT_NATIVE_REPORT");
        NativeHostInputs inputs;
        if (producer)
        {
            string inputPath = RequiredPath("SECRETKIT_NATIVE_INPUTS");
            NativeObservationReport.Require(Path.GetFileName(inputPath) == "candidate-inputs.json", "native-producer-input");
            string directory = Path.GetDirectoryName(inputPath)!;
            CandidateInputs candidateInputs = Candidate.ReadInputs(directory);
            ReleaseScope scope = Manifest.Parse<ReleaseScope>(Manifest.ReadDigest(directory, candidateInputs.Manifest.Scope));
            inputs = ProducerInputs(candidateInputs, scope, provider, RequiredValue("SECRETKIT_NATIVE_KIND"),
                RequiredValue("SECRETKIT_NATIVE_PLATFORM"),
                long.Parse(RequiredValue("SECRETKIT_REPORT_JOB_ID"), CultureInfo.InvariantCulture));
        }
        else
            inputs = NativeRunProtocol.Parse<NativeHostInputs>(await ReadAsync(RequiredPath("SECRETKIT_NATIVE_REQUEST"), token));
        NativeObservationReport.Require(inputs.Provider == provider, "native-host-provider");
        PackageCandidate candidate = PackageCandidate.FromEnvironment(root);
        (NativeRunRequest request, NativeReportContext context) = Prepare(root, candidate, inputs);
        // Credentials are not read until the isolated package-only build has finished.
        string outputs = Path.Combine(root, "artifacts", "native-consumers", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputs);
        ConsumerInstallation installation = candidate.PrepareConsumer(outputs);
        string project = Path.Combine(root, "tests/fixtures/SecretKit.PackageConsumer/SecretKit.PackageConsumer.csproj");
        XDocument projectXml = XDocument.Load(project);
        NativeObservationReport.Require(!projectXml.Descendants("ProjectReference").Any(), "native-project-reference");
        using var buildDeadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        buildDeadline.CancelAfter(TimeSpan.FromMinutes(5));
        int restore = await ProcessAsync(root, ["restore", project, "--configfile", installation.Configuration,
            .. installation.Properties], null, buildDeadline.Token);
        NativeObservationReport.Require(restore == 0, "native-consumer-restore");
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"), installation.Packages);
        int build = await ProcessAsync(root, ["build", project, "--no-restore", "--configuration", "Release",
            .. installation.Properties], null, buildDeadline.Token);
        NativeObservationReport.Require(build == 0, "native-consumer-build");
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"), installation.Packages);
        VerifyOriginals(candidate, inputs.SourceCommit, context.Packages);

        DateTimeOffset started = DateTimeOffset.UtcNow;
        string childReport = Path.Combine(outputs, "native-result.json");
        NativeRunResult? measured = null;
        int exit = -1;
        string? failure = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromMinutes(15));
        try
        {
            byte[] settingsBytes = producer ? Encoding.UTF8.GetBytes(RequiredValue("SECRETKIT_NATIVE_SETTINGS"))
                : await ReadAsync(RequiredPath("SECRETKIT_NATIVE_SETTINGS"), deadline.Token);
            NativeObservationReport.Require(settingsBytes.Length <= NativeRunProtocol.MaximumBytes, "native-input-size");
            using JsonDocument settings = JsonDocument.Parse(settingsBytes);
            JsonElement selectedSettings = producer ? settings.RootElement.GetProperty(provider) : settings.RootElement;
            byte[] stdin = JsonSerializer.SerializeToUtf8Bytes(new NativeRunEnvelope(request, selectedSettings),
                NativeRunProtocol.JsonOptions);
            NativeObservationReport.Require(stdin.Length <= NativeRunProtocol.MaximumBytes, "native-input-size");
            exit = await ProcessAsync(root,
                [Path.Combine(installation.Binary, "Release/net10.0/SecretKit.PackageConsumer.dll"),
                    "native", provider, childReport], stdin, deadline.Token);
            if (File.Exists(childReport))
                measured = NativeRunProtocol.Parse<NativeRunResult>(await ReadAsync(childReport, deadline.Token));
        }
        catch (OperationCanceledException) { failure = token.IsCancellationRequested ? "unexpected-cancellation" : "deadline-exceeded"; }
        catch (Exception) { failure = "incomplete-execution"; }
        DateTimeOffset completed = DateTimeOffset.UtcNow;
        string os = measured?.Installation.OperatingSystem ??
            (OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsWindows() ? "windows" : "unsupported");
        var observedInstallation = new InstallationObservation(os,
            measured?.Installation.Architecture ?? RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant(),
            measured?.Installation.Framework ?? $"net{Environment.Version.Major}.0", exit, 0, true, "candidate-only");
        MachineReport report = NativeObservationReport.Create(request, context, measured, observedInstallation,
            started, completed, exit, failure);
        await NativeObservationReport.WriteAsync(reportPath, report, CancellationToken.None);
        return report;
    }

    internal static NativeHostInputs ProducerInputs(CandidateInputs inputs, ReleaseScope scope,
        string provider, string kind, string platform, long jobId)
    {
        NativeObservationReport.Require(inputs.SchemaVersion == 1 &&
            inputs.Purpose == "candidate-inputs-not-approved" && inputs.RunAttempt > 0 &&
            inputs.Manifest.SourceRunId > 0 && jobId > 0 && inputs.Manifest.Gates.Length == 0 &&
            inputs.Manifest.Version == scope.Version && inputs.Manifest.SourceCommit == scope.SourceCommit &&
            kind is "native-operations" or "live-conformance" &&
            platform is "linux-x64-net10.0" or "windows-x64-net10.0" &&
            provider is "Infisical" or "AzureKeyVault", "native-producer-input");
        NativeProviderScope[] scopes = scope.ProviderScopes.Select(s => new NativeProviderScope(
            s.Label, s.Provider, s.Deployment, s.ApiVersion, s.RuntimeIdentity, s.ObserverIdentity,
            s.SetupIdentity, s.DeniedIdentity, s.AdministrativeIdentity)).ToArray();
        return new("release-observation", provider, kind, platform, scope.SourceCommit,
            inputs.Manifest.SourceRunId, inputs.RunAttempt, jobId, scopes, []);
    }

    internal static (NativeRunRequest Request, NativeReportContext Context) Prepare(string root,
        PackageCandidate candidate, NativeHostInputs inputs)
    {
        NativeObservationReport.Require(inputs.Scopes.Length is > 0 and <= 64 &&
            inputs.Scopes.All(s => s.Provider is "Infisical" or "AzureKeyVault" && NativeRunRequest.ValidScope(s)) &&
            inputs.Scopes.Select(s => s.Label).Distinct().Count() == inputs.Scopes.Length &&
            inputs.Operations.Distinct().Count() == inputs.Operations.Length &&
            (inputs.Purpose != "release-observation" || inputs.Operations.Length == 0 &&
                inputs.Scopes.Select(s => s.Provider).Distinct().Order().SequenceEqual(new[] { "AzureKeyVault", "Infisical" })),
            "native-operation-filter");
        var inventories = new List<AdmissionInventory>();
        var digests = new List<FileDigest>();
        foreach (string file in new[] { "infisical.json", "azure-key-vault.json" })
        {
            byte[] bytes = Manifest.ReadFile(Path.Combine(root, "docs/internal/releases/admission"), file, 4 * 1024 * 1024);
            AdmissionInventory inventory = Manifest.Parse<AdmissionInventory>(bytes);
            Admission.Validate(inventory, inventory.Operations.Select(o => o.Member).ToArray());
            foreach (FileDigest source in inventory.Sources)
                NativeObservationReport.Require(Manifest.Hash(Manifest.ReadFile(Path.Combine(root, Path.GetDirectoryName(source.File)!),
                    Path.GetFileName(source.File), 4 * 1024 * 1024)) == source.Sha256, "native-admission-source");
            inventories.Add(inventory);
            digests.Add(new(file, Manifest.Hash(bytes)));
        }
        AdmissionInventory selected = inventories.Single(i => i.Provider == inputs.Provider);
        NativeObservationReport.Require(inputs.Operations.All(id => selected.Operations.Any(o => o.Id == id)),
            "native-unknown-operation");
        AdmissionOperation[] operations = selected.Operations.Where(o =>
            inputs.Operations.Length == 0 || inputs.Operations.Contains(o.Id, StringComparer.Ordinal)).ToArray();
        NativeProviderScope[] selectedScopes = inputs.Scopes.Where(s => s.Provider == inputs.Provider).ToArray();
        NativeOperation[] scopeOperations = inputs.Scopes.SelectMany(s => inventories.Single(i => i.Provider == s.Provider)
            .Operations.Where(o => inputs.Purpose == "release-observation" || s.Provider != inputs.Provider ||
                inputs.Operations.Length == 0 || inputs.Operations.Contains(o.Id, StringComparer.Ordinal))
            .SelectMany(o => o.Variants.Select(v => new NativeOperation(s.Provider, o.Id, v, s.Label, "complete")))).ToArray();
        ProviderScope[] scopes = inputs.Scopes.Select(s => new ProviderScope(s.Label, s.Provider, s.Deployment, s.ApiVersion,
            s.RuntimeIdentity, s.ObserverIdentity, s.SetupIdentity, s.DeniedIdentity, s.AdministrativeIdentity)).ToArray();
        var scope = new ReleaseScope(candidate.Version, inputs.SourceCommit, PackageCandidate.PackageIds,
            scopeOperations, GateSemantics.Platforms.ToArray(), digests.ToArray(), "complete-live", scopes);
        NativeCaseDefinition[] expected = selectedScopes.SelectMany(s => operations.SelectMany(o =>
            o.Variants.SelectMany(v => o.RequiredCases.Select(c =>
                new NativeCaseDefinition(new(inputs.Provider, o.Id, v, s.Label, c), o.Member))))).ToArray();
        NativePrerequisiteKey[] prerequisites = selectedScopes.SelectMany(s => operations.SelectMany(o =>
            o.Prerequisites).Distinct().Select(p => new NativePrerequisiteKey(inputs.Provider, s.Label, p))).ToArray();
        var request = new NativeRunRequest(inputs.Purpose, inputs.Provider, inputs.Kind, inputs.Platform,
            candidate.Version, inputs.SourceCommit, Manifest.Hash(JsonSerializer.SerializeToUtf8Bytes(scope, Manifest.JsonOptions)),
            inputs.RunId, inputs.RunAttempt, inputs.JobId, selectedScopes, expected, prerequisites);
        request.Validate();
        PackageRecord[] packages = PackageCandidate.PackageIds.Select(id =>
        {
            string file = $"{id}.{candidate.Version}.nupkg";
            using FileStream original = File.OpenRead(candidate.ArchivePath(id));
            return new PackageRecord(id, file, Convert.ToHexStringLower(SHA256.HashData(original)));
        }).ToArray();
        VerifyOriginals(candidate, inputs.SourceCommit, packages);
        return (request, new(scope, packages, operations.Where(o => o.Contract == "contract-gap").Select(o => o.Id).ToArray()));
    }

    private static void VerifyOriginals(PackageCandidate candidate, string commit, PackageRecord[] packages)
    {
        foreach (PackageRecord package in packages)
        {
            using FileStream original = File.OpenRead(candidate.ArchivePath(package.Id));
            NativeObservationReport.Require(Convert.ToHexStringLower(SHA256.HashData(original)) == package.Sha256,
                "native-original-bytes");
            using ZipArchive archive = ZipFile.OpenRead(candidate.ArchivePath(package.Id));
            using Stream stream = archive.GetEntry(package.Id + ".nuspec")!.Open();
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 65536 });
            XElement metadata = XDocument.Load(reader).Descendants().Single(e => e.Name.LocalName == "repository");
            NativeObservationReport.Require(metadata.Attribute("commit")?.Value == commit &&
                metadata.Attribute("url")?.Value == Manifest.Repository && metadata.Attribute("type")?.Value == "git",
                "native-original-source");
        }
    }

    internal static async Task<int> ProcessAsync(string root, string[] arguments, byte[]? stdin, CancellationToken token)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = root,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        // A native credential belongs only in redirected stdin, not the build or child environment.
        process.StartInfo.Environment.Clear();
        foreach (string key in new[] { "PATH", "HOME", "USERPROFILE", "SYSTEMROOT", "WINDIR",
            "TEMP", "TMP", "TMPDIR", "DOTNET_ROOT", "DOTNET_ROOT_X64", "DOTNET_CLI_HOME" })
            if (Environment.GetEnvironmentVariable(key) is string value)
                process.StartInfo.Environment[key] = value;
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        token.ThrowIfCancellationRequested();
        process.Start();
        Task output = process.StandardOutput.BaseStream.CopyToAsync(Stream.Null);
        Task error = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        try
        {
            if (stdin is not null) await process.StandardInput.BaseStream.WriteAsync(stdin, token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(token);
            await Task.WhenAll(output, error);
            return process.ExitCode;
        }
        catch
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync(CancellationToken.None);
            await Task.WhenAll(output, error);
            throw;
        }
    }

    private static async Task<byte[]> ReadAsync(string path, CancellationToken token)
    {
        await using FileStream stream = File.OpenRead(path);
        return await NativeRunProtocol.ReadBoundedAsync(stream, token);
    }
    private static string RequiredPath(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value) || !Path.IsPathFullyQualified(value))
            throw new InvalidOperationException("native-gate-input-missing");
        return value;
    }
    private static string RequiredValue(string name)
    {
        string? value = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(value)) throw new InvalidOperationException("native-gate-input-missing");
        return value;
    }
}
