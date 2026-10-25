using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record DemoAppInput(string Id, string SourceLockSha256, string LockSha256, FileDigest[] Inputs);
public sealed record DemoInputManifest(int SchemaVersion, string Purpose, long WorkflowRunId,
    int WorkflowRunAttempt, string SourceCommit, string Sdk, string Version,
    string QualificationSha256, DemoAppInput[] Apps);

// Local, credential-free consistency only. This cannot create a public release
// or upgrade the qualification status of the historical local candidate.
public static class DemoInputs
{
    public const string ManifestFile = "demo-inputs.json";
    private static readonly string[] Apps = ["console", "worker", "web"];

    public static async Task PrepareAsync(string source, string originals, string qualification,
        string output, string commit, long run, int attempt, string sdk)
    {
        source = Path.GetFullPath(source);
        LocalQualificationRecord record = LocalQualification.Check(source, originals, qualification);
        Context(source, record, commit, run, attempt, sdk);
        await RequireSdkAsync(source, sdk);
        byte[] qualificationBytes = Manifest.ReadFile(qualification, LocalQualification.RecordFile, 4 * 1024 * 1024);
        string qualificationHash = Manifest.Hash(qualificationBytes);
        DemoAppInput[] baseline = Apps.Select(id => new DemoAppInput(id,
            Manifest.Hash(Read(source, SourceLock(id))), "", InputFiles(id).Select(file =>
                new FileDigest(file, Manifest.Hash(Read(source, file)))).ToArray())).ToArray();
        foreach (DemoAppInput app in baseline)
        {
            RequireAppFiles(source, app.Id);
            // Fail before any restore if the finalized source baseline selects
            // a different candidate. Never adjust versions to make CI pass.
            ValidateLockChange(Read(source, SourceLock(app.Id)), Read(source, SourceLock(app.Id)),
                app.Id, record.Version, null);
        }
        string destination = Path.GetFullPath(output);
        Guard.Require(!Directory.Exists(destination) && !File.Exists(destination), "demo-output-exists");
        NoLinks(Path.GetDirectoryName(destination)!);
        // Source snapshots intentionally exclude artifacts; no other source
        // directory may become an unrecorded producer input.
        string relative = Path.GetRelativePath(source, destination).Replace('\\', '/');
        Guard.Require(relative.StartsWith("artifacts/", StringComparison.Ordinal) ||
            relative.StartsWith("../", StringComparison.Ordinal) || Path.IsPathRooted(relative),
            "demo-output-in-source");
        string workspace = Path.Combine(Path.GetDirectoryName(destination)!, "demo-work-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspace);
        try
        {
            var staged = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            foreach (DemoAppInput app in baseline)
            {
                string work = Path.Combine(workspace, app.Id);
                foreach (FileDigest input in app.Inputs)
                {
                    string target = CopyPath(work, app.Id, input.File);
                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    File.WriteAllBytes(target, Read(source, input.File));
                }
                string appDirectory = Path.Combine(work, "app");
                string configuration = Path.Combine(work, "NuGet.Config");
                string cache = Path.Combine(work, "packages");
                new XDocument(new XElement("configuration",
                    new XElement("packageSources", new XElement("clear"),
                        new XElement("add", new XAttribute("key", "local"),
                            new XAttribute("value", Path.GetFullPath(originals))),
                        new XElement("add", new XAttribute("key", "nuget.org"),
                            new XAttribute("value", "https://api.nuget.org/v3/index.json"))),
                    new XElement("fallbackPackageFolders", new XElement("clear")),
                    new XElement("packageSourceMapping", new XElement("clear"),
                        new XElement("packageSource", new XAttribute("key", "local"),
                            new XElement("package", new XAttribute("pattern", "SecretKit.*"))),
                        new XElement("packageSource", new XAttribute("key", "nuget.org"),
                            new XElement("package", new XAttribute("pattern", "*"))))))
                    .Save(configuration);
                VerifyCopies();
                await DotnetAsync(appDirectory, record.Version, [
                    "restore", Project(app.Id), "--use-lock-file", "--force-evaluate",
                    "--configfile", configuration, "--packages", cache,
                    "-p:RestoreLockedMode=false", "-p:RestoreFallbackFolders=", "-p:NuGetAudit=false"
                ]);
                VerifyCopies();
                byte[] lockBytes = Manifest.ReadFile(appDirectory, "packages.lock.json", 4 * 1024 * 1024);
                ValidateLockChange(Read(source, SourceLock(app.Id)), lockBytes, app.Id, record.Version,
                    id => Manifest.ReadFile(originals, $"{id}.{record.Version}.nupkg", PackageArchive.MaximumBytes));
                staged.Add(app.Id, lockBytes);

                void VerifyCopies()
                {
                    foreach (FileDigest input in app.Inputs)
                    {
                        NoLinks(CopyPath(work, app.Id, input.File));
                        Guard.Require(Manifest.Hash(Read(source, input.File)) == input.Sha256 &&
                            Manifest.Hash(File.ReadAllBytes(CopyPath(work, app.Id, input.File))) == input.Sha256,
                            "demo-copy-changed");
                    }
                }
            }
            _ = LocalQualification.Check(source, originals, qualification);
            Guard.Require(Manifest.Hash(Manifest.ReadFile(qualification, LocalQualification.RecordFile, 4 * 1024 * 1024)) ==
                qualificationHash, "demo-qualification-changed");
            Directory.CreateDirectory(destination);
            Directory.CreateDirectory(Path.Combine(destination, "originals"));
            Directory.CreateDirectory(Path.Combine(destination, "qualification"));
            foreach (PackageRecord package in record.Packages)
                File.WriteAllBytes(Path.Combine(destination, "originals", package.File),
                    Manifest.ReadDigest(originals, new(package.File, package.Sha256)));
            File.WriteAllBytes(Path.Combine(destination, "qualification", LocalQualification.RecordFile), qualificationBytes);
            foreach (string id in Apps)
            {
                string directory = Path.Combine(destination, "locks", id);
                Directory.CreateDirectory(directory);
                File.WriteAllBytes(Path.Combine(directory, "packages.lock.json"), staged[id]);
            }
            var manifest = new DemoInputManifest(1, "ci-temporary-verification", run, attempt, commit, sdk,
                record.Version, qualificationHash, baseline.Select(app =>
                    app with { LockSha256 = Manifest.Hash(staged[app.Id]) }).ToArray());
            Candidate.Write(destination, ManifestFile, manifest);
            _ = Check(source, destination, commit, run, attempt, sdk);
        }
        finally
        {
            Directory.Delete(workspace, recursive: true);
        }
    }

    public static DemoInputManifest Check(string source, string directory,
        string commit, long run, int attempt, string sdk)
    {
        NoLinks(directory);
        ExactDirectory(directory, ["originals", "qualification", "locks", ManifestFile]);
        ExactDirectory(Path.Combine(directory, "qualification"), [LocalQualification.RecordFile]);
        ExactDirectory(Path.Combine(directory, "locks"), Apps);
        DemoInputManifest manifest = Manifest.Parse<DemoInputManifest>(
            Manifest.ReadFile(directory, ManifestFile, 4 * 1024 * 1024));
        Guard.Require(manifest.SchemaVersion == 1 && manifest.Purpose == "ci-temporary-verification" &&
            manifest.WorkflowRunId == run && manifest.WorkflowRunAttempt == attempt &&
            manifest.SourceCommit == commit && manifest.Sdk == sdk, "demo-context");
        byte[] qualification = Manifest.ReadFile(Path.Combine(directory, "qualification"),
            LocalQualification.RecordFile, 4 * 1024 * 1024);
        Guard.Require(Manifest.IsHash(manifest.QualificationSha256) &&
            Manifest.Hash(qualification) == manifest.QualificationSha256, "demo-qualification");
        string originals = Path.Combine(directory, "originals");
        LocalQualificationRecord record = LocalQualification.Check(source, originals,
            Path.Combine(directory, "qualification"));
        Context(source, record, commit, run, attempt, sdk);
        Guard.Require(manifest.Version == record.Version, "demo-version");
        Manifest.ExactSet(manifest.Apps.Select(app => app.Id), Apps, "demo-apps");
        foreach (DemoAppInput app in manifest.Apps)
        {
            RequireAppFiles(source, app.Id);
            Manifest.ExactSet(app.Inputs.Select(input => input.File), InputFiles(app.Id), "demo-app-inputs");
            foreach (FileDigest input in app.Inputs)
                Guard.Require(Manifest.IsHash(input.Sha256) &&
                    Manifest.Hash(Read(source, input.File)) == input.Sha256, "demo-source-input");
            byte[] sourceLock = Read(source, SourceLock(app.Id));
            Guard.Require(Manifest.IsHash(app.SourceLockSha256) && Manifest.Hash(sourceLock) == app.SourceLockSha256,
                "demo-source-lock");
            string lockDirectory = Path.Combine(directory, "locks", app.Id);
            ExactDirectory(lockDirectory, ["packages.lock.json"]);
            byte[] staged = Manifest.ReadDigest(lockDirectory, new("packages.lock.json", app.LockSha256));
            ValidateLockChange(sourceLock, staged, app.Id, record.Version,
                id => Manifest.ReadFile(originals, $"{id}.{record.Version}.nupkg", PackageArchive.MaximumBytes));
        }
        return manifest;
    }

    internal static void ValidateLockChange(byte[] baseline, byte[] staged, string app, string version,
        Func<string, byte[]>? archive)
    {
        _ = Manifest.Parse<JsonElement>(baseline);
        _ = Manifest.Parse<JsonElement>(staged);
        JsonObject original = JsonNode.Parse(baseline)!.AsObject();
        JsonObject current = JsonNode.Parse(staged)!.AsObject();
        Guard.Require(original["version"]!.GetValue<int>() == 1 && current["version"]!.GetValue<int>() == 1,
            "demo-lock-schema");
        Manifest.ExactSet(original["dependencies"]!.AsObject().Select(p => p.Key), ["net10.0"], "demo-lock-framework");
        Manifest.ExactSet(current["dependencies"]!.AsObject().Select(p => p.Key), ["net10.0"], "demo-lock-framework");
        JsonObject expected = original["dependencies"]!["net10.0"]!.AsObject();
        JsonObject actual = current["dependencies"]!["net10.0"]!.AsObject();
        string[] packages = app switch
        {
            "console" => ["SecretKit.Core", "SecretKit.Infisical"],
            "worker" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Hosting"],
            "web" => ["SecretKit.Core", "SecretKit.Infisical", "SecretKit.Extensions.Configuration"],
            _ => throw new ReleaseException("demo-app")
        };
        foreach (JsonObject graph in new[] { expected, actual })
        {
            Manifest.ExactSet(graph.Where(p => p.Key.StartsWith("SecretKit.", StringComparison.OrdinalIgnoreCase))
                .Select(p => p.Key), packages, "demo-lock-family");
            foreach (string id in packages)
            {
                JsonObject package = graph[id]!.AsObject();
                Guard.Require(package["resolved"]!.GetValue<string>() == version &&
                    package["type"]!.GetValue<string>() == "Direct" &&
                    package["requested"]!.GetValue<string>() == $"[{version}, {version}]" &&
                    Convert.FromBase64String(package["contentHash"]!.GetValue<string>()).Length == 64,
                    "demo-lock-version");
            }
        }
        foreach (string id in packages)
        {
            if (archive is not null)
                Guard.Require(actual[id]!["contentHash"]!.GetValue<string>() ==
                    Convert.ToBase64String(SHA512.HashData(archive(id))), "demo-lock-original");
            actual[id]!["contentHash"] = expected[id]!["contentHash"]!.DeepClone();
        }
        // Object property order is immaterial; every value other than the
        // admitted internal archive hashes remains part of the frozen graph.
        Guard.Require(JsonNode.DeepEquals(original, current), "demo-lock-graph");
    }

    public static async Task RequireSdkAsync(string source, string sdk)
    {
        string observed = await DotnetAsync(source, "", ["--version"]);
        Guard.Require(observed.Trim() == sdk, "demo-current-sdk");
    }

    private static void Context(string source, LocalQualificationRecord record,
        string commit, long run, int attempt, string sdk)
    {
        Guard.Require(commit.Length == 40 && commit.All(c => char.IsAsciiHexDigitLower(c)) &&
            run > 0 && attempt > 0 && record.SourceCommit == commit, "demo-selected-source");
        JsonElement global = Manifest.Parse<JsonElement>(Manifest.ReadFile(source, "global.json", 64 * 1024));
        Guard.Require(global.GetProperty("sdk").GetProperty("version").GetString() == sdk,
            "demo-selected-sdk");
    }

    private static string Kind(string id) => id switch
    {
        "console" => "Console",
        "worker" => "Worker",
        "web" => "Web",
        _ => throw new ReleaseException("demo-app")
    };
    private static string Project(string id) => $"Infisical.{Kind(id)}Demo.csproj";
    private static string AppDirectory(string id) => $"samples/Infisical.{Kind(id)}Demo";
    private static string SourceLock(string id) => AppDirectory(id) + "/packages.lock.json";
    private static string[] InputFiles(string id) =>
    [
        $"{AppDirectory(id)}/{Project(id)}", $"{AppDirectory(id)}/Program.cs", $"{AppDirectory(id)}/README.md",
        "samples/Infisical.Demos/DemoInput.cs", "samples/Infisical.Demos/DemoInputReader.cs",
        "samples/Infisical.Demos/DemoOutput.cs",
        .. id == "worker" ? new[] { "samples/Infisical.Demos/WorkerInput.cs" } :
            new[] { "samples/Infisical.Demos/DemoTokenSource.cs" },
        .. id switch
        {
            "console" => new[]
            {
                "samples/Infisical.Demos/MutationInput.cs",
                "samples/Infisical.ConsoleDemo/ConsoleDemoApplication.cs",
                "samples/Infisical.ConsoleDemo/ConsoleDemoCommand.cs",
                "samples/Infisical.ConsoleDemo/ConsoleDemoOutcomes.cs"
            },
            "worker" => new[] { "samples/Infisical.WorkerDemo/WorkerDemoApplication.cs",
                "samples/Infisical.WorkerDemo/SecretWorker.cs" },
            "web" => new[] { "samples/Infisical.WebDemo/WebDemoApplication.cs",
                "samples/Infisical.WebDemo/WebDemoRuntime.cs", "samples/Infisical.WebDemo/WebDemoEndpoints.cs",
                "samples/Infisical.WebDemo/WebDemoOptions.cs", "samples/Infisical.WebDemo/JobClient.cs" },
            _ => throw new ReleaseException("demo-app")
        },
        .. id == "web" ? new[]
        {
            "samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs",
            "samples/RuntimeConfiguration/RuntimeGenerationLease.cs"
        } : []
    ];
    private static string CopyPath(string workspace, string id, string input) =>
        input.StartsWith(AppDirectory(id) + "/", StringComparison.Ordinal)
            ? Path.Combine(workspace, "app", Path.GetFileName(input))
            : Path.Combine(workspace, input["samples/".Length..]);

    private static byte[] Read(string source, string relative) =>
        Manifest.ReadFile(Path.Combine(source, Path.GetDirectoryName(relative)!),
            Path.GetFileName(relative), 4 * 1024 * 1024);

    private static void RequireAppFiles(string source, string id)
    {
        string directory = Path.Combine(source, AppDirectory(id));
        NoLinks(directory);
        Manifest.ExactSet(Directory.GetFiles(directory).Select(path => Path.GetFileName(path)),
            InputFiles(id).Where(file => file.StartsWith(AppDirectory(id) + "/", StringComparison.Ordinal))
                .Select(Path.GetFileName).Select(file => file!).Append("packages.lock.json"), "demo-extra-input");
        Guard.Require(Directory.GetDirectories(directory).All(path =>
            Path.GetFileName(path) is "bin" or "obj"), "demo-extra-input");
    }

    private static void ExactDirectory(string directory, IEnumerable<string> entries)
    {
        NoLinks(directory);
        string[] paths = Directory.GetFileSystemEntries(directory);
        Manifest.ExactSet(paths.Select(Path.GetFileName).Select(name => name!), entries, "demo-bundle-files");
        foreach (string path in paths) NoLinks(path);
    }

    private static void NoLinks(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            Guard.Require((File.GetAttributes(current) & FileAttributes.ReparsePoint) == 0, "demo-input-link");
    }

    private static async Task<string> DotnetAsync(string directory, string version, string[] arguments)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(3));
        using var process = new Process
        {
            StartInfo = new("dotnet")
            {
                WorkingDirectory = directory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            }
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment["ImportDirectoryBuildProps"] = "false";
        process.StartInfo.Environment["ImportDirectoryBuildTargets"] = "false";
        process.StartInfo.Environment["SecretKitCandidateVersion"] = version;
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        process.StartInfo.Environment["NUGET_HTTP_CACHE_PATH"] = Path.Combine(directory, "http-cache");
        process.StartInfo.Environment["NUGET_PLUGINS_CACHE_PATH"] = Path.Combine(directory, "plugin-cache");
        process.Start();
        Task<string> output = process.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> error = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            string observed = await output;
            _ = await error;
            Guard.Require(process.ExitCode == 0, "demo-restore-or-sdk");
            return observed;
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, error);
        }
    }
}
