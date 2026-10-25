using System.Diagnostics;
using SecretKit.TestFixtures;

namespace SecretKit.Demo.Tests;

internal sealed class DemoProcess(string? diagnosticCapture = null,
    (string Directory, string Version)? candidateSelection = null, string? stagedLockDirectory = null)
{
    private readonly string _root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);

    internal Task<DemoResult> ConsoleAsync(string input, params string[] arguments) =>
        ExecuteAsync("Console", input, arguments);

    internal Task<DemoResult> WorkerAsync(string input, string[] arguments,
        Func<string, StreamWriter, Task>? onEvent = null) =>
        ExecuteAsync("Worker", input, arguments, onEvent);

    internal Task<DemoResult> WorkerAsync(Func<string> input, string[] arguments,
        Func<string, StreamWriter, Task>? onEvent = null) =>
        ExecuteAsync("Worker", "", arguments, onEvent, input);

    internal Task<DemoResult> WebAsync(Func<string> input, string[] arguments,
        Func<string, StreamWriter, Task>? onEvent = null) =>
        ExecuteAsync("Web", "", arguments, onEvent, input);

    private async Task<DemoResult> ExecuteAsync(string kind, string input, string[] arguments,
        Func<string, StreamWriter, Task>? onEvent = null, Func<string>? inputFactory = null)
    {
        string selected = candidateSelection?.Directory ?? Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY") ??
            throw new InvalidOperationException("Select exact demo candidate originals.");
        string version = candidateSelection?.Version ?? Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_VERSION") ??
            throw new InvalidOperationException("Select the exact demo candidate version.");
        string? bundle = stagedLockDirectory ?? Environment.GetEnvironmentVariable("SECRETKIT_DEMO_STAGED_LOCK_DIRECTORY");
        string? manifestHash = null;
        string? qualificationHash = null;
        string[]? bundleContext = null;
        if (bundle is not null)
        {
            bundle = Path.GetFullPath(bundle);
            bundleContext =
            [
                Environment.GetEnvironmentVariable("GITHUB_SHA") ?? "",
                Environment.GetEnvironmentVariable("GITHUB_RUN_ID") ?? "",
                Environment.GetEnvironmentVariable("GITHUB_RUN_ATTEMPT") ?? "",
                Environment.GetEnvironmentVariable("SECRETKIT_DEMO_SDK") ?? ""
            ];
            await CheckBundleAsync();
            using var manifest = System.Text.Json.JsonDocument.Parse(File.ReadAllBytes(Path.Combine(bundle, "demo-inputs.json")));
            if (manifest.RootElement.GetProperty("version").GetString() != version ||
                !SamePath(selected, Path.Combine(bundle, "originals")))
                throw new InvalidOperationException("Conflicting demo bundle selectors.");
            manifestHash = Hash(Path.Combine(bundle, "demo-inputs.json"));
            qualificationHash = Hash(Path.Combine(bundle, "qualification/local-qualification.json"));
        }
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(selected, version);
        string run = Path.Combine(_root, "artifacts/runtime-adoption-hardening/demo-tests", Guid.NewGuid().ToString("N"));
        string mode = kind switch { "Worker" => "hosting", "Web" => "configuration", _ => "minimal" };
        ConsumerInstallation installation = candidate.PrepareConsumer(run, mode);
        string app = Path.Combine(run, "app");
        Directory.CreateDirectory(app);
        string source = Path.Combine(_root, $"samples/Infisical.{kind}Demo");
        string[] appFiles = [$"Infisical.{kind}Demo.csproj", "Program.cs", "README.md", "packages.lock.json",
            .. kind switch
            {
                "Console" => new[] { "ConsoleDemoApplication.cs", "ConsoleDemoCommand.cs", "ConsoleDemoOutcomes.cs" },
                "Worker" => new[] { "WorkerDemoApplication.cs", "SecretWorker.cs" },
                "Web" => new[] { "WebDemoApplication.cs", "WebDemoRuntime.cs", "WebDemoEndpoints.cs",
                    "WebDemoOptions.cs", "JobClient.cs" },
                _ => throw new InvalidOperationException("Unknown demo application.")
            }];
        if (!Directory.GetFiles(source).Select(Path.GetFileName).Order(StringComparer.Ordinal)
                .SequenceEqual(appFiles.Order(StringComparer.Ordinal)))
            throw new InvalidOperationException("Unexpected demo application inputs.");
        var inputs = new List<(string Source, string Copy, string Hash)>();
        foreach (string name in appFiles)
        {
            string file = Path.Combine(source, name);
            File.Copy(file, Path.Combine(app, Path.GetFileName(file)));
            inputs.Add((file, Path.Combine(app, name), Hash(file)));
        }
        string shared = Path.Combine(run, "Infisical.Demos");
        Directory.CreateDirectory(shared);
        string[] sharedFiles = ["DemoInput.cs", "DemoInputReader.cs", "DemoOutput.cs",
            .. kind == "Worker" ? new[] { "WorkerInput.cs" } : new[] { "DemoTokenSource.cs" },
            .. kind == "Console" ? new[] { "MutationInput.cs" } : []];
        foreach (string name in sharedFiles)
        {
            string file = Path.Combine(_root, "samples/Infisical.Demos", name);
            File.Copy(file, Path.Combine(shared, name));
            inputs.Add((file, Path.Combine(shared, name), Hash(file)));
        }
        if (kind == "Web")
        {
            string runtime = Path.Combine(run, "RuntimeConfiguration");
            Directory.CreateDirectory(runtime);
            foreach (string file in new[] { "RuntimeIntegrationCoordinator.cs", "RuntimeGenerationLease.cs" })
            {
                File.Copy(Path.Combine(_root, "samples/RuntimeConfiguration", file), Path.Combine(runtime, file));
                inputs.Add((Path.Combine(_root, "samples/RuntimeConfiguration", file),
                    Path.Combine(runtime, file), Hash(Path.Combine(runtime, file))));
            }
        }
        string sourceLockHash = Hash(Path.Combine(source, "packages.lock.json"));
        string selectedLock = bundle is null ? Path.Combine(source, "packages.lock.json") :
            Path.Combine(bundle, "locks", kind.ToLowerInvariant(), "packages.lock.json");
        string lockHash = Hash(selectedLock);
        File.Copy(selectedLock, Path.Combine(app, "packages.lock.json"), overwrite: true);
        inputs.RemoveAll(pair => pair.Copy == Path.Combine(app, "packages.lock.json"));
        inputs.Add((selectedLock, Path.Combine(app, "packages.lock.json"), lockHash));
        VerifyInputs();
        string project = Path.Combine(app, $"Infisical.{kind}Demo.csproj");
        DemoResult restored = await RunAsync(app, "", ["restore", project, "--locked-mode", "--configfile",
            installation.Configuration, .. installation.Properties], version);
        RequireSuccess(restored);
        VerifyInstallation();
        if (kind == "Worker") VerifyWorkerGraph(Path.Combine(installation.Intermediate, "project.assets.json"));
        DemoResult built = await RunAsync(app, "", ["build", project, "--configuration", "Release",
            "--no-restore", .. installation.Properties], version);
        RequireSuccess(built);
        RequireSuccess(await RunAsync(app, "", ["format", project, "--verify-no-changes",
            "--no-restore", "--verbosity", "quiet"], version));
        DemoResult result = await RunAsync(app, inputFactory?.Invoke() ?? input,
            [Path.Combine(installation.Binary, $"Release/net10.0/Infisical.{kind}Demo.dll"), .. arguments],
            version, onEvent, diagnosticCapture is null ? null :
                (Path.Combine(_root, "tests/fixtures/DemoDiagnosticsHook/bin/Release/net10.0/DemoDiagnosticsHook.dll"),
                Path.GetFullPath(diagnosticCapture)));
        VerifyInstallation();
        VerifyInputs();
        if (bundle is not null) await CheckBundleAsync();
        DemoResult sdk = await RunAsync(app, "", ["--version"], version);
        RequireSuccess(sdk);
        string evidence = Path.Combine(run, "installation.json");
        var record = new
        {
            kind = "installed-demo-offline",
            app = kind.ToLowerInvariant(),
            version,
            nativeQualified = false,
            diagnosticsObserved = diagnosticCapture is not null,
            platform = System.Runtime.InteropServices.RuntimeInformation.RuntimeIdentifier,
            sdk = sdk.Output.Trim(),
            lockOrigin = bundle is null ? "source" : "ci-temporary-verification",
            sourceLockHash,
            lockHash,
            manifestHash,
            qualificationHash,
            result.ExitCode,
            originals = LocalPackageCandidate.PackageIds.Select(id => new
            {
                id,
                sha256 = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(
                    File.ReadAllBytes(candidate.ArchivePath(id))))
            }).ToArray()
        };
        await File.WriteAllTextAsync(evidence, System.Text.Json.JsonSerializer.Serialize(record));
        if (Environment.GetEnvironmentVariable("SECRETKIT_DEMO_INSTALL_REPORTS") is { } reports)
        {
            Directory.CreateDirectory(reports);
            File.Copy(evidence, Path.Combine(reports, kind.ToLowerInvariant() + "-" + Path.GetFileName(run) + ".json"),
                overwrite: false);
        }
        return result;

        async Task CheckBundleAsync()
        {
            DemoResult check = await RunAsync(_root, "", [
                Path.Combine(_root, "tools/SecretKit.Release/bin/Release/net10.0/SecretKit.Release.dll"),
                "local-demo-check", _root, bundle!, .. bundleContext!], version);
            if (check.ExitCode != 0)
                throw new InvalidOperationException("Invalid explicit demo bundle.");
        }

        void VerifyInputs()
        {
            if (!Directory.GetFiles(app).Select(Path.GetFileName).Order(StringComparer.Ordinal)
                    .SequenceEqual(appFiles.Order(StringComparer.Ordinal)) ||
                !Directory.GetFiles(shared).Select(Path.GetFileName).Order(StringComparer.Ordinal)
                    .SequenceEqual(sharedFiles.Order(StringComparer.Ordinal)) ||
                Directory.GetDirectories(app).Any(path => Path.GetFileName(path) is not ("bin" or "obj")))
                throw new InvalidOperationException("Unexpected copied demo inputs.");
            if (Hash(Path.Combine(source, "packages.lock.json")) != sourceLockHash ||
                inputs.Any(pair => Hash(pair.Source) != pair.Hash || Hash(pair.Copy) != pair.Hash) ||
                bundle is not null && (Hash(Path.Combine(bundle, "demo-inputs.json")) != manifestHash ||
                    Hash(Path.Combine(bundle, "qualification/local-qualification.json")) != qualificationHash))
                throw new InvalidOperationException("Demo inputs changed during execution.");
        }

        void VerifyInstallation()
        {
            string assets = Path.Combine(installation.Intermediate, "project.assets.json");
            if (kind == "Web") VerifyWebGraph(candidate, assets, installation.Packages);
            else candidate.VerifyRestored(assets, installation.Packages, mode);
        }
    }

    private static string Hash(string path)
    {
        for (string? current = Path.GetFullPath(path); current is not null; current = Path.GetDirectoryName(current))
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Unexpected demo input link.");
        return Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)));
    }

    private static bool SamePath(string left, string right) =>
        string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);

    private static void VerifyWebGraph(LocalPackageCandidate candidate, string assetsPath, string cache)
    {
        // App-only framework allowance: do not weaken the four SDK fixture profiles.
        using var assets = System.Text.Json.JsonDocument.Parse(File.ReadAllText(assetsPath));
        var document = assets.RootElement;
        string[] folders = document.GetProperty("packageFolders").EnumerateObject().Select(p => p.Name).ToArray();
        if (folders.Length != 1 || !SamePath(folders[0], cache))
            throw new InvalidOperationException("Unexpected web package cache.");
        var expected = new HashSet<string>(StringComparer.Ordinal)
        {
            $"SecretKit.Core/{candidate.Version}", $"SecretKit.Infisical/{candidate.Version}",
            $"SecretKit.Extensions.Configuration/{candidate.Version}",
            "Refit/16.3.0", "ReactiveUI.Disposables/8.2.0", "ReactiveUI.Primitives/8.2.0",
            "ReactiveUI.Primitives.Core/8.2.0"
        };
        var libraries = document.GetProperty("libraries").EnumerateObject().ToArray();
        if (!libraries.Select(p => p.Name).ToHashSet(StringComparer.Ordinal).SetEquals(expected) ||
            libraries.Any(p => p.Value.GetProperty("type").GetString() != "package"))
            throw new InvalidOperationException("Unexpected web package graph.");
        foreach (string id in LocalPackageCandidate.Expected("configuration"))
        {
            string directory = Path.Combine(cache, id.ToLowerInvariant(), candidate.Version.ToLowerInvariant());
            string archive = Path.Combine(directory, $"{id.ToLowerInvariant()}.{candidate.Version.ToLowerInvariant()}.nupkg");
            for (string? current = directory; current is not null; current = Path.GetDirectoryName(current))
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Unexpected web package link.");
            if ((File.GetAttributes(archive) & FileAttributes.ReparsePoint) != 0 ||
                !System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(archive)).AsSpan()
                    .SequenceEqual(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(candidate.ArchivePath(id)))))
                throw new InvalidOperationException("Unexpected web package bytes.");
            using var metadata = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, ".nupkg.metadata")));
            if (!SamePath(metadata.RootElement.GetProperty("source").GetString()!, candidate.Directory))
                throw new InvalidOperationException("Unexpected web package source.");
        }
        foreach (var framework in document.GetProperty("project").GetProperty("frameworks").EnumerateObject())
            if (!framework.Value.GetProperty("frameworkReferences").EnumerateObject().Select(p => p.Name)
                .ToHashSet(StringComparer.Ordinal).SetEquals(["Microsoft.NETCore.App", "Microsoft.AspNetCore.App"]))
                throw new InvalidOperationException("Unexpected web framework graph.");

        static bool SamePath(string left, string right) =>
            string.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
                Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
    }

    private static void VerifyWorkerGraph(string assetsPath)
    {
        // The app's Generic Host closure is separate from the unchanged SDK profile witnesses.
        using var assets = System.Text.Json.JsonDocument.Parse(File.ReadAllText(assetsPath));
        string[] microsoft =
        [
            "Configuration", "Configuration.Abstractions", "Configuration.Binder", "Configuration.CommandLine",
            "Configuration.EnvironmentVariables", "Configuration.FileExtensions", "Configuration.Json",
            "Configuration.UserSecrets", "DependencyInjection", "DependencyInjection.Abstractions",
            "Diagnostics", "Diagnostics.Abstractions", "Diagnostics.HealthChecks.Abstractions",
            "FileProviders.Abstractions", "FileProviders.Physical", "FileSystemGlobbing",
            "Hosting", "Hosting.Abstractions", "Logging", "Logging.Abstractions", "Logging.Configuration",
            "Logging.Console", "Logging.Debug", "Logging.EventLog", "Logging.EventSource",
            "Options", "Options.ConfigurationExtensions", "Primitives"
        ];
        var expected = microsoft.Select(id => $"Microsoft.Extensions.{id}/10.0.12")
            .Concat(["System.Diagnostics.EventLog/10.0.12", "Refit/16.3.0",
                "ReactiveUI.Disposables/8.2.0", "ReactiveUI.Primitives/8.2.0", "ReactiveUI.Primitives.Core/8.2.0"])
            .ToHashSet(StringComparer.Ordinal);
        var actual = assets.RootElement.GetProperty("libraries").EnumerateObject()
            .Where(library => !library.Name.StartsWith("SecretKit.", StringComparison.Ordinal))
            .Select(library => library.Name).ToHashSet(StringComparer.Ordinal);
        if (!actual.SetEquals(expected))
            throw new InvalidOperationException("Unexpected worker application dependency graph.");
    }

    private static void RequireSuccess(DemoResult result)
    {
        if (result.ExitCode != 0)
            throw new InvalidOperationException("Demo build failed: " + result.Output + result.Error);
    }

    private static async Task<DemoResult> RunAsync(string cwd, string input, string[] arguments, string version,
        Func<string, StreamWriter, Task>? onEvent = null,
        (string Assembly, string Destination)? diagnostics = null)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        using var process = new Process
        {
            StartInfo = new("dotnet")
            {
                WorkingDirectory = cwd,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        process.StartInfo.Environment["ImportDirectoryBuildProps"] = "false";
        process.StartInfo.Environment["ImportDirectoryBuildTargets"] = "false";
        process.StartInfo.Environment["SecretKitCandidateVersion"] = version;
        process.StartInfo.Environment["NUGET_HTTP_CACHE_PATH"] = Path.Combine(cwd, "obj/http-cache");
        process.StartInfo.Environment["NUGET_PLUGINS_CACHE_PATH"] = Path.Combine(cwd, "obj/plugin-cache");
        if (diagnostics is { } observer)
        {
            if (!File.Exists(observer.Assembly) || File.Exists(observer.Destination))
                throw new InvalidOperationException("Select a built observer and a fresh capture.");
            process.StartInfo.Environment["DOTNET_STARTUP_HOOKS"] = observer.Assembly;
            process.StartInfo.Environment["SECRETKIT_DEMO_DIAGNOSTIC_CAPTURE"] = observer.Destination;
        }
        process.EnableRaisingEvents = true;
        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += (_, _) => exited.TrySetResult();
        process.Start();
        Task<string> output = DrainAsync(process.StandardOutput, deadline.Token,
            onEvent is null ? null : line => onEvent(line, process.StandardInput));
        Task<string> error = DrainAsync(process.StandardError, deadline.Token);
        try
        {
            await process.StandardInput.WriteAsync(input.AsMemory(), deadline.Token);
            await process.StandardInput.FlushAsync(deadline.Token);
            if (onEvent is null) process.StandardInput.Close();
            await exited.Task.WaitAsync(deadline.Token);
            return new(process.ExitCode, await output, await error);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, error);
        }
    }

    private static async Task<string> DrainAsync(StreamReader stream, CancellationToken token,
        Func<string, Task>? onLine = null)
    {
        char[] buffer = new char[4096];
        var text = new System.Text.StringBuilder();
        var line = new System.Text.StringBuilder();
        int count;
        while ((count = await stream.ReadAsync(buffer.AsMemory(), token)) != 0)
        {
            if (text.Length + count > 1024 * 1024)
                throw new InvalidOperationException("Demo process output exceeded its budget.");
            text.Append(buffer, 0, count);
            if (onLine is not null)
                for (int i = 0; i < count; i++)
                {
                    if (buffer[i] == '\n')
                    {
                        await onLine(line.ToString());
                        line.Clear();
                    }
                    else
                        line.Append(buffer[i]);
                }
        }
        return text.ToString();
    }
}

internal sealed record DemoResult(int ExitCode, string Output, string Error);
