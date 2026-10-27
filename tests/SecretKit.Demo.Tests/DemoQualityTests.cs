using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.TestFixtures;

namespace SecretKit.Demo.Tests;

public sealed class DemoQualityTests
{
    [Test]
    [Arguments("trim")]
    [Arguments("aot")]
    public async Task SelectedConsoleProfileRecordsPublishAndRunObservations(string profile)
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string version = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_VERSION") ??
            throw new InvalidOperationException("Select exact demo version.");
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(
            Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY") ??
                throw new InvalidOperationException("Select exact demo originals."), version);
        string run = Path.Combine(root, "artifacts/runtime-adoption-hardening/quality",
            profile + "-" + Guid.NewGuid().ToString("N"));
        ConsumerInstallation installation = candidate.PrepareConsumer(run, "minimal");
        string app = Path.Combine(run, "app");
        string shared = Path.Combine(run, "Infisical.Demos");
        Directory.CreateDirectory(app);
        Directory.CreateDirectory(shared);
        string[] sources =
        [
            "samples/Infisical.ConsoleDemo/Infisical.ConsoleDemo.csproj",
            "samples/Infisical.ConsoleDemo/Program.cs",
            "samples/Infisical.ConsoleDemo/ConsoleDemoApplication.cs",
            "samples/Infisical.ConsoleDemo/ConsoleDemoCommand.cs",
            "samples/Infisical.ConsoleDemo/ConsoleDemoOutcomes.cs",
            "samples/Infisical.ConsoleDemo/packages.lock.json",
            "samples/Infisical.Demos/DemoInput.cs",
            "samples/Infisical.Demos/DemoInputReader.cs",
            "samples/Infisical.Demos/MutationInput.cs",
            "samples/Infisical.Demos/DemoTokenSource.cs",
            "samples/Infisical.Demos/DemoOutput.cs"
        ];
        foreach (string source in sources)
            File.Copy(Path.Combine(root, source), Path.Combine(
                source.Contains("Infisical.Demos/", StringComparison.Ordinal) ? shared : app, Path.GetFileName(source)));
        var sourceBindings = sources.Select(path => new
        {
            path,
            sha256 = Hash(Path.Combine(path.Contains("Infisical.Demos/", StringComparison.Ordinal)
                ? shared : app, Path.GetFileName(path)))
        }).ToArray();
        string project = Path.Combine(app, "Infisical.ConsoleDemo.csproj");
        string[] properties = [.. installation.Properties, "-r", "linux-x64",
            "-p:SelfContained=true", profile == "aot" ? "-p:PublishAot=true" : "-p:PublishTrimmed=true"];
        // RID/tool packs belong to this generated profile lock, never the source app lock.
        string[] restore = ["restore", project, "--force-evaluate", "--configfile", installation.Configuration,
            .. properties];
        var restored = await CaptureAsync(app, restore);
        var commands = new List<object> { new { arguments = restore, result = restored } };
        CommandResult? published = null;
        CommandResult? help = null;
        CommandResult? read = null;
        if (restored.ExitCode == 0)
        {
            string[] lockedRestore = ["restore", project, "--locked-mode", "--configfile",
                installation.Configuration, .. properties];
            var locked = await CaptureAsync(app, lockedRestore);
            commands.Add(new { arguments = lockedRestore, result = locked });
            if (locked.ExitCode != 0)
                throw new InvalidOperationException("Isolated locked profile restore failed: " + locked.Output + locked.Error);
            candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"),
                installation.Packages, "minimal");
            string[] publish = ["publish", project, "-c", "Release", "--no-restore",
                "--self-contained", "true", "-o", Path.Combine(run, "published"), .. properties];
            published = await CaptureAsync(app, publish);
            commands.Add(new { arguments = publish, result = published });
            if (published.ExitCode == 0)
            {
                string executable = Path.Combine(run, "published/Infisical.ConsoleDemo");
                help = await CaptureAsync(app, ["--help"], executable);
                await using var server = new ControlledInfisicalServer(_ => new(200,
                    """{"secret":{"secretKey":"key","secretValue":"synthetic-quality-value","secretValueHidden":false,"workspace":"project","environment":"env","secretPath":"/","version":1}}"""));
                string input = JsonSerializer.Serialize(new
                {
                    origin = server.Origin.AbsoluteUri,
                    project = "project",
                    environment = "env",
                    folder = "/",
                    key = "key",
                    token = "synthetic-quality-token",
                    allowLoopbackDevelopmentHttp = true
                });
                read = await CaptureAsync(app, ["read"], executable, input);
            }
        }
        bool observedSuccess = published?.ExitCode == 0 && help?.ExitCode == 0 && read?.ExitCode == 0;
        var record = new
        {
            kind = "selected-console-analysis",
            observational = true,
            profile,
            version,
            rid = "linux-x64",
            sdk = (await CommandAsync(app, ["--version"])).Trim(),
            runtime = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription,
            os = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
            osVersion = Environment.OSVersion.VersionString,
            observedSuccess,
            scope = "Console help and controlled local read only; no library-wide compatibility claim.",
            commands,
            help,
            read,
            originals = LocalPackageCandidate.PackageIds.Select(id => new
            {
                id,
                sha256 = Hash(candidate.ArchivePath(id))
            }).ToArray(),
            sources = sourceBindings,
            generatedProfileLockSha256 = Hash(Path.Combine(app, "packages.lock.json"))
        };
        string report = Path.Combine(run, "compatibility.json");
        await File.WriteAllTextAsync(report, JsonSerializer.Serialize(record));
        using var saved = JsonDocument.Parse(await File.ReadAllTextAsync(report));
        JsonElement result = saved.RootElement;
        await Assert.That(result.GetProperty("observational").GetBoolean()).IsTrue();
        bool executionsPassed = new[] { "help", "read" }.All(name =>
            result.GetProperty(name).ValueKind == JsonValueKind.Object &&
            result.GetProperty(name).GetProperty("ExitCode").GetInt32() == 0);
        bool commandsPassed = result.GetProperty("commands").EnumerateArray()
            .All(command => command.GetProperty("result").GetProperty("ExitCode").GetInt32() == 0);
        await Assert.That(result.GetProperty("observedSuccess").GetBoolean())
            .IsEqualTo(commandsPassed && executionsPassed);
        Console.WriteLine("P6 compatibility record: " + report);
    }

    [Test]
    public async Task FixedWorkloadMeasuresRealCollectionsExportsLeasesAndRetirement()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string selected = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_DIRECTORY") ??
            throw new InvalidOperationException("Select exact demo originals.");
        string version = Environment.GetEnvironmentVariable("SECRETKIT_DEMO_CANDIDATE_VERSION") ??
            throw new InvalidOperationException("Select exact demo version.");
        LocalPackageCandidate candidate = LocalPackageCandidate.Select(selected, version);
        string run = Path.Combine(root, "artifacts/runtime-adoption-hardening/quality", Guid.NewGuid().ToString("N"));
        ConsumerInstallation installation = candidate.PrepareConsumer(run, "configuration");
        string app = Path.Combine(run, "app");
        Directory.CreateDirectory(app);
        string[] sources =
        [
            "samples/Infisical.Demos/Measurements.cs",
            "samples/RuntimeConfiguration/RuntimeIntegrationCoordinator.cs",
            "samples/RuntimeConfiguration/RuntimeGenerationLease.cs"
        ];
        foreach (string source in sources)
            File.Copy(Path.Combine(root, source), Path.Combine(app, Path.GetFileName(source)));
        string project = Path.Combine(app, "Measurements.csproj");
        await File.WriteAllTextAsync(project, $"""
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <OutputType>Exe</OutputType>
                <TargetFramework>net10.0</TargetFramework>
                <LangVersion>14.0</LangVersion>
                <ImplicitUsings>enable</ImplicitUsings>
                <Nullable>enable</Nullable>
                <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
                <IsPackable>false</IsPackable>
                <ManagePackageVersionsCentrally>false</ManagePackageVersionsCentrally>
                <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="SecretKit.Core" Version="[{version}]" />
                <PackageReference Include="SecretKit.Infisical" Version="[{version}]" />
                <PackageReference Include="SecretKit.Extensions.Configuration" Version="[{version}]" />
              </ItemGroup>
            </Project>
            """);
        await File.WriteAllTextAsync(Path.Combine(app, "Program.cs"),
            "Console.WriteLine(await SecretKit.Samples.Infisical.Measurements.RunAsync());\n");
        await CommandAsync(app, ["restore", project, "--configfile", installation.Configuration,
            .. installation.Properties]);
        await CommandAsync(app, ["restore", project, "--locked-mode", "--configfile", installation.Configuration,
            .. installation.Properties]);
        candidate.VerifyRestored(Path.Combine(installation.Intermediate, "project.assets.json"),
            installation.Packages, "configuration");
        await CommandAsync(app, ["build", project, "-c", "Release", "--no-restore", .. installation.Properties]);
        string output = await CommandAsync(app, [Path.Combine(installation.Binary, "Release/net10.0/Measurements.dll")]);
        using JsonDocument measured = JsonDocument.Parse(output);
        JsonElement result = measured.RootElement;
        await Assert.That(result.GetProperty("keys").GetInt32()).IsEqualTo(8);
        await Assert.That(result.GetProperty("warmup").GetInt32()).IsEqualTo(16);
        await Assert.That(result.GetProperty("repetitions").GetInt32()).IsEqualTo(128);
        await Assert.That(result.GetProperty("rows").GetArrayLength()).IsEqualTo(6);
        foreach (JsonElement row in result.GetProperty("rows").EnumerateArray())
        {
            await Assert.That(row.GetProperty("ticks").GetArrayLength()).IsEqualTo(128);
            await Assert.That(row.GetProperty("processAllocatedBytes").GetArrayLength()).IsEqualTo(128);
        }
        JsonElement state = result.GetProperty("invariants");
        await Assert.That(state.GetProperty("replacements").GetInt32()).IsEqualTo(64);
        await Assert.That(state.GetProperty("liveAfterEachReplacement").GetArrayLength()).IsEqualTo(64);
        await Assert.That(state.GetProperty("liveAfterEachReplacement").EnumerateArray()
            .All(item => item.GetInt32() == 2)).IsTrue();
        await Assert.That(state.GetProperty("peakLive").GetInt32()).IsEqualTo(3);
        await Assert.That(state.GetProperty("afterRelease").GetInt32()).IsEqualTo(1);
        await Assert.That(state.GetProperty("finalLive").GetInt32()).IsEqualTo(0);
        await Assert.That(state.GetProperty("Created").GetInt32()).IsEqualTo(65);
        await Assert.That(state.GetProperty("Disposed").GetInt32()).IsEqualTo(65);
        await Assert.That(state.GetProperty("DuplicateDisposals").GetInt32()).IsEqualTo(0);
        await Assert.That(state.GetProperty("coherent").GetBoolean()).IsTrue();
        await Assert.That(state.GetProperty("shutdownHeld").GetBoolean()).IsTrue();
        await Assert.That(state.GetProperty("cancellationPreservedGeneration").GetBoolean()).IsTrue();
        // No assertion constrains elapsed time, allocations or GC scheduling.
        var record = new
        {
            measured = result.Clone(),
            version,
            sdk = (await CommandAsync(app, ["--version"])).Trim(),
            originals = LocalPackageCandidate.PackageIds.Select(id => new
            {
                id,
                sha256 = Hash(candidate.ArchivePath(id))
            }).ToArray(),
            sources = sources.Select(path => new { path, sha256 = Hash(Path.Combine(app, Path.GetFileName(path))) }).ToArray()
        };
        await File.WriteAllTextAsync(Path.Combine(run, "measurements.json"), JsonSerializer.Serialize(record));
        Console.WriteLine("P6 measurement record: " + Path.Combine(run, "measurements.json"));
    }

    private static string Hash(string path) =>
        Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(path)));

    private static async Task<string> CommandAsync(string cwd, string[] arguments)
    {
        CommandResult result = await CaptureAsync(cwd, arguments);
        if (result.ExitCode != 0)
            throw new InvalidOperationException("Isolated quality command failed: " + result.Output + result.Error);
        return result.Output;
    }

    private sealed record CommandResult(int ExitCode, string Output, string Error);

    private static async Task<CommandResult> CaptureAsync(string cwd, string[] arguments,
        string executable = "dotnet", string? input = null)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        using var process = new Process
        {
            StartInfo = new(executable)
            {
                WorkingDirectory = cwd,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            }
        };
        foreach (string argument in arguments) process.StartInfo.ArgumentList.Add(argument);
        process.StartInfo.Environment["ImportDirectoryBuildProps"] = "false";
        process.StartInfo.Environment["ImportDirectoryBuildTargets"] = "false";
        process.StartInfo.Environment["DOTNET_CLI_TELEMETRY_OPTOUT"] = "1";
        process.Start();
        Task<string> output = process.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> error = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            if (input is not null) await process.StandardInput.WriteAsync(input.AsMemory(), deadline.Token);
            process.StandardInput.Close();
            await process.WaitForExitAsync(deadline.Token);
            string text = await output;
            string diagnostics = await error;
            return new(process.ExitCode, text, diagnostics);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            await Task.WhenAll(output, error);
        }
    }
}
