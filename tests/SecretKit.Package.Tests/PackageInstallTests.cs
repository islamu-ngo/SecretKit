using System.Diagnostics;
using System.IO.Compression;
using System.Text.Json;
using System.Xml.Linq;

namespace SecretKit.Package.Tests;

public sealed class PackageInstallTests
{
    [Test]
    public async Task MinimalFamilyInstallsAndRunsWithoutProjectReferencesOrApplicationFrameworks()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        string packages = Path.Combine(root, "artifacts", "packages");
        string fixture = Path.Combine(root, "tests", "fixtures", "SecretKit.PackageConsumer");
        string outputs = Path.Combine(root, "artifacts", "package-consumers", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputs);
        foreach (string package in new[] { "SecretKit.Core", "SecretKit.Infisical", "SecretKit.AzureKeyVault", "SecretKit.Extensions.Configuration", "SecretKit.Extensions.Hosting", "SecretKit.Infisical.Management", "SecretKit.AzureKeyVault.Management" })
        {
            using ZipArchive archive = ZipFile.OpenRead(Path.Combine(packages, $"{package}.0.1.0-preview.1.nupkg"));
            await Assert.That(archive.GetEntry("README.md") is not null).IsTrue();
            await Assert.That(archive.GetEntry("THIRD-PARTY-NOTICES.md") is not null).IsTrue();
            using Stream manifest = archive.GetEntry($"{package}.nuspec")!.Open();
            XDocument metadata = XDocument.Load(manifest);
            XNamespace ns = metadata.Root!.Name.Namespace;
            await Assert.That(metadata.Root.Element(ns + "metadata")!.Element(ns + "license")!.Value).IsEqualTo("MIT");
            if (package == "SecretKit.Core")
            {
                await Assert.That(metadata.Descendants(ns + "dependency").Any()).IsFalse();
            }
        }

        string intermediate = Path.Combine(outputs, "obj") + Path.DirectorySeparatorChar;
        string binary = Path.Combine(outputs, "bin") + Path.DirectorySeparatorChar;
        string[] properties =
        [
            $"-p:RestorePackagesPath={Path.Combine(outputs, "packages")}",
            $"-p:BaseIntermediateOutputPath={intermediate}",
            $"-p:MSBuildProjectExtensionsPath={intermediate}",
            $"-p:BaseOutputPath={binary}"
        ];
        await Run(root, ["restore", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"),
            "--configfile", Path.Combine(fixture, "NuGet.Config"), .. properties]);
        await Run(root, ["build", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"), "--no-restore",
            "--configuration", "Release", .. properties]);
        string result = await Run(root, [Path.Combine(binary, "Release", "net10.0", "SecretKit.PackageConsumer.dll")]);
        await Assert.That(result.Contains("PACKAGE_CONSUMER_OK", StringComparison.Ordinal)).IsTrue();

        using JsonDocument assets = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(intermediate, "project.assets.json")));
        foreach (JsonProperty library in assets.RootElement.GetProperty("libraries").EnumerateObject())
        {
            await Assert.That(library.Value.GetProperty("type").GetString()).IsEqualTo("package");
            await Assert.That(library.Name.StartsWith("Infisical.Sdk/", StringComparison.OrdinalIgnoreCase)).IsFalse();
            await Assert.That(library.Name.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal) ||
                library.Name.StartsWith("Npgsql", StringComparison.Ordinal) ||
                library.Name.StartsWith("MySql", StringComparison.Ordinal) ||
                library.Name.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal)).IsFalse();
        }

        foreach (JsonProperty framework in assets.RootElement.GetProperty("project").GetProperty("frameworks").EnumerateObject())
        {
            await Assert.That(framework.Value.GetProperty("frameworkReferences")
                .EnumerateObject().Any(reference => reference.Name == "Microsoft.AspNetCore.App")).IsFalse();
        }
    }

    private static async Task<string> Run(string root, string[] arguments)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            },
            EnableRaisingEvents = true
        };
        foreach (string argument in arguments)
        {
            process.StartInfo.ArgumentList.Add(argument);
        }

        var exited = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        process.Exited += (_, _) => exited.TrySetResult();
        process.Start();
        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync();
        Task<string> standardError = process.StandardError.ReadToEndAsync();
        try
        {
            await exited.Task.WaitAsync(TimeSpan.FromMinutes(2));
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw;
        }

        string output = await standardOutput;
        string error = await standardError;
        await Assert.That(process.ExitCode).IsEqualTo(0).Because(output + error);
        return output;
    }
}
