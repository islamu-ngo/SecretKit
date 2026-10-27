using System.Diagnostics;
using System.IO.Compression;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using SecretKit.TestFixtures;

namespace SecretKit.Package.Tests;

public sealed class PackageInstallTests
{
    [Test]
    public async Task MinimalFamilyInstallsAndRunsWithoutProjectReferencesOrApplicationFrameworks()
    {
        DateTimeOffset startedAt = DateTimeOffset.UtcNow;
        string? sourceCommit = null;
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        var candidate = PackageCandidate.FromEnvironment(root);
        string fixture = Path.Combine(root, "tests", "fixtures", "SecretKit.PackageConsumer");
        string outputs = Path.Combine(root, "artifacts", "package-consumers", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(outputs);
        foreach (string package in PackageCandidate.PackageIds)
        {
            using ZipArchive archive = ZipFile.OpenRead(candidate.ArchivePath(package));
            await Assert.That(archive.GetEntry("README.md") is not null).IsTrue();
            await Assert.That(archive.GetEntry("THIRD-PARTY-NOTICES.md") is not null).IsTrue();
            await VerifyXmlDocumentationAsync(archive, package);
            using Stream manifest = archive.GetEntry($"{package}.nuspec")!.Open();
            XDocument metadata = XDocument.Load(manifest);
            XNamespace ns = metadata.Root!.Name.Namespace;
            string commit = metadata.Descendants(ns + "repository").Single().Attribute("commit")!.Value;
            sourceCommit ??= commit;
            await Assert.That(commit).IsEqualTo(sourceCommit);
            await Assert.That(metadata.Root.Element(ns + "metadata")!.Element(ns + "license")!.Value).IsEqualTo("MIT");
            if (package == "SecretKit.Core")
            {
                await Assert.That(metadata.Descendants(ns + "dependency").Any()).IsFalse();
            }
        }

        var installation = candidate.PrepareConsumer(outputs);
        string intermediate = installation.Intermediate;
        string binary = installation.Binary;
        string[] properties = installation.Properties;
        await Run(root, ["restore", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"),
            "--configfile", installation.Configuration, .. properties]);
        candidate.VerifyRestored(Path.Combine(intermediate, "project.assets.json"), installation.Packages);
        await Run(root, ["build", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"), "--no-restore",
            "--configuration", "Release", .. properties]);
        string result = await Run(root, [Path.Combine(binary, "Release", "net10.0", "SecretKit.PackageConsumer.dll")]);
        await Assert.That(result.Contains("PACKAGE_CONSUMER_OK", StringComparison.Ordinal)).IsTrue();

        using JsonDocument assets = JsonDocument.Parse(await File.ReadAllTextAsync(Path.Combine(intermediate, "project.assets.json")));
        foreach (JsonProperty library in assets.RootElement.GetProperty("libraries").EnumerateObject())
        {
            await Assert.That(library.Value.GetProperty("type").GetString()).IsEqualTo("package");
            await Assert.That(library.Name.StartsWith("Infisical.Sdk/", StringComparison.OrdinalIgnoreCase)).IsFalse();
            await Assert.That(ExcludedFromMinimalConsumer(library.Name)).IsFalse();
        }

        foreach (JsonProperty framework in assets.RootElement.GetProperty("project").GetProperty("frameworks").EnumerateObject())
        {
            await Assert.That(framework.Value.GetProperty("frameworkReferences")
                .EnumerateObject().Any(reference => reference.Name == "Microsoft.AspNetCore.App")).IsFalse();
        }
        string sdkVersion = (await Run(root, ["--version"])).Trim();
        await PlatformInstallTests.ObserveAsync(candidate, sourceCommit!, startedAt, 0, 0, sdkVersion);
    }

    internal static async Task VerifyXmlDocumentationAsync(ZipArchive archive, string package)
    {
        string[] members = package switch
        {
            "SecretKit.Core" =>
                ["T:SecretKit.Core.SecretMaterial", "M:SecretKit.Core.SecretMaterial.Copy"],
            "SecretKit.Infisical" =>
                ["T:SecretKit.Infisical.InfisicalTransportOptions", "P:SecretKit.Infisical.InfisicalTransportOptions.SafeDefault"],
            "SecretKit.Infisical.Management" =>
                ["T:SecretKit.Infisical.Management.ManagementClient", "P:SecretKit.Infisical.Management.ManagementClient.Authority"],
            "SecretKit.Extensions.Configuration" =>
                ["T:SecretKit.Extensions.Configuration.SecretConfigurationExport", "M:SecretKit.Extensions.Configuration.SecretConfigurationExport.Dispose"],
            _ => []
        };
        // Excluded Azure packages keep their own documentation scope.
        if (members.Length == 0) return;
        ZipArchiveEntry? entry = archive.GetEntry($"lib/net10.0/{package}.xml");
        await Assert.That(entry is not null && entry.Length is > 0 and <= 4 * 1024 * 1024).IsTrue();
        using Stream stream = entry!.Open();
        using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = 4 * 1024 * 1024
        });
        XDocument documentation = XDocument.Load(reader);
        await Assert.That(documentation.Root!.Element("assembly")!.Element("name")!.Value).IsEqualTo(package);
        foreach (string id in members)
        {
            XElement? member = documentation.Root.Element("members")!.Elements("member")
                .SingleOrDefault(element => (string?)element.Attribute("name") == id);
            await Assert.That(member is not null &&
                !string.IsNullOrWhiteSpace(member.Element("summary")?.Value)).IsTrue();
        }
    }

    [Test]
    [Arguments("Microsoft.EntityFrameworkCore/10.0.0")]
    [Arguments("Microsoft.AspNetCore.Example/10.0.0")]
    [Arguments("Npgsql/10.0.0")]
    [Arguments("MySqlConnector/2.4.0")]
    [Arguments("MySql.Data/9.0.0")]
    [Arguments("Microsoft.Data.SqlClient/6.0.0")]
    [Arguments("System.Data.SqlClient/4.9.0")]
    [Arguments("System.Data.Odbc/10.0.0")]
    [Arguments("MariaDB.ExampleDriver/1.0.0")]
    [Arguments("npgsql/10.0.0")]
    [Arguments("mysqlconnector/2.4.0")]
    [Arguments("system.data.odbc/10.0.0")]
    public async Task KnownExcludedDependenciesCannotEnterMinimalConsumer(string library)
    {
        await Assert.That(ExcludedFromMinimalConsumer(library)).IsTrue();
    }

    [Test]
    [Arguments("SecretKit.Core/0.1.0-preview.1")]
    [Arguments("Azure.Core/1.49.0")]
    [Arguments("Refit/10.0.1")]
    [Arguments("System.Memory.Data/10.0.0")]
    public async Task NonDatabaseDependenciesAreNotRejectedByNameAlone(string library)
    {
        await Assert.That(ExcludedFromMinimalConsumer(library)).IsFalse();
    }

    private static bool ExcludedFromMinimalConsumer(string library) =>
        library.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("Npgsql", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("MySql", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("Microsoft.Data.SqlClient", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("System.Data.SqlClient", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("System.Data.Odbc", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("MariaDB", StringComparison.OrdinalIgnoreCase) ||
        library.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase);

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
        _ = await standardError;
        await Assert.That(process.ExitCode).IsEqualTo(0).Because("Installed consumer process failed; protected diagnostics withheld.");
        return output;
    }
}
