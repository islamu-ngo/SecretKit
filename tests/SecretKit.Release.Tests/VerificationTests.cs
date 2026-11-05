using System.Diagnostics;
using System.Xml.Linq;
using SecretKit.Release;

namespace SecretKit.Release.Tests;

public sealed class VerificationTests
{
    [Test]
    [Arguments("public-install", false)]
    [Arguments("post-pack", true)]
    public async Task CompiledPackageDiscoveryPreservesPublicAndCompleteLocalSelections(string lane, bool local)
    {
        VerificationHost host = Verification.Hosts.Single(item => item.Name == "SecretKit.Package.Tests" && item.Lane == lane);
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = Repository.Source,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        start.ArgumentList.Add(Path.Combine(Repository.Source,
            "tests/SecretKit.Package.Tests/bin/Release/net10.0/SecretKit.Package.Tests.dll"));
        start.ArgumentList.Add("--list-tests");
        if (host.Filter is not null)
        {
            start.ArgumentList.Add("--treenode-filter");
            start.ArgumentList.Add(host.Filter);
        }
        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(1));
        using Process process = Process.Start(start)!;
        Task<string> stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
        Task<string> stderr = process.StandardError.ReadToEndAsync(deadline.Token);
        try
        {
            await process.WaitForExitAsync(deadline.Token);
            string discovery = await stdout;
            _ = await stderr;
            await Assert.That(process.ExitCode).IsEqualTo(0);
            await Assert.That(discovery.Contains("MinimalFamilyInstallsAndRunsWithoutProjectReferencesOrApplicationFrameworks",
                StringComparison.Ordinal)).IsTrue();
            await Assert.That(discovery.Contains("SelectedOriginalsExerciseSeparateIntegrationQualityScenarios",
                StringComparison.Ordinal)).IsEqualTo(local);
            await Assert.That(discovery.Contains("OriginalLocalProfileInstallsAndRunsIndependentModes",
                StringComparison.Ordinal)).IsEqualTo(local);
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
    }

    [Test]
    public async Task PublicInstallRejectsMissingExplicitSelectorsBeforeChildren()
    {
        using var fixture = new Repository();
        await Assert.That(() => Verification.RunAsync(fixture.Root, "public-install",
            new Dictionary<string, string>())).Throws<ReleaseException>();
        await Assert.That(Directory.Exists(Path.Combine(fixture.Root, "artifacts"))).IsFalse();
    }

    [Test]
    [Arguments("/*/*/ProcessLifetimeTests/*")]
    [Arguments("/*/*/OwnedSandboxTests/*")]
    [Arguments("/*/*/AzureVaultFixtureProvisionerTests/*Delivery*")]
    [Arguments("/*/*/AzureVaultFixtureProvisionerTests/Webhook*")]
    [Arguments("/*/*/AzureVaultFixtureProvisionerTests/HostedWebhook*")]
    [Arguments("/*/*/LocalProfileAdmissionTests/*")]
    [Arguments("/*/*/LocalNativeProofTests/*")]
    [Arguments("/*/*/LocalProfileFunctionalAdmissionTests/*")]
    [Arguments("/*/*/LocalProfileUpdateWitnessTests/*")]
    [Arguments("/*/*/InfisicalPeriodicRenewalGateTests/*")]
    [Arguments("/*/*/InfisicalRotationCancellationAdmissionTests/*")]
    [Arguments("/*/*/RuntimeHardeningAdmissionTests/*")]
    [Arguments("/*/*/EnterpriseHardeningAdmissionTests/*")]
    public async Task EverySafeConformanceSelectionIsRequired(string filter)
    {
        using var fixture = new Repository();
        VerificationHost[] omitted = Verification.Hosts.Where(host => host.Filter != filter).ToArray();

        await Assert.That(() => Verification.ValidateCoverage(fixture.Root, omitted)).Throws<ReleaseException>();
    }

    [Test]
    public async Task MissingHostsFailWithoutPreventingIndependentHostResults()
    {
        using var fixture = new Repository();
        fixture.CopyHost("SecretKit.ProviderContract.Tests", "SecretKit.Core.Tests");

        (int exit, string output) = await fixture.Run("ordinary");

        Console.WriteLine(output);
        await Assert.That(exit).IsEqualTo(1);
        await Assert.That(output.Contains("verification-result:SecretKit.Core.Tests:missing",
            StringComparison.Ordinal)).IsTrue();
        await Assert.That(output.Contains("verification-result:SecretKit.ProviderContract.Tests:0",
            StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task AddedSolutionTestHostFailsCoverageBeforeLaunchingChildren()
    {
        using var fixture = new Repository();
        fixture.AddHost("Unassigned.Tests");

        (int exit, string output) = await fixture.Run("ordinary");

        await Assert.That(exit).IsEqualTo(1);
        await Assert.That(output.Contains("verification-host-coverage", StringComparison.Ordinal)).IsTrue();
        await Assert.That(output.Contains("verification-result:", StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task SafeConformanceSelectionsRejectRealZeroDiscoveryAndContinue()
    {
        using var fixture = new Repository();
        fixture.CopyHost("SecretKit.Infisical.Conformance.Tests", "SecretKit.Core.Tests");
        fixture.CopyHost("SecretKit.AzureKeyVault.Conformance.Tests", "SecretKit.Core.Tests");

        (int exit, string output) = await fixture.Run("offline-conformance");

        await Assert.That(exit).IsEqualTo(1);
        await Assert.That(output.Split('\n').Count(line =>
            line.StartsWith("verification-result:", StringComparison.Ordinal))).IsEqualTo(13);
        await Assert.That(output.Contains("verification-result:SecretKit.Infisical.Conformance.Tests:0",
            StringComparison.Ordinal)).IsFalse();
        await Assert.That(output.Contains("verification-result:SecretKit.AzureKeyVault.Conformance.Tests:0",
            StringComparison.Ordinal)).IsFalse();
    }

    [Test]
    public async Task IncompletePostPackInputsFailBeforeLaunchingChildren()
    {
        using var fixture = new Repository();

        (int exit, string output) = await fixture.Run("post-pack", fixture.Root);

        await Assert.That(exit).IsEqualTo(1);
        await Assert.That(output.Contains("verification-result:", StringComparison.Ordinal)).IsFalse();
    }

    internal sealed class Repository : IDisposable
    {
        internal string Root { get; } = Path.Combine(Path.GetTempPath(),
            "secretkit-verification-" + Guid.NewGuid().ToString("N"));
        internal static string Source
        {
            get
            {
                DirectoryInfo? directory = new(AppContext.BaseDirectory);
                while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "SecretKit.slnx")))
                    directory = directory.Parent;
                return directory?.FullName ?? throw new InvalidOperationException("Repository unavailable.");
            }
        }

        internal Repository()
        {
            Directory.CreateDirectory(Root);
            File.Copy(Path.Combine(Source, "SecretKit.slnx"), Path.Combine(Root, "SecretKit.slnx"));
            File.Copy(Path.Combine(Source, "SecretKit.Conformance.slnx"), Path.Combine(Root, "SecretKit.Conformance.slnx"));
            foreach (string solution in new[] { "SecretKit.slnx", "SecretKit.Conformance.slnx" })
                foreach (XElement project in XDocument.Load(Path.Combine(Source, solution)).Descendants("Project"))
                {
                    string relative = project.Attribute("Path")!.Value;
                    string destination = Path.Combine(Root, relative);
                    Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                    File.Copy(Path.Combine(Source, relative), destination, overwrite: true);
                }
        }

        internal void AddHost(string name)
        {
            string path = $"tests/{name}/{name}.csproj";
            Directory.CreateDirectory(Path.Combine(Root, "tests", name));
            File.WriteAllText(Path.Combine(Root, path),
                "<Project><PropertyGroup><IsTestProject>true</IsTestProject></PropertyGroup></Project>");
            XDocument solution = XDocument.Load(Path.Combine(Root, "SecretKit.slnx"));
            solution.Root!.Add(new XElement("Project", new XAttribute("Path", path)));
            solution.Save(Path.Combine(Root, "SecretKit.slnx"));
        }

        internal void CopyHost(string name, string original)
        {
            string source = Path.Combine(Source, "tests", original, "bin", "Release", "net10.0");
            string destination = Path.Combine(Root, "tests", name, "bin", "Release", "net10.0");
            Directory.CreateDirectory(destination);
            foreach (string file in Directory.GetFiles(source))
                File.Copy(file, Path.Combine(destination, Path.GetFileName(file)));
            foreach (string extension in new[] { ".dll", ".deps.json", ".runtimeconfig.json" })
                File.Copy(Path.Combine(source, original + extension), Path.Combine(destination, name + extension));
            string intermediate = Path.Combine(Root, "tests", name, "obj");
            Directory.CreateDirectory(intermediate);
            File.Copy(Path.Combine(Source, "tests", original, "obj", "project.assets.json"),
                Path.Combine(intermediate, "project.assets.json"));
        }

        internal async Task<(int Exit, string Output)> Run(params string[] arguments)
        {
            string assembly = typeof(VerificationTests).Assembly.Location;
            var start = new ProcessStartInfo("dotnet")
            {
                WorkingDirectory = Root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false
            };
            foreach (string argument in new[] { "exec", "--runtimeconfig",
                Path.ChangeExtension(assembly, ".runtimeconfig.json"), "--depsfile",
                Path.ChangeExtension(assembly, ".deps.json"), typeof(Program).Assembly.Location,
                "verification" }.Concat(arguments))
                start.ArgumentList.Add(argument);
            foreach (string key in start.Environment.Keys.Where(key =>
                key.StartsWith("SECRETKIT_", StringComparison.Ordinal)).ToArray())
                start.Environment.Remove(key);
            // Ordinary execution must neither need nor consume a candidate.
            start.Environment["SECRETKIT_CANDIDATE_DIRECTORY"] = "unselected";
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            using Process process = Process.Start(start)!;
            Task<string> stdout = process.StandardOutput.ReadToEndAsync(deadline.Token);
            Task<string> stderr = process.StandardError.ReadToEndAsync(deadline.Token);
            try
            {
                await process.WaitForExitAsync(deadline.Token);
                return (process.ExitCode, await stdout + await stderr);
            }
            finally
            {
                if (!process.HasExited) process.Kill(entireProcessTree: true);
            }
        }

        public void Dispose() => Directory.Delete(Root, recursive: true);
    }
}
