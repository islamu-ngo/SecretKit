using System.Diagnostics;
using System.Globalization;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Xml.Linq;

namespace SecretKit.Release;

public sealed record VerificationHost(string Name, string Lane, string? Filter = null, int Minimum = 1);

public static class Verification
{
    public const string PublicInstallFilter =
        "/*/*/(PackageInstallTests|PackageSelectionTests|PlatformInstallTests|ArchitectureBoundaryTests)/*";

    public static IReadOnlyList<VerificationHost> Hosts { get; } = Array.AsReadOnly<VerificationHost>(
    [
        new("SecretKit.Core.Tests", "ordinary"),
        new("SecretKit.Infisical.Tests", "ordinary"),
        new("SecretKit.AzureKeyVault.Tests", "ordinary"),
        new("SecretKit.Consumer.Tests", "ordinary"),
        new("SecretKit.Assessment.Tests", "ordinary"),
        new("SecretKit.Configuration.Tests", "ordinary"),
        new("SecretKit.Hosting.Tests", "ordinary"),
        new("SecretKit.Infisical.Management.Tests", "ordinary"),
        new("SecretKit.AzureKeyVault.Management.Tests", "ordinary"),
        new("SecretKit.Release.Tests", "ordinary"),
        new("SecretKit.ProviderContract.Tests", "ordinary"),
        new("SecretKit.Package.Tests", "post-pack", Minimum: 127),
        new("SecretKit.Demo.Tests", "post-pack", Minimum: 67),
        new("SecretKit.Release.Tests", "post-pack"),
        new("SecretKit.Package.Tests", "public-install", PublicInstallFilter, 27),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/ProcessLifetimeTests/*", 3),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/OwnedSandboxTests/*", 11),
        new("SecretKit.AzureKeyVault.Conformance.Tests", "offline-conformance", "/*/*/AzureVaultFixtureProvisionerTests/*Delivery*", 1),
        new("SecretKit.AzureKeyVault.Conformance.Tests", "offline-conformance", "/*/*/AzureVaultFixtureProvisionerTests/Webhook*", 1),
        new("SecretKit.AzureKeyVault.Conformance.Tests", "offline-conformance", "/*/*/AzureVaultFixtureProvisionerTests/HostedWebhook*", 1),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/LocalProfileAdmissionTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/LocalNativeProofTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/LocalProfileFunctionalAdmissionTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/LocalProfileUpdateWitnessTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/InfisicalPeriodicRenewalGateTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/InfisicalRotationCancellationAdmissionTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/RuntimeHardeningAdmissionTests/*"),
        new("SecretKit.Infisical.Conformance.Tests", "offline-conformance", "/*/*/EnterpriseHardeningAdmissionTests/*")
    ]);

    public static void ValidateCoverage(string source, IReadOnlyList<VerificationHost> hosts)
    {
        Manifest.ExactSet(hosts.Where(host => host.Lane != "offline-conformance").Select(host => host.Name).Distinct(),
            Discover("SecretKit.slnx"), "verification-host-coverage");
        Manifest.ExactSet(hosts.Where(host => host.Lane == "offline-conformance").Select(host => host.Name).Distinct(),
            Discover("SecretKit.Conformance.slnx"), "verification-conformance-host-coverage");
        // These selections are an offline safety boundary, independent of the
        // solution inventory. A whole conformance host is never an admissible lane.
        Manifest.ExactSet(hosts.Where(host => host.Lane == "offline-conformance")
            .Select(host => $"{host.Name}:{host.Filter}:{host.Minimum}"),
        [
            "SecretKit.Infisical.Conformance.Tests:/*/*/ProcessLifetimeTests/*:3",
            "SecretKit.Infisical.Conformance.Tests:/*/*/OwnedSandboxTests/*:11",
            "SecretKit.AzureKeyVault.Conformance.Tests:/*/*/AzureVaultFixtureProvisionerTests/*Delivery*:1",
            "SecretKit.AzureKeyVault.Conformance.Tests:/*/*/AzureVaultFixtureProvisionerTests/Webhook*:1",
            "SecretKit.AzureKeyVault.Conformance.Tests:/*/*/AzureVaultFixtureProvisionerTests/HostedWebhook*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/LocalProfileAdmissionTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/LocalNativeProofTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/LocalProfileFunctionalAdmissionTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/LocalProfileUpdateWitnessTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/InfisicalPeriodicRenewalGateTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/InfisicalRotationCancellationAdmissionTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/RuntimeHardeningAdmissionTests/*:1",
            "SecretKit.Infisical.Conformance.Tests:/*/*/EnterpriseHardeningAdmissionTests/*:1"
        ], "verification-offline-coverage");

        IEnumerable<string> Discover(string solution)
        {
            foreach (XElement project in XDocument.Load(Path.Combine(source, solution)).Descendants("Project"))
            {
                string path = project.Attribute("Path")!.Value;
                XDocument definition = XDocument.Load(Path.Combine(source, path));
                if (definition.Descendants("IsTestProject").Any(element => element.Value == "true"))
                    yield return Path.GetFileNameWithoutExtension(path);
            }
        }
    }

    public static async Task<int> RunAsync(string source, string lane,
        IReadOnlyDictionary<string, string>? inputs = null)
    {
        source = Path.GetFullPath(source);
        Guard.Require(lane is "ordinary" or "post-pack" or "offline-conformance" or "public-install", "verification-lane");
        Guard.Require(lane != "post-pack" || inputs is not null, "verification-post-pack-inputs");
        if (lane == "public-install")
        {
            string[] selectors = ["SECRETKIT_CANDIDATE_DIRECTORY", "SECRETKIT_CANDIDATE_VERSION",
                "SECRETKIT_PLATFORM_OBSERVATION"];
            var selected = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string selector in selectors)
            {
                string? value = inputs is null ? Environment.GetEnvironmentVariable(selector) :
                    inputs.GetValueOrDefault(selector);
                Guard.Require(!string.IsNullOrWhiteSpace(value), "verification-public-install-inputs");
                selected.Add(selector, value!);
            }
            Guard.Require(Path.IsPathFullyQualified(selected[selectors[0]]) &&
                Path.IsPathFullyQualified(selected[selectors[2]]), "verification-public-install-paths");
            CandidateInputs candidate = Candidate.ReadInputs(selected[selectors[0]]);
            Guard.Require(candidate.Manifest.Version == selected[selectors[1]], "verification-public-install-version");
            inputs = selected;
        }
        ValidateCoverage(source, Hosts);
        bool failed = false;
        foreach (VerificationHost host in Hosts.Where(host => host.Lane == lane))
        {
            string executable = Path.Combine(source, "tests", host.Name, "bin", "Release", "net10.0", host.Name + ".dll");
            if (!File.Exists(executable))
            {
                Console.WriteLine($"verification-result:{host.Name}:missing:{host.Filter}");
                failed = true;
                continue;
            }
            var arguments = new List<string> { executable, "--minimum-expected-tests",
                host.Minimum.ToString(CultureInfo.InvariantCulture), "--zero-tests-policy", "strict" };
            string? filter = host.Name == "SecretKit.Release.Tests" ? ReleaseFilter(executable, lane) : host.Filter;
            if (filter is not null)
                arguments.AddRange(["--treenode-filter", filter]);
            if (lane is "post-pack" or "public-install")
                arguments.AddRange(["--maximum-parallel-tests", "2"]);
            try
            {
                int exit = await RunProcessAsync(source, arguments, inputs);
                Console.WriteLine($"verification-result:{host.Name}:{exit}:{host.Filter}");
                failed |= exit != 0;
            }
            catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception)
            {
                Console.WriteLine($"verification-result:{host.Name}:launch-failed:{host.Filter}");
                failed = true;
            }
        }
        if (lane == "ordinary")
            foreach (string sample in new[] { "RuntimeConfiguration", "ProviderAssessment" })
            {
                string executable = Path.Combine(source, "samples", sample, "bin", "Release", "net10.0", sample + ".dll");
                if (!File.Exists(executable))
                {
                    Console.WriteLine($"verification-result:{sample}:missing");
                    failed = true;
                    continue;
                }
                try
                {
                    int exit = await RunProcessAsync(source, [executable]);
                    Console.WriteLine($"verification-result:{sample}:{exit}");
                    failed |= exit != 0;
                }
                catch (Exception error) when (error is IOException or System.ComponentModel.Win32Exception)
                {
                    Console.WriteLine($"verification-result:{sample}:launch-failed");
                    failed = true;
                }
            }
        return failed ? 1 : 0;
    }

    private static string ReleaseFilter(string executable, string lane)
    {
        using FileStream input = File.OpenRead(executable);
        using var image = new PEReader(input);
        MetadataReader metadata = image.GetMetadataReader();
        string[] classes = metadata.TypeDefinitions.Select(metadata.GetTypeDefinition)
            .Where(type => type.GetMethods().Any(method =>
                metadata.GetMethodDefinition(method).GetCustomAttributes().Any(attribute =>
                {
                    EntityHandle constructor = metadata.GetCustomAttribute(attribute).Constructor;
                    if (constructor.Kind != HandleKind.MemberReference) return false;
                    EntityHandle owner = metadata.GetMemberReference((MemberReferenceHandle)constructor).Parent;
                    return owner.Kind == HandleKind.TypeReference &&
                        metadata.GetString(metadata.GetTypeReference((TypeReferenceHandle)owner).Name) == "TestAttribute";
                })))
            .Select(type => metadata.GetString(type.Name)).Order(StringComparer.Ordinal).ToArray();
        string[] installed = ["ArchiveTests", "NativeObservationReportTests"];
        Guard.Require(installed.All(classes.Contains) && classes.Length > installed.Length, "verification-release-coverage");
        string[] selected = classes.Where(name => installed.Contains(name) == (lane == "post-pack")).ToArray();
        return "/*/*/(" + string.Join('|', selected) + ")/*";
    }

    internal static async Task<int> RunProcessAsync(string source, IEnumerable<string> arguments,
        IReadOnlyDictionary<string, string>? inputs = null)
    {
        var start = new ProcessStartInfo("dotnet")
        {
            WorkingDirectory = source,
            UseShellExecute = false
        };
        foreach (string argument in arguments) start.ArgumentList.Add(argument);
        foreach (string key in start.Environment.Keys.Where(key =>
            key.StartsWith("SECRETKIT_", StringComparison.Ordinal)).ToArray())
            start.Environment.Remove(key);
        start.Environment["MSBUILDTERMINALLOGGER"] = "off";
        if (inputs is not null)
            foreach ((string key, string value) in inputs) start.Environment[key] = value;
        using Process process = Process.Start(start) ?? throw new IOException("verification-launch");
        await process.WaitForExitAsync();
        return process.ExitCode;
    }
}
