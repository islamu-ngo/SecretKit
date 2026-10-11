using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using SecretKit.Core;
using SecretKit.Extensions.Configuration;
using SecretKit.Infisical;
using SecretKit.Samples.ProviderAssessment;
using SecretKit.Samples.RuntimeConfiguration;

internal static class InstalledInfisical
{
    internal static async Task RunAsync()
    {
        var origin = new Uri(Required("SECRETKIT_LIVE_ORIGIN"));
        Require(origin.Scheme == "http" && origin.Host == "127.0.0.1" && origin.AbsolutePath == "/");
        string project = Required("SECRETKIT_LIVE_PROJECT");
        string otherProject = Required("SECRETKIT_LIVE_OTHER_PROJECT");
        string expected = Required("SECRETKIT_LIVE_EXPECTED");
        string otherExpected = Required("SECRETKIT_LIVE_OTHER_EXPECTED");
        using var adminTokens = new Tokens(Required("SECRETKIT_LIVE_ADMIN_TOKEN"));
        using var runtimeTokens = new Tokens(Required("SECRETKIT_LIVE_RUNTIME_TOKEN"));
        using var deniedTokens = new Tokens(Required("SECRETKIT_LIVE_DENIED_TOKEN"));
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        await using var admin = new InfisicalClient(origin, adminTokens, network);
        await using var runtime = new InfisicalClient(origin, runtimeTokens, network);
        await using var denied = new InfisicalClient(origin, deniedTokens, network);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        const string key = "SDK_CONFORMANCE_VALUE";
        SecretReference Reference(InfisicalClient client, string selectedProject, string name = key,
            string environment = "dev", string path = "/", int? version = null) =>
            new(client.Authority, new InfisicalSecretAddress(selectedProject, environment, path, name, version));
        var selected = Reference(runtime, project);
        var delivered = await runtime.ReadAsync(selected, deadline.Token);
        Require(delivered.Status == SecretStatus.Success);
        using var read = delivered.Value;
        Require(read.Material.Reveal() == expected);
        Require(int.TryParse(read.Observation.Version, NumberStyles.None, CultureInfo.InvariantCulture, out int version) && version > 0);
        var versioned = await runtime.ReadAsync(Reference(runtime, project, version: version), deadline.Token);
        Require(versioned.Status == SecretStatus.Success);
        using (var exact = versioned.Value)
            Require(exact.Material.Reveal() == expected && exact.Observation.Version == read.Observation.Version);

        var concurrent = await Task.WhenAll(admin.ReadAsync(Reference(admin, project), deadline.Token).AsTask(),
            admin.ReadAsync(Reference(admin, otherProject), deadline.Token).AsTask());
        Require(concurrent.All(result => result.Status == SecretStatus.Success));
        using (var first = concurrent[0].Value)
        using (var second = concurrent[1].Value)
            Require(first.Material.Reveal() == expected && second.Material.Reveal() == otherExpected && expected != otherExpected);
        Require((await runtime.ReadAsync(Reference(runtime, project, "SDK_ABSENT_VALUE"), deadline.Token)).Status == SecretStatus.Absent);
        Require((await runtime.ReadAsync(Reference(runtime, otherProject), deadline.Token)).Status == SecretStatus.Denied);
        Require((await denied.ReadAsync(Reference(denied, project), deadline.Token)).Status == SecretStatus.Denied);
        var wrongEnvironment = await runtime.ReadAsync(Reference(runtime, project, environment: "sdk-missing"), deadline.Token);
        Require(wrongEnvironment.Status is SecretStatus.Absent or SecretStatus.Denied or SecretStatus.Invalid);
        var wrongPath = await runtime.ReadAsync(Reference(runtime, project, path: "/sdk-missing"), deadline.Token);
        Require(wrongPath.Status is SecretStatus.Absent or SecretStatus.Denied or SecretStatus.Invalid);
        using var replacement = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        var deniedTarget = Reference(runtime, project, "SDK_DENIED_PACKAGE_WRITE");
        var deniedReceipt = new MutationReceipt(deniedTarget);
        Require((await runtime.CreateAsync(deniedTarget, replacement, deniedReceipt, deadline.Token)).Status == SecretStatus.Denied);
        Require(deniedReceipt.Evidence == DispatchEvidence.Rejected);
        var scope = new InfisicalInventoryScope(admin.Authority, project, "dev", "/");
        var inventory = await admin.InspectAsync(scope, deadline.Token);
        Require(inventory.Status == SecretStatus.Success && inventory.Value.IsComplete && inventory.Value.Items.Count > 0);
        Console.WriteLine("INSTALLED_NATIVE_READ_WRITE_INVENTORY_AND_IDENTITIES_PASSED");

        var missingBootstrap = await BootstrapScenario.PrepareAsync(runtime,
            new Dictionary<string, SecretReference> { ["consumer:required"] = Reference(runtime, project, "SDK_ABSENT_VALUE") },
            deadline.Token);
        Require(missingBootstrap.Status == SecretStatus.Absent);
        var prepared = await BootstrapScenario.PrepareAsync(runtime,
            new Dictionary<string, SecretReference> { ["consumer:required"] = selected }, deadline.Token);
        Require(prepared.IsSuccess);
        using (var candidate = prepared.Value)
            Require(candidate.ExportOver(new Dictionary<string, string> { ["consumer:required"] = "local-default" })
                ["consumer:required"] == expected);
        using var loader = new SecretSnapshotLoader([new SecretSelection("required", runtime, selected)]);
        Require((await loader.RefreshAsync(deadline.Token)).IsSuccess);
        using var pinned = loader.Acquire();
        using var export = SecretConfigurationExport.CreateAcknowledgingManagedStrings(pinned,
            [new SecretConfigurationMapping("required", "consumer:required")]);
        var builder = new Microsoft.Extensions.Configuration.ConfigurationBuilder();
        builder.Add(export);
        using var configuration = (Microsoft.Extensions.Configuration.ConfigurationRoot)builder.Build();
        Require(configuration["consumer:required"] == expected);

        var optional = Reference(runtime, project, "SDK_OPTIONAL_PACKAGE_VALUE");
        var assessment = new AssessmentScenario(admin, runtime);
        FeatureRequirement[] requirements =
            [new("optional", false, [new KeyRequirement("optional", optional, DeliveryKind.Direct)])];
        var absent = await assessment.CheckAsync(scope, requirements, deadline.Token);
        Require(absent.CanProceed && !absent.Features.Single().CanEnable &&
            absent.Features.Single().Keys.Single().State == AssessmentState.Absent);
        var optionalTarget = Reference(admin, project, "SDK_OPTIONAL_PACKAGE_VALUE");
        var optionalReceipt = new MutationReceipt(optionalTarget);
        Require((await admin.CreateAsync(optionalTarget, replacement, optionalReceipt, deadline.Token)).IsSuccess);
        var present = await assessment.CheckAsync(scope, requirements, deadline.Token);
        Require(present.Features.Single().CanEnable);
        var deniedAssessment = new AssessmentScenario(admin, denied);
        var deniedReport = await deniedAssessment.CheckAsync(scope,
            [new FeatureRequirement("required", true, [new KeyRequirement("required", Reference(denied, project), DeliveryKind.Direct)])],
            deadline.Token);
        Require(deniedReport.Inventory.VisibleItems > 0 && !deniedReport.CanProceed &&
            deniedReport.Features.Single().Keys.Single().State == AssessmentState.Denied);
        var updateTarget = Reference(admin, project);
        var updateReceipt = new MutationReceipt(updateTarget);
        Require((await admin.UpdateValueAsync(updateTarget, replacement, updateReceipt, deadline.Token)).IsSuccess);
        Require(updateReceipt.Evidence == DispatchEvidence.Applied);
        Require((await loader.RefreshAsync(deadline.Token)).IsSuccess);
        using var current = loader.Acquire();
        using var oldRead = pinned.Read("required");
        using var currentRead = current.Read("required");
        Require(oldRead.Material.Reveal() == expected && currentRead.Material.Reveal() == replacement.Reveal());
        Require(configuration["consumer:required"] == expected);
        Console.WriteLine("INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED");
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value : throw new InvalidOperationException("Missing explicit installed live input.");
    private static void Require(bool value)
    {
        if (!value) throw new InvalidOperationException("Installed live contract failed.");
    }
    private sealed class Tokens : IInfisicalTokenSource, IDisposable
    {
        private readonly SecretMaterial _material;
        internal Tokens(string value) => _material = SecretMaterial.FromText(value);
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(_material.Copy())));
        }
        public void Dispose() => _material.Dispose();
        public override string ToString() => "[InstalledFixtureToken]";
    }
}
