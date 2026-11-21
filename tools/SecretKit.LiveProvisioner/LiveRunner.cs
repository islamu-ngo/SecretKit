using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.TestFixtures;

namespace SecretKit.LiveProvisioner;

internal enum LiveRole { Setup, Runtime, Denied, Administrative, Observer }

internal sealed record LivePrincipal(string IdentityId, string ClientId, SecretMaterial ClientSecret)
{
    public override string ToString() => "[LivePrincipal]";
}

internal sealed class LiveTokens(InfisicalUniversalLogin[] logins) : IDisposable
{
    internal string Reveal(LiveRole role) => logins[(int)role].Token.Material.Reveal();
    public void Dispose()
    {
        foreach (InfisicalUniversalLogin login in logins) login.Dispose();
    }
}

internal static class LiveRunner
{
    private const string Conformance = "tests/SecretKit.Infisical.Conformance.Tests/SecretKit.Infisical.Conformance.Tests.csproj";
    private const string PackageConsumer = "tests/fixtures/SecretKit.PackageConsumer/SecretKit.PackageConsumer.csproj";

    internal static async Task<int> RunAsync(LiveEnvConfig config, string scenario, string? candidatePath,
        string? requestPath, string? settingsTemplatePath, CancellationToken token)
    {
        if (!OperatingSystem.IsLinux())
            throw new ProvisioningException("Live provisioning requires Linux.");
        if (scenario is not ("installed-narrative" or "native-conformance" or "owned-sandbox" or "baseline") ||
            scenario != "native-conformance" && (requestPath is not null || settingsTemplatePath is not null) ||
            scenario is "owned-sandbox" or "baseline" && (config.Target != LiveTarget.Local || candidatePath is not null))
            throw new ProvisioningException("The live scenario and selected inputs are incompatible.");

        string root = config.RepositoryRoot;
        PackageCandidate? candidate = null;
        using NativeLiveInputs? native = scenario == "native-conformance"
            ? await NativeLiveInputs.LoadAsync(root, requestPath, settingsTemplatePath, token)
            : null;
        if (scenario is "installed-narrative" or "native-conformance")
        {
            if (native is not null && candidatePath is null)
                throw new ProvisioningException("Native conformance requires an explicit package candidate directory.");
            try
            {
                string path = Path.GetFullPath(candidatePath ?? "artifacts/packages", root);
                NativeLiveInputs.RequireUnlinked(path);
                foreach (string archive in Directory.EnumerateFiles(path, "*.nupkg").Take(8))
                    NativeLiveInputs.RequireUnlinked(archive);
                candidate = PackageCandidate.Select(root, directory: path);
                if (native is not null)
                    _ = NativeConsumerLauncher.Prepare(root, candidate, native.Request);
            }
            catch (Exception error) when (error is not OperationCanceledException)
            {
                throw new ProvisioningException("Live package candidate or native request was rejected.");
            }
        }

        await VerifyReadyAsync(config, token);
        string profile = config.Target == LiveTarget.Local ? "local-podman-ce" : "remote-playground";
        Console.WriteLine($"Selected live profile: {profile} (not edition evidence)");
        await ProviderStatus.ReportAsync(config, Console.Out, token);
        string live = LiveProcess.ArtifactDirectory(root);
        string? consumer = scenario == "installed-narrative"
            ? await BuildInstalledAsync(root, live, candidate!, token)
            : null;
        int build = scenario switch
        {
            "native-conformance" or "owned-sandbox" => await BuildAsync(root,
                ["build", Conformance, "--configuration", "Release"], token),
            "baseline" => await BuildAsync(root,
                ["build", "tools/SecretKit.ConsumerBaseline/SecretKit.ConsumerBaseline.csproj", "--configuration", "Release"], token),
            _ => 0
        };
        if (build != 0) return build;

        using LiveFixtures fixtures = await new FixtureReconciler().ReconcileAsync(config, token, issueCredentials: true);
        LivePrincipal[] principals = [Principal(fixtures.Setup), Principal(fixtures.Runtime), Principal(fixtures.Denied),
            Principal(fixtures.Administrative), Principal(fixtures.Observer)];
        using LiveTokens tokens = await MintAsync(config.Origin, principals, token);
        if (native is not null)
            return await native.RunAsync(config, candidate!, tokens, token);

        var selected = new Dictionary<string, string> { ["SECRETKIT_LIVE_ORIGIN"] = config.Origin.AbsoluteUri };
        switch (scenario)
        {
            case "installed-narrative":
                selected["SECRETKIT_LIVE_PROJECT"] = fixtures.ProjectAId;
                selected["SECRETKIT_LIVE_OTHER_PROJECT"] = fixtures.ProjectBId;
                selected["SECRETKIT_LIVE_EXPECTED"] = fixtures.ExpectedA.Reveal();
                selected["SECRETKIT_LIVE_OTHER_EXPECTED"] = fixtures.ExpectedB.Reveal();
                selected["SECRETKIT_LIVE_ADMIN_TOKEN"] = tokens.Reveal(LiveRole.Administrative);
                selected["SECRETKIT_LIVE_RUNTIME_TOKEN"] = tokens.Reveal(LiveRole.Runtime);
                selected["SECRETKIT_LIVE_DENIED_TOKEN"] = tokens.Reveal(LiveRole.Denied);
                return await LiveProcess.RunAsync(root, new(LiveProcess.Command(root, "dotnet", [consumer!, "live-infisical"]),
                    selected, RequireInstalledMarkers: true), token);
            case "owned-sandbox":
                selected["SECRETKIT_LIVE_OWNER"] = config.Owner!;
                selected["SECRETKIT_LIVE_ORGANIZATION"] = config.OrganizationId;
                selected["SECRETKIT_LIVE_ADMIN_TOKEN"] = tokens.Reveal(LiveRole.Setup);
                return await LiveProcess.RunAsync(root,
                    new(LiveProcess.Command(root, "dotnet", TestArguments("IdentitySetupTests/*")), selected), token);
            case "baseline":
                selected["SECRETKIT_LIVE_ORGANIZATION"] = config.OrganizationId;
                selected["SECRETKIT_LIVE_ADMIN_TOKEN"] = tokens.Reveal(LiveRole.Setup);
                return await LiveProcess.RunAsync(root, new(LiveProcess.Command(root, "dotnet",
                    ["tools/SecretKit.ConsumerBaseline/bin/Release/net10.0/SecretKit.ConsumerBaseline.dll", "live-infisical"]),
                    selected), token);
            default:
                throw new ProvisioningException("Invalid live scenario.");
        }
    }

    private static LivePrincipal Principal(ActorCredentials actor) =>
        new(actor.IdentityId, actor.ClientId, actor.ClientSecret);

    internal static string[] TestArguments(string test) =>
        ["tests/SecretKit.Infisical.Conformance.Tests/bin/Release/net10.0/SecretKit.Infisical.Conformance.Tests.dll",
            "--treenode-filter", "/*/*/" + test, "--minimum-expected-tests", "1"];

    internal static async Task<LiveTokens> MintAsync(Uri origin, IReadOnlyList<LivePrincipal> principals, CancellationToken token)
    {
        if (principals.Count != Enum.GetValues<LiveRole>().Length ||
            principals.Any(p => string.IsNullOrWhiteSpace(p.IdentityId)) ||
            principals.Select(p => p.IdentityId).Distinct(StringComparer.OrdinalIgnoreCase).Count() != principals.Count)
            throw new ProvisioningException("Live fixture identities must be distinct.");
        using var authentication = new InfisicalUniversalAuthentication(origin,
            new() { AllowLoopbackDevelopmentHttp = origin.Scheme == Uri.UriSchemeHttp && origin.IsLoopback });
        var logins = new List<InfisicalUniversalLogin>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            foreach (LivePrincipal actor in principals)
            {
                var receipt = authentication.CreateReceipt();
                var result = await authentication.LoginAsync(actor.ClientId, actor.ClientSecret, receipt,
                    cancellationToken: token);
                if (!result.IsSuccess)
                    throw new ProvisioningException("A selected live fixture login failed.");
                logins.Add(result.Value);
                if (!seen.Add(result.Value.Token.Material.Reveal()))
                    throw new ProvisioningException("Live fixture bearer tokens must be distinct.");
            }
            return new LiveTokens(logins.ToArray());
        }
        catch
        {
            foreach (InfisicalUniversalLogin login in logins) login.Dispose();
            throw;
        }
    }

    private static async Task VerifyReadyAsync(LiveEnvConfig config, CancellationToken token)
    {
        if (config.Target == LiveTarget.Local)
            await LocalSandboxReadiness.VerifyAsync(config.RepositoryRoot, config.Owner!, config.Origin, token);
    }

    private static Task<int> BuildAsync(string root, string[] arguments, CancellationToken token) =>
        LiveProcess.RunAsync(root, new(LiveProcess.Command(root, "flock",
            ["-o", "/tmp/secretkit-provider-engineering-build.lock", "dotnet", .. arguments]),
            new Dictionary<string, string>()), token);

    private static async Task<string> BuildInstalledAsync(string root, string live, PackageCandidate candidate, CancellationToken token)
    {
        string outputs = LiveProcess.PrivateDirectory(live, "installed-");
        ConsumerInstallation installation = candidate.PrepareConsumer(outputs);
        string assets = Path.Combine(installation.Intermediate, "project.assets.json");
        if (await BuildAsync(root, ["restore", PackageConsumer, "--configfile", installation.Configuration,
            .. installation.Properties], token) != 0)
            throw new ProvisioningException("Installed consumer restore failed.");
        candidate.VerifyRestored(assets, installation.Packages);
        if (await BuildAsync(root, ["build", PackageConsumer, "--no-restore", "--configuration", "Release",
            .. installation.Properties], token) != 0)
            throw new ProvisioningException("Installed consumer build failed.");
        candidate.VerifyRestored(assets, installation.Packages);
        return Path.Combine(installation.Binary, "Release", "net10.0", "SecretKit.PackageConsumer.dll");
    }
}
