using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal enum OwnedConformanceScenario { Identity, InstalledWorkflows, DispatchEffects, ImportDelivery, ImportEffects, ImportPolicy, Authentication, TokenPolicy, BootstrapRecovery, SqlLifecycle, Rotation }

public sealed class IdentitySetupTests
{
    [Test]
    public async Task GeneratedMachineActorsHaveIndependentNativeAuthority() => await RunAsync(OwnedConformanceScenario.Identity);

    internal static async Task RunAsync(OwnedConformanceScenario scenario)
    {
        if (!OperatingSystem.IsLinux())
            throw new InvalidOperationException("Owned conformance requires the supported Linux sandbox.");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
        using var setupMaterial = SecretMaterial.FromText(Required("SECRETKIT_LIVE_ADMIN_TOKEN"));
        using var sandbox = new OwnedSandbox(new Uri(Required("SECRETKIT_LIVE_ORIGIN")),
            Required("SECRETKIT_LIVE_OWNER"), Required("SECRETKIT_LIVE_ORGANIZATION"), setupMaterial);
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        await sandbox.VerifyAsync(root, deadline.Token);
        string manifestRoot = Path.Combine(root, "artifacts", "conformance");
        Directory.CreateDirectory(manifestRoot);
        using var manifest = new FileStream(Path.Combine(manifestRoot, Guid.NewGuid().ToString("N") + ".jsonl"),
            new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            });
        using var transport = new ManagementTransport(sandbox.Origin, new() { AllowLoopbackDevelopmentHttp = true });
        var management = new ManagementClient(transport);
        using var setupTokens = new SelectedTokens(setupMaterial);
        var receipts = new List<ManagementReceipt>();

        using var admin = await Actor("admin", "admin", setupTokens);
        var administration = new ManagementAuthority(management.Authority, admin, sandbox.OrganizationId);
        string slug = "sdk-conformance-" + Guid.NewGuid().ToString("N")[..12];
        using var projectRequest = ProjectOperations.CreateProject(sandbox.OrganizationId, "Owned conformance", slug);
        var project = await Apply(projectRequest, administration,
            ProjectOperations.ProjectCreateTarget(sandbox.OrganizationId, "Owned conformance", slug), "machine-project-create");
        Record("project", project.Id);
        string otherSlug = "sdk-isolation-" + Guid.NewGuid().ToString("N")[..12];
        using var otherRequest = ProjectOperations.CreateProject(sandbox.OrganizationId, "Owned isolation", otherSlug);
        var otherProject = await Apply(otherRequest, administration,
            ProjectOperations.ProjectCreateTarget(sandbox.OrganizationId, "Owned isolation", otherSlug), "isolation-project-create");
        Record("project", otherProject.Id);
        using var runtime = await Actor("runtime", "no-access", admin, project.Id);
        using var denied = await Actor("denied", "no-access", admin);

        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        await using var writer = new InfisicalClient(sandbox.Origin, admin, network);
        await using var reader = new InfisicalClient(sandbox.Origin, runtime, network);
        await using var deniedReader = new InfisicalClient(sandbox.Origin, denied, network);
        const string key = "SDK_CONFORMANCE_VALUE";
        using var material = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        using var otherMaterial = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        var writeTarget = new SecretReference(writer.Authority, new InfisicalSecretAddress(project.Id, "dev", "/", key));
        var writeReceipt = new MutationReceipt(writeTarget);
        var written = await writer.CreateAsync(writeTarget, material, writeReceipt, deadline.Token);
        Require(written.Status, "machine-secret-create", writeReceipt.Evidence);
        var otherWriteTarget = new SecretReference(writer.Authority,
            new InfisicalSecretAddress(otherProject.Id, "dev", "/", key));
        var otherWriteReceipt = new MutationReceipt(otherWriteTarget);
        var otherWritten = await writer.CreateAsync(otherWriteTarget, otherMaterial, otherWriteReceipt, deadline.Token);
        Require(otherWritten.Status, "isolation-secret-create", otherWriteReceipt.Evidence);
        var runtimeTarget = new SecretReference(reader.Authority, new InfisicalSecretAddress(project.Id, "dev", "/", key));
        var read = await reader.ReadAsync(runtimeTarget, deadline.Token);
        Require(read.Status, "restricted-runtime-read", DispatchEvidence.NotDispatched);
        using var observed = read.Value;
        if (observed.Material.Reveal() != material.Reveal())
            throw new InvalidOperationException("Owned runtime material did not match.");
        var selectedDeniedWrite = new SecretReference(reader.Authority,
            new InfisicalSecretAddress(project.Id, "dev", "/", "SDK_DENIED_WRITE"));
        var actualDeniedReceipt = new MutationReceipt(selectedDeniedWrite);
        var actualDenied = await reader.CreateAsync(selectedDeniedWrite, material, actualDeniedReceipt, deadline.Token);
        await Assert.That(actualDenied.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That(actualDeniedReceipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);
        var deniedRead = await deniedReader.ReadAsync(new SecretReference(deniedReader.Authority,
            new InfisicalSecretAddress(project.Id, "dev", "/", key)), deadline.Token);
        await Assert.That(deniedRead.Status).IsEqualTo(SecretStatus.Denied);
        var wrongProjectRead = await reader.ReadAsync(new SecretReference(reader.Authority,
            new InfisicalSecretAddress(otherProject.Id, "dev", "/", key)), deadline.Token);
        await Assert.That(wrongProjectRead.Status).IsEqualTo(SecretStatus.Denied);
        await Assert.That((await reader.ReadAsync(new SecretReference(writer.Authority,
            new InfisicalSecretAddress(project.Id, "dev", "/", key)), deadline.Token)).Status)
            .IsEqualTo(SecretStatus.Invalid);
        await Assert.That(receipts.All(receipt => receipt.Evidence == DispatchEvidence.Applied)).IsTrue();
        Console.WriteLine("OWNED_MACHINE_ACTORS_AND_SCOPE_PASSED");
        if (scenario == OwnedConformanceScenario.Authentication)
            await NativeAuthenticationTests.VerifyAsync(sandbox.Origin, admin, sandbox.OrganizationId,
                runtime.IdentityId ?? throw new InvalidOperationException("Generated runtime identity is missing."),
                project.Id, otherProject.Id, key, material, Record, deadline.Token);
        if (scenario == OwnedConformanceScenario.TokenPolicy)
            await NativeTokenPolicyTests.VerifyAsync(sandbox.Origin, admin, sandbox.OrganizationId,
                runtime.IdentityId ?? throw new InvalidOperationException("Generated runtime identity is missing."),
                project.Id, key, material, Record, deadline.Token);
        if (scenario == OwnedConformanceScenario.BootstrapRecovery)
            await NativeBootstrapRecoveryTests.VerifyAsync(sandbox.Origin, admin, sandbox.OrganizationId,
                runtime.IdentityId ?? throw new InvalidOperationException("Generated runtime identity is missing."),
                project.Id, key, material, Record, deadline.Token);
        if (scenario == OwnedConformanceScenario.SqlLifecycle)
            await DynamicSqlLifecycleTests.VerifyAsync(sandbox.Origin, admin, project.Id, slug, Record, deadline.Token);
        if (scenario == OwnedConformanceScenario.Rotation)
            await RotationProgressTests.VerifyAsync(sandbox.Origin, admin, sandbox.OrganizationId,
                project.Id, Record, deadline.Token);
        if (scenario == OwnedConformanceScenario.DispatchEffects)
            await MutationUncertaintyTests.VerifyAsync(sandbox.Origin, admin, project.Id, deadline.Token);
        if (scenario is OwnedConformanceScenario.ImportDelivery or OwnedConformanceScenario.ImportEffects or OwnedConformanceScenario.ImportPolicy)
            await ImportDeliveryTests.VerifyAsync(sandbox.Origin, admin, runtime, denied, project.Id, deadline.Token,
                scenario);
        if (scenario == OwnedConformanceScenario.InstalledWorkflows)
        {
            var candidate = PackageCandidate.FromEnvironment(root);
            string fixture = Path.Combine(root, "tests", "fixtures", "SecretKit.PackageConsumer");
            string outputs = Path.Combine(root, "artifacts", "package-consumers", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(outputs);
            var installation = candidate.PrepareConsumer(outputs);
            string intermediate = installation.Intermediate;
            string binary = installation.Binary;
            string[] properties = installation.Properties;
            var restore = await OwnedProcess.RunAsync("dotnet",
                ["restore", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"),
                    "--configfile", installation.Configuration, .. properties], root,
                cancellationToken: deadline.Token);
            if (restore.ExitCode != 0) throw new InvalidOperationException("Installed fixture restore failed.");
            candidate.VerifyRestored(Path.Combine(intermediate, "project.assets.json"), installation.Packages);
            var build = await OwnedProcess.RunAsync("dotnet",
                ["build", Path.Combine(fixture, "SecretKit.PackageConsumer.csproj"), "--no-restore",
                    "--configuration", "Release", .. properties], root, cancellationToken: deadline.Token);
            if (build.ExitCode != 0) throw new InvalidOperationException("Installed fixture build failed.");
            using var assets = JsonDocument.Parse(await File.ReadAllTextAsync(
                Path.Combine(intermediate, "project.assets.json"), deadline.Token));
            await Assert.That(assets.RootElement.GetProperty("libraries").EnumerateObject()
                .All(library => library.Value.GetProperty("type").GetString() == "package" &&
                    !library.Name.StartsWith("Infisical.Sdk/", StringComparison.OrdinalIgnoreCase))).IsTrue();
            using var adminMaterial = admin.CopyMaterial();
            using var runtimeMaterial = runtime.CopyMaterial();
            using var deniedMaterial = denied.CopyMaterial();
            var consumer = await OwnedProcess.RunAsync("dotnet",
                [Path.Combine(binary, "Release", "net10.0", "SecretKit.PackageConsumer.dll"), "live-infisical"], root,
                new Dictionary<string, string>
                {
                    ["SECRETKIT_LIVE_ORIGIN"] = sandbox.Origin.AbsoluteUri,
                    ["SECRETKIT_LIVE_PROJECT"] = project.Id,
                    ["SECRETKIT_LIVE_OTHER_PROJECT"] = otherProject.Id,
                    ["SECRETKIT_LIVE_ADMIN_TOKEN"] = adminMaterial.Reveal(),
                    ["SECRETKIT_LIVE_RUNTIME_TOKEN"] = runtimeMaterial.Reveal(),
                    ["SECRETKIT_LIVE_DENIED_TOKEN"] = deniedMaterial.Reveal(),
                    ["SECRETKIT_LIVE_EXPECTED"] = material.Reveal(),
                    ["SECRETKIT_LIVE_OTHER_EXPECTED"] = otherMaterial.Reveal()
                }, deadline.Token);
            await Assert.That(consumer.ExitCode).IsEqualTo(0);
            await Assert.That(consumer.Output.Contains("INSTALLED_NATIVE_READ_WRITE_INVENTORY_AND_IDENTITIES_PASSED",
                StringComparison.Ordinal)).IsTrue();
            await Assert.That(consumer.Output.Contains("INSTALLED_BOOTSTRAP_CONFIGURATION_AND_ASSESSMENT_PASSED",
                StringComparison.Ordinal)).IsTrue();
        }

        async Task<SelectedTokens> Actor(string purpose, string role, SelectedTokens issuer, string? projectId = null)
        {
            var authority = new ManagementAuthority(management.Authority, issuer, sandbox.OrganizationId);
            string name = "sdk-" + purpose + "-" + Guid.NewGuid().ToString("N");
            using var create = IdentityOperations.CreateOrganizationIdentity(sandbox.OrganizationId, name, role);
            var identity = await Apply(create, authority,
                IdentityOperations.OrganizationIdentityCreateTarget(sandbox.OrganizationId, name, role), "identity-create");
            Record("identity", identity.Id);
            if (projectId is not null)
            {
                using var membership = MembershipOperations.AddProjectIdentity(sandbox.OrganizationId, projectId,
                    identity.Id, [new MembershipRole("viewer")]);
                var projectAuthority = new ManagementAuthority(management.Authority, issuer, sandbox.OrganizationId, projectId);
                _ = await Apply(membership, projectAuthority,
                    MembershipOperations.RoleChangeTarget(sandbox.OrganizationId, projectId, identity.Id, [new MembershipRole("viewer")]),
                    "runtime-membership");
            }
            var policy = new UniversalAuthConfigurationInput(accessTokenTTL: 3600, accessTokenMaxTTL: 7200,
                accessTokenNumUsesLimit: 0, accessTokenPeriod: 0);
            using var attach = IdentityAuthenticationOperations.AttachUniversalAuth(sandbox.OrganizationId, identity.Id, policy);
            var configuration = await Apply(attach, authority,
                IdentityAuthenticationOperations.UniversalAuthConfigurationTarget(sandbox.OrganizationId, identity.Id, policy),
                "universal-attach");
            using var secretRequest = IdentityAuthenticationOperations.CreateUniversalClientSecret(sandbox.OrganizationId,
                identity.Id, ttl: 3600, numUsesLimit: 0);
            using var secret = await Apply(secretRequest, authority,
                IdentityAuthenticationOperations.ClientSecretCreateTarget(sandbox.OrganizationId, identity.Id,
                    ttl: 3600, numUsesLimit: 0), "client-secret-create");
            using var authentication = new InfisicalUniversalAuthentication(sandbox.Origin,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            var loginReceipt = authentication.CreateReceipt();
            string clientId = configuration.ClientId ??
                throw new InvalidOperationException("Universal configuration did not report a client identifier.");
            var login = await authentication.LoginAsync(clientId, secret.ClientSecret, loginReceipt,
                cancellationToken: deadline.Token);
            Require(login.Status, "universal-login", loginReceipt.Evidence);
            using var issued = login.Value;
            return new SelectedTokens(issued.Token.Material, identity.Id);
        }

        async Task<T> Apply<T>(ManagementRequest<T> request, ManagementAuthority authority, ManagementTarget target,
            string step) where T : notnull
        {
            var receipt = management.CreateReceipt(request);
            receipts.Add(receipt);
            var result = await management.ExecuteAsync(request, authority, authority.IssueGrant(request.OperationId, target),
                receipt, deadline.Token);
            Require(result.Status, step, receipt.Evidence);
            return result.Value;
        }

        void Record(string kind, string id)
        {
            // Deliberate private recovery export, never a diagnostic or credential export.
            byte[] row = JsonSerializer.SerializeToUtf8Bytes(new
            {
                schemaVersion = 1,
                owner = sandbox.Owner,
                imageDigest = OwnedSandbox.AppDigest,
                kind,
                id,
                evidence = "Applied"
            });
            manifest.Write(row);
            manifest.WriteByte((byte)'\n');
            manifest.Flush(flushToDisk: true);
            Array.Clear(row);
        }
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name) is { Length: > 0 } value
        ? value : throw new InvalidOperationException("Missing explicit owned conformance injection.");
    private static void Require(SecretStatus status, string step, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned conformance {step}: {status}; evidence: {evidence}.");
    }

    private sealed class SelectedTokens : IInfisicalTokenSource, IDisposable
    {
        private readonly SecretMaterial _material;
        internal SelectedTokens(SecretMaterial material, string? identityId = null)
        {
            _material = material.Copy();
            IdentityId = identityId;
        }
        internal string? IdentityId { get; }
        internal SecretMaterial CopyMaterial() => _material.Copy();
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(_material.Copy())));
        }
        public void Dispose() => _material.Dispose();
        public override string ToString() => "[SelectedConformanceTokens]";
    }
}
