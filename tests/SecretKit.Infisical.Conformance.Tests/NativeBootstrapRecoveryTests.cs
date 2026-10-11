using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class NativeBootstrapRecoveryTests
{
    [Test]
    public async Task ConsumedBootstrapCannotSurviveProcessLossWithoutExplicitRecovery() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.BootstrapRecovery);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource administrator,
        string organization, string identity, string project, string key, SecretMaterial expected,
        Action<string, string> record, CancellationToken cancellationToken)
    {
        using var transport = new ManagementTransport(origin, allowLoopbackDevelopmentHttp: true);
        var management = new ManagementClient(transport);
        var authority = new ManagementAuthority(management.Authority, administrator, organization);
        using var get = IdentityAuthenticationOperations.GetUniversalAuth(organization, identity);
        var configuration = await management.ExecuteAsync(get, authority,
            authority.IssueGrant(get.OperationId, new(organization, resourceId: identity)),
            cancellationToken: cancellationToken);
        Require(configuration.Status);
        string clientId = configuration.Value.ClientId!;
        string? consumedId = null;
        for (int generation = 0; generation < 2; generation++)
        {
            // Recovery is a new independently granted administrator operation.
            // Neither child receives the previous bootstrap or any ambient authority.
            using var create = IdentityAuthenticationOperations.CreateUniversalClientSecret(organization, identity,
                ttl: 600, numUsesLimit: 1);
            var receipt = management.CreateReceipt(create);
            var created = await management.ExecuteAsync(create, authority,
                authority.IssueGrant(create.OperationId,
                    IdentityAuthenticationOperations.ClientSecretCreateTarget(organization, identity,
                        ttl: 600, numUsesLimit: 1)), receipt, cancellationToken);
            Require(created.Status);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            using var secret = created.Value;
            record("client-secret", secret.Metadata.Id);
            await Assert.That(secret.Metadata.Id != consumedId).IsTrue();
            var injection = new Dictionary<string, string>
            {
                ["SECRETKIT_RECOVERY_ORIGIN"] = origin.AbsoluteUri,
                ["SECRETKIT_RECOVERY_CLIENT_ID"] = clientId,
                ["SECRETKIT_RECOVERY_BOOTSTRAP"] = secret.ClientSecret.Reveal(),
                ["SECRETKIT_RECOVERY_PROJECT"] = project,
                ["SECRETKIT_RECOVERY_KEY"] = key,
                ["SECRETKIT_RECOVERY_EXPECTED"] = expected.Reveal()
            };
            var loginChild = await Child("LoginOnceAndRead", injection);
            await Assert.That(loginChild.Output.Contains("OWNED_CHILD_ONE_BOOTSTRAP_READ_PASSED",
                StringComparison.Ordinal)).IsTrue();
            using var inspect = IdentityAuthenticationOperations.GetUniversalClientSecret(organization, identity,
                secret.Metadata.Id);
            var metadata = await management.ExecuteAsync(inspect, authority,
                authority.IssueGrant(inspect.OperationId,
                    new(organization, resourceId: identity, secondaryId: secret.Metadata.Id)),
                cancellationToken: cancellationToken);
            Require(metadata.Status);
            await Assert.That(metadata.Value.ClientSecretNumUses).IsEqualTo(1);
            await Assert.That(metadata.Value.ClientSecretNumUsesLimit).IsEqualTo(1);
            consumedId = secret.Metadata.Id;
            if (generation == 0)
            {
                var loss = await Child("RestartWithoutMaterialRequiresRecovery",
                    new Dictionary<string, string> { ["SECRETKIT_RECOVERY_ORIGIN"] = origin.AbsoluteUri });
                await Assert.That(loss.Output.Contains("OWNED_CHILD_RECOVERY_REQUIRED",
                    StringComparison.Ordinal)).IsTrue();
            }
        }
        Console.WriteLine("OWNED_PROCESS_LOSS_AND_EXPLICIT_RECOVERY_PASSED");

        async Task<(int ExitCode, string Output)> Child(string method, IReadOnlyDictionary<string, string> injection)
        {
            var result = await OwnedProcess.RunAsync("dotnet",
                [typeof(NativeBootstrapRecoveryTests).Assembly.Location,
                    "--treenode-filter", $"/*/*/BootstrapRecoveryChildTests/{method}", "--minimum-expected-tests", "1"],
                AppContext.BaseDirectory, injection, cancellationToken);
            await Assert.That(result.ExitCode).IsEqualTo(0);
            return result;
        }
    }

    private static void Require(SecretStatus status)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned bootstrap recovery: {status}.");
    }
}

/// <summary>Only launched with a single exact child stage by the owned parent.</summary>
public sealed class BootstrapRecoveryChildTests
{
    [Test]
    public async Task LoginOnceAndRead()
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var origin = Origin();
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        using var bootstrap = SecretMaterial.FromText(Required("SECRETKIT_RECOVERY_BOOTSTRAP"));
        using var authentication = new InfisicalUniversalAuthentication(origin, network);
        var receipt = authentication.CreateReceipt();
        var login = await authentication.LoginAsync(Required("SECRETKIT_RECOVERY_CLIENT_ID"), bootstrap,
            receipt, cancellationToken: deadline.Token);
        await Assert.That(login.Status).IsEqualTo(SecretStatus.Success);
        await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
        using var issued = login.Value;
        await using var session = new InfisicalPeriodicTokenSession(origin, issued.Token.Material,
            Evidence(issued.ExpiresIn, issued.AccessTokenMaxTTL), TimeSpan.FromSeconds(10),
            TimeSpan.FromSeconds(10), network);
        await using var reader = new InfisicalClient(origin, session, network);
        var result = await reader.ReadAsync(new SecretReference(reader.Authority,
            new InfisicalSecretAddress(Required("SECRETKIT_RECOVERY_PROJECT"), "dev", "/",
                Required("SECRETKIT_RECOVERY_KEY"))), deadline.Token);
        await Assert.That(result.Status).IsEqualTo(SecretStatus.Success);
        using var value = result.Value;
        await Assert.That(value.Material.Reveal() == Required("SECRETKIT_RECOVERY_EXPECTED")).IsTrue();
        // Bypass the test runner's successful-test Console capture. This fixed
        // material-free marker is the parent process protocol, not diagnostics.
        await Console.OpenStandardOutput().WriteAsync("OWNED_CHILD_ONE_BOOTSTRAP_READ_PASSED\n"u8.ToArray());
    }

    [Test]
    public async Task RestartWithoutMaterialRequiresRecovery()
    {
        await Assert.That(Environment.GetEnvironmentVariable("SECRETKIT_RECOVERY_BOOTSTRAP")).IsNull();
        await Assert.That(Environment.GetEnvironmentVariable("SECRETKIT_LIVE_ADMIN_TOKEN")).IsNull();
        await using var session = new InfisicalPeriodicTokenSession(Origin(), null, Evidence(3600, 7200),
            TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10),
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
        await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.RecoveryRequired);
        await Assert.That((await session.GetTokenAsync(CancellationToken.None)).Status)
            .IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
        await Assert.That(session.LastRenewal).IsNull();
        await Console.OpenStandardOutput().WriteAsync("OWNED_CHILD_RECOVERY_REQUIRED\n"u8.ToArray());
    }

    private static InfisicalTokenLifetimeEvidence Evidence(double expiry, double maximum)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new()
        {
            OriginalIssuedAt = now,
            ExpiresAt = now.AddSeconds(expiry),
            ReportedMaximumTtl = TimeSpan.FromSeconds(maximum),
            Lifetime = InfisicalTokenLifetime.Finite
        };
    }

    private static Uri Origin()
    {
        var origin = new Uri(Required("SECRETKIT_RECOVERY_ORIGIN"));
        if (origin.Scheme != "http" || origin.Host != "127.0.0.1" || origin.IsDefaultPort ||
            origin.AbsolutePath != "/" || origin.Query.Length != 0 || origin.Fragment.Length != 0 ||
            origin.UserInfo.Length != 0)
            throw new InvalidOperationException("An owned loopback origin is required.");
        return origin;
    }

    private static string Required(string name) => Environment.GetEnvironmentVariable(name) ??
        throw new InvalidOperationException("Explicit child recovery input is missing.");
}
