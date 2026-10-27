using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class NativeTokenPolicyTests
{
    [Test]
    public async Task OrdinaryAndPeriodicPoliciesHaveDistinctNativeLifetimes() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.TokenPolicy);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource administrator,
        string organization, string identity, string project, string key, SecretMaterial expected,
        Action<string, string> record, CancellationToken cancellationToken)
    {
        using var transport = new ManagementTransport(origin, new() { AllowLoopbackDevelopmentHttp = true });
        var management = new ManagementClient(transport);
        var authority = new ManagementAuthority(management.Authority, administrator, organization);
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        foreach (bool periodic in new[] { false, true })
        {
            var policy = new UniversalAuthConfigurationInput(accessTokenTTL: 10, accessTokenMaxTTL: 20,
                accessTokenNumUsesLimit: 0, accessTokenPeriod: periodic ? 60 : 0);
            using var update = IdentityAuthenticationOperations.UpdateUniversalAuth(organization, identity, policy);
            var configuration = await Apply(update,
                IdentityAuthenticationOperations.UniversalAuthConfigurationTarget(organization, identity, policy, true));
            await Assert.That(configuration.AccessTokenTTL).IsEqualTo(10);
            await Assert.That(configuration.AccessTokenMaxTTL).IsEqualTo(20);
            await Assert.That(configuration.AccessTokenPeriod).IsEqualTo(periodic ? 60 : 0);
            await Assert.That(configuration.AccessTokenNumUsesLimit).IsEqualTo(0);
            using var create = IdentityAuthenticationOperations.CreateUniversalClientSecret(organization, identity,
                ttl: 600, numUsesLimit: 1);
            using var secret = await Apply(create,
                IdentityAuthenticationOperations.ClientSecretCreateTarget(organization, identity,
                    ttl: 600, numUsesLimit: 1));
            record("client-secret", secret.Metadata.Id);
            using var authentication = new InfisicalUniversalAuthentication(origin, network);
            var loginReceipt = authentication.CreateReceipt();
            DateTimeOffset sentAt = DateTimeOffset.UtcNow;
            var login = await authentication.LoginAsync(configuration.ClientId!, secret.ClientSecret,
                loginReceipt, cancellationToken: cancellationToken);
            Require(login.Status, loginReceipt.Evidence);
            await Assert.That(loginReceipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            using var issued = login.Value;
            await Assert.That(issued.ExpiresIn).IsEqualTo(periodic ? 60 : 10);
            // This pinned server retains configured max=20 in administration,
            // but reports an unlimited maximum (0) for the periodic credential.
            await Assert.That(issued.AccessTokenMaxTTL).IsEqualTo(periodic ? 0 : 20);
            await using var session = new InfisicalPeriodicTokenSession(origin, issued.Token.Material,
                new InfisicalTokenLifetimeEvidence
                {
                    OriginalIssuedAt = sentAt,
                    ExpiresAt = sentAt.AddSeconds(issued.ExpiresIn),
                    ReportedMaximumTtl = TimeSpan.FromSeconds(issued.AccessTokenMaxTTL),
                    Lifetime = periodic ? InfisicalTokenLifetime.Periodic : InfisicalTokenLifetime.Finite,
                    Period = periodic ? TimeSpan.FromSeconds(60) : null
                }, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(10), network);
            await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.Ready);
            await Assert.That(await session.RenewAsync(cancellationToken)).IsEqualTo(SecretStatus.Success);
            await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.Applied);
            await using var reader = new InfisicalClient(origin, session, network);
            var result = await reader.ReadAsync(new SecretReference(reader.Authority,
                new InfisicalSecretAddress(project, "dev", "/", key)), cancellationToken);
            Require(result.Status, DispatchEvidence.NotDispatched);
            using var value = result.Value;
            await Assert.That(value.Material.Reveal() == expected.Reveal()).IsTrue();
            await session.StopAsync();
            await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.Stopped);
            Console.WriteLine(periodic
                ? "OWNED_PERIODIC_TTL_60_CONFIGURED_MAX_20_RENEWAL_PASSED"
                : "OWNED_ORDINARY_TTL_10_MAX_20_RENEWAL_PASSED");
        }

        async Task<T> Apply<T>(ManagementRequest<T> request, ManagementTarget target) where T : notnull
        {
            var receipt = management.CreateReceipt(request);
            var result = await management.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, target), receipt, cancellationToken);
            Require(result.Status, receipt.Evidence);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            return result.Value;
        }
    }

    private static void Require(SecretStatus status, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned native token policy: {status}; evidence: {evidence}.");
    }
}
