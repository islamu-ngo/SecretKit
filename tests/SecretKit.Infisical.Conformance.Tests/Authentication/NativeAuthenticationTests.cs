using SecretKit.Core;
using SecretKit.Infisical;
using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class NativeAuthenticationTests
{
    [Test]
    public async Task TokenAuthorityRenewalAndBothRevocationRoutesHaveNativeEffect() =>
        await IdentitySetupTests.RunAsync(OwnedConformanceScenario.Authentication);

    internal static async Task VerifyAsync(Uri origin, IInfisicalTokenSource administrator,
        string organization, string identity, string project, string otherProject, string key,
        SecretMaterial expected, Action<string, string> record, CancellationToken cancellationToken)
    {
        using var transport = new ManagementTransport(origin, new() { AllowLoopbackDevelopmentHttp = true });
        var management = new ManagementClient(transport);
        var authority = new ManagementAuthority(management.Authority, administrator, organization);
        var policy = new TokenAuthConfigurationInput(accessTokenTTL: 600, accessTokenMaxTTL: 1200,
            accessTokenNumUsesLimit: 0);
        using var attach = IdentityAuthenticationOperations.AttachTokenAuth(organization, identity, policy);
        _ = await Apply(attach,
            IdentityAuthenticationOperations.TokenAuthConfigurationTarget(organization, identity, policy),
            "token-attach");
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        foreach (bool generic in new[] { false, true })
        {
            string name = generic ? "Owned generic lifecycle" : "Owned token lifecycle";
            using var create = IdentityAuthenticationOperations.CreateToken(organization, identity, name);
            using var issued = await Apply(create,
                IdentityAuthenticationOperations.TokenCreateTarget(organization, identity, name), "token-create");
            record("token", issued.Metadata.Id);
            await Assert.That(issued.Metadata.IdentityId == identity).IsTrue();
            await Assert.That(issued.Metadata.AuthMethod).IsEqualTo("token-auth");
            await Assert.That(issued.ExpiresIn).IsEqualTo(600);
            await Assert.That(issued.AccessTokenMaxTTL).IsEqualTo(1200);
            await using var session = new InfisicalPeriodicTokenSession(origin, issued.AccessToken,
                new InfisicalTokenLifetimeEvidence
                {
                    OriginalIssuedAt = issued.Metadata.CreatedAt,
                    ExpiresAt = issued.Metadata.CreatedAt.AddSeconds(issued.ExpiresIn),
                    Lifetime = InfisicalTokenLifetime.Finite,
                    ReportedMaximumTtl = TimeSpan.FromSeconds(issued.AccessTokenMaxTTL)
                }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10), network);
            await Assert.That(session.State).IsEqualTo(InfisicalTokenSessionState.Ready);
            await using var reader = new InfisicalClient(origin, session, network);
            var selected = new SecretReference(reader.Authority,
                new InfisicalSecretAddress(project, "dev", "/", key));
            await VerifyRead();
            var denied = await reader.ReadAsync(new SecretReference(reader.Authority,
                new InfisicalSecretAddress(otherProject, "dev", "/", key)), cancellationToken);
            if (denied.IsSuccess) denied.Value.Dispose();
            await Assert.That(denied.Status).IsEqualTo(SecretStatus.Denied);
            var writeTarget = new SecretReference(reader.Authority,
                new InfisicalSecretAddress(project, "dev", "/", "SDK_NATIVE_TOKEN_DENIED"));
            var writeReceipt = new MutationReceipt(writeTarget);
            var write = await reader.CreateAsync(writeTarget, expected, writeReceipt, cancellationToken);
            await Assert.That(write.Status).IsEqualTo(SecretStatus.Denied);
            await Assert.That(writeReceipt.Evidence).IsEqualTo(DispatchEvidence.Rejected);

            if (generic)
            {
                await Assert.That(await session.RenewAsync(cancellationToken)).IsEqualTo(SecretStatus.Success);
                await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.Applied);
                await VerifyRead();
                using var current = (await session.GetTokenAsync(cancellationToken)).Value;
                using var proof = new InfisicalProofAuthentication(origin, network);
                var receipt = proof.CreateRevocationReceipt();
                await Assert.That(await proof.RevokeTokenAsync(current.Material, receipt, cancellationToken))
                    .IsEqualTo(SecretStatus.Success);
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
                await Assert.That(await proof.RevokeTokenAsync(current.Material, receipt, cancellationToken))
                    .IsEqualTo(SecretStatus.Invalid);
            }
            else
            {
                using var revoke = IdentityAuthenticationOperations.RevokeToken(organization, issued.Metadata.Id);
                _ = await Apply(revoke, new(organization, resourceId: issued.Metadata.Id), "token-revoke");
            }
            if (!generic)
            {
                using var inspect = IdentityAuthenticationOperations.GetToken(organization, issued.Metadata.Id);
                var metadata = await management.ExecuteAsync(inspect, authority,
                    authority.IssueGrant(inspect.OperationId, new(organization, resourceId: issued.Metadata.Id)),
                    cancellationToken: cancellationToken);
                Require(metadata.Status, "revoked-token-inspection", DispatchEvidence.NotDispatched);
                await Assert.That(metadata.Value.IsAccessTokenRevoked == true).IsTrue();
            }
            // Generic revocation addresses the renewed credential, not an asserted
            // token-management row state. Both routes must deny an actual fresh read.
            var revoked = await reader.ReadAsync(selected, cancellationToken);
            if (revoked.IsSuccess) revoked.Value.Dispose();
            await Assert.That(revoked.Status).IsEqualTo(SecretStatus.Denied);

            async Task VerifyRead()
            {
                var result = await reader.ReadAsync(selected, cancellationToken);
                Require(result.Status, "token-runtime-read", DispatchEvidence.NotDispatched);
                using var observed = result.Value;
                await Assert.That(observed.Material.Reveal() == expected.Reveal()).IsTrue();
            }
        }
        Console.WriteLine("OWNED_NATIVE_TOKEN_RENEWAL_AND_REVOCATION_PASSED");

        async Task<T> Apply<T>(ManagementRequest<T> request, ManagementTarget target, string step) where T : notnull
        {
            var receipt = management.CreateReceipt(request);
            var result = await management.ExecuteAsync(request, authority,
                authority.IssueGrant(request.OperationId, target), receipt, cancellationToken);
            Require(result.Status, step, receipt.Evidence);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            return result.Value;
        }
    }

    private static void Require(SecretStatus status, string step, DispatchEvidence evidence)
    {
        if (status != SecretStatus.Success)
            throw new InvalidOperationException($"Owned native authentication {step}: {status}; evidence: {evidence}.");
    }
}
