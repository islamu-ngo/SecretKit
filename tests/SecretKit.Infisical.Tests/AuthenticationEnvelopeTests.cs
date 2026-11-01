using System.Net;
using System.Text;
using SecretKit.Core;

namespace SecretKit.Infisical.Tests;

public sealed class AuthenticationEnvelopeTests
{
    [Test]
    [Arguments("universal", "type")]
    [Arguments("proof", "type")]
    [Arguments("renewal", "type")]
    [Arguments("universal", "missing")]
    [Arguments("proof", "missing")]
    [Arguments("renewal", "missing")]
    [Arguments("universal", "lifetime")]
    [Arguments("proof", "lifetime")]
    [Arguments("renewal", "lifetime")]
    [Arguments("universal", "deep")]
    [Arguments("proof", "deep")]
    [Arguments("renewal", "deep")]
    [Arguments("universal", "large")]
    [Arguments("proof", "large")]
    [Arguments("renewal", "large")]
    public async Task AdditivePolicyRetainsKnownTypesLifetimeAndStructuralBounds(string owner, string mode)
    {
        const string valid = """{"accessToken":"issued-token","expiresIn":120,"accessTokenMaxTTL":0,"tokenType":"Bearer"}""";
        string body = mode switch
        {
            "type" => valid.Replace("\"tokenType\":\"Bearer\"", "\"tokenType\":12", StringComparison.Ordinal),
            "missing" => valid.Replace("\"expiresIn\":120,", "", StringComparison.Ordinal),
            "lifetime" => valid.Replace("\"expiresIn\":120", "\"expiresIn\":-1", StringComparison.Ordinal),
            "deep" => valid[..^1] + ""","metadata":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":1}}}}}}}}}}""",
            "large" => valid[..^1] + ",\"metadata\":\"" + new string('x', 2048) + "\"}",
            _ => throw new InvalidOperationException("Unexpected envelope fixture.")
        };
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(body) });
        var network = new InfisicalNetworkOptions
        { Transport = InfisicalTransportOptions.HostControlled(wire), MaximumResponseBytes = 1024 };
        using var secret = SecretMaterial.FromText("input-token");
        if (owner == "universal")
        {
            using var client = new InfisicalUniversalAuthentication(new("https://auth.test"), network, clock);
            var receipt = client.CreateReceipt();
            var result = await client.LoginAsync("client", secret, receipt);
            if (result.IsSuccess) result.Value.Dispose();
            await Assert.That(result.IsSuccess).IsFalse();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        else if (owner == "proof")
        {
            using var client = new InfisicalProofAuthentication(new("https://auth.test"), network, clock);
            using var proof = InfisicalLoginProof.Jwt("identity", secret);
            var receipt = client.CreateReceipt();
            var result = await client.LoginAsync(proof, receipt);
            if (result.IsSuccess) result.Value.Dispose();
            await Assert.That(result.IsSuccess).IsFalse();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        else
        {
            await using var session = new InfisicalPeriodicTokenSession(new("https://auth.test"), secret,
                new InfisicalTokenLifetimeEvidence
                {
                    OriginalIssuedAt = clock.GetUtcNow(),
                    ExpiresAt = clock.GetUtcNow().AddMinutes(2),
                    Lifetime = InfisicalTokenLifetime.Periodic,
                    Period = TimeSpan.FromMinutes(2),
                    ReportedMaximumTtl = TimeSpan.Zero
                }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5), network, clock);
            await Assert.That(await session.RenewAsync()).IsEqualTo(SecretStatus.RecoveryRequired);
            await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(InfisicalRenewalEvidence.PossiblyDispatched);
        }
        await Assert.That(wire.Requests).IsEqualTo(1);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task RenewalAcceptsAdditionsButNeverDuplicateUnknownMembers(bool duplicate)
    {
        var clock = new InfisicalTransportOwnershipTests.ShutdownClock();
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("""{"accessToken":"renewed-token","expiresIn":120,"accessTokenMaxTTL":0,"tokenType":"Bearer","metadata":1""" +
                (duplicate ? ""","metadata":2}""" : "}"))
        });
        using var token = SecretMaterial.FromText("original-token");
        await using var session = new InfisicalPeriodicTokenSession(new("https://auth.test"), token,
            new InfisicalTokenLifetimeEvidence
            {
                OriginalIssuedAt = clock.GetUtcNow(),
                ExpiresAt = clock.GetUtcNow().AddMinutes(2),
                Lifetime = InfisicalTokenLifetime.Periodic,
                Period = TimeSpan.FromMinutes(2),
                ReportedMaximumTtl = TimeSpan.Zero
            }, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(5),
            new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) }, clock);
        var status = await session.RenewAsync();
        await Assert.That(status).IsEqualTo(duplicate ? SecretStatus.RecoveryRequired : SecretStatus.Success);
        await Assert.That(session.LastRenewal!.Evidence).IsEqualTo(duplicate
            ? InfisicalRenewalEvidence.PossiblyDispatched : InfisicalRenewalEvidence.Applied);
    }

    [Test]
    [Arguments(false, """{"metadata":{"private":"unknown-canary"}}""", true)]
    [Arguments(true, """{"metadata":{"private":"unknown-canary"}}""", true)]
    [Arguments(false, """{"metadata":1,"metadata":2}""", false)]
    [Arguments(true, """{"metadata":1,"metadata":2}""", false)]
    [Arguments(false, """{"tokenType":12}""", false)]
    [Arguments(true, """{"expiresIn":"120"}""", false)]
    public async Task BoundedAdditionsAreIgnoredButAmbiguousEnvelopesAreRejected(bool proof, string extra, bool success)
    {
        string body = """{"accessToken":"issued-token","expiresIn":120,"accessTokenMaxTTL":30,"tokenType":"Bearer",""" +
            extra[1..];
        using var wire = new FailureEvidenceTests.Wire(_ => new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        var network = new InfisicalNetworkOptions { Transport = InfisicalTransportOptions.HostControlled(wire) };
        using var secret = SecretMaterial.FromText("bootstrap-canary");
        if (proof)
        {
            using var authentication = new InfisicalProofAuthentication(new("https://auth.test"), network);
            using var input = InfisicalLoginProof.Jwt("identity", secret);
            var receipt = authentication.CreateReceipt();
            var outcome = await authentication.LoginAsync(input, receipt);
            if (outcome.IsSuccess) outcome.Value.Dispose();
            await Assert.That(outcome.IsSuccess).IsEqualTo(success);
            await Assert.That(receipt.Evidence).IsEqualTo(success ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        }
        else
        {
            using var authentication = new InfisicalUniversalAuthentication(new("https://auth.test"), network);
            var receipt = authentication.CreateReceipt();
            var outcome = await authentication.LoginAsync("client", secret, receipt);
            if (outcome.IsSuccess) outcome.Value.Dispose();
            await Assert.That(outcome.IsSuccess).IsEqualTo(success);
            await Assert.That(receipt.Evidence).IsEqualTo(success ? DispatchEvidence.Applied : DispatchEvidence.PossiblyDispatched);
        }
        await Assert.That(wire.Requests).IsEqualTo(1);
    }
}
