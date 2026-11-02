using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthenticationIssuanceCalibrationTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task IndependentSourceCapturesActualSdkCredentialAndPreservesSeparateDelivery(bool proof)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture();
        fixture.Server.HoldResponse = false;
        var root = fixture.Root(proof ? "proof.Jwt" : "organizationSlug.omitted", proof);
        using var verifier = new AuthenticationIssuanceVerifier(root);
        using var capability = SecretMaterial.FromText("owned-capability");
        using var supplied = SecretMaterial.FromText("original-proof");
        byte[] key = RandomNumberGenerator.GetBytes(32);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        AuthenticationIssuanceCaptured? capture = null;
        InfisicalAccessToken? issued = null;
        try
        {
            await Step(AuthenticationIssuanceStep.Reserve, capability);
            await Step(AuthenticationIssuanceStep.Open);
            await Step(AuthenticationIssuanceStep.Arm);
            var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
            if (proof)
            {
                using var authentication = new InfisicalProofAuthentication(fixture.Server.Origin, network);
                using var request = InfisicalAuthenticationIssuanceTests.Proof("proof.Jwt", supplied);
                var receipt = authentication.CreateReceipt();
                var result = await authentication.LoginAsync(request, receipt, deadline.Token);
                await Assert.That(result.IsSuccess).IsTrue();
                using var login = result.Value;
                issued = new(login.Token.Material.Copy());
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            }
            else
            {
                using var authentication = new InfisicalUniversalAuthentication(fixture.Server.Origin, network);
                var receipt = authentication.CreateReceipt();
                var result = await authentication.LoginAsync("original-client", supplied, receipt,
                    cancellationToken: deadline.Token);
                await Assert.That(result.IsSuccess).IsTrue();
                using var login = result.Value;
                issued = new(login.Token.Material.Copy());
                await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.Applied);
            }
            var settled = await Step(AuthenticationIssuanceStep.Settle);
            capture = await fixture.Source.TakeCaptureAsync(root, settled.Captures.Single().Content.Header.Event, deadline.Token);
            var issuer = settled.Issuers.Single().Content;
            await Assert.That(settled.Deliveries.Single().Content.ResponseDelivered).IsTrue();
            await Assert.That(AuthenticationIssuanceContract.EqualWitness(issuer.CredentialWitness,
                AuthenticationIssuanceContract.Witness(root, key, issued.Material))).IsTrue();
            await Assert.That(AuthenticationIssuanceContract.EqualWitness(issuer.CredentialWitness,
                AuthenticationIssuanceContract.Witness(root, key, capture.Material))).IsTrue();
            await Assert.That(AuthenticationIssuanceContract.EqualWitness(issuer.CredentialWitness,
                AuthenticationIssuanceContract.Witness(root with { Nonce = "another-attempt" }, key, capture.Material))).IsFalse();
            await using var client = new InfisicalClient(fixture.Server.Origin,
                new AuthenticationTokenSource(capture.Material), network);
            foreach (string name in new[] { "ALLOWED", "DENIED" })
            {
                var result = await client.ReadAsync(new(client.Authority,
                    new InfisicalSecretAddress("project", "dev", "/", name)), deadline.Token);
                using SecretRead? value = result.IsSuccess ? result.Value : null;
                await Assert.That(result.Status).IsEqualTo(name == "ALLOWED" ? SecretStatus.Success : SecretStatus.Denied);
            }
            var access = await Step(AuthenticationIssuanceStep.Access);
            await Assert.That(access.Access.Select(a => a.Content.Allowed).SequenceEqual(new[] { true, false })).IsTrue();
            await Assert.That(access.Access.All(a => a.Content.CredentialWitness == issuer.CredentialWitness &&
                a.Content.IssuerEvent == issuer.Header.Event)).IsTrue();
        }
        finally
        {
            capture?.Dispose(); issued?.Dispose();
            CryptographicOperations.ZeroMemory(key);
            await Step(AuthenticationIssuanceStep.Close);
        }
        await Assert.That(fixture.Server.Logins).IsEqualTo(1);
        await InfisicalAuthenticationIssuanceTests.ReleasedAsync(fixture);
        async ValueTask<AuthenticationIssuancePacket> Step(AuthenticationIssuanceStep step, SecretMaterial? authority = null)
        {
            var packet = await fixture.Source.StepAsync(root, step, authority,
                step == AuthenticationIssuanceStep.Arm ? key : ReadOnlyMemory<byte>.Empty, deadline.Token);
            verifier.Packet(packet, step);
            return packet;
        }
    }

    [Test]
    [Arguments("foreign-root")]
    [Arguments("reordered-step")]
    [Arguments("second-open")]
    public async Task PrivateSourceRejectsRebindingOrReplayBeforeProviderDispatch(string attack)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture();
        var root = fixture.Root();
        using var capability = SecretMaterial.FromText("owned-capability");
        await fixture.Source.StepAsync(root, AuthenticationIssuanceStep.Reserve, capability, ReadOnlyMemory<byte>.Empty,
            CancellationToken.None);
        bool rejected = false;
        try
        {
            if (attack == "second-open")
            {
                await fixture.Source.StepAsync(root, AuthenticationIssuanceStep.Open, null, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None);
                await fixture.Source.StepAsync(root, AuthenticationIssuanceStep.Open, null, ReadOnlyMemory<byte>.Empty,
                    CancellationToken.None);
            }
            else
                await fixture.Source.StepAsync(attack == "foreign-root" ? root with { Nonce = "foreign" } : root,
                    attack == "reordered-step" ? AuthenticationIssuanceStep.Settle : AuthenticationIssuanceStep.Open,
                    null, ReadOnlyMemory<byte>.Empty, CancellationToken.None);
        }
        catch (NativeCaseFailureException) { rejected = true; }
        finally
        {
            await fixture.Source.StepAsync(root, AuthenticationIssuanceStep.Close, null, ReadOnlyMemory<byte>.Empty,
                CancellationToken.None);
        }
        await Assert.That(rejected).IsTrue();
        await Assert.That(fixture.Server.Logins).IsEqualTo(0);
        await InfisicalAuthenticationIssuanceTests.ReleasedAsync(fixture);
    }

    [Test]
    [Arguments("same-key")]
    [Arguments("same-writer")]
    [Arguments("same-channel")]
    [Arguments("coordinator-writer")]
    public async Task HostPinSeparationIsRequiredBeforeBootstrap(string attack)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture();
        var root = fixture.Root();
        var first = root.Profile.Pins[0];
        root.Profile.Pins[1] = attack switch
        {
            "same-key" => root.Profile.Pins[1] with { SubjectPublicKeyInfo = first.SubjectPublicKeyInfo },
            "same-writer" => root.Profile.Pins[1] with { Writer = first.Writer },
            "same-channel" => root.Profile.Pins[1] with { Channel = first.Channel },
            _ => root.Profile.Pins[1] with { Writer = root.Source }
        };
        using var capability = SecretMaterial.FromText("owned-capability");
        bool rejected = false, retained = false;
        try
        {
            await AuthenticationIssuanceTrial.OpenAsync(fixture.Source, root, capability,
                _ => retained = true, CancellationToken.None);
        }
        catch (NativeCaseFailureException error) { rejected = error.Message == "missing-input"; }
        await Assert.That(rejected && !retained && !fixture.Server.Exists).IsTrue();
        await Assert.That(fixture.Server.Logins).IsEqualTo(0);
    }
}
