using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

public sealed class InfisicalAuthenticationIssuanceTests
{
    [Test]
    [Arguments(false, "organizationSlug.omitted")]
    [Arguments(false, "organizationSlug.value")]
    [Arguments(true, "proof.AliCloud")]
    [Arguments(true, "proof.Aws.method-omitted")]
    [Arguments(true, "proof.Aws.method-value")]
    [Arguments(true, "proof.Azure")]
    [Arguments(true, "proof.Gcp")]
    [Arguments(true, "proof.Jwt")]
    [Arguments(true, "proof.Kubernetes")]
    [Arguments(true, "proof.Oidc")]
    [Arguments(true, "proof.Spiffe.JWT-SVID")]
    [Arguments(true, "proof.Ldap")]
    [Arguments(true, "proof.Oci.date")]
    [Arguments(true, "proof.Oci.x-date")]
    [Arguments(true, "proof.Oci.date-and-x-date")]
    [Arguments(true, "proof.Oci.dates-omitted")]
    [Arguments(true, "organizationSlug.omitted")]
    [Arguments(true, "organizationSlug.value")]
    [Arguments(true, "maximumTTL.zero")]
    [Arguments(true, "maximumTTL.positive")]
    public async Task InterruptedOriginalUsesExactCapturedCredentialWithoutReceiptRewrite(bool proof, string variant)
    {
        foreach (string boundary in new[] { "cancellation-boundary", "lost-response-no-replay" })
            foreach (bool applied in new[] { false, true })
            {
                await using var fixture = new InfisicalAuthenticationIssuanceFixture();
                fixture.Server.Apply = applied;
                var root = fixture.Root(variant, proof, boundary);
                var outcome = await ExerciseAsync(fixture, root, proof);
                await Assert.That(outcome).IsEqualTo(applied ? AuthenticationIssuanceDisposition.Applied :
                    AuthenticationIssuanceDisposition.NonApplied);
                await Assert.That(fixture.Server.Logins).IsEqualTo(1);
                await Assert.That(fixture.CapturesTaken).IsEqualTo(applied ? 1 : 0);
                await ReleasedAsync(fixture);
            }
    }

    [Test]
    [Arguments("bad-signature", "observer-unavailable")]
    [Arguments("missing-seal", "observer-unavailable")]
    [Arguments("tampered-content", "observer-unavailable")]
    [Arguments("wrong-nonce", "observer-unavailable")]
    [Arguments("wrong-identity", "effect-mismatch")]
    [Arguments("wrong-method", "effect-mismatch")]
    [Arguments("wrong-request", "effect-mismatch")]
    [Arguments("wrong-ingress", "effect-mismatch")]
    [Arguments("wrong-metadata", "effect-mismatch")]
    [Arguments("wrong-policy", "effect-mismatch")]
    [Arguments("wrong-state", "effect-mismatch")]
    [Arguments("wrong-capture", "effect-mismatch")]
    [Arguments("wrong-credential", "effect-mismatch")]
    [Arguments("contradictory-delivery", "effect-mismatch")]
    [Arguments("contradictory-issuer", "observer-unavailable")]
    [Arguments("omitted-capture", "observer-unavailable")]
    [Arguments("partial", "observer-unavailable")]
    [Arguments("pending-issuer", "observer-unavailable")]
    [Arguments("pending-capture", "observer-unavailable")]
    [Arguments("pending-delivery", "observer-unavailable")]
    [Arguments("pending-seal", "observer-unavailable")]
    [Arguments("lost-capture", "observer-unavailable")]
    [Arguments("wrong-access", "effect-mismatch")]
    public async Task SourceAndEffectCounterexamplesFailClosed(string fault, string reason)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture { Fault = fault };
        string? observed = null;
        try { await ExerciseAsync(fixture, fixture.Root(), false); }
        catch (NativeCaseFailureException error) { observed = error.Message; }
        await Assert.That(observed).IsEqualTo(reason);
        await Assert.That(fixture.FaultReached).IsTrue();
        await Assert.That(fixture.Server.Logins).IsEqualTo(1);
        await ReleasedAsync(fixture);
    }

    [Test]
    [Arguments("key-cleanup")]
    [Arguments("registration-cleanup")]
    [Arguments("remaining-cleanup")]
    [Arguments("missing-revocation")]
    [Arguments("borrowed-cleanup")]
    public async Task CleanupEvidenceCannotCertifyUnsettledOrForeignOwnership(string fault)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture { Fault = fault };
        string? reason = null;
        try { await ExerciseAsync(fixture, fixture.Root(), false); }
        catch (NativeCaseFailureException error) { reason = error.Message; }
        await Assert.That(reason).IsEqualTo("cleanup-incomplete");
        await Assert.That(fixture.FaultReached).IsTrue();
        await Assert.That(fixture.OwnedBuffers.All(b => b.All(value => value == 0))).IsTrue();
    }

    [Test]
    [Arguments("lost-open")]
    [Arguments("cancel-open")]
    [Arguments("collision")]
    [Arguments("enrollment")]
    public async Task RecoveryPrecedesBootstrapAndDoesNotNeedReturnedIds(string fault)
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture { Fault = fault };
        AuthenticationIssuanceTrial? retained = null;
        bool failed = false;
        using var capability = SecretMaterial.FromText("owned-capability");
        try
        {
            await AuthenticationIssuanceTrial.OpenAsync(fixture.Source, fixture.Root(), capability,
                value => retained = value, CancellationToken.None);
        }
        catch (Exception error) when (error is NativeCaseFailureException or OperationCanceledException) { failed = true; }
        finally { if (retained is not null) await retained.DisposeAsync(); }
        await Assert.That(failed && retained is not null && fixture.FaultReached).IsTrue();
        await Assert.That(fixture.Server.Logins).IsEqualTo(0);
        await ReleasedAsync(fixture);
    }

    [Test]
    public async Task CancelledTransportWithoutIssuerIngressRequiresTerminalNoLateCommitFence()
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture();
        fixture.Server.BlockIngress = fixture.Server.HoldHeaders = true;
        var root = fixture.Root(boundary: "cancellation-boundary");
        using var capability = SecretMaterial.FromText("owned-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var cancel = new CancellationTokenSource();
        AuthenticationIssuanceTrial? trial = null;
        try
        {
            await AuthenticationIssuanceTrial.OpenAsync(fixture.Source, root, capability, t => trial = t, deadline.Token);
            using var authentication = new InfisicalUniversalAuthentication(fixture.Server.Origin,
                new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true });
            using var credential = SecretMaterial.FromText("original-proof");
            var receipt = authentication.CreateReceipt();
            await trial!.ArmAsync(receipt, deadline.Token);
            var original = authentication.LoginAsync("original-client", credential, receipt,
                cancellationToken: cancel.Token).AsTask();
            await fixture.Server.TransportArrived.Task.WaitAsync(deadline.Token);
            await cancel.CancelAsync();
            bool interrupted = false;
            try { await original.WaitAsync(deadline.Token); }
            catch (OperationCanceledException) when (!deadline.IsCancellationRequested) { interrupted = true; }
            await Assert.That(interrupted && receipt.Evidence == DispatchEvidence.PossiblyDispatched).IsTrue();
            await trial.SettleAsync(deadline.Token);
            using var environment = fixture.Environment();
            using var value = SecretMaterial.FromText("owned-material");
            await trial.ObserveAsync(environment, value, deadline.Token);
            await Assert.That(trial.Outcome).IsEqualTo(AuthenticationIssuanceDisposition.NonApplied);
            await Assert.That(fixture.Server.Applied).IsFalse();
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        finally { if (trial is not null) await trial.DisposeAsync(); }
        await ReleasedAsync(fixture);
    }

    [Test]
    public async Task CloseWaitsForExactDrainSignalBeforeCertifyingInventory()
    {
        await using var fixture = new InfisicalAuthenticationIssuanceFixture { Fault = "drain-barrier" };
        using var capability = SecretMaterial.FromText("owned-capability");
        var trial = await AuthenticationIssuanceTrial.OpenAsync(fixture.Source, fixture.Root(), capability,
            _ => { }, CancellationToken.None);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        Task closed = trial.DisposeAsync().AsTask();
        await fixture.DrainEntered.Task.WaitAsync(deadline.Token);
        await Assert.That(closed.IsCompleted).IsFalse();
        fixture.DrainRelease.TrySetResult();
        await closed.WaitAsync(deadline.Token);
        await ReleasedAsync(fixture);
    }

    [Test]
    public async Task RetainedInventoryKeepsTwentyOnePairsAndAllOneHundredFiveBoundaries()
    {
        string root = Path.GetFullPath("../../../../../", AppContext.BaseDirectory);
        using var document = JsonDocument.Parse(await File.ReadAllTextAsync(
            Path.Combine(root, "docs/internal/releases/admission/infisical.json")));
        var definitions = document.RootElement.GetProperty("operations").EnumerateArray().Where(o =>
            o.GetProperty("id").GetString() is InfisicalUniversalAuthenticationEffects.Operation or
                InfisicalProofAuthenticationEffects.Operation).SelectMany(o =>
                o.GetProperty("variants").EnumerateArray().SelectMany(v =>
                    o.GetProperty("requiredCases").EnumerateArray().Select(c => new NativeCaseDefinition(
                        new("Infisical", o.GetProperty("id").GetString()!, v.GetString()!, "local", c.GetString()!),
                        o.GetProperty("member").GetString()!)))).ToArray();
        await Assert.That(definitions.Length).IsEqualTo(105);
        await Assert.That(definitions.Select(d => (d.Key.Operation, d.Key.Variant)).Distinct().Count()).IsEqualTo(21);
        await Assert.That(definitions.All(AuthenticationIssuanceContract.Owns)).IsTrue();
        await Assert.That(definitions.Count(d => AuthenticationIssuanceContract.Interrupted(d.Key.Case))).IsEqualTo(42);
        // mTLS presentation stays host-owned; this fixture has not qualified it.
        await Assert.That(definitions.Count(d => d.Key.Variant == "proof.TlsCertificate.host-mtls")).IsEqualTo(5);
    }

    private static async Task<AuthenticationIssuanceDisposition?> ExerciseAsync(
        InfisicalAuthenticationIssuanceFixture fixture, AuthenticationIssuanceRoot root, bool proof)
    {
        AuthenticationIssuanceTrial? trial = null;
        using var capability = SecretMaterial.FromText("owned-capability");
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var environment = fixture.Environment();
        try
        {
            await AuthenticationIssuanceTrial.OpenAsync(fixture.Source, root, capability, value => trial = value, deadline.Token);
            await DispatchAsync(fixture, root, trial!, proof, deadline.Token);
            await trial!.SettleAsync(deadline.Token);
            using var value = SecretMaterial.FromText("owned-material");
            await trial.ObserveAsync(environment, value, deadline.Token);
            return trial.Outcome;
        }
        finally { if (trial is not null) await trial.DisposeAsync(); }
    }

    internal static async ValueTask DispatchAsync(InfisicalAuthenticationIssuanceFixture fixture,
        AuthenticationIssuanceRoot root, AuthenticationIssuanceTrial trial, bool proof, CancellationToken token)
    {
        fixture.Server.HoldHeaders = true;
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        using var credential = SecretMaterial.FromText("original-proof");
        var network = new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = true };
        if (proof)
        {
            using var authentication = new InfisicalProofAuthentication(fixture.Server.Origin, network);
            using var input = Proof(root.Variant, credential);
            var receipt = authentication.CreateReceipt();
            await trial.ArmAsync(receipt, token);
            Task<SecretOutcome<InfisicalProofLogin>> call = authentication.LoginAsync(input, receipt, cancellation.Token).AsTask();
            await InterruptAsync(call);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        else
        {
            using var authentication = new InfisicalUniversalAuthentication(fixture.Server.Origin, network);
            var receipt = authentication.CreateReceipt();
            await trial.ArmAsync(receipt, token);
            Task<SecretOutcome<InfisicalUniversalLogin>> call = authentication.LoginAsync("original-client", credential,
                receipt, root.Variant == "organizationSlug.value" ? "owned" : null, cancellation.Token).AsTask();
            await InterruptAsync(call);
            await Assert.That(receipt.Evidence).IsEqualTo(DispatchEvidence.PossiblyDispatched);
        }
        async ValueTask InterruptAsync<T>(Task<SecretOutcome<T>> call) where T : notnull
        {
            await fixture.Server.Received.Task.WaitAsync(token);
            if (root.Boundary == "cancellation-boundary") await cancellation.CancelAsync();
            else await fixture.Server.DrainAsync(token);
            bool cancelled = false;
            try
            {
                var result = await call.WaitAsync(token);
                if (result.IsSuccess && result.Value is IDisposable owned) owned.Dispose();
                await Assert.That(result.Status).IsEqualTo(SecretStatus.Unknown);
            }
            catch (OperationCanceledException) when (!token.IsCancellationRequested) { cancelled = true; }
            await Assert.That(cancelled).IsEqualTo(root.Boundary == "cancellation-boundary");
        }
    }
    internal static InfisicalLoginProof Proof(string variant, SecretMaterial credential)
    {
        const string identity = InfisicalAuthenticationIssuanceServer.Identity;
        string? slug = variant == "organizationSlug.value" ? "owned" : null;
        return variant switch
        {
            "proof.AliCloud" => InfisicalLoginProof.AliCloud(identity, credential, credential, credential,
                "2026-10-14T00:00:00Z", "2015-04-01", slug),
            "proof.Aws.method-omitted" => InfisicalLoginProof.Aws(identity, credential, credential, null, slug),
            "proof.Aws.method-value" => InfisicalLoginProof.Aws(identity, credential, credential, "POST", slug),
            "proof.Azure" => InfisicalLoginProof.Azure(identity, credential, slug),
            "proof.Gcp" => InfisicalLoginProof.Gcp(identity, credential, slug),
            "proof.Kubernetes" => InfisicalLoginProof.Kubernetes(identity, credential, slug),
            "proof.Oidc" => InfisicalLoginProof.Oidc(identity, credential, slug),
            "proof.Spiffe.JWT-SVID" => InfisicalLoginProof.Spiffe(identity, credential, slug),
            "proof.Ldap" => InfisicalLoginProof.Ldap(identity, "owned-user", credential, slug),
            "proof.Oci.date" => InfisicalLoginProof.Oci(identity, "owned-user", credential, "issuer", "date", null, slug),
            "proof.Oci.x-date" => InfisicalLoginProof.Oci(identity, "owned-user", credential, "issuer", null, "x-date", slug),
            "proof.Oci.date-and-x-date" => InfisicalLoginProof.Oci(identity, "owned-user", credential, "issuer", "date", "x-date", slug),
            "proof.Oci.dates-omitted" => InfisicalLoginProof.Oci(identity, "owned-user", credential, "issuer", null, null, slug),
            "proof.TlsCertificate.host-mtls" => InfisicalLoginProof.TlsCertificate(identity, slug),
            _ => InfisicalLoginProof.Jwt(identity, credential, slug)
        };
    }
    internal static async Task ReleasedAsync(InfisicalAuthenticationIssuanceFixture fixture)
    {
        await Assert.That(fixture.Closed && !fixture.Server.Exists && fixture.BorrowedExists).IsTrue();
        await Assert.That(fixture.CloseCalls).IsEqualTo(1);
        await Assert.That(fixture.OwnedBuffers.All(b => b.All(value => value == 0))).IsTrue();
        await Assert.That(fixture.OwnedCharacters.All(c => c.All(value => value == '\0'))).IsTrue();
    }
}
