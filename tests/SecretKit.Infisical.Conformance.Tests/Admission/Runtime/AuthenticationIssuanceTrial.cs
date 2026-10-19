using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Single original dispatch only. The getter is bound to the actual public receipt
// before Arm. Settlement never writes that receipt and cannot dispatch a login.
internal sealed class AuthenticationIssuanceTrial : IAsyncDisposable
{
    private readonly IAuthenticationIssuanceSource source;
    private readonly AuthenticationIssuanceRoot root;
    private readonly string rootHash;
    private readonly AuthenticationIssuanceVerifier verifier;
    private readonly byte[] key;
    private readonly object gate = new();
    private AuthenticationIssuanceOwner? reservation;
    private AuthenticationIssuanceCaptured? captured;
    private AuthenticationIssuanceIssuer? issuer;
    private Func<DispatchEvidence>? receipt;
    private int stage;
    private bool busy, failed, closed;
    internal AuthenticationIssuanceDisposition? Outcome { get; private set; }
    internal DispatchEvidence? OriginalEvidence { get; private set; }

    private AuthenticationIssuanceTrial(IAuthenticationIssuanceSource source, AuthenticationIssuanceRoot root)
    {
        this.source = source; this.root = root;
        rootHash = AuthenticationIssuanceContract.Hash(root);
        verifier = new(root);
        key = RandomNumberGenerator.GetBytes(32);
    }

    internal static async ValueTask<AuthenticationIssuanceTrial> OpenAsync(IAuthenticationIssuanceSource source,
        AuthenticationIssuanceRoot root, SecretMaterial capability, Action<AuthenticationIssuanceTrial> retain,
        CancellationToken token)
    {
        AuthenticationIssuanceContract.Require(source.Identity == root.Source && source.Kind == root.Kind &&
            Enum.IsDefined(root.Kind) && AuthenticationIssuanceContract.Interrupted(root.Boundary) &&
            AuthenticationIssuanceContract.Owns(new(new("Infisical", root.Operation, root.Variant, root.Scope,
                root.Boundary), root.Member)) &&
            new[] { root.Id, root.Nonce, root.Organization, root.Identity, root.Method, root.ObserverIdentity,
                root.Project, root.Environment, root.Folder, root.AllowedKey, root.DeniedKey }.All(AuthenticationIssuanceContract.Text) &&
            Guid.TryParseExact(root.Identity, "D", out var identity) && identity != Guid.Empty &&
            AuthenticationIssuanceContract.MatchesMethod(root) && root.AllowedKey != root.DeniedKey &&
            root.ObserverIdentity != root.Identity && root.Source != root.Identity &&
            root.Source != root.ObserverIdentity &&
            root.Profile.Pins.All(p => p.Writer != root.Source && p.Writer != root.Identity &&
                p.Writer != root.ObserverIdentity), "missing-input");
        var trial = new AuthenticationIssuanceTrial(source, root);
        retain(trial); // Recovery anchored before Reserve/Open, even if their replies are lost.
        var reserve = await trial.StepAsync(AuthenticationIssuanceStep.Reserve, capability, token);
        trial.reservation = reserve.Owner.Content;
        trial.Require(trial.reservation.CollisionChecked && trial.reservation.PreEnrolled &&
            trial.reservation.Remaining.Length == 0);
        await trial.StepAsync(AuthenticationIssuanceStep.Open, null, token);
        return trial;
    }

    internal ValueTask ArmAsync(InfisicalUniversalLoginReceipt original, CancellationToken token) =>
        ArmAsync(() => original.Evidence, token);
    internal ValueTask ArmAsync(InfisicalProofLoginReceipt original, CancellationToken token) =>
        ArmAsync(() => original.Evidence, token);
    private async ValueTask ArmAsync(Func<DispatchEvidence> original, CancellationToken token)
    {
        Require(receipt is null && original() == DispatchEvidence.NotDispatched, "contract-mismatch");
        receipt = original;
        var packet = await StepAsync(AuthenticationIssuanceStep.Arm, null, token);
        Require(packet.Owner.Content.IssuerArmed && packet.Owner.Content.CaptureArmed);
    }

    internal async ValueTask SettleAsync(CancellationToken token)
    {
        Require(receipt is not null && receipt() == DispatchEvidence.PossiblyDispatched, "contract-mismatch");
        OriginalEvidence = receipt!();
        var packet = await StepAsync(AuthenticationIssuanceStep.Settle, null, token);
        Require(packet.Ingress.Length <= 1 && packet.Issuers.Length == 1 &&
            packet.Deliveries.Length == 1 && packet.Access.Length == 0, "effect-mismatch");
        var ingress = packet.Ingress.SingleOrDefault()?.Content;
        issuer = packet.Issuers[0].Content;
        var delivery = packet.Deliveries[0].Content;
        Require((ingress is null ? issuer.Request == "" && issuer.IngressEvent == "" &&
                issuer.Disposition == AuthenticationIssuanceDisposition.NonApplied :
                AuthenticationIssuanceContract.Text(ingress.Request) && ingress.Identity == root.Identity &&
                ingress.Method == root.Method && ingress.Path == "/api/v1/auth/" + root.Method + "/login" &&
                issuer.Request == ingress.Request && issuer.IngressEvent == ingress.Header.Event) &&
            issuer.Identity == root.Identity && issuer.Method == root.Method &&
            AuthenticationIssuanceContract.Text(issuer.StateRevision) &&
            delivery.Request == issuer.Request && delivery.IssuerEvent == issuer.Header.Event &&
            delivery.Settled && !delivery.ResponseDelivered, "effect-mismatch");
        // A separately signed label is not a documented incomplete issuer state.
        Require(issuer.Disposition != AuthenticationIssuanceDisposition.Partial);
        Require(Enum.IsDefined(issuer.Disposition), "effect-mismatch");
        if (issuer.Disposition == AuthenticationIssuanceDisposition.NonApplied)
        {
            Require(issuer.MetadataId == "" && issuer.CredentialWitness == "" &&
                packet.Metadata.Length == 0 && packet.Captures.Length == 0, "effect-mismatch");
        }
        else
        {
            Require(ingress is { Authorized: true } && Guid.TryParseExact(issuer.MetadataId, "D", out var metadataId) &&
                metadataId != Guid.Empty && !reservation!.Borrowed.Any(b => b.Id == issuer.MetadataId) &&
                packet.Metadata.Length == 1 && packet.Captures.Length <= 1, "effect-mismatch");
            var metadata = packet.Metadata[0].Content;
            Require(metadata.Request == issuer.Request && metadata.IssuerEvent == issuer.Header.Event &&
                metadata.Identity == root.Identity && metadata.Method == root.Method &&
                metadata.MetadataId == issuer.MetadataId && metadata.StateRevision == issuer.StateRevision &&
                metadata.CredentialWitness == issuer.CredentialWitness &&
                metadata.Policy == root.Policy && metadata.Active, "effect-mismatch");
            Require(packet.Captures.Length == 1); // Missing capture is unavailable, not Partial.
            var capture = packet.Captures[0].Content;
            Require(capture.Request == issuer.Request && capture.IssuerEvent == issuer.Header.Event &&
                capture.Identity == root.Identity && capture.Method == root.Method &&
                capture.MetadataId == issuer.MetadataId && capture.StateRevision == issuer.StateRevision &&
                capture.CredentialWitness == issuer.CredentialWitness, "effect-mismatch");
            Require(capture.PrivateDeliveryReady);
            try
            {
                captured = await source.TakeCaptureAsync(root, capture.Header.Event, token);
                Require(captured.CaptureEvent == capture.Header.Event &&
                    AuthenticationIssuanceContract.EqualWitness(issuer.CredentialWitness,
                        AuthenticationIssuanceContract.Witness(root, key, captured.Material)), "effect-mismatch");
            }
            catch
            {
                failed = true; captured?.Dispose(); captured = null;
                throw;
            }
        }
        Require(receipt() == OriginalEvidence, "contract-mismatch");
        Outcome = issuer.Disposition;
    }

    internal async ValueTask ObserveAsync(NativeEnvironment environment, SecretMaterial expectedValue,
        CancellationToken token)
    {
        Require(Outcome is not null && issuer is not null && environment.Origin.AbsoluteUri == root.Origin);
        var expected = new List<(string Identity, string Witness, string Key, bool Authenticated, bool Allowed)>();
        string valueWitness = AuthenticationIssuanceContract.Witness(root, key, expectedValue, "canary");
        try
        {
            if (Outcome == AuthenticationIssuanceDisposition.Applied)
            {
                Require(captured is not null);
                // No local ExpiresAt hint: these must be actual provider reads.
                await using var consumer = environment.CreateClient(new AuthenticationTokenSource(captured!.Material));
                await ReadAsync(consumer, root.AllowedKey, true);
                await ReadAsync(consumer, root.DeniedKey, false);
                expected.Add((root.Identity, issuer!.CredentialWitness, root.AllowedKey, true, true));
                expected.Add((root.Identity, issuer.CredentialWitness, root.DeniedKey, true, false));
            }
            using var wrong = SecretMaterial.FromText(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
            await using (var denied = environment.CreateClient(new AuthenticationTokenSource(wrong)))
                await ReadAsync(denied, root.AllowedKey, false);
            expected.Add(("", AuthenticationIssuanceContract.Witness(root, key, wrong), root.AllowedKey, false, false));
            await using (var observer = environment.CreateObserverClient())
                await ReadAsync(observer, root.AllowedKey, true);
            expected.Add((root.ObserverIdentity, "", root.AllowedKey, true, true));
            var packet = await StepAsync(AuthenticationIssuanceStep.Access, null, token);
            Require(packet.Ingress.Length == 0 && packet.Issuers.Length == 0 && packet.Deliveries.Length == 0 &&
                packet.Metadata.Length == 0 && packet.Captures.Length == 0 && packet.Access.Length == expected.Count &&
                packet.Access.Select(a => a.Content.Request).Distinct().Count() == expected.Count, "effect-mismatch");
            for (int i = 0; i < expected.Count; i++)
            {
                var fact = packet.Access[i].Content;
                var want = expected[i];
                Require(AuthenticationIssuanceContract.Text(fact.Request) && fact.Request != issuer!.Request &&
                    fact.IssuerEvent == issuer.Header.Event && fact.Identity == want.Identity &&
                    fact.CredentialWitness == want.Witness && fact.Key == want.Key &&
                    fact.Authenticated == want.Authenticated && fact.Allowed == want.Allowed &&
                    fact.ValueWitness == (want.Allowed ? valueWitness : ""), "effect-mismatch");
            }
            Require(receipt!() == OriginalEvidence, "contract-mismatch");
        }
        finally { captured?.Dispose(); captured = null; }

        async ValueTask ReadAsync(InfisicalClient client, string name, bool allowed)
        {
            var result = await client.ReadAsync(new(client.Authority,
                new InfisicalSecretAddress(root.Project, root.Environment, root.Folder, name)), token);
            using SecretRead? read = result.IsSuccess ? result.Value : null;
            Require(result.Status == (allowed ? SecretStatus.Success : SecretStatus.Denied) &&
                (!allowed || AuthenticationIssuanceContract.EqualWitness(valueWitness,
                    AuthenticationIssuanceContract.Witness(root, key, read!.Material, "canary"))), "effect-mismatch");
        }
    }

    private async ValueTask<AuthenticationIssuancePacket> StepAsync(AuthenticationIssuanceStep step,
        SecretMaterial? capability, CancellationToken token)
    {
        lock (gate)
        {
            Require(!closed && !busy && !failed && stage == (int)step &&
                rootHash == AuthenticationIssuanceContract.Hash(root));
            busy = failed = true; stage++;
        }
        try
        {
            var packet = await source.StepAsync(root, step, capability,
                step == AuthenticationIssuanceStep.Arm ? key : ReadOnlyMemory<byte>.Empty, token);
            Owner(packet, step);
            if (step is AuthenticationIssuanceStep.Reserve or AuthenticationIssuanceStep.Open or AuthenticationIssuanceStep.Arm)
                Require(packet.Ingress.Length + packet.Issuers.Length + packet.Deliveries.Length +
                    packet.Metadata.Length + packet.Captures.Length + packet.Access.Length == 0, "effect-mismatch");
            failed = false;
            return packet;
        }
        finally { lock (gate) busy = false; }
    }
    private void Owner(AuthenticationIssuancePacket packet, AuthenticationIssuanceStep step)
    {
        verifier.Packet(packet, step);
        var owner = packet.Owner.Content;
        Require(owner.Exclusive && owner.PreEnrolled && owner.CollisionChecked && owner.Terminal &&
            owner.PendingIssuers == 0 && owner.PendingCaptures == 0 && owner.PendingDeliveries == 0 &&
            owner.Registrations == (step == AuthenticationIssuanceStep.Close ? 0 : 1) &&
            owner.Enrolled.Length == 7 && owner.Enrolled.Select(e => e.Kind).Distinct().Count() == 7 &&
            owner.Enrolled.All(e => Enum.IsDefined(e.Kind) && e.Root == root.Id && e.Nonce == root.Nonce &&
                AuthenticationIssuanceContract.Text(e.Slot)) &&
            owner.Enrolled.Select(e => e.Slot).Distinct().Count() == 7 &&
            owner.Remaining.Distinct().Count() == owner.Remaining.Length &&
            owner.Remaining.All(e => owner.Enrolled.Contains(e)) &&
            owner.Borrowed.Select(b => (b.Kind, b.Id)).Distinct().Count() == owner.Borrowed.Length &&
            owner.Borrowed.All(b => new[] { b.Kind, b.Id, b.Revision }.All(AuthenticationIssuanceContract.Text) &&
                b.Id != root.Identity && owner.Enrolled.All(e => e.Slot != b.Id)) &&
            owner.RevokedMetadata.Length <= 1 && owner.RevokedMetadata.All(id =>
                Guid.TryParseExact(id, "D", out _) && owner.Borrowed.All(b => b.Id != id)) &&
            (reservation is null || owner.Enrolled.SequenceEqual(reservation.Enrolled) &&
                owner.Borrowed.SequenceEqual(reservation.Borrowed)));
    }
    public async ValueTask DisposeAsync()
    {
        lock (gate)
        {
            if (closed) return;
            Require(!busy, "cleanup-incomplete");
            closed = true;
        }
        captured?.Dispose(); captured = null;
        // Release local copies even when remote Close is interrupted or rejects.
        CryptographicOperations.ZeroMemory(key);
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        try
        {
            var packet = await source.StepAsync(root, AuthenticationIssuanceStep.Close, null,
                ReadOnlyMemory<byte>.Empty, deadline.Token);
            Owner(packet, AuthenticationIssuanceStep.Close);
            var owner = packet.Owner.Content;
            Require(owner.KeysReleased && owner.Registrations == 0 && owner.Remaining.Length == 0 &&
                (issuer is not { Disposition: AuthenticationIssuanceDisposition.Applied } ||
                    owner.RevokedMetadata.Contains(issuer.MetadataId)) &&
                packet.Ingress.Length + packet.Issuers.Length + packet.Deliveries.Length +
                    packet.Metadata.Length + packet.Captures.Length + packet.Access.Length == 0, "cleanup-incomplete");
        }
        catch (Exception e) when (e is NativeCaseFailureException or OperationCanceledException)
        { throw new NativeCaseFailureException("cleanup-incomplete"); }
        finally { verifier.Dispose(); }
    }
    private void Require(bool condition, string code = "observer-unavailable")
    {
        if (!condition) failed = true;
        AuthenticationIssuanceContract.Require(condition, code);
    }
    public override string ToString() => "[AuthenticationIssuanceTrial]";
}
