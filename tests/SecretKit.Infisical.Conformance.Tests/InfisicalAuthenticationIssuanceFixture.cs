using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Test-only fixture. Its seven journal writers own distinct keys. The coordinator
// below transports their signed output; it cannot sign with any writer's key.
internal sealed class InfisicalAuthenticationIssuanceFixture : IAsyncDisposable
{
    private readonly Dictionary<AuthenticationIssuanceJournal, Writer> writers =
        Enum.GetValues<AuthenticationIssuanceJournal>().ToDictionary(j => j, j => new Writer(j));
    private readonly Coordinator coordinator;
    private AuthenticationIssuanceResource[] enrolled = [];
    private byte[]? key;
    private char[]? captured;
    private string witness = "";
    private string captureEvent = "";
    private string issuerEvent = "";
    internal InfisicalAuthenticationIssuanceServer Server { get; }
    internal string Fault { get; set; } = "";
    internal bool FaultReached { get; private set; }
    internal bool Closed { get; private set; }
    internal int CapturesTaken { get; private set; }
    internal List<byte[]> OwnedBuffers { get; } = [];
    internal List<char[]> OwnedCharacters { get; } = [];
    internal bool BorrowedExists { get; private set; } = true;
    internal int CloseCalls { get; private set; }
    internal TaskCompletionSource DrainEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal TaskCompletionSource DrainRelease { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    internal InfisicalAuthenticationIssuanceSource Source { get; }

    internal InfisicalAuthenticationIssuanceFixture(bool tls = false)
    {
        Server = new(tls) { Exists = false };
        coordinator = new(this);
        Source = new(new(new(new Uri("https://issuance.invalid/"), "private-channel", "capture-coordinator", 15),
            coordinator, length => { var bytes = new byte[length]; OwnedBuffers.Add(bytes); return bytes; }),
            "capture-coordinator", AuthenticationIssuanceKind.ControlledFixture);
    }
    internal AuthenticationIssuanceRoot Root(string variant = "organizationSlug.omitted", bool proof = false,
        string boundary = "lost-response-no-replay") => new(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"),
        Server.Origin.AbsoluteUri, proof ? InfisicalProofAuthenticationEffects.Operation :
            InfisicalUniversalAuthenticationEffects.Operation, proof ? InfisicalProofAuthenticationEffects.Member :
            InfisicalUniversalAuthenticationEffects.Member, variant, boundary, "local", Source.Identity, Source.Kind,
        new("owned-local", "epoch-one", "controlled-only-v1", writers.Values.Select(w => w.Pin).ToArray()),
        InfisicalAuthenticationIssuanceServer.Organization, InfisicalAuthenticationIssuanceServer.Identity,
        proof ? Method(variant) : "universal-auth", "observer", "project", "dev", "/", "ALLOWED", "DENIED",
        new(600, variant == "maximumTTL.zero" ? 0 : 1200, 0, 0));

    internal static string Method(string variant) => variant switch
    {
        "proof.AliCloud" => "alicloud-auth",
        "proof.Azure" => "azure-auth",
        "proof.Gcp" => "gcp-auth",
        "proof.Kubernetes" => "kubernetes-auth",
        "proof.Oidc" => "oidc-auth",
        "proof.Spiffe.JWT-SVID" => "spiffe-auth",
        "proof.Ldap" => "ldap-auth",
        "proof.TlsCertificate.host-mtls" => "tls-cert-auth",
        _ when variant.StartsWith("proof.Aws.", StringComparison.Ordinal) => "aws-auth",
        _ when variant.StartsWith("proof.Oci.", StringComparison.Ordinal) => "oci-auth",
        _ => "jwt-auth"
    };
    internal NativeEnvironment Environment() => NativeEnvironment.Create(JsonSerializer.SerializeToElement(new
    {
        origin = Server.Origin.AbsoluteUri,
        allowLoopbackDevelopmentHttp = true,
        setup = "setup",
        runtime = "runtime",
        denied = "denied",
        administrative = "administrative",
        observer = "observer",
        families = new { }
    }, new JsonSerializerOptions(NativeRunProtocol.JsonOptions) { IgnoreReadOnlyProperties = false }));

    private async ValueTask<AuthenticationIssuancePacket> StepAsync(AuthenticationIssuanceRoot root,
        AuthenticationIssuanceStep step, JsonElement command, CancellationToken token)
    {
        if (step == AuthenticationIssuanceStep.Reserve)
        {
            if (command.GetProperty("capability").GetString() != "owned-capability" || Server.Exists)
                throw new NativeCaseFailureException("observer-unavailable");
            enrolled = Enum.GetValues<AuthenticationIssuanceResourceKind>().Select(k =>
                new AuthenticationIssuanceResource(k, root.Id + "/" + k, root.Id, root.Nonce)).ToArray();
        }
        if (step == AuthenticationIssuanceStep.Open)
        {
            Server.Exists = true;
            Server.MaximumTtl = checked((int)root.Policy.MaximumTtl);
            if (Hit("lost-open")) throw new HttpRequestException("fixture-open-loss");
            if (Hit("cancel-open")) throw new OperationCanceledException(token);
        }
        if (step == AuthenticationIssuanceStep.Arm)
        {
            key = command.GetProperty("correlationKey").GetBytesFromBase64();
            OwnedBuffers.Add(key);
            Server.Issued = () =>
            {
                captured = Server.Credential.ToCharArray();
                OwnedCharacters.Add(captured);
                witness = IndependentWitness(root, key, (char[])captured.Clone());
            };
            while (Server.Reads.TryDequeue(out _)) { }
        }
        if (step is AuthenticationIssuanceStep.Settle or AuthenticationIssuanceStep.Close)
        {
            Server.FenceIssuance();
            if (step == AuthenticationIssuanceStep.Close && Fault == "drain-barrier")
            {
                DrainEntered.TrySetResult();
                await DrainRelease.Task.WaitAsync(token);
            }
            await Server.DrainAsync(token);
        }
        if (step == AuthenticationIssuanceStep.Close)
        {
            CloseCalls++;
            Server.Revoked = true; Server.Exists = false;
            Server.Issued = null;
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (captured is not null) Array.Clear(captured);
            Closed = true;
            if (Hit("borrowed-cleanup")) BorrowedExists = false;
        }

        AuthenticationIssuanceHeader Header(AuthenticationIssuanceJournal journal) =>
            writers[journal].Header(root, step);
        var remaining = step is AuthenticationIssuanceStep.Reserve or AuthenticationIssuanceStep.Close ?
            Array.Empty<AuthenticationIssuanceResource>() : enrolled;
        var owner = new AuthenticationIssuanceOwner(Header(AuthenticationIssuanceJournal.Ownership),
            !HitAt("collision", step, AuthenticationIssuanceStep.Reserve),
            !HitAt("enrollment", step, AuthenticationIssuanceStep.Reserve), true,
            step >= AuthenticationIssuanceStep.Arm, step >= AuthenticationIssuanceStep.Arm,
            true, step == AuthenticationIssuanceStep.Close && !Hit("key-cleanup"),
            HitAt("pending-issuer", step, AuthenticationIssuanceStep.Settle) ? 1 : 0,
            HitAt("pending-capture", step, AuthenticationIssuanceStep.Settle) ? 1 : 0,
            HitAt("pending-delivery", step, AuthenticationIssuanceStep.Settle) ? 1 : 0,
            step == AuthenticationIssuanceStep.Close ? Hit("registration-cleanup") ? 1 : 0 : 1,
            HitAt("wrong-nonce", step, AuthenticationIssuanceStep.Settle) ?
                enrolled.Select(e => e with { Nonce = "other" }).ToArray() : enrolled,
            HitAt("remaining-cleanup", step, AuthenticationIssuanceStep.Close) ? enrolled : remaining,
            BorrowedExists ? [new("identity", "d1111111-1111-4111-8111-111111111111", "revision-one"),
                new("token", "e1111111-1111-4111-8111-111111111111", "revision-one")] : [],
            step == AuthenticationIssuanceStep.Close && Server.Applied && !Hit("missing-revocation") ?
                [InfisicalAuthenticationIssuanceServer.Metadata] : []);
        var packet = new AuthenticationIssuancePacket(Sign(owner, AuthenticationIssuanceJournal.Ownership),
            [], [], [], [], [], [], []);
        if (step == AuthenticationIssuanceStep.Settle)
        {
            var ingress = new AuthenticationIssuanceIngress(Header(AuthenticationIssuanceJournal.Ingress),
                Server.RequestId, Server.SelectedIdentity, Server.Method,
                "/api/v1/auth/" + Server.Method + "/login", Server.Apply);
            var issued = new AuthenticationIssuanceIssuer(Header(AuthenticationIssuanceJournal.Issuer),
                Server.RequestId, Server.RequestId.Length == 0 ? "" : ingress.Header.Event,
                Server.RequestId.Length == 0 ? root.Identity : Server.SelectedIdentity,
                Server.RequestId.Length == 0 ? root.Method : Server.Method,
                Hit("partial") ? AuthenticationIssuanceDisposition.Partial : Server.Applied ?
                    AuthenticationIssuanceDisposition.Applied : AuthenticationIssuanceDisposition.NonApplied,
                Server.Applied ? InfisicalAuthenticationIssuanceServer.Metadata : "", Server.Applied ? witness : "",
                "issuer-state-one");
            issuerEvent = issued.Header.Event;
            if (Hit("wrong-identity")) issued = issued with { Identity = "other-identity" };
            if (Hit("wrong-method")) issued = issued with { Method = "other-auth" };
            if (Hit("wrong-request")) issued = issued with { Request = "another-original" };
            if (Hit("wrong-ingress")) issued = issued with { IngressEvent = "another-ingress" };
            var delivery = new AuthenticationIssuanceDelivery(Header(AuthenticationIssuanceJournal.Delivery),
                Server.RequestId, issuerEvent, true,
                !Server.HoldResponse && !Server.HoldHeaders || Hit("contradictory-delivery"));
            packet = packet with
            {
                Ingress = Server.RequestId.Length == 0 ? [] : [Sign(ingress, AuthenticationIssuanceJournal.Ingress)],
                Issuers = [Sign(issued, AuthenticationIssuanceJournal.Issuer)],
                Deliveries = [Sign(delivery, AuthenticationIssuanceJournal.Delivery)]
            };
            if (Server.Applied)
            {
                var metadata = new AuthenticationIssuanceMetadata(Header(AuthenticationIssuanceJournal.Metadata),
                    Server.RequestId, issuerEvent, Server.SelectedIdentity, Server.Method,
                    InfisicalAuthenticationIssuanceServer.Metadata, witness, "issuer-state-one",
                    new(600, Server.MaximumTtl, 0, 0), true);
                if (Hit("wrong-metadata")) metadata = metadata with { MetadataId = Guid.NewGuid().ToString() };
                if (Hit("wrong-policy")) metadata = metadata with { Policy = new(1, 1200, 0, 0) };
                if (Hit("wrong-state")) metadata = metadata with { StateRevision = "unrelated-state" };
                var capture = new AuthenticationIssuanceCapture(Header(AuthenticationIssuanceJournal.Capture),
                    Server.RequestId, issuerEvent, Server.SelectedIdentity, Server.Method,
                    InfisicalAuthenticationIssuanceServer.Metadata, witness, "issuer-state-one", true);
                captureEvent = capture.Header.Event;
                if (Hit("wrong-capture")) capture = capture with { IssuerEvent = "another-issuance" };
                packet = packet with
                {
                    Metadata = [Sign(metadata, AuthenticationIssuanceJournal.Metadata)],
                    Captures = Hit("omitted-capture") ? [] : [Sign(capture, AuthenticationIssuanceJournal.Capture)]
                };
            }
            if (Hit("contradictory-issuer")) packet = packet with { Issuers = [.. packet.Issuers, packet.Issuers[0]] };
        }
        if (step == AuthenticationIssuanceStep.Access)
        {
            var reads = new List<AuthenticationIssuanceSigned<AuthenticationIssuanceAccess>>();
            while (Server.Reads.TryDequeue(out var read))
            {
                bool observer = read.Credential == "observer", authentic = observer || read.Credential == Server.Credential;
                var access = new AuthenticationIssuanceAccess(Header(AuthenticationIssuanceJournal.Access), read.Request,
                    issuerEvent, observer ? "observer" : authentic ? Server.SelectedIdentity : "",
                    observer ? "" : IndependentWitness(root, key!, read.Credential.ToCharArray()),
                    read.Key, authentic, read.Allowed,
                    read.Allowed ? IndependentWitness(root, key!, "owned-material".ToCharArray(), "canary") : "");
                if (Hit("wrong-access")) access = access with { Authenticated = !authentic };
                reads.Add(Sign(access, AuthenticationIssuanceJournal.Access));
            }
            packet = packet with { Access = reads.ToArray() };
        }
        var seals = new List<AuthenticationIssuanceSigned<AuthenticationIssuanceSeal>>();
        Seal(new[] { packet.Owner }, AuthenticationIssuanceJournal.Ownership);
        Seal(packet.Ingress, AuthenticationIssuanceJournal.Ingress);
        Seal(packet.Issuers, AuthenticationIssuanceJournal.Issuer);
        Seal(packet.Deliveries, AuthenticationIssuanceJournal.Delivery);
        Seal(packet.Metadata, AuthenticationIssuanceJournal.Metadata);
        Seal(packet.Captures, AuthenticationIssuanceJournal.Capture);
        Seal(packet.Access, AuthenticationIssuanceJournal.Access);
        packet = packet with { Seals = seals.ToArray() };
        if (HitAt("missing-seal", step, AuthenticationIssuanceStep.Settle))
            packet = packet with { Seals = packet.Seals[..^1] };
        if (HitAt("tampered-content", step, AuthenticationIssuanceStep.Settle))
            packet = packet with
            {
                Issuers = [packet.Issuers[0] with
                { Content = packet.Issuers[0].Content with { StateRevision = "unsigned-change" } }]
            };
        return packet;

        void Seal<T>(AuthenticationIssuanceSigned<T>[] entries, AuthenticationIssuanceJournal journal)
            where T : IAuthenticationIssuanceEvidence
        {
            var seal = new AuthenticationIssuanceSeal(Header(journal),
                AuthenticationIssuanceContract.Hash(entries.Select(e => e.Content).ToArray()), entries.Length, true,
                HitAt("pending-seal", step, AuthenticationIssuanceStep.Settle) && journal == AuthenticationIssuanceJournal.Capture ? 1 : 0);
            seals.Add(Sign(seal, journal));
        }
    }
    private AuthenticationIssuanceSigned<T> Sign<T>(T content, AuthenticationIssuanceJournal journal)
        where T : IAuthenticationIssuanceEvidence => writers[journal].Sign(content);
    private bool Hit(string value)
    {
        if (Fault != value) return false;
        FaultReached = true; return true;
    }
    private bool HitAt(string value, AuthenticationIssuanceStep actual, AuthenticationIssuanceStep expected) =>
        actual == expected && Hit(value);
    private static string IndependentWitness(AuthenticationIssuanceRoot root, byte[] key, char[] chars,
        string domain = "credential")
    {
        byte[] text = Encoding.UTF8.GetBytes(chars);
        byte[] prefix = Encoding.UTF8.GetBytes(string.Join('\0', "secretkit-interrupted-issuance-v1",
            domain, root.Id, root.Nonce, root.Operation, root.Identity, root.Method, ""));
        try
        {
            using var algorithm = new HMACSHA256(key);
            algorithm.TransformBlock(prefix, 0, prefix.Length, null, 0);
            algorithm.TransformFinalBlock(text, 0, text.Length);
            return Convert.ToBase64String(algorithm.Hash!);
        }
        finally { Array.Clear(chars); CryptographicOperations.ZeroMemory(text); CryptographicOperations.ZeroMemory(prefix); }
    }
    private sealed class Writer(AuthenticationIssuanceJournal journal) : IDisposable
    {
        private readonly ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private long sequence;
        internal AuthenticationIssuancePin Pin => new(journal, journal + "-writer", journal + "-channel",
            "issuance-v1", Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
        internal AuthenticationIssuanceHeader Header(AuthenticationIssuanceRoot root, AuthenticationIssuanceStep step) =>
            new(AuthenticationIssuanceContract.Hash(root), journal, Pin.Writer, Pin.Channel, Pin.Schema,
                Guid.NewGuid().ToString("N"), ++sequence, step);
        internal AuthenticationIssuanceSigned<T> Sign<T>(T content) where T : IAuthenticationIssuanceEvidence
        {
            byte[] bytes = AuthenticationIssuanceContract.Bytes(content);
            try
            {
                return new(content, Convert.ToBase64String(key.SignData(bytes, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        public void Dispose() => key.Dispose();
    }
    private sealed class Coordinator(InfisicalAuthenticationIssuanceFixture fixture) : HttpMessageHandler
    {
        private readonly ECDsa unrelatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
        {
            if (request.Headers.Authorization?.Parameter != "private-channel") return new(HttpStatusCode.Forbidden);
            byte[] bytes = await request.Content!.ReadAsByteArrayAsync(token);
            fixture.OwnedBuffers.Add(bytes);
            try
            {
                using var document = JsonDocument.Parse(bytes);
                var command = document.RootElement;
                var root = command.GetProperty("root").Deserialize<AuthenticationIssuanceRoot>(AuthenticationIssuanceContract.Options)!;
                object facts;
                byte[]? capturedBytes = null;
                if (request.RequestUri!.AbsolutePath == "/authentication-issuance/step")
                {
                    var step = (AuthenticationIssuanceStep)command.GetProperty("step").GetInt32();
                    var packet = await fixture.StepAsync(root, step, command, token);
                    if (fixture.HitAt("bad-signature", step, AuthenticationIssuanceStep.Settle))
                    {
                        var first = packet.Issuers[0];
                        byte[] content = AuthenticationIssuanceContract.Bytes(first.Content);
                        try
                        {
                            packet.Issuers[0] = first with
                            {
                                Signature = Convert.ToBase64String(unrelatedKey.SignData(
                            content, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                            };
                        }
                        finally { CryptographicOperations.ZeroMemory(content); }
                    }
                    facts = packet;
                }
                else if (request.RequestUri.AbsolutePath == "/authentication-issuance/capture")
                {
                    fixture.CapturesTaken++;
                    if (fixture.Hit("lost-capture")) throw new HttpRequestException("fixture-capture-loss");
                    capturedBytes = fixture.Hit("wrong-credential") ? Encoding.UTF8.GetBytes("different-credential") :
                        Encoding.UTF8.GetBytes(fixture.captured!);
                    fixture.OwnedBuffers.Add(capturedBytes);
                    facts = new { captureEvent = fixture.captureEvent, material = capturedBytes };
                }
                else return new(HttpStatusCode.NotFound);
                try
                {
                    byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        schemaVersion = 1,
                        nonce = command.GetProperty("nonce").GetString(),
                        observerIdentity = "capture-coordinator",
                        observedAt = DateTimeOffset.UtcNow,
                        facts
                    }, AuthenticationIssuanceContract.Options);
                    fixture.OwnedBuffers.Add(payload);
                    return new(HttpStatusCode.OK) { Content = new ClearingContent(payload) };
                }
                finally { if (capturedBytes is not null) CryptographicOperations.ZeroMemory(capturedBytes); }
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        protected override void Dispose(bool disposing)
        {
            if (disposing) unrelatedKey.Dispose();
            base.Dispose(disposing);
        }
    }
    private sealed class ClearingContent : ByteArrayContent
    {
        private readonly byte[] bytes;
        internal ClearingContent(byte[] bytes) : base(bytes) => this.bytes = bytes;
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            if (disposing) CryptographicOperations.ZeroMemory(bytes);
        }
    }
    public async ValueTask DisposeAsync()
    {
        if (key is not null) CryptographicOperations.ZeroMemory(key);
        if (captured is not null) Array.Clear(captured);
        coordinator.Dispose();
        foreach (var writer in writers.Values) writer.Dispose();
        await Server.DisposeAsync();
    }
}
