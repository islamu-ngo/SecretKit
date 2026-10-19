using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private witness protocol, not a provider transaction API. Native qualification: 0.
// Public login contracts (Tavily, 2026-10-14):
// https://infisical.com/docs/api-reference/endpoints/universal-auth/login
// https://infisical.com/docs/api-reference/endpoints/kubernetes-auth/login
// establish credential/lifetime fields, not a metadata ID or a Partial transition.
// Therefore Partial is deliberately unqualified. Missing capture is availability,
// never Partial application; wrong credential/identity/method/metadata is mismatch.
// Pins authenticate complete statements, not the truth of a compromised writer.
internal enum AuthenticationIssuanceKind { NativeProvider, ControlledFixture }
internal enum AuthenticationIssuanceJournal { Ownership, Ingress, Issuer, Delivery, Metadata, Capture, Access }
internal enum AuthenticationIssuanceStep { Reserve, Open, Arm, Settle, Access, Close }
internal enum AuthenticationIssuanceDisposition { Applied, NonApplied, Partial }
internal enum AuthenticationIssuanceResourceKind { Identity, BootstrapCredential, Token, Metadata, Capture, Key, Registration }
internal sealed record AuthenticationIssuancePin(AuthenticationIssuanceJournal Journal, string Writer,
    string Channel, string Schema, string SubjectPublicKeyInfo);
internal sealed record AuthenticationIssuanceProfile(string Deployment, string Epoch, string Revision,
    AuthenticationIssuancePin[] Pins);
internal sealed record AuthenticationIssuanceRoot(string Id, string Nonce, string Origin, string Operation,
    string Member, string Variant, string Boundary, string Scope, string Source, AuthenticationIssuanceKind Kind,
    AuthenticationIssuanceProfile Profile, string Organization, string Identity, string Method, string ObserverIdentity,
    string Project, string Environment, string Folder, string AllowedKey, string DeniedKey,
    AuthenticationExpiryPolicy Policy)
{
    public override string ToString() => "[AuthenticationIssuanceRoot]";
}
internal sealed record AuthenticationIssuanceHeader(string RootHash, AuthenticationIssuanceJournal Journal,
    string Writer, string Channel, string Schema, string Event, long Sequence, AuthenticationIssuanceStep Step);
internal interface IAuthenticationIssuanceEvidence { AuthenticationIssuanceHeader Header { get; } }
internal sealed record AuthenticationIssuanceSigned<T>(T Content, string Signature) where T : IAuthenticationIssuanceEvidence;
// Enrollment reserves an exclusive root-owned slot BEFORE creation, not a guessed
// provider ID. Exact provider IDs are subsequently joined by the issuer/metadata
// journals and revoked during Close; borrowed IDs never enter these slots.
internal sealed record AuthenticationIssuanceResource(AuthenticationIssuanceResourceKind Kind,
    string Slot, string Root, string Nonce);
internal sealed record AuthenticationIssuanceBorrowed(string Kind, string Id, string Revision);
internal sealed record AuthenticationIssuanceOwner(AuthenticationIssuanceHeader Header,
    bool CollisionChecked, bool PreEnrolled, bool Exclusive, bool IssuerArmed, bool CaptureArmed,
    bool Terminal, bool KeysReleased, int PendingIssuers, int PendingCaptures, int PendingDeliveries,
    int Registrations, AuthenticationIssuanceResource[] Enrolled, AuthenticationIssuanceResource[] Remaining,
    AuthenticationIssuanceBorrowed[] Borrowed, string[] RevokedMetadata) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceIngress(AuthenticationIssuanceHeader Header, string Request,
    string Identity, string Method, string Path, bool Authorized) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceIssuer(AuthenticationIssuanceHeader Header, string Request,
    string IngressEvent, string Identity, string Method, AuthenticationIssuanceDisposition Disposition,
    string MetadataId, string CredentialWitness, string StateRevision) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceDelivery(AuthenticationIssuanceHeader Header, string Request,
    string IssuerEvent, bool Settled, bool ResponseDelivered) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceMetadata(AuthenticationIssuanceHeader Header, string Request,
    string IssuerEvent, string Identity, string Method, string MetadataId, string CredentialWitness,
    string StateRevision, AuthenticationExpiryPolicy Policy, bool Active) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceCapture(AuthenticationIssuanceHeader Header, string Request,
    string IssuerEvent, string Identity, string Method, string MetadataId, string CredentialWitness,
    string StateRevision, bool PrivateDeliveryReady) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceAccess(AuthenticationIssuanceHeader Header, string Request,
    string IssuerEvent, string Identity, string CredentialWitness, string Key, bool Authenticated,
    bool Allowed, string ValueWitness) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuanceSeal(AuthenticationIssuanceHeader Header,
    string ContentHash, int Count, bool Terminal, int Pending) : IAuthenticationIssuanceEvidence;
internal sealed record AuthenticationIssuancePacket(AuthenticationIssuanceSigned<AuthenticationIssuanceOwner> Owner,
    AuthenticationIssuanceSigned<AuthenticationIssuanceIngress>[] Ingress,
    AuthenticationIssuanceSigned<AuthenticationIssuanceIssuer>[] Issuers,
    AuthenticationIssuanceSigned<AuthenticationIssuanceDelivery>[] Deliveries,
    AuthenticationIssuanceSigned<AuthenticationIssuanceMetadata>[] Metadata,
    AuthenticationIssuanceSigned<AuthenticationIssuanceCapture>[] Captures,
    AuthenticationIssuanceSigned<AuthenticationIssuanceAccess>[] Access,
    AuthenticationIssuanceSigned<AuthenticationIssuanceSeal>[] Seals);
internal sealed class AuthenticationIssuanceCaptured(string captureEvent, SecretMaterial material) : IDisposable
{
    internal string CaptureEvent { get; } = captureEvent;
    internal SecretMaterial Material { get; } = material;
    public void Dispose() => Material.Dispose();
    public override string ToString() => "[AuthenticationIssuanceCaptured]";
}
internal interface IAuthenticationIssuanceSource
{
    string Identity { get; }
    AuthenticationIssuanceKind Kind { get; }
    ValueTask<AuthenticationIssuancePacket> StepAsync(AuthenticationIssuanceRoot root,
        AuthenticationIssuanceStep step, SecretMaterial? capability, ReadOnlyMemory<byte> correlationKey,
        CancellationToken token);
    ValueTask<AuthenticationIssuanceCaptured> TakeCaptureAsync(AuthenticationIssuanceRoot root,
        string captureEvent, CancellationToken token);
}

internal static class AuthenticationIssuanceContract
{
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    {
        IgnoreReadOnlyProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };
    internal static readonly string[] Boundaries = ["selected-contract", "denied-authority",
        "cancellation-boundary", "independent-effect", "lost-response-no-replay"];
    internal static bool Owns(NativeCaseDefinition d) => d.Key.Provider == "Infisical" &&
        Boundaries.Contains(d.Key.Case, StringComparer.Ordinal) &&
        (d.Key.Operation == InfisicalUniversalAuthenticationEffects.Operation &&
            d.Member == InfisicalUniversalAuthenticationEffects.Member &&
            InfisicalUniversalAuthenticationEffects.Variants.Contains(d.Key.Variant, StringComparer.Ordinal) ||
        d.Key.Operation == InfisicalProofAuthenticationEffects.Operation &&
            d.Member == InfisicalProofAuthenticationEffects.Member &&
            InfisicalProofAuthenticationEffects.Variants.Contains(d.Key.Variant, StringComparer.Ordinal));
    internal static bool Interrupted(string boundary) =>
        boundary is "cancellation-boundary" or "lost-response-no-replay";
    internal static bool MatchesMethod(AuthenticationIssuanceRoot root)
    {
        if (root.Operation == InfisicalUniversalAuthenticationEffects.Operation)
            return root.Method == "universal-auth";
        return root.Variant switch
        {
            "proof.AliCloud" => root.Method == "alicloud-auth",
            "proof.Aws.method-omitted" or "proof.Aws.method-value" => root.Method == "aws-auth",
            "proof.Azure" => root.Method == "azure-auth",
            "proof.Gcp" => root.Method == "gcp-auth",
            "proof.Jwt" => root.Method == "jwt-auth",
            "proof.Kubernetes" => root.Method == "kubernetes-auth",
            "proof.Oidc" => root.Method == "oidc-auth",
            "proof.Spiffe.JWT-SVID" => root.Method == "spiffe-auth",
            "proof.Ldap" => root.Method == "ldap-auth",
            "proof.Oci.date" or "proof.Oci.x-date" or "proof.Oci.date-and-x-date" or "proof.Oci.dates-omitted" =>
                root.Method == "oci-auth",
            "proof.TlsCertificate.host-mtls" => root.Method == "tls-cert-auth",
            _ => root.Method is "alicloud-auth" or "aws-auth" or "azure-auth" or "gcp-auth" or "jwt-auth" or
                "kubernetes-auth" or "oidc-auth" or "spiffe-auth" or "ldap-auth" or "oci-auth" or "tls-cert-auth"
        };
    }
    internal static bool Text(string? value) => value is { Length: > 0 and <= 16384 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] content = Bytes(value);
        try { return Convert.ToHexString(SHA256.HashData(content)); }
        finally { CryptographicOperations.ZeroMemory(content); }
    }
    internal static string Witness(AuthenticationIssuanceRoot root, ReadOnlySpan<byte> key,
        SecretMaterial material, string domain = "credential")
    {
        char[] characters = material.ExportCharacters();
        byte[] bytes = new byte[Encoding.UTF8.GetByteCount(characters)];
        byte[] prefix = Encoding.UTF8.GetBytes("secretkit-interrupted-issuance-v1\0" + domain + "\0" +
            root.Id + "\0" + root.Nonce + "\0" + root.Operation + "\0" + root.Identity + "\0" + root.Method + "\0");
        try
        {
            Encoding.UTF8.GetBytes(characters, bytes);
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key);
            hmac.AppendData(prefix); hmac.AppendData(bytes);
            byte[] digest = hmac.GetHashAndReset();
            try { return Convert.ToBase64String(digest); }
            finally { CryptographicOperations.ZeroMemory(digest); }
        }
        finally
        {
            Array.Clear(characters);
            CryptographicOperations.ZeroMemory(bytes);
            CryptographicOperations.ZeroMemory(prefix);
        }
    }
    internal static bool EqualWitness(string left, string right)
    {
        Span<byte> a = stackalloc byte[32], b = stackalloc byte[32];
        return Convert.TryFromBase64String(left, a, out int ac) && ac == 32 &&
            Convert.TryFromBase64String(right, b, out int bc) && bc == 32 &&
            CryptographicOperations.FixedTimeEquals(a, b);
    }
    internal static void ValidateProfile(AuthenticationIssuanceProfile profile)
    {
        Require(profile is not null && new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(Text) &&
            profile.Pins is { Length: 7 } && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && Text(p.Writer) && Text(p.Channel) && Text(p.Schema)) &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7, "missing-input");
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pin in profile!.Pins)
        {
            using var key = ECDsa.Create();
            byte[] encoded = Convert.FromBase64String(pin.SubjectPublicKeyInfo);
            key.ImportSubjectPublicKeyInfo(encoded, out int used);
            Require(used == encoded.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                keys.Add(Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()))), "missing-input");
        }
    }
}

internal sealed class AuthenticationIssuanceVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<AuthenticationIssuanceJournal, (AuthenticationIssuancePin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<AuthenticationIssuanceJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal AuthenticationIssuanceVerifier(AuthenticationIssuanceRoot root)
    {
        AuthenticationIssuanceContract.ValidateProfile(root.Profile);
        rootHash = AuthenticationIssuanceContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.SubjectPublicKeyInfo), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal void Packet(AuthenticationIssuancePacket packet, AuthenticationIssuanceStep step)
    {
        AuthenticationIssuanceContract.Require(packet.Seals.Length == 7 &&
            packet.Seals.Select(s => s.Content.Header.Journal).Distinct().Count() == 7);
        Journal(new[] { packet.Owner }, AuthenticationIssuanceJournal.Ownership);
        Journal(packet.Ingress, AuthenticationIssuanceJournal.Ingress);
        Journal(packet.Issuers, AuthenticationIssuanceJournal.Issuer);
        Journal(packet.Deliveries, AuthenticationIssuanceJournal.Delivery);
        Journal(packet.Metadata, AuthenticationIssuanceJournal.Metadata);
        Journal(packet.Captures, AuthenticationIssuanceJournal.Capture);
        Journal(packet.Access, AuthenticationIssuanceJournal.Access);
        void Journal<T>(AuthenticationIssuanceSigned<T>[] entries, AuthenticationIssuanceJournal journal)
            where T : IAuthenticationIssuanceEvidence
        {
            AuthenticationIssuanceContract.Require(entries.Length <= 16);
            foreach (var entry in entries) Verify(entry, journal, step);
            var seal = packet.Seals.Single(s => s.Content.Header.Journal == journal);
            Verify(seal, journal, step);
            AuthenticationIssuanceContract.Require(seal.Content.Terminal && seal.Content.Pending == 0 &&
                seal.Content.Count == entries.Length && seal.Content.ContentHash ==
                    AuthenticationIssuanceContract.Hash(entries.Select(e => e.Content).ToArray()));
        }
    }
    private void Verify<T>(AuthenticationIssuanceSigned<T> value, AuthenticationIssuanceJournal journal,
        AuthenticationIssuanceStep step) where T : IAuthenticationIssuanceEvidence
    {
        var (pin, key) = keys[journal];
        byte[] content = AuthenticationIssuanceContract.Bytes(value.Content);
        bool valid;
        try
        {
            valid = key.VerifyData(content, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is CryptographicException or FormatException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(content); }
        var h = value.Content.Header;
        AuthenticationIssuanceContract.Require(valid && h.RootHash == rootHash && h.Journal == journal &&
            h.Writer == pin.Writer && h.Channel == pin.Channel && h.Schema == pin.Schema && h.Step == step &&
            AuthenticationIssuanceContract.Text(h.Event) && events.Add(h.Event) &&
            h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
    }
    public void Dispose()
    {
        foreach (var (_, key) in keys.Values) key.Dispose();
        keys.Clear();
    }
}
