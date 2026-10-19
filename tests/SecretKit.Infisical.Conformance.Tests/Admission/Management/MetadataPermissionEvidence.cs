using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private admission protocol, not an SDK/provider API. Native qualification: 0.
//
// Trust decision: InfisicalLifecycleObservers authenticates the COORDINATOR
// channel only. Writer/schema labels do not authenticate a journal. Here the
// HOST supplies six distinct P-256 SPKI pins, each bound to a writer, channel,
// journal and schema before Reserve. No response may announce/replace a key.
// Every typed payload (including every collection and the complete root hash)
// is signed. A coordinator holding its own credentials/key cannot relabel a
// journal, splice content, substitute a key, or produce a valid terminal fence.
// Compromise of a pinned writer remains a trust failure; signatures do not
// qualify that writer's implementation, completeness, clock or native semantics.
// Operator qualification and vendor primary-shape admission remain external.
// WorkloadTransition's externally qualified coordinator contract is UNCHANGED.
//
// Causality uses request IDs, predecessor revisions, policy/issuance parents,
// exact principal/scope/action/material joins and per-writer sequences, not
// timestamp ordering or latest GET. Ownership pre-enrolls before creation.
// Retain original-root recovery before Reserve; failed/lost Open can only Close.
// Terminal fences seal original 0..1 dispatch and drain work before evidence.
// A receipt is the immutable actual SDK receipt, never rewritten by settlement.
internal enum MetadataPermissionJournal { Ownership, Ingress, Storage, Policy, Issuance, Backend }
internal enum MetadataPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum MetadataPermissionOutcome { Applied, NonApplied, Partial }
internal enum MetadataPermissionSubject { DynamicSecrets, Certificates }
internal enum MetadataPermissionOperator { Equal, Included, NotEqual, EmptyMatch, EmptyKey, EmptyValue, EmptyIncluded }
internal enum MetadataPermissionAction { Select, WrongCredential, ForbiddenWrite, Recheck }
internal enum MetadataPermissionSourceKind { NativeProvider, ControlledFixture }

internal sealed record MetadataPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[MetadataPermissionAuthorities]";
}
internal sealed record MetadataPermissionPin(MetadataPermissionJournal Journal, string Writer,
    string Channel, string Schema, string SubjectPublicKeyInfo)
{
    public override string ToString() => "[MetadataPermissionPin]";
}
internal sealed record MetadataPermissionProfile(string Deployment, string Epoch, string ProviderRevision,
    MetadataPermissionPin[] Pins)
{
    public override string ToString() => "[MetadataPermissionProfile]";
}
internal sealed record MetadataPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source,
    MetadataPermissionSourceKind Kind, MetadataPermissionSubject Subject, MetadataPermissionOperator Operator,
    MetadataPermissionAuthorities Authorities, MetadataPermissionProfile Profile)
{
    public override string ToString() => "[MetadataPermissionRoot]";
}
internal sealed record MetadataPermissionHeader(string RootHash, MetadataPermissionJournal Journal,
    string Writer, string Channel, string Schema, string KeyHash, string Event, long Sequence, string Window);
internal interface IMetadataPermissionEvidence { MetadataPermissionHeader Header { get; } }
internal sealed record MetadataPermissionSigned<T>(T Content, string Signature) where T : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record MetadataPermissionBorrowed(string Kind, string Id, string Revision);
internal sealed record MetadataPermissionEntry(string Key, string Value);
internal sealed record MetadataPermissionRow(string Name, string Project, string ProjectSlug, string Environment,
    string Path, Guid Folder, Guid Definition, string MetadataRevision, MetadataPermissionEntry[] Metadata);
internal sealed record MetadataPermissionIssued(string Project, string ProjectSlug, string ControlProject,
    string Membership, string PolicyId, string PolicySlug, string TemplateId, string CopySlug,
    string BaselineRevision, string ProtectedRowHash, MetadataPermissionRow[] Rows, MetadataPermissionRow[] CopyRows)
{
    public override string ToString() => "[MetadataPermissionIssued]";
}
internal sealed record MetadataPermissionOwner(MetadataPermissionHeader Header, MetadataPermissionStep Step,
    bool CollisionChecked, bool PreEnrolled, bool Exclusive, bool Terminal, int Pending, int Registrations,
    MetadataPermissionIssued? Issued, MetadataPermissionResource[] Enrolled,
    MetadataPermissionResource[] Remaining, MetadataPermissionBorrowed[] Borrowed) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionIngress(MetadataPermissionHeader Header, string Request,
    string Actor, string Method, string Path, string IntentHash, bool Authorized) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionCommit(MetadataPermissionHeader Header, string Request, string Resource,
    string PreviousRevision, string Revision, string PolicyHash, string Principal, string Project,
    string? SourceRevision) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionDecision(MetadataPermissionHeader Header, string Request, string Actor,
    string Project, Guid Definition, string ConfigurationRevision, string MetadataRevision, string Action,
    string TokenHash, bool Allowed) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionLease(MetadataPermissionHeader Header, string Request, string Decision,
    string Actor, string Project, Guid Definition, string ConfigurationRevision, string MetadataRevision,
    Guid Lease, string MaterialHash) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionBackend(MetadataPermissionHeader Header, Guid Lease, string MaterialHash,
    string Principal, string Project, MetadataPermissionAction Action, bool Authenticated, bool Allowed,
    string ProtectedRowHash) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionSeal(MetadataPermissionHeader Header, string ContentHash,
    int Count, bool Terminal, int Pending) : IMetadataPermissionEvidence;
internal sealed record MetadataPermissionPacket(MetadataPermissionSigned<MetadataPermissionOwner> Owner,
    MetadataPermissionSigned<MetadataPermissionIngress>[] Requests,
    MetadataPermissionSigned<MetadataPermissionCommit>[] Commits,
    MetadataPermissionSigned<MetadataPermissionDecision>[] Decisions,
    MetadataPermissionSigned<MetadataPermissionLease>[] Leases,
    MetadataPermissionSigned<MetadataPermissionSeal>[] Seals);
internal sealed record MetadataPermissionReceipt(DispatchEvidence Evidence, SecretStatus? Status,
    bool Cancelled, string IntentHash);
internal sealed record MetadataPermissionAttempt(string Actor, string TokenHash, MetadataPermissionRow Row,
    bool Allowed, Guid? Lease, string? MaterialHash);

internal interface IMetadataPermissionSource
{
    string Identity { get; }
    MetadataPermissionSourceKind Kind { get; }
    ValueTask<MetadataPermissionPacket> StepAsync(MetadataPermissionRoot root, MetadataPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
    ValueTask<MetadataPermissionSigned<MetadataPermissionBackend>> MeasureAsync(MetadataPermissionRoot root,
        Guid lease, SecretMaterial username, SecretMaterial password, MetadataPermissionAction action,
        CancellationToken token);
}

internal sealed record MetadataPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    MetadataPermissionProfile Profile, MetadataPermissionSubject Subject, MetadataPermissionOperator Operator,
    int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        MetadataPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("metadataPermission", out _);
    internal static MetadataPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("metadataPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<MetadataPermissionInput>(MetadataPermissionContract.Options);
            MetadataPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                MetadataPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Subject) &&
                Enum.IsDefined(result.Operator), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            MetadataPermissionContract.ValidateProfile(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[MetadataPermissionInput]";
}

internal static class MetadataPermissionContract
{
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    {
        IgnoreReadOnlyProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };
    internal static bool Owns(NativeCaseDefinition d) =>
        d.Key.Variant is "condition.metadata.elemMatch" or "permissions.metadata.elemMatch" &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static bool Template(string operation) => operation.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string operation) => operation.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string? Gate(NativeCaseDefinition d, MetadataPermissionInput? input) =>
        !Owns(d) ? "contract-mismatch" : input is null ? "metadata-permission-attestations-unavailable" :
        input.Subject == MetadataPermissionSubject.Certificates ? "certificate-sdk-protected-action-unavailable" :
        null;
    internal static bool Text(string? value) => value is { Length: > 0 and <= 16384 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Require(bool value, string code = "observer-unavailable")
    { if (!value) throw new NativeCaseFailureException(code); }
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] bytes = Bytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string MaterialHash(string username, string password) => Hash(new[] { username, password });
    internal static void ValidateProfile(MetadataPermissionProfile profile)
    {
        Require(profile is not null && new[] { profile.Deployment, profile.Epoch, profile.ProviderRevision }.All(Text) &&
            profile.Pins is { Length: 6 } && profile.Pins.Select(p => p.Journal).Distinct().Count() == 6 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && Text(p.Writer) && Text(p.Channel) && Text(p.Schema)) &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 6 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 6, "missing-input");
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
    internal static bool Expected(MetadataPermissionOperator op, MetadataPermissionRow row) =>
        row.Name != "cross-scope" && (op switch
        {
            MetadataPermissionOperator.Equal or MetadataPermissionOperator.Included => row.Name == "same-entry",
            MetadataPermissionOperator.NotEqual => row.Name is "same-entry" or "value-only" or "split-entry",
            MetadataPermissionOperator.EmptyMatch or MetadataPermissionOperator.EmptyKey or MetadataPermissionOperator.EmptyValue =>
                row.Metadata.Length != 0,
            MetadataPermissionOperator.EmptyIncluded => false,
            _ => false
        });
    internal static string PolicyHash(MetadataPermissionOperator op) =>
        Hash(Policy(op));
    internal static MetadataPermissionPolicy Policy(MetadataPermissionOperator op) => new("dynamic-secrets", "lease", "witness", "/",
        op switch
        {
            MetadataPermissionOperator.Equal => new("team", null, null),
            MetadataPermissionOperator.Included => new(null, null, ["team"]),
            MetadataPermissionOperator.NotEqual => new(null, "blocked", null),
            MetadataPermissionOperator.EmptyKey => new(null, null, null),
            MetadataPermissionOperator.EmptyIncluded => new(null, null, []),
            _ => null
        },
        op switch
        {
            MetadataPermissionOperator.Equal => new("blue", null, null),
            MetadataPermissionOperator.Included => new(null, null, ["blue"]),
            MetadataPermissionOperator.NotEqual => new(null, "red", null),
            MetadataPermissionOperator.EmptyValue => new(null, null, null),
            _ => null
        });
    internal static (string Hash, MetadataPermissionHeader[] Headers) Contents(MetadataPermissionPacket packet,
        MetadataPermissionJournal journal) => journal switch
        {
            MetadataPermissionJournal.Ingress => (Hash(packet.Requests.Select(s => s.Content).ToArray()),
                packet.Requests.Select(s => s.Content.Header).ToArray()),
            MetadataPermissionJournal.Storage => (Hash(packet.Commits.Select(s => s.Content).ToArray()),
                packet.Commits.Select(s => s.Content.Header).ToArray()),
            MetadataPermissionJournal.Policy => (Hash(packet.Decisions.Select(s => s.Content).ToArray()),
                packet.Decisions.Select(s => s.Content.Header).ToArray()),
            MetadataPermissionJournal.Issuance => (Hash(packet.Leases.Select(s => s.Content).ToArray()),
                packet.Leases.Select(s => s.Content.Header).ToArray()),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
}
internal sealed record MetadataPermissionOperand(string? Equal, string? NotEqual, string[]? Included);
internal sealed record MetadataPermissionPolicy(string? Subject, string? Action, string? Environment, string? Path,
    MetadataPermissionOperand? Key, MetadataPermissionOperand? Value);

internal sealed class MetadataPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<MetadataPermissionJournal, (MetadataPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<MetadataPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal MetadataPermissionVerifier(MetadataPermissionRoot root)
    {
        MetadataPermissionContract.ValidateProfile(root.Profile);
        rootHash = MetadataPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.SubjectPublicKeyInfo), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(MetadataPermissionSigned<T> signed, MetadataPermissionJournal journal, string window)
        where T : IMetadataPermissionEvidence
    {
        var (pin, key) = keys[journal];
        var header = signed.Content.Header;
        // Authenticate complete content BEFORE accepting any source labels/joins.
        byte[] content = MetadataPermissionContract.Bytes(signed.Content);
        bool valid;
        try
        {
            valid = key.VerifyData(content, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(content); }
        MetadataPermissionContract.Require(valid, "observer-unavailable");
        MetadataPermissionContract.Require(header.RootHash == rootHash && header.Journal == journal &&
            header.Writer == pin.Writer && header.Channel == pin.Channel && header.Schema == pin.Schema &&
            header.KeyHash == Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())) &&
            header.Window == window && MetadataPermissionContract.Text(header.Event) &&
            events.Add(header.Event) && header.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = header.Sequence;
        return signed.Content;
    }
    public void Dispose()
    {
        foreach (var (_, key) in keys.Values) key.Dispose();
    }
}
