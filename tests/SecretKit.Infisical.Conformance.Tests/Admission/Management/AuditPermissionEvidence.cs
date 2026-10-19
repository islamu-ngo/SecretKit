using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline protocol, NOT native qualification. Interface facts checked 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/api-reference/endpoints/audit-logs/export-audit-log
// https://infisical.com/docs/documentation/platform/audit-logs
// AuditLogs has READ only. Settings PUT does not establish AuditLogs.edit.
// Eight independent pinned writers: Publisher cannot be the coordinator, ingress,
// issuer or storage writer. A signature authenticates testimony, not native truth.
// Seed SDK POST -> authenticated ingress -> committed empty role -> publication
// envelope -> independently issued canonical audit ID -> stored row. Exact parent
// IDs and full hashes, not timestamps or SDK metadata, establish these edges.
// Publication is an exclusive, fenced census, not a polling timeout or empty page.
// Native queue watermarks, producer cardinality, partition exclusion, history
// completeness and retention authority need separate deployment qualification.
// Close fences all producers, dispatch, issuance and publication, drains admitted
// work, removes enrolled mutable resources, and seals bounded historical residue.
// No audit row DELETE exists here. Borrowed history and immutable original receipts
// survive unchanged. Owned arrays clear; managed strings/socket buffers do not.
internal enum AuditPermissionAction { Read, Edit }
internal enum AuditPermissionScope { Project, Organization }
internal enum AuditPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access, Publisher }
internal enum AuditPermissionStep { Reserve, Open, SeedBefore, PublishedBefore, Before, ObserveBefore, Arm, Settle, SeedAfter, PublishedAfter, After, ObserveAfter, Close }
internal enum AuditPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record AuditPermissionPin(AuditPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record AuditPermissionProfile(string Deployment, string Epoch, string Revision, System.Collections.Immutable.ImmutableArray<AuditPermissionPin> Pins, string BorrowedHash);
internal sealed record AuditPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    AuditPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, AuditPermissionAction Action,
    MemberPermissionAuthorities Authorities, AuditPermissionProfile Profile, DateTimeOffset From, DateTimeOffset Until, DateTimeOffset RetainUntil)
{
    public override string ToString() => "[AuditPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record AuditPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, System.Collections.Immutable.ImmutableArray<string> Dependencies, string Work);
internal sealed record AuditPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record AuditPermissionResource(string Intent, string CanonicalId);
internal sealed record AuditPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record AuditPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[AuditPermissionActor]";
}
internal sealed record AuditPermissionRow(string Key, string Window, string Control, AuditPermissionAction Action,
    string Organization, string Project, int Actor);
internal sealed record AuditPermissionIssued(AuditPermissionActor[] Actors, AuditPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[AuditPermissionIssued]";
}
internal sealed record AuditPermissionOwner(AuditPermissionIntent[] Intents, AuditPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    bool ProducerFence, bool PublicationFence, int Pending, int Registrations, AuditPermissionActor[] Actors, string ResidueHash, DateTimeOffset RetainUntil);
internal sealed record AuditPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase, DateTimeOffset At);
internal sealed record AuditPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role, string Configuration);
internal sealed record AuditPermissionCommit(string Request, string PreviousRevision, AuditPermissionPolicy Policy);
internal sealed record AuditPermissionPolicies(AuditPermissionPolicy[] Inventory, AuditPermissionCommit[] Commits);
internal sealed record AuditPermissionSeed(string Key, string Window, string Organization, string Project, string Name, string Slug)
{
    internal string Target => "seed-" + Key;
    internal string Audit => "audit-" + Key;
}
internal sealed record AuditPermissionSeedCommit(string Seed, string Request, string Target, string Organization, string Project, string InputHash);
internal sealed record AuditPermissionEvent(string Seed, string Event, long Ordinal, string ParentRequest, string ProducerCommitHash,
    string Actor, MemberPermissionActorKind Kind, string CredentialId, string CredentialHash, string Organization, string Project,
    string EventType, AuditEventClass EventClass, DateTimeOffset At, string InputHash, string Target);
internal sealed record AuditPermissionPublication(AuditPermissionEvent[] Events, bool ProducerFence, bool PublicationFence,
    int PendingProducers, int PendingPublications, long Watermark, int Count, string CensusHash);
internal sealed record AuditPermissionState(string Id, string Publication, string ParentRequest, string EventHash,
    string Organization, string Project, string Actor, MemberPermissionActorKind Kind, string CredentialHash,
    string EventType, AuditEventClass EventClass, DateTimeOffset At, string InputHash, string Target, DateTimeOffset ExpiresAt);
internal sealed record AuditPermissionView(string Id, string Project, string ActorType, string EventType,
    AuditEventClass EventClass, DateTimeOffset At);
internal sealed record AuditPermissionStorage(AuditPermissionBinding[] Bindings, AuditPermissionState[] Inventory,
    AuditPermissionSeedCommit[] Seeds, string CensusHash);
internal sealed record AuditPermissionIssuance(AuditPermissionBinding[] Bindings, AuditPermissionCredential[] Credentials, AuditPermissionCredential[] History);
internal sealed record AuditPermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record AuditPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Revision, string QueryHash, int Offset, int Limit, string[] Returned, bool Allowed);
internal sealed record AuditPermissionHeader(string RootHash, AuditPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, AuditPermissionStep Step);
internal sealed record AuditPermissionPayload<T>(AuditPermissionHeader Header, T Content);
internal sealed record AuditPermissionSigned<T>(AuditPermissionPayload<T> Payload, string Signature);
internal sealed record AuditPermissionPacket(AuditPermissionSigned<AuditPermissionOwner> Owner,
    AuditPermissionSigned<AuditPermissionIngress[]> Ingress, AuditPermissionSigned<AuditPermissionPolicies> Policy,
    AuditPermissionSigned<AuditPermissionStorage> Storage, AuditPermissionSigned<AuditPermissionIssuance> Issuer,
    AuditPermissionSigned<AuditPermissionJoin[]> Membership, AuditPermissionSigned<AuditPermissionAccess[]> Access,
    AuditPermissionSigned<AuditPermissionPublication> Publisher,
    AuditPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record AuditPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[AuditPermissionReceipt]";
}
internal sealed record AuditPermissionPage(int Offset, int Limit, string QueryHash, SecretStatus Status, AuditPermissionView[] Values, bool Complete);
internal sealed record AuditPermissionAttempt(AuditPermissionRow Row, string CredentialHash, AuditPermissionPage[] Pages);
internal sealed record AuditPermissionSeedReceipt(AuditPermissionSeed Seed, AuditPermissionReceipt Receipt, string Target);
internal interface IAuditPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<AuditPermissionPacket> StepAsync(AuditPermissionRoot root, AuditPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record AuditPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    AuditPermissionProfile Profile, AuditPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    AuditPermissionAction Action, int TimeoutSeconds, DateTimeOffset From, DateTimeOffset Until, DateTimeOffset RetainUntil)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        AuditPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("auditPermission", out _);
    internal static AuditPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("auditPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<AuditPermissionInput>(AuditPermissionContract.Options);
            AuditPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && input.Until > input.From && input.Until - input.From <= TimeSpan.FromMinutes(10) &&
                input.RetainUntil > input.Until && input.RetainUntil - input.Until <= TimeSpan.FromDays(30) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            AuditPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[AuditPermissionInput]";
}
internal static class AuditPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static AuditPermissionScope Scope(string operation) => MemberPermissionContract.Scope(operation) == MemberPermissionScope.Project ? AuditPermissionScope.Project : AuditPermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static AuditPermissionAction[] Actions(AuditPermissionScope scope) => Enum.GetValues<AuditPermissionAction>();
    internal static string? Gate(AuditPermissionAction action) => action == AuditPermissionAction.Edit ? "audit-edit-no-native-permission-contract" : null;
    internal static AuditPermissionAction[] Supported(AuditPermissionScope scope) => [AuditPermissionAction.Read];
    internal static string Wire(AuditPermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(AuditPermissionAction action) => "permission.AuditLogs." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(AuditPermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(AuditPermissionRoot root, AuditPermissionRow row, bool after, AuditPermissionOutcome outcome) =>
        row.Control == "selected" && after && outcome == AuditPermissionOutcome.Applied;
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class AuditPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<AuditPermissionJournal, (AuditPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<AuditPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(AuditPermissionProfile profile)
    {
        AuditPermissionContract.Require(profile.Pins.Length == 8 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 8 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 8 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 8 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision, profile.BorrowedHash }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            AuditPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(AuditPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal AuditPermissionVerifier(AuditPermissionRoot root)
    {
        Validate(root.Profile); rootHash = AuditPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(AuditPermissionSigned<T> value, AuditPermissionJournal journal, AuditPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = AuditPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        AuditPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == AuditPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(AuditPermissionPacket packet, AuditPermissionStep step)
    {
        AuditPermissionContract.Require(packet.Seals.Length == 8 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 8);
        CheckJournal(packet.Owner, AuditPermissionJournal.Ownership); CheckJournal(packet.Ingress, AuditPermissionJournal.Ingress);
        CheckJournal(packet.Policy, AuditPermissionJournal.Policy); CheckJournal(packet.Storage, AuditPermissionJournal.Storage);
        CheckJournal(packet.Issuer, AuditPermissionJournal.Issuer); CheckJournal(packet.Membership, AuditPermissionJournal.Membership);
        CheckJournal(packet.Access, AuditPermissionJournal.Access); CheckJournal(packet.Publisher, AuditPermissionJournal.Publisher);
        void CheckJournal<T>(AuditPermissionSigned<T> signed, AuditPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            AuditPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == AuditPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
