using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence is not native qualification. Tavily primary facts, 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/internals/permissions/organization-permissions
// Role read/create/edit/delete applies to actual downstream roles in that scope.
// Policy actors, grant roles and target CRUD roles are separate immutable bindings.
// Closed target payloads grant nothing; full storage bytes are independently signed.
// RoleSummary projects metadata and action/subject/inversion, not condition values.
// Conditions are not inferred or certified; only unconditional Role CRUD is supported.
// Seven independent host-pinned P256 writers sign complete journals and terminal seals.
// Root recovery precedes Reserve; logical intents precede generated canonical IDs.
// Owned buffers are erased; SDK strings and framework/socket buffers are not erasable.
internal enum RolePermissionAction { Read, Create, Edit, Delete }
internal enum RolePermissionScope { Project, Organization }
internal enum RolePermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum RolePermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum RolePermissionOutcome { NonApplied, Applied, Partial }
internal sealed record RolePermissionPin(RolePermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record RolePermissionProfile(string Deployment, string Epoch, string Revision, RolePermissionPin[] Pins);
internal sealed record RolePermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    RolePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, RolePermissionAction Action,
    MemberPermissionAuthorities Authorities, RolePermissionProfile Profile)
{
    public override string ToString() => "[RolePermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record RolePermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record RolePermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record RolePermissionResource(string Intent, string CanonicalId);
internal sealed record RolePermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record RolePermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[RolePermissionActor]";
}
internal sealed record RolePermissionRow(string Key, string Window, string Control, RolePermissionAction Action,
    string Organization, string Project, string Target, string Name, string Slug, int Actor);
internal sealed record RolePermissionIssued(RolePermissionActor[] Actors, RolePermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[RolePermissionIssued]";
}
internal sealed record RolePermissionOwner(RolePermissionIntent[] Intents, RolePermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, RolePermissionActor[] Actors);
internal sealed record RolePermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record RolePermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role);
internal sealed record RolePermissionCommit(string Request, string PreviousRevision, RolePermissionPolicy Policy);
internal sealed record RolePermissionPolicies(RolePermissionPolicy[] Inventory, RolePermissionCommit[] Commits);
internal sealed record RolePermissionState(string Row, string Target, string Organization, string Project,
    string Name, string Slug, string Description, string Permissions, int Version);
internal sealed record RolePermissionChange(string Request, string Row, RolePermissionState? Before, RolePermissionState? After);
internal sealed record RolePermissionStorage(RolePermissionBinding[] Bindings, RolePermissionState[] Inventory, RolePermissionChange[] Changes);
internal sealed record RolePermissionIssuance(RolePermissionBinding[] Bindings, RolePermissionCredential[] Credentials);
internal sealed record RolePermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record RolePermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, RolePermissionAction Action, bool Allowed);
internal sealed record RolePermissionHeader(string RootHash, RolePermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, RolePermissionStep Step);
internal sealed record RolePermissionPayload<T>(RolePermissionHeader Header, T Content);
internal sealed record RolePermissionSigned<T>(RolePermissionPayload<T> Payload, string Signature);
internal sealed record RolePermissionPacket(RolePermissionSigned<RolePermissionOwner> Owner,
    RolePermissionSigned<RolePermissionIngress[]> Ingress, RolePermissionSigned<RolePermissionPolicies> Policy,
    RolePermissionSigned<RolePermissionStorage> Storage, RolePermissionSigned<RolePermissionIssuance> Issuer,
    RolePermissionSigned<RolePermissionJoin[]> Membership, RolePermissionSigned<RolePermissionAccess[]> Access,
    RolePermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record RolePermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[RolePermissionReceipt]";
}
internal sealed record RolePermissionAttempt(RolePermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, RolePermissionState? Value, bool Complete);
internal interface IRolePermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<RolePermissionPacket> StepAsync(RolePermissionRoot root, RolePermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record RolePermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    RolePermissionProfile Profile, RolePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    RolePermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        RolePermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("rolePermission", out _);
    internal static RolePermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("rolePermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<RolePermissionInput>(RolePermissionContract.Options);
            RolePermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            RolePermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[RolePermissionInput]";
}
internal static class RolePermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static RolePermissionScope Scope(string operation) => MemberPermissionContract.Scope(operation) == MemberPermissionScope.Project ? RolePermissionScope.Project : RolePermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static RolePermissionAction[] Actions(RolePermissionScope scope) => Enum.GetValues<RolePermissionAction>();
    internal static string? Gate(RolePermissionScope scope, RolePermissionAction action) => null;
    internal static RolePermissionAction[] Supported(RolePermissionScope scope) => Actions(scope);
    internal static RolePermissionAction Baseline(RolePermissionRoot root) => (RolePermissionAction)(((int)root.Action + 1) % 4);
    internal static string Wire(RolePermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(RolePermissionAction action) => "permission.Role." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(RolePermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(RolePermissionRoot root, RolePermissionRow row, bool after, RolePermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == RolePermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class RolePermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<RolePermissionJournal, (RolePermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<RolePermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(RolePermissionProfile profile)
    {
        RolePermissionContract.Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            RolePermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(RolePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal RolePermissionVerifier(RolePermissionRoot root)
    {
        Validate(root.Profile); rootHash = RolePermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(RolePermissionSigned<T> value, RolePermissionJournal journal, RolePermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = RolePermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        RolePermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == RolePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(RolePermissionPacket packet, RolePermissionStep step)
    {
        RolePermissionContract.Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        CheckJournal(packet.Owner, RolePermissionJournal.Ownership); CheckJournal(packet.Ingress, RolePermissionJournal.Ingress);
        CheckJournal(packet.Policy, RolePermissionJournal.Policy); CheckJournal(packet.Storage, RolePermissionJournal.Storage);
        CheckJournal(packet.Issuer, RolePermissionJournal.Issuer); CheckJournal(packet.Membership, RolePermissionJournal.Membership);
        CheckJournal(packet.Access, RolePermissionJournal.Access);
        void CheckJournal<T>(RolePermissionSigned<T> signed, RolePermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            RolePermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == RolePermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
