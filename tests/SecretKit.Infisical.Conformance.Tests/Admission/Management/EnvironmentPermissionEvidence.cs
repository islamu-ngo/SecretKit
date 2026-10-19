using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Offline controlled evidence is not native qualification. Primary interface facts, 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/api-reference/endpoints/environments/create
// https://infisical.com/docs/api-reference/endpoints/environments/update
// https://infisical.com/docs/api-reference/endpoints/environments/delete
// https://infisical.com/docs/api-reference/endpoints/projects/get-project
// Environments CRUD is project-scoped and unconditional. Delete uses ONLY explicit
// hardDelete=true on closed owned canaries. Soft-delete/restore variants are not certified.
// GetProject is the real typed active/deleted inventory; no environment-list route
// is invented. Fresh GetEnvironmentBySlug supplies position and deletion fields.
// Seven host-pinned writers, generated IDs and root recovery follow the role protocol.
// Policy roles, policy actors and target environments have independent bindings.
// Owned buffers are erased; strings/framework/socket storage is not claimed erased.
internal enum EnvironmentPermissionAction { Read, Create, Edit, Delete }
internal enum EnvironmentPermissionScope { Project, Organization }
internal enum EnvironmentPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum EnvironmentPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum EnvironmentPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record EnvironmentPermissionPin(EnvironmentPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record EnvironmentPermissionProfile(string Deployment, string Epoch, string Revision, EnvironmentPermissionPin[] Pins);
internal sealed record EnvironmentPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    EnvironmentPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, EnvironmentPermissionAction Action,
    MemberPermissionAuthorities Authorities, EnvironmentPermissionProfile Profile)
{
    public override string ToString() => "[EnvironmentPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record EnvironmentPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record EnvironmentPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record EnvironmentPermissionResource(string Intent, string CanonicalId);
internal sealed record EnvironmentPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record EnvironmentPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[EnvironmentPermissionActor]";
}
internal sealed record EnvironmentPermissionRow(string Key, string Window, string Control, EnvironmentPermissionAction Action,
    string Organization, string Project, string Target, string Name, string Slug, int Actor);
internal sealed record EnvironmentPermissionIssued(EnvironmentPermissionActor[] Actors, EnvironmentPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[EnvironmentPermissionIssued]";
}
internal sealed record EnvironmentPermissionOwner(EnvironmentPermissionIntent[] Intents, EnvironmentPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, EnvironmentPermissionActor[] Actors);
internal sealed record EnvironmentPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record EnvironmentPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role, string Configuration);
internal sealed record EnvironmentPermissionCommit(string Request, string PreviousRevision, EnvironmentPermissionPolicy Policy);
internal sealed record EnvironmentPermissionPolicies(EnvironmentPermissionPolicy[] Inventory, EnvironmentPermissionCommit[] Commits);
internal sealed record EnvironmentPermissionState(string Row, string Target, string Organization, string Project,
    string Name, string Slug, double Position, bool Deleted, int Version,
    string? SoftDeletedAt = null, string? DeleteAfter = null, string? DeletedBy = null);
internal sealed record EnvironmentPermissionChange(string Request, string Row, EnvironmentPermissionState? Before, EnvironmentPermissionState? After);
internal sealed record EnvironmentPermissionStorage(EnvironmentPermissionBinding[] Bindings, EnvironmentPermissionState[] Inventory, EnvironmentPermissionChange[] Changes);
internal sealed record EnvironmentPermissionIssuance(EnvironmentPermissionBinding[] Bindings, EnvironmentPermissionCredential[] Credentials);
internal sealed record EnvironmentPermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record EnvironmentPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, EnvironmentPermissionAction Action, bool Allowed);
internal sealed record EnvironmentPermissionHeader(string RootHash, EnvironmentPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, EnvironmentPermissionStep Step);
internal sealed record EnvironmentPermissionPayload<T>(EnvironmentPermissionHeader Header, T Content);
internal sealed record EnvironmentPermissionSigned<T>(EnvironmentPermissionPayload<T> Payload, string Signature);
internal sealed record EnvironmentPermissionPacket(EnvironmentPermissionSigned<EnvironmentPermissionOwner> Owner,
    EnvironmentPermissionSigned<EnvironmentPermissionIngress[]> Ingress, EnvironmentPermissionSigned<EnvironmentPermissionPolicies> Policy,
    EnvironmentPermissionSigned<EnvironmentPermissionStorage> Storage, EnvironmentPermissionSigned<EnvironmentPermissionIssuance> Issuer,
    EnvironmentPermissionSigned<EnvironmentPermissionJoin[]> Membership, EnvironmentPermissionSigned<EnvironmentPermissionAccess[]> Access,
    EnvironmentPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record EnvironmentPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[EnvironmentPermissionReceipt]";
}
internal sealed record EnvironmentPermissionAttempt(EnvironmentPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, EnvironmentPermissionState? Value, bool Complete);
internal interface IEnvironmentPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<EnvironmentPermissionPacket> StepAsync(EnvironmentPermissionRoot root, EnvironmentPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record EnvironmentPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    EnvironmentPermissionProfile Profile, EnvironmentPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    EnvironmentPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        EnvironmentPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("environmentPermission", out _);
    internal static EnvironmentPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("environmentPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<EnvironmentPermissionInput>(EnvironmentPermissionContract.Options);
            EnvironmentPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            EnvironmentPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[EnvironmentPermissionInput]";
}
internal static class EnvironmentPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Where(op => !op.EndsWith("OrganizationRole", StringComparison.Ordinal)).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static EnvironmentPermissionScope Scope(string operation) => EnvironmentPermissionScope.Project;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static EnvironmentPermissionAction[] Actions(EnvironmentPermissionScope scope) => Enum.GetValues<EnvironmentPermissionAction>();
    internal static string? Gate(EnvironmentPermissionScope scope, EnvironmentPermissionAction action) => null;
    internal static EnvironmentPermissionAction[] Supported(EnvironmentPermissionScope scope) => Actions(scope);
    internal static EnvironmentPermissionAction Baseline(EnvironmentPermissionRoot root) => (EnvironmentPermissionAction)(((int)root.Action + 1) % 4);
    internal static string Wire(EnvironmentPermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(EnvironmentPermissionAction action) => "permission.Environments." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(EnvironmentPermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(EnvironmentPermissionRoot root, EnvironmentPermissionRow row, bool after, EnvironmentPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == EnvironmentPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class EnvironmentPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<EnvironmentPermissionJournal, (EnvironmentPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<EnvironmentPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(EnvironmentPermissionProfile profile)
    {
        EnvironmentPermissionContract.Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            EnvironmentPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(EnvironmentPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal EnvironmentPermissionVerifier(EnvironmentPermissionRoot root)
    {
        Validate(root.Profile); rootHash = EnvironmentPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(EnvironmentPermissionSigned<T> value, EnvironmentPermissionJournal journal, EnvironmentPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = EnvironmentPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        EnvironmentPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == EnvironmentPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(EnvironmentPermissionPacket packet, EnvironmentPermissionStep step)
    {
        EnvironmentPermissionContract.Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        CheckJournal(packet.Owner, EnvironmentPermissionJournal.Ownership); CheckJournal(packet.Ingress, EnvironmentPermissionJournal.Ingress);
        CheckJournal(packet.Policy, EnvironmentPermissionJournal.Policy); CheckJournal(packet.Storage, EnvironmentPermissionJournal.Storage);
        CheckJournal(packet.Issuer, EnvironmentPermissionJournal.Issuer); CheckJournal(packet.Membership, EnvironmentPermissionJournal.Membership);
        CheckJournal(packet.Access, EnvironmentPermissionJournal.Access);
        void CheckJournal<T>(EnvironmentPermissionSigned<T> signed, EnvironmentPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            EnvironmentPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == EnvironmentPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
