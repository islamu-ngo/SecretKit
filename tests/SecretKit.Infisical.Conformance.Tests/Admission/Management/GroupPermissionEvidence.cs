using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence is not native qualification. Primary interface facts, 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/api-reference/endpoints/groups/create
// https://infisical.com/docs/api-reference/endpoints/groups/update
// https://infisical.com/docs/api-reference/endpoints/project-group-memberships/create
// https://infisical.com/docs/api-reference/endpoints/project-group-memberships/update
// Tavily was attempted first (429); the official pages were retrieved directly.
// Project create links an existing group; organization create creates a group.
// Project edit and legacy grant-privileges lack an established exact typed seam.
// Never substitute an organization endpoint or secret read for those twelve pairs.
// Seven independent host-pinned P256 writers sign whole journals and empty seals.
// A coordinator cannot certify its own claims. Compromised pinned writers remain
// a trust boundary; no native journal instrumentation is qualified by these tests.
internal enum GroupPermissionAction { Read, Create, Edit, Delete, GrantPrivileges, AssignRole, AddIdentities, AddMembers, RemoveMembers, RemoveIdentities }
internal enum GroupPermissionScope { Project, Organization }
internal enum GroupPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum GroupPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum GroupPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record GroupPermissionPin(GroupPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record GroupPermissionProfile(string Deployment, string Epoch, string Revision, GroupPermissionPin[] Pins);
internal sealed record GroupPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    GroupPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, GroupPermissionAction Action,
    MemberPermissionAuthorities Authorities, GroupPermissionProfile Profile)
{
    public override string ToString() => "[GroupPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record GroupPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record GroupPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record GroupPermissionResource(string Intent, string CanonicalId);
internal sealed record GroupPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record GroupPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[GroupPermissionActor]";
}
internal sealed record GroupPermissionRow(string Key, string Window, string Control, GroupPermissionAction Action,
    string Organization, string Project, string Group, string Name, string Membership, string User, string Identity,
    string UserLink, string IdentityLink, int Actor);
internal sealed record GroupPermissionIssued(GroupPermissionActor[] Actors, GroupPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[GroupPermissionIssued]";
}
internal sealed record GroupPermissionOwner(GroupPermissionIntent[] Intents, GroupPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, GroupPermissionActor[] Actors);
internal sealed record GroupPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record GroupPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role);
internal sealed record GroupPermissionCommit(string Request, string PreviousRevision, GroupPermissionPolicy Policy);
internal sealed record GroupPermissionPolicies(GroupPermissionPolicy[] Inventory, GroupPermissionCommit[] Commits);
internal sealed record GroupPermissionState(string Row, string Group, string Membership, string Organization,
    string Project, string Name, string Role, string User, string Identity, string UserLink, string IdentityLink, int Version);
internal sealed record GroupPermissionChange(string Request, string Row, GroupPermissionState? Before, GroupPermissionState? After);
internal sealed record GroupPermissionStorage(GroupPermissionBinding[] Bindings, GroupPermissionState[] Inventory, GroupPermissionChange[] Changes);
internal sealed record GroupPermissionIssuance(GroupPermissionBinding[] Bindings, GroupPermissionCredential[] Credentials);
internal sealed record GroupPermissionJoin(string Principal, string Kind, string Organization,
    string Project, string Group, string Membership, bool Assigned);
internal sealed record GroupPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Group, string Membership,
    string User, string Identity, string Revision, GroupPermissionAction Action, bool Allowed);
internal sealed record GroupPermissionHeader(string RootHash, GroupPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, GroupPermissionStep Step);
internal sealed record GroupPermissionPayload<T>(GroupPermissionHeader Header, T Content);
internal sealed record GroupPermissionSigned<T>(GroupPermissionPayload<T> Payload, string Signature);
internal sealed record GroupPermissionPacket(GroupPermissionSigned<GroupPermissionOwner> Owner,
    GroupPermissionSigned<GroupPermissionIngress[]> Ingress, GroupPermissionSigned<GroupPermissionPolicies> Policy,
    GroupPermissionSigned<GroupPermissionStorage> Storage, GroupPermissionSigned<GroupPermissionIssuance> Issuer,
    GroupPermissionSigned<GroupPermissionJoin[]> Membership, GroupPermissionSigned<GroupPermissionAccess[]> Access,
    GroupPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record GroupPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[GroupPermissionReceipt]";
}
internal sealed record GroupPermissionAttempt(GroupPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, string Group, string Membership, string Member, string Name, string Role, bool Complete);
internal interface IGroupPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<GroupPermissionPacket> StepAsync(GroupPermissionRoot root, GroupPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record GroupPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    GroupPermissionProfile Profile, GroupPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    GroupPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        GroupPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("groupPermission", out _);
    internal static GroupPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("groupPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<GroupPermissionInput>(GroupPermissionContract.Options);
            GroupPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            GroupPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[GroupPermissionInput]";
}
internal static class GroupPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static GroupPermissionScope Scope(string operation) => MemberPermissionContract.Scope(operation) ==
        MemberPermissionScope.Project ? GroupPermissionScope.Project : GroupPermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static GroupPermissionAction[] Actions(GroupPermissionScope scope) => scope == GroupPermissionScope.Project ?
        [GroupPermissionAction.Read, GroupPermissionAction.Create, GroupPermissionAction.Edit, GroupPermissionAction.Delete,
            GroupPermissionAction.GrantPrivileges, GroupPermissionAction.AssignRole] :
        Enum.GetValues<GroupPermissionAction>().Where(a => a != GroupPermissionAction.AssignRole).ToArray();
    internal static string? Gate(GroupPermissionScope scope, GroupPermissionAction action) => (scope, action) switch
    {
        (GroupPermissionScope.Project, GroupPermissionAction.Edit) => "typed-project-group-details-unavailable",
        (GroupPermissionScope.Project, GroupPermissionAction.GrantPrivileges) => "typed-legacy-group-privileges-unavailable",
        _ => null
    };
    internal static GroupPermissionAction[] Supported(GroupPermissionScope scope) => Actions(scope).Where(a => Gate(scope, a) is null).ToArray();
    internal static GroupPermissionAction Baseline(GroupPermissionRoot root)
    {
        var actions = Supported(root.ScopeProfile);
        return actions[(Array.IndexOf(actions, root.Action) + 1) % actions.Length];
    }
    internal static string Wire(GroupPermissionAction action) => action switch
    {
        GroupPermissionAction.Read => "read",
        GroupPermissionAction.Create => "create",
        GroupPermissionAction.Edit => "edit",
        GroupPermissionAction.Delete => "delete",
        GroupPermissionAction.GrantPrivileges => "grant-privileges",
        GroupPermissionAction.AssignRole => "assign-role",
        GroupPermissionAction.AddIdentities => "add-identities",
        GroupPermissionAction.AddMembers => "add-members",
        GroupPermissionAction.RemoveMembers => "remove-members",
        GroupPermissionAction.RemoveIdentities => "remove-identities",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string Variant(GroupPermissionAction action) => "permission.Groups." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(GroupPermissionAction action) => action == GroupPermissionAction.AssignRole ?
        ["selected", "scope", "actor", "kind", "credential", "group", "role"] : ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(GroupPermissionRoot root, GroupPermissionRow row, bool after, GroupPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == GroupPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class GroupPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<GroupPermissionJournal, (GroupPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<GroupPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(GroupPermissionProfile profile)
    {
        GroupPermissionContract.Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            GroupPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(GroupPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal GroupPermissionVerifier(GroupPermissionRoot root)
    {
        Validate(root.Profile); rootHash = GroupPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(GroupPermissionSigned<T> value, GroupPermissionJournal journal, GroupPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = GroupPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        GroupPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == GroupPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(GroupPermissionPacket packet, GroupPermissionStep step)
    {
        GroupPermissionContract.Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        CheckJournal(packet.Owner, GroupPermissionJournal.Ownership); CheckJournal(packet.Ingress, GroupPermissionJournal.Ingress);
        CheckJournal(packet.Policy, GroupPermissionJournal.Policy); CheckJournal(packet.Storage, GroupPermissionJournal.Storage);
        CheckJournal(packet.Issuer, GroupPermissionJournal.Issuer); CheckJournal(packet.Membership, GroupPermissionJournal.Membership);
        CheckJournal(packet.Access, GroupPermissionJournal.Access);
        void CheckJournal<T>(GroupPermissionSigned<T> signed, GroupPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            GroupPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == GroupPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
