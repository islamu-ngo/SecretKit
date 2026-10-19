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
// Workspace maps to project: organization create, project edit/delete only.
// https://infisical.com/docs/api-reference/endpoints/projects/create-project
// https://infisical.com/docs/api-reference/endpoints/projects/update-project
// https://infisical.com/docs/api-reference/endpoints/projects/delete-project
// Public deletion documentation does NOT establish the complete native cascade.
// An empty policy baseline keeps the ORIGINAL scope alive until the tested write.
// Denied controls precede the single authorized deletion. No project is recreated.
// Pre-dispatch grant/membership evidence is joined to terminal absence, not live
// membership after deletion. Only the explicit bounded settings payload is proved.
// Seven independent host-pinned P256 writers sign complete journals and terminal seals.
// Root recovery precedes Reserve; logical intents precede generated canonical IDs.
// Owned buffers are erased; SDK strings and framework/socket buffers are not erasable.
internal enum WorkspacePermissionAction { Create, Edit, Delete }
internal enum WorkspacePermissionScope { Project, Organization }
internal enum WorkspacePermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum WorkspacePermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum WorkspacePermissionOutcome { NonApplied, Applied, Partial }
internal sealed record WorkspacePermissionPin(WorkspacePermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record WorkspacePermissionProfile(string Deployment, string Epoch, string Revision, WorkspacePermissionPin[] Pins);
internal sealed record WorkspacePermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    WorkspacePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, WorkspacePermissionAction Action,
    MemberPermissionAuthorities Authorities, WorkspacePermissionProfile Profile)
{
    public override string ToString() => "[WorkspacePermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record WorkspacePermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record WorkspacePermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record WorkspacePermissionResource(string Intent, string CanonicalId);
internal sealed record WorkspacePermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record WorkspacePermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[WorkspacePermissionActor]";
}
internal sealed record WorkspacePermissionRow(string Key, string Window, string Control, WorkspacePermissionAction Action,
    string Organization, string Project, string Target, string Name, string Slug, int Actor);
internal sealed record WorkspacePermissionIssued(WorkspacePermissionActor[] Actors, WorkspacePermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[WorkspacePermissionIssued]";
}
internal sealed record WorkspacePermissionOwner(WorkspacePermissionIntent[] Intents, WorkspacePermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, WorkspacePermissionActor[] Actors);
internal sealed record WorkspacePermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record WorkspacePermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role, string TemplateConfiguration = "");
internal sealed record WorkspacePermissionCommit(string Request, string PreviousRevision, WorkspacePermissionPolicy Policy);
internal sealed record WorkspacePermissionPolicies(WorkspacePermissionPolicy[] Inventory, WorkspacePermissionCommit[] Commits);
internal sealed record WorkspacePermissionState(string Row, string Target, string Organization, string Project,
    string Name, string Slug, string Description, string Configuration, int Version);
internal sealed record WorkspacePermissionChange(string Request, string Row, WorkspacePermissionState? Before, WorkspacePermissionState? After);
internal sealed record WorkspacePermissionStorage(WorkspacePermissionBinding[] Bindings, WorkspacePermissionState[] Inventory, WorkspacePermissionChange[] Changes, WorkspacePermissionCascade[] Cascades);
// Storage is a separate authority from access, policy, membership and issuance.
// A deletion preserves the binding ledger, removes the complete project-owned
// closure, and preserves every resource outside it, including borrowed actors.
internal sealed record WorkspacePermissionCascade(string Request, string Project, string PolicyHash, string MembershipHash,
    string CredentialId, string CredentialHash, WorkspacePermissionResource[] Removed, WorkspacePermissionResource[] Retained);
internal sealed record WorkspacePermissionIssuance(WorkspacePermissionBinding[] Bindings, WorkspacePermissionCredential[] Credentials);
internal sealed record WorkspacePermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record WorkspacePermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, WorkspacePermissionAction Action, bool Allowed);
internal sealed record WorkspacePermissionHeader(string RootHash, WorkspacePermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, WorkspacePermissionStep Step);
internal sealed record WorkspacePermissionPayload<T>(WorkspacePermissionHeader Header, T Content);
internal sealed record WorkspacePermissionSigned<T>(WorkspacePermissionPayload<T> Payload, string Signature);
internal sealed record WorkspacePermissionPacket(WorkspacePermissionSigned<WorkspacePermissionOwner> Owner,
    WorkspacePermissionSigned<WorkspacePermissionIngress[]> Ingress, WorkspacePermissionSigned<WorkspacePermissionPolicies> Policy,
    WorkspacePermissionSigned<WorkspacePermissionStorage> Storage, WorkspacePermissionSigned<WorkspacePermissionIssuance> Issuer,
    WorkspacePermissionSigned<WorkspacePermissionJoin[]> Membership, WorkspacePermissionSigned<WorkspacePermissionAccess[]> Access,
    WorkspacePermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record WorkspacePermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[WorkspacePermissionReceipt]";
}
internal sealed record WorkspacePermissionAttempt(WorkspacePermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, WorkspacePermissionState? Value, bool Complete, string IntentHash);
internal interface IWorkspacePermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<WorkspacePermissionPacket> StepAsync(WorkspacePermissionRoot root, WorkspacePermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record WorkspacePermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    WorkspacePermissionProfile Profile, WorkspacePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    WorkspacePermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        WorkspacePermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("workspacePermission", out _);
    internal static WorkspacePermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("workspacePermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<WorkspacePermissionInput>(WorkspacePermissionContract.Options);
            WorkspacePermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            WorkspacePermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[WorkspacePermissionInput]";
}
internal static class WorkspacePermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static WorkspacePermissionScope Scope(string operation) => MemberPermissionContract.Scope(operation) == MemberPermissionScope.Project ? WorkspacePermissionScope.Project : WorkspacePermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static WorkspacePermissionAction[] Actions(WorkspacePermissionScope scope) => scope == WorkspacePermissionScope.Organization ?
        [WorkspacePermissionAction.Create] : [WorkspacePermissionAction.Edit, WorkspacePermissionAction.Delete];
    internal static string? Gate(WorkspacePermissionScope scope, WorkspacePermissionAction action) =>
        !Actions(scope).Contains(action) ? "unsupported-action" :
        action == WorkspacePermissionAction.Edit ? "unestablished-action" : null;
    internal const int NativeQualified = 0;
    internal static string[] NativeGates => ["deployment-authority", "independent-source-enrollment", "complete-native-cascade", "native-template-copy", "native-settings-defaults"];
    internal static WorkspacePermissionAction[] Supported(WorkspacePermissionScope scope) => Actions(scope).Where(a => Gate(scope, a) is null).ToArray();
    internal static string Wire(WorkspacePermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(WorkspacePermissionAction action) => "permission.Workspace." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(WorkspacePermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(WorkspacePermissionRoot root, WorkspacePermissionRow row, bool after, WorkspacePermissionOutcome outcome) =>
        row.Action != WorkspacePermissionAction.Edit && row.Control == "selected" && after && outcome == WorkspacePermissionOutcome.Applied && row.Action == root.Action;
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class WorkspacePermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<WorkspacePermissionJournal, (WorkspacePermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<WorkspacePermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(WorkspacePermissionProfile profile)
    {
        WorkspacePermissionContract.Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            WorkspacePermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(WorkspacePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal WorkspacePermissionVerifier(WorkspacePermissionRoot root)
    {
        Validate(root.Profile); rootHash = WorkspacePermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(WorkspacePermissionSigned<T> value, WorkspacePermissionJournal journal, WorkspacePermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = WorkspacePermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        WorkspacePermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == WorkspacePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(WorkspacePermissionPacket packet, WorkspacePermissionStep step)
    {
        WorkspacePermissionContract.Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        CheckJournal(packet.Owner, WorkspacePermissionJournal.Ownership); CheckJournal(packet.Ingress, WorkspacePermissionJournal.Ingress);
        CheckJournal(packet.Policy, WorkspacePermissionJournal.Policy); CheckJournal(packet.Storage, WorkspacePermissionJournal.Storage);
        CheckJournal(packet.Issuer, WorkspacePermissionJournal.Issuer); CheckJournal(packet.Membership, WorkspacePermissionJournal.Membership);
        CheckJournal(packet.Access, WorkspacePermissionJournal.Access);
        void CheckJournal<T>(WorkspacePermissionSigned<T> signed, WorkspacePermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            WorkspacePermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == WorkspacePermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
