using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence is not native qualification. Primary interface facts: Tavily, 2026-10-14.
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/api-reference/endpoints/project-templates/create
// https://infisical.com/docs/api-reference/endpoints/project-templates/update
// https://infisical.com/docs/api-reference/endpoints/project-templates/get-by-id
// https://infisical.com/docs/api-reference/endpoints/project-templates/delete
// Org role policies grant project-templates CRUD to an explicitly issued USER.
// This is not a project-role/template permission or template activation witness.
// The closed SecretManager canary grants no permissions and has explicit empty
// principal collections. Whole persisted configuration is compared, not echoed.
// Seven distinct host-pinned P256 writers and terminal seals attest independent
// ownership, ingress, policy, storage, issuance, membership and access journals.
// Root recovery precedes Reserve; immutable intents precede canonical ID commits.
// Owned buffers are released; SDK/JSON strings and socket buffers are not erasable.
internal enum ProjectTemplatePermissionAction { Read, Create, Edit, Delete }
internal enum ProjectTemplatePermissionScope { Project, Organization }
internal enum ProjectTemplatePermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum ProjectTemplatePermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum ProjectTemplatePermissionOutcome { NonApplied, Applied, Partial }
internal sealed record ProjectTemplatePermissionPin(ProjectTemplatePermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record ProjectTemplatePermissionProfile(string Deployment, string Epoch, string Revision, ProjectTemplatePermissionPin[] Pins);
internal sealed record ProjectTemplatePermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    ProjectTemplatePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, ProjectTemplatePermissionAction Action,
    MemberPermissionAuthorities Authorities, ProjectTemplatePermissionProfile Profile)
{
    public override string ToString() => "[ProjectTemplatePermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record ProjectTemplatePermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record ProjectTemplatePermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record ProjectTemplatePermissionResource(string Intent, string CanonicalId);
internal sealed record ProjectTemplatePermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record ProjectTemplatePermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[ProjectTemplatePermissionActor]";
}
internal sealed record ProjectTemplatePermissionRow(string Key, string Window, string Control, ProjectTemplatePermissionAction Action,
    string Organization, string Template, string Name, int Actor);
internal sealed record ProjectTemplatePermissionIssued(ProjectTemplatePermissionActor[] Actors, ProjectTemplatePermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[ProjectTemplatePermissionIssued]";
}
internal sealed record ProjectTemplatePermissionOwner(ProjectTemplatePermissionIntent[] Intents, ProjectTemplatePermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, ProjectTemplatePermissionActor[] Actors);
internal sealed record ProjectTemplatePermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record ProjectTemplatePermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role);
internal sealed record ProjectTemplatePermissionCommit(string Request, string PreviousRevision, ProjectTemplatePermissionPolicy Policy);
internal sealed record ProjectTemplatePermissionPolicies(ProjectTemplatePermissionPolicy[] Inventory, ProjectTemplatePermissionCommit[] Commits);
internal sealed record ProjectTemplatePermissionState(string Row, string Template, string Organization,
    string Name, string Description, string Type, string Configuration, int Version);
internal sealed record ProjectTemplatePermissionChange(string Request, string Row, ProjectTemplatePermissionState? Before, ProjectTemplatePermissionState? After);
internal sealed record ProjectTemplatePermissionStorage(ProjectTemplatePermissionBinding[] Bindings, ProjectTemplatePermissionState[] Inventory, ProjectTemplatePermissionChange[] Changes);
internal sealed record ProjectTemplatePermissionIssuance(ProjectTemplatePermissionBinding[] Bindings, ProjectTemplatePermissionCredential[] Credentials);
internal sealed record ProjectTemplatePermissionJoin(string Principal, string Kind, string Organization, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record ProjectTemplatePermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Template, string Revision, ProjectTemplatePermissionAction Action, bool Allowed);
internal sealed record ProjectTemplatePermissionHeader(string RootHash, ProjectTemplatePermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, ProjectTemplatePermissionStep Step);
internal sealed record ProjectTemplatePermissionPayload<T>(ProjectTemplatePermissionHeader Header, T Content);
internal sealed record ProjectTemplatePermissionSigned<T>(ProjectTemplatePermissionPayload<T> Payload, string Signature);
internal sealed record ProjectTemplatePermissionPacket(ProjectTemplatePermissionSigned<ProjectTemplatePermissionOwner> Owner,
    ProjectTemplatePermissionSigned<ProjectTemplatePermissionIngress[]> Ingress, ProjectTemplatePermissionSigned<ProjectTemplatePermissionPolicies> Policy,
    ProjectTemplatePermissionSigned<ProjectTemplatePermissionStorage> Storage, ProjectTemplatePermissionSigned<ProjectTemplatePermissionIssuance> Issuer,
    ProjectTemplatePermissionSigned<ProjectTemplatePermissionJoin[]> Membership, ProjectTemplatePermissionSigned<ProjectTemplatePermissionAccess[]> Access,
    ProjectTemplatePermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record ProjectTemplatePermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[ProjectTemplatePermissionReceipt]";
}
internal sealed record ProjectTemplatePermissionAttempt(ProjectTemplatePermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, ProjectTemplatePermissionState? Value, bool Complete);
internal interface IProjectTemplatePermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<ProjectTemplatePermissionPacket> StepAsync(ProjectTemplatePermissionRoot root, ProjectTemplatePermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record ProjectTemplatePermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    ProjectTemplatePermissionProfile Profile, ProjectTemplatePermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    ProjectTemplatePermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        ProjectTemplatePermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("projectTemplatePermission", out _);
    internal static ProjectTemplatePermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("projectTemplatePermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<ProjectTemplatePermissionInput>(ProjectTemplatePermissionContract.Options);
            ProjectTemplatePermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            ProjectTemplatePermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[ProjectTemplatePermissionInput]";
}
internal static class ProjectTemplatePermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Skip(6).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static ProjectTemplatePermissionScope Scope(string operation) => ProjectTemplatePermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionActorKind.User;
    internal static bool Create(string operation) => operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal);
    internal static string Family(string operation) => "RoleChanges";
    internal static ProjectTemplatePermissionAction[] Actions(ProjectTemplatePermissionScope scope) => Enum.GetValues<ProjectTemplatePermissionAction>();
    internal static string? Gate(ProjectTemplatePermissionScope scope, ProjectTemplatePermissionAction action) => null;
    internal static ProjectTemplatePermissionAction[] Supported(ProjectTemplatePermissionScope scope) => Actions(scope);
    internal static ProjectTemplatePermissionAction Baseline(ProjectTemplatePermissionRoot root) => (ProjectTemplatePermissionAction)(((int)root.Action + 1) % 4);
    internal static string Wire(ProjectTemplatePermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(ProjectTemplatePermissionAction action) => "permission.ProjectTemplates." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(ProjectTemplatePermissionScope.Organization).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) && InfisicalPermissionFamilies.Valid(d);
    internal static string[] Controls(ProjectTemplatePermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(ProjectTemplatePermissionRoot root, ProjectTemplatePermissionRow row, bool after, ProjectTemplatePermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == ProjectTemplatePermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class ProjectTemplatePermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<ProjectTemplatePermissionJournal, (ProjectTemplatePermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<ProjectTemplatePermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(ProjectTemplatePermissionProfile profile)
    {
        ProjectTemplatePermissionContract.Require(profile.Pins.Length == 7 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 7 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 7 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 7 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            ProjectTemplatePermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(ProjectTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal ProjectTemplatePermissionVerifier(ProjectTemplatePermissionRoot root)
    {
        Validate(root.Profile); rootHash = ProjectTemplatePermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(ProjectTemplatePermissionSigned<T> value, ProjectTemplatePermissionJournal journal, ProjectTemplatePermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = ProjectTemplatePermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        ProjectTemplatePermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == ProjectTemplatePermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(ProjectTemplatePermissionPacket packet, ProjectTemplatePermissionStep step)
    {
        ProjectTemplatePermissionContract.Require(packet.Seals.Length == 7 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 7);
        CheckJournal(packet.Owner, ProjectTemplatePermissionJournal.Ownership); CheckJournal(packet.Ingress, ProjectTemplatePermissionJournal.Ingress);
        CheckJournal(packet.Policy, ProjectTemplatePermissionJournal.Policy); CheckJournal(packet.Storage, ProjectTemplatePermissionJournal.Storage);
        CheckJournal(packet.Issuer, ProjectTemplatePermissionJournal.Issuer); CheckJournal(packet.Membership, ProjectTemplatePermissionJournal.Membership);
        CheckJournal(packet.Access, ProjectTemplatePermissionJournal.Access);
        void CheckJournal<T>(ProjectTemplatePermissionSigned<T> signed, ProjectTemplatePermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            ProjectTemplatePermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == ProjectTemplatePermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
