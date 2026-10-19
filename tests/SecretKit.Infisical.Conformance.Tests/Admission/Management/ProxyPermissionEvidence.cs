using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled configuration witness; native qualification remains zero. Facts checked 2026-10-14:
// https://infisical.com/docs/api-reference/endpoints/proxied-services/update
// https://infisical.com/docs/documentation/platform/agent-proxy/standalone-agent-proxy
// Tavily primary documentation: supplied credentials replace the entire collection.
// IDs are response metadata, never input allocations. Native retention/reallocation
// and complete retirement are NOT established by that PATCH contract.
// The service alone is a resource binding with injective request and commit IDs.
// An eighth independent P256 collection writer joins ordered versions to storage,
// issuer bindings, protected input, ingress and complete active/deleted inventories.
// Retained and replaced IDs are both observed; neither is inferred. No ID can move
// between parents/slots, collide with a resource/borrowed ID, or resurrect after removal.
// Bounded profile: exactly two static credential-substitution entries, explicit
// header/query surfaces, protected placeholders, destination, environment and path.
// No header rewrite, dynamic lease, omission/clear, routing, login or usage claim.
// Runtime proxy and trusted usage-reporting identities require distinct seams;
// canProxy metadata is neither effect. Exercising actors receive no secret-read grant.
// Only owned byte arrays are erased, not strings, framework or socket storage.
internal enum ProxyPermissionAction { Read, Create, Edit, Delete, Proxy, ReportUsage }
internal enum ProxyPermissionScope { Project, Organization }
internal enum ProxyPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access, Collection }
internal enum ProxyPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum ProxyPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record ProxyPermissionPin(ProxyPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record ProxyPermissionProfile(string Deployment, string Epoch, string Revision, ProxyPermissionPin[] Pins);
internal sealed record ProxyPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    ProxyPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, ProxyPermissionAction Action,
    MemberPermissionAuthorities Authorities, ProxyPermissionProfile Profile)
{
    public override string ToString() => "[ProxyPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record ProxyPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record ProxyPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record ProxyPermissionResource(string Intent, string CanonicalId);
internal sealed record ProxyPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record ProxyPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[ProxyPermissionActor]";
}
internal sealed record ProxyPermissionRow(string Key, string Window, string Control, ProxyPermissionAction Action,
    string Organization, string Project, string Target, string Name, string Slug, int Actor,
    string Environment, string SecretPath, string Folder);
internal sealed record ProxyPermissionIssued(ProxyPermissionActor[] Actors, ProxyPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[ProxyPermissionIssued]";
}
internal sealed record ProxyPermissionOwner(ProxyPermissionIntent[] Intents, ProxyPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, MemberPermissionBorrowed[] BorrowedBaseline, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, ProxyPermissionActor[] Actors);
internal sealed record ProxyPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record ProxyPermissionCollectionDispatch(string Root, string Nonce, string Request, string Service, string InputHash, string Phase);
internal sealed record ProxyPermissionIngressLog(ProxyPermissionIngress[] Window, ProxyPermissionCollectionDispatch[] Collection);
internal sealed record ProxyPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role, string Configuration);
internal sealed record ProxyPermissionCommit(string Request, string PreviousRevision, ProxyPermissionPolicy Policy);
internal sealed record ProxyPermissionPolicies(ProxyPermissionPolicy[] Inventory, ProxyPermissionCommit[] Commits);
internal sealed record ProxyPermissionCredentialState(int Slot, string Id, string ServiceId, string Fingerprint);
internal sealed record ProxyPermissionState(string Row, string Target, string Organization, string Project,
    string Name, string Host, string Environment, string SecretPath, string Folder, bool Enabled, int Version,
    ProxyPermissionCredentialState First, ProxyPermissionCredentialState Second)
{
    internal ProxyPermissionCredentialState[] Credentials => [First, Second];
    public override string ToString() => "[ProxyPermissionState]";
}
internal sealed record ProxyPermissionRetirement(string Service, int Version, int Slot, string Credential,
    string Fingerprint, string Request, string Reason);
internal sealed record ProxyPermissionCollectionChange(string Root, string Nonce, string Request, string Commit,
    string InputHash, ProxyPermissionState? Before, ProxyPermissionState? After);
internal sealed record ProxyPermissionCollections(ProxyPermissionState[] Inventory,
    ProxyPermissionCollectionChange[] History, ProxyPermissionRetirement[] Retired,
    ProxyPermissionCredentialState[] Active, ProxyPermissionCredentialState[] Deleted, ProxyPermissionState[] DeletedServices);
internal sealed record ProxyPermissionTemplate(string Project, string Environment, double Position, string Configuration);
internal sealed record ProxyPermissionChange(string Request, string Row, ProxyPermissionState? Before, ProxyPermissionState? After);
internal sealed record ProxyPermissionStorage(ProxyPermissionBinding[] Bindings, ProxyPermissionState[] Inventory, ProxyPermissionChange[] Changes, ProxyPermissionCollectionChange[] CollectionHistory, ProxyPermissionTemplate[] Templates, ProxyPermissionState[] Deleted);
internal sealed record ProxyPermissionIssuance(ProxyPermissionBinding[] Bindings, ProxyPermissionCredential[] Credentials);
internal sealed record ProxyPermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record ProxyPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, ProxyPermissionAction Action, bool Allowed);
internal sealed record ProxyPermissionHeader(string RootHash, ProxyPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, ProxyPermissionStep Step);
internal sealed record ProxyPermissionPayload<T>(ProxyPermissionHeader Header, T Content);
internal sealed record ProxyPermissionSigned<T>(ProxyPermissionPayload<T> Payload, string Signature);
internal sealed record ProxyPermissionPacket(ProxyPermissionSigned<ProxyPermissionOwner> Owner,
    ProxyPermissionSigned<ProxyPermissionIngressLog> Ingress, ProxyPermissionSigned<ProxyPermissionPolicies> Policy,
    ProxyPermissionSigned<ProxyPermissionStorage> Storage, ProxyPermissionSigned<ProxyPermissionIssuance> Issuer,
    ProxyPermissionSigned<ProxyPermissionJoin[]> Membership, ProxyPermissionSigned<ProxyPermissionAccess[]> Access,
    ProxyPermissionSigned<ProxyPermissionCollections> Collection, ProxyPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record ProxyPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[ProxyPermissionReceipt]";
}
internal sealed record ProxyPermissionAttempt(ProxyPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, ProxyPermissionState? Value, bool Complete, string InputHash);
internal interface IProxyPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<ProxyPermissionPacket> StepAsync(ProxyPermissionRoot root, ProxyPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record ProxyPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    ProxyPermissionProfile Profile, ProxyPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    ProxyPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        ProxyPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("proxyPermission", out _);
    internal static ProxyPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("proxyPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<ProxyPermissionInput>(ProxyPermissionContract.Options);
            ProxyPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            ProxyPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[ProxyPermissionInput]";
}
internal static class ProxyPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Where(op => !op.EndsWith("OrganizationRole", StringComparison.Ordinal)).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static ProxyPermissionScope Scope(string operation) => ProxyPermissionScope.Project;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static ProxyPermissionAction[] Actions(ProxyPermissionScope scope) => Enum.GetValues<ProxyPermissionAction>();
    internal static string? Gate(ProxyPermissionScope scope, ProxyPermissionAction action) => action switch
    {
        ProxyPermissionAction.Proxy => "missing-typed-proxy-runtime-effect",
        ProxyPermissionAction.ReportUsage => "missing-typed-trusted-usage-reporting-effect",
        _ => null
    };
    internal static ProxyPermissionAction[] Supported(ProxyPermissionScope scope) => [ProxyPermissionAction.Read, ProxyPermissionAction.Create, ProxyPermissionAction.Edit, ProxyPermissionAction.Delete];
    internal static ProxyPermissionAction Baseline(ProxyPermissionRoot root) => (ProxyPermissionAction)(((int)root.Action + 1) % 4);
    internal static string Wire(ProxyPermissionAction action) => action == ProxyPermissionAction.ReportUsage ? "report-usage" : action.ToString().ToLowerInvariant();
    internal static string Variant(ProxyPermissionAction action) => "permission.ProxiedServices." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    // Parent forwards this resolver and optional source; all six actions stay selected.
    internal static NativeCaseDefinition? Resolve(NativeCaseDefinition definition, NativeEnvironment env)
    {
        const string prefix = "factory.";
        if (!definition.Key.Variant.StartsWith(prefix, StringComparison.Ordinal)) return null;
        string operation = definition.Key.Variant[prefix.Length..];
        if (!Operations.Contains(operation) || !env.TryGetFamilyInput("C08-IM-" + Family(operation), out var family) ||
            !family.TryGetProperty("scopes", out var scopes) || !scopes.TryGetProperty(definition.Key.Scope, out var scope)) return null;
        var input = ProxyPermissionInput.FromScope(scope);
        string member = InfisicalPermissionFamilies.Bindings.TryGetValue(operation, out var binding) ? binding.Member : InfisicalProjectFamilies.Bindings[operation].Member;
        return input is null ? null : new(definition.Key with { Operation = operation, Variant = Variant(input.Action) }, member);
    }
    internal static string[] Controls(ProxyPermissionAction action) => ["selected", "scope", "environment", "path", "actor", "kind", "credential"];
    internal static bool Allowed(ProxyPermissionRoot root, ProxyPermissionRow row, bool after, ProxyPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == ProxyPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class ProxyPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<ProxyPermissionJournal, (ProxyPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<ProxyPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(ProxyPermissionProfile profile)
    {
        ProxyPermissionContract.Require(profile.Pins.Length == 8 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 8 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 8 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 8 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            ProxyPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(ProxyPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal ProxyPermissionVerifier(ProxyPermissionRoot root)
    {
        Validate(root.Profile); rootHash = ProxyPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(ProxyPermissionSigned<T> value, ProxyPermissionJournal journal, ProxyPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = ProxyPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        ProxyPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == ProxyPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(ProxyPermissionPacket packet, ProxyPermissionStep step)
    {
        ProxyPermissionContract.Require(packet.Seals.Length == 8 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 8);
        CheckJournal(packet.Owner, ProxyPermissionJournal.Ownership); CheckJournal(packet.Ingress, ProxyPermissionJournal.Ingress);
        CheckJournal(packet.Policy, ProxyPermissionJournal.Policy); CheckJournal(packet.Storage, ProxyPermissionJournal.Storage);
        CheckJournal(packet.Issuer, ProxyPermissionJournal.Issuer); CheckJournal(packet.Membership, ProxyPermissionJournal.Membership);
        CheckJournal(packet.Access, ProxyPermissionJournal.Access); CheckJournal(packet.Collection, ProxyPermissionJournal.Collection);
        void CheckJournal<T>(ProxyPermissionSigned<T> signed, ProxyPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            ProxyPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == ProxyPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
