using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence only; native qualification is zero. Primary interface facts, 2026-10-14:
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/api-reference/endpoints/gateways/create
// https://infisical.com/docs/api-reference/endpoints/gateways/update
// https://infisical.com/docs/api-reference/endpoints/gateways/get
// https://infisical.com/docs/documentation/platform/gateways/gateway-deployment
// Tavily primary extraction and Context7 establish settings, not agent authentication.
// Ownership decision: gateway-owned versioned AWS configuration. The gateway has an
// immutable canonical binding. Native config IDs are OBSERVED revision metadata;
// neither retention nor replacement is a provider allocation guarantee. Every
// superseded revision needs a signed retirement and every active/retired config is
// in complete inventory. An eighth independent writer joins configuration history
// to storage and ingress, including parent, root, request and protected payload hash.
// Separately owned config resources would require an unestablished native lifetime
// contract. No config ID is preselected or added to append-only resource bindings.
// Only explicit AWS account AND principal allowlists are certified offline. No GCP,
// Kubernetes, token, identity, omission/clear, cross-method or agent-auth claims.
// Native revision, complete inventory, retirement and writer independence remain gates.
// Only owned byte arrays are erased, never managed strings or framework/socket data.
internal enum GatewayPermissionAction { Create, Edit, List, Delete, Attach, Revoke }
internal enum GatewayPermissionScope { Project, Organization }
internal enum GatewayPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access, Configuration }
internal enum GatewayPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum GatewayPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record GatewayPermissionPin(GatewayPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record GatewayPermissionProfile(string Deployment, string Epoch, string Revision, GatewayPermissionPin[] Pins);
internal sealed record GatewayPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    GatewayPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, GatewayPermissionAction Action,
    MemberPermissionAuthorities Authorities, GatewayPermissionProfile Profile)
{
    public override string ToString() => "[GatewayPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record GatewayPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record GatewayPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record GatewayPermissionResource(string Intent, string CanonicalId);
internal sealed record GatewayPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record GatewayPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[GatewayPermissionActor]";
}
internal sealed record GatewayPermissionRow(string Key, string Window, string Control, GatewayPermissionAction Action,
    string Organization, string Project, string Target, string Name, int Actor);
internal sealed record GatewayPermissionIssued(GatewayPermissionActor[] Actors, GatewayPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[GatewayPermissionIssued]";
}
internal sealed record GatewayPermissionOwner(GatewayPermissionIntent[] Intents, GatewayPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, GatewayPermissionActor[] Actors);
internal sealed record GatewayPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record GatewayPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role);
internal sealed record GatewayPermissionCommit(string Request, string PreviousRevision, GatewayPermissionPolicy Policy);
internal sealed record GatewayPermissionPolicies(GatewayPermissionPolicy[] Inventory, GatewayPermissionCommit[] Commits);
internal sealed record GatewayPermissionState(string Row, string Target, string Organization, string Project,
    string Name, string ConfigId, string ConfigRevision, string Accounts, string Principals, int Version,
    string ConfigCreatedAt, string ConfigUpdatedAt)
{
    public override string ToString() => "[GatewayPermissionState]";
}
internal sealed record GatewayPermissionRetirement(string Gateway, string ConfigId, string Revision, string Request, string Reason);
internal sealed record GatewayPermissionConfigurationChange(string Root, string Nonce, string Request,
    GatewayPermissionState? Before, GatewayPermissionState? After, GatewayPermissionRetirement? Retirement);
internal sealed record GatewayPermissionConfigurations(GatewayPermissionState[] Inventory,
    GatewayPermissionConfigurationChange[] History, GatewayPermissionRetirement[] Retired);
internal sealed record GatewayPermissionChange(string Request, string Row, GatewayPermissionState? Before, GatewayPermissionState? After);
internal sealed record GatewayPermissionStorage(GatewayPermissionBinding[] Bindings, GatewayPermissionState[] Inventory, GatewayPermissionChange[] Changes, GatewayPermissionConfigurationChange[] ConfigurationHistory);
internal sealed record GatewayPermissionIssuance(GatewayPermissionBinding[] Bindings, GatewayPermissionCredential[] Credentials);
internal sealed record GatewayPermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record GatewayPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, GatewayPermissionAction Action, bool Allowed);
internal sealed record GatewayPermissionHeader(string RootHash, GatewayPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, GatewayPermissionStep Step);
internal sealed record GatewayPermissionPayload<T>(GatewayPermissionHeader Header, T Content);
internal sealed record GatewayPermissionSigned<T>(GatewayPermissionPayload<T> Payload, string Signature);
internal sealed record GatewayPermissionPacket(GatewayPermissionSigned<GatewayPermissionOwner> Owner,
    GatewayPermissionSigned<GatewayPermissionIngress[]> Ingress, GatewayPermissionSigned<GatewayPermissionPolicies> Policy,
    GatewayPermissionSigned<GatewayPermissionStorage> Storage, GatewayPermissionSigned<GatewayPermissionIssuance> Issuer,
    GatewayPermissionSigned<GatewayPermissionJoin[]> Membership, GatewayPermissionSigned<GatewayPermissionAccess[]> Access,
    GatewayPermissionSigned<GatewayPermissionConfigurations> Configuration, GatewayPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record GatewayPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[GatewayPermissionReceipt]";
}
internal sealed record GatewayPermissionAttempt(GatewayPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, GatewayPermissionState? Value, bool Complete, string InputHash);
internal interface IGatewayPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<GatewayPermissionPacket> StepAsync(GatewayPermissionRoot root, GatewayPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record GatewayPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    GatewayPermissionProfile Profile, GatewayPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    GatewayPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        GatewayPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("gatewayPermission", out _);
    internal static GatewayPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("gatewayPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<GatewayPermissionInput>(GatewayPermissionContract.Options);
            GatewayPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            GatewayPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[GatewayPermissionInput]";
}
internal static class GatewayPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Where(op => op.EndsWith("OrganizationRole", StringComparison.Ordinal)).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static GatewayPermissionScope Scope(string operation) => GatewayPermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionActorKind.User;
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static GatewayPermissionAction[] Actions(GatewayPermissionScope scope) => Enum.GetValues<GatewayPermissionAction>();
    internal static string? Gate(GatewayPermissionScope scope, GatewayPermissionAction action) => action switch
    {
        GatewayPermissionAction.Create or GatewayPermissionAction.Edit => null,
        GatewayPermissionAction.List => "missing-typed-gateway-list",
        GatewayPermissionAction.Delete => "missing-typed-gateway-delete",
        GatewayPermissionAction.Attach => "missing-typed-gateway-attach",
        _ => "missing-typed-gateway-revoke"
    };
    internal static GatewayPermissionAction[] Supported(GatewayPermissionScope scope) => [GatewayPermissionAction.Create, GatewayPermissionAction.Edit];
    internal static GatewayPermissionAction Baseline(GatewayPermissionRoot root) => root.Action == GatewayPermissionAction.Create ? GatewayPermissionAction.Edit : GatewayPermissionAction.Create;
    internal static string Wire(GatewayPermissionAction action) => action == GatewayPermissionAction.Revoke ? "revoke-gateway-access" : action.ToString().ToLowerInvariant() + "-gateways";
    internal static string Variant(GatewayPermissionAction action) => "permission.Gateway." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    // Isolated resolver for parent forwarding; missing-seam actions remain selected.
    internal static NativeCaseDefinition? Resolve(NativeCaseDefinition definition, NativeEnvironment env)
    {
        const string prefix = "factory.";
        if (!definition.Key.Variant.StartsWith(prefix, StringComparison.Ordinal)) return null;
        string operation = definition.Key.Variant[prefix.Length..];
        if (!Operations.Contains(operation) || !env.TryGetFamilyInput("C08-IM-" + Family(operation), out var family) ||
            !family.TryGetProperty("scopes", out var scopes) || !scopes.TryGetProperty(definition.Key.Scope, out var scope)) return null;
        var input = GatewayPermissionInput.FromScope(scope);
        return input is null ? null : new(new(definition.Key.Provider, operation, Variant(input.Action), definition.Key.Scope, definition.Key.Case),
            InfisicalPermissionFamilies.Bindings[operation].Member);
    }
    internal static string[] Controls(GatewayPermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(GatewayPermissionRoot root, GatewayPermissionRow row, bool after, GatewayPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == GatewayPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class GatewayPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<GatewayPermissionJournal, (GatewayPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<GatewayPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(GatewayPermissionProfile profile)
    {
        GatewayPermissionContract.Require(profile.Pins.Length == 8 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 8 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 8 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 8 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            GatewayPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(GatewayPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal GatewayPermissionVerifier(GatewayPermissionRoot root)
    {
        Validate(root.Profile); rootHash = GatewayPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(GatewayPermissionSigned<T> value, GatewayPermissionJournal journal, GatewayPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = GatewayPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        GatewayPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == GatewayPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(GatewayPermissionPacket packet, GatewayPermissionStep step)
    {
        GatewayPermissionContract.Require(packet.Seals.Length == 8 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 8);
        CheckJournal(packet.Owner, GatewayPermissionJournal.Ownership); CheckJournal(packet.Ingress, GatewayPermissionJournal.Ingress);
        CheckJournal(packet.Policy, GatewayPermissionJournal.Policy); CheckJournal(packet.Storage, GatewayPermissionJournal.Storage);
        CheckJournal(packet.Issuer, GatewayPermissionJournal.Issuer); CheckJournal(packet.Membership, GatewayPermissionJournal.Membership);
        CheckJournal(packet.Access, GatewayPermissionJournal.Access); CheckJournal(packet.Configuration, GatewayPermissionJournal.Configuration);
        void CheckJournal<T>(GatewayPermissionSigned<T> signed, GatewayPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            GatewayPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == GatewayPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
