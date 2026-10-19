using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence is not native qualification. Official interface facts retrieved
// with Tavily on 2026-10-14; no vendor implementation was used.
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/documentation/platform/identities/machine-identities
// https://infisical.com/docs/api-reference/endpoints/identities/get-by-id
// https://infisical.com/docs/api-reference/endpoints/identities/create
// https://infisical.com/docs/api-reference/endpoints/identities/update
// https://infisical.com/docs/api-reference/endpoints/identities/delete
// https://infisical.com/docs/api-reference/endpoints/project-identities/update-identity
// https://infisical.com/docs/api-reference/endpoints/project-identities-membership/get-by-id
// https://infisical.com/docs/api-reference/endpoints/project-identities-membership/add-identity-membership
// https://infisical.com/docs/api-reference/endpoints/project-identities-membership/update-identity-membership
// https://infisical.com/docs/api-reference/endpoints/project-identities-membership/delete-identity-membership
// https://infisical.com/docs/documentation/platform/access-controls/additional-privileges
// https://infisical.com/docs/api-reference/endpoints/identity-specific-privilege/v2/create
// https://infisical.com/docs/api-reference/endpoints/token-auth/update
// https://infisical.com/docs/api-reference/endpoints/token-auth/revoke
// https://infisical.com/docs/api-reference/endpoints/token-auth/create-token
// https://infisical.com/docs/api-reference/endpoints/token-auth/get-tokens
// https://infisical.com/docs/api-reference/endpoints/token-auth/revoke-token
// Project create adds existing identity membership. Edit changes project-managed
// identity details. Org edit changes name; org grant changes role. Additional
// privileges use the documented V2 create endpoint. Legacy grant and assumption
// have no established exact authorization equivalence here: retain explicit gates.
// Typed mapping (IdentityPermissionClient is the executable selection):
// project read/create/delete/assign-role -> MembershipOperations.GetProjectIdentityMembership/
// AddProjectIdentity/RemoveProjectIdentity/UpdateProjectIdentityRoles;
// project edit -> IdentityOperations.UpdateProjectIdentity;
// project assign-additional-privileges -> IdentityPrivilegeChangeOperations.CreateProjectPrivilege.
// organization read/create/edit/delete/grant-privileges -> IdentityOperations
// GetOrganizationIdentity/CreateOrganizationIdentity/UpdateOrganizationIdentity(name)/
// DeleteOrganizationIdentity/UpdateOrganizationIdentity(role).
// both scopes revoke-auth/edit-auth/create-token/get-token/delete-token ->
// IdentityAuthenticationOperations.DeleteTokenAuth/UpdateTokenAuth/CreateToken/ListTokens/RevokeToken.
// 86 supported pairs/430 cases; 12 gated pairs/60 cases; all 98/490 retained.
// Token auth routes resolve authority from the identity's native owning scope,
// never from a name selector or a client-provided project header.
// Actor credential inventory is immutable. Target tokens have a separate causal
// append/transition journal, private capture and actual SDK authentication probes.
// Nine distinct host-pinned P256 writers sign whole contents and terminal seals.
// Authentication evidence does not substitute for action authorization evidence.
// Compromised pinned writers remain a trust assumption. Buffers are erased, not
// immutable framework strings, sockets or remote provider storage.
internal enum IdentityPermissionAction { Read, Create, Edit, Delete, GrantPrivileges, AssignRole, AssignAdditionalPrivileges, AssumePrivileges, RevokeAuth, EditAuth, CreateToken, GetToken, DeleteToken }
internal enum IdentityPermissionScope { Project, Organization }
internal enum IdentityPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access, Capture, TokenState }
internal enum IdentityPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum IdentityPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record IdentityPermissionPin(IdentityPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record IdentityPermissionProfile(string Deployment, string Epoch, string Revision, IdentityPermissionPin[] Pins);
internal sealed record IdentityPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    IdentityPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, IdentityPermissionAction Action,
    MemberPermissionAuthorities Authorities, IdentityPermissionProfile Profile)
{
    public override string ToString() => "[IdentityPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record IdentityPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record IdentityPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record IdentityPermissionResource(string Intent, string CanonicalId);
internal sealed record IdentityPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record IdentityPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[IdentityPermissionActor]";
}
internal sealed record IdentityPermissionRow(string Key, string Window, string Control, IdentityPermissionAction Action,
    string Organization, string Project, string Identity, string Name, string Membership, string Auth, string Token,
    string Canary, string ReadPolicy, string Privilege, int Actor);
internal sealed record IdentityPermissionTarget(string Row, string Token, byte[] Material)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Material);
    public override string ToString() => "[IdentityPermissionTarget]";
}
internal sealed record IdentityPermissionIssued(IdentityPermissionActor[] Actors, IdentityPermissionBinding[] Bindings, IdentityPermissionTarget[] Targets)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); foreach (var target in Targets) target.Erase(); }
    public override string ToString() => "[IdentityPermissionIssued]";
}
internal sealed record IdentityPermissionOwner(IdentityPermissionIntent[] Intents, IdentityPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, IdentityPermissionActor[] Actors, IdentityPermissionTarget[] Targets, bool CaptureFence, bool AccessFence);
internal sealed record IdentityPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record IdentityPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role);
internal sealed record IdentityPermissionCommit(string Request, string PreviousRevision, IdentityPermissionPolicy Policy);
internal sealed record IdentityPermissionReadPolicy(string Id, string Principal, string Organization, string Project,
    string Canary, string Subject, string Action);
internal sealed record IdentityPermissionPolicies(IdentityPermissionPolicy[] Inventory, IdentityPermissionCommit[] Commits,
    IdentityPermissionReadPolicy[] TargetReads);
internal sealed record IdentityPermissionState(string Row, string Identity, string Membership, string Organization,
    string Project, string Name, string Role, string Auth, int Ttl, string Privilege, int Version)
{
    public string DelegatedPermission { get; init; } = "";
}
internal sealed record IdentityPermissionChange(string Request, string Row, IdentityPermissionState? Before, IdentityPermissionState? After);
internal sealed record IdentityPermissionStorage(IdentityPermissionBinding[] Bindings, IdentityPermissionState[] Inventory,
    IdentityPermissionChange[] Changes, IdentityPermissionToken[] Tokens);
internal sealed record IdentityPermissionIssuance(IdentityPermissionBinding[] Bindings, IdentityPermissionCredential[] Credentials,
    IdentityPermissionTokenIssue[] Tokens);
internal sealed record IdentityPermissionJoin(string Principal, string Kind, string Organization,
    string Project, string Membership, bool Assigned);
internal sealed record IdentityPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Identity, string Membership,
    string Revision, IdentityPermissionAction Action, bool Allowed);
internal enum IdentityPermissionAuthentication { Authenticated, InvalidToken, ScopeDenied }
internal sealed record IdentityPermissionTokenIssue(string Row, string Intent, string Token, string Identity, string Organization,
    string Project, string Auth, string Request, string Commit, string Hash);
internal sealed record IdentityPermissionToken(string Id, string Issue, bool Revoked, string Transition);
internal sealed record IdentityPermissionCapture(string Row, string Token, string Request, string Hash, bool Released);
internal sealed record IdentityPermissionAuthenticationEvent(string Request, string Token, string Hash, string Identity,
    string Organization, string Project, string Canary, string Policy, string Phase, IdentityPermissionAuthentication Result, int HttpStatus);
internal sealed record IdentityPermissionAccessJournal(IdentityPermissionAccess[] Decisions, IdentityPermissionAuthenticationEvent[] Authentication);
internal sealed record IdentityPermissionTokenJournal(IdentityPermissionToken[] Inventory, IdentityPermissionAuthenticationEvent[] Access,
    bool IssuerDrained, bool CaptureDrained, bool AccessDrained);
internal sealed record IdentityPermissionHeader(string RootHash, IdentityPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, IdentityPermissionStep Step);
internal sealed record IdentityPermissionPayload<T>(IdentityPermissionHeader Header, T Content);
internal sealed record IdentityPermissionSigned<T>(IdentityPermissionPayload<T> Payload, string Signature);
internal sealed record IdentityPermissionPacket(IdentityPermissionSigned<IdentityPermissionOwner> Owner,
    IdentityPermissionSigned<IdentityPermissionIngress[]> Ingress, IdentityPermissionSigned<IdentityPermissionPolicies> Policy,
    IdentityPermissionSigned<IdentityPermissionStorage> Storage, IdentityPermissionSigned<IdentityPermissionIssuance> Issuer,
    IdentityPermissionSigned<IdentityPermissionJoin[]> Membership, IdentityPermissionSigned<IdentityPermissionAccessJournal> Access,
    IdentityPermissionSigned<IdentityPermissionCapture[]> Capture, IdentityPermissionSigned<IdentityPermissionTokenJournal> TokenState,
    IdentityPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record IdentityPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[IdentityPermissionReceipt]";
}
internal sealed record IdentityPermissionAttempt(IdentityPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, string Identity, string Membership, string Name, string Value, bool Complete, string IntentHash);
internal interface IIdentityPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask CaptureAsync(IdentityPermissionRoot root, string row, string tokenId, SecretMaterial material, CancellationToken token);
    ValueTask<IdentityPermissionPacket> StepAsync(IdentityPermissionRoot root, IdentityPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record IdentityPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    IdentityPermissionProfile Profile, IdentityPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    IdentityPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        IdentityPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("identityPermission", out _);
    internal static IdentityPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("identityPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<IdentityPermissionInput>(IdentityPermissionContract.Options);
            IdentityPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            IdentityPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[IdentityPermissionInput]";
}
internal static class IdentityPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static IdentityPermissionScope Scope(string operation) => MemberPermissionContract.Scope(operation) ==
        MemberPermissionScope.Project ? IdentityPermissionScope.Project : IdentityPermissionScope.Organization;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static IdentityPermissionAction[] Actions(IdentityPermissionScope scope) => Enum.GetValues<IdentityPermissionAction>()
        .Where(a => scope == IdentityPermissionScope.Project || a is not (IdentityPermissionAction.AssignRole or
            IdentityPermissionAction.AssignAdditionalPrivileges or IdentityPermissionAction.AssumePrivileges)).ToArray();
    internal static string? Gate(IdentityPermissionScope scope, IdentityPermissionAction action) => (scope, action) switch
    {
        (IdentityPermissionScope.Project, IdentityPermissionAction.GrantPrivileges) => "legacy-identity-grant-equivalence-unavailable",
        (_, IdentityPermissionAction.AssumePrivileges) => "typed-identity-assumption-unavailable",
        _ => null
    };
    internal static bool TokenAction(IdentityPermissionAction action) => action is IdentityPermissionAction.RevokeAuth or
        IdentityPermissionAction.EditAuth or IdentityPermissionAction.CreateToken or IdentityPermissionAction.GetToken or IdentityPermissionAction.DeleteToken;
    internal static IdentityPermissionAction[] Supported(IdentityPermissionScope scope) => Actions(scope).Where(a => Gate(scope, a) is null).ToArray();
    internal static IdentityPermissionAction Baseline(IdentityPermissionRoot root)
    {
        var actions = Supported(root.ScopeProfile);
        return actions[(Array.IndexOf(actions, root.Action) + 1) % actions.Length];
    }
    internal static string Wire(IdentityPermissionAction action) => action switch
    {
        IdentityPermissionAction.Read => "read",
        IdentityPermissionAction.Create => "create",
        IdentityPermissionAction.Edit => "edit",
        IdentityPermissionAction.Delete => "delete",
        IdentityPermissionAction.GrantPrivileges => "grant-privileges",
        IdentityPermissionAction.AssignRole => "assign-role",
        IdentityPermissionAction.AssignAdditionalPrivileges => "assign-additional-privileges",
        IdentityPermissionAction.AssumePrivileges => "assume-privileges",
        IdentityPermissionAction.RevokeAuth => "revoke-auth",
        IdentityPermissionAction.EditAuth => "edit-auth",
        IdentityPermissionAction.CreateToken => "create-token",
        IdentityPermissionAction.GetToken => "get-token",
        IdentityPermissionAction.DeleteToken => "delete-token",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string Variant(IdentityPermissionAction action) => "permission.Identity." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(IdentityPermissionAction action) => action == IdentityPermissionAction.AssignRole ?
        ["selected", "scope", "actor", "kind", "credential", "target", "role"] : action == IdentityPermissionAction.AssignAdditionalPrivileges ?
        ["selected", "scope", "actor", "kind", "credential", "target", "subject", "action"] : ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(IdentityPermissionRoot root, IdentityPermissionRow row, bool after, IdentityPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == IdentityPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class IdentityPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<IdentityPermissionJournal, (IdentityPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<IdentityPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(IdentityPermissionProfile profile)
    {
        IdentityPermissionContract.Require(profile.Pins.Length == 9 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 9 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 9 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 9 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            IdentityPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(IdentityPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal IdentityPermissionVerifier(IdentityPermissionRoot root)
    {
        Validate(root.Profile); rootHash = IdentityPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(IdentityPermissionSigned<T> value, IdentityPermissionJournal journal, IdentityPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = IdentityPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        IdentityPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == IdentityPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(IdentityPermissionPacket packet, IdentityPermissionStep step)
    {
        IdentityPermissionContract.Require(packet.Seals.Length == 9 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 9);
        CheckJournal(packet.Owner, IdentityPermissionJournal.Ownership); CheckJournal(packet.Ingress, IdentityPermissionJournal.Ingress);
        CheckJournal(packet.Policy, IdentityPermissionJournal.Policy); CheckJournal(packet.Storage, IdentityPermissionJournal.Storage);
        CheckJournal(packet.Issuer, IdentityPermissionJournal.Issuer); CheckJournal(packet.Membership, IdentityPermissionJournal.Membership);
        CheckJournal(packet.Access, IdentityPermissionJournal.Access);
        CheckJournal(packet.Capture, IdentityPermissionJournal.Capture); CheckJournal(packet.TokenState, IdentityPermissionJournal.TokenState);
        void CheckJournal<T>(IdentityPermissionSigned<T> signed, IdentityPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            IdentityPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == IdentityPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
