using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private source protocol, not a public user provisioning API. Native qualification: zero.
// Primary interface facts: Tavily, 2026-10-14, Infisical project-permissions and
// organization-permissions under https://infisical.com/docs/internals/permissions/.
// Member assumption is temporary impersonation, NOT a grant or a secret read.
// The SDK also lacks user additional privileges, legacy member permission-level
// changes, project member-details editing and organization invitation. Keep their
// 26 pairs/130 cases in discovery; only 32 pairs/160 cases have exact typed seams.
// Project CRUD has no established member-specific restriction. Wrong-member
// joins/returned effects must fail; do not pretend an unconditional policy denies
// another same-project member. Delegation uses the supported userEmail condition.
//
// Trust: seven distinct host-pinned P256 writers attest ownership, authenticated
// ingress, policy storage, resource storage, issuance, membership and decisions.
// Every journal has a terminal seal, including empty journals. Transport identity
// and coordinator signatures cannot replace those writers. Trusted compromised
// writers can still lie; controlled fixtures are not native qualification.
// Reserve enrolls future resources/issuers before creation. Recovery is retained
// before Reserve, keys on the original root, and never needs an Open reply.
// Close fences issuer/ingress work, drains it, removes only enrolled resources,
// and proves zero inventories/registrations plus unchanged borrowed resources.
// Owned byte/character buffers are cleared on every exit. JSON and SDK-created
// managed strings and host socket buffers are not claimed to be erasable.
internal enum MemberPermissionAction { Read, Create, Edit, Delete, GrantPrivileges, AssignRole, AssignAdditionalPrivileges, AssumePrivileges }
internal enum MemberPermissionScope { Project, Organization }
internal enum MemberPermissionActorKind { User, Machine }
internal enum MemberPermissionSourceKind { NativeProvider, ControlledFixture }
internal enum MemberPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access }
internal enum MemberPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum MemberPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record MemberPermissionPin(MemberPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record MemberPermissionProfile(string Deployment, string Epoch, string Revision, MemberPermissionPin[] Pins);
internal sealed record MemberPermissionAuthorities(string Setup, string Runtime, string Denied, string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[MemberPermissionAuthorities]";
}
internal sealed record MemberPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    MemberPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, MemberPermissionAction Action,
    MemberPermissionAuthorities Authorities, MemberPermissionProfile Profile)
{
    public override string ToString() => "[MemberPermissionRoot]";
}
internal sealed record MemberPermissionHeader(string RootHash, MemberPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, MemberPermissionStep Step);
internal sealed record MemberPermissionPayload<T>(MemberPermissionHeader Header, T Content);
internal sealed record MemberPermissionSigned<T>(MemberPermissionPayload<T> Payload, string Signature);
internal sealed record MemberPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record MemberPermissionBorrowed(string Kind, string Id, string Digest);
internal sealed record MemberPermissionPrincipal(string Id, MemberPermissionActorKind Kind, string Username,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned, string OrganizationMembership,
    string ProjectMembership, string CopyMembership)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[MemberPermissionPrincipal]";
}
internal sealed record MemberPermissionUser(string Id, string Username, string Email, string CredentialId, string CredentialHash)
{
    public override string ToString() => "[MemberPermissionUser]";
}
internal sealed record MemberPermissionRow(string Id, string Window, string Control, MemberPermissionAction Action,
    string Organization, string Project, string Membership, MemberPermissionUser User, int Actor)
{
    public override string ToString() => "[MemberPermissionRow]";
}
internal sealed record MemberPermissionIssued(string Project, string ProjectSlug, string OtherProject, string OtherOrganization,
    string CopyProject, string CopySlug, string PolicyId, string PolicySlug, string TemplateId, string AssignedRole,
    string BaselineRevision, MemberPermissionPrincipal[] Principals, MemberPermissionRow[] Rows)
{
    internal void Erase() { foreach (var principal in Principals) principal.Erase(); }
    public override string ToString() => "[MemberPermissionIssued]";
}
internal sealed record MemberPermissionOwner(bool CollisionChecked, bool PreEnrolled, bool Exclusive,
    bool IssuerFence, bool IngressFence, int Pending, int Registrations, MemberPermissionIssued? Issued,
    MemberPermissionResource[] Enrolled, MemberPermissionResource[] Remaining, MemberPermissionBorrowed[] Borrowed);
internal sealed record MemberPermissionIngress(string Request, string ActorId, MemberPermissionActorKind ActorKind,
    string CredentialHash, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase)
{
    public override string ToString() => "[MemberPermissionIngress]";
}
internal sealed record MemberPermissionPolicy(string Resource, string Revision, string ActorId, MemberPermissionActorKind ActorKind,
    string Organization, string Project, string Subject, string[] Actions, string[] Emails, string AssignedRole)
{
    public override string ToString() => "[MemberPermissionPolicy]";
}
internal sealed record MemberPermissionCommit(string Request, string PreviousRevision, MemberPermissionPolicy Policy);
internal sealed record MemberPermissionPolicies(MemberPermissionPolicy[] Inventory, MemberPermissionCommit[] Commits);
internal sealed record MemberPermissionState(string Membership, string User, string Organization, string Project,
    string Username, string Role, bool Active, int Version)
{
    public override string ToString() => "[MemberPermissionState]";
}
internal sealed record MemberPermissionChange(string Request, string Membership, MemberPermissionState? Before, MemberPermissionState? After);
internal sealed record MemberPermissionStorage(MemberPermissionState[] Inventory, MemberPermissionChange[] Changes);
internal sealed record MemberPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind, string Hash, bool Owned)
{
    public override string ToString() => "[MemberPermissionCredential]";
}
internal sealed record MemberPermissionJoin(string Principal, MemberPermissionActorKind Kind, string Organization,
    string Project, string Membership, bool Assigned)
{
    public override string ToString() => "[MemberPermissionJoin]";
}
internal sealed record MemberPermissionAccess(string Request, string ActorId, MemberPermissionActorKind ActorKind,
    string CredentialId, string CredentialHash, string Organization, string Project, string? User, string? Membership,
    string Revision, MemberPermissionAction Action, bool Allowed)
{
    public override string ToString() => "[MemberPermissionAccess]";
}
internal sealed record MemberPermissionSeal(string ContentHash, bool Terminal, int Pending, int Count);
internal sealed record MemberPermissionPacket(MemberPermissionSigned<MemberPermissionOwner> Owner,
    MemberPermissionSigned<MemberPermissionIngress[]> Ingress,
    MemberPermissionSigned<MemberPermissionPolicies> Policy,
    MemberPermissionSigned<MemberPermissionStorage> Storage,
    MemberPermissionSigned<MemberPermissionCredential[]> Issuer,
    MemberPermissionSigned<MemberPermissionJoin[]> Membership,
    MemberPermissionSigned<MemberPermissionAccess[]> Access,
    MemberPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record MemberPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[MemberPermissionReceipt]";
}
internal sealed record MemberPermissionAttempt(MemberPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, MemberPermissionState[] Values, bool Complete);
internal interface IMemberPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<MemberPermissionPacket> StepAsync(MemberPermissionRoot root, MemberPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record MemberPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    MemberPermissionProfile Profile, MemberPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    MemberPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        MemberPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("memberPermission", out _);
    internal static MemberPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("memberPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<MemberPermissionInput>(MemberPermissionContract.Options);
            MemberPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action) &&
                Enum.IsDefined(result.ActorKind) && Enum.IsDefined(result.ScopeProfile), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            MemberPermissionContract.Validate(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[MemberPermissionInput]";
}
internal static class MemberPermissionContract
{
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    {
        IgnoreReadOnlyProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };
    internal static readonly string[] Operations =
    [
        "i.management.IdentityPrivilegeChangeOperations.CreateProjectPrivilege",
        "i.management.IdentityPrivilegeChangeOperations.UpdateProjectPrivilege",
        "i.management.RoleChangeOperations.CreateProjectRole",
        "i.management.RoleChangeOperations.UpdateProjectRole",
        "i.management.ProjectTemplateOperations.CreateProjectTemplate",
        "i.management.ProjectTemplateOperations.UpdateProjectTemplate",
        "i.management.RoleChangeOperations.CreateOrganizationRole",
        "i.management.RoleChangeOperations.UpdateOrganizationRole"
    ];
    internal static readonly string[] Boundaries = ["selected-contract", "denied-authority", "cancellation-boundary",
        "independent-effect", "lost-response-no-replay"];
    internal static MemberPermissionScope Scope(string op) => op switch
    {
        "i.management.RoleChangeOperations.CreateOrganizationRole" or "i.management.RoleChangeOperations.UpdateOrganizationRole" =>
            MemberPermissionScope.Organization,
        _ when Operations.Contains(op) => MemberPermissionScope.Project,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static MemberPermissionActorKind ActorKind(string op) => op switch
    {
        "i.management.IdentityPrivilegeChangeOperations.CreateProjectPrivilege" or
        "i.management.IdentityPrivilegeChangeOperations.UpdateProjectPrivilege" => MemberPermissionActorKind.Machine,
        _ when Operations.Contains(op) => MemberPermissionActorKind.User,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static bool Template(string op) => op is
        "i.management.ProjectTemplateOperations.CreateProjectTemplate" or "i.management.ProjectTemplateOperations.UpdateProjectTemplate";
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string Family(string op) => Template(op) ? "ProjectTemplates" :
        ActorKind(op) == MemberPermissionActorKind.Machine ? "IdentityPrivilegeChanges" : "RoleChanges";
    internal static MemberPermissionAction[] Actions(MemberPermissionScope scope) => scope == MemberPermissionScope.Project ?
        Enum.GetValues<MemberPermissionAction>() :
        [MemberPermissionAction.Read, MemberPermissionAction.Create, MemberPermissionAction.Edit,
            MemberPermissionAction.Delete, MemberPermissionAction.GrantPrivileges];
    internal static string? Gate(MemberPermissionScope scope, MemberPermissionAction action) => (scope, action) switch
    {
        (MemberPermissionScope.Project, MemberPermissionAction.Edit) => "typed-project-member-details-unavailable",
        (MemberPermissionScope.Project, MemberPermissionAction.GrantPrivileges) => "typed-member-permission-level-unavailable",
        (MemberPermissionScope.Project, MemberPermissionAction.AssignAdditionalPrivileges) => "typed-user-additional-privileges-unavailable",
        (MemberPermissionScope.Project, MemberPermissionAction.AssumePrivileges) => "typed-member-assumption-unavailable",
        (MemberPermissionScope.Organization, MemberPermissionAction.Create) => "typed-organization-invitation-unavailable",
        _ => null
    };
    internal static MemberPermissionAction[] Supported(MemberPermissionScope scope) =>
        Actions(scope).Where(a => Gate(scope, a) is null).ToArray();
    internal static MemberPermissionAction Baseline(MemberPermissionRoot root)
    {
        var actions = Supported(root.ScopeProfile);
        return actions[(Array.IndexOf(actions, root.Action) + 1) % actions.Length];
    }
    internal static string Wire(MemberPermissionAction action) => action switch
    {
        MemberPermissionAction.Read => "read",
        MemberPermissionAction.Create => "create",
        MemberPermissionAction.Edit => "edit",
        MemberPermissionAction.Delete => "delete",
        MemberPermissionAction.GrantPrivileges => "grant-privileges",
        MemberPermissionAction.AssignRole => "assign-role",
        MemberPermissionAction.AssignAdditionalPrivileges => "assign-additional-privileges",
        MemberPermissionAction.AssumePrivileges => "assume-privileges",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(MemberPermissionAction action) => action switch
    {
        MemberPermissionAction.Read => ProjectRoleAction.Read,
        MemberPermissionAction.Create => ProjectRoleAction.Create,
        MemberPermissionAction.Edit => ProjectRoleAction.Edit,
        MemberPermissionAction.Delete => ProjectRoleAction.Delete,
        MemberPermissionAction.GrantPrivileges => ProjectRoleAction.GrantPrivileges,
        MemberPermissionAction.AssignRole => ProjectRoleAction.AssignRole,
        MemberPermissionAction.AssignAdditionalPrivileges => ProjectRoleAction.AssignAdditionalPrivileges,
        MemberPermissionAction.AssumePrivileges => ProjectRoleAction.AssumePrivileges,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static OrganizationRoleAction OrganizationSdk(MemberPermissionAction action) => action switch
    {
        MemberPermissionAction.Read => OrganizationRoleAction.Read,
        MemberPermissionAction.Create => OrganizationRoleAction.Create,
        MemberPermissionAction.Edit => OrganizationRoleAction.Edit,
        MemberPermissionAction.Delete => OrganizationRoleAction.Delete,
        MemberPermissionAction.GrantPrivileges => OrganizationRoleAction.GrantPrivileges,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string Variant(MemberPermissionAction action) => "permission.Member." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) &&
        Boundaries.Contains(d.Key.Case) && (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(MemberPermissionAction action) => action == MemberPermissionAction.AssignRole ?
        ["selected", "scope", "actor", "kind", "credential", "member"] : ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(MemberPermissionRoot root, MemberPermissionRow row, bool after, MemberPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == MemberPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static MemberPermissionState Initial(MemberPermissionRow row) =>
        new(row.Membership, row.User.Id, row.Organization, row.Project, row.User.Username, "no-access", true, 1);
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] bytes = Bytes(value);
        try { return RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string RawHash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static bool Text(string? value) => value is { Length: > 0 and <= 16384 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
    internal static void Validate(MemberPermissionProfile profile)
    {
        int count = Enum.GetValues<MemberPermissionJournal>().Length;
        Require(profile is not null && new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(Text) &&
            profile.Pins.Length == count && profile.Pins.Select(p => p.Journal).Distinct().Count() == count &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && Text(p.Writer) && Text(p.Channel) && Text(p.Schema)) &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == count &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == count, "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile!.Pins)
        {
            using var key = ECDsa.Create();
            byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
}
internal sealed class MemberPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<MemberPermissionJournal, (MemberPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<MemberPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal MemberPermissionVerifier(MemberPermissionRoot root)
    {
        MemberPermissionContract.Validate(root.Profile);
        rootHash = MemberPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(MemberPermissionSigned<T> signed, MemberPermissionJournal journal, MemberPermissionStep step)
    {
        var (pin, key) = keys[journal];
        byte[] bytes = MemberPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = signed.Payload.Header;
        MemberPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal &&
            h.Writer == pin.Writer && h.Channel == pin.Channel && h.Schema == pin.Schema &&
            h.KeyHash == MemberPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) && h.Step == step &&
            h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    internal T Journal<T>(MemberPermissionSigned<T> signed, MemberPermissionPacket packet,
        MemberPermissionJournal journal, MemberPermissionStep step)
    {
        T content = Verify(signed, journal, step);
        var seals = packet.Seals.Where(s => s.Payload.Header.Journal == journal).ToArray();
        MemberPermissionContract.Require(seals.Length == 1);
        var seal = Verify(seals[0], journal, step);
        MemberPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 &&
            seal.ContentHash == MemberPermissionContract.Hash(signed.Payload));
        return content;
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
