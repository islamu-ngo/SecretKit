using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private optional admission protocol, never an SDK API. Native qualification: ZERO.
// The host pins six independent journal writers before Reserve. The coordinator
// authenticates transport only; it cannot select or replace these verification keys.
// Signed terminal inventories/fences, not a latest GET, settle original dispatch.
// External writer/service/completeness/clock qualification remains an operator gate.
//
// Primary research 2026-10-14: Tavily search found
// https://infisical.com/docs/internals/permissions/migration (V1 edit migration
// adds edit-root-credential AND lease). Tavily extraction returned HTTP 429.
// This does not establish isolated V2 actions, endpoint prerequisite permissions,
// role assignment/copy inheritance, atomicity, denial effects, or cleanup semantics.
// The controlled provider below tests those explicit assumptions, not vendor parity.
internal enum DynamicPermissionAction { Read, Create, Edit, Delete, Lease }
internal enum DynamicPermissionJournal { Ownership, Ingress, Policy, Resources, Issuance, Backend }
internal enum DynamicPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum DynamicPermissionOutcome { Applied, NonApplied, Partial }
internal enum DynamicPermissionSourceKind { NativeProvider, ControlledFixture }
internal enum DynamicPermissionSqlAction { Read, WrongCredential, Write, Recheck }
internal sealed record DynamicPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[DynamicPermissionAuthorities]";
}
internal sealed record DynamicPermissionPin(DynamicPermissionJournal Journal, string Writer, string Channel,
    string Schema, string Spki);
internal sealed record DynamicPermissionProfile(string Deployment, string Epoch, string Revision,
    DynamicPermissionPin[] Pins);
internal sealed record DynamicPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, DynamicPermissionSourceKind Kind,
    DynamicPermissionAction Action, DynamicPermissionAuthorities Authorities, DynamicPermissionProfile Profile)
{
    public override string ToString() => "[DynamicPermissionRoot]";
}
internal sealed record DynamicPermissionHeader(string RootHash, DynamicPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, string Event, long Sequence, string Window);
internal sealed record DynamicPermissionPayload<T>(DynamicPermissionHeader Header, T Content);
internal sealed record DynamicPermissionSigned<T>(DynamicPermissionPayload<T> Payload, string Signature);
internal sealed record DynamicPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record DynamicPermissionBorrowed(string Kind, string Id, string Revision);
internal sealed record DynamicPermissionRow(string Name, string Project, string Slug, string Environment,
    string Path, Guid Folder, Guid Definition, string Window, string Principal, string Control,
    DynamicPermissionAction Action);
internal sealed record DynamicPermissionIssued(string Project, string Slug, string ControlProject, string CopyProject,
    string CopySlug, string PolicyId, string PolicySlug, string Membership, string TemplateId,
    string BaselineRevision, string ProtectedHash, DynamicPermissionRow[] Rows, DynamicPermissionSqlProfile Sql);
internal sealed record DynamicPermissionSqlProfile(NativeSqlEngine Engine, string Host, int Port, string Username,
    string Password, string Database, string Creation, string Revocation)
{
    internal NativeSqlDefinitionProfile Create() => new(Engine, Host, Port, Username, Password, Database, Creation, Revocation);
    public override string ToString() => "[DynamicPermissionSqlProfile]";
}
internal sealed record DynamicPermissionOwner(DynamicPermissionStep Step, bool CollisionChecked, bool PreEnrolled,
    bool Exclusive, bool Terminal, int Pending, int Registrations, DynamicPermissionIssued? Issued,
    DynamicPermissionResource[] Enrolled, DynamicPermissionResource[] Remaining, DynamicPermissionBorrowed[] Borrowed);
internal sealed record DynamicPermissionIngress(string Request, string Principal, string TokenHash,
    string Method, string Path, string BodyHash, string IntentHash, Guid? Definition, bool Bootstrap, bool Authorized);
internal sealed record DynamicPermissionCommit(string Request, string Resource, string PreviousRevision,
    string Revision, string PolicyHash, string Principal, string Project, string? SourceRevision);
internal sealed record DynamicPermissionPolicyState(string Resource, string Principal, string Project,
    string Revision, string PolicyHash);
internal sealed record DynamicPermissionDecision(string Request, string Principal, string TokenHash, string Project,
    Guid Definition, string Revision, DynamicPermissionAction Action, bool Allowed);
internal sealed record DynamicPermissionState(Guid Definition, bool Exists, int Version, string ProfileHash);
internal sealed record DynamicPermissionChange(string Request, DynamicPermissionState Before, DynamicPermissionState After);
internal sealed record DynamicPermissionLease(string Request, string Decision, string Principal, string Project,
    Guid Definition, string Revision, Guid Lease, string MaterialHash);
internal sealed record DynamicPermissionSql(Guid Lease, string MaterialHash, string Principal, string Project,
    DynamicPermissionSqlAction Action, bool Authenticated, bool Allowed, string ProtectedHash);
internal sealed record DynamicPermissionSqlInventory(int Credentials, int ProtectedRows, int Leases, Guid[] LeaseIds);
internal sealed record DynamicPermissionSeal(string ContentHash, int Count, bool Terminal, int Pending);
internal sealed record DynamicPermissionPacket(DynamicPermissionSigned<DynamicPermissionOwner> Owner,
    DynamicPermissionSigned<DynamicPermissionIngress>[] Requests,
    DynamicPermissionSigned<DynamicPermissionCommit>[] Commits,
    DynamicPermissionSigned<DynamicPermissionDecision>[] Decisions,
    DynamicPermissionSigned<DynamicPermissionChange>[] Changes,
    DynamicPermissionSigned<DynamicPermissionLease>[] Leases,
    DynamicPermissionSigned<DynamicPermissionPolicyState[]> Policies,
    DynamicPermissionSigned<DynamicPermissionState[]> Inventory,
    DynamicPermissionSigned<DynamicPermissionSqlInventory> Backend,
    DynamicPermissionSigned<DynamicPermissionSeal>[] Seals);
internal sealed record DynamicPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled,
    string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[DynamicPermissionReceipt]";
}
internal sealed record DynamicPermissionAttempt(DynamicPermissionRow Row, string TokenHash, string? SetupHash,
    SecretStatus Status, DispatchEvidence? Evidence, Guid? Lease, string? MaterialHash);
internal interface IDynamicPermissionSource
{
    string Identity { get; }
    DynamicPermissionSourceKind Kind { get; }
    ValueTask<DynamicPermissionPacket> StepAsync(DynamicPermissionRoot root, DynamicPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
    ValueTask<DynamicPermissionSigned<DynamicPermissionSql>> MeasureAsync(DynamicPermissionRoot root, Guid lease,
        SecretMaterial username, SecretMaterial password, DynamicPermissionSqlAction action, CancellationToken token);
}
internal sealed record DynamicPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    DynamicPermissionProfile Profile, DynamicPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        DynamicPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("dynamicPermission", out _);
    internal static DynamicPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("dynamicPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<DynamicPermissionInput>(DynamicPermissionContract.Options);
            DynamicPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                DynamicPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            DynamicPermissionContract.Validate(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[DynamicPermissionInput]";
}
internal static class DynamicPermissionContract
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
        "i.management.ProjectTemplateOperations.UpdateProjectTemplate"
    ];
    internal static string Wire(DynamicPermissionAction a) => a switch
    {
        DynamicPermissionAction.Read => "read-root-credential",
        DynamicPermissionAction.Create => "create-root-credential",
        DynamicPermissionAction.Edit => "edit-root-credential",
        DynamicPermissionAction.Delete => "delete-root-credential",
        DynamicPermissionAction.Lease => "lease",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(DynamicPermissionAction a) => a switch
    {
        DynamicPermissionAction.Read => ProjectRoleAction.ReadRootCredential,
        DynamicPermissionAction.Create => ProjectRoleAction.CreateRootCredential,
        DynamicPermissionAction.Edit => ProjectRoleAction.EditRootCredential,
        DynamicPermissionAction.Delete => ProjectRoleAction.DeleteRootCredential,
        DynamicPermissionAction.Lease => ProjectRoleAction.Lease,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static bool Template(string op) => op.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string Variant(string op, DynamicPermissionAction a) => "permission.DynamicSecrets." + Wire(a);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<DynamicPermissionAction>().Any(a => Variant(d.Key.Operation, a) == d.Key.Variant) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static DynamicPermissionAction Baseline(DynamicPermissionRoot root) =>
        (DynamicPermissionAction)(((int)root.Action + 1) % 5);
    internal static bool Bootstrap(DynamicPermissionAction a) =>
        a is DynamicPermissionAction.Edit or DynamicPermissionAction.Delete or DynamicPermissionAction.Lease;
    internal static bool Allowed(DynamicPermissionRoot root, DynamicPermissionRow row, bool after,
        DynamicPermissionOutcome outcome) => row.Principal == root.Authorities.Observer ||
        row.Principal == root.Authorities.Runtime && row.Control == "selected" &&
        (after && outcome == DynamicPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string PolicyHash(DynamicPermissionAction a) => Hash(new[] { "dynamic-secrets", Wire(a), "witness", "/" });
    internal static string MaterialHash(string username, string password) => Hash(new[] { username, password });
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] bytes = Bytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string RawHash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static void Require(bool condition, string code = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(code); }
    internal static bool Text(string? value) => value is { Length: > 0 and <= 16384 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Validate(DynamicPermissionProfile profile)
    {
        Require(profile is not null && new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(Text) &&
            profile.Pins.Length == 6 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 6 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && Text(p.Writer) && Text(p.Channel) && Text(p.Schema)) &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 6 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 6, "missing-input");
        var keys = new HashSet<string>();
        foreach (var pin in profile!.Pins)
        {
            using var key = ECDsa.Create();
            byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                keys.Add(RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal static (string Hash, DynamicPermissionHeader[] Headers) Contents(DynamicPermissionPacket packet,
        DynamicPermissionJournal journal) => journal switch
        {
            DynamicPermissionJournal.Ingress => (Hash(packet.Requests.Select(x => x.Payload).ToArray()),
                packet.Requests.Select(x => x.Payload.Header).ToArray()),
            DynamicPermissionJournal.Policy => (Hash(new object[] { packet.Commits.Select(x => x.Payload).ToArray(),
                packet.Decisions.Select(x => x.Payload).ToArray(), packet.Policies.Payload }), packet.Commits.Select(x => x.Payload.Header)
                .Concat(packet.Decisions.Select(x => x.Payload.Header)).Append(packet.Policies.Payload.Header).ToArray()),
            DynamicPermissionJournal.Resources => (Hash(new object[] { packet.Changes.Select(x => x.Payload).ToArray(),
                packet.Inventory.Payload }), packet.Changes.Select(x => x.Payload.Header).Append(packet.Inventory.Payload.Header).ToArray()),
            DynamicPermissionJournal.Issuance => (Hash(packet.Leases.Select(x => x.Payload).ToArray()),
                packet.Leases.Select(x => x.Payload.Header).ToArray()),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
}
internal sealed class DynamicPermissionVerifier : IDisposable
{
    private readonly string hash;
    private readonly Dictionary<DynamicPermissionJournal, (DynamicPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<DynamicPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal DynamicPermissionVerifier(DynamicPermissionRoot root)
    {
        DynamicPermissionContract.Validate(root.Profile);
        hash = DynamicPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(DynamicPermissionSigned<T> signed, DynamicPermissionJournal journal, string window)
    {
        var (pin, key) = keys[journal];
        byte[] bytes = DynamicPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        DynamicPermissionContract.Require(valid);
        var h = signed.Payload.Header;
        DynamicPermissionContract.Require(h.RootHash == hash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == DynamicPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Window == window && DynamicPermissionContract.Text(h.Event) && events.Add(h.Event) &&
            h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
