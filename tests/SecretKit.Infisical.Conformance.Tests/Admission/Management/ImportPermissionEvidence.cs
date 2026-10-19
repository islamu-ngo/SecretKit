using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private optional admission protocol; native qualification: ZERO.
// Host-pinned writers authenticate entire typed content and terminal inventories.
// Coordinator transport labels cannot authenticate journals. Original root/nonce
// recovery precedes Reserve/Open. No latest GET, replay, or receipt rewriting.
// Primary facts (Tavily, 2026-10-14): Infisical project-permissions documents
// secret-imports read/create/edit/delete, environment and secretPath conditions.
// Import endpoints retain receiver coordinates, source environment/path, IDs and position.
// No docs establish isolated-action prerequisites, parent-versus-child permission
// evaluation, atomicity, template inheritance or recovery completeness. Controlled
// assumptions below do not establish vendor parity, entitlement or deployment.
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/api-reference/endpoints/secret-imports/create
// https://infisical.com/docs/api-reference/endpoints/secret-imports/update
// https://infisical.com/docs/api-reference/endpoints/secret-imports/list
// Additional secret-read prerequisites are UNQUALIFIED. No runtime material grant
// is made; protected imported material is calibrated only under fixture setup/observer
// authority. No approval, replication delivery, inheritance or atomicity is claimed.
internal enum ImportPermissionAction { Read, Create, Edit, Delete }
internal enum ImportPermissionJournal { Ownership, Ingress, Policy, Resources, Issuance }
internal enum ImportPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum ImportPermissionOutcome { Applied, NonApplied, Partial }
internal enum ImportPermissionSourceKind { NativeProvider, ControlledFixture }
internal sealed record ImportPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[ImportPermissionAuthorities]";
}
internal sealed record ImportPermissionPin(ImportPermissionJournal Journal, string Writer, string Channel,
    string Schema, string Spki);
internal sealed record ImportPermissionProfile(string Deployment, string Epoch, string Revision,
    ImportPermissionPin[] Pins);
internal sealed record ImportPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, ImportPermissionSourceKind Kind,
    ImportPermissionAction Action, ImportPermissionAuthorities Authorities, ImportPermissionProfile Profile)
{
    public override string ToString() => "[ImportPermissionRoot]";
}
internal sealed record ImportPermissionHeader(string RootHash, ImportPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, string Event, long Sequence, string Window);
internal sealed record ImportPermissionPayload<T>(ImportPermissionHeader Header, T Content);
internal sealed record ImportPermissionSigned<T>(ImportPermissionPayload<T> Payload, string Signature);
internal sealed record ImportPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record ImportPermissionBorrowed(string Kind, string Id, string Revision);
internal sealed record ImportPermissionRow(string Name, string Project, string Slug, string Environment,
    string Path, Guid EnvironmentId, Guid Id, string Window, string Principal, string Control,
    ImportPermissionAction Action, bool List, Guid FolderId, Guid SourceFolderId, Guid ChangedSourceFolderId);
internal sealed record ImportPermissionIssued(string Project, string Slug, string ControlProject, string CopyProject,
    string CopySlug, string PolicyId, string PolicySlug, string Membership, string TemplateId,
    string BaselineRevision, ImportPermissionRow[] Rows);
internal sealed record ImportPermissionOwner(ImportPermissionStep Step, bool CollisionChecked, bool PreEnrolled,
    bool Exclusive, bool Terminal, int Pending, int Registrations, ImportPermissionIssued? Issued,
    ImportPermissionResource[] Enrolled, ImportPermissionResource[] Remaining, ImportPermissionBorrowed[] Borrowed);
internal sealed record ImportPermissionIngress(string Request, string Principal, string TokenHash,
    string Method, string Path, string BodyHash, string IntentHash, Guid? Folder, bool Bootstrap, bool Authorized);
internal sealed record ImportPermissionCommit(string Request, string Resource, string PreviousRevision,
    string Revision, string PolicyHash, string Principal, string Project, string? SourceRevision);
internal sealed record ImportPermissionPolicyState(string Resource, string Principal, string Project,
    string Revision, string PolicyHash);
internal sealed record ImportPermissionDecision(string Request, string Principal, string TokenHash, string Project,
    Guid Folder, string Revision, ImportPermissionAction Action, bool Allowed);
internal sealed record ImportPermissionValue(Guid Id, Guid FolderId, string SourceEnvironment, string SourcePath,
    string SourceProject, double Position, bool? Replication, bool? ReplicationSuccess, string? ReplicationStatus,
    DateTimeOffset? LastReplicated);
internal sealed record ImportPermissionSourceState(Guid FolderId, string Project, string Environment, string Path,
    string Key, string MaterialHash, string Root, string Nonce);
internal sealed record ImportPermissionReceiver(Guid FolderId, string Project, string Environment, string Path);
internal sealed record ImportPermissionState(Guid Folder, bool Exists, int Version, ImportPermissionValue? Value);
internal sealed record ImportPermissionChange(string Request, ImportPermissionState Before, ImportPermissionState After);
internal sealed record ImportPermissionSeal(string ContentHash, int Count, bool Terminal, int Pending);
internal sealed record ImportPermissionPacket(ImportPermissionSigned<ImportPermissionOwner> Owner,
    ImportPermissionSigned<ImportPermissionIngress>[] Requests,
    ImportPermissionSigned<ImportPermissionCommit>[] Commits,
    ImportPermissionSigned<ImportPermissionDecision>[] Decisions,
    ImportPermissionSigned<ImportPermissionChange>[] Changes,
    ImportPermissionSigned<ImportPermissionPolicyState[]> Policies,
    ImportPermissionSigned<ImportPermissionState[]> Inventory,
    ImportPermissionSigned<ImportPermissionSourceState[]> Sources,
    ImportPermissionSigned<ImportPermissionReceiver[]> Receivers,
    ImportPermissionSigned<ImportPermissionSeal>[] Seals);
internal sealed record ImportPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled,
    string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[ImportPermissionReceipt]";
}
internal sealed record ImportPermissionAttempt(ImportPermissionRow Row, string TokenHash, string? SetupHash,
    SecretStatus Status, DispatchEvidence? Evidence, ImportPermissionValue[] Values, bool Complete);
internal interface IImportPermissionSource
{
    string Identity { get; }
    ImportPermissionSourceKind Kind { get; }
    ValueTask<ImportPermissionPacket> StepAsync(ImportPermissionRoot root, ImportPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record ImportPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    ImportPermissionProfile Profile, ImportPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        ImportPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("importPermission", out _);
    internal static ImportPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("importPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<ImportPermissionInput>(ImportPermissionContract.Options);
            ImportPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                ImportPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            ImportPermissionContract.Validate(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[ImportPermissionInput]";
}
internal static class ImportPermissionContract
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
    internal static string SourcePath(ImportPermissionRow row, bool changed) =>
        (changed ? "/changed-" : "/source-") + row.Id.ToString("N");
    internal static byte[] Material(ImportPermissionRoot root, ImportPermissionRow row, bool changed) =>
        System.Text.Encoding.UTF8.GetBytes(root.Nonce + ":" + row.Id + ":" + (changed ? "source-b" : "source-a"));
    internal static string MaterialHash(ImportPermissionRoot root, ImportPermissionRow row, bool changed)
    {
        byte[] bytes = Material(root, row, changed);
        try { return RawHash(bytes); } finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string Wire(ImportPermissionAction a) => a switch
    {
        ImportPermissionAction.Read => "read",
        ImportPermissionAction.Create => "create",
        ImportPermissionAction.Edit => "edit",
        ImportPermissionAction.Delete => "delete",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(ImportPermissionAction a) => a switch
    {
        ImportPermissionAction.Read => ProjectRoleAction.Read,
        ImportPermissionAction.Create => ProjectRoleAction.Create,
        ImportPermissionAction.Edit => ProjectRoleAction.Edit,
        ImportPermissionAction.Delete => ProjectRoleAction.Delete,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static bool Template(string op) => op.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string Variant(string op, ImportPermissionAction a) => "permission.SecretImports." + Wire(a);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<ImportPermissionAction>().Any(a => Variant(d.Key.Operation, a) == d.Key.Variant) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static ImportPermissionAction Baseline(ImportPermissionRoot root) =>
        (ImportPermissionAction)(((int)root.Action + 1) % 4);
    internal static bool Allowed(ImportPermissionRoot root, ImportPermissionRow row, bool after,
        ImportPermissionOutcome outcome) => row.Principal == root.Authorities.Setup ||
        row.Principal == root.Authorities.Observer ||
        row.Principal == root.Authorities.Runtime && row.Control == "selected" &&
        (after && outcome == ImportPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string PolicyHash(ImportPermissionAction a) => Hash(new[] { "secret-imports", Wire(a), "witness", "/" });
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
    internal static void Validate(ImportPermissionProfile profile)
    {
        Require(profile is not null && new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(Text) &&
            profile.Pins.Length == 5 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 5 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && Text(p.Writer) && Text(p.Channel) && Text(p.Schema)) &&
            profile.Pins.Select(p => p.Writer).Distinct().Count() == 5 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 5, "missing-input");
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
    internal static (string Hash, ImportPermissionHeader[] Headers) Contents(ImportPermissionPacket packet,
        ImportPermissionJournal journal) => journal switch
        {
            ImportPermissionJournal.Ingress => (Hash(packet.Requests.Select(x => x.Payload).ToArray()),
                packet.Requests.Select(x => x.Payload.Header).ToArray()),
            ImportPermissionJournal.Policy => (Hash(new object[] { packet.Commits.Select(x => x.Payload).ToArray(),
                packet.Decisions.Select(x => x.Payload).ToArray(), packet.Policies.Payload }), packet.Commits.Select(x => x.Payload.Header)
                .Concat(packet.Decisions.Select(x => x.Payload.Header)).Append(packet.Policies.Payload.Header).ToArray()),
            ImportPermissionJournal.Resources => (Hash(new object[] { packet.Changes.Select(x => x.Payload).ToArray(),
                packet.Inventory.Payload, packet.Sources.Payload, packet.Receivers.Payload }), packet.Changes.Select(x => x.Payload.Header)
                .Append(packet.Inventory.Payload.Header).Append(packet.Sources.Payload.Header).Append(packet.Receivers.Payload.Header).ToArray()),
            ImportPermissionJournal.Issuance => (Hash(Array.Empty<ImportPermissionHeader>()), []),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
}
internal sealed class ImportPermissionVerifier : IDisposable
{
    private readonly string hash;
    private readonly Dictionary<ImportPermissionJournal, (ImportPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<ImportPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal ImportPermissionVerifier(ImportPermissionRoot root)
    {
        ImportPermissionContract.Validate(root.Profile);
        hash = ImportPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(ImportPermissionSigned<T> signed, ImportPermissionJournal journal, string window)
    {
        var (pin, key) = keys[journal];
        byte[] bytes = ImportPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        ImportPermissionContract.Require(valid);
        var h = signed.Payload.Header;
        ImportPermissionContract.Require(h.RootHash == hash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == ImportPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Window == window && ImportPermissionContract.Text(h.Event) && events.Add(h.Event) &&
            h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
