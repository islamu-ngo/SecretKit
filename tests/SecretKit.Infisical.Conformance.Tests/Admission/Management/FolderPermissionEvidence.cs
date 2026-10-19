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
// secret-folders read/create/edit/delete, environment and secretPath conditions.
// Folder endpoint docs establish IDs, names, descriptions and envId inventories.
// No docs establish isolated-action prerequisites, parent-versus-child permission
// evaluation, atomicity, template inheritance or recovery completeness. Controlled
// assumptions below do not establish vendor parity, entitlement or deployment.
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/api-reference/endpoints/folders/list
internal enum FolderPermissionAction { Read, Create, Edit, Delete }
internal enum FolderPermissionJournal { Ownership, Ingress, Policy, Resources, Issuance }
internal enum FolderPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum FolderPermissionOutcome { Applied, NonApplied, Partial }
internal enum FolderPermissionSourceKind { NativeProvider, ControlledFixture }
internal sealed record FolderPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[FolderPermissionAuthorities]";
}
internal sealed record FolderPermissionPin(FolderPermissionJournal Journal, string Writer, string Channel,
    string Schema, string Spki);
internal sealed record FolderPermissionProfile(string Deployment, string Epoch, string Revision,
    FolderPermissionPin[] Pins);
internal sealed record FolderPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, FolderPermissionSourceKind Kind,
    FolderPermissionAction Action, FolderPermissionAuthorities Authorities, FolderPermissionProfile Profile)
{
    public override string ToString() => "[FolderPermissionRoot]";
}
internal sealed record FolderPermissionHeader(string RootHash, FolderPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, string Event, long Sequence, string Window);
internal sealed record FolderPermissionPayload<T>(FolderPermissionHeader Header, T Content);
internal sealed record FolderPermissionSigned<T>(FolderPermissionPayload<T> Payload, string Signature);
internal sealed record FolderPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record FolderPermissionBorrowed(string Kind, string Id, string Revision);
internal sealed record FolderPermissionRow(string Name, string Project, string Slug, string Environment,
    string Path, Guid EnvironmentId, Guid Id, string Window, string Principal, string Control,
    FolderPermissionAction Action, bool List);
internal sealed record FolderPermissionIssued(string Project, string Slug, string ControlProject, string CopyProject,
    string CopySlug, string PolicyId, string PolicySlug, string Membership, string TemplateId,
    string BaselineRevision, FolderPermissionRow[] Rows);
internal sealed record FolderPermissionOwner(FolderPermissionStep Step, bool CollisionChecked, bool PreEnrolled,
    bool Exclusive, bool Terminal, int Pending, int Registrations, FolderPermissionIssued? Issued,
    FolderPermissionResource[] Enrolled, FolderPermissionResource[] Remaining, FolderPermissionBorrowed[] Borrowed);
internal sealed record FolderPermissionIngress(string Request, string Principal, string TokenHash,
    string Method, string Path, string BodyHash, string IntentHash, Guid? Folder, bool Bootstrap, bool Authorized);
internal sealed record FolderPermissionCommit(string Request, string Resource, string PreviousRevision,
    string Revision, string PolicyHash, string Principal, string Project, string? SourceRevision);
internal sealed record FolderPermissionPolicyState(string Resource, string Principal, string Project,
    string Revision, string PolicyHash);
internal sealed record FolderPermissionDecision(string Request, string Principal, string TokenHash, string Project,
    Guid Folder, string Revision, FolderPermissionAction Action, bool Allowed);
internal sealed record FolderPermissionValue(Guid Id, Guid EnvironmentId, string Name, string? Description, string Path);
internal sealed record FolderPermissionState(Guid Folder, bool Exists, int Version, FolderPermissionValue? Value);
internal sealed record FolderPermissionChange(string Request, FolderPermissionState Before, FolderPermissionState After);
internal sealed record FolderPermissionSeal(string ContentHash, int Count, bool Terminal, int Pending);
internal sealed record FolderPermissionPacket(FolderPermissionSigned<FolderPermissionOwner> Owner,
    FolderPermissionSigned<FolderPermissionIngress>[] Requests,
    FolderPermissionSigned<FolderPermissionCommit>[] Commits,
    FolderPermissionSigned<FolderPermissionDecision>[] Decisions,
    FolderPermissionSigned<FolderPermissionChange>[] Changes,
    FolderPermissionSigned<FolderPermissionPolicyState[]> Policies,
    FolderPermissionSigned<FolderPermissionState[]> Inventory,
    FolderPermissionSigned<FolderPermissionSeal>[] Seals);
internal sealed record FolderPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled,
    string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[FolderPermissionReceipt]";
}
internal sealed record FolderPermissionAttempt(FolderPermissionRow Row, string TokenHash, string? SetupHash,
    SecretStatus Status, DispatchEvidence? Evidence, FolderPermissionValue[] Values, bool Complete);
internal interface IFolderPermissionSource
{
    string Identity { get; }
    FolderPermissionSourceKind Kind { get; }
    ValueTask<FolderPermissionPacket> StepAsync(FolderPermissionRoot root, FolderPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record FolderPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    FolderPermissionProfile Profile, FolderPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        FolderPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("folderPermission", out _);
    internal static FolderPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("folderPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<FolderPermissionInput>(FolderPermissionContract.Options);
            FolderPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                FolderPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            FolderPermissionContract.Validate(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[FolderPermissionInput]";
}
internal static class FolderPermissionContract
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
    internal static string Wire(FolderPermissionAction a) => a switch
    {
        FolderPermissionAction.Read => "read",
        FolderPermissionAction.Create => "create",
        FolderPermissionAction.Edit => "edit",
        FolderPermissionAction.Delete => "delete",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(FolderPermissionAction a) => a switch
    {
        FolderPermissionAction.Read => ProjectRoleAction.Read,
        FolderPermissionAction.Create => ProjectRoleAction.Create,
        FolderPermissionAction.Edit => ProjectRoleAction.Edit,
        FolderPermissionAction.Delete => ProjectRoleAction.Delete,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static bool Template(string op) => op.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string Variant(string op, FolderPermissionAction a) => "permission.SecretFolders." + Wire(a);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<FolderPermissionAction>().Any(a => Variant(d.Key.Operation, a) == d.Key.Variant) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static FolderPermissionAction Baseline(FolderPermissionRoot root) =>
        (FolderPermissionAction)(((int)root.Action + 1) % 4);
    internal static bool Allowed(FolderPermissionRoot root, FolderPermissionRow row, bool after,
        FolderPermissionOutcome outcome) => row.Principal == root.Authorities.Setup ||
        row.Principal == root.Authorities.Observer ||
        row.Principal == root.Authorities.Runtime && row.Control == "selected" &&
        (after && outcome == FolderPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string PolicyHash(FolderPermissionAction a) => Hash(new[] { "secret-folders", Wire(a), "witness", "/" });
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
    internal static void Validate(FolderPermissionProfile profile)
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
    internal static (string Hash, FolderPermissionHeader[] Headers) Contents(FolderPermissionPacket packet,
        FolderPermissionJournal journal) => journal switch
        {
            FolderPermissionJournal.Ingress => (Hash(packet.Requests.Select(x => x.Payload).ToArray()),
                packet.Requests.Select(x => x.Payload.Header).ToArray()),
            FolderPermissionJournal.Policy => (Hash(new object[] { packet.Commits.Select(x => x.Payload).ToArray(),
                packet.Decisions.Select(x => x.Payload).ToArray(), packet.Policies.Payload }), packet.Commits.Select(x => x.Payload.Header)
                .Concat(packet.Decisions.Select(x => x.Payload.Header)).Append(packet.Policies.Payload.Header).ToArray()),
            FolderPermissionJournal.Resources => (Hash(new object[] { packet.Changes.Select(x => x.Payload).ToArray(),
                packet.Inventory.Payload }), packet.Changes.Select(x => x.Payload.Header).Append(packet.Inventory.Payload.Header).ToArray()),
            FolderPermissionJournal.Issuance => (Hash(Array.Empty<FolderPermissionHeader>()), []),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
}
internal sealed class FolderPermissionVerifier : IDisposable
{
    private readonly string hash;
    private readonly Dictionary<FolderPermissionJournal, (FolderPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<FolderPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal FolderPermissionVerifier(FolderPermissionRoot root)
    {
        FolderPermissionContract.Validate(root.Profile);
        hash = FolderPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(FolderPermissionSigned<T> signed, FolderPermissionJournal journal, string window)
    {
        var (pin, key) = keys[journal];
        byte[] bytes = FolderPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        FolderPermissionContract.Require(valid);
        var h = signed.Payload.Header;
        FolderPermissionContract.Require(h.RootHash == hash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == FolderPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Window == window && FolderPermissionContract.Text(h.Event) && events.Add(h.Event) &&
            h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
