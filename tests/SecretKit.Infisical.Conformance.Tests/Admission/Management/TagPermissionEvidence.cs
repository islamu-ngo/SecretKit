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
// Primary facts (Tavily, 2026-10-14): tags read/create/edit/delete are project-level.
// POST/PATCH accept slug/color; GET by ID can project a distinct optional name.
// Tags have NO SDK conditions, inversion, environment or path authorization.
// Native prerequisites, default/inherited grants, template copying, atomicity,
// response name completeness and cleanup/recovery remain qualification gates.
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/api-reference/endpoints/secret-tags/create
// https://infisical.com/docs/api-reference/endpoints/secret-tags/update
// https://infisical.com/docs/api-reference/endpoints/secret-tags/delete
// https://infisical.com/docs/api-reference/endpoints/secret-tags/get-by-id
// https://infisical.com/docs/api-reference/endpoints/secret-tags/list
// Operator route: scopes.<scope>.tagPermission supplies Observer, Capability,
// Profile, Action and TimeoutSeconds. Profile pins all five independent journal
// authorities (distinct P-256 SPKI, writer, channel and schema) plus deployment,
// epoch and revision. POST tag-permission/step transports only this closed root,
// step and optional Reserve capability. The host owns all five SDK identities.
// Controlled rows comprise 30 attempts per before/after/copy window: four actions
// and List for runtime selected/wrong-project, setup, denied, admin and observer.
// Setup/observer bootstrap rights are explicit; they are not runtime preparation.
// Buffers are cleared; SDK token Reveal creates ordinary strings, not erasable
// storage. Native qualification remains zero until all external gates are met.
internal enum TagPermissionAction { Read, Create, Edit, Delete }
internal enum TagPermissionJournal { Ownership, Ingress, Policy, Resources, Issuance }
internal enum TagPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum TagPermissionOutcome { Applied, NonApplied, Partial }
internal enum TagPermissionSourceKind { NativeProvider, ControlledFixture }
internal sealed record TagPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[TagPermissionAuthorities]";
}
internal sealed record TagPermissionPin(TagPermissionJournal Journal, string Writer, string Channel,
    string Schema, string Spki);
internal sealed record TagPermissionProfile(string Deployment, string Epoch, string Revision,
    TagPermissionPin[] Pins);
internal sealed record TagPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, TagPermissionSourceKind Kind,
    TagPermissionAction Action, TagPermissionAuthorities Authorities, TagPermissionProfile Profile)
{
    public override string ToString() => "[TagPermissionRoot]";
}
internal sealed record TagPermissionHeader(string RootHash, TagPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, string Event, long Sequence, string Window);
internal sealed record TagPermissionPayload<T>(TagPermissionHeader Header, T Content);
internal sealed record TagPermissionSigned<T>(TagPermissionPayload<T> Payload, string Signature);
internal sealed record TagPermissionResource(string Kind, string Id, string Root, string Nonce);
internal sealed record TagPermissionBorrowed(string Kind, string Id, string Revision);
internal sealed record TagPermissionRow(string Name, string Project, string Slug, string TagSlug, string Color,
    Guid Id, string Window, string Principal, string Control,
    TagPermissionAction Action, bool List);
internal sealed record TagPermissionIssued(string Project, string Slug, string ControlProject, string CopyProject,
    string CopySlug, string PolicyId, string PolicySlug, string Membership, string TemplateId,
    string BaselineRevision, TagPermissionRow[] Rows);
internal sealed record TagPermissionOwner(TagPermissionStep Step, bool CollisionChecked, bool PreEnrolled,
    bool Exclusive, bool Terminal, int Pending, int Registrations, TagPermissionIssued? Issued,
    TagPermissionResource[] Enrolled, TagPermissionResource[] Remaining, TagPermissionBorrowed[] Borrowed);
internal sealed record TagPermissionIngress(string Request, string Principal, string TokenHash,
    string Method, string Path, string BodyHash, string IntentHash, Guid? Tag, bool Bootstrap, bool Authorized);
internal sealed record TagPermissionCommit(string Request, string Resource, string PreviousRevision,
    string Revision, string PolicyHash, string Principal, string Project, string? SourceRevision);
internal sealed record TagPermissionPolicyState(string Resource, string Principal, string Project,
    string Revision, string PolicyHash);
internal sealed record TagPermissionDecision(string Request, string Principal, string TokenHash, string Project,
    Guid Tag, string Revision, TagPermissionAction Action, bool Allowed);
internal sealed record TagPermissionValue(Guid Id, string Project, string Name, string Slug, string Color);
internal sealed record TagPermissionState(Guid Tag, bool Exists, int Version, TagPermissionValue? Value);
internal sealed record TagPermissionChange(string Request, TagPermissionState Before, TagPermissionState After);
internal sealed record TagPermissionSeal(string ContentHash, int Count, bool Terminal, int Pending);
internal sealed record TagPermissionPacket(TagPermissionSigned<TagPermissionOwner> Owner,
    TagPermissionSigned<TagPermissionIngress>[] Requests,
    TagPermissionSigned<TagPermissionCommit>[] Commits,
    TagPermissionSigned<TagPermissionDecision>[] Decisions,
    TagPermissionSigned<TagPermissionChange>[] Changes,
    TagPermissionSigned<TagPermissionPolicyState[]> Policies,
    TagPermissionSigned<TagPermissionState[]> Inventory,
    TagPermissionSigned<TagPermissionSeal>[] Seals);
internal sealed record TagPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled,
    string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[TagPermissionReceipt]";
}
internal sealed record TagPermissionAttempt(TagPermissionRow Row, string TokenHash, string? SetupHash,
    SecretStatus Status, DispatchEvidence? Evidence, TagPermissionValue[] Values, bool Complete);
internal interface ITagPermissionSource
{
    string Identity { get; }
    TagPermissionSourceKind Kind { get; }
    ValueTask<TagPermissionPacket> StepAsync(TagPermissionRoot root, TagPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record TagPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    TagPermissionProfile Profile, TagPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        TagPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("tagPermission", out _);
    internal static TagPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("tagPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var result = value.Deserialize<TagPermissionInput>(TagPermissionContract.Options);
            TagPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
                TagPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action), "missing-input");
            _ = new InfisicalLifecycleObservers(result!.Observer);
            TagPermissionContract.Validate(result.Profile);
            return result;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[TagPermissionInput]";
}
internal static class TagPermissionContract
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
    internal static string Wire(TagPermissionAction a) => a switch
    {
        TagPermissionAction.Read => "read",
        TagPermissionAction.Create => "create",
        TagPermissionAction.Edit => "edit",
        TagPermissionAction.Delete => "delete",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(TagPermissionAction a) => a switch
    {
        TagPermissionAction.Read => ProjectRoleAction.Read,
        TagPermissionAction.Create => ProjectRoleAction.Create,
        TagPermissionAction.Edit => ProjectRoleAction.Edit,
        TagPermissionAction.Delete => ProjectRoleAction.Delete,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static bool Template(string op) => op.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static string Variant(string op, TagPermissionAction a) => "permission.Tags." + Wire(a);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<TagPermissionAction>().Any(a => Variant(d.Key.Operation, a) == d.Key.Variant) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static TagPermissionAction Baseline(TagPermissionRoot root) =>
        (TagPermissionAction)(((int)root.Action + 1) % 4);
    internal static bool Allowed(TagPermissionRoot root, TagPermissionRow row, bool after,
        TagPermissionOutcome outcome) => row.Principal == root.Authorities.Setup ||
        row.Principal == root.Authorities.Observer ||
        row.Principal == root.Authorities.Runtime && row.Control == "selected" &&
        (after && outcome == TagPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string PolicyHash(TagPermissionAction a) => Hash(new[] { "tags", Wire(a) });
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
    internal static void Validate(TagPermissionProfile profile)
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
    internal static (string Hash, TagPermissionHeader[] Headers) Contents(TagPermissionPacket packet,
        TagPermissionJournal journal) => journal switch
        {
            TagPermissionJournal.Ingress => (Hash(packet.Requests.Select(x => x.Payload).ToArray()),
                packet.Requests.Select(x => x.Payload.Header).ToArray()),
            TagPermissionJournal.Policy => (Hash(new object[] { packet.Commits.Select(x => x.Payload).ToArray(),
                packet.Decisions.Select(x => x.Payload).ToArray(), packet.Policies.Payload }), packet.Commits.Select(x => x.Payload.Header)
                .Concat(packet.Decisions.Select(x => x.Payload.Header)).Append(packet.Policies.Payload.Header).ToArray()),
            TagPermissionJournal.Resources => (Hash(new object[] { packet.Changes.Select(x => x.Payload).ToArray(),
                packet.Inventory.Payload }), packet.Changes.Select(x => x.Payload.Header).Append(packet.Inventory.Payload.Header).ToArray()),
            TagPermissionJournal.Issuance => (Hash(Array.Empty<TagPermissionHeader>()), []),
            _ => throw new NativeCaseFailureException("observer-unavailable")
        };
}
internal sealed class TagPermissionVerifier : IDisposable
{
    private readonly string hash;
    private readonly Dictionary<TagPermissionJournal, (TagPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<TagPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal TagPermissionVerifier(TagPermissionRoot root)
    {
        TagPermissionContract.Validate(root.Profile);
        hash = TagPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    internal T Verify<T>(TagPermissionSigned<T> signed, TagPermissionJournal journal, string window)
    {
        var (pin, key) = keys[journal];
        byte[] bytes = TagPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        TagPermissionContract.Require(valid);
        var h = signed.Payload.Header;
        TagPermissionContract.Require(h.RootHash == hash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == TagPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Window == window && TagPermissionContract.Text(h.Event) && events.Add(h.Event) &&
            h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
