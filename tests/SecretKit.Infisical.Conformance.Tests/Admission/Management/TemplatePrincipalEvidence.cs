using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private witness protocol, not an SDK user administrator or native issuer.
// Public interface facts checked through Tavily on 2026-10-14:
// https://infisical.com/docs/api-reference/endpoints/project-templates/create
// https://infisical.com/docs/api-reference/endpoints/project-templates/update
// https://infisical.com/docs/api-reference/endpoints/projects/create-project
// https://infisical.com/docs/documentation/platform/groups
// https://infisical.com/docs/api-reference/endpoints/token-auth/create-token
// users select username, groups groupSlug, managed identities name; each selects
// roles. CreateProject selects a template NAME, not a returned template ID.
// Enterprise entitlement, native omission/null policy, fresh user issuance,
// managed-identity discovery/issuer qualification and native journals remain 0.
//
// The coordinator channel authenticates only the coordinator. Six distinct,
// host-pinned P-256 writers sign complete typed journals, including empty ones,
// root/profile/step/sequence and terminal fences. Labels are NOT authentication.
// Writers remain trusted for completeness and meaning; signatures cannot qualify
// native issuer semantics. Controlled writers in one fixture are not independent
// processes. The fixture proves joins and rejects coordinator-only forgery.
//
// Reserve collision-checks and enrolls a durable creation plan before issuance.
// Original-root Close seals and drains creation/dispatch, including unknown IDs
// after lost/partial Open. External atomic enrollment requires a qualified
// coordinator; in-process locking does not establish that external guarantee.
internal enum TemplatePrincipalKind { NativeProvider, ControlledFixture }
internal enum TemplatePrincipalShape { Values, Empty }
internal enum TemplatePrincipalOutcome { NonApplied, Applied, Partial }
internal enum TemplatePrincipalStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum TemplatePrincipalJournal { Ownership, Ingress, Template, Issuer, Membership, Access }
internal sealed record TemplatePrincipalAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    internal string Actor(string boundary) => boundary == "denied-authority" ? Denied : Administrative;
    public override string ToString() => "[TemplatePrincipalAuthorities]";
}
internal sealed record TemplatePrincipalPin(TemplatePrincipalJournal Journal, string Writer, string Channel,
    string Schema, string PublicKey);
internal sealed record TemplatePrincipalProfile(string Deployment, string Epoch, string ProviderRevision,
    TemplatePrincipalPin[] Pins);
internal sealed record TemplatePrincipalRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, TemplatePrincipalKind Kind,
    TemplatePrincipalShape Shape, TemplatePrincipalAuthorities Authorities, TemplatePrincipalProfile Profile)
{
    public override string ToString() => "[TemplatePrincipalRoot]";
}
internal sealed record TemplatePrincipalResource(string Root, string Nonce, string Kind, string Id);
internal sealed record TemplatePrincipalBorrowed(string Kind, string Id, string Revision);
internal sealed record TemplatePrincipalCredential(string Principal, string Username, string Kind, string Project,
    string CredentialId, string Hash, byte[] Bytes)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Bytes);
    public override string ToString() => "[TemplatePrincipalCredential]";
}
internal sealed record TemplatePrincipalIssued(string TemplateId, string TemplateName, string SeedId, string SeedName,
    string GroupId, string GroupSlug, string ManagedName, string BeforeProject, string AfterProject,
    string BeforeSlug, string AfterSlug, string BeforeManaged, string AfterManaged,
    string ReaderRole, string MarkerRole, string Key, string ValueHash, byte[] Value,
    TemplatePrincipalCredential[] Users)
{
    internal void Erase()
    {
        CryptographicOperations.ZeroMemory(Value);
        foreach (var c in Users) c.Erase();
    }
    public override string ToString() => "[TemplatePrincipalIssued]";
}
internal sealed record TemplatePrincipalOwner(bool CollisionChecked, bool PreEnrolled, bool Exclusive,
    bool Terminal, int PendingIssuers, int PendingDispatches, int Registrations, bool PrivateReleased,
    TemplatePrincipalIssued? Issued, TemplatePrincipalResource[] Enrolled, TemplatePrincipalResource[] Remaining,
    TemplatePrincipalBorrowed[] Borrowed);
internal sealed record TemplatePrincipalIngress(string Request, string Actor, string Method, string Path,
    string IntentHash, bool Authorized);
internal sealed record TemplatePrincipalCommit(string Request, string Template, string PreviousRevision,
    string Revision, string ConfigurationHash, string Field);
internal sealed record TemplatePrincipalIssuer(string Request, string Principal, string Credential,
    string CredentialHash, string Kind, string Project, string Membership);
internal sealed record TemplatePrincipalMembership(string Id, string CopyRequest, string Template, string Revision,
    string ConfigurationHash, string Project, string Principal, string Kind, string[] Roles, string PolicyHash,
    string? Group, string? GroupMember);
internal sealed record TemplatePrincipalAccess(string Request, string Principal, string Credential,
    string CredentialHash, string Project, string Revision, string Key, string Environment, bool Allowed,
    string? ValueHash);
internal sealed record TemplatePrincipalEnvelope<T>(string RootHash, TemplatePrincipalJournal Journal,
    string Writer, string Channel, string Schema, string Window, long Sequence, bool Terminal, int Pending,
    T Content);
internal sealed record TemplatePrincipalSigned<T>(TemplatePrincipalEnvelope<T> Payload, string Signature);
internal sealed record TemplatePrincipalPacket(TemplatePrincipalSigned<TemplatePrincipalOwner> Owner,
    TemplatePrincipalSigned<TemplatePrincipalIngress[]> Ingress,
    TemplatePrincipalSigned<TemplatePrincipalCommit[]> Templates,
    TemplatePrincipalSigned<TemplatePrincipalIssuer[]> Issuers,
    TemplatePrincipalSigned<TemplatePrincipalMembership[]> Memberships,
    TemplatePrincipalSigned<TemplatePrincipalAccess[]> Access);
internal sealed record TemplatePrincipalReceipt(DispatchEvidence Evidence, SecretStatus? Status, bool Cancelled,
    string IntentHash);
internal sealed record TemplatePrincipalAttempt(string Principal, string Credential, string Hash, string Project,
    string Environment, bool Allowed, string? ValueHash);
internal interface ITemplatePrincipalSource
{
    string Identity { get; }
    TemplatePrincipalKind Kind { get; }
    ValueTask<TemplatePrincipalPacket> StepAsync(TemplatePrincipalRoot root, TemplatePrincipalStep step,
        SecretMaterial? capability, TemplatePrincipalReceipt? receipt, CancellationToken token);
}
internal sealed record TemplatePrincipalInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    TemplatePrincipalProfile Profile, TemplatePrincipalShape Shape, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        TemplatePrincipalContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("templatePrincipal", out _);
    internal static TemplatePrincipalInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("templatePrincipal", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<TemplatePrincipalInput>(TemplatePrincipalContract.Options);
            TemplatePrincipalContract.Require(input is not null && Enum.IsDefined(input.Shape) &&
                input.TimeoutSeconds is >= 1 and <= 300 && TemplatePrincipalContract.Text(input.Capability), "missing-input");
            TemplatePrincipalContract.Profile(input!.Profile);
            _ = new InfisicalLifecycleObservers(input.Observer);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[TemplatePrincipalInput]";
}
internal static class TemplatePrincipalContract
{
    internal const string Create = "i.management.ProjectTemplateOperations.CreateProjectTemplate";
    internal const string Update = "i.management.ProjectTemplateOperations.UpdateProjectTemplate";
    internal static readonly string[] Fields = ["users", "groups", "projectManagedIdentities"];
    internal static readonly string[] Cases = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    internal static readonly string[] GenericLabels = ["factory." + Create, "factory." + Update];
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    {
        IgnoreReadOnlyProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        RespectRequiredConstructorParameters = true,
        RespectNullableAnnotations = true
    };
    internal static IEnumerable<(string Operation, string Variant, string Boundary)> CasesInventory() =>
        from operation in new[] { Create, Update }
        from field in Fields
        from variant in new[] { "ProjectTemplateConfiguration." + field + ".omitted",
            "ProjectTemplateConfiguration." + field + ".value", field + ".null" }
        where operation == Update || !variant.EndsWith(".null", StringComparison.Ordinal)
        from boundary in Cases
        select (operation, variant, boundary);
    internal static bool Owns(NativeCaseDefinition d) => InfisicalProjectFamilies.Valid(d) &&
        CasesInventory().Any(c => c.Operation == d.Key.Operation && c.Variant == d.Key.Variant && c.Boundary == d.Key.Case);
    internal static string Field(string variant) => variant.Replace("ProjectTemplateConfiguration.", "", StringComparison.Ordinal).Split('.')[0];
    internal static bool Present(TemplatePrincipalRoot root, string field, bool after, TemplatePrincipalOutcome outcome)
    {
        if (!after) return true;
        if (outcome == TemplatePrincipalOutcome.NonApplied) return root.Operation == Update;
        if (Field(root.Variant) != field) return true;
        if (root.Variant.EndsWith(".omitted", StringComparison.Ordinal)) return root.Operation == Update;
        return !root.Variant.EndsWith(".null", StringComparison.Ordinal) && root.Shape == TemplatePrincipalShape.Values;
    }
    internal static string Environment(bool after, TemplatePrincipalOutcome outcome) =>
        after && outcome != TemplatePrincipalOutcome.NonApplied ? "witness" : "baseline";
    internal static bool Text(string? s) => s is { Length: > 0 and <= 16384 } && !s.Any(char.IsControl) && !string.IsNullOrWhiteSpace(s);
    internal static void Require(bool valid, string code = "observer-unavailable")
    { if (!valid) throw new NativeCaseFailureException(code); }
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] bytes = Bytes(value);
        try { return HashBytes(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string HashBytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static SecretMaterial Material(byte[] bytes)
    {
        char[] chars = Encoding.UTF8.GetChars(bytes);
        try { return SecretMaterial.FromText(chars); }
        finally { Array.Clear(chars); }
    }
    internal static string PolicyHash(string environment) => Hash(new[] { "secrets", "read", environment, "/" });
    internal static void Profile(TemplatePrincipalProfile p)
    {
        Require(p is not null && new[] { p.Deployment, p.Epoch, p.ProviderRevision }.All(Text) &&
            p.Pins.Length == 6 && p.Pins.Select(x => x.Journal).Distinct().Count() == 6 &&
            p.Pins.Select(x => x.Writer).Distinct().Count() == 6 &&
            p.Pins.Select(x => x.Channel).Distinct().Count() == 6, "missing-input");
        var hashes = new HashSet<string>();
        foreach (var pin in p!.Pins)
        {
            Require(Enum.IsDefined(pin.Journal) && Text(pin.Writer) && Text(pin.Channel) && Text(pin.Schema), "missing-input");
            using var key = ECDsa.Create();
            byte[] encoded = Convert.FromBase64String(pin.PublicKey);
            key.ImportSubjectPublicKeyInfo(encoded, out int used);
            Require(used == encoded.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                hashes.Add(HashBytes(encoded)), "missing-input");
        }
    }
}
internal sealed class TemplatePrincipalVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<TemplatePrincipalJournal, TemplatePrincipalPin> pins;
    private readonly Dictionary<TemplatePrincipalJournal, long> sequences = [];
    private readonly Dictionary<TemplatePrincipalJournal, ECDsa> keys = [];
    internal TemplatePrincipalVerifier(TemplatePrincipalRoot root)
    {
        TemplatePrincipalContract.Profile(root.Profile);
        rootHash = TemplatePrincipalContract.Hash(root);
        pins = root.Profile.Pins.ToDictionary(p => p.Journal);
        foreach (var pin in pins.Values)
        {
            var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.PublicKey), out _);
            keys.Add(pin.Journal, key);
        }
    }
    internal T Verify<T>(TemplatePrincipalSigned<T> signed, TemplatePrincipalJournal journal,
        TemplatePrincipalStep step)
    {
        var pin = pins[journal];
        var key = keys[journal];
        byte[] content = TemplatePrincipalContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(content, Convert.FromBase64String(signed.Signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(content); }
        var p = signed.Payload;
        TemplatePrincipalContract.Require(valid && p.RootHash == rootHash &&
            p.Journal == journal && p.Writer == pin.Writer && p.Channel == pin.Channel && p.Schema == pin.Schema &&
            p.Window == step.ToString() && p.Sequence > sequences.GetValueOrDefault(journal) &&
            p.Terminal && p.Pending == 0);
        sequences[journal] = p.Sequence;
        return p.Content;
    }
    public void Dispose() { foreach (var key in keys.Values) key.Dispose(); }
}
