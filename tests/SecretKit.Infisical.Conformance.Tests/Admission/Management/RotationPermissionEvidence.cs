using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Optional PRIVATE protocol. Native/provider qualification remains ZERO.
// Source facts, 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// documents six secret-rotation actions and environment/secretPath/connectionId.
// https://infisical.com/docs/api-reference/endpoints/secret-rotations/postgres-credentials/create
// https://infisical.com/docs/api-reference/endpoints/secret-rotations/postgres-credentials/rotate-secrets
// https://infisical.com/docs/documentation/platform/secret-rotation/postgres-credentials
// requires an authorized connection and two separately provisioned database users.
// The current SDK ALSO admits GetGeneratedCredentials in all three SQL families;
// the guessed documentation /get-generated-credentials URL returned 404. Endpoint
// documentation completeness is not inferred from the SDK or from ordinary reads.
// This unit selects typed PostgreSQL, MySQL and MSSQL configuration shapes. Actual
// server login, native prerequisites, inheritance, entitlement, version/platform,
// atomicity and material-retirement behavior remain explicit external gates.
// Controlled Linux SQLite authentication is NOT any vendor SQL server authentication.
// Owned byte/character copies and disposable material are cleared. Reveal,
// JSON/HTTP and SQLite/framework string copies are ordinary plaintext strings;
// this protocol makes no claim that their storage can be erased.
internal enum RotationPermissionAction { Read, ReadGeneratedCredentials, Create, Edit, Delete, RotateSecrets }
internal enum RotationPermissionJournal { Ownership, Ingress, Policy, Resources, Issuance, Backend }
internal enum RotationPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum RotationPermissionOutcome { Applied, NonApplied, Partial }
internal enum RotationPermissionSourceKind { NativeProvider, ControlledFixture }
internal sealed record RotationPermissionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    public override string ToString() => "[RotationPermissionAuthorities]";
}
internal sealed record RotationPermissionPin(RotationPermissionJournal Journal, string Writer, string Channel,
    string Schema, string Spki);
internal sealed record RotationPermissionProfile(string Deployment, string Epoch, string Revision,
    InfisicalRotationProfile SqlProfile, RotationPermissionPin[] Pins);
internal sealed record RotationPermissionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source, RotationPermissionSourceKind Kind,
    RotationPermissionAction Action, RotationPermissionAuthorities Authorities, RotationPermissionProfile Profile)
{
    public override string ToString() => "[RotationPermissionRoot]";
}
internal sealed record RotationPermissionHeader(string RootHash, RotationPermissionJournal Journal, string Writer,
    string Channel, string Schema, string Event, long Sequence, string Window);
internal sealed record RotationPermissionPayload<T>(RotationPermissionHeader Header, T Content);
internal sealed record RotationPermissionSigned<T>(RotationPermissionPayload<T> Payload, string Signature);
internal sealed record RotationPermissionOwned(string Kind, string Id, string Root, string Nonce);
internal sealed record RotationPermissionBorrowed(string Kind, string Id, string Hash);
internal sealed record RotationPermissionRow(Guid Id, string Project, string Environment, string Path,
    Guid EnvironmentId, Guid FolderId, string Connection, string Name, string Principal, string Control,
    string Window, RotationPermissionAction Action, bool List,
    InfisicalRotationProfile SqlProfile = InfisicalRotationProfile.PostgresCredentials)
{
    internal InfisicalRotationAddress Address => new(Project, Environment, Path,
        SqlProfile, Id.ToString());
    internal string Username1 => "u" + Id.ToString("N") + "a";
    internal string Username2 => "u" + Id.ToString("N") + "b";
    internal string UsernameKey => "U" + Id.ToString("N");
    internal string PasswordKey => "P" + Id.ToString("N");
    public override string ToString() => "[RotationPermissionRow]";
}
// No plaintext credentials/statements in journals. Configuration fingerprints
// include the complete typed input, including the protected statement digest.
internal sealed record RotationPermissionConfiguration(string Id, string Project, string Environment, string Path,
    string Connection, string Name, string Username1, string Username2, string UsernameKey, string PasswordKey,
    double Interval, double Hours, double Minutes, bool Enabled, bool HasDescription, string? Description,
    double Length, double Digits, double Lowercase, double Symbols, double Uppercase, string AllowedSymbols,
    string StatementHash, string EnvironmentId, string FolderId, InfisicalRotationProfile SqlProfile)
{
    public override string ToString() => "[RotationPermissionConfiguration]";
}
internal sealed record RotationPermissionState(Guid Id, bool Exists, int Version,
    RotationPermissionConfiguration? Configuration, int Generation, string MaterialHash);
internal sealed record RotationPermissionIssued(string Project, string Slug, string ControlProject, string CopyProject,
    string CopySlug, string PolicyId, string PolicySlug, string Membership, string TemplateId,
    string Connection, string ControlConnection, string BaselineRevision, RotationPermissionRow[] Rows);
internal sealed record RotationPermissionOwner(RotationPermissionStep Step, bool CollisionChecked, bool PreEnrolled,
    bool Exclusive, bool Terminal, int Pending, int Registrations, RotationPermissionIssued? Issued,
    RotationPermissionOwned[] Enrolled, RotationPermissionOwned[] Remaining, RotationPermissionBorrowed[] Borrowed);
internal sealed record RotationPermissionIngress(string Request, string Principal, string TokenHash, string Method,
    string Path, string BodyHash, string IntentHash, Guid? Rotation, bool Bootstrap, bool Authorized);
internal sealed record RotationPermissionPolicy(string Resource, string Principal, string Project, string Revision,
    string PolicyHash, string? SourceRevision);
internal sealed record RotationPermissionCommit(string Request, string PreviousRevision, RotationPermissionPolicy State);
internal sealed record RotationPermissionDecision(string Request, string Principal, string TokenHash, Guid Rotation,
    string Project, string Environment, string Path, string Connection, RotationPermissionAction Action,
    string Revision, bool Allowed);
internal sealed record RotationPermissionChange(string Request, RotationPermissionState Before, RotationPermissionState After);
internal sealed record RotationPermissionMaterial(string Request, Guid Rotation, int Generation, string UsernameHash,
    string PasswordHash, string MaterialHash, bool MeetsRequirements);
internal sealed record RotationPermissionBackend(string Request, Guid Rotation, string MaterialHash,
    bool Authenticated, bool WrongRejected, bool ReadAllowed, bool WriteDenied, string ProtectedHash);
internal sealed record RotationPermissionSeal(string Hash, int Count, bool Terminal, int Pending);
internal sealed record RotationPermissionStoreInventory(int Count, int Pending, int Registrations, bool BorrowedPreserved,
    int ProtectedRows = 0);
internal sealed record RotationPermissionPacket(RotationPermissionSigned<RotationPermissionOwner> Owner,
    RotationPermissionSigned<RotationPermissionIngress>[] Requests,
    RotationPermissionSigned<RotationPermissionCommit>[] Commits,
    RotationPermissionSigned<RotationPermissionDecision>[] Decisions,
    RotationPermissionSigned<RotationPermissionChange>[] Changes,
    RotationPermissionSigned<RotationPermissionMaterial>[] Materials,
    RotationPermissionSigned<RotationPermissionBackend>[] Backend,
    RotationPermissionSigned<RotationPermissionPolicy[]> Policies,
    RotationPermissionSigned<RotationPermissionState[]> Inventory,
    RotationPermissionSigned<RotationPermissionStoreInventory> IssuanceInventory,
    RotationPermissionSigned<RotationPermissionStoreInventory> BackendInventory,
    RotationPermissionSigned<RotationPermissionSeal>[] Seals);
internal sealed record RotationPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled,
    string IntentHash, string TokenHash = "")
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[RotationPermissionReceipt]";
}
internal sealed record RotationPermissionAttempt(RotationPermissionRow Row, string TokenHash, SecretStatus Status,
    DispatchEvidence? Evidence, InfisicalRotationDispatch? RotationDispatch,
    RotationPermissionConfiguration[] Values, bool Complete, string[] MaterialHashes);
internal interface IRotationPermissionSource
{
    string Identity { get; }
    RotationPermissionSourceKind Kind { get; }
    ValueTask<RotationPermissionPacket> StepAsync(RotationPermissionRoot root, RotationPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record RotationPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    RotationPermissionProfile Profile, RotationPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        RotationPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("rotationPermission", out _);
    internal static RotationPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("rotationPermission", out var value)) return null;
        NativeRunProtocol.RejectDuplicates(value);
        var result = value.Deserialize<RotationPermissionInput>(RotationPermissionContract.Options);
        RotationPermissionContract.Require(result is not null && result.TimeoutSeconds is >= 1 and <= 300 &&
            RotationPermissionContract.Text(result.Capability) && Enum.IsDefined(result.Action), "missing-input");
        RotationPermissionContract.Validate(result!.Profile);
        return result;
    }
    public override string ToString() => "[RotationPermissionInput]";
}
internal static class RotationPermissionContract
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
    internal static readonly string[] Boundaries = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    internal static string Wire(RotationPermissionAction a) => a switch
    {
        RotationPermissionAction.Read => "read",
        RotationPermissionAction.ReadGeneratedCredentials => "read-generated-credentials",
        RotationPermissionAction.Create => "create",
        RotationPermissionAction.Edit => "edit",
        RotationPermissionAction.Delete => "delete",
        RotationPermissionAction.RotateSecrets => "rotate-secrets",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static ProjectRoleAction Sdk(RotationPermissionAction a) => a switch
    {
        RotationPermissionAction.Read => ProjectRoleAction.Read,
        RotationPermissionAction.ReadGeneratedCredentials => ProjectRoleAction.ReadGeneratedCredentials,
        RotationPermissionAction.Create => ProjectRoleAction.Create,
        RotationPermissionAction.Edit => ProjectRoleAction.Edit,
        RotationPermissionAction.Delete => ProjectRoleAction.Delete,
        RotationPermissionAction.RotateSecrets => ProjectRoleAction.RotateSecrets,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string Variant(RotationPermissionAction a) => "permission.SecretRotation." + Wire(a);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<RotationPermissionAction>().Any(a => Variant(a) == d.Key.Variant) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static bool Supported(NativeCaseDefinition d, InfisicalRotationProfile profile) => Owns(d) &&
        profile is InfisicalRotationProfile.PostgresCredentials or InfisicalRotationProfile.MysqlCredentials or
            InfisicalRotationProfile.MssqlCredentials;
    internal static readonly string[] NativeGates = ["provider-version-and-entitlement",
        "isolated-action-administrative-and-runtime-prerequisites", "postgres-server-authentication",
        "native-template-name-copy-and-explicit-role-assignment", "native-generated-credentials-endpoint-documentation",
        "native-cleanup-and-original-causal-settlement", "mysql-server-authentication", "mssql-server-authentication"];
    internal static bool Template(string op) => op.Contains(".ProjectTemplateOperations.", StringComparison.Ordinal);
    internal static bool Create(string op) => op.Split('.').Last().StartsWith("Create", StringComparison.Ordinal);
    internal static RotationPermissionAction Baseline(RotationPermissionRoot r) => (RotationPermissionAction)(((int)r.Action + 1) % 6);
    internal static RoleCondition[] Conditions(string connection) =>
    [
        new(RoleConditionField.Environment, RoleStringClause.Literal("witness")),
        new(RoleConditionField.SecretPath, RoleStringClause.Literal("/owned")),
        new(RoleConditionField.ConnectionId, RoleStringClause.Literal(connection))
    ];
    internal static string PolicyHash(RotationPermissionAction action, string connection) =>
        Hash(new[] { "secret-rotation", Wire(action), "witness", "/owned", connection });
    internal static bool Allowed(RotationPermissionRoot root, RotationPermissionRow row, bool after,
        RotationPermissionOutcome outcome) => row.Principal == root.Authorities.Setup ||
        row.Principal == root.Authorities.Observer ||
        row.Principal == root.Authorities.Runtime && row.Control == "selected" &&
        (after && outcome == RotationPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal const string Statement = "ALTER USER {{username}} WITH PASSWORD '{{password}}';";
    internal static string ProfileStatement(InfisicalRotationProfile profile) => profile switch
    {
        InfisicalRotationProfile.PostgresCredentials => Statement,
        InfisicalRotationProfile.MysqlCredentials => "ALTER USER '{{username}}'@'%' IDENTIFIED BY '{{password}}';",
        InfisicalRotationProfile.MssqlCredentials => "ALTER LOGIN [{{username}}] WITH PASSWORD = '{{password}}';",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string ProfileWire(InfisicalRotationProfile profile) => profile switch
    {
        InfisicalRotationProfile.PostgresCredentials => "postgres-credentials",
        InfisicalRotationProfile.MysqlCredentials => "mysql-credentials",
        InfisicalRotationProfile.MssqlCredentials => "mssql-credentials",
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static RotationPermissionConfiguration Initial(RotationPermissionRow row) =>
        new(row.Id.ToString(), row.Project, row.Environment, row.Path, row.Connection, row.Name, row.Username1,
            row.Username2, row.UsernameKey, row.PasswordKey, 2, 3, 4, false, true, "owned", 24, 2, 2, 2, 2, "!@",
            Hash(ProfileStatement(row.SqlProfile)), row.EnvironmentId.ToString(), row.FolderId.ToString(), row.SqlProfile);
    internal static RotationPermissionConfiguration Edited(RotationPermissionConfiguration c) =>
        c with
        {
            Name = c.Name + "-changed",
            Interval = 3,
            Hours = 5,
            Minutes = 6,
            Description = "changed",
            Enabled = true,
            UsernameKey = c.UsernameKey + "X",
            PasswordKey = c.PasswordKey + "X",
            Length = 32,
            Digits = 3,
            Lowercase = 3,
            Symbols = 3,
            Uppercase = 3,
            AllowedSymbols = "!@#",
            StatementHash = Hash(ProfileStatement(c.SqlProfile) + " -- changed")
        };
    internal static string MaterialHash(string username, string password) => Hash(new[] { username, password });
    internal static byte[] Bytes<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Options);
    internal static string Hash<T>(T value)
    {
        byte[] bytes = Bytes(value);
        try { return RawHash(bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static string RawHash(ReadOnlySpan<byte> bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static bool Text(string? v) => v is { Length: > 0 and <= 16384 } && !string.IsNullOrWhiteSpace(v) && !v.Any(char.IsControl);
    internal static void Require(bool v, string code = "observer-unavailable")
    { if (!v) throw new NativeCaseFailureException(code); }
    internal static void Validate(RotationPermissionProfile p)
    {
        Require(p is not null && new[] { p.Deployment, p.Epoch, p.Revision }.All(Text) &&
            Enum.IsDefined(p.SqlProfile) &&
            p.Pins.Length == 6 && p.Pins.Select(x => x.Journal).Distinct().Count() == 6 &&
            p.Pins.All(x => Enum.IsDefined(x.Journal) && Text(x.Writer) && Text(x.Channel) && Text(x.Schema)) &&
            p.Pins.Select(x => x.Writer).Distinct().Count() == 6 && p.Pins.Select(x => x.Channel).Distinct().Count() == 6,
            "missing-input");
        var keys = new HashSet<string>();
        foreach (var pin in p!.Pins)
        {
            using var key = ECDsa.Create();
            byte[] bytes = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(bytes, out int used);
            Require(used == bytes.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                keys.Add(RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal static object[] Contents(RotationPermissionPacket p, RotationPermissionJournal j) => j switch
    {
        RotationPermissionJournal.Ownership => [p.Owner.Payload],
        RotationPermissionJournal.Ingress => p.Requests.Select(x => (object)x.Payload).ToArray(),
        RotationPermissionJournal.Policy => p.Commits.Select(x => (object)x.Payload)
            .Concat(p.Decisions.Select(x => (object)x.Payload)).Append(p.Policies.Payload).ToArray(),
        RotationPermissionJournal.Resources => p.Changes.Select(x => (object)x.Payload).Append(p.Inventory.Payload).ToArray(),
        RotationPermissionJournal.Issuance => p.Materials.Select(x => (object)x.Payload).Append(p.IssuanceInventory.Payload).ToArray(),
        RotationPermissionJournal.Backend => p.Backend.Select(x => (object)x.Payload).Append(p.BackendInventory.Payload).ToArray(),
        _ => throw new NativeCaseFailureException("observer-unavailable")
    };
}
internal sealed class RotationPermissionVerifier(RotationPermissionRoot root) : IDisposable
{
    private readonly Dictionary<RotationPermissionJournal, long> sequences = [];
    private readonly HashSet<string> events = [];
    internal T Verify<T>(RotationPermissionSigned<T> signed, RotationPermissionJournal journal, string window)
    {
        var pin = root.Profile.Pins.Single(x => x.Journal == journal);
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
        byte[] bytes = RotationPermissionContract.Bytes(signed.Payload);
        bool valid;
        try
        {
            valid = key.VerifyData(bytes, Convert.FromBase64String(signed.Signature),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = signed.Payload.Header;
        RotationPermissionContract.Require(valid && h.RootHash == RotationPermissionContract.Hash(root) &&
            h.Journal == journal && h.Writer == pin.Writer && h.Channel == pin.Channel && h.Schema == pin.Schema &&
            h.Window == window && events.Add(h.Event) && h.Sequence > sequences.GetValueOrDefault(journal));
        sequences[journal] = h.Sequence;
        return signed.Payload.Content;
    }
    public void Dispose() { }
}
