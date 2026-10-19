using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Controlled evidence only: native qualification, enforcement authority, source independence,
// clock and certification remain zero. Primary facts checked through Tavily, 2026-10-14:
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/documentation/platform/secret-validation-rules
// Nine independently pinned writers are required. Enforcement owns constraint decisions;
// Backend owns committed secret versions. Neither may sign coordinator observations.
// A deployment must independently provision writer keys, immutable log capture, issuer,
// policy/storage/authorization taps, and admission fences. Distinct keys alone do not
// establish independence. This controlled simulator cannot qualify those obligations.
// The bounded profile is StaticSecrets, exact environment/path, non-unique text bounds.
// Dynamic/rotation kinds, other providers and glob/uniqueness semantics are unqualified.
// MutationReceipt is only target-bound single-use dispatch evidence; protected input,
// rule revision and commit causality come from the joined journals below.
// Source transport is explicitly brotli-base64-v1: the shared outer 1 MiB budget
// remains unchanged and decoded histories are bounded at 8 MiB. No evidence is
// dropped to fit a response. Owned buffers are cleared, not managed strings or
// framework/TLS/socket copies. The root identifies one closed, bounded trial.
internal enum ValidationPermissionAction { Read, Create, Edit, Delete }
internal enum ValidationPermissionScope { Project, Organization }
internal enum ValidationPermissionJournal { Ownership, Ingress, Policy, Storage, Issuer, Membership, Access, Enforcement, Backend }
internal enum ValidationPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum ValidationPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record ValidationPermissionPin(ValidationPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record ValidationPermissionProfile(string Deployment, string Epoch, string Revision, ValidationPermissionPin[] Pins);
internal sealed record ValidationPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    ValidationPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, ValidationPermissionAction Action,
    MemberPermissionAuthorities Authorities, ValidationPermissionProfile Profile)
{
    public override string ToString() => "[ValidationPermissionRoot]";
}
// Keys and references are logical creation intents, never proposed native IDs.
// Input is an exact normalized constructor input with explicit dependency keys.
internal sealed record ValidationPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope,
    string Input, string[] Dependencies, string Work);
internal sealed record ValidationPermissionBinding(string Intent, string IntentHash, string Work, string Kind,
    string Scope, string InputHash, string CanonicalId, string Request, string Commit);
internal sealed record ValidationPermissionResource(string Intent, string CanonicalId);
internal sealed record ValidationPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind,
    string Organization, string Hash, bool Owned);
internal sealed record ValidationPermissionActor(string Principal, MemberPermissionActorKind Kind, string Organization,
    string CredentialId, string CredentialHash, byte[] Credential, bool Owned)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[ValidationPermissionActor]";
}
internal sealed record ValidationPermissionRow(string Key, string Window, string Control, ValidationPermissionAction Action,
    string Organization, string Project, string Target, string Name, string Slug, int Actor);
internal sealed record ValidationPermissionIssued(ValidationPermissionActor[] Actors, ValidationPermissionBinding[] Bindings)
{
    internal string Id(string key) => key.StartsWith("@", StringComparison.Ordinal) ? key[1..] :
        Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[ValidationPermissionIssued]";
}
internal sealed record ValidationPermissionOwner(ValidationPermissionIntent[] Intents, ValidationPermissionResource[] Remaining,
    MemberPermissionBorrowed[] Borrowed, bool CollisionChecked, bool Exclusive, bool IssuerFence, bool IngressFence,
    int Pending, int Registrations, ValidationPermissionActor[] Actors, bool EnforcementFence, bool BackendFence);
internal sealed record ValidationPermissionIngresses(ValidationPermissionIngress[] Events, ValidationPermissionIngress[] History);
internal sealed record ValidationPermissionIngress(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, bool Authorized, string Phase);
internal sealed record ValidationPermissionPolicy(string Resource, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string[] Names, string Role, string Configuration);
internal sealed record ValidationPermissionCommit(string Request, string PreviousRevision, ValidationPermissionPolicy Policy);
internal sealed record ValidationPermissionPolicies(ValidationPermissionPolicy[] Inventory, ValidationPermissionCommit[] Commits, ValidationPermissionWriteGrant[] WriteGrants, ValidationPermissionCommit[] History);
internal sealed record ValidationPermissionConstraints(int? MinimumLength, int? MaximumLength, string? RegexPattern,
    string? RequiredPrefix, string? RequiredSuffix, int? UniqueAcrossLastVersions, bool? UniqueWithinScope)
{
    internal InfisicalTextConstraints Build() => new(MinimumLength, MaximumLength, RegexPattern, RequiredPrefix, RequiredSuffix, UniqueAcrossLastVersions, UniqueWithinScope);
    internal static ValidationPermissionConstraints? From(InfisicalTextConstraints? c) => c is null ? null :
        new(c.MinimumLength, c.MaximumLength, c.RegexPattern, c.RequiredPrefix, c.RequiredSuffix, c.UniqueAcrossLastVersions, c.UniqueWithinScope);
    public override string ToString() => "[ValidationPermissionConstraints]";
}
internal sealed record ValidationPermissionState(string Row, string Target, string Organization, string Project,
    string Name, string? Description, string? Environment, string Path, bool Active, int Version,
    ValidationPermissionConstraints? Key, ValidationPermissionConstraints? Value, InfisicalValidationKind Kind = InfisicalValidationKind.StaticSecrets)
{
    public override string ToString() => "[ValidationPermissionState]";
}
internal sealed record ValidationPermissionChange(string Request, string Row, ValidationPermissionState? Before, ValidationPermissionState? After);
internal sealed record ValidationPermissionCopiedEnvironment(string Project, string Id, string Name, string Slug, double Position, string Template, string Configuration);
internal sealed record ValidationPermissionStorage(ValidationPermissionBinding[] Bindings, ValidationPermissionState[] Inventory, ValidationPermissionChange[] Changes, ValidationPermissionCopiedEnvironment[] Configurations, ValidationPermissionChange[] History);
internal sealed record ValidationPermissionIssuance(ValidationPermissionBinding[] Bindings, ValidationPermissionCredential[] Credentials, ValidationPermissionCredential[] History);
internal sealed record ValidationPermissionJoin(string Principal, string Kind, string Organization, string Project, string Membership,
    bool Assigned, string RoleId, string RoleSlug, bool Active, string Status);
internal sealed record ValidationPermissionAccess(string Request, string Actor, MemberPermissionActorKind Kind,
    string CredentialId, string CredentialHash, string Organization, string Project, string Target, string Revision, ValidationPermissionAction Action, bool Allowed);
internal sealed record ValidationPermissionHeader(string RootHash, ValidationPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, long Sequence, string Event, ValidationPermissionStep Step);
internal sealed record ValidationPermissionPayload<T>(ValidationPermissionHeader Header, T Content);
internal sealed record ValidationPermissionSigned<T>(ValidationPermissionPayload<T> Payload, string Signature);
internal sealed record ValidationPermissionPacket(ValidationPermissionSigned<ValidationPermissionOwner> Owner,
    ValidationPermissionSigned<ValidationPermissionIngresses> Ingress, ValidationPermissionSigned<ValidationPermissionPolicies> Policy,
    ValidationPermissionSigned<ValidationPermissionStorage> Storage, ValidationPermissionSigned<ValidationPermissionIssuance> Issuer,
    ValidationPermissionSigned<ValidationPermissionJoin[]> Membership, ValidationPermissionSigned<ValidationPermissionAccesses> Access,
    ValidationPermissionSigned<ValidationPermissionEnforcementHistory> Enforcement, ValidationPermissionSigned<ValidationPermissionBackendHistory> Backend,
    ValidationPermissionSigned<MemberPermissionSeal>[] Seals);
internal sealed record ValidationPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
    public override string ToString() => "[ValidationPermissionReceipt]";
}
internal sealed record ValidationPermissionAttempt(ValidationPermissionRow Row, string CredentialHash, SecretStatus Status,
    DispatchEvidence? Evidence, ValidationPermissionState? Value, bool Complete, string InputHash, ValidationPermissionWriteAttempt[] Before, ValidationPermissionWriteAttempt[] After);
internal interface IValidationPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<ValidationPermissionPacket> StepAsync(ValidationPermissionRoot root, ValidationPermissionStep step, SecretMaterial? capability, CancellationToken token);
}
internal sealed record ValidationPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    ValidationPermissionProfile Profile, ValidationPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    ValidationPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        ValidationPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("validationPermission", out _);
    internal static ValidationPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("validationPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<ValidationPermissionInput>(ValidationPermissionContract.Options);
            ValidationPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            ValidationPermissionVerifier.Validate(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[ValidationPermissionInput]";
}
internal static class ValidationPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Where(op => !op.EndsWith("OrganizationRole", StringComparison.Ordinal)).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static ValidationPermissionScope Scope(string operation) => ValidationPermissionScope.Project;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static ValidationPermissionAction[] Actions(ValidationPermissionScope scope) => Enum.GetValues<ValidationPermissionAction>();
    internal static string? Gate(ValidationPermissionScope scope, ValidationPermissionAction action) => null;
    internal static ValidationPermissionAction[] Supported(ValidationPermissionScope scope) => Actions(scope);
    internal static bool Supports(InfisicalValidationKind kind) => kind == InfisicalValidationKind.StaticSecrets;
    internal static ValidationPermissionAction Baseline(ValidationPermissionRoot root) => (ValidationPermissionAction)(((int)root.Action + 1) % 4);
    internal static string Wire(ValidationPermissionAction action) => action.ToString().ToLowerInvariant();
    internal static string Variant(ValidationPermissionAction action) => "permission.SecretValidationRules." + Wire(action);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string[] Controls(ValidationPermissionAction action) => ["selected", "scope", "actor", "kind", "credential"];
    internal static bool Allowed(ValidationPermissionRoot root, ValidationPermissionRow row, bool after, ValidationPermissionOutcome outcome) =>
        row.Control == "selected" && (after && outcome == ValidationPermissionOutcome.Applied ? row.Action == root.Action :
            !Create(root.Operation) && row.Action == Baseline(root));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static void Require(bool value, string code = "observer-unavailable") => MemberPermissionContract.Require(value, code);
}
internal sealed class ValidationPermissionVerifier : IDisposable
{
    private readonly string rootHash;
    private readonly Dictionary<ValidationPermissionJournal, (ValidationPermissionPin Pin, ECDsa Key)> keys = [];
    private readonly Dictionary<ValidationPermissionJournal, long> sequence = [];
    private readonly HashSet<string> events = [];
    internal static void Validate(ValidationPermissionProfile profile)
    {
        ValidationPermissionContract.Require(profile.Pins.Length == 9 && profile.Pins.Select(p => p.Journal).Distinct().Count() == 9 &&
            profile.Pins.All(p => Enum.IsDefined(p.Journal) && MemberPermissionContract.Text(p.Writer) && MemberPermissionContract.Text(p.Channel) &&
                MemberPermissionContract.Text(p.Schema)) && profile.Pins.Select(p => p.Writer).Distinct().Count() == 9 &&
            profile.Pins.Select(p => p.Channel).Distinct().Count() == 9 &&
            new[] { profile.Deployment, profile.Epoch, profile.Revision }.All(MemberPermissionContract.Text), "missing-input");
        var fingerprints = new HashSet<string>();
        foreach (var pin in profile.Pins)
        {
            using var key = ECDsa.Create(); byte[] spki = Convert.FromBase64String(pin.Spki);
            key.ImportSubjectPublicKeyInfo(spki, out int used);
            ValidationPermissionContract.Require(used == spki.Length && key.KeySize == 256 &&
                key.ExportParameters(false).Curve.Oid.Value == ECCurve.NamedCurves.nistP256.Oid.Value &&
                fingerprints.Add(ValidationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo())), "missing-input");
        }
    }
    internal ValidationPermissionVerifier(ValidationPermissionRoot root)
    {
        Validate(root.Profile); rootHash = ValidationPermissionContract.Hash(root);
        foreach (var pin in root.Profile.Pins)
        {
            var key = ECDsa.Create(); key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(pin.Spki), out _);
            keys.Add(pin.Journal, (pin, key));
        }
    }
    private T Verify<T>(ValidationPermissionSigned<T> value, ValidationPermissionJournal journal, ValidationPermissionStep step)
    {
        var (pin, key) = keys[journal]; byte[] bytes = ValidationPermissionContract.Bytes(value.Payload); bool valid;
        try { valid = key.VerifyData(bytes, Convert.FromBase64String(value.Signature), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
        catch (Exception e) when (e is FormatException or CryptographicException) { valid = false; }
        finally { CryptographicOperations.ZeroMemory(bytes); }
        var h = value.Payload.Header;
        ValidationPermissionContract.Require(valid && h.RootHash == rootHash && h.Journal == journal && h.Writer == pin.Writer &&
            h.Channel == pin.Channel && h.Schema == pin.Schema && h.KeyHash == ValidationPermissionContract.RawHash(key.ExportSubjectPublicKeyInfo()) &&
            h.Step == step && h.Sequence > sequence.GetValueOrDefault(journal) && MemberPermissionContract.Text(h.Event) && events.Add(h.Event));
        sequence[journal] = h.Sequence; return value.Payload.Content;
    }
    internal void Check(ValidationPermissionPacket packet, ValidationPermissionStep step)
    {
        ValidationPermissionContract.Require(packet.Seals.Length == 9 && packet.Seals.Select(s => s.Payload.Header.Journal).Distinct().Count() == 9);
        CheckJournal(packet.Owner, ValidationPermissionJournal.Ownership); CheckJournal(packet.Ingress, ValidationPermissionJournal.Ingress);
        CheckJournal(packet.Policy, ValidationPermissionJournal.Policy); CheckJournal(packet.Storage, ValidationPermissionJournal.Storage);
        CheckJournal(packet.Issuer, ValidationPermissionJournal.Issuer); CheckJournal(packet.Membership, ValidationPermissionJournal.Membership);
        CheckJournal(packet.Access, ValidationPermissionJournal.Access);
        CheckJournal(packet.Enforcement, ValidationPermissionJournal.Enforcement); CheckJournal(packet.Backend, ValidationPermissionJournal.Backend);
        void CheckJournal<T>(ValidationPermissionSigned<T> signed, ValidationPermissionJournal journal)
        {
            _ = Verify(signed, journal, step);
            var seal = Verify(packet.Seals.Single(s => s.Payload.Header.Journal == journal), journal, step);
            ValidationPermissionContract.Require(seal.Terminal && seal.Pending == 0 && seal.Count == 1 && seal.ContentHash == ValidationPermissionContract.Hash(signed.Payload));
        }
    }
    public void Dispose() { foreach (var (_, key) in keys.Values) key.Dispose(); }
}
