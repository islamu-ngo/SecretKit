using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Native qualification: zero. Bounded owned SecretManager name/slug/description patch.
// Primary functional facts, retrieved by the parent on 2026-10-14 (main, not a qualified deployment):
// https://infisical.com/docs/internals/permissions/project-permissions
// https://infisical.com/docs/internals/permissions/organization-permissions
// https://infisical.com/docs/api-reference/endpoints/projects/update-project
// https://raw.githubusercontent.com/Infisical/infisical/main/backend/src/services/project/project-service.ts
// https://raw.githubusercontent.com/Infisical/infisical/main/backend/src/services/org/org-service.ts
// PATCH /api/v1/projects/{projectId} requires project Settings.edit, NOT Workspace.edit.
// No organization-update or workflow-settings read/delete SDK seam is invented.
// Retain 32 pairs / 160 native + 160 configured generic rows: six project edit
// pairs / 30 + 30 supported locally; remaining 26 pairs / 130 + 130 gated.
// Seven independently enrolled writers own immutable capture and terminal count/head.
// The coordinator cannot submit snapshots for signing. Native source independence,
// deployment revision and provider qualification remain external, unqualified gates.
// Storage captures the complete bounded configuration, including workflow and other
// unprojected configuration digests. Missing SDK fields are never inferred from a
// mutation response. Observer reads corroborate fields the typed SDK exposes.
internal enum SettingsPermissionAction { Read, Create, Edit, Delete }
internal enum SettingsPermissionScope { Project, Organization }
internal enum SettingsPermissionJournal { Ownership, Issuer, Storage, Policy, Membership, Ingress, Access }
internal enum SettingsPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum SettingsPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record SettingsPermissionPin(SettingsPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record SettingsPermissionProfile(string Deployment, string Epoch, string Revision, SettingsPermissionPin[] Pins);
internal sealed record SettingsPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    SettingsPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, SettingsPermissionAction Action,
    MemberPermissionAuthorities Authorities, SettingsPermissionProfile Profile)
{
    public override string ToString() => "[SettingsPermissionRoot]";
}
internal sealed record SettingsPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope, string Input, string[] Dependencies);
internal sealed record SettingsPermissionBinding(string Intent, string IntentHash, string Kind, string Scope, string InputHash,
    string CanonicalId, string Request, string RequestInputHash, string Commit, string ParentCommit);
internal sealed record SettingsPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind, string Organization, string Hash, bool Owned);
internal sealed record SettingsPermissionActor(SettingsPermissionCredential Identity, byte[] Credential)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[SettingsPermissionActor]";
}
internal sealed record SettingsPermissionIssued(SettingsPermissionBinding[] Bindings, SettingsPermissionActor[] Actors)
{
    internal string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[SettingsPermissionIssued]";
}
internal sealed record SettingsPermissionFixed(bool DeleteProtection, bool AutoCapitalization, bool EncryptedMetadata,
    bool SecretSharing, bool LegacyPrivileges, bool BlindIndex, bool LegacySnapshots, int AuditRetention, int PitLimit,
    int ProjectVersion, string DefaultProduct, string? UpgradeStatus, string? CertificateKey, string? SecretManagerKey,
    string IgnoreValuesHash, string WorkflowHash, string UnprojectedHash, string Environment, string EnvironmentName,
    string EnvironmentSlug, double EnvironmentPosition, string DeletedEnvironmentsHash);
internal sealed record SettingsPermissionState(string Id, string Organization, string Name, string Slug, string Description,
    string Type, string CreatedAt, string UpdatedAt, int Revision, SettingsPermissionFixed Fixed)
{
    public override string ToString() => "[SettingsPermissionState]";
}
internal sealed record SettingsPermissionChange(string Request, string DecisionHash, string InputHash, string Commit,
    SettingsPermissionState? Before, SettingsPermissionState? After);
internal sealed record SettingsPermissionPolicy(string Id, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string Role, string Configuration, string Template);
internal sealed record SettingsPermissionPolicyChange(string Request, string PreviousHash, SettingsPermissionPolicy? Before, SettingsPermissionPolicy? After);
internal sealed record SettingsPermissionMember(string Id, string Principal, MemberPermissionActorKind Kind, string Organization,
    string Project, string Role, string Slug, bool Active, string Status, string Assignment = "");
internal sealed record SettingsPermissionMemberChange(string Request, SettingsPermissionMember? Before, SettingsPermissionMember? After);
internal sealed record SettingsPermissionRequest(string Id, string Actor, MemberPermissionActorKind Kind, string CredentialId,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, string Phase);
internal sealed record SettingsPermissionDecision(string Request, string RequestHash, string CredentialHash, string Organization,
    string Project, string Subject, string Action, string PolicyHash, string MembershipHash, bool Allowed);
internal sealed record SettingsPermissionCopy(string Request, string Template, string Configuration, string Project,
    string Policy, string Environment, string EnvironmentName, string EnvironmentSlug, double EnvironmentPosition,
    string Membership, string Username, string ParentCommit);
internal sealed record SettingsPermissionOwner(SettingsPermissionIntent[] Intents, MemberPermissionBorrowed[] Borrowed, bool Exclusive);
internal sealed record SettingsPermissionRetirement(string Id, string BindingHash);
internal sealed record SettingsPermissionEvent(int Sequence, string Previous, string Kind, JsonElement Value);
internal sealed record SettingsPermissionPublication(string RootHash, SettingsPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, SettingsPermissionStep Step, long Publication, int Count, string Head,
    bool Terminal, bool Fenced, int Pending, SettingsPermissionEvent[] Events);
internal sealed record SettingsPermissionSigned(SettingsPermissionPublication Content, string Signature);
internal sealed record SettingsPermissionPacket(SettingsPermissionSigned[] Journals, SettingsPermissionActor[] Actors)
{
    internal T[] Values<T>(SettingsPermissionJournal journal, string kind) => Journals.Single(j => j.Content.Journal == journal)
        .Content.Events.Where(e => e.Kind == kind).Select(e => e.Value.Deserialize<T>(SettingsPermissionContract.Options)!).ToArray();
}
internal sealed record SettingsPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
}
internal sealed record SettingsPermissionRow(string Control, string Project, int Actor);
internal sealed record SettingsPermissionAttempt(SettingsPermissionRow Row, string CredentialHash, SecretStatus Status,
    ManagementReceipt Receipt, DispatchEvidence Evidence, string InputHash, ProjectSummary? Value);
internal interface ISettingsPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<SettingsPermissionPacket> StepAsync(SettingsPermissionRoot root, SettingsPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record SettingsPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    SettingsPermissionProfile Profile, SettingsPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    SettingsPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        SettingsPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("settingsPermission", out _);
    internal static SettingsPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("settingsPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<SettingsPermissionInput>(SettingsPermissionContract.Options);
            SettingsPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            SettingsPermissionVerifier.Validate(input.Profile); return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[SettingsPermissionInput]";
}
internal static class SettingsPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations;
    internal static string[] SupportedOperations => Operations.Where(op => Scope(op) == SettingsPermissionScope.Project).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static SettingsPermissionScope Scope(string operation) => operation.EndsWith("OrganizationRole", StringComparison.Ordinal) ? SettingsPermissionScope.Organization : SettingsPermissionScope.Project;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static string Variant(SettingsPermissionAction action) => "permission.Settings." + action.ToString().ToLowerInvariant();
    internal static SettingsPermissionAction[] Actions(SettingsPermissionScope scope) => Enum.GetValues<SettingsPermissionAction>();
    internal static string? Gate(SettingsPermissionScope scope, SettingsPermissionAction action) =>
        scope != SettingsPermissionScope.Project || action != SettingsPermissionAction.Edit ? "observer-unavailable" : null;
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static void Require(bool condition, string code = "observer-unavailable") => MemberPermissionContract.Require(condition, code);
}
