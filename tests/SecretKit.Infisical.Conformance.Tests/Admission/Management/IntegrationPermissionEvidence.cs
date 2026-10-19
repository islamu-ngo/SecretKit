using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Native qualification: zero. This is a bounded, controlled metadata-read witness.
// Public interface facts (2026-10-14):
// https://infisical.com/docs/internals/permissions/project-permissions#subject-integrations
// Parent's independent functional corroboration, main retrieved 2026-10-14:
// https://raw.githubusercontent.com/Infisical/infisical/main/backend/src/server/routes/v1/project-router.ts
// https://raw.githubusercontent.com/Infisical/infisical/main/backend/src/services/integration/integration-service.ts
// GET /:projectId/integrations -> listIntegrationByProject -> Integrations.Read.
// No vendor implementation is copied into this controlled witness.
// ProjectConnectionOperations.ListIntegrations is nonpaginated and its rows do NOT
// attest project/org scope, connector credentials, synchronization or delivery.
// Retain all 24 pairs / 120 native + 120 configured generic rows. Only six read
// pairs / 30 + 30 rows have an exercising SDK seam. CRUD mutations remain gates.
//
// Each native writer must independently enroll this root, retain its own complete
// append-only capture, and fence/drain its actual subsystem. The coordinator can
// collect publications but cannot submit content for a writer to sign. Key
// distinctness and this simulator do not establish native writer independence.
internal enum IntegrationPermissionAction { Read, Create, Edit, Delete }
internal enum IntegrationPermissionScope { Project, Organization }
internal enum IntegrationPermissionJournal { Ownership, Issuer, Storage, Policy, Membership, Ingress, Access, Collection }
internal enum IntegrationPermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum IntegrationPermissionOutcome { NonApplied, Applied, Partial }
internal sealed record IntegrationPermissionPin(IntegrationPermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record IntegrationPermissionProfile(string Deployment, string Epoch, string Revision, IntegrationPermissionPin[] Pins);
internal sealed record IntegrationPermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    IntegrationPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind, IntegrationPermissionAction Action,
    MemberPermissionAuthorities Authorities, IntegrationPermissionProfile Profile)
{
    public override string ToString() => "[IntegrationPermissionRoot]";
}
internal sealed record IntegrationPermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope, string Input, string[] Dependencies);
internal sealed record IntegrationPermissionBinding(string Intent, string IntentHash, string Kind, string Scope, string InputHash,
    string CanonicalId, string Request, string RequestInputHash, string Commit, string ParentCommit);
internal sealed record IntegrationPermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind, string Organization, string Hash, bool Owned);
internal sealed record IntegrationPermissionActor(IntegrationPermissionCredential Identity, byte[] Credential)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[IntegrationPermissionActor]";
}
internal sealed record IntegrationPermissionIssued(IntegrationPermissionBinding[] Bindings, IntegrationPermissionActor[] Actors)
{
    internal string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[IntegrationPermissionIssued]";
}
internal sealed record IntegrationPermissionMetadata(string Id, bool IsActive, string Integration, string AuthorizationId,
    string EnvironmentId, string EnvironmentName, string EnvironmentSlug, string CreatedAt, string UpdatedAt,
    string? Url, string? App, string? AppId, string? TargetEnvironment, string? TargetEnvironmentId,
    string? TargetService, string? TargetServiceId, string? Owner, string? Path, string? Region, string? Scope,
    string? SecretPath, string? LastUsed, string? LastSyncJobId, bool? IsSynced)
{
    internal static IntegrationPermissionMetadata From(ProjectConnectionIntegration row)
    {
        IntegrationPermissionContract.Require(!row.HasProjectScopeAttestation && !row.HasOrganizationScopeAttestation &&
            !row.IncludesMetadata && !row.IncludesSyncMessage, "effect-mismatch");
        return new(row.Id, row.IsActive, row.Integration, row.AuthorizationId, row.EnvironmentId, row.Environment.Name,
            row.Environment.Slug, row.CreatedAt, row.UpdatedAt, row.Url, row.App, row.AppId, row.TargetEnvironment,
            row.TargetEnvironmentId, row.TargetService, row.TargetServiceId, row.Owner, row.Path, row.Region, row.Scope,
            row.SecretPath, row.LastUsed, row.LastSyncJobId, row.IsSynced);
    }
    public override string ToString() => "[IntegrationPermissionMetadata]";
}
internal sealed record IntegrationPermissionStored(string Organization, string Project, IntegrationPermissionMetadata Value);
internal sealed record IntegrationPermissionPolicy(string Id, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Project, string Subject, string[] Actions, string Role, string Configuration, string Template);
internal sealed record IntegrationPermissionPolicyChange(string Request, string PreviousHash, IntegrationPermissionPolicy? Before, IntegrationPermissionPolicy? After);
internal sealed record IntegrationPermissionMember(string Id, string Principal, MemberPermissionActorKind Kind, string Organization,
    string Project, string Role, string Slug, bool Active, string Status, string Assignment = "");
internal sealed record IntegrationPermissionMemberChange(string Request, IntegrationPermissionMember? Before, IntegrationPermissionMember? After);
internal sealed record IntegrationPermissionRequest(string Id, string Actor, MemberPermissionActorKind Kind, string CredentialId,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, string Phase);
internal sealed record IntegrationPermissionDecision(string Request, string RequestHash, string CredentialHash, string Organization,
    string Project, string Subject, string Action, string PolicyHash, string MembershipHash, bool Allowed);
internal sealed record IntegrationPermissionCollection(string Request, string DecisionHash, string Organization, string Project,
    bool Complete, IntegrationPermissionMetadata[] Rows);
internal sealed record IntegrationPermissionCopy(string Request, string Template, string Configuration, string Project,
    string Policy, string Environment, string EnvironmentName, string EnvironmentSlug, double EnvironmentPosition,
    string Membership, string Username, string ParentCommit);
internal sealed record IntegrationPermissionOwner(IntegrationPermissionIntent[] Intents, MemberPermissionBorrowed[] Borrowed, bool Exclusive);
internal sealed record IntegrationPermissionRetirement(string Id, string BindingHash);
internal sealed record IntegrationPermissionEvent(int Sequence, string Previous, string Kind, JsonElement Value);
internal sealed record IntegrationPermissionPublication(string RootHash, IntegrationPermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, IntegrationPermissionStep Step, long Publication, int Count, string Head,
    bool Terminal, bool Fenced, int Pending, IntegrationPermissionEvent[] Events);
internal sealed record IntegrationPermissionSigned(IntegrationPermissionPublication Content, string Signature);
internal sealed record IntegrationPermissionPacket(IntegrationPermissionSigned[] Journals, IntegrationPermissionActor[] Actors)
{
    internal T[] Values<T>(IntegrationPermissionJournal journal, string kind) => Journals.Single(j => j.Content.Journal == journal)
        .Content.Events.Where(e => e.Kind == kind).Select(e => e.Value.Deserialize<T>(IntegrationPermissionContract.Options)!).ToArray();
}
internal sealed record IntegrationPermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
}
internal sealed record IntegrationPermissionRow(string Control, string Project, int Actor);
internal sealed record IntegrationPermissionAttempt(IntegrationPermissionRow Row, string CredentialHash, SecretStatus Status,
    bool Complete, IntegrationPermissionMetadata[] Rows);
internal interface IIntegrationPermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<IntegrationPermissionPacket> StepAsync(IntegrationPermissionRoot root, IntegrationPermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record IntegrationPermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    IntegrationPermissionProfile Profile, IntegrationPermissionScope ScopeProfile, MemberPermissionActorKind ActorKind,
    IntegrationPermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition d) =>
        IntegrationPermissionContract.Owns(d) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("integrationPermission", out _);
    internal static IntegrationPermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("integrationPermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<IntegrationPermissionInput>(IntegrationPermissionContract.Options);
            IntegrationPermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action) &&
                Enum.IsDefined(input.ScopeProfile) && Enum.IsDefined(input.ActorKind), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            IntegrationPermissionVerifier.Validate(input.Profile); return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[IntegrationPermissionInput]";
}
internal static class IntegrationPermissionContract
{
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations => MemberPermissionContract.Operations.Where(op => !op.EndsWith("OrganizationRole", StringComparison.Ordinal)).ToArray();
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static IntegrationPermissionScope Scope(string operation) => IntegrationPermissionScope.Project;
    internal static MemberPermissionActorKind ActorKind(string operation) => MemberPermissionContract.ActorKind(operation);
    internal static bool Create(string operation) => MemberPermissionContract.Create(operation);
    internal static bool Template(string operation) => MemberPermissionContract.Template(operation);
    internal static string Family(string operation) => MemberPermissionContract.Family(operation);
    internal static string Variant(IntegrationPermissionAction action) => "permission.Integrations." + action.ToString().ToLowerInvariant();
    internal static IntegrationPermissionAction[] Actions(IntegrationPermissionScope scope) => Enum.GetValues<IntegrationPermissionAction>();
    internal static string? Gate(IntegrationPermissionScope scope, IntegrationPermissionAction action) =>
        scope != IntegrationPermissionScope.Project || action != IntegrationPermissionAction.Read ? "observer-unavailable" : null;
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Actions(Scope(d.Key.Operation)).Any(a => Variant(a) == d.Key.Variant) && Boundaries.Contains(d.Key.Case) &&
        (InfisicalPermissionFamilies.Valid(d) || InfisicalProjectFamilies.Valid(d));
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static void Require(bool condition, string code = "observer-unavailable") => MemberPermissionContract.Require(condition, code);
}
