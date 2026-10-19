using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private provisioning and measurement contract, not a provider API or user
// issuer. Public vocabulary checked through Tavily on 2026-10-14:
// https://infisical.com/docs/api-reference/endpoints/projects/list-projects
// GET /api/v1/projects selects type/includeRoles; projects contain orgId,
// identity, timestamps, lifecycle fields and optional embedded role metadata.
// That reference currently omits agent-vault from its query enumeration.
// The current SDK accepts it; live revision/entitlement qualification stays 0.
//
// Separately qualified source requirements:
// Reserve collision-checks the original host root/nonce before any creation.
// Source-chosen project and role IDs, including pending issuer work, enter the
// root's durable issuance inventory BEFORE creation. Close uses only that root,
// seals creation and ingress, drains pending work, and removes its enrolled
// IDs. Lost Open and partial issuance must not strand authority or resources.
// Observe reads independent provider type/inventory and authenticated request
// journals under a held window, not the SDK list response or a final GET.
// Arm admits 0..1 exact original GET, bound to actor, scope and typed query.
// Settle consumes the stage and closes ingress without inventing a mutation
// receipt. No read-only lost-response variant is admitted.
// Deployment/source/epoch/revision/root/nonce joins and strictly increasing
// source sequences are required. UTC times can be equal; host time proves
// neither native termination nor cleanup. Fixture atomicity is controlled
// evidence only, not a claim about an external provisioning coordinator.
internal enum ProjectTypeSourceKind { NativeProvider, ControlledFixture }

internal sealed record ProjectTypeAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    internal string Actor(string boundary) => boundary == "denied-authority" ? Denied : Administrative;
    public override string ToString() => "[ProjectTypeAuthorities]";
}

internal sealed record ProjectTypeQuery(ProjectType? Type, bool? IncludeRoles)
{
    public override string ToString() => "[ProjectTypeQuery]";
}

internal sealed record ProjectTypeRoot(string Id, string Nonce, string Origin, string OrganizationId,
    string Operation, string Variant, string Case, string Scope, string ProviderRevision,
    string Deployment, string Epoch, string SourceIdentity, ProjectTypeSourceKind Source,
    ProjectTypeAuthorities Authorities, ProjectTypeQuery Query)
{
    public override string ToString() => "[ProjectTypeRoot]";
}

internal sealed record ProjectTypeClock(
    [property: JsonRequired] string Deployment, [property: JsonRequired] string Epoch,
    [property: JsonRequired] string Authority, [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At);
internal sealed record ProjectTypeStamp(
    [property: JsonRequired] ProjectTypeRoot Root, [property: JsonRequired] string Registration,
    [property: JsonRequired] string Event, [property: JsonRequired] ProjectTypeClock Clock);
internal sealed record ProjectTypeResource(string RootId, string Nonce, string Kind, string Id);
internal sealed record ProjectTypeBorrowed(string Kind, string Id, string Revision);
internal sealed record ProjectTypeRole(string Id, string Name, string Slug, string Description,
    string CreatedAt, string UpdatedAt, double Version);
internal sealed record ProjectTypeMetadata(string? UpgradeStatus, string? KmsCertificateKeyId,
    string? KmsSecretManagerKeyId, double? AuditLogsRetentionDays, double PitVersionLimit,
    bool? AutoCapitalization, bool? EncryptedMetadata, bool LegacyAdditionalPrivileges,
    bool SecretBlindIndexEnabled, bool SecretSharing, bool ShowSnapshotsLegacy, string[] IgnoreValues,
    int EnvironmentCount, int DeletedEnvironmentCount);
internal sealed record ProjectTypeState(string OrganizationId, string Id, string Name, string Slug,
    string Type, string Description, string CreatedAt, string UpdatedAt, string NativeId,
    string DefaultProduct, double Version, bool DeleteProtection, ProjectTypeMetadata Metadata, ProjectTypeRole[] Roles)
{
    public override string ToString() => "[ProjectTypeState]";
}
internal sealed record ProjectTypeReservation(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] bool CollisionChecked,
    [property: JsonRequired] bool ExclusiveRoot, [property: JsonRequired] bool EnrolledBeforeCreation,
    [property: JsonRequired] bool Complete, [property: JsonRequired] ProjectTypeResource[] Owned,
    [property: JsonRequired] ProjectTypeBorrowed[] Borrowed);
internal sealed record ProjectTypeIssuance(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] bool RootReservedBeforeCreation,
    [property: JsonRequired] bool Complete, [property: JsonRequired] ProjectTypeState[] Projects,
    [property: JsonRequired] ProjectTypeResource[] Inventory);
internal sealed record ProjectTypeWindow(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] string Phase,
    [property: JsonRequired] bool Exclusive, [property: JsonRequired] bool StateHeld);
internal sealed record ProjectTypeAccess(string RequestId, string Actor, string OrganizationId,
    ProjectTypeQuery Query, bool Allowed);
internal sealed record ProjectTypeObservation(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] string WindowEvent,
    [property: JsonRequired] string Phase, [property: JsonRequired] bool Complete,
    [property: JsonRequired] bool IndependentTypeStorage, [property: JsonRequired] bool IndependentInventory,
    [property: JsonRequired] bool IndependentAuthenticatedAccess,
    [property: JsonRequired] ProjectTypeState[] Projects, [property: JsonRequired] ProjectTypeAccess[] Access,
    [property: JsonRequired] ProjectTypeBorrowed[] Borrowed);
internal sealed record ProjectTypeArm(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] bool ExactQuery,
    [property: JsonRequired] bool ExclusiveIngress, [property: JsonRequired] int MaximumOriginalRequests);
// GET has status/cancellation only; there is deliberately no DispatchEvidence.
internal sealed record ProjectTypeReadResult(SecretStatus? Status, bool Cancelled);
internal sealed record ProjectTypeOriginal(string RequestId, string Actor, string OrganizationId,
    string Method, string Path, ProjectTypeQuery Query);
internal sealed record ProjectTypeFence(
    [property: JsonRequired] ProjectTypeStamp Stamp, [property: JsonRequired] string ArmEvent,
    [property: JsonRequired] bool Terminal, [property: JsonRequired] bool LateDispatchExcluded,
    [property: JsonRequired] bool NoReplay, [property: JsonRequired] int PendingWork,
    [property: JsonRequired] ProjectTypeOriginal[] Requests);
internal sealed record ProjectTypeCleanup(
    [property: JsonRequired] ProjectTypeRoot Root, [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] ProjectTypeClock Clock, [property: JsonRequired] bool CompleteIssuanceInventory,
    [property: JsonRequired] bool CreationFence, [property: JsonRequired] bool DispatchFence,
    [property: JsonRequired] bool OriginalTerminal, [property: JsonRequired] int PendingIssuers,
    [property: JsonRequired] int PendingDispatches, [property: JsonRequired] int Registrations,
    [property: JsonRequired] ProjectTypeResource[] Issued, [property: JsonRequired] ProjectTypeResource[] Remaining,
    [property: JsonRequired] ProjectTypeBorrowed[] Borrowed, [property: JsonRequired] bool BorrowedPreserved);

internal interface IProjectTypeSource
{
    ProjectTypeSourceKind Kind { get; }
    string Identity { get; }
    ValueTask<ProjectTypeReservation> ReserveAsync(ProjectTypeRoot root, SecretMaterial capability, CancellationToken token);
    ValueTask<ProjectTypeIssuance> OpenAsync(ProjectTypeRoot root, CancellationToken token);
    ValueTask<ProjectTypeWindow> BeginAsync(ProjectTypeRoot root, string phase, CancellationToken token);
    ValueTask<ProjectTypeObservation> ObserveAsync(ProjectTypeRoot root, string phase, CancellationToken token);
    ValueTask<ProjectTypeArm> ArmAsync(ProjectTypeRoot root, CancellationToken token);
    ValueTask<ProjectTypeFence> SettleAsync(ProjectTypeRoot root, CancellationToken token);
    ValueTask<ProjectTypeCleanup> CloseAsync(ProjectTypeRoot root, CancellationToken token);
}

internal sealed record ProjectTypeInput(InfisicalLifecycleObservers.Settings Observer,
    string Capability, string Deployment, string Epoch, string ProviderRevision, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment environment, string family, NativeCaseDefinition definition) =>
        ProjectTypeContract.Owns(definition.Key.Operation) &&
        environment.TryGetFamilyInput(family, out var input) && input.TryGetProperty("scopes", out var scopes) &&
        scopes.TryGetProperty(definition.Key.Scope, out var scope) && scope.TryGetProperty("projectType", out _);
    internal static ProjectTypeInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("projectType", out var input)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(input);
            var value = input.Deserialize<ProjectTypeInput>(ProjectTypeContract.Options);
            ProjectTypeContract.Require(value is not null && value.TimeoutSeconds is >= 1 and <= 300 &&
                new[] { value.Capability, value.Deployment, value.Epoch, value.ProviderRevision }
                    .All(ProjectTypeContract.Text), "missing-input");
            _ = new InfisicalLifecycleObservers(value!.Observer);
            return value;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[ProjectTypeInput]";
}

internal static class ProjectTypeContract
{
    internal const string Operation = "i.management.ProjectOperations.ListProjects";
    internal static readonly string[] Cases = ["selected-contract", "independent-effect",
        "denied-authority", "cancellation-boundary"];
    internal static readonly string[] Variants = ["type.SecretManager", "type.CertificateManager", "type.Kms",
        "type.SecretScanning", "type.Pam", "type.AgentVault", "type.omitted", "includeRoles.omitted",
        "includeRoles.false", "includeRoles.true"];
    internal static readonly string[] Types = ["secret-manager", "cert-manager", "kms", "secret-scanning", "pam", "agent-vault"];
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    internal static bool Owns(string operation) => operation == Operation;
    internal static ProjectTypeQuery Query(string variant) => new(variant switch
    {
        "type.omitted" => null,
        "type.CertificateManager" => ProjectType.CertificateManager,
        "type.Kms" => ProjectType.Kms,
        "type.SecretScanning" => ProjectType.SecretScanning,
        "type.Pam" => ProjectType.Pam,
        "type.AgentVault" => ProjectType.AgentVault,
        _ => ProjectType.SecretManager
    }, variant == "includeRoles.omitted" ? null : variant == "includeRoles.true");
    internal static string? Type(ProjectTypeQuery query) =>
        query.Type is { } type ? Types[(int)type] : null;
    internal static bool Text(string? value) => value is { Length: > 0 and <= 2048 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static void Require(bool condition, string reason = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(reason); }
    internal static bool BorrowedEqual(ProjectTypeBorrowed[] a, ProjectTypeBorrowed[] b) =>
        a.Length == b.Length && a.Select(x => (x.Kind, x.Id)).Distinct().Count() == a.Length &&
        a.All(b.Contains);
    internal static bool StateEqual(ProjectTypeState a, ProjectTypeState b) =>
        a with { Roles = b.Roles, Metadata = b.Metadata } == b && a.Roles.SequenceEqual(b.Roles) &&
        a.Metadata with { IgnoreValues = b.Metadata.IgnoreValues } == b.Metadata &&
        a.Metadata.IgnoreValues.SequenceEqual(b.Metadata.IgnoreValues);
    internal static bool StatesEqual(ProjectTypeState[] a, ProjectTypeState[] b) =>
        a.Length == b.Length && a.Select(x => x.Id).Distinct().Count() == a.Length &&
        a.All(x => b.Any(y => StateEqual(x, y)));
}
