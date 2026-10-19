using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private setup capability, never a public user-creation SDK abstraction.
// Public interface facts retrieved through Tavily, 2026-10-14:
// https://infisical.com/docs/api-reference/endpoints/organizations/update-membership
// https://infisical.com/docs/api-reference/endpoints/organizations/delete-membership
// https://infisical.com/docs/api-reference/endpoints/organizations/memberships
// PATCH selects role/isActive/metadata. Membership inventory joins user.id and
// username; mutation replies do not attest permissions. Metadata readback,
// private user creation and a native partial-batch trigger remain unestablished.
//
// Ownership argument (requirements on the separately qualified source):
// 1. Reserve atomically claims (deployment, organization, root, nonce) before
//    Open can start. Collision checks precede all provider creation. Host retains
//    cleanup before Reserve, so neither a lost Reserve nor Open loses authority.
// 2. Each source-issued ID/credential and its issuer work are transactionally
//    enrolled in that root's durable issuance inventory BEFORE they can exist.
//    Recovery includes partially issued users, credentials, memberships, roles,
//    canaries and pending issuer work. A provider without native transactional
//    enrollment needs a qualified issuance coordinator; a label is insufficient.
// 3. Open never creates under a closed root. Close seals the original root,
//    drains/aborts enrolled work, then removes ONLY its resource IDs. The terminal
//    creation fence survives lost replies and prevents resurrection. Close does
//    not require any ID from Open's reply, and never follows substituted IDs.
// 4. Arm grants exactly one original request opportunity. The source recognizes
//    the actual authenticated actor, exact path/body and membership IDs. Settle
//    fences all ingress and in-flight work, joins commits to that request, and
//    reports Applied/NonApplied/Partial independently of the caller's receipt.
//    NotDispatched is not a server-completion claim; it must have zero requests.
// 5. Every sample belongs to the exact deployment/application-clock epoch and
//    source registration. Strict sequence/event uniqueness and source-consumed
//    stages reject replay and late delivery; UTC instants may be equal. No host
//    elapsed-time assumption establishes native completion or cleanup.
// 6. Issuer credential hashes bind actual bytes to a fresh user and membership.
//    The independently authenticated access journal must agree with those joins.
//    Role labels, token inequality, SDK replies and a latest GET are not proof.
//    Group-read canaries exercise organization permissions, not project grants.
//
// These invariants, not fixture tests alone, are the mechanism. This repository
// supplies the client and controlled model, not a qualified external coordinator.
internal enum OrganizationUserSourceKind { NativeProvider, ControlledFixture }
internal enum OrganizationUserOutcome { NonApplied, Applied, Partial }

internal sealed record OrganizationUserAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    internal string Selected(string boundary) => boundary == "denied-authority" ? Denied : Administrative;
    public override string ToString() => "[OrganizationUserAuthorities]";
}

internal sealed record OrganizationUserRoot(string Id, string Nonce, string Origin, string OrganizationId,
    string Operation, string Variant, string Case, string Scope, string ProviderRevision,
    string Deployment, string Epoch, string SourceIdentity, OrganizationUserSourceKind Source,
    OrganizationUserAuthorities Authorities)
{
    public override string ToString() => "[OrganizationUserRoot]";
}

internal sealed record OrganizationUserScopeClock(
    [property: JsonRequired] string Deployment,
    [property: JsonRequired] string Authority,
    [property: JsonRequired] string Epoch,
    [property: JsonRequired] long Sequence,
    [property: JsonRequired] DateTimeOffset At);

internal sealed record OrganizationUserStamp(
    [property: JsonRequired] OrganizationUserRoot Root,
    [property: JsonRequired] string Registration,
    [property: JsonRequired] string Event,
    [property: JsonRequired] OrganizationUserScopeClock Clock)
{
    public override string ToString() => "[OrganizationUserStamp]";
}

internal sealed record OrganizationUserBorrowed(string Kind, string Id, string Revision)
{
    public override string ToString() => "[OrganizationUserBorrowed]";
}

internal sealed record OrganizationUserResource(string RootId, string Nonce, string Kind, string Id)
{
    public override string ToString() => "[OrganizationUserResource]";
}

internal sealed record OrganizationUserReservation(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] bool CollisionChecked,
    [property: JsonRequired] bool ExclusiveRoot,
    [property: JsonRequired] bool TransactionalIssuanceInventory,
    [property: JsonRequired] bool Complete,
    [property: JsonRequired] OrganizationUserResource[] Owned,
    [property: JsonRequired] OrganizationUserBorrowed[] Borrowed)
{
    public override string ToString() => "[OrganizationUserReservation]";
}

internal sealed record OrganizationUserPrincipal(
    [property: JsonRequired] int Slot,
    [property: JsonRequired] string UserId,
    [property: JsonRequired] string Username,
    [property: JsonRequired] string MembershipId,
    [property: JsonRequired] string CredentialId,
    [property: JsonRequired] string CredentialHash,
    [property: JsonRequired] byte[] Credential)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[OrganizationUserPrincipal]";
}

internal sealed record OrganizationUserIssuance(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] OrganizationUserPrincipal[] Principals,
    [property: JsonRequired] string AllowedRole,
    [property: JsonRequired] string DeniedRole,
    [property: JsonRequired] string AllowedRoleId,
    [property: JsonRequired] string DeniedRoleId,
    [property: JsonRequired] string CanaryId,
    [property: JsonRequired] string CanaryName,
    [property: JsonRequired] bool RootReservedBeforeIssuance,
    [property: JsonRequired] bool Complete,
    [property: JsonRequired] bool IndependentCredentialUserJoin,
    [property: JsonRequired] OrganizationUserResource[] Inventory)
{
    internal void Erase() { foreach (var principal in Principals) principal.Erase(); }
    public override string ToString() => "[OrganizationUserIssuance]";
}

internal sealed record OrganizationUserState(string UserId, string MembershipId, string Username,
    string Role, bool Active, string Status)
{
    public override string ToString() => "[OrganizationUserState]";
}

internal sealed record OrganizationUserAccess(string RequestId, string PrincipalId, string? CredentialId,
    string CredentialHash, string CanaryId, bool Allowed)
{
    public override string ToString() => "[OrganizationUserAccess]";
}

internal sealed record OrganizationUserWindow(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] bool Exclusive,
    [property: JsonRequired] bool StateHeld);

internal sealed record OrganizationUserObservation(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] string WindowEvent,
    [property: JsonRequired] string Phase,
    [property: JsonRequired] bool Complete,
    [property: JsonRequired] bool IndependentMembershipStorage,
    [property: JsonRequired] bool IndependentAuthenticatedAccess,
    [property: JsonRequired] bool CredentialIssuanceUnchanged,
    [property: JsonRequired] OrganizationUserState[] Memberships,
    [property: JsonRequired] OrganizationUserAccess[] Access,
    [property: JsonRequired] OrganizationUserBorrowed[] Borrowed)
{
    public override string ToString() => "[OrganizationUserObservation]";
}

internal sealed record OrganizationUserIntent(string Method, string[] MembershipIds, string? Role, bool? Active)
{
    public override string ToString() => "[OrganizationUserIntent]";
}

internal sealed record OrganizationUserArm(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] bool ExactIntent,
    [property: JsonRequired] bool ExclusiveIngress,
    [property: JsonRequired] int MaximumOriginalRequests);

internal sealed record OrganizationUserReceipt(DispatchEvidence Evidence, SecretStatus? Status, bool Cancelled);

internal sealed record OrganizationUserFence(
    [property: JsonRequired] OrganizationUserStamp Stamp,
    [property: JsonRequired] string ArmEvent,
    [property: JsonRequired] OrganizationUserReceipt Receipt,
    [property: JsonRequired] string[] RequestIds,
    [property: JsonRequired] string[] CommittedMembershipIds,
    [property: JsonRequired] OrganizationUserOutcome Outcome,
    [property: JsonRequired] bool ExactAuthenticatedOriginal,
    [property: JsonRequired] bool Terminal,
    [property: JsonRequired] bool LateDispatchExcluded,
    [property: JsonRequired] bool NoReplay,
    [property: JsonRequired] int PendingWork)
{
    public override string ToString() => "[OrganizationUserFence]";
}

internal sealed record OrganizationUserCleanup(
    [property: JsonRequired] OrganizationUserRoot Root,
    [property: JsonRequired] string SourceIdentity,
    [property: JsonRequired] OrganizationUserScopeClock Clock,
    [property: JsonRequired] bool CompleteIssuanceInventory,
    [property: JsonRequired] bool CreationFence,
    [property: JsonRequired] bool DispatchFence,
    [property: JsonRequired] bool OriginalTerminal,
    [property: JsonRequired] bool PrivateCopiesReleased,
    [property: JsonRequired] int PendingIssuers,
    [property: JsonRequired] int PendingDispatches,
    [property: JsonRequired] int Registrations,
    [property: JsonRequired] OrganizationUserResource[] Issued,
    [property: JsonRequired] OrganizationUserResource[] Remaining,
    [property: JsonRequired] OrganizationUserBorrowed[] Borrowed,
    [property: JsonRequired] bool BorrowedPreserved)
{
    public override string ToString() => "[OrganizationUserCleanup]";
}

internal interface IOrganizationUserSource
{
    OrganizationUserSourceKind Kind { get; }
    string Identity { get; }
    ValueTask<OrganizationUserReservation> ReserveAsync(OrganizationUserRoot root, SecretMaterial capability,
        CancellationToken token);
    ValueTask<OrganizationUserIssuance> OpenAsync(OrganizationUserRoot root, CancellationToken token);
    ValueTask<OrganizationUserWindow> BeginAsync(OrganizationUserRoot root, string phase, CancellationToken token);
    ValueTask<OrganizationUserObservation> ObserveAsync(OrganizationUserRoot root, string phase, CancellationToken token);
    ValueTask<OrganizationUserArm> ArmAsync(OrganizationUserRoot root, OrganizationUserIntent intent, CancellationToken token);
    ValueTask<OrganizationUserFence> SettleAsync(OrganizationUserRoot root, OrganizationUserReceipt receipt,
        CancellationToken token);
    ValueTask<OrganizationUserCleanup> CloseAsync(OrganizationUserRoot root, CancellationToken token);
}

internal sealed record OrganizationUserInput(InfisicalLifecycleObservers.Settings Observer,
    string Capability, string Deployment, string Epoch, string ProviderRevision, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment environment, string family, NativeCaseDefinition definition) =>
        OrganizationUserContract.Owns(definition.Key.Operation) && !OrganizationUserContract.Gated(definition.Key.Variant) &&
        environment.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) &&
        scopes.TryGetProperty(definition.Key.Scope, out var scope) && scope.TryGetProperty("organizationUser", out _);

    internal static OrganizationUserInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("organizationUser", out var input)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(input);
            var selected = input.Deserialize<OrganizationUserInput>(OrganizationUserContract.Options);
            OrganizationUserContract.Require(selected is not null && selected.TimeoutSeconds is >= 1 and <= 300 &&
                new[] { selected.Capability, selected.Deployment, selected.Epoch, selected.ProviderRevision }
                    .All(OrganizationUserContract.Text), "missing-input");
            _ = new InfisicalLifecycleObservers(selected!.Observer);
            return selected;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[OrganizationUserInput]";
}

internal static class OrganizationUserContract
{
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    { IgnoreReadOnlyProperties = false };
    internal const string Prefix = "i.management.OrganizationMembershipOperations.";
    internal const string Batch = "i.management.MembershipMutationOperations.DeleteOrganizationMemberships";
    internal static readonly string[] Cases = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    internal static bool Owns(string operation) => operation == Batch ||
        operation is Prefix + "UpdateOrganizationMembership" or Prefix + "DeleteOrganizationMembership" or
            Prefix + "ListOrganizationMemberships";
    internal static bool Gated(string variant) => variant.StartsWith("metadata.", StringComparison.Ordinal) ||
        variant == "result.partial";
    internal static bool List(OrganizationUserRoot root) => root.Operation == Prefix + "ListOrganizationMemberships";
    internal static int Targets(OrganizationUserRoot root) => root.Operation == Batch ? 2 : 1;
    internal static bool BaselineActive(OrganizationUserRoot root) => root.Variant != "isActive.true";
    internal static bool BaselineGranted(OrganizationUserRoot root) => root.Variant is not ("role.value" or "isActive.omitted");
    internal static OrganizationUserIntent Intent(OrganizationUserRoot root, OrganizationUserIssuance issued)
    {
        var ids = issued.Principals.Where(p => p.Slot < Targets(root)).OrderBy(p => p.Slot)
            .Select(p => p.MembershipId).ToArray();
        return List(root) ? new("GET", [], null, null) :
            root.Operation is Batch or Prefix + "DeleteOrganizationMembership" ? new("DELETE", ids, null, null) :
            root.Variant switch
            {
                "role.omitted" => new("PATCH", ids, null, false),
                "role.value" or "isActive.omitted" => new("PATCH", ids, issued.AllowedRole, null),
                "isActive.false" => new("PATCH", ids, null, false),
                "isActive.true" => new("PATCH", ids, null, true),
                _ => throw new NativeCaseFailureException("observer-unavailable")
            };
    }
    internal static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));
    internal static SecretMaterial Material(byte[] bytes)
    {
        char[] chars = Encoding.UTF8.GetChars(bytes);
        try { return SecretMaterial.FromText(chars); }
        finally { Array.Clear(chars); }
    }
    internal static bool Text(string? value) => value is { Length: > 0 and <= 2048 } &&
        !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl);
    internal static bool BorrowedEqual(OrganizationUserBorrowed[] a, OrganizationUserBorrowed[] b) =>
        a.Length == b.Length && a.Distinct().Count() == a.Length &&
        a.Select(r => (r.Kind, r.Id)).Distinct().Count() == a.Length && a.All(b.Contains);
    internal static void Require(bool condition, string reason = "observer-unavailable")
    { if (!condition) throw new NativeCaseFailureException(reason); }
}
