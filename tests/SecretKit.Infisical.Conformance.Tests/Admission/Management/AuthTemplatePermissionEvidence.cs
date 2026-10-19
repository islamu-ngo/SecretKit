using System.Security.Cryptography;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Functional facts only, Tavily retrieved 2026-10-14, Infisical revision
// b44114a1d97e361d6ac55bac15e4b352da6b823c:
// https://github.com/Infisical/infisical/blob/b44114a1d97e361d6ac55bac15e4b352da6b823c/backend/src/ee/routes/v1/identity-template-router.ts
// https://github.com/Infisical/infisical/blob/b44114a1d97e361d6ac55bac15e4b352da6b823c/backend/src/ee/services/identity-auth-template/identity-auth-template-service.ts
// OrganizationActionScope.Any uses authenticated actor organization. Search/get/
// usage require list-templates; authMethod available listing requires attach-templates.
// Available listing is NOT linking, propagation, or successful authentication.
// Unlink service supplies no array although router/SDK require one: gate before
// enrollment, never synthesize success. Retain 12 pairs / 60 native + 60 generic;
// five actions / 10 pairs / 50 + 50 supported locally, 2 pairs / 10 + 10 gated.
// Native qualification is zero; entitlement, deployment and separately controlled
// writer enrollment remain external. Simulator keys establish no native authority.
internal enum AuthTemplatePermissionAction { List, Create, Edit, Delete, Unlink, Attach }
internal enum AuthTemplatePermissionJournal { Ownership, Issuer, Storage, Policy, Membership, Ingress, Access, Collection }
internal enum AuthTemplatePermissionStep { Reserve, Open, Before, ObserveBefore, Arm, Settle, After, ObserveAfter, Close }
internal enum AuthTemplatePermissionOutcome { NonApplied, Applied, Partial }
internal sealed record AuthTemplatePermissionPin(AuthTemplatePermissionJournal Journal, string Writer, string Channel, string Schema, string Spki);
internal sealed record AuthTemplatePermissionProfile(string Deployment, string Epoch, string Revision, AuthTemplatePermissionPin[] Pins);
internal sealed record AuthTemplatePermissionRoot(string Id, string Nonce, string Origin, string Organization, string Operation,
    string Variant, string Boundary, string Scope, string Source, MemberPermissionSourceKind Kind,
    AuthTemplatePermissionAction Action, MemberPermissionAuthorities Authorities, AuthTemplatePermissionProfile Profile)
{
    public override string ToString() => "[AuthTemplatePermissionRoot]";
}
internal sealed record AuthTemplatePermissionIntent(string Key, string Root, string Nonce, string Kind, string Scope, string Input, string[] Dependencies);
internal sealed record AuthTemplatePermissionBinding(string Intent, string IntentHash, string Kind, string Scope, string InputHash,
    string CanonicalId, string Request, string RequestInputHash, string Commit, string ParentCommit);
internal sealed record AuthTemplatePermissionCredential(string Id, string Principal, MemberPermissionActorKind Kind, string Organization, string Hash, bool Owned);
internal sealed record AuthTemplatePermissionActor(AuthTemplatePermissionCredential Identity, byte[] Credential)
{
    internal void Erase() => CryptographicOperations.ZeroMemory(Credential);
    public override string ToString() => "[AuthTemplatePermissionActor]";
}
internal sealed record AuthTemplatePermissionIssued(AuthTemplatePermissionBinding[] Bindings, AuthTemplatePermissionActor[] Actors)
{
    internal string Id(string key) => key.StartsWith('@') ? key[1..] : Bindings.SingleOrDefault(b => b.Intent == key)?.CanonicalId ?? "";
    internal void Erase() { foreach (var actor in Actors) actor.Erase(); }
    public override string ToString() => "[AuthTemplatePermissionIssued]";
}
internal sealed record AuthTemplatePermissionConfiguration(string Mode, string Host, string Ca, bool VerifyTls,
    string Audience, bool HasCredential, string CredentialHash, string? Gateway, string? GatewayPool);
internal sealed record AuthTemplatePermissionState(string Id, string Organization, string Name, string Method,
    string CreatedAt, string UpdatedAt, int Revision, AuthTemplatePermissionConfiguration Configuration);
internal sealed record AuthTemplatePermissionChange(string Request, string DecisionHash, string InputHash, string Commit,
    string Target, AuthTemplatePermissionState? Before, AuthTemplatePermissionState? After);
internal sealed record AuthTemplatePermissionPolicy(string Id, string Revision, string Actor, MemberPermissionActorKind Kind,
    string Organization, string Subject, string[] Actions, string Slug, string Configuration);
internal sealed record AuthTemplatePermissionPolicyChange(string Request, string PreviousHash, AuthTemplatePermissionPolicy? Before, AuthTemplatePermissionPolicy? After);
internal sealed record AuthTemplatePermissionMember(string Id, string Principal, MemberPermissionActorKind Kind, string Organization,
    string Role, string Slug, bool Active, string Status, string Assignment);
internal sealed record AuthTemplatePermissionMemberChange(string Request, AuthTemplatePermissionMember? Before, AuthTemplatePermissionMember? After);
internal sealed record AuthTemplatePermissionRequest(string Id, string Actor, MemberPermissionActorKind Kind, string CredentialId,
    string CredentialHash, string Organization, string Method, string Path, string BodyHash, string IntentHash, string Phase);
internal sealed record AuthTemplatePermissionDecision(string Request, string RequestHash, string CredentialHash, string Organization,
    string Subject, string Action, string PolicyHash, string MembershipHash, bool Allowed);
internal sealed record AuthTemplatePermissionCollection(string Request, string DecisionHash, string Organization,
    string Operation, bool Complete, AuthTemplatePermissionState[] Rows);
internal sealed record AuthTemplatePermissionOwner(AuthTemplatePermissionIntent[] Intents, MemberPermissionBorrowed[] Borrowed, bool Exclusive);
internal sealed record AuthTemplatePermissionRetirement(string Id, string BindingHash);
internal sealed record AuthTemplatePermissionEvent(int Sequence, string Previous, string Kind, JsonElement Value);
internal sealed record AuthTemplatePermissionPublication(string RootHash, AuthTemplatePermissionJournal Journal, string Writer,
    string Channel, string Schema, string KeyHash, AuthTemplatePermissionStep Step, long Publication, int Count, string Head,
    bool Terminal, bool Fenced, int Pending, AuthTemplatePermissionEvent[] Events);
internal sealed record AuthTemplatePermissionSigned(AuthTemplatePermissionPublication Content, string Signature);
internal sealed record AuthTemplatePermissionPacket(AuthTemplatePermissionSigned[] Journals, AuthTemplatePermissionActor[] Actors)
{
    internal T[] Values<T>(AuthTemplatePermissionJournal journal, string kind) => Journals.Single(j => j.Content.Journal == journal)
        .Content.Events.Where(e => e.Kind == kind).Select(e => e.Value.Deserialize<T>(AuthTemplatePermissionContract.Options)!).ToArray();
}
internal sealed record AuthTemplatePermissionReceipt(ManagementReceipt Native, SecretStatus? Status, bool Cancelled, string IntentHash)
{
    internal DispatchEvidence Evidence { get; } = Native.Evidence;
}
internal sealed record AuthTemplatePermissionRow(string Control, int Actor, AuthTemplatePermissionAction Action);
internal sealed record AuthTemplatePermissionAttempt(AuthTemplatePermissionRow Row, string CredentialHash, SecretStatus Status,
    ManagementReceipt? Receipt, DispatchEvidence Evidence, string IntentHash, IdentityTemplateSummary[] Values, bool Complete);
internal interface IAuthTemplatePermissionSource
{
    string Identity { get; }
    MemberPermissionSourceKind Kind { get; }
    ValueTask<AuthTemplatePermissionPacket> StepAsync(AuthTemplatePermissionRoot root, AuthTemplatePermissionStep step,
        SecretMaterial? capability, CancellationToken token);
}
internal sealed record AuthTemplatePermissionInput(InfisicalLifecycleObservers.Settings Observer, string Capability,
    AuthTemplatePermissionProfile Profile, AuthTemplatePermissionAction Action, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment env, string family, NativeCaseDefinition definition) =>
        AuthTemplatePermissionContract.Owns(definition) && env.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(definition.Key.Scope, out var scope) &&
        scope.TryGetProperty("authTemplatePermission", out _);
    internal static AuthTemplatePermissionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("authTemplatePermission", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<AuthTemplatePermissionInput>(AuthTemplatePermissionContract.Options);
            AuthTemplatePermissionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                MemberPermissionContract.Text(input.Capability) && Enum.IsDefined(input.Action), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            AuthTemplatePermissionVerifier.Validate(input.Profile); return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException or CryptographicException or FormatException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[AuthTemplatePermissionInput]";
}
internal static class AuthTemplatePermissionContract
{
    internal const string Subject = "machine-identity-auth-template";
    internal const string Path = "/api/v1/identity-templates";
    internal static JsonSerializerOptions Options => MemberPermissionContract.Options;
    internal static string[] Operations =>
        ["i.management.RoleChangeOperations.CreateOrganizationRole", "i.management.RoleChangeOperations.UpdateOrganizationRole"];
    internal static string[] Boundaries => MemberPermissionContract.Boundaries;
    internal static AuthTemplatePermissionAction[] Supported => Enum.GetValues<AuthTemplatePermissionAction>().Where(a => Gate(a) is null).ToArray();
    internal static string Wire(AuthTemplatePermissionAction action) => action.ToString().ToLowerInvariant() + "-templates";
    internal static string Variant(AuthTemplatePermissionAction action) => "permission.MachineIdentityAuthTemplate." + Wire(action);
    internal static string? Gate(AuthTemplatePermissionAction action) => action == AuthTemplatePermissionAction.Unlink ? "observer-unavailable" : null;
    internal static bool Create(string operation) => operation.EndsWith(".CreateOrganizationRole", StringComparison.Ordinal);
    internal static bool Owns(NativeCaseDefinition d) => Operations.Contains(d.Key.Operation) &&
        Enum.GetValues<AuthTemplatePermissionAction>().Any(a => Variant(a) == d.Key.Variant) &&
        Boundaries.Contains(d.Key.Case) && InfisicalPermissionFamilies.Valid(d);
    internal static OrganizationRoleAction Sdk(AuthTemplatePermissionAction action) => action switch
    {
        AuthTemplatePermissionAction.List => OrganizationRoleAction.ListTemplates,
        AuthTemplatePermissionAction.Create => OrganizationRoleAction.CreateTemplates,
        AuthTemplatePermissionAction.Edit => OrganizationRoleAction.EditTemplates,
        AuthTemplatePermissionAction.Delete => OrganizationRoleAction.DeleteTemplates,
        AuthTemplatePermissionAction.Attach => OrganizationRoleAction.AttachTemplates,
        AuthTemplatePermissionAction.Unlink => OrganizationRoleAction.UnlinkTemplates,
        _ => throw new NativeCaseFailureException("missing-input")
    };
    internal static string Hash<T>(T value) => MemberPermissionContract.Hash(value);
    internal static string RawHash(ReadOnlySpan<byte> value) => MemberPermissionContract.RawHash(value);
    internal static byte[] Bytes<T>(T value) => MemberPermissionContract.Bytes(value);
    internal static void Require(bool condition, string code = "observer-unavailable") => MemberPermissionContract.Require(condition, code);
}
