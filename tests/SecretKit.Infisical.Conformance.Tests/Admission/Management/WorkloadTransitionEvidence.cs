using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.Core;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

// Private, separately qualified measurement/provisioning protocol; NOT native
// Infisical API vocabulary. Native coordinator/profile/clock/join qualification: 0.
// Public functional facts supplied with this task (2026-10-14):
// https://infisical.com/docs/api-reference/endpoints/kubernetes-auth/update
// https://infisical.com/docs/api-reference/endpoints/oidc-auth/update
// Unlink retains copied settings. Kubernetes documents reviewer/client fallback,
// but null/clear/encrypted readback boundaries are not established by these facts.
// https://infisical.com/docs/api-reference/endpoints/jwt-auth/attach
// Static keys are described; accepting an empty array is NOT established.
//
// Causal invariant: authenticated ingress owns original request IDs; the SDK
// receipt does not. Reserve an exclusive original window before dispatch and
// admit at most one matching authenticated request. Storage commits identify
// their cause and predecessor revision. Reviewer events name the exact login
// ingress and consumed configuration revision; issuance names that review;
// access names the issued token fingerprint and authenticated principal.
// Each journal has an independently pinned writer/schema, monotonic sequence,
// unique event IDs and root/deployment/epoch/revision. Cross-journal timestamps
// are not an ordering oracle. Only explicit parent edges establish causality.
// A terminal exclusive window seals dispatch and subordinate work. Partial is
// derived from causal commits, NEVER latest GET or the source's boolean verdict.
// Stages are consumed before I/O; failure permits only original-root Close.
// Enroll identities, proofs, resources and issuer work BEFORE creating them.
// Close uses the original root even after Reserve/Open loses its reply; it seals
// creation/dispatch, drains work, inventories every enrolled resource and proves
// absence plus borrowed preservation. No returned ID is needed for recovery.
internal enum WorkloadTransitionSourceKind { NativeProvider, ControlledFixture }
internal enum WorkloadTransitionOutcome { Applied, NonApplied, Partial }
internal enum WorkloadTransitionField { Omitted, Value, Null }

internal sealed record WorkloadTransitionAuthorities(string Setup, string Runtime, string Denied,
    string Administrative, string Observer)
{
    internal string[] All => [Setup, Runtime, Denied, Administrative, Observer];
    internal string Actor(string boundary) => boundary == "denied-authority" ? Denied : Administrative;
    public override string ToString() => "[WorkloadTransitionAuthorities]";
}
internal sealed record WorkloadTransitionJournal(string Kind, string Writer, string Schema);
internal sealed record WorkloadTransitionProfile(string Revision, string Deployment, string Epoch,
    WorkloadTransitionJournal[] Journals, bool CopiedTemplateRetention, bool ReviewerNullUsesClient,
    bool OmittedReviewerUsesClient)
{
    public override string ToString() => "[WorkloadTransitionProfile]";
}
internal sealed record WorkloadTransitionRoot(string Id, string Nonce, string Origin, string Organization,
    string Operation, string Variant, string Boundary, string Scope, string Source,
    WorkloadTransitionSourceKind Kind, WorkloadTransitionAuthorities Authorities, WorkloadTransitionProfile Profile)
{
    public override string ToString() => "[WorkloadTransitionRoot]";
}
internal sealed record WorkloadTransitionStamp(WorkloadTransitionRoot Root, string Registration,
    string Event, long Sequence, DateTimeOffset At);
internal sealed record WorkloadTransitionEvent(string Root, string Nonce, string Deployment, string Epoch,
    string ProviderRevision, string Journal, string Writer, string Schema, string Id, long Sequence, string Window);
internal sealed record WorkloadTransitionResource(string Root, string Nonce, string Kind, string Id);
internal sealed record WorkloadTransitionBorrowed(string Kind, string Id, string Revision);
internal sealed record WorkloadTransitionReservation(WorkloadTransitionStamp Stamp, bool CollisionChecked,
    bool Exclusive, bool EnrolledBeforeCreation, WorkloadTransitionBorrowed[] Borrowed);

// Semantic storage, not encrypted GET fields. Public keys identify real proof
// verification; reviewer identity is measured from authenticated TokenReview.
internal sealed record WorkloadTransitionConfiguration(bool Attached, string Revision, string? Template,
    string PublicKey, string Subject, string? Reviewer, string Issuer, string Audience)
{
    public override string ToString() => "[WorkloadTransitionConfiguration]";
}
internal sealed record WorkloadTransitionPrincipal(string Identity, string Project, string CanaryKey,
    string CanaryValue)
{
    public override string ToString() => "[WorkloadTransitionPrincipal]";
}
internal sealed record WorkloadTransitionProof(string Name, string Jwt, string PublicKey, string Subject)
{
    public override string ToString() => "[WorkloadTransitionProof]";
}
internal sealed record WorkloadTransitionIssuance(WorkloadTransitionStamp Stamp, bool Complete,
    WorkloadTransitionPrincipal Target, WorkloadTransitionPrincipal Control,
    string TemplateA, string TemplateB, string ReviewerA, string ReviewerB,
    string ReviewerCredentialB, string ReviewerHashA, string ReviewerHashB, string Issuer, string Audience,
    WorkloadTransitionConfiguration Baseline, WorkloadTransitionConfiguration TemplateConfigurationA,
    WorkloadTransitionConfiguration TemplateConfigurationB, WorkloadTransitionProof[] Proofs,
    WorkloadTransitionResource[] Inventory)
{
    public override string ToString() => "[WorkloadTransitionIssuance]";
}
internal sealed record WorkloadTransitionIntent(string Method, string Path, WorkloadTransitionField Template,
    string? TemplateId, WorkloadTransitionField Reviewer, string? ReviewerHash, bool EmptyKeys);
internal sealed record WorkloadTransitionWindow(WorkloadTransitionStamp Stamp, string Phase, bool Exclusive,
    bool StateHeld);
internal sealed record WorkloadTransitionArm(WorkloadTransitionStamp Stamp, WorkloadTransitionIntent Intent,
    bool Exclusive, int MaximumRequests);
internal sealed record WorkloadTransitionIngress(WorkloadTransitionEvent Event, string RequestId,
    string Actor, string Identity, string Method, string Path, WorkloadTransitionIntent? Intent,
    string? ProofHash, string? ConfigurationRevision, bool Authorized, string? SdkIntentHash = null);
internal sealed record WorkloadTransitionStorage(WorkloadTransitionEvent Event, string CauseRequest,
    string Identity, string PreviousRevision, WorkloadTransitionConfiguration Configuration);
internal sealed record WorkloadTransitionReview(WorkloadTransitionEvent Event, string LoginRequest,
    string Identity, string ConfigurationRevision, string ProofHash, string Reviewer,
    string CredentialHash, bool Allowed);
internal sealed record WorkloadTransitionToken(WorkloadTransitionEvent Event, string LoginRequest,
    string ReviewEvent, string Identity, string ConfigurationRevision, string TokenHash, string TokenId);
internal sealed record WorkloadTransitionAccess(WorkloadTransitionEvent Event, string RequestId,
    string TokenHash, string Identity, string Project, string Key, bool Allowed);
internal sealed record WorkloadTransitionObservation(WorkloadTransitionStamp Stamp, string Window,
    string Phase, bool Complete, WorkloadTransitionConfiguration Target,
    WorkloadTransitionConfiguration Control, WorkloadTransitionStorage[] Snapshots, WorkloadTransitionIngress[] Logins,
    WorkloadTransitionReview[] Reviews, WorkloadTransitionToken[] Tokens, WorkloadTransitionAccess[] Access,
    WorkloadTransitionBorrowed[] Borrowed);
internal sealed record WorkloadTransitionReceipt(DispatchEvidence Evidence, SecretStatus? Status, bool Cancelled,
    string? IntentHash = null);
internal sealed record WorkloadTransitionFence(WorkloadTransitionStamp Stamp, string Arm,
    bool Terminal, bool Exclusive, bool NoReplay, int PendingWork,
    WorkloadTransitionIngress[] Requests, WorkloadTransitionStorage[] Commits);
internal sealed record WorkloadTransitionCleanup(WorkloadTransitionStamp Stamp, bool CreationFence,
    bool DispatchFence, bool CompleteInventory, int PendingWork, int Registrations,
    WorkloadTransitionResource[] Enrolled, WorkloadTransitionResource[] Remaining,
    WorkloadTransitionBorrowed[] Borrowed);
internal sealed record WorkloadTransitionAttempt(string Identity, string ProofHash, bool Allowed,
    string? TokenHash, WorkloadTransitionRead[] Reads);
internal sealed record WorkloadTransitionRead(string TokenHash, string Identity, string Project, string Key, bool Allowed);

internal interface IWorkloadTransitionSource
{
    string Identity { get; }
    WorkloadTransitionSourceKind Kind { get; }
    ValueTask<WorkloadTransitionReservation> ReserveAsync(WorkloadTransitionRoot root, SecretMaterial capability, CancellationToken token);
    ValueTask<WorkloadTransitionIssuance> OpenAsync(WorkloadTransitionRoot root, CancellationToken token);
    ValueTask<WorkloadTransitionWindow> BeginAsync(WorkloadTransitionRoot root, string phase, CancellationToken token);
    ValueTask<WorkloadTransitionObservation> ObserveAsync(WorkloadTransitionRoot root, string phase, CancellationToken token);
    ValueTask<WorkloadTransitionArm> ArmAsync(WorkloadTransitionRoot root, CancellationToken token);
    ValueTask<WorkloadTransitionFence> SettleAsync(WorkloadTransitionRoot root, CancellationToken token);
    ValueTask<WorkloadTransitionCleanup> CloseAsync(WorkloadTransitionRoot root, CancellationToken token);
}

internal sealed record WorkloadTransitionInput(InfisicalLifecycleObservers.Settings Observer,
    string Capability, WorkloadTransitionProfile Profile, int TimeoutSeconds)
{
    internal static bool Selected(NativeEnvironment environment, string family, NativeCaseDefinition d) =>
        WorkloadTransitionContract.Owns(d) && environment.TryGetFamilyInput(family, out var input) &&
        input.TryGetProperty("scopes", out var scopes) && scopes.TryGetProperty(d.Key.Scope, out var scope) &&
        scope.TryGetProperty("workloadTransition", out _);
    internal static WorkloadTransitionInput? FromScope(JsonElement scope)
    {
        if (!scope.TryGetProperty("workloadTransition", out var value)) return null;
        try
        {
            NativeRunProtocol.RejectDuplicates(value);
            var input = value.Deserialize<WorkloadTransitionInput>(WorkloadTransitionContract.Options);
            WorkloadTransitionContract.Require(input is not null && input.TimeoutSeconds is >= 1 and <= 300 &&
                WorkloadTransitionContract.Text(input.Capability), "missing-input");
            _ = new InfisicalLifecycleObservers(input!.Observer);
            WorkloadTransitionContract.Profile(input.Profile);
            return input;
        }
        catch (Exception e) when (e is JsonException or ArgumentException or InvalidOperationException)
        { throw new NativeCaseFailureException("missing-input"); }
    }
    public override string ToString() => "[WorkloadTransitionInput]";
}

internal static class WorkloadTransitionContract
{
    internal const string Prefix = "i.management.WorkloadIdentityAuthenticationOperations.";
    internal static readonly string[] Cases = ["selected-contract", "independent-effect", "denied-authority",
        "cancellation-boundary", "lost-response-no-replay"];
    internal static readonly string[] Journals = ["ingress", "storage", "reviewer", "issuance", "access"];
    internal static JsonSerializerOptions Options { get; } = new(InfisicalStaticFamilies.Options)
    { IgnoreReadOnlyProperties = false, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
    internal static bool Owns(NativeCaseDefinition d) => InfisicalIdentityAuthenticationFamilies.Valid(d) &&
        d.Key.Operation.StartsWith(Prefix, StringComparison.Ordinal) &&
        (d.Key.Operation[Prefix.Length..].StartsWith("Attach", StringComparison.Ordinal) ||
            d.Key.Operation[Prefix.Length..].StartsWith("Update", StringComparison.Ordinal)) &&
        !d.Key.Variant.EndsWith(".rejected", StringComparison.Ordinal) &&
        (d.Key.Variant == "publicKeys.empty" || d.Key.Variant.Contains("templateId", StringComparison.Ordinal) ||
            d.Key.Variant.Contains("tokenReviewerJwt", StringComparison.Ordinal) ||
            d.Key.Variant.Contains("reviewerJwt", StringComparison.Ordinal) ||
            d.Key.Variant.Contains("clearTokenReviewerJwt", StringComparison.Ordinal));
    internal static bool Attach(WorkloadTransitionRoot root) => root.Operation[Prefix.Length..].StartsWith("Attach", StringComparison.Ordinal);
    internal static string Mechanism(WorkloadTransitionRoot root) => root.Operation.Contains("Kubernetes", StringComparison.Ordinal) ?
        "kubernetes" : root.Operation.Contains("Oidc", StringComparison.Ordinal) ? "oidc" : "jwt";
    internal static string? Gate(NativeCaseDefinition d, WorkloadTransitionInput? input)
    {
        if (!Owns(d)) return "contract-mismatch";
        if (d.Key.Variant == "publicKeys.empty") return "empty-static-key-authentication-witness-unavailable";
        if (input is null) return "reviewer-template-transition-observer-unavailable";
        if (!input.Profile.CopiedTemplateRetention || !input.Profile.ReviewerNullUsesClient ||
            !input.Profile.OmittedReviewerUsesClient) return "observer-unavailable";
        return null;
    }
    internal static void Profile(WorkloadTransitionProfile p) => Require(p is not null &&
        new[] { p.Revision, p.Deployment, p.Epoch }.All(Text) &&
        p.Journals.Length == Journals.Length && Journals.All(k => p.Journals.Count(j => j.Kind == k) == 1) &&
        p.Journals.All(j => Text(j.Writer) && Text(j.Schema)) &&
        p.Journals.Select(j => j.Writer).Distinct().Count() == Journals.Length, "missing-input");
    internal static WorkloadTransitionIntent Intent(WorkloadTransitionRoot root, WorkloadTransitionIssuance issued)
    {
        string v = root.Variant;
        var template = v.EndsWith("templateId.value", StringComparison.Ordinal) ? WorkloadTransitionField.Value :
            v == "templateId.null" ? WorkloadTransitionField.Null : WorkloadTransitionField.Omitted;
        var reviewer = v.EndsWith("tokenReviewerJwt.value", StringComparison.Ordinal) ? WorkloadTransitionField.Value :
            v == "reviewerJwt.null" || v.EndsWith("clearTokenReviewerJwt.true", StringComparison.Ordinal) ?
                WorkloadTransitionField.Null : WorkloadTransitionField.Omitted;
        return new(Attach(root) ? "POST" : "PATCH",
            "/api/v1/auth/" + Mechanism(root) + "-auth/identities/" + issued.Target.Identity,
            template, template == WorkloadTransitionField.Value ? issued.TemplateB : null,
            reviewer, reviewer == WorkloadTransitionField.Value ? issued.ReviewerHashB : null, v == "publicKeys.empty");
    }
    internal static WorkloadTransitionConfiguration Expected(WorkloadTransitionRoot root, WorkloadTransitionIssuance issued)
    {
        var intent = Intent(root, issued);
        var current = Attach(root) ? issued.TemplateConfigurationB with { Template = null, Reviewer = null } : issued.Baseline;
        if (intent.Template == WorkloadTransitionField.Value) current = issued.TemplateConfigurationB;
        if (intent.Template == WorkloadTransitionField.Null) current = current with { Template = null };
        if (intent.Reviewer == WorkloadTransitionField.Value)
            current = current with { Reviewer = issued.ReviewerB, PublicKey = issued.TemplateConfigurationB.PublicKey };
        if (intent.Reviewer == WorkloadTransitionField.Null) current = current with { Reviewer = null };
        return current with { Attached = true };
    }
    internal static bool SemanticEqual(WorkloadTransitionConfiguration a, WorkloadTransitionConfiguration b) =>
        a with { Revision = b.Revision } == b;
    internal static bool SameRoot(WorkloadTransitionRoot a, WorkloadTransitionRoot b) =>
        JsonSerializer.Serialize(a, Options) == JsonSerializer.Serialize(b, Options);
    internal static bool Text(string? text) => text is { Length: > 0 and <= 16384 } &&
        !string.IsNullOrWhiteSpace(text) && !text.Any(char.IsControl);
    internal static void Require(bool value, string reason = "observer-unavailable")
    { if (!value) throw new NativeCaseFailureException(reason); }
    internal static string Hash(string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    internal static bool Borrowed(WorkloadTransitionBorrowed[] a, WorkloadTransitionBorrowed[] b) =>
        a.Length == b.Length && a.Select(x => (x.Kind, x.Id)).Distinct().Count() == a.Length && a.All(b.Contains);
}
