using System.Text.Json;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class InfisicalAuthTemplatePermissionPolicy(InfisicalAuthTemplatePermissionStorage storage,
    InfisicalAuthTemplatePermissionIngress ingress, string fault)
    : InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal.Policy)
{
    private readonly Dictionary<string, AuthTemplatePermissionPolicy> policies = [];
    internal AuthTemplatePermissionPolicy[] Inventory => policies.Values.ToArray();
    internal void Bootstrap(AuthTemplatePermissionActor actor)
    {
        if (AuthTemplatePermissionContract.Create(Root.Operation)) return;
        var binding = storage.Create(AuthTemplatePermissionPlan.Policy);
        Commit("bootstrap", new(binding.CanonicalId, "policy-1", actor.Identity.Principal, actor.Identity.Kind,
            Root.Organization, AuthTemplatePermissionContract.Subject, [], Plan.Slug, "bootstrap"));
    }
    internal void Apply(AuthTemplatePermissionRequest request, byte[] bytes, AuthTemplatePermissionActor actor)
    {
        Accept(); AuthTemplatePermissionContract.Require(ingress.Contains(request) && request.BodyHash == AuthTemplatePermissionContract.RawHash(bytes));
        using var document = JsonDocument.Parse(bytes); var body = document.RootElement;
        var permission = body.GetProperty("permissions").EnumerateArray().Single();
        if (fault is "ignored-policy" or "lost-nonapplied") return;
        if (storage.Id(AuthTemplatePermissionPlan.Policy).Length == 0) storage.Create(AuthTemplatePermissionPlan.Policy, request.Id, request.BodyHash);
        var action = permission.GetProperty("action");
        string[] actions = action.ValueKind == JsonValueKind.Array ? action.EnumerateArray().Select(a => a.GetString()!).ToArray() : [action.GetString()!];
        var policy = new AuthTemplatePermissionPolicy(storage.Id(AuthTemplatePermissionPlan.Policy), "policy-2",
            actor.Identity.Principal, actor.Identity.Kind, Root.Organization, permission.GetProperty("subject").GetString()!,
            fault == "partial" ? [] : actions, body.GetProperty("slug").GetString()!, request.BodyHash);
        policy = fault switch
        {
            "wrong-subject" => policy with { Subject = "identity" },
            "wrong-actor" => policy with { Actor = Root.Authorities.Observer },
            "wrong-organization" => policy with { Organization = storage.Id(AuthTemplatePermissionPlan.OtherOrganization) },
            "wrong-configuration" => policy with { Configuration = "foreign" },
            _ => policy
        };
        Commit(request.Id, policy);
    }
    private void Commit(string request, AuthTemplatePermissionPolicy value)
    {
        var before = policies.GetValueOrDefault(value.Id); policies[value.Id] = value;
        Append("change", new AuthTemplatePermissionPolicyChange(request, AuthTemplatePermissionContract.Hash(before), before, value));
    }
    internal void Clear()
    {
        AuthTemplatePermissionContract.Require(Fenced);
        foreach (var before in policies.Values) Append("change", new AuthTemplatePermissionPolicyChange("cleanup", AuthTemplatePermissionContract.Hash(before), before, null));
        policies.Clear();
    }
    public override void Dispose() { policies.Clear(); base.Dispose(); }
}

internal sealed class InfisicalAuthTemplatePermissionAccess(InfisicalAuthTemplatePermissionIngress ingress,
    InfisicalAuthTemplatePermissionPolicy policies, InfisicalAuthTemplatePermissionMembership memberships, string fault)
    : InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal.Access)
{
    private readonly Dictionary<string, AuthTemplatePermissionDecision> decisions = [];
    internal bool Contains(AuthTemplatePermissionDecision decision) => decisions.GetValueOrDefault(decision.Request) == decision;
    internal AuthTemplatePermissionDecision Decide(AuthTemplatePermissionRequest request, string action)
    {
        Accept(); AuthTemplatePermissionContract.Require(ingress.Contains(request) && !decisions.ContainsKey(request.Id));
        var policy = policies.Inventory.SingleOrDefault(p => p.Actor == request.Actor && p.Kind == request.Kind &&
            p.Organization == request.Organization && p.Subject == AuthTemplatePermissionContract.Subject && p.Actions.Contains(action));
        var member = policy is null ? null : memberships.Inventory.SingleOrDefault(m => m.Principal == request.Actor &&
            m.Kind == request.Kind && m.Organization == request.Organization && m.Role == policy.Id && m.Slug == policy.Slug && m.Active && m.Status == "accepted");
        bool allowed = request.Phase.StartsWith("template", StringComparison.Ordinal) ? policy is not null && member is not null :
            request.Kind == MemberPermissionActorKind.Machine && request.Organization == Root.Organization &&
            request.Actor == (request.Phase == "original" ? Root.Authorities.Administrative :
                request.Phase == "observer" ? Root.Authorities.Observer : Root.Authorities.Setup);
        if (request.Phase == "template" && policies.Inventory.Any(p => p.Actions.Contains(action)) && memberships.Inventory.Any(m => m.Role.Length > 0))
        {
            if (fault == "actor-leak") allowed = true;
            if (fault == "organization-leak" && request.Organization != Root.Organization) allowed = true;
            if (fault == "kind-leak" && request.Kind == MemberPermissionActorKind.Machine) allowed = true;
            if (fault == "credential-leak" && request.Actor == memberships.Inventory[3].Principal) allowed = true;
        }
        var decision = new AuthTemplatePermissionDecision(request.Id, AuthTemplatePermissionContract.Hash(request), request.CredentialHash,
            request.Organization, AuthTemplatePermissionContract.Subject, request.Phase.StartsWith("template", StringComparison.Ordinal) ? action : request.Phase,
            policy is null ? "" : AuthTemplatePermissionContract.Hash(policy), member is null ? "" : AuthTemplatePermissionContract.Hash(member), allowed);
        if (fault == "wrong-credential" && request.Phase == "template") decision = decision with { CredentialHash = "foreign" };
        decisions.Add(request.Id, decision); Append("decision", decision); return decision;
    }
    public override void Dispose() { decisions.Clear(); base.Dispose(); }
}

internal sealed class InfisicalAuthTemplatePermissionCollection(InfisicalAuthTemplatePermissionStorage storage,
    InfisicalAuthTemplatePermissionIngress ingress, InfisicalAuthTemplatePermissionAccess access, string fault)
    : InfisicalAuthTemplatePermissionJournal(AuthTemplatePermissionJournal.Collection)
{
    internal AuthTemplatePermissionState[] Read(AuthTemplatePermissionRequest request, AuthTemplatePermissionDecision decision)
    {
        Accept(); AuthTemplatePermissionContract.Require(ingress.Contains(request) && access.Contains(decision) && decision.Request == request.Id && request.Method == "GET");
        // The authenticated organization, not the caller's SDK organization argument,
        // determines the provider's collection. The argument is absent on this wire.
        var rows = decision.Allowed ? storage.States.Where(s => s.Organization == request.Organization).ToArray() : [];
        if (request.Phase is "observer" or "template-get" or "template-usage")
            rows = rows.Where(s => request.Path == AuthTemplatePermissionContract.Path + "/" + s.Id +
                (request.Phase == "template-usage" ? "/usage" : "")).ToArray();
        else if (request.Path.Contains("?authMethod=", StringComparison.Ordinal)) rows = rows.Where(s => s.Method == "kubernetes").ToArray();
        if (fault == "empty-collection" && request.Phase == "template") rows = [];
        if (fault == "readback-echo" && request.Phase == "observer") rows = rows.Select(s => s with { Name = "unpersisted" }).ToArray();
        Append("read", new AuthTemplatePermissionCollection(request.Id, AuthTemplatePermissionContract.Hash(decision),
            request.Organization, request.Path, true, rows));
        return rows;
    }
}
