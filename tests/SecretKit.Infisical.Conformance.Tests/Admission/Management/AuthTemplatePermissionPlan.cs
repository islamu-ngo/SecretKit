using SecretKit.Infisical.Management;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class AuthTemplatePermissionPlan
{
    internal const string Policy = "policy", Selected = "selected", Peer = "peer", Created = "created", OtherOrganization = "other-organization";
    internal AuthTemplatePermissionRoot Root { get; }
    internal AuthTemplatePermissionIntent[] Intents { get; }
    internal string Slug => "auth-policy-" + Root.Nonce;
    internal string Name(string key) => "auth-" + key + "-" + Root.Nonce;
    internal string ActorKey(int i) => "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 2 ? MemberPermissionActorKind.Machine : MemberPermissionActorKind.User;
    internal string OrganizationKey(int i) => i == 4 ? OtherOrganization : "@" + Root.Organization;
    internal AuthTemplatePermissionPlan(AuthTemplatePermissionRoot root)
    {
        Root = root; var intents = new List<AuthTemplatePermissionIntent>();
        Add(OtherOrganization, "organization", "@" + root.Organization, Name(OtherOrganization));
        Add(Policy, "role", "@" + root.Organization, Slug);
        for (int i = 0; i < 5; i++)
        {
            string org = OrganizationKey(i);
            Add(ActorKey(i), ActorKind(i) == MemberPermissionActorKind.User ? "user" : "machine", org, Name(ActorKey(i)));
            Add("credential-" + i, "credential", org, "actor:" + ActorKey(i), ActorKey(i));
            Add("member-" + i, "membership", org, ActorKey(i), ActorKey(i));
        }
        Add("assignment", "role-assignment", "@" + root.Organization, Slug, Policy, "member-0");
        foreach (string key in new[] { Selected, Peer, Created }) Add(key, "template", "@" + root.Organization, Name(key));
        Add("foreign", "template", OtherOrganization, Name("foreign"));
        Add("deferred", "canary", "@" + root.Organization, root.Id + ":deferred");
        Intents = intents.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] deps) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, deps));
    }
    internal AuthTemplatePermissionRow[] Rows()
    {
        var rows = new List<AuthTemplatePermissionRow>
        {
            new("selected", 0, Root.Action), new("organization", 4, Root.Action), new("actor", 1, Root.Action),
            new("kind", 2, Root.Action), new("credential", 3, Root.Action)
        };
        if (Root.Action is AuthTemplatePermissionAction.List or AuthTemplatePermissionAction.Attach)
            rows.Add(new("inverse", 0, Root.Action == AuthTemplatePermissionAction.List ? AuthTemplatePermissionAction.Attach : AuthTemplatePermissionAction.List));
        return rows.ToArray();
    }
    internal static string InputHash(AuthTemplatePermissionIntent intent, Func<string, string> id) =>
        AuthTemplatePermissionContract.Hash(new { intent.Kind, Scope = id(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(id).ToArray() });
    internal AuthTemplatePermissionState Initial(string key, Func<string, string> id) =>
        new(id(key), key == "foreign" ? id(OtherOrganization) : Root.Organization, Name(key), "kubernetes",
            "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1,
            new("api", "https://kubernetes.example.invalid", "", false, "baseline", false, "", null, null));
    internal AuthTemplatePermissionState Changed(AuthTemplatePermissionState before) => before with
    {
        Name = Name("changed"),
        UpdatedAt = "2026-01-01T00:00:01Z",
        Revision = before.Revision + 1,
        Configuration = before.Configuration with { Audience = "changed-" + Root.Nonce }
    };
    internal IdentityTemplateKubernetesFields CreateFields() => new(IdentityTemplateTokenReviewMode.Api,
        IdentityTemplateNullableText.FromValue("https://kubernetes.example.invalid"), caCertificate: "",
        verifyTlsCertificate: false, allowedAudience: "baseline");
    internal IdentityTemplateKubernetesFields EditFields() => new(allowedAudience: "changed-" + Root.Nonce);
    internal string BodyHash(AuthTemplatePermissionAction action) => action switch
    {
        AuthTemplatePermissionAction.Create => AuthTemplatePermissionContract.Hash(new
        {
            name = Name(Created),
            authMethod = "kubernetes",
            templateFields = new { tokenReviewMode = "api", kubernetesHost = "https://kubernetes.example.invalid", caCert = "", verifyTlsCertificate = false, allowedAudience = "baseline" }
        }),
        AuthTemplatePermissionAction.Edit => AuthTemplatePermissionContract.Hash(new
        { name = Name("changed"), templateFields = new { allowedAudience = "changed-" + Root.Nonce } }),
        _ => AuthTemplatePermissionContract.RawHash([])
    };
    internal string RequestPath(AuthTemplatePermissionAction action, Func<string, string> id) => action switch
    {
        AuthTemplatePermissionAction.List => AuthTemplatePermissionContract.Path + "/search?offset=0&limit=100",
        AuthTemplatePermissionAction.Attach => AuthTemplatePermissionContract.Path + "?authMethod=kubernetes",
        AuthTemplatePermissionAction.Create => AuthTemplatePermissionContract.Path,
        _ => AuthTemplatePermissionContract.Path + "/" + id(Selected)
    };
    internal static string Method(AuthTemplatePermissionAction action) => action switch
    {
        AuthTemplatePermissionAction.Create => "POST",
        AuthTemplatePermissionAction.Edit => "PATCH",
        AuthTemplatePermissionAction.Delete => "DELETE",
        _ => "GET"
    };
}
