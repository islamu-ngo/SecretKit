namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class SettingsPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project", Policy = "policy", Template = "template", CopyPolicy = "copy-policy";
    internal SettingsPermissionRoot Root { get; }
    internal SettingsPermissionIntent[] Intents { get; }
    internal string Slug => "settings-policy-" + Root.Nonce;
    internal string ProjectSlug => "settings-project-" + Root.Nonce;
    internal string CopySlug => "settings-copy-" + Root.Nonce;
    internal string PolicyKey => SettingsPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.Machine ? MemberPermissionActorKind.User : MemberPermissionActorKind.Machine : Root.ActorKind;
    internal string Username(int i) => "settings-user-" + i + "-" + Root.Nonce + "@example.invalid";
    internal SettingsPermissionPlan(SettingsPermissionRoot root)
    {
        Root = root; var intents = new List<SettingsPermissionIntent>();
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role", Project, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template=" + Slug, Template);
        Add(CopyPolicy, "role", CopyProject, Slug, Template);
        for (int i = 0; i < 4; i++)
        {
            if (!ActorKey(i).StartsWith('@'))
            {
                Add(ActorKey(i), ActorKind(i) == MemberPermissionActorKind.User ? "user" : "machine", "@" + root.Organization, Username(i));
                Add("credential-" + i, "credential", "@" + root.Organization, "actor:" + ActorKey(i), ActorKey(i));
            }
            Add("member-" + i, "membership", Project, ActorKey(i), ActorKey(i));
        }
        Add("copy-member", "membership", CopyProject, ActorKey(0), ActorKey(0), CopyPolicy);
        Add("assignment", "role-assignment", Project, Slug, Policy, "member-0");
        Add("copy-assignment", "role-assignment", CopyProject, Slug, CopyPolicy, "copy-member");
        foreach (string project in new[] { Project, OtherProject, CopyProject })
            Add(project + "-env", "environment", project, "Development:dev:1.5");
        Add("deferred", "canary", Project, root.Id + ":deferred");
        Intents = intents.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] deps) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, deps));
    }
    internal SettingsPermissionRow[] Rows(bool copied) =>
        [new("selected", copied ? CopyProject : Project, 0), new("scope", OtherProject, 0),
         new("actor", copied ? CopyProject : Project, 1), new("kind", copied ? CopyProject : Project, 2),
         new("credential", copied ? CopyProject : Project, 3)];
    internal static string InputHash(SettingsPermissionIntent intent, Func<string, string> id) =>
        SettingsPermissionContract.Hash(new { intent.Kind, Scope = id(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(id).ToArray() });
    internal string Name(string project) => project == CopyProject ? CopySlug : project == Project ? ProjectSlug : "other-" + ProjectSlug;
    internal SettingsPermissionState Initial(string project, Func<string, string> id) =>
        new(id(project), Root.Organization, Name(project), Name(project), "baseline " + Root.Nonce,
            "secret-manager", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", 1,
            new(false, false, false, false, false, true, false, 30, 10, 3, "secret-manager", null, null, null,
                SettingsPermissionContract.Hash(Array.Empty<string>()), SettingsPermissionContract.Hash("owned-empty-workflows"),
                SettingsPermissionContract.Hash("owned-unselected-configuration"), id(project + "-env"), "Development", "dev", 1.5,
                SettingsPermissionContract.Hash(Array.Empty<string>())));
    internal string ChangedName => "changed-" + Root.Nonce;
    internal string ChangedSlug => "changed-" + Root.Nonce;
    internal string ChangedDescription => "changed description " + Root.Nonce;
    internal SettingsPermissionState Changed(SettingsPermissionState before) => before with
    {
        Name = ChangedName,
        Slug = ChangedSlug,
        Description = ChangedDescription,
        UpdatedAt = "2026-01-01T00:00:01Z",
        Revision = before.Revision + 1
    };
    internal string PatchHash => SettingsPermissionContract.Hash(new
    { name = ChangedName, slug = ChangedSlug, description = ChangedDescription });

}
