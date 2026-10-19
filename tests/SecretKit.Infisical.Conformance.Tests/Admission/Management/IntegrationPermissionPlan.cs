namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class IntegrationPermissionPlan
{
    internal const string Project = "project", OtherProject = "other-project", CopyProject = "copy-project", Policy = "policy", Template = "template", CopyPolicy = "copy-policy";
    internal IntegrationPermissionRoot Root { get; }
    internal IntegrationPermissionIntent[] Intents { get; }
    internal string Slug => "integration-policy-" + Root.Nonce;
    internal string ProjectSlug => "integration-project-" + Root.Nonce;
    internal string CopySlug => "integration-copy-" + Root.Nonce;
    internal string PolicyKey => IntegrationPermissionContract.Template(Root.Operation) ? Template : Policy;
    internal string ActorKey(int i) => Root.ActorKind == MemberPermissionActorKind.Machine ?
        i == 0 ? "@" + Root.Authorities.Runtime : i == 1 ? "@" + Root.Authorities.Denied : "actor-2" :
        i == 2 ? "@" + Root.Authorities.Runtime : "actor-" + i;
    internal MemberPermissionActorKind ActorKind(int i) => i == 2 ?
        Root.ActorKind == MemberPermissionActorKind.Machine ? MemberPermissionActorKind.User : MemberPermissionActorKind.Machine : Root.ActorKind;
    internal string Username(int i) => "integration-user-" + i + "-" + Root.Nonce + "@example.invalid";
    internal IntegrationPermissionPlan(IntegrationPermissionRoot root)
    {
        Root = root; var intents = new List<IntegrationPermissionIntent>();
        Add(Project, "project", "@" + root.Organization, ProjectSlug);
        Add(OtherProject, "project", "@" + root.Organization, "other-" + ProjectSlug);
        Add(Policy, root.ActorKind == MemberPermissionActorKind.Machine ? "privilege" : "role", Project, Slug);
        Add(Template, "template", "@" + root.Organization, Slug);
        Add(CopyProject, "project", "@" + root.Organization, CopySlug + ":template=" + Slug, Template);
        Add(CopyPolicy, "role", CopyProject, Slug, Template);
        for (int i = 0; i < 3; i++)
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
        {
            Add(project + "-env", "environment", project, "Development:dev:1.5");
            Add(project + "-authorization", "authorization", project, "controlled-metadata-only", project + "-env");
            for (int i = 0; i < 2; i++) Add(project + "-row-" + i, "integration", project, "metadata:" + i + ":" + root.Nonce, project + "-env", project + "-authorization");
        }
        Add("deferred", "canary", Project, root.Id + ":deferred");
        Intents = intents.ToArray();
        void Add(string key, string kind, string scope, string input, params string[] deps) =>
            intents.Add(new(key, root.Id, root.Nonce, kind, scope, input, deps));
    }
    internal IntegrationPermissionRow[] Rows(bool copied) =>
        [new("selected", copied ? CopyProject : Project, 0), new("scope", OtherProject, 0),
         new("actor", copied ? CopyProject : Project, 1), new("kind", copied ? CopyProject : Project, 2),
         new("credential", copied ? CopyProject : Project, 1)];
    internal static string InputHash(IntegrationPermissionIntent intent, Func<string, string> id) =>
        IntegrationPermissionContract.Hash(new { intent.Kind, Scope = id(intent.Scope), intent.Input, Dependencies = intent.Dependencies.Select(id).ToArray() });
    internal IntegrationPermissionMetadata Metadata(string project, int i, Func<string, string> id) =>
        new(id(project + "-row-" + i), i == 0, "controlled-metadata-" + i, id(project + "-authorization"), id(project + "-env"),
            "Development", "dev", "2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z",
            i == 0 ? "https://metadata.invalid/" + Root.Nonce : null, i == 0 ? "app-" + Root.Nonce : null,
            i == 0 ? "app-id" : null, i == 0 ? "preview" : null, i == 0 ? "target-env" : null,
            i == 0 ? "service" : null, i == 0 ? "service-id" : null, i == 0 ? "owner" : null,
            i == 0 ? "/metadata" : null, i == 0 ? "region" : null, i == 0 ? "scope" : null,
            i == 0 ? "/secrets" : null, i == 0 ? "2026-01-01T00:00:02Z" : null, i == 0 ? "unqualified-job" : null, i == 0 ? false : null);
}
