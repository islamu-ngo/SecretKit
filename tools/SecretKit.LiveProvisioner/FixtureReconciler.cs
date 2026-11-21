using System.Security.Cryptography;
using SecretKit.Core;
using SecretKit.Infisical.Management;

namespace SecretKit.LiveProvisioner;

internal sealed class ActorCredentials(string identityId, string clientId, SecretMaterial? clientSecret) : IDisposable
{
    internal string IdentityId { get; } = identityId;
    internal string ClientId { get; } = clientId;
    internal SecretMaterial ClientSecret => clientSecret ?? throw new ProvisioningException("This reconciliation did not issue run credentials.");
    public void Dispose() => clientSecret?.Dispose();
    public override string ToString() => "[ActorCredentials]";
}

internal sealed class LiveFixtures(string a, string b, string import, ActorCredentials[] actors,
    SecretMaterial expectedA, SecretMaterial expectedB) : IDisposable
{
    internal string ProjectAId { get; } = a;
    internal string ProjectBId { get; } = b;
    internal string ImportProjectId { get; } = import;
    internal ActorCredentials Setup => actors[0];
    internal ActorCredentials Runtime => actors[1];
    internal ActorCredentials Denied => actors[2];
    internal ActorCredentials Administrative => actors[3];
    internal ActorCredentials Observer => actors[4];
    internal SecretMaterial ExpectedA { get; } = expectedA;
    internal SecretMaterial ExpectedB { get; } = expectedB;

    public void Dispose()
    {
        foreach (var actor in actors)
            actor.Dispose();
        ExpectedA.Dispose();
        ExpectedB.Dispose();
    }

    public override string ToString() => "[LiveFixtures]";
}

internal sealed class FixtureReconciler(HttpClient? pipeline = null)
{
    private const string Prefix = "sdk-live-";
    private static readonly (string Name, string OrgRole, string?[] ProjectRoles)[] Roles =
    [
        ("setup", "admin", ["admin", "admin", "admin"]),
        ("runtime", "no-access", ["viewer", null, "viewer"]),
        ("denied", "no-access", [null, null, null]),
        ("administrative", "admin", ["admin", "admin", "admin"]),
        ("observer", "no-access", ["viewer", "viewer", "viewer"])
    ];

    internal async Task<LiveFixtures> ReconcileAsync(LiveEnvConfig config, CancellationToken ct, bool issueCredentials = true)
    {
        using var session = await ProvisioningSession.OpenAsync(config, pipeline, ct);
        string org = session.OrganizationId;
        var projects = await session.Apply(ProjectOperations.ListProjects(org), "list projects", ct);
        var identities = await session.Apply(IdentityOperations.ListOrganizationIdentities(org), "list identities", ct);
        if (!projects.IsComplete || !identities.IsComplete)
            throw new ProvisioningException("Incomplete project or identity inventory; refusing to reconcile.");
        var existingProjects = new[]
        {
            Select(projects.Items, Prefix + "a", config.Pin("PROJECT_A_ID"), p => p.Slug, p => p.Id),
            Select(projects.Items, Prefix + "b", config.Pin("PROJECT_B_ID"), p => p.Slug, p => p.Id),
            Select(projects.Items, Prefix + "import", config.Pin("IMPORT_PROJECT_ID"), p => p.Slug, p => p.Id)
        };
        string[] selectedIds = existingProjects.OfType<ProjectSummary>().Select(p => p.Id).ToArray();
        if (selectedIds.Distinct(StringComparer.Ordinal).Count() != selectedIds.Length)
            throw new ProvisioningException("Fixture projects must be distinct.");

        var selectedActors = Roles.Select((role, index) => Select(identities.Items, Prefix + role.Name,
            config.Pin(EnvEnrollment.Slots[index + 3]), i => i.Name, i => i.Id)).ToArray();
        string[] ids = selectedActors.OfType<IdentitySummary>().Select(x => x.Id).ToArray();
        if (ids.Distinct(StringComparer.Ordinal).Count() != ids.Length)
            throw new ProvisioningException("Fixture identities must be distinct.");

        var policy = new UniversalAuthConfigurationInput(accessTokenTTL: 3600, accessTokenMaxTTL: 7200,
            accessTokenNumUsesLimit: 0, accessTokenPeriod: 0);
        var clientIds = new HashSet<string>(StringComparer.Ordinal) { config.AutomationClientId };
        var verifiedClients = new string?[Roles.Length];
        for (int index = 0; index < selectedActors.Length; index++)
        {
            if (selectedActors[index] is not { } identity)
                continue;
            if (!identity.Membership.IsPresent || identity.Membership.IsNull ||
                !identity.Membership.Value.Role.IsPresent || identity.Membership.Value.Role.IsNull ||
                identity.Membership.Value.Role.Value != Roles[index].OrgRole ||
                identity.Membership.Value.CustomRole is { IsPresent: true, IsNull: false } ||
                !identity.AuthMethods.IsPresent || identity.AuthMethods.IsNull ||
                !identity.AuthMethods.Value.SequenceEqual(["universal-auth"]))
                throw new ProvisioningException("An enrolled fixture identity has unexpected privilege or authentication configuration.");
            verifiedClients[index] = VerifyAuth(await session.Apply(IdentityAuthenticationOperations.GetUniversalAuth(org, identity.Id),
                "read enrolled fixture Universal Auth", ct));
        }
        var parentMemberships = new List<ProjectIdentityMembershipSummary>[existingProjects.Length];
        for (int project = 0; project < existingProjects.Length; project++)
        {
            parentMemberships[project] = existingProjects[project] is { } observed
                ? await ReadMemberships(session, observed.Id, ct) : [];
            for (int actor = 0; actor < selectedActors.Length; actor++)
            {
                if (selectedActors[actor] is not { } identity)
                    continue;
                var membership = Single(parentMemberships[project].Where(member => member.IdentityId == identity.Id));
                if (membership is not null && (Roles[actor].ProjectRoles[project] is not { } role ||
                    membership.Roles.Count != 1 || membership.Roles[0].Role != role ||
                    membership.Roles[0].CustomRoleId is not null || membership.Roles[0].IsTemporary != false))
                    throw new ProvisioningException("An enrolled fixture identity has unexpected project privileges.");
            }
        }
        using var enrollment = config.BeginMutation();
        string a = await EnsureProject(0, Prefix + "a");
        string b = await EnsureProject(1, Prefix + "b");
        string import = await EnsureProject(2, Prefix + "import");
        string[] fixtureProjects = [a, b, import];
        if (fixtureProjects.Distinct(StringComparer.Ordinal).Count() != fixtureProjects.Length)
            throw new ProvisioningException("Provider reported overlapping fixture projects.");
        var actors = new List<ActorCredentials>();
        using var expectedA = SecretMaterial.FromText("fixture-a-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
        using var expectedB = SecretMaterial.FromText("fixture-b-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));
        var configurations = new List<(string Id, string ClientId)>();
        try
        {
            for (int i = 0; i < Roles.Length; i++)
            {
                var role = Roles[i];
                var found = selectedActors[i];
                if (found is not null)
                {
                    configurations.Add((found.Id, verifiedClients[i]!));
                    continue;
                }
                config.VerifyEnrollment();
                var identity = await session.Apply(IdentityOperations.CreateOrganizationIdentity(org, Prefix + role.Name, role.OrgRole),
                    "create fixture identity", ct);
                if (identity.Name != Prefix + role.Name || identities.Items.Any(item => item.Id == identity.Id))
                    throw new ProvisioningException("Identity creation returned an unexpected resource; inspect the dispatched operation.");
                config.Enroll(EnvEnrollment.Slots[i + 3], identity.Id);
                var auth = await session.Apply(IdentityAuthenticationOperations.AttachUniversalAuth(org, identity.Id, policy),
                    "attach new fixture Universal Auth", ct);
                configurations.Add((identity.Id, VerifyAuth(auth)));
            }
            for (int project = 0; project < fixtureProjects.Length; project++)
            {
                config.VerifyEnrollment();
                for (int actor = 0; actor < configurations.Count; actor++)
                {
                    string id = configurations[actor].Id;
                    if (Roles[actor].ProjectRoles[project] is { } role &&
                        !parentMemberships[project].Any(member => member.IdentityId == id))
                        await session.Apply(MembershipOperations.AddProjectIdentity(org, fixtureProjects[project], id, [new MembershipRole(role)]),
                            "add fixture membership", ct);
                }
            }
            config.VerifyEnrollment();
            await FixtureSecrets.ResetAsync(session, a, b, import, expectedA, expectedB, ct);
            foreach (var actor in configurations)
            {
                if (issueCredentials)
                {
                    config.VerifyEnrollment();
                    using var secret = await session.Apply(IdentityAuthenticationOperations.CreateUniversalClientSecret(
                        org, actor.Id, "SecretKit live run", numUsesLimit: 1, ttl: 900), "issue single-use fixture credential", ct);
                    actors.Add(new(actor.Id, actor.ClientId, secret.ClientSecret.Copy()));
                }
                else
                    actors.Add(new(actor.Id, actor.ClientId, null));
            }
            return new(a, b, import, actors.ToArray(), expectedA.Copy(), expectedB.Copy());
        }
        catch
        {
            foreach (var actor in actors)
                actor.Dispose();
            throw;
        }

        async Task<string> EnsureProject(int index, string slug)
        {
            if (existingProjects[index] is { } existing)
                return existing.Id;
            config.VerifyEnrollment();
            var created = await session.Apply(ProjectOperations.CreateProject(org, slug, slug), "create fixture project", ct);
            if (created.Slug != slug || projects.Items.Any(item => item.Id == created.Id))
                throw new ProvisioningException("Project creation returned an unexpected resource; inspect the dispatched operation.");
            config.Enroll(EnvEnrollment.Slots[index], created.Id);
            return created.Id;
        }

        string VerifyAuth(IdentityAuthenticationConfiguration auth)
        {
            if (auth.ClientId is not { Length: > 0 } clientId || !clientIds.Add(clientId) ||
                auth.AccessTokenTTL?.GetInt64() != 3600 || auth.AccessTokenMaxTTL?.GetInt64() != 7200 ||
                auth.AccessTokenNumUsesLimit?.GetInt64() != 0 || auth.AccessTokenPeriod?.GetInt64() != 0)
                throw new ProvisioningException("Fixture Universal Auth policy or client separation could not be established.");
            return clientId;
        }
    }

    private static T? Select<T>(IReadOnlyList<T> inventory, string name, string? pin, Func<T, string> nameOf, Func<T, string> idOf)
        where T : class
    {
        var named = Single(inventory.Where(item => nameOf(item) == name));
        if (pin is null)
            return named is null ? null : throw new ProvisioningException("An unpinned resource occupies a reserved fixture name; refusing adoption.");
        var selected = Single(inventory.Where(item => idOf(item) == pin));
        return selected is not null && ReferenceEquals(selected, named) ? selected :
            throw new ProvisioningException("An enrolled resource is missing or no longer matches its fixture name.");
    }

    private static T? Single<T>(IEnumerable<T> candidates) where T : class
    {
        var matches = candidates.Take(2).ToArray();
        return matches.Length switch
        {
            0 => null,
            1 => matches[0],
            _ => throw new ProvisioningException("Ambiguous fixture resource; refusing to reconcile.")
        };
    }

    private static async Task<List<ProjectIdentityMembershipSummary>> ReadMemberships(ProvisioningSession session, string project,
        CancellationToken ct)
    {
        string org = session.OrganizationId;
        var members = new List<ProjectIdentityMembershipSummary>();
        int offset = 0;
        while (true)
        {
            var page = await session.Apply(ProjectMembershipOperations.ListProjectIdentityMemberships(org, project, offset),
                "list fixture project memberships", ct);
            members.AddRange(page.Items);
            if (page.IsComplete)
                break;
            if (page.NextOffset is not int next || next <= offset || next > 10000)
                throw new ProvisioningException("Incomplete fixture membership inventory.");
            offset = next;
        }
        return members;
    }
}
