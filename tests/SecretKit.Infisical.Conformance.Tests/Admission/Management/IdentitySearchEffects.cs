using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class IdentitySearchEffects
{
    private sealed record Witness(IdentitySearchScope Scope, string? ProjectId, string IdentityId,
        string MembershipId, string Name, string[] Roles, IReadOnlyList<ProjectMembershipRole>? Assignments = null)
    {
        internal (IdentitySearchScope, string?, string) Coordinate => (Scope, ProjectId, IdentityId);
        public override string ToString() => "[IdentitySearchWitness]";
    }

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (c.Variant == "order.LastLogin")
        {
            LdapLoginTrial? trial = await LdapLoginTrial.CreateAsync(c, token);
            if (trial is not null)
            {
                await LastLoginAsync(c, trial, token);
                return;
            }
        }
        string role = c.Required("identityRole");
        string projectRole = c.Required("projectIdentityRole");
        bool roleWitness = c.Variant.StartsWith("role.", StringComparison.Ordinal) ||
            c.Variant is "order.Role" or "filter.all";
        string alternateRole = roleWitness ? c.Required("updatedIdentityRole") : role;
        if (roleWitness) c.Probe.Contract(role != alternateRole, NativeFailure.MissingInput);
        string excludedRole = c.Variant == "role.in" ? c.Required("identitySearchExcludedRole") : alternateRole;
        if (c.Variant == "role.in")
            c.Probe.Contract(excludedRole != role && excludedRole != alternateRole, NativeFailure.MissingInput);
        if (c.Variant == "role.contains")
            c.Probe.Contract(role.Length > 1 && !alternateRole.Contains(role[..^1], StringComparison.Ordinal),
                NativeFailure.MissingInput);

        await c.EnsureProjectAsync(token);
        string prefix = ProjectFamilyContext.FreshName();
        // Name and role orders deliberately disagree, so a name-sorted role response cannot pass.
        bool reverseNames = c.Variant == "order.Role" && StringComparer.Ordinal.Compare(role, alternateRole) < 0;
        string name = prefix + (reverseNames ? "b" : "a");
        string secondName = prefix + (reverseNames ? "a" : "b");
        var fixtures = new List<(string Name, string Role)>
        {
            (name, role),
            (secondName, c.Variant == "filter.all" ? role : alternateRole),
            (ProjectFamilyContext.FreshName(), c.Variant == "filter.all" ? role : excludedRole)
        };
        if (c.Variant == "filter.all") fixtures.Add((prefix + "c", alternateRole));
        var owned = new List<Witness>();
        foreach (var fixture in fixtures)
        {
            var identity = await IdentitiesEffects.PrepareOrganizationAsync(c, fixture.Name, token);
            if (fixture.Role != role)
                await c.NeedAsync(() => IdentityOperations.UpdateOrganizationIdentity(c.OrganizationId,
                    identity.Id, role: fixture.Role), NativeIdentityRole.Setup, token);
            var membership = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId,
                c.ProjectId, identity.Id, new MembershipRoleSelection(roles: [new(projectRole)])),
                NativeIdentityRole.Setup, token);
            owned.Add(new(IdentitySearchScope.Organization, null, identity.Id, "", fixture.Name, [fixture.Role]));
            owned.Add(new(IdentitySearchScope.Projects, c.ProjectId, identity.Id, membership.Id, fixture.Name, [projectRole]));
        }
        IdentitySearchScope scope = c.Variant switch
        {
            "scope.Projects" => IdentitySearchScope.Projects,
            "scope.Organization-Projects" => IdentitySearchScope.Organization | IdentitySearchScope.Projects,
            _ => IdentitySearchScope.Organization
        };
        IdentitySearchFilter? filter = Filter(c.Variant, prefix, name, secondName, role, alternateRole);
        IdentitySearchOrder order = c.Variant switch
        {
            "order.Role" => IdentitySearchOrder.Role,
            "order.LastLogin" => IdentitySearchOrder.LastLogin,
            _ => IdentitySearchOrder.Name
        };
        ManagementListOrder direction = c.Variant == "direction.Descending"
            ? ManagementListOrder.Descending : ManagementListOrder.Ascending;

        async ValueTask<Witness[]> Inventory(CancellationToken t)
        {
            var inventory = await ReadInventoryAsync(c, scope, t);
            foreach (Witness fixture in owned.Where(w => (scope & w.Scope) != 0))
            {
                Witness? found = inventory.SingleOrDefault(w => w.Coordinate == fixture.Coordinate);
                c.Probe.Contract(found is not null && found.Name == fixture.Name &&
                    found.Roles.SequenceEqual(fixture.Roles) &&
                    (fixture.Scope == IdentitySearchScope.Organization || found.MembershipId == fixture.MembershipId),
                    NativeFailure.EffectMismatch);
            }
            return inventory.Where(w => Matches(filter, w)).ToArray();
        }

        // Complete non-search inventories and exact typed reads are the oracle. Search and
        // count cannot certify one another, even if both consistently omit or duplicate rows.
        Witness[] expected = await Inventory(token);
        bool Counts(IdentitySearchCounts counts) =>
            counts.Organization == ((scope & IdentitySearchScope.Organization) != 0
                ? expected.Count(w => w.Scope == IdentitySearchScope.Organization) : null) &&
            counts.Projects == ((scope & IdentitySearchScope.Projects) != 0
                ? expected.Count(w => w.Scope == IdentitySearchScope.Projects) : null);

        bool Search(ManagementPage<IdentitySearchSummary> page)
        {
            if (!page.IsComplete || page.Items.Count != expected.Length ||
                page.Items.Select(r => (r.Scope, r.ProjectId, r.Identity.Id)).Distinct().Count() != page.Items.Count ||
                page.Items.Select(r => (r.Scope, r.ProjectId, r.MembershipId)).Distinct().Count() != page.Items.Count)
                return false;
            var ordered = new List<Witness>();
            foreach (var row in page.Items)
            {
                Witness? witness = expected.SingleOrDefault(w => w.Coordinate == (row.Scope, row.ProjectId, row.Identity.Id));
                if (witness is null || row.MembershipId != witness.MembershipId || row.Identity.Name != witness.Name ||
                    row.Roles.Count != witness.Roles.Length ||
                    row.Roles.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != row.Roles.Count ||
                    !row.Roles.Select(r => r.Role).Order(StringComparer.Ordinal)
                        .SequenceEqual(witness.Roles.Order(StringComparer.Ordinal))) return false;
                if (witness.Assignments is { } assignments && !row.Roles.All(r => assignments.Any(a =>
                    a.Id == r.Id && a.Role == r.Role && a.CustomRoleId == r.CustomRoleId &&
                    a.IsTemporary == r.IsTemporary && a.Mode == r.Mode && a.Range == r.Range &&
                    a.StartsAt == r.StartsAt && a.EndsAt == r.EndsAt))) return false;
                ordered.Add(witness);
            }
            // LastLogin has no established native login witnesses. The family classifies that
            // row unavailable after exercising its feasible contract/denial/cancellation checks.
            if (order == IdentitySearchOrder.LastLogin) return true;
            string[] keys = ordered.Select(w => order == IdentitySearchOrder.Role ? w.Roles.Single() : w.Name).ToArray();
            return keys.SequenceEqual(direction == ManagementListOrder.Ascending
                ? keys.Order(StringComparer.Ordinal) : keys.OrderDescending(StringComparer.Ordinal));
        }

        async ValueTask<bool> Observe(bool _, CancellationToken t)
        {
            Witness[] observed = await Inventory(t);
            if (observed.Length != expected.Length || !observed.All(w => expected.Any(e =>
                e.Coordinate == w.Coordinate && e.MembershipId == w.MembershipId && e.Name == w.Name &&
                e.Roles.Order(StringComparer.Ordinal).SequenceEqual(w.Roles.Order(StringComparer.Ordinal))))) return false;
            var counts = await c.NeedAsync(() => IdentitySearchOperations.CountIdentities(c.OrganizationId,
                scope, filter), NativeIdentityRole.Observer, t);
            if (c.Operation == "CountIdentities") return Counts(counts);
            var search = await c.NeedAsync(() => IdentitySearchOperations.SearchIdentities(c.OrganizationId,
                scope, filter, limit: 100, order: order, direction: direction), NativeIdentityRole.Observer, t);
            return Counts(counts) && Search(search);
        }
        if (c.Operation == "CountIdentities")
            await c.CaseAsync(() => IdentitySearchOperations.CountIdentities(c.OrganizationId, scope, filter),
                Counts, Observe, token);
        else
            await c.CaseAsync(() => IdentitySearchOperations.SearchIdentities(c.OrganizationId, scope, filter,
                limit: 100, order: order, direction: direction), Search, Observe, token);
    }

    private static async ValueTask LastLoginAsync(ProjectFamilyContext c, LdapLoginTrial trial,
        CancellationToken token)
    {
        await c.EnsureProjectAsync(token);
        string prefix = ProjectFamilyContext.FreshName();
        string[] names = [prefix + "b", prefix + "a", prefix + "c"];
        string template = await trial.CreateTemplateAsync(ProjectFamilyContext.FreshName(),
            LdapServiceCredential.Original, token);
        var identities = new List<(string Id, string Name, string Membership, string ProjectMembership)>();
        foreach (string name in names)
        {
            var identity = await IdentitiesEffects.PrepareOrganizationAsync(c, name, token);
            var actual = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(
                c.OrganizationId, identity.Id), NativeIdentityRole.Observer, token);
            c.Probe.Contract(actual.Membership.IsPresent && !actual.Membership.IsNull,
                NativeFailure.EffectMismatch);
            var project = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId,
                c.ProjectId, identity.Id, new MembershipRoleSelection(roles: [new(c.Required("projectIdentityRole"))])),
                NativeIdentityRole.Setup, token);
            await trial.GrantCanaryAsync(identity.Id, token);
            await trial.AttachAsync(template, identity.Id, token);
            identities.Add((identity.Id, name, actual.Membership.Value.Id, project.Id));
        }
        var logins = new Dictionary<string, LdapLoginFence>(StringComparer.Ordinal);
        foreach (var identity in identities.Take(2))
        {
            LdapLoginFence login = await trial.LoginAsync(identity.Id, template,
                LdapServiceCredential.Original, false, true, token);
            if (login.Arm.Attempt.MembershipId != identity.Membership || login.LastLoginAt is null)
                throw new NativeCaseFailureException("effect-mismatch");
            logins.Add(identity.Id, login);
            // A user-password failure must not become another successful login,
            // overwrite ordering evidence, or acquire access to either canary.
            await trial.LoginAsync(identity.Id, template, LdapServiceCredential.Original, true, false, token);
        }
        if (logins[identities[0].Id].LastLoginAt >= logins[identities[1].Id].LastLoginAt)
            throw new NativeCaseFailureException("effect-mismatch");
        await trial.SealAsync(token);
        const IdentitySearchScope scope = IdentitySearchScope.Organization | IdentitySearchScope.Projects;
        var filter = new IdentitySearchFilter(all: new(name: new(anyOf: names)));
        async ValueTask<Witness[]> Inventory(CancellationToken ct)
        {
            Witness[] rows = (await ReadInventoryAsync(c, scope, ct)).Where(w => Matches(filter, w)).ToArray();
            foreach (var identity in identities)
            {
                if (rows.Count(w => w.Coordinate == (IdentitySearchScope.Organization, (string?)null, identity.Id) &&
                    w.MembershipId == identity.Membership && w.Name == identity.Name) != 1 ||
                    rows.Count(w => w.Coordinate == (IdentitySearchScope.Projects, (string?)c.ProjectId, identity.Id) &&
                    w.MembershipId == identity.ProjectMembership && w.Name == identity.Name) != 1)
                    throw new NativeCaseFailureException("effect-mismatch");
            }
            return rows;
        }
        Witness[] expected = await Inventory(token);
        DateTimeOffset? Time(Witness w) => logins.TryGetValue(w.IdentityId, out LdapLoginFence? login)
            ? login.LastLoginAt : null;
        bool MatchesPage(ManagementPage<IdentitySearchSummary> page, ManagementListOrder direction, int offset = 0)
        {
            if (offset < 0 || offset > expected.Length || page.Items.Count > expected.Length - offset ||
                page.IsComplete && offset + page.Items.Count != expected.Length ||
                !page.IsComplete && (page.Items.Count == 0 ||
                    page.NextOffset != offset + page.Items.Count)) return false;
            Witness[] ordered = direction == ManagementListOrder.Ascending
                ? expected.OrderBy(w => Time(w) is null).ThenBy(Time)
                    .ThenBy(w => w.MembershipId, StringComparer.Ordinal).ToArray()
                : expected.OrderBy(w => Time(w) is null).ThenByDescending(Time)
                    .ThenBy(w => w.MembershipId, StringComparer.Ordinal).ToArray();
            for (int i = 0; i < page.Items.Count; i++)
            {
                Witness witness = ordered[offset + i];
                IdentitySearchSummary row = page.Items[i];
                if (witness.Coordinate != (row.Scope, row.ProjectId, row.Identity.Id) ||
                    witness.MembershipId != row.MembershipId || witness.Name != row.Identity.Name ||
                    !row.Roles.Select(r => r.Role).Order(StringComparer.Ordinal)
                        .SequenceEqual(witness.Roles.Order(StringComparer.Ordinal)) ||
                    row.Roles.Select(r => r.Id).Distinct(StringComparer.Ordinal).Count() != row.Roles.Count ||
                    !row.LastLoginTime.IsPresent || !row.LastLoginAuthMethod.IsPresent) return false;
                if (witness.Assignments is { } assignments && !row.Roles.All(r => assignments.Any(a =>
                    a.Id == r.Id && a.Role == r.Role && a.CustomRoleId == r.CustomRoleId &&
                    a.IsTemporary == r.IsTemporary && a.Mode == r.Mode && a.Range == r.Range &&
                    a.StartsAt == r.StartsAt && a.EndsAt == r.EndsAt))) return false;
                DateTimeOffset? at = Time(witness);
                if (at is null)
                {
                    if (!row.LastLoginTime.IsNull || !row.LastLoginAuthMethod.IsNull) return false;
                }
                else if (row.LastLoginTime.IsNull || row.LastLoginAuthMethod.IsNull ||
                    !DateTimeOffset.TryParse(row.LastLoginTime.Value,
                        System.Globalization.CultureInfo.InvariantCulture,
                        System.Globalization.DateTimeStyles.None, out DateTimeOffset actual) ||
                    actual != at || row.LastLoginAuthMethod.Value != "ldap-auth") return false;
            }
            return true;
        }
        async ValueTask<bool> Observe(bool _, CancellationToken ct)
        {
            Witness[] rows = await Inventory(ct);
            if (rows.Length != expected.Length || !rows.All(r => expected.Any(e =>
                e.Coordinate == r.Coordinate && e.MembershipId == r.MembershipId &&
                e.Name == r.Name && e.Roles.SequenceEqual(r.Roles)))) return false;
            foreach (ManagementListOrder direction in Enum.GetValues<ManagementListOrder>())
            {
                int offset = 0;
                while (true)
                {
                    var page = await c.NeedAsync(() => IdentitySearchOperations.SearchIdentities(c.OrganizationId,
                        scope, filter, offset: offset, limit: 100, order: IdentitySearchOrder.LastLogin,
                        direction: direction), NativeIdentityRole.Observer, ct);
                    if (!MatchesPage(page, direction, offset)) return false;
                    if (page.IsComplete) break;
                    offset += page.Items.Count;
                }
            }
            return true;
        }
        await c.CaseAsync(() => IdentitySearchOperations.SearchIdentities(c.OrganizationId, scope, filter,
            limit: 100, order: IdentitySearchOrder.LastLogin, direction: ManagementListOrder.Ascending),
            page => MatchesPage(page, ManagementListOrder.Ascending), Observe, token);
        c.LdapWitnessObserved = true;
    }

    private static async ValueTask<Witness[]> ReadInventoryAsync(ProjectFamilyContext c,
        IdentitySearchScope scope, CancellationToken token)
    {
        var witnesses = new List<Witness>();
        if ((scope & IdentitySearchScope.Organization) != 0)
        {
            var identities = await c.NeedAsync(() => IdentityOperations.ListOrganizationIdentities(c.OrganizationId),
                NativeIdentityRole.Observer, token);
            c.Probe.Contract(identities.IsComplete, NativeFailure.ObserverUnavailable);
            c.Probe.Contract(identities.Items.Select(i => i.Id).Distinct(StringComparer.Ordinal).Count() == identities.Items.Count,
                NativeFailure.EffectMismatch);
            foreach (var item in identities.Items)
            {
                var actual = await c.NeedAsync(() => IdentityOperations.GetOrganizationIdentity(c.OrganizationId,
                    item.Id), NativeIdentityRole.Observer, token);
                c.Probe.Contract(item.Membership.IsPresent && actual.Membership.IsPresent &&
                    item.Name == actual.Name && item.Membership.Value.Id == actual.Membership.Value.Id &&
                    item.Membership.Value.Role.Value == actual.Membership.Value.Role.Value, NativeFailure.EffectMismatch);
                witnesses.Add(new(IdentitySearchScope.Organization, null, actual.Id, actual.Membership.Value.Id,
                    actual.Name, [actual.Membership.Value.Role.Value]));
            }
        }
        if ((scope & IdentitySearchScope.Projects) != 0)
        {
            var projects = await c.NeedAsync(() => ProjectOperations.ListProjects(c.OrganizationId, type: null),
                NativeIdentityRole.Observer, token);
            c.Probe.Contract(projects.IsComplete, NativeFailure.ObserverUnavailable);
            c.Probe.Contract(projects.Items.Select(p => p.Id).Distinct(StringComparer.Ordinal).Count() == projects.Items.Count &&
                projects.Items.Any(p => p.Id == c.ProjectId), NativeFailure.EffectMismatch);
            foreach (var project in projects.Items)
            {
                var memberships = await c.NeedAsync(() => ProjectMembershipOperations.ListProjectIdentityMemberships(
                    c.OrganizationId, project.Id, limit: 100), NativeIdentityRole.Observer, token);
                c.Probe.Contract(memberships.IsComplete, NativeFailure.ObserverUnavailable);
                foreach (var item in memberships.Items)
                {
                    var actual = await c.NeedAsync(() => MembershipOperations.GetProjectIdentityMembership(
                        c.OrganizationId, project.Id, item.IdentityId), NativeIdentityRole.Observer, token);
                    c.Probe.Contract(item.Id == actual.Id && item.Identity.Name == actual.Identity.Name &&
                        item.Roles.Select(r => (r.Id, r.Role)).OrderBy(r => r.Id, StringComparer.Ordinal)
                            .SequenceEqual(actual.Roles.Select(r => (r.Id, r.Role)).OrderBy(r => r.Id, StringComparer.Ordinal)),
                        NativeFailure.EffectMismatch);
                    witnesses.Add(new(IdentitySearchScope.Projects, project.Id, actual.IdentityId, actual.Id,
                        actual.Identity.Name, actual.Roles.Select(r => r.Role).ToArray(), actual.Roles));
                }
            }
        }
        c.Probe.Contract(witnesses.Select(w => w.Coordinate).Distinct().Count() == witnesses.Count &&
            witnesses.Select(w => (w.Scope, w.ProjectId, w.MembershipId)).Distinct().Count() == witnesses.Count,
            NativeFailure.EffectMismatch);
        return witnesses.ToArray();
    }

    private static bool Matches(IdentitySearchFilter? filter, Witness witness)
    {
        static bool Text(IdentitySearchText? text, string value) => text is null ||
            (text.ShorthandValue is null || value == text.ShorthandValue) &&
            (text.Equal is null || value == text.Equal) &&
            (text.Contains is null || value.Contains(text.Contains, StringComparison.Ordinal)) &&
            (text.AnyOf is null || text.AnyOf.Contains(value, StringComparer.Ordinal));
        bool Clause(IdentitySearchClause? clause) => clause is null ||
            Text(clause.Name, witness.Name) && (clause.Role is null || witness.Roles.Any(r => Text(clause.Role, r)));
        return filter is null || Clause(filter.All) && (filter.AnyOf is null || filter.AnyOf.Any(Clause));
    }

    private static IdentitySearchFilter? Filter(string variant, string prefix, string name, string secondName,
        string role, string alternateRole)
    {
        if (variant == "filter.omitted") return null;
        if (variant == "filter.empty") return new();
        if (variant == "filter.anyOf.empty") return new(anyOf: []);
        if (variant == "filter.anyOf.clauses")
            return new(anyOf: [new(name: new(equal: name)), new(name: new(equal: secondName))]);
        if (variant == "filter.all") return new(all: new(name: new(contains: prefix), role: new(equal: role)));
        if (variant.StartsWith("order.", StringComparison.Ordinal) || variant.StartsWith("direction.", StringComparison.Ordinal))
            return new(all: new(name: new(anyOf: [name, secondName])));
        bool roleFilter = variant.StartsWith("role.", StringComparison.Ordinal);
        string value = roleFilter ? role : name;
        IdentitySearchText text = variant.Split('.').Last() switch
        {
            "shorthand" => IdentitySearchText.Shorthand(value),
            "contains" => new(contains: roleFilter ? role[..^1] : prefix),
            "in" => new(anyOf: [value, roleFilter ? alternateRole : secondName]),
            _ => new(equal: value)
        };
        return new(all: roleFilter ? new(role: text) : new(name: text));
    }
}
