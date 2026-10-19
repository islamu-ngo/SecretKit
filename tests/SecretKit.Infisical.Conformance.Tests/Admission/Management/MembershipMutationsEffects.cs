using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class MembershipMutationsEffects
{
    internal static string? UnavailableReason(NativeCaseDefinition definition)
    {
        if (definition.Key.Operation.EndsWith(".DeleteOrganizationMemberships", StringComparison.Ordinal))
            return "fresh-organization-user-membership-provisioner-unavailable";
        return definition.Key.Variant switch
        {
            "result.partial" => "version-bound-partial-batch-trigger-unavailable",
            _ => null
        };
    }

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, CancellationToken token)
    {
        if (c.Variant == "principals.emails-and-usernames")
        {
            await ExecuteMixedAsync(c, token);
            return;
        }
        await c.EnsureProjectAsync(token);
        string username = c.Required("runtimeUsername"), userId = c.Required("runtimeUserId");
        bool invite = c.Operation == "InviteProjectMembers";
        var principals = c.Variant == "principals.emails" ?
            new MembershipPrincipals(emails: [c.Required("runtimeEmail")]) : new MembershipPrincipals(usernames: [username]);
        string[]? roles = c.Variant == "roleSlugs.omitted" ? null : ["viewer"];
        var canary = await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token);
        if (!invite)
            await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId,
                c.ProjectId, principals, ["viewer"]), NativeIdentityRole.Setup, token);
        SecretOutcome<ProjectMembershipSummary> before = await c.ExecuteAsync(
            () => ProjectMembershipOperations.InspectProjectMembershipByUsername(c.OrganizationId, c.ProjectId, username),
            NativeIdentityRole.Observer, token);
        c.Probe.Contract(invite ? before.Status == SecretStatus.Absent :
            before.IsSuccess && before.Value.UserId == userId, NativeFailure.MissingPrerequisite);
        c.Probe.Contract(await canary.ReadAsync(NativeIdentityRole.Runtime, !invite, token) &&
            await canary.ReadAsync(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);
        Func<ManagementRequest<ManagementPage<ProjectMembershipMutationSummary>>> request = invite ?
            () => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId, c.ProjectId, principals, roles) :
            () => MembershipMutationOperations.RemoveProjectMembers(c.OrganizationId, c.ProjectId, principals);
        await c.CaseAsync(request,
            page => page.IsComplete && page.Items.Count == 1 && page.Items[0].UserId == userId &&
                page.Items[0].ProjectId == c.ProjectId && (invite || page.Items[0].Id == before.Value.Id),
            async (applied, ct) =>
            {
                bool present = applied ? invite : !invite;
                SecretOutcome<ProjectMembershipSummary> observed = await c.ExecuteAsync(
                    () => ProjectMembershipOperations.InspectProjectMembershipByUsername(c.OrganizationId, c.ProjectId, username),
                    NativeIdentityRole.Observer, ct);
                bool matched = (present ? observed.IsSuccess && observed.Value.UserId == userId &&
                    observed.Value.User.Username == username &&
                    (roles is null || observed.Value.Roles.Any(r => r.Role == "viewer" && r.IsTemporary != true)) :
                    observed.Status == SecretStatus.Absent) &&
                    await canary.ReadAsync(NativeIdentityRole.Runtime, present, ct) &&
                    await canary.ReadAsync(NativeIdentityRole.Denied, false, ct);
                if (matched) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope,
                    "membership-principal-observer", NativeObservation.Matched);
                return matched;
            }, token);
    }

    private static async ValueTask ExecuteMixedAsync(ProjectFamilyContext c, CancellationToken token)
    {
        string[] usernames = [c.Required("runtimeUsername"), c.Required("secondRuntimeUsername")];
        string[] users = [c.Required("runtimeUserId"), c.Required("secondRuntimeUserId")];
        string[] emails = [c.Required("runtimeEmail"), c.Required("secondRuntimeEmail")];
        c.Probe.Contract(usernames.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2 &&
            users.Distinct(StringComparer.Ordinal).Count() == 2 &&
            emails.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 2, NativeFailure.MissingInput);
        using var secondary = new PrincipalTokens(SecretMaterial.FromText(c.Required("secondRuntimeToken")));
        foreach (NativeIdentityRole role in Enum.GetValues<NativeIdentityRole>())
        {
            var selected = await c.Environment.Tokens(role).GetTokenAsync(token);
            c.Probe.Contract(selected.IsSuccess, NativeFailure.MissingInput);
            using var credential = selected.Value;
            char[] first = credential.Material.ExportCharacters(), second = secondary.Material.ExportCharacters();
            try { c.Probe.Contract(!first.AsSpan().SequenceEqual(second), NativeFailure.MissingInput); }
            finally { Array.Clear(first); Array.Clear(second); }
        }
        await using var secondReader = new InfisicalClient(c.Environment.Origin, secondary,
            new InfisicalNetworkOptions { AllowLoopbackDevelopmentHttp = c.Environment.AllowLoopbackDevelopmentHttp });
        var firstSelection = new MembershipPrincipals(usernames: [usernames[0]]);
        var secondSelection = new MembershipPrincipals(emails: [emails[1]]);
        var principals = new MembershipPrincipals(emails: [emails[1]], usernames: [usernames[0]]);
        await c.EnsureProjectAsync(token);
        var canary = await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token);
        async ValueTask<bool> Access(bool first, bool second, CancellationToken ct)
        {
            bool a = await canary.ReadAsync(NativeIdentityRole.Runtime, first, ct);
            bool b = await canary.ReadAsync(secondReader, second, ct);
            bool denied = await canary.ReadAsync(NativeIdentityRole.Denied, false, ct);
            return a && b && denied;
        }
        async ValueTask<SecretOutcome<ProjectMembershipSummary>> Inspect(int index, CancellationToken ct) =>
            await c.ExecuteAsync(() => ProjectMembershipOperations.InspectProjectMembershipByUsername(
                c.OrganizationId, c.ProjectId, usernames[index]), NativeIdentityRole.Observer, ct);
        bool Member(SecretOutcome<ProjectMembershipSummary> result, int index) =>
            result.IsSuccess && result.Value.UserId == users[index] &&
            result.Value.User.Username == usernames[index] &&
            result.Value.Roles.Any(r => r.Role == "viewer" && r.IsTemporary != true);
        c.Probe.Contract((await Inspect(0, token)).Status == SecretStatus.Absent &&
            (await Inspect(1, token)).Status == SecretStatus.Absent && await Access(false, false, token),
            NativeFailure.MissingPrerequisite);
        // Token text is not principal evidence. Asymmetric access binds both
        // selected credential sources before the case can mutate memberships.
        foreach (bool firstOnly in new[] { true, false })
        {
            var selection = firstOnly ? firstSelection : secondSelection;
            await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId,
                c.ProjectId, selection, ["viewer"]), NativeIdentityRole.Setup, token);
            int active = firstOnly ? 0 : 1;
            c.Probe.Contract(Member(await Inspect(active, token), active) &&
                (await Inspect(1 - active, token)).Status == SecretStatus.Absent &&
                await Access(firstOnly, !firstOnly, token), NativeFailure.MissingPrerequisite);
            await c.NeedAsync(() => MembershipMutationOperations.RemoveProjectMembers(c.OrganizationId,
                c.ProjectId, selection), NativeIdentityRole.Setup, token);
            c.Probe.Contract(await Access(false, false, token), NativeFailure.MissingPrerequisite);
        }
        bool invite = c.Operation == "InviteProjectMembers";
        if (!invite)
            await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId,
                c.ProjectId, principals, ["viewer"]), NativeIdentityRole.Setup, token);
        var before = new[] { await Inspect(0, token), await Inspect(1, token) };
        c.Probe.Contract(Enumerable.Range(0, 2).All(i => invite ? before[i].Status == SecretStatus.Absent :
            Member(before[i], i)) && await Access(!invite, !invite, token), NativeFailure.MissingPrerequisite);
        Func<ManagementRequest<ManagementPage<ProjectMembershipMutationSummary>>> request = invite ?
            () => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId, c.ProjectId, principals, ["viewer"]) :
            () => MembershipMutationOperations.RemoveProjectMembers(c.OrganizationId, c.ProjectId, principals);
        await c.CaseAsync(request,
            page => page.IsComplete && page.Items.Count == 2 &&
                page.Items.Select(m => m.Id).Distinct(StringComparer.Ordinal).Count() == 2 &&
                users.All(user => page.Items.Count(m => m.UserId == user && m.ProjectId == c.ProjectId) == 1) &&
                (invite || Enumerable.Range(0, 2).All(i =>
                    page.Items.Single(m => m.UserId == users[i]).Id == before[i].Value.Id)),
            async (applied, ct) =>
            {
                bool present = applied ? invite : !invite;
                var observed = new[] { await Inspect(0, ct), await Inspect(1, ct) };
                bool state = Enumerable.Range(0, 2).All(i =>
                    present ? Member(observed[i], i) : observed[i].Status == SecretStatus.Absent);
                bool access = await Access(present, present, ct);
                if (state && access) c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope,
                    "membership-principal-observer", NativeObservation.Matched);
                return state && access;
            }, token);
    }

    private sealed class PrincipalTokens(SecretMaterial material) : IInfisicalTokenSource, IDisposable
    {
        internal SecretMaterial Material => material;
        public ValueTask<SecretOutcome<InfisicalAccessToken>> GetTokenAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            return ValueTask.FromResult(SecretOutcome<InfisicalAccessToken>.Success(new(material.Copy())));
        }
        public void Dispose() => material.Dispose();
        public override string ToString() => "[PrincipalTokens]";
    }
}
