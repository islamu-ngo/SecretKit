using System.Globalization;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class TemporalMembershipEffects
{
    private sealed record State(string Id, string Principal, IReadOnlyList<ProjectMembershipRole> Roles)
    {
        public override string ToString() => "[TemporalMembershipState]";
    }

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IMembershipExpiryObserver? observer,
        CancellationToken token)
    {
        bool injected = observer is not null;
        if (!c.Input.TryGetProperty("temporal", out JsonElement input))
        {
            if (!injected) c.Probe.Effect(NativeObservation.Unavailable);
            throw new NativeCaseFailureException("missing-input");
        }
        if (input.ValueKind != JsonValueKind.Object ||
            !input.TryGetProperty("nativeDuration", out var duration) || duration.GetString() != "1m" ||
            !input.TryGetProperty("activationLeadSeconds", out var leadValue) || !leadValue.TryGetInt32(out int lead) ||
            lead is < 1 or > 300 || !input.TryGetProperty("sourceProfile", out var profile) ||
            profile.ValueKind != JsonValueKind.String || !Enum.TryParse<MembershipExpirySource>(
                profile.GetString(), out var source) || !Enum.IsDefined(source) ||
            source == MembershipExpirySource.ControlledFixture && !injected ||
            InfisicalGovernanceFamilies.CaseTimeout(c.Input).TotalSeconds < lead + 90)
            throw new NativeCaseFailureException("missing-input");
        observer ??= InfisicalMembershipExpiryObserver.FromInputs(c.Environment, "C08-IM-" +
            (c.Operation == "UpdateProjectMembershipRoles" ? "ProjectMemberships" : "Memberships"));
        if (observer is null) c.Probe.Effect(NativeObservation.Unavailable);
        if (!injected)
        {
            var settings = c.Environment.RequireFamilyInput("C08-IM-" +
                (c.Operation == "UpdateProjectMembershipRoles" ? "ProjectMemberships" : "Memberships"))
                .GetProperty("observer");
            c.Probe.Contract(settings.GetProperty("timeoutSeconds").TryGetInt32(out int seconds) &&
                seconds >= 60, NativeFailure.MissingInput);
        }
        bool user = c.Operation == "UpdateProjectMembershipRoles";
        bool group = c.Operation.Contains("Group", StringComparison.Ordinal);
        bool add = c.Operation.StartsWith("Add", StringComparison.Ordinal);
        string runtime = c.Required(user ? "runtimeUserId" : "runtimeIdentityId");
        string? username = user ? c.Required("runtimeUsername") : null;
        await c.EnsureProjectAsync(token);
        string project = c.ProjectId;
        string principal = group ? (await MembershipsEffects.SeedGroupAsync(c, token)).Id : runtime;
        if (group)
            await c.NeedAsync(() => ScopedAccessOperations.AddGroupIdentity(c.OrganizationId, principal, runtime),
                NativeIdentityRole.Setup, token);
        if (!add)
        {
            if (user)
                await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId, project,
                    new(usernames: [username!]), ["no-access"]), NativeIdentityRole.Setup, token);
            else
                await c.NeedAsync(() => group ? MembershipOperations.AddProjectGroup(c.OrganizationId, project,
                    principal, new MembershipRoleSelection(roles: [new("no-access")])) :
                    MembershipOperations.AddProjectIdentity(c.OrganizationId, project, principal,
                        new MembershipRoleSelection(roles: [new("no-access")])), NativeIdentityRole.Setup, token);
        }
        async ValueTask<State?> Read(CancellationToken ct)
        {
            if (group)
            {
                var r = await c.ExecuteAsync(() => MembershipOperations.GetProjectGroup(c.OrganizationId,
                    project, principal), NativeIdentityRole.Observer, ct);
                if (r.Status == SecretStatus.Absent) return null;
                c.Probe.Contract(r.IsSuccess && r.Value.Group?.Id == principal && r.Value.Roles.IsPresent &&
                    !r.Value.Roles.IsNull, NativeFailure.ContractMismatch);
                return new(r.Value.Id, r.Value.PrincipalId, r.Value.Roles.Value);
            }
            if (user)
            {
                var r = await c.ExecuteAsync(() => ProjectMembershipOperations.InspectProjectMembershipByUsername(
                    c.OrganizationId, project, username!), NativeIdentityRole.Observer, ct);
                if (r.Status == SecretStatus.Absent) return null;
                c.Probe.Contract(r.IsSuccess && r.Value.User.Username == username, NativeFailure.ContractMismatch);
                return new(r.Value.Id, r.Value.UserId, r.Value.Roles);
            }
            var identity = await c.ExecuteAsync(() => MembershipOperations.GetProjectIdentityMembership(
                c.OrganizationId, project, principal), NativeIdentityRole.Observer, ct);
            if (identity.Status == SecretStatus.Absent) return null;
            c.Probe.Contract(identity.IsSuccess, NativeFailure.ContractMismatch);
            return new(identity.Value.Id, identity.Value.IdentityId, identity.Value.Roles);
        }
        State? before = await Read(token);
        c.Probe.Contract(add ? before is null : before is not null && before.Principal == principal &&
            Permanent(before.Roles), NativeFailure.MissingPrerequisite);
        var canary = await ProjectCanary.CreateAsync(c, project, "witness", token);
        c.Probe.Contract(await canary.ReadAsync(NativeIdentityRole.Runtime, false, token) &&
            await canary.ReadAsync(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);
        string controlName = ProjectFamilyContext.FreshName();
        c.OwnProject(controlName);
        var controlProject = await c.NeedAsync(() => ProjectOperations.CreateProject(c.OrganizationId,
            controlName, controlName, createDefaultEnvironments: false), NativeIdentityRole.Setup, token);
        await c.AddObserversAsync(controlProject.Id, token);
        if (user)
            await c.NeedAsync(() => MembershipMutationOperations.InviteProjectMembers(c.OrganizationId,
                controlProject.Id, new(usernames: [username!]), ["viewer"]), NativeIdentityRole.Setup, token);
        else
            await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId, controlProject.Id,
                runtime, new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, token);
        var control = await ProjectCanary.CreateAsync(c, controlProject.Id, "witness", token);
        c.Probe.Contract(await control.ReadAsync(NativeIdentityRole.Runtime, true, token),
            NativeFailure.MissingPrerequisite);
        var attempt = new MembershipExpiryAttempt(Guid.NewGuid().ToString("N"), c.Definition.Key.Identity,
            c.OrganizationId, project, group ? MembershipExpiryPrincipal.Group :
                user ? MembershipExpiryPrincipal.User : MembershipExpiryPrincipal.Identity,
            principal, runtime, before?.Id, source);
        var intent = new MembershipExpiryIntent(attempt, "1m", lead);
        bool armed = false;
        c.Cleanup(async ct =>
        {
            if (!armed) return true;
            var cleanup = await observer!.CloseAsync(attempt, ct);
            return cleanup.Attempt == attempt && cleanup.Closed && cleanup.LateCreationFenced &&
                cleanup.MutationSettled && cleanup.InventoryComplete &&
                cleanup.RemainingRegistrations == 0 && cleanup.PendingDeliveries == 0;
        });
        armed = true;
        var arm = await observer!.ArmAsync(intent, token);
        c.Probe.Contract(arm.Intent == intent && Text(arm.RegistrationId) && Text(arm.SourceIdentity) &&
            !new[] { "setup", "runtime", "denied", "administrative", "observer", runtime,
                c.Required("administrativeIdentityId"), c.Required("observerIdentityId") }.Contains(arm.SourceIdentity) &&
            Text(arm.ClockAuthority) && Text(arm.ClockEpoch) && arm.CaptureArmed && arm.Cursor >= 0 &&
            Utc(arm.ArmedAt) && Utc(arm.StartsAt) && Utc(arm.EndsAt) &&
            arm.StartsAt - arm.ArmedAt == TimeSpan.FromSeconds(lead) &&
            arm.EndsAt - arm.StartsAt == TimeSpan.FromMinutes(1), NativeFailure.ContractMismatch);
        MembershipRole[] roles = [new("no-access"), new("viewer", arm.StartsAt, "1m")];
        bool Match(MembershipSummary m) => m.PrincipalId == principal && (add || m.Id == before!.Id);
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            bool cancelled = c.Definition.Key.Case == "cancellation-boundary";
            var binding = cancelled ? new MembershipExpiryFence(arm, null, MembershipExpiryDisposition.NotDispatched,
                before?.Id, null, checked(arm.Cursor + 1), true) : await observer.CompleteAsync(arm, ct);
            c.Probe.Contract(binding.Arm == arm && binding.ExcludesLateCommit && binding.Sequence > arm.Cursor &&
                binding.Disposition == (cancelled ? MembershipExpiryDisposition.NotDispatched : applied ?
                    MembershipExpiryDisposition.Applied : MembershipExpiryDisposition.Rejected) &&
                (cancelled ? binding.ProviderRequestId is null : Text(binding.ProviderRequestId)) &&
                (applied ? Text(binding.MembershipId) && Text(binding.AssignmentId) &&
                    (add || binding.MembershipId == before!.Id) :
                    binding.MembershipId == before?.Id && binding.AssignmentId is null), NativeFailure.ContractMismatch);
            long sequence = binding.Sequence;
            string? permanentId = null;
            foreach (var phase in Enum.GetValues<MembershipExpiryPhase>())
            {
                var observed = await observer.ObserveAsync(binding, phase, async sampleToken =>
                {
                    State? current = await Read(sampleToken);
                    bool state;
                    if (!applied)
                        state = before is null ? current is null : current is not null && current.Id == before.Id &&
                            current.Principal == principal && SameRoles(before.Roles, current.Roles);
                    else
                    {
                        state = current is not null && current.Id == binding.MembershipId && current.Principal == principal &&
                            current.Roles.Select(r => r.Id).Distinct().Count() == current.Roles.Count;
                        if (state)
                        {
                            var permanent = current!.Roles.Where(NoAccess).ToArray();
                            state = permanent.Length == 1 && (permanentId is null || permanent[0].Id == permanentId);
                            if (state) permanentId ??= permanent[0].Id;
                            var temporary = current.Roles.Where(r => !NoAccess(r)).ToArray();
                            state &= phase == MembershipExpiryPhase.Expired && temporary.Length == 0 ||
                                temporary.Length == 1 && Temporary(temporary[0], arm, binding.AssignmentId!);
                        }
                    }
                    bool link = true;
                    if (group)
                    {
                        var linked = await c.ExecuteAsync(() => ScopedAccessOperations.ListGroupMembers(
                            c.OrganizationId, principal), NativeIdentityRole.Observer, sampleToken);
                        link = linked.IsSuccess && linked.Value.IsComplete &&
                            linked.Value.Items.Count == 1 &&
                            linked.Value.Items.Count(m => m.PrincipalId == runtime &&
                                m.Kind == GroupMemberKind.MachineIdentity) == 1;
                    }
                    bool value = await canary.ReadAsync(NativeIdentityRole.Runtime,
                        applied && phase == MembershipExpiryPhase.Active, sampleToken);
                    bool denied = await canary.ReadAsync(NativeIdentityRole.Denied, false, sampleToken);
                    bool exists = await canary.ReadAsync(NativeIdentityRole.Observer, true, sampleToken);
                    bool authenticated = await control.ReadAsync(NativeIdentityRole.Runtime, true, sampleToken);
                    return state && link && value && denied && exists && authenticated;
                }, ct);
                var window = observed.Window;
                c.Probe.Contract(window.Binding == binding && window.Phase == phase && Text(window.WindowId) &&
                    Text(window.EventId) && window.Authoritative && window.EventObserved && window.Sequence > sequence &&
                    Utc(window.OpenedAt) && Utc(window.ClosedAt) && window.ClosedAt >= window.OpenedAt &&
                    InPhase(window.OpenedAt, arm, phase) && InPhase(window.ClosedAt, arm, phase),
                    NativeFailure.ContractMismatch);
                sequence = window.Sequence;
                if (!observed.Sample) return false;
            }
            c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "membership-principal-observer", NativeObservation.Matched);
            return true;
        }
        if (user)
            await c.CaseAsync(() => ProjectMembershipOperations.UpdateProjectMembershipRoles(c.OrganizationId,
                project, before!.Id, roles), page => page.IsComplete && page.Items.Count == 2 &&
                page.Items.Count(NoAccess) == 1 && page.Items.Count(r => Temporary(r, arm, r.Id)) == 1,
                Observe, token);
        else if (c.Operation == "UpdateProjectGroupRoles")
            await c.CaseAsync(() => MembershipOperations.UpdateProjectGroupRoles(c.OrganizationId, project, principal,
                before!.Id, roles), page => page.IsComplete && page.Items.Count == 2 &&
                before is not null && page.Items.All(r => r.MembershipId == before.Id) &&
                page.Items.Count(r => r.Role == "no-access" && r.IsTemporary == false) == 1 &&
                page.Items.Count(r => r.Role == "viewer" && r.IsTemporary == true && r.Mode == "relative" &&
                    r.Range == "1m" && Time(r.StartsAt, arm.StartsAt) && Time(r.EndsAt, arm.EndsAt)) == 1,
                Observe, token);
        else
        {
            bool list = c.Definition.Key.Operation.EndsWith(".Roles", StringComparison.Ordinal);
            Func<ManagementRequest<MembershipSummary>> request = c.Operation switch
            {
                "AddProjectGroup" when list => () => MembershipOperations.AddProjectGroup(c.OrganizationId, project, principal, roles),
                "AddProjectGroup" => () => MembershipOperations.AddProjectGroup(c.OrganizationId, project, principal,
                    new MembershipRoleSelection(roles: roles)),
                "AddProjectIdentity" when list => () => MembershipOperations.AddProjectIdentity(c.OrganizationId, project, principal, roles),
                "AddProjectIdentity" => () => MembershipOperations.AddProjectIdentity(c.OrganizationId, project, principal,
                    new MembershipRoleSelection(roles: roles)),
                "UpdateProjectIdentityRoles" => () => MembershipOperations.UpdateProjectIdentityRoles(c.OrganizationId, project, principal, roles),
                _ => throw new NativeCaseFailureException("contract-mismatch")
            };
            await c.CaseAsync(request, Match, Observe, token);
        }
    }

    private static bool NoAccess(ProjectMembershipRole r) => r.Role == "no-access" && r.IsTemporary == false &&
        r.Mode is null && r.Range is null && r.StartsAt is null && r.EndsAt is null;
    private static bool Permanent(IReadOnlyList<ProjectMembershipRole> roles) => roles.Count == 1 && NoAccess(roles[0]);
    private static bool Temporary(ProjectMembershipRole r, MembershipExpiryArm arm, string id) =>
        r.Id == id && r.Role == "viewer" && r.IsTemporary == true && r.Mode == "relative" &&
        r.Range == "1m" && Time(r.StartsAt, arm.StartsAt) && Time(r.EndsAt, arm.EndsAt);
    private static bool SameRoles(IReadOnlyList<ProjectMembershipRole> a, IReadOnlyList<ProjectMembershipRole> b) =>
        a.Count == b.Count && a.All(x => b.Count(y => x.Id == y.Id && x.Role == y.Role &&
            x.IsTemporary == y.IsTemporary && x.Mode == y.Mode && x.Range == y.Range &&
            x.StartsAt == y.StartsAt && x.EndsAt == y.EndsAt) == 1);
    private static bool Time(string? value, DateTimeOffset expected) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) && parsed == expected;
    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool InPhase(DateTimeOffset value, MembershipExpiryArm arm, MembershipExpiryPhase phase) => phase switch
    {
        MembershipExpiryPhase.BeforeActivation => value >= arm.ArmedAt && value < arm.StartsAt,
        MembershipExpiryPhase.Active => value >= arm.StartsAt && value < arm.EndsAt,
        MembershipExpiryPhase.Expired => value >= arm.EndsAt,
        _ => false
    };
}
