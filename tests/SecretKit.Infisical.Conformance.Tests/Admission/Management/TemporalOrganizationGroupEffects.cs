using System.Globalization;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class TemporalOrganizationGroupEffects
{
    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IOrganizationGroupExpiryObserver? observer,
        CancellationToken token)
    {
        bool injected = observer is not null;
        if (!c.Input.TryGetProperty("temporal", out var input) || input.ValueKind != JsonValueKind.Object ||
            !input.TryGetProperty("nativeDuration", out var duration) || duration.ValueKind != JsonValueKind.String ||
            duration.GetString() != "1m" || !input.TryGetProperty("activationLeadSeconds", out var leadValue) ||
            leadValue.ValueKind != JsonValueKind.Number || !leadValue.TryGetInt32(out int lead) || lead is < 1 or > 300 ||
            !input.TryGetProperty("sourceProfile", out var profile) || profile.ValueKind != JsonValueKind.String ||
            profile.GetString() is not ("NativeProvider" or "ControlledFixture") ||
            !input.TryGetProperty("expiredMetadata", out var metadata) || metadata.ValueKind != JsonValueKind.String ||
            metadata.GetString() is not ("RetainedInactive" or "RemovedAssignment"))
            throw new NativeCaseFailureException("missing-input");
        var source = Enum.Parse<MembershipExpirySource>(profile.GetString()!);
        var policy = Enum.Parse<OrganizationGroupExpiredMetadata>(metadata.GetString()!);
        if (source == MembershipExpirySource.ControlledFixture && !injected ||
            source == MembershipExpirySource.NativeProvider &&
                InfisicalGovernanceFamilies.CaseTimeout(c.Input).TotalSeconds < lead + 90)
            throw new NativeCaseFailureException("missing-input");
        if (!c.Input.TryGetProperty("groupOwner", out var ownerInput) || ownerInput.ValueKind != JsonValueKind.Object)
            throw new NativeCaseFailureException("missing-input");
        string Id(string? value)
        {
            if (!Guid.TryParseExact(value, "D", out var id) || id == Guid.Empty)
                throw new NativeCaseFailureException("missing-input");
            return id.ToString("D");
        }
        string OwnerId(string name) => ownerInput.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ?
            Id(value.GetString()) : throw new NativeCaseFailureException("missing-input");
        var scopes = new OrganizationGroupExpiryScopes(OwnerId("organizationId"), OwnerId("setupIdentityId"),
            OwnerId("observerIdentityId"), Id(c.OrganizationId), Id(c.Required("setupIdentityId")),
            Id(c.Required("administrativeIdentityId")), Id(c.Required("observerIdentityId")),
            Id(c.Required("runtimeIdentityId")), Id(c.Required("deniedIdentityId")));
        string[] principals = [scopes.OwnerSetupIdentityId, scopes.OwnerObserverIdentityId, scopes.TargetSetupIdentityId,
            scopes.TargetAdministrativeIdentityId, scopes.TargetObserverIdentityId, scopes.TargetRuntimeIdentityId,
            scopes.TargetDeniedIdentityId];
        c.Probe.Contract(scopes.OwnerOrganizationId != scopes.TargetOrganizationId &&
            principals.Distinct(StringComparer.Ordinal).Count() == 7, NativeFailure.MissingInput);
        observer ??= InfisicalOrganizationGroupExpiryObserver.FromInputs(c.Environment, "C08-IM-Memberships");
        if (observer is null) throw new NativeCaseFailureException("observer-unavailable");
        if (!injected)
        {
            var settings = c.Environment.RequireFamilyInput("C08-IM-Memberships").GetProperty("observer");
            c.Probe.Contract(settings.GetProperty("timeoutSeconds").TryGetInt32(out int seconds) && seconds >= 60,
                NativeFailure.MissingInput);
        }
        var owner = await OrganizationGroupOwner.CreateAsync(c, token);
        string roleName = ProjectFamilyContext.FreshName();
        string? roleId = null;
        c.Cleanup(async ct =>
        {
            var found = await c.ExecuteAsync(() => ScopedAccessOperations.GetOrganizationRoleBySlug(c.OrganizationId, roleName),
                NativeIdentityRole.Observer, ct);
            if (found.Status == SecretStatus.Absent) return true;
            if (!found.IsSuccess || roleId is not null && found.Value.Id != roleId) return false;
            var removed = await c.ExecuteAsync(() => ScopedAccessOperations.DeleteOrganizationRole(c.OrganizationId, found.Value.Id),
                NativeIdentityRole.Setup, ct);
            var absent = await c.ExecuteAsync(() => ScopedAccessOperations.GetOrganizationRoleBySlug(c.OrganizationId, roleName),
                NativeIdentityRole.Observer, ct);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        var role = await c.NeedAsync(() => RoleChangeOperations.CreateOrganizationRole(c.OrganizationId,
            new(roleName, roleName, permissions: [new(OrganizationRoleSubject.Groups, OrganizationRoleAction.Read)])),
            NativeIdentityRole.Setup, token);
        roleId = role.Id;
        var group = await owner.SeedAsync(token);
        string? targetId = null;
        owner.CleanupTarget(group, () => targetId);
        async ValueTask<MembershipSummary?> Read(CancellationToken ct)
        {
            var row = await c.ExecuteAsync(() => MembershipOperations.GetOrganizationGroup(c.OrganizationId, group.Id),
                NativeIdentityRole.Observer, ct);
            if (row.Status == SecretStatus.Absent) return null;
            c.Probe.Contract(row.IsSuccess && OrganizationGroupOwner.Parent(row.Value, group.Id, owner.OrganizationId) &&
                row.Value.Id != owner.MembershipId(group) && (targetId is null || row.Value.Id == targetId) &&
                row.Value.Roles.IsPresent && !row.Value.Roles.IsNull, NativeFailure.ContractMismatch);
            return row.Value;
        }
        c.Probe.Contract(await Read(token) is null, NativeFailure.MissingPrerequisite);
        bool add = c.Operation == "AddOrganizationGroup";
        MembershipSummary? before = null;
        if (!add)
        {
            before = await c.NeedAsync(() => MembershipOperations.AddOrganizationGroup(c.OrganizationId, group.Id,
                [new("no-access")]), NativeIdentityRole.Setup, token);
            targetId = before.Id;
            var selected = await Read(token);
            c.Probe.Contract(selected is not null && selected.Roles.Value.Count == 1 &&
                NoAccess(selected.Roles.Value[0]), NativeFailure.MissingPrerequisite);
            before = selected;
        }
        async ValueTask<bool> GroupAccess(NativeIdentityRole selectedRole, bool allowed, CancellationToken ct)
        {
            var result = await c.ExecuteAsync(() => ScopedAccessOperations.GetGroup(owner.OrganizationId, group.Id), selectedRole, ct);
            return allowed ? result.IsSuccess && result.Value.Id == group.Id &&
                result.Value.Name == group.Name && result.Value.Slug == group.Slug : result.Status == SecretStatus.Denied;
        }
        c.Probe.Contract(await GroupAccess(NativeIdentityRole.Runtime, false, token) &&
            await GroupAccess(NativeIdentityRole.Denied, false, token), NativeFailure.MissingPrerequisite);
        await c.EnsureProjectAsync(token, runtimeMember: true);
        var control = await ProjectCanary.CreateAsync(c, c.ProjectId, "witness", token);
        c.Probe.Contract(await control.ReadAsync(NativeIdentityRole.Runtime, true, token), NativeFailure.MissingPrerequisite);
        var attempt = new OrganizationGroupExpiryAttempt(Guid.NewGuid().ToString("N"), c.Definition.Key.Identity,
            c.Definition.Key.Operation, "v0.166.3", scopes, group.Id, owner.MembershipId(group),
            owner.RuntimeLinkId(group), role.Id, role.Slug, targetId, source, policy);
        var intent = new OrganizationGroupExpiryIntent(attempt, "1m", lead);
        bool armed = false;
        c.Cleanup(async ct =>
        {
            if (!armed) return true;
            var cleanup = await observer.CloseAsync(attempt, ct);
            return cleanup.Attempt == attempt && cleanup.Closed && cleanup.LateCreationFenced &&
                cleanup.MutationSettled && cleanup.InventoryComplete && cleanup.RemainingRegistrations == 0 &&
                cleanup.PendingDeliveries == 0;
        });
        armed = true;
        var arm = await observer.ArmAsync(intent, token);
        c.Probe.Contract(arm.Intent == intent && Text(arm.RegistrationId) && Text(arm.SourceIdentity) &&
            !principals.Contains(arm.SourceIdentity) &&
            !new[] { "setup", "runtime", "denied", "administrative", "observer", "owner-setup", "owner-observer" }.Contains(arm.SourceIdentity) &&
            arm.AuthenticatedScopesObserved && arm.ObservedScopes == scopes && Text(arm.ClockAuthority) &&
            Text(arm.ClockEpoch) && arm.CaptureArmed && arm.Cursor >= 0 &&
            Utc(arm.ArmedAt) && Utc(arm.StartsAt) && Utc(arm.EndsAt) &&
            arm.StartsAt - arm.ArmedAt == TimeSpan.FromSeconds(lead) &&
            arm.EndsAt - arm.StartsAt == TimeSpan.FromMinutes(1), NativeFailure.ContractMismatch);
        bool Temporary(ProjectMembershipRole row, string? id) =>
            (id is null || row.Id == id) && row.Role == "custom" && row.CustomRoleId == role.Id &&
            row.CustomRoleSlug == role.Slug && row.IsTemporary == true && row.Mode == "relative" &&
            row.Range == "1m" && Time(row.StartsAt, arm.StartsAt) && Time(row.EndsAt, arm.EndsAt);
        bool Match(MembershipSummary row)
        {
            bool matches = OrganizationGroupOwner.Parent(row, group.Id, owner.OrganizationId) &&
                row.Id != owner.MembershipId(group) && (targetId is null || row.Id == targetId) &&
                row.Roles.IsPresent && !row.Roles.IsNull && row.Roles.Value.Count == 2 &&
                row.Roles.Value.Select(r => r.Id).Distinct().Count() == 2 &&
                row.Roles.Value.Count(NoAccess) == 1 && row.Roles.Value.Count(r => Temporary(r, null)) == 1;
            if (matches) targetId ??= row.Id;
            return matches;
        }
        bool observationStarted = false;
        async ValueTask<bool> Observe(bool applied, CancellationToken ct)
        {
            observationStarted = true;
            bool cancelled = c.Definition.Key.Case == "cancellation-boundary";
            var binding = cancelled ? new OrganizationGroupExpiryFence(arm, null, MembershipExpiryDisposition.NotDispatched,
                attempt.ExistingTargetMembershipId, null, null, null, checked(arm.Cursor + 1), true) :
                await observer.CompleteAsync(arm, ct);
            c.Probe.Contract(binding.Arm == arm && binding.ExcludesLateCommit && binding.Sequence > arm.Cursor &&
                binding.Disposition == (cancelled ? MembershipExpiryDisposition.NotDispatched : applied ?
                    MembershipExpiryDisposition.Applied : MembershipExpiryDisposition.Rejected) &&
                (cancelled ? binding.ProviderRequestId is null && binding.MutationOrganizationId is null &&
                    binding.MutationIdentityId is null : Text(binding.ProviderRequestId) &&
                    binding.MutationOrganizationId == scopes.TargetOrganizationId &&
                    binding.MutationIdentityId == (applied ? scopes.TargetAdministrativeIdentityId : scopes.TargetDeniedIdentityId)) &&
                (applied ? Text(binding.TargetMembershipId) && binding.TargetMembershipId != attempt.OwnerMembershipId &&
                    (targetId is null || binding.TargetMembershipId == targetId) && Text(binding.TemporaryAssignmentId) :
                    binding.TargetMembershipId == attempt.ExistingTargetMembershipId && binding.TemporaryAssignmentId is null),
                NativeFailure.ContractMismatch);
            string? permanentId = null;
            long sequence = binding.Sequence;
            var windows = new HashSet<string>(StringComparer.Ordinal);
            var events = new HashSet<string>(StringComparer.Ordinal);
            foreach (var phase in Enum.GetValues<MembershipExpiryPhase>())
            {
                var observed = await observer.ObserveAsync(binding, phase, async sampleToken =>
                {
                    var row = await Read(sampleToken);
                    bool state;
                    if (!applied)
                        state = before is null ? row is null : row is not null && row.Id == before.Id &&
                            SameRoles(row.Roles.Value, before.Roles.Value);
                    else
                    {
                        bool removed = phase == MembershipExpiryPhase.Expired &&
                            policy == OrganizationGroupExpiredMetadata.RemovedAssignment;
                        state = row is not null && row.Id == binding.TargetMembershipId &&
                            row.Roles.Value.Count == (removed ? 1 : 2) &&
                            row.Roles.Value.Select(r => r.Id).Distinct().Count() == row.Roles.Value.Count;
                        if (state)
                        {
                            var permanent = row!.Roles.Value.Where(NoAccess).ToArray();
                            state = permanent.Length == 1 && (permanentId is null || permanent[0].Id == permanentId);
                            if (state) permanentId ??= permanent[0].Id;
                            state &= removed || row.Roles.Value.Count(r => Temporary(r, binding.TemporaryAssignmentId)) == 1;
                        }
                        if (state) targetId ??= row!.Id;
                    }
                    bool ownerState = await owner.ObserveAsync(group, sampleToken);
                    bool access = await GroupAccess(NativeIdentityRole.Runtime, applied && phase == MembershipExpiryPhase.Active, sampleToken);
                    bool denied = await GroupAccess(NativeIdentityRole.Denied, false, sampleToken);
                    bool inspected = await GroupAccess(NativeIdentityRole.Observer, true, sampleToken);
                    bool authenticated = await control.ReadAsync(NativeIdentityRole.Runtime, true, sampleToken);
                    return state && ownerState && access && denied && inspected && authenticated;
                }, ct);
                var window = observed.Window;
                c.Probe.Contract(window.Binding == binding && window.Phase == phase && Text(window.WindowId) &&
                    Text(window.EventId) && windows.Add(window.WindowId) && events.Add(window.EventId) &&
                    window.Authoritative && window.EventObserved && window.Sequence > sequence &&
                    window.RuntimeOrganizationId == scopes.TargetOrganizationId &&
                    window.RuntimeIdentityId == scopes.TargetRuntimeIdentityId &&
                    Utc(window.OpenedAt) && Utc(window.ClosedAt) && window.ClosedAt >= window.OpenedAt &&
                    InPhase(window.OpenedAt, arm, phase) && InPhase(window.ClosedAt, arm, phase),
                    NativeFailure.ContractMismatch);
                sequence = window.Sequence;
                if (!observed.Sample) return false;
            }
            c.Environment.ConfirmPrerequisite(c.Definition.Key.Scope, "membership-principal-observer", NativeObservation.Matched);
            return true;
        }
        MembershipRole[] roles = [new("no-access"), new(role.Slug, arm.StartsAt, "1m")];
        try
        {
            await c.CaseAsync(() => add ? MembershipOperations.AddOrganizationGroup(c.OrganizationId, group.Id, roles) :
                MembershipOperations.UpdateOrganizationGroupRoles(c.OrganizationId, group.Id, roles), Match, Observe, token);
        }
        catch (NativeCaseFailureException) when (!observationStarted && c.Definition.Key.Case == "denied-authority")
        {
            // A successful forbidden response already latched failure. Still
            // settle the prearmed native request before owned cleanup; no replay.
            await observer.CompleteAsync(arm, token);
            throw;
        }
    }

    private static bool NoAccess(ProjectMembershipRole row) => row.Role == "no-access" && row.IsTemporary == false &&
        row.CustomRoleId is null && row.Mode is null && row.Range is null && row.StartsAt is null && row.EndsAt is null;
    private static bool SameRoles(IReadOnlyList<ProjectMembershipRole> a, IReadOnlyList<ProjectMembershipRole> b) =>
        a.Count == b.Count && a.All(x => b.Count(y => x.Id == y.Id && x.Role == y.Role &&
            x.CustomRoleId == y.CustomRoleId && x.CustomRoleSlug == y.CustomRoleSlug && x.IsTemporary == y.IsTemporary &&
            x.Mode == y.Mode && x.Range == y.Range && x.StartsAt == y.StartsAt && x.EndsAt == y.EndsAt) == 1);
    private static bool Time(string? value, DateTimeOffset expected) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) && parsed == expected;
    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool InPhase(DateTimeOffset value, OrganizationGroupExpiryArm arm, MembershipExpiryPhase phase) => phase switch
    {
        MembershipExpiryPhase.BeforeActivation => value >= arm.ArmedAt && value < arm.StartsAt,
        MembershipExpiryPhase.Active => value >= arm.StartsAt && value < arm.EndsAt,
        MembershipExpiryPhase.Expired => value >= arm.EndsAt,
        _ => false
    };
}
