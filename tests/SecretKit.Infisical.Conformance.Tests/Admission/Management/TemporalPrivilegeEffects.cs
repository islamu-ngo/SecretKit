using System.Globalization;
using System.Text.Json;
using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal static class TemporalPrivilegeEffects
{
    internal static bool Owns(NativeCaseDefinition definition) =>
        definition.Key.Operation.StartsWith("i.management.IdentityPrivilegeChangeOperations.", StringComparison.Ordinal) &&
        (definition.Key.Variant.Contains("relative", StringComparison.Ordinal) ||
            definition.Key.Operation.EndsWith("CreateTemporaryLegacyPrivilege", StringComparison.Ordinal));

    internal static async ValueTask ExecuteAsync(ProjectFamilyContext c, IPrivilegeExpiryObserver? observer,
        CancellationToken token)
    {
        bool injected = observer is not null;
        if (!c.Input.TryGetProperty("temporal", out JsonElement input) || input.ValueKind != JsonValueKind.Object ||
            !input.TryGetProperty("nativeDuration", out var durationValue) ||
            durationValue.ValueKind != JsonValueKind.String ||
            !input.TryGetProperty("activationLeadSeconds", out var leadValue) || !leadValue.TryGetInt32(out int lead) ||
            lead is < 1 or > 300 || !input.TryGetProperty("sourceProfile", out var profile) ||
            profile.ValueKind != JsonValueKind.String || !Enum.TryParse<PrivilegeExpirySource>(
                profile.GetString(), out var source) || !Enum.IsDefined(source) ||
            source == PrivilegeExpirySource.ControlledFixture && !injected)
            throw new NativeCaseFailureException("missing-input");
        string duration = durationValue.GetString()!;
        int seconds = duration switch { "1m" => 60, "1h" => 3600, "1d" => 86400, _ => 0 };
        string? required = c.Variant switch
        {
            "lifetime.relative-minute" => "1m",
            "lifetime.relative-hour" => "1h",
            "lifetime.relative-day" => "1d",
            _ => null
        };
        TimeSpan budget = InfisicalGovernanceFamilies.CaseTimeout(c.Input);
        if (seconds == 0 || required is not null && duration != required ||
            source == PrivilegeExpirySource.NativeProvider && (duration != "1m" || budget.TotalSeconds < seconds + lead + 30))
            throw new NativeCaseFailureException("missing-input");
        observer ??= InfisicalPrivilegeExpiryObserver.FromInputs(c.Environment, "C08-IM-IdentityPrivilegeChanges");
        if (observer is null) throw new NativeCaseFailureException("observer-unavailable");
        if (!injected)
        {
            var settings = c.Environment.RequireFamilyInput("C08-IM-IdentityPrivilegeChanges").GetProperty("observer");
            c.Probe.Contract(settings.GetProperty("timeoutSeconds").TryGetInt32(out int timeout) &&
                timeout >= seconds, NativeFailure.MissingInput);
        }
        bool legacy = c.Operation.Contains("Legacy", StringComparison.Ordinal);
        bool update = c.Operation.StartsWith("Update", StringComparison.Ordinal);
        bool read = c.Operation == "GetProjectPrivilegeBySlug";
        await c.EnsureProjectAsync(token);
        string principal = c.Required("runtimeIdentityId");
        MembershipSummary membership = await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(
            c.OrganizationId, c.ProjectId, principal, new MembershipRoleSelection(roles: [new("no-access")])),
            NativeIdentityRole.Setup, token);
        var selection = new LegacyPrivilegeSelection(c.OrganizationId, c.ProjectId, c.ProjectSlug, principal, membership.Id);
        async ValueTask<bool> Baseline(CancellationToken ct)
        {
            var selected = await c.ExecuteAsync(() => MembershipOperations.GetProjectIdentityMembership(
                c.OrganizationId, c.ProjectId, principal), NativeIdentityRole.Observer, ct);
            return selected.IsSuccess && selected.Value.Id == membership.Id && selected.Value.IdentityId == principal &&
                selected.Value.Roles.Count == 1 && selected.Value.Roles.All(r => r.Role == "no-access" &&
                    r.IsTemporary == false && r.Mode is null && r.Range is null && r.StartsAt is null && r.EndsAt is null);
        }
        c.Probe.Contract(await Baseline(token), NativeFailure.MissingPrerequisite);
        var witness = await PermissionWitness.CreateAsync(c, token);
        c.Probe.Contract(await witness.ObserveAsync(false, token), NativeFailure.MissingPrerequisite);
        string controlName = ProjectFamilyContext.FreshName();
        c.OwnProject(controlName);
        var controlProject = await c.NeedAsync(() => ProjectOperations.CreateProject(c.OrganizationId,
            controlName, controlName, createDefaultEnvironments: false), NativeIdentityRole.Setup, token);
        await c.AddObserversAsync(controlProject.Id, token);
        await c.NeedAsync(() => MembershipOperations.AddProjectIdentity(c.OrganizationId, controlProject.Id,
            principal, new MembershipRoleSelection(roles: [new("viewer")])), NativeIdentityRole.Setup, token);
        var control = await ProjectCanary.CreateAsync(c, controlProject.Id, "witness", token);
        c.Probe.Contract(await control.ReadAsync(NativeIdentityRole.Runtime, true, token), NativeFailure.MissingPrerequisite);
        string slug = ProjectFamilyContext.FreshName();
        string? id = null;
        async ValueTask<IdentityPrivilegeSummary?> Read(CancellationToken ct)
        {
            var inventory = await c.ExecuteAsync(() => legacy ? LegacyIdentityPrivilegeOperations.ListPrivileges(selection) :
                IdentityPrivilegeOperations.ListProjectPrivileges(c.OrganizationId, c.ProjectId, principal),
                NativeIdentityRole.Observer, ct);
            c.Probe.Contract(inventory.IsSuccess && inventory.Value.IsComplete &&
                inventory.Value.Items.Select(p => p.Id).Distinct().Count() == inventory.Value.Items.Count,
                NativeFailure.ContractMismatch);
            var found = inventory.Value.Items.Where(p => p.Slug == slug).ToArray();
            if (found.Length == 0) return null;
            c.Probe.Contract(found.Length == 1 && (id is null || found[0].Id == id), NativeFailure.ContractMismatch);
            var row = await c.ExecuteAsync(() => legacy ? LegacyIdentityPrivilegeOperations.GetPrivilege(selection, slug) :
                IdentityPrivilegeOperations.GetProjectPrivilege(c.OrganizationId, c.ProjectId, principal, found[0].Id),
                NativeIdentityRole.Observer, ct);
            c.Probe.Contract(row.IsSuccess && row.Value.Id == found[0].Id && row.Value.Slug == slug,
                NativeFailure.ContractMismatch);
            return row.Value;
        }
        // Register resource ownership before either setup or measured creation.
        c.Cleanup(async ct =>
        {
            // Cleanup inventory is the selected project/identity's V2 ID catalog,
            // not a fallback mutation after a malformed V1 membership response.
            var inventory = await c.ExecuteAsync(() =>
                IdentityPrivilegeOperations.ListProjectPrivileges(c.OrganizationId, c.ProjectId, principal),
                NativeIdentityRole.Observer, ct);
            if (!inventory.IsSuccess || !inventory.Value.IsComplete ||
                inventory.Value.Items.Select(p => p.Id).Distinct().Count() != inventory.Value.Items.Count) return false;
            var owned = inventory.Value.Items.Where(p => id is null ? p.Slug == slug : p.Id == id).ToArray();
            if (owned.Length == 0) return true;
            if (owned.Length != 1) return false;
            var current = owned[0];
            var removed = await c.ExecuteAsync(() => legacy ? LegacyIdentityPrivilegeOperations.DeletePrivilege(selection, current.Slug) :
                IdentityPrivilegeOperations.DeleteProjectPrivilege(c.OrganizationId, c.ProjectId, principal, current.Id),
                NativeIdentityRole.Setup, ct);
            var absent = await c.ExecuteAsync(() => legacy ? LegacyIdentityPrivilegeOperations.GetPrivilege(selection, current.Slug) :
                IdentityPrivilegeOperations.GetProjectPrivilege(c.OrganizationId, c.ProjectId, principal, current.Id),
                NativeIdentityRole.Observer, ct);
            return removed.IsSuccess && absent.Status == SecretStatus.Absent;
        });
        if (update)
        {
            var seed = await c.NeedAsync(() => legacy ?
                IdentityPrivilegeChangeOperations.CreatePermanentLegacyPrivilege(selection, new(slug, permissions: [])) :
                IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, new([], PrivilegeLifetime.Permanent(), slug)),
                NativeIdentityRole.Setup, token);
            id = seed.Id;
        }
        IdentityPrivilegeSummary? before = await Read(token);
        c.Probe.Contract(update ? before is not null && before.Id == id && before.IsTemporary == false &&
            PermissionPrivilegeScenario.PermissionMetadata(before.Permissions, "permissions.empty") : before is null,
            NativeFailure.MissingPrerequisite);
        var attempt = new PrivilegeExpiryAttempt(Guid.NewGuid().ToString("N"), c.Definition.Key.Identity,
            c.Definition.Key.Operation, legacy ? PrivilegeExpiryVersion.LegacyV1 : PrivilegeExpiryVersion.ProjectV2,
            c.OrganizationId, c.ProjectId, c.ProjectSlug, principal, membership.Id, slug, id, source);
        var intent = new PrivilegeExpiryIntent(attempt, duration, lead);
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
        PrivilegeExpiryArm arm = await observer.ArmAsync(intent, token);
        c.Probe.Contract(arm.Intent == intent && Text(arm.RegistrationId) && Text(arm.SourceIdentity) &&
            !new[] { "setup", "runtime", "denied", "administrative", "observer", principal,
                c.Required("setupIdentityId"), c.Required("deniedIdentityId"), c.Required("administrativeIdentityId"),
                c.Required("observerIdentityId") }.Contains(arm.SourceIdentity) &&
            Text(arm.ClockAuthority) && Text(arm.ClockEpoch) && arm.CaptureArmed && arm.Cursor >= 0 &&
            Utc(arm.ArmedAt) && Utc(arm.StartsAt) && Utc(arm.EndsAt) &&
            arm.StartsAt - arm.ArmedAt == TimeSpan.FromSeconds(lead) &&
            arm.EndsAt - arm.StartsAt == TimeSpan.FromSeconds(seconds), NativeFailure.ContractMismatch);
        var lifetime = PrivilegeLifetime.Temporary(duration, arm.StartsAt);
        var legacyChange = c.Variant == "permissions.array" ?
            new LegacyPrivilegeChange(slug, privilegePermission: new([LegacyPrivilegeAction.Read], new("witness", "/"))) :
            new LegacyPrivilegeChange(slug, permissions: c.Variant == "permissions.empty" ? [] :
                [new(ProjectRoleSubject.Secrets, LegacyPrivilegeAction.Read, new("witness", "/"))],
                isTemporary: update ? true : null, temporaryMode: update ? PrivilegeTemporaryMode.Relative : null,
                temporaryRange: update ? duration : null, temporaryAccessStartTime: update ? arm.StartsAt : null);
        var modern = new ProjectPrivilegeChange(PermissionWitness.Policy(c.Variant), lifetime, slug);
        bool Match(IdentityPrivilegeSummary row)
        {
            bool matches = row.Slug == slug && (id is null || row.Id == id) &&
                Temporary(row, arm) && PermissionPrivilegeScenario.PermissionMetadata(row.Permissions, c.Variant);
            if (matches) id ??= row.Id;
            return matches;
        }
        if (read)
        {
            var seeded = await c.NeedAsync(() => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, modern),
                NativeIdentityRole.Setup, token);
            c.Probe.Contract(Match(seeded), NativeFailure.MissingPrerequisite);
            id = seeded.Id;
        }
        async ValueTask<bool> Observe(bool dispatched, CancellationToken ct)
        {
            bool applied = read || dispatched;
            bool cancelled = !read && c.Definition.Key.Case == "cancellation-boundary";
            var binding = cancelled ? new PrivilegeExpiryFence(arm, null, PrivilegeExpiryDisposition.NotDispatched,
                attempt.ExistingPrivilegeId, slug, checked(arm.Cursor + 1), true) : await observer.CompleteAsync(arm, ct);
            c.Probe.Contract(binding.Arm == arm && binding.ExcludesLateCommit && binding.Sequence > arm.Cursor &&
                binding.PrivilegeSlug == slug &&
                binding.Disposition == (cancelled ? PrivilegeExpiryDisposition.NotDispatched : applied ?
                    PrivilegeExpiryDisposition.Applied : PrivilegeExpiryDisposition.Rejected) &&
                (cancelled ? binding.ProviderRequestId is null : Text(binding.ProviderRequestId)) &&
                (applied ? Text(binding.PrivilegeId) && (id is null || binding.PrivilegeId == id) :
                    binding.PrivilegeId == attempt.ExistingPrivilegeId), NativeFailure.ContractMismatch);
            long sequence = binding.Sequence;
            foreach (var phase in Enum.GetValues<PrivilegeExpiryPhase>())
            {
                var observed = await observer.ObserveAsync(binding, phase, async sampleToken =>
                {
                    IdentityPrivilegeSummary? row = await Read(sampleToken);
                    bool metadata = !applied ? before is null ? row is null :
                        row is not null && row.Id == before.Id && row.IsTemporary == before.IsTemporary &&
                        row.Mode == before.Mode && row.Range == before.Range && row.StartsAt == before.StartsAt &&
                        row.EndsAt == before.EndsAt && PermissionPrivilegeScenario.PermissionMetadata(
                            row.Permissions, "permissions.empty") :
                        phase == PrivilegeExpiryPhase.Expired && row is null || row is not null &&
                            row.Id == binding.PrivilegeId && Match(row);
                    bool permanent = await Baseline(sampleToken);
                    bool access = await witness.ObserveAsync(applied && c.Variant != "permissions.empty" &&
                        phase == PrivilegeExpiryPhase.Active, sampleToken);
                    bool authenticated = await control.ReadAsync(NativeIdentityRole.Runtime, true, sampleToken);
                    return metadata && permanent && access && authenticated;
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
            return true;
        }
        Func<ManagementRequest<IdentityPrivilegeSummary>> request = c.Operation switch
        {
            "CreateTemporaryLegacyPrivilege" => () => IdentityPrivilegeChangeOperations.CreateTemporaryLegacyPrivilege(selection, legacyChange, lifetime),
            "CreateProjectPrivilege" => () => IdentityPrivilegeChangeOperations.CreateProjectPrivilege(selection, modern),
            "UpdateLegacyPrivilege" => () => IdentityPrivilegeChangeOperations.UpdateLegacyPrivilege(selection, slug, legacyChange),
            "UpdateProjectPrivilege" => () => IdentityPrivilegeChangeOperations.UpdateProjectPrivilege(selection, id!, modern),
            "GetProjectPrivilegeBySlug" => () => IdentityPrivilegeChangeOperations.GetProjectPrivilegeBySlug(selection, slug),
            _ => throw new NativeCaseFailureException("contract-mismatch")
        };
        await c.CaseAsync(request, Match, Observe, token);
    }

    private static bool Temporary(IdentityPrivilegeSummary row, PrivilegeExpiryArm arm) =>
        row.IsTemporary == true && row.Mode == "relative" && row.Range == arm.Intent.RelativeDuration &&
        Time(row.StartsAt, arm.StartsAt) && Time(row.EndsAt, arm.EndsAt);
    private static bool Time(string? value, DateTimeOffset expected) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var parsed) && parsed == expected;
    private static bool Text(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 512 && !value.Any(char.IsControl);
    private static bool Utc(DateTimeOffset value) => value != default && value.Offset == TimeSpan.Zero;
    private static bool InPhase(DateTimeOffset value, PrivilegeExpiryArm arm, PrivilegeExpiryPhase phase) => phase switch
    {
        PrivilegeExpiryPhase.BeforeActivation => value >= arm.ArmedAt && value < arm.StartsAt,
        PrivilegeExpiryPhase.Active => value >= arm.StartsAt && value < arm.EndsAt,
        PrivilegeExpiryPhase.Expired => value >= arm.EndsAt,
        _ => false
    };
}
