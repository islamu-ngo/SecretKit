using SecretKit.Core;
using SecretKit.Infisical.Management;
using SecretKit.TestFixtures;

namespace SecretKit.Infisical.Conformance.Tests;

internal sealed class ProjectTypeTrial(IProjectTypeSource source, ProjectTypeRoot root, int seconds) : IAsyncDisposable
{
    private ProjectTypeReservation? reservation;
    private ProjectTypeIssuance? issuance;
    private ProjectTypeWindow? window;
    private ProjectTypeArm? arm;
    private ProjectTypeState[]? baseline;
    private readonly HashSet<string> events = [];
    private string? registration;
    private long sequence = -1;
    private DateTimeOffset at;
    private int stage;
    private bool busy, failed, closed;
    internal ProjectTypeIssuance Issued => issuance ?? throw new NativeCaseFailureException("observer-unavailable");

    internal static async ValueTask<ProjectTypeTrial> OpenAsync(IProjectTypeSource source, ProjectTypeRoot root,
        SecretMaterial capability, int seconds, Action<ProjectTypeTrial> retain, CancellationToken token)
    {
        ProjectTypeContract.Require(seconds is >= 1 and <= 300 && root.Source == source.Kind &&
            root.SourceIdentity == source.Identity && Enum.IsDefined(root.Source) &&
            ProjectTypeContract.Owns(root.Operation) && ProjectTypeContract.Variants.Contains(root.Variant) &&
            ProjectTypeContract.Cases.Contains(root.Case) && root.Query == ProjectTypeContract.Query(root.Variant) &&
            new[] { root.Id, root.Nonce, root.OrganizationId, root.Scope, root.ProviderRevision, root.Deployment,
                root.Epoch, root.SourceIdentity, root.Origin }.All(ProjectTypeContract.Text) &&
            root.Authorities.All.All(ProjectTypeContract.Text) && root.Authorities.All.Distinct().Count() == 5 &&
            !root.Authorities.All.Contains(root.SourceIdentity), "missing-input");
        var trial = new ProjectTypeTrial(source, root, seconds);
        retain(trial); // Before Reserve/Open: compensation never depends on a reply.
        trial.busy = trial.failed = true;
        using var deadline = trial.Deadline(token);
        var reserved = await source.ReserveAsync(root, capability, deadline.Token);
        trial.Stamp(reserved.Stamp);
        ProjectTypeContract.Require(reserved.CollisionChecked && reserved.ExclusiveRoot &&
            reserved.EnrolledBeforeCreation && reserved.Complete && reserved.Owned.Length == 0 &&
            ProjectTypeContract.BorrowedEqual(reserved.Borrowed, reserved.Borrowed));
        trial.reservation = reserved;
        var issued = await source.OpenAsync(root, deadline.Token);
        trial.Stamp(issued.Stamp);
        ProjectTypeContract.Require(issued.RootReservedBeforeCreation && issued.Complete &&
            trial.Inventory(issued.Inventory) && issued.Projects.Length >= 12 &&
            issued.Projects.Select(p => p.Id).Distinct().Count() == issued.Projects.Length &&
            issued.Projects.Select(p => p.Slug).Distinct().Count() == issued.Projects.Length &&
            ProjectTypeContract.Types.All(t => issued.Projects.Count(p => p.Type == t) >= 2) &&
            issued.Projects.All(p => p.OrganizationId == root.OrganizationId && ProjectTypeContract.Types.Contains(p.Type) &&
                new[] { p.Id, p.Name, p.Slug, p.Description, p.CreatedAt, p.UpdatedAt, p.NativeId, p.DefaultProduct }
                    .All(ProjectTypeContract.Text) && p.Roles.Length > 0 &&
                p.Roles.All(r => new[] { r.Id, r.Name, r.Slug, r.Description, r.CreatedAt, r.UpdatedAt }
                    .All(ProjectTypeContract.Text))) &&
            issued.Projects.All(p => !reserved.Borrowed.Any(b => b.Kind == "project" && b.Id == p.Id)));
        var expected = issued.Projects.SelectMany(p => new[]
        {
            new ProjectTypeResource(root.Id, root.Nonce, "project", p.Id)
        }.Concat(p.Roles.Select(r => new ProjectTypeResource(root.Id, root.Nonce, "role", r.Id)))).ToArray();
        ProjectTypeContract.Require(expected.Length == issued.Inventory.Length && expected.All(issued.Inventory.Contains));
        trial.issuance = issued;
        trial.busy = trial.failed = false;
        return trial;
    }

    internal async ValueTask BeginAsync(string phase, CancellationToken token)
    {
        Enter(phase == "before" ? 0 : 4);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.BeginAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            ProjectTypeContract.Require(phase is "before" or "after" && facts.Phase == phase &&
                facts.Exclusive && facts.StateHeld);
            window = facts; failed = false;
        }
        finally { busy = false; }
    }

    internal async ValueTask ObserveAsync(string phase,
        ManagementPage<ProjectSummary> full, ManagementPage<ProjectSummary>[] selected,
        ProjectTypeAccess[] expectedAccess, CancellationToken token)
    {
        Enter(phase == "before" ? 1 : 5);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ObserveAsync(root, phase, deadline.Token);
            Stamp(facts.Stamp);
            ProjectTypeContract.Require(window is not null && facts.WindowEvent == window.Stamp.Event &&
                facts.Phase == phase && facts.Complete && facts.IndependentTypeStorage &&
                facts.IndependentInventory && facts.IndependentAuthenticatedAccess);
            var owned = Issued.Projects;
            var borrowedIds = reservation!.Borrowed.Where(b => b.Kind == "project").Select(b => b.Id).ToArray();
            ProjectTypeContract.Require(facts.Projects.Length == owned.Length + borrowedIds.Length &&
                facts.Projects.All(p => p.OrganizationId == root.OrganizationId) &&
                ProjectTypeContract.StatesEqual(facts.Projects.Where(p => owned.Any(o => o.Id == p.Id)).ToArray(), owned) &&
                facts.Projects.Where(p => !owned.Any(o => o.Id == p.Id)).Select(p => p.Id).Order()
                    .SequenceEqual(borrowedIds.Order()) &&
                (baseline is null || ProjectTypeContract.StatesEqual(facts.Projects, baseline)) &&
                ProjectTypeContract.BorrowedEqual(facts.Borrowed, reservation.Borrowed) &&
                Page(full, facts.Projects, new(null, true)) && selected.Length == 3 &&
                selected.All(p => Page(p, facts.Projects, root.Query)) &&
                facts.Access.Length == expectedAccess.Length &&
                facts.Access.Select(a => a.RequestId).Distinct().Count() == facts.Access.Length &&
                facts.Access.All(a => ProjectTypeContract.Text(a.RequestId)) &&
                facts.Access.Zip(expectedAccess).All(pair =>
                    pair.First with { RequestId = "" } == pair.Second with { RequestId = "" }), "effect-mismatch");
            baseline ??= facts.Projects;
            failed = false;
        }
        finally { busy = false; }
    }

    internal bool Page(ManagementPage<ProjectSummary> page, ProjectTypeState[] inventory, ProjectTypeQuery query)
    {
        string? type = ProjectTypeContract.Type(query);
        var expected = inventory.Where(p => type is null || p.Type == type).ToArray();
        return page.IsComplete && expected.Length >= 2 && page.Items.Count == expected.Length &&
            page.Items.Select(p => p.Id).Distinct().Count() == expected.Length &&
            page.Items.All(p => expected.Any(e => Match(p, e, query.IncludeRoles == true)));
    }
    internal bool OriginalPage(ManagementPage<ProjectSummary> page) =>
        baseline is not null && Page(page, baseline, root.Query);
    private static bool Match(ProjectSummary p, ProjectTypeState e, bool roles) =>
        p.Id == e.Id && p.Name == e.Name && p.Slug == e.Slug && p.Type == e.Type && p.Description == e.Description &&
        Field(p.DescriptionField, e.Description) && Field(p.CreatedAt, e.CreatedAt) && Field(p.UpdatedAt, e.UpdatedAt) &&
        Field(p.NativeId, e.NativeId) && Field(p.DefaultProduct, e.DefaultProduct) &&
        Field(p.Version, e.Version) && Field(p.HasDeleteProtection, e.DeleteProtection) &&
        NullableString(p.UpgradeStatus, e.Metadata.UpgradeStatus) &&
        NullableString(p.KmsCertificateKeyId, e.Metadata.KmsCertificateKeyId) &&
        NullableString(p.KmsSecretManagerKeyId, e.Metadata.KmsSecretManagerKeyId) &&
        NullableNumber(p.AuditLogsRetentionDays, e.Metadata.AuditLogsRetentionDays) &&
        Field(p.PitVersionLimit, e.Metadata.PitVersionLimit) &&
        NullableBoolean(p.AutoCapitalization, e.Metadata.AutoCapitalization) &&
        NullableBoolean(p.EnforceEncryptedSecretManagerSecretMetadata, e.Metadata.EncryptedMetadata) &&
        Field(p.IsLegacyAdditionalPrivilegesEnabled, e.Metadata.LegacyAdditionalPrivileges) &&
        Field(p.SecretBlindIndexEnabled, e.Metadata.SecretBlindIndexEnabled) &&
        Field(p.SecretSharing, e.Metadata.SecretSharing) && Field(p.ShowSnapshotsLegacy, e.Metadata.ShowSnapshotsLegacy) &&
        p.SecretDetectionIgnoreValues.IsPresent && !p.SecretDetectionIgnoreValues.IsNull &&
        p.SecretDetectionIgnoreValues.Value.SequenceEqual(e.Metadata.IgnoreValues) &&
        p.Environments.IsPresent && !p.Environments.IsNull && p.Environments.Value.Count == e.Metadata.EnvironmentCount &&
        p.DeletedEnvironments.IsPresent && !p.DeletedEnvironments.IsNull &&
        p.DeletedEnvironments.Value.Count == e.Metadata.DeletedEnvironmentCount &&
        (!roles ? !p.Roles.IsPresent : p.Roles.IsPresent && !p.Roles.IsNull && p.Roles.Value.Count == e.Roles.Length &&
            p.Roles.Value.Select(r => r.Id).Distinct().Count() == e.Roles.Length &&
            p.Roles.Value.All(r => e.Roles.Any(s => r.Id == s.Id && r.Name == s.Name && r.Slug == s.Slug &&
                r.CreatedAt == s.CreatedAt && r.UpdatedAt == s.UpdatedAt && Field(r.Description, s.Description) &&
                Field(r.Version, s.Version) && r.HasPermissions && !r.PermissionsIsNull && !r.IncludesPermissionValues)));
    private static bool Field<T>(ProjectField<T> field, T value) where T : notnull =>
        field.IsPresent && !field.IsNull && EqualityComparer<T>.Default.Equals(field.Value, value);
    private static bool NullableString(ProjectField<string> field, string? value) =>
        value is null ? field.IsPresent && field.IsNull : Field(field, value);
    private static bool NullableNumber(ProjectField<double> field, double? value) =>
        value is null ? field.IsPresent && field.IsNull : Field(field, value.Value);
    private static bool NullableBoolean(ProjectField<bool> field, bool? value) =>
        value is null ? field.IsPresent && field.IsNull : Field(field, value.Value);

    internal async ValueTask ArmAsync(CancellationToken token)
    {
        Enter(2);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.ArmAsync(root, deadline.Token);
            Stamp(facts.Stamp);
            ProjectTypeContract.Require(facts.ExactQuery && facts.ExclusiveIngress && facts.MaximumOriginalRequests == 1);
            arm = facts; failed = false;
        }
        finally { busy = false; }
    }
    internal async ValueTask SettleAsync(ProjectTypeReadResult read, CancellationToken token)
    {
        Enter(3);
        try
        {
            using var deadline = Deadline(token);
            var facts = await source.SettleAsync(root, deadline.Token);
            Stamp(facts.Stamp);
            bool presend = root.Case == "cancellation-boundary";
            ProjectTypeContract.Require(arm is not null && facts.ArmEvent == arm.Stamp.Event &&
                facts.Terminal && facts.LateDispatchExcluded && facts.NoReplay && facts.PendingWork == 0 &&
                facts.Requests.Length == (presend ? 0 : 1) &&
                facts.Requests.All(r => ProjectTypeContract.Text(r.RequestId) &&
                    r.Actor == root.Authorities.Actor(root.Case) && r.OrganizationId == root.OrganizationId &&
                    r.Method == "GET" && r.Path == "/api/v1/projects" && r.Query == root.Query) &&
                read.Cancelled == presend && (presend ? read.Status is null :
                    read.Status == (root.Case == "denied-authority" ? SecretStatus.Denied : SecretStatus.Success)),
                "effect-mismatch");
            failed = false;
        }
        finally { busy = false; }
    }
    public async ValueTask DisposeAsync()
    {
        if (closed) return;
        closed = true;
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        try
        {
            var facts = await source.CloseAsync(root, deadline.Token);
            ProjectTypeContract.Require(facts.Root == root && facts.SourceIdentity == source.Identity && Clock(facts.Clock) &&
                facts.CompleteIssuanceInventory && facts.CreationFence && facts.DispatchFence && facts.OriginalTerminal &&
                facts.PendingIssuers == 0 && facts.PendingDispatches == 0 && facts.Registrations == 0 &&
                Inventory(facts.Issued) && facts.Remaining.Length == 0 &&
                (issuance is null || issuance.Inventory.All(facts.Issued.Contains)) &&
                facts.BorrowedPreserved && (reservation is null ||
                    ProjectTypeContract.BorrowedEqual(facts.Borrowed, reservation.Borrowed)), "cleanup-incomplete");
        }
        catch (Exception) { throw new NativeCaseFailureException("cleanup-incomplete"); }
    }
    private bool Inventory(ProjectTypeResource[] resources) =>
        resources.All(r => r.RootId == root.Id && r.Nonce == root.Nonce &&
            r.Kind is "project" or "role" && ProjectTypeContract.Text(r.Id)) &&
        resources.Select(r => (r.Kind, r.Id)).Distinct().Count() == resources.Length;
    private void Stamp(ProjectTypeStamp stamp)
    {
        ProjectTypeContract.Require(stamp.Root == root && ProjectTypeContract.Text(stamp.Registration) &&
            (registration is null || registration == stamp.Registration) &&
            ProjectTypeContract.Text(stamp.Event) && events.Add(stamp.Event) && Clock(stamp.Clock));
        registration ??= stamp.Registration;
    }
    private bool Clock(ProjectTypeClock clock)
    {
        if (clock.Deployment != root.Deployment || clock.Epoch != root.Epoch ||
            clock.Authority != "provider-application-clock" || clock.Sequence <= sequence || clock.At == default ||
            clock.At.Offset != TimeSpan.Zero || clock.At < at) return false;
        sequence = clock.Sequence; at = clock.At; return true;
    }
    private void Enter(int expected)
    {
        ProjectTypeContract.Require(!busy && !failed && !closed && stage == expected);
        busy = failed = true; stage++;
    }
    private CancellationTokenSource Deadline(CancellationToken token)
    {
        var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(seconds));
        return deadline;
    }
    public override string ToString() => "[ProjectTypeTrial]";
}
