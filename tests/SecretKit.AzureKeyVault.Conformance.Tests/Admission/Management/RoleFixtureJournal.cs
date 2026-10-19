using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using SecretKit.AzureKeyVault.Management;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Service-local ownership, not a provider result or a release qualification.
// The host supplies a private, trusted directory on durable local storage.
// Every transition is appended and flushed before its caller may dispatch.
internal sealed class RoleFixtureJournal(string directory)
{
    internal sealed class StatusRoleDeleteIndependentHistoryException : InvalidOperationException
    {
        internal StatusRoleDeleteIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }

    internal sealed class StatusSucceededDeleteVaultCancellationHistoryException : InvalidOperationException
    {
        internal StatusSucceededDeleteVaultCancellationHistoryException() : base("fixture-journal-unavailable") { }
    }

    internal sealed class StatusSucceededDeleteVaultIndependentHistoryException : InvalidOperationException
    {
        internal StatusSucceededDeleteVaultIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }

    private const int MaximumFrame = 64 * 1024;
    private const int MaximumJournal = 16 * 1024 * 1024;
    private readonly object gate = new();
    private readonly HashSet<Guid> invalidIndependentRoleHistory = [];
    private readonly HashSet<Guid> invalidNotificationUpdateIndependentHistory = [];
    internal sealed class StatusNotificationUpdateIndependentHistoryException : InvalidOperationException
    {
        internal StatusNotificationUpdateIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }
    private readonly HashSet<Guid> invalidNotificationCreateIndependentHistory = [];
    internal sealed class StatusNotificationCreateIndependentHistoryException : InvalidOperationException
    {
        internal StatusNotificationCreateIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }
    private readonly Dictionary<ManagementOperationFixtureObserverService.PrivateConnectionDeleteCertificates,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> privateDeleteCompletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PrivateConnectionDeleteTermination,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> privateDeleteTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PrivateConnectionDeleteSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> privateDeleteSettlements =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PrivateConnectionUpdateTermination,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> privateUpdateTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PrivateConnectionUpdateSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> privateUpdateSettlements =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.RecoverVaultTermination,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> recoverVaultTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.RecoverVaultSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> recoverVaultCompletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.CreateOrUpdateVaultTermination,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> createVaultTerminations =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> createVaultCompletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<VaultFixtureObserverService.SettingsSettlement, (string Owner, FixtureSelector Selector,
        Guid Lease, Guid Dispatch)> settingsCompletions = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.DeleteVaultSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> deleteVaultCompletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PurgeDeletedVaultSettlement,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> purgeDeletedVaultCompletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<ManagementOperationFixtureObserverService.PurgeDeletedVaultTermination,
        (string Owner, FixtureSelector Selector, Guid Lease, Guid Dispatch)> purgeDeletedVaultTerminations =
        new(ReferenceEqualityComparer.Instance);
    internal sealed record Resource(string Id, bool Borrowed, bool CreateAttempted = false,
        bool DeleteAttempted = false, Guid ActiveDispatch = default, bool Absent = false, bool CleanupOnly = false,
        bool InvocationTerminated = false, bool SelectedAttempted = false)
    {
        public override string ToString() => "[RoleFixtureResource]";
    }
    internal sealed record PrivateEndpointDeclaration(string VaultId, string EndpointId, string BorrowedSubnetId,
        string NetworkConnectionName, string ExpectedNicId, string OwnerTagName, string OwnerTagValue)
    {
        public override string ToString() => "[PrivateEndpointDeclaration]";
    }
    internal sealed record PrivateEndpointState(PrivateEndpointDeclaration Declaration,
        Guid CreationDispatch = default, Resource? Connection = null, bool NicAbsent = false,
        Guid DeletionDispatch = default, Guid ApprovalSettledDispatch = default,
        PrivateConnectionUpdateState? OriginalUpdate = null, PrivateConnectionDeleteState? OriginalDelete = null,
        Guid StatusDeleteSettledDispatch = default)
    {
        public override string ToString() => "[PrivateEndpointState]";
    }
    internal enum PrivateConnectionUpdateDisposition { None, Updated, Denied, InvalidInput }
    internal enum PrivateConnectionDeleteDisposition { None, Denied, Deleted }
    internal sealed record PrivateConnectionDeleteState(VaultAdministrationEffects.Configuration Baseline,
        Guid InvocationDispatch = default, Guid SettledDispatch = default,
        PrivateConnectionDeleteDisposition Disposition = PrivateConnectionDeleteDisposition.None)
    {
        public override string ToString() => "[PrivateConnectionDeleteState]";
    }
    internal sealed record PrivateConnectionUpdateState(PrivateConnectionState Requested,
        VaultAdministrationEffects.Configuration Baseline, Guid InvocationDispatch = default,
        Guid SettledDispatch = default,
        PrivateConnectionUpdateDisposition Disposition = PrivateConnectionUpdateDisposition.None)
    {
        public override string ToString() => "[PrivateConnectionUpdateState]";
    }
    internal sealed record SettingsState(string VaultId, VaultAdministrationEffects.Configuration Baseline,
        Guid InvocationDispatch = default, Guid SettledDispatch = default,
        VaultAdministrationEffects.Configuration? SettledConfiguration = null)
    {
        public override string ToString() => "[VaultSettingsState]";
    }
    internal enum DeleteVaultDisposition { None, Deleted, Denied }
    internal sealed record DeleteVaultState(string VaultId, VaultAdministrationEffects.Configuration Baseline,
        Guid InvocationDispatch = default, Guid SettledDispatch = default,
        DeleteVaultDisposition Disposition = DeleteVaultDisposition.None)
    {
        public override string ToString() => "[DeleteVaultState]";
    }
    internal enum PurgeDeletedVaultDisposition { None, Purged, Denied }
    internal enum StatusPendingPurgeStage
    {
        None = 0, Prepared = 1, OriginalAdmitted = 2, OriginalDrained = 3,
        SelectedAdmitted = 4, PendingObserved = 5, CleanupAdmitted = 6, CleanupTerminal = 7
    }
    internal sealed record PurgeDeletedVaultState(string VaultId, string DeletedVaultId,
        VaultAdministrationEffects.Configuration Baseline, Guid InvocationDispatch = default,
        Guid SettledDispatch = default, PurgeDeletedVaultDisposition Disposition = PurgeDeletedVaultDisposition.None,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingDefault)] StatusPendingPurgeStage PendingStage = default)
    {
        public override string ToString() => "[PurgeDeletedVaultState]";
    }
    internal enum CreateOrUpdateVaultDisposition { None, Updated, Denied }
    internal enum RecoverVaultDisposition { None, Recovered, Denied }
    internal sealed record RecoverVaultState(string VaultId, string DeletedVaultId,
        VaultAdministrationEffects.Configuration Baseline, VaultAdministrationEffects.Configuration Selected,
        Guid InvocationDispatch = default, Guid SettledDispatch = default,
        RecoverVaultDisposition Disposition = RecoverVaultDisposition.None, string? DeletedBaselineSha256 = null)
    {
        public override string ToString() => "[RecoverVaultState]";
    }
    internal sealed record CreateOrUpdateVaultState(string VaultId, VaultAdministrationEffects.Configuration Baseline,
        VaultAdministrationEffects.Configuration Selected, Guid InvocationDispatch = default,
        Guid SettledDispatch = default, CreateOrUpdateVaultDisposition Disposition = CreateOrUpdateVaultDisposition.None)
    {
        public override string ToString() => "[CreateOrUpdateVaultState]";
    }
    internal sealed record NotificationAbsentCreateState(int ContractVersion, Guid NamespaceEpoch,
        string ParentId, string ChildId, Guid InvocationDispatch = default, Guid SettledDispatch = default,
        string? BaselineSha256 = null, string? StartSha256 = null, string? SelectedSha256 = null,
        string? CompletionSha256 = null, string? ConfigurationSha256 = null)
    {
        public override string ToString() => "[NotificationAbsentCreateState]";
    }
    internal sealed record StatusSucceededDeleteVaultState(int ContractVersion, ManagementMutation Operation,
        string VaultId, string DeletedId, VaultAdministrationEffects.Configuration Baseline,
        Guid InvocationDispatch = default, Guid SettledDispatch = default, string? BaselineSha256 = null)
    {
        public VaultAdministrationEffects.Configuration Baseline { get; init; } = CopySettings(Baseline);
        public override string ToString() => "[StatusSucceededDeleteVaultState]";
    }
    internal sealed record Snapshot(string Owner, FixtureSelector Selector, Guid LeaseId,
        bool Closing, Resource[] Resources,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PrivateEndpointState? PrivateEndpoint = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] SettingsState? Settings = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] DeleteVaultState? DeleteVault = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] PurgeDeletedVaultState? PurgeDeletedVault = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] CreateOrUpdateVaultState? CreateOrUpdateVault = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] RecoverVaultState? RecoverVault = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        VaultAdministrationEffects.Configuration? StatusVaultRecoverCancellationBaseline = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        VaultAdministrationEffects.Configuration? StatusVaultUpdateCancellationBaseline = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        NotificationAbsentCreateState? NotificationAbsentCreate = null,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        StatusSucceededDeleteVaultState? StatusSucceededDeleteVault = null)
    {
        [JsonIgnore] internal long Revision { get; init; }
        internal bool SettingsUnsettled => Settings is { } settings &&
            settings.InvocationDispatch != settings.SettledDispatch;
        internal bool DeleteVaultUnsettled => DeleteVault is { } deletion &&
            deletion.InvocationDispatch != deletion.SettledDispatch;
        internal bool PurgeDeletedVaultUnsettled => PurgeDeletedVault is { } purge &&
            purge.InvocationDispatch != purge.SettledDispatch;
        internal bool CreateOrUpdateVaultUnsettled => CreateOrUpdateVault is { } creation &&
            creation.InvocationDispatch != creation.SettledDispatch;
        internal bool RecoverVaultUnsettled => RecoverVault is { } recovery &&
            recovery.InvocationDispatch != recovery.SettledDispatch;
        internal bool NotificationAbsentCreateUnsettled => NotificationAbsentCreate is { } creation &&
            creation.InvocationDispatch != creation.SettledDispatch;
        internal bool Idle => (PrivateEndpoint?.OriginalDelete is not { } deletion ||
                deletion.InvocationDispatch == deletion.SettledDispatch) &&
            (PrivateEndpoint?.OriginalUpdate is not { } update ||
                update.InvocationDispatch == update.SettledDispatch) &&
            !NotificationAbsentCreateUnsettled &&
            (StatusSucceededDeleteVault is not { } succeeded || succeeded.InvocationDispatch == succeeded.SettledDispatch) &&
            !RecoverVaultUnsettled && !CreateOrUpdateVaultUnsettled && !SettingsUnsettled && !DeleteVaultUnsettled && !PurgeDeletedVaultUnsettled &&
            Resources.All(r => r.ActiveDispatch == Guid.Empty) &&
            (PrivateEndpoint is null || PrivateEndpoint.CreationDispatch == Guid.Empty &&
                PrivateEndpoint.DeletionDispatch == Guid.Empty) &&
            (PrivateEndpoint?.Connection is not { } connection || connection.ActiveDispatch == Guid.Empty);
        internal bool PrivateEndpointAbsent => PrivateEndpoint is null ||
            PrivateEndpoint is { NicAbsent: true } slot && PrivateEndpointCleanupEligible &&
            Resources.Any(r => r.Id == slot.Declaration.EndpointId && r.Absent &&
                (!r.CreateAttempted || r.DeleteAttempted && r.InvocationTerminated)) &&
            (slot.Connection is null || slot.Connection is { Absent: true, ActiveDispatch: var active } && active == Guid.Empty);
        internal bool PrivateConnectionCleanupEligible => PrivateEndpoint is { } slot &&
            !Resources.Any(r => r.SelectedAttempted) &&
            ((VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(Selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(Selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(Selector))
                ? (VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(Selector)
                    ? StatusPrivateConnectionDeleteIndependentRoot(this)
                    : VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(Selector)
                    ? StatusPrivateConnectionDeleteSelectedRoot(this) : StatusPrivateConnectionDeleteRoot(this)) &&
                    (slot.Connection is null || slot.Connection is
                    { SelectedAttempted: false, DeleteAttempted: false, ActiveDispatch: var unselected } &&
                        unselected == Guid.Empty || slot.StatusDeleteSettledDispatch != Guid.Empty &&
                        slot.Connection is
                        {
                            SelectedAttempted: true, DeleteAttempted: true,
                            InvocationTerminated: true, ActiveDispatch: var deletedStatus
                        } && deletedStatus == Guid.Empty)
            : slot.StatusDeleteSettledDispatch == Guid.Empty &&
            (slot.OriginalDelete is { } deletion ? slot.OriginalUpdate is null &&
                slot.ApprovalSettledDispatch == Guid.Empty &&
                (deletion.InvocationDispatch == Guid.Empty
                    ? deletion.SettledDispatch == Guid.Empty && deletion.Disposition == PrivateConnectionDeleteDisposition.None &&
                        (slot.Connection is null || slot.Connection is
                        { SelectedAttempted: false, DeleteAttempted: false, ActiveDispatch: var uninvokedDelete } &&
                            uninvokedDelete == Guid.Empty)
                    : deletion.InvocationDispatch == deletion.SettledDispatch &&
                        deletion.Disposition is PrivateConnectionDeleteDisposition.Denied or
                            PrivateConnectionDeleteDisposition.Deleted && slot.Connection is
                            {
                                CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: true,
                                InvocationTerminated: true, Borrowed: false, CleanupOnly: false, ActiveDispatch: var denied
                            } &&
                        denied == Guid.Empty)
            : slot.OriginalUpdate is { } update ? slot.ApprovalSettledDispatch == Guid.Empty &&
                (update.InvocationDispatch == Guid.Empty
                    ? update.SettledDispatch == Guid.Empty && update.Disposition == PrivateConnectionUpdateDisposition.None &&
                        (slot.Connection is null || slot.Connection is
                        { SelectedAttempted: false, ActiveDispatch: var uninvoked } && uninvoked == Guid.Empty)
                    : update.InvocationDispatch == update.SettledDispatch && slot.Connection is
                    {
                        CreateAttempted: true, InvocationTerminated: true, Borrowed: false, CleanupOnly: false,
                        DeleteAttempted: false, ActiveDispatch: var settled
                    } childUpdate && settled == Guid.Empty &&
                        (update.Disposition == PrivateConnectionUpdateDisposition.InvalidInput
                            ? !childUpdate.SelectedAttempted
                            : childUpdate.SelectedAttempted && update.Disposition is
                                PrivateConnectionUpdateDisposition.Updated or PrivateConnectionUpdateDisposition.Denied))
            : (slot.Connection is null && slot.ApprovalSettledDispatch == Guid.Empty || slot.Connection is
            {
                CreateAttempted: true, Borrowed: false, CleanupOnly: false, DeleteAttempted: false,
                InvocationTerminated: true, ActiveDispatch: var active
            } child && active == Guid.Empty &&
                (!child.SelectedAttempted && slot.ApprovalSettledDispatch == Guid.Empty ||
                    child.SelectedAttempted && slot.ApprovalSettledDispatch != Guid.Empty &&
                    (Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                        Selector.Variant == "operation.UpdatePrivateConnection" && Selector.Case == "selected-contract" ||
                        VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(Selector) &&
                        StatusPrivateConnectionUpdateRoot(this) ||
                        VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(Selector) &&
                        StatusPrivateConnectionUpdateIndependentRoot(this)) &&
                    child.Id.StartsWith(slot.Declaration.VaultId + "/privateEndpointConnections/", StringComparison.Ordinal) &&
                child.Id[(slot.Declaration.VaultId.Length + "/privateEndpointConnections/".Length)..] is
                { Length: > 0 } name && !name.Contains('/')))));
        internal bool PrivateEndpointCleanupEligible => Closing && Idle && PrivateConnectionCleanupEligible;
        internal bool Released => Closing && Idle && PrivateEndpointAbsent &&
            Resources.All(r => r.Borrowed || r.Absent && r.ActiveDispatch == Guid.Empty);
        public override string ToString() => "[RoleFixtureSnapshot]";
    }
    // The frame sequence is an opaque local revision, not a time/freshness claim.
    internal sealed class AbsenceRevision(long sequence)
    {
        internal bool Matches(Snapshot snapshot) => snapshot.Revision == sequence;
        internal bool MatchesEndpointDrain(Snapshot snapshot, Resource endpoint) =>
            snapshot.Revision == sequence && !endpoint.InvocationTerminated ||
            snapshot.Revision == sequence + 1 && endpoint.InvocationTerminated;
        public override string ToString() => "[PrivateEndpointAbsenceRevision]";
    }
    private sealed record Frame(long Sequence, string Previous, Snapshot State);

    internal sealed class StatusPendingPurgeHistoryException : InvalidOperationException
    {
        internal StatusPendingPurgeHistoryException() : base("fixture-journal-unavailable") { }
    }
    private readonly HashSet<(string Owner, Guid Nonce)> invalidStatusPendingPurgeHistory = [];
    private readonly Dictionary<(string Owner, Guid Nonce), (long Sequence, string Digest)> observedStatusPendingPurgeHistory = [];
    internal sealed class StatusPendingPurgeIndependentHistoryException : InvalidOperationException
    {
        internal StatusPendingPurgeIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }
    private readonly HashSet<(string Owner, Guid Nonce)> invalidStatusPendingPurgeIndependentHistory = [];
    private readonly Dictionary<(string Owner, Guid Nonce), (long Sequence, string Digest)> observedStatusPendingPurgeIndependentHistory = [];
    private (string Owner, FixtureSelector Selector, long Revision)? pendingIndependentFlushFailure;

    internal void FailStatusPendingPurgeIndependentFlushOnce(string owner, FixtureSelector selector, long revision)
    {
        Require(owner is { Length: > 0 and <= 128 } && VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) &&
            selector.Nonce != Guid.Empty && new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }
                .All(s => !string.IsNullOrWhiteSpace(s) && s.Length <= 1024) && revision > 0);
        lock (gate)
        {
            Require(pendingIndependentFlushFailure is null);
            pendingIndependentFlushFailure = (owner, selector with { }, revision);
        }
    }
    internal sealed class StatusPendingPurgeCancellationHistoryException : InvalidOperationException
    {
        internal StatusPendingPurgeCancellationHistoryException() : base("fixture-journal-unavailable") { }
    }
    private readonly HashSet<(string Owner, Guid Nonce)> invalidStatusPendingPurgeCancellationHistory = [];
    private readonly Dictionary<(string Owner, Guid Nonce), (long Sequence, string Digest)> observedStatusPendingPurgeCancellationHistory = [];
    private (string Owner, FixtureSelector Selector, long Revision)? pendingCancellationFlushFailure;

    private bool pendingCancellationFlushFailureArmed;

    internal void FailStatusPendingPurgeCancellationFlushOnce(string owner, FixtureSelector selector, long revision)
    {
        Require(owner is { Length: > 0 and <= 128 } && VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) &&
            selector.Nonce != Guid.Empty && new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }
                .All(s => !string.IsNullOrWhiteSpace(s) && s.Length <= 1024) && revision > 0);
        lock (gate)
        {
            Require(!pendingCancellationFlushFailureArmed);
            pendingCancellationFlushFailureArmed = true;
            pendingCancellationFlushFailure = (owner, selector with { }, revision);
        }
    }
    private static bool PendingSelector(FixtureSelector selector) =>
        VaultFixtureProvisioner.StatusPendingPurgeSelector(selector) || VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) ||
        VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector);
    private static bool PendingRoot(Snapshot state) => StatusPendingPurgeRoot(state) || StatusPendingPurgeIndependentRoot(state) ||
        StatusPendingPurgeCancellationRoot(state);

    internal Snapshot PrepareStatusPendingPurge(string owner, FixtureSelector selector,
        VaultFixtureProvisioner.StatusPendingPurgePreparation preparation)
    {
        Require(preparation is not null);
        return PreparePending(owner, selector, preparation.ValidateInitial, preparation.AcceptPostimage, () => preparation.Postimage, false);
    }
    internal Snapshot PrepareStatusPendingPurgeIndependent(string owner, FixtureSelector selector,
        VaultFixtureProvisioner.StatusPendingPurgeIndependentPreparation preparation)
    {
        Require(preparation is not null);
        return PreparePending(owner, selector, preparation.ValidateInitial, preparation.AcceptPostimage, () => preparation.Postimage, true);
    }
    internal Snapshot PrepareStatusPendingPurgeCancellation(string owner, FixtureSelector selector,
        VaultFixtureProvisioner.StatusPendingPurgeCancellationPreparation preparation)
    {
        Require(preparation is not null);
        return PreparePending(owner, selector, preparation.ValidateInitial, preparation.AcceptPostimage, () => preparation.Postimage, false, cancellation: true);
    }
    private Snapshot PreparePending(string owner, FixtureSelector selector,
        Func<RoleFixtureJournal, string, FixtureSelector, bool> initial,
        Func<RoleFixtureJournal, Snapshot, bool> accept, Func<Snapshot> image, bool independent, bool cancellation = false) =>
        Change(owner, selector, state =>
        {
            RequirePendingHistory(owner, selector);
            Require(cancellation ? VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) :
                independent ? VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) :
                VaultFixtureProvisioner.StatusPendingPurgeSelector(selector));
            if (state is not null)
            {
                Require(accept(this, state));
                return state;
            }
            Require(initial(this, owner, selector));
            var prepared = image();
            var maximum = prepared with
            {
                Resources = prepared.Resources.Select(r => r with { ActiveDispatch = prepared.LeaseId }).ToArray(),
                PurgeDeletedVault = prepared.PurgeDeletedVault! with
                {
                    InvocationDispatch = prepared.LeaseId, SettledDispatch = prepared.LeaseId,
                    PendingStage = StatusPendingPurgeStage.OriginalAdmitted,
                    Disposition = PurgeDeletedVaultDisposition.Purged
                }
            };
            Require(JsonSerializer.SerializeToUtf8Bytes(new Frame(long.MaxValue, new string('F', 64), maximum),
                ManagementAdmission.Json).Length <= MaximumFrame);
            return prepared;
        }, statusPending: !independent && !cancellation, statusPendingIndependent: independent, statusPendingCancellation: cancellation);

    internal Snapshot BeginStatusPendingPurgeFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeFixtureAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared);
    internal Snapshot EndStatusPendingPurgeFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeFixtureDrain drain) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared, drainOnly: drain.DrainOnly);
    internal Snapshot BeginStatusPendingPurgeInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPendingPurgeAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.OriginalAdmitted);
    internal Snapshot EndStatusPendingPurgeStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeStartDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.OriginalAdmitted, StatusPendingPurgeStage.OriginalDrained);
    internal Snapshot AdmitStatusPendingPurgeRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeReadAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.OriginalDrained, StatusPendingPurgeStage.SelectedAdmitted);
    internal Snapshot CompleteStatusPendingPurgeRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeObservation observation) =>
        PendingChange(owner, selector, leaseId, dispatch, observation.Validate, observation.AcceptPostimage,
            () => observation.Postimage, StatusPendingPurgeStage.SelectedAdmitted, StatusPendingPurgeStage.PendingObserved);
    internal Snapshot AdmitStatusPendingPurgeCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCleanupAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.PendingObserved, StatusPendingPurgeStage.CleanupAdmitted);
    internal Snapshot CompleteStatusPendingPurgeCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCleanupCompletion completion) =>
        PendingChange(owner, selector, leaseId, dispatch, completion.Validate, completion.AcceptPostimage,
            () => completion.Postimage, StatusPendingPurgeStage.CleanupAdmitted, StatusPendingPurgeStage.CleanupTerminal);
    internal Snapshot EndStatusPendingPurgeInvocation(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeInvocationDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, null, null, drainOnly: true);
    internal Snapshot RecordStatusPendingPurgeAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeAbsence absence) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, absence.Validate, absence.AcceptPostimage,
            () => absence.Postimage, null, null);

    internal Snapshot BeginStatusPendingPurgeIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeIndependentFixtureAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared, independent: true);
    internal Snapshot EndStatusPendingPurgeIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeIndependentFixtureDrain drain) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared, drainOnly: drain.DrainOnly, independent: true);
    internal Snapshot BeginStatusPendingPurgeIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.OriginalAdmitted, independent: true);
    internal Snapshot EndStatusPendingPurgeIndependentStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentStartDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.OriginalAdmitted, StatusPendingPurgeStage.OriginalDrained, independent: true);
    internal Snapshot AdmitStatusPendingPurgeIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentReadAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.OriginalDrained, StatusPendingPurgeStage.SelectedAdmitted, independent: true);
    internal Snapshot CompleteStatusPendingPurgeIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentObservation observation) =>
        PendingChange(owner, selector, leaseId, dispatch, observation.Validate, observation.AcceptPostimage,
            () => observation.Postimage, StatusPendingPurgeStage.SelectedAdmitted, StatusPendingPurgeStage.PendingObserved, independent: true);
    internal Snapshot AdmitStatusPendingPurgeIndependentCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentCleanupAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.PendingObserved, StatusPendingPurgeStage.CleanupAdmitted, independent: true);
    internal Snapshot CompleteStatusPendingPurgeIndependentCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentCleanupCompletion completion) =>
        PendingChange(owner, selector, leaseId, dispatch, completion.Validate, completion.AcceptPostimage,
            () => completion.Postimage, StatusPendingPurgeStage.CleanupAdmitted, StatusPendingPurgeStage.CleanupTerminal, independent: true);
    internal Snapshot EndStatusPendingPurgeIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeIndependentInvocationDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, null, null, drainOnly: true, independent: true);
    internal Snapshot RecordStatusPendingPurgeIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeIndependentAbsence absence) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, absence.Validate, absence.AcceptPostimage,
            () => absence.Postimage, null, null, independent: true);

    internal Snapshot BeginStatusPendingPurgeCancellationFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeCancellationFixtureAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared, cancellation: true);
    internal Snapshot EndStatusPendingPurgeCancellationFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeCancellationFixtureDrain drain) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.Prepared, drainOnly: drain.DrainOnly, cancellation: true);
    internal Snapshot BeginStatusPendingPurgeCancellationInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationAdmission admission) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.Prepared, StatusPendingPurgeStage.OriginalAdmitted, cancellation: true);
    internal Snapshot EndStatusPendingPurgeCancellationStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationStartDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, StatusPendingPurgeStage.OriginalAdmitted, StatusPendingPurgeStage.OriginalDrained, cancellation: true);
    internal Snapshot AdmitStatusPendingPurgeCancellationRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationReadAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.OriginalDrained, StatusPendingPurgeStage.SelectedAdmitted, cancellation: true);
    internal Snapshot CompleteStatusPendingPurgeCancellationRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationObservation observation) =>
        PendingChange(owner, selector, leaseId, dispatch, observation.Validate, observation.AcceptPostimage,
            () => observation.Postimage, StatusPendingPurgeStage.SelectedAdmitted, StatusPendingPurgeStage.PendingObserved, cancellation: true);
    internal Snapshot AdmitStatusPendingPurgeCancellationCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationCleanupAdmission admission) =>
        PendingChange(owner, selector, leaseId, dispatch, admission.Validate, admission.AcceptPostimage,
            () => admission.Postimage, StatusPendingPurgeStage.PendingObserved, StatusPendingPurgeStage.CleanupAdmitted, cancellation: true);
    internal Snapshot CompleteStatusPendingPurgeCancellationCleanupRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationCleanupCompletion completion) =>
        PendingChange(owner, selector, leaseId, dispatch, completion.Validate, completion.AcceptPostimage,
            () => completion.Postimage, StatusPendingPurgeStage.CleanupAdmitted, StatusPendingPurgeStage.CleanupTerminal, cancellation: true);
    internal Snapshot EndStatusPendingPurgeCancellationInvocation(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPendingPurgeCancellationInvocationDrain drain) =>
        PendingChange(owner, selector, leaseId, dispatch, drain.Validate, drain.AcceptPostimage,
            () => drain.Postimage, null, null, drainOnly: true, cancellation: true);
    internal Snapshot RecordStatusPendingPurgeCancellationAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPendingPurgeCancellationAbsence absence) =>
        PendingChange(owner, selector, leaseId, Guid.Empty, absence.Validate, absence.AcceptPostimage,
            () => absence.Postimage, null, null, cancellation: true);

    private Snapshot PendingChange(string owner, FixtureSelector selector, Guid lease, Guid dispatch,
        Func<RoleFixtureJournal, Snapshot, bool> validate, Func<RoleFixtureJournal, Snapshot, bool> accept,
        Func<Snapshot> image, StatusPendingPurgeStage? from, StatusPendingPurgeStage? to, bool drainOnly = false, bool independent = false,
        bool cancellation = false) =>
        Change(owner, selector, state =>
        {
            if (!drainOnly) RequirePendingHistory(owner, selector);
            Require((cancellation ? VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) :
                independent ? VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) :
                VaultFixtureProvisioner.StatusPendingPurgeSelector(selector)) && state is not null &&
                (cancellation ? StatusPendingPurgeCancellationRoot(state) :
                    independent ? StatusPendingPurgeIndependentRoot(state) : StatusPendingPurgeRoot(state)) &&
                lease != Guid.Empty && state.LeaseId == lease &&
                (dispatch == Guid.Empty || state.PurgeDeletedVault!.InvocationDispatch == dispatch));
            if (accept(this, state)) return state;
            Require(validate(this, state) && (from is null || state.PurgeDeletedVault!.PendingStage == from));
            var next = image();
            Require(to is null || next.PurgeDeletedVault!.PendingStage == to);
            if (drainOnly)
                Require(SameStatusPendingPurgeSnapshot(next with { Resources = state.Resources, Revision = state.Revision }, state) &&
                    next.Resources.Zip(state.Resources).All(pair =>
                        pair.First == pair.Second || pair.First == pair.Second with { InvocationTerminated = true }));
            return next;
        }, statusPending: !independent && !cancellation, statusPendingIndependent: independent, statusPendingCancellation: cancellation);

    private void RequirePendingHistory(string owner, FixtureSelector selector)
    {
        if (VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector))
        {
            if (invalidStatusPendingPurgeCancellationHistory.Contains((owner, selector.Nonce)))
                throw new StatusPendingPurgeCancellationHistoryException();
        }
        else if (VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector))
        {
            if (invalidStatusPendingPurgeIndependentHistory.Contains((owner, selector.Nonce)))
                throw new StatusPendingPurgeIndependentHistoryException();
        }
        else if (invalidStatusPendingPurgeHistory.Contains((owner, selector.Nonce)))
            throw new StatusPendingPurgeHistoryException();
    }

    internal static bool SameStatusPendingPurgeSnapshot(Snapshot expected, Snapshot actual) =>
        expected.Revision == actual.Revision &&
        JsonSerializer.SerializeToUtf8Bytes(expected, ManagementAdmission.Json).AsSpan()
            .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(actual, ManagementAdmission.Json));

    internal static Snapshot CopyStatusPendingPurgeSnapshot(Snapshot state) => state with
    {
        Resources = state.Resources.ToArray(),
        PurgeDeletedVault = state.PurgeDeletedVault is { } purge
            ? purge with { Baseline = CopySettings(purge.Baseline) } : null
    };

    internal static bool StatusPendingPurgeRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPendingPurgeSelector(state.Selector) && PendingShape(state);
    internal static bool StatusPendingPurgeIndependentRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(state.Selector) && PendingShape(state);
    internal static bool StatusPendingPurgeCancellationRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(state.Selector) && PendingShape(state);
    private static bool PendingShape(Snapshot state)
    {
        if (state.LeaseId == Guid.Empty ||
            state.PurgeDeletedVault is not { } p || p.PendingStage == StatusPendingPurgeStage.None ||
            !Enum.IsDefined(p.PendingStage) || state.PrivateEndpoint is not null || state.Settings is not null ||
            state.DeleteVault is not null || state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.StatusSucceededDeleteVault is not null || state.NotificationAbsentCreate is not null ||
            state.StatusVaultRecoverCancellationBaseline is not null || state.StatusVaultUpdateCancellationBaseline is not null ||
            state.Resources is not { Length: 3 } || state.Resources.Any(r => r is null || r.Borrowed) ||
            p.Baseline is not { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 })
            return false;
        string[] path = p.VaultId.Split('/');
        if (path.Length != 9 || path[0] != "" || path[1] != "subscriptions" ||
            !Guid.TryParseExact(path[2], "D", out var subscription) || subscription == Guid.Empty ||
            path[3] != "resourceGroups" || path[4].Length is < 1 or > 90 ||
            !path[4].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') ||
            path[5] != "providers" || path[6] != "Microsoft.KeyVault" || path[7] != "vaults" ||
            path[8].Length != 24 || !path[8].StartsWith("skv", StringComparison.Ordinal) ||
            !path[8][3..].All(char.IsAsciiHexDigit) || p.Baseline.Location is not { Length: >= 1 and <= 50 } ||
            !p.Baseline.Location.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') ||
            p.DeletedVaultId != $"/subscriptions/{subscription:D}/providers/Microsoft.KeyVault/locations/{p.Baseline.Location}/deletedVaults/{path[8]}")
            return false;
        return state.Resources[0].Id == p.VaultId && !state.Resources[0].CleanupOnly &&
            state.Resources[1].Id == p.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary && state.Resources[1].CleanupOnly &&
            state.Resources[2].Id == p.DeletedVaultId && !state.Resources[2].CleanupOnly;
    }

    private static void ValidateStatusPendingPurgeState(Snapshot state, Snapshot? previous)
    {
        if (!PendingSelector(state.Selector))
        {
            Require(state.PurgeDeletedVault is null || state.PurgeDeletedVault.PendingStage == StatusPendingPurgeStage.None);
            return;
        }
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && state.PurgeDeletedVault is null &&
                state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
                state.CreateOrUpdateVault is null && state.RecoverVault is null && state.NotificationAbsentCreate is null &&
                state.StatusSucceededDeleteVault is null && state.StatusVaultRecoverCancellationBaseline is null &&
                state.StatusVaultUpdateCancellationBaseline is null && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(PendingRoot(state));
        var p = state.PurgeDeletedVault!;
        _ = p.Baseline.Build();
        var a = state.Resources[0];
        var c = state.Resources[1];
        var d = state.Resources[2];
        Require(!a.SelectedAttempted && !a.DeleteAttempted &&
            !c.CreateAttempted && !c.DeleteAttempted && !c.SelectedAttempted &&
            !c.InvocationTerminated && c.ActiveDispatch == Guid.Empty &&
            state.Resources.All(r => r.Absent == a.Absent) &&
            (!a.Absent || state.Closing && state.Idle && PendingAbsenceEligible(state)));
        if (p.PendingStage == StatusPendingPurgeStage.Prepared)
            Require(p.InvocationDispatch == Guid.Empty && p.SettledDispatch == Guid.Empty &&
                p.Disposition == PurgeDeletedVaultDisposition.None && !d.SelectedAttempted &&
                (!d.CreateAttempted || a.CreateAttempted && a.InvocationTerminated && a.ActiveDispatch == Guid.Empty) &&
                (!d.DeleteAttempted || state.Closing && d.CreateAttempted) &&
                (a.CreateAttempted || !a.InvocationTerminated && a.ActiveDispatch == Guid.Empty) &&
                (d.CreateAttempted || !d.InvocationTerminated && d.ActiveDispatch == Guid.Empty));
        else
            Require(a.CreateAttempted && a.InvocationTerminated && a.ActiveDispatch == Guid.Empty &&
                d.CreateAttempted && !d.DeleteAttempted && d.SelectedAttempted && p.InvocationDispatch != Guid.Empty &&
                (p.PendingStage == StatusPendingPurgeStage.CleanupTerminal
                    ? state.Closing && p.SettledDispatch == p.InvocationDispatch &&
                        p.Disposition == PurgeDeletedVaultDisposition.Purged && d.ActiveDispatch == Guid.Empty && d.InvocationTerminated
                    : p.SettledDispatch == Guid.Empty && p.Disposition == PurgeDeletedVaultDisposition.None &&
                        d.ActiveDispatch == p.InvocationDispatch && !a.Absent) &&
                (p.PendingStage != StatusPendingPurgeStage.CleanupAdmitted || state.Closing));
        if (previous is null)
        {
            Require(!state.Closing && p.PendingStage == StatusPendingPurgeStage.Prepared &&
                state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                    !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(PendingRoot(previous));
        bool Same(Snapshot candidate) => SameStatusPendingPurgeSnapshot(
            candidate with { Revision = state.Revision }, state);
        if (!previous.Closing && Same(previous with { Closing = true })) return;
        if (previous.Closing && previous.Resources.Any(r => r.Absent) &&
            Same(previous with { Resources = previous.Resources.Select(r => r with { Absent = false }).ToArray() })) return;
        if (previous.Closing && previous.Idle && PendingAbsenceEligible(previous) &&
            !previous.Resources.Any(r => r.Absent) &&
            Same(previous with { Resources = previous.Resources.Select(r => r with { Absent = true }).ToArray() })) return;
        var old = previous.PurgeDeletedVault!;
        var row = previous.Resources[2];
        Snapshot Delta(StatusPendingPurgeStage stage, bool terminated, Guid active, Guid invocation, Guid settled,
            PurgeDeletedVaultDisposition disposition) => previous with
            {
                Resources = [previous.Resources[0], previous.Resources[1],
                    row with { ActiveDispatch = active, InvocationTerminated = terminated,
                        SelectedAttempted = invocation != Guid.Empty }],
                PurgeDeletedVault = old with { PendingStage = stage, InvocationDispatch = invocation,
                    SettledDispatch = settled, Disposition = disposition }
            };
        if (old.PendingStage == StatusPendingPurgeStage.Prepared)
        {
            if (!previous.Closing && previous.Idle && previous.Resources[0] is
                { CreateAttempted: true, InvocationTerminated: true } &&
                row is { CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false } &&
                !previous.Resources.Any(r => r.Absent) && p.InvocationDispatch != Guid.Empty &&
                Same(Delta(StatusPendingPurgeStage.OriginalAdmitted, false, p.InvocationDispatch,
                    p.InvocationDispatch, Guid.Empty, PurgeDeletedVaultDisposition.None))) return;
            for (int index = 0; index < 3; index += 2)
            {
                var priorRow = previous.Resources[index];
                var nextRow = state.Resources[index];
                bool cleanup = previous.Closing;
                bool eligible = !cleanup ? !priorRow.CreateAttempted &&
                    (index == 0 || previous.Resources[0] is { CreateAttempted: true, InvocationTerminated: true,
                        ActiveDispatch: var first } && first == Guid.Empty)
                    : index == 2 && priorRow is { CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false } &&
                        previous.Resources[0] is { CreateAttempted: true, InvocationTerminated: true };
                if (previous.Idle && eligible && nextRow.ActiveDispatch != Guid.Empty)
                {
                    var rows = previous.Resources.Select(r => r with { Absent = false }).ToArray();
                    rows[index] = priorRow with { CreateAttempted = priorRow.CreateAttempted || !cleanup,
                        DeleteAttempted = cleanup, ActiveDispatch = nextRow.ActiveDispatch, InvocationTerminated = false, Absent = false };
                    if (Same(previous with { Resources = rows })) return;
                }
                if (priorRow.ActiveDispatch != Guid.Empty && !priorRow.InvocationTerminated)
                {
                    var rows = previous.Resources.ToArray();
                    rows[index] = priorRow with { InvocationTerminated = true };
                    if (Same(previous with { Resources = rows })) return;
                    rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
                    if (Same(previous with { Resources = rows })) return;
                }
            }
        }
        else if (row.ActiveDispatch == old.InvocationDispatch)
        {
            if (!row.InvocationTerminated && old.PendingStage is StatusPendingPurgeStage.OriginalAdmitted or
                StatusPendingPurgeStage.SelectedAdmitted or StatusPendingPurgeStage.CleanupAdmitted)
            {
                if (Same(Delta(old.PendingStage, true, row.ActiveDispatch, old.InvocationDispatch,
                    old.SettledDispatch, old.Disposition))) return;
                if (!previous.Closing && old.PendingStage == StatusPendingPurgeStage.OriginalAdmitted &&
                    Same(Delta(StatusPendingPurgeStage.OriginalDrained, true, row.ActiveDispatch,
                        old.InvocationDispatch, Guid.Empty, old.Disposition))) return;
                if (!previous.Closing && old.PendingStage == StatusPendingPurgeStage.SelectedAdmitted &&
                    Same(Delta(StatusPendingPurgeStage.PendingObserved, true, row.ActiveDispatch,
                        old.InvocationDispatch, Guid.Empty, old.Disposition))) return;
                if (previous.Closing && old.PendingStage == StatusPendingPurgeStage.CleanupAdmitted &&
                    Same(Delta(StatusPendingPurgeStage.CleanupTerminal, true, Guid.Empty,
                        old.InvocationDispatch, old.InvocationDispatch, PurgeDeletedVaultDisposition.Purged))) return;
            }
            if (row.InvocationTerminated && ((!previous.Closing && old.PendingStage == StatusPendingPurgeStage.OriginalDrained) ||
                (previous.Closing && old.PendingStage == StatusPendingPurgeStage.PendingObserved)) &&
                Same(Delta(previous.Closing ? StatusPendingPurgeStage.CleanupAdmitted : StatusPendingPurgeStage.SelectedAdmitted,
                    false, row.ActiveDispatch, old.InvocationDispatch, Guid.Empty, old.Disposition))) return;
        }
        throw Failure();
    }

    private static bool PendingAbsenceEligible(Snapshot state) =>
        state.PurgeDeletedVault is { PendingStage: StatusPendingPurgeStage.CleanupTerminal } ||
        state.PurgeDeletedVault is { PendingStage: StatusPendingPurgeStage.Prepared, InvocationDispatch: var dispatch } &&
        dispatch == Guid.Empty && state.Idle && (!state.Resources.Any(r => r.CreateAttempted) ||
            state.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
            state.Resources[2] is { CreateAttempted: true, InvocationTerminated: true });

    private static void ValidateStatusPendingPurgeFrame(byte[] payload, FixtureSelector requested)
    {
        using var document = JsonDocument.Parse(payload);
        var frame = document.RootElement;
        if (!PendingSelector(requested))
        {
            if (frame.ValueKind == JsonValueKind.Object)
                foreach (var state in frame.EnumerateObject().Where(p => p.Name.Equals("state", StringComparison.OrdinalIgnoreCase)))
                    if (state.Value.ValueKind == JsonValueKind.Object)
                        foreach (var purge in state.Value.EnumerateObject().Where(p => p.Name.Equals("purgeDeletedVault", StringComparison.OrdinalIgnoreCase)))
                            if (purge.Value.ValueKind == JsonValueKind.Object)
                                Require(!purge.Value.EnumerateObject().Any(p => p.Name.Equals("pendingStage", StringComparison.OrdinalIgnoreCase)));
            return;
        }
        Object(frame, ["sequence", "previous", "state"]);
        Require(frame.GetProperty("sequence").TryGetInt64(out long sequence) && sequence > 0);
        String(frame.GetProperty("previous"));
        var s = frame.GetProperty("state");
        string[] nulls = ["privateEndpoint", "settings", "deleteVault", "createOrUpdateVault", "recoverVault",
            "statusVaultRecoverCancellationBaseline", "statusVaultUpdateCancellationBaseline", "notificationAbsentCreate", "statusSucceededDeleteVault"];
        Object(s, ["owner", "selector", "leaseId", "closing", "resources"], ["purgeDeletedVault", .. nulls]);
        foreach (var name in nulls) Require(!s.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null);
        String(s.GetProperty("owner")); GuidValue(s.GetProperty("leaseId")); Boolean(s.GetProperty("closing"));
        var selector = s.GetProperty("selector");
        Object(selector, ["scope", "operation", "variant", "case", "nonce"]);
        foreach (var name in new[] { "scope", "operation", "variant", "case" }) String(selector.GetProperty(name));
        GuidValue(selector.GetProperty("nonce"));
        Require(selector.GetProperty("scope").GetString() == requested.Scope &&
            selector.GetProperty("operation").GetString() == requested.Operation &&
            selector.GetProperty("variant").GetString() == requested.Variant &&
            selector.GetProperty("case").GetString() == requested.Case &&
            selector.GetProperty("nonce").GetGuid() == requested.Nonce);
        var rows = s.GetProperty("resources");
        Require(rows.ValueKind == JsonValueKind.Array);
        foreach (var row in rows.EnumerateArray())
        {
            Object(row, ["id", "borrowed", "createAttempted", "deleteAttempted", "activeDispatch", "absent",
                "cleanupOnly", "invocationTerminated", "selectedAttempted"]);
            String(row.GetProperty("id")); GuidValue(row.GetProperty("activeDispatch"));
            foreach (var name in new[] { "borrowed", "createAttempted", "deleteAttempted", "absent", "cleanupOnly", "invocationTerminated", "selectedAttempted" })
                Boolean(row.GetProperty(name));
        }
        if (rows.GetArrayLength() == 0)
        {
            Require(!s.TryGetProperty("purgeDeletedVault", out var empty) || empty.ValueKind == JsonValueKind.Null);
            return;
        }
        Require(s.TryGetProperty("purgeDeletedVault", out var p));
        Object(p, ["vaultId", "deletedVaultId", "baseline", "invocationDispatch", "settledDispatch", "disposition", "pendingStage"]);
        String(p.GetProperty("vaultId")); String(p.GetProperty("deletedVaultId"));
        GuidValue(p.GetProperty("invocationDispatch")); GuidValue(p.GetProperty("settledDispatch"));
        Require(p.GetProperty("disposition").ValueKind == JsonValueKind.String &&
            p.GetProperty("disposition").GetString() is "None" or "Purged");
        Require(p.GetProperty("pendingStage").ValueKind == JsonValueKind.String &&
            p.GetProperty("pendingStage").GetString() is "Prepared" or "OriginalAdmitted" or "OriginalDrained" or
                "SelectedAdmitted" or "PendingObserved" or "CleanupAdmitted" or "CleanupTerminal");
        var q = p.GetProperty("baseline");
        Object(q, ["location", "tenantId", "sku", "rbac", "purgeProtection", "retentionDays", "publicNetworkAccess", "policies"]);
        String(q.GetProperty("location")); GuidValue(q.GetProperty("tenantId"));
        Require(q.GetProperty("sku").ValueKind == JsonValueKind.String && q.GetProperty("sku").GetString() is "Standard" or "Premium");
        Boolean(q.GetProperty("rbac")); Boolean(q.GetProperty("purgeProtection")); Boolean(q.GetProperty("publicNetworkAccess"));
        Require(q.GetProperty("retentionDays").TryGetInt32(out _) && q.GetProperty("policies").ValueKind == JsonValueKind.Array &&
            q.GetProperty("policies").GetArrayLength() == 0);

        static void Object(JsonElement node, string[] required, string[]? optional = null)
        {
            Require(node.ValueKind == JsonValueKind.Object);
            var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in node.EnumerateObject())
                Require(keys.Add(p.Name) && (required.Contains(p.Name, StringComparer.Ordinal) ||
                    optional?.Contains(p.Name, StringComparer.Ordinal) == true));
            Require(required.All(name => node.TryGetProperty(name, out _)));
        }
        static void String(JsonElement node) => Require(node.ValueKind == JsonValueKind.String && node.GetString() is not null);
        static void GuidValue(JsonElement node) => Require(node.ValueKind == JsonValueKind.String &&
            Guid.TryParseExact(node.GetString(), "D", out _));
        static void Boolean(JsonElement node) => Require(node.ValueKind is JsonValueKind.True or JsonValueKind.False);
    }

    internal Snapshot PrepareStatusSucceededDeleteVault(string owner, FixtureSelector selector, Resource[] resources,
        VaultAdministrationEffects.Configuration baseline)
    {
        Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector) && resources is { Length: 3 } &&
            resources.All(r => !r.Borrowed && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) &&
            resources.Count(r => !r.CleanupOnly) == 1);
        var copied = CopySettings(baseline);
        var rows = resources.ToArray();
        var vault = rows.Single(r => !r.CleanupOnly).Id;
        var deleted = rows.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)).Id;
        return Change(owner, selector, state =>
        {
            Require(state is null);
            return new(owner, selector, Guid.NewGuid(), false, rows,
                StatusSucceededDeleteVault: new(1, ManagementMutation.DeleteVault, vault, deleted, copied));
        });
    }

    internal Guid BeginStatusSucceededDeleteVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                StatusSucceededDeleteVaultRoot(state) && state.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.ToArray();
            int index = Index(rows, typed.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                DeleteAttempted: false, Absent: false
            } &&
                rows.Where(r => r.Id != typed.VaultId).All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                    !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            rows[index] = rows[index] with { SelectedAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = typed with
                { InvocationDispatch = dispatch, BaselineSha256 = admission.BaselineSha256 }
            };
        });
        return dispatch;
    }

    internal void AdmitStatusSucceededDeleteVaultRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusSucceededDeleteVaultRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && completion is not null && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(!rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = state.StatusSucceededDeleteVault with { SettledDispatch = dispatch }
            };
        });

    private static void RequireStatusSucceededDispatch([NotNull] Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && StatusSucceededDeleteVaultRoot(state) && state.LeaseId == leaseId &&
            leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.StatusSucceededDeleteVault!.InvocationDispatch == dispatch &&
            state.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
            state.Resources.Single(r => r.Id == state.StatusSucceededDeleteVault.VaultId) is
            { SelectedAttempted: true, DeleteAttempted: false, ActiveDispatch: var active } && active == dispatch);

    internal Guid BeginStatusSucceededDeleteVaultCleanupDispatch(string owner, FixtureSelector selector, Guid leaseId,
        string resourceId, VaultFixtureProvisioner.StatusSucceededDeleteVaultCleanupAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && state.Closing && state.Idle &&
                StatusSucceededDeleteVaultRoot(state) && admission is not null && admission.ResourceId == resourceId &&
                admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.Select(r => r with { Absent = false }).ToArray();
            int index = Index(rows, resourceId);
            Require(!rows[index].DeleteAttempted && rows[index].ActiveDispatch == Guid.Empty &&
                (resourceId == typed.VaultId ? typed.InvocationDispatch == Guid.Empty && rows[index].CreateAttempted :
                    resourceId == typed.DeletedId && (typed.SettledDispatch != Guid.Empty ||
                        rows.Single(r => r.Id == typed.VaultId) is { DeleteAttempted: true, InvocationTerminated: true })));
            rows[index] = rows[index] with { DeleteAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal Snapshot PrepareStatusSucceededDeleteVaultIndependent(string owner, FixtureSelector selector, Resource[] resources,
        VaultAdministrationEffects.Configuration baseline)
    {
        Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector) && resources is { Length: 3 } &&
            resources.All(r => !r.Borrowed && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) &&
            resources.Count(r => !r.CleanupOnly) == 1);
        var copied = CopySettings(baseline);
        var rows = resources.ToArray();
        var vault = rows.Single(r => !r.CleanupOnly).Id;
        var deleted = rows.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)).Id;
        return Change(owner, selector, state =>
        {
            Require(state is null);
            return new(owner, selector, Guid.NewGuid(), false, rows,
                StatusSucceededDeleteVault: new(1, ManagementMutation.DeleteVault, vault, deleted, copied));
        });
    }

    internal Guid BeginStatusSucceededDeleteVaultIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultIndependentAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                StatusSucceededDeleteVaultIndependentRoot(state) && state.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.ToArray();
            int index = Index(rows, typed.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                DeleteAttempted: false, Absent: false
            } &&
                rows.Where(r => r.Id != typed.VaultId).All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                    !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            rows[index] = rows[index] with { SelectedAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = typed with
                { InvocationDispatch = dispatch, BaselineSha256 = admission.BaselineSha256 }
            };
        });
        return dispatch;
    }

    internal Snapshot AdmitStatusSucceededDeleteVaultIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededIndependentDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusSucceededDeleteVaultIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededIndependentDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && completion is not null && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(!rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = state.StatusSucceededDeleteVault with { SettledDispatch = dispatch }
            };
        });

    private static void RequireStatusSucceededIndependentDispatch([NotNull] Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && StatusSucceededDeleteVaultIndependentRoot(state) && state.LeaseId == leaseId &&
            leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.StatusSucceededDeleteVault!.InvocationDispatch == dispatch &&
            state.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
            state.Resources.Single(r => r.Id == state.StatusSucceededDeleteVault.VaultId) is
            { SelectedAttempted: true, DeleteAttempted: false, ActiveDispatch: var active } && active == dispatch);

    internal Guid BeginStatusSucceededDeleteVaultIndependentCleanupDispatch(string owner, FixtureSelector selector, Guid leaseId,
        string resourceId, VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentCleanupAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && state.Closing && state.Idle &&
                StatusSucceededDeleteVaultIndependentRoot(state) && admission is not null && admission.ResourceId == resourceId &&
                admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.Select(r => r with { Absent = false }).ToArray();
            int index = Index(rows, resourceId);
            Require(!rows[index].DeleteAttempted && rows[index].ActiveDispatch == Guid.Empty &&
                (resourceId == typed.VaultId ? typed.InvocationDispatch == Guid.Empty && rows[index].CreateAttempted :
                    resourceId == typed.DeletedId && (typed.SettledDispatch != Guid.Empty ||
                        rows.Single(r => r.Id == typed.VaultId) is { DeleteAttempted: true, InvocationTerminated: true })));
            rows[index] = rows[index] with { DeleteAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal Snapshot PrepareStatusSucceededDeleteVaultCancellation(string owner, FixtureSelector selector, Resource[] resources,
        VaultAdministrationEffects.Configuration baseline)
    {
        Require(VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector) && resources is { Length: 3 } &&
            resources.All(r => !r.Borrowed && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) &&
            resources.Count(r => !r.CleanupOnly) == 1);
        var copied = CopySettings(baseline);
        var rows = resources.ToArray();
        var vault = rows.Single(r => !r.CleanupOnly).Id;
        var deleted = rows.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)).Id;
        return Change(owner, selector, state =>
        {
            Require(state is null);
            return new(owner, selector, Guid.NewGuid(), false, rows,
                StatusSucceededDeleteVault: new(1, ManagementMutation.DeleteVault, vault, deleted, copied));
        });
    }

    internal Snapshot BeginStatusSucceededDeleteVaultCancellationInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultCancellationAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        return Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                StatusSucceededDeleteVaultCancellationRoot(state) && state.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.ToArray();
            int index = Index(rows, typed.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                DeleteAttempted: false, Absent: false
            } &&
                rows.Where(r => r.Id != typed.VaultId).All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                    !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            rows[index] = rows[index] with { SelectedAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = typed with
                { InvocationDispatch = dispatch, BaselineSha256 = admission.BaselineSha256 }
            };
        });
    }

    internal Snapshot AdmitStatusSucceededDeleteVaultCancellationCanceledRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultCancellationCanceledReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededCancellationDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot AdmitStatusSucceededDeleteVaultCancellationRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultCancellationReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededCancellationDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusSucceededDeleteVaultCancellationRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededCancellationDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && completion is not null && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(!rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                StatusSucceededDeleteVault = state.StatusSucceededDeleteVault with { SettledDispatch = dispatch }
            };
        });

    private static void RequireStatusSucceededCancellationDispatch([NotNull] Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && StatusSucceededDeleteVaultCancellationRoot(state) && state.LeaseId == leaseId &&
            leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.StatusSucceededDeleteVault!.InvocationDispatch == dispatch &&
            state.StatusSucceededDeleteVault.SettledDispatch == Guid.Empty &&
            state.Resources.Single(r => r.Id == state.StatusSucceededDeleteVault.VaultId) is
            { SelectedAttempted: true, DeleteAttempted: false, ActiveDispatch: var active } && active == dispatch);

    internal Snapshot BeginStatusSucceededDeleteVaultCancellationCleanupDispatch(string owner, FixtureSelector selector, Guid leaseId,
        string resourceId, VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationCleanupAdmission admission)
    {
        var dispatch = Guid.NewGuid();
        return Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && state.Closing && state.Idle &&
                StatusSucceededDeleteVaultCancellationRoot(state) && admission is not null && admission.ResourceId == resourceId &&
                admission.Validate(this, state));
            var typed = state.StatusSucceededDeleteVault!;
            var rows = state.Resources.Select(r => r with { Absent = false }).ToArray();
            int index = Index(rows, resourceId);
            Require(!rows[index].DeleteAttempted && rows[index].ActiveDispatch == Guid.Empty &&
                (resourceId == typed.VaultId ? typed.InvocationDispatch == Guid.Empty && rows[index].CreateAttempted :
                    resourceId == typed.DeletedId && (typed.SettledDispatch != Guid.Empty ||
                        rows.Single(r => r.Id == typed.VaultId) is { DeleteAttempted: true, InvocationTerminated: true })));
            rows[index] = rows[index] with { DeleteAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusSucceededDeleteVaultCancellationCanceledRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusSucceededDeleteVaultCancellationCanceledDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireStatusSucceededCancellationDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && drain is not null && drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.StatusSucceededDeleteVault!.VaultId);
            Require(!rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot EndStatusSucceededDeleteVaultCancellationFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && StatusSucceededDeleteVaultCancellationRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty && drain.Validate(this, state) &&
                state.StatusSucceededDeleteVault!.InvocationDispatch != drain.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with
            { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal static bool StatusSucceededDeleteVaultCancellationRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(state.Selector) && StatusSucceededDeleteVaultShape(state);

    internal static bool SameStatusSucceededDeleteVaultCancellationSnapshot(Snapshot expected, Snapshot actual) =>
        StatusSucceededDeleteVaultCancellationRoot(expected) && StatusSucceededDeleteVaultCancellationRoot(actual) &&
        expected.Resources.SequenceEqual(actual.Resources) &&
        (actual with { Resources = expected.Resources, StatusSucceededDeleteVault = expected.StatusSucceededDeleteVault }) == expected &&
        (actual.StatusSucceededDeleteVault! with { Baseline = expected.StatusSucceededDeleteVault!.Baseline }) == expected.StatusSucceededDeleteVault &&
        VaultAdministrationEffects.SameConfiguration(expected.StatusSucceededDeleteVault.Baseline, actual.StatusSucceededDeleteVault!.Baseline);

    internal static bool StatusSucceededDeleteVaultRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(state.Selector) && StatusSucceededDeleteVaultShape(state);

    internal static bool StatusSucceededDeleteVaultIndependentRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(state.Selector) && StatusSucceededDeleteVaultShape(state);

    private static bool StatusSucceededDeleteVaultShape(Snapshot state)
    {
        if (state.LeaseId == Guid.Empty ||
            state.StatusSucceededDeleteVault is not { ContractVersion: 1, Operation: ManagementMutation.DeleteVault } typed ||
            state.PrivateEndpoint is not null || state.Settings is not null || state.DeleteVault is not null ||
            state.PurgeDeletedVault is not null || state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.NotificationAbsentCreate is not null || state.StatusVaultRecoverCancellationBaseline is not null ||
            state.StatusVaultUpdateCancellationBaseline is not null || state.Resources.Length != 3 ||
            state.Resources.Any(r => r is null || r.Borrowed) || typed.VaultId is not { Length: > 0 } || typed.Baseline is not
            { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 }) return false;
        string[] path = typed.VaultId.Split('/');
        if (path.Length != 9 || path[0] != "" || path[1] != "subscriptions" ||
            !Guid.TryParseExact(path[2], "D", out var subscription) || subscription == Guid.Empty ||
            path[3] != "resourceGroups" || path[4].Length is < 1 or > 90 ||
            !path[4].All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') ||
            typed.Baseline.Location is not { Length: >= 1 and <= 50 } ||
            !typed.Baseline.Location.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.') ||
            path[5] != "providers" ||
            path[6] != "Microsoft.KeyVault" || path[7] != "vaults" ||
            path[8] is not { Length: 24 } || !path[8].StartsWith("skv", StringComparison.Ordinal) ||
            !path[8][3..].All(char.IsAsciiHexDigit) ||
            typed.DeletedId != $"/subscriptions/{subscription:D}/providers/Microsoft.KeyVault/locations/{typed.Baseline.Location}/deletedVaults/{path[8]}")
            return false;
        return state.Resources.Count(r => r.Id == typed.VaultId && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == typed.DeletedId && r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == typed.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary && r.CleanupOnly) == 1;
    }

    private static void ValidateStatusSucceededDeleteVaultState(Snapshot state, Snapshot? previous)
    {
        if (state.StatusSucceededDeleteVault is null &&
            !VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(state.Selector) &&
            !VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(state.Selector) &&
            !VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(state.Selector)) return;
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && state.StatusSucceededDeleteVault is null &&
                (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusSucceededDeleteVaultRoot(state) || StatusSucceededDeleteVaultIndependentRoot(state) ||
            StatusSucceededDeleteVaultCancellationRoot(state));
        var typed = state.StatusSucceededDeleteVault!;
        _ = typed.Baseline.Build();
        var vault = state.Resources.Single(r => r.Id == typed.VaultId);
        var deleted = state.Resources.Single(r => r.Id == typed.DeletedId);
        var secret = state.Resources.Single(r => r.Id == typed.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary);
        Require(!secret.CreateAttempted && !secret.DeleteAttempted && !secret.SelectedAttempted &&
            !secret.InvocationTerminated && secret.ActiveDispatch == Guid.Empty && !deleted.CreateAttempted &&
            !deleted.SelectedAttempted && (!vault.DeleteAttempted || typed.InvocationDispatch == Guid.Empty) &&
            (typed.InvocationDispatch == Guid.Empty
                ? typed.SettledDispatch == Guid.Empty && typed.BaselineSha256 is null && !vault.SelectedAttempted
                : vault.CreateAttempted && vault.SelectedAttempted && !vault.DeleteAttempted &&
                    typed.BaselineSha256 is { Length: 64 } hash && hash.All(char.IsAsciiHexDigit) &&
                    (typed.SettledDispatch == Guid.Empty
                        ? vault.ActiveDispatch == typed.InvocationDispatch && !deleted.DeleteAttempted
                        : typed.SettledDispatch == typed.InvocationDispatch &&
                            vault.ActiveDispatch == Guid.Empty && vault.InvocationTerminated)));
        Require(state.Resources.All(r => !r.Absent || state.Closing && state.Idle) &&
            (!deleted.DeleteAttempted || state.Closing && typed.InvocationDispatch == typed.SettledDispatch) &&
            (!deleted.DeleteAttempted || typed.SettledDispatch != Guid.Empty ||
                vault is { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: true, ActiveDispatch: var cleanup } &&
                cleanup == Guid.Empty) &&
            (vault.ActiveDispatch == Guid.Empty || vault.CreateAttempted) &&
            (!vault.InvocationTerminated || vault.CreateAttempted) &&
            (!vault.DeleteAttempted || state.Closing) &&
            (deleted.ActiveDispatch == Guid.Empty || deleted.DeleteAttempted) &&
            (!deleted.InvocationTerminated || deleted.DeleteAttempted));
        if (previous is null)
            Require(!state.Closing && typed.InvocationDispatch == Guid.Empty &&
                state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted && !r.InvocationTerminated &&
                    !r.SelectedAttempted && !r.Absent && r.ActiveDispatch == Guid.Empty));
        else
        {
            Require(previous.StatusSucceededDeleteVault is not null);
            var prior = previous.StatusSucceededDeleteVault;
            Require(previous.LeaseId == state.LeaseId &&
                previous.Owner == state.Owner && previous.Selector == state.Selector && (!previous.Closing || state.Closing) &&
                prior.ContractVersion == typed.ContractVersion && prior.Operation == typed.Operation &&
                prior.VaultId == typed.VaultId && prior.DeletedId == typed.DeletedId &&
                VaultAdministrationEffects.SameConfiguration(prior.Baseline, typed.Baseline) &&
                (prior.InvocationDispatch == Guid.Empty || prior.InvocationDispatch == typed.InvocationDispatch) &&
                (prior.SettledDispatch == Guid.Empty || prior.SettledDispatch == typed.SettledDispatch) &&
                (prior.BaselineSha256 is null || prior.BaselineSha256 == typed.BaselineSha256));
            var oldVault = previous.Resources.Single(r => r.Id == typed.VaultId);
            if (prior.InvocationDispatch == Guid.Empty && typed.InvocationDispatch != Guid.Empty)
                Require(!previous.Closing && !state.Closing && previous.Idle &&
                    oldVault is
                    {
                        CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                        DeleteAttempted: false, Absent: false
                    } && !vault.InvocationTerminated &&
                    state.Resources.Where(r => r.Id != typed.VaultId)
                        .SequenceEqual(previous.Resources.Where(r => r.Id != typed.VaultId)));
            if (prior.SettledDispatch == Guid.Empty && typed.SettledDispatch != Guid.Empty)
                Require(!previous.Closing && !state.Closing && prior.InvocationDispatch == typed.InvocationDispatch &&
                    oldVault.ActiveDispatch == typed.InvocationDispatch && !oldVault.InvocationTerminated &&
                    state.Resources.Where(r => r.Id != typed.VaultId)
                        .SequenceEqual(previous.Resources.Where(r => r.Id != typed.VaultId)));
            foreach (var row in state.Resources)
            {
                var old = previous.Resources.Single(r => r.Id == row.Id);
                Require(row.Borrowed == old.Borrowed && row.CleanupOnly == old.CleanupOnly &&
                    (!old.CreateAttempted || row.CreateAttempted) && (!old.DeleteAttempted || row.DeleteAttempted) &&
                    (!old.DeleteAttempted || old.ActiveDispatch != Guid.Empty || row.ActiveDispatch == Guid.Empty) &&
                    (!old.SelectedAttempted || row.SelectedAttempted) &&
                    (old.ActiveDispatch == Guid.Empty || row.ActiveDispatch == old.ActiveDispatch ||
                        row.ActiveDispatch == Guid.Empty && row.InvocationTerminated) &&
                    (!old.InvocationTerminated || row.InvocationTerminated ||
                        row.ActiveDispatch != Guid.Empty && (old.ActiveDispatch == Guid.Empty ||
                            row.Id == typed.VaultId && row.ActiveDispatch == typed.InvocationDispatch &&
                            typed.SettledDispatch == Guid.Empty)));
            }
        }
    }

    internal Snapshot Prepare(string owner, FixtureSelector selector, Resource[] resources,
        PrivateEndpointDeclaration? privateEndpoint = null,
        VaultAdministrationEffects.Configuration? settingsBaseline = null,
        VaultAdministrationEffects.Configuration? deleteVaultBaseline = null,
        VaultAdministrationEffects.Configuration? purgeDeletedVaultBaseline = null,
        VaultAdministrationEffects.Configuration? createOrUpdateVaultBaseline = null,
        VaultAdministrationEffects.Configuration? createOrUpdateVaultSelected = null,
        VaultAdministrationEffects.Configuration? recoverVaultBaseline = null,
        VaultAdministrationEffects.Configuration? recoverVaultSelected = null,
        VaultAdministrationEffects.Configuration? privateConnectionUpdateBaseline = null,
        VaultAdministrationEffects.Configuration? privateConnectionDeleteBaseline = null,
        VaultAdministrationEffects.Configuration? statusVaultRecoverCancellationBaseline = null,
        VaultAdministrationEffects.Configuration? statusVaultUpdateCancellationBaseline = null)
    {
        Require(!VaultFixtureProvisioner.StatusSucceededDeleteVaultSelector(selector) &&
            !VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector) &&
            !VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector));
        Require(resources.Length is > 0 and <= 24 &&
            resources.All(r => r.Id.StartsWith("/subscriptions/", StringComparison.OrdinalIgnoreCase) &&
                r.Id.Length <= 2048 && !r.CreateAttempted && !r.DeleteAttempted &&
                r.ActiveDispatch == Guid.Empty && !r.Absent && !r.InvocationTerminated && !r.SelectedAttempted &&
                (!r.CleanupOnly || !r.Borrowed)) &&
            resources.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() == resources.Length);
        if (privateEndpoint is { } declaration)
        {
            Require(resources.Length <= 22 && resources.Length == 5 &&
                resources.Count(r => r.Borrowed) == 1 &&
                resources.Any(r => r.Id == declaration.VaultId && !r.Borrowed && !r.CleanupOnly) &&
                resources.Any(r => r.Id == declaration.EndpointId && !r.Borrowed && !r.CleanupOnly) &&
                resources.Any(r => r.Id == declaration.BorrowedSubnetId && r.Borrowed) &&
                !resources.Any(r => r.Id == declaration.ExpectedNicId));
            PrivateEndpointResourceCollector.ValidateBinding(new(selector, Guid.NewGuid(), declaration.EndpointId,
                declaration.VaultId, declaration.BorrowedSubnetId, declaration.ExpectedNicId,
                declaration.NetworkConnectionName, "declaration", declaration.OwnerTagName, declaration.OwnerTagValue));
        }
        return Change(owner, selector, state =>
        {
            Require(state is null); // No provisioning replay, even for an identical request.
            Require(privateConnectionDeleteBaseline is null ||
                VaultFixtureProvisioner.PrivateConnectionDeleteSelector(selector) && privateEndpoint is not null &&
                privateConnectionUpdateBaseline is null && settingsBaseline is null && deleteVaultBaseline is null &&
                purgeDeletedVaultBaseline is null && createOrUpdateVaultBaseline is null && recoverVaultBaseline is null &&
                privateConnectionDeleteBaseline.PublicNetworkAccess && !privateConnectionDeleteBaseline.PurgeProtection &&
                resources.Length == 5 &&
                resources.Count(r => r.Id == privateEndpoint.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                    !r.Borrowed && !r.CleanupOnly) == 1);
            Require(!VaultFixtureProvisioner.PrivateConnectionDeleteSelector(selector) ||
                privateConnectionDeleteBaseline is not null);
            Require(privateConnectionUpdateBaseline is null ||
                VaultFixtureProvisioner.PrivateConnectionUpdateSelector(selector) && privateEndpoint is not null &&
                privateConnectionDeleteBaseline is null &&
                settingsBaseline is null && deleteVaultBaseline is null && purgeDeletedVaultBaseline is null &&
                createOrUpdateVaultBaseline is null && recoverVaultBaseline is null &&
                privateConnectionUpdateBaseline.PublicNetworkAccess && !privateConnectionUpdateBaseline.PurgeProtection &&
                resources.Length == 5 &&
                resources.Count(r => r.Id == privateEndpoint.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                    !r.Borrowed && !r.CleanupOnly) == 1);
            Require(!VaultFixtureProvisioner.PrivateConnectionUpdateSelector(selector) ||
                privateConnectionUpdateBaseline is not null);
            Require((recoverVaultBaseline is null) == (recoverVaultSelected is null));
            Require(recoverVaultBaseline is null ||
                VaultFixtureProvisioner.RecoverVaultSelector(selector) && settingsBaseline is null &&
                deleteVaultBaseline is null && purgeDeletedVaultBaseline is null && createOrUpdateVaultBaseline is null &&
                privateEndpoint is null && resources.Length == 3 && resources.All(r => !r.Borrowed) &&
                resources.Count(r => !r.CleanupOnly) == 2);
            Require((createOrUpdateVaultBaseline is null) == (createOrUpdateVaultSelected is null));
            Require(createOrUpdateVaultBaseline is null ||
                VaultFixtureProvisioner.CreateOrUpdateVaultSelector(selector) && settingsBaseline is null &&
                deleteVaultBaseline is null && purgeDeletedVaultBaseline is null && privateEndpoint is null &&
                resources.Length == 3 && resources.All(r => !r.Borrowed) && resources.Count(r => !r.CleanupOnly) == 1);
            Require(settingsBaseline is null || IsSettings(selector) && privateEndpoint is null &&
                resources.Length == 3 && resources.All(r => !r.Borrowed) &&
                resources.Count(r => !r.CleanupOnly) == 1);
            Require(deleteVaultBaseline is null || VaultFixtureProvisioner.DeleteVaultSelector(selector) &&
                settingsBaseline is null && privateEndpoint is null && !deleteVaultBaseline.PurgeProtection &&
                resources.Length == 3 && resources.All(r => !r.Borrowed) &&
                resources.Count(r => !r.CleanupOnly) == 1);
            Require(purgeDeletedVaultBaseline is null || VaultFixtureProvisioner.PurgeDeletedVaultSelector(selector) &&
                settingsBaseline is null && deleteVaultBaseline is null && privateEndpoint is null &&
                !purgeDeletedVaultBaseline.PurgeProtection && resources.Length == 3 &&
                resources.All(r => !r.Borrowed) && resources.Count(r => !r.CleanupOnly) == 2);
            var prepared = new Snapshot(owner, selector, Guid.NewGuid(), false, resources.ToArray(),
                privateEndpoint is null ? null : new(privateEndpoint, OriginalUpdate:
                    privateConnectionUpdateBaseline is null ? null :
                        new(Enum.Parse<PrivateConnectionState>(selector.Variant.Split('.')[1]),
                            CopySettings(privateConnectionUpdateBaseline)),
                    OriginalDelete: privateConnectionDeleteBaseline is null ? null :
                        new(CopySettings(privateConnectionDeleteBaseline))),
                settingsBaseline is null ? null : new(resources.Single(r => !r.CleanupOnly).Id,
                    CopySettings(settingsBaseline)),
                deleteVaultBaseline is null ? null : new(resources.Single(r => !r.CleanupOnly).Id,
                    CopySettings(deleteVaultBaseline)),
                purgeDeletedVaultBaseline is null ? null : new(
                    resources.Single(r => !r.CleanupOnly && r.Id.Contains("/vaults/", StringComparison.Ordinal)).Id,
                    resources.Single(r => !r.CleanupOnly && r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)).Id,
                    CopySettings(purgeDeletedVaultBaseline)),
                createOrUpdateVaultBaseline is null ? null : new(resources.Single(r => !r.CleanupOnly).Id,
                    CopySettings(createOrUpdateVaultBaseline), CopySettings(createOrUpdateVaultSelected!)),
                recoverVaultBaseline is null ? null : new(
                    resources.Single(r => !r.CleanupOnly && r.Id.Contains("/vaults/", StringComparison.Ordinal)).Id,
                    resources.Single(r => !r.CleanupOnly && r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)).Id,
                    CopySettings(recoverVaultBaseline), CopySettings(recoverVaultSelected!)),
                statusVaultRecoverCancellationBaseline is null ? null : CopySettings(statusVaultRecoverCancellationBaseline),
                statusVaultUpdateCancellationBaseline is null ? null : CopySettings(statusVaultUpdateCancellationBaseline));
            // Coordinates, ownership and selector never grow. Mutable flags start
            // false (the longer JSON boolean); dispatch and lease GUIDs have fixed
            // serialized width. Measure the real schema with populated dispatches,
            // the widest sequence and a complete preceding hash, not just frame 1.
            var maximum = prepared with
            {
                Resources = prepared.Resources.Select(r => r with { ActiveDispatch = prepared.LeaseId }).ToArray(),
                RecoverVault = prepared.RecoverVault is null ? null : prepared.RecoverVault with
                {
                    InvocationDispatch = prepared.LeaseId,
                    SettledDispatch = prepared.LeaseId,
                    Disposition = RecoverVaultDisposition.Recovered,
                    DeletedBaselineSha256 = new string('F', 64)
                },
                CreateOrUpdateVault = prepared.CreateOrUpdateVault is null ? null : prepared.CreateOrUpdateVault with
                {
                    InvocationDispatch = prepared.LeaseId,
                    SettledDispatch = prepared.LeaseId,
                    Disposition = CreateOrUpdateVaultDisposition.Updated
                },
                // Reserve the generated connection and managed NIC before any
                // dispatch, including worst-case escaped coordinate bytes.
                PrivateEndpoint = prepared.PrivateEndpoint is null ? null : prepared.PrivateEndpoint with
                {
                    CreationDispatch = prepared.LeaseId,
                    DeletionDispatch = prepared.LeaseId,
                    ApprovalSettledDispatch = prepared.LeaseId,
                    OriginalDelete = prepared.PrivateEndpoint.OriginalDelete is not { } deletion ? null : deletion with
                    {
                        InvocationDispatch = prepared.LeaseId,
                        SettledDispatch = prepared.LeaseId,
                        Disposition = PrivateConnectionDeleteDisposition.Denied
                    },
                    OriginalUpdate = prepared.PrivateEndpoint.OriginalUpdate is not { } update ? null : update with
                    {
                        InvocationDispatch = prepared.LeaseId,
                        SettledDispatch = prepared.LeaseId,
                        Disposition = PrivateConnectionUpdateDisposition.InvalidInput
                    },
                    Connection = new(new string('\u0001', 2048), false, ActiveDispatch: prepared.LeaseId)
                },
                DeleteVault = prepared.DeleteVault is null ? null : prepared.DeleteVault with
                {
                    InvocationDispatch = prepared.LeaseId,
                    SettledDispatch = prepared.LeaseId,
                    Disposition = DeleteVaultDisposition.Deleted
                },
                PurgeDeletedVault = prepared.PurgeDeletedVault is null ? null : prepared.PurgeDeletedVault with
                {
                    InvocationDispatch = prepared.LeaseId,
                    SettledDispatch = prepared.LeaseId,
                    Disposition = PurgeDeletedVaultDisposition.Purged
                },
                Settings = prepared.Settings is null ? null : prepared.Settings with
                {
                    Baseline = prepared.Settings.Baseline with
                    { Rbac = false, PurgeProtection = false, PublicNetworkAccess = false },
                    InvocationDispatch = prepared.LeaseId,
                    SettledDispatch = prepared.LeaseId,
                    // All false booleans are the longest representation.
                    SettledConfiguration = prepared.Settings.Baseline with
                    { Rbac = false, PurgeProtection = false, PublicNetworkAccess = false }
                }
            };
            Require(JsonSerializer.SerializeToUtf8Bytes(
                new Frame(long.MaxValue, Convert.ToHexString(new byte[32]), maximum),
                ManagementAdmission.Json).Length <= MaximumFrame);
            return prepared;
        }, privateIndependent: true);
    }

    internal Snapshot Close(string owner, FixtureSelector selector, Func<Snapshot, bool>? validate = null) =>
        Change(owner, selector, state =>
        {
            if (state is null) return new(owner, selector, Guid.Empty, true, []); // Release can win before prepare.
            Require(validate is null || validate(state));
            return state with { Closing = true };
        }, privateIndependent: true, statusPending: true, statusPendingIndependent: true, statusPendingCancellation: true);

    internal Guid BeginSelectedDispatch(string owner, FixtureSelector selector, string resourceId, bool delete) =>
        BeginSelectedDispatch(owner, selector, resourceId, delete, update: false);

    internal Guid BeginSelectedUpdate(string owner, FixtureSelector selector, string resourceId) =>
        BeginSelectedDispatch(owner, selector, resourceId, delete: false, update: true);

    private Guid BeginSelectedDispatch(string owner, FixtureSelector selector, string resourceId, bool delete, bool update)
    {
        Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !IsSettings(selector) && !VaultFixtureProvisioner.DeleteVaultSelector(selector) &&
                state.StatusSucceededDeleteVault is null &&
                !NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) &&
                !NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) &&
                !NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector) &&
                !VaultFixtureProvisioner.PurgeDeletedVaultSelector(selector) &&
                state.CreateOrUpdateVault is null && state.RecoverVault is null &&
                !state.Closing && state.Idle && state.PrivateEndpoint is null);
            Resource[] rows = state!.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, resourceId);
            Resource row = rows[index];
            Require(!row.Borrowed && !row.CleanupOnly && !row.SelectedAttempted &&
                (update ? row.CreateAttempted && !row.DeleteAttempted : row.CreateAttempted == delete));
            if (RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector))
                Require(delete && !update && StatusRoleDeleteRoot(state) &&
                    row.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal) &&
                    state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                        r.ActiveDispatch == Guid.Empty && (r.Borrowed || r.CleanupOnly
                            ? !r.CreateAttempted && !r.InvocationTerminated
                            : r.CreateAttempted && r.InvocationTerminated)));
            if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector))
                Require(delete && !update && StatusNotificationDeleteRoot(state) &&
                    row.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                    state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                        r.ActiveDispatch == Guid.Empty && (r.CleanupOnly
                            ? !r.CreateAttempted && !r.InvocationTerminated
                            : r.CreateAttempted && r.InvocationTerminated)));
            if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
                Require(update && !delete && state.StatusVaultUpdateCancellationBaseline is not null &&
                    row.Id.Contains("/vaults/", StringComparison.Ordinal) && row.InvocationTerminated &&
                    rows.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                        r.ActiveDispatch == Guid.Empty) &&
                    rows.Where(r => r.Id != resourceId).All(r => r.CleanupOnly && !r.CreateAttempted &&
                        !r.InvocationTerminated));
            if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector))
            {
                Require(update && !delete && state.StatusVaultRecoverCancellationBaseline is not null &&
                    row.Id.Contains("/vaults/", StringComparison.Ordinal) &&
                    rows.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                        r.ActiveDispatch == Guid.Empty) &&
                    rows.Where(r => !r.CleanupOnly).All(r => r.CreateAttempted && r.InvocationTerminated));
            }
            if (VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector))
            {
                Require(delete && !update && state.Settings is null && state.DeleteVault is null &&
                    state.PurgeDeletedVault is null && rows.Length == 3 &&
                    rows.All(r => !r.Borrowed && r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted &&
                        !r.DeleteAttempted && !r.Absent) &&
                    row.Id.Contains("/deletedVaults/", StringComparison.Ordinal) &&
                    row.CreateAttempted && row.InvocationTerminated &&
                    rows.Count(r => r.Id != resourceId && !r.CleanupOnly && r.CreateAttempted &&
                        r.InvocationTerminated) == 1 &&
                    rows.Count(r => r.Id != resourceId && r.CleanupOnly && !r.CreateAttempted &&
                        !r.InvocationTerminated) == 1);
            }
            rows[index] = row with
            {
                SelectedAttempted = true,
                CreateAttempted = true,
                ActiveDispatch = dispatch,
                InvocationTerminated = false
            };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal Snapshot Read(string owner, FixtureSelector selector) =>
        Access(owner, selector, null);

    internal Guid BeginPrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.PrivateEndpoint is { OriginalDelete: { InvocationDispatch: var prior }, Connection: { } } &&
                prior == Guid.Empty && admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint;
            Require(slot.Connection is
            {
                CreateAttempted: true, SelectedAttempted: false, InvocationTerminated: true,
                DeleteAttempted: false, Absent: false, Borrowed: false, CleanupOnly: false
            } &&
                state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted &&
                    !r.DeleteAttempted && !r.Absent) &&
                state.Resources.Where(r => r.Id == slot.Declaration.VaultId || r.Id == slot.Declaration.EndpointId ||
                    r.Id == slot.Declaration.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary)
                    .All(r => r.CreateAttempted && r.InvocationTerminated));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection with { ActiveDispatch = dispatch, InvocationTerminated = false },
                    OriginalDelete = slot.OriginalDelete! with { InvocationDispatch = dispatch }
                }
            };
        });
        return dispatch;
    }

    internal void AdmitPrivateConnectionDeleteSend(string owner, FixtureSelector selector, Guid leaseId,
        Guid dispatch, ManagementOperationFixtureObserverService.PrivateConnectionDeleteAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateDeleteDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(!slot.Connection!.SelectedAttempted && !slot.Connection.DeleteAttempted &&
                !slot.Connection.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                { Connection = slot.Connection with { SelectedAttempted = true, DeleteAttempted = true } }
            };
        });

    internal ManagementOperationFixtureObserverService.PrivateConnectionDeleteTermination?
        RegisterPrivateConnectionDeleteTermination(string owner, FixtureSelector selector, Guid leaseId,
            Guid dispatch, Func<ManagementOperationFixtureObserverService.PrivateConnectionDeleteTermination> create)
    {
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteTermination? certificate = null;
        Change(owner, selector, state =>
        {
            RequirePrivateDeleteDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            certificate = create();
            Require(certificate is not null && !certificate.Paired &&
                certificate.Dispatch == dispatch && certificate.Validate(this, state));
            privateDeleteTerminations.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal ManagementOperationFixtureObserverService.PrivateConnectionDeleteCertificates?
        RegisterPrivateConnectionDeleteCompletion(string owner, FixtureSelector selector, Guid leaseId,
            Guid dispatch, Func<ManagementOperationFixtureObserverService.PrivateConnectionDeleteCertificates> create)
    {
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteCertificates? pair = null;
        Change(owner, selector, state =>
        {
            RequirePrivateDeleteDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            Require(state.PrivateEndpoint!.Connection is
            { SelectedAttempted: true, DeleteAttempted: true, InvocationTerminated: false } &&
                !privateDeleteCompletions.Values.Contains((owner, selector, leaseId, dispatch)) &&
                !privateDeleteTerminations.Values.Contains((owner, selector, leaseId, dispatch)) &&
                !privateDeleteSettlements.Values.Contains((owner, selector, leaseId, dispatch)));
            var created = create();
            Require(created is { Termination: not null, Settlement: not null } &&
                created.Termination.Dispatch == dispatch && created.Settlement.Dispatch == dispatch &&
                created.Termination.OwnsPair(created) &&
                created.Termination.Validate(this, state) && created.Settlement.Validate(this, state) &&
                created.Settlement.Disposition == PrivateConnectionDeleteDisposition.Deleted);
            // One in-memory registration under the same Close/file gate. No
            // durable termination is required until End is invoked separately.
            privateDeleteCompletions.Add(created, (owner, selector, leaseId, dispatch));
            pair = created;
            return state;
        });
        return pair;
    }

    internal void EndPrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state) &&
                (privateDeleteTerminations.TryGetValue(completion, out var registered) &&
                    registered == (owner, selector, leaseId, completion.Dispatch) ||
                 privateDeleteCompletions.Any(p => ReferenceEquals(p.Key.Termination, completion) &&
                    p.Value == (owner, selector, leaseId, completion.Dispatch))));
            var slot = state.PrivateEndpoint!;
            if (slot.OriginalDelete!.SettledDispatch == completion.Dispatch) return state;
            RequirePrivateDeleteDispatch(state, leaseId, completion.Dispatch);
            if (slot.Connection!.InvocationTerminated) return state;
            return state with
            {
                PrivateEndpoint = slot with
                { Connection = slot.Connection with { InvocationTerminated = true } }
            };
        });

    internal ManagementOperationFixtureObserverService.PrivateConnectionDeleteSettlement?
        RegisterPrivateConnectionDeleteSettlement(string owner, FixtureSelector selector, Guid leaseId,
            Guid dispatch, Func<ManagementOperationFixtureObserverService.PrivateConnectionDeleteSettlement> create)
    {
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteSettlement? certificate = null;
        Change(owner, selector, state =>
        {
            RequirePrivateDeleteDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            Require(state.PrivateEndpoint!.Connection!.InvocationTerminated);
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state) &&
                certificate.Disposition == PrivateConnectionDeleteDisposition.Denied);
            privateDeleteSettlements.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal Snapshot SettlePrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionDeleteSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state) &&
                (privateDeleteSettlements.TryGetValue(completion, out var registered) &&
                    registered == (owner, selector, leaseId, completion.Dispatch) ||
                 privateDeleteCompletions.Any(p => ReferenceEquals(p.Key.Settlement, completion) &&
                    p.Value == (owner, selector, leaseId, completion.Dispatch))));
            var slot = state.PrivateEndpoint!;
            var deletion = slot.OriginalDelete!;
            if (deletion.SettledDispatch == completion.Dispatch)
            {
                Require(deletion.Disposition == completion.Disposition);
                return state;
            }
            RequirePrivateDeleteDispatch(state, leaseId, completion.Dispatch);
            Require(slot.Connection is { InvocationTerminated: true, SelectedAttempted: true, DeleteAttempted: true } &&
                completion.Disposition is PrivateConnectionDeleteDisposition.Denied or PrivateConnectionDeleteDisposition.Deleted);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { ActiveDispatch = Guid.Empty },
                    OriginalDelete = deletion with
                    { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
                }
            };
        });

    private static void RequirePrivateDeleteDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.PrivateEndpoint is { OriginalDelete: { } deletion, OriginalUpdate: null, Connection: { } child } slot &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.ApprovalSettledDispatch == Guid.Empty && deletion.InvocationDispatch == dispatch &&
            deletion.SettledDispatch == Guid.Empty && deletion.Disposition == PrivateConnectionDeleteDisposition.None &&
            child.ActiveDispatch == dispatch && child.CreateAttempted && !child.Absent &&
            !child.Borrowed && !child.CleanupOnly && child.DeleteAttempted == child.SelectedAttempted &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted && !r.DeleteAttempted));

    internal Guid BeginPrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionUpdateAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.PrivateEndpoint is { OriginalUpdate: { InvocationDispatch: var prior }, Connection: { } } &&
                prior == Guid.Empty && admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint;
            Require(slot.Connection is
            {
                CreateAttempted: true, SelectedAttempted: false, InvocationTerminated: true,
                DeleteAttempted: false, Absent: false, Borrowed: false, CleanupOnly: false
            } &&
                state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted &&
                    !r.DeleteAttempted && !r.Absent) &&
                state.Resources.Where(r => r.Id == slot.Declaration.VaultId ||
                    r.Id == slot.Declaration.EndpointId ||
                    r.Id == slot.Declaration.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary)
                    .All(r => r.CreateAttempted && r.InvocationTerminated));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection with { ActiveDispatch = dispatch, InvocationTerminated = false },
                    OriginalUpdate = slot.OriginalUpdate! with { InvocationDispatch = dispatch }
                }
            };
        });
        return dispatch;
    }

    internal void AdmitPrivateConnectionUpdateSend(string owner, FixtureSelector selector, Guid leaseId,
        Guid dispatch, ManagementOperationFixtureObserverService.PrivateConnectionUpdateAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(!slot.Connection!.SelectedAttempted && !slot.Connection.InvocationTerminated &&
                slot.OriginalUpdate!.Requested is PrivateConnectionState.Approved or PrivateConnectionState.Rejected);
            return state with
            {
                PrivateEndpoint = slot with
                { Connection = slot.Connection with { SelectedAttempted = true } }
            };
        });

    internal ManagementOperationFixtureObserverService.PrivateConnectionUpdateTermination?
        RegisterPrivateConnectionUpdateTermination(string owner, FixtureSelector selector, Guid leaseId,
            Guid dispatch, Func<ManagementOperationFixtureObserverService.PrivateConnectionUpdateTermination> create)
    {
        ManagementOperationFixtureObserverService.PrivateConnectionUpdateTermination? certificate = null;
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            privateUpdateTerminations.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal void EndPrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionUpdateTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null && state is not null && completion.Validate(this, state) &&
                privateUpdateTerminations.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            var slot = state.PrivateEndpoint!;
            if (slot.OriginalUpdate!.SettledDispatch == completion.Dispatch) return state;
            RequirePrivateUpdateDispatch(state, leaseId, completion.Dispatch);
            if (slot.Connection!.InvocationTerminated) return state;
            return state with
            {
                PrivateEndpoint = slot with
                { Connection = slot.Connection with { InvocationTerminated = true } }
            };
        });

    internal ManagementOperationFixtureObserverService.PrivateConnectionUpdateSettlement?
        RegisterPrivateConnectionUpdateSettlement(string owner, FixtureSelector selector, Guid leaseId,
            Guid dispatch, Func<ManagementOperationFixtureObserverService.PrivateConnectionUpdateSettlement> create)
    {
        ManagementOperationFixtureObserverService.PrivateConnectionUpdateSettlement? certificate = null;
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            Require(state.PrivateEndpoint!.Connection!.InvocationTerminated);
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            privateUpdateSettlements.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal Snapshot SettlePrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionUpdateSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state) &&
                privateUpdateSettlements.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            var slot = state.PrivateEndpoint!;
            var update = slot.OriginalUpdate!;
            if (update.SettledDispatch == completion.Dispatch)
            {
                Require(update.Disposition == completion.Disposition);
                return state;
            }
            RequirePrivateUpdateDispatch(state, leaseId, completion.Dispatch);
            Require(slot.Connection!.InvocationTerminated &&
                (completion.Disposition == PrivateConnectionUpdateDisposition.InvalidInput
                    ? !slot.Connection.SelectedAttempted &&
                        update.Requested is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected)
                    : slot.Connection.SelectedAttempted && completion.Disposition is
                        PrivateConnectionUpdateDisposition.Updated or PrivateConnectionUpdateDisposition.Denied));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { ActiveDispatch = Guid.Empty },
                    OriginalUpdate = update with
                    { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
                }
            };
        });

    private static void RequirePrivateUpdateDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.PrivateEndpoint is { OriginalUpdate: { } update, Connection: { } child } slot &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.ApprovalSettledDispatch == Guid.Empty && update.InvocationDispatch == dispatch &&
            update.SettledDispatch == Guid.Empty && update.Disposition == PrivateConnectionUpdateDisposition.None &&
            child.ActiveDispatch == dispatch && child.CreateAttempted && !child.DeleteAttempted &&
            !child.Absent && !child.Borrowed && !child.CleanupOnly &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted && !r.DeleteAttempted));

    internal Guid BeginCreateOrUpdateVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.CreateOrUpdateVault is { InvocationDispatch: var prior } && prior == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var creation = state.CreateOrUpdateVault;
            var rows = state.Resources.ToArray();
            int index = Index(rows, creation.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false,
                SelectedAttempted: false, Borrowed: false, CleanupOnly: false, Absent: false
            });
            rows[index] = rows[index] with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows, CreateOrUpdateVault = creation with { InvocationDispatch = dispatch } };
        });
        return dispatch;
    }

    internal void AdmitCreateOrUpdateVaultSend(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireCreateVaultDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.CreateOrUpdateVault!.VaultId);
            Require(!rows[index].InvocationTerminated && !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { SelectedAttempted = true };
            return state with { Resources = rows };
        });

    internal ManagementOperationFixtureObserverService.CreateOrUpdateVaultTermination? RegisterCreateOrUpdateVaultTermination(
        string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        Func<ManagementOperationFixtureObserverService.CreateOrUpdateVaultTermination> create)
    {
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultTermination? certificate = null;
        Change(owner, selector, state =>
        {
            RequireCreateVaultDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            createVaultTerminations.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal void EndCreateOrUpdateVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null);
            RequireCreateVaultDispatch(state, leaseId, completion.Dispatch);
            Require(completion.Validate(this, state!) && createVaultTerminations.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            var rows = state!.Resources.ToArray();
            int index = Index(rows, state.CreateOrUpdateVault!.VaultId);
            if (rows[index].InvocationTerminated) return state;
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement? RegisterCreateOrUpdateVaultSettlement(
        string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        Func<ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement> create)
    {
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement? certificate = null;
        Change(owner, selector, state =>
        {
            RequireCreateVaultDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            Require(state.Resources.Single(r => r.Id == state.CreateOrUpdateVault!.VaultId).InvocationTerminated);
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            createVaultCompletions.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal void RegisterCreateOrUpdateVaultSettlement(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state) &&
                createVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            return state;
        });

    internal Snapshot SettleCreateOrUpdateVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.CreateOrUpdateVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && completion is not null &&
                createVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch) && completion.Validate(this, state) &&
                state.CreateOrUpdateVault is { } && state.CreateOrUpdateVault.InvocationDispatch == completion.Dispatch);
            var creation = state.CreateOrUpdateVault;
            if (creation.SettledDispatch == completion.Dispatch)
            {
                Require(creation.Disposition == completion.Disposition);
                return state;
            }
            RequireCreateVaultDispatch(state, leaseId, completion.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, creation.VaultId);
            Require(rows[index].InvocationTerminated && rows[index].SelectedAttempted &&
                completion.Disposition is CreateOrUpdateVaultDisposition.Updated or CreateOrUpdateVaultDisposition.Denied &&
                VaultAdministrationEffects.SameConfiguration(completion.Configuration,
                    completion.Disposition == CreateOrUpdateVaultDisposition.Updated ? creation.Selected : creation.Baseline));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                CreateOrUpdateVault = creation with
                { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
            };
        });

    private static void RequireCreateVaultDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.CreateOrUpdateVault is { } creation && creation.InvocationDispatch == dispatch &&
            creation.SettledDispatch == Guid.Empty && creation.Disposition == CreateOrUpdateVaultDisposition.None &&
            state.Resources.Single(r => r.Id == creation.VaultId) is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, Absent: false,
                ActiveDispatch: var active
            } && active == dispatch &&
            state.Resources.Where(r => r.Id != creation.VaultId).All(r => r.ActiveDispatch == Guid.Empty));

    internal Guid BeginRecoverVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.RecoverVaultAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.RecoverVault is { InvocationDispatch: var prior } && prior == Guid.Empty &&
                admission is not null && admission.Validate(this, state) &&
                admission.DeletedDigest is { Length: 64 } digest && digest.All(char.IsAsciiHexDigit));
            var recovery = state.RecoverVault;
            var rows = state.Resources.ToArray();
            int index = Index(rows, recovery.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false,
                SelectedAttempted: false, Borrowed: false, CleanupOnly: false, Absent: false
            });
            rows[index] = rows[index] with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with
            {
                Resources = rows,
                RecoverVault = recovery with { InvocationDispatch = dispatch, DeletedBaselineSha256 = admission.DeletedDigest }
            };
        });
        return dispatch;
    }

    internal void AdmitRecoverVaultSend(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.RecoverVaultAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireRecoverVaultDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.RecoverVault!.VaultId);
            Require(!rows[index].InvocationTerminated && !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { SelectedAttempted = true };
            return state with { Resources = rows };
        });

    internal ManagementOperationFixtureObserverService.RecoverVaultTermination? RegisterRecoverVaultTermination(
        string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        Func<ManagementOperationFixtureObserverService.RecoverVaultTermination> create)
    {
        ManagementOperationFixtureObserverService.RecoverVaultTermination? certificate = null;
        Change(owner, selector, state =>
        {
            RequireRecoverVaultDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            recoverVaultTerminations.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal void EndRecoverVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.RecoverVaultTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null);
            RequireRecoverVaultDispatch(state, leaseId, completion.Dispatch);
            Require(completion.Validate(this, state!) && recoverVaultTerminations.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            var rows = state!.Resources.ToArray();
            int index = Index(rows, state.RecoverVault!.VaultId);
            if (rows[index].InvocationTerminated) return state;
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal ManagementOperationFixtureObserverService.RecoverVaultSettlement? RegisterRecoverVaultSettlement(
        string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        Func<ManagementOperationFixtureObserverService.RecoverVaultSettlement> create)
    {
        ManagementOperationFixtureObserverService.RecoverVaultSettlement? certificate = null;
        Change(owner, selector, state =>
        {
            RequireRecoverVaultDispatch(state, leaseId, dispatch);
            if (state!.Closing) return state;
            Require(state.Resources.Single(r => r.Id == state.RecoverVault!.VaultId).InvocationTerminated);
            certificate = create();
            Require(certificate is not null && certificate.Dispatch == dispatch && certificate.Validate(this, state));
            recoverVaultCompletions.Add(certificate, (owner, selector, leaseId, dispatch));
            return state;
        });
        return certificate;
    }

    internal void RegisterRecoverVaultSettlement(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.RecoverVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state) &&
                recoverVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            return state;
        });

    internal Snapshot SettleRecoverVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.RecoverVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && completion is not null &&
                recoverVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch) && completion.Validate(this, state) &&
                state.RecoverVault is { } && state.RecoverVault.InvocationDispatch == completion.Dispatch);
            var recovery = state.RecoverVault;
            if (recovery.SettledDispatch == completion.Dispatch)
            {
                Require(recovery.Disposition == completion.Disposition);
                return state;
            }
            RequireRecoverVaultDispatch(state, leaseId, completion.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, recovery.VaultId);
            Require(rows[index].InvocationTerminated && rows[index].SelectedAttempted &&
                completion.Disposition is RecoverVaultDisposition.Recovered or RecoverVaultDisposition.Denied &&
                VaultAdministrationEffects.SameConfiguration(completion.Configuration,
                    completion.Disposition == RecoverVaultDisposition.Recovered ? recovery.Selected : recovery.Baseline));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                RecoverVault = recovery with
                { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
            };
        });

    private static void RequireRecoverVaultDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.RecoverVault is { } recovery && recovery.InvocationDispatch == dispatch &&
            recovery.SettledDispatch == Guid.Empty && recovery.Disposition == RecoverVaultDisposition.None &&
            state.Resources.Single(r => r.Id == recovery.VaultId) is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, Absent: false,
                ActiveDispatch: var active
            } && active == dispatch &&
            state.Resources.Where(r => r.Id != recovery.VaultId).All(r => r.ActiveDispatch == Guid.Empty));

    internal Guid BeginPurgeDeletedVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PurgeDeletedVaultAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.PurgeDeletedVault is { InvocationDispatch: var prior } && prior == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var purge = state.PurgeDeletedVault;
            var rows = state.Resources.ToArray();
            int index = Index(rows, purge.DeletedVaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false,
                SelectedAttempted: false, Borrowed: false, CleanupOnly: false, Absent: false
            } && rows.Single(r => r.Id == purge.VaultId) is
            { CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false, SelectedAttempted: false });
            rows[index] = rows[index] with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows, PurgeDeletedVault = purge with { InvocationDispatch = dispatch } };
        });
        return dispatch;
    }

    internal void AdmitPurgeDeletedVaultSend(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.PurgeDeletedVaultAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePurgeDeletedVaultDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.PurgeDeletedVault!.DeletedVaultId);
            Require(!rows[index].InvocationTerminated && !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { SelectedAttempted = true };
            return state with { Resources = rows };
        });

    internal ManagementOperationFixtureObserverService.PurgeDeletedVaultTermination? RegisterPurgeDeletedVaultTermination(
        string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        Func<ManagementOperationFixtureObserverService.PurgeDeletedVaultTermination> create)
    {
        ManagementOperationFixtureObserverService.PurgeDeletedVaultTermination? completion = null;
        Change(owner, selector, state =>
        {
            RequirePurgeDeletedVaultDispatch(state, leaseId, dispatch);
            // Certificate creation and registration share the durable Close gate.
            if (state!.Closing) return state;
            completion = create();
            Require(completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            purgeDeletedVaultTerminations.Add(completion, (owner, selector, leaseId, completion.Dispatch));
            return state;
        });
        return completion;
    }

    internal void EndPurgeDeletedVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PurgeDeletedVaultTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null);
            RequirePurgeDeletedVaultDispatch(state, leaseId, completion.Dispatch);
            Require(completion.Validate(this, state!) &&
                purgeDeletedVaultTerminations.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch));
            var rows = state!.Resources.ToArray();
            int index = Index(rows, state.PurgeDeletedVault!.DeletedVaultId);
            if (rows[index].InvocationTerminated) return state;
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal void RegisterPurgeDeletedVaultSettlement(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PurgeDeletedVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state));
            if (purgeDeletedVaultCompletions.TryGetValue(completion, out var registered))
            {
                Require(registered == (owner, selector, leaseId, completion.Dispatch));
                return state;
            }
            Require(!state.Closing);
            RequirePurgeDeletedVaultDispatch(state, leaseId, completion.Dispatch);
            Require(state.Resources.Single(r => r.Id == state.PurgeDeletedVault!.DeletedVaultId).InvocationTerminated);
            purgeDeletedVaultCompletions.Add(completion, (owner, selector, leaseId, completion.Dispatch));
            return state;
        });

    internal Snapshot SettlePurgeDeletedVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PurgeDeletedVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && completion is not null &&
                purgeDeletedVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch) &&
                completion.Validate(this, state) && state.PurgeDeletedVault is { } &&
                state.PurgeDeletedVault.InvocationDispatch == completion.Dispatch);
            var purge = state.PurgeDeletedVault;
            if (purge.SettledDispatch == completion.Dispatch)
            {
                Require(purge.Disposition == completion.Disposition);
                return state;
            }
            RequirePurgeDeletedVaultDispatch(state, leaseId, completion.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, purge.DeletedVaultId);
            Require(rows[index].InvocationTerminated && rows[index].SelectedAttempted &&
                completion.Disposition is PurgeDeletedVaultDisposition.Purged or PurgeDeletedVaultDisposition.Denied);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                PurgeDeletedVault = purge with
                { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
            };
        });

    private static void RequirePurgeDeletedVaultDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.PurgeDeletedVault is { } purge && purge.InvocationDispatch == dispatch &&
            purge.SettledDispatch == Guid.Empty && purge.Disposition == PurgeDeletedVaultDisposition.None &&
            state.Resources.Single(r => r.Id == purge.DeletedVaultId) is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false,
                Absent: false, ActiveDispatch: var active
            } && active == dispatch &&
            state.Resources.Where(r => r.Id != purge.DeletedVaultId).All(r => r.ActiveDispatch == Guid.Empty));

    internal Guid BeginDeleteVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.DeleteVaultAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.DeleteVault is { InvocationDispatch: var prior } && prior == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var deletion = state.DeleteVault;
            var rows = state.Resources.ToArray();
            int index = Index(rows, deletion.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false,
                SelectedAttempted: false, Borrowed: false, CleanupOnly: false, Absent: false
            });
            rows[index] = rows[index] with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows, DeleteVault = deletion with { InvocationDispatch = dispatch } };
        });
        return dispatch;
    }

    internal void AdmitDeleteVaultSend(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.DeleteVaultAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireDeleteVaultDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.DeleteVault!.VaultId);
            Require(!rows[index].InvocationTerminated && !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { SelectedAttempted = true };
            return state with { Resources = rows };
        });

    internal void EndDeleteVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.DeleteVaultTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null);
            RequireDeleteVaultDispatch(state, leaseId, completion.Dispatch);
            Require(completion.Validate(this, state!));
            var rows = state!.Resources.ToArray();
            int index = Index(rows, state.DeleteVault!.VaultId);
            if (rows[index].InvocationTerminated) return state;
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal void RegisterDeleteVaultSettlement(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.DeleteVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state));
            if (deleteVaultCompletions.TryGetValue(completion, out var registered))
            {
                Require(registered == (owner, selector, leaseId, completion.Dispatch));
                return state;
            }
            Require(!state.Closing);
            RequireDeleteVaultDispatch(state, leaseId, completion.Dispatch);
            Require(state.Resources.Single(r => r.Id == state.DeleteVault!.VaultId).InvocationTerminated);
            deleteVaultCompletions.Add(completion, (owner, selector, leaseId, completion.Dispatch));
            return state;
        });

    internal Snapshot SettleDeleteVaultInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.DeleteVaultSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && completion is not null &&
                deleteVaultCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch) &&
                completion.Validate(this, state) && state.DeleteVault is { } &&
                state.DeleteVault.InvocationDispatch == completion.Dispatch);
            var deletion = state.DeleteVault;
            if (deletion.SettledDispatch == completion.Dispatch)
            {
                Require(deletion.Disposition == completion.Disposition);
                return state;
            }
            RequireDeleteVaultDispatch(state, leaseId, completion.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, deletion.VaultId);
            Require(rows[index].InvocationTerminated && rows[index].SelectedAttempted &&
                completion.Disposition is DeleteVaultDisposition.Deleted or DeleteVaultDisposition.Denied);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                DeleteVault = deletion with
                { SettledDispatch = completion.Dispatch, Disposition = completion.Disposition }
            };
        });

    private static void RequireDeleteVaultDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty && dispatch != Guid.Empty &&
            state.DeleteVault is { } deletion && deletion.InvocationDispatch == dispatch &&
            deletion.SettledDispatch == Guid.Empty && deletion.Disposition == DeleteVaultDisposition.None &&
            state.Resources.Single(r => r.Id == deletion.VaultId) is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false,
                Absent: false, ActiveDispatch: var active
            } && active == dispatch &&
            state.Resources.Where(r => r.Id != deletion.VaultId).All(r => r.ActiveDispatch == Guid.Empty));

    // These tokens are not bearer coordinates. Validation consults the source's
    // private reference registry, whose values contain only immutable evidence.
    internal Guid BeginSettingsInvocation(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureObserverService.SettingsAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                state.Settings is { InvocationDispatch: var prior } && prior == Guid.Empty &&
                admission is not null && admission.Validate(this, state));
            var settings = state.Settings;
            var rows = state.Resources.ToArray();
            int index = Index(rows, settings.VaultId);
            Require(rows[index] is
            {
                CreateAttempted: true, InvocationTerminated: true, DeleteAttempted: false,
                SelectedAttempted: false, Borrowed: false, CleanupOnly: false, Absent: false
            });
            rows[index] = rows[index] with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows, Settings = settings with { InvocationDispatch = dispatch } };
        });
        return dispatch;
    }

    internal void AdmitSettingsSend(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        VaultFixtureObserverService.SettingsAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireSettingsDispatch(state, leaseId, dispatch);
            Require(!state!.Closing && admission is not null && admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, state.Settings!.VaultId);
            Require(!rows[index].InvocationTerminated && !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { SelectedAttempted = true };
            return state with { Resources = rows };
        });

    internal void EndSettingsInvocation(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureObserverService.SettingsTermination completion) =>
        Change(owner, selector, state =>
        {
            Require(completion is not null);
            RequireSettingsDispatch(state, leaseId, completion.Dispatch);
            Require(completion.Validate(this, state!));
            var rows = state!.Resources.ToArray();
            int index = Index(rows, state.Settings!.VaultId);
            if (rows[index].InvocationTerminated) return state;
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot SettleSettingsInvocation(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureObserverService.SettingsSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && completion is not null &&
                settingsCompletions.TryGetValue(completion, out var registered) &&
                registered == (owner, selector, leaseId, completion.Dispatch) &&
                completion.Validate(this, state) && state.Settings is { } &&
                state.Settings.InvocationDispatch == completion.Dispatch);
            var settings = state.Settings;
            // Lost local acknowledgement retries only this exact registered
            // completion. There is no new invocation or provider call.
            if (settings.SettledDispatch == completion.Dispatch)
            {
                Require(settings.SettledConfiguration is not null &&
                    VaultAdministrationEffects.SameConfiguration(settings.SettledConfiguration, completion.Configuration));
                return state;
            }
            RequireSettingsDispatch(state, leaseId, completion.Dispatch);
            var rows = state.Resources.ToArray();
            int index = Index(rows, settings.VaultId);
            Require(rows[index].InvocationTerminated);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                Settings = settings with
                {
                    SettledDispatch = completion.Dispatch,
                    SettledConfiguration = CopySettings(completion.Configuration)
                }
            };
        });

    internal void RegisterSettingsSettlement(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureObserverService.SettingsSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && completion is not null && completion.Validate(this, state));
            if (settingsCompletions.TryGetValue(completion, out var registered))
            {
                Require(registered == (owner, selector, leaseId, completion.Dispatch));
                return state;
            }
            // This is the certificate's linearization point against durable
            // Close. Once registered it can finish/retry local persistence after
            // Close, but Close never allows a new certificate to be minted.
            Require(!state.Closing);
            RequireSettingsDispatch(state, leaseId, completion.Dispatch);
            Require(state.Resources.Single(r => r.Id == state.Settings!.VaultId).InvocationTerminated);
            settingsCompletions.Add(completion, (owner, selector, leaseId, completion.Dispatch));
            return state;
        });

    private static void RequireSettingsDispatch(Snapshot? state, Guid leaseId, Guid dispatch) =>
        Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty &&
            dispatch != Guid.Empty && state.Settings is { } settings &&
            settings.InvocationDispatch == dispatch && settings.SettledDispatch == Guid.Empty &&
            state.Resources.Single(r => r.Id == settings.VaultId) is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false,
                Absent: false, ActiveDispatch: var active
            } && active == dispatch &&
            state.Resources.Where(r => r.Id != settings.VaultId).All(r => r.ActiveDispatch == Guid.Empty));

    private static bool IsSettings(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.UpdateSettingsAsync";

    private static VaultAdministrationEffects.Configuration CopySettings(VaultAdministrationEffects.Configuration value)
    {
        _ = value.Build();
        return value with { Policies = value.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray() };
    }

    internal Guid BeginPrivateConnectionApproval(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionApprovalAdmission candidate)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && leaseId != Guid.Empty &&
                state.LeaseId == leaseId && candidate is not null && candidate.Validate(this, state) &&
                selector.Operation == ManagementOperationEffects.Members[0].Operation &&
                selector.Variant == "operation.UpdatePrivateConnection" && selector.Case == "selected-contract" &&
                state.PrivateEndpoint is
                {
                    OriginalUpdate: null, OriginalDelete: null,
                    CreationDispatch: var creation, DeletionDispatch: var deletion,
                    ApprovalSettledDispatch: var approval, Connection: { }
                } &&
                creation == Guid.Empty && deletion == Guid.Empty && approval == Guid.Empty &&
                !state.Resources.Any(r => r.SelectedAttempted));
            var slot = state.PrivateEndpoint;
            var child = slot.Connection!;
            Require(child is
            {
                CreateAttempted: true, SelectedAttempted: false, DeleteAttempted: false,
                Borrowed: false, CleanupOnly: false, Absent: false, InvocationTerminated: true
            } &&
                state.Resources.Single(r => r.Id == slot.Declaration.EndpointId) is
                { CreateAttempted: true, DeleteAttempted: false, InvocationTerminated: true, Absent: false });
            return state with
            {
                Resources = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray(),
                PrivateEndpoint = slot with
                {
                    NicAbsent = false,
                    Connection = child with
                    {
                        SelectedAttempted = true,
                        ActiveDispatch = dispatch,
                        InvocationTerminated = false,
                        Absent = false
                    }
                }
            };
        });
        return dispatch;
    }

    internal Guid BeginStatusPrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateCancellationAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                leaseId != Guid.Empty && StatusPrivateConnectionUpdateRoot(state) &&
                admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
                slot.ApprovalSettledDispatch == Guid.Empty && slot.Connection is
                {
                    CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                    DeleteAttempted: false, Absent: false
                } &&
                StatusPrivateConnectionReadyRows(state));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with
                    { SelectedAttempted = true, ActiveDispatch = dispatch, InvocationTerminated = false }
                }
            };
        });
        return dispatch;
    }

    internal void CheckStatusPrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionUpdateDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && !state.PrivateEndpoint!.Connection!.InvocationTerminated);
            return state;
        });

    internal Snapshot EndStatusPrivateConnectionUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionUpdateDispatch(state, leaseId, declaration, connectionId, dispatch);
            var slot = state!.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = true } }
            };
        });

    internal void AdmitStatusPrivateConnectionUpdateRead(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionUpdateDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && state.PrivateEndpoint!.Connection!.InvocationTerminated);
            var slot = state.PrivateEndpoint;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = false } }
            };
        });

    internal Snapshot CompleteStatusPrivateConnectionUpdateCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            RequireStatusPrivateConnectionUpdateDispatch(state, leaseId, slot.Declaration, slot.Connection!.Id, dispatch);
            Require(!slot.Connection.InvocationTerminated);
            // Close and this single flushed frame share Change's transaction.
            // No intermediate drained-but-unsettled completion is published.
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { InvocationTerminated = true, ActiveDispatch = Guid.Empty },
                    ApprovalSettledDispatch = dispatch
                }
            };
        });

    private static void RequireStatusPrivateConnectionUpdateDispatch(Snapshot? state, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Require(state is not null && StatusPrivateConnectionUpdateRoot(state) && leaseId != Guid.Empty &&
            state.LeaseId == leaseId && state.PrivateEndpoint is { } slot && slot.Declaration == declaration &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.ApprovalSettledDispatch == Guid.Empty && slot.Connection is
            { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: false, Absent: false } child &&
            child.Id == connectionId && dispatch != Guid.Empty && child.ActiveDispatch == dispatch &&
            StatusPrivateConnectionReadyRows(state));

    private static bool StatusPrivateConnectionReadyRows(Snapshot state) =>
        state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
            r.ActiveDispatch == Guid.Empty && (r.Borrowed || r.CleanupOnly
                ? !r.CreateAttempted && !r.InvocationTerminated : r.CreateAttempted && r.InvocationTerminated));

    private readonly HashSet<(string Owner, Guid Nonce)> invalidPrivateUpdateIndependentHistory = [];
    internal sealed class StatusPrivateConnectionUpdateIndependentHistoryException : InvalidOperationException
    {
        internal StatusPrivateConnectionUpdateIndependentHistoryException() : base("fixture-journal-unavailable") { }
    }
    private void RequirePrivateUpdateIndependentHistory(string owner, FixtureSelector selector)
    {
        if (invalidPrivateUpdateIndependentHistory.Contains((owner, selector.Nonce)))
            throw new StatusPrivateConnectionUpdateIndependentHistoryException();
    }
    internal static bool StatusPrivateConnectionUpdateIndependentRoot(Snapshot state) =>
        state is not null && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(state.Selector) &&
        state.Resources is { Length: 5 } && state.Resources.All(r => r is not null && !string.IsNullOrEmpty(r.Id)) &&
        state.PrivateEndpoint?.Declaration is { } declaration &&
        new[] { declaration.VaultId, declaration.EndpointId, declaration.BorrowedSubnetId, declaration.NetworkConnectionName,
            declaration.ExpectedNicId, declaration.OwnerTagName, declaration.OwnerTagValue }.All(v => !string.IsNullOrEmpty(v)) &&
        state.StatusSucceededDeleteVault is null && StatusPrivateConnectionRoot(state, delete: false) &&
        state.Resources[0].Id == state.PrivateEndpoint!.Declaration.VaultId &&
        state.Resources[1].Id == state.PrivateEndpoint.Declaration.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
        state.Resources[2].Id.Contains("/deletedVaults/", StringComparison.Ordinal) &&
        state.Resources[3].Id == state.PrivateEndpoint.Declaration.EndpointId &&
        state.Resources[4].Id == state.PrivateEndpoint.Declaration.BorrowedSubnetId;
    internal static bool SameStatusPrivateConnectionUpdateIndependentSnapshot(Snapshot expected, Snapshot actual) =>
        expected is not null && actual is not null && StatusPrivateConnectionUpdateIndependentRoot(expected) &&
        StatusPrivateConnectionUpdateIndependentRoot(actual) && expected.Resources.SequenceEqual(actual.Resources) &&
        (actual with { Resources = expected.Resources }) == expected;

    internal Snapshot BeginStatusPrivateConnectionUpdateIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateIndependentAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && state.Idle && StatusPrivateConnectionReadyRows(state) && admission is not null &&
                admission.Dispatch != Guid.Empty && admission.Validate(this, state) && state.PrivateEndpoint!.Connection is
                { SelectedAttempted: false, DeleteAttempted: false, Absent: false, InvocationTerminated: true } &&
                state.PrivateEndpoint.ApprovalSettledDispatch == Guid.Empty);
            var slot = state.PrivateEndpoint!;
            return state with { PrivateEndpoint = slot with { Connection = slot.Connection! with
                { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = admission.Dispatch } } };
        }, privateIndependent: true);
    internal Snapshot EndStatusPrivateConnectionUpdateIndependentStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateIndependentStartDrain drain) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && drain is not null && drain.Dispatch == dispatch);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state) && state.PrivateEndpoint!.Connection is
                { SelectedAttempted: true, InvocationTerminated: false } && state.PrivateEndpoint.Connection.ActiveDispatch == dispatch);
            return state with { PrivateEndpoint = state.PrivateEndpoint with
                { Connection = state.PrivateEndpoint.Connection with { InvocationTerminated = true } } };
        }, privateIndependent: true);
    internal Snapshot AdmitStatusPrivateConnectionUpdateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && admission is not null && admission.Dispatch == dispatch &&
                admission.Validate(this, state) && state.PrivateEndpoint!.Connection is
                { SelectedAttempted: true, InvocationTerminated: true } && state.PrivateEndpoint.Connection.ActiveDispatch == dispatch);
            return state with { PrivateEndpoint = state.PrivateEndpoint with
                { Connection = state.PrivateEndpoint.Connection with { InvocationTerminated = false } } };
        }, privateIndependent: true);
    internal Snapshot CompleteStatusPrivateConnectionUpdateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionUpdateIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch);
            if (completion.AcceptPostimage(this, state)) return state;
            Require(completion.Validate(this, state) && state.PrivateEndpoint!.ApprovalSettledDispatch == Guid.Empty &&
                state.PrivateEndpoint.Connection is { SelectedAttempted: true, InvocationTerminated: false } &&
                state.PrivateEndpoint.Connection.ActiveDispatch == dispatch);
            return state with { PrivateEndpoint = state.PrivateEndpoint with
            { ApprovalSettledDispatch = dispatch, Connection = state.PrivateEndpoint.Connection with
                { InvocationTerminated = true, ActiveDispatch = Guid.Empty } } };
        }, privateIndependent: true);

    private static bool PrivateUpdateIndependentFixtureAllowed(Snapshot state, string id, bool delete)
    {
        if (!StatusPrivateConnectionUpdateIndependentRoot(state) || !state.Idle || state.Closing != delete) return false;
        var row = state.Resources.SingleOrDefault(r => r.Id == id);
        if (row is null || row.Borrowed || row.ActiveDispatch != Guid.Empty) return false;
        var parent = state.Resources[0];
        var endpoint = state.Resources[3];
        if (!delete)
            return !row.CreateAttempted && !row.DeleteAttempted && !row.CleanupOnly && !row.Absent &&
                state.PrivateEndpoint!.Connection is null && (id == parent.Id || id == endpoint.Id && parent.CreateAttempted && parent.InvocationTerminated);
        if (row.DeleteAttempted || !state.PrivateConnectionCleanupEligible) return false;
        if (id == endpoint.Id) return endpoint.CreateAttempted && endpoint.InvocationTerminated && state.PrivateEndpoint!.Connection is not null;
        return state.PrivateEndpointAbsent && (id == parent.Id && parent.CreateAttempted || id == state.Resources[2].Id &&
            (!parent.CreateAttempted || parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty));
    }
    private static Snapshot PrivateUpdateIndependentFixtureBegin(Snapshot state, string id, bool delete, Guid dispatch)
    {
        var slot = state.PrivateEndpoint!;
        return state with
        {
            Resources = state.Resources.Select(r => r.Borrowed ? r : r.Id == id ? r with
            { CreateAttempted = r.CreateAttempted || !delete, DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false, ActiveDispatch = dispatch, Absent = false } : r with { Absent = false }).ToArray(),
            PrivateEndpoint = slot with
            {
                CreationDispatch = id == slot.Declaration.EndpointId && !delete ? dispatch : slot.CreationDispatch,
                DeletionDispatch = id == slot.Declaration.EndpointId && delete ? dispatch : slot.DeletionDispatch,
                NicAbsent = false, Connection = slot.Connection is null ? null : slot.Connection with { Absent = false }
            }
        };
    }
    private static Snapshot PrivateUpdateIndependentFixtureEnd(Snapshot state, string id, Guid dispatch, bool settled, string? connectionId)
    {
        var slot = state.PrivateEndpoint!;
        bool endpoint = id == slot.Declaration.EndpointId;
        return state with
        {
            Resources = state.Resources.Select(r => r.Id == id ? r with
                { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray(),
            PrivateEndpoint = !endpoint || !settled ? slot : slot with
            {
                CreationDispatch = Guid.Empty, DeletionDispatch = Guid.Empty,
                Connection = slot.Connection ?? new(connectionId!, false, CreateAttempted: true, InvocationTerminated: true)
            }
        };
    }
    private static Snapshot PrivateUpdateIndependentAbsenceImage(Snapshot state, bool final)
    {
        var slot = state.PrivateEndpoint!;
        var next = state with
        {
            Resources = state.Resources.Select(r => !r.Borrowed && (final || r.Id == slot.Declaration.EndpointId) ? r with { Absent = true } : r).ToArray(),
            PrivateEndpoint = slot with { NicAbsent = true, Connection = slot.Connection is null ? null : slot.Connection with { Absent = true } }
        };
        return SameStatusPrivateConnectionUpdateIndependentSnapshot(state, next) ? state : next;
    }

    internal Snapshot BeginStatusPrivateConnectionUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentFixtureAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId && admission is not null &&
                admission.Dispatch != Guid.Empty && admission.Validate(this, state) &&
                PrivateUpdateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete) &&
                admission.ResourceId != state.PrivateEndpoint!.Declaration.EndpointId);
            return PrivateUpdateIndependentFixtureBegin(state, admission.ResourceId, admission.Delete, admission.Dispatch);
        }, privateIndependent: true);
    internal Snapshot EndStatusPrivateConnectionUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId && drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var row = state.Resources.Single(r => r.Id == drain.ResourceId);
            Require(row.ActiveDispatch == drain.Dispatch && !row.InvocationTerminated);

            return PrivateUpdateIndependentFixtureEnd(state, drain.ResourceId, drain.Dispatch, drain.Settled, null);
        }, privateIndependent: true);
    internal Snapshot RecordStatusPrivateConnectionUpdateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.PrivateEndpointCleanupEligible && absence is not null && state.PrivateEndpointAbsent);
            if (absence.AcceptPostimage(this, state)) return state;
            Require(absence.Validate(this, state));
            return PrivateUpdateIndependentAbsenceImage(state, final: true);
        }, privateIndependent: true);

    internal Snapshot BeginStatusPrivateConnectionUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentFixtureAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId && admission is not null &&
                admission.Dispatch != Guid.Empty && admission.Validate(this, state) &&
                PrivateUpdateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete) &&
                admission.ResourceId == state.PrivateEndpoint!.Declaration.EndpointId);
            return PrivateUpdateIndependentFixtureBegin(state, admission.ResourceId, admission.Delete, admission.Dispatch);
        }, privateIndependent: true);
    internal Snapshot EndStatusPrivateConnectionUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId && drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var row = state.Resources.Single(r => r.Id == drain.ResourceId);
            Require(row.ActiveDispatch == drain.Dispatch && !row.InvocationTerminated);
            Require(!drain.Settled || state.PrivateEndpoint!.Connection is not null || !string.IsNullOrEmpty(drain.ConnectionId));
            return PrivateUpdateIndependentFixtureEnd(state, drain.ResourceId, drain.Dispatch, drain.Settled, drain.ConnectionId);
        }, privateIndependent: true);
    internal Snapshot RecordStatusPrivateConnectionUpdateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequirePrivateUpdateIndependentHistory(owner, selector);
            Require(state is not null && StatusPrivateConnectionUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.PrivateEndpointCleanupEligible && absence is not null );
            if (absence.AcceptPostimage(this, state)) return state;
            Require(absence.Validate(this, state));
            return PrivateUpdateIndependentAbsenceImage(state, final: false);
        }, privateIndependent: true);

    private static void ValidatePrivateUpdateIndependentState(Snapshot state, Snapshot? previous, ref int stage)
    {
        if (!VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(state.Selector)) return;
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && state.PrivateEndpoint is null &&
                state.Settings is null && state.DeleteVault is null && state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null &&
                state.RecoverVault is null && state.StatusVaultRecoverCancellationBaseline is null && state.StatusVaultUpdateCancellationBaseline is null &&
                state.NotificationAbsentCreate is null && state.StatusSucceededDeleteVault is null && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusPrivateConnectionUpdateIndependentRoot(state));
        var slot = state.PrivateEndpoint!;
        if (previous is null)
        {
            Require(!state.Closing && slot.Connection is null && !slot.NicAbsent && slot.CreationDispatch == Guid.Empty &&
                slot.DeletionDispatch == Guid.Empty && slot.ApprovalSettledDispatch == Guid.Empty &&
                state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(StatusPrivateConnectionUpdateIndependentRoot(previous) && previous.Owner == state.Owner && previous.Selector == state.Selector &&
            previous.LeaseId == state.LeaseId && (!previous.Closing || state.Closing));
        var old = previous.PrivateEndpoint!;
        bool Image(Snapshot expected) => SameStatusPrivateConnectionUpdateIndependentSnapshot(expected with { Revision = state.Revision }, state);
        if (Image(previous)) return;
        if (!previous.Closing && state.Closing && Image(previous with { Closing = true })) return;
        Require(previous.Closing == state.Closing && old.Declaration == slot.Declaration);
        if (old.Connection is { } child && slot.Connection is { } next && previous.Resources.SequenceEqual(state.Resources))
        {
            if (!child.SelectedAttempted && next.SelectedAttempted)
            {
                Require(!state.Closing && stage == 0 && previous.Idle && StatusPrivateConnectionReadyRows(previous) &&
                    next.ActiveDispatch != Guid.Empty && Image(previous with { PrivateEndpoint = old with { Connection = child with
                    { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = next.ActiveDispatch } } }));
                stage = 1;
                return;
            }
            if (child.SelectedAttempted && child.ActiveDispatch != Guid.Empty)
            {
                if (!child.InvocationTerminated && Image(previous with { PrivateEndpoint = old with { Connection = child with { InvocationTerminated = true } } }))
                { Require(stage is 1 or 3); stage = stage == 1 ? 2 : -1; return; }
                if (child.InvocationTerminated && Image(previous with { PrivateEndpoint = old with { Connection = child with { InvocationTerminated = false } } }))
                { Require(!state.Closing && stage == 2); stage = 3; return; }
                Require(!state.Closing && stage == 3 && !child.InvocationTerminated && Image(previous with { PrivateEndpoint = old with
                { ApprovalSettledDispatch = child.ActiveDispatch, Connection = child with { InvocationTerminated = true, ActiveDispatch = Guid.Empty } } }));
                stage = 4;
                return;
            }
        }
        if (previous.Idle)
        {
            var dispatches = state.Resources.Where(r => r.ActiveDispatch != Guid.Empty).ToArray();
            if (dispatches is [var started])
            {
                Require(PrivateUpdateIndependentFixtureAllowed(previous, started.Id, state.Closing) &&
                    Image(PrivateUpdateIndependentFixtureBegin(previous, started.Id, state.Closing, started.ActiveDispatch)));
                return;
            }
            Require(state.Closing && state.Idle && previous.PrivateConnectionCleanupEligible);
            if (Image(PrivateUpdateIndependentAbsenceImage(previous, false)))
            {
                Require(!previous.Resources[3].CreateAttempted || previous.Resources[3] is { DeleteAttempted: true, InvocationTerminated: true });
                return;
            }
            if (previous.PrivateEndpointAbsent && Image(PrivateUpdateIndependentAbsenceImage(previous, true))) return;
        }
        // Presence invalidation can revoke a tuple, including while a dispatch
        // is unresolved, but cannot grant absence or clear an active fence.
        var invalidated = previous with
        {
            Resources = previous.Resources.Select(r => r.Id == old.Declaration.EndpointId ? r with { Absent = false } : r).ToArray(),
            PrivateEndpoint = old with { NicAbsent = false, Connection = old.Connection is null ? null : old.Connection with { Absent = false } }
        };
        if (Image(invalidated) || previous.Resources.Where(r => !r.Borrowed).Any(row => Image(invalidated with
            { Resources = invalidated.Resources.Select(r => r.Id == row.Id ? r with { Absent = false } : r).ToArray() }))) return;
        var active = previous.Resources.Where(r => r.ActiveDispatch != Guid.Empty).ToArray();
        Require(active.Length == 1);
        var before = active[0];
        var ended = state.Resources.Single(r => r.Id == before.Id);
        Require(!before.InvocationTerminated && ended.InvocationTerminated &&
            (ended.ActiveDispatch == Guid.Empty || ended.ActiveDispatch == before.ActiveDispatch) &&
            Image(PrivateUpdateIndependentFixtureEnd(previous, before.Id, before.ActiveDispatch,
                ended.ActiveDispatch == Guid.Empty, slot.Connection?.Id)));
    }
    private static void ValidatePrivateUpdateIndependentFrame(byte[] payload)
    {
        using var document = JsonDocument.Parse(payload);
        var root = document.RootElement;
        Complete(root, "sequence", "previous", "state");
        var state = root.GetProperty("state");
        Fields(state, "owner", "selector", "leaseId", "closing", "resources", "privateEndpoint", "settings", "deleteVault", "purgeDeletedVault",
            "createOrUpdateVault", "recoverVault", "statusVaultRecoverCancellationBaseline", "statusVaultUpdateCancellationBaseline", "notificationAbsentCreate", "statusSucceededDeleteVault");
        Require(new[] { "owner", "selector", "leaseId", "closing", "resources" }.All(name => state.TryGetProperty(name, out _)));
        Complete(state.GetProperty("selector"), "scope", "operation", "variant", "case", "nonce");
        foreach (var row in state.GetProperty("resources").EnumerateArray()) Row(row);
        foreach (string name in new[] { "settings", "deleteVault", "purgeDeletedVault", "createOrUpdateVault", "recoverVault",
            "statusVaultRecoverCancellationBaseline", "statusVaultUpdateCancellationBaseline", "notificationAbsentCreate", "statusSucceededDeleteVault" })
            Require(!state.TryGetProperty(name, out var unrelated) || unrelated.ValueKind == JsonValueKind.Null);
        if (state.TryGetProperty("privateEndpoint", out var slot) && slot.ValueKind != JsonValueKind.Null)
        {
            Complete(slot, "declaration", "creationDispatch", "connection", "nicAbsent", "deletionDispatch", "approvalSettledDispatch", "originalUpdate", "originalDelete", "statusDeleteSettledDispatch");
            Complete(slot.GetProperty("declaration"), "vaultId", "endpointId", "borrowedSubnetId", "networkConnectionName", "expectedNicId", "ownerTagName", "ownerTagValue");
            Require((!slot.TryGetProperty("originalUpdate", out var update) || update.ValueKind == JsonValueKind.Null) &&
                (!slot.TryGetProperty("originalDelete", out var deletion) || deletion.ValueKind == JsonValueKind.Null));
            if (slot.TryGetProperty("connection", out var child) && child.ValueKind != JsonValueKind.Null) Row(child);
        }
        static void Row(JsonElement row) => Complete(row, "id", "borrowed", "createAttempted", "deleteAttempted", "activeDispatch", "absent", "cleanupOnly", "invocationTerminated", "selectedAttempted");
        static void Complete(JsonElement node, params string[] required)
        { Fields(node, required); Require(node.EnumerateObject().Count() == required.Length); }
        static void Fields(JsonElement node, params string[] allowed)
        {
            Require(node.ValueKind == JsonValueKind.Object);
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var field in node.EnumerateObject()) Require(names.Add(field.Name) && allowed.Contains(field.Name, StringComparer.Ordinal));
        }
    }

    internal static bool StatusPrivateConnectionUpdateRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(state.Selector) &&
        StatusPrivateConnectionRoot(state, delete: false);

    internal static bool StatusPrivateConnectionDeleteRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(state.Selector) &&
        StatusPrivateConnectionRoot(state, delete: true);

    internal static bool StatusPrivateConnectionDeleteSelectedRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(state.Selector) &&
        StatusPrivateConnectionRoot(state, delete: true);

    internal static bool StatusPrivateConnectionDeleteIndependentRoot(Snapshot state) =>
        VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(state.Selector) &&
        state.StatusSucceededDeleteVault is null && StatusPrivateConnectionRoot(state, delete: true);

    private static bool StatusPrivateConnectionRoot(Snapshot state, bool delete)
    {
        if (state.LeaseId == Guid.Empty || state.PrivateEndpoint is not
            { OriginalUpdate: null, OriginalDelete: null } slot || state.Resources.Length != 5 ||
            state.Settings is not null || state.DeleteVault is not null || state.PurgeDeletedVault is not null ||
            state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.StatusVaultRecoverCancellationBaseline is not null ||
            state.StatusVaultUpdateCancellationBaseline is not null || state.NotificationAbsentCreate is not null ||
            (delete ? slot.ApprovalSettledDispatch : slot.StatusDeleteSettledDispatch) != Guid.Empty) return false;
        Guid settlement = delete ? slot.StatusDeleteSettledDispatch : slot.ApprovalSettledDispatch;
        var d = slot.Declaration;
        string[] vault = d.VaultId.Split('/');
        if (vault.Length != 9 || vault[0].Length != 0 || vault[1] != "subscriptions" ||
            !Guid.TryParseExact(vault[2], "D", out var subscription) || subscription == Guid.Empty ||
            vault[3] != "resourceGroups" || vault[4].Length == 0 || vault[5] != "providers" ||
            vault[6] != "Microsoft.KeyVault" || vault[7] != "vaults" ||
            vault[8].Length != 24 || !vault[8].StartsWith("skv", StringComparison.Ordinal) ||
            !vault[8][3..].All(char.IsAsciiHexDigit)) return false;
        string group = "/subscriptions/" + vault[2] + "/resourceGroups/" + vault[4];
        if (d.EndpointId != group + "/providers/Microsoft.Network/privateEndpoints/" + vault[8] + "-pe" ||
            d.ExpectedNicId != group + "/providers/Microsoft.Network/networkInterfaces/" + vault[8] + "-nic" ||
            d.NetworkConnectionName != vault[8] + "-link" || d.OwnerTagName != "secretkit-fixture" ||
            d.OwnerTagValue != state.Selector.Nonce.ToString("N") ||
            state.Resources.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 5 ||
            state.Resources.Count(r => r.Id == d.VaultId && !r.Borrowed && !r.CleanupOnly) != 1 ||
            state.Resources.Count(r => r.Id == d.EndpointId && !r.Borrowed && !r.CleanupOnly) != 1 ||
            state.Resources.Count(r => r.Id == d.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                !r.Borrowed && r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted &&
                !r.InvocationTerminated && !r.SelectedAttempted && r.ActiveDispatch == Guid.Empty) != 1 ||
            state.Resources.Count(r => r.Id == d.BorrowedSubnetId && r.Borrowed && !r.CleanupOnly &&
                !r.CreateAttempted && !r.DeleteAttempted && !r.InvocationTerminated && !r.SelectedAttempted &&
                !r.Absent && r.ActiveDispatch == Guid.Empty) != 1) return false;
        var deleted = state.Resources.SingleOrDefault(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        string prefix = "/subscriptions/" + vault[2] + "/providers/Microsoft.KeyVault/locations/";
        if (deleted is null || !deleted.Id.StartsWith(prefix, StringComparison.Ordinal) ||
            deleted.Id[prefix.Length..].Split('/') is not [var location, "deletedVaults", var name] ||
            location.Length == 0 || name != vault[8] || deleted.Borrowed || !deleted.CleanupOnly ||
            deleted.CreateAttempted || deleted.SelectedAttempted || state.Resources.Any(r => r.SelectedAttempted))
            return false;
        try
        {
            PrivateEndpointResourceCollector.ValidateBinding(new(state.Selector, state.LeaseId, d.EndpointId,
                d.VaultId, d.BorrowedSubnetId, d.ExpectedNicId, d.NetworkConnectionName, location,
                d.OwnerTagName, d.OwnerTagValue));
        }
        catch (Exception) { return false; }
        var parent = state.Resources.Single(r => r.Id == d.VaultId);
        var endpoint = state.Resources.Single(r => r.Id == d.EndpointId);
        if (!state.Closing && state.Resources.Any(r => r.DeleteAttempted || r.Absent) ||
            state.Resources.Any(r => r.ActiveDispatch != Guid.Empty && !r.CreateAttempted && !r.DeleteAttempted) ||
            parent.DeleteAttempted && (!state.Closing || !parent.CreateAttempted) ||
            deleted.InvocationTerminated && !deleted.DeleteAttempted ||
            deleted.DeleteAttempted && (!state.Closing || parent.CreateAttempted &&
                (!parent.DeleteAttempted || !parent.InvocationTerminated || parent.ActiveDispatch != Guid.Empty)) ||
            (slot.CreationDispatch != Guid.Empty
                ? slot.Connection is not null || !endpoint.CreateAttempted || endpoint.DeleteAttempted ||
                    endpoint.ActiveDispatch != slot.CreationDispatch || slot.DeletionDispatch != Guid.Empty
                : slot.Connection is null
                    ? endpoint.CreateAttempted || endpoint.DeleteAttempted || endpoint.ActiveDispatch != Guid.Empty
                    : !endpoint.CreateAttempted || !parent.CreateAttempted ||
                        (slot.DeletionDispatch == Guid.Empty
                            ? endpoint.ActiveDispatch != Guid.Empty || !endpoint.InvocationTerminated
                            : !state.Closing || !endpoint.DeleteAttempted ||
                                endpoint.ActiveDispatch != slot.DeletionDispatch)))
            return false;
        if (slot.Connection is not { } child) return settlement == Guid.Empty;
        string childPrefix = d.VaultId + "/privateEndpointConnections/";
        if (!child.Id.StartsWith(childPrefix, StringComparison.Ordinal) ||
            child.Id[childPrefix.Length..] is not { Length: > 0 } childName || childName.Contains('/') ||
            child.Borrowed || child.CleanupOnly || !child.CreateAttempted ||
            child.DeleteAttempted != (delete && child.SelectedAttempted) ||
            slot.CreationDispatch != Guid.Empty) return false;
        return !child.SelectedAttempted
            ? settlement == Guid.Empty && child.ActiveDispatch == Guid.Empty && child.InvocationTerminated
            : settlement == Guid.Empty
                ? child.ActiveDispatch != Guid.Empty && !child.Absent && slot.DeletionDispatch == Guid.Empty &&
                    StatusPrivateConnectionReadyRows(state)
                : child.ActiveDispatch == Guid.Empty && child.InvocationTerminated;
    }

    private static void ValidateStatusPrivateConnectionUpdateState(Snapshot state, Snapshot? previous)
    {
        bool independentDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(state.Selector);
        bool selectedDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(state.Selector);
        bool delete = independentDelete || selectedDelete || VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(state.Selector);
        if (!delete)
            Require(state.PrivateEndpoint is null || state.PrivateEndpoint.StatusDeleteSettledDispatch == Guid.Empty);
        if (!delete && !VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(state.Selector)) return;
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.PrivateEndpoint is null && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(independentDelete ? StatusPrivateConnectionDeleteIndependentRoot(state) :
            selectedDelete ? StatusPrivateConnectionDeleteSelectedRoot(state) :
            delete ? StatusPrivateConnectionDeleteRoot(state) : StatusPrivateConnectionUpdateRoot(state));
        if (previous is null)
        {
            Require(!state.Closing && state.PrivateEndpoint is
            {
                Connection: null, NicAbsent: false, CreationDispatch: var creation,
                DeletionDispatch: var deletion, ApprovalSettledDispatch: var approval,
                StatusDeleteSettledDispatch: var statusDelete
            } &&
                creation == Guid.Empty && deletion == Guid.Empty && approval == Guid.Empty && statusDelete == Guid.Empty &&
                state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted && !r.InvocationTerminated &&
                    !r.SelectedAttempted && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(previous.Resources.Length == 5 && previous.LeaseId == state.LeaseId &&
            (!previous.Closing || state.Closing) &&
            previous.PrivateEndpoint!.Declaration == state.PrivateEndpoint!.Declaration &&
            previous.Resources.All(row => state.Resources.Any(next => next.Id == row.Id &&
                next.Borrowed == row.Borrowed && next.CleanupOnly == row.CleanupOnly &&
                (!row.CreateAttempted || next.CreateAttempted) && (!row.DeleteAttempted || next.DeleteAttempted))));
        if (independentDelete)
            Require(previous.Resources.All(row => state.Resources.Any(next => next.Id == row.Id &&
                (!row.DeleteAttempted ||
                    (next.ActiveDispatch == Guid.Empty || next.ActiveDispatch == row.ActiveDispatch) &&
                    (!row.InvocationTerminated || next.InvocationTerminated)))));
        var old = previous.PrivateEndpoint;
        var slot = state.PrivateEndpoint;
        if (old.Connection is { } child)
            Require(slot.Connection is { } next && child.Id == next.Id && (!child.SelectedAttempted || next.SelectedAttempted) &&
                (!child.DeleteAttempted || next.DeleteAttempted));
        Guid oldSettlement = delete ? old.StatusDeleteSettledDispatch : old.ApprovalSettledDispatch;
        Guid settlement = delete ? slot.StatusDeleteSettledDispatch : slot.ApprovalSettledDispatch;
        if (oldSettlement != Guid.Empty)
            Require(settlement == oldSettlement);
        else if (settlement != Guid.Empty)
            Require(!previous.Closing && !state.Closing && previous.Resources.SequenceEqual(state.Resources) &&
                old.Connection is { SelectedAttempted: true, InvocationTerminated: false } pending &&
                pending.ActiveDispatch == settlement && slot.Connection ==
                    (pending with { ActiveDispatch = Guid.Empty, InvocationTerminated = true }));
        if (old.Connection is { SelectedAttempted: true, ActiveDispatch: var active } && active != Guid.Empty &&
            settlement == Guid.Empty)
            Require(slot.Connection!.ActiveDispatch == active && previous.Resources.SequenceEqual(state.Resources));
    }

    internal Guid BeginStatusPrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteCancellationAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                leaseId != Guid.Empty && StatusPrivateConnectionDeleteRoot(state) &&
                admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
                slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
                {
                    CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                    DeleteAttempted: false, Absent: false
                } && StatusPrivateConnectionReadyRows(state));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with
                    {
                        SelectedAttempted = true,
                        DeleteAttempted = true,
                        ActiveDispatch = dispatch,
                        InvocationTerminated = false
                    }
                }
            };
        });
        return dispatch;
    }

    internal void CheckStatusPrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && !state.PrivateEndpoint!.Connection!.InvocationTerminated);
            return state;
        });

    internal Snapshot EndStatusPrivateConnectionDeleteInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteDispatch(state, leaseId, declaration, connectionId, dispatch);
            var slot = state!.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = true } }
            };
        });

    internal void AdmitStatusPrivateConnectionDeleteRead(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && state.PrivateEndpoint!.Connection!.InvocationTerminated);
            var slot = state.PrivateEndpoint;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = false } }
            };
        });

    internal Snapshot CompleteStatusPrivateConnectionDeleteCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            RequireStatusPrivateConnectionDeleteDispatch(state, leaseId, slot.Declaration, slot.Connection!.Id, dispatch);
            Require(!slot.Connection.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { InvocationTerminated = true, ActiveDispatch = Guid.Empty },
                    StatusDeleteSettledDispatch = dispatch
                }
            };
        });

    private static void RequireStatusPrivateConnectionDeleteDispatch(Snapshot? state, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Require(state is not null && StatusPrivateConnectionDeleteRoot(state) && leaseId != Guid.Empty &&
            state.LeaseId == leaseId && state.PrivateEndpoint is { } slot && slot.Declaration == declaration &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
            { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: true, Absent: false } child &&
            child.Id == connectionId && dispatch != Guid.Empty && child.ActiveDispatch == dispatch &&
            StatusPrivateConnectionReadyRows(state));

    internal Guid BeginStatusPrivateConnectionDeleteSelectedInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteSelectedAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                leaseId != Guid.Empty && StatusPrivateConnectionDeleteSelectedRoot(state) &&
                admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
                slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
                {
                    CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                    DeleteAttempted: false, Absent: false
                } && StatusPrivateConnectionReadyRows(state));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with
                    {
                        SelectedAttempted = true,
                        DeleteAttempted = true,
                        ActiveDispatch = dispatch,
                        InvocationTerminated = false
                    }
                }
            };
        });
        return dispatch;
    }

    internal void CheckStatusPrivateConnectionDeleteSelectedInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteSelectedDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && !state.PrivateEndpoint!.Connection!.InvocationTerminated);
            return state;
        });

    internal Snapshot EndStatusPrivateConnectionDeleteSelectedInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteSelectedDispatch(state, leaseId, declaration, connectionId, dispatch);
            var slot = state!.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = true } }
            };
        });

    internal void AdmitStatusPrivateConnectionDeleteSelectedRead(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteSelectedDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && state.PrivateEndpoint!.Connection!.InvocationTerminated);
            var slot = state.PrivateEndpoint;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = false } }
            };
        });

    internal Snapshot CompleteStatusPrivateConnectionDeleteSelectedRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteSelectedSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            RequireStatusPrivateConnectionDeleteSelectedDispatch(state, leaseId, slot.Declaration, slot.Connection!.Id, dispatch);
            Require(!slot.Connection.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { InvocationTerminated = true, ActiveDispatch = Guid.Empty },
                    StatusDeleteSettledDispatch = dispatch
                }
            };
        });

    private static void RequireStatusPrivateConnectionDeleteSelectedDispatch(Snapshot? state, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Require(state is not null && StatusPrivateConnectionDeleteSelectedRoot(state) && leaseId != Guid.Empty &&
            state.LeaseId == leaseId && state.PrivateEndpoint is { } slot && slot.Declaration == declaration &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
            { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: true, Absent: false } child &&
            child.Id == connectionId && dispatch != Guid.Empty && child.ActiveDispatch == dispatch &&
            StatusPrivateConnectionReadyRows(state));

    internal Guid BeginStatusPrivateConnectionDeleteIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteIndependentAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Idle && state.LeaseId == leaseId &&
                leaseId != Guid.Empty && StatusPrivateConnectionDeleteIndependentRoot(state) &&
                admission is not null && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            Require(slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
                slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
                {
                    CreateAttempted: true, InvocationTerminated: true, SelectedAttempted: false,
                    DeleteAttempted: false, Absent: false
                } && StatusPrivateConnectionReadyRows(state));
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with
                    {
                        SelectedAttempted = true,
                        DeleteAttempted = true,
                        ActiveDispatch = dispatch,
                        InvocationTerminated = false
                    }
                }
            };
        });
        return dispatch;
    }

    internal void CheckStatusPrivateConnectionDeleteIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteIndependentDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && !state.PrivateEndpoint!.Connection!.InvocationTerminated);
            return state;
        });

    internal Snapshot EndStatusPrivateConnectionDeleteIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequireStatusPrivateConnectionDeleteIndependentDispatch(state, leaseId, declaration, connectionId, dispatch);
            var slot = state!.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = true } }
            };
        });

    internal void AdmitStatusPrivateConnectionDeleteIndependentRead(string owner, FixtureSelector selector, Guid leaseId,
        Guid dispatch, ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && admission is not null && admission.Dispatch == dispatch && admission.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            RequireStatusPrivateConnectionDeleteIndependentDispatch(state, leaseId, slot.Declaration, slot.Connection!.Id, dispatch);
            Require(!state.Closing && slot.Connection.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with { Connection = slot.Connection! with { InvocationTerminated = false } }
            };
        });

    internal Snapshot CompleteStatusPrivateConnectionDeleteIndependentRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusPrivateConnectionDeleteIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            RequireStatusPrivateConnectionDeleteIndependentDispatch(state, leaseId, slot.Declaration, slot.Connection!.Id, dispatch);
            Require(!slot.Connection.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection with { InvocationTerminated = true, ActiveDispatch = Guid.Empty },
                    StatusDeleteSettledDispatch = dispatch
                }
            };
        });

    private static void RequireStatusPrivateConnectionDeleteIndependentDispatch(Snapshot? state, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Require(state is not null && StatusPrivateConnectionDeleteIndependentRoot(state) && leaseId != Guid.Empty &&
            state.LeaseId == leaseId && state.PrivateEndpoint is { } slot && slot.Declaration == declaration &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.StatusDeleteSettledDispatch == Guid.Empty && slot.Connection is
            { CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: true, Absent: false } child &&
            child.Id == connectionId && dispatch != Guid.Empty && child.ActiveDispatch == dispatch &&
            StatusPrivateConnectionReadyRows(state));

    internal void CheckPrivateConnectionApproval(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequirePrivateConnectionDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && !state.PrivateEndpoint!.Connection!.InvocationTerminated);
            return state;
        });

    // Actual drain is not remote settlement, including after Close has won.
    internal Snapshot EndPrivateConnectionApprovalInvocation(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequirePrivateConnectionDispatch(state, leaseId, declaration, connectionId, dispatch);
            var slot = state!.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection! with { InvocationTerminated = true }
                }
            };
        });

    internal void AdmitPrivateConnectionApprovalStatus(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            RequirePrivateConnectionDispatch(state, leaseId, declaration, connectionId, dispatch);
            Require(!state!.Closing && state.PrivateEndpoint!.Connection!.InvocationTerminated);
            var slot = state.PrivateEndpoint;
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection! with { InvocationTerminated = false }
                }
            };
        });

    internal Snapshot SettlePrivateConnectionApproval(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.PrivateConnectionApprovalSettlement candidate) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                candidate is not null && candidate.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            var child = slot.Connection!;
            RequirePrivateConnectionDispatch(state, leaseId, slot.Declaration, child.Id, candidate.Dispatch);
            Require(child.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = child with { ActiveDispatch = Guid.Empty },
                    ApprovalSettledDispatch = candidate.Dispatch
                }
            };
        });

    private static void RequirePrivateConnectionDispatch(Snapshot? state, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
            state.Selector.Operation == ManagementOperationEffects.Members[0].Operation &&
            state.Selector.Variant == "operation.UpdatePrivateConnection" && state.Selector.Case == "selected-contract" &&
            state.PrivateEndpoint is { OriginalUpdate: null, OriginalDelete: null } slot && slot.Declaration == declaration &&
            slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == Guid.Empty &&
            slot.ApprovalSettledDispatch == Guid.Empty &&
            slot.Connection is
            {
                CreateAttempted: true, SelectedAttempted: true, DeleteAttempted: false,
                Borrowed: false, CleanupOnly: false, Absent: false
            } child &&
            child.Id == connectionId && dispatch != Guid.Empty && child.ActiveDispatch == dispatch &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted) &&
            state.Resources.Single(r => r.Id == declaration.EndpointId) is
            { CreateAttempted: true, DeleteAttempted: false, InvocationTerminated: true, Absent: false });

    internal Guid BeginPrivateConnectionRead(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.PrivateConnectionReadAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            RequirePrivateConnectionRead(state, leaseId, admission, Guid.Empty);
            Require(!state!.Closing && state.Idle && state.PrivateEndpoint!.Connection!.InvocationTerminated);
            var slot = state.PrivateEndpoint!;
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection! with { ActiveDispatch = dispatch, InvocationTerminated = false }
                }
            };
        });
        return dispatch;
    }

    internal void CheckPrivateConnectionRead(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.PrivateConnectionReadAdmission admission, Guid dispatch)
    {
        var snapshot = Read(owner, selector);
        Require(dispatch != Guid.Empty);
        RequirePrivateConnectionRead(snapshot, leaseId, admission, dispatch);
        Require(!snapshot.Closing && !snapshot.PrivateEndpoint!.Connection!.InvocationTerminated);
    }

    // Only the originally registered read can drain after Close. No mutation
    // marker or setup/delete fence is cleared by this transition.
    internal void EndPrivateConnectionRead(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.PrivateConnectionReadAdmission admission, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            Require(dispatch != Guid.Empty);
            RequirePrivateConnectionRead(state, leaseId, admission, dispatch);
            Require(admission.ValidateDrain(this, state!, dispatch));
            var slot = state!.PrivateEndpoint!;
            Require(!slot.Connection!.InvocationTerminated);
            return state with
            {
                PrivateEndpoint = slot with
                {
                    Connection = slot.Connection! with { ActiveDispatch = Guid.Empty, InvocationTerminated = true }
                }
            };
        });

    private void RequirePrivateConnectionRead(Snapshot? state, Guid leaseId,
        VaultFixtureProvisioner.PrivateConnectionReadAdmission admission, Guid dispatch) =>
        Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
            admission is not null && admission.Validate(this, state) &&
            VaultFixtureProvisioner.PrivateConnectionReadSelector(state.Selector) &&
            state.PrivateEndpoint is
            {
                OriginalUpdate: null, OriginalDelete: null,
                CreationDispatch: var creation, DeletionDispatch: var deletion,
                ApprovalSettledDispatch: var approval, Connection: { } child
            } &&
            creation == Guid.Empty && deletion == Guid.Empty && approval == Guid.Empty &&
            child is
            {
                CreateAttempted: true, SelectedAttempted: false, DeleteAttempted: false,
                Borrowed: false, CleanupOnly: false, Absent: false
            } &&
            child.ActiveDispatch == dispatch &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent) &&
            state.Resources.Single(r => r.Id == state.PrivateEndpoint.Declaration.EndpointId) is
            { CreateAttempted: true, InvocationTerminated: true } &&
            state.Resources.Single(r => r.Id == state.PrivateEndpoint.Declaration.VaultId) is
            { CreateAttempted: true, InvocationTerminated: true } &&
            state.Resources.Single(r => r.Id == state.PrivateEndpoint.Declaration.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary) is
            { CreateAttempted: true, CleanupOnly: false, InvocationTerminated: true });

    internal Guid BeginSelectedRead(string owner, FixtureSelector selector, Guid leaseId, string resourceId)
    {
        Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && !VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) &&
                state.StatusSucceededDeleteVault is null &&
                !NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) &&
                !NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) &&
                !NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector) &&
                !VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) &&
                !NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) &&
                !RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) &&
                !IsSettings(selector) && !VaultFixtureProvisioner.DeleteVaultSelector(selector) &&
                !VaultFixtureProvisioner.PurgeDeletedVaultSelector(selector) &&
                state.CreateOrUpdateVault is null && state.RecoverVault is null &&
                state.LeaseId == leaseId && leaseId != Guid.Empty &&
                !state.Closing && state.Idle && state.PrivateEndpoint is null);
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Resource row = rows[index];
            Require(!row.Borrowed && row.CreateAttempted && !row.DeleteAttempted && !row.Absent &&
                !row.CleanupOnly && !row.SelectedAttempted);
            rows[index] = row with { ActiveDispatch = dispatch, InvocationTerminated = false };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    // Admit only observation of this retained invocation. Reusing its dispatch
    // keeps Close/release fenced while the newly admitted status borrower runs.
    internal void AdmitStatusRead(string owner, FixtureSelector selector, Guid leaseId, string resourceId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
            Require(state is not null && !IsSettings(selector) && !VaultFixtureProvisioner.DeleteVaultSelector(selector) &&
                state.StatusSucceededDeleteVault is null &&
                !NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) &&
                !VaultFixtureProvisioner.PurgeDeletedVaultSelector(selector) &&
                state.CreateOrUpdateVault is null && state.RecoverVault is null &&
                leaseId != Guid.Empty && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && state.PrivateEndpoint is null);
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Resource row = rows[index];
            Require(!row.Borrowed && !row.CleanupOnly && row.ActiveDispatch == dispatch &&
                row.InvocationTerminated && rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty));
            if (RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector))
                Require(StatusRoleDeleteRoot(state) && row.SelectedAttempted && row.CreateAttempted &&
                    !row.DeleteAttempted && !row.Absent &&
                    row.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal) &&
                    rows.Where((_, i) => i != index).All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                        (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                            r.CreateAttempted && r.InvocationTerminated)));
            Require(!VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                state.StatusVaultRecoverCancellationBaseline is not null && row.SelectedAttempted &&
                !row.DeleteAttempted && !row.Absent && row.Id.Contains("/vaults/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent));
            Require(!VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
                state.StatusVaultUpdateCancellationBaseline is not null && row.SelectedAttempted &&
                !row.DeleteAttempted && !row.Absent && row.Id.Contains("/vaults/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.CleanupOnly && !r.CreateAttempted &&
                    !r.SelectedAttempted && !r.DeleteAttempted && !r.InvocationTerminated && !r.Absent));
            if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector))
                Require(StatusNotificationDeleteRoot(state) && row.SelectedAttempted && row.CreateAttempted &&
                    !row.DeleteAttempted && !row.Absent &&
                    row.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                    rows.Where((_, i) => i != index).All(r => !r.SelectedAttempted && !r.DeleteAttempted &&
                        !r.Absent && (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                            r.CreateAttempted && r.InvocationTerminated)));
            if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector))
                Require(StatusNotificationUpdateRoot(state) && row.SelectedAttempted && row.CreateAttempted &&
                    !row.DeleteAttempted && !row.Absent &&
                    row.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                    rows.Where((_, i) => i != index).All(r => !r.SelectedAttempted && !r.DeleteAttempted &&
                        !r.Absent && (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                            r.CreateAttempted && r.InvocationTerminated)));
            if (NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
                Require(StatusNotificationCreateRoot(state) && row.SelectedAttempted && row.CreateAttempted &&
                    !row.DeleteAttempted && !row.Absent &&
                    row.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                    rows.Where((_, i) => i != index).All(r => !r.SelectedAttempted && !r.DeleteAttempted &&
                        !r.Absent && (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                            r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = row with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusVaultDeleteCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusVaultDeleteCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) &&
                leaseId != Guid.Empty && state.LeaseId == leaseId && dispatch != Guid.Empty &&
                state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
                state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
                state.Resources.Length == 3 && state.Resources.All(r => !r.Borrowed) &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false
            } &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                    !r.InvocationTerminated));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusVaultPurgeCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusVaultPurgeCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) &&
                leaseId != Guid.Empty && state.LeaseId == leaseId && dispatch != Guid.Empty &&
                state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
                state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
                state.Resources.Length == 3 && state.Resources.All(r => !r.Borrowed) &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false
            } &&
                rows[index].Id.Contains("/deletedVaults/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted) &&
                rows.Count(r => !r.CleanupOnly && r.CreateAttempted && r.InvocationTerminated) == 1 &&
                rows.Count(r => r.CleanupOnly && !r.CreateAttempted && !r.InvocationTerminated) == 1);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusVaultRecoverCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusVaultRecoverCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) &&
                state.StatusVaultRecoverCancellationBaseline is not null &&
                leaseId != Guid.Empty && state.LeaseId == leaseId && dispatch != Guid.Empty &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains("/vaults/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent) &&
                rows.Count(r => !r.CleanupOnly && r.CreateAttempted && r.InvocationTerminated) == 1);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusVaultUpdateCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusVaultUpdateCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) &&
                state.StatusVaultUpdateCancellationBaseline is not null &&
                leaseId != Guid.Empty && state.LeaseId == leaseId && dispatch != Guid.Empty &&
                completion is not null && completion.Dispatch == dispatch && completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains("/vaults/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    r.CleanupOnly && !r.CreateAttempted && !r.InvocationTerminated &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot DeclareNotificationAbsentCreate(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.ExclusiveCreationRegistration declaration) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                StatusNotificationCreateRoot(state) && state.NotificationAbsentCreate is null &&
                !state.Closing && declaration is not null && declaration.Validate(this, state) &&
                state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                    !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return state with { NotificationAbsentCreate = declaration.State };
        });

    internal Guid BeginStatusNotificationAbsentCreateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationCreateCancellationAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            var creation = state?.NotificationAbsentCreate ?? throw Failure();
            Require(state is not null && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                StatusNotificationCreateRoot(state) &&
                creation.InvocationDispatch == Guid.Empty && !state.Closing && state.Idle &&
                admission is not null && admission.Validate(this, state) &&
                admission.AbsentCreate is { } frozen && frozen == creation &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.Id == creation.ParentId ? r.CreateAttempted && r.InvocationTerminated :
                        !r.CreateAttempted && !r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Index(rows, creation.ChildId);
            rows[index] = rows[index] with
            {
                CreateAttempted = true,
                SelectedAttempted = true,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with
            {
                Resources = rows,
                NotificationAbsentCreate = creation with
                {
                    InvocationDispatch = dispatch,
                    BaselineSha256 = admission.BaselineSha256
                }
            };
        });
        return dispatch;
    }

    internal Snapshot CompleteStatusNotificationAbsentCreateCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationCreateCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            var creation = state?.NotificationAbsentCreate ?? throw Failure();
            Require(state is not null && !state.Closing && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                StatusNotificationCreateRoot(state) &&
                dispatch != Guid.Empty && creation.InvocationDispatch == dispatch &&
                creation.SettledDispatch == Guid.Empty && completion is not null &&
                completion.Dispatch == dispatch && completion.Validate(this, state));
            var settled = completion.AbsentCreate ?? throw Failure();
            Require(settled.InvocationDispatch == dispatch &&
                settled.SettledDispatch == dispatch && settled.NamespaceEpoch == creation.NamespaceEpoch &&
                settled.ParentId == creation.ParentId && settled.ChildId == creation.ChildId &&
                settled.ContractVersion == creation.ContractVersion && settled.BaselineSha256 == creation.BaselineSha256);
            var rows = state.Resources.ToArray();
            int index = Index(rows, creation.ChildId);
            Require(rows[index] is
            {
                CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, Absent: false, InvocationTerminated: false
            } &&
                rows[index].ActiveDispatch == dispatch &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows, NotificationAbsentCreate = settled };
        });

    internal Guid BeginStatusNotificationCreateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationCreateCancellationAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Owner == owner && state.Selector == selector &&
                StatusNotificationCreateRoot(state) && state.NotificationAbsentCreate is null &&
                state.LeaseId == leaseId && leaseId != Guid.Empty &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix,
                StringComparison.Ordinal));
            rows[index] = rows[index] with
            {
                SelectedAttempted = true,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal Snapshot CompleteStatusNotificationCreateCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationCreateCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                StatusNotificationCreateRoot(state) && state.NotificationAbsentCreate is null &&
                leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch &&
                completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Guid BeginStatusNotificationUpdateInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateCancellationAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Owner == owner && state.Selector == selector &&
                StatusNotificationUpdateRoot(state) && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix,
                StringComparison.Ordinal));
            rows[index] = rows[index] with
            {
                SelectedAttempted = true,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal Snapshot CompleteStatusNotificationUpdateCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                StatusNotificationUpdateRoot(state) && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch &&
                completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Guid BeginStatusNotificationDeleteIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationDeleteIndependentAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Owner == owner && state.Selector == selector &&
                StatusNotificationDeleteIndependentRoot(state) && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Index(rows, admission.ResourceId);
            Require(rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                !rows[index].CleanupOnly);
            rows[index] = rows[index] with
            {
                SelectedAttempted = true,
                CreateAttempted = true,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
        return dispatch;
    }

    internal void AdmitStatusNotificationDeleteIndependentRead(string owner, FixtureSelector selector, Guid leaseId,
        Guid dispatch, ManagementOperationFixtureObserverService.StatusNotificationDeleteIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                StatusNotificationDeleteIndependentRoot(state) && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && admission is not null && admission.Dispatch == dispatch &&
                admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: true, Absent: false
            } &&
                rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusNotificationDeleteIndependentRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch, ManagementOperationFixtureObserverService.StatusNotificationDeleteIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                StatusNotificationDeleteIndependentRoot(state) && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch &&
                completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusNotificationDeleteCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationDeleteCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) &&
                StatusNotificationDeleteRoot(state) && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch &&
                completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusNotificationUpdateIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateIndependentAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Index(rows, admission.ResourceId);
            Require(rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                !rows[index].Borrowed && !rows[index].CleanupOnly);
            rows[index] = rows[index] with { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = dispatch };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationUpdateIndependentStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateIndependentStartDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && drain is not null && drain.Dispatch == dispatch);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot AdmitStatusNotificationUpdateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && admission is not null && admission.Dispatch == dispatch &&
                admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusNotificationUpdateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationUpdateIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch);
            if (completion.AcceptPostimage(this, state)) return state;
            Require(completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusNotificationUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentFixtureAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                admission is not null && admission.Validate(this, state) &&
                NotificationUpdateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete));
            var rows = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, admission.ResourceId);
            rows[index] = rows[index] with
            {
                CreateAttempted = rows[index].CreateAttempted || !admission.Delete,
                DeleteAttempted = rows[index].DeleteAttempted || admission.Delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated &&
                (!rows[index].SelectedAttempted || state.Closing && rows[index].DeleteAttempted));
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal Snapshot RecordStatusNotificationUpdateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.Closing && state.Idle && absence is not null && !absence.Final && absence.Validate(this, state) &&
                state.Resources.Any(r => r.Id == absence.ResourceId && r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)));
            var rows = state.Resources.Select(r => !r.Borrowed && (absence.Final || r.Id == absence.ResourceId)
                ? r with { Absent = true } : r).ToArray();
            if (rows.SequenceEqual(state.Resources)) return state;
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusNotificationUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationUpdateIndependentFixtureAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                admission is not null && admission.Validate(this, state) &&
                NotificationUpdateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete));
            var rows = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, admission.ResourceId);
            rows[index] = rows[index] with
            {
                CreateAttempted = rows[index].CreateAttempted || !admission.Delete,
                DeleteAttempted = rows[index].DeleteAttempted || admission.Delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationUpdateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationUpdateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated &&
                (!rows[index].SelectedAttempted || state.Closing && rows[index].DeleteAttempted));
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal Snapshot RecordStatusNotificationUpdateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationUpdateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequireNotificationUpdateIndependentHistory(selector);
            Require(state is not null && StatusNotificationUpdateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.Closing && state.Idle && absence is not null && absence.Final && absence.Validate(this, state) &&
                state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)).Absent &&
                state.Resources.Any(r => r.Id == absence.ResourceId && !r.CleanupOnly &&
                    !r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)));
            var rows = state.Resources.Select(r => !r.Borrowed && (absence.Final || r.Id == absence.ResourceId)
                ? r with { Absent = true } : r).ToArray();
            if (rows.SequenceEqual(state.Resources)) return state;
            return state with { Resources = rows };
        });

    private static bool NotificationUpdateIndependentFixtureAllowed(Snapshot state, string id, bool delete)
    {
        if (!StatusNotificationUpdateIndependentRoot(state) || !state.Idle || state.Closing != delete) return false;
        var child = state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        string vaultId = child.Id[..child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)];
        var vault = state.Resources.Single(r => r.Id == vaultId);
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        var row = state.Resources.SingleOrDefault(r => r.Id == id);
        if (row is null || row.Borrowed || row.Absent || row.ActiveDispatch != Guid.Empty) return false;
        if (!delete)
            return !state.Resources.Any(r => r.SelectedAttempted) && !row.CreateAttempted && !row.CleanupOnly &&
                (id == vault.Id || id == child.Id && vault.CreateAttempted && vault.InvocationTerminated);
        if (row.DeleteAttempted) return false;
        if (id == child.Id) return child.CreateAttempted;
        return child.Absent && child.ActiveDispatch == Guid.Empty &&
            (id == vault.Id && vault.CreateAttempted || id == marker.Id &&
                (!vault.CreateAttempted || vault.DeleteAttempted && vault.InvocationTerminated && vault.ActiveDispatch == Guid.Empty));
    }

    internal static bool SameStatusNotificationUpdateIndependentSnapshot(Snapshot expected, Snapshot actual) =>
        expected is not null && actual is not null && StatusNotificationUpdateIndependentRoot(expected) &&
        StatusNotificationUpdateIndependentRoot(actual) && expected.Resources.SequenceEqual(actual.Resources) &&
        (actual with { Resources = expected.Resources }) == expected;

    internal static bool StatusNotificationUpdateIndependentRoot(Snapshot state)
    {
        if (state is null || state.Resources is not { Length: 4 } ||
            state.Resources.Any(r => r is null || string.IsNullOrEmpty(r.Id)) ||
            !NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(state.Selector) ||
            state.NotificationAbsentCreate is not null || state.StatusSucceededDeleteVault is not null ||
            state.Resources.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4 || !StatusNotificationRoot(state)) return false;
        var child = state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        int split = child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal);
        string[] vault = child.Id[..split].Split('/');
        string name = child.Id[(split + VaultFixtureProvisioner.NotificationPrefix.Length)..];
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        string[] deleted = marker.Id.Split('/');
        return IndependentSegment(vault[4], 90) && vault[8].Length == 24 &&
            vault[8].StartsWith("skv", StringComparison.Ordinal) && vault[8][3..].All(char.IsAsciiHexDigit) &&
            name.Length == 36 && name.StartsWith("skn-", StringComparison.Ordinal) && name[4..].All(char.IsAsciiHexDigit) &&
            IndependentSegment(deleted[6], 50);
    }

    private void RequireNotificationUpdateIndependentHistory(FixtureSelector selector)
    {
        if (invalidNotificationUpdateIndependentHistory.Contains(selector.Nonce))
            throw new StatusNotificationUpdateIndependentHistoryException();
    }

    private static void ValidateStatusNotificationUpdateIndependentState(Snapshot state, Snapshot? previous, ref int stage)
    {
        if (!NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(state.Selector)) return;
        Require(state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            state.NotificationAbsentCreate is null && state.StatusSucceededDeleteVault is null &&
            state.StatusVaultRecoverCancellationBaseline is null && state.StatusVaultUpdateCancellationBaseline is null);
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusNotificationUpdateIndependentRoot(state));
        var child = state.Resources.Single(r => !r.Borrowed &&
            r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        string parentId = child.Id[..child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)];
        var parent = state.Resources.Single(r => r.Id == parentId);
        var secret = state.Resources.Single(r => r.Id == parentId + "/secrets/" + VaultFixtureProvisioner.Canary);
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        Require(state.Resources.Count(r => r.ActiveDispatch != Guid.Empty) <= 1 &&
            state.Resources.All(r => (!r.Absent || state.Closing) && (r.ActiveDispatch == Guid.Empty || !r.Absent) &&
                (!r.SelectedAttempted || r.Id == child.Id)) &&
            !secret.CreateAttempted && !secret.DeleteAttempted && !secret.InvocationTerminated && secret.ActiveDispatch == Guid.Empty && !marker.CreateAttempted &&
            (!child.SelectedAttempted || child.CreateAttempted && parent.CreateAttempted) &&
            (!child.DeleteAttempted || state.Closing && child.CreateAttempted) &&
            (!parent.DeleteAttempted || state.Closing && parent.CreateAttempted) &&
            (!marker.DeleteAttempted || state.Closing && (!parent.CreateAttempted ||
                parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty)));
        if (previous is null)
        {
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(StatusNotificationUpdateIndependentRoot(previous) && previous.Owner == state.Owner &&
            previous.Selector == state.Selector && previous.LeaseId == state.LeaseId &&
            (!previous.Closing || state.Closing) && previous.Resources.Select(r => r.Id).SequenceEqual(state.Resources.Select(r => r.Id)));
        bool Rows(Resource[] expected) => expected.SequenceEqual(state.Resources);
        if (Rows(previous.Resources)) return; // Close or a read-only transaction.
        Require(previous.Closing == state.Closing);
        var beforeChild = previous.Resources.Single(r => r.Id == child.Id);
        if (!previous.Closing && !beforeChild.SelectedAttempted && child.SelectedAttempted)
        {
            Require(stage == 0 && previous.Idle && child.ActiveDispatch != Guid.Empty &&
                previous.Resources.All(r => !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)) &&
                Rows(previous.Resources.Select(r => r.Id == child.Id ? r with
                { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = child.ActiveDispatch } : r).ToArray()));
            stage = 1;
            return;
        }
        if (beforeChild.SelectedAttempted && !beforeChild.DeleteAttempted && beforeChild.ActiveDispatch != Guid.Empty)
        {
            Require(previous.Resources.Where(r => r.Id != child.Id).SequenceEqual(state.Resources.Where(r => r.Id != child.Id)) &&
                !parent.DeleteAttempted && !marker.DeleteAttempted && state.Resources.All(r => !r.Absent));
            if (!beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = true }))
            {
                Require(stage is 1 or 3);
                stage = stage == 1 ? 2 : -1;
                return;
            }
            if (beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = false }))
            {
                Require(!state.Closing && stage == 2);
                stage = 3;
                return;
            }
            Require(!state.Closing && stage == 3 && !beforeChild.InvocationTerminated &&
                child == (beforeChild with { InvocationTerminated = true, ActiveDispatch = Guid.Empty }));
            stage = 4;
            return;
        }
        if (previous.Idle)
        {
            var started = state.Resources.Where(r => r.ActiveDispatch != Guid.Empty).ToArray();
            if (started is [var row])
            {
                bool delete = state.Closing;
                Require(NotificationUpdateIndependentFixtureAllowed(previous, row.Id, delete) &&
                    Rows(previous.Resources.Select(r => r.Borrowed ? r : r.Id == row.Id ? r with
                    {
                        Absent = false,
                        CreateAttempted = r.CreateAttempted || !delete,
                        DeleteAttempted = r.DeleteAttempted || delete,
                        ActiveDispatch = row.ActiveDispatch,
                        InvocationTerminated = false
                    } : r with { Absent = false }).ToArray()));
                return;
            }
            Require(state.Closing && state.Idle);
            bool absent = Rows(previous.Resources.Select(r => r.Id == child.Id ? r with { Absent = true } : r).ToArray()) ||
                Rows(previous.Resources.Select(r => r.Borrowed ? r : r with { Absent = true }).ToArray());
            bool present = previous.Resources.Where(r => !r.Borrowed && r.Absent).Any(row =>
                Rows(previous.Resources.Select(r => r.Id == row.Id ? r with { Absent = false } : r).ToArray()));
            Require(absent || present);
            return;
        }
        var active = previous.Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        var ended = state.Resources.Single(r => r.Id == active.Id);
        Require((!active.SelectedAttempted || previous.Closing && active.DeleteAttempted) && !active.InvocationTerminated && ended.InvocationTerminated &&
            (ended.ActiveDispatch == Guid.Empty || ended.ActiveDispatch == active.ActiveDispatch) &&
            Rows(previous.Resources.Select(r => r.Id == active.Id ? r with
            { InvocationTerminated = true, ActiveDispatch = ended.ActiveDispatch } : r).ToArray()));
    }


    internal Snapshot BeginStatusNotificationCreateIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        ManagementOperationFixtureObserverService.StatusNotificationCreateIndependentAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Index(rows, admission.ResourceId);
            Require(rows[index].Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal) &&
                !rows[index].Borrowed && !rows[index].CleanupOnly);
            rows[index] = rows[index] with { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = dispatch };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationCreateIndependentStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationCreateIndependentStartDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && drain is not null && drain.Dispatch == dispatch);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot AdmitStatusNotificationCreateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationCreateIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && admission is not null && admission.Dispatch == dispatch &&
                admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusNotificationCreateIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        ManagementOperationFixtureObserverService.StatusNotificationCreateIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch);
            if (completion.AcceptPostimage(this, state)) return state;
            Require(completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusNotificationCreateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentFixtureAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                admission is not null && admission.Validate(this, state) &&
                NotificationCreateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete));
            var rows = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, admission.ResourceId);
            rows[index] = rows[index] with
            {
                CreateAttempted = rows[index].CreateAttempted || !admission.Delete,
                DeleteAttempted = rows[index].DeleteAttempted || admission.Delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationCreateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated &&
                (!rows[index].SelectedAttempted || state.Closing && rows[index].DeleteAttempted));
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal Snapshot RecordStatusNotificationCreateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.Closing && state.Idle && absence is not null && !absence.Final && absence.Validate(this, state) &&
                state.Resources.Any(r => r.Id == absence.ResourceId && r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)));
            var rows = state.Resources.Select(r => !r.Borrowed && (absence.Final || r.Id == absence.ResourceId)
                ? r with { Absent = true } : r).ToArray();
            if (rows.SequenceEqual(state.Resources)) return state;
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusNotificationCreateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationCreateIndependentFixtureAdmission admission)
    {
        Guid dispatch = admission.Dispatch;
        return Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                admission is not null && admission.Validate(this, state) &&
                NotificationCreateIndependentFixtureAllowed(state, admission.ResourceId, admission.Delete));
            var rows = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, admission.ResourceId);
            rows[index] = rows[index] with
            {
                CreateAttempted = rows[index].CreateAttempted || !admission.Delete,
                DeleteAttempted = rows[index].DeleteAttempted || admission.Delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusNotificationCreateIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationCreateIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated &&
                (!rows[index].SelectedAttempted || state.Closing && rows[index].DeleteAttempted));
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal Snapshot RecordStatusNotificationCreateIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        VaultFixtureProvisioner.StatusNotificationCreateIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequireNotificationCreateIndependentHistory(selector);
            Require(state is not null && StatusNotificationCreateIndependentRoot(state) && state.LeaseId == leaseId &&
                state.Closing && state.Idle && absence is not null && absence.Final && absence.Validate(this, state) &&
                state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)).Absent &&
                state.Resources.Any(r => r.Id == absence.ResourceId && !r.CleanupOnly &&
                    !r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)));
            var rows = state.Resources.Select(r => !r.Borrowed && (absence.Final || r.Id == absence.ResourceId)
                ? r with { Absent = true } : r).ToArray();
            if (rows.SequenceEqual(state.Resources)) return state;
            return state with { Resources = rows };
        });

    private static bool NotificationCreateIndependentFixtureAllowed(Snapshot state, string id, bool delete)
    {
        if (!StatusNotificationCreateIndependentRoot(state) || !state.Idle || state.Closing != delete) return false;
        var child = state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        string vaultId = child.Id[..child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)];
        var vault = state.Resources.Single(r => r.Id == vaultId);
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        var row = state.Resources.SingleOrDefault(r => r.Id == id);
        if (row is null || row.Borrowed || row.Absent || row.ActiveDispatch != Guid.Empty) return false;
        if (!delete)
            return !state.Resources.Any(r => r.SelectedAttempted) && !row.CreateAttempted && !row.CleanupOnly &&
                (id == vault.Id || id == child.Id && vault.CreateAttempted && vault.InvocationTerminated);
        if (row.DeleteAttempted) return false;
        if (id == child.Id) return child.CreateAttempted;
        return child.Absent && child.ActiveDispatch == Guid.Empty &&
            (id == vault.Id && vault.CreateAttempted || id == marker.Id &&
                (!vault.CreateAttempted || vault.DeleteAttempted && vault.InvocationTerminated && vault.ActiveDispatch == Guid.Empty));
    }

    internal static bool SameStatusNotificationCreateIndependentSnapshot(Snapshot expected, Snapshot actual) =>
        expected is not null && actual is not null && StatusNotificationCreateIndependentRoot(expected) &&
        StatusNotificationCreateIndependentRoot(actual) && expected.Resources.SequenceEqual(actual.Resources) &&
        (actual with { Resources = expected.Resources }) == expected;

    internal static bool StatusNotificationCreateIndependentRoot(Snapshot state)
    {
        if (state is null || state.Resources is not { Length: 4 } ||
            state.Resources.Any(r => r is null || string.IsNullOrEmpty(r.Id)) ||
            !NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(state.Selector) ||
            state.NotificationAbsentCreate is not null || state.StatusSucceededDeleteVault is not null ||
            state.Resources.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 4 || !StatusNotificationRoot(state)) return false;
        var child = state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        int split = child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal);
        string[] vault = child.Id[..split].Split('/');
        string name = child.Id[(split + VaultFixtureProvisioner.NotificationPrefix.Length)..];
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        string[] deleted = marker.Id.Split('/');
        return IndependentSegment(vault[4], 90) && vault[8].Length == 24 &&
            vault[8].StartsWith("skv", StringComparison.Ordinal) && vault[8][3..].All(char.IsAsciiHexDigit) &&
            name.Length == 36 && name.StartsWith("skn-", StringComparison.Ordinal) && name[4..].All(char.IsAsciiHexDigit) &&
            IndependentSegment(deleted[6], 50);
    }

    private void RequireNotificationCreateIndependentHistory(FixtureSelector selector)
    {
        if (invalidNotificationCreateIndependentHistory.Contains(selector.Nonce))
            throw new StatusNotificationCreateIndependentHistoryException();
    }

    private static void ValidateStatusNotificationCreateIndependentState(Snapshot state, Snapshot? previous, ref int stage)
    {
        if (!NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(state.Selector)) return;
        Require(state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            state.NotificationAbsentCreate is null && state.StatusSucceededDeleteVault is null &&
            state.StatusVaultRecoverCancellationBaseline is null && state.StatusVaultUpdateCancellationBaseline is null);
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusNotificationCreateIndependentRoot(state));
        var child = state.Resources.Single(r => !r.Borrowed &&
            r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        string parentId = child.Id[..child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal)];
        var parent = state.Resources.Single(r => r.Id == parentId);
        var secret = state.Resources.Single(r => r.Id == parentId + "/secrets/" + VaultFixtureProvisioner.Canary);
        var marker = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        Require(state.Resources.Count(r => r.ActiveDispatch != Guid.Empty) <= 1 &&
            state.Resources.All(r => (!r.Absent || state.Closing) && (r.ActiveDispatch == Guid.Empty || !r.Absent) &&
                (!r.SelectedAttempted || r.Id == child.Id)) &&
            !secret.CreateAttempted && !secret.DeleteAttempted && !secret.InvocationTerminated && secret.ActiveDispatch == Guid.Empty && !marker.CreateAttempted &&
            (!child.SelectedAttempted || child.CreateAttempted && parent.CreateAttempted) &&
            (!child.DeleteAttempted || state.Closing && child.CreateAttempted) &&
            (!parent.DeleteAttempted || state.Closing && parent.CreateAttempted) &&
            (!marker.DeleteAttempted || state.Closing && (!parent.CreateAttempted ||
                parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty)));
        if (previous is null)
        {
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(StatusNotificationCreateIndependentRoot(previous) && previous.Owner == state.Owner &&
            previous.Selector == state.Selector && previous.LeaseId == state.LeaseId &&
            (!previous.Closing || state.Closing) && previous.Resources.Select(r => r.Id).SequenceEqual(state.Resources.Select(r => r.Id)));
        bool Rows(Resource[] expected) => expected.SequenceEqual(state.Resources);
        if (Rows(previous.Resources)) return; // Close or a read-only transaction.
        Require(previous.Closing == state.Closing);
        var beforeChild = previous.Resources.Single(r => r.Id == child.Id);
        if (!previous.Closing && !beforeChild.SelectedAttempted && child.SelectedAttempted)
        {
            Require(stage == 0 && previous.Idle && child.ActiveDispatch != Guid.Empty &&
                previous.Resources.All(r => !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)) &&
                Rows(previous.Resources.Select(r => r.Id == child.Id ? r with
                { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = child.ActiveDispatch } : r).ToArray()));
            stage = 1;
            return;
        }
        if (beforeChild.SelectedAttempted && !beforeChild.DeleteAttempted && beforeChild.ActiveDispatch != Guid.Empty)
        {
            Require(previous.Resources.Where(r => r.Id != child.Id).SequenceEqual(state.Resources.Where(r => r.Id != child.Id)) &&
                !parent.DeleteAttempted && !marker.DeleteAttempted && state.Resources.All(r => !r.Absent));
            if (!beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = true }))
            {
                Require(stage is 1 or 3);
                stage = stage == 1 ? 2 : -1;
                return;
            }
            if (beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = false }))
            {
                Require(!state.Closing && stage == 2);
                stage = 3;
                return;
            }
            Require(!state.Closing && stage == 3 && !beforeChild.InvocationTerminated &&
                child == (beforeChild with { InvocationTerminated = true, ActiveDispatch = Guid.Empty }));
            stage = 4;
            return;
        }
        if (previous.Idle)
        {
            var started = state.Resources.Where(r => r.ActiveDispatch != Guid.Empty).ToArray();
            if (started is [var row])
            {
                bool delete = state.Closing;
                Require(NotificationCreateIndependentFixtureAllowed(previous, row.Id, delete) &&
                    Rows(previous.Resources.Select(r => r.Borrowed ? r : r.Id == row.Id ? r with
                    {
                        Absent = false,
                        CreateAttempted = r.CreateAttempted || !delete,
                        DeleteAttempted = r.DeleteAttempted || delete,
                        ActiveDispatch = row.ActiveDispatch,
                        InvocationTerminated = false
                    } : r with { Absent = false }).ToArray()));
                return;
            }
            Require(state.Closing && state.Idle);
            bool absent = Rows(previous.Resources.Select(r => r.Id == child.Id ? r with { Absent = true } : r).ToArray()) ||
                Rows(previous.Resources.Select(r => r.Borrowed ? r : r with { Absent = true }).ToArray());
            bool present = previous.Resources.Where(r => !r.Borrowed && r.Absent).Any(row =>
                Rows(previous.Resources.Select(r => r.Id == row.Id ? r with { Absent = false } : r).ToArray()));
            Require(absent || present);
            return;
        }
        var active = previous.Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        var ended = state.Resources.Single(r => r.Id == active.Id);
        Require((!active.SelectedAttempted || previous.Closing && active.DeleteAttempted) && !active.InvocationTerminated && ended.InvocationTerminated &&
            (ended.ActiveDispatch == Guid.Empty || ended.ActiveDispatch == active.ActiveDispatch) &&
            Rows(previous.Resources.Select(r => r.Id == active.Id ? r with
            { InvocationTerminated = true, ActiveDispatch = ended.ActiveDispatch } : r).ToArray()));
    }

    internal Snapshot BeginStatusRoleDeleteIndependentInvocation(string owner, FixtureSelector selector, Guid leaseId,
        RoleManagementOperationFixtureObserverService.StatusRoleDeleteIndependentAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        return Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && state.Idle && admission is not null && admission.Validate(this, state) &&
                state.Resources.All(r => !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            var rows = state.Resources.ToArray();
            int index = Index(rows, admission.ResourceId);
            Require(rows[index].Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal) &&
                !rows[index].Borrowed && !rows[index].CleanupOnly);
            rows[index] = rows[index] with { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = dispatch };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusRoleDeleteIndependentStart(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        RoleManagementOperationFixtureObserverService.StatusRoleDeleteIndependentStartDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && drain is not null && drain.Dispatch == dispatch);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Snapshot AdmitStatusRoleDeleteIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        RoleManagementOperationFixtureObserverService.StatusRoleDeleteIndependentReadAdmission admission) =>
        Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && admission is not null && admission.Dispatch == dispatch &&
                admission.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = false };
            return state with { Resources = rows };
        });

    internal Snapshot CompleteStatusRoleDeleteIndependentRead(string owner, FixtureSelector selector, Guid leaseId, Guid dispatch,
        RoleManagementOperationFixtureObserverService.StatusRoleDeleteIndependentSettlement completion) =>
        Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                !state.Closing && dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch);
            if (completion.AcceptPostimage(this, state)) return state;
            Require(completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index].SelectedAttempted && !rows[index].InvocationTerminated);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = Guid.Empty };
            return state with { Resources = rows };
        });

    internal Snapshot BeginStatusRoleDeleteIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        RoleFixtureProvisioner.StatusRoleDeleteIndependentFixtureAdmission admission)
    {
        Guid dispatch = Guid.NewGuid();
        return Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                admission is not null && admission.Validate(this, state) &&
                IndependentFixtureAllowed(state, admission.ResourceId, admission.Delete));
            var rows = state.Resources.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            int index = Index(rows, admission.ResourceId);
            rows[index] = rows[index] with
            {
                CreateAttempted = rows[index].CreateAttempted || !admission.Delete,
                DeleteAttempted = rows[index].DeleteAttempted || admission.Delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch
            };
            return state with { Resources = rows };
        });
    }

    internal Snapshot EndStatusRoleDeleteIndependentFixtureDispatch(string owner, FixtureSelector selector, Guid leaseId,
        RoleFixtureProvisioner.StatusRoleDeleteIndependentFixtureDrain drain) =>
        Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                drain is not null && drain.Dispatch != Guid.Empty);
            if (drain.AcceptPostimage(this, state)) return state;
            Require(drain.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Index(rows, drain.ResourceId);
            Require(rows[index].ActiveDispatch == drain.Dispatch && !rows[index].InvocationTerminated &&
                !rows[index].SelectedAttempted);
            rows[index] = rows[index] with { InvocationTerminated = true, ActiveDispatch = drain.Settled ? Guid.Empty : drain.Dispatch };
            return state with { Resources = rows };
        });

    internal Snapshot RecordStatusRoleDeleteIndependentAbsence(string owner, FixtureSelector selector, Guid leaseId,
        RoleFixtureProvisioner.StatusRoleDeleteIndependentAbsence absence) =>
        Change(owner, selector, state =>
        {
            RequireIndependentRoleHistory(selector);
            Require(state is not null && StatusRoleDeleteIndependentRoot(state) && state.LeaseId == leaseId &&
                state.Closing && state.Idle && absence is not null && absence.Validate(this, state));
            var rows = state.Resources.Select(r => !r.Borrowed && (absence.Final || r.Id == absence.ResourceId)
                ? r with { Absent = true } : r).ToArray();
            if (rows.SequenceEqual(state.Resources)) return state;
            return state with { Resources = rows };
        });

    private static bool IndependentFixtureAllowed(Snapshot state, string id, bool delete)
    {
        if (!state.Idle || state.Closing != delete) return false;
        var child = state.Resources.Single(r => !r.Borrowed &&
            r.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal));
        string vaultId = child.Id[..child.Id.IndexOf("/providers/Microsoft.Authorization/", StringComparison.Ordinal)];
        var vault = state.Resources.Single(r => r.Id == vaultId);
        var secret = state.Resources.Single(r => r.Id == vaultId + "/secrets/" + RoleFixtureProvisioner.Canary);
        var marker = state.Resources.Single(r => r.CleanupOnly);
        var row = state.Resources.SingleOrDefault(r => r.Id == id);
        if (row is null || row.Borrowed || row.Absent || row.ActiveDispatch != Guid.Empty) return false;
        if (!delete)
            return !state.Resources.Any(r => r.SelectedAttempted) && !row.CreateAttempted && !row.CleanupOnly &&
                (id == vault.Id || id == secret.Id && vault.CreateAttempted && vault.InvocationTerminated ||
                    id == child.Id && vault.CreateAttempted && vault.InvocationTerminated &&
                    secret.CreateAttempted && secret.InvocationTerminated);
        if (row.DeleteAttempted) return false;
        if (id == child.Id) return child.CreateAttempted && !child.SelectedAttempted;
        return child.Absent && child.ActiveDispatch == Guid.Empty &&
            (id == vault.Id && vault.CreateAttempted ||
                id == marker.Id && (!vault.CreateAttempted ||
                    vault.DeleteAttempted && vault.InvocationTerminated && vault.ActiveDispatch == Guid.Empty));
    }

    internal Snapshot CompleteStatusRoleDeleteCancellationRead(string owner, FixtureSelector selector,
        Guid leaseId, Guid dispatch,
        RoleManagementOperationFixtureObserverService.StatusRoleDeleteCancellationSettlement completion) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && !state.Closing && state.Owner == owner && state.Selector == selector &&
                StatusRoleDeleteRoot(state) && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                dispatch != Guid.Empty && completion is not null && completion.Dispatch == dispatch &&
                completion.Validate(this, state));
            var rows = state.Resources.ToArray();
            int index = Array.FindIndex(rows, r => r.ActiveDispatch == dispatch);
            Require(index >= 0 && rows[index] is
            {
                CleanupOnly: false, Borrowed: false, CreateAttempted: true, SelectedAttempted: true,
                DeleteAttempted: false, InvocationTerminated: false, Absent: false
            } &&
                rows[index].Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal) &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty, InvocationTerminated = true };
            return state with { Resources = rows };
        });

    internal Guid BeginDispatch(string owner, FixtureSelector selector, string resourceId, bool delete,
        Func<Snapshot, bool>? validate = null)
    {
        Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Closing == delete &&
                state.Idle);
            Require(state!.StatusSucceededDeleteVault is not { } succeeded ||
                !delete && resourceId == succeeded.VaultId && succeeded.InvocationDispatch == Guid.Empty);
            // Pure dependency checks run under the same file/transaction lock
            // as admission, before dispatch invalidates any absence evidence.
            Require(validate is null || validate(state!));
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Resource row = rows[index];
            if (state.NotificationAbsentCreate is { } creation)
                Require(delete
                    ? !state.NotificationAbsentCreateUnsettled &&
                        (resourceId != creation.ChildId || creation.SettledDispatch != Guid.Empty)
                    : resourceId == creation.ParentId && creation.InvocationDispatch == Guid.Empty);
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) ||
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector))
            {
                Require(VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector)
                    ? StatusPrivateConnectionDeleteIndependentRoot(state) :
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector)
                    ? StatusPrivateConnectionDeleteSelectedRoot(state) :
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector)
                    ? StatusPrivateConnectionDeleteRoot(state) : StatusPrivateConnectionUpdateRoot(state));
                var declaration = state.PrivateEndpoint!.Declaration;
                var parent = rows.Single(r => r.Id == declaration.VaultId);
                if (!delete)
                    Require(state.PrivateEndpoint.Connection is null &&
                        (resourceId == declaration.VaultId || resourceId == declaration.EndpointId &&
                            parent.CreateAttempted && parent.InvocationTerminated));
                else
                {
                    Require(validate is not null && state.PrivateEndpointCleanupEligible && state.PrivateEndpointAbsent &&
                        (resourceId == declaration.VaultId || resourceId.Contains("/deletedVaults/", StringComparison.Ordinal)));
                    if (resourceId != declaration.VaultId && parent.CreateAttempted)
                        Require(parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty);
                }
            }
            if (RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector))
            {
                Require(StatusRoleDeleteRoot(state));
                var child = rows.Single(r => !r.Borrowed &&
                    r.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal));
                string parentId = child.Id[..child.Id.IndexOf("/providers/Microsoft.Authorization/", StringComparison.Ordinal)];
                var parent = rows.Single(r => r.Id == parentId);
                var marker = rows.Single(r => r.CleanupOnly);
                if (!delete)
                    Require(!rows.Any(r => r.SelectedAttempted) &&
                        (resourceId == parent.Id || resourceId == parent.Id + "/secrets/" + RoleFixtureProvisioner.Canary ||
                            resourceId == child.Id) &&
                        (resourceId == parent.Id || parent.CreateAttempted && parent.InvocationTerminated));
                else if (resourceId == child.Id)
                    Require(!child.SelectedAttempted);
                else
                {
                    Require(validate is not null && child.Absent && child.ActiveDispatch == Guid.Empty &&
                        (resourceId == parent.Id || resourceId == marker.Id) &&
                        (!child.SelectedAttempted || child.CreateAttempted && child.InvocationTerminated &&
                            !child.DeleteAttempted));
                    if (resourceId == marker.Id && parent.CreateAttempted)
                        Require(parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty);
                }
            }
            if (NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector))
            {
                Require(NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector)
                    ? StatusNotificationDeleteIndependentRoot(state) : StatusNotificationDeleteRoot(state));
                var child = rows.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
                var parent = rows.Single(r => !r.CleanupOnly && r.Id != child.Id);
                var marker = rows.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
                if (!delete)
                    Require(!rows.Any(r => r.SelectedAttempted) && (resourceId == parent.Id ||
                        resourceId == child.Id && parent.CreateAttempted && parent.InvocationTerminated));
                else if (resourceId == child.Id)
                    Require(!child.SelectedAttempted && !rows.Any(r => r.SelectedAttempted));
                else
                {
                    // Both the caller's pure NotificationsAbsent predicate and
                    // this structural dependency are mandatory in this transaction.
                    Require(validate is not null && child.Absent && child.ActiveDispatch == Guid.Empty &&
                        (resourceId == parent.Id || resourceId == marker.Id) &&
                        (!child.SelectedAttempted || child.CreateAttempted && child.InvocationTerminated &&
                            !child.DeleteAttempted));
                    if (child.SelectedAttempted && resourceId == marker.Id)
                        Require(parent.CreateAttempted && parent.DeleteAttempted && parent.InvocationTerminated &&
                            parent.ActiveDispatch == Guid.Empty);
                }
            }
            if (NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector))
            {
                Require(NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector)
                    ? StatusNotificationCreateRoot(state) : StatusNotificationUpdateRoot(state));
                var child = rows.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
                var parent = rows.Single(r => !r.CleanupOnly && r.Id != child.Id);
                var marker = rows.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
                if (!delete)
                    Require(!rows.Any(r => r.SelectedAttempted) && (resourceId == parent.Id ||
                        resourceId == child.Id && parent.CreateAttempted && parent.InvocationTerminated));
                else if (resourceId == child.Id)
                    Require(!child.DeleteAttempted && (!child.SelectedAttempted || child.CreateAttempted &&
                        child.InvocationTerminated && child.ActiveDispatch == Guid.Empty));
                else
                {
                    Require(validate is not null && child.Absent && child.ActiveDispatch == Guid.Empty &&
                        (resourceId == parent.Id || resourceId == marker.Id) &&
                        (!child.SelectedAttempted || child.CreateAttempted && child.InvocationTerminated));
                    if (resourceId == marker.Id && parent.CreateAttempted)
                        Require(parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty);
                }
            }
            if (VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector))
                Require(delete
                    ? validate is not null && (row.Id.Contains("/vaults/", StringComparison.Ordinal) && !row.CleanupOnly ||
                        row.Id.Contains("/deletedVaults/", StringComparison.Ordinal) && row.CleanupOnly &&
                        rows.Single(r => !r.CleanupOnly) is
                        { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: true })
                    : !rows.Any(r => r.SelectedAttempted));
            if (VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector))
                Require(delete
                    ? validate is not null && !row.CleanupOnly &&
                        (!rows.Any(r => r.SelectedAttempted) ||
                            rows.Single(r => r.SelectedAttempted) is { CreateAttempted: true, InvocationTerminated: true } selected &&
                            (resourceId == selected.Id || selected.DeleteAttempted))
                    : !rows.Any(r => r.SelectedAttempted));
            Require(!delete || state.DeleteVault is not { Disposition: DeleteVaultDisposition.Deleted } deletion ||
                resourceId != deletion.VaultId);
            Require(state.PurgeDeletedVault is not { } purge ||
                (!delete ? purge.InvocationDispatch == Guid.Empty :
                    resourceId == purge.DeletedVaultId && purge.Disposition != PurgeDeletedVaultDisposition.Purged));
            Require(state.RecoverVault is not { } recovery ||
                (!delete ? recovery.InvocationDispatch == Guid.Empty :
                    resourceId == recovery.DeletedVaultId && !recovery.Baseline.PurgeProtection ||
                    resourceId == recovery.VaultId && recovery.Disposition == RecoverVaultDisposition.Recovered));
            Require(!row.Borrowed && !row.Absent && row.ActiveDispatch == Guid.Empty &&
                (delete ? (row.CreateAttempted || row.CleanupOnly ||
                    VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) &&
                    row.Id.Contains("/deletedVaults/", StringComparison.Ordinal) &&
                    rows.Any(r => r.Id.Contains("/vaults/", StringComparison.Ordinal) &&
                        r.CreateAttempted && r.DeleteAttempted && r.InvocationTerminated)) && !row.DeleteAttempted :
                    !row.CreateAttempted && !row.CleanupOnly));
            Require(!delete || !VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                !row.SelectedAttempted || row.CleanupOnly);
            Require(!delete || !VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector) ||
                !rows.Any(r => r.SelectedAttempted));
            var slot = state.PrivateEndpoint;
            if (slot is not null)
            {
                Require(slot.CreationDispatch == Guid.Empty);
                if (resourceId == slot.Declaration.EndpointId)
                {
                    // Deletion has a separate original-proof-only admission.
                    Require(!delete && slot.Connection is null);
                    slot = slot with { CreationDispatch = dispatch };
                }
                else if (delete) Require(state.PrivateEndpointAbsent);
                slot = slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection is null ? null :
                    slot.Connection with { Absent = false }
                };
            }
            // A dispatch can change another planned coordinate (vault deletion
            // creates a deleted-vault record). Earlier absence is no longer proof.
            rows = rows.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            rows[index] = row with
            {
                CreateAttempted = row.CreateAttempted || !delete,
                DeleteAttempted = row.DeleteAttempted || delete,
                ActiveDispatch = dispatch,
                InvocationTerminated = false
            };
            return state with { Resources = rows, PrivateEndpoint = slot };
        });
        return dispatch;
    }

    // Call only after the native invocation has terminated, including uncertain
    // response loss. A crashed invocation remains active; reopening never erases it.
    internal Snapshot EndDispatch(string owner, FixtureSelector selector, string resourceId, Guid dispatch,
        bool nativeSettled = true, AbsenceRevision? beforeEndpointDrain = null) =>
        Change(owner, selector, state =>
        {
            Require(!nativeSettled || !RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
            Require(state is not null && dispatch != Guid.Empty &&
                (!nativeSettled || !StatusSucceededDeleteVaultCancellationRoot(state) &&
                    state.StatusSucceededDeleteVault?.InvocationDispatch != dispatch) &&
                (state.Settings is null || state.Settings.InvocationDispatch != dispatch) &&
                (state.DeleteVault is null || state.DeleteVault.InvocationDispatch != dispatch) &&
                (state.PurgeDeletedVault is null || state.PurgeDeletedVault.InvocationDispatch != dispatch) &&
                (state.CreateOrUpdateVault is null || state.CreateOrUpdateVault.InvocationDispatch != dispatch) &&
                (state.RecoverVault is null || state.RecoverVault.InvocationDispatch != dispatch) &&
                (state.PrivateEndpoint?.OriginalDelete is null ||
                    state.PrivateEndpoint.OriginalDelete.InvocationDispatch != dispatch) &&
                (state.PrivateEndpoint?.OriginalUpdate is null ||
                    state.PrivateEndpoint.OriginalUpdate.InvocationDispatch != dispatch));
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) && !nativeSettled &&
                state.PrivateEndpoint?.Connection is { } child && child.Id == resourceId)
            {
                Require(child.ActiveDispatch == dispatch && child.SelectedAttempted);
                if (child.InvocationTerminated) return state;
                return state with { PrivateEndpoint = state.PrivateEndpoint with { Connection = child with { InvocationTerminated = true } } };
            }
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Require(rows[index].ActiveDispatch == dispatch);
            Require(beforeEndpointDrain is null ||
                !nativeSettled && StatusPrivateConnectionDeleteIndependentRoot(state) && state.Closing &&
                state.PrivateEndpoint!.Declaration.EndpointId == resourceId &&
                state.PrivateEndpoint.DeletionDispatch == dispatch && rows[index].DeleteAttempted &&
                beforeEndpointDrain.MatchesEndpointDrain(state, rows[index]));
            Require(!nativeSettled ||
                !(VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                    VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector)) ||
                !rows[index].SelectedAttempted || rows[index].CleanupOnly);
            Require(!nativeSettled || !VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!nativeSettled || !VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!nativeSettled || !NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(!nativeSettled || !NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(!nativeSettled || !NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!nativeSettled || !NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!nativeSettled || !RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(!nativeSettled || state.PrivateEndpoint?.Declaration.EndpointId != rows[index].Id);
            if ((RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) ||
                (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector))) && rows[index].InvocationTerminated)
                return state;
            rows[index] = rows[index] with
            {
                ActiveDispatch = nativeSettled ? Guid.Empty : dispatch,
                InvocationTerminated = true
            };
            return state with { Resources = rows };
        }, privateIndependent: !nativeSettled);

    // Native settlement is a separate observation after local invocation drain.
    // A process restart cannot infer either fact from an absent resource.
    internal Snapshot SettleDispatch(string owner, FixtureSelector selector, string resourceId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
            Require(state is not null && dispatch != Guid.Empty &&
                !StatusSucceededDeleteVaultCancellationRoot(state) &&
                state.StatusSucceededDeleteVault?.InvocationDispatch != dispatch &&
                (state.Settings is null || state.Settings.InvocationDispatch != dispatch) &&
                (state.DeleteVault is null || state.DeleteVault.InvocationDispatch != dispatch) &&
                (state.PurgeDeletedVault is null || state.PurgeDeletedVault.InvocationDispatch != dispatch) &&
                (state.CreateOrUpdateVault is null || state.CreateOrUpdateVault.InvocationDispatch != dispatch) &&
                (state.RecoverVault is null || state.RecoverVault.InvocationDispatch != dispatch) &&
                (state.PrivateEndpoint?.OriginalDelete is null ||
                    state.PrivateEndpoint.OriginalDelete.InvocationDispatch != dispatch) &&
                (state.PrivateEndpoint?.OriginalUpdate is null ||
                    state.PrivateEndpoint.OriginalUpdate.InvocationDispatch != dispatch));
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Require(rows[index].ActiveDispatch == dispatch && rows[index].InvocationTerminated);
            Require(!(VaultFixtureProvisioner.StatusVaultDeleteCancellationSelector(selector) ||
                    VaultFixtureProvisioner.StatusVaultPurgeCancellationSelector(selector)) ||
                !rows[index].SelectedAttempted || rows[index].CleanupOnly);
            Require(!VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(!NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(!NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(selector) ||
                !rows[index].SelectedAttempted || rows[index].DeleteAttempted);
            Require(!RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(selector) ||
                !rows[index].SelectedAttempted);
            Require(state.PrivateEndpoint?.Declaration.EndpointId != rows[index].Id);
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with { Resources = rows };
        });

    // The service must independently observe native absence after every dispatch
    // has terminated. This journal does not turn a delete response into absence.
    internal Snapshot RecordAbsence(string owner, FixtureSelector selector, string resourceId) =>
        Change(owner, selector, state =>
        {
            Require(!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) &&
                !(NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)));
            Require(state is not null && state.Closing &&
                state.Idle);
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Require(!rows[index].Borrowed && rows[index].ActiveDispatch == Guid.Empty);
            Require(state.PrivateEndpoint?.Declaration.EndpointId != rows[index].Id);
            if (rows[index].Absent) return state;
            rows[index] = rows[index] with { Absent = true };
            return state with { Resources = rows };
        });

    internal Guid BeginPrivateEndpointDelete(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId)
    {
        Guid dispatch = Guid.NewGuid();
        Change(owner, selector, state =>
        {
            Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                state.PrivateEndpointCleanupEligible && state.PrivateEndpoint is { } &&
                state.PrivateEndpoint.Declaration == declaration &&
                state.PrivateEndpoint.Connection is { } child && child.Id == connectionId &&
                child.CreateAttempted && (!child.DeleteAttempted ||
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(selector) &&
                        StatusPrivateConnectionDeleteRoot(state) && state.PrivateEndpoint.StatusDeleteSettledDispatch != Guid.Empty ||
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(selector) &&
                        StatusPrivateConnectionDeleteSelectedRoot(state) && state.PrivateEndpoint.StatusDeleteSettledDispatch != Guid.Empty ||
                    VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(selector) &&
                        StatusPrivateConnectionDeleteIndependentRoot(state) && state.PrivateEndpoint.StatusDeleteSettledDispatch != Guid.Empty ||
                    state.PrivateEndpoint.OriginalDelete?.Disposition is PrivateConnectionDeleteDisposition.Denied or
                        PrivateConnectionDeleteDisposition.Deleted) &&
                !child.Borrowed && !child.CleanupOnly);
            var rows = state.Resources.ToArray();
            int index = Index(rows, declaration.EndpointId);
            Require(rows[index] is
            {
                Borrowed: false, CleanupOnly: false, CreateAttempted: true,
                DeleteAttempted: false, InvocationTerminated: true
            });
            rows = rows.Select(r => r.Borrowed ? r : r with { Absent = false }).ToArray();
            rows[index] = rows[index] with
            {
                DeleteAttempted = true,
                ActiveDispatch = dispatch,
                InvocationTerminated = false
            };
            return state with
            {
                Resources = rows,
                PrivateEndpoint = state.PrivateEndpoint with
                {
                    DeletionDispatch = dispatch,
                    NicAbsent = false,
                    Connection = state.PrivateEndpoint.Connection! with { Absent = false }
                }
            };
        });
        return dispatch;
    }

    internal Snapshot SettlePrivateEndpointDeletion(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.DeletionCandidate candidate) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                state.Closing && state.PrivateEndpoint is { } && candidate is not null &&
                candidate.Validate(this, state));
            var slot = state.PrivateEndpoint;
            var rows = state.Resources.ToArray();
            int index = Index(rows, slot.Declaration.EndpointId);
            Require(slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch != Guid.Empty &&
                state.PrivateConnectionCleanupEligible &&
                slot.Connection is { ActiveDispatch: var childDispatch } &&
                childDispatch == Guid.Empty &&
                rows[index] is { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: true } &&
                rows[index].ActiveDispatch == slot.DeletionDispatch &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty) &&
                !rows.Any(r => r.SelectedAttempted));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                PrivateEndpoint = slot with { DeletionDispatch = Guid.Empty }
            };
        });

    internal void CheckPrivateEndpointDelete(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointDeclaration declaration, string connectionId, Guid dispatch) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Closing && state.LeaseId == leaseId && leaseId != Guid.Empty &&
                state.PrivateEndpoint is { } slot && slot.Declaration == declaration &&
                slot.CreationDispatch == Guid.Empty && slot.DeletionDispatch == dispatch && dispatch != Guid.Empty &&
                state.PrivateConnectionCleanupEligible &&
                slot.Connection is { ActiveDispatch: var childDispatch } child &&
                child.Id == connectionId && childDispatch == Guid.Empty &&
                state.Resources.Single(r => r.Id == declaration.EndpointId) is
                { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: false, ActiveDispatch: var active } &&
                active == dispatch && !state.Resources.Any(r => r.SelectedAttempted) &&
                state.Resources.Where(r => r.Id != declaration.EndpointId).All(r => r.ActiveDispatch == Guid.Empty));
            return state;
        });

    internal Snapshot InvalidatePrivateEndpointAbsence(string owner, FixtureSelector selector) =>
        Change(owner, selector, state =>
        {
            Require(state is not null);
            if (state.PrivateEndpoint is not { } slot) return state;
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) && !slot.NicAbsent &&
                slot.Connection is not { Absent: true } && !state.Resources.Single(r => r.Id == slot.Declaration.EndpointId).Absent) return state;
            return state with
            {
                Resources = state.Resources.Select(r => r.Id == slot.Declaration.EndpointId ?
                    r with { Absent = false } : r).ToArray(),
                PrivateEndpoint = slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection is null ? null : slot.Connection with { Absent = false }
                }
            };
        }, privateIndependent: true);

    internal AbsenceRevision BeginPrivateEndpointAbsence(string owner, FixtureSelector selector, Guid leaseId)
    {
        // Invalidation and revision issue share the durable transaction. Even
        // an already-false tuple receives a fresh frame before any host read.
        var snapshot = Change(owner, selector, state =>
        {
            Require(state is not null && state.Closing && leaseId != Guid.Empty &&
                state.LeaseId == leaseId && state.PrivateEndpoint is not null);
            var slot = state.PrivateEndpoint;
            return state with
            {
                Resources = state.Resources.Select(r => r.Id == slot.Declaration.EndpointId ?
                    r with { Absent = false } : r).ToArray(),
                PrivateEndpoint = slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection is null ? null : slot.Connection with { Absent = false }
                }
            };
        });
        return new(snapshot.Revision);
    }

    internal Snapshot CommitPrivateEndpointAbsence(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.AbsenceCandidate candidate) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                state.PrivateEndpointCleanupEligible && candidate is not null && candidate.Validate(this, state));
            var slot = state.PrivateEndpoint!;
            var rows = state.Resources.ToArray();
            int index = Index(rows, slot.Declaration.EndpointId);
            Require(slot.Connection is null
                ? !rows[index].CreateAttempted && !rows[index].DeleteAttempted
                : rows[index] is { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: true });
            rows[index] = rows[index] with { Absent = true };
            return state with
            {
                Resources = rows,
                PrivateEndpoint = slot with
                {
                    NicAbsent = true,
                    Connection = slot.Connection is null ? null : slot.Connection with { Absent = true }
                }
            };
        });

    internal Snapshot RecordPresence(string owner, FixtureSelector selector, string resourceId) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && state.Closing);
            Resource[] rows = state!.Resources.ToArray();
            int index = Index(rows, resourceId);
            Require(!rows[index].Borrowed);
            if (PendingSelector(selector))
                return rows.All(r => !r.Absent) ? state :
                    state with { Resources = rows.Select(r => r with { Absent = false }).ToArray() };
            if (!rows[index].Absent && (state.PrivateEndpoint is null ||
                !state.PrivateEndpoint.NicAbsent && state.PrivateEndpoint.Connection is not { Absent: true }))
                return state;
            rows[index] = rows[index] with { Absent = false };
            return state with
            {
                Resources = state.PrivateEndpoint is not { } endpoint ? rows :
                    rows.Select(r => r.Id == endpoint.Declaration.EndpointId ? r with { Absent = false } : r).ToArray(),
                PrivateEndpoint = state.PrivateEndpoint is not { } slot ? null : slot with
                {
                    NicAbsent = false,
                    Connection = slot.Connection is null ? null : slot.Connection with { Absent = false }
                }
            };
        }, privateIndependent: true, statusPending: true, statusPendingIndependent: true, statusPendingCancellation: true);

    // The only transition that settles the original endpoint creation. It also
    // records the provider-assigned child, without growing Resources membership.
    internal Snapshot BindGeneratedPrivateConnection(string owner, FixtureSelector selector, Guid leaseId,
        PrivateEndpointFixtureProvisioner.BindingCandidate candidate) =>
        Change(owner, selector, state =>
        {
            Require(state is not null && leaseId != Guid.Empty && state.LeaseId == leaseId &&
                state.PrivateEndpoint is { Connection: null } && candidate is not null &&
                candidate.Validate(this, state));
            var slot = state!.PrivateEndpoint!;
            Require(slot.CreationDispatch != Guid.Empty);
            var rows = state.Resources.ToArray();
            int index = Index(rows, slot.Declaration.EndpointId);
            Require(rows[index] is { Borrowed: false, CreateAttempted: true, InvocationTerminated: true } &&
                rows[index].ActiveDispatch == slot.CreationDispatch &&
                rows.Where((_, i) => i != index).All(r => r.ActiveDispatch == Guid.Empty));
            string connection = candidate.ConnectionId;
            Require(connection.Length <= 2048 && connection.StartsWith(
                slot.Declaration.VaultId + "/privateEndpointConnections/", StringComparison.Ordinal) &&
                !rows.Any(r => r.Id.Equals(connection, StringComparison.OrdinalIgnoreCase)));
            rows[index] = rows[index] with { ActiveDispatch = Guid.Empty };
            return state with
            {
                Resources = rows,
                PrivateEndpoint = slot with
                {
                    CreationDispatch = Guid.Empty,
                    Connection = new(connection, false, CreateAttempted: true, InvocationTerminated: true)
                }
            };
        });

    private Snapshot Change(string owner, FixtureSelector selector, Func<Snapshot?, Snapshot> change,
        bool privateIndependent = false, bool statusPending = false, bool statusPendingIndependent = false,
        bool statusPendingCancellation = false)
    {
        Require(!VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) || privateIndependent);
        Require(!VaultFixtureProvisioner.StatusPendingPurgeSelector(selector) || statusPending);
        Require(!VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) || statusPendingIndependent);
        Require(!VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) || statusPendingCancellation);
        return Access(owner, selector, change);
    }

    private Snapshot Access(string owner, FixtureSelector selector, Func<Snapshot?, Snapshot>? change)
    {
        lock (gate) return AccessLocked(owner, selector, change);
    }

    private Snapshot AccessLocked(string owner, FixtureSelector selector, Func<Snapshot?, Snapshot>? change)
    {
        Require(owner.Length is > 0 and <= 128 && selector.Nonce != Guid.Empty &&
            new[] { selector.Scope, selector.Operation, selector.Variant, selector.Case }
                .All(s => !string.IsNullOrWhiteSpace(s) && s.Length <= 1024));
        bool pendingIndependent = VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector);
        bool pendingCancellation = VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector);
        var observedPendingHistory = pendingCancellation ? observedStatusPendingPurgeCancellationHistory :
            pendingIndependent ? observedStatusPendingPurgeIndependentHistory : observedStatusPendingPurgeHistory;
        observedPendingHistory.TryGetValue((owner, selector.Nonce), out var observed);
        bool reading = true;
        try
        {
            // Nonce is the lookup key, not a caller-returned lease. Authenticated
            // owner and the complete immutable selector are checked under the lock.
            var options = new FileStreamOptions
            {
                Mode = FileMode.OpenOrCreate,
                Access = FileAccess.ReadWrite,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows())
                options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using var file = new FileStream(Path.Combine(directory, selector.Nonce.ToString("N") + ".journal"), options);
            Require(file.Length <= MaximumJournal);
            if (PendingSelector(selector))
                Require(file.Length != 0 || observed.Sequence == 0);
            byte[] previous = new byte[32];
            Snapshot? state = null;
            long sequence = 0;
            int independentRoleStage = 0;
            int notificationUpdateStage = 0;
            int notificationCreateIndependentStage = 0;
            int privateUpdateIndependentStage = 0;
            Span<byte> header = stackalloc byte[4];
            while (file.Position < file.Length)
            {
                file.ReadExactly(header);
                int length = BinaryPrimitives.ReadInt32LittleEndian(header);
                Require(length is > 0 and <= MaximumFrame && file.Length - file.Position >= length + 32);
                byte[] payload = new byte[length];
                file.ReadExactly(payload);
                byte[] digest = new byte[32];
                file.ReadExactly(digest);
                Require(CryptographicOperations.FixedTimeEquals(SHA256.HashData(payload), digest));
                ValidateStatusPendingPurgeFrame(payload, selector);
                if (RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector) ||
                    (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)))
                    ValidateIndependentFrame(payload);
                if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector)) ValidatePrivateUpdateIndependentFrame(payload);
                Frame frame = JsonSerializer.Deserialize<Frame>(payload, ManagementAdmission.Json)
                    ?? throw Failure();
                Require(frame.Sequence == ++sequence && frame.Previous == Convert.ToHexString(previous) &&
                    frame.State is not null && frame.State.Selector is not null &&
                    frame.State.Resources is not null && frame.State.Resources.All(r => r is not null && r.Id is not null) &&
                    frame.State.Owner == owner && frame.State.Selector == selector);
                if (PendingSelector(selector))
                    Require(state is null || !SameStatusPendingPurgeSnapshot(frame.State with { Revision = state.Revision }, state));
                ValidateStatusPendingPurgeState(frame.State, state);
                ValidateStatusVaultRecoverCancellationState(frame.State, state);
                ValidateStatusSucceededDeleteVaultState(frame.State, state);
                ValidateStatusVaultUpdateCancellationState(frame.State, state);
                ValidateStatusNotificationDeleteCancellationState(frame.State, state);
                ValidateNotificationAbsentCreateState(frame.State, state);
                ValidateStatusRoleDeleteCancellationState(frame.State, state);
                ValidateStatusRoleDeleteIndependentState(frame.State, state, ref independentRoleStage);
                ValidateStatusNotificationUpdateIndependentState(frame.State, state, ref notificationUpdateStage);
                ValidateStatusNotificationCreateIndependentState(frame.State, state, ref notificationCreateIndependentStage);
                ValidateStatusPrivateConnectionUpdateState(frame.State, state);
                ValidatePrivateUpdateIndependentState(frame.State, state, ref privateUpdateIndependentStage);
                state = frame.State with { Revision = sequence };
                ValidateSettingsState(state);
                ValidateDeleteVaultState(state);
                ValidatePurgeDeletedVaultState(state);
                ValidateCreateOrUpdateVaultState(state);
                ValidateRecoverVaultState(state);
                ValidatePrivateConnectionUpdateState(state);
                ValidatePrivateConnectionDeleteState(state);
                if (PendingSelector(selector) && sequence == observed.Sequence)
                    Require(Convert.ToHexString(digest) == observed.Digest);
                previous = digest;
            }
            if (PendingSelector(selector))
            {
                Require(sequence >= observed.Sequence);
                if (state is not null)
                    observedPendingHistory[(owner, selector.Nonce)] = (sequence, Convert.ToHexString(previous));
            }
            if (change is null)
            {
                if (PendingSelector(selector))
                    RequirePendingHistory(owner, selector);
                RequireNotificationUpdateIndependentHistory(selector);
                RequireNotificationCreateIndependentHistory(selector);
                RequirePrivateUpdateIndependentHistory(owner, selector);
                if (state is null && PendingSelector(selector))
                { reading = false; throw Failure(); }
                return CopyStatusRecoveryBaseline(state ?? throw Failure());
            }
            reading = false;
            Snapshot next = change(state);
            if (next != state) ValidateStatusPendingPurgeState(next, state);
            ValidateStatusVaultRecoverCancellationState(next, state);
            ValidateStatusSucceededDeleteVaultState(next, state);
            ValidateStatusVaultUpdateCancellationState(next, state);
            ValidateStatusNotificationDeleteCancellationState(next, state);
            ValidateNotificationAbsentCreateState(next, state);
            ValidateStatusRoleDeleteCancellationState(next, state);
            ValidateStatusRoleDeleteIndependentState(next, state, ref independentRoleStage);
            ValidateStatusNotificationUpdateIndependentState(next, state, ref notificationUpdateStage);
            ValidateStatusNotificationCreateIndependentState(next, state, ref notificationCreateIndependentStage);
            ValidateStatusPrivateConnectionUpdateState(next, state);
            ValidatePrivateUpdateIndependentState(next, state, ref privateUpdateIndependentStage);
            ValidateSettingsState(next);
            ValidateDeleteVaultState(next);
            ValidatePurgeDeletedVaultState(next);
            ValidateCreateOrUpdateVaultState(next);
            ValidateRecoverVaultState(next);
            ValidatePrivateConnectionUpdateState(next);
            ValidatePrivateConnectionDeleteState(next);
            if (next == state)
            {
                if (PendingSelector(selector) ||
                    VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector) ||
                    NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)) file.Flush(flushToDisk: true);
                return CopyStatusRecoveryBaseline(next);
            }
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(
                new Frame(sequence + 1, Convert.ToHexString(previous), next), ManagementAdmission.Json);
            ValidateStatusPendingPurgeFrame(bytes, selector);
            Require(bytes.Length <= MaximumFrame && file.Length + bytes.Length + 36 <= MaximumJournal);
            Span<byte> prefix = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(prefix, bytes.Length);
            file.Write(prefix);
            file.Write(bytes);
            byte[] nextDigest = SHA256.HashData(bytes);
            file.Write(nextDigest);
            if (PendingSelector(selector))
                observedPendingHistory[(owner, selector.Nonce)] = (sequence + 1, Convert.ToHexString(nextDigest));
            // Failure-only test seam: the bytes exist, but the mandatory real
            // Flush has not run. This is not a simulated kernel fsync result.
            if (pendingIndependent && pendingIndependentFlushFailure is { } fault &&
                fault.Owner == owner && fault.Selector == selector && fault.Revision == sequence + 1)
            {
                pendingIndependentFlushFailure = null;
                throw new IOException("fixture-journal-unavailable");
            }
            if (pendingCancellation && pendingCancellationFlushFailure is { } cancellationFault &&
                cancellationFault.Owner == owner && cancellationFault.Selector == selector && cancellationFault.Revision == sequence + 1)
            {
                pendingCancellationFlushFailure = null;
                throw new IOException("fixture-journal-unavailable");
            }
            file.Flush(flushToDisk: true);
            return CopyStatusRecoveryBaseline(next with { Revision = sequence + 1 });
        }
        catch (Exception exception) when (reading && VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector) &&
            exception is EndOfStreamException or InvalidOperationException or JsonException or ArgumentException)
        { invalidStatusPendingPurgeCancellationHistory.Add((owner, selector.Nonce)); throw new StatusPendingPurgeCancellationHistoryException(); }
        catch (IOException) when (VaultFixtureProvisioner.StatusPendingPurgeCancellationSelector(selector)) { throw; }
        catch (Exception exception) when (reading && VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector) &&
            exception is EndOfStreamException or InvalidOperationException or JsonException or ArgumentException)
        { invalidStatusPendingPurgeIndependentHistory.Add((owner, selector.Nonce)); throw new StatusPendingPurgeIndependentHistoryException(); }
        catch (IOException) when (VaultFixtureProvisioner.StatusPendingPurgeIndependentSelector(selector)) { throw; }
        catch (Exception exception) when (reading && VaultFixtureProvisioner.StatusPendingPurgeSelector(selector) &&
            exception is EndOfStreamException or InvalidOperationException or JsonException or ArgumentException)
        { invalidStatusPendingPurgeHistory.Add((owner, selector.Nonce)); throw new StatusPendingPurgeHistoryException(); }
        catch (IOException) when (VaultFixtureProvisioner.StatusPendingPurgeSelector(selector)) { throw; }
        catch (EndOfStreamException) when (reading && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector))
        { invalidPrivateUpdateIndependentHistory.Add((owner, selector.Nonce)); throw new StatusPrivateConnectionUpdateIndependentHistoryException(); }
        catch (InvalidOperationException) when (reading && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector))
        { invalidPrivateUpdateIndependentHistory.Add((owner, selector.Nonce)); throw new StatusPrivateConnectionUpdateIndependentHistoryException(); }
        catch (JsonException) when (reading && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector))
        { invalidPrivateUpdateIndependentHistory.Add((owner, selector.Nonce)); throw new StatusPrivateConnectionUpdateIndependentHistoryException(); }
        catch (IOException) when (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(selector)) { throw; }
        catch (EndOfStreamException) when (reading && NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector))
        { invalidNotificationCreateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationCreateIndependentHistoryException(); }
        catch (InvalidOperationException) when (reading && NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector))
        { invalidNotificationCreateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationCreateIndependentHistoryException(); }
        catch (JsonException) when (reading && NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector))
        { invalidNotificationCreateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationCreateIndependentHistoryException(); }
        catch (IOException) when (NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)) { throw; }
        catch (EndOfStreamException) when (reading && NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector))
        { invalidNotificationUpdateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationUpdateIndependentHistoryException(); }
        catch (InvalidOperationException) when (reading && NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector))
        { invalidNotificationUpdateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationUpdateIndependentHistoryException(); }
        catch (JsonException) when (reading && NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector))
        { invalidNotificationUpdateIndependentHistory.Add(selector.Nonce); throw new StatusNotificationUpdateIndependentHistoryException(); }
        catch (IOException) when (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector)) { throw; }
        catch (EndOfStreamException) when (reading && RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector))
        { invalidIndependentRoleHistory.Add(selector.Nonce); throw new StatusRoleDeleteIndependentHistoryException(); }
        catch (InvalidOperationException) when (reading && RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector))
        { invalidIndependentRoleHistory.Add(selector.Nonce); throw new StatusRoleDeleteIndependentHistoryException(); }
        catch (JsonException) when (reading && RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(selector))
        { invalidIndependentRoleHistory.Add(selector.Nonce); throw new StatusRoleDeleteIndependentHistoryException(); }
        catch (EndOfStreamException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector))
        { throw new StatusSucceededDeleteVaultCancellationHistoryException(); }
        catch (InvalidOperationException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector))
        { throw new StatusSucceededDeleteVaultCancellationHistoryException(); }
        catch (JsonException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultCancellationSelector(selector))
        { throw new StatusSucceededDeleteVaultCancellationHistoryException(); }
        catch (EndOfStreamException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector))
        { throw new StatusSucceededDeleteVaultIndependentHistoryException(); }
        catch (InvalidOperationException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector))
        { throw new StatusSucceededDeleteVaultIndependentHistoryException(); }
        catch (JsonException) when (reading && VaultFixtureProvisioner.StatusSucceededDeleteVaultIndependentSelector(selector))
        { throw new StatusSucceededDeleteVaultIndependentHistoryException(); }
        catch (IOException) { throw Failure(); }
        catch (UnauthorizedAccessException) { throw Failure(); }
        catch (JsonException) { throw Failure(); }
    }

    // A detected corrupt history cannot regain in-memory capability authority
    // merely because the bytes are later restored. Close and actual drain-only
    // transitions remain available; a restarted source has no retained proofs.
    private void RequireIndependentRoleHistory(FixtureSelector selector)
    {
        if (invalidIndependentRoleHistory.Contains(selector.Nonce))
            throw new StatusRoleDeleteIndependentHistoryException();
    }

    private static void ValidateIndependentFrame(byte[] payload)
    {
        using var json = JsonDocument.Parse(payload);
        var root = json.RootElement;
        Require(root.ValueKind == JsonValueKind.Object);
        Require(root.TryGetProperty("state", out var state));
        Require(state.ValueKind == JsonValueKind.Object);
        Require(state.TryGetProperty("selector", out var selector) && selector.ValueKind == JsonValueKind.Object);
        Require(state.TryGetProperty("resources", out var resources) && resources.ValueKind == JsonValueKind.Array);
        foreach (string name in new[] { "privateEndpoint", "settings", "deleteVault", "purgeDeletedVault",
            "createOrUpdateVault", "recoverVault", "statusVaultRecoverCancellationBaseline",
            "statusVaultUpdateCancellationBaseline", "notificationAbsentCreate", "statusSucceededDeleteVault" })
            Require(!state.TryGetProperty(name, out var typed) || typed.ValueKind == JsonValueKind.Null);
        foreach (var row in resources.EnumerateArray())
            Require(row.ValueKind == JsonValueKind.Object && row.TryGetProperty("id", out var id) &&
                id.ValueKind == JsonValueKind.String && id.GetString() is { Length: > 0 and <= 2048 });
        Unique(root);

        static void Unique(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var property in node.EnumerateObject())
                {
                    Require(names.Add(property.Name));
                    Unique(property.Value);
                }
            }
            else if (node.ValueKind == JsonValueKind.Array)
                foreach (var item in node.EnumerateArray()) Unique(item);
        }
    }

    internal static bool SameStatusRoleDeleteIndependentSnapshot(Snapshot expected, Snapshot actual) =>
        expected is not null && actual is not null && StatusRoleDeleteIndependentRoot(expected) &&
        StatusRoleDeleteIndependentRoot(actual) && expected.Resources.SequenceEqual(actual.Resources) &&
        (actual with { Resources = expected.Resources }) == expected;

    internal static bool StatusRoleDeleteIndependentRoot(Snapshot state)
    {
        if (state is null || !RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(state.Selector) ||
            state.LeaseId == Guid.Empty || state.Resources is not { Length: 5 } ||
            state.Resources.Any(r => r is null || string.IsNullOrEmpty(r.Id)) ||
            state.PrivateEndpoint is not null || state.Settings is not null || state.DeleteVault is not null ||
            state.PurgeDeletedVault is not null || state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.NotificationAbsentCreate is not null || state.StatusSucceededDeleteVault is not null ||
            state.StatusVaultRecoverCancellationBaseline is not null || state.StatusVaultUpdateCancellationBaseline is not null ||
            state.Resources.Select(r => r.Id).Distinct(StringComparer.OrdinalIgnoreCase).Count() != 5) return false;
        const string role = "/providers/Microsoft.Authorization/roleAssignments/";
        var children = state.Resources.Where(r => !r.Borrowed && r.Id.Contains(role, StringComparison.Ordinal)).ToArray();
        if (children is not [var child] || child.CleanupOnly) return false;
        int split = child.Id.IndexOf(role, StringComparison.Ordinal);
        string parent = child.Id[..split];
        string[] vault = parent.Split('/');
        if (vault.Length != 9 || vault[0] != "" || vault[1] != "subscriptions" ||
            !Guid.TryParseExact(vault[2], "D", out var subscription) || subscription == Guid.Empty ||
            vault[3] != "resourceGroups" || !IndependentSegment(vault[4], 90) || vault[5] != "providers" ||
            vault[6] != "Microsoft.KeyVault" || vault[7] != "vaults" || vault[8].Length != 24 ||
            !vault[8].StartsWith("sk", StringComparison.Ordinal) || !vault[8][2..].All(char.IsAsciiHexDigit) ||
            !Guid.TryParseExact(child.Id[(split + role.Length)..], "D", out var assignment) || assignment == Guid.Empty)
            return false;
        string definition = $"/subscriptions/{vault[2]}/providers/Microsoft.Authorization/roleDefinitions/";
        var markers = state.Resources.Where(r => r.CleanupOnly && !r.Borrowed).ToArray();
        if (markers is not [var marker]) return false;
        string[] deleted = marker.Id.Split('/');
        return deleted.Length == 9 && deleted[0] == "" && deleted[1] == "subscriptions" && deleted[2] == vault[2] &&
            deleted[3] == "providers" && deleted[4] == "Microsoft.KeyVault" && deleted[5] == "locations" &&
            IndependentSegment(deleted[6], 50) && deleted[7] == "deletedVaults" && deleted[8] == vault[8] &&
            state.Resources.Count(r => r.Id == parent && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == parent + "/secrets/" + RoleFixtureProvisioner.Canary &&
                !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Borrowed && r.Id.StartsWith(definition, StringComparison.Ordinal) &&
                Guid.TryParseExact(r.Id[definition.Length..], "D", out var id) && id != Guid.Empty &&
                !r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) == 1;
    }

    private static bool IndependentSegment(string value, int maximum) =>
        value.Length is > 0 && value.Length <= maximum && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    private static void ValidateStatusRoleDeleteIndependentState(Snapshot state, Snapshot? previous, ref int stage)
    {
        if (!RoleFixtureProvisioner.StatusRoleDeleteIndependentSelector(state.Selector)) return;
        Require(state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            state.NotificationAbsentCreate is null && state.StatusSucceededDeleteVault is null &&
            state.StatusVaultRecoverCancellationBaseline is null && state.StatusVaultUpdateCancellationBaseline is null);
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusRoleDeleteIndependentRoot(state));
        var child = state.Resources.Single(r => !r.Borrowed &&
            r.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal));
        string parentId = child.Id[..child.Id.IndexOf("/providers/Microsoft.Authorization/", StringComparison.Ordinal)];
        var parent = state.Resources.Single(r => r.Id == parentId);
        var secret = state.Resources.Single(r => r.Id == parentId + "/secrets/" + RoleFixtureProvisioner.Canary);
        var marker = state.Resources.Single(r => r.CleanupOnly);
        Require(state.Resources.Count(r => r.ActiveDispatch != Guid.Empty) <= 1 &&
            state.Resources.All(r => (!r.Absent || state.Closing) && (r.ActiveDispatch == Guid.Empty || !r.Absent) &&
                (!r.SelectedAttempted || r.Id == child.Id)) &&
            !secret.DeleteAttempted && !marker.CreateAttempted &&
            (!child.SelectedAttempted || child.CreateAttempted && !child.DeleteAttempted &&
                parent.CreateAttempted && secret.CreateAttempted) &&
            (!child.DeleteAttempted || state.Closing && !child.SelectedAttempted && child.CreateAttempted) &&
            (!parent.DeleteAttempted || state.Closing && parent.CreateAttempted) &&
            (!marker.DeleteAttempted || state.Closing && (!parent.CreateAttempted ||
                parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty)));
        if (previous is null)
        {
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
            return;
        }
        Require(StatusRoleDeleteIndependentRoot(previous) && previous.Owner == state.Owner &&
            previous.Selector == state.Selector && previous.LeaseId == state.LeaseId &&
            (!previous.Closing || state.Closing) && previous.Resources.Select(r => r.Id).SequenceEqual(state.Resources.Select(r => r.Id)));
        bool Rows(Resource[] expected) => expected.SequenceEqual(state.Resources);
        if (Rows(previous.Resources)) return; // Close or a read-only transaction.
        Require(previous.Closing == state.Closing);
        var beforeChild = previous.Resources.Single(r => r.Id == child.Id);
        if (!previous.Closing && !beforeChild.SelectedAttempted && child.SelectedAttempted)
        {
            Require(stage == 0 && previous.Idle && child.ActiveDispatch != Guid.Empty &&
                previous.Resources.All(r => !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent &&
                    (r.Borrowed || r.CleanupOnly ? !r.CreateAttempted && !r.InvocationTerminated :
                        r.CreateAttempted && r.InvocationTerminated)) &&
                Rows(previous.Resources.Select(r => r.Id == child.Id ? r with
                { SelectedAttempted = true, InvocationTerminated = false, ActiveDispatch = child.ActiveDispatch } : r).ToArray()));
            stage = 1;
            return;
        }
        if (beforeChild.SelectedAttempted && beforeChild.ActiveDispatch != Guid.Empty)
        {
            Require(previous.Resources.Where(r => r.Id != child.Id).SequenceEqual(state.Resources.Where(r => r.Id != child.Id)) &&
                !parent.DeleteAttempted && !marker.DeleteAttempted && state.Resources.All(r => !r.Absent));
            if (!beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = true }))
            {
                Require(stage is 1 or 3);
                stage = stage == 1 ? 2 : -1;
                return;
            }
            if (beforeChild.InvocationTerminated && child == (beforeChild with { InvocationTerminated = false }))
            {
                Require(!state.Closing && stage == 2);
                stage = 3;
                return;
            }
            Require(!state.Closing && stage == 3 && !beforeChild.InvocationTerminated &&
                child == (beforeChild with { InvocationTerminated = true, ActiveDispatch = Guid.Empty }));
            stage = 4;
            return;
        }
        if (previous.Idle)
        {
            var started = state.Resources.Where(r => r.ActiveDispatch != Guid.Empty).ToArray();
            if (started is [var row])
            {
                bool delete = state.Closing;
                Require(IndependentFixtureAllowed(previous, row.Id, delete) &&
                    Rows(previous.Resources.Select(r => r.Borrowed ? r : r.Id == row.Id ? r with
                    {
                        Absent = false,
                        CreateAttempted = r.CreateAttempted || !delete,
                        DeleteAttempted = r.DeleteAttempted || delete,
                        ActiveDispatch = row.ActiveDispatch,
                        InvocationTerminated = false
                    } : r with { Absent = false }).ToArray()));
                return;
            }
            Require(state.Closing && state.Idle);
            bool absent = Rows(previous.Resources.Select(r => r.Id == child.Id ? r with { Absent = true } : r).ToArray()) ||
                Rows(previous.Resources.Select(r => r.Borrowed ? r : r with { Absent = true }).ToArray());
            bool present = previous.Resources.Where(r => !r.Borrowed && r.Absent).Any(row =>
                Rows(previous.Resources.Select(r => r.Id == row.Id ? r with { Absent = false } : r).ToArray()));
            Require(absent || present);
            return;
        }
        var active = previous.Resources.Single(r => r.ActiveDispatch != Guid.Empty);
        var ended = state.Resources.Single(r => r.Id == active.Id);
        Require(!active.SelectedAttempted && !active.InvocationTerminated && ended.InvocationTerminated &&
            (ended.ActiveDispatch == Guid.Empty || ended.ActiveDispatch == active.ActiveDispatch) &&
            Rows(previous.Resources.Select(r => r.Id == active.Id ? r with
            { InvocationTerminated = true, ActiveDispatch = ended.ActiveDispatch } : r).ToArray()));
    }

    // Pure structural root check, also used by the original owned child reader.
    // No source locks, provider work or journal rereads enter a transaction.
    internal static bool StatusRoleDeleteRoot(Snapshot state)
    {
        if (!RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(state.Selector) ||
            state.LeaseId == Guid.Empty || state.Resources.Length != 5 ||
            state.PrivateEndpoint is not null || state.Settings is not null || state.DeleteVault is not null ||
            state.PurgeDeletedVault is not null || state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.StatusVaultRecoverCancellationBaseline is not null || state.StatusVaultUpdateCancellationBaseline is not null)
            return false;
        const string role = "/providers/Microsoft.Authorization/roleAssignments/";
        var children = state.Resources.Where(r => !r.Borrowed && r.Id.Contains(role, StringComparison.Ordinal)).ToArray();
        if (children is not [var child] || child.CleanupOnly) return false;
        int split = child.Id.IndexOf(role, StringComparison.Ordinal);
        string parent = child.Id[..split];
        string[] vault = parent.Split('/');
        if (vault.Length != 9 || vault[0] != "" || vault[1] != "subscriptions" ||
            !Guid.TryParseExact(vault[2], "D", out var subscription) || subscription == Guid.Empty ||
            vault[3] != "resourceGroups" || vault[4].Length == 0 || vault[5] != "providers" ||
            vault[6] != "Microsoft.KeyVault" || vault[7] != "vaults" || vault[8].Length != 24 ||
            !vault[8].StartsWith("sk", StringComparison.Ordinal) || !vault[8][2..].All(char.IsAsciiHexDigit) ||
            !Guid.TryParseExact(child.Id[(split + role.Length)..], "D", out var assignment) || assignment == Guid.Empty)
            return false;
        string definition = $"/subscriptions/{vault[2]}/providers/Microsoft.Authorization/roleDefinitions/";
        return state.Resources.Count(r => r.Id == parent && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == parent + "/secrets/" + RoleFixtureProvisioner.Canary &&
                !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.CleanupOnly && !r.Borrowed &&
                r.Id.StartsWith($"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/", StringComparison.Ordinal) &&
                r.Id.EndsWith("/deletedVaults/" + vault[8], StringComparison.Ordinal)) == 1 &&
            state.Resources.Count(r => r.Borrowed && r.Id.StartsWith(definition, StringComparison.Ordinal) &&
                Guid.TryParseExact(r.Id[definition.Length..], "D", out var id) && id != Guid.Empty &&
                !r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) == 1;
    }

    private static void ValidateStatusRoleDeleteCancellationState(Snapshot state, Snapshot? previous)
    {
        if (!RoleFixtureProvisioner.StatusRoleDeleteCancellationSelector(state.Selector)) return;
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(StatusRoleDeleteRoot(state));
        var child = state.Resources.Single(r => !r.Borrowed &&
            r.Id.Contains("/providers/Microsoft.Authorization/roleAssignments/", StringComparison.Ordinal));
        string parentId = child.Id[..child.Id.IndexOf("/providers/Microsoft.Authorization/", StringComparison.Ordinal)];
        var parent = state.Resources.Single(r => r.Id == parentId);
        var secret = state.Resources.Single(r => r.Id == parentId + "/secrets/" + RoleFixtureProvisioner.Canary);
        var marker = state.Resources.Single(r => r.CleanupOnly);
        Require(state.Resources.All(r => (!r.Absent || state.Closing) &&
            (r.ActiveDispatch == Guid.Empty || !r.Absent) && (!r.SelectedAttempted || r.Id == child.Id)) &&
            (!child.SelectedAttempted || child.CreateAttempted && !child.DeleteAttempted &&
                parent.CreateAttempted && secret.CreateAttempted) &&
            (!child.DeleteAttempted || state.Closing && !child.SelectedAttempted && child.CreateAttempted) &&
            !secret.DeleteAttempted && !marker.CreateAttempted &&
            (!parent.DeleteAttempted || state.Closing && parent.CreateAttempted) &&
            (!marker.DeleteAttempted || state.Closing && (!parent.CreateAttempted ||
                parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty)));
        if (child.SelectedAttempted && child.ActiveDispatch != Guid.Empty)
            Require(!parent.DeleteAttempted && !marker.DeleteAttempted && state.Resources.All(r => !r.Absent) &&
                state.Resources.Where(r => r.Id != child.Id).All(r => r.ActiveDispatch == Guid.Empty));
        if (previous is null)
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
        else
            Require(previous.Owner == state.Owner && previous.Selector == state.Selector && previous.LeaseId == state.LeaseId &&
                (!previous.Closing || state.Closing) && previous.Resources.Length == 5 && previous.Resources.All(p =>
                    state.Resources.Count(r => r.Id == p.Id && r.Borrowed == p.Borrowed && r.CleanupOnly == p.CleanupOnly &&
                        (!p.CreateAttempted || r.CreateAttempted) && (!p.DeleteAttempted || r.DeleteAttempted) &&
                        (!p.SelectedAttempted || r.SelectedAttempted)) == 1));
    }

    internal static bool StatusNotificationDeleteRoot(Snapshot state) =>
        NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(state.Selector) &&
        StatusNotificationRoot(state);

    internal static bool StatusNotificationDeleteIndependentRoot(Snapshot state) =>
        NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(state.Selector) &&
        state.NotificationAbsentCreate is null && StatusNotificationRoot(state);

    internal static bool StatusNotificationUpdateRoot(Snapshot state) =>
        NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(state.Selector) &&
        StatusNotificationRoot(state);

    internal static bool StatusNotificationCreateRoot(Snapshot state) =>
        NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(state.Selector) &&
        StatusNotificationRoot(state);

    private static bool StatusNotificationRoot(Snapshot state)
    {
        if (state.LeaseId == Guid.Empty || state.Resources.Length != 4 || state.Resources.Any(r => r.Borrowed) ||
            state.PrivateEndpoint is not null || state.Settings is not null || state.DeleteVault is not null ||
            state.PurgeDeletedVault is not null || state.CreateOrUpdateVault is not null || state.RecoverVault is not null ||
            state.StatusVaultRecoverCancellationBaseline is not null || state.StatusVaultUpdateCancellationBaseline is not null)
            return false;
        var children = state.Resources.Where(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix,
            StringComparison.Ordinal)).ToArray();
        if (children is not [var child] || child.CleanupOnly) return false;
        int split = child.Id.IndexOf(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal);
        string parentId = child.Id[..split], name = child.Id[(split + VaultFixtureProvisioner.NotificationPrefix.Length)..];
        string[] vault = parentId.Split('/');
        if (vault.Length != 9 || vault[0].Length != 0 || vault[1] != "subscriptions" ||
            !Guid.TryParseExact(vault[2], "D", out var subscription) || subscription == Guid.Empty ||
            vault[3] != "resourceGroups" || vault[4].Length == 0 || vault[5] != "providers" ||
            vault[6] != "Microsoft.KeyVault" || vault[7] != "vaults" || vault[8].Length == 0 ||
            name.Length == 0 || name.Contains('/')) return false;
        var deleted = state.Resources.Where(r => r.Id.StartsWith(
            $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/", StringComparison.Ordinal) &&
            r.Id.EndsWith("/deletedVaults/" + vault[8], StringComparison.Ordinal) &&
            r.Id.Split('/').Length == 9 && r.CleanupOnly && !r.CreateAttempted && !r.SelectedAttempted).ToArray();
        return deleted.Length == 1 &&
            state.Resources.Count(r => r.Id == parentId && !r.CleanupOnly && !r.SelectedAttempted) == 1 &&
            state.Resources.Count(r => r.Id == parentId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1;
    }

    private static void ValidateStatusNotificationDeleteCancellationState(Snapshot state, Snapshot? previous)
    {
        bool create = NotificationFixtureProvisioner.StatusNotificationCreateCancellationSelector(state.Selector);
        bool update = create || NotificationFixtureProvisioner.StatusNotificationUpdateCancellationSelector(state.Selector);
        bool independent = NotificationFixtureProvisioner.StatusNotificationDeleteIndependentSelector(state.Selector);
        if (!update && !independent && !NotificationFixtureProvisioner.StatusNotificationDeleteCancellationSelector(state.Selector)) return;
        if (state.Resources.Length == 0)
        {
            Require(state.Closing && state.LeaseId == Guid.Empty && (previous is null || previous.Resources.Length == 0));
            return;
        }
        Require(create ? StatusNotificationCreateRoot(state) :
            update ? StatusNotificationUpdateRoot(state) : independent
                ? StatusNotificationDeleteIndependentRoot(state) : StatusNotificationDeleteRoot(state));
        var child = state.Resources.Single(r => r.Id.Contains(VaultFixtureProvisioner.NotificationPrefix, StringComparison.Ordinal));
        var parent = state.Resources.Single(r => !r.CleanupOnly && r.Id != child.Id);
        var deleted = state.Resources.Single(r => r.Id.Contains("/deletedVaults/", StringComparison.Ordinal));
        bool parentPrepared = parent.CreateAttempted && (parent.InvocationTerminated ||
            state.Closing && parent.DeleteAttempted && parent.ActiveDispatch != Guid.Empty);
        Require(state.Resources.All(r => !r.Absent || state.Closing) &&
            (!child.SelectedAttempted || child.CreateAttempted && (update || !child.DeleteAttempted) &&
                parentPrepared) &&
            (!child.CreateAttempted || parentPrepared) &&
            (!child.DeleteAttempted || state.Closing && child.CreateAttempted && (update || !child.SelectedAttempted)) &&
            (!parent.DeleteAttempted || state.Closing && parent.CreateAttempted) &&
            (!deleted.DeleteAttempted || state.Closing) &&
            (deleted.DeleteAttempted || !deleted.InvocationTerminated && deleted.ActiveDispatch == Guid.Empty) &&
            state.Resources.All(r => r.ActiveDispatch == Guid.Empty || !r.Absent) &&
            new[] { child, parent }.All(r => r.CreateAttempted ||
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty));
        if (child.SelectedAttempted && deleted.DeleteAttempted)
            Require(parent.DeleteAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty);
        if (child.SelectedAttempted && child.ActiveDispatch != Guid.Empty)
            Require(update && child.DeleteAttempted
                ? state.Closing && !parent.DeleteAttempted && !deleted.DeleteAttempted
                : !parent.DeleteAttempted && !deleted.DeleteAttempted &&
                    state.Resources.All(r => !r.Absent) &&
                    state.Resources.Where(r => r.Id != child.Id).All(r => r.ActiveDispatch == Guid.Empty));
        if (previous is null)
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
        else
            Require(previous.LeaseId == state.LeaseId && previous.Owner == state.Owner &&
                previous.Selector == state.Selector && (!previous.Closing || state.Closing) &&
                previous.Resources.Length == 4 && previous.Resources.All(p =>
                    state.Resources.Count(r => r.Id == p.Id && r.CleanupOnly == p.CleanupOnly && r.Borrowed == p.Borrowed &&
                        (!p.CreateAttempted || r.CreateAttempted) && (!p.SelectedAttempted || r.SelectedAttempted) &&
                        (!p.DeleteAttempted || r.DeleteAttempted)) == 1));
    }

    private static void ValidateNotificationAbsentCreateState(Snapshot state, Snapshot? previous)
    {
        var old = previous?.NotificationAbsentCreate;
        if (state.NotificationAbsentCreate is not { } creation)
        {
            Require(old is null);
            return;
        }
        Require(StatusNotificationCreateRoot(state) && creation.ContractVersion == 1 &&
            creation.NamespaceEpoch != Guid.Empty &&
            state.Resources.Count(r => r.Id == creation.ParentId && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == creation.ChildId && !r.CleanupOnly) == 1 &&
            creation.ChildId.StartsWith(creation.ParentId + VaultFixtureProvisioner.NotificationPrefix,
                StringComparison.Ordinal));
        var child = state.Resources.Single(r => r.Id == creation.ChildId);
        if (old is null)
        {
            Require(previous is not null && !previous.Closing && !state.Closing &&
                previous.Resources.SequenceEqual(state.Resources) &&
                state.Resources.All(r => !r.CreateAttempted && !r.SelectedAttempted && !r.DeleteAttempted &&
                    !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty) &&
                creation.InvocationDispatch == Guid.Empty);
        }
        else
        {
            Require(creation.ContractVersion == old.ContractVersion && creation.NamespaceEpoch == old.NamespaceEpoch &&
                creation.ParentId == old.ParentId && creation.ChildId == old.ChildId &&
                (old.InvocationDispatch == Guid.Empty || creation.InvocationDispatch == old.InvocationDispatch) &&
                (old.SettledDispatch == Guid.Empty || creation == old) &&
                (old.BaselineSha256 is null || creation.BaselineSha256 == old.BaselineSha256));
        }
        if (creation.InvocationDispatch == Guid.Empty)
        {
            Require(!child.CreateAttempted && !child.SelectedAttempted && !child.DeleteAttempted &&
                !child.InvocationTerminated && child.ActiveDispatch == Guid.Empty &&
                creation.SettledDispatch == Guid.Empty && creation.BaselineSha256 is null &&
                creation.StartSha256 is null && creation.SelectedSha256 is null &&
                creation.CompletionSha256 is null && creation.ConfigurationSha256 is null);
            return;
        }
        Require(child.CreateAttempted && child.SelectedAttempted && Hash(creation.BaselineSha256));
        if (old?.InvocationDispatch == Guid.Empty)
        {
            Require(!state.Closing && previous!.Idle &&
                previous.Resources.Single(r => r.Id == creation.ChildId) is
                { CreateAttempted: false, SelectedAttempted: false } &&
                !child.InvocationTerminated && child.ActiveDispatch == creation.InvocationDispatch &&
                previous.Resources.Where(r => r.Id != creation.ChildId)
                    .SequenceEqual(state.Resources.Where(r => r.Id != creation.ChildId)) &&
                creation.SettledDispatch == Guid.Empty);
        }
        if (creation.SettledDispatch == Guid.Empty)
        {
            Require(child.ActiveDispatch == creation.InvocationDispatch && !child.DeleteAttempted && !child.Absent &&
                state.Resources.Where(r => r.Id != child.Id).All(r =>
                    r.ActiveDispatch == Guid.Empty && !r.DeleteAttempted && !r.Absent) &&
                creation.StartSha256 is null && creation.SelectedSha256 is null &&
                creation.CompletionSha256 is null && creation.ConfigurationSha256 is null);
            return;
        }
        Require(creation.SettledDispatch == creation.InvocationDispatch &&
            Hash(creation.StartSha256) && Hash(creation.SelectedSha256) &&
            Hash(creation.CompletionSha256) && Hash(creation.ConfigurationSha256));
        if (old?.SettledDispatch == Guid.Empty)
            Require(!state.Closing && !previous!.Closing && old.InvocationDispatch == creation.InvocationDispatch &&
                previous.Resources.Single(r => r.Id == child.Id) is
                { InvocationTerminated: false, DeleteAttempted: false, Absent: false } before &&
                before.ActiveDispatch == creation.InvocationDispatch &&
                child == (before with { ActiveDispatch = Guid.Empty, InvocationTerminated = true }) &&
                previous.Resources.Where(r => r.Id != child.Id)
                    .SequenceEqual(state.Resources.Where(r => r.Id != child.Id)));

        static bool Hash(string? value) => value is { Length: 64 } && value.All(char.IsAsciiHexDigit);
    }

    private static Snapshot CopyStatusRecoveryBaseline(Snapshot state) =>
        PendingSelector(state.Selector) ? CopyStatusPendingPurgeSnapshot(state) :
        state.StatusVaultRecoverCancellationBaseline is null && state.StatusVaultUpdateCancellationBaseline is null &&
        state.StatusSucceededDeleteVault is null
        ? state : state with
        {
            StatusSucceededDeleteVault = state.StatusSucceededDeleteVault is { } succeeded
            ? succeeded with { Baseline = CopySettings(succeeded.Baseline) } : null,
            StatusVaultRecoverCancellationBaseline = state.StatusVaultRecoverCancellationBaseline is { } recovery
            ? CopySettings(recovery) : null,
            StatusVaultUpdateCancellationBaseline = state.StatusVaultUpdateCancellationBaseline is { } update
            ? CopySettings(update) : null
        };

    private static void ValidateStatusVaultUpdateCancellationState(Snapshot state, Snapshot? previous)
    {
        if (state.StatusVaultUpdateCancellationBaseline is not { } baseline)
        {
            Require(!VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(state.Selector) ||
                state.Resources.Length == 0 && state.Closing && state.LeaseId == Guid.Empty);
            Require(previous?.StatusVaultUpdateCancellationBaseline is null);
            return;
        }
        Require(VaultFixtureProvisioner.StatusVaultUpdateCancellationSelector(state.Selector) &&
            state.LeaseId != Guid.Empty && state.StatusVaultRecoverCancellationBaseline is null &&
            state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            state.Resources.Length == 3 && state.Resources.All(r => !r.Borrowed) &&
            baseline.Rbac && !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
        _ = baseline.Build();
        var active = state.Resources.Single(r => !r.CleanupOnly);
        string[] vault = active.Id.Split('/');
        Require(vault.Length == 9 && vault[0].Length == 0 && vault[1] == "subscriptions" &&
            Guid.TryParseExact(vault[2], "D", out var subscription) && subscription != Guid.Empty &&
            vault[3] == "resourceGroups" && vault[4].Length is > 0 and <= 90 &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults");
        _ = new VaultScope(new(new(Guid.Parse(vault[2])), vault[4]), vault[8]);
        string deletedId = $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{baseline.Location}/deletedVaults/{vault[8]}";
        Require(state.Resources.Count(r => r.Id == deletedId && r.CleanupOnly && !r.CreateAttempted &&
                !r.SelectedAttempted) == 1 &&
            state.Resources.Count(r => r.Id == active.Id + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1);
        var deleted = state.Resources.Single(r => r.Id == deletedId);
        Require(!active.SelectedAttempted || active.CreateAttempted);
        Require(state.Resources.All(r => !r.Absent || state.Closing) &&
            (active.CreateAttempted || !active.InvocationTerminated && active.ActiveDispatch == Guid.Empty) &&
            (active.ActiveDispatch == Guid.Empty || active.CreateAttempted && !active.Absent));
        Require(!active.DeleteAttempted || state.Closing && active.CreateAttempted);
        Require(!deleted.DeleteAttempted
            ? !deleted.InvocationTerminated && deleted.ActiveDispatch == Guid.Empty
            : state.Closing && active.CreateAttempted && active.DeleteAttempted &&
                active.InvocationTerminated && active.ActiveDispatch == Guid.Empty);
        if (active.SelectedAttempted && !active.DeleteAttempted && active.ActiveDispatch != Guid.Empty)
            Require(!active.Absent && !deleted.Absent && !deleted.DeleteAttempted);
        if (previous is not null)
            Require(previous.StatusVaultUpdateCancellationBaseline is { } prior &&
                VaultAdministrationEffects.SameConfiguration(prior, baseline) &&
                previous.LeaseId == state.LeaseId && previous.Owner == state.Owner &&
                previous.Selector == state.Selector && (!previous.Closing || state.Closing) &&
                previous.Resources.Length == 3 &&
                previous.Resources.All(p => state.Resources.Count(r => r.Id == p.Id && r.CleanupOnly == p.CleanupOnly &&
                    (!p.CreateAttempted || r.CreateAttempted) && (!p.SelectedAttempted || r.SelectedAttempted) &&
                    (!p.DeleteAttempted || r.DeleteAttempted)) == 1));
        else
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
    }

    private static void ValidateStatusVaultRecoverCancellationState(Snapshot state, Snapshot? previous)
    {
        if (state.StatusVaultRecoverCancellationBaseline is not { } baseline)
        {
            Require(!VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(state.Selector) ||
                state.Resources.Length == 0 && state.Closing && state.LeaseId == Guid.Empty);
            Require(previous?.StatusVaultRecoverCancellationBaseline is null);
            return;
        }
        Require(VaultFixtureProvisioner.StatusVaultRecoverCancellationSelector(state.Selector) &&
            state.LeaseId != Guid.Empty && state.PrivateEndpoint is null && state.Settings is null &&
            state.DeleteVault is null && state.PurgeDeletedVault is null && state.CreateOrUpdateVault is null &&
            state.RecoverVault is null && state.Resources.Length == 3 &&
            state.Resources.All(r => !r.Borrowed) && baseline.Rbac && !baseline.PurgeProtection &&
            baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
        _ = baseline.Build();
        var active = state.Resources.Single(r => !r.CleanupOnly && r.Id.Contains("/vaults/", StringComparison.Ordinal));
        string[] vault = active.Id.Split('/');
        Require(vault.Length == 9 && vault[0].Length == 0 && vault[1] == "subscriptions" &&
            Guid.TryParseExact(vault[2], "D", out var subscription) && subscription != Guid.Empty &&
            vault[3] == "resourceGroups" && vault[4].Length is > 0 and <= 90 &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults");
        _ = new VaultScope(new(new(Guid.Parse(vault[2])), vault[4]), vault[8]);
        string deletedId = $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{baseline.Location}/deletedVaults/{vault[8]}";
        Require(state.Resources.Count(r => r.Id == deletedId && !r.CleanupOnly && !r.SelectedAttempted) == 1 &&
            state.Resources.Count(r => r.Id == active.Id + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1);
        var deleted = state.Resources.Single(r => r.Id == deletedId);
        Require(!active.SelectedAttempted || active.CreateAttempted && deleted.CreateAttempted &&
            (deleted.InvocationTerminated || deleted.DeleteAttempted));
        Require(!active.DeleteAttempted && !deleted.DeleteAttempted || state.Closing);
        Require(!deleted.CreateAttempted || active.CreateAttempted &&
            (active.InvocationTerminated || active.SelectedAttempted || active.DeleteAttempted));
        if (active.SelectedAttempted && !active.DeleteAttempted && active.ActiveDispatch != Guid.Empty)
            Require(!active.Absent && !deleted.Absent && !deleted.DeleteAttempted &&
                deleted.InvocationTerminated && deleted.ActiveDispatch == Guid.Empty);
        if (previous is not null)
        {
            Require(previous.StatusVaultRecoverCancellationBaseline is { } prior &&
                VaultAdministrationEffects.SameConfiguration(prior, baseline) &&
                previous.LeaseId == state.LeaseId && previous.Owner == state.Owner &&
                previous.Selector == state.Selector && (!previous.Closing || state.Closing) &&
                previous.Resources.Length == 3 &&
                previous.Resources.All(p => state.Resources.Count(r => r.Id == p.Id && r.CleanupOnly == p.CleanupOnly &&
                    (!p.CreateAttempted || r.CreateAttempted) && (!p.SelectedAttempted || r.SelectedAttempted) &&
                    (!p.DeleteAttempted || r.DeleteAttempted)) == 1));
        }
        else
            Require(!state.Closing && state.Resources.All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.SelectedAttempted && !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty));
    }

    private static void ValidatePrivateConnectionDeleteState(Snapshot state)
    {
        if (state.PrivateEndpoint?.OriginalDelete is not { } deletion)
        {
            Require(!VaultFixtureProvisioner.PrivateConnectionDeleteSelector(state.Selector) || state.Resources.Length == 0);
            return;
        }
        var slot = state.PrivateEndpoint;
        var d = slot.Declaration;
        Require(VaultFixtureProvisioner.PrivateConnectionDeleteSelector(state.Selector) &&
            slot.OriginalUpdate is null && slot.ApprovalSettledDispatch == Guid.Empty &&
            state.Settings is null && state.DeleteVault is null && state.PurgeDeletedVault is null &&
            state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            Enum.IsDefined(deletion.Disposition) && deletion.Baseline.PublicNetworkAccess &&
            !deletion.Baseline.PurgeProtection && state.Resources.Length == 5 &&
            state.Resources.All(r => !r.SelectedAttempted) &&
            state.Resources.Count(r => r.Id == d.VaultId && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == d.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                !r.Borrowed && !r.CleanupOnly && !r.DeleteAttempted) == 1 &&
            state.Resources.Count(r => r.Id == d.EndpointId && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == d.BorrowedSubnetId && r.Borrowed && !r.CleanupOnly &&
                !r.CreateAttempted && !r.DeleteAttempted && !r.InvocationTerminated &&
                r.ActiveDispatch == Guid.Empty && !r.Absent) == 1 &&
            state.Resources.Count(r => r.CleanupOnly && !r.Borrowed && !r.CreateAttempted &&
                r.Id.Contains("/deletedVaults/", StringComparison.Ordinal)) == 1);
        _ = deletion.Baseline.Build();
        string[] vault = d.VaultId.Split('/');
        Require(vault.Length == 9 && vault[1] == "subscriptions" && vault[3] == "resourceGroups" &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults" &&
            state.Resources.Count(r => r.Id ==
                $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{deletion.Baseline.Location}/deletedVaults/{vault[8]}" &&
                !r.Borrowed && r.CleanupOnly && !r.CreateAttempted) == 1);
        if (slot.Connection is { } child)
            Require(child.Id.StartsWith(d.VaultId + "/privateEndpointConnections/", StringComparison.Ordinal) &&
                child.Id[(d.VaultId.Length + "/privateEndpointConnections/".Length)..] is { Length: > 0 } name &&
                !name.Contains('/') && child.CreateAttempted && !child.Borrowed && !child.CleanupOnly &&
                child.DeleteAttempted == child.SelectedAttempted && slot.CreationDispatch == Guid.Empty);
        if (deletion.InvocationDispatch == Guid.Empty)
            Require(deletion.SettledDispatch == Guid.Empty && deletion.Disposition == PrivateConnectionDeleteDisposition.None &&
                (slot.Connection is null || !slot.Connection.SelectedAttempted &&
                    slot.Connection.ActiveDispatch == Guid.Empty));
        else
        {
            Require(slot.Connection is not null && slot.CreationDispatch == Guid.Empty &&
                state.Resources.Where(r => r.Id == d.VaultId || r.Id == d.EndpointId ||
                    r.Id == d.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary).All(r => r.CreateAttempted));
            if (deletion.SettledDispatch == Guid.Empty)
                Require(deletion.Disposition == PrivateConnectionDeleteDisposition.None &&
                    slot.Connection.ActiveDispatch == deletion.InvocationDispatch && !slot.Connection.Absent &&
                    slot.DeletionDispatch == Guid.Empty &&
                    state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.DeleteAttempted && !r.Absent));
            else
                Require(deletion.SettledDispatch == deletion.InvocationDispatch &&
                    deletion.Disposition is PrivateConnectionDeleteDisposition.Denied or PrivateConnectionDeleteDisposition.Deleted &&
                    slot.Connection.ActiveDispatch == Guid.Empty && slot.Connection.InvocationTerminated &&
                    slot.Connection.SelectedAttempted && slot.Connection.DeleteAttempted);
        }
    }

    private static void ValidatePrivateConnectionUpdateState(Snapshot state)
    {
        if (state.PrivateEndpoint?.OriginalUpdate is not { } update)
        {
            Require(!VaultFixtureProvisioner.PrivateConnectionUpdateSelector(state.Selector) || state.Resources.Length == 0);
            return;
        }
        var slot = state.PrivateEndpoint;
        var d = slot.Declaration;
        Require(VaultFixtureProvisioner.PrivateConnectionUpdateSelector(state.Selector) &&
            slot.OriginalDelete is null &&
            state.Settings is null && state.DeleteVault is null && state.PurgeDeletedVault is null &&
            state.CreateOrUpdateVault is null && state.RecoverVault is null &&
            slot.ApprovalSettledDispatch == Guid.Empty && state.Resources.Length == 5 &&
            update.Requested == Enum.Parse<PrivateConnectionState>(state.Selector.Variant.Split('.')[1]) &&
            Enum.IsDefined(update.Disposition) && update.Baseline.PublicNetworkAccess && !update.Baseline.PurgeProtection &&
            state.Resources.All(r => !r.SelectedAttempted) &&
            state.Resources.Count(r => r.Id == d.VaultId && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == d.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                !r.Borrowed && !r.CleanupOnly && !r.DeleteAttempted) == 1 &&
            state.Resources.Count(r => r.Id == d.EndpointId && !r.Borrowed && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == d.BorrowedSubnetId && r.Borrowed && !r.CleanupOnly &&
                !r.CreateAttempted && !r.DeleteAttempted && !r.InvocationTerminated &&
                r.ActiveDispatch == Guid.Empty && !r.Absent) == 1);
        _ = update.Baseline.Build();
        string[] vault = d.VaultId.Split('/');
        Require(vault.Length == 9 && vault[1] == "subscriptions" && vault[3] == "resourceGroups" &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults" &&
            state.Resources.Count(r => r.Id ==
                $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{update.Baseline.Location}/deletedVaults/{vault[8]}" &&
                !r.Borrowed && r.CleanupOnly && !r.CreateAttempted) == 1);
        if (slot.Connection is { } child)
            Require(child.Id.StartsWith(d.VaultId + "/privateEndpointConnections/", StringComparison.Ordinal) &&
                child.Id[(d.VaultId.Length + "/privateEndpointConnections/".Length)..] is { Length: > 0 } name &&
                !name.Contains('/') && child.CreateAttempted && !child.Borrowed && !child.CleanupOnly &&
                !child.DeleteAttempted && slot.CreationDispatch == Guid.Empty);
        if (update.InvocationDispatch == Guid.Empty)
            Require(update.SettledDispatch == Guid.Empty && update.Disposition == PrivateConnectionUpdateDisposition.None &&
                (slot.Connection is null || !slot.Connection.SelectedAttempted && slot.Connection.ActiveDispatch == Guid.Empty));
        else
        {
            Require(slot.Connection is not null && slot.CreationDispatch == Guid.Empty &&
                state.Resources.Where(r => r.Id == d.VaultId || r.Id == d.EndpointId ||
                    r.Id == d.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary).All(r => r.CreateAttempted));
            if (update.SettledDispatch == Guid.Empty)
                Require(update.Disposition == PrivateConnectionUpdateDisposition.None &&
                    slot.Connection.ActiveDispatch == update.InvocationDispatch && !slot.Connection.Absent &&
                    slot.DeletionDispatch == Guid.Empty &&
                    state.Resources.All(r => r.ActiveDispatch == Guid.Empty && !r.DeleteAttempted && !r.Absent));
            else
                Require(update.SettledDispatch == update.InvocationDispatch &&
                    slot.Connection.ActiveDispatch == Guid.Empty && slot.Connection.InvocationTerminated &&
                    (update.Disposition == PrivateConnectionUpdateDisposition.InvalidInput
                        ? !slot.Connection.SelectedAttempted &&
                            update.Requested is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected)
                        : slot.Connection.SelectedAttempted &&
                            update.Requested is PrivateConnectionState.Approved or PrivateConnectionState.Rejected &&
                            update.Disposition is PrivateConnectionUpdateDisposition.Updated or PrivateConnectionUpdateDisposition.Denied));
        }
    }

    private static void ValidateRecoverVaultState(Snapshot state)
    {
        if (state.RecoverVault is not { } recovery)
        {
            Require(!VaultFixtureProvisioner.RecoverVaultSelector(state.Selector) || state.Resources.Length == 0);
            return;
        }
        Require(VaultFixtureProvisioner.RecoverVaultSelector(state.Selector) &&
            state.CreateOrUpdateVault is null && state.PurgeDeletedVault is null && state.DeleteVault is null &&
            state.Settings is null && state.PrivateEndpoint is null && state.Resources.Length == 3 &&
            state.Resources.All(r => !r.Borrowed) && Enum.IsDefined(recovery.Disposition) &&
            VaultFixtureProvisioner.ValidRecoverVaultConfigurations(state.Selector.Variant, recovery.Baseline, recovery.Selected) &&
            state.Resources.Count(r => r.Id == recovery.VaultId && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == recovery.DeletedVaultId && !r.CleanupOnly && !r.SelectedAttempted) == 1 &&
            state.Resources.Count(r => r.Id == recovery.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1);
        string[] vault = recovery.VaultId.Split('/');
        Require(vault.Length == 9 && vault[1] == "subscriptions" && vault[3] == "resourceGroups" &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults" &&
            recovery.DeletedVaultId ==
                $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{recovery.Baseline.Location}/deletedVaults/{vault[8]}");
        var row = state.Resources.Single(r => r.Id == recovery.VaultId);
        var deleted = state.Resources.Single(r => r.Id == recovery.DeletedVaultId);
        if (recovery.InvocationDispatch == Guid.Empty)
            Require(recovery.SettledDispatch == Guid.Empty && recovery.Disposition == RecoverVaultDisposition.None &&
                recovery.DeletedBaselineSha256 is null && !row.SelectedAttempted && !row.DeleteAttempted);
        else
        {
            Require(row.CreateAttempted && deleted.CreateAttempted && (deleted.InvocationTerminated || deleted.DeleteAttempted) &&
                recovery.DeletedBaselineSha256 is { Length: 64 } hash && hash.All(char.IsAsciiHexDigit));
            if (recovery.SettledDispatch == Guid.Empty)
                Require(recovery.Disposition == RecoverVaultDisposition.None &&
                    row.ActiveDispatch == recovery.InvocationDispatch && !row.DeleteAttempted && !row.Absent &&
                    deleted.InvocationTerminated && !deleted.DeleteAttempted && !deleted.Absent && deleted.ActiveDispatch == Guid.Empty);
            else
                Require(recovery.SettledDispatch == recovery.InvocationDispatch && row.SelectedAttempted &&
                    (row.InvocationTerminated || row.DeleteAttempted) && row.ActiveDispatch != recovery.InvocationDispatch &&
                    recovery.Disposition is RecoverVaultDisposition.Recovered or RecoverVaultDisposition.Denied &&
                    (recovery.Disposition != RecoverVaultDisposition.Denied || !row.DeleteAttempted));
        }
        if (deleted.CreateAttempted && recovery.InvocationDispatch == Guid.Empty)
            Require(row.CreateAttempted && row.InvocationTerminated && row.ActiveDispatch == Guid.Empty);
        Require(!deleted.DeleteAttempted || !recovery.Baseline.PurgeProtection);
    }

    private static void ValidateCreateOrUpdateVaultState(Snapshot state)
    {
        if (state.CreateOrUpdateVault is not { } creation)
        {
            return;
        }
        Require(VaultFixtureProvisioner.CreateOrUpdateVaultSelector(state.Selector) &&
            state.PrivateEndpoint is null && state.Settings is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.Resources.Length == 3 && state.Resources.All(r => !r.Borrowed) &&
            state.Resources.Count(r => r.Id == creation.VaultId && !r.CleanupOnly) == 1 &&
            state.Resources.Count(r => r.Id == creation.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
            Enum.IsDefined(creation.Disposition));
        Require(VaultFixtureProvisioner.ValidCreateVaultConfigurations(state.Selector.Variant,
            creation.Baseline, creation.Selected));
        string[] vault = creation.VaultId.Split('/');
        Require(vault.Length == 9 && vault[1] == "subscriptions" && vault[3] == "resourceGroups" &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults" &&
            state.Resources.Count(r => r.Id ==
                $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{creation.Baseline.Location}/deletedVaults/{vault[8]}" &&
                r.CleanupOnly && !r.CreateAttempted && !r.SelectedAttempted) == 1);
        var row = state.Resources.Single(r => r.Id == creation.VaultId);
        if (creation.InvocationDispatch == Guid.Empty)
            Require(creation.SettledDispatch == Guid.Empty && creation.Disposition == CreateOrUpdateVaultDisposition.None &&
                !row.SelectedAttempted);
        else if (creation.SettledDispatch == Guid.Empty)
            Require(creation.Disposition == CreateOrUpdateVaultDisposition.None &&
                row.ActiveDispatch == creation.InvocationDispatch && row.CreateAttempted && !row.DeleteAttempted && !row.Absent);
        else
            Require(creation.SettledDispatch == creation.InvocationDispatch && row.CreateAttempted && row.SelectedAttempted &&
                (row.InvocationTerminated || row.DeleteAttempted) && row.ActiveDispatch != creation.InvocationDispatch &&
                creation.Disposition is CreateOrUpdateVaultDisposition.Updated or CreateOrUpdateVaultDisposition.Denied);
    }

    private static int Index(Resource[] rows, string id)
    {
        int index = Array.FindIndex(rows, r => r.Id.Equals(id, StringComparison.OrdinalIgnoreCase));
        Require(index >= 0);
        return index;
    }
    private static void ValidateSettingsState(Snapshot state)
    {
        if (state.Settings is not { } settings)
        {
            Require(!IsSettings(state.Selector) || !state.Resources.Any(r => r.SelectedAttempted));
            return;
        }
        Require(IsSettings(state.Selector) && state.PrivateEndpoint is null && state.DeleteVault is null &&
            state.PurgeDeletedVault is null && state.Resources.Length == 3 &&
            state.Resources.All(r => !r.Borrowed) &&
            state.Resources.Count(r => r.Id == settings.VaultId && !r.CleanupOnly) == 1 &&
            state.Resources.Where(r => r.Id != settings.VaultId).All(r => r.CleanupOnly && !r.SelectedAttempted));
        _ = settings.Baseline.Build();
        var row = state.Resources.Single(r => r.Id == settings.VaultId);
        if (settings.InvocationDispatch == Guid.Empty)
            Require(settings.SettledDispatch == Guid.Empty && settings.SettledConfiguration is null && !row.SelectedAttempted);
        else if (settings.SettledDispatch == Guid.Empty)
            Require(settings.SettledConfiguration is null && row.ActiveDispatch == settings.InvocationDispatch &&
                row.CreateAttempted && !row.DeleteAttempted && !row.Absent);
        else
        {
            Require(settings.SettledDispatch == settings.InvocationDispatch && settings.SettledConfiguration is not null &&
                row.CreateAttempted && (row.InvocationTerminated || row.DeleteAttempted) &&
                row.ActiveDispatch != settings.InvocationDispatch);
            _ = settings.SettledConfiguration.Build();
            Require(VaultAdministrationEffects.SameConfiguration(settings.SettledConfiguration, settings.Baseline) ||
                row.SelectedAttempted && VaultAdministrationEffects.SameConfiguration(settings.SettledConfiguration,
                    VaultAdministrationEffects.SettingsConfiguration(settings.Baseline, state.Selector.Variant)));
        }
    }
    private static void ValidateDeleteVaultState(Snapshot state)
    {
        if (state.DeleteVault is not { } deletion)
        {
            Require(!VaultFixtureProvisioner.DeleteVaultSelector(state.Selector) ||
                !state.Resources.Any(r => r.SelectedAttempted));
            return;
        }
        Require(VaultFixtureProvisioner.DeleteVaultSelector(state.Selector) && state.Settings is null &&
            state.PurgeDeletedVault is null &&
            state.PrivateEndpoint is null && state.Resources.Length == 3 &&
            state.Resources.All(r => !r.Borrowed) && !deletion.Baseline.PurgeProtection &&
            Enum.IsDefined(deletion.Disposition) &&
            state.Resources.Count(r => r.Id == deletion.VaultId && !r.CleanupOnly) == 1 &&
            state.Resources.Where(r => r.Id != deletion.VaultId).All(r =>
                r.CleanupOnly && !r.CreateAttempted && !r.SelectedAttempted));
        _ = deletion.Baseline.Build();
        var row = state.Resources.Single(r => r.Id == deletion.VaultId);
        if (deletion.InvocationDispatch == Guid.Empty)
            Require(deletion.SettledDispatch == Guid.Empty && deletion.Disposition == DeleteVaultDisposition.None &&
                !row.SelectedAttempted);
        else if (deletion.SettledDispatch == Guid.Empty)
            Require(deletion.Disposition == DeleteVaultDisposition.None &&
                row.ActiveDispatch == deletion.InvocationDispatch && row.CreateAttempted && !row.DeleteAttempted && !row.Absent);
        else
            Require(deletion.SettledDispatch == deletion.InvocationDispatch && row.CreateAttempted &&
                row.SelectedAttempted && (row.InvocationTerminated || row.DeleteAttempted) &&
                row.ActiveDispatch != deletion.InvocationDispatch &&
                deletion.Disposition is DeleteVaultDisposition.Deleted or DeleteVaultDisposition.Denied &&
                (deletion.Disposition != DeleteVaultDisposition.Deleted || !row.DeleteAttempted));
    }
    private static void ValidatePurgeDeletedVaultState(Snapshot state)
    {
        if (PendingSelector(state.Selector))
        {
            Require(state.Resources.Length == 0 || PendingRoot(state));
            return;
        }
        if (state.PurgeDeletedVault is not { } purge)
        {
            Require(!VaultFixtureProvisioner.PurgeDeletedVaultSelector(state.Selector) || state.Resources.Length == 0);
            return;
        }
        Require(VaultFixtureProvisioner.PurgeDeletedVaultSelector(state.Selector) &&
            purge.PendingStage == StatusPendingPurgeStage.None &&
            state.Settings is null && state.DeleteVault is null && state.PrivateEndpoint is null &&
            state.Resources.Length == 3 && state.Resources.All(r => !r.Borrowed) &&
            !purge.Baseline.PurgeProtection && Enum.IsDefined(purge.Disposition) &&
            state.Resources.Count(r => r.Id == purge.VaultId && !r.CleanupOnly &&
                !r.SelectedAttempted && !r.DeleteAttempted) == 1 &&
            state.Resources.Count(r => r.Id == purge.VaultId + "/secrets/" + VaultFixtureProvisioner.Canary &&
                r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                !r.InvocationTerminated && r.ActiveDispatch == Guid.Empty) == 1 &&
            state.Resources.Count(r => r.Id == purge.DeletedVaultId && !r.CleanupOnly) == 1);
        _ = purge.Baseline.Build();
        string[] vault = purge.VaultId.Split('/');
        Require(vault.Length == 9 && vault[1] == "subscriptions" && vault[3] == "resourceGroups" &&
            vault[5] == "providers" && vault[6] == "Microsoft.KeyVault" && vault[7] == "vaults" &&
            purge.DeletedVaultId == $"/subscriptions/{vault[2]}/providers/Microsoft.KeyVault/locations/{purge.Baseline.Location}/deletedVaults/{vault[8]}");
        var row = state.Resources.Single(r => r.Id == purge.DeletedVaultId);
        var parent = state.Resources.Single(r => r.Id == purge.VaultId);
        if (row.CreateAttempted)
            Require(parent.CreateAttempted && parent.InvocationTerminated && parent.ActiveDispatch == Guid.Empty);
        if (purge.InvocationDispatch == Guid.Empty)
            Require(purge.SettledDispatch == Guid.Empty && purge.Disposition == PurgeDeletedVaultDisposition.None &&
                !row.SelectedAttempted);
        else if (purge.SettledDispatch == Guid.Empty)
            Require(purge.Disposition == PurgeDeletedVaultDisposition.None &&
                row.ActiveDispatch == purge.InvocationDispatch && row.CreateAttempted &&
                !row.DeleteAttempted && !row.Absent);
        else
            Require(purge.SettledDispatch == purge.InvocationDispatch && row.CreateAttempted &&
                row.SelectedAttempted && (row.InvocationTerminated || row.DeleteAttempted) &&
                row.ActiveDispatch != purge.InvocationDispatch &&
                purge.Disposition is PurgeDeletedVaultDisposition.Purged or PurgeDeletedVaultDisposition.Denied &&
                (purge.Disposition != PurgeDeletedVaultDisposition.Purged || !row.DeleteAttempted));
    }

    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw Failure();
    }
    private static InvalidOperationException Failure() => new("role-fixture-journal-unavailable");
    public override string ToString() => "[RoleFixtureJournal]";
}
