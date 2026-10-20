using System.Diagnostics.CodeAnalysis;
using System.Text.Json.Serialization;
using Azure.Core;
using Azure.Core.Pipeline;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;
using Endpoint = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.PrivateEndpointResourceCollector;
using Resource = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.ManagementOperationResourceCollector;
using Vault = SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management.VaultAdministrationCollector;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// Original setup and endpoint-only cleanup. No selected-operation proof, NIC mutation,
// remote qualification, coordinate adoption, or mutation replay.
internal sealed class PrivateEndpointFixtureProvisioner : IAsyncDisposable
{
    internal enum State { Ready, Pending, Incomplete, Uncertain, Closing }
    internal enum CleanupState { Pending, Uncertain, Incomplete, DependenciesAbsent }

    internal sealed class CleanupResult
    {
        internal required CleanupState State { get; init; }
        [JsonIgnore] internal required RoleFixtureJournal.Snapshot Journal { get; init; }
        public override string ToString() => "[PrivateEndpointCleanupResult]";
    }

    internal sealed class Plan(object source, VaultFixtureProvisioner.Plan parent)
    {
        private readonly object source = source;
        private readonly VaultFixtureProvisioner.Plan parent = parent;
        internal bool Matches(object identity, VaultFixtureProvisioner.Plan original) =>
            ReferenceEquals(source, identity) && ReferenceEquals(parent, original);
        public override string ToString() => "[PrivateEndpointFixturePlan]";
    }

    internal sealed class Result
    {
        internal required State State { get; init; }
        [JsonIgnore] internal required RoleFixtureJournal.Snapshot Journal { get; init; }
        [JsonIgnore] internal string? ConnectionId { get; init; }
        public override string ToString() => "[PrivateEndpointFixtureResult]";
    }

    // Construction and matching fields confer no authority. Only the private
    // source registry, populated after its actual original tasks drain, does.
    internal sealed class BindingCandidate(PrivateEndpointFixtureProvisioner source, string connectionId)
    {
        private readonly PrivateEndpointFixtureProvisioner source = source;
        [JsonIgnore] internal string ConnectionId { get; } = connectionId;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateCandidate(this, journal, snapshot);
        public override string ToString() => "[PrivateEndpointBindingCandidate]";
    }

    internal sealed class DeletionCandidate(PrivateEndpointFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateDeletion(this, journal, snapshot);
        public override string ToString() => "[PrivateEndpointDeletionCandidate]";
    }

    internal sealed class AbsenceCandidate(PrivateEndpointFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.ValidateAbsence(this, journal, snapshot);
        public override string ToString() => "[PrivateEndpointAbsenceCandidate]";
    }

    private enum DeniedDeleteStage { Admission, Drain, Absence }
    private sealed record DeniedDeleteFacts(VaultFixtureProvisioner.Plan Parent,
        RoleFixtureJournal.Snapshot Preimage, RoleFixtureJournal.Snapshot Postimage, Guid Dispatch,
        bool Delete, bool Settled, string? ConnectionId, DeniedDeleteStage Stage,
        CancellationToken[] Tokens, Task[] Tasks, Resource.StatusDeniedPrivateConnectionDeleteReadProof? ReadProof = null)
    {
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, DeniedDeleteFacts> deniedDeleteFacts =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<VaultFixtureProvisioner.Plan, object> deniedDeletePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<VaultFixtureProvisioner.Plan, CancellationToken[]> deniedDeleteTokens =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> deniedDeleteRevoked = new();

    internal sealed class StatusDeniedPrivateConnectionDeleteFixtureAdmission(PrivateEndpointFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedDeleteFacts.TryGetValue(this, out var f) ? f.Preimage.PrivateEndpoint!.Declaration.EndpointId : "";
        internal Guid Dispatch => source.deniedDeleteFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedDeleteFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Admission);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Admission, true);
        internal RoleFixtureJournal.Snapshot Postimage => source.DeniedDeletePostimage(this);
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteFixtureAdmission]";
    }
    internal sealed class StatusDeniedPrivateConnectionDeleteFixtureDrain(PrivateEndpointFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedDeleteFacts.TryGetValue(this, out var f) ? f.Preimage.PrivateEndpoint!.Declaration.EndpointId : "";
        internal Guid Dispatch => source.deniedDeleteFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedDeleteFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Settled => source.deniedDeleteFacts.TryGetValue(this, out var f) && f.Settled;
        internal string? ConnectionId => source.deniedDeleteFacts.TryGetValue(this, out var f) ? f.ConnectionId : null;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Drain, true);
        internal RoleFixtureJournal.Snapshot Postimage => source.DeniedDeletePostimage(this);
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteFixtureDrain]";
    }
    internal sealed class StatusDeniedPrivateConnectionDeleteAbsence(PrivateEndpointFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Absence, true);
        internal RoleFixtureJournal.Snapshot Postimage => source.DeniedDeletePostimage(this);
        internal bool ValidateParentDependency(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state, VaultFixtureProvisioner.Plan parent) =>
            source.deniedDeleteFacts.TryGetValue(this, out var f) && ReferenceEquals(f.Parent, parent) &&
            source.ValidateDeniedDelete(this, journal, state, DeniedDeleteStage.Absence, true);
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteAbsence]";
    }
    private RoleFixtureJournal.Snapshot DeniedDeletePostimage(object capability)
    {
        Require(deniedDeleteFacts.TryGetValue(capability, out var f));
        return RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(f.Postimage);
    }
    private bool ValidateDeniedDelete(object capability, RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state,
        DeniedDeleteStage stage, bool postimage = false) =>
        ReferenceEquals(journal, vaultSource.Journal) && deniedDeleteFacts.TryGetValue(capability, out var f) && f.Stage == stage &&
        (stage == DeniedDeleteStage.Drain && !f.Settled ||
            (!closed || deniedDeletePending.TryGetValue(f.Parent, out var retained) && ReferenceEquals(retained, capability)) &&
            !deniedDeleteRevoked.ContainsKey(f.Parent.Selector.Nonce) &&
            f.Tokens.All(t => !t.IsCancellationRequested) &&
            deniedDeleteTokens.GetValueOrDefault(f.Parent, []).All(t => !t.IsCancellationRequested)) &&
        f.Tasks.All(t => t.IsCompleted) &&
        (stage == DeniedDeleteStage.Drain && !f.Settled || f.Tasks.All(t => t.IsCompletedSuccessfully)) &&
        (stage == DeniedDeleteStage.Admission || stage == DeniedDeleteStage.Drain && !f.Settled ||
            f.ConnectionId is null && stage == DeniedDeleteStage.Absence ||
            f.ReadProof is { } proof && proof.NativeTask.IsCompleted &&
            (stage == DeniedDeleteStage.Drain && !f.Delete
                ? proof is { HttpStatus: 200, Phase: Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Discovery,
                    Facts: { State: "Pending", Provisioning: "Succeeded" } } && proof.Facts.Id == f.ConnectionId &&
                    proof.Facts.EndpointId == f.Preimage.PrivateEndpoint!.Declaration.EndpointId
                : proof is { HttpStatus: 404, Facts: null, ErrorCode: "NotFound" or "ResourceNotFound",
                    Phase: Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup })) &&
        RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private void TrackDeniedDeleteTokens(VaultFixtureProvisioner.Plan parent, CancellationToken token, CancellationToken caller)
    {
        var old = deniedDeleteTokens.GetValueOrDefault(parent, []);
        Require(!deniedDeleteRevoked.ContainsKey(parent.Selector.Nonce) &&
            old.All(t => !t.IsCancellationRequested) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        deniedDeleteTokens[parent] = [.. old, token, caller];
    }
    private void RevokeDeniedDelete(VaultFixtureProvisioner.Plan parent)
    {
        deniedDeleteRevoked.TryAdd(parent.Selector.Nonce, 0);
        foreach (var pair in deniedDeleteFacts)
            if (ReferenceEquals(pair.Value.Parent, parent)) deniedDeleteFacts.TryRemove(pair.Key, out _);
        deniedDeletePending.TryRemove(parent, out _);
    }
    internal bool HasStatusDeniedPrivateConnectionDeletePersistence(VaultFixtureProvisioner.Plan parent) =>
        deniedDeletePending.ContainsKey(parent);

    internal RoleFixtureJournal.Snapshot RetryStatusDeniedPrivateConnectionDeletePersistence(VaultFixtureProvisioner.Plan parent)
    {
        Require(deniedDeletePending.TryGetValue(parent, out var capability) &&
            deniedDeleteFacts.TryGetValue(capability, out var f) && ReferenceEquals(f.Parent, parent));
        return PersistDeniedDelete(capability);
    }
    private RoleFixtureJournal.Snapshot PersistDeniedDelete(object capability)
    {
        Require(deniedDeleteFacts.TryGetValue(capability, out var f) &&
            deniedDeletePending.TryGetValue(f.Parent, out var pending) && ReferenceEquals(pending, capability));
        try
        {
            var committed = capability switch
            {
                StatusDeniedPrivateConnectionDeleteFixtureAdmission admission =>
                    vaultSource.Journal.BeginStatusDeniedPrivateConnectionDeleteFixtureDispatch(f.Parent.Owner, f.Parent.Selector, f.Parent.LeaseId, admission),
                StatusDeniedPrivateConnectionDeleteFixtureDrain drain =>
                    vaultSource.Journal.EndStatusDeniedPrivateConnectionDeleteFixtureDispatch(f.Parent.Owner, f.Parent.Selector, f.Parent.LeaseId, drain),
                StatusDeniedPrivateConnectionDeleteAbsence absence =>
                    vaultSource.Journal.RecordStatusDeniedPrivateConnectionDeleteAbsence(f.Parent.Owner, f.Parent.Selector, f.Parent.LeaseId, absence),
                _ => throw new InvalidOperationException("private-endpoint-fixture-boundary")
            };
            Require(RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(f.Postimage, committed));
            if (capability is StatusDeniedPrivateConnectionDeleteAbsence dependency)
                vaultSource.RetainStatusDeniedPrivateConnectionDeleteAbsence(f.Parent, dependency, committed);
            lock (gate)
            {
                var registration = plans.Values.SingleOrDefault(r => ReferenceEquals(r.Parent, f.Parent));
                cleanup.TryGetValue(f.Parent, out var teardown);
                if (capability is StatusDeniedPrivateConnectionDeleteFixtureAdmission)
                {
                    if (!f.Delete && registration is not null)
                    {
                        registration.DeniedDeleteAdmitted = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(committed);
                        registration.Dispatch = f.Dispatch;
                    }
                    if (f.Delete && teardown is not null)
                    {
                        teardown.DeniedDeleteAdmitted = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(committed);
                        teardown.Dispatch = f.Dispatch;
                    }
                }
                if (capability is StatusDeniedPrivateConnectionDeleteFixtureDrain)
                {
                    if (!f.Delete && registration is not null) registration.Bound = f.Settled;
                    if (f.Delete && teardown is not null) teardown.Settled = f.Settled;
                }
                if (capability is StatusDeniedPrivateConnectionDeleteAbsence absence && teardown is not null)
                {
                    teardown.DeniedDeletePublishedAbsence = absence;
                    teardown.DeniedDeleteAbsence = null;
                }
            }
            deniedDeletePending.TryRemove(f.Parent, out _);
            return RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(committed);
        }
        catch (IOException) { throw; }
        catch { RevokeDeniedDelete(f.Parent); throw; }
    }
    private RoleFixtureJournal.Snapshot BeginDeniedDelete(VaultFixtureProvisioner.Plan parent, bool delete, CancellationToken token)
    {
        Require(!deniedDeletePending.ContainsKey(parent));
        var preimage = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(vaultSource.Journal.Read(parent.Owner, parent.Selector));
        Require(!closed && RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(preimage) &&
            !deniedDeleteRevoked.ContainsKey(parent.Selector.Nonce) && !token.IsCancellationRequested);
        var dispatch = Guid.NewGuid();
        var slot = preimage.PrivateEndpoint!;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Borrowed ? r : r.Id == slot.Declaration.EndpointId ? r with
            { CreateAttempted = r.CreateAttempted || !delete, DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false, ActiveDispatch = dispatch, Absent = false } : r with { Absent = false }).ToArray(),
            PrivateEndpoint = slot with { CreationDispatch = delete ? slot.CreationDispatch : dispatch,
                DeletionDispatch = delete ? dispatch : slot.DeletionDispatch, NicAbsent = false,
                Connection = slot.Connection is null ? null : slot.Connection with { Absent = false } }
        };
        var admission = new StatusDeniedPrivateConnectionDeleteFixtureAdmission(this);
        Require(deniedDeleteFacts.TryAdd(admission, new(parent, preimage, postimage, dispatch, delete, false,
            slot.Connection?.Id, DeniedDeleteStage.Admission, [.. deniedDeleteTokens.GetValueOrDefault(parent, []), token], [])));
        Require(deniedDeletePending.TryAdd(parent, admission));
        return PersistDeniedDelete(admission);
    }
    private StatusDeniedPrivateConnectionDeleteFixtureDrain RetainDeniedDeleteDrain(VaultFixtureProvisioner.Plan parent,
        bool delete, bool settled, string? connectionId, Resource.StatusDeniedPrivateConnectionDeleteReadProof? readProof, params Task[] tasks)
    {
        Require(!deniedDeletePending.ContainsKey(parent) && tasks.Length != 0 && tasks.All(t => t.IsCompleted) &&
            (!settled || tasks.All(t => t.IsCompletedSuccessfully)));
        var preimage = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(vaultSource.Journal.Read(parent.Owner, parent.Selector));
        var slot = preimage.PrivateEndpoint!;
        var dispatch = delete ? slot.DeletionDispatch : slot.CreationDispatch;
        Require(dispatch != Guid.Empty);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == slot.Declaration.EndpointId ? r with
                { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray(),
            PrivateEndpoint = !settled ? slot : slot with { CreationDispatch = Guid.Empty, DeletionDispatch = Guid.Empty,
                Connection = slot.Connection ?? new(connectionId!, false, CreateAttempted: true, InvocationTerminated: true) }
        };
        var drain = new StatusDeniedPrivateConnectionDeleteFixtureDrain(this);
        Require(deniedDeleteFacts.TryAdd(drain, new(parent, preimage, postimage, dispatch, delete, settled,
            connectionId, DeniedDeleteStage.Drain, deniedDeleteTokens.GetValueOrDefault(parent, []).ToArray(), tasks.ToArray(), readProof)));
        Require(deniedDeletePending.TryAdd(parent, drain));
        return drain;
    }

    private enum PrivateUpdateIndependentStage { Admission, Drain, Absence }
    private sealed record PrivateUpdateIndependentFacts(VaultFixtureProvisioner.Plan Parent,
        RoleFixtureJournal.Snapshot Preimage, RoleFixtureJournal.Snapshot Postimage, Guid Dispatch,
        bool Delete, bool Settled, string? ConnectionId, PrivateUpdateIndependentStage Stage,
        CancellationToken[] Tokens, Task[] Tasks)
    {
        public override string ToString() => "[PrivateUpdateIndependentFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, PrivateUpdateIndependentFacts> privateUpdateIndependentFacts = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> privateUpdateIndependentRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<VaultFixtureProvisioner.Plan, CancellationToken[]> privateUpdateIndependentTokens = new(ReferenceEqualityComparer.Instance);
    private void TrackPrivateUpdateIndependentTokens(VaultFixtureProvisioner.Plan parent, CancellationToken token, CancellationToken caller)
    {
        var old = privateUpdateIndependentTokens.GetValueOrDefault(parent, []);
        Require(old.All(t => !t.IsCancellationRequested) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        privateUpdateIndependentTokens[parent] = [.. old, token, caller];
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentFixtureAdmission(PrivateEndpointFixtureProvisioner source)
    {
        internal string ResourceId => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Preimage.PrivateEndpoint!.Declaration.EndpointId : "";
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Admission);
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentFixtureDrain(PrivateEndpointFixtureProvisioner source)
    {
        internal string ResourceId => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Preimage.PrivateEndpoint!.Declaration.EndpointId : "";
        internal Guid Dispatch => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) && f.Settled;
        internal string? ConnectionId => source.privateUpdateIndependentFacts.TryGetValue(this, out var f) ? f.ConnectionId : null;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Drain, true);
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentAbsence(PrivateEndpointFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Absence, true);
        internal bool ValidateParentDependency(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state, VaultFixtureProvisioner.Plan parent) =>
            source.privateUpdateIndependentFacts.TryGetValue(this, out var f) && ReferenceEquals(f.Parent, parent) &&
            source.ValidatePrivateUpdateIndependent(this, journal, state, PrivateUpdateIndependentStage.Absence, true);
    }
    private bool ValidatePrivateUpdateIndependent(object capability, RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state,
        PrivateUpdateIndependentStage stage, bool postimage = false) =>
        !closed && ReferenceEquals(journal, vaultSource.Journal) && privateUpdateIndependentFacts.TryGetValue(capability, out var f) &&
        !privateUpdateIndependentRevoked.ContainsKey(f.Parent.Selector.Nonce) && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) &&
        privateUpdateIndependentTokens.GetValueOrDefault(f.Parent, []).All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompletedSuccessfully) &&
        RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);
    private static RoleFixtureJournal.Snapshot FreezePrivateUpdateIndependent(RoleFixtureJournal.Snapshot state) => state with
    {
        Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray(),
        PrivateEndpoint = state.PrivateEndpoint! with { Declaration = state.PrivateEndpoint.Declaration with { },
            Connection = state.PrivateEndpoint.Connection is null ? null : state.PrivateEndpoint.Connection with { } }
    };
    private void RevokePrivateUpdateIndependent(VaultFixtureProvisioner.Plan parent)
    {
        privateUpdateIndependentRevoked.TryAdd(parent.Selector.Nonce, 0);
        foreach (var pair in privateUpdateIndependentFacts)
            if (pair.Value.Parent.Selector == parent.Selector) privateUpdateIndependentFacts.TryRemove(pair.Key, out _);
    }
    private RoleFixtureJournal.Snapshot BeginPrivateUpdateIndependent(VaultFixtureProvisioner.Plan parent, bool delete, CancellationToken[] tokens)
    {
        var preimage = FreezePrivateUpdateIndependent(vaultSource.Journal.Read(parent.Owner, parent.Selector));
        Require(!closed && !privateUpdateIndependentRevoked.ContainsKey(parent.Selector.Nonce) && tokens.All(t => !t.IsCancellationRequested));
        Guid dispatch = Guid.NewGuid();
        var slot = preimage.PrivateEndpoint!;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Borrowed ? r : r.Id == slot.Declaration.EndpointId ? r with
            { CreateAttempted = r.CreateAttempted || !delete, DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false, ActiveDispatch = dispatch, Absent = false } : r with { Absent = false }).ToArray(),
            PrivateEndpoint = slot with { CreationDispatch = delete ? slot.CreationDispatch : dispatch,
                DeletionDispatch = delete ? dispatch : slot.DeletionDispatch, NicAbsent = false,
                Connection = slot.Connection is null ? null : slot.Connection with { Absent = false } }
        };
        var admission = new StatusPrivateConnectionUpdateIndependentFixtureAdmission(this);
        Require(privateUpdateIndependentFacts.TryAdd(admission, new(parent, preimage, postimage, dispatch, delete, false,
            slot.Connection?.Id, PrivateUpdateIndependentStage.Admission, [.. privateUpdateIndependentTokens.GetValueOrDefault(parent, []), .. tokens], [])));
        try
        {
            var committed = vaultSource.Journal.BeginStatusPrivateConnectionUpdateIndependentFixtureDispatch(parent.Owner, parent.Selector, parent.LeaseId, admission);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(postimage, committed));
            return FreezePrivateUpdateIndependent(committed);
        }
        finally { privateUpdateIndependentFacts.TryRemove(admission, out _); }
    }
    private StatusPrivateConnectionUpdateIndependentFixtureDrain RetainPrivateUpdateIndependentDrain(VaultFixtureProvisioner.Plan parent,
        RoleFixtureJournal.Snapshot admitted, bool delete, string? connectionId, CancellationToken[] tokens, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompletedSuccessfully) && tokens.All(t => !t.IsCancellationRequested));
        var preimage = FreezePrivateUpdateIndependent(admitted);
        var slot = preimage.PrivateEndpoint!;
        Guid dispatch = delete ? slot.DeletionDispatch : slot.CreationDispatch;
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == slot.Declaration.EndpointId ? r with
                { InvocationTerminated = true, ActiveDispatch = Guid.Empty } : r).ToArray(),
            PrivateEndpoint = slot with { CreationDispatch = Guid.Empty, DeletionDispatch = Guid.Empty,
                Connection = slot.Connection ?? new(connectionId!, false, CreateAttempted: true, InvocationTerminated: true) }
        };
        var drain = new StatusPrivateConnectionUpdateIndependentFixtureDrain(this);
        Require(privateUpdateIndependentFacts.TryAdd(drain, new(parent, preimage, postimage, dispatch, delete, true,
            connectionId, PrivateUpdateIndependentStage.Drain, [.. privateUpdateIndependentTokens.GetValueOrDefault(parent, []), .. tokens], tasks.ToArray())));
        return drain;
    }
    private RoleFixtureJournal.Snapshot PersistPrivateUpdateIndependentDrain(StatusPrivateConnectionUpdateIndependentFixtureDrain drain)
    {
        Require(privateUpdateIndependentFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = vaultSource.Journal.EndStatusPrivateConnectionUpdateIndependentFixtureDispatch(f.Parent.Owner, f.Parent.Selector, f.Parent.LeaseId, drain);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(f.Postimage, committed));
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokePrivateUpdateIndependent(f.Parent); throw; }
    }
    private CleanupResult PersistPrivateUpdateIndependentAbsence(CleanupRegistration r)
    {
        var absence = r.IndependentAbsence!;
        Require(privateUpdateIndependentFacts.TryGetValue(absence, out var f));
        try
        {
            var committed = vaultSource.Journal.RecordStatusPrivateConnectionUpdateIndependentAbsence(r.Parent.Owner, r.Parent.Selector, r.Parent.LeaseId, absence);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(f.Postimage, committed));
            vaultSource.RetainStatusPrivateConnectionUpdateIndependentAbsence(r.Parent, absence, committed);
            r.IndependentPublishedAbsence = absence;
            r.IndependentAbsence = null;
            return CleanupFinish(r, CleanupState.DependenciesAbsent);
        }
        catch (IOException) { throw; }
        catch { RevokePrivateUpdateIndependent(r.Parent); throw; }
    }

    private sealed class CleanupRegistration(VaultFixtureProvisioner.Plan parent, Endpoint.Binding binding)
    {
        internal readonly VaultFixtureProvisioner.Plan Parent = parent;
        internal readonly Endpoint.Binding Binding = binding;
        internal readonly CancellationTokenSource Stop = new();
        internal readonly List<CancellationToken> IndependentTokens = [];
        internal RoleFixtureJournal.Snapshot? IndependentAdmitted;
        internal StatusPrivateConnectionUpdateIndependentFixtureDrain? IndependentDrain;
        internal StatusPrivateConnectionUpdateIndependentAbsence? IndependentAbsence, IndependentPublishedAbsence;
        internal RoleFixtureJournal.Snapshot? DeniedDeleteAdmitted;
        internal StatusDeniedPrivateConnectionDeleteFixtureDrain? DeniedDeleteDrain;
        internal StatusDeniedPrivateConnectionDeleteAbsence? DeniedDeleteAbsence, DeniedDeletePublishedAbsence;
        internal Resource.StatusDeniedPrivateConnectionDeleteReadProof? DeniedDeleteBeforeChild;
        internal Task<Endpoint.Measurement>? IndependentBeforeEndpoint;
        internal TaskCompletionSource? Drained;
        internal PrivateEndpointNativeCapture? Native;
        internal PrivateEndpointNativeCapture.DeleteWindow? Window;
        internal Task<SecretStatus>? Start, Check;
        internal Task<Resource.Measurement>? BeforeDeleteChildRead;
        internal DeleteChildAbsence? BeforeDeleteChildAbsence;
        internal RoleFixtureJournal.AbsenceRevision? BeforeDeleteDrainRevision;
        internal PrivateEndpointNativeCapture.DeletionProof? Proof;
        internal DeletionCandidate? Candidate;
        internal string? ConnectionId;
        internal Guid Dispatch;
        internal bool Consumed;
        internal volatile bool Busy, SettlementAttempted, Settled;
    }

    private sealed record DeleteChildAbsence(ManagementOperationNativeCapture.Binding Binding,
        Resource.Window Window, RoleFixtureJournal.AbsenceRevision Revision, string ConnectionId,
        Task<Resource.Measurement> Task, Resource.Measurement Measurement,
        Resource.StatusPrivateConnectionDeleteReadProof? StatusDeleteProof = null,
        Resource.StatusPrivateConnectionDeleteSelectedReadProof? SelectedDeleteProof = null,
        Resource.StatusPrivateConnectionDeleteIndependentReadProof? IndependentDeleteProof = null);

    private sealed class AbsenceObservation(CleanupRegistration registration,
        RoleFixtureJournal.AbsenceRevision revision, string? connectionId, CancellationToken cancellation)
    {
        internal readonly CleanupRegistration Registration = registration;
        internal readonly RoleFixtureJournal.AbsenceRevision Revision = revision;
        internal readonly string? ConnectionId = connectionId;
        internal readonly CancellationToken Cancellation = cancellation;
        internal Task<Endpoint.Measurement>? EndpointRead, NicRead;
        internal Task<Resource.Measurement>? ChildRead;
        internal Resource.StatusPrivateConnectionUpdateReadProof? StatusPrivateChildAbsence;
        internal Resource.StatusPrivateConnectionDeleteReadProof? StatusPrivateDeleteChildAbsence;
        internal Resource.StatusPrivateConnectionDeleteSelectedReadProof? StatusPrivateDeleteSelectedChildAbsence;
        internal Resource.StatusPrivateConnectionDeleteIndependentReadProof? StatusPrivateDeleteIndependentChildAbsence;
    }

    private sealed class Registration(Plan plan, VaultFixtureProvisioner.Plan parent, Endpoint.Binding binding,
        PrivateEndpointNativeCapture native, PrivateEndpointNativeCapture.Window window)
    {
        internal readonly Plan Plan = plan;
        internal readonly VaultFixtureProvisioner.Plan Parent = parent;
        internal readonly Endpoint.Binding Binding = binding;
        internal readonly PrivateEndpointNativeCapture Native = native;
        internal readonly PrivateEndpointNativeCapture.Window Window = window;
        internal readonly CancellationTokenSource Stop = new();
        internal readonly List<CancellationToken> IndependentTokens = [];
        internal RoleFixtureJournal.Snapshot? IndependentAdmitted;
        internal StatusPrivateConnectionUpdateIndependentFixtureDrain? IndependentDrain;
        internal Resource.StatusPrivateConnectionUpdateIndependentReadProof? IndependentDiscovery;
        internal RoleFixtureJournal.Snapshot? DeniedDeleteAdmitted;
        internal StatusDeniedPrivateConnectionDeleteFixtureDrain? DeniedDeleteDrain;
        internal Resource.StatusDeniedPrivateConnectionDeleteReadProof? DeniedDeleteDiscovery;
        internal TaskCompletionSource? Drained;
        internal Task<Endpoint.Measurement>? EndpointAbsent, NicAbsent, EndpointRead;
        internal Task<Vault.Measurement>? Inventory;
        internal Task<Resource.Measurement>? ConnectionRead;
        internal Task<SecretStatus>? Start, Check;
        internal PrivateEndpointNativeCapture.CreationProof? Proof;
        internal BindingCandidate? Candidate;
        internal Guid Dispatch;
        internal bool Consumed;
        internal volatile bool Busy, BindingAttempted, Bound;
    }

    private readonly VaultFixtureProvisioner vaultSource;
    private readonly Resource.Authority endpointReader;
    private readonly Vault.Authority vaultReader;
    private readonly Resource.Authority endpointSetup;
    private readonly Resource.Limits limits;
    private readonly Vault.Limits inventoryLimits;
    private readonly TimeProvider time;
    private readonly object source = new(), gate = new();
    private readonly Dictionary<Plan, Registration> plans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<BindingCandidate, Registration> candidates =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<VaultFixtureProvisioner.Plan, CleanupRegistration> cleanup =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<DeletionCandidate, CleanupRegistration> deletions =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<AbsenceCandidate, AbsenceObservation> absences =
        new(ReferenceEqualityComparer.Instance);
    private volatile bool closed;
    private Task? disposal;

    internal PrivateEndpointFixtureProvisioner(VaultFixtureProvisioner vaultSource,
        Resource.Authority endpointSetup, Resource.Authority endpointReader, Vault.Authority vaultReader,
        Resource.Limits limits, Vault.Limits inventoryLimits, TimeProvider? time = null)
    {
        Require(vaultSource is not null && endpointSetup is not null && endpointReader is not null &&
            vaultReader is not null && endpointSetup.Credential is not null && endpointReader.Credential is not null &&
            vaultReader.Credential is not null && endpointSetup.Transport is not null &&
            endpointReader.Transport is not null && vaultReader.Transport is not null &&
            !ReferenceEquals(endpointSetup.Credential, endpointReader.Credential) &&
            !ReferenceEquals(endpointSetup.Transport, endpointReader.Transport) &&
            !ReferenceEquals(endpointSetup.Credential, vaultReader.Credential) &&
            !ReferenceEquals(endpointSetup.Transport, vaultReader.Transport) &&
            endpointSetup.Label != endpointReader.Label && endpointSetup.Label != vaultReader.Label);
        this.vaultSource = vaultSource;
        this.endpointSetup = endpointSetup;
        this.endpointReader = endpointReader;
        this.vaultReader = vaultReader;
        this.limits = limits;
        this.inventoryLimits = inventoryLimits;
        this.time = time ?? TimeProvider.System;
        // Validate the existing sources' contracts without invoking host time,
        // credentials, transport, or any provider work.
        _ = new Endpoint(endpointReader, limits, this.time);
        _ = new Vault(vaultReader, inventoryLimits, this.time);
        _ = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport),
            limits, this.time, vaultSource.FixtureTenantId);
    }

    internal Plan PlanDeclaredEndpoint(VaultFixtureProvisioner.Plan originalParent)
    {
        lock (gate)
        {
            Require(!closed && vaultSource.OwnsPreparedPlan(originalParent) &&
                originalParent.PrivateEndpoint is not null &&
                (!originalParent.SeedCanary || VaultFixtureProvisioner.PrivateConnectionReadProfile(originalParent) ||
                    originalParent.OriginalPrivateConnectionUpdate || originalParent.OriginalPrivateConnectionDelete) &&
                originalParent.PolicyChildren.Count == 0 && originalParent.OwnedNotificationNames.Count == 0 &&
                !plans.Values.Any(r => ReferenceEquals(r.Parent, originalParent)));
            var binding = vaultSource.EndpointBinding(originalParent);
            var snapshot = vaultSource.Journal.Read(originalParent.Owner, originalParent.Selector);
            Require(snapshot.PrivateEndpoint is { Connection: null, CreationDispatch: var dispatch } &&
                dispatch == Guid.Empty && snapshot.Resources.Single(r => r.Id == binding.EndpointId) is
                { CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false, Absent: false });
            Registration? registration = null;
            var transport = new SetupTransport(endpointSetup.Transport,
                () => ValidateBeforeSend(registration ?? throw new InvalidOperationException("private-endpoint-fixture-boundary")));
            var native = new PrivateEndpointNativeCapture(new(endpointSetup.Label, endpointSetup.Credential, transport), limits, time);
            var plan = new Plan(source, originalParent);
            registration = new(plan, originalParent, binding, native, native.Arm(binding));
            plans.Add(plan, registration);
            return plan;
        }
    }

    internal async ValueTask<Result> ProvisionAsync(Plan originalPlan, CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Registration r = Enter(originalPlan, preparation: true);
        try
        {
            lock (gate) { Require(!r.Consumed); r.Consumed = true; }
            if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
            {
                Require(!HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent));
                TrackDeniedDeleteTokens(r.Parent, cancellationToken, originalCallerToken ?? cancellationToken);
            }
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
            {
                TrackPrivateUpdateIndependentTokens(r.Parent, cancellationToken, originalCallerToken ?? cancellationToken);
                r.IndependentTokens.Add(cancellationToken);
                r.IndependentTokens.Add(originalCallerToken ?? cancellationToken);
                r.IndependentAdmitted = BeginPrivateUpdateIndependent(r.Parent, false, r.IndependentTokens.ToArray());
                r.Dispatch = r.IndependentAdmitted.PrivateEndpoint!.CreationDispatch;
            }
            using var linked = VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. deniedDeleteTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. privateUpdateIndependentTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, r.Stop.Token);
            // These are fresh original observations by distinct single-arm
            // collectors. A matching tag never permits overwriting either row.
            var endpoint = new Endpoint(endpointReader, limits, time);
            r.EndpointAbsent = endpoint.CollectAsync(endpoint.Arm(r.Binding), r.Binding, linked.Token).AsTask();
            var before = await r.EndpointAbsent.ConfigureAwait(false);
            if (!before.ResponseComplete || before.Kind != Endpoint.ReadKind.Endpoint ||
                before.ResourceStatus != SecretStatus.Absent) return Finish(r, State.Incomplete);
            var nic = new Endpoint(endpointReader, limits, time);
            r.NicAbsent = nic.CollectAsync(nic.ArmNicAbsence(r.Binding), r.Binding, linked.Token).AsTask();
            var beforeNic = await r.NicAbsent.ConfigureAwait(false);
            if (!beforeNic.ResponseComplete || beforeNic.Kind != Endpoint.ReadKind.NicAbsence ||
                beforeNic.ResourceStatus != SecretStatus.Absent) return Finish(r, State.Incomplete);
            r.Start = r.Native.StartAsync(r.Window, r.Binding, () =>
            {
                lock (gate)
                {
                    Require(!closed && (r.IndependentAdmitted is not null || r.Dispatch == Guid.Empty));
                    linked.Token.ThrowIfCancellationRequested();
                    if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
                    {
                        r.DeniedDeleteAdmitted = BeginDeniedDelete(r.Parent, false, linked.Token);
                        r.Dispatch = r.DeniedDeleteAdmitted.PrivateEndpoint!.CreationDispatch;
                    }
                    else if (r.IndependentAdmitted is null) r.Dispatch = vaultSource.BeginPrivateEndpointCreate(r.Parent);
                    else Require(r.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                        RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(r.IndependentAdmitted, Snapshot(r)));
                    var admitted = Snapshot(r);
                    Require(admitted.PrivateEndpoint?.CreationDispatch == r.Dispatch &&
                        admitted.Resources.Single(row => row.Id == r.Binding.EndpointId).ActiveDispatch == r.Dispatch);
                    return r.Dispatch;
                }
            }, linked.Token).AsTask();
            if (await r.Start.ConfigureAwait(false) != SecretStatus.Success) return Finish(r, State.Uncertain);
            return await CompleteCore(r, linked.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(r, State.Uncertain);
        }
        finally
        {
            try { RetainCreationFence(r); }
            finally { Exit(r); }
        }
    }

    internal bool OwnsBoundPlan(Plan originalEndpointPlan, VaultFixtureProvisioner.Plan originalParent,
        string connectionId)
    {
        lock (gate)
        {
            if (originalParent is not null && VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(originalParent.Selector))
            {
                if (closed || originalEndpointPlan is null || originalParent.Restored ||
                    !plans.TryGetValue(originalEndpointPlan, out var denied) || denied.Busy || !denied.Consumed || !denied.Bound ||
                    !ReferenceEquals(denied.Parent, originalParent) || !originalEndpointPlan.Matches(source, originalParent) ||
                    denied.DeniedDeleteDrain is null || denied.DeniedDeleteDiscovery is null ||
                    HasStatusDeniedPrivateConnectionDeletePersistence(originalParent) ||
                    !deniedDeleteFacts.TryGetValue(denied.DeniedDeleteDrain, out var f) ||
                    f.Stage != DeniedDeleteStage.Drain || !f.Settled || f.Delete || f.ConnectionId != connectionId ||
                    deniedDeleteRevoked.ContainsKey(originalParent.Selector.Nonce) ||
                    f.Tokens.Any(t => t.IsCancellationRequested) ||
                    deniedDeleteTokens.GetValueOrDefault(originalParent, []).Any(t => t.IsCancellationRequested) ||
                    f.Tasks.Any(t => !t.IsCompletedSuccessfully)) return false;
                var current = Snapshot(denied);
                return vaultSource.MatchesOwnedPlan(originalParent, current) &&
                    RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(current) &&
                    current.PrivateEndpoint is { CreationDispatch: var deniedCreation, Connection: { } deniedChild } &&
                    deniedCreation == Guid.Empty && deniedChild.Id == connectionId && deniedChild.CreateAttempted && !deniedChild.Borrowed && !deniedChild.CleanupOnly &&
                    current.PrivateEndpoint.Declaration == f.Postimage.PrivateEndpoint!.Declaration &&
                    current.Resources[3] is { CreateAttempted: true, InvocationTerminated: true, ActiveDispatch: var deniedActive } &&
                    deniedActive == Guid.Empty;
            }
            if (originalParent is not null && VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(originalParent.Selector))
            {
                if (closed || originalEndpointPlan is null || originalParent.Restored || !plans.TryGetValue(originalEndpointPlan, out var independent) ||
                    !ReferenceEquals(independent.Parent, originalParent) || !originalEndpointPlan.Matches(source, originalParent) || independent.Busy ||
                    !independent.Bound || independent.IndependentDrain is null || !privateUpdateIndependentFacts.TryGetValue(independent.IndependentDrain, out var facts) ||
                    facts.ConnectionId != connectionId || facts.Stage != PrivateUpdateIndependentStage.Drain || !facts.Settled ||
                    privateUpdateIndependentRevoked.ContainsKey(originalParent.Selector.Nonce) || facts.Tokens.Any(t => t.IsCancellationRequested) ||
                    privateUpdateIndependentTokens.GetValueOrDefault(originalParent, []).Any(t => t.IsCancellationRequested) ||
                    facts.Tasks.Any(t => !t.IsCompletedSuccessfully)) return false;
                var current = Snapshot(independent);
                return RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(current) && current.PrivateEndpoint!.Connection?.Id == connectionId &&
                    current.PrivateEndpoint.Declaration == facts.Postimage.PrivateEndpoint!.Declaration && current.PrivateEndpoint.CreationDispatch == Guid.Empty;
            }
            if (closed || originalEndpointPlan is null || originalParent is null || originalParent.Restored ||
                !plans.TryGetValue(originalEndpointPlan, out var r) ||
                !ReferenceEquals(r.Parent, originalParent) || !originalEndpointPlan.Matches(source, originalParent) ||
                r.Busy || !r.Bound || !r.Consumed || r.Dispatch == Guid.Empty || r.Candidate is null ||
                !candidates.TryGetValue(r.Candidate, out var registered) || !ReferenceEquals(registered, r) ||
                r.Candidate.ConnectionId != connectionId || r.Proof is null ||
                r.Start is not { IsCompletedSuccessfully: true } || r.Start.Result != SecretStatus.Success ||
                r.Check is not { IsCompletedSuccessfully: true } || r.Check.Result != SecretStatus.Success ||
                r.EndpointAbsent is not { IsCompletedSuccessfully: true } ||
                r.NicAbsent is not { IsCompletedSuccessfully: true } ||
                r.EndpointRead is not { IsCompletedSuccessfully: true } ||
                r.Inventory is not { IsCompletedSuccessfully: true } ||
                r.ConnectionRead is not { IsCompletedSuccessfully: true } ||
                !r.Native.OwnsCreationProof(r.Proof, r.Window, r.Binding, r.Dispatch)) return false;
            var snapshot = Snapshot(r);
            return vaultSource.MatchesOwnedPlan(originalParent, snapshot) &&
                snapshot.PrivateEndpoint is { CreationDispatch: var creation, Connection: { } child } &&
                creation == Guid.Empty && child.Id == connectionId &&
                child is { CreateAttempted: true, Borrowed: false, CleanupOnly: false } &&
                snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId) is
                { CreateAttempted: true, InvocationTerminated: true };
        }
    }

    // Continues only this source's retained original work or a local durable
    // append. It cannot recreate the endpoint, rearm a reader, or rebind.
    internal async ValueTask<Result> CompleteBindingAsync(Plan originalPlan, CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Registration r = Enter(originalPlan, preparation: false);
        try
        {
            if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
            {
                if (HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent))
                    _ = RetryStatusDeniedPrivateConnectionDeletePersistence(r.Parent);
                TrackDeniedDeleteTokens(r.Parent, cancellationToken, originalCallerToken ?? cancellationToken);
            }
            Require(r.Consumed && r.Dispatch != Guid.Empty);
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
            {
                Require(r.IndependentTokens.All(t => !t.IsCancellationRequested));
                TrackPrivateUpdateIndependentTokens(r.Parent, cancellationToken, originalCallerToken ?? cancellationToken);
                r.IndependentTokens.Add(cancellationToken);
                r.IndependentTokens.Add(originalCallerToken ?? cancellationToken);
            }
            using var linked = VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. deniedDeleteTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. privateUpdateIndependentTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, r.Stop.Token);
            return await CompleteCore(r, linked.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(r, State.Uncertain);
        }
        finally
        {
            try { RetainCreationFence(r); }
            finally { Exit(r); }
        }
    }

    // Only the parent's registered original plan or OpenCleanupPlan result is
    // accepted. A restart may own coordinates, never an active original proof.
    internal ValueTask<CleanupResult> CleanupAsync(VaultFixtureProvisioner.Plan parent,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null) =>
        CleanupCore(parent, delete: true, parentEntered: false, cancellationToken, originalCallerToken);

    internal ValueTask<CleanupResult> RefreshAbsenceAsync(VaultFixtureProvisioner.Plan parent,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null) =>
        CleanupCore(parent, delete: false, parentEntered: false, cancellationToken, originalCallerToken);

    // Release explicitly calls this between its observations and mutations.
    // It lends its already-held parent entry, never a measurement or callback.
    internal ValueTask<CleanupResult> RefreshAbsenceForParentAsync(VaultFixtureProvisioner parentSource,
        VaultFixtureProvisioner.Plan parent, CancellationToken cancellationToken, CancellationToken? originalCallerToken = null)
    {
        Require(ReferenceEquals(parentSource, vaultSource) && parent.Busy == 1);
        return CleanupCore(parent, delete: false, parentEntered: true, cancellationToken, originalCallerToken);
    }

    private async ValueTask<CleanupResult> CleanupCore(VaultFixtureProvisioner.Plan parent, bool delete,
        bool parentEntered, CancellationToken cancellationToken, CancellationToken? originalCallerToken)
    {
        if (parent is not null && VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector))
        {
            deniedDeletePending.TryGetValue(parent, out var retained);
            foreach (var pair in deniedDeleteFacts)
                if (ReferenceEquals(pair.Value.Parent, parent) && pair.Value.Stage == DeniedDeleteStage.Absence &&
                    !ReferenceEquals(pair.Key, retained)) deniedDeleteFacts.TryRemove(pair.Key, out _);
        }
        cancellationToken.ThrowIfCancellationRequested();
        CleanupRegistration r;
        lock (gate)
        {
            Require(!closed && parent is not null);
            Require(!VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector) ||
                !HasStatusDeniedPrivateConnectionDeletePersistence(parent));
            var binding = vaultSource.EndpointBinding(parent);
            var snapshot = delete ? vaultSource.CloseSelectedRoot(parent.Owner, parent.Selector) :
                vaultSource.Journal.Read(parent.Owner, parent.Selector);
            Require(vaultSource.MatchesOwnedPlan(parent, snapshot));
            if (!cleanup.TryGetValue(parent, out r!))
            {
                r = new(parent, binding);
                cleanup.Add(parent, r);
            }
            if (r.Busy || !parentEntered && !vaultSource.TryEnterNotification(parent, preparation: false))
                return CleanupFinish(r, CleanupState.Pending);
            r.Busy = true;
            r.Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        try
        {
            if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector))
                TrackDeniedDeleteTokens(parent, cancellationToken, originalCallerToken ?? cancellationToken);
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(parent.Selector))
            {
                lock (gate)
                {
                    Require(r.IndependentTokens.All(t => !t.IsCancellationRequested));
                    TrackPrivateUpdateIndependentTokens(parent, cancellationToken, originalCallerToken ?? cancellationToken);
                    r.IndependentTokens.Add(cancellationToken);
                    r.IndependentTokens.Add(originalCallerToken ?? cancellationToken);
                }
            }
            using var linked = VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. deniedDeleteTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. privateUpdateIndependentTokens.GetValueOrDefault(r.Parent, []), cancellationToken, r.Stop.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, r.Stop.Token);
            var snapshot = CleanupSnapshot(r);
            if (!snapshot.Closing) return CleanupFinish(r, CleanupState.Pending);
            // Absence never settles selected work. Only its already-durable,
            // exact approval marker can permit endpoint cleanup.
            if (!snapshot.PrivateConnectionCleanupEligible)
            {
                if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector) ||
                    VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(parent.Selector))
                    _ = vaultSource.Journal.InvalidatePrivateEndpointAbsence(parent.Owner, parent.Selector);
                else _ = vaultSource.Journal.BeginPrivateEndpointAbsence(parent.Owner, parent.Selector, parent.LeaseId);
                return CleanupFinish(r, CleanupState.Uncertain);
            }
            if (delete && snapshot.PrivateEndpoint!.CreationDispatch == Guid.Empty)
            {
                if (r.Dispatch != Guid.Empty && !r.Settled)
                {
                    if (!await CompleteDeletion(r, linked.Token).ConfigureAwait(false))
                        return CleanupFinish(r, CleanupState.Uncertain);
                }
                else if (snapshot.Idle && snapshot.PrivateEndpoint.Connection is { } child &&
                    snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId) is { DeleteAttempted: false })
                {
                    if (r.Consumed) return CleanupFinish(r, CleanupState.Uncertain);
                    r.Consumed = true;
                    r.ConnectionId = child.Id;
                    if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(parent.Selector))
                    {
                        r.IndependentAdmitted = BeginPrivateUpdateIndependent(parent, true, [.. r.IndependentTokens, linked.Token]);
                        r.Dispatch = r.IndependentAdmitted.PrivateEndpoint!.DeletionDispatch;
                    }
                    var transport = new DeleteTransport(endpointSetup.Transport,
                        message => ValidateDeleteBeforeSendAsync(r, message));
                    r.Native = new(new(endpointSetup.Label, endpointSetup.Credential, transport), limits, time);
                    r.Window = r.Native.ArmDelete(r.Binding);
                    r.Start = r.Native.StartDeleteAsync(r.Window, r.Binding, () =>
                    {
                        linked.Token.ThrowIfCancellationRequested();
                        Require(!closed && r.Busy && r.ConnectionId is not null && (r.IndependentAdmitted is not null || r.Dispatch == Guid.Empty));
                        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector))
                        {
                            r.DeniedDeleteAdmitted = BeginDeniedDelete(parent, true, linked.Token);
                            r.Dispatch = r.DeniedDeleteAdmitted.PrivateEndpoint!.DeletionDispatch;
                        }
                        else if (r.IndependentAdmitted is null)
                            r.Dispatch = vaultSource.Journal.BeginPrivateEndpointDelete(parent.Owner, parent.Selector, parent.LeaseId, parent.PrivateEndpoint!, r.ConnectionId);
                        else Require(r.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(r.IndependentAdmitted, CleanupSnapshot(r)));
                        return r.Dispatch;
                    }, linked.Token).AsTask();
                    if (!await CompleteDeletion(r, linked.Token).ConfigureAwait(false))
                        return CleanupFinish(r, CleanupState.Uncertain);
                }
            }
            return await RefreshCore(r, linked.Token).ConfigureAwait(false);
        }
        catch (Exception)
        {
            if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(parent.Selector))
            {
                if (r.DeniedDeletePublishedAbsence is { } old) deniedDeleteFacts.TryRemove(old, out _);
                r.DeniedDeletePublishedAbsence = null;
                if (r.DeniedDeleteAbsence is null && !HasStatusDeniedPrivateConnectionDeletePersistence(parent))
                    _ = vaultSource.Journal.InvalidatePrivateEndpointAbsence(parent.Owner, parent.Selector);
            }
            cancellationToken.ThrowIfCancellationRequested();
            return CleanupFinish(r, CleanupState.Uncertain);
        }
        finally
        {
            try
            {
                // A local journal failure can occur while the actual original
                // start is still borrowing host work. Do not publish termination
                // or release the parent entry until that work really drains.
                try
                {
                    if (r.Start is not null) _ = await r.Start.ConfigureAwait(false);
                    if (r.Check is not null) _ = await r.Check.ConfigureAwait(false);
                }
                catch (Exception) { }
                if (r.BeforeDeleteChildRead is { } childRead)
                {
                    try { _ = await childRead.ConfigureAwait(false); }
                    catch (Exception) { }
                    if (childRead.IsCompletedSuccessfully) childRead.Result.Dispose();
                }
                RetainDeletionFence(r);
            }
            finally
            {
                lock (gate)
                {
                    if (!parentEntered) vaultSource.ExitNotification(parent);
                    r.Busy = false;
                    r.Drained!.TrySetResult();
                }
            }
        }
    }

    private async Task<CleanupResult> RefreshDeniedDelete(CleanupRegistration r, CancellationToken token)
    {
        if (r.DeniedDeletePublishedAbsence is { } old) deniedDeleteFacts.TryRemove(old, out _);
        r.DeniedDeletePublishedAbsence = null;
        // Revoke source membership before any callback can fail, including time,
        // credentials and journal reads. Only the retained append is retryable.
        var state = CleanupSnapshot(r);
        Require(RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(state) && state.PrivateEndpointCleanupEligible);
        var preimage = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(state);
        var row = state.Resources[3];
        if (row.CreateAttempted && (!row.DeleteAttempted || !row.InvocationTerminated || row.ActiveDispatch != Guid.Empty))
            return CleanupFinish(r, CleanupState.Pending);
        try
        {
            var endpoint = new Endpoint(endpointReader, limits, time);
            var endpointTask = endpoint.CollectAsync(endpoint.Arm(r.Binding), r.Binding, token).AsTask();
            var endpointResult = await endpointTask.ConfigureAwait(false);
            var nic = new Endpoint(endpointReader, limits, time);
            var nicTask = nic.CollectAsync(nic.ArmNicAbsence(r.Binding), r.Binding, token).AsTask();
            var nicResult = await nicTask.ConfigureAwait(false);
            var tasks = new List<Task> { endpointTask, nicTask };
            Require(endpointResult is { ResponseComplete: true, Kind: Endpoint.ReadKind.Endpoint, ResourceStatus: SecretStatus.Absent, HttpStatus: 404 } &&
                nicResult is { ResponseComplete: true, Kind: Endpoint.ReadKind.NicAbsence, ResourceStatus: SecretStatus.Absent, HttpStatus: 404 });
            Resource.StatusDeniedPrivateConnectionDeleteReadProof? childProof = null;
            if (state.PrivateEndpoint!.Connection is { } child)
            {
                var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), child.Id.Split('/')[^1]);
                Require(scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + scope.ConnectionName == child.Id);
                var binding = new ManagementOperationNativeCapture.Binding(r.Parent.Selector, r.Parent.LeaseId, scope,
                    ManagementMutation.DeletePrivateConnection, r.Binding.Location, Vault.Revision);
                var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport), limits, time, vaultSource.FixtureTenantId);
                var window = reader.ArmStatusDeniedPrivateConnectionDelete(binding, Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup);
                var task = reader.CollectAsync(window, binding, token, deniedDeleteTokens[r.Parent][0]).AsTask();
                using var result = await task.ConfigureAwait(false);
                Require(reader.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, task, out childProof) &&
                    reader.OwnsStatusDeniedPrivateConnectionDeleteRead(childProof, window, binding, task) &&
                    childProof is { HttpStatus: 404, Facts: null, ErrorCode: "NotFound" or "ResourceNotFound",
                        Phase: Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup });
                tasks.Add(task);
            }
            token.ThrowIfCancellationRequested();
            Require(deniedDeleteTokens[r.Parent].All(t => !t.IsCancellationRequested) &&
                RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(preimage, CleanupSnapshot(r)));
            var slot = preimage.PrivateEndpoint!;
            var postimage = preimage with
            {
                Revision = preimage.Revision + 1,
                Resources = preimage.Resources.Select(resource => resource.Id == slot.Declaration.EndpointId ? resource with { Absent = true } : resource).ToArray(),
                PrivateEndpoint = slot with { NicAbsent = true, Connection = slot.Connection is null ? null : slot.Connection with { Absent = true } }
            };
            var absence = new StatusDeniedPrivateConnectionDeleteAbsence(this);
            Require(deniedDeleteFacts.TryAdd(absence, new(r.Parent, preimage, postimage, Guid.Empty, false, false,
                slot.Connection?.Id, DeniedDeleteStage.Absence, [.. deniedDeleteTokens[r.Parent], token], tasks.ToArray(), childProof)));
            Require(deniedDeletePending.TryAdd(r.Parent, absence));
            r.DeniedDeleteAbsence = absence;
            _ = PersistDeniedDelete(absence);
            token.ThrowIfCancellationRequested();
            r.DeniedDeletePublishedAbsence = absence;
            r.DeniedDeleteAbsence = null;
            return CleanupFinish(r, CleanupState.DependenciesAbsent);
        }
        catch
        {
            if (r.DeniedDeleteAbsence is null)
                _ = vaultSource.Journal.InvalidatePrivateEndpointAbsence(r.Parent.Owner, r.Parent.Selector);
            throw;
        }
    }

    private async ValueTask ValidateDeniedDeleteBeforeSend(CleanupRegistration r, HttpMessage message)
    {
        Require(r.DeniedDeleteAdmitted is not null && r.ConnectionId is not null && r.BeforeDeleteChildRead is null &&
            r.DeniedDeleteBeforeChild is null && r.Dispatch != Guid.Empty);
        var preimage = r.DeniedDeleteAdmitted;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void Check()
        {
            Require(!closed && r.Busy && !HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent) &&
                deniedDeleteTokens[r.Parent].All(t => !t.IsCancellationRequested) &&
                RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(preimage) && preimage.PrivateConnectionCleanupEligible &&
                preimage.PrivateEndpoint!.Connection?.Id == r.ConnectionId && preimage.PrivateEndpoint.DeletionDispatch == r.Dispatch &&
                (!preimage.PrivateEndpoint.Connection.SelectedAttempted || preimage.PrivateEndpoint.StatusDeleteSettledDispatch != Guid.Empty) &&
                ReferenceEquals(message.Request, request) && request.Method == RequestMethod.Delete && request.Content is null &&
                request.Uri.ToUri().OriginalString == Resource.ArmOrigin + r.Binding.EndpointId + "?api-version=" + Endpoint.Revision &&
                headers.SequenceEqual(request.Headers) && request.Headers.TryGetValue("Authorization", out var auth) &&
                auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(preimage, CleanupSnapshot(r)));
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        Check();
        var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), r.ConnectionId.Split('/')[^1]);
        Require(scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + scope.ConnectionName == r.ConnectionId);
        var binding = new ManagementOperationNativeCapture.Binding(r.Parent.Selector, r.Parent.LeaseId, scope,
            ManagementMutation.DeletePrivateConnection, r.Binding.Location, Vault.Revision);
        var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport), limits, time, vaultSource.FixtureTenantId);
        var window = reader.ArmStatusDeniedPrivateConnectionDelete(binding, Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup);
        r.BeforeDeleteChildRead = reader.CollectAsync(window, binding, message.CancellationToken, deniedDeleteTokens[r.Parent][0]).AsTask();
        _ = await r.BeforeDeleteChildRead.ConfigureAwait(false);
        Require(reader.TryGetStatusDeniedPrivateConnectionDeleteRead(window, binding, r.BeforeDeleteChildRead, out var proof) &&
            reader.OwnsStatusDeniedPrivateConnectionDeleteRead(proof, window, binding, r.BeforeDeleteChildRead) &&
            proof is { HttpStatus: 404, Facts: null, ErrorCode: "NotFound" or "ResourceNotFound",
                Phase: Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Cleanup });
        Check();
        r.DeniedDeleteBeforeChild = proof;
    }

    private async Task<bool> CompleteDeniedDeleteDeletion(CleanupRegistration r, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (r.DeniedDeleteDrain is null)
        {
            if (r.Start is null || await r.Start.ConfigureAwait(false) != SecretStatus.Success) return false;
            Require(r.Native is not null && r.Window is not null && r.DeniedDeleteAdmitted is not null);
            r.Check ??= r.Native.CheckDeleteStatusAsync(r.Window, r.Binding, token).AsTask();
            if (await r.Check.ConfigureAwait(false) != SecretStatus.Success ||
                !r.Native.TryGetDeletionProof(r.Window, r.Binding, out var proof) ||
                !r.Native.OwnsDeletionProof(proof, r.Window, r.Binding, r.Dispatch)) return false;
            Require(r.BeforeDeleteChildRead is { IsCompletedSuccessfully: true } && r.DeniedDeleteBeforeChild is not null &&
                RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(r.DeniedDeleteAdmitted, CleanupSnapshot(r)));
            r.Proof = proof;
            r.DeniedDeleteDrain = RetainDeniedDeleteDrain(r.Parent, true, true, r.ConnectionId, r.DeniedDeleteBeforeChild,
                r.Start, r.Check, r.BeforeDeleteChildRead);
        }
        if (HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent)) _ = PersistDeniedDelete(r.DeniedDeleteDrain);
        token.ThrowIfCancellationRequested();
        Require(r.DeniedDeleteDrain.Settled &&
            RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(r.DeniedDeleteDrain.Postimage, CleanupSnapshot(r)));
        r.Settled = true;
        return true;
    }

    private async Task<CleanupResult> RefreshPrivateUpdateIndependent(CleanupRegistration r, CancellationToken token)
    {
        if (r.IndependentAbsence is not null) return PersistPrivateUpdateIndependentAbsence(r);
        if (r.IndependentPublishedAbsence is { } old) privateUpdateIndependentFacts.TryRemove(old, out _);
        r.IndependentPublishedAbsence = null;
        var state = vaultSource.Journal.Read(r.Parent.Owner, r.Parent.Selector);
        Require(state.PrivateEndpointCleanupEligible && r.IndependentTokens.All(t => !t.IsCancellationRequested));
        var preimage = FreezePrivateUpdateIndependent(state);
        var row = state.Resources[3];
        if (row.CreateAttempted && (!row.DeleteAttempted || !row.InvocationTerminated)) return CleanupFinish(r, CleanupState.Pending);
        try
        {
        var endpoint = new Endpoint(endpointReader, limits, time);
        var endpointWindow = endpoint.Arm(r.Binding);
        var endpointTask = endpoint.CollectAsync(endpointWindow, r.Binding, token).AsTask();
        var endpointResult = await endpointTask.ConfigureAwait(false);
        var nic = new Endpoint(endpointReader, limits, time);
        var nicWindow = nic.ArmNicAbsence(r.Binding);
        var nicTask = nic.CollectAsync(nicWindow, r.Binding, token).AsTask();
        var nicResult = await nicTask.ConfigureAwait(false);
        var tasks = new List<Task> { endpointTask, nicTask };
        Require(endpointResult is { ResponseComplete: true, Kind: Endpoint.ReadKind.Endpoint, ResourceStatus: SecretStatus.Absent, HttpStatus: 404 } &&
            nicResult is { ResponseComplete: true, Kind: Endpoint.ReadKind.NicAbsence, ResourceStatus: SecretStatus.Absent, HttpStatus: 404 });
        if (state.PrivateEndpoint!.Connection is { } child)
        {
            var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), child.Id.Split('/')[^1]);
            var binding = new ManagementOperationNativeCapture.Binding(r.Parent.Selector, r.Parent.LeaseId, scope,
                ManagementMutation.UpdatePrivateConnection, r.Binding.Location, Vault.Revision);
            var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport), limits, time, vaultSource.FixtureTenantId);
            var window = reader.ArmStatusPrivateConnectionUpdateIndependent(binding, Resource.StatusPrivateConnectionUpdateIndependentReadPhase.Cleanup);
            var task = reader.CollectAsync(window, binding, token, r.IndependentTokens[0]).AsTask();
            using var result = await task.ConfigureAwait(false);
            Require(reader.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, task, out var proof) &&
                reader.OwnsStatusPrivateConnectionUpdateIndependentRead(proof, window, binding, task) &&
                proof is { HttpStatus: 404, Facts: null, ErrorCode: "NotFound", Phase: Resource.StatusPrivateConnectionUpdateIndependentReadPhase.Cleanup });
            tasks.Add(task);
        }
        token.ThrowIfCancellationRequested();
        Require(r.IndependentTokens.All(t => !t.IsCancellationRequested) && RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, CleanupSnapshot(r)));
        var slot = preimage.PrivateEndpoint!;
        var postimage = preimage with
        {
            Resources = preimage.Resources.Select(row => row.Id == slot.Declaration.EndpointId ? row with { Absent = true } : row).ToArray(),
            PrivateEndpoint = slot with { NicAbsent = true, Connection = slot.Connection is null ? null : slot.Connection with { Absent = true } }
        };
        postimage = postimage with { Revision = preimage.Revision +
            (RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, postimage) ? 0 : 1) };
        var absence = new StatusPrivateConnectionUpdateIndependentAbsence(this);
        Require(privateUpdateIndependentFacts.TryAdd(absence, new(r.Parent, preimage, postimage, Guid.Empty, false, false,
            slot.Connection?.Id, PrivateUpdateIndependentStage.Absence, [.. privateUpdateIndependentTokens.GetValueOrDefault(r.Parent, []), .. r.IndependentTokens, token], tasks.ToArray())));
        r.IndependentAbsence = absence;
        return PersistPrivateUpdateIndependentAbsence(r);
        }
        catch
        {
            if (r.IndependentAbsence is null)
                vaultSource.Journal.InvalidatePrivateEndpointAbsence(r.Parent.Owner, r.Parent.Selector);
            throw;
        }
    }
    private async ValueTask ValidatePrivateUpdateIndependentDeleteBeforeSend(CleanupRegistration r, HttpMessage message)
    {
        Require(r.IndependentAdmitted is not null && r.ConnectionId is not null && r.BeforeDeleteChildRead is null &&
            r.IndependentBeforeEndpoint is null && r.IndependentTokens.All(t => !t.IsCancellationRequested));
        var preimage = r.IndependentAdmitted;
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void Check()
        {
            Require(!closed && r.IndependentTokens.All(t => !t.IsCancellationRequested) && ReferenceEquals(message.Request, request) &&
                request.Method == RequestMethod.Delete && request.Content is null && headers.SequenceEqual(request.Headers) &&
                request.Uri.ToUri().AbsoluteUri == Resource.ArmOrigin + r.Binding.EndpointId + "?api-version=" + Endpoint.Revision &&
                request.Headers.TryGetValue("Authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, CleanupSnapshot(r)));
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        Check();
        var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), r.ConnectionId.Split('/')[^1]);
        var binding = new ManagementOperationNativeCapture.Binding(r.Parent.Selector, r.Parent.LeaseId, scope,
            ManagementMutation.UpdatePrivateConnection, r.Binding.Location, Vault.Revision);
        var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport), limits, time, vaultSource.FixtureTenantId);
        var window = reader.ArmStatusPrivateConnectionUpdateIndependent(binding, Resource.StatusPrivateConnectionUpdateIndependentReadPhase.BeforeEndpointDelete);
        r.BeforeDeleteChildRead = reader.CollectAsync(window, binding, message.CancellationToken, r.IndependentTokens[0]).AsTask();
        _ = await r.BeforeDeleteChildRead.ConfigureAwait(false);
        Require(reader.TryGetStatusPrivateConnectionUpdateIndependentRead(window, binding, r.BeforeDeleteChildRead, out var proof) &&
            reader.OwnsStatusPrivateConnectionUpdateIndependentRead(proof, window, binding, r.BeforeDeleteChildRead) && proof.HttpStatus == 200 &&
            proof.Facts is { Provisioning: "Succeeded" } facts && facts.Id == r.ConnectionId && facts.EndpointId == r.Binding.EndpointId);
        string expected = preimage.PrivateEndpoint!.Connection!.SelectedAttempted ? "Approved" : "Pending";
        Require(proof.Facts.State == expected && (!preimage.PrivateEndpoint.Connection.SelectedAttempted || preimage.PrivateEndpoint.ApprovalSettledDispatch != Guid.Empty));
        var endpoint = new Endpoint(endpointReader, limits, time);
        var endpointWindow = endpoint.Arm(r.Binding);
        r.IndependentBeforeEndpoint = endpoint.CollectAsync(endpointWindow, r.Binding, message.CancellationToken).AsTask();
        var result = await r.IndependentBeforeEndpoint.ConfigureAwait(false);
        Require(result is { ResponseComplete: true, Kind: Endpoint.ReadKind.Endpoint, ResourceStatus: SecretStatus.Success,
            HttpStatus: 200, NativeState: "Succeeded", MatchesDeclarationConfiguration: true } && result.ManualConnectionState == expected);
        Check();
    }
    private async Task<bool> CompletePrivateUpdateIndependentDeletion(CleanupRegistration r, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (r.IndependentDrain is null)
        {
            if (r.Start is null || await r.Start.ConfigureAwait(false) != SecretStatus.Success) return false;
            Require(r.Native is not null && r.Window is not null && r.IndependentAdmitted is not null);
            r.Check ??= r.Native.CheckDeleteStatusAsync(r.Window, r.Binding, token).AsTask();
            if (await r.Check.ConfigureAwait(false) != SecretStatus.Success ||
                !r.Native.TryGetDeletionProof(r.Window, r.Binding, out var proof) || !r.Native.OwnsDeletionProof(proof, r.Window, r.Binding, r.Dispatch)) return false;
            Require(r.BeforeDeleteChildRead is { IsCompletedSuccessfully: true } && r.IndependentBeforeEndpoint is { IsCompletedSuccessfully: true });
            r.Proof = proof;
            r.IndependentDrain = RetainPrivateUpdateIndependentDrain(r.Parent, r.IndependentAdmitted, true, r.ConnectionId,
                [.. r.IndependentTokens, token], r.Start, r.Check, r.BeforeDeleteChildRead, r.IndependentBeforeEndpoint);
        }
        PersistPrivateUpdateIndependentDrain(r.IndependentDrain);
        r.Settled = true;
        return true;
    }

    private async Task<bool> CompleteDeletion(CleanupRegistration r, CancellationToken token)
    {
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
            return await CompleteDeniedDeleteDeletion(r, token).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
            return await CompletePrivateUpdateIndependentDeletion(r, token).ConfigureAwait(false);
        token.ThrowIfCancellationRequested();
        var snapshot = CleanupSnapshot(r);
        if (r.Candidate is not null && r.SettlementAttempted &&
            snapshot.PrivateEndpoint is { DeletionDispatch: var dispatch } && dispatch == Guid.Empty &&
            snapshot.PrivateEndpoint.Connection?.Id == r.ConnectionId &&
            snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId) is
            { DeleteAttempted: true, ActiveDispatch: var active, InvocationTerminated: true } && active == Guid.Empty)
        {
            r.Settled = true;
            return true;
        }
        if (r.Candidate is null)
        {
            if (r.Start is null || await r.Start.ConfigureAwait(false) != SecretStatus.Success) return false;
            Require(r.Native is not null && r.Window is not null);
            r.Check ??= r.Native.CheckDeleteStatusAsync(r.Window, r.Binding, token).AsTask();
            if (await r.Check.ConfigureAwait(false) != SecretStatus.Success ||
                !r.Native.TryGetDeletionProof(r.Window, r.Binding, out var proof) ||
                !r.Native.OwnsDeletionProof(proof, r.Window, r.Binding, r.Dispatch)) return false;
            // Cache private native registry facts outside the journal lock.
            r.Proof = proof;
            token.ThrowIfCancellationRequested();
            r.Candidate = new(this);
            Require(deletions.TryAdd(r.Candidate, r));
        }
        token.ThrowIfCancellationRequested();
        Require(!closed);
        RetainDeletionFence(r);
        r.SettlementAttempted = true;
        _ = vaultSource.Journal.SettlePrivateEndpointDeletion(r.Parent.Owner, r.Parent.Selector,
            r.Parent.LeaseId, r.Candidate);
        r.Settled = true;
        return true;
    }

    private async Task<CleanupResult> RefreshCore(CleanupRegistration r, CancellationToken token)
    {
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
            return await RefreshDeniedDelete(r, token).ConfigureAwait(false);
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
            return await RefreshPrivateUpdateIndependent(r, token).ConfigureAwait(false);
        var revision = vaultSource.Journal.BeginPrivateEndpointAbsence(r.Parent.Owner, r.Parent.Selector,
            r.Parent.LeaseId);
        var snapshot = CleanupSnapshot(r);
        if (!snapshot.PrivateEndpointCleanupEligible)
            return CleanupFinish(r, CleanupState.Pending);
        var row = snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId);
        if (snapshot.PrivateEndpoint!.Connection is null ? row.CreateAttempted || row.DeleteAttempted :
            !row.DeleteAttempted || !row.InvocationTerminated)
            return CleanupFinish(r, CleanupState.Pending);
        var observation = new AbsenceObservation(r, revision, snapshot.PrivateEndpoint.Connection?.Id, token);
        AbsenceCandidate? candidate = null;
        bool committed = false;
        try
        {
            var endpoint = new Endpoint(endpointReader, limits, time);
            observation.EndpointRead = endpoint.CollectAsync(endpoint.Arm(r.Binding), r.Binding, token).AsTask();
            _ = await observation.EndpointRead.ConfigureAwait(false);
            var nic = new Endpoint(endpointReader, limits, time);
            observation.NicRead = nic.CollectAsync(nic.ArmNicAbsence(r.Binding), r.Binding, token).AsTask();
            _ = await observation.NicRead.ConfigureAwait(false);
            if (observation.ConnectionId is { } connectionId)
            {
                var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), connectionId.Split('/')[^1]);
                Require(r.Parent.VaultId + "/privateEndpointConnections/" + scope.ConnectionName == connectionId);
                bool independentDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(r.Parent.Selector);
                bool selectedDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(r.Parent.Selector);
                bool statusDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(r.Parent.Selector);
                var selector = independentDelete || selectedDelete || statusDelete || VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(r.Parent.Selector)
                    ? r.Parent.Selector : r.Parent.Selector with
                {
                    Operation = ManagementOperationEffects.Members[0].Operation,
                    Variant = "operation.UpdatePrivateConnection",
                    Case = "independent-effect"
                };
                var binding = new ManagementOperationNativeCapture.Binding(selector, r.Parent.LeaseId, scope,
                    independentDelete || selectedDelete || statusDelete ? ManagementMutation.DeletePrivateConnection : ManagementMutation.UpdatePrivateConnection,
                    r.Binding.Location, Vault.Revision);
                var child = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport),
                    limits, time, vaultSource.FixtureTenantId);
                var window = independentDelete
                    ? child.ArmStatusPrivateConnectionDeleteIndependent(binding, Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup)
                    : child.Arm(binding, statusPrivateDeleteSelectedProfile:
                        VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(binding.Selector));
                observation.ChildRead = child.CollectAsync(window, binding, token).AsTask();
                _ = await observation.ChildRead.ConfigureAwait(false);
                if (independentDelete)
                {
                    Require(child.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, observation.ChildRead, out var proof) &&
                        child.OwnsStatusPrivateConnectionDeleteIndependentRead(proof, window, binding, observation.ChildRead) &&
                        proof is { HttpStatus: 404, Facts: null, Phase: Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup });
                    observation.StatusPrivateDeleteIndependentChildAbsence = proof;
                }
                if (selectedDelete)
                {
                    Require(child.TryGetStatusPrivateConnectionDeleteSelectedRead(window, binding, observation.ChildRead, out var proof) &&
                        child.OwnsStatusPrivateConnectionDeleteSelectedRead(proof, window, binding, observation.ChildRead) &&
                        proof.HttpStatus == 404 && proof.Facts is null);
                    observation.StatusPrivateDeleteSelectedChildAbsence = proof;
                }
                if (statusDelete)
                {
                    Require(child.TryGetStatusPrivateConnectionDeleteRead(window, binding, observation.ChildRead, out var proof) &&
                        child.OwnsStatusPrivateConnectionDeleteRead(proof, window, binding, observation.ChildRead) &&
                        proof.HttpStatus == 404 && proof.Facts is null);
                    observation.StatusPrivateDeleteChildAbsence = proof;
                }
                if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(selector))
                {
                    Require(child.TryGetStatusPrivateConnectionUpdateRead(window, binding, observation.ChildRead, out var proof) &&
                        child.OwnsStatusPrivateConnectionUpdateRead(proof, window, binding, observation.ChildRead) &&
                        proof.HttpStatus == 404 && proof.Facts is null && proof.Phase == "cleanup");
                    observation.StatusPrivateChildAbsence = proof;
                }
            }
            token.ThrowIfCancellationRequested();
            if (!observation.EndpointRead.Result.ResponseComplete || !observation.NicRead.Result.ResponseComplete ||
                observation.ChildRead is not null && !observation.ChildRead.Result.ResponseComplete)
                return CleanupFinish(r, CleanupState.Uncertain);
            if (!Absent(observation)) return CleanupFinish(r, CleanupState.Incomplete);
            candidate = new(this);
            Require(absences.TryAdd(candidate, observation));
            token.ThrowIfCancellationRequested();
            Require(!closed);
            _ = vaultSource.Journal.CommitPrivateEndpointAbsence(r.Parent.Owner, r.Parent.Selector,
                r.Parent.LeaseId, candidate);
            token.ThrowIfCancellationRequested();
            committed = true;
            return CleanupFinish(r, CleanupState.DependenciesAbsent);
        }
        finally
        {
            if (candidate is not null) absences.TryRemove(candidate, out _);
            if (observation.ChildRead is { IsCompletedSuccessfully: true }) observation.ChildRead.Result.Dispose();
            // A failed older observer must not leave a newer tuple live after
            // observing reappearance, denial or cancellation.
            if (!committed)
                vaultSource.Journal.InvalidatePrivateEndpointAbsence(r.Parent.Owner, r.Parent.Selector);
        }
    }

    private static bool Absent(AbsenceObservation observation) =>
        observation.EndpointRead is { IsCompletedSuccessfully: true } endpoint &&
        endpoint.Result is { Kind: Endpoint.ReadKind.Endpoint, ResponseComplete: true, ResourceStatus: SecretStatus.Absent } &&
        observation.NicRead is { IsCompletedSuccessfully: true } nic &&
        nic.Result is { Kind: Endpoint.ReadKind.NicAbsence, ResponseComplete: true, ResourceStatus: SecretStatus.Absent } &&
        (observation.ConnectionId is null ? observation.ChildRead is null :
            observation.ChildRead is { IsCompletedSuccessfully: true } child &&
            child.Result is { ResponseComplete: true, ResourceStatus: SecretStatus.Absent } &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(observation.Registration.Parent.Selector) ||
                observation.StatusPrivateDeleteIndependentChildAbsence is
                    { HttpStatus: 404, Facts: null, Phase: Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup }) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(observation.Registration.Parent.Selector) ||
                observation.StatusPrivateDeleteSelectedChildAbsence is { HttpStatus: 404, Facts: null }) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(observation.Registration.Parent.Selector) ||
                observation.StatusPrivateDeleteChildAbsence is { HttpStatus: 404, Facts: null }) &&
            (!VaultFixtureProvisioner.StatusPrivateConnectionUpdateCancellationSelector(observation.Registration.Parent.Selector) ||
                observation.StatusPrivateChildAbsence is { HttpStatus: 404, Facts: null }));

    // These validators run under the journal lock: no source lock, host clock,
    // native proof callback, credential or transport is touched here.
    private bool ValidateDeletion(DeletionCandidate candidate, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot snapshot) =>
        !closed && ReferenceEquals(journal, vaultSource.Journal) && deletions.TryGetValue(candidate, out var r) &&
        ReferenceEquals(r.Candidate, candidate) && r.Busy && !r.Settled && r.SettlementAttempted &&
        r.Proof is not null && r.Start is { IsCompletedSuccessfully: true } &&
        r.Check is { IsCompletedSuccessfully: true } && MatchesCleanupRoot(r, snapshot) &&
        snapshot.PrivateEndpoint is { } slot && slot.Connection?.Id == r.ConnectionId &&
        (slot.OriginalDelete?.Disposition != RoleFixtureJournal.PrivateConnectionDeleteDisposition.Deleted &&
            slot.StatusDeleteSettledDispatch == Guid.Empty ||
            r.BeforeDeleteChildAbsence is { } absence && absence.ConnectionId == r.ConnectionId &&
            ReferenceEquals(absence.Task, r.BeforeDeleteChildRead) &&
            absence.Task is { IsCompletedSuccessfully: true } && ReferenceEquals(absence.Task.Result, absence.Measurement) &&
            absence.Measurement is { ResponseComplete: true, HttpStatus: 404, ResourceStatus: SecretStatus.Absent } &&
            (slot.StatusDeleteSettledDispatch == Guid.Empty ||
                (VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(snapshot.Selector)
                    ? RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot) &&
                        r.BeforeDeleteDrainRevision is { } drained && drained.Matches(snapshot) &&
                        absence.IndependentDeleteProof is
                            { HttpStatus: 404, Facts: null, Phase: Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup }
                    : VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(snapshot.Selector)
                    ? RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot) &&
                        absence.SelectedDeleteProof is { HttpStatus: 404, Facts: null }
                    : RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot) &&
                        absence.StatusDeleteProof is { HttpStatus: 404, Facts: null }))) &&
        r.Dispatch != Guid.Empty && slot.DeletionDispatch == r.Dispatch;

    private bool ValidateAbsence(AbsenceCandidate candidate, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot snapshot) =>
        !closed && ReferenceEquals(journal, vaultSource.Journal) && absences.TryGetValue(candidate, out var observation) &&
        observation.Registration.Busy && !observation.Cancellation.IsCancellationRequested &&
        observation.Revision.Matches(snapshot) &&
        MatchesCleanupRoot(observation.Registration, snapshot) &&
        snapshot.PrivateEndpoint?.Connection?.Id == observation.ConnectionId && Absent(observation);

    private void ValidateDeleteBeforeSend(CleanupRegistration r)
    {
        Require(!closed && r.Busy && r.Dispatch != Guid.Empty && r.ConnectionId is not null);
        vaultSource.Journal.CheckPrivateEndpointDelete(r.Parent.Owner, r.Parent.Selector, r.Parent.LeaseId,
            r.Parent.PrivateEndpoint!, r.ConnectionId, r.Dispatch);
    }

    private async ValueTask ValidateDeleteBeforeSendAsync(CleanupRegistration r, HttpMessage message)
    {
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
        { await ValidateDeniedDeleteBeforeSend(r, message).ConfigureAwait(false); return; }
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
        { await ValidatePrivateUpdateIndependentDeleteBeforeSend(r, message).ConfigureAwait(false); return; }
        ValidateDeleteBeforeSend(r);
        var snapshot = CleanupSnapshot(r);
        bool independentDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(r.Parent.Selector) &&
            snapshot.PrivateEndpoint?.Connection is { SelectedAttempted: true };
        bool selectedDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(r.Parent.Selector) &&
            snapshot.PrivateEndpoint?.Connection is { SelectedAttempted: true };
        bool statusDelete = VaultFixtureProvisioner.StatusPrivateConnectionDeleteCancellationSelector(r.Parent.Selector) &&
            snapshot.PrivateEndpoint?.Connection is { SelectedAttempted: true };
        if (!independentDelete && !selectedDelete && !statusDelete &&
            snapshot.PrivateEndpoint?.OriginalDelete?.Disposition != RoleFixtureJournal.PrivateConnectionDeleteDisposition.Deleted)
            return;
        Require(!independentDelete || RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot) &&
            snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch != Guid.Empty);
        Require(!selectedDelete || RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot) &&
            snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch != Guid.Empty);
        Require(!statusDelete || RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot) &&
            snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch != Guid.Empty);
        Require(r.BeforeDeleteChildRead is null && r.BeforeDeleteChildAbsence is null && r.ConnectionId is not null);
        var request = message.Request;
        var headers = request.Headers.ToArray();
        void CheckRequest()
        {
            Require(ReferenceEquals(message.Request, request) && request.Method == RequestMethod.Delete &&
                request.Content is null && request.Uri.ToUri().OriginalString ==
                    Resource.ArmOrigin + r.Binding.EndpointId + "?api-version=" + Endpoint.Revision &&
                headers.SequenceEqual(request.Headers) &&
                request.Headers.TryGetValue("Authorization", out var authorization) &&
                authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7);
            message.CancellationToken.ThrowIfCancellationRequested();
        }
        CheckRequest();
        // This is inside the authenticated endpoint DELETE boundary, not a
        // pre-credential observation that could survive child resurrection.
        var revision = new RoleFixtureJournal.AbsenceRevision(snapshot.Revision);
        var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), r.ConnectionId.Split('/')[^1]);
        Require(scope.Vault.ExportResourceId() + "/privateEndpointConnections/" + scope.ConnectionName == r.ConnectionId);
        var selector = independentDelete || selectedDelete || statusDelete ? r.Parent.Selector : r.Parent.Selector with
        {
            Operation = ManagementOperationEffects.Members[0].Operation,
            Variant = "operation.DeletePrivateConnection",
            Case = "independent-effect"
        };
        var binding = new ManagementOperationNativeCapture.Binding(selector, r.Parent.LeaseId, scope,
            ManagementMutation.DeletePrivateConnection, r.Binding.Location, Vault.Revision);
        var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport),
            limits, time, vaultSource.FixtureTenantId);
        var window = independentDelete
            ? reader.ArmStatusPrivateConnectionDeleteIndependent(binding, Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup)
            : reader.Arm(binding, statusPrivateDeleteSelectedProfile:
                VaultFixtureProvisioner.StatusPrivateConnectionDeleteSelectedSelector(binding.Selector));
        r.BeforeDeleteChildRead = reader.CollectAsync(window, binding, message.CancellationToken).AsTask();
        var measured = await r.BeforeDeleteChildRead.ConfigureAwait(false);
        Resource.StatusPrivateConnectionDeleteIndependentReadProof? independentDeleteProof = null;
        if (independentDelete)
            Require(reader.TryGetStatusPrivateConnectionDeleteIndependentRead(window, binding, r.BeforeDeleteChildRead, out independentDeleteProof) &&
                reader.OwnsStatusPrivateConnectionDeleteIndependentRead(independentDeleteProof, window, binding, r.BeforeDeleteChildRead) &&
                independentDeleteProof is { HttpStatus: 404, Facts: null, Phase: Resource.StatusPrivateConnectionDeleteIndependentReadPhase.Cleanup });
        Resource.StatusPrivateConnectionDeleteSelectedReadProof? selectedDeleteProof = null;
        if (selectedDelete)
            Require(reader.TryGetStatusPrivateConnectionDeleteSelectedRead(window, binding, r.BeforeDeleteChildRead, out selectedDeleteProof) &&
                reader.OwnsStatusPrivateConnectionDeleteSelectedRead(selectedDeleteProof, window, binding, r.BeforeDeleteChildRead) &&
                selectedDeleteProof is { HttpStatus: 404, Facts: null });
        Resource.StatusPrivateConnectionDeleteReadProof? statusDeleteProof = null;
        if (statusDelete)
            Require(reader.TryGetStatusPrivateConnectionDeleteRead(window, binding, r.BeforeDeleteChildRead, out statusDeleteProof) &&
                reader.OwnsStatusPrivateConnectionDeleteRead(statusDeleteProof, window, binding, r.BeforeDeleteChildRead) &&
                statusDeleteProof is { HttpStatus: 404, Facts: null });
        Require(measured is { ResponseComplete: true, HttpStatus: 404, ResourceStatus: SecretStatus.Absent,
                ResourceId: null, ConnectionState: null, PrivateEndpointId: null, NativeRequestId: not null } &&
            ReferenceEquals(measured.Binding, binding) && measured.WindowId == window.Id &&
            measured.ApiRevision == Vault.Revision && measured.StartedAt >= window.ArmedAt &&
            measured.FinishedAt >= measured.StartedAt);
        var current = CleanupSnapshot(r);
        Require(revision.Matches(current) &&
            (independentDelete ? RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(current) &&
                current.PrivateEndpoint!.StatusDeleteSettledDispatch == snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch :
                selectedDelete ? RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(current) &&
                current.PrivateEndpoint!.StatusDeleteSettledDispatch == snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch :
                statusDelete ? RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(current) &&
                current.PrivateEndpoint!.StatusDeleteSettledDispatch == snapshot.PrivateEndpoint!.StatusDeleteSettledDispatch :
                current.PrivateEndpoint?.OriginalDelete?.Disposition == RoleFixtureJournal.PrivateConnectionDeleteDisposition.Deleted));
        ValidateDeleteBeforeSend(r);
        CheckRequest();
        r.BeforeDeleteChildAbsence = new(binding, window, revision, r.ConnectionId, r.BeforeDeleteChildRead, measured,
            statusDeleteProof, selectedDeleteProof, independentDeleteProof);
    }

    private sealed class DeleteTransport(HttpPipelineTransport inner, Func<HttpMessage, ValueTask> validate) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) =>
            throw new InvalidOperationException("private-endpoint-fixture-boundary");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            if (message.Request.Method == RequestMethod.Delete) await validate(message).ConfigureAwait(false);
            await inner.ProcessAsync(message).ConfigureAwait(false);
        }
    }

    private void RetainDeletionFence(CleanupRegistration r)
    {
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
        {
            if (r.Dispatch == Guid.Empty || r.Settled || r.DeniedDeleteDrain is not null ||
                HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent)) return;
            var state = CleanupSnapshot(r);
            if (state.PrivateEndpoint?.DeletionDispatch != r.Dispatch ||
                state.Resources[3].InvocationTerminated) return;
            var tasks = new Task?[] { r.Start, r.Check, r.BeforeDeleteChildRead }.OfType<Task>().ToArray();
            Require(tasks.All(t => t.IsCompleted));
            r.DeniedDeleteDrain = RetainDeniedDeleteDrain(r.Parent, true, false, r.ConnectionId, null, tasks);
            _ = PersistDeniedDelete(r.DeniedDeleteDrain);
            return;
        }
        if (r.Dispatch == Guid.Empty || r.Settled || r.IndependentDrain is not null) return;
        var snapshot = CleanupSnapshot(r);
        if (snapshot.PrivateEndpoint?.DeletionDispatch == r.Dispatch)
        {
            if (VaultFixtureProvisioner.StatusPrivateConnectionDeleteIndependentSelector(r.Parent.Selector) &&
                r.BeforeDeleteChildAbsence is { } absence)
            {
                // Retrying local persistence never refreshes retained absence
                // authority after another journal transition.
                if (r.BeforeDeleteDrainRevision is not null) return;
                var endpoint = snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId);
                if (absence.Revision.MatchesEndpointDrain(snapshot, endpoint))
                {
                    var after = vaultSource.Journal.EndDispatch(r.Parent.Owner, r.Parent.Selector, r.Binding.EndpointId,
                        r.Dispatch, nativeSettled: false, beforeEndpointDrain: absence.Revision);
                    r.BeforeDeleteDrainRevision = new(after.Revision);
                }
                else
                    // Drain remains a fact even when settlement evidence is stale.
                    vaultSource.Journal.EndDispatch(r.Parent.Owner, r.Parent.Selector, r.Binding.EndpointId,
                        r.Dispatch, nativeSettled: false);
            }
            else
                vaultSource.Journal.EndDispatch(r.Parent.Owner, r.Parent.Selector, r.Binding.EndpointId,
                    r.Dispatch, nativeSettled: false);
        }
    }

    private RoleFixtureJournal.Snapshot CleanupSnapshot(CleanupRegistration r)
    {
        RoleFixtureJournal.Snapshot snapshot;
        try { snapshot = vaultSource.Journal.Read(r.Parent.Owner, r.Parent.Selector); }
        catch (RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteHistoryException) { RevokeDeniedDelete(r.Parent); throw; }
        catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException) { RevokePrivateUpdateIndependent(r.Parent); throw; }
        Require(MatchesCleanupRoot(r, snapshot));
        return snapshot;
    }

    private static bool MatchesCleanupRoot(CleanupRegistration r, RoleFixtureJournal.Snapshot snapshot) =>
        r.Parent.Owner == snapshot.Owner && r.Parent.Selector == snapshot.Selector &&
        r.Parent.LeaseId == snapshot.LeaseId && r.Parent.PrivateEndpoint == snapshot.PrivateEndpoint?.Declaration &&
        r.Parent.Manifest.Count == snapshot.Resources.Length && r.Parent.Manifest.All(m =>
            snapshot.Resources.Count(row => row.Id == m.Id && row.Borrowed == m.Borrowed &&
                row.CleanupOnly == m.CleanupOnly) == 1);

    private CleanupResult CleanupFinish(CleanupRegistration r, CleanupState state)
    {
        var snapshot = CleanupSnapshot(r);
        if (state == CleanupState.DependenciesAbsent && !snapshot.PrivateEndpointAbsent)
            state = CleanupState.Pending;
        return new() { State = state, Journal = snapshot };
    }

    private async Task<Result> CompleteCore(Registration r, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
        {
            if (HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent))
                _ = RetryStatusDeniedPrivateConnectionDeletePersistence(r.Parent);
            if (r.DeniedDeleteDrain is not null)
            {
                if (!r.DeniedDeleteDrain.Settled) return Finish(r, State.Uncertain);
                Require(RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(r.DeniedDeleteDrain.Postimage, Snapshot(r)));
                r.Bound = true;
                return Finish(r, State.Ready);
            }
        }
        if (r.Bound) return Finish(r, State.Ready);
        if (r.IndependentDrain is not null)
        { PersistPrivateUpdateIndependentDrain(r.IndependentDrain); r.Bound = true; return Finish(r, State.Ready); }
        if (r.Candidate is not null) return Bind(r, token);
        Require(r.Start is { IsCompletedSuccessfully: true } && r.Start.Result == SecretStatus.Success);
        if (r.Check is null)
            r.Check = r.Native.CheckStatusAsync(r.Window, r.Binding, token).AsTask();
        if (await r.Check.ConfigureAwait(false) != SecretStatus.Success ||
            !r.Native.TryGetCreationProof(r.Window, r.Binding, out var proof))
            return Finish(r, State.Pending);
        r.Proof = proof;
        if (r.EndpointRead is null)
        {
            var reader = new Endpoint(endpointReader, limits, time);
            r.EndpointRead = reader.CollectAsync(reader.Arm(r.Binding), r.Binding, token).AsTask();
        }
        var endpoint = await r.EndpointRead.ConfigureAwait(false);
        if (!endpoint.ResponseComplete || endpoint.Kind != Endpoint.ReadKind.Endpoint ||
            endpoint.ResourceStatus != SecretStatus.Success || !endpoint.MatchesDeclaration ||
            endpoint.NativeState != "Succeeded" || endpoint.ManualConnectionState != "Pending")
            return Finish(r, State.Incomplete);
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector) &&
            !endpoint.MatchesDeclarationConfiguration) return Finish(r, State.Incomplete);
        if (r.Inventory is null)
        {
            // A native inventory selector describes the read, not the selected
            // operation. The private registration retains its parent/root join.
            var selector = r.Parent.Selector with
            {
                Operation = Vault.Operation(Vault.QueryKind.ListPrivateConnections),
                Variant = "collection.bounded"
            };
            var b = new Vault.Binding(selector, r.Parent.LeaseId, Vault.QueryKind.ListPrivateConnections,
                Vault.ReadKind.ListPrivateConnections, vaultSource.Host.SubscriptionId,
                vaultSource.Host.ResourceGroup, r.Binding.Location, r.Parent.VaultName, null);
            var reader = new Vault(vaultReader, inventoryLimits, time);
            r.Inventory = reader.CollectAsync(reader.Arm(b), b, token).AsTask();
        }
        var inventory = await r.Inventory.ConfigureAwait(false);
        if (!inventory.InventoryComplete || (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector) ||
            VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector)) &&
            inventory.Connections.Count() != 1) return Finish(r, State.Incomplete);
        var matching = inventory.Connections.Where(c => Same(c.PrivateEndpointId, r.Binding.EndpointId)).ToArray();
        if (matching.Length != 1 || matching[0].State != PrivateConnectionState.Pending ||
            matching[0].ProvisioningState != NativeProvisioningState.Succeeded)
            return Finish(r, State.Incomplete);
        var row = matching[0];
        var scope = new PrivateConnectionScope(vaultSource.Scope(r.Parent), row.Name);
        string id = r.Parent.VaultId + "/privateEndpointConnections/" + scope.ConnectionName;
        Require(row.ResourceId == id);
        if (r.ConnectionRead is null)
        {
            bool deniedDelete = VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector);
            var selector = deniedDelete ? r.Parent.Selector : r.Parent.Selector with
            {
                Operation = ManagementOperationEffects.Members[0].Operation,
                Variant = "operation.UpdatePrivateConnection",
                Case = "independent-effect"
            };
            var b = new ManagementOperationNativeCapture.Binding(selector, r.Parent.LeaseId, scope,
                deniedDelete ? ManagementMutation.DeletePrivateConnection : ManagementMutation.UpdatePrivateConnection, r.Binding.Location, Vault.Revision);
            var reader = new Resource(new(vaultReader.Label, vaultReader.Credential, vaultReader.Transport),
                limits, time, vaultSource.FixtureTenantId);
            var window = deniedDelete
                ? reader.ArmStatusDeniedPrivateConnectionDelete(b, Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Discovery)
                : VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector)
                ? reader.ArmStatusPrivateConnectionUpdateIndependent(b, Resource.StatusPrivateConnectionUpdateIndependentReadPhase.Discovery)
                : reader.Arm(b);
            r.ConnectionRead = reader.CollectAsync(window, b, token, deniedDelete ? deniedDeleteTokens[r.Parent][0] :
                r.IndependentTokens.Count == 0 ? null : r.IndependentTokens[0]).AsTask();
            if (deniedDelete)
            {
                using var result = await r.ConnectionRead.ConfigureAwait(false);
                Require(reader.TryGetStatusDeniedPrivateConnectionDeleteRead(window, b, r.ConnectionRead, out var discovery) &&
                    reader.OwnsStatusDeniedPrivateConnectionDeleteRead(discovery, window, b, r.ConnectionRead) &&
                    discovery is { HttpStatus: 200, Phase: Resource.StatusDeniedPrivateConnectionDeleteReadPhase.Discovery,
                        Facts: { State: "Pending", Provisioning: "Succeeded" } } &&
                    discovery.Facts.Id == id && discovery.Facts.EndpointId == r.Binding.EndpointId);
                r.DeniedDeleteDiscovery = discovery;
            }
            if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
            {
                _ = await r.ConnectionRead.ConfigureAwait(false);
                Require(reader.TryGetStatusPrivateConnectionUpdateIndependentRead(window, b, r.ConnectionRead, out var discovery) &&
                    reader.OwnsStatusPrivateConnectionUpdateIndependentRead(discovery, window, b, r.ConnectionRead) &&
                    discovery.Facts is { State: "Pending", Provisioning: "Succeeded" } && discovery.Facts.EndpointId == r.Binding.EndpointId);
                r.IndependentDiscovery = discovery;
            }
        }
        var connection = await r.ConnectionRead.ConfigureAwait(false);
        if (!connection.ResponseComplete || connection.ResourceStatus != SecretStatus.Success ||
            !connection.PersistedStateEligible || connection.ResourceId != id ||
            connection.ConnectionState != PrivateConnectionState.Pending || connection.NativeState != "Succeeded" ||
            !Same(connection.PrivateEndpointId, r.Binding.EndpointId)) return Finish(r, State.Incomplete);
        token.ThrowIfCancellationRequested();
        Require(r.Native.OwnsCreationProof(proof, r.Window, r.Binding, r.Dispatch));
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
        {
            Require(r.DeniedDeleteAdmitted is not null && r.DeniedDeleteDiscovery is not null &&
                RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(r.DeniedDeleteAdmitted, Snapshot(r)));
            r.DeniedDeleteDrain = RetainDeniedDeleteDrain(r.Parent, false, true, id, r.DeniedDeleteDiscovery,
                r.Start!, r.Check!, r.EndpointAbsent!, r.NicAbsent!, r.EndpointRead!, r.Inventory!, r.ConnectionRead!);
            _ = PersistDeniedDelete(r.DeniedDeleteDrain);
            token.ThrowIfCancellationRequested();
            r.Bound = true;
            return Finish(r, State.Ready);
        }
        if (VaultFixtureProvisioner.StatusPrivateConnectionUpdateIndependentSelector(r.Parent.Selector))
        {
            Require(r.IndependentAdmitted is not null && r.IndependentDiscovery is not null);
            r.IndependentDrain = RetainPrivateUpdateIndependentDrain(r.Parent, r.IndependentAdmitted, false, id,
                [.. r.IndependentTokens, token], r.Start!, r.Check!, r.EndpointAbsent!, r.NicAbsent!, r.EndpointRead!, r.Inventory!, r.ConnectionRead!);
            PersistPrivateUpdateIndependentDrain(r.IndependentDrain);
            r.Bound = true;
            return Finish(r, State.Ready);
        }
        lock (gate)
        {
            Require(!closed && r.Candidate is null);
            var candidate = new BindingCandidate(this, id);
            r.Candidate = candidate;
            Require(candidates.TryAdd(candidate, r));
        }
        return Bind(r, token);
    }

    private Result Bind(Registration r, CancellationToken token)
    {
        lock (gate)
        {
            token.ThrowIfCancellationRequested();
            Require(!closed && r.Candidate is not null);
            var snapshot = Snapshot(r);
            // An uncertain flushed acknowledgement can be inspected only by the
            // same retained original candidate that attempted that append.
            if (r.BindingAttempted && snapshot.PrivateEndpoint is
                { CreationDispatch: var dispatch, Connection: { } connection } &&
                dispatch == Guid.Empty && connection.Id == r.Candidate.ConnectionId &&
                snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId).ActiveDispatch == Guid.Empty)
            {
                r.Bound = true;
                return Finish(r, State.Ready);
            }
            Require(r.Proof is not null &&
                r.Native.OwnsCreationProof(r.Proof, r.Window, r.Binding, r.Dispatch));
            Require(!closed);
            token.ThrowIfCancellationRequested();
            RetainCreationFence(r);
            r.BindingAttempted = true;
            _ = vaultSource.Journal.BindGeneratedPrivateConnection(r.Parent.Owner, r.Parent.Selector,
                r.Parent.LeaseId, r.Candidate);
            r.Bound = true;
            return Finish(r, State.Ready);
        }
    }

    private bool ValidateCandidate(BindingCandidate candidate, RoleFixtureJournal journal,
        RoleFixtureJournal.Snapshot snapshot)
    {
        // Called under the journal lock. Never acquire a source/parent lock
        // here: a forged candidate must not invert binding's lock order.
        return !closed && ReferenceEquals(journal, vaultSource.Journal) &&
                candidates.TryGetValue(candidate, out var r) &&
                ReferenceEquals(candidate, r.Candidate) && !r.Bound && r.Busy && r.BindingAttempted &&
                r.Plan.Matches(source, r.Parent) && MatchesRoot(r, snapshot) &&
                snapshot.PrivateEndpoint?.CreationDispatch == r.Dispatch && r.Dispatch != Guid.Empty &&
                r.Proof is not null && r.Start is { IsCompletedSuccessfully: true } &&
                r.Check is { IsCompletedSuccessfully: true } && r.EndpointAbsent is { IsCompletedSuccessfully: true } &&
                r.NicAbsent is { IsCompletedSuccessfully: true } && r.EndpointRead is { IsCompletedSuccessfully: true } &&
                r.Inventory is { IsCompletedSuccessfully: true } && r.ConnectionRead is { IsCompletedSuccessfully: true };
    }

    private void ValidateBeforeSend(Registration r)
    {
        lock (gate)
        {
            Require(!closed && r.Busy && r.Dispatch != Guid.Empty &&
                plans.TryGetValue(r.Plan, out var retained) && ReferenceEquals(retained, r));
            var snapshot = Snapshot(r);
            Require(!VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector) ||
                r.DeniedDeleteAdmitted is not null && !HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent) &&
                deniedDeleteTokens[r.Parent].All(t => !t.IsCancellationRequested) &&
                RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(r.DeniedDeleteAdmitted, snapshot));
            Require(r.IndependentAdmitted is null || r.IndependentTokens.All(t => !t.IsCancellationRequested) &&
                RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(r.IndependentAdmitted, snapshot));
            Require(!snapshot.Closing && !snapshot.Released &&
                vaultSource.MatchesOwnedPlan(r.Parent, snapshot) &&
                snapshot.PrivateEndpoint?.CreationDispatch == r.Dispatch &&
                snapshot.Resources.Single(row => row.Id == r.Binding.EndpointId).ActiveDispatch == r.Dispatch);
        }
    }

    // This borrowed boundary runs after credential acquisition, immediately
    // before the original PUT reaches the host transport. Status reads drain
    // already admitted work and do not authorize a new mutation.
    private sealed class SetupTransport(HttpPipelineTransport inner, Action validate) : HttpPipelineTransport
    {
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) =>
            throw new InvalidOperationException("private-endpoint-fixture-boundary");
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            if (message.Request.Method == RequestMethod.Put) validate();
            await inner.ProcessAsync(message).ConfigureAwait(false);
        }
    }

    private void RetainCreationFence(Registration r)
    {
        if (VaultFixtureProvisioner.StatusDeniedPrivateConnectionDeleteSelector(r.Parent.Selector))
        {
            if (r.Dispatch == Guid.Empty || r.Bound || r.DeniedDeleteDrain is not null ||
                HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent)) return;
            var state = Snapshot(r);
            if (state.PrivateEndpoint?.CreationDispatch != r.Dispatch || state.Resources[3].InvocationTerminated) return;
            var tasks = new Task?[] { r.Start, r.Check, r.EndpointAbsent, r.NicAbsent, r.EndpointRead, r.Inventory, r.ConnectionRead }
                .OfType<Task>().ToArray();
            Require(tasks.All(t => t.IsCompleted));
            r.DeniedDeleteDrain = RetainDeniedDeleteDrain(r.Parent, false, false, null, null, tasks);
            _ = PersistDeniedDelete(r.DeniedDeleteDrain);
            return;
        }
        if (r.Dispatch == Guid.Empty || r.Bound || r.IndependentDrain is not null) return;
        var snapshot = Snapshot(r);
        if (snapshot.PrivateEndpoint?.CreationDispatch == r.Dispatch)
            vaultSource.Journal.EndDispatch(r.Parent.Owner, r.Parent.Selector, r.Binding.EndpointId,
                r.Dispatch, nativeSettled: false);
    }

    private RoleFixtureJournal.Snapshot Snapshot(Registration r)
    {
        RoleFixtureJournal.Snapshot snapshot;
        try { snapshot = vaultSource.Journal.Read(r.Parent.Owner, r.Parent.Selector); }
        catch (RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteHistoryException) { RevokeDeniedDelete(r.Parent); throw; }
        catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException) { RevokePrivateUpdateIndependent(r.Parent); throw; }
        Require(MatchesRoot(r, snapshot));
        return snapshot;
    }

    private static bool MatchesRoot(Registration r, RoleFixtureJournal.Snapshot snapshot) =>
        r.Parent.Owner == snapshot.Owner && r.Parent.Selector == snapshot.Selector &&
        r.Parent.LeaseId == snapshot.LeaseId && r.Parent.PrivateEndpoint == snapshot.PrivateEndpoint?.Declaration &&
        r.Parent.Manifest.Count == snapshot.Resources.Length && r.Parent.Manifest.All(m =>
            snapshot.Resources.Count(row => row.Id == m.Id && row.Borrowed == m.Borrowed &&
                row.CleanupOnly == m.CleanupOnly) == 1);

    private Registration Enter(Plan plan, bool preparation)
    {
        lock (gate)
        {
            Require(!closed && plan is not null && plans.TryGetValue(plan, out _));
            var r = plans[plan];
            Require(plan.Matches(source, r.Parent) && !r.Busy &&
                (!preparation || vaultSource.OwnsPreparedPlan(r.Parent)));
            Require(vaultSource.TryEnterNotification(r.Parent, preparation));
            r.Busy = true;
            r.Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
            return r;
        }
    }

    private void Exit(Registration r)
    {
        lock (gate)
        {
            vaultSource.ExitNotification(r.Parent);
            r.Busy = false;
            r.Drained!.TrySetResult();
        }
    }

    private Result Finish(Registration r, State state)
    {
        var snapshot = Snapshot(r);
        return new()
        {
            State = closed || snapshot.Closing ? State.Closing : state,
            Journal = snapshot,
            ConnectionId = r.Bound ? snapshot.PrivateEndpoint?.Connection?.Id : null
        };
    }

    public ValueTask DisposeAsync()
    {
        TaskCompletionSource start;
        Task task;
        lock (gate)
        {
            closed = true;
            if (disposal is not null) return new(disposal);
            start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = disposal = Drain(plans.Values.ToArray(), cleanup.Values.ToArray(), start.Task);
        }
        start.SetResult();
        return new(task);
    }

    private async Task Drain(Registration[] registrations, CleanupRegistration[] cleanups, Task start)
    {
        await start.ConfigureAwait(false);
        Exception? failure = null;
        try
        {
            // Finish only the already-retained exact append before Close can
            // change its pre/postimage. This does not create a new capability.
            foreach (var parent in registrations.Select(r => r.Parent).Concat(cleanups.Select(r => r.Parent)).Distinct())
                if (HasStatusDeniedPrivateConnectionDeletePersistence(parent))
                    try { _ = RetryStatusDeniedPrivateConnectionDeletePersistence(parent); }
                    catch (Exception exception) { failure ??= exception; }
            foreach (var r in registrations)
                try
                {
                    if (!HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent))
                        vaultSource.CloseSelectedRoot(r.Parent.Owner, r.Parent.Selector);
                }
                catch (Exception exception) { failure ??= exception; }
            foreach (var r in cleanups)
                try
                {
                    if (!HasStatusDeniedPrivateConnectionDeletePersistence(r.Parent))
                        vaultSource.CloseSelectedRoot(r.Parent.Owner, r.Parent.Selector);
                }
                catch (Exception exception) { failure ??= exception; }
        }
        finally
        {
            foreach (var r in registrations)
                try { await r.Stop.CancelAsync().ConfigureAwait(false); }
                catch (Exception exception) { failure ??= exception; }
            foreach (var r in cleanups)
                try { await r.Stop.CancelAsync().ConfigureAwait(false); }
                catch (Exception exception) { failure ??= exception; }
            foreach (var r in registrations)
                try { await r.Native.DisposeAsync().ConfigureAwait(false); }
                catch (Exception exception) { failure ??= exception; }
            await Task.WhenAll(registrations.Where(r => r.Busy).Select(r => r.Drained!.Task)).ConfigureAwait(false);
            await Task.WhenAll(cleanups.Where(r => r.Busy).Select(r => r.Drained!.Task)).ConfigureAwait(false);
            // Closing the root revokes new reads. Retained child-read borrowers
            // may still be in credentials, host I/O, body parsing or SDK return.
            // Keep this original source's proofs alive until those loans drain.
            await Task.WhenAll(registrations.Select(r => vaultSource.PrivateConnectionReadDrain(this, r.Parent)))
                .ConfigureAwait(false);
            await Task.WhenAll(registrations.Select(r => vaultSource.PrivateConnectionUpdateDrain(this, r.Parent)))
                .ConfigureAwait(false);
            await Task.WhenAll(registrations.Select(r => vaultSource.PrivateConnectionDeleteDrain(this, r.Parent)))
                .ConfigureAwait(false);
            foreach (var r in cleanups)
            {
                if (r.Native is not null)
                    try { await r.Native.DisposeAsync().ConfigureAwait(false); }
                    catch (Exception exception) { failure ??= exception; }
                r.Stop.Dispose();
            }
            foreach (var r in registrations)
            {
                if (r.ConnectionRead is { IsCompletedSuccessfully: true }) r.ConnectionRead.Result.Dispose();
                r.Stop.Dispose();
            }
            lock (gate)
            {
                candidates.Clear();
                deletions.Clear();
                absences.Clear();
                privateUpdateIndependentFacts.Clear();
                privateUpdateIndependentTokens.Clear();
                deniedDeleteFacts.Clear();
                deniedDeletePending.Clear();
                deniedDeleteTokens.Clear();
            }
        }
        if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
    }

    private static bool Same(string? left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static void Require([DoesNotReturnIf(false)] bool condition)
    {
        if (!condition) throw new InvalidOperationException("private-endpoint-fixture-boundary");
    }
    public override string ToString() => "[PrivateEndpointFixtureProvisioner]";
}
