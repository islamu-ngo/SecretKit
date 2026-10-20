using System.ClientModel.Primitives;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Azure;
using Azure.Core;
using Azure.Core.Pipeline;
using Azure.ResourceManager;
using Azure.ResourceManager.KeyVault;
using Azure.ResourceManager.KeyVault.Models;
using Azure.Security.KeyVault.Secrets;
using SecretKit.AzureKeyVault.Management;
using SecretKit.Core;

namespace SecretKit.AzureKeyVault.Conformance.Tests.Admission.Management;

// A local source component, not an authenticated service, collector or provider
// qualification. The host owns credentials, transports, namespace exclusivity
// and source selection of the baseline. Baseline is NOT the selected outcome.
// ARM PUT has no conditional-create guarantee; preflight alone is not isolation.
internal sealed class VaultFixtureProvisioner : IAsyncDisposable
{
    private bool statusDeniedVaultUpdateProfile, statusDeniedVaultUpdateCleanup;
    private sealed record DeniedVaultUpdateFacts(Plan Plan, RoleFixtureJournal.Snapshot? Before,
        RoleFixtureJournal.Snapshot After, int Edge, string ResourceId, Guid Dispatch, bool Delete, bool Settled,
        CancellationToken[] Tokens, Task[] Tasks);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, DeniedVaultUpdateFacts> deniedVaultUpdateFacts =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, object> deniedVaultUpdatePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> deniedVaultUpdateTokens =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, System.Action> deniedVaultUpdateLifetime =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, Guid> deniedVaultUpdateDispatches =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> deniedVaultUpdateRevoked = [];
    private sealed record DeniedVaultUpdateParentRead(RoleFixtureJournal.Snapshot Image, Task Task, string Id, int Status);
    private readonly Dictionary<Plan, (DeniedVaultUpdateParentRead? Active, DeniedVaultUpdateParentRead? Deleted)> deniedVaultUpdateReads =
        new(ReferenceEqualityComparer.Instance);

    internal static bool StatusDeniedVaultUpdateSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.CreateOrUpdateVault" && selector.Case == "denied-authority";
    internal static VaultFixtureProvisioner ForStatusDeniedVaultUpdate(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm, Limits limits, TimeProvider? time = null)
    {
        var source = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        source.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && source.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: false, Policies.Length: 0 } &&
            source.baseline.Location == host.Location && source.baseline.TenantId == host.TenantId);
        _ = source.baseline.Build();
        source.statusDeniedVaultUpdateProfile = true;
        return source;
    }
    internal static VaultFixtureProvisioner ForStatusDeniedVaultUpdateCleanup(RoleFixtureJournal journal, HostScope host,
        Authority setupArm, Authority readArm, Limits limits, TimeProvider? time = null)
    {
        Require(host.AllowPurge);
        return new(journal, host, setupArm, readArm, limits, time)
        { statusDeniedVaultUpdateProfile = true, statusDeniedVaultUpdateCleanup = true };
    }
    internal VaultAdministrationEffects.Configuration StatusDeniedVaultUpdateConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(statusDeniedVaultUpdateProfile && !statusDeniedVaultUpdateCleanup && !closed && host == expected &&
            baselineConfiguration is not null && statusReader is { Credential: not null, Transport: not null } &&
            resourceReader is { Credential: not null, Transport: not null } && selectedBackend is not null &&
            ReferenceEquals(resourceReader.Credential, readArm.Credential) &&
            ReferenceEquals(resourceReader.Transport, readArm.Transport) && resourceReader.Label == readArm.Label &&
            new[] { setupArm, readArm }.All(a => a.Label != statusReader.Label &&
                !ReferenceEquals(a.Credential, statusReader.Credential) && !ReferenceEquals(a.Transport, statusReader.Transport) &&
                !ReferenceEquals(a.Transport, selectedBackend)) && !ReferenceEquals(statusReader.Transport, selectedBackend));
        return CopyConfiguration(baseline);
    }
    private bool DeniedVaultUpdateLive(Plan plan) => !closed && !deniedVaultUpdateRevoked.ContainsKey(plan.Selector.Nonce) &&
        deniedVaultUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested);
    private void TrackDeniedVaultUpdate(Plan plan, CancellationToken token, CancellationToken caller)
    {
        Require(DeniedVaultUpdateLive(plan) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        deniedVaultUpdateTokens.AddOrUpdate(plan, [token, caller], (_, old) => [.. old, token, caller]);
    }
    private void CheckDeniedVaultUpdateLifetime(Plan plan, RoleFixtureJournal.Snapshot image)
    {
        Require(DeniedVaultUpdateLive(plan) && RoleFixtureJournal.StatusDeniedVaultUpdateRoot(image) &&
            MatchesPlan(plan, image) && !plan.OriginalCreate && !plan.OriginalRecover);
        if (!image.Closing)
        {
            Require(!plan.Restored);
            Require(deniedVaultUpdateLifetime.TryGetValue(plan, out var validate));
            validate();
        }
    }
    internal bool OwnsStatusDeniedVaultUpdatePreparation(Plan originalPlan)
    {
        CheckPlan(originalPlan);
        lock (plans)
            return statusDeniedVaultUpdateProfile && !statusDeniedVaultUpdateCleanup && !originalPlan.Restored &&
                !originalPlan.OriginalCreate && originalPlan.Preparation == Preparation.Active && !originalPlan.SeedCanary &&
                originalReady.Contains(originalPlan) && prepared.Contains(originalPlan) && originalPlan.Consumed == 1 &&
                originalPlan.Busy == 0 && DeniedVaultUpdateLive(originalPlan);
    }
    internal void BindStatusDeniedVaultUpdateLifetime(Plan originalPlan, System.Action validate)
    {
        CheckPlan(originalPlan);
        Require(!statusDeniedVaultUpdateCleanup && !originalPlan.Restored && validate is not null &&
            deniedVaultUpdateLifetime.TryAdd(originalPlan, validate));
    }
    internal void RetainStatusDeniedVaultUpdateDispatch(Plan originalPlan, Guid dispatch)
    {
        Require(OwnsStatusDeniedVaultUpdatePreparation(originalPlan) && dispatch != Guid.Empty);
        var state = ReadPlan(originalPlan.Owner, originalPlan.Selector);
        Require(!state.Closing && state.CreateOrUpdateVault!.InvocationDispatch == dispatch &&
            state.CreateOrUpdateVaultUnsettled && deniedVaultUpdateDispatches.TryAdd(originalPlan, dispatch));
    }

    internal sealed class StatusDeniedVaultUpdatePreparation(VaultFixtureProvisioner source)
    {
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.deniedVaultUpdateFacts.TryGetValue(this, out var f) && f.Before is null &&
            f.Plan.Owner == owner && f.Plan.Selector == selector && source.ValidateDeniedVaultUpdateFixture(this, journal, f.After, 0, true);
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedVaultUpdateFixture(this, journal, state, 0, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(source.deniedVaultUpdateFacts[this].After);
    }
    internal sealed class StatusDeniedVaultUpdateFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 1, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 1, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(source.deniedVaultUpdateFacts[this].After);
    }
    internal sealed class StatusDeniedVaultUpdateFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Settled => source.deniedVaultUpdateFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 2, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 2, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(source.deniedVaultUpdateFacts[this].After);
    }
    internal sealed class StatusDeniedVaultUpdateAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 3, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => source.ValidateDeniedVaultUpdateFixture(this, journal, state, 3, true);
        internal RoleFixtureJournal.Snapshot Postimage => RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(source.deniedVaultUpdateFacts[this].After);
    }
    // Called under Jlock: immutable registry reads only. The host lifetime
    // callback and native evidence are evaluated before this fact is issued.
    private bool ValidateDeniedVaultUpdateFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, int edge, bool post) =>
        ReferenceEquals(journal, candidateJournal) && deniedVaultUpdateFacts.TryGetValue(capability, out var f) && f.Edge == edge &&
        f.Tasks.All(t => t.IsCompleted) && (edge == 2 && !f.Settled ||
            DeniedVaultUpdateLive(f.Plan) && f.Tokens.All(t => !t.IsCancellationRequested)) &&
        (post || f.Before is not null) &&
        RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(post ? f.After : f.Before!, state);
    private void IssueDeniedVaultUpdateFixture(object candidate, DeniedVaultUpdateFacts facts)
    {
        var frozen = facts with
        {
            Before = facts.Before is null ? null : RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(facts.Before),
            After = RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(facts.After),
            Tokens = facts.Tokens.ToArray(), Tasks = facts.Tasks.ToArray()
        };
        Require(deniedVaultUpdateFacts.TryAdd(candidate, frozen) && deniedVaultUpdatePending.TryAdd(facts.Plan, candidate));
    }
    internal bool HasStatusDeniedVaultUpdatePersistence(Plan originalPlan) => deniedVaultUpdatePending.ContainsKey(originalPlan);
    internal RoleFixtureJournal.Snapshot RetryStatusDeniedVaultUpdatePersistence(Plan originalPlan)
    {
        Require(deniedVaultUpdatePending.TryGetValue(originalPlan, out var candidate));
        Require(deniedVaultUpdateFacts.TryGetValue(candidate, out var f));
        try
        {
            var image = candidate switch
            {
                StatusDeniedVaultUpdatePreparation preparation => journal.PrepareStatusDeniedVaultUpdate(f.Plan.Owner, f.Plan.Selector, preparation),
                StatusDeniedVaultUpdateFixtureAdmission admission => journal.BeginStatusDeniedVaultUpdateFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, admission),
                StatusDeniedVaultUpdateFixtureDrain drain => journal.EndStatusDeniedVaultUpdateFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain),
                StatusDeniedVaultUpdateAbsence absence => journal.RecordStatusDeniedVaultUpdateAbsence(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, absence),
                _ => throw Failure()
            };
            Require(RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(f.After, image));
            deniedVaultUpdatePending.TryRemove(originalPlan, out _);
            return image;
        }
        catch (IOException) { throw; }
        catch { deniedVaultUpdateRevoked.TryAdd(originalPlan.Selector.Nonce, 0); throw; }
    }
    private Plan PlanDeniedVaultUpdate(string owner, FixtureSelector selector, CancellationToken token, CancellationToken caller)
    {
        lock (plans)
        {
            Require(!closed && !statusDeniedVaultUpdateCleanup && !plans.ContainsKey(selector.Nonce));
            string name = "skv" + Guid.NewGuid().ToString("N")[..21];
            string vault = GroupId + "/providers/Microsoft.KeyVault/vaults/" + name;
            string deleted = DeletedId(name);
            RoleFixtureJournal.Resource[] rows = [new(vault, false), new(vault + "/secrets/" + Canary, false, CleanupOnly: true),
                new(deleted, false, CleanupOnly: true)];
            var plan = new Plan(source, owner, selector with { }, Guid.NewGuid(), vault, deleted, Preparation.Active, false, manifest: rows);
            var image = new RoleFixtureJournal.Snapshot(owner, selector with { }, plan.LeaseId, false, rows,
                CreateOrUpdateVault: new(vault, CopyConfiguration(baseline), CopyConfiguration(baseline) with { PublicNetworkAccess = true })) { Revision = 1 };
            plans.Add(selector.Nonce, plan);
            TrackDeniedVaultUpdate(plan, token, caller);
            IssueDeniedVaultUpdateFixture(new StatusDeniedVaultUpdatePreparation(this),
                new(plan, null, image, 0, vault, Guid.Empty, false, false, deniedVaultUpdateTokens[plan], []));
            return plan;
        }
    }
    private VaultAdministrationEffects.Configuration DeniedVaultUpdateConfiguration(Plan plan, RoleFixtureJournal.Snapshot image)
    {
        CheckDeniedVaultUpdateLifetime(plan, image);
        var slot = image.CreateOrUpdateVault!;
        if (slot.InvocationDispatch == Guid.Empty) return CopyConfiguration(slot.Baseline);
        if (slot.SettledDispatch == slot.InvocationDispatch && slot.Disposition == RoleFixtureJournal.CreateOrUpdateVaultDisposition.Updated)
            return CopyConfiguration(slot.Selected);
        Require(!image.Closing && !plan.Restored && deniedVaultUpdateDispatches.TryGetValue(plan, out var d) &&
            d == slot.InvocationDispatch && image.Resources[0].InvocationTerminated);
        return CopyConfiguration(slot.Selected);
    }

    private async Task<State> MutateDeniedVaultUpdate(Plan plan, string id, Action action,
        Func<BoundaryTransport, CancellationToken, Task<Operation?>> invoke, CancellationToken token, CancellationToken caller)
    {
        TrackDeniedVaultUpdate(plan, token, caller);
        var pre = ReadPlan(plan.Owner, plan.Selector);
        CheckDeniedVaultUpdateLifetime(plan, pre);
        Require(!HasStatusDeniedVaultUpdatePersistence(plan) && action is Action.CreateVault or Action.DeleteVault or Action.PurgeVault);
        bool delete = action != Action.CreateVault;
        DeniedVaultUpdateParentRead activeRead, deletedRead;
        lock (plans)
        {
            var reads = deniedVaultUpdateReads.GetValueOrDefault(plan);
            Require(reads.Active is not null && reads.Deleted is not null);
            activeRead = reads.Active; deletedRead = reads.Deleted;
        }
        Require(RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(pre, activeRead.Image) &&
            RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(pre, deletedRead.Image) &&
            (action == Action.CreateVault ? activeRead.Status == 404 && deletedRead.Status == 404 :
                action == Action.DeleteVault ? activeRead.Status == 200 && deletedRead.Status == 404 :
                activeRead.Status == 404 && deletedRead.Status == 200));
        var dispatch = Guid.NewGuid();
        var post = RoleFixtureJournal.StatusDeniedVaultUpdateFixtureImage(pre, id, dispatch, delete, false, false);
        IssueDeniedVaultUpdateFixture(new StatusDeniedVaultUpdateFixtureAdmission(this),
            new(plan, pre, post, 1, id, dispatch, delete, false, deniedVaultUpdateTokens[plan], [activeRead.Task, deletedRead.Task]));
        var admitted = RetryStatusDeniedVaultUpdatePersistence(plan);
        var receipt = new Receipt(action, id) { Dispatch = dispatch, Attempted = true };
        lock (plan.History) plan.History.Add(receipt);
        using var boundary = new BoundaryTransport(setupArm.Transport, ArmOrigin,
            action == Action.PurgeVault ? plan.DeletedId + "/purge" : plan.VaultId, Revision,
            action == Action.PurgeVault ? RequestMethod.Post : delete ? RequestMethod.Delete : RequestMethod.Put,
            limits.MaximumResponseBytes, false, SubscriptionId, host.Location,
            beforeSend: () =>
            {
                token.ThrowIfCancellationRequested(); caller.ThrowIfCancellationRequested();
                Require(RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(admitted, ReadPlan(plan.Owner, plan.Selector)));
                CheckDeniedVaultUpdateLifetime(plan, admitted);
            }, shape: action == Action.CreateVault ? VaultShape : null,
            statusSucceededCancellationMutation: true, notificationUpdateIndependentMutation: true);
        receipt.Boundary = boundary;
        bool settled = false;
        try
        {
            receipt.NativeTask = invoke(boundary, token);
            receipt.NativeOperation = await receipt.NativeTask.ConfigureAwait(false);
            if (action is Action.CreateVault or Action.PurgeVault && boundary.Status == 200 && !boundary.HasAsync &&
                receipt.NativeOperation is { HasCompleted: false } operation)
            {
                boundary.BeginStatus();
                receipt.StatusTask = operation.UpdateStatusAsync(token).AsTask();
                using var response = await receipt.StatusTask.ConfigureAwait(false);
            }
            settled = DeniedVaultUpdateLive(plan) && !token.IsCancellationRequested && !caller.IsCancellationRequested &&
                boundary.Valid && !boundary.HasAsync && boundary.Status is 200 or 201 or 204 &&
                receipt.NativeTask.IsCompletedSuccessfully && receipt.NativeOperation is { HasCompleted: true } &&
                (receipt.StatusTask is null || receipt.StatusTask.IsCompletedSuccessfully);
        }
        catch (Exception) { settled = false; }
        finally
        {
            receipt.Terminated = true; receipt.HttpStatus = boundary.Status; receipt.NativeRequestId = boundary.RequestId;
            try { boundary.Dispose(); } catch { settled = false; }
            settled &= boundary.FixtureDrainComplete;
            receipt.RemoteSettled = settled;
            receipt.Outcome = settled ? State.Ready : State.Uncertain;
            if (receipt.NativeTask is { IsCompleted: true } native && boundary.FixturePhysicalDrainComplete)
            {
                var drainedPre = ReadPlan(plan.Owner, plan.Selector);
                var drainedPost = RoleFixtureJournal.StatusDeniedVaultUpdateFixtureImage(drainedPre, id, dispatch, delete, true, settled);
                IssueDeniedVaultUpdateFixture(new StatusDeniedVaultUpdateFixtureDrain(this),
                    new(plan, drainedPre, drainedPost, 2, id, dispatch, delete, settled, deniedVaultUpdateTokens[plan],
                        receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]));
                RetryStatusDeniedVaultUpdatePersistence(plan);
            }
        }
        token.ThrowIfCancellationRequested(); caller.ThrowIfCancellationRequested();
        return receipt.Outcome;
    }

    private async Task<T?> ReadDeniedVaultUpdateArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var pre = ReadPlan(plan.Owner, plan.Selector);
        CheckDeniedVaultUpdateLifetime(plan, pre);
        Require(!HasStatusDeniedVaultUpdatePersistence(plan));
        var expected = DeniedVaultUpdateConfiguration(plan, pre);
        lock (plans)
        {
            var old = deniedVaultUpdateReads.GetValueOrDefault(plan);
            deniedVaultUpdateReads[plan] = id == plan.VaultId ? (null, null) : (old.Active, null);
        }
        using var boundary = new DeniedVaultUpdateReadTransport(this, plan, id, pre);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                Require(pre.Resources[0].CreateAttempted && !pre.Resources[0].DeleteAttempted &&
                    VaultAdministrationEffects.SameConfiguration(Configuration(vault.Data), expected));
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, expected);
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                Require(pre.Closing && pre.Idle && pre.Resources[0] is { DeleteAttempted: true, InvocationTerminated: true });
                ManagementOperationResourceCollector.ValidateStatusSucceededDeleted(raw.RootElement, deleted.Data,
                    plan.DeletedId, plan.VaultId, plan.Selector.Nonce, expected);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404)
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            Require(raw.RootElement.EnumerateObject().Count() == 1 &&
                raw.RootElement.GetProperty("error").GetProperty("code").GetString() == error.ErrorCode &&
                error.ErrorCode is "NotFound" or "ResourceNotFound" or "VaultNotFound");
        }
        boundary.Dispose();
        token.ThrowIfCancellationRequested();
        CheckDeniedVaultUpdateLifetime(plan, pre);
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(pre, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new DeniedVaultUpdateParentRead(RoleFixtureJournal.CopyStatusDeniedVaultUpdateSnapshot(pre), task, id, result is null ? 404 : 200);
            var old = deniedVaultUpdateReads.GetValueOrDefault(plan);
            deniedVaultUpdateReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }
    private sealed class DeniedVaultUpdateReadTransport(VaultFixtureProvisioner source, Plan plan, string id,
        RoleFixtureJournal.Snapshot preimage) : HttpPipelineTransport, IDisposable
    {
        private readonly OwnedArmResponse.Storage storage = new();
        private Request? request;
        private int sends;
        internal OwnedArmResponse.Body? Body;
        internal OwnedArmResponse.ParserCustody? Parser;
        public override Request CreateRequest() { Require(request is null); return request = source.readArm.Transport.CreateRequest(); }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(++sends == 1);
            var headers = message.Request.Headers.ToArray();
            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                source.CheckDeniedVaultUpdateLifetime(plan, preimage);
                Require(ReferenceEquals(request, message.Request) && message.Request.Method == RequestMethod.Get &&
                    message.Request.Content is null && message.Request.Uri.ToUri().OriginalString == ArmOrigin + id + "?api-version=" + Revision &&
                    headers.SequenceEqual(message.Request.Headers) && headers.Length <= 32 &&
                    headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                        !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
                    !headers.Any(h => new[] { "Content-Length", "Content-Encoding", "Transfer-Encoding", "Range", "Content-Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) &&
                    message.Request.Headers.TryGetValue("Authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(preimage, source.ReadPlan(plan.Owner, plan.Selector)));
                if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
            }
            Check();
            message.BufferResponse = false;
            try { await source.readArm.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) storage.Own(message.Response); }
            Check();
            Require(message.HasResponse);
            var response = message.Response;
            var stream = response.ContentStream;
            Body = await OwnedArmResponse.CaptureAsync(message, source.limits.MaximumResponseBytes, storage).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && Body.Response.Status is 200 or 404);
            using var raw = JsonDocument.Parse(Body.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
            BoundaryTransport.Unique(raw.RootElement);
            if (Body.Response.Status == 404)
            {
                Require(raw.RootElement.ValueKind == JsonValueKind.Object && raw.RootElement.EnumerateObject().Count() == 1);
                Require(raw.RootElement.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object);
                Require(error.EnumerateObject().All(p => p.Name is "code" or "message") &&
                    error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.String &&
                    code.GetString() is "NotFound" or "ResourceNotFound" or "VaultNotFound");
                if (error.TryGetProperty("message", out var text))
                    Require(text.ValueKind == JsonValueKind.String && text.GetString()!.Length <= 4096 &&
                        !text.GetString()!.Any(char.IsControl));
            }
            Parser = OwnedArmResponse.ParserCustody.Install(message, Body.Response, Body.Bytes, storage,
                requireRebuffer: false, requireDownstreamRead: true);
        }
        public void Dispose() => storage.Dispose();
    }
    private async Task<Result> ReleaseDeniedVaultUpdate(Plan plan, CancellationToken token, CancellationToken caller)
    {
        TrackDeniedVaultUpdate(plan, token, caller);
        var image = ReadPlan(plan.Owner, plan.Selector);
        Require(image.Closing && image.Idle && RoleFixtureJournal.StatusDeniedVaultUpdateRoot(image));
        _ = DeniedVaultUpdateConfiguration(plan, image);
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        if (!image.Resources[0].DeleteAttempted)
        {
            Require(vault is not null && deleted is null && image.Resources[0] is { CreateAttempted: true, InvocationTerminated: true });
            if (await MutateDeniedVaultUpdate(plan, plan.VaultId, Action.DeleteVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                    .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, caller).ConfigureAwait(false) != State.Ready)
                return Finish(State.Uncertain, plan);
        }
        else Require(vault is null);
        image = ReadPlan(plan.Owner, plan.Selector);
        if (!image.Idle) return Finish(State.Pending, plan);
        vault = await ReadVault(plan, token).ConfigureAwait(false);
        deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        Require(vault is null);
        if (!image.Resources[2].DeleteAttempted)
        {
            Require(host.AllowPurge && deleted is not null);
            if (await MutateDeniedVaultUpdate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, caller).ConfigureAwait(false) != State.Ready)
                return Finish(State.Uncertain, plan);
        }
        image = ReadPlan(plan.Owner, plan.Selector);
        if (!image.Idle) return Finish(State.Pending, plan);
        Require(await ReadVault(plan, token).ConfigureAwait(false) is null &&
            await ReadDeleted(plan, token).ConfigureAwait(false) is null);
        DeniedVaultUpdateParentRead activeRead, deletedRead;
        lock (plans)
        {
            var reads = deniedVaultUpdateReads[plan];
            Require(reads.Active is not null && reads.Deleted is not null);
            activeRead = reads.Active; deletedRead = reads.Deleted;
        }
        Require(activeRead.Status == 404 && deletedRead.Status == 404 && activeRead.Task.IsFaulted && deletedRead.Task.IsFaulted &&
            RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(image, activeRead.Image) &&
            RoleFixtureJournal.SameStatusDeniedVaultUpdateSnapshot(image, deletedRead.Image));
        IssueDeniedVaultUpdateFixture(new StatusDeniedVaultUpdateAbsence(this),
            new(plan, image, RoleFixtureJournal.StatusDeniedVaultUpdateAbsenceImage(image), 3, plan.VaultId, Guid.Empty,
                false, false, deniedVaultUpdateTokens[plan], [activeRead.Task, deletedRead.Task]));
        var committed = RetryStatusDeniedVaultUpdatePersistence(plan);
        return Finish(committed.Released ? State.Released : State.Closing, plan);
    }

    private bool statusDeniedPrivateDeleteProfile, statusDeniedPrivateDeleteCleanup;
    private enum DeniedPrivateDeleteFixtureStage { Admission, Drain, Absence }
    private sealed record DeniedPrivateDeleteFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled,
        DeniedPrivateDeleteFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        PrivateEndpointFixtureProvisioner.StatusDeniedPrivateConnectionDeleteAbsence? Dependency)
    {
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, DeniedPrivateDeleteFixtureFacts>
        deniedPrivateDeleteFacts = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, object>
        deniedPrivateDeletePending = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]>
        deniedPrivateDeleteTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, System.Action>
        deniedPrivateDeleteLifetime = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, PrivateEndpointFixtureProvisioner.StatusDeniedPrivateConnectionDeleteAbsence>
        deniedPrivateDeleteAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> deniedPrivateDeleteRevoked = [];
    private readonly Dictionary<Guid, (string Owner, FixtureSelector Selector, RoleFixtureJournal.Resource[] Rows,
        RoleFixtureJournal.PrivateEndpointDeclaration Declaration)> deniedPrivateDeleteRoots = [];

    internal static bool StatusDeniedPrivateConnectionDeleteSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeletePrivateConnection" && selector.Case == "denied-authority";
    internal static VaultFixtureProvisioner ForStatusDeniedPrivateConnectionDelete(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret, Authority readArm,
        Authority readSecret, Limits limits, TimeProvider? time = null)
    {
        var source = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret, readArm, readSecret, limits, time);
        Require(host.AllowPurge && source.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 });
        source.statusDeniedPrivateDeleteProfile = true;
        return source;
    }
    internal static VaultFixtureProvisioner ForStatusDeniedPrivateConnectionDeleteCleanup(RoleFixtureJournal journal, HostScope host,
        Authority setupArm, Authority readArm, Limits limits, TimeProvider? time = null)
    {
        Require(host.AllowPurge);
        return new(journal, host, setupArm, readArm, limits, time)
        { statusDeniedPrivateDeleteProfile = true, statusDeniedPrivateDeleteCleanup = true };
    }
    internal VaultAdministrationEffects.Configuration StatusDeniedPrivateConnectionDeleteConfiguration(HostScope expected,
        ManagementOperationResourceCollector.Authority resourceReader, HttpPipelineTransport selectedBackend)
    {
        Require(statusDeniedPrivateDeleteProfile && !statusDeniedPrivateDeleteCleanup && !closed && host == expected &&
            baselineConfiguration is not null && resourceReader is { Credential: not null, Transport: not null } &&
            !ReferenceEquals(setupArm.Credential, resourceReader.Credential) &&
            !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
            !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
            !ReferenceEquals(resourceReader.Transport, selectedBackend));
        return CopyConfiguration(baseline);
    }
    internal void BindStatusDeniedPrivateConnectionDeleteLifetime(Plan plan, System.Action validate)
    {
        CheckPlan(plan);
        Require(statusDeniedPrivateDeleteProfile && !statusDeniedPrivateDeleteCleanup && !plan.Restored &&
            StatusDeniedPrivateConnectionDeleteSelector(plan.Selector) && validate is not null &&
            deniedPrivateDeleteLifetime.TryAdd(plan, validate));
    }
    private bool DeniedPrivateDeleteLive(Plan plan) => !closed && !deniedPrivateDeleteRevoked.ContainsKey(plan.Selector.Nonce) &&
        deniedPrivateDeleteTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested);
    private void CheckDeniedPrivateDeleteLifetime(Plan plan)
    {
        Require(DeniedPrivateDeleteLive(plan));
        if (!ReadPlan(plan.Owner, plan.Selector).Closing)
        {
            Require(!plan.Restored);
            Require(deniedPrivateDeleteLifetime.TryGetValue(plan, out var validate));
            validate();
        }
    }
    private void TrackDeniedPrivateDelete(Plan plan, CancellationToken token, CancellationToken caller)
    {
        Require(DeniedPrivateDeleteLive(plan) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        deniedPrivateDeleteTokens.AddOrUpdate(plan, [token, caller], (_, old) => [.. old, token, caller]);
    }
    internal sealed class StatusDeniedPrivateConnectionDeleteFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Admission, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Admission, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(source.deniedPrivateDeleteFacts[this].Postimage);
    }
    internal sealed class StatusDeniedPrivateConnectionDeleteFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Settled => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Drain, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Drain, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(source.deniedPrivateDeleteFacts[this].Postimage);
    }
    internal sealed class StatusDeniedPrivateConnectionDeleteAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.deniedPrivateDeleteFacts.TryGetValue(this, out var f) && f.Stage == DeniedPrivateDeleteFixtureStage.Absence;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Absence, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedPrivateDeleteFixture(this, journal, state, DeniedPrivateDeleteFixtureStage.Absence, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(source.deniedPrivateDeleteFacts[this].Postimage);
    }
    private bool ValidateDeniedPrivateDeleteFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, DeniedPrivateDeleteFixtureStage stage, bool post) =>
        ReferenceEquals(journal, candidateJournal) && deniedPrivateDeleteFacts.TryGetValue(capability, out var f) &&
        f.Stage == stage && f.Tasks.All(t => t.IsCompleted) &&
        (stage == DeniedPrivateDeleteFixtureStage.Drain && !f.Settled ||
            DeniedPrivateDeleteLive(f.Plan) && f.Tokens.All(t => !t.IsCancellationRequested)) &&
        (!(stage == DeniedPrivateDeleteFixtureStage.Admission && f.Delete || stage == DeniedPrivateDeleteFixtureStage.Absence) ||
            f.Dependency is not null && f.Dependency.ValidateParentDependency(journal, f.Preimage, f.Plan)) &&
        RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(post ? f.Postimage : f.Preimage, state);

    internal void RetainStatusDeniedPrivateConnectionDeleteAbsence(Plan plan,
        PrivateEndpointFixtureProvisioner.StatusDeniedPrivateConnectionDeleteAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(statusDeniedPrivateDeleteProfile && absence.ValidateParentDependency(journal, committed, plan));
        deniedPrivateDeleteAbsences[plan] = absence;
    }
    internal bool HasStatusDeniedPrivateConnectionDeletePersistence(Plan plan) => deniedPrivateDeletePending.ContainsKey(plan);
    internal RoleFixtureJournal.Snapshot RetryStatusDeniedPrivateConnectionDeletePersistence(Plan plan)
    {
        Require(deniedPrivateDeletePending.TryGetValue(plan, out var candidate));
        return PersistDeniedPrivateDeleteFixture(candidate);
    }
    private RoleFixtureJournal.Snapshot PersistDeniedPrivateDeleteFixture(object candidate)
    {
        Require(deniedPrivateDeleteFacts.TryGetValue(candidate, out var f) &&
            deniedPrivateDeletePending.TryGetValue(f.Plan, out var pending) && ReferenceEquals(candidate, pending));
        try
        {
            var committed = candidate switch
            {
                StatusDeniedPrivateConnectionDeleteFixtureAdmission admission =>
                    journal.BeginStatusDeniedPrivateConnectionDeleteFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, admission),
                StatusDeniedPrivateConnectionDeleteFixtureDrain drain =>
                    journal.EndStatusDeniedPrivateConnectionDeleteFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain),
                StatusDeniedPrivateConnectionDeleteAbsence absence =>
                    journal.RecordStatusDeniedPrivateConnectionDeleteAbsence(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, absence),
                _ => throw Failure()
            };
            Require(RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(f.Postimage, committed));
            deniedPrivateDeletePending.TryRemove(f.Plan, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { deniedPrivateDeleteRevoked.TryAdd(f.Plan.Selector.Nonce, 0); throw; }
    }
    private void RegisterDeniedPrivateDeleteFixture(object candidate, DeniedPrivateDeleteFixtureFacts facts)
    {
        Require(deniedPrivateDeleteFacts.TryAdd(candidate, facts) && deniedPrivateDeletePending.TryAdd(facts.Plan, candidate));
    }

    private async Task<State> MutateDeniedPrivateDelete(Plan plan, string id, Action action,
        Func<BoundaryTransport, CancellationToken, Task<Operation?>> invoke, CancellationToken token, CancellationToken caller)
    {
        TrackDeniedPrivateDelete(plan, token, caller);
        CheckDeniedPrivateDeleteLifetime(plan);
        Require(!HasStatusDeniedPrivateConnectionDeletePersistence(plan) &&
            action is Action.CreateVault or Action.DeleteVault or Action.PurgeVault);
        bool delete = action != Action.CreateVault;
        var pre = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(ReadPlan(plan.Owner, plan.Selector));
        deniedPrivateDeleteAbsences.TryGetValue(plan, out var dependency);
        Require(!delete || dependency is not null && dependency.ValidateParentDependency(journal, pre, plan));
        var dispatch = Guid.NewGuid();
        var post = pre with
        {
            Revision = pre.Revision + 1,
            Resources = pre.Resources.Select(r => r.Borrowed ? r : r.Id == id ? r with
            { CreateAttempted = r.CreateAttempted || !delete, DeleteAttempted = delete, InvocationTerminated = false,
                ActiveDispatch = dispatch, Absent = false } : r with { Absent = false }).ToArray(),
            PrivateEndpoint = pre.PrivateEndpoint! with { NicAbsent = false,
                Connection = pre.PrivateEndpoint.Connection is null ? null : pre.PrivateEndpoint.Connection with { Absent = false } }
        };
        var admission = new StatusDeniedPrivateConnectionDeleteFixtureAdmission(this);
        RegisterDeniedPrivateDeleteFixture(admission, new(plan, pre, post, id, dispatch, delete, false,
            DeniedPrivateDeleteFixtureStage.Admission, deniedPrivateDeleteTokens[plan].ToArray(), [], dependency));
        var committed = PersistDeniedPrivateDeleteFixture(admission);
        // The source retains the pre-mutation tuple while admission atomically
        // consumes that exact journal image. At send, both the tuple and the
        // exact admitted image are checked; no revision rebasing is permitted.
        var receipt = new Receipt(action, id) { Dispatch = dispatch, Attempted = true };
        lock (plan.History) plan.History.Add(receipt);
        using var boundary = new BoundaryTransport(setupArm.Transport, ArmOrigin,
            action == Action.PurgeVault ? plan.DeletedId + "/purge" : plan.VaultId, Revision,
            action == Action.PurgeVault ? RequestMethod.Post : delete ? RequestMethod.Delete : RequestMethod.Put,
            limits.MaximumResponseBytes, false, SubscriptionId, host.Location,
            beforeSend: () =>
            {
                Require(DeniedPrivateDeleteLive(plan) && !token.IsCancellationRequested && !caller.IsCancellationRequested &&
                    RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(committed, ReadPlan(plan.Owner, plan.Selector)) &&
                    (!delete || dependency!.ValidateParentDependency(journal, pre, plan)));
                if (!delete) deniedPrivateDeleteLifetime[plan]();
            }, shape: action == Action.CreateVault ? VaultShape : null,
            statusSucceededCancellationMutation: true, notificationUpdateIndependentMutation: true);
        receipt.Boundary = boundary;
        bool settled = false;
        try
        {
            receipt.NativeTask = invoke(boundary, token);
            receipt.NativeOperation = await receipt.NativeTask.ConfigureAwait(false);
            if (action is Action.CreateVault or Action.PurgeVault && boundary.Status == 200 && !boundary.HasAsync &&
                receipt.NativeOperation is { HasCompleted: false } operation)
            {
                boundary.BeginStatus();
                receipt.StatusTask = operation.UpdateStatusAsync(token).AsTask();
                using var response = await receipt.StatusTask.ConfigureAwait(false);
            }
            settled = DeniedPrivateDeleteLive(plan) && !token.IsCancellationRequested && !caller.IsCancellationRequested &&
                boundary.Valid && !boundary.HasAsync && boundary.Status is 200 or 201 or 204 &&
                receipt.NativeTask.IsCompletedSuccessfully && receipt.NativeOperation is { HasCompleted: true } &&
                (receipt.StatusTask is null || receipt.StatusTask.IsCompletedSuccessfully);
        }
        catch (Exception) { settled = false; }
        finally
        {
            receipt.Terminated = true;
            receipt.HttpStatus = boundary.Status;
            receipt.NativeRequestId = boundary.RequestId;
            try { boundary.Dispose(); } catch { settled = false; }
            settled &= boundary.FixtureDrainComplete;
            receipt.RemoteSettled = settled;
            receipt.Outcome = settled ? State.Ready : State.Uncertain;
            if (receipt.NativeTask is { IsCompleted: true } native && boundary.FixturePhysicalDrainComplete)
            {
                // A concurrent Close may only change Closing; physical drain
                // is frozen against that actual image, never a stale admission.
                var drainedPre = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(ReadPlan(plan.Owner, plan.Selector));
                Require(drainedPre.Resources.Single(r => r.Id == id).ActiveDispatch == dispatch);
                var drainedPost = drainedPre with { Revision = drainedPre.Revision + 1,
                    Resources = drainedPre.Resources.Select(r => r.Id == id ? r with
                    { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray() };
                var drain = new StatusDeniedPrivateConnectionDeleteFixtureDrain(this);
                RegisterDeniedPrivateDeleteFixture(drain, new(plan, drainedPre, drainedPost, id, dispatch, delete, settled,
                    DeniedPrivateDeleteFixtureStage.Drain, deniedPrivateDeleteTokens[plan].ToArray(),
                    receipt.StatusTask is null ? [native] : [native, receipt.StatusTask], null));
                PersistDeniedPrivateDeleteFixture(drain);
            }
        }
        token.ThrowIfCancellationRequested();
        caller.ThrowIfCancellationRequested();
        return receipt.Outcome;
    }

    private sealed record DeniedPrivateDeleteRead(RoleFixtureJournal.Snapshot Image, Task Task, string Id, int Status)
    {
        public override string ToString() => "[StatusDeniedPrivateConnectionDeleteParentRead]";
    }
    private readonly Dictionary<Plan, (DeniedPrivateDeleteRead? Active, DeniedPrivateDeleteRead? Deleted)> deniedPrivateDeleteReads =
        new(ReferenceEqualityComparer.Instance);
    private async Task<T?> ReadDeniedPrivateDeleteArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        CheckDeniedPrivateDeleteLifetime(plan);
        var pre = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(ReadPlan(plan.Owner, plan.Selector));
        Require(pre.Idle);
        lock (plans)
        {
            var old = deniedPrivateDeleteReads.GetValueOrDefault(plan);
            deniedPrivateDeleteReads[plan] = id == plan.VaultId ? (null, null) : (old.Active, null);
        }
        using var boundary = new DeniedPrivateDeleteReadTransport(this, plan, id, pre);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                ValidateDeleted(plan, deleted.Data);
                DeletedShape(raw.RootElement);
                var p = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    p.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    p.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    p.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    p.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    p.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    p.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } && DeniedPrivateDeleteLive(plan) &&
            !token.IsCancellationRequested && RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(pre, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new DeniedPrivateDeleteRead(pre, task, id, result is null ? 404 : 200);
            var old = deniedPrivateDeleteReads.GetValueOrDefault(plan);
            deniedPrivateDeleteReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordDeniedPrivateDeleteAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        TrackDeniedPrivateDelete(plan, token, caller);
        var pre = RoleFixtureJournal.CopyStatusDeniedPrivateConnectionDeleteSnapshot(ReadPlan(plan.Owner, plan.Selector));
        DeniedPrivateDeleteRead activeRead, deletedRead;
        lock (plans)
        {
            var pair = deniedPrivateDeleteReads.GetValueOrDefault(plan);
            Require(pair.Active is not null && pair.Deleted is not null);
            activeRead = pair.Active; deletedRead = pair.Deleted;
        }
        Require(activeRead.Status == 404 && deletedRead.Status == 404 && activeRead.Task.IsFaulted && deletedRead.Task.IsFaulted &&
            RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(pre, activeRead.Image) &&
            RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(pre, deletedRead.Image));
        Require(deniedPrivateDeleteAbsences.TryGetValue(plan, out var dependency) && dependency.ValidateParentDependency(journal, pre, plan));
        var post = pre with { Revision = pre.Revision + (pre.Released ? 0 : 1),
            Resources = pre.Resources.Select(r => r.Borrowed ? r : r with { Absent = true }).ToArray() };
        var absence = new StatusDeniedPrivateConnectionDeleteAbsence(this);
        RegisterDeniedPrivateDeleteFixture(absence, new(plan, pre, post, plan.VaultId, Guid.Empty, false, false,
            DeniedPrivateDeleteFixtureStage.Absence, deniedPrivateDeleteTokens[plan].ToArray(),
            [activeRead.Task, deletedRead.Task], dependency));
        return PersistDeniedPrivateDeleteFixture(absence);
    }

    private sealed class DeniedPrivateDeleteReadTransport(VaultFixtureProvisioner source, Plan plan, string id,
        RoleFixtureJournal.Snapshot preimage) : HttpPipelineTransport, IDisposable
    {
        private readonly OwnedArmResponse.Storage storage = new();
        private Request? request;
        private int sends;
        internal OwnedArmResponse.Body? Body;
        internal OwnedArmResponse.ParserCustody? Parser;
        public override Request CreateRequest()
        {
            Require(request is null);
            return request = source.readArm.Transport.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(++sends == 1);
            var headers = message.Request.Headers.ToArray();
            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(source.DeniedPrivateDeleteLive(plan) && ReferenceEquals(request, message.Request) &&
                    message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    message.Request.Uri.ToUri().OriginalString == ArmOrigin + id + "?api-version=" + Revision &&
                    headers.SequenceEqual(message.Request.Headers) && headers.Length <= 32 &&
                    headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                        !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
                    !headers.Any(h => new[] { "Content-Length", "Content-Encoding", "Transfer-Encoding", "Range", "Content-Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)) &&
                    message.Request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    RoleFixtureJournal.SameStatusDeniedPrivateConnectionDeleteSnapshot(preimage, source.ReadPlan(plan.Owner, plan.Selector)));
                if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                if (!preimage.Closing) source.deniedPrivateDeleteLifetime[plan]();
            }
            Check();
            message.BufferResponse = false;
            try { await source.readArm.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (message.HasResponse)
                {
                    storage.Own(message.Response);
                    if (message.Response.Status == 200 && preimage.Resources.Single(r => r.Id == id).Absent)
                    {
                        source.deniedPrivateDeleteAbsences.TryRemove(plan, out _);
                        source.Presence(plan, id);
                    }
                }
            }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            Body = await OwnedArmResponse.CaptureAsync(message, source.limits.MaximumResponseBytes, storage).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && Body.Response.Status is 200 or 404);
            using var raw = JsonDocument.Parse(Body.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
            BoundaryTransport.Unique(raw.RootElement);
            if (Body.Response.Status == 404) ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
            Parser = OwnedArmResponse.ParserCustody.Install(message, Body.Response, Body.Bytes, storage,
                requireRebuffer: false, requireDownstreamRead: true);
        }
        public void Dispose() => storage.Dispose();
    }
    private const string ArmOrigin = "https://management.azure.com";
    private const string Revision = "2026-02-01";
    private const string SecretRevision = "2025-07-01";
    private const string OwnershipTag = "secretkit-fixture";
    internal const string Canary = "canary";
    internal enum Preparation { Active, Absent, Deleted }
    internal enum State { Ready, Pending, Incomplete, Denied, Uncertain, Closing, SoftDeleted, Released }
    internal enum Action { CreateVault, SetCanary, PrepareDeletedVault, DeleteVault, PurgeVault, PreparePolicyChild }
    internal sealed record PrivateEndpointSpecification([property: JsonIgnore] string BorrowedSubnetId)
    {
        public override string ToString() => "[PrivateEndpointSpecification]";
    }
    internal sealed record PolicyChildSpecification(
        [property: JsonIgnore] string Name,
        Preparation Preparation,
        [property: JsonIgnore] SecretMaterial OwnedSet,
        bool RetainBackup = false)
    {
        public override string ToString() => "[PolicyChildSpecification]";
    }
    // Only the source can publish preparation. Exports are independent protected
    // copies; the retained snapshots belong to this source until it drains.
    internal sealed class PolicyChild
    {
        internal string Name { get; }
        internal Preparation? Desired { get; }
        internal bool RetainBackup { get; }
        internal string? Sha256 { get; }
        internal string? Version { get; private set; }
        internal bool Prepared { get; private set; }
        private readonly object gate = new();
        private readonly char[]? set;
        private byte[]? backup;
        private bool disposed;
        private PolicyChild(string name, Preparation? desired, bool retainBackup, char[]? set, string? digest)
        {
            Name = name;
            Desired = desired;
            RetainBackup = retainBackup;
            this.set = set;
            Sha256 = digest;
        }
        internal static PolicyChild Snapshot(PolicyChildSpecification specification, int maximum)
        {
            Require(specification is not null && PolicyName(specification.Name) &&
                !Same(specification.Name, Canary) && Enum.IsDefined(specification.Preparation) && specification.OwnedSet is not null);
            char[] copy = specification.OwnedSet.ExportCharacters();
            try
            {
                Require(copy.Length is > 0 and <= 4096 && Encoding.UTF8.GetByteCount(copy) <= maximum);
                return new(specification.Name, specification.Preparation, specification.RetainBackup, copy, Hash(new string(copy)));
            }
            catch { Array.Clear(copy); throw; }
        }
        internal static PolicyChild Reconstructed(string name) => new(name, null, false, null, null);
        internal SecretMaterial CopySet()
        {
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                Require(set is not null);
                return SecretMaterial.FromText(new string(set));
            }
        }
        internal AzureSecretBackup? CopyBackup()
        {
            lock (gate)
            {
                ObjectDisposedException.ThrowIf(disposed, this);
                Require(Prepared);
                return backup is null ? null : AzureSecretBackup.FromBytes(backup);
            }
        }
        internal void CaptureVersion(string version) => Version = version;
        internal void CaptureBackup(byte[] bytes)
        {
            lock (gate) { Require(!disposed && backup is null); backup = bytes.ToArray(); }
        }
        internal void Complete() { lock (gate) { Require(!disposed); Prepared = true; } }
        internal void Clear()
        {
            lock (gate)
            {
                disposed = true;
                Prepared = false;
                if (set is not null) Array.Clear(set);
                if (backup is not null) CryptographicOperations.ZeroMemory(backup);
            }
        }
        public override string ToString() => "[PreparedPolicyChild]";
    }
    internal sealed record Limits(int MaximumResponseBytes, TimeSpan Timeout);
    internal sealed record HostScope(
        [property: JsonIgnore] Guid SubscriptionId,
        [property: JsonIgnore] string ResourceGroup,
        [property: JsonIgnore] string Location,
        [property: JsonIgnore] Guid TenantId,
        bool ExclusiveFixtureNamespace, bool AllowPurge = false)
    {
        public override string ToString() => "[VaultFixtureHostScope]";
    }
    internal sealed record Authority(
        [property: JsonIgnore] string Label,
        [property: JsonIgnore] TokenCredential Credential,
        [property: JsonIgnore] HttpPipelineTransport Transport)
    {
        public override string ToString() => "[VaultFixtureAuthority]";
    }
    internal sealed class Receipt(Action action, string resourceId)
    {
        internal Action Action { get; } = action;
        internal string ResourceId { get; } = resourceId;
        internal Guid Dispatch { get; set; }
        internal bool Attempted { get; set; }
        internal bool Terminated { get; set; }
        internal bool RemoteSettled { get; set; }
        internal int? HttpStatus { get; set; }
        internal string? NativeRequestId { get; set; }
        internal State Outcome { get; set; } = State.Uncertain;
        internal Task<Operation?>? NativeTask { get; set; }
        internal Operation? NativeOperation { get; set; }
        internal Task<Response>? StatusTask { get; set; }
        internal BoundaryTransport? Boundary { get; set; }
        public override string ToString() => "[VaultFixtureReceipt]";
    }
    internal sealed class Plan(object source, string owner, FixtureSelector selector, Guid leaseId,
        string vaultId, string deletedId, Preparation preparation, bool seedCanary, bool restored = false,
        PolicyChild[]? policyChildren = null, string[]? ownedNotificationNames = null,
        RoleFixtureJournal.Resource[]? manifest = null,
        RoleFixtureJournal.PrivateEndpointDeclaration? privateEndpoint = null, bool originalCreate = false,
        bool originalRecover = false, bool originalPrivateConnectionUpdate = false,
        bool originalPrivateConnectionDelete = false, bool statusSucceededDeleteVaultProfile = false,
        bool statusSucceededDeleteVaultIndependentProfile = false, bool statusSucceededDeleteVaultCancellationProfile = false)
    {
        internal object Source { get; } = source;
        internal string Owner { get; } = owner;
        internal FixtureSelector Selector { get; } = selector;
        internal Guid LeaseId { get; } = leaseId;
        internal string VaultId { get; } = vaultId;
        internal string DeletedId { get; } = deletedId;
        internal string VaultName => VaultId[(VaultId.LastIndexOf('/') + 1)..];
        internal string SecretId => VaultId + "/secrets/" + Canary;
        internal Preparation Preparation { get; } = preparation;
        internal bool SeedCanary { get; } = seedCanary;
        internal bool Restored { get; } = restored;
        internal bool OriginalCreate { get; } = originalCreate;
        internal bool OriginalRecover { get; } = originalRecover;
        internal bool OriginalPrivateConnectionUpdate { get; } = originalPrivateConnectionUpdate;
        internal bool OriginalPrivateConnectionDelete { get; } = originalPrivateConnectionDelete;
        internal bool StatusSucceededDeleteVaultProfile { get; } = statusSucceededDeleteVaultProfile;
        internal bool StatusSucceededDeleteVaultIndependentProfile { get; } = statusSucceededDeleteVaultIndependentProfile;
        internal bool StatusSucceededDeleteVaultCancellationProfile { get; } = statusSucceededDeleteVaultCancellationProfile;
        [JsonIgnore] internal RoleFixtureJournal.PrivateEndpointDeclaration? PrivateEndpoint { get; } = privateEndpoint;
        internal IReadOnlyList<PolicyChild> PolicyChildren { get; } = Array.AsReadOnly((policyChildren ?? []).ToArray());
        internal IReadOnlyList<string> OwnedNotificationNames { get; } = Array.AsReadOnly((ownedNotificationNames ?? []).ToArray());
        internal IReadOnlyList<string> OwnedNotificationIds { get; } = Array.AsReadOnly((ownedNotificationNames ?? [])
            .Select(name => vaultId + NotificationPrefix + name).ToArray());
        internal IReadOnlyList<RoleFixtureJournal.Resource> Manifest { get; } = Array.AsReadOnly((manifest ?? [])
            .Select(r => new RoleFixtureJournal.Resource(r.Id, r.Borrowed, CleanupOnly: r.CleanupOnly)).ToArray());
        internal int Consumed, Busy;
        internal TaskCompletionSource? Drained;
        internal string? CanarySha256, CanaryVersion;
        internal readonly List<Receipt> History = [];
        internal IReadOnlyList<Receipt> Receipts { get { lock (History) return History.ToArray(); } }
        public override string ToString() => "[VaultFixturePlan]";
    }
    internal sealed class Result
    {
        internal required State State { get; init; }
        internal required RoleFixtureJournal.Snapshot Journal { get; init; }
        internal IReadOnlyList<Receipt> Receipts { get; init; } = [];
        internal bool? VaultPresent { get; init; }
        internal bool? DeletedVaultPresent { get; init; }
        internal bool? CanaryPresent { get; init; }
        internal string? CanarySha256 { get; init; }
        internal string? CanaryVersion { get; init; }
        internal VaultAdministrationEffects.Configuration? Configuration { get; init; }
        internal VaultAdministrationEffects.DeletedVaultRow? DeletedVault { get; init; }
        public override string ToString() => "[VaultFixtureResult]";
    }

    private sealed class StatusFailedPurgeCancellationProfile { }
    private StatusFailedPurgeCancellationProfile? failedCancellationProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusFailedPurgeCancellationProfile>
        failedCancellationPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusFailedPurgeCancellationCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        failedCancellationCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeCancellationPreparation, PendingFixtureFacts>
        failedCancellationPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeCancellationFixtureAdmission, PendingFixtureFacts>
        failedCancellationFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeCancellationFixtureDrain, PendingFixtureFacts>
        failedCancellationFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeCancellationAbsence, PendingFixtureFacts>
        failedCancellationAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusFailedPurgeCancellationPreparation>
        failedCancellationPreparationRoots = [];
    internal sealed class StatusFailedPurgeCancellationPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.failedCancellationPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.failedCancellationProfile is not null && ReferenceEquals(f.FailedCancellationProfile, source.failedCancellationProfile) &&
            StatusFailedPurgeCancellationSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationPreparations.GetValueOrDefault(this), journal, state, true, failedCancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedCancellationPreparations[this].After);
        public override string ToString() => "[StatusFailedPurgeCancellationPreparation]";
    }
    internal sealed class StatusFailedPurgeCancellationFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, false, failedCancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, true, failedCancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedCancellationFixtureAdmissions[this].After);
        public override string ToString() => "[StatusFailedPurgeCancellationFixtureAdmission]";
    }
    internal sealed class StatusFailedPurgeCancellationFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationFixtureDrains.GetValueOrDefault(this), journal, state, false, failedCancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationFixtureDrains.GetValueOrDefault(this), journal, state, true, failedCancellation: true);
        internal bool DrainOnly => source.failedCancellationFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedCancellationFixtureDrains[this].After);
        public override string ToString() => "[StatusFailedPurgeCancellationFixtureDrain]";
    }
    internal sealed class StatusFailedPurgeCancellationAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationAbsences.GetValueOrDefault(this), journal, state, false, failedCancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedCancellationAbsences.GetValueOrDefault(this), journal, state, true, failedCancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedCancellationAbsences[this].After);
        public override string ToString() => "[StatusFailedPurgeCancellationAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusFailedPurgeCancellation(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { failedCancellationProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    private sealed class StatusFailedPurgeIndependentProfile { }
    private StatusFailedPurgeIndependentProfile? failedIndependentProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusFailedPurgeIndependentProfile>
        failedIndependentPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusFailedPurgeIndependentCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        failedIndependentCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeIndependentPreparation, PendingFixtureFacts>
        failedIndependentPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeIndependentFixtureAdmission, PendingFixtureFacts>
        failedIndependentFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeIndependentFixtureDrain, PendingFixtureFacts>
        failedIndependentFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeIndependentAbsence, PendingFixtureFacts>
        failedIndependentAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusFailedPurgeIndependentPreparation>
        failedIndependentPreparationRoots = [];
    internal sealed class StatusFailedPurgeIndependentPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.failedIndependentPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.failedIndependentProfile is not null && ReferenceEquals(f.FailedIndependentProfile, source.failedIndependentProfile) &&
            StatusFailedPurgeIndependentSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentPreparations.GetValueOrDefault(this), journal, state, true, failedIndependent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedIndependentPreparations[this].After);
        public override string ToString() => "[StatusFailedPurgeIndependentPreparation]";
    }
    internal sealed class StatusFailedPurgeIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, false, failedIndependent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, true, failedIndependent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedIndependentFixtureAdmissions[this].After);
        public override string ToString() => "[StatusFailedPurgeIndependentFixtureAdmission]";
    }
    internal sealed class StatusFailedPurgeIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentFixtureDrains.GetValueOrDefault(this), journal, state, false, failedIndependent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentFixtureDrains.GetValueOrDefault(this), journal, state, true, failedIndependent: true);
        internal bool DrainOnly => source.failedIndependentFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedIndependentFixtureDrains[this].After);
        public override string ToString() => "[StatusFailedPurgeIndependentFixtureDrain]";
    }
    internal sealed class StatusFailedPurgeIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentAbsences.GetValueOrDefault(this), journal, state, false, failedIndependent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedIndependentAbsences.GetValueOrDefault(this), journal, state, true, failedIndependent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedIndependentAbsences[this].After);
        public override string ToString() => "[StatusFailedPurgeIndependentAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusFailedPurgeIndependent(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { failedIndependentProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    private sealed class StatusCanceledPurgeCancellationProfile { }
    private StatusCanceledPurgeCancellationProfile? canceledCancellationProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusCanceledPurgeCancellationProfile>
        canceledCancellationPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusCanceledPurgeCancellationCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        canceledCancellationCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeCancellationPreparation, PendingFixtureFacts>
        canceledCancellationPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeCancellationFixtureAdmission, PendingFixtureFacts>
        canceledCancellationFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeCancellationFixtureDrain, PendingFixtureFacts>
        canceledCancellationFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeCancellationAbsence, PendingFixtureFacts>
        canceledCancellationAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusCanceledPurgeCancellationPreparation>
        canceledCancellationPreparationRoots = [];
    internal sealed class StatusCanceledPurgeCancellationPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.canceledCancellationPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.canceledCancellationProfile is not null && ReferenceEquals(f.CanceledCancellationProfile, source.canceledCancellationProfile) &&
            StatusCanceledPurgeCancellationSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationPreparations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledCancellationPreparations[this].After);
        public override string ToString() => "[StatusCanceledPurgeCancellationPreparation]";
    }
    internal sealed class StatusCanceledPurgeCancellationFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledCancellationFixtureAdmissions[this].After);
        public override string ToString() => "[StatusCanceledPurgeCancellationFixtureAdmission]";
    }
    internal sealed class StatusCanceledPurgeCancellationFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationFixtureDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationFixtureDrains.GetValueOrDefault(this), journal, state, true);
        internal bool DrainOnly => source.canceledCancellationFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledCancellationFixtureDrains[this].After);
        public override string ToString() => "[StatusCanceledPurgeCancellationFixtureDrain]";
    }
    internal sealed class StatusCanceledPurgeCancellationAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationAbsences.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledCancellationFixtureValid(source.canceledCancellationAbsences.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledCancellationAbsences[this].After);
        public override string ToString() => "[StatusCanceledPurgeCancellationAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusCanceledPurgeCancellation(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { canceledCancellationProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    private sealed class StatusCanceledPurgeIndependentProfile { }
    private StatusCanceledPurgeIndependentProfile? canceledIndependentProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusCanceledPurgeIndependentProfile>
        canceledIndependentPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusCanceledPurgeIndependentCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        canceledIndependentCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeIndependentPreparation, PendingFixtureFacts>
        canceledIndependentPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeIndependentFixtureAdmission, PendingFixtureFacts>
        canceledIndependentFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeIndependentFixtureDrain, PendingFixtureFacts>
        canceledIndependentFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeIndependentAbsence, PendingFixtureFacts>
        canceledIndependentAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusCanceledPurgeIndependentPreparation>
        canceledIndependentPreparationRoots = [];
    internal sealed class StatusCanceledPurgeIndependentPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.canceledIndependentPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.canceledIndependentProfile is not null && ReferenceEquals(f.CanceledIndependentProfile, source.canceledIndependentProfile) &&
            StatusCanceledPurgeIndependentSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentPreparations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledIndependentPreparations[this].After);
        public override string ToString() => "[StatusCanceledPurgeIndependentPreparation]";
    }
    internal sealed class StatusCanceledPurgeIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledIndependentFixtureAdmissions[this].After);
        public override string ToString() => "[StatusCanceledPurgeIndependentFixtureAdmission]";
    }
    internal sealed class StatusCanceledPurgeIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentFixtureDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentFixtureDrains.GetValueOrDefault(this), journal, state, true);
        internal bool DrainOnly => source.canceledIndependentFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledIndependentFixtureDrains[this].After);
        public override string ToString() => "[StatusCanceledPurgeIndependentFixtureDrain]";
    }
    internal sealed class StatusCanceledPurgeIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentAbsences.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledIndependentFixtureValid(source.canceledIndependentAbsences.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledIndependentAbsences[this].After);
        public override string ToString() => "[StatusCanceledPurgeIndependentAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusCanceledPurgeIndependent(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { canceledIndependentProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }

    private sealed class StatusCanceledPurgeProfile { }
    private StatusCanceledPurgeProfile? canceledProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusCanceledPurgeProfile>
        canceledPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusCanceledPurgeCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        canceledCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgePreparation, PendingFixtureFacts>
        canceledPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeFixtureAdmission, PendingFixtureFacts>
        canceledFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeFixtureDrain, PendingFixtureFacts>
        canceledFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusCanceledPurgeAbsence, PendingFixtureFacts>
        canceledAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusCanceledPurgePreparation>
        canceledPreparationRoots = [];
    internal sealed class StatusCanceledPurgePreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.canceledPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.canceledProfile is not null && ReferenceEquals(f.CanceledProfile, source.canceledProfile) &&
            StatusCanceledPurgeSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledPreparations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledPreparations[this].After);
        public override string ToString() => "[StatusCanceledPurgePreparation]";
    }
    internal sealed class StatusCanceledPurgeFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledFixtureAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledFixtureAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledFixtureAdmissions[this].After);
        public override string ToString() => "[StatusCanceledPurgeFixtureAdmission]";
    }
    internal sealed class StatusCanceledPurgeFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledFixtureDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledFixtureDrains.GetValueOrDefault(this), journal, state, true);
        internal bool DrainOnly => source.canceledFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledFixtureDrains[this].After);
        public override string ToString() => "[StatusCanceledPurgeFixtureDrain]";
    }
    internal sealed class StatusCanceledPurgeAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledAbsences.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.CanceledFixtureValid(source.canceledAbsences.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.canceledAbsences[this].After);
        public override string ToString() => "[StatusCanceledPurgeAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusCanceledPurge(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { canceledProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }

    private sealed class StatusDeniedPurgeProfile(string variant = "operation.PurgeDeletedVault")
    {
        internal string Variant { get; } = variant;
    }
    private StatusDeniedPurgeProfile? deniedProfile;
    private bool DeclaredDeniedSelector(FixtureSelector selector) =>
        deniedProfile is not null && StatusDeniedPurgeSelector(selector) && selector.Variant == deniedProfile.Variant;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusDeniedPurgeProfile>
        deniedPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusDeniedPurgePreparation, PendingFixtureFacts>
        deniedPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusDeniedPurgeFixtureAdmission, PendingFixtureFacts>
        deniedFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusDeniedPurgeFixtureDrain, PendingFixtureFacts>
        deniedFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusDeniedPurgeAbsence, PendingFixtureFacts>
        deniedAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusDeniedPurgePreparation>
        deniedPreparationRoots = [];
    internal sealed class StatusDeniedPurgePreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.deniedPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.deniedProfile is not null && ReferenceEquals(f.DeniedProfile, source.deniedProfile) &&
            source.DeclaredDeniedSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedPreparations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.deniedPreparations[this].After);
        public override string ToString() => "[StatusDeniedPurgePreparation]";
    }
    internal sealed class StatusDeniedPurgeFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedFixtureAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedFixtureAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.deniedFixtureAdmissions[this].After);
        public override string ToString() => "[StatusDeniedPurgeFixtureAdmission]";
    }
    internal sealed class StatusDeniedPurgeFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedFixtureDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedFixtureDrains.GetValueOrDefault(this), journal, state, true);
        internal bool DrainOnly => source.deniedFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.deniedFixtureDrains[this].After);
        public override string ToString() => "[StatusDeniedPurgeFixtureDrain]";
    }
    internal sealed class StatusDeniedPurgeAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedAbsences.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.DeniedFixtureValid(source.deniedAbsences.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.deniedAbsences[this].After);
        public override string ToString() => "[StatusDeniedPurgeAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusDeniedPurge(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { deniedProfile = new() };
        Require(host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    internal static VaultFixtureProvisioner ForStatusDeniedPurgeStatus(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, NativeProvisioningState variant,
        TimeProvider? time = null)
    {
        Require(Enum.IsDefined(variant));
        var parent = ForStatusDeniedPurge(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time);
        parent.deniedProfile = new("status." + variant);
        return parent;
    }
    private sealed class StatusFailedPurgeProfile { }
    private StatusFailedPurgeProfile? failedProfile;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusFailedPurgeProfile>
        failedPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan,
        (ManagementOperationFixtureObserverService.StatusFailedPurgeCleanupAuthorization Authorization, RoleFixtureJournal.Snapshot Closed)>
        failedCleanup = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgePreparation, PendingFixtureFacts>
        failedPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeFixtureAdmission, PendingFixtureFacts>
        failedFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeFixtureDrain, PendingFixtureFacts>
        failedFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusFailedPurgeAbsence, PendingFixtureFacts>
        failedAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusFailedPurgePreparation>
        failedPreparationRoots = [];
    internal sealed class StatusFailedPurgePreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.failedPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.failedProfile is not null && ReferenceEquals(f.FailedProfile, source.failedProfile) &&
            StatusFailedPurgeSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedPreparations.GetValueOrDefault(this), journal, state, true, failed: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedPreparations[this].After);
        public override string ToString() => "[StatusFailedPurgePreparation]";
    }
    internal sealed class StatusFailedPurgeFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedFixtureAdmissions.GetValueOrDefault(this), journal, state, false, failed: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedFixtureAdmissions.GetValueOrDefault(this), journal, state, true, failed: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedFixtureAdmissions[this].After);
        public override string ToString() => "[StatusFailedPurgeFixtureAdmission]";
    }
    internal sealed class StatusFailedPurgeFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedFixtureDrains.GetValueOrDefault(this), journal, state, false, failed: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedFixtureDrains.GetValueOrDefault(this), journal, state, true, failed: true);
        internal bool DrainOnly => source.failedFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedFixtureDrains[this].After);
        public override string ToString() => "[StatusFailedPurgeFixtureDrain]";
    }
    internal sealed class StatusFailedPurgeAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedAbsences.GetValueOrDefault(this), journal, state, false, failed: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.failedAbsences.GetValueOrDefault(this), journal, state, true, failed: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.failedAbsences[this].After);
        public override string ToString() => "[StatusFailedPurgeAbsence]";
    }
    internal static VaultFixtureProvisioner ForStatusFailedPurge(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { failedProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    private bool statusPendingPurgeProfile;
    private sealed class StatusPendingPurgeIndependentProfile { }
    private StatusPendingPurgeIndependentProfile? pendingIndependentProfile;
    private sealed class StatusPendingPurgeCancellationProfile { }
    private StatusPendingPurgeCancellationProfile? pendingCancellationProfile;
    private bool PendingProfile => deniedProfile is not null || canceledCancellationProfile is not null || canceledIndependentProfile is not null || canceledProfile is not null || statusPendingPurgeProfile || pendingIndependentProfile is not null || pendingCancellationProfile is not null || failedProfile is not null || failedIndependentProfile is not null || failedCancellationProfile is not null || failedCancellationProfile is not null;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusPendingPurgeIndependentProfile>
        pendingIndependentPlans = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusPendingPurgeCancellationProfile>
        pendingCancellationPlans = new(ReferenceEqualityComparer.Instance);
    private sealed record PendingFixtureFacts(Plan? Plan, RoleFixtureJournal.Snapshot? Before,
        RoleFixtureJournal.Snapshot After, CancellationToken[] Tokens, Task[] Tasks, bool DrainOnly = false,
        object[]? Proofs = null)
    {
        internal volatile bool Invalid;
        internal long Started { get; init; } = TimeProvider.System.GetTimestamp();
        internal StatusFailedPurgeCancellationProfile? FailedCancellationProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusFailedPurgeCancellationCleanupAuthorization? CancellationCleanupAuthorization { get; init; }
        internal StatusFailedPurgeIndependentProfile? FailedIndependentProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusFailedPurgeIndependentCleanupAuthorization? IndependentCleanupAuthorization { get; init; }
        internal StatusCanceledPurgeCancellationProfile? CanceledCancellationProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusCanceledPurgeCancellationCleanupAuthorization? CanceledCancellationCleanupAuthorization { get; init; }
        internal StatusCanceledPurgeIndependentProfile? CanceledIndependentProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusCanceledPurgeIndependentCleanupAuthorization? CanceledIndependentCleanupAuthorization { get; init; }
        internal StatusCanceledPurgeProfile? CanceledProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusCanceledPurgeCleanupAuthorization? CanceledCleanupAuthorization { get; init; }
        internal StatusDeniedPurgeProfile? DeniedProfile { get; init; }
        internal StatusFailedPurgeProfile? FailedProfile { get; init; }
        internal ManagementOperationFixtureObserverService.StatusFailedPurgeCleanupAuthorization? CleanupAuthorization { get; init; }
        internal RoleFixtureJournal.Snapshot? CleanupClosed { get; init; }
        internal StatusPendingPurgeIndependentProfile? Profile { get; init; }
        internal StatusPendingPurgeCancellationProfile? CancellationProfile { get; init; }
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgePreparation, PendingFixtureFacts>
        pendingPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusPendingPurgePreparation>
        pendingPreparationRoots = [];
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeFixtureAdmission, PendingFixtureFacts>
        pendingFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeFixtureDrain, PendingFixtureFacts>
        pendingFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeAbsence, PendingFixtureFacts>
        pendingAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]>
        pendingCallers = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, object>
        pendingPersistence = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, object>
        pendingLastPersistence = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, PendingFixtureFacts>
        pendingReadyReads = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, System.Action>
        pendingLifetimeChecks = new(ReferenceEqualityComparer.Instance);

    // Registered once before original admission. This is only a revocation
    // guard, never settlement authority, and is never invoked from J.
    internal void BindStatusFailedPurgeCancellationLifetime(Plan plan, System.Action validate)
    {
        Require(failedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusFailedPurgeIndependentLifetime(Plan plan, System.Action validate)
    {
        Require(failedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusCanceledPurgeCancellationLifetime(Plan plan, System.Action validate)
    {
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusCanceledPurgeIndependentLifetime(Plan plan, System.Action validate)
    {
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusCanceledPurgeLifetime(Plan plan, System.Action validate)
    {
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusDeniedPurgeLifetime(Plan plan, System.Action validate)
    {
        Require(DeclaredDeniedSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }

    internal void BindStatusFailedPurgeLifetime(Plan plan, System.Action validate)
    {
        Require(failedProfile is not null && StatusFailedPurgeSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusPendingPurgeLifetime(Plan plan, System.Action validate)
    {
        Require(statusPendingPurgeProfile && StatusPendingPurgeSelector(plan.Selector));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusPendingPurgeIndependentLifetime(Plan plan, System.Action validate)
    {
        Require(IndependentPending(plan));
        BindPendingLifetime(plan, validate);
    }
    internal void BindStatusPendingPurgeCancellationLifetime(Plan plan, System.Action validate)
    {
        Require(CancellationPending(plan));
        BindPendingLifetime(plan, validate);
    }
    private void BindPendingLifetime(Plan plan, System.Action validate)
    {
        CheckPlan(plan);
        Require(PendingProfile && !plan.Restored && validate is not null &&
            ReadPlan(plan.Owner, plan.Selector).PurgeDeletedVault is
            ({ DeniedStage: RoleFixtureJournal.StatusDeniedPurgeStage.Prepared } or
             { PendingStage: RoleFixtureJournal.StatusPendingPurgeStage.Prepared } or
             { FailedStage: RoleFixtureJournal.StatusFailedPurgeStage.Prepared } or
             { CanceledStage: RoleFixtureJournal.StatusCanceledPurgeStage.Prepared }));
        Require(pendingLifetimeChecks.TryAdd(plan, validate));
        validate();
    }
    private void CheckPendingLifetime(Plan plan)
    {
        Require(!closed && pendingCallers.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
        if (pendingLifetimeChecks.TryGetValue(plan, out var check)) check();
    }
    private void CheckPendingFacts(PendingFixtureFacts facts)
    {
        if (facts.DrainOnly) return;
        var elapsed = TimeProvider.System.GetElapsedTime(facts.Started);
        if (elapsed < TimeSpan.Zero || elapsed >= limits.Timeout || facts.Tokens.Any(t => t.IsCancellationRequested))
            facts.Invalid = true;
        Require(!facts.Invalid);
    }
    private static bool OwnsPendingReadFacts(PendingFixtureFacts facts)
    {
        if (facts.Proofs is not { Length: 8 } proof || facts.Tasks is not
            [Task<ManagementOperationResourceCollector.Measurement> activeTask, Task<ManagementOperationResourceCollector.Measurement> deletedTask] ||
            proof[0] is not ManagementOperationResourceCollector active || proof[1] is not ManagementOperationNativeCapture.Binding activeBinding ||
            proof[2] is not ManagementOperationResourceCollector.Window activeWindow ||
            proof[4] is not ManagementOperationResourceCollector deleted || proof[5] is not ManagementOperationNativeCapture.Binding deletedBinding ||
            proof[6] is not ManagementOperationResourceCollector.Window deletedWindow) return false;
        return (proof[3], proof[7]) switch
        {
            (ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadProof a,
                ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadProof d) =>
                facts.FailedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(facts.After.Selector) &&
                active.OwnsStatusFailedPurgeCancellationRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeCancellationRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadProof a,
                ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadProof d) =>
                facts.FailedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(facts.After.Selector) &&
                active.OwnsStatusFailedPurgeIndependentRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeIndependentRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadProof a,
                ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadProof d) =>
                facts.CanceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(facts.After.Selector) &&
                active.OwnsStatusCanceledPurgeCancellationRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeCancellationRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadProof a,
                ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadProof d) =>
                facts.CanceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(facts.After.Selector) &&
                active.OwnsStatusCanceledPurgeIndependentRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeIndependentRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusCanceledPurgeReadProof a,
                ManagementOperationResourceCollector.StatusCanceledPurgeReadProof d) =>
                facts.CanceledProfile is not null && StatusCanceledPurgeSelector(facts.After.Selector) &&
                active.OwnsStatusCanceledPurgeRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusDeniedPurgeReadProof a,
                ManagementOperationResourceCollector.StatusDeniedPurgeReadProof d) =>
                facts.DeniedProfile is not null && StatusDeniedPurgeSelector(facts.After.Selector) &&
                active.OwnsStatusDeniedPurgeRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusDeniedPurgeRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusFailedPurgeReadProof a,
                ManagementOperationResourceCollector.StatusFailedPurgeReadProof d) =>
                facts.FailedProfile is not null && StatusFailedPurgeSelector(facts.After.Selector) &&
                active.OwnsStatusFailedPurgeRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadProof a,
                ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadProof d) =>
                facts.Profile is not null && StatusPendingPurgeIndependentSelector(facts.After.Selector) &&
                active.OwnsStatusPendingPurgeIndependentRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeIndependentRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadProof a,
                ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadProof d) =>
                facts.CancellationProfile is not null && StatusPendingPurgeCancellationSelector(facts.After.Selector) &&
                active.OwnsStatusPendingPurgeCancellationRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeCancellationRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            (ManagementOperationResourceCollector.StatusPendingPurgeReadProof a,
                ManagementOperationResourceCollector.StatusPendingPurgeReadProof d) =>
                facts.Profile is null && StatusPendingPurgeSelector(facts.After.Selector) &&
                active.OwnsStatusPendingPurgeRead(a, activeWindow, activeBinding, a.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeRead(d, deletedWindow, deletedBinding, d.Phase, deletedTask),
            _ => false
        };
    }

    internal sealed class StatusPendingPurgePreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.pendingPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.statusPendingPurgeProfile && f.Profile is null && StatusPendingPurgeSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingPreparations.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingPreparations[this].After);
        public override string ToString() => "[StatusPendingPurgePreparation]";
    }
    internal sealed class StatusPendingPurgeFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingFixtureAdmissions.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingFixtureAdmissions.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingFixtureAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeFixtureAdmission]";
    }
    internal sealed class StatusPendingPurgeFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingFixtureDrains.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingFixtureDrains.GetValueOrDefault(this), journal, state, true);
        internal bool DrainOnly => source.pendingFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingFixtureDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeFixtureDrain]";
    }
    internal sealed class StatusPendingPurgeAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingAbsences.GetValueOrDefault(this), journal, state, false);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingAbsences.GetValueOrDefault(this), journal, state, true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingAbsences[this].After);
        public override string ToString() => "[StatusPendingPurgeAbsence]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentPreparation, PendingFixtureFacts>
        pendingIndependentPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentFixtureAdmission, PendingFixtureFacts>
        pendingIndependentFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentFixtureDrain, PendingFixtureFacts>
        pendingIndependentFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeIndependentAbsence, PendingFixtureFacts>
        pendingIndependentAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusPendingPurgeIndependentPreparation>
        pendingIndependentPreparationRoots = [];
    internal sealed class StatusPendingPurgeIndependentPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.pendingIndependentPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.pendingIndependentProfile is not null && ReferenceEquals(f.Profile, source.pendingIndependentProfile) &&
            StatusPendingPurgeIndependentSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentPreparations.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentPreparations[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentPreparation]";
    }
    internal sealed class StatusPendingPurgeIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentFixtureAdmissions.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentFixtureAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentFixtureAdmission]";
    }
    internal sealed class StatusPendingPurgeIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentFixtureDrains.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentFixtureDrains.GetValueOrDefault(this), journal, state, true, independent: true);
        internal bool DrainOnly => source.pendingIndependentFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentFixtureDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentFixtureDrain]";
    }
    internal sealed class StatusPendingPurgeIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentAbsences.GetValueOrDefault(this), journal, state, false, independent: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingIndependentAbsences.GetValueOrDefault(this), journal, state, true, independent: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingIndependentAbsences[this].After);
        public override string ToString() => "[StatusPendingPurgeIndependentAbsence]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationPreparation, PendingFixtureFacts>
        pendingCancellationPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationFixtureAdmission, PendingFixtureFacts>
        pendingCancellationFixtureAdmissions = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationFixtureDrain, PendingFixtureFacts>
        pendingCancellationFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusPendingPurgeCancellationAbsence, PendingFixtureFacts>
        pendingCancellationAbsences = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, StatusPendingPurgeCancellationPreparation>
        pendingCancellationPreparationRoots = [];
    internal sealed class StatusPendingPurgeCancellationPreparation(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) => false;
        internal bool ValidateInitial(RoleFixtureJournal journal, string owner, FixtureSelector selector) =>
            source.pendingCancellationPreparations.TryGetValue(this, out var f) && ReferenceEquals(source.journal, journal) &&
            source.pendingCancellationProfile is not null && ReferenceEquals(f.CancellationProfile, source.pendingCancellationProfile) &&
            StatusPendingPurgeCancellationSelector(selector) &&
            !source.closed && !f.Invalid && f.Tokens.All(t => !t.IsCancellationRequested) &&
            f.Before is null && f.After.Owner == owner && f.After.Selector == selector;
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationPreparations.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationPreparations[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationPreparation]";
    }
    internal sealed class StatusPendingPurgeCancellationFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationFixtureAdmissions.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationFixtureAdmissions[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationFixtureAdmission]";
    }
    internal sealed class StatusPendingPurgeCancellationFixtureDrain(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationFixtureDrains.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationFixtureDrains.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal bool DrainOnly => source.pendingCancellationFixtureDrains.TryGetValue(this, out var f) && f.DrainOnly;
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationFixtureDrains[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationFixtureDrain]";
    }
    internal sealed class StatusPendingPurgeCancellationAbsence(VaultFixtureProvisioner source)
    {
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationAbsences.GetValueOrDefault(this), journal, state, false, cancellation: true);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.PendingFixtureValid(source.pendingCancellationAbsences.GetValueOrDefault(this), journal, state, true, cancellation: true);
        internal RoleFixtureJournal.Snapshot Postimage =>
            RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(source.pendingCancellationAbsences[this].After);
        public override string ToString() => "[StatusPendingPurgeCancellationAbsence]";
    }
    private bool CanceledCancellationFixtureValid(PendingFixtureFacts? facts, RoleFixtureJournal target,
        RoleFixtureJournal.Snapshot state, bool post)
    {
        if (facts is null || !ReferenceEquals(target, journal) || facts.Invalid) return false;
        if (canceledCancellationProfile is null || !ReferenceEquals(facts.CanceledCancellationProfile, canceledCancellationProfile) ||
            !StatusCanceledPurgeCancellationSelector(facts.After.Selector) || facts.Plan is not null &&
            (!canceledCancellationPlans.TryGetValue(facts.Plan, out var profile) || !ReferenceEquals(profile, canceledCancellationProfile))) return false;
        bool live = facts.DrainOnly || !closed &&
            (facts.CanceledCancellationCleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.CanceledCancellationCleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Plan is null || !pendingCallers.TryGetValue(facts.Plan, out var callers) ||
                callers.All(t => !t.IsCancellationRequested));
        bool valid = live && facts.Tasks.All(t => t.IsCompleted) &&
            (post ? RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) :
                facts.Before is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state));
        // A preimage probe may encounter the candidate's own postimage on retry.
        if (!live || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) &&
            (facts.Before is null || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state)))
            facts.Invalid = true;
        return valid;
    }
    private bool CanceledIndependentFixtureValid(PendingFixtureFacts? facts, RoleFixtureJournal target,
        RoleFixtureJournal.Snapshot state, bool post)
    {
        if (facts is null || !ReferenceEquals(target, journal) || facts.Invalid) return false;
        if (canceledIndependentProfile is null || !ReferenceEquals(facts.CanceledIndependentProfile, canceledIndependentProfile) ||
            !StatusCanceledPurgeIndependentSelector(facts.After.Selector) || facts.Plan is not null &&
            (!canceledIndependentPlans.TryGetValue(facts.Plan, out var profile) || !ReferenceEquals(profile, canceledIndependentProfile))) return false;
        bool live = facts.DrainOnly || !closed &&
            (facts.CanceledIndependentCleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.CanceledIndependentCleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Plan is null || !pendingCallers.TryGetValue(facts.Plan, out var callers) ||
                callers.All(t => !t.IsCancellationRequested));
        bool valid = live && facts.Tasks.All(t => t.IsCompleted) &&
            (post ? RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) :
                facts.Before is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state));
        // A preimage probe may encounter the candidate's own postimage on retry.
        if (!live || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) &&
            (facts.Before is null || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state)))
            facts.Invalid = true;
        return valid;
    }
    private bool DeniedFixtureValid(PendingFixtureFacts? facts, RoleFixtureJournal target,
        RoleFixtureJournal.Snapshot state, bool post)
    {
        if (facts is null || !ReferenceEquals(target, journal) || facts.Invalid) return false;
        if (deniedProfile is null || !ReferenceEquals(facts.DeniedProfile, deniedProfile) ||
            !DeclaredDeniedSelector(facts.After.Selector) || facts.Plan is not null &&
            (!deniedPlans.TryGetValue(facts.Plan, out var profile) || !ReferenceEquals(profile, deniedProfile))) return false;
        bool live = facts.DrainOnly || !closed &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Plan is null || !pendingCallers.TryGetValue(facts.Plan, out var callers) ||
                callers.All(t => !t.IsCancellationRequested));
        bool valid = live && facts.Tasks.All(t => t.IsCompleted) &&
            (post ? RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) :
                facts.Before is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state));
        // A preimage probe may encounter the candidate's own postimage on retry.
        if (!live || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) &&
            (facts.Before is null || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state)))
            facts.Invalid = true;
        return valid;
    }

    private bool CanceledFixtureValid(PendingFixtureFacts? facts, RoleFixtureJournal target,
        RoleFixtureJournal.Snapshot state, bool post)
    {
        if (facts is null || !ReferenceEquals(target, journal) || facts.Invalid) return false;
        if (canceledProfile is null || !ReferenceEquals(facts.CanceledProfile, canceledProfile) ||
            !StatusCanceledPurgeSelector(facts.After.Selector) || facts.Plan is not null &&
            (!canceledPlans.TryGetValue(facts.Plan, out var profile) || !ReferenceEquals(profile, canceledProfile))) return false;
        bool live = facts.DrainOnly || !closed &&
            (facts.CanceledCleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.CanceledCleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Plan is null || !pendingCallers.TryGetValue(facts.Plan, out var callers) ||
                callers.All(t => !t.IsCancellationRequested));
        bool valid = live && facts.Tasks.All(t => t.IsCompleted) &&
            (post ? RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) :
                facts.Before is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state));
        // A preimage probe may encounter the candidate's own postimage on retry.
        if (!live || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) &&
            (facts.Before is null || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state)))
            facts.Invalid = true;
        return valid;
    }
    private bool PendingFixtureValid(PendingFixtureFacts? facts, RoleFixtureJournal target,
        RoleFixtureJournal.Snapshot state, bool post, bool independent = false, bool cancellation = false, bool failed = false, bool failedIndependent = false, bool failedCancellation = false)
    {
        if (facts is null || !ReferenceEquals(target, journal) || facts.Invalid) return false;
        if (failedCancellation ? failedCancellationProfile is null || !ReferenceEquals(facts.FailedCancellationProfile, failedCancellationProfile) ||
            !StatusFailedPurgeCancellationSelector(facts.After.Selector) || facts.Plan is not null &&
                (!failedCancellationPlans.TryGetValue(facts.Plan, out var failedCancellationOwner) || !ReferenceEquals(failedCancellationOwner, facts.FailedCancellationProfile)) :
            failedIndependent ? failedIndependentProfile is null || !ReferenceEquals(facts.FailedIndependentProfile, failedIndependentProfile) ||
            !StatusFailedPurgeIndependentSelector(facts.After.Selector) || facts.Plan is not null &&
                (!failedIndependentPlans.TryGetValue(facts.Plan, out var failedIndependentOwner) || !ReferenceEquals(failedIndependentOwner, facts.FailedIndependentProfile)) :
            failed ? failedProfile is null || !ReferenceEquals(facts.FailedProfile, failedProfile) ||
            !StatusFailedPurgeSelector(facts.After.Selector) || facts.Plan is not null &&
                (!failedPlans.TryGetValue(facts.Plan, out var failedOwner) || !ReferenceEquals(failedOwner, facts.FailedProfile)) :
            cancellation ? pendingCancellationProfile is null || !ReferenceEquals(facts.CancellationProfile, pendingCancellationProfile) ||
            !StatusPendingPurgeCancellationSelector(facts.After.Selector) || facts.Plan is not null &&
                (!pendingCancellationPlans.TryGetValue(facts.Plan, out var cancellationProfile) || !ReferenceEquals(cancellationProfile, facts.CancellationProfile)) :
            independent ? pendingIndependentProfile is null || !ReferenceEquals(facts.Profile, pendingIndependentProfile) ||
            !StatusPendingPurgeIndependentSelector(facts.After.Selector) || facts.Plan is not null &&
                (!pendingIndependentPlans.TryGetValue(facts.Plan, out var profile) || !ReferenceEquals(profile, facts.Profile)) :
            !statusPendingPurgeProfile || facts.Profile is not null || !StatusPendingPurgeSelector(facts.After.Selector)) return false;
        bool live = facts.DrainOnly || !closed &&
            (facts.CancellationCleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.CancellationCleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            (facts.IndependentCleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.IndependentCleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            (facts.CleanupAuthorization is null || facts.CleanupClosed is not null && facts.Plan is not null &&
                facts.CleanupAuthorization.Validate(this, facts.Plan, journal, facts.CleanupClosed)) &&
            facts.Tokens.All(t => !t.IsCancellationRequested) &&
            (facts.Plan is null || !pendingCallers.TryGetValue(facts.Plan, out var callers) ||
                callers.All(t => !t.IsCancellationRequested));
        bool valid = live && facts.Tasks.All(t => t.IsCompleted) &&
            (post ? RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) :
                facts.Before is not null && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state));
        // A preimage probe may encounter the candidate's own postimage on retry.
        if (!live || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.After, state) &&
            (facts.Before is null || !RoleFixtureJournal.SameStatusPendingPurgeSnapshot(facts.Before, state)))
            facts.Invalid = true;
        return valid;
    }
    internal static bool StatusFailedPurgeCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Failed" && selector.Case == "cancellation-boundary";
    internal static bool StatusFailedPurgeIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Failed" && selector.Case == "independent-effect";
    internal static bool StatusCanceledPurgeCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Canceled" && selector.Case == "cancellation-boundary";
    internal static bool StatusCanceledPurgeIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Canceled" && selector.Case == "independent-effect";
    internal static bool StatusCanceledPurgeSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Canceled" && selector.Case == "selected-contract";
    internal static bool StatusDeniedPurgeSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant is "operation.PurgeDeletedVault" or "status.Succeeded" or "status.Pending" or
            "status.Failed" or "status.Canceled" or "status.Unknown" && selector.Case == "denied-authority";
    internal static bool StatusFailedPurgeSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Failed" && selector.Case == "selected-contract";
    internal static bool StatusPendingPurgeSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Pending" && selector.Case == "selected-contract";

    internal static bool StatusPendingPurgeIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Pending" && selector.Case == "independent-effect";
    internal static bool StatusPendingPurgeCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Pending" && selector.Case == "cancellation-boundary";
    private static bool PendingSelector(FixtureSelector selector) =>
        StatusDeniedPurgeSelector(selector) ||
        StatusCanceledPurgeCancellationSelector(selector) || StatusCanceledPurgeIndependentSelector(selector) || StatusCanceledPurgeSelector(selector) || StatusPendingPurgeSelector(selector) || StatusPendingPurgeIndependentSelector(selector) || StatusPendingPurgeCancellationSelector(selector) || StatusFailedPurgeSelector(selector) || StatusFailedPurgeIndependentSelector(selector) || StatusFailedPurgeCancellationSelector(selector);
    private static bool PendingRoot(RoleFixtureJournal.Snapshot state) =>
        RoleFixtureJournal.StatusDeniedPurgeRoot(state) ||
        RoleFixtureJournal.StatusCanceledPurgeCancellationRoot(state) || RoleFixtureJournal.StatusCanceledPurgeIndependentRoot(state) || RoleFixtureJournal.StatusCanceledPurgeRoot(state) || RoleFixtureJournal.StatusPendingPurgeRoot(state) || RoleFixtureJournal.StatusPendingPurgeIndependentRoot(state) ||
        RoleFixtureJournal.StatusPendingPurgeCancellationRoot(state) || RoleFixtureJournal.StatusFailedPurgeRoot(state) || RoleFixtureJournal.StatusFailedPurgeIndependentRoot(state) || RoleFixtureJournal.StatusFailedPurgeCancellationRoot(state);
    private bool IndependentPending(Plan plan)
    {
        if (StatusFailedPurgeCancellationSelector(plan.Selector))
        {
            Require(failedCancellationProfile is not null && failedCancellationPlans.TryGetValue(plan, out var failedCancellationOwner) && ReferenceEquals(failedCancellationOwner, failedCancellationProfile));
            return false;
        }
        if (StatusFailedPurgeIndependentSelector(plan.Selector))
        {
            Require(failedIndependentProfile is not null && failedIndependentPlans.TryGetValue(plan, out var failedIndependentOwner) && ReferenceEquals(failedIndependentOwner, failedIndependentProfile));
            return false;
        }
        if (StatusCanceledPurgeCancellationSelector(plan.Selector))
        {
            Require(canceledCancellationProfile is not null && canceledCancellationPlans.TryGetValue(plan, out var canceledCancellationOwner) && ReferenceEquals(canceledCancellationOwner, canceledCancellationProfile));
            return false;
        }
        if (StatusCanceledPurgeIndependentSelector(plan.Selector))
        {
            Require(canceledIndependentProfile is not null && canceledIndependentPlans.TryGetValue(plan, out var canceledIndependentOwner) && ReferenceEquals(canceledIndependentOwner, canceledIndependentProfile));
            return false;
        }
        if (StatusCanceledPurgeSelector(plan.Selector))
        {
            Require(canceledProfile is not null && canceledPlans.TryGetValue(plan, out var canceledOwner) && ReferenceEquals(canceledOwner, canceledProfile));
            return false;
        }
        if (StatusDeniedPurgeSelector(plan.Selector))
        {
            Require(DeclaredDeniedSelector(plan.Selector) && deniedPlans.TryGetValue(plan, out var deniedOwner) && ReferenceEquals(deniedOwner, deniedProfile));
            return false;
        }
        if (StatusFailedPurgeSelector(plan.Selector))
        {
            Require(failedProfile is not null && failedPlans.TryGetValue(plan, out var failedOwner) && ReferenceEquals(failedOwner, failedProfile));
            return false;
        }
        if (StatusPendingPurgeCancellationSelector(plan.Selector))
        {
            Require(CancellationPending(plan));
            return false;
        }
        Require(StatusPendingPurgeIndependentSelector(plan.Selector)
            ? pendingIndependentProfile is not null && pendingIndependentPlans.TryGetValue(plan, out var profile) &&
                ReferenceEquals(profile, pendingIndependentProfile)
            : statusPendingPurgeProfile && StatusPendingPurgeSelector(plan.Selector));
        return StatusPendingPurgeIndependentSelector(plan.Selector);
    }

    private bool CancellationPending(Plan plan)
    {
        if (!StatusPendingPurgeCancellationSelector(plan.Selector))
        {
            _ = IndependentPending(plan);
            return false;
        }
        Require(pendingCancellationProfile is not null && pendingCancellationPlans.TryGetValue(plan, out var profile) &&
            ReferenceEquals(profile, pendingCancellationProfile));
        return true;
    }

    internal static VaultFixtureProvisioner ForStatusPendingPurge(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { statusPendingPurgeProfile = true };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    internal static VaultFixtureProvisioner ForStatusPendingPurgeIndependent(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { pendingIndependentProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    internal static VaultFixtureProvisioner ForStatusPendingPurgeCancellation(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority observerArm, Authority observerSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret,
            observerArm, observerSecret, limits, time) { pendingCancellationProfile = new() };
        Require(ReferenceEquals(parent.time, TimeProvider.System) && host.AllowPurge &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
            typeof(TokenCredential).Assembly.GetName().Version == new Version(1, 63, 0, 0) &&
            typeof(ArmClient).Assembly.GetName().Version == new Version(1, 14, 0, 0) &&
            typeof(KeyVaultResource).Assembly.GetName().Version == new Version(1, 4, 0, 0));
        return parent;
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeCancellationConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(failedCancellationProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeCancellationCleanupConfiguration(HostScope expected)
    {
        Require(failedCancellationProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(failedIndependentProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeIndependentCleanupConfiguration(HostScope expected)
    {
        Require(failedIndependentProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeCancellationConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(canceledCancellationProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeCancellationCleanupConfiguration(HostScope expected)
    {
        Require(canceledCancellationProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(canceledIndependentProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeIndependentCleanupConfiguration(HostScope expected)
    {
        Require(canceledIndependentProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(canceledProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusCanceledPurgeCleanupConfiguration(HostScope expected)
    {
        Require(canceledProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusDeniedPurgeConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend, NativeProvisioningState? statusVariant = null)
    {
        Require(statusVariant is null || Enum.IsDefined(statusVariant.Value));
        Require(deniedProfile is not null &&
            deniedProfile.Variant == (statusVariant is null ? "operation.PurgeDeletedVault" : "status." + statusVariant.Value));
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusDeniedPurgeCleanupConfiguration(HostScope expected,
        NativeProvisioningState? statusVariant = null)
    {
        Require(statusVariant is null || Enum.IsDefined(statusVariant.Value));
        Require(deniedProfile is not null &&
            deniedProfile.Variant == (statusVariant is null ? "operation.PurgeDeletedVault" : "status." + statusVariant.Value));
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(failedProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusFailedPurgeCleanupConfiguration(HostScope expected)
    {
        Require(failedProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(statusPendingPurgeProfile);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(pendingIndependentProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeCancellationConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(pendingCancellationProfile is not null);
        return PendingConfiguration(expected, statusReader, resourceReader, selectedBackend);
    }
    private VaultAdministrationEffects.Configuration PendingConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        Require(statusReader is { Credential: not null, Transport: not null } && resourceReader is not null &&
            resourceReader.Label == readArm.Label && ReferenceEquals(resourceReader.Credential, readArm.Credential) &&
            ReferenceEquals(resourceReader.Transport, readArm.Transport) && selectedBackend is not null &&
            new[] { setupArm, setupSecret, readArm, readSecret }.All(a => a.Label != statusReader.Label &&
                !ReferenceEquals(a.Credential, statusReader.Credential) && !ReferenceEquals(a.Transport, statusReader.Transport) &&
                !ReferenceEquals(a.Transport, selectedBackend)) && !ReferenceEquals(statusReader.Transport, selectedBackend));
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeCleanupConfiguration(HostScope expected)
    {
        Require(statusPendingPurgeProfile);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeIndependentCleanupConfiguration(HostScope expected)
    {
        Require(pendingIndependentProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    internal VaultAdministrationEffects.Configuration StatusPendingPurgeCancellationCleanupConfiguration(HostScope expected)
    {
        Require(pendingCancellationProfile is not null);
        return PendingCleanupConfiguration(expected);
    }
    private VaultAdministrationEffects.Configuration PendingCleanupConfiguration(HostScope expected)
    {
        Require(!closed && PendingProfile && host == expected && host.AllowPurge &&
            (deniedProfile is not null || ReferenceEquals(time, TimeProvider.System)) &&
            baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 });
        return CopyConfiguration(baseline);
    }
    private RoleFixtureJournal.Snapshot PreparePendingRoot(string owner, FixtureSelector selector,
        RoleFixtureJournal.Resource[] rows, CancellationToken token, CancellationToken caller)
    {
        var image = new RoleFixtureJournal.Snapshot(owner, selector with { }, Guid.NewGuid(), false, rows.ToArray(),
            PurgeDeletedVault: new(rows[0].Id, rows[2].Id, CopyConfiguration(baseline),
                DeniedStage: deniedProfile is not null ? RoleFixtureJournal.StatusDeniedPurgeStage.Prepared : default,
                PendingStage: deniedProfile is null && canceledCancellationProfile is null && canceledIndependentProfile is null && canceledProfile is null && failedProfile is null && failedIndependentProfile is null && failedCancellationProfile is null ? RoleFixtureJournal.StatusPendingPurgeStage.Prepared : default,
                FailedStage: failedProfile is not null || failedIndependentProfile is not null || failedCancellationProfile is not null ? RoleFixtureJournal.StatusFailedPurgeStage.Prepared : default,
                CanceledStage: canceledCancellationProfile is not null || canceledIndependentProfile is not null || canceledProfile is not null ? RoleFixtureJournal.StatusCanceledPurgeStage.Prepared : default)) { Revision = 1 };
        Require(!token.IsCancellationRequested && !caller.IsCancellationRequested);
        var facts = new PendingFixtureFacts(null, null, image, [token, caller], [])
            { Profile = pendingIndependentProfile, CancellationProfile = pendingCancellationProfile, CanceledCancellationProfile = canceledCancellationProfile, CanceledIndependentProfile = canceledIndependentProfile, CanceledProfile = canceledProfile, DeniedProfile = deniedProfile, FailedProfile = failedProfile, FailedIndependentProfile = failedIndependentProfile, FailedCancellationProfile = failedCancellationProfile };
        if (failedCancellationProfile is not null)
        {
            Require(StatusFailedPurgeCancellationSelector(selector));
            var candidate = new StatusFailedPurgeCancellationPreparation(this);
            Require(failedCancellationPreparations.TryAdd(candidate, facts) && failedCancellationPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusFailedPurgeCancellationPreparation(owner, selector);
        }
        if (failedIndependentProfile is not null)
        {
            Require(StatusFailedPurgeIndependentSelector(selector));
            var candidate = new StatusFailedPurgeIndependentPreparation(this);
            Require(failedIndependentPreparations.TryAdd(candidate, facts) && failedIndependentPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusFailedPurgeIndependentPreparation(owner, selector);
        }
        if (canceledCancellationProfile is not null)
        {
            Require(StatusCanceledPurgeCancellationSelector(selector));
            var candidate = new StatusCanceledPurgeCancellationPreparation(this);
            Require(canceledCancellationPreparations.TryAdd(candidate, facts) && canceledCancellationPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusCanceledPurgeCancellationPreparation(owner, selector);
        }
        if (canceledIndependentProfile is not null)
        {
            Require(StatusCanceledPurgeIndependentSelector(selector));
            var candidate = new StatusCanceledPurgeIndependentPreparation(this);
            Require(canceledIndependentPreparations.TryAdd(candidate, facts) && canceledIndependentPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusCanceledPurgeIndependentPreparation(owner, selector);
        }
        if (canceledProfile is not null)
        {
            Require(StatusCanceledPurgeSelector(selector));
            var candidate = new StatusCanceledPurgePreparation(this);
            Require(canceledPreparations.TryAdd(candidate, facts) && canceledPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusCanceledPurgePreparation(owner, selector);
        }
        if (deniedProfile is not null)
        {
            Require(DeclaredDeniedSelector(selector));
            var candidate = new StatusDeniedPurgePreparation(this);
            Require(deniedPreparations.TryAdd(candidate, facts) && deniedPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusDeniedPurgePreparation(owner, selector);
        }
        if (failedProfile is not null)
        {
            Require(StatusFailedPurgeSelector(selector));
            var candidate = new StatusFailedPurgePreparation(this);
            Require(failedPreparations.TryAdd(candidate, facts) && failedPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusFailedPurgePreparation(owner, selector);
        }
        if (pendingCancellationProfile is not null)
        {
            Require(StatusPendingPurgeCancellationSelector(selector));
            var candidate = new StatusPendingPurgeCancellationPreparation(this);
            Require(pendingCancellationPreparations.TryAdd(candidate, facts) && pendingCancellationPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusPendingPurgeCancellationPreparation(owner, selector);
        }
        if (pendingIndependentProfile is not null)
        {
            Require(StatusPendingPurgeIndependentSelector(selector));
            var candidate = new StatusPendingPurgeIndependentPreparation(this);
            Require(pendingIndependentPreparations.TryAdd(candidate, facts) && pendingIndependentPreparationRoots.TryAdd(selector.Nonce, candidate));
            return RetryStatusPendingPurgeIndependentPreparation(owner, selector);
        }
        Require(statusPendingPurgeProfile && StatusPendingPurgeSelector(selector));
        var selected = new StatusPendingPurgePreparation(this);
        Require(pendingPreparations.TryAdd(selected, facts) && pendingPreparationRoots.TryAdd(selector.Nonce, selected));
        return RetryStatusPendingPurgePreparation(owner, selector);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgeCancellationPreparation(string owner, FixtureSelector selector)
    {
        Require(failedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(selector));
        Require(failedCancellationPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = failedCancellationPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusFailedPurgeCancellation(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgeIndependentPreparation(string owner, FixtureSelector selector)
    {
        Require(failedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(selector));
        Require(failedIndependentPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = failedIndependentPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusFailedPurgeIndependent(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgeCancellationPreparation(string owner, FixtureSelector selector)
    {
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(selector));
        Require(canceledCancellationPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = canceledCancellationPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusCanceledPurgeCancellation(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgeIndependentPreparation(string owner, FixtureSelector selector)
    {
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(selector));
        Require(canceledIndependentPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = canceledIndependentPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusCanceledPurgeIndependent(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgePreparation(string owner, FixtureSelector selector)
    {
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(selector));
        Require(canceledPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = canceledPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusCanceledPurge(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusDeniedPurgePreparation(string owner, FixtureSelector selector)
    {
        Require(DeclaredDeniedSelector(selector));
        Require(deniedPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = deniedPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusDeniedPurge(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }

    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgePreparation(string owner, FixtureSelector selector)
    {
        Require(failedProfile is not null && StatusFailedPurgeSelector(selector));
        Require(failedPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = failedPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusFailedPurge(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgePreparation(string owner, FixtureSelector selector)
    {
        Require(statusPendingPurgeProfile && StatusPendingPurgeSelector(selector));
        Require(pendingPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = pendingPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusPendingPurge(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeIndependentPreparation(string owner, FixtureSelector selector)
    {
        Require(pendingIndependentProfile is not null && StatusPendingPurgeIndependentSelector(selector));
        Require(pendingIndependentPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = pendingIndependentPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusPendingPurgeIndependent(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeCancellationPreparation(string owner, FixtureSelector selector)
    {
        Require(pendingCancellationProfile is not null && StatusPendingPurgeCancellationSelector(selector));
        Require(pendingCancellationPreparationRoots.TryGetValue(selector.Nonce, out var candidate));
        var facts = pendingCancellationPreparations[candidate];
        CheckPendingFacts(facts);
        var result = journal.PrepareStatusPendingPurgeCancellation(owner, selector, candidate);
        CheckPendingFacts(facts);
        return result;
    }
    private enum PendingFixturePublication { Admission, Drain, Absence }
    private object RegisterPendingFixture(PendingFixtureFacts facts, PendingFixturePublication publication)
    {
        Require(facts.Plan is not null);
        bool independent = IndependentPending(facts.Plan);
        bool cancellation = CancellationPending(facts.Plan);
        facts = facts with { Profile = independent ? pendingIndependentProfile : null,
            CancellationProfile = cancellation ? pendingCancellationProfile : null, CanceledCancellationProfile = canceledCancellationProfile, CanceledIndependentProfile = canceledIndependentProfile, CanceledProfile = canceledProfile, DeniedProfile = deniedProfile, FailedProfile = failedProfile, FailedIndependentProfile = failedIndependentProfile, FailedCancellationProfile = failedCancellationProfile };
        object candidate = facts.DeniedProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusDeniedPurgeFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusDeniedPurgeFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusDeniedPurgeAbsence(this),
            _ => throw Failure()
        } : facts.CanceledCancellationProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusCanceledPurgeCancellationFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusCanceledPurgeCancellationFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusCanceledPurgeCancellationAbsence(this),
            _ => throw Failure()
        } : facts.CanceledIndependentProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusCanceledPurgeIndependentFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusCanceledPurgeIndependentFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusCanceledPurgeIndependentAbsence(this),
            _ => throw Failure()
        } : facts.CanceledProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusCanceledPurgeFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusCanceledPurgeFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusCanceledPurgeAbsence(this),
            _ => throw Failure()
        } : facts.FailedCancellationProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusFailedPurgeCancellationFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusFailedPurgeCancellationFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusFailedPurgeCancellationAbsence(this),
            _ => throw Failure()
        } : facts.FailedIndependentProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusFailedPurgeIndependentFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusFailedPurgeIndependentFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusFailedPurgeIndependentAbsence(this),
            _ => throw Failure()
        } : facts.FailedProfile is not null ? publication switch
        {
            PendingFixturePublication.Admission => new StatusFailedPurgeFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusFailedPurgeFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusFailedPurgeAbsence(this),
            _ => throw Failure()
        } : cancellation ? publication switch
        {
            PendingFixturePublication.Admission => new StatusPendingPurgeCancellationFixtureAdmission(this),
            PendingFixturePublication.Drain => new StatusPendingPurgeCancellationFixtureDrain(this),
            PendingFixturePublication.Absence => new StatusPendingPurgeCancellationAbsence(this),
            _ => throw Failure()
        } : (independent, publication) switch
        {
            (true, PendingFixturePublication.Admission) => new StatusPendingPurgeIndependentFixtureAdmission(this),
            (true, PendingFixturePublication.Drain) => new StatusPendingPurgeIndependentFixtureDrain(this),
            (true, PendingFixturePublication.Absence) => new StatusPendingPurgeIndependentAbsence(this),
            (false, PendingFixturePublication.Admission) => new StatusPendingPurgeFixtureAdmission(this),
            (false, PendingFixturePublication.Drain) => new StatusPendingPurgeFixtureDrain(this),
            (false, PendingFixturePublication.Absence) => new StatusPendingPurgeAbsence(this),
            _ => throw Failure()
        };
        Require(candidate switch
        {
            StatusFailedPurgeCancellationFixtureAdmission value => failedCancellationFixtureAdmissions.TryAdd(value, facts),
            StatusFailedPurgeIndependentFixtureAdmission value => failedIndependentFixtureAdmissions.TryAdd(value, facts),
            StatusFailedPurgeCancellationFixtureDrain value => failedCancellationFixtureDrains.TryAdd(value, facts),
            StatusFailedPurgeIndependentFixtureDrain value => failedIndependentFixtureDrains.TryAdd(value, facts),
            StatusFailedPurgeCancellationAbsence value => failedCancellationAbsences.TryAdd(value, facts),
            StatusFailedPurgeIndependentAbsence value => failedIndependentAbsences.TryAdd(value, facts),
            StatusCanceledPurgeCancellationFixtureAdmission value => canceledCancellationFixtureAdmissions.TryAdd(value, facts),
            StatusCanceledPurgeIndependentFixtureAdmission value => canceledIndependentFixtureAdmissions.TryAdd(value, facts),
            StatusCanceledPurgeFixtureAdmission value => canceledFixtureAdmissions.TryAdd(value, facts),
            StatusCanceledPurgeCancellationFixtureDrain value => canceledCancellationFixtureDrains.TryAdd(value, facts),
            StatusCanceledPurgeIndependentFixtureDrain value => canceledIndependentFixtureDrains.TryAdd(value, facts),
            StatusCanceledPurgeFixtureDrain value => canceledFixtureDrains.TryAdd(value, facts),
            StatusCanceledPurgeCancellationAbsence value => canceledCancellationAbsences.TryAdd(value, facts),
            StatusCanceledPurgeIndependentAbsence value => canceledIndependentAbsences.TryAdd(value, facts),
            StatusCanceledPurgeAbsence value => canceledAbsences.TryAdd(value, facts),
            StatusDeniedPurgeFixtureAdmission value => deniedFixtureAdmissions.TryAdd(value, facts),
            StatusFailedPurgeFixtureAdmission value => failedFixtureAdmissions.TryAdd(value, facts),
            StatusDeniedPurgeFixtureDrain value => deniedFixtureDrains.TryAdd(value, facts),
            StatusFailedPurgeFixtureDrain value => failedFixtureDrains.TryAdd(value, facts),
            StatusDeniedPurgeAbsence value => deniedAbsences.TryAdd(value, facts),
            StatusFailedPurgeAbsence value => failedAbsences.TryAdd(value, facts),
            StatusPendingPurgeFixtureAdmission value => pendingFixtureAdmissions.TryAdd(value, facts),
            StatusPendingPurgeIndependentFixtureAdmission value => pendingIndependentFixtureAdmissions.TryAdd(value, facts),
            StatusPendingPurgeCancellationFixtureAdmission value => pendingCancellationFixtureAdmissions.TryAdd(value, facts),
            StatusPendingPurgeFixtureDrain value => pendingFixtureDrains.TryAdd(value, facts),
            StatusPendingPurgeIndependentFixtureDrain value => pendingIndependentFixtureDrains.TryAdd(value, facts),
            StatusPendingPurgeCancellationFixtureDrain value => pendingCancellationFixtureDrains.TryAdd(value, facts),
            StatusPendingPurgeAbsence value => pendingAbsences.TryAdd(value, facts),
            StatusPendingPurgeIndependentAbsence value => pendingIndependentAbsences.TryAdd(value, facts),
            StatusPendingPurgeCancellationAbsence value => pendingCancellationAbsences.TryAdd(value, facts),
            _ => false
        });
        return candidate;
    }
    private PendingFixtureFacts PendingFixtureFact(object candidate) => candidate switch
    {
        StatusFailedPurgeCancellationFixtureAdmission value => failedCancellationFixtureAdmissions[value],
        StatusFailedPurgeIndependentFixtureAdmission value => failedIndependentFixtureAdmissions[value],
        StatusFailedPurgeCancellationFixtureDrain value => failedCancellationFixtureDrains[value],
        StatusFailedPurgeIndependentFixtureDrain value => failedIndependentFixtureDrains[value],
        StatusFailedPurgeCancellationAbsence value => failedCancellationAbsences[value],
        StatusFailedPurgeIndependentAbsence value => failedIndependentAbsences[value],
        StatusCanceledPurgeCancellationFixtureAdmission value => canceledCancellationFixtureAdmissions[value],
        StatusCanceledPurgeIndependentFixtureAdmission value => canceledIndependentFixtureAdmissions[value],
        StatusCanceledPurgeFixtureAdmission value => canceledFixtureAdmissions[value],
        StatusCanceledPurgeCancellationFixtureDrain value => canceledCancellationFixtureDrains[value],
        StatusCanceledPurgeIndependentFixtureDrain value => canceledIndependentFixtureDrains[value],
        StatusCanceledPurgeFixtureDrain value => canceledFixtureDrains[value],
        StatusCanceledPurgeCancellationAbsence value => canceledCancellationAbsences[value],
        StatusCanceledPurgeIndependentAbsence value => canceledIndependentAbsences[value],
        StatusCanceledPurgeAbsence value => canceledAbsences[value],
        StatusDeniedPurgeFixtureAdmission value => deniedFixtureAdmissions[value],
        StatusFailedPurgeFixtureAdmission value => failedFixtureAdmissions[value],
        StatusDeniedPurgeFixtureDrain value => deniedFixtureDrains[value],
        StatusFailedPurgeFixtureDrain value => failedFixtureDrains[value],
        StatusDeniedPurgeAbsence value => deniedAbsences[value],
        StatusFailedPurgeAbsence value => failedAbsences[value],
        StatusPendingPurgeFixtureAdmission value => pendingFixtureAdmissions[value],
        StatusPendingPurgeIndependentFixtureAdmission value => pendingIndependentFixtureAdmissions[value],
        StatusPendingPurgeCancellationFixtureAdmission value => pendingCancellationFixtureAdmissions[value],
        StatusPendingPurgeFixtureDrain value => pendingFixtureDrains[value],
        StatusPendingPurgeIndependentFixtureDrain value => pendingIndependentFixtureDrains[value],
        StatusPendingPurgeCancellationFixtureDrain value => pendingCancellationFixtureDrains[value],
        StatusPendingPurgeAbsence value => pendingAbsences[value],
        StatusPendingPurgeIndependentAbsence value => pendingIndependentAbsences[value],
        StatusPendingPurgeCancellationAbsence value => pendingCancellationAbsences[value],
        _ => throw Failure()
    };

    private RoleFixtureJournal.Snapshot BeginPendingFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        _ = IndependentPending(plan);
        Require(!pendingPersistence.ContainsKey(plan));
        var before = ReadPlan(plan.Owner, plan.Selector);
        Require(PendingRoot(before) && before.Idle &&
            (StatusDeniedPurgeSelector(plan.Selector)
                ? before.PurgeDeletedVault!.DeniedStage == RoleFixtureJournal.StatusDeniedPurgeStage.Prepared
                : (StatusCanceledPurgeCancellationSelector(plan.Selector) || StatusCanceledPurgeIndependentSelector(plan.Selector) || StatusCanceledPurgeSelector(plan.Selector))
                ? before.PurgeDeletedVault!.CanceledStage == RoleFixtureJournal.StatusCanceledPurgeStage.Prepared ||
                    delete && before.PurgeDeletedVault.CanceledStage == RoleFixtureJournal.StatusCanceledPurgeStage.TerminalCanceled
                : (StatusFailedPurgeSelector(plan.Selector) || StatusFailedPurgeIndependentSelector(plan.Selector) || StatusFailedPurgeCancellationSelector(plan.Selector))
                ? before.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.Prepared ||
                    delete && before.PurgeDeletedVault.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.TerminalFailed
                : before.PurgeDeletedVault!.PendingStage == RoleFixtureJournal.StatusPendingPurgeStage.Prepared) &&
            before.Closing == delete && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var dispatch = Guid.NewGuid();
        bool failedCleanupDispatch = (StatusFailedPurgeSelector(plan.Selector) || StatusFailedPurgeIndependentSelector(plan.Selector) || StatusFailedPurgeCancellationSelector(plan.Selector)) && delete &&
            before.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.TerminalFailed;
        bool canceledCleanupDispatch = (StatusCanceledPurgeCancellationSelector(plan.Selector) || StatusCanceledPurgeIndependentSelector(plan.Selector) || StatusCanceledPurgeSelector(plan.Selector)) && delete &&
            before.PurgeDeletedVault!.CanceledStage == RoleFixtureJournal.StatusCanceledPurgeStage.TerminalCanceled;
        var canceledCancellationCleanupAuthority = canceledCancellationCleanup.GetValueOrDefault(plan);
        var canceledIndependentCleanupAuthority = canceledIndependentCleanup.GetValueOrDefault(plan);
        var canceledCleanupAuthority = canceledCleanup.GetValueOrDefault(plan);
        if (canceledCleanupDispatch) Require(dispatch != before.PurgeDeletedVault!.InvocationDispatch &&
            (StatusCanceledPurgeCancellationSelector(plan.Selector)
                ? canceledCancellationCleanupAuthority.Authorization is not null && canceledCancellationCleanupAuthority.Authorization.Validate(this, plan, journal, before)
            : StatusCanceledPurgeIndependentSelector(plan.Selector)
                ? canceledIndependentCleanupAuthority.Authorization is not null && canceledIndependentCleanupAuthority.Authorization.Validate(this, plan, journal, before)
                : canceledCleanupAuthority.Authorization is not null && canceledCleanupAuthority.Authorization.Validate(this, plan, journal, before)));
        var cleanupAuthority = failedCleanup.GetValueOrDefault(plan);
        var independentCleanupAuthority = failedIndependentCleanup.GetValueOrDefault(plan);
        var cancellationCleanupAuthority = failedCancellationCleanup.GetValueOrDefault(plan);
        if (failedCleanupDispatch) Require(dispatch != before.PurgeDeletedVault!.InvocationDispatch &&
            (StatusFailedPurgeCancellationSelector(plan.Selector)
                ? cancellationCleanupAuthority.Authorization is not null && cancellationCleanupAuthority.Authorization.Validate(this, plan, journal, before)
                : StatusFailedPurgeIndependentSelector(plan.Selector)
                ? independentCleanupAuthority.Authorization is not null && independentCleanupAuthority.Authorization.Validate(this, plan, journal, before)
                : cleanupAuthority.Authorization is not null && cleanupAuthority.Authorization.Validate(this, plan, journal, before)));
        var after = before with
        {
            Revision = before.Revision + 1,
            PurgeDeletedVault = canceledCleanupDispatch ? before.PurgeDeletedVault! with
                { CanceledStage = RoleFixtureJournal.StatusCanceledPurgeStage.CleanupAdmitted } : failedCleanupDispatch ? before.PurgeDeletedVault! with
                { FailedStage = RoleFixtureJournal.StatusFailedPurgeStage.CleanupAdmitted } : before.PurgeDeletedVault,
            Resources = before.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete, DeleteAttempted = delete,
                ActiveDispatch = dispatch, InvocationTerminated = false, Absent = false
            } : r with { Absent = false }).ToArray()
        };
        PendingFixtureFacts? ready = null;
        if (delete)
        {
            Require(pendingReadyReads.TryRemove(plan, out ready) && ready is not null &&
                RoleFixtureJournal.SameStatusPendingPurgeSnapshot(ready.After, before));
            CheckPendingFacts(ready);
            Require(OwnsPendingReadFacts(ready));
        }
        var candidate = RegisterPendingFixture(new PendingFixtureFacts(plan, before, after,
            ready is null ? [token, caller] : [.. ready.Tokens, token, caller], ready?.Tasks ?? [],
            Proofs: ready?.Proofs)
            { Started = ready?.Started ?? TimeProvider.System.GetTimestamp(),
                CanceledCancellationCleanupAuthorization = canceledCleanupDispatch && StatusCanceledPurgeCancellationSelector(plan.Selector) ? canceledCancellationCleanupAuthority.Authorization : null,
                CanceledIndependentCleanupAuthorization = canceledCleanupDispatch && StatusCanceledPurgeIndependentSelector(plan.Selector) ? canceledIndependentCleanupAuthority.Authorization : null,
                CanceledCleanupAuthorization = canceledCleanupDispatch && StatusCanceledPurgeSelector(plan.Selector) ? canceledCleanupAuthority.Authorization : null,
                CleanupAuthorization = failedCleanupDispatch ? cleanupAuthority.Authorization : null,
                IndependentCleanupAuthorization = failedCleanupDispatch ? independentCleanupAuthority.Authorization : null,
                CancellationCleanupAuthorization = failedCleanupDispatch ? cancellationCleanupAuthority.Authorization : null,
                CleanupClosed = canceledCleanupDispatch || failedCleanupDispatch ? RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(before) : null }, PendingFixturePublication.Admission);
        pendingPersistence[plan] = candidate;
        return RetryPendingFixturePersistence(plan);
    }
    private void EndPendingFixture(Plan plan, string resourceId, RoleFixtureJournal.Snapshot admitted,
        Task<Operation?> nativeTask, Task<Response>? statusTask, BoundaryTransport boundary,
        bool terminal, CancellationToken token, CancellationToken caller)
    {
        Require(nativeTask.IsCompleted && (statusTask is null || statusTask.IsCompleted) && boundary.FixturePhysicalDrainComplete);
        var dispatch = admitted.Resources.Single(r => r.Id == resourceId).ActiveDispatch;
        var before = admitted;
        if (!terminal)
        {
            // Close may race physical drain; it never grants positive settlement.
            var current = journal.Read(plan.Owner, plan.Selector);
            Require(RoleFixtureJournal.SameStatusPendingPurgeSnapshot(current, admitted) || current.Closing &&
                RoleFixtureJournal.SameStatusPendingPurgeSnapshot(admitted with { Closing = true, Revision = current.Revision }, current));
            before = current;
        }
        var after = before with
        {
            Revision = before.Revision + 1,
            PurgeDeletedVault = terminal && before.PurgeDeletedVault!.CanceledStage == RoleFixtureJournal.StatusCanceledPurgeStage.CleanupAdmitted
                ? before.PurgeDeletedVault with { CanceledStage = RoleFixtureJournal.StatusCanceledPurgeStage.CleanupTerminal }
                : terminal && before.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.CleanupAdmitted
                ? before.PurgeDeletedVault with { FailedStage = RoleFixtureJournal.StatusFailedPurgeStage.CleanupTerminal } : before.PurgeDeletedVault,
            Resources = before.Resources.Select(r => r.Id == resourceId
                ? r with { InvocationTerminated = true, ActiveDispatch = terminal ? Guid.Empty : dispatch } : r).ToArray()
        };
        var origin = (StatusDeniedPurgeSelector(plan.Selector) ? deniedFixtureAdmissions.Values :
            StatusCanceledPurgeCancellationSelector(plan.Selector) ? canceledCancellationFixtureAdmissions.Values :
            StatusCanceledPurgeIndependentSelector(plan.Selector) ? canceledIndependentFixtureAdmissions.Values :
            StatusCanceledPurgeSelector(plan.Selector) ? canceledFixtureAdmissions.Values :
            StatusFailedPurgeCancellationSelector(plan.Selector) ? failedCancellationFixtureAdmissions.Values :
            StatusFailedPurgeIndependentSelector(plan.Selector) ? failedIndependentFixtureAdmissions.Values :
            StatusFailedPurgeSelector(plan.Selector) ? failedFixtureAdmissions.Values :
            CancellationPending(plan) ? pendingCancellationFixtureAdmissions.Values :
            IndependentPending(plan) ? pendingIndependentFixtureAdmissions.Values : pendingFixtureAdmissions.Values)
            .Single(f => ReferenceEquals(f.Plan, plan) && f.After.Resources.Any(r => r.ActiveDispatch == dispatch)).Started;
        var candidate = RegisterPendingFixture(new PendingFixtureFacts(plan, before, after, [token, caller],
            statusTask is null ? [nativeTask] : [nativeTask, statusTask], !terminal, [boundary]) { Started = origin },
            PendingFixturePublication.Drain);
        pendingPersistence[plan] = candidate;
        try { RetryPendingFixturePersistence(plan); }
        catch (InvalidOperationException) when (terminal && PendingFixtureFact(candidate).Invalid)
        {
            pendingPersistence.TryRemove(plan, out _);
            EndPendingFixture(plan, resourceId, admitted, nativeTask, statusTask, boundary, false, token, caller);
            throw;
        }
        pendingPersistence.TryRemove(plan, out _);
    }
    internal bool HasStatusFailedPurgeCancellationPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(failedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgeCancellationPersistence(Plan plan)
    {
        Require(failedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusFailedPurgeIndependentPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(failedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgeIndependentPersistence(Plan plan)
    {
        Require(failedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusCanceledPurgeCancellationPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgeCancellationPersistence(Plan plan)
    {
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusCanceledPurgeIndependentPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgeIndependentPersistence(Plan plan)
    {
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusCanceledPurgePersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusCanceledPurgePersistence(Plan plan)
    {
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusDeniedPurgePersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(DeclaredDeniedSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusDeniedPurgePersistence(Plan plan)
    {
        Require(DeclaredDeniedSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusFailedPurgePersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(failedProfile is not null && StatusFailedPurgeSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusFailedPurgePersistence(Plan plan)
    {
        Require(failedProfile is not null && StatusFailedPurgeSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal bool HasStatusPendingPurgePersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(statusPendingPurgeProfile && StatusPendingPurgeSelector(plan.Selector));
        return pendingPersistence.ContainsKey(plan);
    }
    internal bool HasStatusPendingPurgeIndependentPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(IndependentPending(plan));
        return pendingPersistence.ContainsKey(plan);
    }
    internal bool HasStatusPendingPurgeCancellationPersistence(Plan plan)
    {
        CheckPlan(plan);
        Require(CancellationPending(plan));
        return pendingPersistence.ContainsKey(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgePersistence(Plan plan)
    {
        Require(statusPendingPurgeProfile && StatusPendingPurgeSelector(plan.Selector));
        return RetryPendingFixturePersistence(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeIndependentPersistence(Plan plan)
    {
        Require(IndependentPending(plan));
        return RetryPendingFixturePersistence(plan);
    }
    internal RoleFixtureJournal.Snapshot RetryStatusPendingPurgeCancellationPersistence(Plan plan)
    {
        Require(CancellationPending(plan));
        return RetryPendingFixturePersistence(plan);
    }
    private RoleFixtureJournal.Snapshot RetryPendingFixturePersistence(Plan plan)
    {
        CheckPlan(plan);
        _ = IndependentPending(plan);
        Require(pendingPersistence.TryGetValue(plan, out var candidate) || pendingLastPersistence.TryGetValue(plan, out candidate));
        var facts = PendingFixtureFact(candidate);
        CheckPendingFacts(facts);
        if (facts.Proofs is { Length: 8 })
        {
            if (!OwnsPendingReadFacts(facts)) facts.Invalid = true;
            Require(!facts.Invalid);
        }
        if (!facts.DrainOnly) CheckPendingLifetime(plan);
        var result = candidate switch
        {
            StatusFailedPurgeCancellationFixtureAdmission admission => journal.BeginStatusFailedPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusFailedPurgeIndependentFixtureAdmission admission => journal.BeginStatusFailedPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusFailedPurgeCancellationFixtureDrain drain => journal.EndStatusFailedPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusFailedPurgeIndependentFixtureDrain drain => journal.EndStatusFailedPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusFailedPurgeCancellationAbsence absence => journal.RecordStatusFailedPurgeCancellationAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusFailedPurgeIndependentAbsence absence => journal.RecordStatusFailedPurgeIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusCanceledPurgeCancellationFixtureAdmission admission => journal.BeginStatusCanceledPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusCanceledPurgeIndependentFixtureAdmission admission => journal.BeginStatusCanceledPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusCanceledPurgeFixtureAdmission admission => journal.BeginStatusCanceledPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusCanceledPurgeCancellationFixtureDrain drain => journal.EndStatusCanceledPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusCanceledPurgeIndependentFixtureDrain drain => journal.EndStatusCanceledPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusCanceledPurgeFixtureDrain drain => journal.EndStatusCanceledPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusCanceledPurgeCancellationAbsence absence => journal.RecordStatusCanceledPurgeCancellationAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusCanceledPurgeIndependentAbsence absence => journal.RecordStatusCanceledPurgeIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusCanceledPurgeAbsence absence => journal.RecordStatusCanceledPurgeAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusDeniedPurgeFixtureAdmission admission => journal.BeginStatusDeniedPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusFailedPurgeFixtureAdmission admission => journal.BeginStatusFailedPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusDeniedPurgeFixtureDrain drain => journal.EndStatusDeniedPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusFailedPurgeFixtureDrain drain => journal.EndStatusFailedPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusDeniedPurgeAbsence absence => journal.RecordStatusDeniedPurgeAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusFailedPurgeAbsence absence => journal.RecordStatusFailedPurgeAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusPendingPurgeIndependentFixtureAdmission admission =>
                journal.BeginStatusPendingPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusPendingPurgeIndependentFixtureDrain drain =>
                journal.EndStatusPendingPurgeIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusPendingPurgeIndependentAbsence absence =>
                journal.RecordStatusPendingPurgeIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusPendingPurgeCancellationFixtureAdmission admission =>
                journal.BeginStatusPendingPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusPendingPurgeCancellationFixtureDrain drain =>
                journal.EndStatusPendingPurgeCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusPendingPurgeCancellationAbsence absence =>
                journal.RecordStatusPendingPurgeCancellationAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            StatusPendingPurgeFixtureAdmission admission =>
                journal.BeginStatusPendingPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, admission),
            StatusPendingPurgeFixtureDrain drain =>
                journal.EndStatusPendingPurgeFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, drain),
            StatusPendingPurgeAbsence absence =>
                journal.RecordStatusPendingPurgeAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence),
            _ => throw Failure()
        };
        CheckPendingFacts(facts);
        if (!facts.DrainOnly) CheckPendingLifetime(plan);
        pendingLastPersistence[plan] = candidate;
        pendingPersistence.TryRemove(plan, out _);
        return result;
    }

    private async Task<bool> ReadPendingPair(Plan plan, bool final, CancellationToken token, CancellationToken caller)
    {
        long epoch = TimeProvider.System.GetTimestamp();
        if (!final) pendingReadyReads.TryRemove(plan, out _);
        var before = ReadPlan(plan.Owner, plan.Selector);
        Require(PendingRoot(before) && MatchesPlan(plan, before));
        CheckPendingLifetime(plan);
        var authority = new ManagementOperationResourceCollector.Authority(readArm.Label, readArm.Credential, readArm.Transport);
        var readLimits = PendingResourceLimits();
        var active = new ManagementOperationResourceCollector(authority, readLimits, time, host.TenantId);
        var deleted = new ManagementOperationResourceCollector(authority, readLimits, time, host.TenantId);
        var activeBinding = new ManagementOperationNativeCapture.Binding(plan.Selector, plan.LeaseId, Scope(plan),
            ManagementMutation.PurgeDeletedVault, host.Location, Revision);
        var deletedBinding = new ManagementOperationNativeCapture.Binding(plan.Selector, plan.LeaseId,
            new DeletedVaultScope(new(host.SubscriptionId), host.Location, plan.VaultName),
            ManagementMutation.PurgeDeletedVault, host.Location, Revision);
        bool independent = IndependentPending(plan);
        bool cancellation = CancellationPending(plan);
        bool failedCancellation = StatusFailedPurgeCancellationSelector(plan.Selector);
        bool failedIndependent = StatusFailedPurgeIndependentSelector(plan.Selector);
        bool canceledCancellation = StatusCanceledPurgeCancellationSelector(plan.Selector);
        bool canceledIndependent = StatusCanceledPurgeIndependentSelector(plan.Selector);
        bool canceled = StatusCanceledPurgeSelector(plan.Selector);
        bool denied = StatusDeniedPurgeSelector(plan.Selector);
        bool failed = StatusFailedPurgeSelector(plan.Selector);
        object activePhase = denied
            ? final ? ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase.FinalActiveAbsent :
                ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase.ReadyActiveAbsent
            : failedCancellation
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.ReadyActiveAbsent
            : failedIndependent
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.ReadyActiveAbsent
            : canceledCancellation
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.ReadyActiveAbsent
            : canceledIndependent
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.ReadyActiveAbsent
            : canceled
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.ReadyActiveAbsent
            : failed
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.FinalActiveAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.CleanupActiveAbsent : ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.ReadyActiveAbsent
            : cancellation
            ? final ? ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase.FinalActiveAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase.ReadyActiveAbsent
            : independent
            ? final ? ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase.FinalActiveAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase.ReadyActiveAbsent
            : final ? ManagementOperationResourceCollector.StatusPendingPurgeReadPhase.FinalActiveAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeReadPhase.ReadyActiveAbsent;
        object deletedPhase = denied
            ? final ? ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase.FinalDeletedAbsent :
                ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase.ReadyDeletedPresent
            : failedCancellation
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase.ReadyDeletedPresent
            : failedIndependent
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase.ReadyDeletedPresent
            : canceledCancellation
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase.ReadyDeletedPresent
            : canceledIndependent
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase.ReadyDeletedPresent
            : canceled
            ? final ? ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase.ReadyDeletedPresent
            : failed
            ? final ? ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.FinalDeletedAbsent : before.Closing
                ? ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.CleanupDeletedPresent : ManagementOperationResourceCollector.StatusFailedPurgeReadPhase.ReadyDeletedPresent
            : cancellation
            ? final ? ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase.FinalDeletedAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase.ReadyDeletedPresent
            : independent
            ? final ? ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase.FinalDeletedAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase.ReadyDeletedPresent
            : final ? ManagementOperationResourceCollector.StatusPendingPurgeReadPhase.FinalDeletedAbsent :
                ManagementOperationResourceCollector.StatusPendingPurgeReadPhase.ReadyDeletedPresent;
        var activeWindow = denied
            ? active.ArmStatusDeniedPurge(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase)activePhase)
            : failedCancellation
            ? active.ArmStatusFailedPurgeCancellation(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase)activePhase)
            : failedIndependent
            ? active.ArmStatusFailedPurgeIndependent(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase)activePhase)
            : canceledCancellation
            ? active.ArmStatusCanceledPurgeCancellation(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase)activePhase)
            : canceledIndependent
            ? active.ArmStatusCanceledPurgeIndependent(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase)activePhase)
            : canceled
            ? active.ArmStatusCanceledPurge(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase)activePhase)
            : failed
            ? active.ArmStatusFailedPurge(activeBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeReadPhase)activePhase)
            : cancellation
            ? active.ArmStatusPendingPurgeCancellation(activeBinding, before.PurgeDeletedVault!.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase)activePhase)
            : independent
            ? active.ArmStatusPendingPurgeIndependent(activeBinding, before.PurgeDeletedVault!.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase)activePhase)
            : active.ArmStatusPendingPurge(activeBinding, before.PurgeDeletedVault!.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeReadPhase)activePhase);
        var deletedWindow = denied
            ? deleted.ArmStatusDeniedPurge(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase)deletedPhase)
            : failedCancellation
            ? deleted.ArmStatusFailedPurgeCancellation(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase)deletedPhase)
            : failedIndependent
            ? deleted.ArmStatusFailedPurgeIndependent(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase)deletedPhase)
            : canceledCancellation
            ? deleted.ArmStatusCanceledPurgeCancellation(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase)deletedPhase)
            : canceledIndependent
            ? deleted.ArmStatusCanceledPurgeIndependent(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase)deletedPhase)
            : canceled
            ? deleted.ArmStatusCanceledPurge(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase)deletedPhase)
            : failed
            ? deleted.ArmStatusFailedPurge(deletedBinding, before.PurgeDeletedVault!.Baseline, (ManagementOperationResourceCollector.StatusFailedPurgeReadPhase)deletedPhase)
            : cancellation
            ? deleted.ArmStatusPendingPurgeCancellation(deletedBinding, before.PurgeDeletedVault!.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase)deletedPhase)
            : independent
            ? deleted.ArmStatusPendingPurgeIndependent(deletedBinding, before.PurgeDeletedVault.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase)deletedPhase)
            : deleted.ArmStatusPendingPurge(deletedBinding, before.PurgeDeletedVault.Baseline,
                (ManagementOperationResourceCollector.StatusPendingPurgeReadPhase)deletedPhase);
        var activeTask = active.CollectAsync(activeWindow, activeBinding, token).AsTask();
        using var activeValue = await activeTask.ConfigureAwait(false);
        if ((canceledCancellation || canceledIndependent || canceled) && before.Closing && activeValue.HttpStatus == 200) journal.RecordPresence(plan.Owner, plan.Selector, plan.VaultId);
        CheckPendingLifetime(plan);
        var deletedTask = deleted.CollectAsync(deletedWindow, deletedBinding, token).AsTask();
        using var deletedValue = await deletedTask.ConfigureAwait(false);
        if ((canceledCancellation || canceledIndependent || canceled) && before.Closing && deletedValue.HttpStatus == 200) journal.RecordPresence(plan.Owner, plan.Selector, plan.DeletedId);
        if (!canceledCancellation && !canceledIndependent && !canceled && final && (activeValue.HttpStatus == 200 || deletedValue.HttpStatus == 200))
            journal.RecordPresence(plan.Owner, plan.Selector, activeValue.HttpStatus == 200 ? plan.VaultId : plan.DeletedId);
        CheckPendingLifetime(plan);
        object? activeProof = null, deletedProof = null;
        bool valid;
        if (denied)
        {
            ManagementOperationResourceCollector.StatusDeniedPurgeReadProof? a = null, d = null;
            valid = active.TryGetStatusDeniedPurgeRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusDeniedPurgeRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusDeniedPurgeReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusDeniedPurgeRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusDeniedPurgeRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (failedCancellation)
        {
            ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadProof? a = null, d = null;
            valid = active.TryGetStatusFailedPurgeCancellationRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusFailedPurgeCancellationRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusFailedPurgeCancellationReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusFailedPurgeCancellationRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeCancellationRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (failedIndependent)
        {
            ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadProof? a = null, d = null;
            valid = active.TryGetStatusFailedPurgeIndependentRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusFailedPurgeIndependentRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusFailedPurgeIndependentReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusFailedPurgeIndependentRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeIndependentRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (canceledCancellation)
        {
            ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadProof? a = null, d = null;
            valid = active.TryGetStatusCanceledPurgeCancellationRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusCanceledPurgeCancellationRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusCanceledPurgeCancellationReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusCanceledPurgeCancellationRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeCancellationRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (canceledIndependent)
        {
            ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadProof? a = null, d = null;
            valid = active.TryGetStatusCanceledPurgeIndependentRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusCanceledPurgeIndependentRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusCanceledPurgeIndependentReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusCanceledPurgeIndependentRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeIndependentRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (canceled)
        {
            ManagementOperationResourceCollector.StatusCanceledPurgeReadProof? a = null, d = null;
            valid = active.TryGetStatusCanceledPurgeRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusCanceledPurgeRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusCanceledPurgeReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusCanceledPurgeRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusCanceledPurgeRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (failed)
        {
            ManagementOperationResourceCollector.StatusFailedPurgeReadProof? a = null, d = null;
            valid = active.TryGetStatusFailedPurgeRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusFailedPurgeReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusFailedPurgeRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusFailedPurgeReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusFailedPurgeRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusFailedPurgeRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (cancellation)
        {
            ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadProof? a = null, d = null;
            valid = active.TryGetStatusPendingPurgeCancellationRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusPendingPurgeCancellationRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusPendingPurgeCancellationReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusPendingPurgeCancellationRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeCancellationRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else if (independent)
        {
            ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadProof? a = null, d = null;
            valid = active.TryGetStatusPendingPurgeIndependentRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusPendingPurgeIndependentRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusPendingPurgeIndependentReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusPendingPurgeIndependentRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeIndependentRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        else
        {
            ManagementOperationResourceCollector.StatusPendingPurgeReadProof? a = null, d = null;
            valid = active.TryGetStatusPendingPurgeRead(activeWindow, activeBinding,
                (ManagementOperationResourceCollector.StatusPendingPurgeReadPhase)activePhase, activeTask, out a) &&
                deleted.TryGetStatusPendingPurgeRead(deletedWindow, deletedBinding,
                    (ManagementOperationResourceCollector.StatusPendingPurgeReadPhase)deletedPhase, deletedTask, out d) &&
                active.OwnsStatusPendingPurgeRead(a!, activeWindow, activeBinding, a!.Phase, activeTask) &&
                deleted.OwnsStatusPendingPurgeRead(d!, deletedWindow, deletedBinding, d!.Phase, deletedTask) &&
                d.StartedAt >= a.FinishedAt && (final || d.OriginalVaultId == plan.VaultId);
            activeProof = a; deletedProof = d;
        }
        valid &= !token.IsCancellationRequested && !caller.IsCancellationRequested;
        // The positive candidate is built from the read epoch's frozen image;
        // publication checks it atomically, without a post-I/O journal rebase.
        if (!valid) return false;
        if (!final)
        {
            pendingReadyReads[plan] = new PendingFixtureFacts(plan, before, before, [token, caller],
                [activeTask, deletedTask], Proofs:
                [active, activeBinding, activeWindow, activeProof!, deleted, deletedBinding, deletedWindow, deletedProof!])
                { Started = epoch, Profile = pendingIndependentProfile, CancellationProfile = pendingCancellationProfile, CanceledCancellationProfile = canceledCancellationProfile, CanceledIndependentProfile = canceledIndependentProfile, CanceledProfile = canceledProfile, DeniedProfile = deniedProfile, FailedProfile = failedProfile, FailedIndependentProfile = failedIndependentProfile, FailedCancellationProfile = failedCancellationProfile };
            Require(RoleFixtureJournal.SameStatusPendingPurgeSnapshot(before, ReadPlan(plan.Owner, plan.Selector)));
            return true;
        }
        if (before.Released)
        {
            Require(RoleFixtureJournal.SameStatusPendingPurgeSnapshot(before, ReadPlan(plan.Owner, plan.Selector)));
            return true;
        }
        CheckPendingLifetime(plan);
        var after = before with { Revision = before.Revision + 1,
            Resources = before.Resources.Select(r => r with { Absent = true }).ToArray() };
        // The retained tasks and closed immutable image are authority; returned
        // measurements and caller flags cannot publish any part of this tuple.
        var candidate = RegisterPendingFixture(new PendingFixtureFacts(plan, before, after, [token, caller], [activeTask, deletedTask],
            Proofs: [active, activeBinding, activeWindow, activeProof!, deleted, deletedBinding, deletedWindow, deletedProof!])
            { Started = epoch }, PendingFixturePublication.Absence);
        pendingPersistence[plan] = candidate;
        RetryPendingFixturePersistence(plan);
        CheckPendingLifetime(plan);
        pendingPersistence.TryRemove(plan, out _);
        return true;
    }

    private ManagementOperationResourceCollector.Limits PendingResourceLimits() =>
        new(Math.Min(limits.MaximumResponseBytes, 1024 * 1024), Math.Min(limits.MaximumResponseBytes, 1024 * 1024),
            4096, 32, 32, limits.Timeout);

    internal async ValueTask<Result> ReleaseStatusFailedPurgeCancellationAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusFailedPurgeCancellationCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(failedCancellationProfile is not null && StatusFailedPurgeCancellationSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan)) RetryPendingFixturePersistence(plan);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            if (snapshot.PurgeDeletedVault is { FailedStage: RoleFixtureJournal.StatusFailedPurgeStage.CleanupTerminal })
            {
                Require(failedCancellationCleanup.TryGetValue(plan, out var completed) &&
                    ReferenceEquals(completed.Authorization, authorization));
                return await ReleasePendingPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
            }
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (failedCancellationCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(failedCancellationCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleasePendingPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal async ValueTask<Result> ReleaseStatusFailedPurgeIndependentAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusFailedPurgeIndependentCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(failedIndependentProfile is not null && StatusFailedPurgeIndependentSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan))
                return Finish(RetryPendingFixturePersistence(plan).Released ? State.Released : State.Closing, plan);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (failedIndependentCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(failedIndependentCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleasePendingPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal async ValueTask<Result> ReleaseStatusCanceledPurgeCancellationAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusCanceledPurgeCancellationCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan))
            {
                var persisted = RetryPendingFixturePersistence(plan);
                return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                    Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
            }
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (canceledCancellationCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(canceledCancellationCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleaseCanceledCancellationPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }
    internal async ValueTask<Result> ReleaseStatusCanceledPurgeIndependentAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusCanceledPurgeIndependentCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan))
            {
                var persisted = RetryPendingFixturePersistence(plan);
                return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                    Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
            }
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (canceledIndependentCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(canceledIndependentCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleaseCanceledIndependentPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal async ValueTask<Result> ReleaseStatusCanceledPurgeAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusCanceledPurgeCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan))
            {
                var persisted = RetryPendingFixturePersistence(plan);
                return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                    Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
            }
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (canceledCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(canceledCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleaseCanceledPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal async ValueTask<Result> ReleaseStatusFailedPurgeAsync(Plan plan,
        ManagementOperationFixtureObserverService.StatusFailedPurgeCleanupAuthorization authorization,
        CancellationToken cancellationToken, CancellationToken originalCallerToken)
    {
        CheckPlan(plan);
        Require(failedProfile is not null && StatusFailedPurgeSelector(plan.Selector) && !plan.Restored && authorization is not null);
        cancellationToken.ThrowIfCancellationRequested();
        originalCallerToken.ThrowIfCancellationRequested();
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            pendingCallers.AddOrUpdate(plan, [cancellationToken, originalCallerToken], (_, old) => [.. old, cancellationToken, originalCallerToken]);
            if (pendingPersistence.ContainsKey(plan))
                return Finish(RetryPendingFixturePersistence(plan).Released ? State.Released : State.Closing, plan);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(authorization.Validate(this, plan, journal, snapshot));
            if (failedCleanup.TryGetValue(plan, out var retained))
                Require(ReferenceEquals(retained.Authorization, authorization) && RoleFixtureJournal.SameStatusPendingPurgeSnapshot(retained.Closed, snapshot));
            else Require(failedCleanup.TryAdd(plan, (authorization, RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot))));
            return await ReleasePendingPurge(plan, cancellationToken, originalCallerToken).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            originalCallerToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    private async Task<Result> ReleaseCanceledCancellationPurge(Plan plan, CancellationToken token, CancellationToken caller)
    {
        CheckPlan(plan);
        Require(canceledCancellationProfile is not null && StatusCanceledPurgeCancellationSelector(plan.Selector) &&
            canceledCancellationPlans.TryGetValue(plan, out var profile) && ReferenceEquals(profile, canceledCancellationProfile));
        pendingCallers.AddOrUpdate(plan, [token, caller], (_, old) => [.. old, token, caller]);
        if (pendingPersistence.ContainsKey(plan))
        {
            var persisted = RetryPendingFixturePersistence(plan);
            return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
        }
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(RoleFixtureJournal.StatusCanceledPurgeCancellationRoot(snapshot) && snapshot.Closing);
        if (!snapshot.Idle) return Finish(State.Pending, plan);
        var stage = snapshot.PurgeDeletedVault!.CanceledStage;
        if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.Prepared)
        {
            bool pristine = snapshot.Resources.All(r => !r.CreateAttempted);
            if (!pristine && !(snapshot.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
                snapshot.Resources[2] is { CreateAttempted: true, InvocationTerminated: true }))
                return Finish(State.Incomplete, plan);
            if (!pristine)
            {
                if (await ReadVault(plan, token).ConfigureAwait(false) is not null) return Finish(State.Incomplete, plan);
                if (await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
                {
                    if (snapshot.Resources[2].DeleteAttempted ||
                        !await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
                    var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                        async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                            .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
                    if (result != State.Ready) return Finish(State.Incomplete, plan);
                }
            }
        }
        else if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.TerminalCanceled)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !canceledCancellationCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (stage != RoleFixtureJournal.StatusCanceledPurgeStage.CleanupTerminal)
            return Finish(State.Incomplete, plan);
        return Finish(await ReadPendingPair(plan, true, token, caller).ConfigureAwait(false) ? State.Released : State.Incomplete, plan);
    }
    private async Task<Result> ReleaseCanceledIndependentPurge(Plan plan, CancellationToken token, CancellationToken caller)
    {
        CheckPlan(plan);
        Require(canceledIndependentProfile is not null && StatusCanceledPurgeIndependentSelector(plan.Selector) &&
            canceledIndependentPlans.TryGetValue(plan, out var profile) && ReferenceEquals(profile, canceledIndependentProfile));
        pendingCallers.AddOrUpdate(plan, [token, caller], (_, old) => [.. old, token, caller]);
        if (pendingPersistence.ContainsKey(plan))
        {
            var persisted = RetryPendingFixturePersistence(plan);
            return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
        }
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(RoleFixtureJournal.StatusCanceledPurgeIndependentRoot(snapshot) && snapshot.Closing);
        if (!snapshot.Idle) return Finish(State.Pending, plan);
        var stage = snapshot.PurgeDeletedVault!.CanceledStage;
        if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.Prepared)
        {
            bool pristine = snapshot.Resources.All(r => !r.CreateAttempted);
            if (!pristine && !(snapshot.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
                snapshot.Resources[2] is { CreateAttempted: true, InvocationTerminated: true }))
                return Finish(State.Incomplete, plan);
            if (!pristine)
            {
                if (await ReadVault(plan, token).ConfigureAwait(false) is not null) return Finish(State.Incomplete, plan);
                if (await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
                {
                    if (snapshot.Resources[2].DeleteAttempted ||
                        !await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
                    var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                        async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                            .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
                    if (result != State.Ready) return Finish(State.Incomplete, plan);
                }
            }
        }
        else if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.TerminalCanceled)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !canceledIndependentCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (stage != RoleFixtureJournal.StatusCanceledPurgeStage.CleanupTerminal)
            return Finish(State.Incomplete, plan);
        return Finish(await ReadPendingPair(plan, true, token, caller).ConfigureAwait(false) ? State.Released : State.Incomplete, plan);
    }

    private async Task<Result> ReleaseCanceledPurge(Plan plan, CancellationToken token, CancellationToken caller)
    {
        CheckPlan(plan);
        Require(canceledProfile is not null && StatusCanceledPurgeSelector(plan.Selector) &&
            canceledPlans.TryGetValue(plan, out var profile) && ReferenceEquals(profile, canceledProfile));
        pendingCallers.AddOrUpdate(plan, [token, caller], (_, old) => [.. old, token, caller]);
        if (pendingPersistence.ContainsKey(plan))
        {
            var persisted = RetryPendingFixturePersistence(plan);
            return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                Receipts = plan.Receipts, CanarySha256 = plan.CanarySha256, CanaryVersion = plan.CanaryVersion };
        }
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(RoleFixtureJournal.StatusCanceledPurgeRoot(snapshot) && snapshot.Closing);
        if (!snapshot.Idle) return Finish(State.Pending, plan);
        var stage = snapshot.PurgeDeletedVault!.CanceledStage;
        if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.Prepared)
        {
            bool pristine = snapshot.Resources.All(r => !r.CreateAttempted);
            if (!pristine && !(snapshot.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
                snapshot.Resources[2] is { CreateAttempted: true, InvocationTerminated: true }))
                return Finish(State.Incomplete, plan);
            if (!pristine)
            {
                if (await ReadVault(plan, token).ConfigureAwait(false) is not null) return Finish(State.Incomplete, plan);
                if (await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
                {
                    if (snapshot.Resources[2].DeleteAttempted ||
                        !await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
                    var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                        async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                            .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
                    if (result != State.Ready) return Finish(State.Incomplete, plan);
                }
            }
        }
        else if (stage == RoleFixtureJournal.StatusCanceledPurgeStage.TerminalCanceled)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !canceledCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (stage != RoleFixtureJournal.StatusCanceledPurgeStage.CleanupTerminal)
            return Finish(State.Incomplete, plan);
        return Finish(await ReadPendingPair(plan, true, token, caller).ConfigureAwait(false) ? State.Released : State.Incomplete, plan);
    }

    private async Task<Result> ReleaseDeniedPurge(Plan plan, CancellationToken token, CancellationToken caller)
    {
        _ = IndependentPending(plan);
        pendingCallers.AddOrUpdate(plan, [caller], (_, old) => [.. old, caller]);
        if (pendingPersistence.ContainsKey(plan))
        {
            var persisted = RetryPendingFixturePersistence(plan);
            if (persisted.Released && !pendingPersistence.ContainsKey(plan)) return Finish(State.Released, plan);
        }
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(RoleFixtureJournal.StatusDeniedPurgeRoot(snapshot) && snapshot.Closing);
        if (!snapshot.Idle) return Finish(State.Incomplete, plan);
        if (snapshot.PurgeDeletedVault!.DeniedStage == RoleFixtureJournal.StatusDeniedPurgeStage.Prepared)
        {
            bool pristine = snapshot.Resources.All(r => !r.CreateAttempted);
            if (!pristine)
            {
                if (!(snapshot.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
                    snapshot.Resources[2] is { CreateAttempted: true, InvocationTerminated: true }))
                    return Finish(State.Incomplete, plan);
                if (!snapshot.Resources[2].DeleteAttempted)
                {
                    if (plan.Restored || !await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false))
                        return Finish(State.Incomplete, plan);
                    var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                        async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                            .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false),
                        token, fixtureCallerCancellation: caller).ConfigureAwait(false);
                    if (result != State.Ready) return Finish(State.Incomplete, plan);
                }
            }
        }
        else if (snapshot.PurgeDeletedVault.DeniedStage != RoleFixtureJournal.StatusDeniedPurgeStage.DeniedObserved ||
            snapshot.PurgeDeletedVault.Disposition != RoleFixtureJournal.PurgeDeletedVaultDisposition.Purged)
            return Finish(State.Incomplete, plan);
        return Finish(await ReadPendingPair(plan, true, token, caller).ConfigureAwait(false) &&
            !pendingPersistence.ContainsKey(plan) ? State.Released : State.Incomplete, plan);
    }

    private async Task<Result> ReleasePendingPurge(Plan plan, CancellationToken token, CancellationToken caller)
    {
        if (StatusDeniedPurgeSelector(plan.Selector)) return await ReleaseDeniedPurge(plan, token, caller).ConfigureAwait(false);
        if (StatusCanceledPurgeCancellationSelector(plan.Selector)) return await ReleaseCanceledCancellationPurge(plan, token, caller).ConfigureAwait(false);
        if (StatusCanceledPurgeIndependentSelector(plan.Selector)) return await ReleaseCanceledIndependentPurge(plan, token, caller).ConfigureAwait(false);
        if (StatusCanceledPurgeSelector(plan.Selector)) return await ReleaseCanceledPurge(plan, token, caller).ConfigureAwait(false);
        _ = IndependentPending(plan);
        pendingCallers.AddOrUpdate(plan, [caller], (_, old) => [.. old, caller]);
        if (pendingPersistence.ContainsKey(plan))
            return Finish(RetryPendingFixturePersistence(plan).Released ? State.Released : State.Closing, plan);
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(PendingRoot(snapshot) && snapshot.Closing);
        if (!snapshot.Idle) return Finish(State.Pending, plan);
        var stage = StatusFailedPurgeSelector(plan.Selector) || StatusFailedPurgeIndependentSelector(plan.Selector) || StatusFailedPurgeCancellationSelector(plan.Selector)
            ? (RoleFixtureJournal.StatusPendingPurgeStage)(int)snapshot.PurgeDeletedVault!.FailedStage
            : snapshot.PurgeDeletedVault!.PendingStage;
        if (stage == RoleFixtureJournal.StatusPendingPurgeStage.Prepared)
        {
            bool pristine = snapshot.Resources.All(r => !r.CreateAttempted);
            if (!pristine && !(snapshot.Resources[0] is { CreateAttempted: true, InvocationTerminated: true } &&
                snapshot.Resources[2] is { CreateAttempted: true, InvocationTerminated: true }))
                return Finish(State.Incomplete, plan);
            if (!pristine)
            {
                // Inspect the original owned coordinates; never repair active-only
                // setup or create a replacement operation after reconstruction.
                if (await ReadVault(plan, token).ConfigureAwait(false) is not null)
                    return Finish(State.Incomplete, plan);
                if (await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
                {
                    if (snapshot.Resources[2].DeleteAttempted ||
                        !await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false))
                        return Finish(State.Incomplete, plan);
                    var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                        async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                            .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false),
                        token, fixtureCallerCancellation: caller).ConfigureAwait(false);
                    if (result != State.Ready) return Finish(State.Incomplete, plan);
                }
            }
        }
        else if (StatusFailedPurgeCancellationSelector(plan.Selector) && snapshot.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.TerminalFailed)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !failedCancellationCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (StatusFailedPurgeIndependentSelector(plan.Selector) && snapshot.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.TerminalFailed)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !failedIndependentCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (StatusFailedPurgeSelector(plan.Selector) && snapshot.PurgeDeletedVault!.FailedStage == RoleFixtureJournal.StatusFailedPurgeStage.TerminalFailed)
        {
            if (plan.Restored || snapshot.Resources[2].DeleteAttempted ||
                !failedCleanup.TryGetValue(plan, out var authorization) ||
                !authorization.Authorization.Validate(this, plan, journal, snapshot)) return Finish(State.Incomplete, plan);
            CheckPendingLifetime(plan);
            if (!await ReadPendingPair(plan, false, token, caller).ConfigureAwait(false)) return Finish(State.Incomplete, plan);
            var result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token, fixtureCallerCancellation: caller).ConfigureAwait(false);
            if (result != State.Ready) return Finish(State.Incomplete, plan);
        }
        else if (stage != RoleFixtureJournal.StatusPendingPurgeStage.CleanupTerminal)
            return Finish(State.Incomplete, plan);
        return Finish(await ReadPendingPair(plan, true, token, caller).ConfigureAwait(false)
            ? State.Released : State.Incomplete, plan);
    }

    private bool statusPrivateUpdateIndependentProfile;
    private enum PrivateUpdateIndependentFixtureStage { Admission, Drain, Absence }
    private sealed record PrivateUpdateIndependentFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        PrivateUpdateIndependentFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[PrivateUpdateIndependentFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, PrivateUpdateIndependentFixtureFacts>
        privateUpdateIndependentFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusPrivateConnectionUpdateIndependentFixtureDrain> privateUpdateIndependentPending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> privateUpdateIndependentRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentAbsence>
        privateUpdateIndependentAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusPrivateConnectionUpdateIndependentAbsence(Plan plan,
        PrivateEndpointFixtureProvisioner.StatusPrivateConnectionUpdateIndependentAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        privateUpdateIndependentAbsences[plan] = absence;
    }

    internal sealed class StatusPrivateConnectionUpdateIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependentFixture(this, journal, state, PrivateUpdateIndependentFixtureStage.Admission);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentFixtureAdmission]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependentFixture(this, journal, state, PrivateUpdateIndependentFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependentFixture(this, journal, state, PrivateUpdateIndependentFixtureStage.Drain, true);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentFixtureDrain]";
    }
    internal sealed class StatusPrivateConnectionUpdateIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.privateUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependentFixture(this, journal, state, PrivateUpdateIndependentFixtureStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidatePrivateUpdateIndependentFixture(this, journal, state, PrivateUpdateIndependentFixtureStage.Absence, true);
        public override string ToString() => "[StatusPrivateConnectionUpdateIndependentAbsence]";
    }
    private bool ValidatePrivateUpdateIndependentFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, PrivateUpdateIndependentFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && privateUpdateIndependentFixtureFacts.TryGetValue(capability, out var f) &&
        !privateUpdateIndependentRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (!(stage == PrivateUpdateIndependentFixtureStage.Admission && f.Delete || stage == PrivateUpdateIndependentFixtureStage.Absence) ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, postimage ? f.Preimage : state, f.Plan)) &&
        RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezePrivateUpdateIndependentFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray(),
            PrivateEndpoint = state.PrivateEndpoint! with { Declaration = state.PrivateEndpoint.Declaration with { },
                Connection = state.PrivateEndpoint.Connection is null ? null : state.PrivateEndpoint.Connection with { } } };

    private void RevokePrivateUpdateIndependentFixture(FixtureSelector selector)
    {
        privateUpdateIndependentRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in privateUpdateIndependentFixtureFacts)
            if (pair.Value.Plan.Selector == selector) privateUpdateIndependentFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginPrivateUpdateIndependentFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezePrivateUpdateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!privateUpdateIndependentRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(preimage));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r.Borrowed ? r : r with { Absent = false }).ToArray(),
            PrivateEndpoint = preimage.PrivateEndpoint! with { NicAbsent = false,
                Connection = preimage.PrivateEndpoint.Connection is null ? null : preimage.PrivateEndpoint.Connection with { Absent = false } }
        };
        var capability = new StatusPrivateConnectionUpdateIndependentFixtureAdmission(this);
        privateUpdateIndependentAbsences.TryGetValue(plan, out var childAbsence);
        Require(privateUpdateIndependentFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, PrivateUpdateIndependentFixtureStage.Admission, [.. privateUpdateIndependentTokens.GetValueOrDefault(plan, []), token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusPrivateConnectionUpdateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(postimage, committed));
            return FreezePrivateUpdateIndependentFixture(committed);
        }
        finally { privateUpdateIndependentFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistPrivateUpdateIndependentFixture(StatusPrivateConnectionUpdateIndependentFixtureDrain drain)
    {
        Require(privateUpdateIndependentFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusPrivateConnectionUpdateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(f.Postimage, committed));
            lock (plans)
                foreach (var receipt in privateUpdateIndependentPending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    privateUpdateIndependentPending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokePrivateUpdateIndependentFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainPrivateUpdateIndependentFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezePrivateUpdateIndependentFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusPrivateConnectionUpdateIndependentFixtureDrain(this);
        Require(privateUpdateIndependentFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, PrivateUpdateIndependentFixtureStage.Drain, [.. privateUpdateIndependentTokens.GetValueOrDefault(plan, []), token, caller], tasks.ToArray())));
        lock (plans) privateUpdateIndependentPending.Add(receipt, drain);
        PersistPrivateUpdateIndependentFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusPrivateConnectionUpdateIndependentConfiguration(HostScope expected,
        ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && baseline.Policies.Length == 0);
            statusPrivateUpdateIndependentProfile = true;
            return CopyConfiguration(baseline);
        }
    }

    private sealed record PrivateUpdateIndependentParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status)
    {
        public override string ToString() => "[PrivateUpdateIndependentParentRead]";
    }
    private readonly Dictionary<Plan, (PrivateUpdateIndependentParentRead? Active, PrivateUpdateIndependentParentRead? Deleted)>
        privateUpdateIndependentParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadPrivateUpdateIndependentArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        Require(PrivateUpdateIndependentLive(plan));
        var preimage = FreezePrivateUpdateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(PrivateUpdateIndependentReadAllowed(plan, preimage) && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new PrivateUpdateIndependentParentRead(preimage, task, id, result is null ? 404 : 200);
            var old = privateUpdateIndependentParentReads.GetValueOrDefault(plan);
            privateUpdateIndependentParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordPrivateUpdateIndependentParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        PrivateUpdateIndependentParentRead active, deleted;
        lock (plans)
        {
            Require(privateUpdateIndependentParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && preimage.PrivateEndpointAbsent);
        var postimage = preimage with
        {
            Revision = preimage.Revision + (preimage.Resources.All(r => r.Borrowed || r.Absent) ? 0 : 1),
            Resources = preimage.Resources.Select(r => r.Borrowed ? r : r with { Absent = true }).ToArray()
        };
        Require(privateUpdateIndependentAbsences.TryGetValue(plan, out var childAbsence) &&
            childAbsence.ValidateParentDependency(journal, preimage, plan));
        var absence = new StatusPrivateConnectionUpdateIndependentAbsence(this);
        Require(privateUpdateIndependentFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, PrivateUpdateIndependentFixtureStage.Absence, [.. privateUpdateIndependentTokens.GetValueOrDefault(plan, []), token, caller], [active.Task, deleted.Task], childAbsence)));
        privateUpdateIndependentPendingAbsence[plan] = absence;
        return PersistPrivateUpdateIndependentAbsence(plan, absence);
    }

    private RoleFixtureJournal.Snapshot PersistPrivateUpdateIndependentAbsence(Plan plan, StatusPrivateConnectionUpdateIndependentAbsence absence)
    {
        Require(privateUpdateIndependentFixtureFacts.TryGetValue(absence, out var facts));
        try
        {
            var committed = journal.RecordStatusPrivateConnectionUpdateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(facts.Postimage, committed));
            privateUpdateIndependentPendingAbsence.TryRemove(plan, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokePrivateUpdateIndependentFixture(plan.Selector); throw; }
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, RoleFixtureJournal.Snapshot> privateUpdateIndependentSetup = new(ReferenceEqualityComparer.Instance);
    private bool PrivateUpdateIndependentReadAllowed(Plan plan, RoleFixtureJournal.Snapshot state) => state.Idle ||
        plan.Receipts.Count == 0 && privateUpdateIndependentSetup.TryGetValue(plan, out var admitted) &&
        RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(admitted, state);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> privateUpdateIndependentTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusPrivateConnectionUpdateIndependentAbsence> privateUpdateIndependentPendingAbsence = new(ReferenceEqualityComparer.Instance);
    private void TrackPrivateUpdateIndependentCaller(Plan plan, CancellationToken token, CancellationToken caller)
    {
        if (!StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)) return;
        var previous = privateUpdateIndependentTokens.GetValueOrDefault(plan, []);
        Require(previous.All(t => !t.IsCancellationRequested) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        privateUpdateIndependentTokens[plan] = [.. previous, token, caller];
    }
    private bool PrivateUpdateIndependentLive(Plan plan) => !privateUpdateIndependentRevoked.ContainsKey(plan.Selector.Nonce) &&
        privateUpdateIndependentTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested);

    private enum UnknownNotificationUpdateCancellationFixtureStage { Admission, Drain, Absence }
    private sealed record UnknownNotificationUpdateCancellationFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        UnknownNotificationUpdateCancellationFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[UnknownNotificationUpdateCancellationFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, UnknownNotificationUpdateCancellationFixtureFacts>
        unknownNotificationUpdateCancellationFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusUnknownNotificationUpdateCancellationFixtureDrain> unknownNotificationUpdateCancellationPending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> unknownNotificationUpdateCancellationRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationAbsence>
        unknownNotificationUpdateCancellationAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusUnknownNotificationUpdateCancellationAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        unknownNotificationUpdateCancellationAbsences[plan] = absence;
    }

    internal sealed class StatusUnknownNotificationUpdateCancellationFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateCancellationFixture(this, journal, state, UnknownNotificationUpdateCancellationFixtureStage.Admission);
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationFixtureAdmission]";
    }
    internal sealed class StatusUnknownNotificationUpdateCancellationFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateCancellationFixture(this, journal, state, UnknownNotificationUpdateCancellationFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateCancellationFixture(this, journal, state, UnknownNotificationUpdateCancellationFixtureStage.Drain, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationFixtureDrain]";
    }
    internal sealed class StatusUnknownNotificationUpdateCancellationAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateCancellationFixture(this, journal, state, UnknownNotificationUpdateCancellationFixtureStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateCancellationFixture(this, journal, state, UnknownNotificationUpdateCancellationFixtureStage.Absence, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateCancellationAbsence]";
    }
    private bool ValidateUnknownNotificationUpdateCancellationFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, UnknownNotificationUpdateCancellationFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(capability, out var f) &&
        !unknownNotificationUpdateCancellationRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) &&
        unknownNotificationUpdateCancellationTokens.GetValueOrDefault(f.Plan, []).All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (stage != UnknownNotificationUpdateCancellationFixtureStage.Admission || !f.Delete ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeUnknownNotificationUpdateCancellationFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeUnknownNotificationUpdateCancellationFixture(FixtureSelector selector)
    {
        unknownNotificationUpdateCancellationRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in unknownNotificationUpdateCancellationFixtureFacts)
            if (pair.Value.Plan.Selector == selector) unknownNotificationUpdateCancellationFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginUnknownNotificationUpdateCancellationFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeUnknownNotificationUpdateCancellationFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!unknownNotificationUpdateCancellationRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusUnknownNotificationUpdateCancellationRoot(preimage) &&
            unknownNotificationUpdateCancellationTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusUnknownNotificationUpdateCancellationFixtureAdmission(this);
        unknownNotificationUpdateCancellationAbsences.TryGetValue(plan, out var childAbsence);
        Require(unknownNotificationUpdateCancellationFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, UnknownNotificationUpdateCancellationFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusUnknownNotificationUpdateCancellationFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(postimage, committed));
            return FreezeUnknownNotificationUpdateCancellationFixture(committed);
        }
        finally { unknownNotificationUpdateCancellationFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateCancellationFixture(StatusUnknownNotificationUpdateCancellationFixtureDrain drain)
    {
        Require(unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusUnknownNotificationUpdateCancellationFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in unknownNotificationUpdateCancellationPending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    unknownNotificationUpdateCancellationPending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeUnknownNotificationUpdateCancellationFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainUnknownNotificationUpdateCancellationFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeUnknownNotificationUpdateCancellationFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusUnknownNotificationUpdateCancellationFixtureDrain(this);
        Require(unknownNotificationUpdateCancellationFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, UnknownNotificationUpdateCancellationFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) unknownNotificationUpdateCancellationPending.Add(receipt, drain);
        PersistUnknownNotificationUpdateCancellationFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusUnknownNotificationUpdateCancellationConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record UnknownNotificationUpdateCancellationParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status, CancellationToken Token)
    {
        public override string ToString() => "[UnknownNotificationUpdateCancellationParentRead]";
    }
    private readonly Dictionary<Plan, (UnknownNotificationUpdateCancellationParentRead? Active, UnknownNotificationUpdateCancellationParentRead? Deleted)>
        unknownNotificationUpdateCancellationParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadUnknownNotificationUpdateCancellationArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeUnknownNotificationUpdateCancellationFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        catch
        {
            if (boundary.ObservedStatus == 200 && preimage.Closing) journal.RecordPresence(plan.Owner, plan.Selector, id);
            throw;
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new UnknownNotificationUpdateCancellationParentRead(preimage, task, id, result is null ? 404 : 200, token);
            var old = unknownNotificationUpdateCancellationParentReads.GetValueOrDefault(plan);
            unknownNotificationUpdateCancellationParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordUnknownNotificationUpdateCancellationParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        UnknownNotificationUpdateCancellationParentRead active, deleted;
        lock (plans)
        {
            Require(unknownNotificationUpdateCancellationParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            !active.Token.IsCancellationRequested && !deleted.Token.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage.Resources.All(r => r.Absent) ? preimage : preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        var absence = new StatusUnknownNotificationUpdateCancellationAbsence(this);
        Require(unknownNotificationUpdateCancellationFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, UnknownNotificationUpdateCancellationFixtureStage.Absence, [token, caller, active.Token, deleted.Token], [active.Task, deleted.Task])));
        Require(unknownNotificationUpdateCancellationPendingAbsence.TryAdd(plan, absence));
        return PersistUnknownNotificationUpdateCancellationAbsence(plan, absence);
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> unknownNotificationUpdateCancellationTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusUnknownNotificationUpdateCancellationAbsence>
        unknownNotificationUpdateCancellationPendingAbsence = new(ReferenceEqualityComparer.Instance);

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateCancellationAbsence(Plan plan, StatusUnknownNotificationUpdateCancellationAbsence absence)
    {
        try
        {
            var committed = journal.RecordStatusUnknownNotificationUpdateCancellationAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(unknownNotificationUpdateCancellationFixtureFacts.TryGetValue(absence, out var facts) &&
                RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(facts.Postimage, committed));
            unknownNotificationUpdateCancellationPendingAbsence.TryRemove(plan, out _);
            unknownNotificationUpdateCancellationFixtureFacts.TryRemove(absence, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokeUnknownNotificationUpdateCancellationFixture(plan.Selector); throw; }
    }

    private enum UnknownNotificationUpdateIndependentFixtureStage { Admission, Drain, Absence }
    private sealed record UnknownNotificationUpdateIndependentFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        UnknownNotificationUpdateIndependentFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[UnknownNotificationUpdateIndependentFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, UnknownNotificationUpdateIndependentFixtureFacts>
        unknownNotificationUpdateIndependentFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusUnknownNotificationUpdateIndependentFixtureDrain> unknownNotificationUpdateIndependentPending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> unknownNotificationUpdateIndependentRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentAbsence>
        unknownNotificationUpdateIndependentAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusUnknownNotificationUpdateIndependentAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        unknownNotificationUpdateIndependentAbsences[plan] = absence;
    }

    internal sealed class StatusUnknownNotificationUpdateIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateIndependentFixture(this, journal, state, UnknownNotificationUpdateIndependentFixtureStage.Admission);
        public override string ToString() => "[StatusUnknownNotificationUpdateIndependentFixtureAdmission]";
    }
    internal sealed class StatusUnknownNotificationUpdateIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateIndependentFixture(this, journal, state, UnknownNotificationUpdateIndependentFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateIndependentFixture(this, journal, state, UnknownNotificationUpdateIndependentFixtureStage.Drain, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateIndependentFixtureDrain]";
    }
    internal sealed class StatusUnknownNotificationUpdateIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateIndependentFixture(this, journal, state, UnknownNotificationUpdateIndependentFixtureStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateIndependentFixture(this, journal, state, UnknownNotificationUpdateIndependentFixtureStage.Absence, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateIndependentAbsence]";
    }
    private bool ValidateUnknownNotificationUpdateIndependentFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, UnknownNotificationUpdateIndependentFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(capability, out var f) &&
        !unknownNotificationUpdateIndependentRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) &&
        unknownNotificationUpdateIndependentTokens.GetValueOrDefault(f.Plan, []).All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (stage != UnknownNotificationUpdateIndependentFixtureStage.Admission || !f.Delete ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeUnknownNotificationUpdateIndependentFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeUnknownNotificationUpdateIndependentFixture(FixtureSelector selector)
    {
        unknownNotificationUpdateIndependentRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in unknownNotificationUpdateIndependentFixtureFacts)
            if (pair.Value.Plan.Selector == selector) unknownNotificationUpdateIndependentFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginUnknownNotificationUpdateIndependentFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeUnknownNotificationUpdateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!unknownNotificationUpdateIndependentRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusUnknownNotificationUpdateIndependentRoot(preimage) &&
            unknownNotificationUpdateIndependentTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusUnknownNotificationUpdateIndependentFixtureAdmission(this);
        unknownNotificationUpdateIndependentAbsences.TryGetValue(plan, out var childAbsence);
        Require(unknownNotificationUpdateIndependentFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, UnknownNotificationUpdateIndependentFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusUnknownNotificationUpdateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(postimage, committed));
            return FreezeUnknownNotificationUpdateIndependentFixture(committed);
        }
        finally { unknownNotificationUpdateIndependentFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateIndependentFixture(StatusUnknownNotificationUpdateIndependentFixtureDrain drain)
    {
        Require(unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusUnknownNotificationUpdateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in unknownNotificationUpdateIndependentPending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    unknownNotificationUpdateIndependentPending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeUnknownNotificationUpdateIndependentFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainUnknownNotificationUpdateIndependentFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeUnknownNotificationUpdateIndependentFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusUnknownNotificationUpdateIndependentFixtureDrain(this);
        Require(unknownNotificationUpdateIndependentFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, UnknownNotificationUpdateIndependentFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) unknownNotificationUpdateIndependentPending.Add(receipt, drain);
        PersistUnknownNotificationUpdateIndependentFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusUnknownNotificationUpdateIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record UnknownNotificationUpdateIndependentParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status, CancellationToken Token)
    {
        public override string ToString() => "[UnknownNotificationUpdateIndependentParentRead]";
    }
    private readonly Dictionary<Plan, (UnknownNotificationUpdateIndependentParentRead? Active, UnknownNotificationUpdateIndependentParentRead? Deleted)>
        unknownNotificationUpdateIndependentParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadUnknownNotificationUpdateIndependentArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeUnknownNotificationUpdateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        catch
        {
            if (boundary.ObservedStatus == 200 && preimage.Closing) journal.RecordPresence(plan.Owner, plan.Selector, id);
            throw;
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new UnknownNotificationUpdateIndependentParentRead(preimage, task, id, result is null ? 404 : 200, token);
            var old = unknownNotificationUpdateIndependentParentReads.GetValueOrDefault(plan);
            unknownNotificationUpdateIndependentParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordUnknownNotificationUpdateIndependentParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        UnknownNotificationUpdateIndependentParentRead active, deleted;
        lock (plans)
        {
            Require(unknownNotificationUpdateIndependentParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            !active.Token.IsCancellationRequested && !deleted.Token.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage.Resources.All(r => r.Absent) ? preimage : preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        var absence = new StatusUnknownNotificationUpdateIndependentAbsence(this);
        Require(unknownNotificationUpdateIndependentFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, UnknownNotificationUpdateIndependentFixtureStage.Absence, [token, caller, active.Token, deleted.Token], [active.Task, deleted.Task])));
        Require(unknownNotificationUpdateIndependentPendingAbsence.TryAdd(plan, absence));
        return PersistUnknownNotificationUpdateIndependentAbsence(plan, absence);
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> unknownNotificationUpdateIndependentTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusUnknownNotificationUpdateIndependentAbsence>
        unknownNotificationUpdateIndependentPendingAbsence = new(ReferenceEqualityComparer.Instance);

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateIndependentAbsence(Plan plan, StatusUnknownNotificationUpdateIndependentAbsence absence)
    {
        try
        {
            var committed = journal.RecordStatusUnknownNotificationUpdateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(unknownNotificationUpdateIndependentFixtureFacts.TryGetValue(absence, out var facts) &&
                RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(facts.Postimage, committed));
            unknownNotificationUpdateIndependentPendingAbsence.TryRemove(plan, out _);
            unknownNotificationUpdateIndependentFixtureFacts.TryRemove(absence, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokeUnknownNotificationUpdateIndependentFixture(plan.Selector); throw; }
    }

    private enum UnknownNotificationUpdateFixtureStage { Admission, Drain, Absence }
    private sealed record UnknownNotificationUpdateFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        UnknownNotificationUpdateFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[UnknownNotificationUpdateFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, UnknownNotificationUpdateFixtureFacts>
        unknownNotificationUpdateFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusUnknownNotificationUpdateFixtureDrain> unknownNotificationUpdatePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> unknownNotificationUpdateRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusUnknownNotificationUpdateAbsence>
        unknownNotificationUpdateAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusUnknownNotificationUpdateAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusUnknownNotificationUpdateAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        unknownNotificationUpdateAbsences[plan] = absence;
    }

    internal sealed class StatusUnknownNotificationUpdateFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Admission);
        public override string ToString() => "[StatusUnknownNotificationUpdateFixtureAdmission]";
    }
    internal sealed class StatusUnknownNotificationUpdateFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Drain, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateFixtureDrain]";
    }
    internal sealed class StatusUnknownNotificationUpdateAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.unknownNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateUnknownNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Absence, true);
        public override string ToString() => "[StatusUnknownNotificationUpdateAbsence]";
    }
    private bool ValidateUnknownNotificationUpdateFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, UnknownNotificationUpdateFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && unknownNotificationUpdateFixtureFacts.TryGetValue(capability, out var f) &&
        !unknownNotificationUpdateRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) &&
        unknownNotificationUpdateTokens.GetValueOrDefault(f.Plan, []).All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (stage != UnknownNotificationUpdateFixtureStage.Admission || !f.Delete ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeUnknownNotificationUpdateFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeUnknownNotificationUpdateFixture(FixtureSelector selector)
    {
        unknownNotificationUpdateRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in unknownNotificationUpdateFixtureFacts)
            if (pair.Value.Plan.Selector == selector) unknownNotificationUpdateFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginUnknownNotificationUpdateFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeUnknownNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!unknownNotificationUpdateRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusUnknownNotificationUpdateRoot(preimage) &&
            unknownNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusUnknownNotificationUpdateFixtureAdmission(this);
        unknownNotificationUpdateAbsences.TryGetValue(plan, out var childAbsence);
        Require(unknownNotificationUpdateFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, UnknownNotificationUpdateFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusUnknownNotificationUpdateFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(postimage, committed));
            return FreezeUnknownNotificationUpdateFixture(committed);
        }
        finally { unknownNotificationUpdateFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateFixture(StatusUnknownNotificationUpdateFixtureDrain drain)
    {
        Require(unknownNotificationUpdateFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusUnknownNotificationUpdateFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in unknownNotificationUpdatePending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    unknownNotificationUpdatePending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeUnknownNotificationUpdateFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainUnknownNotificationUpdateFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeUnknownNotificationUpdateFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusUnknownNotificationUpdateFixtureDrain(this);
        Require(unknownNotificationUpdateFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, UnknownNotificationUpdateFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) unknownNotificationUpdatePending.Add(receipt, drain);
        PersistUnknownNotificationUpdateFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusUnknownNotificationUpdateConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record UnknownNotificationUpdateParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status, CancellationToken Token)
    {
        public override string ToString() => "[UnknownNotificationUpdateParentRead]";
    }
    private readonly Dictionary<Plan, (UnknownNotificationUpdateParentRead? Active, UnknownNotificationUpdateParentRead? Deleted)>
        unknownNotificationUpdateParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadUnknownNotificationUpdateArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeUnknownNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        catch
        {
            if (boundary.ObservedStatus == 200 && preimage.Closing) journal.RecordPresence(plan.Owner, plan.Selector, id);
            throw;
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new UnknownNotificationUpdateParentRead(preimage, task, id, result is null ? 404 : 200, token);
            var old = unknownNotificationUpdateParentReads.GetValueOrDefault(plan);
            unknownNotificationUpdateParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordUnknownNotificationUpdateParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        UnknownNotificationUpdateParentRead active, deleted;
        lock (plans)
        {
            Require(unknownNotificationUpdateParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            !active.Token.IsCancellationRequested && !deleted.Token.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage.Resources.All(r => r.Absent) ? preimage : preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        var absence = new StatusUnknownNotificationUpdateAbsence(this);
        Require(unknownNotificationUpdateFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, UnknownNotificationUpdateFixtureStage.Absence, [token, caller, active.Token, deleted.Token], [active.Task, deleted.Task])));
        Require(unknownNotificationUpdatePendingAbsence.TryAdd(plan, absence));
        return PersistUnknownNotificationUpdateAbsence(plan, absence);
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> unknownNotificationUpdateTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusUnknownNotificationUpdateAbsence>
        unknownNotificationUpdatePendingAbsence = new(ReferenceEqualityComparer.Instance);

    private RoleFixtureJournal.Snapshot PersistUnknownNotificationUpdateAbsence(Plan plan, StatusUnknownNotificationUpdateAbsence absence)
    {
        try
        {
            var committed = journal.RecordStatusUnknownNotificationUpdateAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(unknownNotificationUpdateFixtureFacts.TryGetValue(absence, out var facts) &&
                RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(facts.Postimage, committed));
            unknownNotificationUpdatePendingAbsence.TryRemove(plan, out _);
            unknownNotificationUpdateFixtureFacts.TryRemove(absence, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokeUnknownNotificationUpdateFixture(plan.Selector); throw; }
    }

    private sealed record DeniedNotificationUpdateFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        UnknownNotificationUpdateFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusDeniedNotificationUpdateAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[DeniedNotificationUpdateFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, DeniedNotificationUpdateFixtureFacts>
        deniedNotificationUpdateFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusDeniedNotificationUpdateFixtureDrain> deniedNotificationUpdatePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> deniedNotificationUpdateRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusDeniedNotificationUpdateAbsence>
        deniedNotificationUpdateAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusDeniedNotificationUpdateAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusDeniedNotificationUpdateAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        deniedNotificationUpdateAbsences[plan] = absence;
    }

    internal sealed class StatusDeniedNotificationUpdateFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Admission);
        public override string ToString() => "[StatusDeniedNotificationUpdateFixtureAdmission]";
    }
    internal sealed class StatusDeniedNotificationUpdateFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Drain, true);
        public override string ToString() => "[StatusDeniedNotificationUpdateFixtureDrain]";
    }
    internal sealed class StatusDeniedNotificationUpdateAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.deniedNotificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Absence);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateDeniedNotificationUpdateFixture(this, journal, state, UnknownNotificationUpdateFixtureStage.Absence, true);
        public override string ToString() => "[StatusDeniedNotificationUpdateAbsence]";
    }
    private bool ValidateDeniedNotificationUpdateFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, UnknownNotificationUpdateFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && deniedNotificationUpdateFixtureFacts.TryGetValue(capability, out var f) &&
        MatchesStatusDeniedNotificationOperation(state.Selector) && f.Plan.Selector == state.Selector &&
        !deniedNotificationUpdateRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) &&
        deniedNotificationUpdateTokens.GetValueOrDefault(f.Plan, []).All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (stage != UnknownNotificationUpdateFixtureStage.Admission || !f.Delete ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeDeniedNotificationUpdateFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeDeniedNotificationUpdateFixture(FixtureSelector selector)
    {
        deniedNotificationUpdateRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in deniedNotificationUpdateFixtureFacts)
            if (pair.Value.Plan.Selector == selector) deniedNotificationUpdateFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginDeniedNotificationUpdateFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeDeniedNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!deniedNotificationUpdateRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusDeniedNotificationUpdateRoot(preimage) &&
            deniedNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusDeniedNotificationUpdateFixtureAdmission(this);
        deniedNotificationUpdateAbsences.TryGetValue(plan, out var childAbsence);
        Require(deniedNotificationUpdateFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, UnknownNotificationUpdateFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusDeniedNotificationUpdateFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(postimage, committed));
            return FreezeDeniedNotificationUpdateFixture(committed);
        }
        finally { deniedNotificationUpdateFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistDeniedNotificationUpdateFixture(StatusDeniedNotificationUpdateFixtureDrain drain)
    {
        Require(deniedNotificationUpdateFixtureFacts.TryGetValue(drain, out var f));
        Require(MatchesStatusDeniedNotificationOperation(f.Plan.Selector));
        try
        {
            var committed = journal.EndStatusDeniedNotificationUpdateFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in deniedNotificationUpdatePending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    deniedNotificationUpdatePending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeDeniedNotificationUpdateFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainDeniedNotificationUpdateFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeDeniedNotificationUpdateFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusDeniedNotificationUpdateFixtureDrain(this);
        Require(deniedNotificationUpdateFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, UnknownNotificationUpdateFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) deniedNotificationUpdatePending.Add(receipt, drain);
        PersistDeniedNotificationUpdateFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusDeniedNotificationUpdateConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record DeniedNotificationUpdateParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status, CancellationToken Token)
    {
        public override string ToString() => "[DeniedNotificationUpdateParentRead]";
    }
    private readonly Dictionary<Plan, (DeniedNotificationUpdateParentRead? Active, DeniedNotificationUpdateParentRead? Deleted)>
        deniedNotificationUpdateParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadDeniedNotificationUpdateArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeDeniedNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        catch
        {
            if (boundary.ObservedStatus == 200 && preimage.Closing) journal.RecordPresence(plan.Owner, plan.Selector, id);
            throw;
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new DeniedNotificationUpdateParentRead(preimage, task, id, result is null ? 404 : 200, token);
            var old = deniedNotificationUpdateParentReads.GetValueOrDefault(plan);
            deniedNotificationUpdateParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordDeniedNotificationUpdateParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        DeniedNotificationUpdateParentRead active, deleted;
        lock (plans)
        {
            Require(deniedNotificationUpdateParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            !active.Token.IsCancellationRequested && !deleted.Token.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage.Resources.All(r => r.Absent) ? preimage : preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        var absence = new StatusDeniedNotificationUpdateAbsence(this);
        Require(deniedNotificationUpdateFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, UnknownNotificationUpdateFixtureStage.Absence, [token, caller, active.Token, deleted.Token], [active.Task, deleted.Task])));
        Require(deniedNotificationUpdatePendingAbsence.TryAdd(plan, absence));
        return PersistDeniedNotificationUpdateAbsence(plan, absence);
    }

    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, CancellationToken[]> deniedNotificationUpdateTokens = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, StatusDeniedNotificationUpdateAbsence>
        deniedNotificationUpdatePendingAbsence = new(ReferenceEqualityComparer.Instance);

    private RoleFixtureJournal.Snapshot PersistDeniedNotificationUpdateAbsence(Plan plan, StatusDeniedNotificationUpdateAbsence absence)
    {
        Require(MatchesStatusDeniedNotificationOperation(plan.Selector));
        try
        {
            var committed = journal.RecordStatusDeniedNotificationUpdateAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(deniedNotificationUpdateFixtureFacts.TryGetValue(absence, out var facts) &&
                RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(facts.Postimage, committed));
            deniedNotificationUpdatePendingAbsence.TryRemove(plan, out _);
            deniedNotificationUpdateFixtureFacts.TryRemove(absence, out _);
            return committed;
        }
        catch (IOException) { throw; }
        catch { RevokeDeniedNotificationUpdateFixture(plan.Selector); throw; }
    }


    private enum NotificationUpdateFixtureStage { Admission, Drain, Absence }
    private sealed record NotificationUpdateFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        NotificationUpdateFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[NotificationUpdateFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationUpdateFixtureFacts>
        notificationUpdateFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusNotificationUpdateIndependentFixtureDrain> notificationUpdatePending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> notificationUpdateRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusNotificationUpdateIndependentAbsence>
        notificationUpdateAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusNotificationUpdateIndependentAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusNotificationUpdateIndependentAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        notificationUpdateAbsences[plan] = absence;
    }

    internal sealed class StatusNotificationUpdateIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Admission);
        public override string ToString() => "[StatusNotificationUpdateIndependentFixtureAdmission]";
    }
    internal sealed class StatusNotificationUpdateIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Drain, true);
        public override string ToString() => "[StatusNotificationUpdateIndependentFixtureDrain]";
    }
    internal sealed class StatusNotificationUpdateIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.notificationUpdateFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationUpdateFixture(this, journal, state, NotificationUpdateFixtureStage.Absence);
        public override string ToString() => "[StatusNotificationUpdateIndependentAbsence]";
    }
    private bool ValidateNotificationUpdateFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, NotificationUpdateFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && notificationUpdateFixtureFacts.TryGetValue(capability, out var f) &&
        !notificationUpdateRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (stage != NotificationUpdateFixtureStage.Admission || !f.Delete ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationUpdateFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeNotificationUpdateFixture(FixtureSelector selector)
    {
        notificationUpdateRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in notificationUpdateFixtureFacts)
            if (pair.Value.Plan.Selector == selector) notificationUpdateFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginNotificationUpdateFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!notificationUpdateRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(preimage));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusNotificationUpdateIndependentFixtureAdmission(this);
        notificationUpdateAbsences.TryGetValue(plan, out var childAbsence);
        Require(notificationUpdateFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, NotificationUpdateFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusNotificationUpdateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(postimage, committed));
            return FreezeNotificationUpdateFixture(committed);
        }
        finally { notificationUpdateFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistNotificationUpdateFixture(StatusNotificationUpdateIndependentFixtureDrain drain)
    {
        Require(notificationUpdateFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusNotificationUpdateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            lock (plans)
                foreach (var receipt in notificationUpdatePending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    notificationUpdatePending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeNotificationUpdateFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainNotificationUpdateFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeNotificationUpdateFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusNotificationUpdateIndependentFixtureDrain(this);
        Require(notificationUpdateFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, NotificationUpdateFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) notificationUpdatePending.Add(receipt, drain);
        PersistNotificationUpdateFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusNotificationUpdateIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record NotificationUpdateParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status)
    {
        public override string ToString() => "[NotificationUpdateParentRead]";
    }
    private readonly Dictionary<Plan, (NotificationUpdateParentRead? Active, NotificationUpdateParentRead? Deleted)>
        notificationUpdateParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadNotificationUpdateIndependentArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeNotificationUpdateFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new NotificationUpdateParentRead(preimage, task, id, result is null ? 404 : 200);
            var old = notificationUpdateParentReads.GetValueOrDefault(plan);
            notificationUpdateParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordNotificationUpdateParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        NotificationUpdateParentRead active, deleted;
        lock (plans)
        {
            Require(notificationUpdateParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        var absence = new StatusNotificationUpdateIndependentAbsence(this);
        Require(notificationUpdateFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, NotificationUpdateFixtureStage.Absence, [token, caller], [active.Task, deleted.Task])));
        try { return journal.RecordStatusNotificationUpdateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence); }
        catch (RoleFixtureJournal.StatusNotificationUpdateIndependentHistoryException) { RevokeNotificationUpdateFixture(plan.Selector); throw; }
        finally { notificationUpdateFixtureFacts.TryRemove(absence, out _); }
    }

    private enum NotificationCreateIndependentFixtureStage { Admission, Drain, Absence }
    private sealed record NotificationCreateIndependentFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        RoleFixtureJournal.Snapshot Postimage, string ResourceId, Guid Dispatch, bool Delete, bool Settled, bool Final,
        NotificationCreateIndependentFixtureStage Stage, CancellationToken[] Tokens, Task[] Tasks,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentAbsence? ChildAbsence = null)
    {
        public override string ToString() => "[NotificationCreateIndependentFixtureFacts]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<object, NotificationCreateIndependentFixtureFacts>
        notificationCreateIndependentFixtureFacts = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusNotificationCreateIndependentFixtureDrain> notificationCreateIndependentPending =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Guid, byte> notificationCreateIndependentRevoked = new();
    private readonly System.Collections.Concurrent.ConcurrentDictionary<Plan, NotificationFixtureProvisioner.StatusNotificationCreateIndependentAbsence>
        notificationCreateIndependentAbsences = new(ReferenceEqualityComparer.Instance);

    internal void RetainStatusNotificationCreateIndependentAbsence(Plan plan,
        NotificationFixtureProvisioner.StatusNotificationCreateIndependentAbsence absence, RoleFixtureJournal.Snapshot committed)
    {
        CheckPlan(plan);
        Require(absence.ValidateParentDependency(journal, committed, plan));
        notificationCreateIndependentAbsences[plan] = absence;
    }

    internal sealed class StatusNotificationCreateIndependentFixtureAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Delete => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Delete;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Admission);
        public override string ToString() => "[StatusNotificationCreateIndependentFixtureAdmission]";
    }
    internal sealed class StatusNotificationCreateIndependentFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Drain);
        internal bool AcceptPostimage(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Drain, true);
        public override string ToString() => "[StatusNotificationCreateIndependentFixtureDrain]";
    }
    internal sealed class StatusNotificationCreateIndependentAbsence(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Final => source.notificationCreateIndependentFixtureFacts.TryGetValue(this, out var f) && f.Final;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot state) =>
            source.ValidateNotificationCreateIndependentFixture(this, journal, state, NotificationCreateIndependentFixtureStage.Absence);
        public override string ToString() => "[StatusNotificationCreateIndependentAbsence]";
    }
    private bool ValidateNotificationCreateIndependentFixture(object capability, RoleFixtureJournal candidateJournal,
        RoleFixtureJournal.Snapshot state, NotificationCreateIndependentFixtureStage stage, bool postimage = false) =>
        ReferenceEquals(journal, candidateJournal) && notificationCreateIndependentFixtureFacts.TryGetValue(capability, out var f) &&
        !notificationCreateIndependentRevoked.ContainsKey(f.Plan.Selector.Nonce) && !closed && f.Stage == stage &&
        f.Tokens.All(t => !t.IsCancellationRequested) && f.Tasks.All(t => t.IsCompleted) &&
        (!(stage == NotificationCreateIndependentFixtureStage.Admission && f.Delete || stage == NotificationCreateIndependentFixtureStage.Absence) ||
            f.ChildAbsence is not null && f.ChildAbsence.ValidateParentDependency(candidateJournal, state, f.Plan)) &&
        RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage ? f.Postimage : f.Preimage, state);

    private static RoleFixtureJournal.Snapshot FreezeNotificationCreateIndependentFixture(RoleFixtureJournal.Snapshot state) =>
        state with { Selector = state.Selector with { }, Resources = state.Resources.Select(r => r with { }).ToArray() };

    private void RevokeNotificationCreateIndependentFixture(FixtureSelector selector)
    {
        notificationCreateIndependentRevoked.TryAdd(selector.Nonce, 0);
        foreach (var pair in notificationCreateIndependentFixtureFacts)
            if (pair.Value.Plan.Selector == selector) notificationCreateIndependentFixtureFacts.TryRemove(pair.Key, out _);
    }

    private RoleFixtureJournal.Snapshot BeginNotificationCreateIndependentFixture(Plan plan, string id, bool delete,
        CancellationToken token, CancellationToken caller)
    {
        var preimage = FreezeNotificationCreateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(!notificationCreateIndependentRevoked.ContainsKey(plan.Selector.Nonce) && !token.IsCancellationRequested &&
            !caller.IsCancellationRequested && !closed && RoleFixtureJournal.StatusNotificationCreateIndependentRoot(preimage));
        Guid dispatch = Guid.NewGuid();
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            {
                CreateAttempted = r.CreateAttempted || !delete,
                DeleteAttempted = r.DeleteAttempted || delete,
                InvocationTerminated = false,
                ActiveDispatch = dispatch,
                Absent = false
            } : r with { Absent = false }).ToArray()
        };
        var capability = new StatusNotificationCreateIndependentFixtureAdmission(this);
        notificationCreateIndependentAbsences.TryGetValue(plan, out var childAbsence);
        Require(notificationCreateIndependentFixtureFacts.TryAdd(capability, new(plan, preimage, postimage, id, dispatch,
            delete, false, false, NotificationCreateIndependentFixtureStage.Admission, [token, caller], [], childAbsence)));
        try
        {
            var committed = journal.BeginStatusNotificationCreateIndependentFixtureDispatch(plan.Owner, plan.Selector, plan.LeaseId, capability);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage, committed));
            return FreezeNotificationCreateIndependentFixture(committed);
        }
        finally { notificationCreateIndependentFixtureFacts.TryRemove(capability, out _); }
    }

    private RoleFixtureJournal.Snapshot PersistNotificationCreateIndependentFixture(StatusNotificationCreateIndependentFixtureDrain drain)
    {
        Require(notificationCreateIndependentFixtureFacts.TryGetValue(drain, out var f));
        try
        {
            var committed = journal.EndStatusNotificationCreateIndependentFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(f.Postimage, committed));
            lock (plans)
                foreach (var receipt in notificationCreateIndependentPending.Where(p => ReferenceEquals(p.Value, drain)).Select(p => p.Key).ToArray())
                    notificationCreateIndependentPending.Remove(receipt);
            return committed;
        }
        catch (IOException) { throw; }
        catch
        {
            RevokeNotificationCreateIndependentFixture(f.Plan.Selector);
            // The actual invocation is drained, but invalid or closed history
            // can never become remote settlement authority.
            try { journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false); }
            catch (InvalidOperationException) { }
            catch (IOException) { }
            throw;
        }
    }

    private void RetainNotificationCreateIndependentFixtureDrain(Plan plan, Receipt receipt, RoleFixtureJournal.Snapshot committed,
        string id, Guid dispatch, bool settled, CancellationToken token, CancellationToken caller, params Task[] tasks)
    {
        Require(tasks.Length != 0 && tasks.All(t => t.IsCompleted) && !token.IsCancellationRequested && !caller.IsCancellationRequested);
        var preimage = FreezeNotificationCreateIndependentFixture(committed);
        var postimage = preimage with
        {
            Revision = preimage.Revision + 1,
            Resources = preimage.Resources.Select(r => r.Id == id ? r with
            { InvocationTerminated = true, ActiveDispatch = settled ? Guid.Empty : dispatch } : r).ToArray()
        };
        var drain = new StatusNotificationCreateIndependentFixtureDrain(this);
        Require(notificationCreateIndependentFixtureFacts.TryAdd(drain, new(plan, preimage, postimage, id, dispatch,
            preimage.Closing, settled, false, NotificationCreateIndependentFixtureStage.Drain, [token, caller], tasks.ToArray())));
        lock (plans) notificationCreateIndependentPending.Add(receipt, drain);
        PersistNotificationCreateIndependentFixture(drain);
    }

    internal VaultAdministrationEffects.Configuration StatusNotificationCreateIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
                recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                !statusSucceededDeleteVaultProfile && !statusSucceededDeleteVaultIndependentProfile && !statusSucceededDeleteVaultCancellationProfile &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is { Credential: not null, Transport: not null } &&
                !ReferenceEquals(setupArm.Credential, statusReader.Credential) && !ReferenceEquals(setupArm.Transport, statusReader.Transport) &&
                !ReferenceEquals(setupArm.Credential, resourceReader.Credential) && !ReferenceEquals(setupArm.Transport, resourceReader.Transport) &&
                !ReferenceEquals(setupArm.Transport, selectedBackend) && !ReferenceEquals(readArm.Transport, selectedBackend) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend) && !ReferenceEquals(resourceReader.Transport, selectedBackend) &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId && baseline.Rbac &&
                !baseline.PurgeProtection && !baseline.PublicNetworkAccess && baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private sealed record NotificationCreateIndependentParentRead(RoleFixtureJournal.Snapshot Preimage, Task Task, string Id, int Status)
    {
        public override string ToString() => "[NotificationCreateIndependentParentRead]";
    }
    private readonly Dictionary<Plan, (NotificationCreateIndependentParentRead? Active, NotificationCreateIndependentParentRead? Deleted)>
        notificationCreateIndependentParentReads = new(ReferenceEqualityComparer.Instance);

    private async Task<T?> ReadNotificationCreateIndependentArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var preimage = FreezeNotificationCreateIndependentFixture(ReadPlan(plan.Owner, plan.Selector));
        Require(preimage.Idle && (id == plan.VaultId || id == plan.DeletedId));
        using var boundary = new StatusSucceededReadTransport(this, plan, id, preimage);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
            {
                ValidateVaultData(plan, vault.Data, selected: false);
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, Configuration(vault.Data));
            }
            else if (result is DeletedKeyVaultResource deleted)
            {
                DeletedShape(raw.RootElement);
                ValidateDeleted(plan, deleted.Data);
                var properties = raw.RootElement.GetProperty("properties");
                Require(raw.RootElement.GetProperty("id").GetString() == deleted.Data.Id?.ToString() &&
                    properties.GetProperty("vaultId").GetString() == deleted.Data.Properties.VaultId &&
                    properties.GetProperty("location").GetString() == deleted.Data.Properties.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == deleted.Data.Properties.PurgeProtectionEnabled &&
                    properties.GetProperty("deletionDate").GetDateTimeOffset() == deleted.Data.Properties.DeletedOn &&
                    properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() == deleted.Data.Properties.ScheduledPurgeOn);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } && boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false } &&
            RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(preimage, ReadPlan(plan.Owner, plan.Selector)));
        lock (plans)
        {
            var fact = new NotificationCreateIndependentParentRead(preimage, task, id, result is null ? 404 : 200);
            var old = notificationCreateIndependentParentReads.GetValueOrDefault(plan);
            notificationCreateIndependentParentReads[plan] = id == plan.VaultId ? (fact, null) : (old.Active, fact);
        }
        return result;
    }

    private RoleFixtureJournal.Snapshot RecordNotificationCreateIndependentParentAbsence(Plan plan, CancellationToken token, CancellationToken caller)
    {
        NotificationCreateIndependentParentRead active, deleted;
        lock (plans)
        {
            Require(notificationCreateIndependentParentReads.TryGetValue(plan, out var pair) && pair.Active is not null && pair.Deleted is not null);
            active = pair.Active;
            deleted = pair.Deleted;
        }
        var preimage = deleted.Preimage;
        Require(active.Status == 404 && deleted.Status == 404 && active.Task.IsFaulted && deleted.Task.IsFaulted &&
            RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(active.Preimage, preimage) &&
            preimage.Closing && preimage.Idle && NotificationsAbsent(plan, preimage));
        var postimage = preimage with
        {
            Revision = preimage.Revision + (preimage.Resources.All(r => r.Absent) ? 0 : 1),
            Resources = preimage.Resources.Select(r => r with { Absent = true }).ToArray()
        };
        Require(notificationCreateIndependentAbsences.TryGetValue(plan, out var childAbsence) &&
            childAbsence.ValidateParentDependency(journal, preimage, plan));
        var absence = new StatusNotificationCreateIndependentAbsence(this);
        Require(notificationCreateIndependentFixtureFacts.TryAdd(absence, new(plan, preimage, postimage, plan.VaultId, Guid.Empty,
            false, false, true, NotificationCreateIndependentFixtureStage.Absence, [token, caller], [active.Task, deleted.Task], childAbsence)));
        try
        {
            var committed = journal.RecordStatusNotificationCreateIndependentAbsence(plan.Owner, plan.Selector, plan.LeaseId, absence);
            Require(RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(postimage, committed));
            return committed;
        }
        catch (RoleFixtureJournal.StatusNotificationCreateIndependentHistoryException) { RevokeNotificationCreateIndependentFixture(plan.Selector); throw; }
        finally { notificationCreateIndependentFixtureFacts.TryRemove(absence, out _); }
    }

    private readonly RoleFixtureJournal journal;
    private readonly HostScope host;
    private VaultAdministrationEffects.Configuration? baselineConfiguration;
    private VaultAdministrationEffects.Configuration baseline => baselineConfiguration ?? throw Failure();
    private readonly Authority setupArm, readArm;
    private readonly Authority? secretSetup, secretRead;
    private Authority setupSecret => secretSetup ?? throw Failure();
    private Authority readSecret => secretRead ?? throw Failure();
    private readonly Limits limits;
    private readonly TimeProvider time;
    private readonly object source = new();
    private readonly Dictionary<Guid, Plan> plans = [];
    private readonly HashSet<Plan> prepared = [];
    private readonly HashSet<Plan> originalReady = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, VaultReadLoan> vaultReads = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, SettingsLoan> settingsLoans = new(ReferenceEqualityComparer.Instance);
    private bool settingsProfile;
    private bool deleteVaultProfile;
    private bool statusSucceededDeleteVaultProfile;
    private bool statusSucceededDeleteVaultCancellationProfile { get; init; }
    private bool statusSucceededDeleteVaultIndependentProfile { get; init; }
    private sealed record StatusSucceededIndependentDrain(string ResourceId, Guid Dispatch, bool Settled);
    private readonly Dictionary<Receipt, StatusSucceededIndependentDrain> statusSucceededIndependentDrains =
        new(ReferenceEqualityComparer.Instance);
    private sealed record StatusSucceededCleanupRead(Plan Plan, string Id, Task NativeTask, int Status,
        long Revision, long Ordinal);
    private sealed record StatusSucceededCleanupFacts(Plan Plan, string ResourceId, long Revision,
        StatusSucceededCleanupRead Active, StatusSucceededCleanupRead Deleted, CancellationToken Token);
    private readonly Dictionary<Plan, (StatusSucceededCleanupRead? Active, StatusSucceededCleanupRead? Deleted)>
        statusSucceededCleanupReads = new(ReferenceEqualityComparer.Instance);
    private long statusSucceededReadOrdinal;
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCleanupAdmission,
        StatusSucceededCleanupFacts> statusSucceededCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusSucceededDeleteVaultCleanupAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.statusSucceededCleanupAdmissions.TryGetValue(this, out var facts)
            ? facts.ResourceId : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCleanupAdmissions.TryGetValue(this, out var f) &&
            ReferenceEquals(source.journal, journal) && !f.Token.IsCancellationRequested &&
            snapshot.Revision == f.Revision && snapshot.Closing && snapshot.Idle &&
            RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) && MatchesPlan(f.Plan, snapshot) &&
            f.Active.Plan == f.Plan && f.Deleted.Plan == f.Plan && f.Active.Id == f.Plan.VaultId &&
            f.Deleted.Id == f.Plan.DeletedId && f.Deleted.Ordinal > f.Active.Ordinal &&
            f.Active.NativeTask.IsCompleted && f.Deleted.NativeTask.IsCompleted &&
            (f.ResourceId == f.Plan.VaultId
                ? snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty &&
                    f.Active.Status == 200 && f.Deleted.Status == 404
                : f.ResourceId == f.Plan.DeletedId && f.Active.Status == 404 && f.Deleted.Status == 200);
        public override string ToString() => "[StatusSucceededDeleteVaultCleanupAdmission]";
    }
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultIndependentCleanupAdmission,
        StatusSucceededCleanupFacts> statusSucceededIndependentCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusSucceededDeleteVaultIndependentCleanupAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.statusSucceededIndependentCleanupAdmissions.TryGetValue(this, out var facts)
            ? facts.ResourceId : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededIndependentCleanupAdmissions.TryGetValue(this, out var f) &&
            ReferenceEquals(source.journal, journal) && !f.Token.IsCancellationRequested &&
            snapshot.Revision == f.Revision && snapshot.Closing && snapshot.Idle &&
            RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) && MatchesPlan(f.Plan, snapshot) &&
            f.Active.Plan == f.Plan && f.Deleted.Plan == f.Plan && f.Active.Id == f.Plan.VaultId &&
            f.Deleted.Id == f.Plan.DeletedId && f.Deleted.Ordinal > f.Active.Ordinal &&
            f.Active.NativeTask.IsCompleted && f.Deleted.NativeTask.IsCompleted &&
            (f.ResourceId == f.Plan.VaultId
                ? snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty &&
                    f.Active.Status == 200 && f.Deleted.Status == 404
                : f.ResourceId == f.Plan.DeletedId && f.Active.Status == 404 && f.Deleted.Status == 200);
        public override string ToString() => "[StatusSucceededDeleteVaultIndependentCleanupAdmission]";
    }
    private sealed record StatusSucceededCancellationCleanupFacts(Plan Plan, string ResourceId, RoleFixtureJournal.Snapshot Preimage,
        StatusSucceededCleanupRead Active, StatusSucceededCleanupRead Deleted, CancellationToken Token);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationCleanupAdmission,
        StatusSucceededCancellationCleanupFacts> statusSucceededCancellationCleanupAdmissions = new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusSucceededDeleteVaultCancellationCleanupAdmission(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.statusSucceededCancellationCleanupAdmissions.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationCleanupAdmissions.TryGetValue(this, out var f) &&
            ReferenceEquals(source.journal, journal) && !f.Token.IsCancellationRequested && !source.closed &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(f.Preimage, snapshot) &&
            snapshot.Closing && snapshot.Idle && MatchesPlan(f.Plan, snapshot) &&
            f.Active.Plan == f.Plan && f.Deleted.Plan == f.Plan && f.Active.Id == f.Plan.VaultId &&
            f.Deleted.Id == f.Plan.DeletedId && f.Deleted.Ordinal > f.Active.Ordinal &&
            f.Active.Revision == snapshot.Revision && f.Deleted.Revision == snapshot.Revision &&
            f.Active.NativeTask.IsCompleted && f.Deleted.NativeTask.IsCompleted &&
            (f.ResourceId == f.Plan.VaultId
                ? snapshot.StatusSucceededDeleteVault!.InvocationDispatch == Guid.Empty && f.Active.Status == 200 && f.Deleted.Status == 404
                : f.ResourceId == f.Plan.DeletedId && f.Active.Status == 404 && f.Deleted.Status == 200);
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationCleanupAdmission]";
    }
    private sealed record StatusSucceededCancellationFixtureFacts(Plan Plan, RoleFixtureJournal.Snapshot Preimage,
        string ResourceId, Guid Dispatch, bool Settled, Task NativeTask, Task? StatusTask, CancellationToken Token, CancellationToken CallerToken);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<StatusSucceededDeleteVaultCancellationFixtureDrain,
        StatusSucceededCancellationFixtureFacts> statusSucceededCancellationFixtureDrains = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Receipt, StatusSucceededDeleteVaultCancellationFixtureDrain> statusSucceededCancellationReceipts =
        new(ReferenceEqualityComparer.Instance);
    internal sealed class StatusSucceededDeleteVaultCancellationFixtureDrain(VaultFixtureProvisioner source)
    {
        internal string ResourceId => source.statusSucceededCancellationFixtureDrains.TryGetValue(this, out var f) ? f.ResourceId : "";
        internal Guid Dispatch => source.statusSucceededCancellationFixtureDrains.TryGetValue(this, out var f) ? f.Dispatch : Guid.Empty;
        internal bool Settled => source.statusSucceededCancellationFixtureDrains.TryGetValue(this, out var f) && f.Settled;
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            source.statusSucceededCancellationFixtureDrains.TryGetValue(this, out var f) &&
            ReferenceEquals(source.journal, journal) && !source.closed && !f.Token.IsCancellationRequested && !f.CallerToken.IsCancellationRequested &&
            f.NativeTask.IsCompleted && (f.StatusTask is null || f.StatusTask.IsCompleted) &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(f.Preimage, snapshot) &&
            MatchesPlan(f.Plan, snapshot) && snapshot.StatusSucceededDeleteVault!.InvocationDispatch != f.Dispatch &&
            snapshot.Resources.Single(r => r.Id == f.ResourceId).ActiveDispatch == f.Dispatch;
        public override string ToString() => "[StatusSucceededDeleteVaultCancellationFixtureDrain]";
    }

    private static RoleFixtureJournal.Snapshot FreezeStatusSucceededCancellationSnapshot(RoleFixtureJournal.Snapshot snapshot) =>
        snapshot with
        {
            Resources = snapshot.Resources.ToArray(),
            StatusSucceededDeleteVault = snapshot.StatusSucceededDeleteVault! with
            { Baseline = CopyConfiguration(snapshot.StatusSucceededDeleteVault.Baseline) }
        };

    private RoleFixtureJournal.Snapshot PersistStatusSucceededCancellationFixture(StatusSucceededDeleteVaultCancellationFixtureDrain drain)
    {
        Require(statusSucceededCancellationFixtureDrains.TryGetValue(drain, out var f));
        RoleFixtureJournal.Snapshot current;
        try { current = ReadPlan(f.Plan.Owner, f.Plan.Selector); }
        catch (RoleFixtureJournal.StatusSucceededDeleteVaultCancellationHistoryException)
        { statusSucceededCancellationFixtureDrains.TryRemove(drain, out _); throw; }
        var expected = f.Preimage with
        {
            Revision = f.Preimage.Revision + 1,
            Resources = f.Preimage.Resources.Select(r => r.Id == f.ResourceId
                ? r with { InvocationTerminated = true, ActiveDispatch = f.Settled ? Guid.Empty : f.Dispatch } : r).ToArray()
        };
        if (!closed && !f.Token.IsCancellationRequested && !f.CallerToken.IsCancellationRequested &&
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, current)) return current;
        if (!drain.Validate(journal, current))
        {
            statusSucceededCancellationFixtureDrains.TryRemove(drain, out _);
            var row = current.Resources.Single(r => r.Id == f.ResourceId);
            if (row.ActiveDispatch == f.Dispatch && !row.InvocationTerminated)
                journal.EndDispatch(f.Plan.Owner, f.Plan.Selector, f.ResourceId, f.Dispatch, nativeSettled: false);
            throw Failure();
        }
        RoleFixtureJournal.Snapshot committed;
        try { committed = journal.EndStatusSucceededDeleteVaultCancellationFixtureDispatch(f.Plan.Owner, f.Plan.Selector, f.Plan.LeaseId, drain); }
        catch (RoleFixtureJournal.StatusSucceededDeleteVaultCancellationHistoryException)
        { statusSucceededCancellationFixtureDrains.TryRemove(drain, out _); throw; }
        Require(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected, committed));
        return committed;
    }

    private bool purgeDeletedVaultProfile;
    private string? privateConnectionUpdateVariant;
    private bool privateConnectionDeleteProfile;
    private readonly Dictionary<Plan, PrivateConnectionDeleteLoan> privateDeleteLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<PrivateConnectionDeleteLoan, List<PrivateConnectionDeleteRead>> privateDeleteReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, PrivateConnectionUpdateLoan> privateUpdateLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<PrivateConnectionUpdateLoan, List<PrivateConnectionUpdateRead>> privateUpdateReads =
        new(ReferenceEqualityComparer.Instance);
    private string? createVaultVariant;
    private VaultAdministrationEffects.Configuration? createVaultSelected;
    private string? recoverVaultVariant;
    private VaultAdministrationEffects.Configuration? recoverVaultSelected;
    private readonly Dictionary<Plan, RecoverVaultLoan> recoverVaultLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<RecoverVaultLoan, List<RecoverVaultRead>> recoverVaultReads = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, RecoverPreparation> recoverPreparations = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, Guid> statusRecoveryDispatches = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, Guid> statusUpdateDispatches = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, CreateOrUpdateVaultLoan> createVaultLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<CreateOrUpdateVaultLoan, List<CreateVaultRead>> createVaultReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, PurgeDeletedVaultLoan> purgeDeletedVaultLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<PurgeDeletedVaultLoan, List<PurgeDeletedVaultRead>> purgeDeletedVaultReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, PurgePreparation> purgePreparations = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<Plan, DeleteVaultLoan> deleteVaultLoans = new(ReferenceEqualityComparer.Instance);
    private readonly Dictionary<DeleteVaultLoan, List<DeleteVaultRead>> deleteVaultReads = new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<PrivateConnectionReadAdmission, Plan> privateReads =
        new(ReferenceEqualityComparer.Instance);
    private readonly System.Collections.Concurrent.ConcurrentDictionary<PrivateConnectionReadAdmission, Guid> privateReadDrains =
        new(ReferenceEqualityComparer.Instance);
    private readonly HashSet<(Guid Nonce, string Id)> notificationBindings = [];
    internal const string NotificationPrefix = "/providers/Microsoft.EventGrid/eventSubscriptions/";
    internal RoleFixtureJournal Journal => journal;
    internal ManagementMutation StatusDeniedNotificationOperation { get; private init; } = ManagementMutation.UpdateNotification;
    internal bool MatchesStatusDeniedNotificationOperation(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Case == "denied-authority" && (StatusDeniedNotificationOperation switch
        {
            ManagementMutation.UpdateNotification => selector.Variant == "operation.UpdateNotification",
            ManagementMutation.CreateOrUpdateNotification => selector.Variant == "operation.CreateOrUpdateNotification",
            _ => false
        });
    internal Guid FixtureTenantId => host.TenantId;
    internal HostScope Host => host;
    private volatile bool closed;
    private Task? disposal;
    private string SubscriptionId => $"/subscriptions/{host.SubscriptionId:D}";
    private string GroupId => SubscriptionId + "/resourceGroups/" + host.ResourceGroup;
    private string DeletedId(string name) => SubscriptionId + "/providers/Microsoft.KeyVault/locations/" + host.Location + "/deletedVaults/" + name;
    private static Uri SecretOrigin(Plan plan) => new($"https://{plan.VaultName}.vault.azure.net");

    internal VaultFixtureProvisioner(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority readArm, Authority readSecret, Limits limits, TimeProvider? time = null)
    {
        Authority[] authorities = [setupArm, setupSecret, readArm, readSecret];
        Require(journal is not null && host is not null && host.ExclusiveFixtureNamespace &&
            host.SubscriptionId != Guid.Empty && host.TenantId != Guid.Empty &&
            Segment(host.ResourceGroup, 90) && Segment(host.Location, 50) &&
            authorities.All(a => a is not null && a.Credential is not null && a.Transport is not null &&
                a.Label is { Length: > 0 and <= 128 }) &&
            authorities.Select(a => a.Credential).Distinct(ReferenceEqualityComparer.Instance).Count() == 4 &&
            authorities.Select(a => a.Transport).Distinct(ReferenceEqualityComparer.Instance).Count() == 4 &&
            authorities.Select(a => a.Label).Distinct(StringComparer.Ordinal).Count() == 4 &&
            limits is not null && limits.MaximumResponseBytes is >= 1024 and <= 16 * 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        // Copy the source-owned mutable arrays before validation. Caller mutation
        // cannot change a prepared baseline or expand native permissions later.
        try
        {
            Require(baseline is not null && baseline.Policies is { Length: <= 16 } &&
                baseline.Policies.All(p => p is not null && p.Permissions is not null &&
                    p.Permissions.Distinct().Count() == p.Permissions.Length));
            baselineConfiguration = baseline with
            {
                Policies = baseline.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray()
            };
            _ = this.baseline.Build();
            Require(this.baseline.TenantId == host.TenantId && this.baseline.Location == host.Location);
        }
        catch (Exception) { throw Failure(); }
        this.journal = journal;
        this.host = host;
        this.setupArm = setupArm;
        secretSetup = setupSecret;
        this.readArm = readArm;
        secretRead = readSecret;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    private VaultFixtureProvisioner(RoleFixtureJournal journal, HostScope host, Authority setupArm,
        Authority readArm, Limits limits, TimeProvider? time)
    {
        Require(journal is not null && host is not null && host.ExclusiveFixtureNamespace &&
            host.SubscriptionId != Guid.Empty && host.TenantId != Guid.Empty &&
            Segment(host.ResourceGroup, 90) && Segment(host.Location, 50) &&
            setupArm is not null && readArm is not null &&
            new[] { setupArm, readArm }.All(a => a.Credential is not null && a.Transport is not null &&
                a.Label is { Length: > 0 and <= 128 }) &&
            !ReferenceEquals(setupArm.Credential, readArm.Credential) &&
            !ReferenceEquals(setupArm.Transport, readArm.Transport) && setupArm.Label != readArm.Label &&
            limits is not null && limits.MaximumResponseBytes is >= 1024 and <= 16 * 1024 * 1024 &&
            limits.Timeout > TimeSpan.Zero && limits.Timeout <= TimeSpan.FromMinutes(2));
        this.journal = journal;
        this.host = host;
        this.setupArm = setupArm;
        this.readArm = readArm;
        this.limits = limits;
        this.time = time ?? TimeProvider.System;
    }

    internal static VaultFixtureProvisioner ForCleanup(RoleFixtureJournal journal, HostScope host,
        Authority setupArm, Authority readArm, Limits limits, TimeProvider? time = null) =>
        new(journal, host, setupArm, readArm, limits, time);

    internal static VaultFixtureProvisioner ForStatusDeniedNotificationPut(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority readArm, Authority readSecret, Limits limits, TimeProvider? time = null) =>
        new(journal, host, baseline, setupArm, setupSecret, readArm, readSecret, limits, time)
        { StatusDeniedNotificationOperation = ManagementMutation.CreateOrUpdateNotification };

    internal static VaultFixtureProvisioner ForStatusDeniedNotificationPutCleanup(RoleFixtureJournal journal, HostScope host,
        Authority setupArm, Authority readArm, Limits limits, TimeProvider? time = null) =>
        new(journal, host, setupArm, readArm, limits, time)
        { StatusDeniedNotificationOperation = ManagementMutation.CreateOrUpdateNotification };

    internal static VaultFixtureProvisioner ForPrivateConnectionUpdate(RoleFixtureJournal journal, HostScope host,
        string variant, VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority readArm, Authority readSecret, Limits limits, TimeProvider? time = null)
    {
        Require(VaultAdministrationEffects.Members.Single(m =>
            m.Operation == "a.management.VaultAdministration.UpdatePrivateConnectionAsync").Variants.Contains(variant));
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret, readArm, readSecret, limits, time);
        Require(host.AllowPurge && parent.baseline.PublicNetworkAccess && !parent.baseline.PurgeProtection);
        parent.privateConnectionUpdateVariant = variant;
        return parent;
    }

    internal static VaultFixtureProvisioner ForPrivateConnectionDelete(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority setupSecret,
        Authority readArm, Authority readSecret, Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, baseline, setupArm, setupSecret, readArm, readSecret, limits, time);
        Require(host.AllowPurge && parent.baseline.PublicNetworkAccess && !parent.baseline.PurgeProtection);
        parent.privateConnectionDeleteProfile = true;
        return parent;
    }

    internal static VaultFixtureProvisioner ForSettings(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location);
        parent.settingsProfile = true;
        return parent;
    }

    internal static VaultFixtureProvisioner ForCreateOrUpdateVault(RoleFixtureJournal journal, HostScope host,
        string variant, VaultAdministrationEffects.Configuration baseline,
        VaultAdministrationEffects.Configuration selected, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        Require(VaultAdministrationEffects.ConfigurationVariants.Contains(variant));
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        parent.createVaultSelected = CopyConfiguration(selected);
        Require(host.AllowPurge && baseline.Location == host.Location && baseline.TenantId == host.TenantId &&
            ValidCreateVaultConfigurations(variant, parent.baselineConfiguration, parent.createVaultSelected));
        parent.createVaultVariant = variant;
        return parent;
    }

    internal (string Variant, VaultAdministrationEffects.Configuration Baseline, VaultAdministrationEffects.Configuration Selected)
        CreateOrUpdateVaultConfigurations(HostScope expected, ManagementOperationStatusCollector.Authority observer,
            HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && createVaultVariant is not null &&
                baselineConfiguration is not null && createVaultSelected is not null && host == expected && host.AllowPurge &&
                observer is { Credential: not null, Transport: not null } &&
                observer.Label is { Length: > 0 and <= 128 } && selectedBackend is not null &&
                new[] { setupArm, readArm }.All(a => a.Label != observer.Label &&
                    !ReferenceEquals(a.Credential, observer.Credential) &&
                    !ReferenceEquals(a.Transport, observer.Transport) && !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(observer.Transport, selectedBackend));
            return (createVaultVariant, CopyConfiguration(baseline), CopyConfiguration(createVaultSelected));
        }
    }

    internal static VaultFixtureProvisioner ForDeleteVault(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && !parent.baseline.PurgeProtection &&
            parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location);
        parent.deleteVaultProfile = true;
        return parent;
    }

    internal static bool StatusSucceededDeleteVaultSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Succeeded" && selector.Case == "selected-contract";

    internal static VaultFixtureProvisioner ForStatusSucceededDeleteVault(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 });
        parent.statusSucceededDeleteVaultProfile = true;
        return parent;
    }

    internal VaultAdministrationEffects.Configuration StatusSucceededDeleteVaultConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && statusSucceededDeleteVaultProfile && host == expected && host.AllowPurge &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is not null &&
                ReferenceEquals(resourceReader.Credential, readArm.Credential) &&
                ReferenceEquals(resourceReader.Transport, readArm.Transport) && resourceReader.Label == readArm.Label &&
                new[] { setupArm, readArm }.All(a => a.Label != statusReader.Label &&
                    !ReferenceEquals(a.Credential, statusReader.Credential) &&
                    !ReferenceEquals(a.Transport, statusReader.Transport) && !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend));
            return CopyConfiguration(baseline);
        }
    }

    internal static bool StatusSucceededDeleteVaultIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Succeeded" && selector.Case == "independent-effect";

    internal static VaultFixtureProvisioner ForStatusSucceededDeleteVaultIndependent(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time)
        { statusSucceededDeleteVaultIndependentProfile = true };
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 });
        return parent;
    }

    internal VaultAdministrationEffects.Configuration StatusSucceededDeleteVaultIndependentConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && statusSucceededDeleteVaultIndependentProfile && host == expected && host.AllowPurge &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is not null &&
                ReferenceEquals(resourceReader.Credential, readArm.Credential) &&
                ReferenceEquals(resourceReader.Transport, readArm.Transport) && resourceReader.Label == readArm.Label &&
                new[] { setupArm, readArm }.All(a => a.Label != statusReader.Label &&
                    !ReferenceEquals(a.Credential, statusReader.Credential) &&
                    !ReferenceEquals(a.Transport, statusReader.Transport) && !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend));
            return CopyConfiguration(baseline);
        }
    }

    internal static bool StatusSucceededDeleteVaultCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "status.Succeeded" && selector.Case == "cancellation-boundary";

    internal static VaultFixtureProvisioner ForStatusSucceededDeleteVaultCancellation(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time)
        { statusSucceededDeleteVaultCancellationProfile = true };
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location &&
            parent.baseline is { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 });
        return parent;
    }

    internal VaultAdministrationEffects.Configuration StatusSucceededDeleteVaultCancellationConfiguration(HostScope expected,
        ManagementOperationStatusCollector.Authority statusReader, ManagementOperationResourceCollector.Authority resourceReader,
        HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && statusSucceededDeleteVaultCancellationProfile && host == expected && host.AllowPurge &&
                statusReader is { Credential: not null, Transport: not null } && resourceReader is not null &&
                ReferenceEquals(resourceReader.Credential, readArm.Credential) &&
                ReferenceEquals(resourceReader.Transport, readArm.Transport) && resourceReader.Label == readArm.Label &&
                new[] { setupArm, readArm }.All(a => a.Label != statusReader.Label &&
                    !ReferenceEquals(a.Credential, statusReader.Credential) &&
                    !ReferenceEquals(a.Transport, statusReader.Transport) && !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(statusReader.Transport, selectedBackend));
            return CopyConfiguration(baseline);
        }
    }

    private VaultAdministrationEffects.Configuration StatusSucceededConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(plan.StatusSucceededDeleteVaultProfile && RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) ||
            plan.StatusSucceededDeleteVaultIndependentProfile && RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) ||
            plan.StatusSucceededDeleteVaultCancellationProfile && RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot));
        return CopyConfiguration(snapshot.StatusSucceededDeleteVault!.Baseline);
    }

    internal bool OwnsStatusSucceededDeleteVaultPreparation(Plan plan)
    {
        lock (plans)
        {
            CheckPlan(plan);
            return statusSucceededDeleteVaultProfile && plan.StatusSucceededDeleteVaultProfile && !plan.Restored &&
                originalReady.Contains(plan) && plan.Busy == 0 && plan.Preparation == Preparation.Active &&
                !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
                plan.PrivateEndpoint is null;
        }
    }

    internal bool OwnsStatusSucceededDeleteVaultIndependentPreparation(Plan plan)
    {
        lock (plans)
        {
            CheckPlan(plan);
            return statusSucceededDeleteVaultIndependentProfile && plan.StatusSucceededDeleteVaultIndependentProfile && !plan.Restored &&
                originalReady.Contains(plan) && plan.Busy == 0 && plan.Preparation == Preparation.Active &&
                !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
                plan.PrivateEndpoint is null;
        }
    }

    internal bool OwnsStatusSucceededDeleteVaultCancellationPreparation(Plan plan)
    {
        lock (plans)
        {
            CheckPlan(plan);
            return statusSucceededDeleteVaultCancellationProfile && plan.StatusSucceededDeleteVaultCancellationProfile && !plan.Restored &&
                originalReady.Contains(plan) && plan.Busy == 0 && plan.Preparation == Preparation.Active &&
                !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
                plan.PrivateEndpoint is null;
        }
    }

    internal static VaultFixtureProvisioner ForRecoverVault(RoleFixtureJournal journal, HostScope host,
        string variant, VaultAdministrationEffects.Configuration baseline,
        VaultAdministrationEffects.Configuration selected, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        parent.recoverVaultSelected = CopyConfiguration(selected);
        Require(host.AllowPurge && parent.baseline.Location == host.Location && parent.baseline.TenantId == host.TenantId &&
            ValidRecoverVaultConfigurations(variant, parent.baseline, parent.recoverVaultSelected));
        parent.recoverVaultVariant = variant;
        return parent;
    }

    internal (string Variant, VaultAdministrationEffects.Configuration Baseline, VaultAdministrationEffects.Configuration Selected)
        RecoverVaultConfigurations(HostScope expected, ManagementOperationStatusCollector.Authority observer,
            HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && recoverVaultVariant is not null && baselineConfiguration is not null &&
                recoverVaultSelected is not null && host == expected && host.AllowPurge &&
                observer is { Credential: not null, Transport: not null } &&
                observer.Label is { Length: > 0 and <= 128 } && selectedBackend is not null &&
                new[] { setupArm, readArm }.All(a => a.Label != observer.Label &&
                    !ReferenceEquals(a.Credential, observer.Credential) &&
                    !ReferenceEquals(a.Transport, observer.Transport) && !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(observer.Transport, selectedBackend));
            return (recoverVaultVariant, CopyConfiguration(baseline), CopyConfiguration(recoverVaultSelected));
        }
    }

    internal VaultAdministrationEffects.Configuration DeleteVaultBaseline(HostScope expected,
        ManagementOperationStatusCollector.Authority observer, HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && deleteVaultProfile && baselineConfiguration is not null && host == expected &&
                host.AllowPurge && !baseline.PurgeProtection &&
                observer is { Credential: not null, Transport: not null } &&
                observer.Label is { Length: > 0 and <= 128 } && selectedBackend is not null &&
                new[] { setupArm, readArm }.All(a => a.Label != observer.Label &&
                    !ReferenceEquals(a.Credential, observer.Credential) &&
                    !ReferenceEquals(a.Transport, observer.Transport) &&
                    !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(observer.Transport, selectedBackend));
            return CopyConfiguration(baseline);
        }
    }

    internal static VaultFixtureProvisioner ForPurgeDeletedVault(RoleFixtureJournal journal, HostScope host,
        VaultAdministrationEffects.Configuration baseline, Authority setupArm, Authority readArm,
        Limits limits, TimeProvider? time = null)
    {
        var parent = new VaultFixtureProvisioner(journal, host, setupArm, readArm, limits, time);
        parent.baselineConfiguration = CopyConfiguration(baseline);
        Require(host.AllowPurge && !parent.baseline.PurgeProtection &&
            parent.baseline.TenantId == host.TenantId && parent.baseline.Location == host.Location);
        parent.purgeDeletedVaultProfile = true;
        return parent;
    }

    internal VaultAdministrationEffects.Configuration PurgeDeletedVaultBaseline(HostScope expected,
        ManagementOperationStatusCollector.Authority observer, HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && purgeDeletedVaultProfile && baselineConfiguration is not null && host == expected &&
                host.AllowPurge && !baseline.PurgeProtection &&
                observer is { Credential: not null, Transport: not null } &&
                observer.Label is { Length: > 0 and <= 128 } && selectedBackend is not null &&
                new[] { setupArm, readArm }.All(a => a.Label != observer.Label &&
                    !ReferenceEquals(a.Credential, observer.Credential) &&
                    !ReferenceEquals(a.Transport, observer.Transport) &&
                    !ReferenceEquals(a.Transport, selectedBackend)) &&
                !ReferenceEquals(observer.Transport, selectedBackend));
            return CopyConfiguration(baseline);
        }
    }

    private static VaultAdministrationEffects.Configuration CopyConfiguration(VaultAdministrationEffects.Configuration value)
    {
        Require(value is not null && value.Policies is { Length: <= 16 } &&
            value.Policies.All(p => p is not null && p.Permissions is not null));
        var copy = value with { Policies = value.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray() };
        _ = copy.Build();
        return copy;
    }

    internal VaultAdministrationEffects.Configuration StatusVaultRecoverCancellationConfiguration(HostScope expected)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile &&
                createVaultVariant is null && recoverVaultVariant is null &&
                privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                baseline.Rbac && !baseline.PurgeProtection && baseline.PublicNetworkAccess &&
                baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private VaultAdministrationEffects.Configuration StatusVaultRecoverCancellationConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(StatusVaultRecoverCancellationSelector(plan.Selector) &&
            snapshot.StatusVaultRecoverCancellationBaseline is { } &&
            snapshot.StatusVaultRecoverCancellationBaseline.Location == host.Location &&
            snapshot.StatusVaultRecoverCancellationBaseline.TenantId == host.TenantId);
        return CopyConfiguration(snapshot.StatusVaultRecoverCancellationBaseline);
    }

    internal bool OwnsStatusVaultRecoverCancellationPreparation(Plan originalPlan)
    {
        lock (plans)
        {
            if (closed || originalPlan is null || originalPlan.Restored || originalPlan.OriginalRecover ||
                !StatusVaultRecoverCancellationSelector(originalPlan.Selector) ||
                !ReferenceEquals(originalPlan.Source, source) ||
                !plans.TryGetValue(originalPlan.Selector.Nonce, out var retained) ||
                !ReferenceEquals(retained, originalPlan) || !originalReady.Contains(originalPlan) ||
                originalPlan.Busy != 0 || !recoverPreparations.TryGetValue(originalPlan, out var preparation) ||
                !ReferenceEquals(preparation.Plan, originalPlan) || !preparation.Task.IsCompletedSuccessfully)
                return false;
            var expected = StatusVaultRecoverCancellationConfiguration(originalPlan);
            return preparation.Digest == ParseOwnedVaultResource(originalPlan.VaultId, originalPlan.Selector.Nonce,
                preparation.Raw, expected, "Succeeded") &&
                VaultAdministrationEffects.SameConfiguration(Configuration(preparation.Native), expected);
        }
    }

    internal void RetainStatusVaultRecoverCancellationDispatch(Plan originalPlan, Guid dispatch)
    {
        lock (plans)
        {
            Require(OwnsStatusVaultRecoverCancellationPreparation(originalPlan) && dispatch != Guid.Empty &&
                !statusRecoveryDispatches.ContainsKey(originalPlan));
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Resources.Single(r => r.Id == originalPlan.VaultId) is
            {
                SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: false,
                ActiveDispatch: var selected
            } && selected == dispatch);
            statusRecoveryDispatches.Add(originalPlan, dispatch);
        }
    }

    internal VaultAdministrationEffects.Configuration StatusVaultUpdateCancellationConfiguration(HostScope expected)
    {
        lock (plans)
        {
            Require(!closed && host == expected && host.AllowPurge && baselineConfiguration is not null &&
                !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile &&
                createVaultVariant is null && recoverVaultVariant is null &&
                privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile &&
                baseline.Location == host.Location && baseline.TenantId == host.TenantId &&
                baseline.Rbac && !baseline.PurgeProtection && !baseline.PublicNetworkAccess &&
                baseline.Policies.Length == 0);
            return CopyConfiguration(baseline);
        }
    }

    private VaultAdministrationEffects.Configuration StatusVaultUpdateCancellationConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(StatusVaultUpdateCancellationSelector(plan.Selector) &&
            snapshot.StatusVaultUpdateCancellationBaseline is { } &&
            snapshot.StatusVaultUpdateCancellationBaseline.Location == host.Location &&
            snapshot.StatusVaultUpdateCancellationBaseline.TenantId == host.TenantId);
        var configuration = CopyConfiguration(snapshot.StatusVaultUpdateCancellationBaseline);
        return snapshot.Resources.Single(r => r.Id == plan.VaultId).SelectedAttempted
            ? configuration with { PublicNetworkAccess = true } : configuration;
    }

    internal bool OwnsStatusVaultUpdateCancellationPreparation(Plan originalPlan)
    {
        lock (plans)
        {
            if (closed || originalPlan is null || originalPlan.Restored ||
                originalPlan.OriginalCreate || originalPlan.OriginalRecover ||
                originalPlan.OriginalPrivateConnectionUpdate || originalPlan.OriginalPrivateConnectionDelete ||
                !StatusVaultUpdateCancellationSelector(originalPlan.Selector) ||
                !ReferenceEquals(originalPlan.Source, source) ||
                !plans.TryGetValue(originalPlan.Selector.Nonce, out var retained) ||
                !ReferenceEquals(retained, originalPlan) || !originalReady.Contains(originalPlan) ||
                !prepared.Contains(originalPlan) || originalPlan.Consumed != 1 || originalPlan.Busy != 0 ||
                originalPlan.Preparation != Preparation.Active || originalPlan.SeedCanary ||
                originalPlan.PrivateEndpoint is not null || originalPlan.PolicyChildren.Count != 0 ||
                originalPlan.OwnedNotificationNames.Count != 0)
                return false;
            var expected = StatusVaultUpdateCancellationConfiguration(host);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            return !snapshot.Closing && snapshot.StatusVaultUpdateCancellationBaseline is { } durable &&
                VaultAdministrationEffects.SameConfiguration(expected, durable) &&
                snapshot.Resources.Single(r => r.Id == originalPlan.VaultId) is
                { CreateAttempted: true, CleanupOnly: false, DeleteAttempted: false, Absent: false } &&
                snapshot.Resources.Where(r => r.Id != originalPlan.VaultId).All(r =>
                    r.CleanupOnly && !r.CreateAttempted && !r.DeleteAttempted && !r.SelectedAttempted &&
                    !r.InvocationTerminated && !r.Absent && r.ActiveDispatch == Guid.Empty);
        }
    }

    internal void RetainStatusVaultUpdateCancellationDispatch(Plan originalPlan, Guid dispatch)
    {
        lock (plans)
        {
            Require(OwnsStatusVaultUpdateCancellationPreparation(originalPlan) && dispatch != Guid.Empty &&
                !statusUpdateDispatches.ContainsKey(originalPlan));
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Resources.Single(r => r.Id == originalPlan.VaultId) is
            {
                SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: false,
                ActiveDispatch: var selected
            } && selected == dispatch);
            statusUpdateDispatches.Add(originalPlan, dispatch);
        }
    }

    internal VaultAdministrationEffects.Configuration SettingsBaseline(RoleFixtureJournal expectedJournal, HostScope expected,
        VaultAdministrationCollector.Authority observer, HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && settingsProfile && baselineConfiguration is not null &&
                ReferenceEquals(journal, expectedJournal) && host == expected &&
                observer is not null && observer.Credential is not null && observer.Transport is not null &&
                observer.Label is { Length: > 0 and <= 128 } && selectedBackend is not null &&
                !ReferenceEquals(selectedBackend, setupArm.Transport) &&
                !ReferenceEquals(selectedBackend, readArm.Transport) &&
                !ReferenceEquals(selectedBackend, observer.Transport));
            // Parent and metadata reads may deliberately share one ARM identity.
            return CopyConfiguration(baseline);
        }
    }

    internal Plan OpenCleanupPlan(string owner, FixtureSelector selector) => Reconstruct(ReadPlan(owner, selector));

    // These are trusted source arguments, not an HTTP request schema. Borrowed
    // IDs are explicit journal-only dependencies; their child source owns any
    // reads or mutations. Endpoint setup requires the explicit declaration and
    // its separate original source; borrowed coordinates grant no mutation.
    internal Plan PlanFixture(string owner, FixtureSelector selector, Preparation preparation,
        string[] borrowedResourceIds, bool seedCanary = true, PolicyChildSpecification[]? policyChildren = null,
        string[]? ownedNotificationNames = null, PrivateEndpointSpecification? privateEndpoint = null,
        CancellationToken originalCallerToken = default, CancellationToken preparationToken = default)
    {
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(selector));
        if (statusDeniedVaultUpdateProfile)
        {
            Require(!statusDeniedVaultUpdateCleanup && preparation == Preparation.Active && !seedCanary &&
                borrowedResourceIds is { Length: 0 } && (policyChildren is null || policyChildren.Length == 0) &&
                (ownedNotificationNames is null || ownedNotificationNames.Length == 0) && privateEndpoint is null);
            return PlanDeniedVaultUpdate(owner, selector, preparationToken, originalCallerToken);
        }
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(selector));
        Require(!statusDeniedPrivateDeleteProfile || !statusDeniedPrivateDeleteCleanup &&
            preparation == Preparation.Active && !seedCanary && borrowedResourceIds is { Length: 0 } &&
            (policyChildren is null || policyChildren.Length == 0) &&
            (ownedNotificationNames is null || ownedNotificationNames.Length == 0) && privateEndpoint is not null);
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) ||
            MatchesStatusDeniedNotificationOperation(selector));
        lock (plans) Require(!closed && baselineConfiguration is not null);
        Require(borrowedResourceIds is not null);
        Require(!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector) || NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector)) ||
            preparation == Preparation.Active && !seedCanary && borrowedResourceIds.Length == 0 &&
            (policyChildren is null || policyChildren.Length == 0) && ownedNotificationNames is { Length: 1 } && privateEndpoint is null);
        borrowedResourceIds = borrowedResourceIds.ToArray();
        policyChildren = (policyChildren ?? []).ToArray();
        ownedNotificationNames = (ownedNotificationNames ?? []).ToArray();
        Require(statusPendingPurgeProfile == StatusPendingPurgeSelector(selector) &&
            (pendingIndependentProfile is not null) == StatusPendingPurgeIndependentSelector(selector) &&
            (pendingCancellationProfile is not null) == StatusPendingPurgeCancellationSelector(selector) &&
            (canceledCancellationProfile is not null) == StatusCanceledPurgeCancellationSelector(selector) &&
            (canceledIndependentProfile is not null) == StatusCanceledPurgeIndependentSelector(selector) &&
            (canceledProfile is not null) == StatusCanceledPurgeSelector(selector) &&
            (deniedProfile is not null) == StatusDeniedPurgeSelector(selector) &&
            (deniedProfile is null || DeclaredDeniedSelector(selector)) &&
            (failedProfile is not null) == StatusFailedPurgeSelector(selector) &&
            (failedIndependentProfile is not null) == StatusFailedPurgeIndependentSelector(selector) &&
            (failedCancellationProfile is not null) == StatusFailedPurgeCancellationSelector(selector));
        Require(!PendingProfile || preparation == Preparation.Deleted && !seedCanary &&
            borrowedResourceIds.Length == 0 && policyChildren.Length == 0 && ownedNotificationNames.Length == 0 &&
            privateEndpoint is null);
        Require(statusSucceededDeleteVaultProfile == StatusSucceededDeleteVaultSelector(selector) &&
            statusSucceededDeleteVaultIndependentProfile == StatusSucceededDeleteVaultIndependentSelector(selector) &&
            statusSucceededDeleteVaultCancellationProfile == StatusSucceededDeleteVaultCancellationSelector(selector));
        Require(!(statusSucceededDeleteVaultProfile || statusSucceededDeleteVaultIndependentProfile || statusSucceededDeleteVaultCancellationProfile) ||
            preparation == Preparation.Active && !seedCanary &&
            borrowedResourceIds.Length == 0 && policyChildren.Length == 0 && ownedNotificationNames.Length == 0 &&
            privateEndpoint is null);
        Require(!settingsProfile || SettingsSelector(selector) && preparation == Preparation.Active &&
            !seedCanary && borrowedResourceIds.Length == 0 && policyChildren.Length == 0 &&
            ownedNotificationNames.Length == 0 && privateEndpoint is null);
        Require(createVaultVariant is null || CreateOrUpdateVaultSelector(selector) &&
            selector.Variant == createVaultVariant && preparation == Preparation.Active && !seedCanary &&
            borrowedResourceIds.Length == 0 && policyChildren.Length == 0 && ownedNotificationNames.Length == 0 &&
            privateEndpoint is null);
        Require(!deleteVaultProfile || DeleteVaultSelector(selector) && preparation == Preparation.Active &&
            !seedCanary && borrowedResourceIds.Length == 0 && policyChildren.Length == 0 &&
            ownedNotificationNames.Length == 0 && privateEndpoint is null);
        Require(!DeleteVaultSelector(selector) || deleteVaultProfile);
        Require(!purgeDeletedVaultProfile || PurgeDeletedVaultSelector(selector) && preparation == Preparation.Deleted &&
            !seedCanary && borrowedResourceIds.Length == 0 && policyChildren.Length == 0 &&
            ownedNotificationNames.Length == 0 && privateEndpoint is null);
        Require(!PurgeDeletedVaultSelector(selector) || purgeDeletedVaultProfile);
        Require(recoverVaultVariant is null || RecoverVaultSelector(selector) && selector.Variant == recoverVaultVariant &&
            preparation == Preparation.Deleted && !seedCanary && borrowedResourceIds.Length == 0 &&
            policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && privateEndpoint is null);
        Require(!RecoverVaultSelector(selector) || recoverVaultVariant is not null);
        Require(privateConnectionUpdateVariant is null || PrivateConnectionUpdateSelector(selector) &&
            selector.Variant == privateConnectionUpdateVariant && preparation == Preparation.Active && seedCanary &&
            borrowedResourceIds.Length == 0 && policyChildren.Length == 0 && ownedNotificationNames.Length == 0 &&
            privateEndpoint is not null);
        Require(!PrivateConnectionUpdateSelector(selector) || privateConnectionUpdateVariant is not null);
        Require(!privateConnectionDeleteProfile || PrivateConnectionDeleteSelector(selector) &&
            preparation == Preparation.Active && seedCanary && borrowedResourceIds.Length == 0 &&
            policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && privateEndpoint is not null);
        Require(!PrivateConnectionDeleteSelector(selector) || privateConnectionDeleteProfile);
        Require(!StatusPrivateConnectionUpdateIndependentSelector(selector) || statusPrivateUpdateIndependentProfile);
        Require(!(StatusPrivateConnectionUpdateIndependentSelector(selector) || StatusPrivateConnectionDeleteCancellationSelector(selector) || StatusPrivateConnectionDeleteSelectedSelector(selector) ||
            StatusPrivateConnectionDeleteIndependentSelector(selector)) ||
            preparation == Preparation.Active && !seedCanary && borrowedResourceIds.Length == 0 &&
            policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && privateEndpoint is not null &&
            !settingsProfile && !deleteVaultProfile && !purgeDeletedVaultProfile && createVaultVariant is null &&
            recoverVaultVariant is null && privateConnectionUpdateVariant is null && !privateConnectionDeleteProfile);
        Require(!StatusVaultPurgeCancellationSelector(selector) || preparation == Preparation.Deleted &&
            !seedCanary && borrowedResourceIds.Length == 0 && policyChildren.Length == 0 &&
            ownedNotificationNames.Length == 0 && privateEndpoint is null);
        if (StatusVaultRecoverCancellationSelector(selector))
        {
            _ = StatusVaultRecoverCancellationConfiguration(host);
            Require(preparation == Preparation.Deleted && !seedCanary && borrowedResourceIds.Length == 0 &&
                policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && privateEndpoint is null);
        }
        if (StatusVaultUpdateCancellationSelector(selector))
        {
            _ = StatusVaultUpdateCancellationConfiguration(host);
            Require(preparation == Preparation.Active && !seedCanary && borrowedResourceIds.Length == 0 &&
                policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && privateEndpoint is null);
        }
        Require(privateEndpoint is null || preparation == Preparation.Active &&
            (!seedCanary || PrivateConnectionReadSelector(selector) || privateConnectionUpdateVariant is not null ||
                privateConnectionDeleteProfile) &&
            policyChildren.Length == 0 && ownedNotificationNames.Length == 0 && borrowedResourceIds.Length == 0);
        Require(Enum.IsDefined(preparation) && (preparation != Preparation.Absent || !seedCanary) &&
            borrowedResourceIds is { Length: <= 13 } && borrowedResourceIds.All(BorrowedId) &&
            policyChildren.Length + ownedNotificationNames.Length + borrowedResourceIds.Length <= 21 &&
            (policyChildren.Length + ownedNotificationNames.Length == 0 || preparation == Preparation.Active) &&
            ownedNotificationNames.All(NotificationName) &&
            ownedNotificationNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() == ownedNotificationNames.Length);
        var children = new List<PolicyChild>();
        try
        {
            foreach (var specification in policyChildren)
            {
                var child = PolicyChild.Snapshot(specification, limits.MaximumResponseBytes);
                children.Add(child);
                Require(child.Desired != Preparation.Absent || host.AllowPurge && !baseline.PurgeProtection);
            }
            Require(children.Select(c => c.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == children.Count);
            string name = "skv" + Guid.NewGuid().ToString("N")[..21];
            string vault = GroupId + "/providers/Microsoft.KeyVault/vaults/" + name;
            string deleted = DeletedId(name);
            RoleFixtureJournal.PrivateEndpointDeclaration? declaration = privateEndpoint is null ? null :
                new(vault, GroupId + "/providers/Microsoft.Network/privateEndpoints/" + name + "-pe",
                    privateEndpoint.BorrowedSubnetId, name + "-link",
                    GroupId + "/providers/Microsoft.Network/networkInterfaces/" + name + "-nic",
                    OwnershipTag, selector.Nonce.ToString("N"));
            if (declaration is not null)
            {
                try
                {
                    PrivateEndpointResourceCollector.ValidateBinding(new(selector, Guid.NewGuid(), declaration.EndpointId,
                        vault, declaration.BorrowedSubnetId, declaration.ExpectedNicId, declaration.NetworkConnectionName,
                        host.Location, declaration.OwnerTagName, declaration.OwnerTagValue));
                }
                catch (Exception) { throw Failure(); }
            }
            // Preparation DELETE creates the deleted coordinate. It is deliberately
            // a setup dispatch on that row, not a selected dispatch or root closure.
            RoleFixtureJournal.Resource[] rows =
            [
                new(vault, false), new(vault + "/secrets/" + Canary, false, CleanupOnly: !seedCanary),
                new(deleted, false, CleanupOnly: preparation != Preparation.Deleted),
                .. children.Select(c => new RoleFixtureJournal.Resource(vault + "/secrets/" + c.Name, false)),
                .. ownedNotificationNames.Select(n => new RoleFixtureJournal.Resource(vault + NotificationPrefix + n, false)),
                .. (declaration is null ? Array.Empty<RoleFixtureJournal.Resource>() :
                    new RoleFixtureJournal.Resource[] { new(declaration.EndpointId, false), new(declaration.BorrowedSubnetId, true) }),
                .. borrowedResourceIds.Select(id => new RoleFixtureJournal.Resource(id, true))
            ];
            if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) || NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector))
                rows = [rows[0], rows[3], rows[1], rows[2]];
            if (statusDeniedPrivateDeleteProfile)
            {
                lock (plans)
                {
                    if (deniedPrivateDeleteRoots.TryGetValue(selector.Nonce, out var retainedRoot))
                    {
                        Require(retainedRoot.Owner == owner && retainedRoot.Selector == selector &&
                            retainedRoot.Declaration.BorrowedSubnetId == privateEndpoint!.BorrowedSubnetId);
                        rows = retainedRoot.Rows.Select(r => r with { }).ToArray();
                        declaration = retainedRoot.Declaration with { };
                        vault = declaration.VaultId;
                        deleted = rows[2].Id;
                    }
                    else deniedPrivateDeleteRoots.Add(selector.Nonce,
                        (owner, selector with { }, rows.Select(r => r with { }).ToArray(), declaration! with { }));
                }
            }
            lock (plans)
            {
                Require(!closed);
                var snapshot = PendingProfile ? PreparePendingRoot(owner, selector, rows, preparationToken, originalCallerToken) :
                    statusSucceededDeleteVaultCancellationProfile
                    ? journal.PrepareStatusSucceededDeleteVaultCancellation(owner, selector, rows, baseline)
                    : statusSucceededDeleteVaultIndependentProfile
                    ? journal.PrepareStatusSucceededDeleteVaultIndependent(owner, selector, rows, baseline)
                    : statusSucceededDeleteVaultProfile
                    ? journal.PrepareStatusSucceededDeleteVault(owner, selector, rows, baseline)
                    : journal.Prepare(owner, selector, rows, declaration, settingsProfile ? baseline : null,
                    deleteVaultProfile ? baseline : null, purgeDeletedVaultProfile ? baseline : null,
                    createVaultVariant is null ? null : baseline, createVaultSelected,
                    recoverVaultVariant is null ? null : baseline, recoverVaultSelected,
                    privateConnectionUpdateVariant is null ? null : baseline,
                    privateConnectionDeleteProfile ? baseline : null,
                    StatusVaultRecoverCancellationSelector(selector) ? baseline : null,
                    StatusVaultUpdateCancellationSelector(selector) ? baseline : null);
                var plan = new Plan(source, owner, selector, snapshot.LeaseId, vault, deleted, preparation, seedCanary,
                    policyChildren: children.ToArray(), ownedNotificationNames: ownedNotificationNames, manifest: rows,
                    privateEndpoint: declaration, originalCreate: createVaultVariant is not null,
                    originalRecover: recoverVaultVariant is not null,
                    originalPrivateConnectionUpdate: privateConnectionUpdateVariant is not null,
                    originalPrivateConnectionDelete: privateConnectionDeleteProfile,
                    statusSucceededDeleteVaultProfile: statusSucceededDeleteVaultProfile,
                    statusSucceededDeleteVaultIndependentProfile: statusSucceededDeleteVaultIndependentProfile,
                    statusSucceededDeleteVaultCancellationProfile: statusSucceededDeleteVaultCancellationProfile);
                if (pendingIndependentProfile is not null)
                    Require(pendingIndependentPlans.TryAdd(plan, pendingIndependentProfile));
                if (pendingCancellationProfile is not null)
                    Require(pendingCancellationPlans.TryAdd(plan, pendingCancellationProfile));
                if (failedCancellationProfile is not null) Require(failedCancellationPlans.TryAdd(plan, failedCancellationProfile));
                if (failedIndependentProfile is not null) Require(failedIndependentPlans.TryAdd(plan, failedIndependentProfile));
                if (canceledCancellationProfile is not null) Require(canceledCancellationPlans.TryAdd(plan, canceledCancellationProfile));
                if (canceledIndependentProfile is not null) Require(canceledIndependentPlans.TryAdd(plan, canceledIndependentProfile));
                if (canceledProfile is not null) Require(canceledPlans.TryAdd(plan, canceledProfile));
                if (deniedProfile is not null) Require(deniedPlans.TryAdd(plan, deniedProfile));
                if (failedProfile is not null) Require(failedPlans.TryAdd(plan, failedProfile));
                plans.Add(selector.Nonce, plan);
                return plan;
            }
        }
        catch { foreach (var child in children) child.Clear(); throw; }
    }

    internal RoleFixtureJournal.Snapshot CloseSelectedRoot(string owner, FixtureSelector selector)
    {
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(selector));
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(selector));
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) ||
            MatchesStatusDeniedNotificationOperation(selector));
        Require((deniedProfile is not null) == StatusDeniedPurgeSelector(selector));
        Require(deniedProfile is null || DeclaredDeniedSelector(selector));
        Require((failedCancellationProfile is not null) == StatusFailedPurgeCancellationSelector(selector));
        Require((failedIndependentProfile is not null) == StatusFailedPurgeIndependentSelector(selector));
        Require((canceledCancellationProfile is not null) == StatusCanceledPurgeCancellationSelector(selector));
        Require((canceledIndependentProfile is not null) == StatusCanceledPurgeIndependentSelector(selector));
        Require((canceledProfile is not null) == StatusCanceledPurgeSelector(selector));
        Require((failedProfile is not null) == StatusFailedPurgeSelector(selector));
        Require(!StatusPendingPurgeIndependentSelector(selector) || pendingIndependentProfile is not null);
        Require(!StatusPendingPurgeCancellationSelector(selector) || pendingCancellationProfile is not null);
        Require(pendingCancellationProfile is null || StatusPendingPurgeCancellationSelector(selector));
        Plan? retained;
        lock (plans) plans.TryGetValue(selector.Nonce, out retained);
        return journal.Close(owner, selector, snapshot => snapshot.Resources.Length == 0 ||
            MatchesHost(snapshot) && (retained is null || MatchesPlan(retained, snapshot)) &&
            (!StatusDeniedPrivateConnectionDeleteSelector(selector) || RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(snapshot)));
    }

    internal async ValueTask<Result> ProvisionAsync(Plan plan, SecretMaterial? transientCanary = null,
        CancellationToken cancellationToken = default, CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CheckPlan(plan);
        if (StatusDeniedVaultUpdateSelector(plan.Selector))
        {
            TrackDeniedVaultUpdate(plan, cancellationToken, originalCallerToken ?? cancellationToken);
            if (HasStatusDeniedVaultUpdatePersistence(plan)) RetryStatusDeniedVaultUpdatePersistence(plan);
            CheckDeniedVaultUpdateLifetime(plan, ReadPlan(plan.Owner, plan.Selector));
            Require(!HasStatusDeniedVaultUpdatePersistence(plan));
        }
        Require(baselineConfiguration is not null && !plan.Restored && (!plan.SeedCanary || transientCanary is not null));
        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector))
        {
            TrackDeniedPrivateDelete(plan, cancellationToken, originalCallerToken ?? cancellationToken);
            CheckDeniedPrivateDeleteLifetime(plan);
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector))
            unknownNotificationUpdateCancellationTokens.TryAdd(plan, [cancellationToken, originalCallerToken ?? cancellationToken]);
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector))
            unknownNotificationUpdateIndependentTokens.TryAdd(plan, [cancellationToken, originalCallerToken ?? cancellationToken]);

        if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector))
            deniedNotificationUpdateTokens.TryAdd(plan, [cancellationToken, originalCallerToken ?? cancellationToken]);
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector))
            unknownNotificationUpdateTokens.TryAdd(plan, [cancellationToken, originalCallerToken ?? cancellationToken]);
        if (PendingSelector(plan.Selector))
            pendingCallers.TryAdd(plan, [cancellationToken, originalCallerToken ?? cancellationToken]);
        TrackPrivateUpdateIndependentCaller(plan, cancellationToken, originalCallerToken ?? cancellationToken);
        if (Interlocked.CompareExchange(ref plan.Consumed, 1, 0) != 0) throw Failure();
        Enter(plan);
        try
        {
            if (StatusPrivateConnectionUpdateIndependentSelector(plan.Selector))
                privateUpdateIndependentSetup[plan] = BeginPrivateUpdateIndependentFixture(plan, plan.VaultId, false,
                    cancellationToken, originalCallerToken ?? cancellationToken);
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. privateUpdateIndependentTokens.GetValueOrDefault(plan, []), cancellationToken, deadline.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(!snapshot.Closing && (StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)
                ? privateUpdateIndependentSetup.TryGetValue(plan, out var admitted) &&
                    RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(admitted, snapshot)
                : snapshot.Resources.All(r => !r.CreateAttempted)));
            // Never adopt even a same-nonce preexisting object.
            Require(await ReadVault(plan, linked.Token).ConfigureAwait(false) is null &&
                await ReadDeleted(plan, linked.Token).ConfigureAwait(false) is null);
            if (plan.Preparation == Preparation.Absent)
                return await ObserveCore(plan, linked.Token).ConfigureAwait(false);
            State created = await Mutate(plan, plan.VaultId, Action.CreateVault, async (boundary, token) =>
            {
                var properties = new KeyVaultProperties(baseline.TenantId,
                    new(KeyVaultSkuFamily.A, baseline.Sku == VaultSku.Standard ? KeyVaultSkuName.Standard : KeyVaultSkuName.Premium))
                {
                    EnableRbacAuthorization = baseline.Rbac,
                    EnableSoftDelete = true,
                    EnablePurgeProtection = baseline.PurgeProtection,
                    SoftDeleteRetentionInDays = baseline.RetentionDays,
                    PublicNetworkAccess = baseline.PublicNetworkAccess ? "Enabled" : "Disabled",
                    CreateMode = KeyVaultCreateMode.Default
                };
                // Mark explicitly empty SDK change-tracking collections as
                // defined; omission must not substitute a different baseline.
                properties.AccessPolicies.Clear();
                foreach (var policy in baseline.Policies)
                {
                    var permissions = new IdentityAccessPermissions();
                    permissions.Secrets.Clear();
                    foreach (var permission in policy.Permissions)
                        permissions.Secrets.Add(new IdentityAccessSecretPermission(permission.ToString().ToLowerInvariant()));
                    properties.AccessPolicies.Add(new KeyVaultAccessPolicy(policy.TenantId, policy.PrincipalId.ToString("D"), permissions)
                    {
                        ApplicationId = policy.ApplicationId
                    });
                }
                var content = new KeyVaultCreateOrUpdateContent(host.Location, properties);
                content.Tags.Add(OwnershipTag, plan.Selector.Nonce.ToString("N"));
                var operation = await Arm(setupArm, boundary).GetResourceGroupResource(new(GroupId)).GetKeyVaults()
                    .CreateOrUpdateAsync(WaitUntil.Started, plan.VaultName, content, token).ConfigureAwait(false);
                if (operation.HasValue) ValidateVaultData(plan, operation.Value.Data, selected: false);
                return operation;
            }, linked.Token, fixtureCallerCancellation: originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (created != State.Ready) return Finish(created, plan);
            var result = await Downstream(plan, transientCanary, linked.Token,
                originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (result.State == State.Ready)
                lock (plans) originalReady.Add(plan);
            return result;
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    // Explicit continuation only for never-attempted downstream setup. A lost
    // mutation cannot be retried here; caller must retain the original plan.
    internal async ValueTask<Result> ContinueAsync(Plan plan, SecretMaterial? transientCanary = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CheckPlan(plan);
        Require(!StatusDeniedVaultUpdateSelector(plan.Selector));
        Require(!StatusDeniedPrivateConnectionDeleteSelector(plan.Selector));
        Require(!PendingSelector(plan.Selector) && !StatusPrivateConnectionUpdateIndependentSelector(plan.Selector) && !PurgeDeletedVaultSelector(plan.Selector) && !plan.OriginalCreate && !plan.OriginalRecover &&
            !plan.OriginalPrivateConnectionUpdate && !plan.OriginalPrivateConnectionDelete &&
            !StatusVaultRecoverCancellationSelector(plan.Selector) && !StatusVaultUpdateCancellationSelector(plan.Selector));
        Require(baselineConfiguration is not null && !plan.Restored && plan.Consumed == 1 && (!plan.SeedCanary || transientCanary is not null));
        Enter(plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(!snapshot.Closing);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            if (plan.Preparation == Preparation.Absent) return await ObserveCore(plan, linked.Token).ConfigureAwait(false);
            Require(snapshot.Resources.Single(r => r.Id == plan.VaultId).CreateAttempted);
            var result = await Downstream(plan, transientCanary, linked.Token).ConfigureAwait(false);
            if (result.State == State.Ready)
                lock (plans) originalReady.Add(plan);
            return result;
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    private async Task<Result> Downstream(Plan plan, SecretMaterial? material, CancellationToken token,
        CancellationToken originalCallerToken = default)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(!snapshot.Closing && snapshot.Idle);
        if (plan.Preparation == Preparation.Deleted && snapshot.Resources.Single(r => r.Id == plan.DeletedId).CreateAttempted)
            return await ObserveCore(plan, token).ConfigureAwait(false);
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        Require(vault is not null);
        ValidateVault(plan, vault);
        if (!Succeeded(vault)) return Finish(State.Pending, plan);
        Require(await ReadDeleted(plan, token).ConfigureAwait(false) is null);
        if (plan.SeedCanary)
        {
            Require(material is not null);
            string text = material.Reveal();
            Require(text.Length is > 0 and <= 4096 && Encoding.UTF8.GetByteCount(text) <= limits.MaximumResponseBytes);
            string digest = Hash(text);
            Require(plan.CanarySha256 is null || plan.CanarySha256 == digest);
            plan.CanarySha256 = digest;
            if (!snapshot.Resources.Single(r => r.Id == plan.SecretId).CreateAttempted)
            {
                // The native SDK exposes an immutable managed string; it cannot
                // be overwritten. Keep it local, never in the retained receipt.
                State set = await Mutate(plan, plan.SecretId, Action.SetCanary, async (boundary, ct) =>
                {
                    var response = await Secret(setupSecret, plan, boundary)
                        .SetSecretAsync(new KeyVaultSecret(Canary, text), ct).ConfigureAwait(false);
                    using var raw = response.GetRawResponse();
                    ValidateSecret(plan, response.Value);
                    Require(Hash(response.Value.Value) == digest);
                    plan.CanaryVersion = response.Value.Properties.Version;
                    return null;
                }, token, text).ConfigureAwait(false);
                if (set != State.Ready) return Finish(set, plan);
            }
            var canary = await ReadCanary(plan, token).ConfigureAwait(false);
            Require(canary.Digest == plan.CanarySha256 && canary.Version == plan.CanaryVersion);
        }
        if (plan.Preparation == Preparation.Deleted)
        {
            if (PurgeDeletedVaultSelector(plan.Selector))
                await CapturePurgePreparation(plan, token).ConfigureAwait(false);
            if (plan.OriginalRecover || StatusVaultRecoverCancellationSelector(plan.Selector))
                await CaptureRecoverPreparation(plan, token).ConfigureAwait(false);
            State deleted = await Mutate(plan, plan.DeletedId, Action.PrepareDeletedVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                    .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                fixtureCallerCancellation: originalCallerToken).ConfigureAwait(false);
            if (deleted != State.Ready) return Finish(deleted, plan);
        }
        if (PendingSelector(plan.Selector))
        {
            bool ready = await ReadPendingPair(plan, false, token, originalCallerToken).ConfigureAwait(false);
            if (ready) lock (plans) prepared.Add(plan);
            return new()
            {
                State = ready ? State.Ready : State.Incomplete, Journal = ReadPlan(plan.Owner, plan.Selector),
                VaultPresent = false, DeletedVaultPresent = ready, Receipts = plan.Receipts
            };
        }
        foreach (var child in plan.PolicyChildren)
        {
            snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(!snapshot.Closing);
            if (child.Prepared) continue;
            string id = plan.VaultId + "/secrets/" + child.Name;
            if (snapshot.Resources.Single(r => r.Id == id).CreateAttempted) return Finish(State.Incomplete, plan);
            State prepared = await PreparePolicyChild(plan, child, token).ConfigureAwait(false);
            if (prepared != State.Ready) return Finish(prepared, plan);
        }
        var result = await ObserveCore(plan, token).ConfigureAwait(false);
        if (result.State == State.Ready)
            lock (plans) prepared.Add(plan);
        return result;
    }

    // An observation is never native settlement and never continues setup.
    internal async ValueTask<Result> ObserveAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var plan = Reconstruct(ReadPlan(owner, selector));
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            if (PendingSelector(selector))
            {
                var pending = ReadPlan(owner, selector);
                if (!pending.Idle || pending.Closing || plan.Restored ||
                    pending.Resources[2] is not { CreateAttempted: true, InvocationTerminated: true })
                    return Finish(State.Incomplete, plan);
                bool ready = await ReadPendingPair(plan, false, linked.Token, cancellationToken).ConfigureAwait(false);
                return new()
                {
                    State = ready ? State.Ready : State.Incomplete, Journal = ReadPlan(owner, selector),
                    VaultPresent = false, DeletedVaultPresent = ready, Receipts = plan.Receipts
                };
            }
            if ((SettingsSelector(selector) || DeleteVaultSelector(selector) || PurgeDeletedVaultSelector(selector) ||
                plan.OriginalCreate || plan.OriginalRecover || plan.OriginalPrivateConnectionUpdate ||
                plan.OriginalPrivateConnectionDelete) &&
                !ReadPlan(owner, selector).Idle)
                return Finish(State.Pending, plan);
            return await ObserveCore(plan, linked.Token).ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    internal async ValueTask<Result> ReleaseAsync(string owner, FixtureSelector selector, bool purge = false,
        CancellationToken cancellationToken = default, bool requireActiveVaultAbsent = false,
        PrivateEndpointFixtureProvisioner? privateEndpointCleanup = null, bool requireOriginalDeletedReadRoot = false,
        CancellationToken? originalCallerToken = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(selector));
        if (statusDeniedVaultUpdateProfile)
        {
            Require(purge && !requireActiveVaultAbsent && !requireOriginalDeletedReadRoot && privateEndpointCleanup is null);
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null && HasStatusDeniedVaultUpdatePersistence(retained))
            {
                if (!TryEnter(retained)) return Finish(State.Pending, retained);
                try { return Finish(RetryStatusDeniedVaultUpdatePersistence(retained).Released ? State.Released : State.Closing, retained); }
                finally { Exit(retained); }
            }
        }
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(selector));
        if (StatusDeniedPrivateConnectionDeleteSelector(selector))
        {
            Require(purge && !requireActiveVaultAbsent && !requireOriginalDeletedReadRoot);
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null && HasStatusDeniedPrivateConnectionDeletePersistence(retained))
            {
                if (!TryEnter(retained)) return Finish(State.Pending, retained);
                try
                {
                    var exact = RetryStatusDeniedPrivateConnectionDeletePersistence(retained);
                    return Finish(exact.Released ? State.Released : State.Closing, retained);
                }
                finally { Exit(retained); }
            }
        }
        Require(!DeletedVaultListReadSelector(selector) || requireOriginalDeletedReadRoot);
        Require(!purge || host.AllowPurge);
        Require(!requireOriginalDeletedReadRoot || purge && !requireActiveVaultAbsent && privateEndpointCleanup is null);
        if (StatusCanceledPurgeCancellationSelector(selector) || StatusCanceledPurgeIndependentSelector(selector) || StatusCanceledPurgeSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null && pendingPersistence.ContainsKey(retained))
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                if (!TryEnter(retained)) return Finish(State.Pending, retained);
                try
                {
                    pendingCallers.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                        (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                    var persisted = RetryPendingFixturePersistence(retained);
                    return new() { State = persisted.Released ? State.Released : State.Closing, Journal = persisted,
                        Receipts = retained.Receipts, CanarySha256 = retained.CanarySha256, CanaryVersion = retained.CanaryVersion };
                }
                finally { Exit(retained); }
            }
        }
        if (StatusDeniedPurgeSelector(selector) || StatusFailedPurgeSelector(selector) || StatusFailedPurgeIndependentSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null && pendingPersistence.ContainsKey(retained))
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                if (!TryEnter(retained)) return Finish(State.Pending, retained);
                try
                {
                    pendingCallers.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                        (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                    var persisted = RetryPendingFixturePersistence(retained);
                    return Finish(persisted.Released ? State.Released : State.Closing, retained);
                }
                finally { Exit(retained); }
            }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null)
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                unknownNotificationUpdateCancellationTokens.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                    (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                StatusUnknownNotificationUpdateCancellationFixtureDrain? drain;
                lock (plans) drain = retained.Receipts.Select(r => unknownNotificationUpdateCancellationPending.GetValueOrDefault(r)).FirstOrDefault(d => d is not null);
                if (unknownNotificationUpdateCancellationPendingAbsence.TryGetValue(retained, out var absence) || drain is not null)
                {
                    if (!TryEnter(retained)) return Finish(State.Pending, retained);
                    try
                    {
                        var committed = absence is not null ? PersistUnknownNotificationUpdateCancellationAbsence(retained, absence) :
                            PersistUnknownNotificationUpdateCancellationFixture(drain!);
                        return new() { State = committed.Released ? State.Released : committed.Closing ? State.Closing : State.Ready,
                            Journal = committed, Receipts = retained.Receipts };
                    }
                    finally { Exit(retained); }
                }
            }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null)
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                unknownNotificationUpdateIndependentTokens.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                    (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                StatusUnknownNotificationUpdateIndependentFixtureDrain? drain;
                lock (plans) drain = retained.Receipts.Select(r => unknownNotificationUpdateIndependentPending.GetValueOrDefault(r)).FirstOrDefault(d => d is not null);
                if (unknownNotificationUpdateIndependentPendingAbsence.TryGetValue(retained, out var absence) || drain is not null)
                {
                    if (!TryEnter(retained)) return Finish(State.Pending, retained);
                    try
                    {
                        var committed = absence is not null ? PersistUnknownNotificationUpdateIndependentAbsence(retained, absence) :
                            PersistUnknownNotificationUpdateIndependentFixture(drain!);
                        return new() { State = committed.Released ? State.Released : committed.Closing ? State.Closing : State.Ready,
                            Journal = committed, Receipts = retained.Receipts };
                    }
                    finally { Exit(retained); }
                }
            }
        }

        if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null)
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                deniedNotificationUpdateTokens.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                    (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                StatusDeniedNotificationUpdateFixtureDrain? drain;
                lock (plans) drain = retained.Receipts.Select(r => deniedNotificationUpdatePending.GetValueOrDefault(r)).FirstOrDefault(d => d is not null);
                if (deniedNotificationUpdatePendingAbsence.TryGetValue(retained, out var absence) || drain is not null)
                {
                    if (!TryEnter(retained)) return Finish(State.Pending, retained);
                    try
                    {
                        var committed = absence is not null ? PersistDeniedNotificationUpdateAbsence(retained, absence) :
                            PersistDeniedNotificationUpdateFixture(drain!);
                        return new() { State = committed.Released ? State.Released : committed.Closing ? State.Closing : State.Ready,
                            Journal = committed, Receipts = retained.Receipts };
                    }
                    finally { Exit(retained); }
                }
            }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector))
        {
            Plan? retained;
            lock (plans) plans.TryGetValue(selector.Nonce, out retained);
            if (retained is not null)
            {
                CheckPlan(retained);
                Require(retained.Owner == owner && retained.Selector == selector);
                unknownNotificationUpdateTokens.AddOrUpdate(retained, [cancellationToken, originalCallerToken ?? cancellationToken],
                    (_, old) => [.. old, cancellationToken, originalCallerToken ?? cancellationToken]);
                StatusUnknownNotificationUpdateFixtureDrain? drain;
                lock (plans) drain = retained.Receipts.Select(r => unknownNotificationUpdatePending.GetValueOrDefault(r)).FirstOrDefault(d => d is not null);
                if (unknownNotificationUpdatePendingAbsence.TryGetValue(retained, out var absence) || drain is not null)
                {
                    if (!TryEnter(retained)) return Finish(State.Pending, retained);
                    try
                    {
                        var committed = absence is not null ? PersistUnknownNotificationUpdateAbsence(retained, absence) :
                            PersistUnknownNotificationUpdateFixture(drain!);
                        return new() { State = committed.Released ? State.Released : committed.Closing ? State.Closing : State.Ready,
                            Journal = committed, Receipts = retained.Receipts };
                    }
                    finally { Exit(retained); }
                }
            }
        }
        var snapshot = CloseSelectedRoot(owner, selector);
        Require(!StatusVaultDeleteCancellationSelector(selector) || !snapshot.Resources.Any(r => r.SelectedAttempted) ||
            purge && requireActiveVaultAbsent && privateEndpointCleanup is null && !requireOriginalDeletedReadRoot);
        bool selectedStatusPurge = StatusVaultPurgeCancellationSelector(selector) &&
            snapshot.Resources.Any(r => r.SelectedAttempted);
        bool statusRecovery = StatusVaultRecoverCancellationSelector(selector);
        bool statusUpdate = StatusVaultUpdateCancellationSelector(selector);
        bool selectedStatusRecovery = statusRecovery && snapshot.Resources.Any(r => r.SelectedAttempted);
        bool selectedStatusUpdate = statusUpdate && snapshot.Resources.Any(r => r.SelectedAttempted);
        Require(!(statusRecovery || statusUpdate) || purge && !requireActiveVaultAbsent &&
            privateEndpointCleanup is null && !requireOriginalDeletedReadRoot);
        Require(!selectedStatusPurge || !purge && requireActiveVaultAbsent &&
            privateEndpointCleanup is null && !requireOriginalDeletedReadRoot);
        Require(snapshot.CreateOrUpdateVault is null ||
            (StatusDeniedVaultUpdateSelector(selector) || CreateOrUpdateVaultSelector(selector)) && purge && !requireActiveVaultAbsent &&
            !requireOriginalDeletedReadRoot && privateEndpointCleanup is null);
        Require(snapshot.RecoverVault is null || RecoverVaultSelector(selector) && purge &&
            !requireActiveVaultAbsent && !requireOriginalDeletedReadRoot && privateEndpointCleanup is null);
        bool originalDelete = DeleteVaultSelector(selector);
        Require(!originalDelete || snapshot.Resources.Length == 0 || snapshot.DeleteVault is not null);
        if (originalDelete && snapshot.DeleteVault?.Disposition == RoleFixtureJournal.DeleteVaultDisposition.Deleted)
            requireActiveVaultAbsent = true;
        bool selectedDeleteCleanup = purge && requireActiveVaultAbsent && !originalDelete;
        Require(!selectedDeleteCleanup || snapshot.Resources.Length != 0);
        if (snapshot.Resources.Length == 0) return new() { State = State.Released, Journal = snapshot };
        var plan = Reconstruct(ReadPlan(owner, selector));
        TrackPrivateUpdateIndependentCaller(plan, cancellationToken, originalCallerToken ?? cancellationToken);
        if (StatusDeniedPrivateConnectionDeleteSelector(selector))
            TrackDeniedPrivateDelete(plan, cancellationToken, originalCallerToken ?? cancellationToken);
        if (StatusPrivateConnectionUpdateIndependentSelector(selector) && privateUpdateIndependentPendingAbsence.TryGetValue(plan, out var retainedAbsence))
            return Finish(PersistPrivateUpdateIndependentAbsence(plan, retainedAbsence).Released ? State.Released : State.Closing, plan);
        Require(!requireOriginalDeletedReadRoot || DeletedVaultReadCleanupRoot(plan, snapshot));
        if (!snapshot.Idle ||
            !TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)
                ? CancellationTokenSource.CreateLinkedTokenSource([.. privateUpdateIndependentTokens.GetValueOrDefault(plan, []), cancellationToken, deadline.Token])
                : CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            snapshot = ReadPlan(owner, selector);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            if (StatusDeniedVaultUpdateSelector(selector))
                return await ReleaseDeniedVaultUpdate(plan, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (PendingSelector(selector))
                return await ReleasePendingPurge(plan, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false);
            if (plan.StatusSucceededDeleteVaultCancellationProfile)
                return await ReleaseStatusSucceededDeleteVaultCancellation(plan, purge, linked.Token, cancellationToken).ConfigureAwait(false);
            if (plan.StatusSucceededDeleteVaultIndependentProfile)
                return await ReleaseStatusSucceededDeleteVaultIndependent(plan, purge, linked.Token).ConfigureAwait(false);
            if (plan.StatusSucceededDeleteVaultProfile)
                return await ReleaseStatusSucceededDeleteVault(plan, purge, linked.Token).ConfigureAwait(false);
            if (selectedStatusPurge)
                return await ReleaseStatusVaultPurgeCancellation(plan, linked.Token).ConfigureAwait(false);
            if (PurgeDeletedVaultSelector(selector))
                return await ReleasePurgeDeletedVault(plan, purge, linked.Token).ConfigureAwait(false);
            if (plan.OriginalRecover)
                return await ReleaseRecoverVault(plan, linked.Token).ConfigureAwait(false);
            Require(!originalDelete || OriginalDeleteCleanupRoot(plan, snapshot));
            Require(!plan.OriginalCreate || CreateVaultCleanupRoot(plan, snapshot));
            Require(!statusRecovery || StatusVaultRecoverCancellationCleanupRoot(plan, snapshot));
            Require(!statusUpdate || StatusVaultUpdateCancellationCleanupRoot(plan, snapshot));
            Require(!requireOriginalDeletedReadRoot || DeletedVaultReadCleanupRoot(plan, snapshot));
            if (!await RefreshPrivateEndpointDependencies(plan, privateEndpointCleanup, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false))
                return Finish(State.Closing, plan);
            // Only the original selected DeleteVault root may combine these
            // flags. Read the closed journal again, not the pre-close snapshot
            // or a caller's notion of native completion.
            Require(!selectedDeleteCleanup || SelectedDeleteCleanupRoot(plan, snapshot));
            Require(!purge || !snapshot.Resources.Single(r => r.Id == plan.DeletedId).SelectedAttempted);
            var vault = await ReadVault(plan, linked.Token).ConfigureAwait(false);
            if (vault is not null)
            {
                Presence(plan, plan.VaultId);
                Presence(plan, plan.SecretId);
                ValidateVault(plan, vault);
                if (requireActiveVaultAbsent || requireOriginalDeletedReadRoot) return Finish(State.Uncertain, plan);
                if (!Terminal(vault)) return Finish(State.Pending, plan);
                // A selected runtime update legitimately replaces the prepared
                // digest/version. Root ownership and dispatch fencing still apply;
                // preparation equality is not an invariant of cleanup afterward.
                if (!plan.Restored && snapshot.Resources.Single(r => r.Id == plan.SecretId) is
                    { CreateAttempted: true, SelectedAttempted: false })
                    _ = await ReadCanary(plan, linked.Token).ConfigureAwait(false);
            }
            var deleted = await ReadDeleted(plan, linked.Token).ConfigureAwait(false);
            if (deleted is not null)
            {
                Presence(plan, plan.DeletedId);
                Presence(plan, plan.SecretId);
                ValidateDeleted(plan, deleted);
            }
            Require(vault is null || deleted is null);
            var vaultRow = snapshot.Resources.Single(r => r.Id == plan.VaultId);
            if (statusRecovery && (vault is not null && vaultRow.DeleteAttempted ||
                selectedStatusRecovery && vault is null && !vaultRow.DeleteAttempted))
                return Finish(State.Uncertain, plan);
            if (statusUpdate && (vault is not null && vaultRow.DeleteAttempted ||
                selectedStatusUpdate && vault is null && !vaultRow.DeleteAttempted))
                return Finish(State.Uncertain, plan);
            if (vault is not null && !requireOriginalDeletedReadRoot && !vaultRow.DeleteAttempted)
            {
                if (!await RefreshPrivateEndpointDependencies(plan, privateEndpointCleanup, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false))
                    return Finish(State.Closing, plan);
                State outcome = await Mutate(plan, plan.VaultId, Action.DeleteVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), linked.Token,
                        fixtureCallerCancellation: originalCallerToken ?? cancellationToken).ConfigureAwait(false);
                if (plan.OwnedNotificationNames.Count != 0)
                    return Finish(ReadPlan(owner, selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty)
                        ? State.Pending : outcome == State.Ready ? State.Closing : outcome, plan);
            }
            snapshot = ReadPlan(owner, selector);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            vault = await ReadVault(plan, linked.Token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, linked.Token).ConfigureAwait(false);
            if (vault is not null)
            {
                Presence(plan, plan.VaultId);
                ValidateVault(plan, vault);
                if (statusRecovery || statusUpdate || requireActiveVaultAbsent || requireOriginalDeletedReadRoot) return Finish(State.Uncertain, plan);
            }
            if (deleted is not null) { Presence(plan, plan.DeletedId); ValidateDeleted(plan, deleted); }
            if (purge && vault is null && deleted is not null && deleted.Properties.PurgeProtectionEnabled == false &&
                !snapshot.Resources.Single(r => r.Id == plan.DeletedId).DeleteAttempted)
            {
                Require(!requireOriginalDeletedReadRoot || DeletedVaultReadCleanupRoot(plan, snapshot, requirePrepared: true));
                if (!await RefreshPrivateEndpointDependencies(plan, privateEndpointCleanup, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false))
                    return Finish(State.Closing, plan);
                State outcome = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                        .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), linked.Token,
                    selectedDeleteCleanup: selectedDeleteCleanup,
                    originalDeletedReadCleanup: requireOriginalDeletedReadRoot,
                    fixtureCallerCancellation: originalCallerToken ?? cancellationToken).ConfigureAwait(false);
                if (plan.OwnedNotificationNames.Count != 0)
                    return Finish(ReadPlan(owner, selector).Resources.Any(r => r.ActiveDispatch != Guid.Empty)
                        ? State.Pending : outcome == State.Ready ? State.Closing : outcome, plan);
            }
            snapshot = ReadPlan(owner, selector);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            if (plan.PrivateEndpoint is null && !NotificationsAbsent(plan, snapshot)) return Finish(State.Closing, plan);
            if ((StatusDeniedPrivateConnectionDeleteSelector(selector) || StatusPrivateConnectionUpdateIndependentSelector(selector)) &&
                !await RefreshPrivateEndpointDependencies(plan, privateEndpointCleanup, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false))
                return Finish(State.Closing, plan);
            // Final independent reads follow every actual native invocation.
            vault = await ReadVault(plan, linked.Token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, linked.Token).ConfigureAwait(false);
            if (vault is not null)
            {
                Presence(plan, plan.VaultId);
                Presence(plan, plan.SecretId);
                ValidateVault(plan, vault);
                if (statusRecovery || statusUpdate || requireActiveVaultAbsent || requireOriginalDeletedReadRoot) return Finish(State.Uncertain, plan);
            }
            if (deleted is not null)
            {
                Presence(plan, plan.DeletedId);
                Presence(plan, plan.SecretId);
                ValidateDeleted(plan, deleted);
            }
            if (StatusDeniedPrivateConnectionDeleteSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordDeniedPrivateDeleteAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                return Finish(ReadPlan(owner, selector).Released ? State.Released : State.Closing, plan);
            }
            if (StatusPrivateConnectionUpdateIndependentSelector(selector))
            {
                if (vault is null && deleted is null) RecordPrivateUpdateIndependentParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordNotificationCreateIndependentParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordUnknownNotificationUpdateCancellationParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordUnknownNotificationUpdateIndependentParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }

            if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordDeniedNotificationUpdateParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordUnknownNotificationUpdateParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector))
            {
                if (vault is null && deleted is null)
                    RecordNotificationUpdateParentAbsence(plan, linked.Token, originalCallerToken ?? cancellationToken);
                snapshot = ReadPlan(owner, selector);
                return Finish(snapshot.Released ? State.Released : State.Closing, plan);
            }
            if (vault is null) journal.RecordAbsence(owner, selector, plan.VaultId);
            if (deleted is null) journal.RecordAbsence(owner, selector, plan.DeletedId);
            // A logical secret cannot be hard-absent while either vault form
            // still retains its contents. No data-plane purge is substituted.
            if (vault is null && deleted is null)
            {
                journal.RecordAbsence(owner, selector, plan.SecretId);
                foreach (var child in plan.PolicyChildren)
                    journal.RecordAbsence(owner, selector, plan.VaultId + "/secrets/" + child.Name);
            }
            if (!await RefreshPrivateEndpointDependencies(plan, privateEndpointCleanup, linked.Token, originalCallerToken ?? cancellationToken).ConfigureAwait(false))
                return Finish(State.Closing, plan);
            snapshot = journal.Read(owner, selector);
            return Finish(snapshot.Released ? State.Released : deleted is not null ? State.SoftDeleted : State.Closing, plan);
        }
        catch (Exception exception)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Finish(FailureState(exception), plan);
        }
        finally { Exit(plan); }
    }

    private async Task<bool> RefreshPrivateEndpointDependencies(Plan plan,
        PrivateEndpointFixtureProvisioner? cleanup, CancellationToken token, CancellationToken? originalCallerToken = null)
    {
        if (plan.PrivateEndpoint is null) return true;
        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector))
            deniedPrivateDeleteAbsences.TryRemove(plan, out _);
        // The caller explicitly supplies its child source. No stored worker,
        // automatic retry, caller measurement, or synthetic child is admitted.
        if (cleanup is null) return false;
        var result = await cleanup.RefreshAbsenceForParentAsync(this, plan, token, originalCallerToken).ConfigureAwait(false);
        return result.State == PrivateEndpointFixtureProvisioner.CleanupState.DependenciesAbsent &&
            MatchesPlan(plan, result.Journal) && result.Journal.PrivateEndpointAbsent;
    }

    private async Task<Result> ReleaseStatusSucceededDeleteVault(Plan plan, bool purge, CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(purge && host.AllowPurge && snapshot.Closing && snapshot.Idle &&
            RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) && MatchesPlan(plan, snapshot));
        // A later release must prove absence again, even if a previous release
        // completed. Failed or malformed reads cannot republish old absence.
        Presence(plan, plan.VaultId);
        Presence(plan, plan.DeletedId);
        Presence(plan, plan.SecretId);
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var typed = snapshot.StatusSucceededDeleteVault!;
        var row = snapshot.Resources.Single(r => r.Id == plan.VaultId);
        if (vault is not null)
        {
            if (typed.InvocationDispatch != Guid.Empty || row.DeleteAttempted || deleted is not null)
                return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededCleanup(plan, plan.VaultId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.VaultId, Action.DeleteVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededCleanup: admission).ConfigureAwait(false);
            }
            finally { statusSucceededCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
            vault = await ReadVault(plan, token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        }
        else if (row.CreateAttempted && typed.InvocationDispatch == Guid.Empty && !row.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        if (vault is not null) return Finish(State.Uncertain, plan);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var deletedRow = snapshot.Resources.Single(r => r.Id == plan.DeletedId);
        if (deleted is not null)
        {
            if (deletedRow.DeleteAttempted) return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededCleanup(plan, plan.DeletedId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                        .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededCleanup: admission).ConfigureAwait(false);
            }
            finally { statusSucceededCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
        }
        else if (row.CreateAttempted && !deletedRow.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        // Never let a prior absence, native mutation response, or reconstructed
        // receipt stand in for the final two independently drained reads.
        if (await ReadVault(plan, token).ConfigureAwait(false) is not null ||
            await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
            return Finish(State.Uncertain, plan);
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);
    }

    private StatusSucceededDeleteVaultCleanupAdmission FreezeStatusSucceededCleanup(Plan plan, string resourceId,
        CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        StatusSucceededCleanupRead active, deleted;
        lock (plans)
        {
            Require(statusSucceededCleanupReads.TryGetValue(plan, out var reads) &&
                reads.Active is not null && reads.Deleted is not null && reads.Deleted.Revision == snapshot.Revision);
            active = reads.Active;
            deleted = reads.Deleted;
            statusSucceededCleanupReads.Remove(plan);
        }
        var admission = new StatusSucceededDeleteVaultCleanupAdmission(this);
        Require(statusSucceededCleanupAdmissions.TryAdd(admission,
            new(plan, resourceId, snapshot.Revision, active, deleted, token)));
        return admission;
    }

    private async Task<Result> ReleaseStatusSucceededDeleteVaultIndependent(Plan plan, bool purge, CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(purge && host.AllowPurge && snapshot.Closing && snapshot.Idle &&
            RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) && MatchesPlan(plan, snapshot));
        // A later release must prove absence again, even if a previous release
        // completed. Failed or malformed reads cannot republish old absence.
        Presence(plan, plan.VaultId);
        Presence(plan, plan.DeletedId);
        Presence(plan, plan.SecretId);
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var typed = snapshot.StatusSucceededDeleteVault!;
        var row = snapshot.Resources.Single(r => r.Id == plan.VaultId);
        if (vault is not null)
        {
            if (typed.InvocationDispatch != Guid.Empty || row.DeleteAttempted || deleted is not null)
                return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededIndependentCleanup(plan, plan.VaultId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.VaultId, Action.DeleteVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededIndependentCleanup: admission).ConfigureAwait(false);
            }
            finally { statusSucceededIndependentCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
            vault = await ReadVault(plan, token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        }
        else if (row.CreateAttempted && typed.InvocationDispatch == Guid.Empty && !row.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        if (vault is not null) return Finish(State.Uncertain, plan);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var deletedRow = snapshot.Resources.Single(r => r.Id == plan.DeletedId);
        if (deleted is not null)
        {
            if (deletedRow.DeleteAttempted) return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededIndependentCleanup(plan, plan.DeletedId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                        .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededIndependentCleanup: admission).ConfigureAwait(false);
            }
            finally { statusSucceededIndependentCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
        }
        else if (row.CreateAttempted && !deletedRow.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        // Never let a prior absence, native mutation response, or reconstructed
        // receipt stand in for the final two independently drained reads.
        if (await ReadVault(plan, token).ConfigureAwait(false) is not null ||
            await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
            return Finish(State.Uncertain, plan);
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);
    }

    private StatusSucceededDeleteVaultIndependentCleanupAdmission FreezeStatusSucceededIndependentCleanup(Plan plan, string resourceId,
        CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        StatusSucceededCleanupRead active, deleted;
        lock (plans)
        {
            Require(statusSucceededCleanupReads.TryGetValue(plan, out var reads) &&
                reads.Active is not null && reads.Deleted is not null && reads.Deleted.Revision == snapshot.Revision);
            active = reads.Active;
            deleted = reads.Deleted;
            statusSucceededCleanupReads.Remove(plan);
        }
        var admission = new StatusSucceededDeleteVaultIndependentCleanupAdmission(this);
        Require(statusSucceededIndependentCleanupAdmissions.TryAdd(admission,
            new(plan, resourceId, snapshot.Revision, active, deleted, token)));
        return admission;
    }

    private async Task<Result> ReleaseStatusSucceededDeleteVaultCancellation(Plan plan, bool purge, CancellationToken token,
        CancellationToken callerCancellation)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(purge && host.AllowPurge && snapshot.Closing && snapshot.Idle &&
            RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot) && MatchesPlan(plan, snapshot));
        // A later release must prove absence again, even if a previous release
        // completed. Failed or malformed reads cannot republish old absence.
        Presence(plan, plan.VaultId);
        Presence(plan, plan.DeletedId);
        Presence(plan, plan.SecretId);
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var typed = snapshot.StatusSucceededDeleteVault!;
        var row = snapshot.Resources.Single(r => r.Id == plan.VaultId);
        if (vault is not null)
        {
            if (typed.InvocationDispatch != Guid.Empty || row.DeleteAttempted || deleted is not null)
                return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededCancellationCleanup(plan, plan.VaultId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.VaultId, Action.DeleteVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                        .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededCancellationCleanup: admission, fixtureCallerCancellation: callerCancellation).ConfigureAwait(false);
            }
            finally { statusSucceededCancellationCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
            vault = await ReadVault(plan, token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        }
        else if (row.CreateAttempted && typed.InvocationDispatch == Guid.Empty && !row.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        if (vault is not null) return Finish(State.Uncertain, plan);
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        var deletedRow = snapshot.Resources.Single(r => r.Id == plan.DeletedId);
        if (deleted is not null)
        {
            if (deletedRow.DeleteAttempted) return Finish(State.Uncertain, plan);
            var admission = FreezeStatusSucceededCancellationCleanup(plan, plan.DeletedId, token);
            State result;
            try
            {
                result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                    async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                        .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token,
                    statusSucceededCancellationCleanup: admission, fixtureCallerCancellation: callerCancellation).ConfigureAwait(false);
            }
            finally { statusSucceededCancellationCleanupAdmissions.TryRemove(admission, out _); }
            if (result != State.Ready) return Finish(result, plan);
        }
        else if (row.CreateAttempted && !deletedRow.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        // Never let a prior absence, native mutation response, or reconstructed
        // receipt stand in for the final two independently drained reads.
        if (await ReadVault(plan, token).ConfigureAwait(false) is not null ||
            await ReadDeleted(plan, token).ConfigureAwait(false) is not null)
            return Finish(State.Uncertain, plan);
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);
    }

    private StatusSucceededDeleteVaultCancellationCleanupAdmission FreezeStatusSucceededCancellationCleanup(Plan plan, string resourceId,
        CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        StatusSucceededCleanupRead active, deleted;
        lock (plans)
        {
            Require(statusSucceededCleanupReads.TryGetValue(plan, out var reads) &&
                reads.Active is not null && reads.Deleted is not null && reads.Deleted.Revision == snapshot.Revision);
            active = reads.Active;
            deleted = reads.Deleted;
            statusSucceededCleanupReads.Remove(plan);
        }
        var admission = new StatusSucceededDeleteVaultCancellationCleanupAdmission(this);
        Require(statusSucceededCancellationCleanupAdmissions.TryAdd(admission,
            new(plan, resourceId, FreezeStatusSucceededCancellationSnapshot(snapshot), active, deleted, token)));
        return admission;
    }

    private async Task<T?> ReadStatusSucceededArm<T>(Plan plan, string id,
        Func<ArmClient, CancellationToken, Task<Response<T>>> read, CancellationToken token) where T : class
    {
        var baseline = PendingSelector(plan.Selector)
            ? ReadPlan(plan.Owner, plan.Selector).PurgeDeletedVault!.Baseline : StatusSucceededConfiguration(plan);
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(snapshot.Idle && (id == plan.VaultId || id == plan.DeletedId));
        lock (plans)
        {
            var old = statusSucceededCleanupReads.GetValueOrDefault(plan);
            statusSucceededCleanupReads[plan] = id == plan.VaultId ? (null, null) : (old.Active, null);
        }
        using var boundary = new StatusSucceededReadTransport(this, plan, id,
            PendingSelector(plan.Selector) ? RoleFixtureJournal.CopyStatusPendingPurgeSnapshot(snapshot) :
            plan.StatusSucceededDeleteVaultCancellationProfile ? FreezeStatusSucceededCancellationSnapshot(snapshot) : null);
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/locations/deletedVaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        var client = new ArmClient(new AudienceCredential(readArm.Credential, ArmOrigin + "/.default"), null, options);
        Task<Response<T>> task = read(client, token);
        T? result = null;
        try
        {
            var response = await task.ConfigureAwait(false);
            Require(boundary.Body is { Response.Status: 200 } && boundary.Parser is { Complete: true, Invalid: false } &&
                boundary.Parser.Owns(response.GetRawResponse()));
            result = response.Value;
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            if (result is KeyVaultResource vault)
                ManagementOperationResourceCollector.ValidateStatusSucceededActive(raw.RootElement, vault.Data,
                    plan.VaultId, plan.Selector.Nonce, baseline);
            else if (result is DeletedKeyVaultResource deleted)
            {
                if (PendingSelector(plan.Selector))
                    ValidatePendingDeleted(raw.RootElement, deleted.Data, plan, baseline);
                else ManagementOperationResourceCollector.ValidateStatusSucceededDeleted(raw.RootElement, deleted.Data,
                    plan.DeletedId, plan.VaultId, plan.Selector.Nonce, baseline);
            }
            else throw Failure();
        }
        catch (RequestFailedException error) when (error.Status == 404 && error.ErrorCode == "ResourceNotFound")
        {
            Require(task.IsFaulted && boundary.Body is { Response.Status: 404 } &&
                boundary.Parser is { Complete: true, Invalid: false });
            using var raw = JsonDocument.Parse(boundary.Body.Bytes);
            ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
        }
        token.ThrowIfCancellationRequested();
        boundary.Dispose();
        Require(boundary.Parser is { Complete: true, Invalid: false });
        var completed = ReadPlan(plan.Owner, plan.Selector);
        Require(completed.Idle && (!plan.StatusSucceededDeleteVaultCancellationProfile ||
            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(snapshot, completed)));
        Require(!PendingSelector(plan.Selector) ||
            RoleFixtureJournal.SameStatusPendingPurgeSnapshot(snapshot, completed));
        snapshot = completed;
        lock (plans)
        {
            var fact = new StatusSucceededCleanupRead(plan, id, task, result is null ? 404 : 200, snapshot.Revision,
                ++statusSucceededReadOrdinal);
            var pair = statusSucceededCleanupReads.GetValueOrDefault(plan);
            statusSucceededCleanupReads[plan] = id == plan.VaultId ? (fact, null) : (pair.Active, fact);
        }
        return result;
    }

    private static void ValidatePendingDeleted(JsonElement root, DeletedKeyVaultData native, Plan plan,
        VaultAdministrationEffects.Configuration baseline)
    {
        Require(root.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(
            new[] { "id", "name", "type", "properties" }.Order()) &&
            root.GetProperty("id").GetString() == plan.DeletedId && root.GetProperty("name").GetString() == plan.VaultName &&
            root.GetProperty("type").GetString() == "Microsoft.KeyVault/deletedVaults");
        var p = root.GetProperty("properties");
        Require(p.EnumerateObject().Select(p => p.Name).Order().SequenceEqual(
            new[] { "vaultId", "location", "tags", "purgeProtectionEnabled", "deletionDate", "scheduledPurgeDate" }.Order()) &&
            p.GetProperty("vaultId").GetString() == plan.VaultId && p.GetProperty("location").GetString() == baseline.Location &&
            p.GetProperty("tags").EnumerateObject().Count() == 1 &&
            p.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
            p.GetProperty("purgeProtectionEnabled").ValueKind == JsonValueKind.False &&
            p.GetProperty("scheduledPurgeDate").GetDateTimeOffset() - p.GetProperty("deletionDate").GetDateTimeOffset() ==
                TimeSpan.FromDays(baseline.RetentionDays));
        Require(native.Id?.ToString() == plan.DeletedId && native.Name == plan.VaultName &&
            native.ResourceType.ToString() == "Microsoft.KeyVault/deletedVaults" && native.Properties.VaultId == plan.VaultId &&
            native.Properties.Location == baseline.Location && native.Properties.Tags.Count == 1 &&
            native.Properties.Tags.TryGetValue(OwnershipTag, out var label) && label == plan.Selector.Nonce.ToString("N") &&
            native.Properties.PurgeProtectionEnabled == false &&
            native.Properties.DeletedOn == p.GetProperty("deletionDate").GetDateTimeOffset() &&
            native.Properties.ScheduledPurgeOn == p.GetProperty("scheduledPurgeDate").GetDateTimeOffset());
    }

    private sealed class StatusSucceededReadTransport(VaultFixtureProvisioner owner, Plan plan, string id,
        RoleFixtureJournal.Snapshot? cancellationPreimage = null)
        : HttpPipelineTransport, IDisposable
    {
        private readonly OwnedArmResponse.Storage storage = new();
        private Request? request;
        private int sends;
        internal OwnedArmResponse.Body? Body;
        internal OwnedArmResponse.ParserCustody? Parser;
        internal int? ObservedStatus;
        public override Request CreateRequest()
        {
            Require(request is null);
            return request = owner.readArm.Transport.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            Require(++sends == 1 && ReferenceEquals(request, message.Request));
            var headers = message.Request.Headers.ToArray();
            void Check()
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(ReferenceEquals(request, message.Request) && headers.SequenceEqual(message.Request.Headers) &&
                    message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    message.Request.Uri.ToUri().AbsoluteUri == ArmOrigin + id + "?api-version=" + Revision &&
                    message.Request.Headers.TryGetValue("Authorization", out var auth) &&
                    auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
                    !headers.Any(h => new[] { "Content-Length", "Content-Encoding", "Transfer-Encoding", "Range", "Content-Range" }
                        .Contains(h.Name, StringComparer.OrdinalIgnoreCase)));
                Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                        !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)));
                if (message.Request.Headers.TryGetValue("Host", out var host)) Require(host == "management.azure.com");
                var current = owner.ReadPlan(plan.Owner, plan.Selector);
                Require((StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)
                    ? owner.PrivateUpdateIndependentReadAllowed(plan, current) : current.Idle) && (cancellationPreimage is null ||
                    (StatusPrivateConnectionUpdateIndependentSelector(plan.Selector)
                        ? owner.PrivateUpdateIndependentLive(plan) && RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(cancellationPreimage, current)
                        : PendingSelector(plan.Selector)
                        ? owner.pendingCallers.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusPendingPurgeSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(plan.Selector)
                        ? RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector)
                        ? owner.unknownNotificationUpdateCancellationTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector)
                        ? owner.unknownNotificationUpdateIndependentTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector)
                        ? owner.deniedNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector)
                        ? owner.unknownNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(cancellationPreimage, current)
                        : NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(plan.Selector)
                        ? RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(cancellationPreimage, current)
                        : RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(cancellationPreimage, current))));
            }
            Check();
            message.BufferResponse = false;
            try { await owner.readArm.Transport.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (message.HasResponse)
                {
                    storage.Own(message.Response);
                    ObservedStatus = message.Response.Status;
                    // This also runs when the backend throws after a response.
                    if (message.Response.Status == 200 && (!StatusPrivateConnectionUpdateIndependentSelector(plan.Selector) ||
                        cancellationPreimage is null || cancellationPreimage.Resources.Single(r => r.Id == id).Absent))
                    {
                        owner.Presence(plan, id);
                        owner.Presence(plan, plan.SecretId);
                    }
                }
            }
            Check();
            var response = message.Response;
            var stream = response.ContentStream;
            Body = await OwnedArmResponse.CaptureAsync(message, owner.limits.MaximumResponseBytes, storage).ConfigureAwait(false);
            Check();
            Require(ReferenceEquals(response.ContentStream, stream) && Body.Response.Status is 200 or 404);
            using var raw = JsonDocument.Parse(Body.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
            BoundaryTransport.Unique(raw.RootElement);
            if (Body.Response.Status == 404) ManagementOperationResourceCollector.ValidateStatusSucceededAbsence(raw.RootElement);
            Parser = OwnedArmResponse.ParserCustody.Install(message, Body.Response, Body.Bytes, storage,
                requireRebuffer: false, requireDownstreamRead: true);
        }
        public void Dispose() => storage.Dispose();
    }

    internal async ValueTask<Result> SettleAsync(string owner, FixtureSelector selector,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(selector));
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(selector));
        var snapshot = journal.Read(owner, selector);
        return snapshot.Resources.Length == 0
            ? new() { State = State.Released, Journal = snapshot }
            : await SettleAsync(Reconstruct(ReadPlan(owner, selector)), cancellationToken).ConfigureAwait(false);
    }

    // At most one explicit native UpdateStatusAsync per outstanding receipt.
    // A restart has no retained tasks/handles and cannot establish settlement.
    internal async ValueTask<Result> SettleAsync(Plan plan, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        CheckPlan(plan);
        if (StatusDeniedVaultUpdateSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                if (HasStatusDeniedVaultUpdatePersistence(plan)) RetryStatusDeniedVaultUpdatePersistence(plan);
                return Finish(State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                if (HasStatusDeniedPrivateConnectionDeletePersistence(plan))
                    RetryStatusDeniedPrivateConnectionDeletePersistence(plan);
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (PendingSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                if (pendingPersistence.ContainsKey(plan)) RetryPendingFixturePersistence(plan);
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (StatusPrivateConnectionUpdateIndependentSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusPrivateConnectionUpdateIndependentFixtureDrain? drain;
                    lock (plans) privateUpdateIndependentPending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistPrivateUpdateIndependentFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusNotificationCreateIndependentFixtureDrain? drain;
                    lock (plans) notificationCreateIndependentPending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistNotificationCreateIndependentFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusUnknownNotificationUpdateCancellationFixtureDrain? drain;
                    lock (plans) unknownNotificationUpdateCancellationPending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistUnknownNotificationUpdateCancellationFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusUnknownNotificationUpdateIndependentFixtureDrain? drain;
                    lock (plans) unknownNotificationUpdateIndependentPending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistUnknownNotificationUpdateIndependentFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }

        if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusDeniedNotificationUpdateFixtureDrain? drain;
                    lock (plans) deniedNotificationUpdatePending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistDeniedNotificationUpdateFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusUnknownNotificationUpdateFixtureDrain? drain;
                    lock (plans) unknownNotificationUpdatePending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistUnknownNotificationUpdateFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(plan.Selector))
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    StatusNotificationUpdateIndependentFixtureDrain? drain;
                    lock (plans) notificationUpdatePending.TryGetValue(receipt, out drain);
                    if (drain is null) continue;
                    PersistNotificationUpdateFixture(drain);
                    cancellationToken.ThrowIfCancellationRequested();
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (plan.StatusSucceededDeleteVaultCancellationProfile)
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                foreach (var receipt in plan.Receipts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    StatusSucceededDeleteVaultCancellationFixtureDrain? drain;
                    lock (plans) statusSucceededCancellationReceipts.TryGetValue(receipt, out drain);
                    if (drain is not null && statusSucceededCancellationFixtureDrains.ContainsKey(drain))
                    {
                        var current = ReadPlan(plan.Owner, plan.Selector);
                        if (current.Resources.Any(r => r.ActiveDispatch == drain.Dispatch))
                            PersistStatusSucceededCancellationFixture(drain);
                    }
                }
                return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (plan.StatusSucceededDeleteVaultIndependentProfile)
        {
            if (!TryEnter(plan)) return Finish(State.Pending, plan);
            try
            {
                var snapshot = ReadPlan(plan.Owner, plan.Selector);
                Require(RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) && MatchesPlan(plan, snapshot));
                foreach (var receipt in plan.Receipts)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    StatusSucceededIndependentDrain? retained;
                    lock (plans) statusSucceededIndependentDrains.TryGetValue(receipt, out retained);
                    if (retained is null) continue;
                    var row = snapshot.Resources.SingleOrDefault(r => r.Id == retained.ResourceId &&
                        r.ActiveDispatch == retained.Dispatch);
                    if (row is null || snapshot.StatusSucceededDeleteVault!.InvocationDispatch == retained.Dispatch) continue;
                    // Only source-retained completed setup/cleanup custody can retry
                    // this local append. Reconstructed plans have no such receipt.
                    if (!row.InvocationTerminated || retained.Settled)
                        snapshot = journal.EndDispatch(plan.Owner, plan.Selector, retained.ResourceId,
                            retained.Dispatch, retained.Settled);
                }
                return Finish(snapshot.Idle ? State.Ready : State.Pending, plan);
            }
            finally { Exit(plan); }
        }
        if (plan.StatusSucceededDeleteVaultProfile)
            return Finish(ReadPlan(plan.Owner, plan.Selector).Idle ? State.Ready : State.Pending, plan);
        if (!TryEnter(plan)) return Finish(State.Pending, plan);
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            foreach (var receipt in plan.Receipts)
            {
                if (receipt.Dispatch == Guid.Empty || !receipt.Terminated) continue;
                var row = journal.Read(plan.Owner, plan.Selector).Resources.SingleOrDefault(r => r.ActiveDispatch == receipt.Dispatch);
                if (row is null) continue;
                // Retained completion precedes persistence. Retrying this append
                // recovers local file contention, never a provider mutation.
                if (!row.InvocationTerminated || receipt.RemoteSettled)
                {
                    journal.EndDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch, receipt.RemoteSettled);
                    if (receipt.RemoteSettled) continue;
                }
                if (receipt.NativeOperation is null || receipt.Boundary is not { CanCheckStatus: true } boundary) continue;
                boundary.BeginStatus();
                try
                {
                    receipt.StatusTask = receipt.NativeOperation.UpdateStatusAsync(linked.Token).AsTask();
                    using var response = await receipt.StatusTask.ConfigureAwait(false);
                    if (boundary.Valid && boundary.TerminalStatus && receipt.NativeOperation.HasCompleted)
                    {
                        receipt.RemoteSettled = true;
                        receipt.Outcome = boundary.SucceededStatus ? State.Ready : State.Uncertain;
                    }
                }
                catch (Exception)
                {
                    // Failed/canceled native terminal states may throw; they
                    // drain only with both native completion and validated wire state.
                    if (!linked.IsCancellationRequested && boundary.Valid && boundary.TerminalStatus &&
                        receipt.NativeOperation.HasCompleted)
                    {
                        receipt.RemoteSettled = true;
                        receipt.Outcome = State.Uncertain;
                    }
                }
                finally
                {
                    boundary.Dispose();
                    if (receipt.RemoteSettled)
                        journal.SettleDispatch(plan.Owner, plan.Selector, row.Id, receipt.Dispatch);
                }
                cancellationToken.ThrowIfCancellationRequested();
            }
            var final = journal.Read(plan.Owner, plan.Selector);
            return Finish(!final.Idle ? State.Pending :
                final.PrivateEndpoint is not null && final.Closing ? State.Closing :
                plan.Restored && final.PrivateEndpoint is not null ? State.Incomplete : State.Ready, plan);
        }
        finally { Exit(plan); }
    }

    private async Task<State> Mutate(Plan plan, string journalId, Action action,
        Func<BoundaryTransport, CancellationToken, Task<Operation?>> invoke, CancellationToken token, string? ownedCanary = null,
        bool selectedDeleteCleanup = false, bool originalDeletedReadCleanup = false,
        StatusSucceededDeleteVaultCleanupAdmission? statusSucceededCleanup = null,
        StatusSucceededDeleteVaultIndependentCleanupAdmission? statusSucceededIndependentCleanup = null,
        StatusSucceededDeleteVaultCancellationCleanupAdmission? statusSucceededCancellationCleanup = null,
        CancellationToken fixtureCallerCancellation = default)
    {
        if (StatusDeniedVaultUpdateSelector(plan.Selector))
            return await MutateDeniedVaultUpdate(plan, journalId, action, invoke, token, fixtureCallerCancellation).ConfigureAwait(false);
        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector))
            return await MutateDeniedPrivateDelete(plan, journalId, action, invoke, token, fixtureCallerCancellation).ConfigureAwait(false);
        bool independentPrivateUpdate = StatusPrivateConnectionUpdateIndependentSelector(plan.Selector);
        bool independentCreate = NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(plan.Selector);
        bool unknownNotificationUpdateCancellation = NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector);
        bool unknownNotificationUpdateIndependent = NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector);

        bool deniedNotificationUpdate = NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector);
        bool unknownNotificationUpdate = NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector);
        bool independent = unknownNotificationUpdateCancellation || unknownNotificationUpdateIndependent || deniedNotificationUpdate || unknownNotificationUpdate || NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(plan.Selector) || independentCreate || independentPrivateUpdate;
        bool secret = action == Action.SetCanary;
        bool cleanup = action is Action.DeleteVault or Action.PurgeVault;
        bool deleting = action is Action.PrepareDeletedVault or Action.DeleteVault;
        var receipt = new Receipt(action, journalId);
        bool pending = PendingSelector(plan.Selector);
        RoleFixtureJournal.Snapshot? pendingAdmitted = pending
            ? BeginPendingFixture(plan, journalId, cleanup, token, fixtureCallerCancellation) : null;
        Task<Operation?>? pendingNativeTask = null;
        Operation? pendingNativeOperation = null;
        Task<Response>? pendingStatusTask = null;
        bool pendingTerminal = false;
        if (pendingAdmitted is not null)
        {
            receipt.Dispatch = pendingAdmitted.Resources.Single(r => r.Id == journalId).ActiveDispatch;
            receipt.Attempted = true;
        }
        RoleFixtureJournal.Snapshot? privateSetup = null;
        if (independentPrivateUpdate && !cleanup)
            Require(action == Action.CreateVault && privateUpdateIndependentSetup.TryRemove(plan, out privateSetup));
        var independentCommitted = unknownNotificationUpdateCancellation
            ? BeginUnknownNotificationUpdateCancellationFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : unknownNotificationUpdateIndependent
            ? BeginUnknownNotificationUpdateIndependentFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : deniedNotificationUpdate
            ? BeginDeniedNotificationUpdateFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : unknownNotificationUpdate
            ? BeginUnknownNotificationUpdateFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : independentPrivateUpdate
            ? privateSetup ?? BeginPrivateUpdateIndependentFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : independentCreate
            ? BeginNotificationCreateIndependentFixture(plan, journalId, cleanup, token, fixtureCallerCancellation)
            : independent ? BeginNotificationUpdateFixture(plan, journalId, cleanup, token, fixtureCallerCancellation) : null;
        if (independentCommitted is not null)
        {
            receipt.Dispatch = independentCommitted.Resources.Single(r => r.Id == journalId).ActiveDispatch;
            receipt.Attempted = true;
        }
        Guid privateUpdateDispatch = independentPrivateUpdate ? independentCommitted!.Resources.Single(r => r.Id == journalId).ActiveDispatch : Guid.Empty;
        Task<Operation?>? privateUpdateNativeTask = null;
        Task<Response>? privateUpdateStatusTask = null;
        Operation? privateUpdateOperation = null;
        bool privateUpdateSettled = false;
        RoleFixtureJournal.Snapshot? cancellationPreimage = null;
        Guid cancellationDispatch = Guid.Empty;
        Task<Operation?>? cancellationNativeTask = null;
        Task<Response>? cancellationStatusTask = null;
        Operation? cancellationOperation = null;
        bool cancellationSettled = false;
        State cancellationOutcome = State.Uncertain;
        lock (plan.History) plan.History.Add(receipt);
        using var boundary = new BoundaryTransport(secret ? setupSecret.Transport : setupArm.Transport,
            secret ? SecretOrigin(plan).GetLeftPart(UriPartial.Authority) : ArmOrigin,
            secret ? "/secrets/" + Canary : action == Action.PurgeVault ? plan.DeletedId + "/purge" : plan.VaultId,
            secret ? SecretRevision : Revision, action == Action.PurgeVault ? RequestMethod.Post :
                deleting ? RequestMethod.Delete : RequestMethod.Put, limits.MaximumResponseBytes, secret,
            SubscriptionId, host.Location, () =>
            {
                lock (plans)
                {
                    Require(!closed);
                    token.ThrowIfCancellationRequested();
                    if (pending)
                    {
                        fixtureCallerCancellation.ThrowIfCancellationRequested();
                        Require(pendingCallers.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                            RoleFixtureJournal.SameStatusPendingPurgeSnapshot(pendingAdmitted!, ReadPlan(plan.Owner, plan.Selector)));
                        return;
                    }
                    if (independent)
                    {
                        Require(!independentPrivateUpdate || PrivateUpdateIndependentLive(plan) && !fixtureCallerCancellation.IsCancellationRequested);
                        Require(!unknownNotificationUpdateCancellation || !fixtureCallerCancellation.IsCancellationRequested &&
                            unknownNotificationUpdateCancellationTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
                        Require(!unknownNotificationUpdateIndependent || !fixtureCallerCancellation.IsCancellationRequested &&
                            unknownNotificationUpdateIndependentTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));

                        Require(!deniedNotificationUpdate || !fixtureCallerCancellation.IsCancellationRequested &&
                            deniedNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
                        Require(!unknownNotificationUpdate || !fixtureCallerCancellation.IsCancellationRequested &&
                            unknownNotificationUpdateTokens.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested));
                        Require(unknownNotificationUpdateCancellation
                            ? RoleFixtureJournal.SameStatusUnknownNotificationUpdateCancellationSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : unknownNotificationUpdateIndependent
                            ? RoleFixtureJournal.SameStatusUnknownNotificationUpdateIndependentSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : deniedNotificationUpdate
                            ? RoleFixtureJournal.SameStatusDeniedNotificationUpdateSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : unknownNotificationUpdate
                            ? RoleFixtureJournal.SameStatusUnknownNotificationUpdateSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : independentPrivateUpdate
                            ? RoleFixtureJournal.SameStatusPrivateConnectionUpdateIndependentSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : independentCreate
                            ? RoleFixtureJournal.SameStatusNotificationCreateIndependentSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector))
                            : RoleFixtureJournal.SameStatusNotificationUpdateIndependentSnapshot(independentCommitted!, ReadPlan(plan.Owner, plan.Selector)));
                        return;
                    }
                    if (plan.StatusSucceededDeleteVaultCancellationProfile)
                    {
                        var current = ReadPlan(plan.Owner, plan.Selector);
                        if (cancellationDispatch == Guid.Empty)
                        {
                            Require(current.Idle);
                            if (cleanup)
                            {
                                cancellationPreimage = journal.BeginStatusSucceededDeleteVaultCancellationCleanupDispatch(plan.Owner, plan.Selector,
                                    plan.LeaseId, journalId, statusSucceededCancellationCleanup ?? throw Failure());
                                cancellationDispatch = cancellationPreimage.Resources.Single(r => r.Id == journalId).ActiveDispatch;
                            }
                            else
                            {
                                cancellationDispatch = journal.BeginDispatch(plan.Owner, plan.Selector, journalId, delete: false);
                                var expected = current with
                                {
                                    Revision = current.Revision + 1,
                                    Resources = current.Resources.Select(r => r.Id == journalId
                                        ? r with { CreateAttempted = true, ActiveDispatch = cancellationDispatch, InvocationTerminated = false }
                                        : r with { Absent = false }).ToArray()
                                };
                                Require(RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(expected,
                                    ReadPlan(plan.Owner, plan.Selector)));
                                cancellationPreimage = expected;
                            }
                            cancellationPreimage = FreezeStatusSucceededCancellationSnapshot(cancellationPreimage);
                            receipt.Dispatch = cancellationDispatch;
                            receipt.Attempted = true;
                        }
                        else Require(cancellationPreimage is not null &&
                            RoleFixtureJournal.SameStatusSucceededDeleteVaultCancellationSnapshot(cancellationPreimage, current));
                        return;
                    }
                    if (receipt.Dispatch == Guid.Empty)
                    {
                        var snapshot = ReadPlan(plan.Owner, plan.Selector);
                        Require(snapshot.Idle);
                        receipt.Dispatch = plan.StatusSucceededDeleteVaultIndependentProfile && cleanup
                            ? journal.BeginStatusSucceededDeleteVaultIndependentCleanupDispatch(plan.Owner, plan.Selector,
                                plan.LeaseId, journalId, statusSucceededIndependentCleanup ?? throw Failure())
                            : plan.StatusSucceededDeleteVaultProfile && cleanup
                            ? journal.BeginStatusSucceededDeleteVaultCleanupDispatch(plan.Owner, plan.Selector,
                                plan.LeaseId, journalId, statusSucceededCleanup ?? throw Failure())
                            : journal.BeginDispatch(plan.Owner, plan.Selector, journalId, cleanup,
                            cleanup ? snapshot => NotificationsAbsent(plan, snapshot) &&
                                (!StatusVaultUpdateCancellationSelector(plan.Selector) ||
                                    StatusVaultUpdateCancellationCleanupRoot(plan, snapshot) &&
                                    (action == Action.DeleteVault ? journalId == plan.VaultId &&
                                        !snapshot.Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted :
                                        action == Action.PurgeVault && journalId == plan.DeletedId &&
                                        snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                                        { CreateAttempted: true, DeleteAttempted: true, InvocationTerminated: true })) &&
                                (!StatusVaultRecoverCancellationSelector(plan.Selector) ||
                                    StatusVaultRecoverCancellationCleanupRoot(plan, snapshot) &&
                                    (action == Action.DeleteVault ? journalId == plan.VaultId &&
                                        !snapshot.Resources.Single(r => r.Id == plan.VaultId).DeleteAttempted :
                                        action == Action.PurgeVault && journalId == plan.DeletedId &&
                                        (!snapshot.Resources.Any(r => r.SelectedAttempted) ||
                                            snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                                            { DeleteAttempted: true, InvocationTerminated: true }))) &&
                                (!plan.OriginalRecover || RecoverVaultCleanupRoot(plan, snapshot) &&
                                    (action == Action.PurgeVault
                                        ? !snapshot.RecoverVault!.Baseline.PurgeProtection
                                        : action == Action.DeleteVault &&
                                            snapshot.RecoverVault!.Disposition == RoleFixtureJournal.RecoverVaultDisposition.Recovered)) &&
                                (!plan.OriginalCreate || CreateVaultCleanupRoot(plan, snapshot) &&
                                    (action != Action.PurgeVault ||
                                        !(snapshot.CreateOrUpdateVault!.Disposition == RoleFixtureJournal.CreateOrUpdateVaultDisposition.Updated
                                            ? snapshot.CreateOrUpdateVault.Selected
                                            : snapshot.CreateOrUpdateVault.Baseline).PurgeProtection)) &&
                                (!PurgeDeletedVaultSelector(plan.Selector) || action == Action.PurgeVault &&
                                    PurgeDeletedVaultCleanupRoot(plan, snapshot, requirePrepared: true) &&
                                    snapshot.PurgeDeletedVault!.Disposition != RoleFixtureJournal.PurgeDeletedVaultDisposition.Purged) &&
                                (!DeleteVaultSelector(plan.Selector) || OriginalDeleteCleanupRoot(plan, snapshot) &&
                                    (snapshot.DeleteVault!.Disposition != RoleFixtureJournal.DeleteVaultDisposition.Deleted ||
                                        action == Action.PurgeVault)) &&
                                (!selectedDeleteCleanup || SelectedDeleteCleanupRoot(plan, snapshot)) &&
                                (!originalDeletedReadCleanup || action == Action.PurgeVault &&
                                    DeletedVaultReadCleanupRoot(plan, snapshot, requirePrepared: true)) : null);
                        receipt.Attempted = true;
                    }
                    else
                    {
                        var snapshot = ReadPlan(plan.Owner, plan.Selector);
                        Require(snapshot.Closing == cleanup &&
                            snapshot.Resources.Single(r => r.Id == journalId).ActiveDispatch == receipt.Dispatch);
                    }
                }
            }, action == Action.CreateVault ? VaultShape : secret ? root => CanaryShape(plan, root) : null,
            ownedCanary: ownedCanary, statusSucceededCancellationMutation: pending || plan.StatusSucceededDeleteVaultCancellationProfile || independent,
            notificationUpdateIndependentMutation: independent || pending,
            failedPurgeMutation: (StatusDeniedPurgeSelector(plan.Selector) || StatusCanceledPurgeCancellationSelector(plan.Selector) || StatusCanceledPurgeIndependentSelector(plan.Selector) || StatusCanceledPurgeSelector(plan.Selector) || StatusFailedPurgeSelector(plan.Selector) || StatusFailedPurgeIndependentSelector(plan.Selector) || StatusFailedPurgeCancellationSelector(plan.Selector)) && action == Action.PurgeVault);
        receipt.Boundary = boundary;
        bool returned = false;
        try
        {
            if (pending)
            {
                pendingNativeTask = invoke(boundary, token);
                receipt.NativeTask = pendingNativeTask;
                pendingNativeOperation = await pendingNativeTask.ConfigureAwait(false);
                receipt.NativeOperation = pendingNativeOperation;
            }
            else if (independentPrivateUpdate)
            {
                privateUpdateNativeTask = invoke(boundary, token);
                receipt.NativeTask = privateUpdateNativeTask;
                privateUpdateOperation = await privateUpdateNativeTask.ConfigureAwait(false);
                receipt.NativeOperation = privateUpdateOperation;
            }
            else if (plan.StatusSucceededDeleteVaultCancellationProfile)
            {
                cancellationNativeTask = invoke(boundary, token);
                receipt.NativeTask = cancellationNativeTask;
                cancellationOperation = await cancellationNativeTask.ConfigureAwait(false);
                receipt.NativeOperation = cancellationOperation;
            }
            else
            {
                receipt.NativeTask = invoke(boundary, token);
                receipt.NativeOperation = await receipt.NativeTask.ConfigureAwait(false);
            }
            // The pinned ARM client retains a lazy operation even for a
            // synchronous 200 vault response. Resolve it with one bounded
            // native status update, not a polling loop or presence inference.
            // Explicit asynchronous starts remain pending for SettleAsync.
            if (pending && boundary.Status is 200 or 204 && !boundary.HasAsync &&
                pendingNativeOperation is { HasCompleted: false } pendingOperation)
            {
                boundary.BeginStatus();
                pendingStatusTask = pendingOperation.UpdateStatusAsync(token).AsTask();
                receipt.StatusTask = pendingStatusTask;
                using var status = await pendingStatusTask.ConfigureAwait(false);
            }
            else if (independentPrivateUpdate)
            {
                if (action is Action.CreateVault or Action.PurgeVault && boundary.Status == 200 && !boundary.HasAsync &&
                    privateUpdateOperation is { HasCompleted: false } actual)
                {
                    boundary.BeginStatus();
                    privateUpdateStatusTask = actual.UpdateStatusAsync(token).AsTask();
                    receipt.StatusTask = privateUpdateStatusTask;
                    using var status = await privateUpdateStatusTask.ConfigureAwait(false);
                }
            }
            else if (plan.StatusSucceededDeleteVaultCancellationProfile)
            {
                if (action is Action.CreateVault or Action.PurgeVault && boundary.Status == 200 && !boundary.HasAsync &&
                    cancellationOperation is { HasCompleted: false } actual)
                {
                    boundary.BeginStatus();
                    cancellationStatusTask = actual.UpdateStatusAsync(token).AsTask();
                    receipt.StatusTask = cancellationStatusTask;
                    using var status = await cancellationStatusTask.ConfigureAwait(false);
                }
            }
            else if (!pending && action is Action.CreateVault or Action.PurgeVault && boundary.Status == 200 && !boundary.HasAsync &&
                receipt.NativeOperation is { HasCompleted: false } synchronous)
            {
                boundary.BeginStatus();
                receipt.StatusTask = synchronous.UpdateStatusAsync(token).AsTask();
                using var status = await receipt.StatusTask.ConfigureAwait(false);
            }
            token.ThrowIfCancellationRequested();
            Require(boundary.Valid && boundary.Status is >= 200 and < 300);
            returned = true;
        }
        catch (Exception)
        {
            receipt.Outcome = boundary.Valid && boundary.Status is 401 or 403 ? State.Denied : State.Uncertain;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
        }
        finally
        {
            receipt.HttpStatus = boundary.Status;
            receipt.NativeRequestId = boundary.RequestId;
            receipt.Terminated = true;
            // A valid empty synchronous 204 is definitive even if the installed
            // ARM delete adapter cannot construct its optional operation body.
            // 202, async headers, cancellation and malformed/lost responses are
            // never this proof; resource readback cannot manufacture it.
            if (plan.StatusSucceededDeleteVaultCancellationProfile)
            {
                cancellationSettled = !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested &&
                    boundary.Valid && !boundary.HasAsync &&
                    (returned && boundary.Status != 202 && cancellationOperation?.HasCompleted == true ||
                        deleting && boundary.Status == 204 && boundary.EmptyBody);
                cancellationOutcome = cancellationSettled ? State.Ready : returned && cancellationOperation is not null ? State.Pending : State.Uncertain;
                receipt.RemoteSettled = cancellationSettled;
                receipt.Outcome = cancellationOutcome;
            }
            else if (!pending)
            {
                receipt.RemoteSettled = !token.IsCancellationRequested && boundary.Valid && !boundary.HasAsync &&
                    (receipt.Outcome == State.Denied || returned && boundary.Status != 202 &&
                        (secret || receipt.NativeOperation?.HasCompleted == true) ||
                        deleting && boundary.Status == 204 && boundary.EmptyBody);
                if (receipt.RemoteSettled && receipt.Outcome != State.Denied) receipt.Outcome = State.Ready;
                else if (returned && receipt.NativeOperation is not null) receipt.Outcome = State.Pending;
            }
            if (independentPrivateUpdate)
            {
                privateUpdateSettled = !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested &&
                    PrivateUpdateIndependentLive(plan) && boundary.Valid && !boundary.HasAsync && returned && boundary.Status is 200 or 201 or 204 &&
                    privateUpdateNativeTask is { IsCompletedSuccessfully: true } && privateUpdateOperation is { HasCompleted: true } &&
                    (privateUpdateStatusTask is null || privateUpdateStatusTask.IsCompletedSuccessfully);
                receipt.RemoteSettled = privateUpdateSettled;
                receipt.Outcome = privateUpdateSettled ? State.Ready : State.Uncertain;
            }
            else if (independent)
            {
                receipt.RemoteSettled = !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested &&
                    boundary.Valid && !boundary.HasAsync && returned && boundary.Status is 200 or 201 or 204 &&
                    receipt.NativeOperation is { HasCompleted: true } &&
                    (receipt.StatusTask is null || receipt.StatusTask.IsCompletedSuccessfully);
                receipt.Outcome = receipt.RemoteSettled ? State.Ready : State.Uncertain;
            }
            if (pending)
            {
                pendingTerminal = !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested &&
                    pendingCallers.GetValueOrDefault(plan, []).All(t => !t.IsCancellationRequested) &&
                    boundary.Valid && !boundary.HasAsync && returned && boundary.Status is 200 or 201 or 204 &&
                    pendingNativeTask is { IsCompletedSuccessfully: true } && pendingNativeOperation is { HasCompleted: true } &&
                    (pendingStatusTask is null || pendingStatusTask.IsCompletedSuccessfully);
                receipt.RemoteSettled = pendingTerminal;
                receipt.Outcome = pendingTerminal ? State.Ready : State.Uncertain;
            }
            if (pending || independent || plan.StatusSucceededDeleteVaultProfile || plan.StatusSucceededDeleteVaultIndependentProfile || plan.StatusSucceededDeleteVaultCancellationProfile)
            {
                // A typed setup/cleanup fence cannot become idle until response and
                // storage disposal really returned. A failed drain is permanent.
                try
                {
                    boundary.Dispose();
                    if (plan.StatusSucceededDeleteVaultIndependentProfile && receipt.Dispatch != Guid.Empty &&
                        receipt.NativeTask is { IsCompleted: true } &&
                        (receipt.StatusTask is null || receipt.StatusTask.IsCompleted))
                        lock (plans) statusSucceededIndependentDrains.Add(receipt,
                            new(journalId, receipt.Dispatch, receipt.RemoteSettled));
                }
                catch
                {
                    pendingTerminal = false;
                    privateUpdateSettled = false;
                    receipt.RemoteSettled = false;
                    receipt.Outcome = State.Uncertain;
                    if (plan.StatusSucceededDeleteVaultCancellationProfile)
                    {
                        cancellationSettled = false;
                        cancellationOutcome = State.Uncertain;
                    }
                }
            }
            // Set fields before append: actual completion survives file contention.
            if (pending)
            {
                pendingTerminal &= boundary.FixtureDrainComplete;
                if (pendingNativeTask is { IsCompleted: true } && boundary.FixturePhysicalDrainComplete)
                    EndPendingFixture(plan, journalId, pendingAdmitted!, pendingNativeTask, pendingStatusTask, boundary,
                        pendingTerminal, token, fixtureCallerCancellation);
            }
            else if (independentPrivateUpdate)
            {
                if (privateUpdateNativeTask is { IsCompleted: true } native && boundary.FixtureDrainComplete &&
                    !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested && PrivateUpdateIndependentLive(plan))
                    RetainPrivateUpdateIndependentFixtureDrain(plan, receipt, independentCommitted!, journalId, privateUpdateDispatch,
                        privateUpdateSettled, token, fixtureCallerCancellation,
                        privateUpdateStatusTask is null ? [native] : [native, privateUpdateStatusTask]);
                else journal.EndDispatch(plan.Owner, plan.Selector, journalId, privateUpdateDispatch, nativeSettled: false);
            }
            else if (independent)
            {
                if (receipt.NativeTask is { IsCompleted: true } native && boundary.FixtureDrainComplete &&
                    !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested)
                {
                    if (unknownNotificationUpdateCancellation)
                        RetainUnknownNotificationUpdateCancellationFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled && receipt.Outcome == State.Ready, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    else if (unknownNotificationUpdateIndependent)
                        RetainUnknownNotificationUpdateIndependentFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled && receipt.Outcome == State.Ready, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    else if (deniedNotificationUpdate)
                        RetainDeniedNotificationUpdateFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled && receipt.Outcome == State.Ready, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    else if (unknownNotificationUpdate)
                        RetainUnknownNotificationUpdateFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled && receipt.Outcome == State.Ready, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    else if (independentCreate)
                        RetainNotificationCreateIndependentFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                    else
                        RetainNotificationUpdateFixtureDrain(plan, receipt, independentCommitted!, journalId, receipt.Dispatch,
                            receipt.RemoteSettled, token, fixtureCallerCancellation,
                            receipt.StatusTask is null ? [native] : [native, receipt.StatusTask]);
                }
                else journal.EndDispatch(plan.Owner, plan.Selector, journalId, receipt.Dispatch, nativeSettled: false);
            }
            else if (plan.StatusSucceededDeleteVaultCancellationProfile)
            {
                if (cancellationDispatch != Guid.Empty)
                {
                    if (cancellationPreimage is not null && cancellationNativeTask is { IsCompleted: true } &&
                        (cancellationStatusTask is null || cancellationStatusTask.IsCompleted) &&
                        boundary.FixtureDrainComplete && !token.IsCancellationRequested && !fixtureCallerCancellation.IsCancellationRequested)
                    {
                        var drain = new StatusSucceededDeleteVaultCancellationFixtureDrain(this);
                        Require(statusSucceededCancellationFixtureDrains.TryAdd(drain, new(plan, cancellationPreimage,
                            journalId, cancellationDispatch, cancellationSettled, cancellationNativeTask, cancellationStatusTask, token, fixtureCallerCancellation)));
                        lock (plans) statusSucceededCancellationReceipts.Add(receipt, drain);
                        PersistStatusSucceededCancellationFixture(drain);
                    }
                    else journal.EndDispatch(plan.Owner, plan.Selector, journalId, cancellationDispatch, nativeSettled: false);
                }
            }
            else if (receipt.Dispatch != Guid.Empty)
                journal.EndDispatch(plan.Owner, plan.Selector, journalId, receipt.Dispatch, receipt.RemoteSettled);
        }
        return pending ? pendingTerminal ? State.Ready : State.Uncertain :
            independentPrivateUpdate ? privateUpdateSettled ? State.Ready : State.Uncertain :
            plan.StatusSucceededDeleteVaultCancellationProfile ? cancellationOutcome : receipt.Outcome;
    }

    private enum PolicyRequest { Get, GetDeleted, Set, Delete, Backup, Purge }
    private sealed class PolicyMissing : Exception { }

    private async Task<State> PreparePolicyChild(Plan plan, PolicyChild child, CancellationToken token)
    {
        Require(!plan.Restored && plan.Preparation == Preparation.Active && child.Desired is not null);
        var receipt = new Receipt(Action.PreparePolicyChild, plan.VaultId + "/secrets/" + child.Name);
        lock (plan.History) plan.History.Add(receipt);
        bool completed = false;
        try
        {
            receipt.NativeTask = Prepare();
            await receipt.NativeTask.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            child.Complete();
            completed = true;
            receipt.Outcome = State.Ready;
        }
        catch (Exception)
        {
            receipt.Outcome = State.Uncertain;
            if (token.IsCancellationRequested) throw new OperationCanceledException(token);
        }
        finally
        {
            receipt.Terminated = true;
            receipt.RemoteSettled = completed && !token.IsCancellationRequested;
            if (receipt.Dispatch != Guid.Empty)
                journal.EndDispatch(plan.Owner, plan.Selector, receipt.ResourceId, receipt.Dispatch, receipt.RemoteSettled);
        }
        return receipt.Outcome;

        async Task<Operation?> Prepare()
        {
            // One original dispatch owns preflight, actual Set, native backup,
            // deletion, purge and independent verification. It is never split
            // into selected attempts, and no subsequent step follows uncertainty.
            Require(!await ReadPolicyChild(plan, child, false, receipt, token).ConfigureAwait(false) &&
                !await ReadPolicyChild(plan, child, true, receipt, token).ConfigureAwait(false));
            using var material = child.CopySet();
            await PolicyCall(plan, child, PolicyRequest.Set, setupSecret, receipt, async client =>
            {
                var value = new KeyVaultSecret(child.Name, material.Reveal());
                value.Properties.Enabled = true;
                var response = await client.SetSecretAsync(value, token).ConfigureAwait(false);
                using var raw = response.GetRawResponse();
                ValidatePolicySecret(plan, child, response.Value.Properties, exactVersion: false);
                Require(Hash(response.Value.Value) == child.Sha256);
                child.CaptureVersion(response.Value.Properties.Version);
                return true;
            }, token).ConfigureAwait(false);
            if (child.RetainBackup)
                await PolicyCall(plan, child, PolicyRequest.Backup, setupSecret, receipt, async client =>
                {
                    var response = await client.BackupSecretAsync(child.Name, token).ConfigureAwait(false);
                    using var raw = response.GetRawResponse();
                    byte[] bytes = response.Value;
                    try
                    {
                        Require(bytes.Length > 0 && bytes.Length <= limits.MaximumResponseBytes);
                        child.CaptureBackup(bytes);
                    }
                    finally { CryptographicOperations.ZeroMemory(bytes); }
                    return true;
                }, token).ConfigureAwait(false);
            if (child.Desired != Preparation.Active)
            {
                await PolicyCall(plan, child, PolicyRequest.Delete, setupSecret, receipt, async client =>
                {
                    var operation = await client.StartDeleteSecretAsync(child.Name, token).ConfigureAwait(false);
                    ValidatePolicySecret(plan, child, operation.Value.Properties, exactVersion: true);
                    // Only the validated whole native 200 below settles this
                    // setup step. A completed SDK wrapper/202 is insufficient.
                    return true;
                }, token).ConfigureAwait(false);
                if (child.Desired == Preparation.Absent)
                {
                    Require(host.AllowPurge && !baseline.PurgeProtection);
                    await PolicyCall(plan, child, PolicyRequest.Purge, setupSecret, receipt, async client =>
                    {
                        using var response = await client.PurgeDeletedSecretAsync(child.Name, token).ConfigureAwait(false);
                        Require(response.Status == 204);
                        return true;
                    }, token).ConfigureAwait(false);
                }
            }
            Require(await ObservePolicyChild(plan, child, token, receipt).ConfigureAwait(false));
            return null;
        }
    }

    private async Task<bool> ObservePolicyChild(Plan plan, PolicyChild child, CancellationToken token, Receipt? setup = null)
    {
        bool active = await ReadPolicyChild(plan, child, false, setup, token).ConfigureAwait(false);
        bool deleted = await ReadPolicyChild(plan, child, true, setup, token).ConfigureAwait(false);
        return child.Desired switch
        {
            Preparation.Active => active && !deleted,
            Preparation.Deleted => !active && deleted,
            Preparation.Absent => !active && !deleted,
            _ => false
        };
    }

    private async Task<bool> ReadPolicyChild(Plan plan, PolicyChild child, bool deleted, Receipt? setup, CancellationToken token)
    {
        try
        {
            return await PolicyCall(plan, child, deleted ? PolicyRequest.GetDeleted : PolicyRequest.Get,
                readSecret, setup, async client =>
                {
                    if (deleted)
                    {
                        var response = await client.GetDeletedSecretAsync(child.Name, token).ConfigureAwait(false);
                        using var raw = response.GetRawResponse();
                        ValidatePolicySecret(plan, child, response.Value.Properties, exactVersion: true);
                    }
                    else
                    {
                        var response = await client.GetSecretAsync(child.Name, cancellationToken: token).ConfigureAwait(false);
                        using var raw = response.GetRawResponse();
                        ValidatePolicySecret(plan, child, response.Value.Properties, exactVersion: true);
                        Require(Hash(response.Value.Value) == child.Sha256);
                    }
                    return true;
                }, token).ConfigureAwait(false);
        }
        catch (PolicyMissing) { return false; }
    }

    private async Task<T> PolicyCall<T>(Plan plan, PolicyChild child, PolicyRequest request, Authority authority,
        Receipt? setup, Func<SecretClient, Task<T>> invoke, CancellationToken token)
    {
        var credential = new PolicyCredential(authority.Credential, time);
        Guid readDispatch = Guid.Empty;
        using var boundary = new PolicyBoundary(authority.Transport, credential, plan, child, request,
            limits.MaximumResponseBytes, time, () =>
            {
                lock (plans)
                {
                    Require(!closed);
                    var snapshot = ReadPlan(plan.Owner, plan.Selector);
                    Require(snapshot.LeaseId == plan.LeaseId && !snapshot.Closing &&
                        snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                        { Borrowed: false, CreateAttempted: true, DeleteAttempted: false, Absent: false } &&
                        snapshot.Resources.Single(r => r.Id == plan.VaultId + "/secrets/" + child.Name) is
                        { Borrowed: false, CleanupOnly: false, DeleteAttempted: false, SelectedAttempted: false });
                    Require(snapshot.Resources.Count(r => !r.Borrowed && r.Id.StartsWith(plan.VaultId + "/secrets/", StringComparison.Ordinal)) ==
                        plan.PolicyChildren.Count + 1 &&
                        plan.PolicyChildren.All(c => snapshot.Resources.Any(r => !r.Borrowed && r.Id == plan.VaultId + "/secrets/" + c.Name)));
                    if (setup is not null)
                    {
                        if (setup.Dispatch == Guid.Empty)
                        {
                            setup.Dispatch = journal.BeginDispatch(plan.Owner, plan.Selector, setup.ResourceId, delete: false);
                            setup.Attempted = true;
                        }
                        else Require(snapshot.Resources.Single(r => r.Id == setup.ResourceId).ActiveDispatch == setup.Dispatch &&
                            snapshot.Resources.Where(r => r.Id != setup.ResourceId).All(r => r.ActiveDispatch == Guid.Empty));
                    }
                    else readDispatch = journal.BeginSelectedRead(plan.Owner, plan.Selector, plan.LeaseId,
                        plan.VaultId + "/secrets/" + child.Name);
                }
            });
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01)
        {
            Transport = boundary,
            DisableChallengeResourceVerification = false
        };
        Quiet(options);
        var client = new SecretClient(SecretOrigin(plan), credential, options);
        try
        {
            // Await actual SDK serialization/credential/transport/parser tasks,
            // including borrowers which ignore caller cancellation.
            T value = await invoke(client).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            Require(boundary.Valid && boundary.Status == (request == PolicyRequest.Purge ? 204 : 200));
            return value;
        }
        catch (RequestFailedException) when (boundary.Valid && boundary.Status == 404 &&
            request is PolicyRequest.Get or PolicyRequest.GetDeleted)
        {
            token.ThrowIfCancellationRequested();
            throw new PolicyMissing();
        }
        finally
        {
            if (setup is not null)
            {
                setup.HttpStatus = boundary.Status;
                setup.NativeRequestId = boundary.RequestId;
            }
            if (readDispatch != Guid.Empty)
                journal.EndDispatch(plan.Owner, plan.Selector, plan.VaultId + "/secrets/" + child.Name, readDispatch);
        }
    }

    private void ValidatePolicySecret(Plan plan, PolicyChild child, Azure.Security.KeyVault.Secrets.SecretProperties properties, bool exactVersion)
    {
        Require(properties.Name == child.Name && properties.VaultUri == SecretOrigin(plan) &&
            properties.Version is { Length: 32 } version && version.All(char.IsAsciiHexDigit) &&
            properties.Id?.OriginalString == SecretOrigin(plan).GetLeftPart(UriPartial.Authority) + "/secrets/" + child.Name + "/" + version &&
            (!exactVersion || child.Version is null || version == child.Version) &&
            properties.Enabled == true &&
            (properties.NotBefore is null || properties.NotBefore <= time.GetUtcNow()) &&
            (properties.ExpiresOn is null || properties.ExpiresOn > time.GetUtcNow()));
    }

    internal sealed class PolicyCredential(TokenCredential inner, TimeProvider time) : TokenCredential
    {
        private const string Audience = "https://vault.azure.net/.default";
        private int calls;
        internal AccessToken? Issued { get; private set; }
        public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken) => throw Failure();
        public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Require(requestContext.Scopes.Length == 1 && requestContext.Scopes[0] == Audience &&
                Interlocked.Increment(ref calls) == 1);
            var issued = await inner.GetTokenAsync(new TokenRequestContext([Audience]), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            Require(issued.Token is { Length: > 0 and <= 16384 } && issued.ExpiresOn > time.GetUtcNow());
            Issued = issued;
            return issued;
        }
    }

    private sealed class PolicyBoundary(HttpPipelineTransport inner, PolicyCredential credential, Plan plan,
        PolicyChild child, PolicyRequest action, int maximum, TimeProvider time, System.Action beforeSend)
        : HttpPipelineTransport, IDisposable
    {
        private readonly List<MemoryStream> storage = [];
        private readonly List<RequestContent> contents = [];
        private Response? nativeResponse;
        private int sends;
        internal bool Valid { get; private set; }
        internal int? Status { get; private set; }
        internal string? RequestId { get; private set; }
        private string Origin => SecretOrigin(plan).GetLeftPart(UriPartial.Authority);
        public override Request CreateRequest() => inner.CreateRequest();
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            Require(Interlocked.Increment(ref sends) == 1);
            ValidateRequest(message);
            MemoryStream? canonical = null;
            if (action == PolicyRequest.Set)
            {
                canonical = new();
                storage.Add(canonical);
                using var material = child.CopySet();
                char[] characters = material.ExportCharacters();
                try
                {
                    using var writer = new Utf8JsonWriter(canonical);
                    writer.WriteStartObject();
                    writer.WriteString("value", characters);
                    writer.WriteStartObject("attributes");
                    writer.WriteBoolean("enabled", true);
                    writer.WriteEndObject();
                    writer.WriteEndObject();
                }
                finally { Array.Clear(characters); }
                Require(canonical.Length <= maximum);
                if (message.Request.Content is { } original)
                {
                    contents.Add(original);
                    Require(original.TryComputeLength(out long length) && length >= 0 && length <= maximum);
                    var serialized = new BoundedPolicyBuffer(maximum);
                    storage.Add(serialized);
                    await original.WriteToAsync(serialized, message.CancellationToken).ConfigureAwait(false);
                    Require(serialized.Length == length);
                    using var body = JsonDocument.Parse(serialized.GetBuffer().AsMemory(0, (int)serialized.Length),
                        new JsonDocumentOptions { MaxDepth = 8 });
                    BoundaryTransport.Unique(body.RootElement);
                    var root = body.RootElement;
                    Require(root.EnumerateObject().All(p => p.Name is "value" or "attributes") &&
                        Hash(root.GetProperty("value").GetString()!) == child.Sha256 &&
                        root.GetProperty("attributes").EnumerateObject().All(p => p.Name == "enabled") &&
                        root.GetProperty("attributes").GetProperty("enabled").ValueKind == JsonValueKind.True);
                }
            }
            var issued = credential.Issued ?? await credential.GetTokenAsync(
                new TokenRequestContext(["https://vault.azure.net/.default"]), message.CancellationToken).ConfigureAwait(false);
            message.CancellationToken.ThrowIfCancellationRequested();
            Require(issued.ExpiresOn > time.GetUtcNow());
            message.Request.Headers.SetValue("Authorization", "Bearer " + issued.Token);
            // Cold SDK challenges can remove the write body. Both cold and warm
            // paths send only canonical source bytes AFTER credential acquisition.
            if (canonical is not null)
            {
                var content = RequestContent.Create(canonical.GetBuffer().AsMemory(0, (int)canonical.Length));
                contents.Add(content);
                message.Request.Content = content;
                message.Request.Headers.SetValue("Content-Type", "application/json");
            }
            ValidateRequest(message);
            var headers = message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray();
            beforeSend();
            message.CancellationToken.ThrowIfCancellationRequested();
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally { if (message.HasResponse) nativeResponse = message.Response; }
            try
            {
                message.CancellationToken.ThrowIfCancellationRequested();
                ValidateRequest(message);
                Require(headers.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                Status = message.Response.Status;
                Require(Status is 200 or 204 or 403 or 404);
                var responseHeaders = message.Response.Headers.ToArray();
                Require(responseHeaders.Length <= 32 && responseHeaders.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    responseHeaders.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == responseHeaders.Length);
                foreach (var header in responseHeaders)
                {
                    Require(header.Name.Length is > 0 and <= 128 && header.Value.Length <= 16384 &&
                        !header.Value.Any(char.IsControl) &&
                        !new[] { "Location", "Operation-Location", "Azure-AsyncOperation", "Retry-After", "WWW-Authenticate" }
                            .Contains(header.Name, StringComparer.OrdinalIgnoreCase));
                }
                if (message.Response.Headers.TryGetValue("x-ms-request-id", out string? id))
                {
                    Require(Segment(id, 256));
                    RequestId = id;
                }
                long? declared = null;
                if (message.Response.Headers.TryGetValue("Content-Length", out string? text))
                {
                    Require(long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long size) && size >= 0 && size <= maximum);
                    declared = size;
                }
                var response = new MemoryStream();
                storage.Add(response);
                byte[] chunk = new byte[4096];
                try
                {
                    using Stream? input = message.Response.ContentStream;
                    if (input is not null)
                    {
                        int count;
                        while ((count = await input.ReadAsync(chunk, message.CancellationToken).ConfigureAwait(false)) != 0)
                        {
                            Require(response.Length + count <= maximum);
                            response.Write(chunk, 0, count);
                        }
                    }
                }
                finally { CryptographicOperations.ZeroMemory(chunk); }
                Require(declared is null || declared == response.Length);
                if (Status == 204) Require(action == PolicyRequest.Purge && response.Length == 0);
                else
                {
                    Require(response.Length > 0);
                    using var document = JsonDocument.Parse(response.GetBuffer().AsMemory(0, (int)response.Length),
                        new JsonDocumentOptions { MaxDepth = 16 });
                    BoundaryTransport.Unique(document.RootElement);
                    ValidateReply(document.RootElement);
                }
                // Give SDK raw-body consumers offset zero and exact length;
                // spare capacity must never enter native backup deserialization.
                var exact = new MemoryStream(response.GetBuffer(), 0, (int)response.Length, false, true);
                storage.Add(exact);
                message.Response.ContentStream = exact;
                Valid = true;
            }
            catch { message.Response.Dispose(); throw; }
        }
        private void ValidateRequest(HttpMessage message)
        {
            string path = action switch
            {
                PolicyRequest.Get => "/secrets/" + child.Name + "/",
                PolicyRequest.GetDeleted or PolicyRequest.Purge => "/deletedsecrets/" + child.Name,
                PolicyRequest.Backup => "/secrets/" + child.Name + "/backup",
                _ => "/secrets/" + child.Name
            };
            RequestMethod method = action switch
            {
                PolicyRequest.Set => RequestMethod.Put,
                PolicyRequest.Backup => RequestMethod.Post,
                PolicyRequest.Delete or PolicyRequest.Purge => RequestMethod.Delete,
                _ => RequestMethod.Get
            };
            Require(message.Request.Method == method && message.Request.Uri.ToUri().OriginalString ==
                Origin + path + "?api-version=" + SecretRevision &&
                (action == PolicyRequest.Set || message.Request.Content is null));
            var headers = message.Request.Headers.ToArray();
            Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 && !h.Value.Any(char.IsControl)));
            if (message.Request.Headers.TryGetValue("Host", out string? host)) Require(host == SecretOrigin(plan).Host);
        }
        private void ValidateReply(JsonElement root)
        {
            if (Status is 403 or 404)
            {
                Require(root.GetProperty("error").GetProperty("code").ValueKind == JsonValueKind.String);
                return;
            }
            Require(Status == 200 && action != PolicyRequest.Purge);
            if (action == PolicyRequest.Backup)
            {
                Require(root.EnumerateObject().All(p => p.Name == "value"));
                string encoded = root.GetProperty("value").GetString()!;
                Require(encoded.Length > 0 && encoded.Length <= ((long)maximum + 2) / 3 * 4 &&
                    encoded.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
                string padded = encoded.Replace('-', '+').Replace('_', '/');
                padded += new string('=', (4 - padded.Length % 4) % 4);
                byte[] bytes = Convert.FromBase64String(padded);
                try { Require(bytes.Length > 0 && bytes.Length <= maximum); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                return;
            }
            Require(root.EnumerateObject().All(p => p.Name is "id" or "value" or "attributes" or "contentType" or "tags" or
                "kid" or "managed" or "recoveryId" or "deletedDate" or "scheduledPurgeDate"));
            string id = root.GetProperty("id").GetString()!;
            string prefix = Origin + "/secrets/" + child.Name + "/";
            Require(id.StartsWith(prefix, StringComparison.Ordinal) && id[prefix.Length..] is { Length: 32 } version &&
                version.All(char.IsAsciiHexDigit) && (child.Version is null || child.Version == version));
            var attributes = root.GetProperty("attributes");
            Require(attributes.GetProperty("enabled").ValueKind == JsonValueKind.True);
            foreach (string name in new[] { "nbf", "exp", "created", "updated" })
                if (attributes.TryGetProperty(name, out var value))
                {
                    Require(value.TryGetInt64(out long seconds));
                    var instant = DateTimeOffset.FromUnixTimeSeconds(seconds);
                    Require(name != "nbf" || instant <= time.GetUtcNow());
                    Require(name != "exp" || instant > time.GetUtcNow());
                }
            if (action is PolicyRequest.Get or PolicyRequest.Set)
                Require(Hash(root.GetProperty("value").GetString()!) == child.Sha256);
            if (action is PolicyRequest.Delete or PolicyRequest.GetDeleted)
            {
                Require(root.GetProperty("recoveryId").GetString() == Origin + "/deletedsecrets/" + child.Name &&
                    root.GetProperty("deletedDate").TryGetInt64(out long deleted) &&
                    root.GetProperty("scheduledPurgeDate").TryGetInt64(out long purge) && purge > deleted);
            }
            else Require(!root.TryGetProperty("recoveryId", out _) && !root.TryGetProperty("deletedDate", out _) &&
                !root.TryGetProperty("scheduledPurgeDate", out _));
        }
        public void Dispose()
        {
            try
            {
                try { nativeResponse?.Dispose(); }
                finally { foreach (var content in contents) content.Dispose(); }
            }
            finally
            {
                foreach (var buffer in storage)
                {
                    if (buffer.TryGetBuffer(out var bytes)) CryptographicOperations.ZeroMemory(bytes.AsSpan());
                    buffer.Dispose();
                }
            }
        }
    }

    private sealed class BoundedPolicyBuffer(int maximum) : MemoryStream
    {
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            Require(Position == Length && buffer.Length <= maximum - Length);
            long position = Position;
            base.SetLength(Length + buffer.Length);
            buffer.CopyTo(GetBuffer().AsSpan((int)position, buffer.Length));
            Position = position + buffer.Length;
        }
        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));
        public override void WriteByte(byte value)
        {
            Require(Position == Length && Length < maximum);
            base.WriteByte(value);
        }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer.Span);
            return ValueTask.CompletedTask;
        }
        public override void SetLength(long value) { Require(value >= 0 && value <= maximum); base.SetLength(value); }
    }

    private async Task<Result> ObserveCore(Plan plan, CancellationToken token)
    {
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        if (vault is not null)
        {
            Presence(plan, plan.VaultId);
            Presence(plan, plan.SecretId);
            ValidateVault(plan, vault);
        }
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        if (deleted is not null)
        {
            Presence(plan, plan.DeletedId);
            Presence(plan, plan.SecretId);
            ValidateDeleted(plan, deleted);
        }
        Require(vault is null || deleted is null);
        string? digest = null, version = null;
        if (!plan.Restored && vault is not null && Succeeded(vault) && plan.SeedCanary)
            (digest, version) = await ReadCanary(plan, token).ConfigureAwait(false);
        bool childrenReady = true;
        foreach (var child in plan.PolicyChildren)
        {
            if (vault is null || !Succeeded(vault) || !child.Prepared || plan.Restored)
            {
                childrenReady = false;
                continue;
            }
            childrenReady &= await ObservePolicyChild(plan, child, token).ConfigureAwait(false);
        }
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        bool ready = !plan.Restored && childrenReady && (plan.Preparation switch
        {
            Preparation.Absent => vault is null && deleted is null,
            Preparation.Deleted => vault is null && deleted is not null &&
                snapshot.Resources.Single(r => r.Id == plan.DeletedId).CreateAttempted,
            _ => vault is not null && Succeeded(vault) && deleted is null &&
                (!plan.SeedCanary || digest is not null && digest == plan.CanarySha256 && version == plan.CanaryVersion)
        });
        return new()
        {
            State = !snapshot.Idle ? State.Pending :
                snapshot.Closing ? State.Closing : ready ? State.Ready : State.Incomplete,
            Journal = snapshot,
            Receipts = plan.Receipts,
            VaultPresent = vault is not null,
            DeletedVaultPresent = deleted is not null,
            Configuration = vault is null ? null : Configuration(vault),
            DeletedVault = deleted is null ? null : ProjectDeleted(deleted),
            CanaryPresent = vault is not null && plan.SeedCanary ? digest is not null : null,
            CanarySha256 = digest ?? plan.CanarySha256,
            CanaryVersion = version ?? plan.CanaryVersion
        };
    }

    private async Task<T?> ReadArm<T>(Plan plan, string id, Func<ArmClient, CancellationToken, Task<Response<T>>> read,
        System.Action<JsonElement> shape, CancellationToken token, VaultReadLoan? readLoan = null,
        SettingsLoan? settingsLoan = null, PurgeDeletedVaultLoan? purgeLoan = null,
        CreateOrUpdateVaultLoan? createLoan = null, RecoverVaultLoan? recoverLoan = null,
        PrivateConnectionUpdateLoan? privateUpdateLoan = null,
        PrivateConnectionDeleteLoan? privateDeleteLoan = null) where T : class
    {
        if (StatusDeniedVaultUpdateSelector(plan.Selector))
        {
            Require(readLoan is null && settingsLoan is null && purgeLoan is null && createLoan is null &&
                recoverLoan is null && privateUpdateLoan is null && privateDeleteLoan is null);
            return await ReadDeniedVaultUpdateArm(plan, id, read, token).ConfigureAwait(false);
        }
        if (StatusPrivateConnectionUpdateIndependentSelector(plan.Selector))
            return await ReadPrivateUpdateIndependentArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(plan.Selector))
            return await ReadNotificationCreateIndependentArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector))
            return await ReadUnknownNotificationUpdateCancellationArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector))
            return await ReadUnknownNotificationUpdateIndependentArm(plan, id, read, token).ConfigureAwait(false);

        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector))
            return await ReadDeniedPrivateDeleteArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector))
            return await ReadDeniedNotificationUpdateArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector))
            return await ReadUnknownNotificationUpdateArm(plan, id, read, token).ConfigureAwait(false);
        if (NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(plan.Selector))
            return await ReadNotificationUpdateIndependentArm(plan, id, read, token).ConfigureAwait(false);
        if (PendingSelector(plan.Selector) || plan.StatusSucceededDeleteVaultProfile || plan.StatusSucceededDeleteVaultIndependentProfile || plan.StatusSucceededDeleteVaultCancellationProfile)
            return await ReadStatusSucceededArm(plan, id, read, token).ConfigureAwait(false);
        bool statusPurgeCleanup = StatusVaultPurgeCancellationSelector(plan.Selector) &&
            ReadPlan(plan.Owner, plan.Selector).Closing;
        bool statusRecovery = StatusVaultRecoverCancellationSelector(plan.Selector);
        bool statusUpdate = StatusVaultUpdateCancellationSelector(plan.Selector);
        bool statusConfiguration = statusRecovery || statusUpdate;
        if (plan.PrivateEndpoint is not null)
            journal.InvalidatePrivateEndpointAbsence(plan.Owner, plan.Selector);
        using var boundary = new BoundaryTransport(readArm.Transport, ArmOrigin, id, Revision, RequestMethod.Get,
            limits.MaximumResponseBytes, false, SubscriptionId, host.Location,
            beforeSend: privateDeleteLoan is not null ? () => CheckPrivateConnectionDeleteLoan(privateDeleteLoan) :
                privateUpdateLoan is not null ? () => CheckPrivateConnectionUpdateLoan(privateUpdateLoan) :
                recoverLoan is not null ? () => CheckRecoverVaultLoan(recoverLoan) :
                createLoan is not null ? () => CheckCreateOrUpdateVaultLoan(createLoan) :
                purgeLoan is not null ? () => CheckPurgeDeletedVaultLoan(purgeLoan) :
                settingsLoan is not null ? () => CheckSettingsLoan(settingsLoan) :
                readLoan is null ? null : () => CheckVaultRead(readLoan), shape: shape, present: () =>
            {
                Presence(plan, id);
                Presence(plan, plan.SecretId);
            }, authenticatedReadGuard: statusPurgeCleanup || statusConfiguration ? message =>
                CheckSettingsRead(plan, null, message, id) : plan.OriginalPrivateConnectionDelete ? message =>
                CheckSettingsRead(plan, null, message, id, privateDeleteLoan: privateDeleteLoan) :
                plan.OriginalPrivateConnectionUpdate ? message =>
                CheckSettingsRead(plan, null, message, id, privateUpdateLoan: privateUpdateLoan) :
                plan.OriginalRecover ? message =>
                CheckSettingsRead(plan, null, message, id, recoverLoan: recoverLoan) :
                plan.OriginalCreate ? message =>
                CheckSettingsRead(plan, null, message, id, createLoan: createLoan) :
                PurgeDeletedVaultSelector(plan.Selector) ? message =>
                CheckSettingsRead(plan, null, message, id, purgeLoan: purgeLoan) : DeleteVaultSelector(plan.Selector) ? message =>
                CheckSettingsRead(plan, null, message, id) : SettingsSelector(plan.Selector) ? message =>
                CheckSettingsRead(plan, settingsLoan, message, id) : readLoan is not null &&
                (readLoan.PrivateConnection is not null || VaultGroupListReadProfile(plan) ||
                    VaultSubscriptionListReadProfile(plan) || DeletedVaultListReadProfile(plan)) ? message =>
                CheckAuthenticatedRead(readLoan, message, ArmOrigin + id + "?api-version=" + Revision) : null,
            verifyReadIntegrity: statusConfiguration || statusPurgeCleanup || plan.OriginalPrivateConnectionDelete || plan.OriginalPrivateConnectionUpdate || plan.OriginalRecover || plan.OriginalCreate || SettingsSelector(plan.Selector) || DeleteVaultSelector(plan.Selector) ||
                PurgeDeletedVaultSelector(plan.Selector) || readLoan is not null &&
                (VaultGroupListReadProfile(plan) || VaultSubscriptionListReadProfile(plan) ||
                    DeletedVaultListReadProfile(plan)),
            strictSettings: statusConfiguration || statusPurgeCleanup || plan.OriginalPrivateConnectionDelete || plan.OriginalPrivateConnectionUpdate || plan.OriginalRecover || plan.OriginalCreate || SettingsSelector(plan.Selector) || DeleteVaultSelector(plan.Selector) || PurgeDeletedVaultSelector(plan.Selector),
            strictDelete: statusConfiguration || statusPurgeCleanup || plan.OriginalPrivateConnectionDelete || plan.OriginalPrivateConnectionUpdate || plan.OriginalRecover || plan.OriginalCreate || DeleteVaultSelector(plan.Selector) || PurgeDeletedVaultSelector(plan.Selector),
            parserCustody: statusConfiguration || statusPurgeCleanup || plan.OriginalPrivateConnectionDelete || plan.OriginalPrivateConnectionUpdate || plan.OriginalRecover || plan.OriginalCreate,
            statusVaultRecoverCancellationRead: statusRecovery, statusVaultUpdateCancellationRead: statusUpdate);
        try
        {
            var response = await read(Arm(readArm, boundary), token).ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            Require(boundary.Valid && boundary.Status == 200 && boundary.OwnsParserResponse(raw));
            var value = response.Value;
            Require(!statusConfiguration || boundary.ParserComplete);
            return value;
        }
        catch (RequestFailedException) when (boundary.Valid && boundary.Status == 404 && boundary.ParserComplete) { return null; }
    }
    private async Task<KeyVaultData?> ReadVault(Plan plan, CancellationToken token, VaultReadLoan? readLoan = null)
    {
        var data = (await ReadArm(plan, plan.VaultId, (client, ct) => client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
            root =>
            {
                VaultShape(root);
                if (StatusVaultRecoverCancellationSelector(plan.Selector))
                    _ = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root,
                        StatusVaultRecoverCancellationConfiguration(plan), "Succeeded", recover: true);
                if (StatusVaultUpdateCancellationSelector(plan.Selector))
                    _ = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root,
                        StatusVaultUpdateCancellationConfiguration(plan), "Succeeded", recover: false);
                if (plan.OriginalPrivateConnectionDelete)
                    _ = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root,
                        PrivateDeleteConfiguration(plan), "Succeeded",
                        privateConnection: ReadPlan(plan.Owner, plan.Selector).PrivateEndpoint!.Connection?.Id,
                        privateEndpoint: plan.PrivateEndpoint!.EndpointId,
                        allowAbsentPrivateConnection: ReadPlan(plan.Owner, plan.Selector).Closing);
                if (plan.OriginalPrivateConnectionUpdate)
                    _ = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root,
                        PrivateUpdateConfiguration(plan), "Succeeded",
                        privateConnection: ReadPlan(plan.Owner, plan.Selector).PrivateEndpoint!.Connection?.Id,
                        privateEndpoint: plan.PrivateEndpoint!.EndpointId,
                        allowAbsentPrivateConnection: ReadPlan(plan.Owner, plan.Selector).Closing);
                if (plan.OriginalRecover)
                    _ = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root,
                        RecoverVaultConfiguration(plan), "Succeeded", recover: true);
                if (plan.OriginalCreate)
                    _ = ParseDeleteVaultResource(plan, root, CreateVaultCleanupConfiguration(plan));
                if (SettingsSelector(plan.Selector))
                    _ = VaultFixtureObserverService.ParseSettingsResource(plan, root, SettingsCleanupConfiguration(plan));
                if (DeleteVaultSelector(plan.Selector))
                    _ = ParseDeleteVaultResource(plan, root, DeleteVaultConfiguration(plan));
                if (PurgeDeletedVaultSelector(plan.Selector))
                    _ = ParseDeleteVaultResource(plan, root, PurgeDeletedVaultConfiguration(plan));
            }, token, readLoan).ConfigureAwait(false))?.Data;
        if (data is not null && StatusVaultRecoverCancellationSelector(plan.Selector))
            JoinRecoverActive(plan, data, StatusVaultRecoverCancellationConfiguration(plan));
        if (data is not null && StatusVaultUpdateCancellationSelector(plan.Selector))
            JoinRecoverActive(plan, data, StatusVaultUpdateCancellationConfiguration(plan));
        return data;
    }
    private async Task<DeletedKeyVaultData?> ReadDeleted(Plan plan, CancellationToken token, VaultReadLoan? readLoan = null)
    {
        JsonElement? recoveryRaw = null;
        var data = (await ReadArm(plan, plan.DeletedId,
            (client, ct) => client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
            root =>
            {
                DeletedShape(root);
                if (StatusVaultRecoverCancellationSelector(plan.Selector))
                {
                    ValidateDeleteVaultResource(plan, root, StatusVaultRecoverCancellationConfiguration(plan));
                    recoveryRaw = root.Clone();
                }
                if (StatusVaultUpdateCancellationSelector(plan.Selector))
                {
                    ValidateDeleteVaultResource(plan, root, StatusVaultUpdateCancellationConfiguration(plan));
                    recoveryRaw = root.Clone();
                }
                if (plan.OriginalPrivateConnectionDelete)
                    ValidateDeleteVaultResource(plan, root, PrivateDeleteConfiguration(plan));
                if (plan.OriginalPrivateConnectionUpdate)
                    ValidateDeleteVaultResource(plan, root, PrivateUpdateConfiguration(plan));
                if (plan.OriginalRecover)
                    ValidateCreateVaultDeletedResource(plan, root, RecoverVaultConfiguration(plan));
                if (plan.OriginalCreate)
                    ValidateCreateVaultDeletedResource(plan, root, CreateVaultCleanupConfiguration(plan));
                if (DeleteVaultSelector(plan.Selector))
                    ValidateDeleteVaultResource(plan, root, DeleteVaultConfiguration(plan));
                if (PurgeDeletedVaultSelector(plan.Selector))
                    ValidateDeleteVaultResource(plan, root, PurgeDeletedVaultConfiguration(plan));
                if (!DeletedVaultReadProfile(plan)) return;
                var properties = root.GetProperty("properties");
                Require(root.GetProperty("id").GetString() == plan.DeletedId &&
                    root.GetProperty("type").GetString() == "Microsoft.KeyVault/locations/deletedVaults" &&
                    properties.GetProperty("vaultId").GetString() == plan.VaultId &&
                    properties.GetProperty("location").GetString() == host.Location &&
                    properties.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
                    properties.GetProperty("purgeProtectionEnabled").GetBoolean() == false);
                var retention = properties.GetProperty("scheduledPurgeDate").GetDateTimeOffset() -
                    properties.GetProperty("deletionDate").GetDateTimeOffset();
                Require(retention >= TimeSpan.FromDays(7) && retention <= TimeSpan.FromDays(90) &&
                    retention.Ticks % TimeSpan.TicksPerDay == 0 &&
                    (baselineConfiguration is null || retention == TimeSpan.FromDays(baseline.RetentionDays)));
            }, token, readLoan).ConfigureAwait(false))?.Data;
        if (data is not null && DeletedVaultReadProfile(plan)) ValidateDeleted(plan, data);
        if (data is not null && (StatusVaultRecoverCancellationSelector(plan.Selector) ||
            StatusVaultUpdateCancellationSelector(plan.Selector)))
        {
            Require(recoveryRaw is not null);
            JoinRecoverDeleted(plan, data, recoveryRaw.Value);
        }
        return data;
    }

    private static VaultAdministrationEffects.DeletedVaultRow ProjectDeleted(DeletedKeyVaultData deleted)
    {
        string? location = deleted.Properties.Location;
        Require(Guid.TryParse(deleted.Id.SubscriptionId, out var subscription) && location is not null);
        return new(subscription, location, deleted.Id.Name,
            deleted.Properties.DeletedOn, deleted.Properties.ScheduledPurgeOn, deleted.Properties.PurgeProtectionEnabled);
    }

    private async Task<(string? Digest, string? Version)> ReadCanary(Plan plan, CancellationToken token,
        VaultReadLoan? readLoan = null, PrivateConnectionUpdateLoan? privateUpdateLoan = null,
        PrivateConnectionDeleteLoan? privateDeleteLoan = null)
    {
        if (plan.PrivateEndpoint is not null)
            journal.InvalidatePrivateEndpointAbsence(plan.Owner, plan.Selector);
        using var boundary = new BoundaryTransport(readSecret.Transport, SecretOrigin(plan).GetLeftPart(UriPartial.Authority),
            "/secrets/" + Canary + "/" + (readLoan is null && privateUpdateLoan is null && privateDeleteLoan is null ? "" : plan.CanaryVersion),
            SecretRevision, RequestMethod.Get, limits.MaximumResponseBytes, true,
            SubscriptionId, host.Location, shape: root => CanaryShape(plan, root), present: () => Presence(plan, plan.SecretId),
            authenticatedReadGuard: privateDeleteLoan is not null ? message =>
                CheckPrivateDeleteCanary(privateDeleteLoan, message) : privateUpdateLoan is not null ? message =>
                CheckPrivateUpdateCanary(privateUpdateLoan, message) : readLoan is null ? null : message =>
                CheckAuthenticatedRead(readLoan, message, SecretOrigin(plan).GetLeftPart(UriPartial.Authority) +
                    "/secrets/" + Canary + "/" + plan.CanaryVersion + "?api-version=" + SecretRevision),
            verifyReadIntegrity: privateUpdateLoan is not null || privateDeleteLoan is not null,
            strictSettings: privateUpdateLoan is not null || privateDeleteLoan is not null,
            strictDelete: privateUpdateLoan is not null || privateDeleteLoan is not null,
            parserCustody: privateUpdateLoan is not null || privateDeleteLoan is not null);
        try
        {
            var response = await Secret(readSecret, plan, boundary).GetSecretAsync(Canary,
                readLoan is null && privateUpdateLoan is null && privateDeleteLoan is null ? null : plan.CanaryVersion,
                cancellationToken: token).ConfigureAwait(false);
            using var raw = response.GetRawResponse();
            Require(boundary.Valid && boundary.Status == 200 && boundary.OwnsParserResponse(raw));
            ValidateSecret(plan, response.Value);
            string hash = Hash(response.Value.Value);
            Require(plan.CanarySha256 is null || hash == plan.CanarySha256);
            return (hash, response.Value.Properties.Version);
        }
        catch (RequestFailedException) when (boundary.Valid && boundary.Status == 404) { return (null, null); }
    }

    private void ValidateSecret(Plan plan, KeyVaultSecret secret) =>
        Require(secret.Name == Canary && secret.Properties.VaultUri == SecretOrigin(plan) &&
            secret.Properties.Version is { Length: 32 } version && version.All(char.IsAsciiHexDigit) &&
            (plan.CanaryVersion is null || plan.CanaryVersion == version) && secret.Value is { Length: > 0 and <= 4096 } &&
            secret.Properties.Enabled == true &&
            (secret.Properties.NotBefore is null || secret.Properties.NotBefore <= time.GetUtcNow()) &&
            (secret.Properties.ExpiresOn is null || secret.Properties.ExpiresOn > time.GetUtcNow()));

    private static void CanaryShape(Plan plan, JsonElement root)
    {
        string prefix = SecretOrigin(plan).GetLeftPart(UriPartial.Authority) + "/secrets/" + Canary + "/";
        string id = root.GetProperty("id").GetString()!;
        Require(id.StartsWith(prefix, StringComparison.Ordinal) && id[prefix.Length..] is { Length: 32 } version &&
            version.All(char.IsAsciiHexDigit) && (plan.CanaryVersion is null || version == plan.CanaryVersion) &&
            root.GetProperty("attributes").GetProperty("enabled").ValueKind == JsonValueKind.True &&
            (plan.CanarySha256 is null || Hash(root.GetProperty("value").GetString()!) == plan.CanarySha256));
    }

    private void ValidateVault(Plan plan, KeyVaultData vault)
    {
        var row = ReadPlan(plan.Owner, plan.Selector).Resources.Single(r => r.Id == plan.VaultId);
        Require(row.CreateAttempted);
        ValidateVaultData(plan, vault, row.SelectedAttempted);
    }
    private void ValidateVaultData(Plan plan, KeyVaultData vault, bool selected)
    {
        Require(Same(vault.Id?.ToString(), plan.VaultId) &&
            vault.Properties is not null && vault.Properties.TenantId == host.TenantId &&
            Same(vault.Location.Name, host.Location) && vault.Properties.VaultUri == SecretOrigin(plan) &&
            vault.Tags.TryGetValue(OwnershipTag, out string? nonce) && nonce == plan.Selector.Nonce.ToString("N"));
        var actual = Configuration(vault);
        // A selected invocation is the parent's separately fenced authority.
        // Its intentional settings change is not mistaken for baseline setup.
        Require(StatusDeniedVaultUpdateSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, DeniedVaultUpdateConfiguration(plan, ReadPlan(plan.Owner, plan.Selector)))
            : StatusVaultUpdateCancellationSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, StatusVaultUpdateCancellationConfiguration(plan))
            : StatusVaultRecoverCancellationSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, StatusVaultRecoverCancellationConfiguration(plan))
            : plan.OriginalPrivateConnectionDelete
            ? VaultAdministrationEffects.SameConfiguration(actual, PrivateDeleteConfiguration(plan))
            : plan.OriginalPrivateConnectionUpdate
            ? VaultAdministrationEffects.SameConfiguration(actual, PrivateUpdateConfiguration(plan))
            : plan.OriginalRecover
            ? VaultAdministrationEffects.SameConfiguration(actual, RecoverVaultConfiguration(plan))
            : plan.OriginalCreate
            ? VaultAdministrationEffects.SameConfiguration(actual, CreateVaultCleanupConfiguration(plan))
            : PurgeDeletedVaultSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, PurgeDeletedVaultConfiguration(plan))
            : DeleteVaultSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, DeleteVaultConfiguration(plan))
            : SettingsSelector(plan.Selector)
            ? VaultAdministrationEffects.SameConfiguration(actual, SettingsCleanupConfiguration(plan))
            : baselineConfiguration is null || selected || VaultAdministrationEffects.SameConfiguration(actual, baseline));
    }
    private void ValidateDeleted(Plan plan, DeletedKeyVaultData deleted)
    {
        var rows = ReadPlan(plan.Owner, plan.Selector).Resources;
        var properties = deleted.Properties;
        Require(rows.Single(r => r.Id == plan.VaultId).CreateAttempted &&
            (rows.Single(r => r.Id == plan.VaultId).DeleteAttempted ||
                rows.Single(r => r.Id == plan.VaultId).SelectedAttempted ||
                rows.Single(r => r.Id == plan.DeletedId).CreateAttempted) &&
            Same(deleted.Id?.ToString(), plan.DeletedId) && properties is not null &&
            Same(properties.VaultId, plan.VaultId) && Same(properties.Location, host.Location) &&
            properties.Tags.TryGetValue(OwnershipTag, out string? nonce) && nonce == plan.Selector.Nonce.ToString("N") &&
            properties.PurgeProtectionEnabled is not null &&
            (StatusVaultUpdateCancellationSelector(plan.Selector) || StatusVaultRecoverCancellationSelector(plan.Selector) || baselineConfiguration is null ||
                !baseline.PurgeProtection || properties.PurgeProtectionEnabled == true));
        if (StatusVaultUpdateCancellationSelector(plan.Selector) || StatusVaultRecoverCancellationSelector(plan.Selector) || plan.OriginalPrivateConnectionDelete || plan.OriginalPrivateConnectionUpdate || plan.OriginalRecover || plan.OriginalCreate || SettingsSelector(plan.Selector) || DeleteVaultSelector(plan.Selector) || PurgeDeletedVaultSelector(plan.Selector))
        {
            var expected = StatusVaultUpdateCancellationSelector(plan.Selector) ? StatusVaultUpdateCancellationConfiguration(plan) :
                StatusVaultRecoverCancellationSelector(plan.Selector) ? StatusVaultRecoverCancellationConfiguration(plan) :
                plan.OriginalPrivateConnectionDelete ? PrivateDeleteConfiguration(plan) :
                plan.OriginalPrivateConnectionUpdate ? PrivateUpdateConfiguration(plan) :
                plan.OriginalRecover ? RecoverVaultConfiguration(plan) : plan.OriginalCreate ? CreateVaultCleanupConfiguration(plan) :
                PurgeDeletedVaultSelector(plan.Selector) ? PurgeDeletedVaultConfiguration(plan) :
                DeleteVaultSelector(plan.Selector) ? DeleteVaultConfiguration(plan) : SettingsCleanupConfiguration(plan);
            Require(properties.PurgeProtectionEnabled == expected.PurgeProtection &&
                properties.DeletedOn is { } deletedAt && properties.ScheduledPurgeOn is { } purgeAt &&
                purgeAt - deletedAt == TimeSpan.FromDays(expected.RetentionDays));
        }
        else if (baselineConfiguration is not null && !rows.Single(r => r.Id == plan.VaultId).SelectedAttempted)
            Require(properties.PurgeProtectionEnabled == baseline.PurgeProtection &&
                properties.DeletedOn is { } deletedOn && properties.ScheduledPurgeOn is { } purgeOn &&
                purgeOn - deletedOn == TimeSpan.FromDays(baseline.RetentionDays));
    }
    private static VaultAdministrationEffects.Configuration Configuration(KeyVaultData vault)
    {
        var properties = vault.Properties;
        Require(properties is not null && properties.Sku is not null && properties.Sku.Family == KeyVaultSkuFamily.A &&
            properties.Sku.Name is var sku && (sku == KeyVaultSkuName.Standard || sku == KeyVaultSkuName.Premium) &&
            properties.EnableSoftDelete == true && properties.EnableRbacAuthorization is not null &&
            properties.EnablePurgeProtection is not null && properties.SoftDeleteRetentionInDays is not null &&
            properties.PublicNetworkAccess is "Enabled" or "Disabled");
        var policies = properties.AccessPolicies.Select(p =>
        {
            Require(Guid.TryParse(p.ObjectId, out Guid principal) && principal != Guid.Empty && p.Permissions is not null);
            var permissions = p.Permissions.Secrets.Select(permission =>
            {
                Require(Enum.TryParse<SecretPermission>(permission.ToString(), true, out var parsed) && Enum.IsDefined(parsed) &&
                    parsed.ToString().Equals(permission.ToString(), StringComparison.OrdinalIgnoreCase));
                return parsed;
            }).ToArray();
            return new VaultAdministrationEffects.Policy(p.TenantId, principal, permissions, p.ApplicationId);
        }).ToArray();
        var result = new VaultAdministrationEffects.Configuration(vault.Location.Name, properties.TenantId,
            properties.Sku.Name == KeyVaultSkuName.Standard ? VaultSku.Standard : VaultSku.Premium,
            properties.EnableRbacAuthorization.Value, properties.EnablePurgeProtection.Value,
            properties.SoftDeleteRetentionInDays.Value, properties.PublicNetworkAccess == "Enabled", policies);
        _ = result.Build();
        return result;
    }

    private ArmClient Arm(Authority authority, BoundaryTransport boundary)
    {
        var options = new ArmClientOptions { Environment = new(new Uri(ArmOrigin), ArmOrigin), Transport = boundary };
        Quiet(options);
        options.SetApiVersion("Microsoft.KeyVault/vaults", Revision);
        options.SetApiVersion("Microsoft.KeyVault/deletedVaults", Revision);
        return new(new AudienceCredential(authority.Credential, ArmOrigin + "/.default"), null, options);
    }
    private SecretClient Secret(Authority authority, Plan plan, BoundaryTransport boundary)
    {
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V2025_07_01) { Transport = boundary };
        Quiet(options);
        var credential = new PolicyCredential(authority.Credential, time);
        boundary.SecretCredential = credential;
        return new(SecretOrigin(plan), credential, options);
    }
    private static void Quiet(ClientOptions options)
    {
        options.Retry.MaxRetries = 0;
        options.Diagnostics.IsLoggingEnabled = false;
        options.Diagnostics.IsLoggingContentEnabled = false;
        options.Diagnostics.IsDistributedTracingEnabled = false;
    }
    private sealed class AudienceCredential(TokenCredential inner, string audience) : TokenCredential
    {
        public override AccessToken GetToken(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Require(context.Scopes.Length == 1 && context.Scopes[0] == audience);
            return inner.GetToken(context, cancellationToken);
        }
        public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext context, CancellationToken cancellationToken)
        {
            Require(context.Scopes.Length == 1 && context.Scopes[0] == audience);
            return inner.GetTokenAsync(context, cancellationToken);
        }
    }

    private RoleFixtureJournal.Snapshot ReadPlan(string owner, FixtureSelector selector)
    {
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(selector));
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(selector));
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) ||
            MatchesStatusDeniedNotificationOperation(selector));
        RoleFixtureJournal.Snapshot snapshot;
        try { snapshot = journal.Read(owner, selector); }
        catch (RoleFixtureJournal.StatusDeniedVaultUpdateHistoryException)
        { deniedVaultUpdateRevoked.TryAdd(selector.Nonce, 0); throw; }
        catch (RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteHistoryException)
        { deniedPrivateDeleteRevoked.TryAdd(selector.Nonce, 0); throw; }
        catch (RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentHistoryException)
        { RevokePrivateUpdateIndependentFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusNotificationCreateIndependentHistoryException)
        { RevokeNotificationCreateIndependentFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusUnknownNotificationUpdateCancellationHistoryException)
        { RevokeUnknownNotificationUpdateCancellationFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusUnknownNotificationUpdateIndependentHistoryException)
        { RevokeUnknownNotificationUpdateIndependentFixture(selector); throw; }

        catch (RoleFixtureJournal.StatusDeniedNotificationUpdateHistoryException)
        { RevokeDeniedNotificationUpdateFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusUnknownNotificationUpdateHistoryException)
        { RevokeUnknownNotificationUpdateFixture(selector); throw; }
        catch (RoleFixtureJournal.StatusNotificationUpdateIndependentHistoryException)
        { RevokeNotificationUpdateFixture(selector); throw; }
        Require(MatchesHost(snapshot) && (!NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(selector) ||
            !unknownNotificationUpdateCancellationRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusUnknownNotificationUpdateCancellationRoot(snapshot)) &&
            (!NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(selector) ||
            !unknownNotificationUpdateIndependentRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusUnknownNotificationUpdateIndependentRoot(snapshot)) &&
            (!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(selector) ||
            !deniedNotificationUpdateRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusDeniedNotificationUpdateRoot(snapshot)) &&
            (!NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(selector) ||
            !unknownNotificationUpdateRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusUnknownNotificationUpdateRoot(snapshot)) &&
            (!NotificationFixtureProvisioner.StatusNotificationUpdateIndependentSelector(selector) ||
            !notificationUpdateRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusNotificationUpdateIndependentRoot(snapshot)) &&
            (!NotificationFixtureProvisioner.StatusNotificationCreateIndependentSelector(selector) ||
                !notificationCreateIndependentRevoked.ContainsKey(selector.Nonce) && RoleFixtureJournal.StatusNotificationCreateIndependentRoot(snapshot)));
        lock (plans)
            if (plans.TryGetValue(selector.Nonce, out var plan)) Require(MatchesPlan(plan, snapshot));
        return snapshot;
    }
    private bool DeniedHost(RoleFixtureJournal.Snapshot snapshot) =>
        (deniedProfile is not null) == StatusDeniedPurgeSelector(snapshot.Selector) &&
        (deniedProfile is null || DeclaredDeniedSelector(snapshot.Selector)) &&
        (!StatusDeniedPurgeSelector(snapshot.Selector) || RoleFixtureJournal.StatusDeniedPurgeRoot(snapshot) &&
            VaultAdministrationEffects.SameConfiguration(snapshot.PurgeDeletedVault!.Baseline, baseline));
    private bool MatchesHost(RoleFixtureJournal.Snapshot snapshot)
    {
        if (statusDeniedVaultUpdateProfile != StatusDeniedVaultUpdateSelector(snapshot.Selector) ||
            StatusDeniedVaultUpdateSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusDeniedVaultUpdateRoot(snapshot) || deniedVaultUpdateRevoked.ContainsKey(snapshot.Selector.Nonce) ||
                snapshot.CreateOrUpdateVault!.Baseline.Location != host.Location ||
                snapshot.CreateOrUpdateVault.Baseline.TenantId != host.TenantId ||
                baselineConfiguration is not null && !VaultAdministrationEffects.SameConfiguration(snapshot.CreateOrUpdateVault.Baseline, baseline)))
            return false;
        if (statusDeniedPrivateDeleteProfile != StatusDeniedPrivateConnectionDeleteSelector(snapshot.Selector) ||
            StatusDeniedPrivateConnectionDeleteSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(snapshot) ||
                deniedPrivateDeleteRevoked.ContainsKey(snapshot.Selector.Nonce))) return false;
        if (NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(snapshot.Selector) &&
            !MatchesStatusDeniedNotificationOperation(snapshot.Selector)) return false;
        if (!DeniedHost(snapshot)) return false;
        if ((canceledCancellationProfile is not null) != StatusCanceledPurgeCancellationSelector(snapshot.Selector)) return false;
        if (StatusCanceledPurgeCancellationSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusCanceledPurgeCancellationRoot(snapshot) ||
                !VaultAdministrationEffects.SameConfiguration(snapshot.PurgeDeletedVault!.Baseline, baseline))) return false;
        if ((canceledIndependentProfile is not null) != StatusCanceledPurgeIndependentSelector(snapshot.Selector)) return false;
        if (StatusCanceledPurgeIndependentSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusCanceledPurgeIndependentRoot(snapshot) ||
                !VaultAdministrationEffects.SameConfiguration(snapshot.PurgeDeletedVault!.Baseline, baseline))) return false;
        if ((canceledProfile is not null) != StatusCanceledPurgeSelector(snapshot.Selector)) return false;
        if (StatusCanceledPurgeSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusCanceledPurgeRoot(snapshot) ||
                !VaultAdministrationEffects.SameConfiguration(snapshot.PurgeDeletedVault!.Baseline, baseline))) return false;
        if (StatusPendingPurgeCancellationSelector(snapshot.Selector) && pendingCancellationProfile is null ||
            pendingCancellationProfile is not null && !StatusPendingPurgeCancellationSelector(snapshot.Selector)) return false;
        if (StatusPendingPurgeIndependentSelector(snapshot.Selector) && pendingIndependentProfile is null ||
            pendingIndependentProfile is not null && !StatusPendingPurgeIndependentSelector(snapshot.Selector)) return false;
        if (PendingSelector(snapshot.Selector) && (!PendingRoot(snapshot) ||
            snapshot.PurgeDeletedVault!.Baseline.Location != host.Location ||
            snapshot.PurgeDeletedVault.Baseline.TenantId != host.TenantId)) return false;
        if (StatusSucceededDeleteVaultCancellationSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot) ||
                snapshot.StatusSucceededDeleteVault!.Baseline.Location != host.Location ||
                snapshot.StatusSucceededDeleteVault.Baseline.TenantId != host.TenantId)) return false;
        if (StatusSucceededDeleteVaultIndependentSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) ||
                snapshot.StatusSucceededDeleteVault!.Baseline.Location != host.Location ||
                snapshot.StatusSucceededDeleteVault.Baseline.TenantId != host.TenantId)) return false;
        if (StatusSucceededDeleteVaultSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) ||
                snapshot.StatusSucceededDeleteVault!.Baseline.Location != host.Location ||
                snapshot.StatusSucceededDeleteVault.Baseline.TenantId != host.TenantId)) return false;
        if (StatusVaultUpdateCancellationSelector(snapshot.Selector) &&
            (snapshot.StatusVaultUpdateCancellationBaseline is not { } update ||
                update.Location != host.Location || update.TenantId != host.TenantId)) return false;
        if (StatusVaultRecoverCancellationSelector(snapshot.Selector) &&
            (snapshot.StatusVaultRecoverCancellationBaseline is not { } recovery ||
                recovery.Location != host.Location || recovery.TenantId != host.TenantId)) return false;
        if (snapshot.PrivateEndpoint is not null) return MatchesPrivateEndpointHost(snapshot);
        var owned = snapshot.Resources.Where(r => !r.Borrowed).ToArray();
        string prefix = GroupId + "/providers/Microsoft.KeyVault/vaults/";
        string? vault = owned.Select(r => r.Id).SingleOrDefault(id => id.StartsWith(prefix, StringComparison.Ordinal) &&
            id[prefix.Length..] is { Length: 24 } name && name.StartsWith("skv", StringComparison.Ordinal) &&
            name[3..].All(char.IsAsciiHexDigit));
        return snapshot.Resources.Length <= 24 && snapshot.Resources.Count(r => r.Borrowed) <= 13 &&
            owned.Length >= 3 && vault is not null &&
            owned.Any(r => r.Id == vault && !r.CleanupOnly) &&
            owned.Any(r => r.Id == vault + "/secrets/" + Canary) &&
            owned.Any(r => r.Id == DeletedId(vault[(vault.LastIndexOf('/') + 1)..])) &&
            owned.All(r => r.Id == vault || r.Id == DeletedId(vault[(vault.LastIndexOf('/') + 1)..]) ||
                r.Id.StartsWith(vault + "/secrets/", StringComparison.Ordinal) &&
                PolicyName(r.Id[(vault.Length + "/secrets/".Length)..]) && (!r.CleanupOnly || r.Id == vault + "/secrets/" + Canary) ||
                r.Id.StartsWith(vault + NotificationPrefix, StringComparison.Ordinal) &&
                NotificationName(r.Id[(vault.Length + NotificationPrefix.Length)..]) && !r.CleanupOnly &&
                owned.Single(d => d.Id == DeletedId(vault[(vault.LastIndexOf('/') + 1)..])).CleanupOnly) &&
            snapshot.Resources.Where(r => r.Borrowed).All(r => BorrowedId(r.Id) &&
                !r.Id.StartsWith(vault + "/", StringComparison.OrdinalIgnoreCase));
    }
    private bool MatchesPrivateEndpointHost(RoleFixtureJournal.Snapshot snapshot)
    {
        if (StatusPrivateConnectionUpdateIndependentSelector(snapshot.Selector) &&
            (!RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(snapshot) || privateUpdateIndependentRevoked.ContainsKey(snapshot.Selector.Nonce))) return false;
        if (StatusPrivateConnectionDeleteIndependentSelector(snapshot.Selector) &&
            !RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot)) return false;
        if (StatusPrivateConnectionDeleteSelectedSelector(snapshot.Selector) &&
            !RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot)) return false;
        if (StatusPrivateConnectionDeleteCancellationSelector(snapshot.Selector) &&
            !RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot)) return false;
        if (StatusPrivateConnectionUpdateCancellationSelector(snapshot.Selector) &&
            !RoleFixtureJournal.StatusPrivateConnectionUpdateRoot(snapshot)) return false;
        var slot = snapshot.PrivateEndpoint!;
        var d = slot.Declaration;
        string name = d.VaultId.Split('/')[^1];
        if (name.Length != 24 || !name.StartsWith("skv", StringComparison.Ordinal) ||
            !name[3..].All(char.IsAsciiHexDigit) ||
            d.VaultId != GroupId + "/providers/Microsoft.KeyVault/vaults/" + name ||
            d.EndpointId != GroupId + "/providers/Microsoft.Network/privateEndpoints/" + name + "-pe" ||
            d.ExpectedNicId != GroupId + "/providers/Microsoft.Network/networkInterfaces/" + name + "-nic" ||
            d.NetworkConnectionName != name + "-link" || d.OwnerTagName != OwnershipTag ||
            d.OwnerTagValue != snapshot.Selector.Nonce.ToString("N") || snapshot.Resources.Length != 5)
            return false;
        try
        {
            PrivateEndpointResourceCollector.ValidateBinding(new(snapshot.Selector, snapshot.LeaseId, d.EndpointId,
                d.VaultId, d.BorrowedSubnetId, d.ExpectedNicId, d.NetworkConnectionName, host.Location,
                d.OwnerTagName, d.OwnerTagValue));
            if (slot.Connection is { } connection)
            {
                var scope = new PrivateConnectionScope(new(new(new(host.SubscriptionId), host.ResourceGroup), name),
                    connection.Id.Split('/')[^1]);
                if (connection.Id != d.VaultId + "/privateEndpointConnections/" + scope.ConnectionName ||
                    connection.Borrowed || connection.CleanupOnly || !connection.CreateAttempted ||
                    slot.CreationDispatch != Guid.Empty) return false;
            }
        }
        catch (Exception) { return false; }
        var canary = snapshot.Resources.SingleOrDefault(r => r.Id == d.VaultId + "/secrets/" + Canary);
        if (canary is null || !canary.CleanupOnly && !PrivateConnectionReadSelector(snapshot.Selector) &&
            snapshot.PrivateEndpoint!.OriginalUpdate is null && snapshot.PrivateEndpoint.OriginalDelete is null) return false;
        RoleFixtureJournal.Resource[] shape =
        [
            new(d.VaultId, false), new(d.VaultId + "/secrets/" + Canary, false,
                CleanupOnly: canary.CleanupOnly),
            new(DeletedId(name), false, CleanupOnly: true), new(d.EndpointId, false), new(d.BorrowedSubnetId, true)
        ];
        var endpoint = snapshot.Resources.SingleOrDefault(r => r.Id == d.EndpointId);
        if ((slot.ApprovalSettledDispatch != Guid.Empty || slot.StatusDeleteSettledDispatch != Guid.Empty) &&
            !snapshot.PrivateConnectionCleanupEligible)
            return false;
        if (endpoint is null || endpoint.SelectedAttempted ||
            (slot.CreationDispatch != Guid.Empty
                ? !endpoint.CreateAttempted || endpoint.DeleteAttempted ||
                    endpoint.ActiveDispatch != slot.CreationDispatch || slot.Connection is not null ||
                    slot.DeletionDispatch != Guid.Empty
                : slot.Connection is not null
                    ? !endpoint.CreateAttempted || (endpoint.DeleteAttempted
                        ? !snapshot.Closing || (slot.DeletionDispatch == Guid.Empty
                            ? endpoint.ActiveDispatch != Guid.Empty || !endpoint.InvocationTerminated
                            : endpoint.ActiveDispatch != slot.DeletionDispatch)
                        : slot.DeletionDispatch != Guid.Empty || endpoint.ActiveDispatch != Guid.Empty ||
                            !endpoint.InvocationTerminated)
                    : endpoint.CreateAttempted || endpoint.DeleteAttempted ||
                        slot.DeletionDispatch != Guid.Empty || endpoint.ActiveDispatch != Guid.Empty))
            return false;
        return shape.All(m => snapshot.Resources.Count(r =>
            r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1) &&
            snapshot.Resources.Where(r => r.Borrowed).All(r => !r.CreateAttempted && !r.DeleteAttempted &&
                !r.Absent && r.ActiveDispatch == Guid.Empty && !r.InvocationTerminated && !r.SelectedAttempted);
    }
    private Plan Reconstruct(RoleFixtureJournal.Snapshot snapshot)
    {
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(snapshot.Selector));
        Require(!statusDeniedVaultUpdateProfile || MatchesHost(snapshot));
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(snapshot.Selector));
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(snapshot.Selector) ||
            MatchesStatusDeniedNotificationOperation(snapshot.Selector));
        lock (plans)
        {
            Require(!closed);
            Require(!StatusVaultRecoverCancellationSelector(snapshot.Selector) ||
                MatchesHost(snapshot) && snapshot.StatusVaultRecoverCancellationBaseline is not null);
            Require(!StatusVaultUpdateCancellationSelector(snapshot.Selector) ||
                MatchesHost(snapshot) && snapshot.StatusVaultUpdateCancellationBaseline is not null);
            if (plans.TryGetValue(snapshot.Selector.Nonce, out var retained))
            {
                Require(retained.Owner == snapshot.Owner && retained.Selector == snapshot.Selector && retained.LeaseId == snapshot.LeaseId);
                return retained;
            }
            string prefix = GroupId + "/providers/Microsoft.KeyVault/vaults/";
            string vault = snapshot.Resources.Single(r => !r.Borrowed && r.Id.StartsWith(prefix, StringComparison.Ordinal) &&
                r.Id[prefix.Length..] is { Length: 24 } name && name.StartsWith("skv", StringComparison.Ordinal) &&
                name[3..].All(char.IsAsciiHexDigit)).Id;
            string deleted = DeletedId(vault[(vault.LastIndexOf('/') + 1)..]);
            var preparation = !snapshot.Resources.Single(r => r.Id == deleted).CleanupOnly ? Preparation.Deleted :
                snapshot.Resources.Single(r => r.Id == vault).CreateAttempted ? Preparation.Active : Preparation.Absent;
            var restored = new Plan(source, snapshot.Owner, snapshot.Selector, snapshot.LeaseId, vault, deleted,
                preparation, !snapshot.Resources.Single(r => r.Id == vault + "/secrets/" + Canary).CleanupOnly, restored: true,
                policyChildren: snapshot.Resources.Where(r => !r.Borrowed && r.Id.StartsWith(vault + "/secrets/", StringComparison.Ordinal) &&
                    r.Id != vault + "/secrets/" + Canary).Select(r => PolicyChild.Reconstructed(r.Id[(vault.Length + "/secrets/".Length)..])).ToArray(),
                ownedNotificationNames: snapshot.Resources.Where(r => !r.Borrowed &&
                    r.Id.StartsWith(vault + NotificationPrefix, StringComparison.Ordinal))
                    .Select(r => r.Id[(vault.Length + NotificationPrefix.Length)..]).ToArray(), manifest: snapshot.Resources,
                privateEndpoint: snapshot.PrivateEndpoint?.Declaration,
                originalCreate: snapshot.CreateOrUpdateVault is not null && CreateOrUpdateVaultSelector(snapshot.Selector),
                originalRecover: snapshot.RecoverVault is not null,
                originalPrivateConnectionUpdate: snapshot.PrivateEndpoint?.OriginalUpdate is not null,
                originalPrivateConnectionDelete: snapshot.PrivateEndpoint?.OriginalDelete is not null,
                statusSucceededDeleteVaultProfile: RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot),
                statusSucceededDeleteVaultIndependentProfile: RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot),
                statusSucceededDeleteVaultCancellationProfile: RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot))
            {
                Consumed = 1
            };
            if (pendingIndependentProfile is not null)
                Require(StatusPendingPurgeIndependentSelector(snapshot.Selector) && pendingIndependentPlans.TryAdd(restored, pendingIndependentProfile));
            if (pendingCancellationProfile is not null)
                Require(StatusPendingPurgeCancellationSelector(snapshot.Selector) && pendingCancellationPlans.TryAdd(restored, pendingCancellationProfile));
            if (failedCancellationProfile is not null)
                Require(StatusFailedPurgeCancellationSelector(snapshot.Selector) && failedCancellationPlans.TryAdd(restored, failedCancellationProfile));
            if (failedIndependentProfile is not null)
                Require(StatusFailedPurgeIndependentSelector(snapshot.Selector) && failedIndependentPlans.TryAdd(restored, failedIndependentProfile));
            if (canceledCancellationProfile is not null)
                Require(StatusCanceledPurgeCancellationSelector(snapshot.Selector) && canceledCancellationPlans.TryAdd(restored, canceledCancellationProfile));
            if (canceledIndependentProfile is not null)
                Require(StatusCanceledPurgeIndependentSelector(snapshot.Selector) && canceledIndependentPlans.TryAdd(restored, canceledIndependentProfile));
            if (canceledProfile is not null)
                Require(StatusCanceledPurgeSelector(snapshot.Selector) && canceledPlans.TryAdd(restored, canceledProfile));
            if (deniedProfile is not null)
                Require(DeclaredDeniedSelector(snapshot.Selector) && deniedPlans.TryAdd(restored, deniedProfile));
            if (failedProfile is not null)
                Require(StatusFailedPurgeSelector(snapshot.Selector) && failedPlans.TryAdd(restored, failedProfile));
            plans.Add(snapshot.Selector.Nonce, restored);
            return restored;
        }
    }
    private void CheckPlan(Plan plan)
    {
        Require(plan is not null && ReferenceEquals(plan.Source, source));
        Require(statusDeniedVaultUpdateProfile == StatusDeniedVaultUpdateSelector(plan.Selector));
        Require(statusDeniedPrivateDeleteProfile == StatusDeniedPrivateConnectionDeleteSelector(plan.Selector));
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector) ||
            MatchesStatusDeniedNotificationOperation(plan.Selector));
        if (PendingSelector(plan.Selector)) _ = IndependentPending(plan);
        lock (plans) Require(!closed && plans.TryGetValue(plan.Selector.Nonce, out var retained) && ReferenceEquals(plan, retained));
    }
    private static bool MatchesPlan(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        plan.Owner == snapshot.Owner && plan.Selector == snapshot.Selector && plan.LeaseId == snapshot.LeaseId &&
        plan.StatusSucceededDeleteVaultProfile == RoleFixtureJournal.StatusSucceededDeleteVaultRoot(snapshot) &&
        plan.StatusSucceededDeleteVaultCancellationProfile == RoleFixtureJournal.StatusSucceededDeleteVaultCancellationRoot(snapshot) &&
        plan.StatusSucceededDeleteVaultIndependentProfile == RoleFixtureJournal.StatusSucceededDeleteVaultIndependentRoot(snapshot) &&
        plan.OriginalPrivateConnectionUpdate == (snapshot.PrivateEndpoint?.OriginalUpdate is not null) &&
        plan.OriginalPrivateConnectionDelete == (snapshot.PrivateEndpoint?.OriginalDelete is not null) &&
        plan.PrivateEndpoint == snapshot.PrivateEndpoint?.Declaration &&
        plan.Manifest.Count == snapshot.Resources.Length && plan.Manifest.All(m =>
            snapshot.Resources.Count(r => r.Id == m.Id && r.Borrowed == m.Borrowed && r.CleanupOnly == m.CleanupOnly) == 1);

    internal static bool StatusVaultDeleteCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeleteVault" && selector.Case == "cancellation-boundary";

    internal static bool StatusVaultPurgeCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.PurgeDeletedVault" && selector.Case == "cancellation-boundary";

    internal static bool StatusVaultRecoverCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.RecoverVault" && selector.Case == "cancellation-boundary";

    internal static bool StatusVaultUpdateCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.CreateOrUpdateVault" && selector.Case == "cancellation-boundary";

    internal static bool StatusPrivateConnectionUpdateIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.UpdatePrivateConnection" && selector.Case == "independent-effect";

    internal static bool StatusPrivateConnectionUpdateCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.UpdatePrivateConnection" && selector.Case == "cancellation-boundary";

    internal static bool StatusPrivateConnectionDeleteSelectedSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeletePrivateConnection" && selector.Case == "selected-contract";

    internal static bool StatusPrivateConnectionDeleteIndependentSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeletePrivateConnection" && selector.Case == "independent-effect";

    internal static bool StatusPrivateConnectionDeleteCancellationSelector(FixtureSelector selector) =>
        selector is not null && selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        selector.Variant == "operation.DeletePrivateConnection" && selector.Case == "cancellation-boundary";

    private static bool StatusVaultUpdateCancellationCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        StatusVaultUpdateCancellationSelector(plan.Selector) && MatchesPlan(plan, snapshot) &&
        snapshot.Closing && snapshot.Idle && snapshot.StatusVaultUpdateCancellationBaseline is
        { Rbac: true, PurgeProtection: false, PublicNetworkAccess: false, Policies.Length: 0 } &&
        snapshot.StatusVaultRecoverCancellationBaseline is null && snapshot.PrivateEndpoint is null &&
        snapshot.Settings is null && snapshot.DeleteVault is null && snapshot.PurgeDeletedVault is null &&
        snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        plan.Preparation is Preparation.Active or Preparation.Absent && !plan.SeedCanary && plan.PrivateEndpoint is null &&
        !plan.OriginalCreate && !plan.OriginalRecover && !plan.OriginalPrivateConnectionUpdate &&
        !plan.OriginalPrivateConnectionDelete && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false } active &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
        { CleanupOnly: true, CreateAttempted: false, SelectedAttempted: false } deleted &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        {
            CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false,
            InvocationTerminated: false
        } &&
        (!active.SelectedAttempted || active.CreateAttempted && active.InvocationTerminated) &&
        (!active.DeleteAttempted || active.CreateAttempted && active.InvocationTerminated) &&
        (!deleted.DeleteAttempted || deleted.InvocationTerminated && active.DeleteAttempted && active.InvocationTerminated);

    private static bool StatusVaultRecoverCancellationCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        StatusVaultRecoverCancellationSelector(plan.Selector) && MatchesPlan(plan, snapshot) &&
        snapshot.Closing && snapshot.Idle && snapshot.StatusVaultRecoverCancellationBaseline is
        { Rbac: true, PurgeProtection: false, PublicNetworkAccess: true, Policies.Length: 0 } &&
        snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.DeleteVault is null &&
        snapshot.PurgeDeletedVault is null && snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
        plan.Preparation == Preparation.Deleted && !plan.SeedCanary && plan.PrivateEndpoint is null &&
        plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false } active &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is { CleanupOnly: false, SelectedAttempted: false } deleted &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        {
            CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false,
            InvocationTerminated: false
        } &&
        (!active.SelectedAttempted || active.CreateAttempted && active.InvocationTerminated &&
            deleted.CreateAttempted && deleted.InvocationTerminated) &&
        (!active.DeleteAttempted || active.CreateAttempted && active.InvocationTerminated) &&
        (!deleted.DeleteAttempted || deleted.InvocationTerminated);

    private async Task<Result> ReleaseStatusVaultPurgeCancellation(Plan plan, CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(StatusVaultPurgeCancellationSelector(plan.Selector) && MatchesPlan(plan, snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpoint is null && snapshot.Settings is null &&
            snapshot.DeleteVault is null && snapshot.PurgeDeletedVault is null &&
            snapshot.CreateOrUpdateVault is null && snapshot.RecoverVault is null &&
            plan.Preparation == Preparation.Deleted && !plan.SeedCanary &&
            plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
            snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && r.ActiveDispatch == Guid.Empty) &&
            snapshot.Resources.Single(r => r.Id == plan.VaultId) is
            {
                CleanupOnly: false, CreateAttempted: true, InvocationTerminated: true,
                SelectedAttempted: false, DeleteAttempted: false
            } &&
            snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
            {
                CleanupOnly: false, CreateAttempted: true, InvocationTerminated: true,
                SelectedAttempted: true, DeleteAttempted: false
            } &&
            snapshot.Resources.Single(r => r.Id == plan.SecretId) is
            {
                CleanupOnly: true, CreateAttempted: false, InvocationTerminated: false,
                SelectedAttempted: false, DeleteAttempted: false
            });
        // A settled status receipt authorizes no cleanup mutation. Both forms
        // must still be independently absent, including after reconstruction.
        var active = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        if (active is not null || deleted is not null)
        {
            if (active is not null) Presence(plan, plan.VaultId);
            if (deleted is not null) Presence(plan, plan.DeletedId);
            Presence(plan, plan.SecretId);
            return Finish(State.Uncertain, plan);
        }
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);
    }

    private static bool SelectedDeleteCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        MatchesPlan(plan, snapshot) && snapshot.Closing && snapshot.PrivateEndpoint is null &&
        snapshot.Selector.Operation == "a.management.ManagementOperation.CheckStatusAsync" &&
        snapshot.Selector.Variant == "operation.DeleteVault" &&
        snapshot.Selector.Case is "selected-contract" or "independent-effect" or "cancellation-boundary" &&
        plan.Preparation == Preparation.Active && !plan.SeedCanary &&
        snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed && r.ActiveDispatch == Guid.Empty) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false, CreateAttempted: true, DeleteAttempted: false, SelectedAttempted: true, InvocationTerminated: true } &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is { CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false, InvocationTerminated: false } &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is { CleanupOnly: true, CreateAttempted: false, SelectedAttempted: false };

    private static bool OriginalDeleteCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        DeleteVaultSelector(plan.Selector) && MatchesPlan(plan, snapshot) && snapshot.Closing && snapshot.Idle &&
        snapshot.DeleteVault is { } deletion && deletion.VaultId == plan.VaultId &&
        !deletion.Baseline.PurgeProtection && snapshot.Settings is null && snapshot.PrivateEndpoint is null &&
        plan.Preparation is Preparation.Active or Preparation.Absent && !plan.SeedCanary &&
        plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && r.ActiveDispatch == Guid.Empty) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false } vault &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        { CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false } &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
        { CleanupOnly: true, CreateAttempted: false, SelectedAttempted: false } &&
        (deletion.InvocationDispatch == Guid.Empty
            ? !vault.SelectedAttempted && deletion.Disposition == RoleFixtureJournal.DeleteVaultDisposition.None
            : vault.SelectedAttempted && deletion.SettledDispatch == deletion.InvocationDispatch &&
                deletion.Disposition is RoleFixtureJournal.DeleteVaultDisposition.Deleted or RoleFixtureJournal.DeleteVaultDisposition.Denied) &&
        (deletion.Disposition != RoleFixtureJournal.DeleteVaultDisposition.Deleted || !vault.DeleteAttempted);

    private static bool PurgeDeletedVaultCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot,
        bool requirePrepared = false) =>
        PurgeDeletedVaultSelector(plan.Selector) && MatchesPlan(plan, snapshot) && snapshot.Closing && snapshot.Idle &&
        snapshot.PurgeDeletedVault is { } purge && purge.VaultId == plan.VaultId &&
        purge.DeletedVaultId == plan.DeletedId && !purge.Baseline.PurgeProtection &&
        snapshot.Settings is null && snapshot.DeleteVault is null && snapshot.PrivateEndpoint is null &&
        plan.Preparation == Preparation.Deleted && !plan.SeedCanary &&
        plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && r.ActiveDispatch == Guid.Empty) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is
        { CleanupOnly: false, DeleteAttempted: false, SelectedAttempted: false } vault &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        { CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false } &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is { CleanupOnly: false } deleted &&
        (purge.InvocationDispatch == Guid.Empty
            ? !deleted.SelectedAttempted && purge.Disposition == RoleFixtureJournal.PurgeDeletedVaultDisposition.None
            : deleted.SelectedAttempted && purge.SettledDispatch == purge.InvocationDispatch &&
                purge.Disposition is RoleFixtureJournal.PurgeDeletedVaultDisposition.Purged or RoleFixtureJournal.PurgeDeletedVaultDisposition.Denied) &&
        (!requirePrepared || vault.CreateAttempted && vault.InvocationTerminated &&
            deleted.CreateAttempted && deleted.InvocationTerminated && !deleted.DeleteAttempted);

    private async Task<Result> ReleasePurgeDeletedVault(Plan plan, bool purge, CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(purge && PurgeDeletedVaultCleanupRoot(plan, snapshot));
        // This profile never deletes an active parent, even during partial
        // preparation or after a settled purge. Caller flags cannot weaken it.
        var active = await ReadVault(plan, token).ConfigureAwait(false);
        if (active is not null)
        {
            Presence(plan, plan.VaultId);
            Presence(plan, plan.SecretId);
            return Finish(State.Uncertain, plan);
        }
        var deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        if (deleted is not null)
        {
            Presence(plan, plan.DeletedId);
            Presence(plan, plan.SecretId);
            ValidateDeleted(plan, deleted);
            if (snapshot.PurgeDeletedVault!.Disposition == RoleFixtureJournal.PurgeDeletedVaultDisposition.Purged)
                return Finish(State.Uncertain, plan);
            Require(PurgeDeletedVaultCleanupRoot(plan, snapshot, requirePrepared: true) &&
                deleted.Properties.PurgeProtectionEnabled == false);
            await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token).ConfigureAwait(false);
            snapshot = ReadPlan(plan.Owner, plan.Selector);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            active = await ReadVault(plan, token).ConfigureAwait(false);
            deleted = await ReadDeleted(plan, token).ConfigureAwait(false);
        }
        if (active is not null || deleted is not null)
        {
            if (active is not null) Presence(plan, plan.VaultId);
            if (deleted is not null) Presence(plan, plan.DeletedId);
            Presence(plan, plan.SecretId);
            return Finish(State.Uncertain, plan);
        }
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);
    }

    private static bool DeletedVaultReadProfile(Plan plan) =>
        GetDeletedVaultReadProfile(plan) || DeletedVaultListReadProfile(plan);

    private static bool GetDeletedVaultReadProfile(Plan plan) =>
        plan.Preparation == Preparation.Deleted && !plan.SeedCanary &&
        plan.Selector.Operation == "a.management.VaultAdministration.GetDeletedVaultAsync" &&
        plan.Selector.Variant == "selector.exact" &&
        plan.Selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal static bool DeletedVaultListReadSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.ListDeletedVaultsAsync" &&
        selector.Variant == "collection.bounded" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    private static bool DeletedVaultListReadProfile(Plan plan) =>
        DeletedVaultListReadSelector(plan.Selector) && plan.Preparation == Preparation.Deleted &&
        !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        plan.PrivateEndpoint is null;

    // This predicate admits coordinates for cleanup, not original readiness.
    // Unknown dispatches remain fenced by the caller's independent Idle gate.
    private static bool DeletedVaultReadCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot,
        bool requirePrepared = false) =>
        DeletedVaultReadProfile(plan) && MatchesPlan(plan, snapshot) && snapshot.Closing &&
        snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed && !r.SelectedAttempted) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false, DeleteAttempted: false } vault &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        { CleanupOnly: true, CreateAttempted: false, DeleteAttempted: false, InvocationTerminated: false, ActiveDispatch: var canary } &&
        canary == Guid.Empty &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is { CleanupOnly: false } deleted &&
        (!requirePrepared || vault.CreateAttempted && vault.InvocationTerminated &&
            deleted.CreateAttempted && deleted.InvocationTerminated && !deleted.DeleteAttempted &&
            snapshot.Idle);

    internal VaultScope Scope(Plan plan)
    {
        CheckPlan(plan);
        Require(MatchesPlan(plan, ReadPlan(plan.Owner, plan.Selector)));
        return new(new(new(host.SubscriptionId), host.ResourceGroup), plan.VaultName);
    }

    internal void BindNotification(Plan plan, RoleFixtureJournal childJournal, VaultScope vault, string notificationName)
    {
        Require(!NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector) ||
            MatchesStatusDeniedNotificationOperation(plan.Selector));
        lock (plans)
        {
            CheckPlan(plan);
            Require(ReferenceEquals(journal, childJournal) && !plan.Restored &&
                plan.Preparation == Preparation.Active && vault.ExportResourceId() == plan.VaultId &&
                plan.OwnedNotificationNames.Contains(notificationName, StringComparer.Ordinal));
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            string id = plan.VaultId + NotificationPrefix + notificationName;
            Require(!snapshot.Closing && snapshot.Idle &&
            snapshot.Resources.Single(r => r.Id == id) is { Borrowed: false, CleanupOnly: false, CreateAttempted: false, DeleteAttempted: false, SelectedAttempted: false, Absent: false });
            Require(notificationBindings.Add((plan.Selector.Nonce, id)));
        }
    }

    internal bool MatchesOwnedPlan(Plan plan, RoleFixtureJournal.Snapshot snapshot)
    {
        lock (plans)
            return !closed && ReferenceEquals(plan.Source, source) &&
                plans.TryGetValue(plan.Selector.Nonce, out var retained) && ReferenceEquals(retained, plan) &&
                MatchesHost(snapshot) && MatchesPlan(plan, snapshot);
    }

    internal bool OwnsPreparedPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && MatchesPlan(plan, snapshot) &&
                plan.Preparation == Preparation.Active &&
                snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                { CreateAttempted: true, DeleteAttempted: false, CleanupOnly: false, Absent: false, SelectedAttempted: false };
        }
    }

    internal bool OwnsPreparedDeletedVaultReadPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0 || !GetDeletedVaultReadProfile(plan)) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && DeletedVaultReadRoot(plan, snapshot);
        }
    }

    internal bool OwnsPreparedDeletedVaultListReadPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0 || !DeletedVaultListReadProfile(plan)) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && DeletedVaultReadRoot(plan, snapshot);
        }
    }

    private static bool VaultNameReadProfile(Plan plan) =>
        plan.Preparation == Preparation.Active && !plan.SeedCanary &&
        plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 && plan.PrivateEndpoint is null &&
        plan.Selector.Operation == "a.management.VaultAdministration.CheckNameAvailabilityAsync" &&
        plan.Selector.Variant == "selector.exact" &&
        plan.Selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal bool OwnsPreparedVaultNameReadPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0 || !VaultNameReadProfile(plan)) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && VaultReadRoot(plan, snapshot);
        }
    }

    internal static bool VaultGroupListReadSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.ListVaultsAsync.ResourceGroup" &&
        selector.Variant == "collection.bounded" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    private static bool VaultGroupListReadProfile(Plan plan) =>
        VaultGroupListReadSelector(plan.Selector) && plan.Preparation == Preparation.Active &&
        !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        plan.PrivateEndpoint is null;

    internal bool OwnsPreparedVaultGroupListReadPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0 || !VaultGroupListReadProfile(plan)) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && VaultReadRoot(plan, snapshot);
        }
    }

    internal static bool VaultSubscriptionListReadSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.ListVaultsAsync.Subscription" &&
        selector.Variant == "collection.bounded" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    private static bool VaultSubscriptionListReadProfile(Plan plan) =>
        VaultSubscriptionListReadSelector(plan.Selector) && plan.Preparation == Preparation.Active &&
        !plan.SeedCanary && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        plan.PrivateEndpoint is null;

    internal bool OwnsPreparedVaultSubscriptionListReadPlan(Plan plan)
    {
        lock (plans)
        {
            if (closed || plan is null || !ReferenceEquals(plan.Source, source) || plan.Restored ||
                !plans.TryGetValue(plan.Selector.Nonce, out var retained) || !ReferenceEquals(retained, plan) ||
                !originalReady.Contains(plan) || plan.Busy != 0 || !VaultSubscriptionListReadProfile(plan)) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            return !snapshot.Closing && snapshot.Idle && VaultReadRoot(plan, snapshot);
        }
    }

    // A read loan owns the original plan's exclusive borrower slot AND the
    // journal fence. It is not readiness reconstructed from stored coordinates.
    internal sealed class VaultReadLoan(Plan plan, Guid dispatch, PrivateConnectionReadAdmission? privateConnection = null)
    {
        internal Plan Plan { get; } = plan;
        internal Guid Dispatch { get; } = dispatch;
        internal PrivateConnectionReadAdmission? PrivateConnection { get; } = privateConnection;
        internal bool Observing, Observed;
        public override string ToString() => "[VaultReadLoan]";
    }

    internal static bool PrivateConnectionDeleteSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.DeletePrivateConnectionAsync" &&
        selector.Variant == "input.scope" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal sealed class PrivateConnectionDeleteLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[PrivateConnectionDeleteLoan]";
    }
    internal sealed record PrivateConnectionDeleteWitness(Result Result, string ActiveDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[PrivateConnectionDeleteWitness]";
    }
    private sealed class PrivateConnectionDeleteRead(PrivateConnectionDeleteLoan loan)
    {
        internal readonly PrivateConnectionDeleteLoan Loan = loan;
        internal Task<PrivateConnectionDeleteWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal Task<(string? Digest, string? Version)>? CanaryTask;
        internal JsonElement? RawParent;
        internal PrivateConnectionDeleteWitness? Witness;
        internal bool Finished;
    }
    private readonly Dictionary<PrivateConnectionDeleteLoan,
        (PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Plan, string Connection)>
        privateDeleteEndpoints = new(ReferenceEqualityComparer.Instance);

    private VaultAdministrationEffects.Configuration PrivateDeleteConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(plan.OriginalPrivateConnectionDelete && snapshot.PrivateEndpoint?.OriginalDelete is not null);
        return CopyConfiguration(snapshot.PrivateEndpoint.OriginalDelete.Baseline);
    }

    internal PrivateConnectionDeleteLoan EnterPrivateConnectionDelete(Plan originalPlan,
        PrivateEndpointFixtureProvisioner endpoints, PrivateEndpointFixtureProvisioner.Plan endpointPlan,
        string connectionId)
    {
        Require(endpoints is not null && endpoints.OwnsBoundPlan(endpointPlan, originalPlan, connectionId));
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(privateConnectionDeleteProfile && originalPlan.OriginalPrivateConnectionDelete &&
                PrivateConnectionDeleteSelector(originalPlan.Selector) && !originalPlan.Restored &&
                originalReady.Contains(originalPlan) && originalPlan.Busy == 0 && originalPlan.SeedCanary &&
                originalPlan.Preparation == Preparation.Active && originalPlan.PrivateEndpoint is not null &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.CanaryVersion is not null && originalPlan.CanarySha256 is not null &&
                !snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpoint?.Connection?.Id == connectionId &&
                snapshot.PrivateEndpoint.OriginalDelete is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                snapshot.Resources.All(r => !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent) &&
                !privateDeleteLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new PrivateConnectionDeleteLoan(originalPlan);
            privateDeleteLoans.Add(originalPlan, loan);
            privateDeleteEndpoints.Add(loan, (endpoints, endpointPlan, connectionId));
            privateDeleteReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckPrivateConnectionDeleteLoan(PrivateConnectionDeleteLoan loan)
    {
        Require(loan is not null);
        (PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Plan, string Connection) endpoint;
        lock (plans)
        {
            Require(!closed && loan.Plan.OriginalPrivateConnectionDelete && !loan.Plan.Restored &&
                loan.Plan.Busy == 1 && originalReady.Contains(loan.Plan) &&
                privateDeleteLoans.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            Require(privateDeleteEndpoints.TryGetValue(loan, out endpoint));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) &&
                snapshot.PrivateEndpoint?.OriginalDelete is not null &&
                snapshot.PrivateEndpoint.Connection?.Id == endpoint.Connection &&
                snapshot.Resources.All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent));
        }
        Require(endpoint.Endpoints.OwnsBoundPlan(endpoint.Plan, loan.Plan, endpoint.Connection));
    }

    internal Task<PrivateConnectionDeleteWitness> ObservePrivateConnectionDeleteAsync(
        PrivateConnectionDeleteLoan loan, CancellationToken token)
    {
        CheckPrivateConnectionDeleteLoan(loan);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<PrivateConnectionDeleteWitness> task;
        lock (plans)
        {
            var reads = privateDeleteReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var read = new PrivateConnectionDeleteRead(loan);
            reads.Add(read);
            task = read.Task = ObservePrivateConnectionDeleteCore(read, token, start.Task);
        }
        // Publish the exact task before any host credential/transport code.
        start.SetResult();
        return task;
    }

    private async Task<PrivateConnectionDeleteWitness> ObservePrivateConnectionDeleteCore(
        PrivateConnectionDeleteRead read, CancellationToken token, Task start)
    {
        await start.ConfigureAwait(false);
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var expected = PrivateDeleteConfiguration(plan);
            JsonElement? raw = null;
            var native = (await ReadArm(plan, plan.VaultId,
                (client, ct) => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
                root => raw = root.Clone(), linked.Token, privateDeleteLoan: read.Loan).ConfigureAwait(false))?.Data;
            var deleted = await ReadArm(plan, plan.DeletedId,
                (client, ct) => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                DeletedShape, linked.Token, privateDeleteLoan: read.Loan).ConfigureAwait(false);
            Require(native is not null && deleted is null && raw is not null);
            PrivateConnectionDeleteRead? baselineRead;
            string connection;
            lock (plans)
            {
                baselineRead = privateDeleteReads[read.Loan].FirstOrDefault(r => !ReferenceEquals(r, read));
                connection = privateDeleteEndpoints[read.Loan].Connection;
            }
            string digest = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, raw.Value,
                expected, "Succeeded", privateConnection: connection, privateEndpoint: plan.PrivateEndpoint!.EndpointId,
                allowAbsentPrivateConnection: baselineRead is not null);
            JoinRecoverActive(plan, native, expected);
            Require(!raw.Value.TryGetProperty("error", out _));
            if (baselineRead is not null)
            {
                Require(baselineRead.RawParent is not null);
                var before = baselineRead.RawParent.Value;
                Require(SamePrivateDeleteFields(before, raw.Value, "properties") &&
                    SamePrivateDeleteFields(before.GetProperty("properties"), raw.Value.GetProperty("properties"),
                        "privateEndpointConnections"));
                if (plan.Selector.Case == "denied-authority")
                    Require(JsonElement.DeepEquals(before, raw.Value));
            }
            if (raw.Value.GetProperty("properties").TryGetProperty("privateEndpointConnections", out var children))
            {
                if (baselineRead is null || plan.Selector.Case == "denied-authority")
                    Require(children.GetArrayLength() == 1 &&
                        children[0].GetProperty("properties").GetProperty("privateLinkServiceConnectionState")
                            .GetProperty("status").GetString() == "Pending" &&
                        children[0].GetProperty("properties").GetProperty("provisioningState").GetString() == "Succeeded");
                else if (children.GetArrayLength() != 0)
                {
                    // Only removal of the selected relationship is tolerated.
                    Require(baselineRead.RawParent!.Value.GetProperty("properties")
                        .TryGetProperty("privateEndpointConnections", out var beforeChildren) &&
                        JsonElement.DeepEquals(beforeChildren, children));
                }
            }
            read.RawParent = raw;
            read.CanaryTask = ReadCanary(plan, linked.Token, privateDeleteLoan: read.Loan);
            var canary = await read.CanaryTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            CheckPrivateConnectionDeleteLoan(read.Loan);
            Require(canary.Digest is not null && canary.Digest == plan.CanarySha256 &&
                canary.Version is not null && canary.Version == plan.CanaryVersion);
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = ReadPlan(plan.Owner, plan.Selector),
                VaultPresent = true,
                DeletedVaultPresent = false,
                Configuration = Configuration(native),
                CanaryPresent = true,
                CanarySha256 = canary.Digest,
                CanaryVersion = canary.Version
            }, digest, started, finished);
        }
        finally { lock (plans) read.Finished = true; }
    }

    private static bool SamePrivateDeleteFields(JsonElement left, JsonElement right, string excluded)
    {
        var fields = left.EnumerateObject().Where(p => p.Name != excluded).ToArray();
        return right.EnumerateObject().Count(p => p.Name != excluded) == fields.Length &&
            fields.All(p => right.TryGetProperty(p.Name, out var value) && JsonElement.DeepEquals(p.Value, value));
    }

    internal bool OwnsPrivateConnectionDeleteWitness(PrivateConnectionDeleteWitness witness,
        PrivateConnectionDeleteLoan loan, Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && privateDeleteReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Loan, loan) && ReferenceEquals(r.Witness, witness) &&
                    ReferenceEquals(r.Task, originalTask) && r.Task is { IsCompletedSuccessfully: true } && r.Finished &&
                    r.ActiveTask is { IsCompletedSuccessfully: true } && r.DeletedTask is { IsCompleted: true } &&
                    r.CanaryTask is { IsCompletedSuccessfully: true } &&
                    witness.Result.CanarySha256 == loan.Plan.CanarySha256 &&
                    witness.Result.CanaryVersion == loan.Plan.CanaryVersion &&
                    witness.Result.Configuration is { } configuration &&
                    VaultAdministrationEffects.SameConfiguration(configuration, Configuration(r.ActiveTask.Result.Value.Data)));
    }

    internal bool OwnsPrivateConnectionDeleteAbsentRelationship(PrivateConnectionDeleteWitness witness,
        PrivateConnectionDeleteLoan loan, Task originalTask)
    {
        lock (plans)
        {
            if (!OwnsPrivateConnectionDeleteWitness(witness, loan, originalTask) ||
                !privateDeleteReads.TryGetValue(loan, out var reads) || reads.Count != 2 ||
                !ReferenceEquals(reads[1].Witness, witness) || !ReferenceEquals(reads[1].Task, originalTask) ||
                reads[0].Witness is null || reads[0].Task is not { IsCompletedSuccessfully: true } ||
                reads[1].RawParent is not { } parent) return false;
            // Omission is permitted, but the service must separately prove the
            // concrete child's 404. A retained Pending relationship cannot pass.
            if (!parent.GetProperty("properties").TryGetProperty("privateEndpointConnections", out var children))
                return true;
            if (children.ValueKind != JsonValueKind.Array || children.GetArrayLength() != 0) return false;
            using var native = JsonDocument.Parse(ModelReaderWriter.Write(reads[1].ActiveTask!.Result.Value.Data).ToMemory());
            return native.RootElement.GetProperty("properties").TryGetProperty("privateEndpointConnections", out var nativeChildren) &&
                JsonElement.DeepEquals(children, nativeChildren);
        }
    }

    internal void ExitPrivateConnectionDelete(PrivateConnectionDeleteLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && privateDeleteLoans.TryGetValue(loan.Plan, out var retained) &&
                ReferenceEquals(retained, loan) &&
                privateDeleteReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            privateDeleteLoans.Remove(loan.Plan);
            Exit(loan.Plan);
        }
    }

    internal Task PrivateConnectionDeleteDrain(PrivateEndpointFixtureProvisioner endpoints, Plan parent)
    {
        lock (plans)
            return privateDeleteLoans.TryGetValue(parent, out var loan) &&
                privateDeleteEndpoints.TryGetValue(loan, out var endpoint) && ReferenceEquals(endpoint.Endpoints, endpoints)
                ? parent.Drained!.Task : Task.CompletedTask;
    }

    private void CheckPrivateDeleteCanary(PrivateConnectionDeleteLoan loan, HttpMessage message)
    {
        CheckPrivateConnectionDeleteLoan(loan);
        var plan = loan.Plan;
        var headers = message.Request.Headers.ToArray();
        Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
            message.Request.Uri.ToUri().OriginalString == SecretOrigin(plan).GetLeftPart(UriPartial.Authority) +
                "/secrets/" + Canary + "/" + plan.CanaryVersion + "?api-version=" + SecretRevision &&
            message.Request.Headers.TryGetValue("Authorization", out var auth) &&
            auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
            headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
            !message.Request.Headers.Contains("Content-Length") && !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
        if (message.Request.Headers.TryGetValue("Host", out var requestHost)) Require(requestHost == SecretOrigin(plan).Host);
        message.CancellationToken.ThrowIfCancellationRequested();
    }

    internal static bool PrivateConnectionUpdateSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.UpdatePrivateConnectionAsync" &&
        selector.Variant is "state.Unknown.rejected" or "state.Pending.rejected" or "state.Approved" or
            "state.Rejected" or "state.Disconnected.rejected" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal sealed class PrivateConnectionUpdateLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[PrivateConnectionUpdateLoan]";
    }
    internal sealed record PrivateConnectionUpdateWitness(Result Result, string ActiveDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[PrivateConnectionUpdateWitness]";
    }
    private sealed class PrivateConnectionUpdateRead(PrivateConnectionUpdateLoan loan,
        PrivateEndpointFixtureProvisioner endpoints, PrivateEndpointFixtureProvisioner.Plan endpointPlan,
        string connectionId)
    {
        internal readonly PrivateConnectionUpdateLoan Loan = loan;
        internal readonly PrivateEndpointFixtureProvisioner Endpoints = endpoints;
        internal readonly PrivateEndpointFixtureProvisioner.Plan EndpointPlan = endpointPlan;
        internal readonly string ConnectionId = connectionId;
        internal Task<PrivateConnectionUpdateWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal Task<(string? Digest, string? Version)>? CanaryTask;
        internal JsonElement? RawParent;
        internal PrivateConnectionUpdateWitness? Witness;
        internal bool Finished;
    }
    private readonly Dictionary<PrivateConnectionUpdateLoan,
        (PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Plan, string Connection)>
        privateUpdateEndpoints = new(ReferenceEqualityComparer.Instance);

    private VaultAdministrationEffects.Configuration PrivateUpdateConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(plan.OriginalPrivateConnectionUpdate && snapshot.PrivateEndpoint?.OriginalUpdate is not null);
        return CopyConfiguration(snapshot.PrivateEndpoint.OriginalUpdate.Baseline);
    }

    internal PrivateConnectionUpdateLoan EnterPrivateConnectionUpdate(Plan originalPlan,
        PrivateEndpointFixtureProvisioner endpoints, PrivateEndpointFixtureProvisioner.Plan endpointPlan,
        string connectionId)
    {
        Require(endpoints is not null && endpoints.OwnsBoundPlan(endpointPlan, originalPlan, connectionId));
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(originalPlan.OriginalPrivateConnectionUpdate &&
                privateConnectionUpdateVariant == originalPlan.Selector.Variant && !originalPlan.Restored &&
                originalReady.Contains(originalPlan) && originalPlan.Busy == 0 && originalPlan.SeedCanary &&
                originalPlan.Preparation == Preparation.Active && originalPlan.PrivateEndpoint is not null &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.CanaryVersion is not null && originalPlan.CanarySha256 is not null &&
                !snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpoint?.Connection?.Id == connectionId &&
                snapshot.PrivateEndpoint.OriginalUpdate is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                snapshot.Resources.All(r => !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent) &&
                !privateUpdateLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new PrivateConnectionUpdateLoan(originalPlan);
            privateUpdateLoans.Add(originalPlan, loan);
            privateUpdateEndpoints.Add(loan, (endpoints, endpointPlan, connectionId));
            privateUpdateReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckPrivateConnectionUpdateLoan(PrivateConnectionUpdateLoan loan)
    {
        Require(loan is not null);
        (PrivateEndpointFixtureProvisioner Endpoints, PrivateEndpointFixtureProvisioner.Plan Plan, string Connection) endpoint;
        lock (plans)
        {
            Require(!closed && loan.Plan.OriginalPrivateConnectionUpdate && !loan.Plan.Restored &&
                loan.Plan.Busy == 1 && originalReady.Contains(loan.Plan) &&
                privateUpdateLoans.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            Require(privateUpdateEndpoints.TryGetValue(loan, out endpoint));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && snapshot.PrivateEndpoint?.OriginalUpdate is not null &&
                snapshot.PrivateEndpoint.Connection?.Id == endpoint.Connection &&
                snapshot.Resources.All(r => r.ActiveDispatch == Guid.Empty &&
                    !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent));
        }
        Require(endpoint.Endpoints.OwnsBoundPlan(endpoint.Plan, loan.Plan, endpoint.Connection));
    }

    internal Task<PrivateConnectionUpdateWitness> ObservePrivateConnectionUpdateAsync(
        PrivateConnectionUpdateLoan loan, CancellationToken token)
    {
        CheckPrivateConnectionUpdateLoan(loan);
        var start = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        Task<PrivateConnectionUpdateWitness> task;
        lock (plans)
        {
            var reads = privateUpdateReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var endpoint = privateUpdateEndpoints[loan];
            var read = new PrivateConnectionUpdateRead(loan, endpoint.Endpoints, endpoint.Plan, endpoint.Connection);
            reads.Add(read);
            task = read.Task = ObservePrivateConnectionUpdateCore(read, token, start.Task);
        }
        start.SetResult();
        return task;
    }

    private async Task<PrivateConnectionUpdateWitness> ObservePrivateConnectionUpdateCore(
        PrivateConnectionUpdateRead read, CancellationToken token, Task start)
    {
        await start.ConfigureAwait(false);
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var expected = PrivateUpdateConfiguration(plan);
            JsonElement? activeRaw = null;
            var native = (await ReadArm(plan, plan.VaultId,
                (client, ct) => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
                root => activeRaw = root.Clone(), linked.Token, privateUpdateLoan: read.Loan).ConfigureAwait(false))?.Data;
            var deleted = await ReadArm(plan, plan.DeletedId,
                (client, ct) => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                DeletedShape, linked.Token, privateUpdateLoan: read.Loan).ConfigureAwait(false);
            Require(native is not null && deleted is null && activeRaw is not null);
            string digest = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, activeRaw.Value,
                expected, "Succeeded", privateConnection: read.ConnectionId, privateEndpoint: plan.PrivateEndpoint!.EndpointId);
            JoinRecoverActive(plan, native, expected);
            Require(!activeRaw.Value.TryGetProperty("error", out _));
            PrivateConnectionUpdateRead? baselineRead;
            lock (plans) baselineRead = privateUpdateReads[read.Loan].FirstOrDefault(r => !ReferenceEquals(r, read));
            if (baselineRead is not null)
            {
                Require(baselineRead.RawParent is not null);
                var before = baselineRead.RawParent.Value;
                var after = activeRaw.Value;
                Require(SameFields(before, after, "properties") &&
                    SameFields(before.GetProperty("properties"), after.GetProperty("properties"), "privateEndpointConnections"));
            }
            if (activeRaw.Value.GetProperty("properties").TryGetProperty("privateEndpointConnections", out var children))
            {
                PrivateConnectionState requested = Enum.Parse<PrivateConnectionState>(plan.Selector.Variant.Split('.')[1]);
                var state = baselineRead is null || plan.Selector.Case == "denied-authority" ||
                    requested is not (PrivateConnectionState.Approved or PrivateConnectionState.Rejected)
                    ? PrivateConnectionState.Pending : requested;
                Require(children[0].GetProperty("properties").GetProperty("privateLinkServiceConnectionState")
                    .GetProperty("status").GetString() == state.ToString() &&
                    children[0].GetProperty("properties").GetProperty("provisioningState").GetString() == "Succeeded");
                using var serialized = JsonDocument.Parse(ModelReaderWriter.Write(native).ToMemory());
                Require(serialized.RootElement.GetProperty("properties").TryGetProperty("privateEndpointConnections",
                    out var nativeChildren) && JsonElement.DeepEquals(children, nativeChildren));
            }
            read.RawParent = activeRaw;
            read.CanaryTask = ReadCanary(plan, linked.Token, privateUpdateLoan: read.Loan);
            var canary = await read.CanaryTask.ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            CheckPrivateConnectionUpdateLoan(read.Loan);
            Require(canary.Digest is not null && canary.Digest == plan.CanarySha256 &&
                canary.Version is not null && canary.Version == plan.CanaryVersion);
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = ReadPlan(plan.Owner, plan.Selector),
                VaultPresent = true,
                DeletedVaultPresent = false,
                Configuration = Configuration(native),
                CanaryPresent = true,
                CanarySha256 = canary.Digest,
                CanaryVersion = canary.Version
            }, digest, started, finished);
        }
        finally { lock (plans) read.Finished = true; }

        static bool SameFields(JsonElement left, JsonElement right, string excluded)
        {
            var fields = left.EnumerateObject().Where(p => p.Name != excluded).ToArray();
            return right.EnumerateObject().Count(p => p.Name != excluded) == fields.Length &&
                fields.All(p => right.TryGetProperty(p.Name, out var value) && JsonElement.DeepEquals(p.Value, value));
        }
    }

    internal bool OwnsPrivateConnectionUpdateWitness(PrivateConnectionUpdateWitness witness,
        PrivateConnectionUpdateLoan loan, Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && privateUpdateReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Loan, loan) && ReferenceEquals(r.Witness, witness) &&
                    ReferenceEquals(r.Task, originalTask) && r.Task is { IsCompletedSuccessfully: true } && r.Finished &&
                    r.ActiveTask is { IsCompletedSuccessfully: true } && r.DeletedTask is { IsCompleted: true } &&
                    r.CanaryTask is { IsCompletedSuccessfully: true } &&
                    witness.Result.CanarySha256 == loan.Plan.CanarySha256 &&
                    witness.Result.CanaryVersion == loan.Plan.CanaryVersion &&
                    witness.Result.Configuration is { } configuration &&
                    VaultAdministrationEffects.SameConfiguration(configuration, Configuration(r.ActiveTask.Result.Value.Data)));
    }

    internal void ExitPrivateConnectionUpdate(PrivateConnectionUpdateLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && privateUpdateLoans.TryGetValue(loan.Plan, out var retained) &&
                ReferenceEquals(retained, loan) &&
                privateUpdateReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            privateUpdateLoans.Remove(loan.Plan);
            Exit(loan.Plan);
        }
    }

    internal Task PrivateConnectionUpdateDrain(PrivateEndpointFixtureProvisioner endpoints, Plan parent)
    {
        lock (plans)
            return privateUpdateLoans.TryGetValue(parent, out var loan) &&
                privateUpdateEndpoints.TryGetValue(loan, out var endpoint) && ReferenceEquals(endpoint.Endpoints, endpoints)
                ? parent.Drained!.Task : Task.CompletedTask;
    }

    private void CheckPrivateUpdateCanary(PrivateConnectionUpdateLoan loan, HttpMessage message)
    {
        CheckPrivateConnectionUpdateLoan(loan);
        var plan = loan.Plan;
        var headers = message.Request.Headers.ToArray();
        Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
            message.Request.Uri.ToUri().OriginalString == SecretOrigin(plan).GetLeftPart(UriPartial.Authority) +
                "/secrets/" + Canary + "/" + plan.CanaryVersion + "?api-version=" + SecretRevision &&
            message.Request.Headers.TryGetValue("Authorization", out var auth) &&
            auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length > 7 &&
            headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
            !message.Request.Headers.Contains("Content-Length") && !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
        if (message.Request.Headers.TryGetValue("Host", out var requestHost))
            Require(requestHost == SecretOrigin(plan).Host);
        message.CancellationToken.ThrowIfCancellationRequested();
    }

    internal static bool PrivateConnectionReadSelector(FixtureSelector selector) =>
        (selector.Operation == "a.management.VaultAdministration.GetPrivateConnectionAsync" &&
            selector.Variant == "selector.exact" ||
         selector.Operation == "a.management.VaultAdministration.ListPrivateConnectionsAsync" &&
            selector.Variant == "collection.bounded" ||
         selector.Operation == "a.management.VaultAdministration.ListPrivateLinkResourcesAsync" &&
            selector.Variant == "collection.bounded") &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal static bool PrivateConnectionReadProfile(Plan plan) =>
        PrivateConnectionReadSelector(plan.Selector) && plan.Preparation == Preparation.Active && plan.SeedCanary &&
        plan.PrivateEndpoint is not null && plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0;

    internal sealed class PrivateConnectionReadAdmission(VaultFixtureProvisioner source, Plan parent,
        PrivateEndpointFixtureProvisioner endpoints, PrivateEndpointFixtureProvisioner.Plan endpointPlan, string connectionId)
    {
        internal Plan Parent { get; } = parent;
        internal PrivateEndpointFixtureProvisioner Endpoints { get; } = endpoints;
        internal PrivateEndpointFixtureProvisioner.Plan EndpointPlan { get; } = endpointPlan;
        internal string ConnectionId { get; } = connectionId;
        // Called under the journal lock. Registry identity and immutable
        // coordinates only: no parent/PPS locks or host callbacks.
        internal bool Validate(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot) =>
            ReferenceEquals(source.journal, journal) && source.privateReads.TryGetValue(this, out var registered) &&
            ReferenceEquals(registered, Parent) && PrivateConnectionReadProfile(Parent) &&
            MatchesPlan(Parent, snapshot) && snapshot.PrivateEndpoint?.Connection?.Id == ConnectionId;
        internal bool ValidateDrain(RoleFixtureJournal journal, RoleFixtureJournal.Snapshot snapshot, Guid dispatch) =>
            Validate(journal, snapshot) && source.privateReadDrains.TryGetValue(this, out var draining) &&
            draining == dispatch && dispatch != Guid.Empty;
        public override string ToString() => "[PrivateConnectionReadAdmission]";
    }

    internal PrivateConnectionReadAdmission RegisterPrivateConnectionRead(Plan parent,
        PrivateEndpointFixtureProvisioner endpoints, PrivateEndpointFixtureProvisioner.Plan endpointPlan, string connectionId)
    {
        Require(endpoints is not null && endpoints.OwnsBoundPlan(endpointPlan, parent, connectionId));
        lock (plans)
        {
            CheckPlan(parent);
            Require(!parent.Restored && PrivateConnectionReadProfile(parent) && originalReady.Contains(parent) &&
                parent.Busy == 0 && parent.CanaryVersion is not null && parent.CanarySha256 is not null &&
                !privateReads.Values.Any(p => ReferenceEquals(p, parent)));
            var snapshot = ReadPlan(parent.Owner, parent.Selector);
            Require(!snapshot.Closing && snapshot.Idle && MatchesPlan(parent, snapshot) &&
                snapshot.PrivateEndpoint?.Connection?.Id == connectionId);
            var admission = new PrivateConnectionReadAdmission(this, parent, endpoints, endpointPlan, connectionId);
            Require(privateReads.TryAdd(admission, parent));
            return admission;
        }
    }

    internal bool TryEnterPrivateConnectionRead(Plan originalPlan, PrivateConnectionReadAdmission admission,
        [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        loan = null;
        // The original PPS proof is checked before acquiring parent/journal
        // locks. The immutable registry check in journal admission is separate.
        Require(admission is not null && ReferenceEquals(admission.Parent, originalPlan) &&
            privateReads.TryGetValue(admission, out var registered) && ReferenceEquals(registered, originalPlan) &&
            admission.Endpoints.OwnsBoundPlan(admission.EndpointPlan, originalPlan, admission.ConnectionId));
        lock (plans)
        {
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) && PrivateConnectionReadProfile(originalPlan));
            if (originalPlan.Busy != 0) return false;
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginPrivateConnectionRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, admission);
                loan = new(originalPlan, dispatch, admission);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal Task PrivateConnectionReadDrain(PrivateEndpointFixtureProvisioner endpoints, Plan parent)
    {
        lock (plans)
            return vaultReads.TryGetValue(parent, out var loan) && loan.PrivateConnection is { } admission &&
                ReferenceEquals(admission.Endpoints, endpoints) ? parent.Drained!.Task : Task.CompletedTask;
    }

    internal VaultAdministrationEffects.Configuration VaultReadBaseline(HostScope expected,
        VaultAdministrationCollector.Authority observer, HttpPipelineTransport selectedBackend)
    {
        lock (plans)
        {
            Require(!closed && baselineConfiguration is not null && host == expected &&
                observer is not null && observer.Credential is not null && observer.Transport is not null &&
                selectedBackend is not null && !ReferenceEquals(observer.Transport, selectedBackend));
            Authority?[] authorities = [setupArm, readArm, secretSetup, secretRead];
            Require(authorities.Where(a => a is not null).All(a => a!.Label != observer.Label &&
                !ReferenceEquals(a.Credential, observer.Credential) &&
                !ReferenceEquals(a.Transport, observer.Transport) &&
                !ReferenceEquals(a.Transport, selectedBackend)));
            return baseline with
            {
                Policies = baseline.Policies.Select(p => p with { Permissions = p.Permissions.ToArray() }).ToArray()
            };
        }
    }

    internal bool TryEnterVaultRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                originalPlan.Preparation == Preparation.Active && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.PrivateEndpoint is null &&
                originalPlan.Selector.Operation == "a.management.VaultAdministration.GetVaultAsync" &&
                originalPlan.Selector.Variant == "selector.exact" &&
                originalPlan.Selector.Case is "selected-contract" or "independent-effect" or
                    "denied-authority" or "cancellation-boundary" or "lost-response-no-replay");
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(VaultReadRoot(originalPlan, snapshot) && !snapshot.Closing && snapshot.Idle);
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal bool TryEnterDeletedVaultRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                GetDeletedVaultReadProfile(originalPlan) && originalPlan.PolicyChildren.Count == 0 &&
                originalPlan.OwnedNotificationNames.Count == 0 && originalPlan.PrivateEndpoint is null);
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Idle && DeletedVaultReadRoot(originalPlan, snapshot));
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal bool TryEnterDeletedVaultListRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                DeletedVaultListReadProfile(originalPlan));
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Idle && DeletedVaultReadRoot(originalPlan, snapshot));
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal bool TryEnterVaultNameRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) && VaultNameReadProfile(originalPlan));
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Idle && VaultReadRoot(originalPlan, snapshot));
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal bool TryEnterVaultGroupListRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                VaultGroupListReadProfile(originalPlan));
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Idle && VaultReadRoot(originalPlan, snapshot));
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    internal bool TryEnterVaultSubscriptionListRead(Plan originalPlan, [NotNullWhen(true)] out VaultReadLoan? loan)
    {
        lock (plans)
        {
            loan = null;
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                VaultSubscriptionListReadProfile(originalPlan));
            if (originalPlan.Busy != 0) return false;
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && snapshot.Idle && VaultReadRoot(originalPlan, snapshot));
            Enter(originalPlan);
            try
            {
                Guid dispatch = journal.BeginSelectedRead(originalPlan.Owner, originalPlan.Selector,
                    originalPlan.LeaseId, originalPlan.VaultId);
                loan = new(originalPlan, dispatch);
                vaultReads.Add(originalPlan, loan);
                return true;
            }
            catch { Exit(originalPlan); throw; }
        }
    }

    private static bool DeletedVaultReadRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        DeletedVaultReadProfile(plan) && MatchesPlan(plan, snapshot) && snapshot.PrivateEndpoint is null &&
        snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false, CreateAttempted: true } &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        { CleanupOnly: true, CreateAttempted: false, InvocationTerminated: false, ActiveDispatch: var canary } &&
        canary == Guid.Empty &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
        { CleanupOnly: false, CreateAttempted: true, InvocationTerminated: true, ActiveDispatch: var deleted } &&
        deleted == Guid.Empty;

    private static bool VaultReadRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        MatchesPlan(plan, snapshot) && snapshot.PrivateEndpoint is null && snapshot.Resources.Length == 3 &&
        snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.SelectedAttempted && !r.Absent) &&
        snapshot.Resources.Single(r => r.Id == plan.VaultId) is { CleanupOnly: false, CreateAttempted: true } &&
        snapshot.Resources.Single(r => r.Id == plan.SecretId) is
        { CleanupOnly: true, CreateAttempted: false, ActiveDispatch: var secret } && secret == Guid.Empty &&
        snapshot.Resources.Single(r => r.Id == plan.DeletedId) is
        { CleanupOnly: true, CreateAttempted: false, ActiveDispatch: var deleted } && deleted == Guid.Empty;

    internal static bool SettingsSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.UpdateSettingsAsync";

    internal static bool ValidCreateVaultConfigurations(string variant,
        VaultAdministrationEffects.Configuration baseline, VaultAdministrationEffects.Configuration selected)
    {
        _ = baseline.Build();
        _ = selected.Build();
        return VaultAdministrationEffects.ConfigurationVariants.Contains(variant) &&
            baseline.Location == selected.Location && baseline.TenantId == selected.TenantId &&
            baseline.RetentionDays == selected.RetentionDays && (!baseline.PurgeProtection || selected.PurgeProtection) &&
            !VaultAdministrationEffects.SameConfiguration(baseline, selected) &&
            VaultAdministrationEffects.SameConfiguration(selected,
                VaultAdministrationEffects.SelectConfiguration(selected, selected.Policies, variant)) &&
            (variant is not ("authorization.access-policy" or "accessPolicies.selected") || selected.Policies.Length != 0);
    }

    internal static bool CreateOrUpdateVaultSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.CreateOrUpdateVaultAsync" &&
        VaultAdministrationEffects.ConfigurationVariants.Contains(selector.Variant) &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal static bool RecoverVaultSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.RecoverVaultAsync" &&
        VaultAdministrationEffects.ConfigurationVariants.Contains(selector.Variant) &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal static bool ValidRecoverVaultConfigurations(string variant,
        VaultAdministrationEffects.Configuration baseline, VaultAdministrationEffects.Configuration selected)
    {
        _ = baseline.Build();
        _ = selected.Build();
        return VaultAdministrationEffects.ConfigurationVariants.Contains(variant) &&
            VaultAdministrationEffects.SameConfiguration(baseline, selected) &&
            VaultAdministrationEffects.SameConfiguration(selected,
                VaultAdministrationEffects.SelectConfiguration(selected, selected.Policies, variant)) &&
            (variant is not ("authorization.access-policy" or "accessPolicies.selected") || selected.Policies.Length != 0);
    }

    internal sealed class RecoverVaultLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[RecoverVaultLoan]";
    }
    internal sealed record RecoverVaultWitness(Result Result, string? ActiveDigest, string? DeletedDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[RecoverVaultWitness]";
    }
    private sealed class RecoverVaultRead(RecoverVaultLoan loan)
    {
        internal readonly RecoverVaultLoan Loan = loan;
        internal Task<RecoverVaultWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal KeyVaultData? Active;
        internal DeletedKeyVaultData? Deleted;
        internal string? ActiveDigest, DeletedDigest;
        internal VaultAdministrationEffects.Configuration? RawConfiguration;
        internal RecoverVaultWitness? Witness;
        internal bool Finished;
    }
    private sealed record RecoverPreparation(Plan Plan, Task<Response<KeyVaultResource>> Task,
        KeyVaultData Native, JsonElement Raw, string Digest);

    private VaultAdministrationEffects.Configuration RecoverVaultConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(plan.OriginalRecover && snapshot.RecoverVault is not null);
        return CopyConfiguration(snapshot.RecoverVault.Baseline);
    }

    private async Task CaptureRecoverPreparation(Plan plan, CancellationToken token)
    {
        Require(plan.OriginalRecover || StatusVaultRecoverCancellationSelector(plan.Selector));
        Task<Response<KeyVaultResource>>? task = null;
        JsonElement? raw = null;
        var native = (await ReadArm(plan, plan.VaultId,
            (client, ct) => task = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
            root => raw = root.Clone(), token).ConfigureAwait(false))?.Data;
        token.ThrowIfCancellationRequested();
        Require(native is not null && task is { IsCompletedSuccessfully: true } && raw is not null);
        var expected = plan.OriginalRecover ? RecoverVaultConfiguration(plan) :
            StatusVaultRecoverCancellationConfiguration(plan);
        string digest = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, raw.Value, expected, "Succeeded");
        JoinRecoverActive(plan, native, expected);
        lock (plans)
        {
            Require(!closed && !plan.Restored && !recoverPreparations.ContainsKey(plan));
            recoverPreparations.Add(plan, new(plan, task, native, raw.Value, digest));
        }
    }

    private void JoinRecoverActive(Plan plan, KeyVaultData native, VaultAdministrationEffects.Configuration expected)
    {
        Require(Succeeded(native) && native.Id.ToString() == plan.VaultId && native.Name == plan.VaultName &&
            native.ResourceType.ToString() == "Microsoft.KeyVault/vaults" && native.Location.Name == host.Location &&
            native.Properties.VaultUri == SecretOrigin(plan) && native.Tags.Count == 1 &&
            native.Tags.TryGetValue(OwnershipTag, out var nonce) && nonce == plan.Selector.Nonce.ToString("N") &&
            VaultAdministrationEffects.SameConfiguration(Configuration(native), expected));
        if (StatusVaultRecoverCancellationSelector(plan.Selector) || StatusVaultUpdateCancellationSelector(plan.Selector))
        {
            using var serialized = JsonDocument.Parse(ModelReaderWriter.Write(native).ToMemory());
            var properties = serialized.RootElement.GetProperty("properties");
            Require(properties.GetProperty("privateEndpointConnections") is { ValueKind: JsonValueKind.Array } children &&
                children.GetArrayLength() == 0 && native.Properties.AccessPolicies.Count == 0);
        }
    }

    private static void JoinRecoverDeleted(Plan plan, DeletedKeyVaultData native, JsonElement raw)
    {
        var p = raw.GetProperty("properties");
        Require(native.Id.ToString() == plan.DeletedId && native.Name == plan.VaultName &&
            native.ResourceType.ToString() == "Microsoft.KeyVault/locations/deletedVaults" &&
            native.Properties.VaultId == p.GetProperty("vaultId").GetString() &&
            native.Properties.Location == p.GetProperty("location").GetString() &&
            native.Properties.Tags.Count == 1 && native.Properties.Tags.TryGetValue(OwnershipTag, out var nonce) &&
            nonce == p.GetProperty("tags").GetProperty(OwnershipTag).GetString() &&
            native.Properties.DeletedOn == p.GetProperty("deletionDate").GetDateTimeOffset() &&
            native.Properties.ScheduledPurgeOn == p.GetProperty("scheduledPurgeDate").GetDateTimeOffset() &&
            native.Properties.PurgeProtectionEnabled == p.GetProperty("purgeProtectionEnabled").GetBoolean());
    }

    internal RecoverVaultLoan EnterRecoverVault(Plan originalPlan)
    {
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(originalPlan.OriginalRecover && recoverVaultVariant == originalPlan.Selector.Variant &&
                !originalPlan.Restored && originalReady.Contains(originalPlan) && originalPlan.Busy == 0 &&
                originalPlan.Preparation == Preparation.Deleted && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.PrivateEndpoint is null && recoverPreparations.ContainsKey(originalPlan) &&
                snapshot.RecoverVault is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                !snapshot.Closing && snapshot.Idle && snapshot.Resources.Length == 3 &&
                snapshot.Resources.All(r => !r.Borrowed && !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent) &&
                snapshot.Resources.Single(r => r.Id == originalPlan.VaultId) is
                { CreateAttempted: true, InvocationTerminated: true, CleanupOnly: false } &&
                snapshot.Resources.Single(r => r.Id == originalPlan.DeletedId) is
                { CreateAttempted: true, InvocationTerminated: true, CleanupOnly: false } &&
                !recoverVaultLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new RecoverVaultLoan(originalPlan);
            recoverVaultLoans.Add(originalPlan, loan);
            recoverVaultReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckRecoverVaultLoan(RecoverVaultLoan loan)
    {
        Require(loan is not null);
        lock (plans)
        {
            Require(!closed && loan.Plan.OriginalRecover && !loan.Plan.Restored && loan.Plan.Busy == 1 &&
                originalReady.Contains(loan.Plan) && recoverPreparations.TryGetValue(loan.Plan, out var preparation) &&
                ReferenceEquals(preparation.Plan, loan.Plan) && preparation.Task.IsCompletedSuccessfully &&
                recoverVaultLoans.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) && snapshot.RecoverVault is not null &&
                snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.Absent));
        }
    }

    internal Task<RecoverVaultWitness> ObserveRecoverVaultAsync(RecoverVaultLoan loan, CancellationToken token)
    {
        CheckRecoverVaultLoan(loan);
        lock (plans)
        {
            var reads = recoverVaultReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var read = new RecoverVaultRead(loan);
            reads.Add(read);
            return read.Task = ObserveRecoverVaultCore(read, token);
        }
    }

    private async Task<RecoverVaultWitness> ObserveRecoverVaultCore(RecoverVaultRead read, CancellationToken token)
    {
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var expected = RecoverVaultConfiguration(plan);
            JsonElement? activeRaw = null, deletedRaw = null;
            read.Active = (await ReadArm(plan, plan.VaultId,
                (client, ct) => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
                root => activeRaw = root.Clone(), linked.Token, recoverLoan: read.Loan).ConfigureAwait(false))?.Data;
            read.Deleted = (await ReadArm(plan, plan.DeletedId,
                (client, ct) => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                root => deletedRaw = root.Clone(), linked.Token, recoverLoan: read.Loan).ConfigureAwait(false))?.Data;
            linked.Token.ThrowIfCancellationRequested();
            CheckRecoverVaultLoan(read.Loan);
            Require(read.Active is null || read.Deleted is null);
            if (read.Active is { } active)
            {
                Require(activeRaw is not null);
                read.ActiveDigest = ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, activeRaw.Value,
                    expected, "Succeeded", recover: true);
                JoinRecoverActive(plan, active, expected);
                read.RawConfiguration = CopyConfiguration(expected);
            }
            if (read.Deleted is { } deleted)
            {
                Require(deletedRaw is not null);
                ValidateCreateVaultDeletedResource(plan, deletedRaw.Value, expected);
                JoinRecoverDeleted(plan, deleted, deletedRaw.Value);
                read.DeletedDigest = Hash(deletedRaw.Value.GetRawText());
            }
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = ReadPlan(plan.Owner, plan.Selector),
                VaultPresent = read.Active is not null,
                DeletedVaultPresent = read.Deleted is not null,
                Configuration = read.Active is null ? null : Configuration(read.Active),
                DeletedVault = read.Deleted is null ? null : ProjectDeleted(read.Deleted)
            }, read.ActiveDigest, read.DeletedDigest, started, finished);
        }
        finally { lock (plans) read.Finished = true; }
    }

    internal bool OwnsRecoverVaultWitness(RecoverVaultWitness witness, RecoverVaultLoan loan, Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && recoverVaultReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Loan, loan) && ReferenceEquals(r.Witness, witness) &&
                    ReferenceEquals(r.Task, originalTask) && r.Task is { IsCompletedSuccessfully: true } && r.Finished &&
                    r.ActiveTask is { IsCompleted: true } && r.DeletedTask is { IsCompleted: true } &&
                    witness.Result.VaultPresent == (r.Active is not null) &&
                    witness.Result.DeletedVaultPresent == (r.Deleted is not null) &&
                    witness.ActiveDigest == r.ActiveDigest && witness.DeletedDigest == r.DeletedDigest &&
                    (r.Active is null ? witness.Result.Configuration is null : r.RawConfiguration is not null &&
                        witness.Result.Configuration is { } configuration &&
                        VaultAdministrationEffects.SameConfiguration(configuration, Configuration(r.Active)) &&
                        VaultAdministrationEffects.SameConfiguration(configuration, r.RawConfiguration)) &&
                    (r.Deleted is null ? witness.Result.DeletedVault is null :
                        witness.Result.DeletedVault == ProjectDeleted(r.Deleted)));
    }

    internal void ExitRecoverVault(RecoverVaultLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && recoverVaultLoans.TryGetValue(loan.Plan, out var retained) &&
                ReferenceEquals(retained, loan) && recoverVaultReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            recoverVaultLoans.Remove(loan.Plan);
            Exit(loan.Plan);
        }
    }

    private static bool RecoverVaultCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        plan.OriginalRecover && MatchesPlan(plan, snapshot) && snapshot.Closing && snapshot.Idle &&
        snapshot.RecoverVault is { } state && state.VaultId == plan.VaultId && state.DeletedVaultId == plan.DeletedId &&
        plan.Preparation == Preparation.Deleted && !plan.SeedCanary && plan.PrivateEndpoint is null &&
        plan.PolicyChildren.Count == 0 && plan.OwnedNotificationNames.Count == 0 &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        (state.InvocationDispatch == Guid.Empty ? !snapshot.Resources.Any(r => r.SelectedAttempted) :
            state.InvocationDispatch == state.SettledDispatch &&
                state.Disposition is RoleFixtureJournal.RecoverVaultDisposition.Recovered or RoleFixtureJournal.RecoverVaultDisposition.Denied);

    private async Task<Result> ReleaseRecoverVault(Plan plan, CancellationToken token)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(RecoverVaultCleanupRoot(plan, snapshot));
        var state = snapshot.RecoverVault!;
        var vault = await ReadVault(plan, token).ConfigureAwait(false);
        var deleted = await ReadRecoveryDeleted().ConfigureAwait(false);
        Require(vault is null || deleted is null);
        var activeRow = snapshot.Resources.Single(r => r.Id == plan.VaultId);
        var deletedRow = snapshot.Resources.Single(r => r.Id == plan.DeletedId);
        if (vault is not null)
        {
            Presence(plan, plan.VaultId);
            Presence(plan, plan.SecretId);
            // A restart cannot promote presence to recovery. A completed cleanup
            // DELETE must never be repeated, including resurrection afterward.
            if (state.Disposition != RoleFixtureJournal.RecoverVaultDisposition.Recovered || activeRow.DeleteAttempted)
                return Finish(State.Uncertain, plan);
            JoinRecoverActive(plan, vault, state.Selected);
            State result = await Mutate(plan, plan.VaultId, Action.DeleteVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetKeyVaultResource(new(plan.VaultId))
                    .DeleteAsync(WaitUntil.Started, ct).ConfigureAwait(false), token).ConfigureAwait(false);
            if (result != State.Ready) return Finish(result, plan);
            snapshot = ReadPlan(plan.Owner, plan.Selector);
            if (!snapshot.Idle) return Finish(State.Pending, plan);
            vault = await ReadVault(plan, token).ConfigureAwait(false);
            deleted = await ReadRecoveryDeleted().ConfigureAwait(false);
        }
        else if (state.Disposition == RoleFixtureJournal.RecoverVaultDisposition.Recovered && !activeRow.DeleteAttempted)
            return Finish(State.Uncertain, plan);
        if (vault is not null) return Finish(State.Uncertain, plan);
        if (deleted is not null)
        {
            Presence(plan, plan.DeletedId);
            Presence(plan, plan.SecretId);
            Require(activeRow.CreateAttempted && deletedRow.CreateAttempted &&
                deletedRow.InvocationTerminated && deleted.Properties.PurgeProtectionEnabled == state.Baseline.PurgeProtection);
            if (state.Baseline.PurgeProtection) return Finish(State.SoftDeleted, plan);
            if (deletedRow.DeleteAttempted) return Finish(State.Uncertain, plan);
            State result = await Mutate(plan, plan.DeletedId, Action.PurgeVault,
                async (boundary, ct) => await Arm(setupArm, boundary).GetDeletedKeyVaultResource(new(plan.DeletedId))
                    .PurgeDeletedAsync(WaitUntil.Started, ct).ConfigureAwait(false), token).ConfigureAwait(false);
            if (result != State.Ready) return Finish(result, plan);
        }
        snapshot = ReadPlan(plan.Owner, plan.Selector);
        if (!snapshot.Idle) return Finish(State.Pending, plan);
        // These reads, not delete/purge flags or earlier observations, release.
        vault = await ReadVault(plan, token).ConfigureAwait(false);
        deleted = await ReadRecoveryDeleted().ConfigureAwait(false);
        if (vault is not null || deleted is not null) return Finish(State.Uncertain, plan);
        if (state.Baseline.PurgeProtection) return Finish(State.Uncertain, plan);
        token.ThrowIfCancellationRequested();
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.VaultId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.DeletedId);
        journal.RecordAbsence(plan.Owner, plan.Selector, plan.SecretId);
        return Finish(State.Released, plan);

        async Task<DeletedKeyVaultData?> ReadRecoveryDeleted()
        {
            JsonElement? raw = null;
            var data = (await ReadArm(plan, plan.DeletedId,
                (client, ct) => client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                root =>
                {
                    ValidateCreateVaultDeletedResource(plan, root, state.Baseline);
                    raw = root.Clone();
                    if (state.Disposition == RoleFixtureJournal.RecoverVaultDisposition.Denied)
                        Require(Hash(root.GetRawText()) == state.DeletedBaselineSha256);
                }, token).ConfigureAwait(false))?.Data;
            if (data is not null)
            {
                Require(raw is not null);
                JoinRecoverDeleted(plan, data, raw.Value);
            }
            return data;
        }
    }

    internal static bool DeleteVaultSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.DeleteVaultAsync" &&
        selector.Variant == "input.scope" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal static bool PurgeDeletedVaultSelector(FixtureSelector selector) =>
        selector.Operation == "a.management.VaultAdministration.PurgeDeletedVaultAsync" &&
        selector.Variant == "input.scope" &&
        selector.Case is "selected-contract" or "independent-effect" or "denied-authority" or
            "cancellation-boundary" or "lost-response-no-replay";

    internal sealed class PurgeDeletedVaultLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[PurgeDeletedVaultLoan]";
    }

    internal sealed record PurgeDeletedVaultWitness(Result Result, string? DeletedDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[PurgeDeletedVaultWitness]";
    }

    private sealed record PurgePreparation(Plan Plan, Task<Response<KeyVaultResource>> Task,
        KeyVaultData Native, string Digest);
    private sealed class PurgeDeletedVaultRead(PurgeDeletedVaultLoan loan)
    {
        internal readonly PurgeDeletedVaultLoan Loan = loan;
        internal Task<PurgeDeletedVaultWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal KeyVaultData? Active;
        internal DeletedKeyVaultData? Deleted;
        internal PurgeDeletedVaultWitness? Witness;
        internal string? DeletedDigest;
        internal bool Finished;
    }

    private async Task CapturePurgePreparation(Plan plan, CancellationToken token)
    {
        Task<Response<KeyVaultResource>>? task = null;
        string? digest = null;
        var native = (await ReadArm(plan, plan.VaultId,
            (client, ct) => task = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
            root => digest = ParseDeleteVaultResource(plan, root, PurgeDeletedVaultConfiguration(plan)),
            token).ConfigureAwait(false))?.Data;
        token.ThrowIfCancellationRequested();
        Require(native is not null && task is { IsCompletedSuccessfully: true } && digest is not null && Succeeded(native));
        ValidateVaultData(plan, native, selected: false);
        lock (plans)
        {
            Require(!closed && !plan.Restored && !purgePreparations.ContainsKey(plan));
            purgePreparations.Add(plan, new(plan, task, native, digest));
        }
    }

    internal PurgeDeletedVaultLoan EnterPurgeDeletedVault(Plan originalPlan)
    {
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(purgeDeletedVaultProfile && PurgeDeletedVaultSelector(originalPlan.Selector) &&
                !originalPlan.Restored && originalReady.Contains(originalPlan) && originalPlan.Busy == 0 &&
                originalPlan.Preparation == Preparation.Deleted && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.PrivateEndpoint is null && purgePreparations.ContainsKey(originalPlan) &&
                snapshot.PurgeDeletedVault is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                !snapshot.Closing && snapshot.Idle && snapshot.Resources.Length == 3 &&
                snapshot.Resources.All(r => !r.Borrowed && !r.SelectedAttempted && !r.DeleteAttempted && !r.Absent) &&
                snapshot.Resources.Single(r => r.Id == originalPlan.VaultId) is
                { CreateAttempted: true, InvocationTerminated: true } &&
                snapshot.Resources.Single(r => r.Id == originalPlan.DeletedId) is
                { CreateAttempted: true, InvocationTerminated: true } &&
                !purgeDeletedVaultLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new PurgeDeletedVaultLoan(originalPlan);
            purgeDeletedVaultLoans.Add(originalPlan, loan);
            purgeDeletedVaultReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckPurgeDeletedVaultLoan(PurgeDeletedVaultLoan loan)
    {
        Require(loan is not null);
        lock (plans)
        {
            Require(!closed && !loan.Plan.Restored && loan.Plan.Busy == 1 && originalReady.Contains(loan.Plan) &&
                purgePreparations.TryGetValue(loan.Plan, out var preparation) &&
                ReferenceEquals(preparation.Plan, loan.Plan) && preparation.Task.IsCompletedSuccessfully &&
                purgeDeletedVaultLoans.TryGetValue(loan.Plan, out var registered) && ReferenceEquals(registered, loan));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) && snapshot.PurgeDeletedVault is not null &&
                snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.DeleteVault is null &&
                snapshot.Resources.Length == 3 &&
                snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.Absent));
        }
    }

    internal Task<PurgeDeletedVaultWitness> ObservePurgeDeletedVaultAsync(PurgeDeletedVaultLoan loan, CancellationToken token)
    {
        CheckPurgeDeletedVaultLoan(loan);
        lock (plans)
        {
            var reads = purgeDeletedVaultReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var read = new PurgeDeletedVaultRead(loan);
            reads.Add(read);
            return read.Task = ObservePurgeDeletedVaultCore(read, token);
        }
    }

    private async Task<PurgeDeletedVaultWitness> ObservePurgeDeletedVaultCore(PurgeDeletedVaultRead read, CancellationToken token)
    {
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var expected = PurgeDeletedVaultConfiguration(plan);
            read.Active = (await ReadArm(plan, plan.VaultId,
                (client, ct) => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
                root => _ = ParseDeleteVaultResource(plan, root, expected), linked.Token,
                purgeLoan: read.Loan).ConfigureAwait(false))?.Data;
            read.Deleted = (await ReadArm(plan, plan.DeletedId,
                (client, ct) => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                root =>
                {
                    ValidateDeleteVaultResource(plan, root, expected);
                    read.DeletedDigest = Hash(root.GetRawText());
                }, linked.Token, purgeLoan: read.Loan).ConfigureAwait(false))?.Data;
            linked.Token.ThrowIfCancellationRequested();
            CheckPurgeDeletedVaultLoan(read.Loan);
            Require(read.Active is null || read.Deleted is null);
            if (read.Active is { } active) ValidateVaultData(plan, active, selected: false);
            if (read.Deleted is { } deleted)
            {
                Require(read.DeletedDigest is not null);
                ValidateDeleted(plan, deleted);
            }
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = journal.Read(plan.Owner, plan.Selector),
                VaultPresent = read.Active is not null,
                DeletedVaultPresent = read.Deleted is not null,
                Configuration = read.Active is null ? null : Configuration(read.Active),
                DeletedVault = read.Deleted is null ? null : ProjectDeleted(read.Deleted)
            }, read.DeletedDigest, started, finished);
        }
        finally { lock (plans) read.Finished = true; }
    }

    internal bool OwnsPurgeDeletedVaultWitness(PurgeDeletedVaultWitness witness, PurgeDeletedVaultLoan loan, Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && originalTask is not null &&
                purgeDeletedVaultReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Loan, loan) && ReferenceEquals(r.Witness, witness) &&
                    ReferenceEquals(r.Task, originalTask) && r.Task is { IsCompletedSuccessfully: true } &&
                    r.ActiveTask is { IsCompleted: true } && r.DeletedTask is { IsCompleted: true } && r.Finished &&
                    witness.Result.VaultPresent == (r.Active is not null) &&
                    witness.Result.DeletedVaultPresent == (r.Deleted is not null) &&
                    witness.DeletedDigest == r.DeletedDigest &&
                    (r.Active is null ? witness.Result.Configuration is null :
                        witness.Result.Configuration is { } config &&
                            VaultAdministrationEffects.SameConfiguration(config, Configuration(r.Active))) &&
                    (r.Deleted is null ? witness.Result.DeletedVault is null :
                        witness.Result.DeletedVault == ProjectDeleted(r.Deleted)));
    }

    internal void ExitPurgeDeletedVault(PurgeDeletedVaultLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && purgeDeletedVaultLoans.TryGetValue(loan.Plan, out var registered) &&
                ReferenceEquals(registered, loan) &&
                purgeDeletedVaultReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            purgeDeletedVaultLoans.Remove(loan.Plan);
            Exit(loan.Plan);
        }
    }

    private VaultAdministrationEffects.Configuration PurgeDeletedVaultConfiguration(Plan plan)
    {
        var snapshot = journal.Read(plan.Owner, plan.Selector);
        Require(MatchesPlan(plan, snapshot) && snapshot.PurgeDeletedVault is not null);
        return CopyConfiguration(snapshot.PurgeDeletedVault.Baseline);
    }

    internal sealed class CreateOrUpdateVaultLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[CreateOrUpdateVaultLoan]";
    }
    internal sealed record CreateOrUpdateVaultWitness(Result Result, string? ActiveDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[CreateOrUpdateVaultWitness]";
    }
    private sealed class CreateVaultRead(CreateOrUpdateVaultLoan loan)
    {
        internal readonly CreateOrUpdateVaultLoan Loan = loan;
        internal Task<CreateOrUpdateVaultWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal KeyVaultData? Active;
        internal VaultAdministrationEffects.Configuration? RawConfiguration;
        internal CreateOrUpdateVaultWitness? Witness;
        internal bool Finished;
    }

    internal CreateOrUpdateVaultLoan EnterCreateOrUpdateVault(Plan originalPlan)
    {
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(createVaultVariant == originalPlan.Selector.Variant && !originalPlan.Restored &&
                originalReady.Contains(originalPlan) && originalPlan.Busy == 0 &&
                originalPlan.Preparation == Preparation.Active && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.PrivateEndpoint is null && !snapshot.Closing && snapshot.Idle &&
                snapshot.CreateOrUpdateVault is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                VaultReadRoot(originalPlan, snapshot) && !createVaultLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new CreateOrUpdateVaultLoan(originalPlan);
            createVaultLoans.Add(originalPlan, loan);
            createVaultReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckCreateOrUpdateVaultLoan(CreateOrUpdateVaultLoan loan)
    {
        Require(loan is not null);
        lock (plans)
        {
            Require(!closed && !loan.Plan.Restored && originalReady.Contains(loan.Plan) && loan.Plan.Busy == 1 &&
                createVaultLoans.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) && snapshot.CreateOrUpdateVault is not null &&
                snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.Absent));
        }
    }

    internal Task<CreateOrUpdateVaultWitness> ObserveCreateOrUpdateVaultAsync(CreateOrUpdateVaultLoan loan,
        CancellationToken token)
    {
        CheckCreateOrUpdateVaultLoan(loan);
        lock (plans)
        {
            var reads = createVaultReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var read = new CreateVaultRead(loan);
            reads.Add(read);
            return read.Task = ObserveCreateVaultCore(read, token);
        }
    }

    private async Task<CreateOrUpdateVaultWitness> ObserveCreateVaultCore(CreateVaultRead read, CancellationToken token)
    {
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            var state = snapshot.CreateOrUpdateVault ?? throw Failure();
            JsonElement? rawConfiguration = null;
            read.Active = (await ReadArm(plan, plan.VaultId,
                (client, ct) => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct),
                root =>
                {
                    rawConfiguration = root.Clone();
                }, linked.Token, createLoan: read.Loan).ConfigureAwait(false))?.Data;
            var deleted = await ReadArm(plan, plan.DeletedId,
                (client, ct) => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                DeletedShape, linked.Token, createLoan: read.Loan).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            CheckCreateOrUpdateVaultLoan(read.Loan);
            Require(read.Active is { } && deleted is null && rawConfiguration is not null);
            var active = read.Active ?? throw Failure();
            var actual = Configuration(active);
            var expected = VaultAdministrationEffects.SameConfiguration(actual, state.Baseline) ? state.Baseline : state.Selected;
            Require(VaultAdministrationEffects.SameConfiguration(actual, expected) &&
                (state.InvocationDispatch != Guid.Empty ||
                    VaultAdministrationEffects.SameConfiguration(expected, state.Baseline)));
            string digest = ParseDeleteVaultResource(plan, rawConfiguration.Value, expected);
            read.RawConfiguration = CopyConfiguration(expected);
            Require(Succeeded(active) && active.Id.ToString() == plan.VaultId &&
                active.Name == plan.VaultName && active.ResourceType.ToString() == "Microsoft.KeyVault/vaults" &&
                active.Location.Name == host.Location && active.Properties.VaultUri == SecretOrigin(plan) &&
                active.Tags.Count == 1 && active.Tags.TryGetValue(OwnershipTag, out var nonce) &&
                nonce == plan.Selector.Nonce.ToString("N") &&
                VaultAdministrationEffects.SameConfiguration(Configuration(active), read.RawConfiguration));
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = ReadPlan(plan.Owner, plan.Selector),
                VaultPresent = true,
                DeletedVaultPresent = false,
                Configuration = Configuration(active)
            }, digest, started, finished);
        }
        finally { lock (plans) read.Finished = true; }
    }

    internal bool OwnsCreateOrUpdateVaultWitness(CreateOrUpdateVaultWitness witness, CreateOrUpdateVaultLoan loan,
        Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && createVaultReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Witness, witness) && ReferenceEquals(r.Task, originalTask) &&
                    r.Task is { IsCompletedSuccessfully: true } && r.Finished &&
                    r.ActiveTask is { IsCompletedSuccessfully: true } && r.DeletedTask is { IsCompleted: true } &&
                    r.Active is not null && r.RawConfiguration is not null && witness.Result.VaultPresent == true &&
                    witness.Result.DeletedVaultPresent == false && witness.Result.Configuration is { } configuration &&
                    VaultAdministrationEffects.SameConfiguration(configuration, Configuration(r.Active)) &&
                    VaultAdministrationEffects.SameConfiguration(configuration, r.RawConfiguration));
    }

    internal void ExitCreateOrUpdateVault(CreateOrUpdateVaultLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && createVaultLoans.TryGetValue(loan.Plan, out var registered) &&
                ReferenceEquals(registered, loan) && createVaultReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            createVaultLoans.Remove(loan.Plan);
            Exit(loan.Plan);
        }
    }

    private VaultAdministrationEffects.Configuration CreateVaultCleanupConfiguration(Plan plan)
    {
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(snapshot.CreateOrUpdateVault is { } && !snapshot.CreateOrUpdateVaultUnsettled);
        var state = snapshot.CreateOrUpdateVault;
        return CopyConfiguration(state.Disposition == RoleFixtureJournal.CreateOrUpdateVaultDisposition.Updated
            ? state.Selected : state.Baseline);
    }

    private static bool CreateVaultCleanupRoot(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        plan.OriginalCreate && MatchesPlan(plan, snapshot) && snapshot.Closing && snapshot.Idle &&
        snapshot.CreateOrUpdateVault is { } state && state.VaultId == plan.VaultId &&
        snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed) &&
        plan.PrivateEndpoint is null && !plan.SeedCanary && plan.PolicyChildren.Count == 0 &&
        plan.OwnedNotificationNames.Count == 0 &&
        (state.InvocationDispatch == Guid.Empty
            ? !snapshot.Resources.Any(r => r.SelectedAttempted)
            : state.InvocationDispatch == state.SettledDispatch &&
                state.Disposition is RoleFixtureJournal.CreateOrUpdateVaultDisposition.Updated or
                    RoleFixtureJournal.CreateOrUpdateVaultDisposition.Denied);

    internal sealed class DeleteVaultLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        public override string ToString() => "[DeleteVaultLoan]";
    }

    internal sealed record DeleteVaultWitness(Result Result, string? ActiveDigest,
        DateTimeOffset StartedAt, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[DeleteVaultWitness]";
    }

    private sealed class DeleteVaultRead(DeleteVaultLoan loan)
    {
        internal readonly DeleteVaultLoan Loan = loan;
        internal Task<DeleteVaultWitness>? Task;
        internal Task<Response<KeyVaultResource>>? ActiveTask;
        internal Task<Response<DeletedKeyVaultResource>>? DeletedTask;
        internal KeyVaultData? Active;
        internal DeletedKeyVaultData? Deleted;
        internal DeleteVaultWitness? Witness;
        internal string? ActiveDigest, DeletedDigest;
        internal bool ActiveComplete, DeletedComplete, Finished;
    }

    internal DeleteVaultLoan EnterDeleteVault(Plan originalPlan)
    {
        lock (plans)
        {
            CheckPlan(originalPlan);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(deleteVaultProfile && DeleteVaultSelector(originalPlan.Selector) &&
                !originalPlan.Restored && originalReady.Contains(originalPlan) && originalPlan.Busy == 0 &&
                originalPlan.Preparation == Preparation.Active && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                snapshot.DeleteVault is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
                !snapshot.Closing && snapshot.Idle && VaultReadRoot(originalPlan, snapshot) &&
                !deleteVaultLoans.ContainsKey(originalPlan));
            Enter(originalPlan);
            var loan = new DeleteVaultLoan(originalPlan);
            deleteVaultLoans.Add(originalPlan, loan);
            deleteVaultReads.Add(loan, []);
            return loan;
        }
    }

    internal void CheckDeleteVaultLoan(DeleteVaultLoan loan)
    {
        Require(loan is not null);
        lock (plans)
        {
            Require(!closed && !loan.Plan.Restored && loan.Plan.Busy == 1 &&
                originalReady.Contains(loan.Plan) &&
                deleteVaultLoans.TryGetValue(loan.Plan, out var registered) && ReferenceEquals(registered, loan));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) && snapshot.DeleteVault is not null &&
                snapshot.PrivateEndpoint is null && snapshot.Settings is null && snapshot.Resources.Length == 3 &&
                snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.Absent));
        }
    }

    internal Task<DeleteVaultWitness> ObserveDeleteVaultAsync(DeleteVaultLoan loan, CancellationToken token)
    {
        CheckDeleteVaultLoan(loan);
        lock (plans)
        {
            var reads = deleteVaultReads[loan];
            Require(reads.Count < 2 && reads.All(r => r.Finished));
            var read = new DeleteVaultRead(loan);
            reads.Add(read);
            return read.Task = ObserveDeleteVaultCore(read, token);
        }
    }

    private async Task<DeleteVaultWitness> ObserveDeleteVaultCore(DeleteVaultRead read, CancellationToken token)
    {
        try
        {
            DateTimeOffset started = time.GetUtcNow();
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, deadline.Token);
            var plan = read.Loan.Plan;
            var expected = DeleteVaultConfiguration(plan);
            read.Active = (await ReadDeleteArm(plan.VaultId,
                client => read.ActiveTask = client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(linked.Token),
                root => read.ActiveDigest = ParseDeleteVaultResource(plan, root, expected)).ConfigureAwait(false))?.Data;
            read.ActiveComplete = true;
            read.Deleted = (await ReadDeleteArm(plan.DeletedId,
                client => read.DeletedTask = client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(linked.Token),
                root =>
                {
                    ValidateDeleteVaultResource(plan, root, expected);
                    read.DeletedDigest = Hash(root.GetRawText());
                }).ConfigureAwait(false))?.Data;
            read.DeletedComplete = true;
            linked.Token.ThrowIfCancellationRequested();
            CheckDeleteVaultLoan(read.Loan);
            Require(read.Active is null || read.Deleted is null);
            if (read.Active is { } active)
            {
                Require(read.ActiveDigest is not null && Succeeded(active));
                ValidateVaultData(plan, active, selected: false);
                Require(VaultAdministrationEffects.SameConfiguration(Configuration(active), expected));
            }
            if (read.Deleted is { } deleted)
            {
                Require(read.DeletedDigest is not null);
                ValidateDeleted(plan, deleted);
            }
            DateTimeOffset finished = time.GetUtcNow();
            Require(finished >= started);
            return read.Witness = new(new()
            {
                State = State.Ready,
                Journal = journal.Read(plan.Owner, plan.Selector),
                VaultPresent = read.Active is not null,
                DeletedVaultPresent = read.Deleted is not null,
                Configuration = read.Active is null ? null : Configuration(read.Active),
                DeletedVault = read.Deleted is null ? null : ProjectDeleted(read.Deleted)
            }, read.ActiveDigest, started, finished);

            async Task<T?> ReadDeleteArm<T>(string id, Func<ArmClient, Task<Response<T>>> invoke,
                System.Action<JsonElement> shape) where T : class
            {
                using var boundary = new BoundaryTransport(readArm.Transport, ArmOrigin, id, Revision, RequestMethod.Get,
                    limits.MaximumResponseBytes, false, SubscriptionId, host.Location,
                    beforeSend: () => CheckDeleteVaultLoan(read.Loan), shape: shape,
                    authenticatedReadGuard: message =>
                    {
                        CheckSettingsRead(plan, null, message, id, deleteLoan: read.Loan);
                    }, verifyReadIntegrity: true, strictSettings: true, strictDelete: true);
                try
                {
                    var response = await invoke(Arm(readArm, boundary)).ConfigureAwait(false);
                    using var raw = response.GetRawResponse();
                    Require(boundary.Valid && boundary.Status == 200);
                    return response.Value;
                }
                catch (RequestFailedException) when (boundary.Valid && boundary.Status == 404)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    return null;
                }
            }
        }
        finally { lock (plans) read.Finished = true; }
    }

    internal bool OwnsDeleteVaultWitness(DeleteVaultWitness witness, DeleteVaultLoan loan, Task originalTask)
    {
        lock (plans)
            return witness is not null && loan is not null && originalTask is not null &&
                deleteVaultReads.TryGetValue(loan, out var reads) &&
                reads.Any(r => ReferenceEquals(r.Loan, loan) && ReferenceEquals(r.Witness, witness) &&
                    ReferenceEquals(r.Task, originalTask) && r.Task is { IsCompletedSuccessfully: true } &&
                    r.ActiveTask is { IsCompleted: true } && r.DeletedTask is { IsCompleted: true } &&
                    r.ActiveComplete && r.DeletedComplete && r.Finished &&
                    witness.Result.VaultPresent == (r.Active is not null) &&
                    witness.Result.DeletedVaultPresent == (r.Deleted is not null) &&
                    witness.ActiveDigest == r.ActiveDigest &&
                    (r.Active is null ? witness.Result.Configuration is null :
                        witness.Result.Configuration is { } config &&
                            VaultAdministrationEffects.SameConfiguration(config, Configuration(r.Active))) &&
                    (r.Deleted is null ? witness.Result.DeletedVault is null :
                        witness.Result.DeletedVault == ProjectDeleted(r.Deleted)));
    }

    internal void ExitDeleteVault(DeleteVaultLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && deleteVaultLoans.TryGetValue(loan.Plan, out var registered) &&
                ReferenceEquals(registered, loan) &&
                deleteVaultReads[loan].All(r => r.Finished && r.Task is { IsCompleted: true }));
            deleteVaultLoans.Remove(loan.Plan);
            // Retain task/native/witness identities for source provenance. Ending
            // the local borrower never changes durable settlement.
            Exit(loan.Plan);
        }
    }

    private VaultAdministrationEffects.Configuration DeleteVaultConfiguration(Plan plan)
    {
        var snapshot = journal.Read(plan.Owner, plan.Selector);
        Require(MatchesPlan(plan, snapshot) && snapshot.DeleteVault is not null);
        return CopyConfiguration(snapshot.DeleteVault.Baseline);
    }

    private static string ParseDeleteVaultResource(Plan plan, JsonElement root,
        VaultAdministrationEffects.Configuration expected) =>
        ParseOwnedVaultResource(plan.VaultId, plan.Selector.Nonce, root, expected, "Succeeded");

    internal static string ParseOwnedVaultResource(string vaultId, Guid nonce, JsonElement root,
        VaultAdministrationEffects.Configuration expected, string provisioningState, bool recover = false,
        string? privateConnection = null, string? privateEndpoint = null, bool allowAbsentPrivateConnection = false)
    {
        BoundaryTransport.Unique(root);
        VaultShape(root);
        Require(root.GetProperty("id").GetString() == vaultId &&
            root.GetProperty("name").GetString() == vaultId[(vaultId.LastIndexOf('/') + 1)..] &&
            root.GetProperty("type").GetString() == "Microsoft.KeyVault/vaults" &&
            root.GetProperty("location").GetString() == expected.Location &&
            root.GetProperty("tags").EnumerateObject().Count() == 1 &&
            root.GetProperty("tags").GetProperty(OwnershipTag).GetString() == nonce.ToString("N"));
        var p = root.GetProperty("properties");
        Require(p.GetProperty("tenantId").GetGuid() == expected.TenantId &&
            p.GetProperty("enableSoftDelete").GetBoolean() &&
            p.GetProperty("enablePurgeProtection").GetBoolean() == expected.PurgeProtection &&
            p.GetProperty("enableRbacAuthorization").GetBoolean() == expected.Rbac &&
            p.GetProperty("softDeleteRetentionInDays").GetInt32() == expected.RetentionDays &&
            p.GetProperty("publicNetworkAccess").GetString() == (expected.PublicNetworkAccess ? "Enabled" : "Disabled") &&
            p.GetProperty("provisioningState").GetString() == provisioningState &&
            Uri.TryCreate(p.GetProperty("vaultUri").GetString(), UriKind.Absolute, out var vaultUri) &&
            vaultUri == new Uri($"https://{vaultId[(vaultId.LastIndexOf('/') + 1)..]}.vault.azure.net") && vaultUri.UserInfo.Length == 0 &&
            vaultUri.Query.Length == 0 && vaultUri.Fragment.Length == 0 &&
            p.GetProperty("sku").GetProperty("family").GetString() == "A" &&
            p.GetProperty("sku").GetProperty("name").GetString() == expected.Sku.ToString().ToLowerInvariant());
        if (privateEndpoint is null)
            Require(p.GetProperty("privateEndpointConnections") is { ValueKind: JsonValueKind.Array } emptyConnections &&
                emptyConnections.GetArrayLength() == 0);
        else if (p.TryGetProperty("privateEndpointConnections", out var children))
        {
            Require(children.ValueKind == JsonValueKind.Array &&
                (children.GetArrayLength() == (privateConnection is null ? 0 : 1) ||
                    allowAbsentPrivateConnection && children.GetArrayLength() == 0));
            if (privateConnection is not null && children.GetArrayLength() != 0)
            {
                var child = children[0];
                Require(child.GetProperty("id").GetString() == privateConnection &&
                    child.GetProperty("properties").GetProperty("privateEndpoint").GetProperty("id").GetString() == privateEndpoint);
            }
        }
        if (p.TryGetProperty("createMode", out var mode))
            Require(mode.GetString() == "default" || recover && mode.GetString() == "recover");
        var policies = p.GetProperty("accessPolicies").EnumerateArray().Select(policy =>
        {
            var permissions = policy.GetProperty("permissions").GetProperty("secrets").EnumerateArray().Select(value =>
            {
                Require(Enum.TryParse<SecretPermission>(value.GetString(), true, out var permission) &&
                    Enum.IsDefined(permission) &&
                    permission.ToString().Equals(value.GetString(), StringComparison.OrdinalIgnoreCase));
                return permission;
            }).ToArray();
            return new VaultAdministrationEffects.Policy(policy.GetProperty("tenantId").GetGuid(),
                policy.GetProperty("objectId").GetGuid(), permissions,
                policy.TryGetProperty("applicationId", out var app) && app.ValueKind != JsonValueKind.Null ? app.GetGuid() : null);
        }).ToArray();
        Require(VaultAdministrationEffects.SamePolicies(policies, expected.Policies));
        // Every raw field, including optional presence and relationships, is
        // bound. Native configuration is joined separately after GetAsync.
        return Hash(root.GetRawText());
    }

    private static void ValidateDeleteVaultResource(Plan plan, JsonElement root,
        VaultAdministrationEffects.Configuration expected)
    {
        BoundaryTransport.Unique(root);
        DeletedShape(root);
        var p = root.GetProperty("properties");
        Require(root.GetProperty("id").GetString() == plan.DeletedId &&
            root.GetProperty("name").GetString() == plan.VaultName &&
            root.GetProperty("type").GetString() == "Microsoft.KeyVault/locations/deletedVaults" &&
            p.GetProperty("vaultId").GetString() == plan.VaultId &&
            p.GetProperty("location").GetString() == expected.Location &&
            p.GetProperty("tags").EnumerateObject().Count() == 1 &&
            p.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
            p.GetProperty("purgeProtectionEnabled").GetBoolean() == false &&
            p.GetProperty("scheduledPurgeDate").GetDateTimeOffset() -
                p.GetProperty("deletionDate").GetDateTimeOffset() == TimeSpan.FromDays(expected.RetentionDays));
    }

    private static void ValidateCreateVaultDeletedResource(Plan plan, JsonElement root,
        VaultAdministrationEffects.Configuration expected)
    {
        BoundaryTransport.Unique(root);
        DeletedShape(root);
        var p = root.GetProperty("properties");
        Require(root.GetProperty("id").GetString() == plan.DeletedId &&
            root.GetProperty("name").GetString() == plan.VaultName &&
            root.GetProperty("type").GetString() == "Microsoft.KeyVault/locations/deletedVaults" &&
            p.GetProperty("vaultId").GetString() == plan.VaultId &&
            p.GetProperty("location").GetString() == expected.Location &&
            p.GetProperty("tags").EnumerateObject().Count() == 1 &&
            p.GetProperty("tags").GetProperty(OwnershipTag).GetString() == plan.Selector.Nonce.ToString("N") &&
            p.GetProperty("purgeProtectionEnabled").GetBoolean() == expected.PurgeProtection &&
            p.GetProperty("scheduledPurgeDate").GetDateTimeOffset() -
                p.GetProperty("deletionDate").GetDateTimeOffset() == TimeSpan.FromDays(expected.RetentionDays));
    }

    internal sealed class SettingsLoan(Plan plan)
    {
        internal Plan Plan { get; } = plan;
        internal bool Observing;
        public override string ToString() => "[VaultSettingsLoan]";
    }

    internal sealed record SettingsWitness(Result Result, string UnchangedDigest, DateTimeOffset FinishedAt)
    {
        public override string ToString() => "[VaultSettingsWitness]";
    }

    internal SettingsLoan EnterSettings(Plan plan)
    {
        CheckPlan(plan);
        var snapshot = ReadPlan(plan.Owner, plan.Selector);
        Require(settingsProfile && !plan.Restored && SettingsSelector(plan.Selector) &&
            plan.Preparation == Preparation.Active && !plan.SeedCanary && plan.PolicyChildren.Count == 0 &&
            plan.OwnedNotificationNames.Count == 0 && !snapshot.Closing && snapshot.Idle &&
            snapshot.Settings is { InvocationDispatch: var dispatch } && dispatch == Guid.Empty &&
            VaultReadRoot(plan, snapshot));
        lock (plans)
        {
            Require(!closed && originalReady.Contains(plan) && plan.Busy == 0 && !settingsLoans.ContainsKey(plan));
            Enter(plan);
            var loan = new SettingsLoan(plan);
            settingsLoans.Add(plan, loan);
            return loan;
        }
    }

    internal void CheckSettingsLoan(SettingsLoan loan)
    {
        Require(loan is not null);
        lock (plans)
            Require(!closed && !loan.Plan.Restored && loan.Plan.Busy == 1 && originalReady.Contains(loan.Plan) &&
                settingsLoans.TryGetValue(loan.Plan, out var registered) && ReferenceEquals(registered, loan));
        var snapshot = journal.Read(loan.Plan.Owner, loan.Plan.Selector);
        Require(!snapshot.Closing && MatchesPlan(loan.Plan, snapshot) && snapshot.Settings is not null &&
            snapshot.Resources.Length == 3 && snapshot.Resources.All(r => !r.Borrowed && !r.DeleteAttempted && !r.Absent));
    }

    internal async ValueTask<SettingsWitness> ObserveSettingsAsync(SettingsLoan loan,
        VaultAdministrationEffects.Configuration expected, CancellationToken cancellationToken)
    {
        CheckSettingsLoan(loan);
        lock (plans) { Require(!loan.Observing); loan.Observing = true; }
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var plan = loan.Plan;
            string? digest = null;
            var vault = (await ReadArm(plan, plan.VaultId,
                (client, ct) => client.GetKeyVaultResource(new(plan.VaultId)).GetAsync(ct), root =>
                {
                    var raw = VaultFixtureObserverService.ParseSettingsResource(plan, root, expected);
                    digest = raw.UnchangedDigest;
                }, linked.Token, settingsLoan: loan).ConfigureAwait(false))?.Data;
            var deleted = await ReadArm(plan, plan.DeletedId,
                (client, ct) => client.GetDeletedKeyVaultResource(new(plan.DeletedId)).GetAsync(ct),
                DeletedShape, linked.Token, settingsLoan: loan).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            CheckSettingsLoan(loan);
            Require(vault is not null && Succeeded(vault) && deleted is null && digest is not null &&
                Same(vault.Id?.ToString(), plan.VaultId) &&
                vault.Properties.TenantId == host.TenantId && Same(vault.Location.Name, host.Location) &&
                vault.Properties.VaultUri == SecretOrigin(plan) &&
                vault.Tags.TryGetValue(OwnershipTag, out string? nonce) && nonce == plan.Selector.Nonce.ToString("N") &&
                VaultAdministrationEffects.SameConfiguration(Configuration(vault), expected));
            return new(new()
            {
                State = State.Ready,
                Journal = journal.Read(plan.Owner, plan.Selector),
                VaultPresent = true,
                DeletedVaultPresent = false,
                Configuration = Configuration(vault)
            }, digest, time.GetUtcNow());
        }
        finally { lock (plans) loan.Observing = false; }
    }

    internal void ExitSettings(SettingsLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && !loan.Observing &&
                settingsLoans.TryGetValue(loan.Plan, out var registered) && ReferenceEquals(registered, loan));
            settingsLoans.Remove(loan.Plan);
            // Local ownership ends; an unresolved durable dispatch does not.
            Exit(loan.Plan);
        }
    }

    private VaultAdministrationEffects.Configuration SettingsCleanupConfiguration(Plan plan)
    {
        var state = journal.Read(plan.Owner, plan.Selector);
        Require(MatchesPlan(plan, state) && state.Settings is not null && !state.SettingsUnsettled);
        return CopyConfiguration(state.Settings.SettledConfiguration ?? state.Settings.Baseline);
    }

    private void CheckSettingsRead(Plan plan, SettingsLoan? loan, HttpMessage message, string id,
        DeleteVaultLoan? deleteLoan = null, PurgeDeletedVaultLoan? purgeLoan = null,
        CreateOrUpdateVaultLoan? createLoan = null, RecoverVaultLoan? recoverLoan = null,
        PrivateConnectionUpdateLoan? privateUpdateLoan = null,
        PrivateConnectionDeleteLoan? privateDeleteLoan = null)
    {
        message.CancellationToken.ThrowIfCancellationRequested();
        var uri = message.Request.Uri.ToUri();
        var headers = message.Request.Headers.ToArray();
        Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
            headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
            headers.All(h => !string.IsNullOrWhiteSpace(h.Name) && h.Name.Length <= 128 &&
                !h.Name.Any(char.IsControl) && !string.IsNullOrWhiteSpace(h.Value) &&
                h.Value.Length <= 16384 && !h.Value.Any(char.IsControl)));
        if (message.Request.Headers.TryGetValue("Host", out var requestHost))
            Require(requestHost == "management.azure.com");
        Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
            uri.Scheme == "https" && uri.IsDefaultPort && uri.GetLeftPart(UriPartial.Authority) == ArmOrigin &&
            Same(uri.AbsolutePath, id) && uri.Query == "?api-version=" + Revision &&
            uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 &&
            message.Request.Headers.TryGetValue("Authorization", out var auth) &&
            auth.StartsWith("Bearer ", StringComparison.Ordinal) && auth.Length is > 7 and <= 16384 &&
            !auth.Any(char.IsControl) && !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding") && !message.Request.Headers.Contains("Content-Length"));
        if (privateDeleteLoan is not null) CheckPrivateConnectionDeleteLoan(privateDeleteLoan);
        else if (privateUpdateLoan is not null) CheckPrivateConnectionUpdateLoan(privateUpdateLoan);
        else if (recoverLoan is not null) CheckRecoverVaultLoan(recoverLoan);
        else if (createLoan is not null) CheckCreateOrUpdateVaultLoan(createLoan);
        else if (purgeLoan is not null) CheckPurgeDeletedVaultLoan(purgeLoan);
        else if (deleteLoan is not null) CheckDeleteVaultLoan(deleteLoan);
        else if (loan is not null) CheckSettingsLoan(loan);
        else if (StatusVaultUpdateCancellationSelector(plan.Selector))
        {
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(MatchesPlan(plan, snapshot) && snapshot.StatusVaultUpdateCancellationBaseline is not null);
            if (snapshot.Closing) Require(StatusVaultUpdateCancellationCleanupRoot(plan, snapshot));
            else if (!snapshot.Resources.Any(r => r.SelectedAttempted)) Require(snapshot.Idle);
            else
            {
                Guid dispatch = Guid.Empty;
                lock (plans)
                    Require(!plan.Restored && statusUpdateDispatches.TryGetValue(plan, out dispatch));
                Require(dispatch != Guid.Empty && snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                {
                    SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: true,
                    ActiveDispatch: var active
                } && active == dispatch &&
                    snapshot.Resources.Where(r => r.Id != plan.VaultId).All(r => r.ActiveDispatch == Guid.Empty &&
                        !r.SelectedAttempted && !r.DeleteAttempted));
            }
        }
        else if (StatusVaultRecoverCancellationSelector(plan.Selector))
        {
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            Require(MatchesPlan(plan, snapshot) && snapshot.StatusVaultRecoverCancellationBaseline is not null);
            if (snapshot.Closing) Require(snapshot.Idle);
            else if (!snapshot.Resources.Any(r => r.SelectedAttempted)) Require(snapshot.Idle);
            else
            {
                Guid dispatch = Guid.Empty;
                lock (plans)
                    Require(!plan.Restored && statusRecoveryDispatches.TryGetValue(plan, out dispatch));
                Require(dispatch != Guid.Empty && snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                {
                    SelectedAttempted: true, DeleteAttempted: false, InvocationTerminated: true,
                    ActiveDispatch: var active
                } && active == dispatch &&
                    snapshot.Resources.Where(r => r.Id != plan.VaultId).All(r => r.ActiveDispatch == Guid.Empty &&
                        !r.SelectedAttempted && !r.DeleteAttempted));
            }
        }
        else Require(journal.Read(plan.Owner, plan.Selector).Idle);
    }

    internal void CheckVaultRead(VaultReadLoan loan)
    {
        if (loan?.PrivateConnection is { } privateConnection)
            Require(privateConnection.Endpoints.OwnsBoundPlan(privateConnection.EndpointPlan,
                loan.Plan, privateConnection.ConnectionId));
        lock (plans)
        {
            Require(loan is not null && !closed && loan.Plan.Busy == 1 &&
                vaultReads.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            CheckPlan(loan.Plan);
            if (loan.PrivateConnection is { } admission)
            {
                Require(!loan.Plan.Restored && originalReady.Contains(loan.Plan) &&
                    PrivateConnectionReadProfile(loan.Plan) && ReferenceEquals(admission.Parent, loan.Plan));
                journal.CheckPrivateConnectionRead(loan.Plan.Owner, loan.Plan.Selector, loan.Plan.LeaseId,
                    admission, loan.Dispatch);
                return;
            }
            Require(!loan.Plan.Restored && originalReady.Contains(loan.Plan) &&
                (loan.Plan.Selector.Operation == "a.management.VaultAdministration.CheckNameAvailabilityAsync"
                    ? VaultNameReadProfile(loan.Plan)
                    : loan.Plan.Selector.Operation == "a.management.VaultAdministration.GetDeletedVaultAsync"
                        ? GetDeletedVaultReadProfile(loan.Plan)
                        : DeletedVaultListReadSelector(loan.Plan.Selector)
                            ? DeletedVaultListReadProfile(loan.Plan)
                            : VaultGroupListReadSelector(loan.Plan.Selector)
                                ? VaultGroupListReadProfile(loan.Plan)
                                : VaultSubscriptionListReadSelector(loan.Plan.Selector)
                                    ? VaultSubscriptionListReadProfile(loan.Plan)
                                    : loan.Plan.Selector.Operation == "a.management.VaultAdministration.GetVaultAsync"));
            var snapshot = ReadPlan(loan.Plan.Owner, loan.Plan.Selector);
            Require(!snapshot.Closing &&
                (DeletedVaultReadProfile(loan.Plan) ? DeletedVaultReadRoot(loan.Plan, snapshot) : VaultReadRoot(loan.Plan, snapshot)) &&
                loan.Dispatch != Guid.Empty &&
                snapshot.Resources.Single(r => r.Id == loan.Plan.VaultId) is
                { InvocationTerminated: false, ActiveDispatch: var dispatch } && dispatch == loan.Dispatch);
        }
    }

    private void CheckAuthenticatedRead(VaultReadLoan loan, HttpMessage message, string exactUri)
    {
        message.CancellationToken.ThrowIfCancellationRequested();
        Require(message.Request.Headers.TryGetValue("Authorization", out var authorization));
        Require(message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
            message.Request.Uri.ToUri().OriginalString == exactUri &&
            authorization.StartsWith("Bearer ", StringComparison.Ordinal) && authorization.Length > 7 &&
            !authorization.Any(char.IsControl) &&
            !message.Request.Headers.Contains("Content-Length") &&
            !message.Request.Headers.Contains("Content-Encoding") &&
            !message.Request.Headers.Contains("Transfer-Encoding"));
        if (VaultGroupListReadProfile(loan.Plan) || VaultSubscriptionListReadProfile(loan.Plan) ||
            DeletedVaultListReadProfile(loan.Plan))
        {
            var headers = message.Request.Headers.ToArray();
            Require(authorization.Length <= 16391 && headers.Length <= 32 &&
                headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                headers.All(h => !string.IsNullOrWhiteSpace(h.Name) && h.Name.Length <= 128 &&
                    !h.Name.Any(char.IsControl) && !string.IsNullOrWhiteSpace(h.Value) &&
                    h.Value.Length <= 16384 && !h.Value.Any(char.IsControl)));
            if (message.Request.Headers.TryGetValue("Host", out var requestHost))
                Require(requestHost == "management.azure.com");
        }
        CheckVaultRead(loan);
    }

    // ObserveAsync deliberately remains exclusive and journal-idle-only. This
    // entry accepts only the live original read loan, never a caller snapshot or
    // a restored plan, and does not enter the plan a second time.
    internal async ValueTask<Result> ObserveVaultReadAsync(VaultReadLoan loan,
        CancellationToken cancellationToken = default)
    {
        CheckVaultRead(loan);
        lock (plans)
        {
            Require(!loan.Observed);
            loan.Observed = loan.Observing = true;
        }
        try
        {
            using var deadline = new CancellationTokenSource(limits.Timeout, time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            var plan = loan.Plan;
            var vault = await ReadVault(plan, linked.Token, loan).ConfigureAwait(false);
            if (vault is not null) ValidateVault(plan, vault);
            var deleted = await ReadDeleted(plan, linked.Token, loan).ConfigureAwait(false);
            if (deleted is not null) ValidateDeleted(plan, deleted);
            (string? Digest, string? Version) canary = (null, null);
            if (loan.PrivateConnection is not null)
            {
                Require(vault is not null && Succeeded(vault) && deleted is null);
                canary = await ReadCanary(plan, linked.Token, loan).ConfigureAwait(false);
                Require(canary.Digest is not null && canary.Digest == plan.CanarySha256 &&
                    canary.Version is not null && canary.Version == plan.CanaryVersion);
            }
            linked.Token.ThrowIfCancellationRequested();
            CheckVaultRead(loan);
            Require(vault is null || deleted is null);
            return new()
            {
                State = (DeletedVaultReadProfile(plan) ? vault is null && deleted is not null :
                    vault is not null && Succeeded(vault) && deleted is null) ? State.Ready : State.Incomplete,
                Journal = ReadPlan(plan.Owner, plan.Selector),
                Receipts = plan.Receipts,
                VaultPresent = vault is not null,
                DeletedVaultPresent = deleted is not null,
                Configuration = vault is null ? null : Configuration(vault),
                DeletedVault = deleted is null ? null : ProjectDeleted(deleted),
                CanaryPresent = loan.PrivateConnection is null ? null : canary.Digest is not null,
                CanarySha256 = canary.Digest,
                CanaryVersion = canary.Version
            };
        }
        finally { lock (plans) loan.Observing = false; }
    }

    // The owner calls this only after its actual SDK/collector tasks and body
    // borrowers terminate. A GET cannot leave a remote mutation outstanding.
    // Failed persistence still leaves the journal fence unknown, never erased.
    internal void ExitVaultRead(VaultReadLoan loan)
    {
        lock (plans)
        {
            Require(loan is not null && !loan.Observing && loan.Plan.Busy == 1 &&
                vaultReads.TryGetValue(loan.Plan, out var retained) && ReferenceEquals(retained, loan));
            Require(ReferenceEquals(loan.Plan.Source, source) && !loan.Plan.Restored &&
                plans.TryGetValue(loan.Plan.Selector.Nonce, out var original) && ReferenceEquals(original, loan.Plan) &&
                (loan.Plan.Selector.Operation != "a.management.VaultAdministration.CheckNameAvailabilityAsync" ||
                    VaultNameReadProfile(loan.Plan)));
            try
            {
                if (loan.PrivateConnection is { } admission)
                {
                    Require(privateReadDrains.TryAdd(admission, loan.Dispatch));
                    try
                    {
                        journal.EndPrivateConnectionRead(loan.Plan.Owner, loan.Plan.Selector, loan.Plan.LeaseId,
                            admission, loan.Dispatch);
                    }
                    finally { privateReadDrains.TryRemove(admission, out _); }
                }
                else journal.EndDispatch(loan.Plan.Owner, loan.Plan.Selector, loan.Plan.VaultId, loan.Dispatch);
            }
            finally
            {
                vaultReads.Remove(loan.Plan);
                Exit(loan.Plan);
            }
        }
    }

    internal PrivateEndpointResourceCollector.Binding EndpointBinding(Plan plan)
    {
        lock (plans)
        {
            CheckPlan(plan);
            Require(plan.PrivateEndpoint is not null && MatchesPlan(plan, ReadPlan(plan.Owner, plan.Selector)));
            var d = plan.PrivateEndpoint;
            return new(plan.Selector, plan.LeaseId, d.EndpointId, d.VaultId, d.BorrowedSubnetId,
                d.ExpectedNicId, d.NetworkConnectionName, host.Location, d.OwnerTagName, d.OwnerTagValue);
        }
    }

    internal Guid BeginPrivateEndpointCreate(Plan plan)
    {
        lock (plans)
        {
            CheckPlan(plan);
            Require(!plan.Restored && originalReady.Contains(plan) && plan.Busy == 1 && plan.PrivateEndpoint is not null);
            return journal.BeginDispatch(plan.Owner, plan.Selector, plan.PrivateEndpoint.EndpointId, false,
                snapshot => MatchesPlan(plan, snapshot) && MatchesHost(snapshot) &&
                    snapshot.Resources.Single(r => r.Id == plan.VaultId) is
                    { CreateAttempted: true, DeleteAttempted: false, SelectedAttempted: false, Absent: false });
        }
    }

    internal bool TryEnterNotification(Plan plan, bool preparation)
    {
        lock (plans)
        {
            CheckPlan(plan);
            if (plan.Busy != 0) return false;
            var snapshot = ReadPlan(plan.Owner, plan.Selector);
            if (preparation) Require(!plan.Restored && prepared.Contains(plan) && !snapshot.Closing &&
                snapshot.Idle);
            return TryEnter(plan);
        }
    }

    internal void ExitNotification(Plan plan) => Exit(plan);

    internal bool TryEnterPrivateConnection(Plan originalPlan, string connectionId)
    {
        lock (plans)
        {
            CheckPlan(originalPlan);
            Require(!originalPlan.Restored && originalReady.Contains(originalPlan) &&
                originalPlan.Preparation == Preparation.Active && !originalPlan.SeedCanary &&
                originalPlan.PolicyChildren.Count == 0 && originalPlan.OwnedNotificationNames.Count == 0 &&
                originalPlan.PrivateEndpoint is not null);
            var snapshot = ReadPlan(originalPlan.Owner, originalPlan.Selector);
            Require(!snapshot.Closing && MatchesPlan(originalPlan, snapshot) &&
                snapshot.PrivateEndpoint?.Connection?.Id == connectionId &&
                (!StatusDeniedPrivateConnectionDeleteSelector(originalPlan.Selector) ||
                    DeniedPrivateDeleteLive(originalPlan) && RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(snapshot)) &&
                (!StatusPrivateConnectionDeleteIndependentSelector(originalPlan.Selector) ||
                    RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot)) &&
                (!StatusPrivateConnectionDeleteSelectedSelector(originalPlan.Selector) ||
                    RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot)) &&
                (!StatusPrivateConnectionDeleteCancellationSelector(originalPlan.Selector) ||
                    RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot)) &&
                (!StatusPrivateConnectionUpdateIndependentSelector(originalPlan.Selector) ||
                    PrivateUpdateIndependentLive(originalPlan) && RoleFixtureJournal.StatusPrivateConnectionUpdateIndependentRoot(snapshot)) &&
                (!StatusPrivateConnectionUpdateCancellationSelector(originalPlan.Selector) ||
                    RoleFixtureJournal.StatusPrivateConnectionUpdateRoot(snapshot)));
            return TryEnter(originalPlan);
        }
    }

    internal void ExitPrivateConnection(Plan originalPlan) => Exit(originalPlan);

    private static bool NotificationsAbsent(Plan plan, RoleFixtureJournal.Snapshot snapshot) =>
        MatchesPlan(plan, snapshot) && snapshot.PrivateEndpointAbsent &&
        (!StatusDeniedPrivateConnectionDeleteSelector(plan.Selector) ||
            RoleFixtureJournal.StatusDeniedPrivateConnectionDeleteRoot(snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpointCleanupEligible) &&
        (!StatusPrivateConnectionDeleteIndependentSelector(plan.Selector) ||
            RoleFixtureJournal.StatusPrivateConnectionDeleteIndependentRoot(snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpointCleanupEligible) &&
        (!StatusPrivateConnectionDeleteSelectedSelector(plan.Selector) ||
            RoleFixtureJournal.StatusPrivateConnectionDeleteSelectedRoot(snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpointCleanupEligible) &&
        (!StatusPrivateConnectionDeleteCancellationSelector(plan.Selector) ||
            RoleFixtureJournal.StatusPrivateConnectionDeleteRoot(snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpointCleanupEligible) &&
        (!StatusPrivateConnectionUpdateCancellationSelector(plan.Selector) ||
            RoleFixtureJournal.StatusPrivateConnectionUpdateRoot(snapshot) &&
            snapshot.Closing && snapshot.Idle && snapshot.PrivateEndpointCleanupEligible) &&
        plan.OwnedNotificationIds.All(id =>
            snapshot.Resources.Any(r => r.Id == id && !r.Borrowed && !r.CleanupOnly &&
                r.Absent && r.ActiveDispatch == Guid.Empty));
    private bool TryEnter(Plan plan)
    {
        lock (plans)
        {
            Require(!closed);
            if (plan.Busy != 0) return false;
            plan.Busy = 1;
            plan.Drained = new(TaskCreationOptions.RunContinuationsAsynchronously);
            return true;
        }
    }
    private void Enter(Plan plan) { Require(TryEnter(plan)); }
    private void Exit(Plan plan)
    {
        lock (plans)
        {
            plan.Busy = 0;
            plan.Drained?.TrySetResult();
        }
    }
    public ValueTask DisposeAsync()
    {
        TaskCompletionSource? start = null;
        Exception? publicationFailure = null;
        Task task;
        lock (plans)
        {
            if (statusDeniedVaultUpdateProfile && !closed)
                foreach (var plan in plans.Values.Where(p => p.Busy == 0 && HasStatusDeniedVaultUpdatePersistence(p)))
                    try { RetryStatusDeniedVaultUpdatePersistence(plan); }
                    catch (Exception exception) { publicationFailure ??= exception; }
            if (statusDeniedPrivateDeleteProfile && !closed)
                foreach (var plan in plans.Values.Where(p => p.Busy == 0 && HasStatusDeniedPrivateConnectionDeletePersistence(p)))
                    try { RetryStatusDeniedPrivateConnectionDeletePersistence(plan); }
                    catch (Exception exception) { publicationFailure ??= exception; }
            closed = true;
            if (disposal is not null) return new(disposal);
            var retained = plans.Values.ToArray();
            if (statusDeniedVaultUpdateProfile || statusDeniedPrivateDeleteProfile || statusPrivateUpdateIndependentProfile || retained.Any(p => StatusPrivateConnectionUpdateIndependentSelector(p.Selector)))
                start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            task = disposal = Drain(retained, start?.Task ?? Task.CompletedTask);
        }
        start?.SetResult();
        return new(task);
        async Task Drain(Plan[] retained, Task admitted)
        {
            await admitted.ConfigureAwait(false);
            Exception? failure = publicationFailure;
            foreach (var plan in retained)
                try { CloseSelectedRoot(plan.Owner, plan.Selector); }
                catch (Exception exception) { failure ??= exception; }
            try
            {
                await Task.WhenAll(retained.Where(p => p.Busy != 0).Select(p => p.Drained!.Task)).ConfigureAwait(false);
            }
            finally
            {
                prepared.Clear();
                originalReady.Clear();
                failedPreparations.Clear();
                failedPreparationRoots.Clear();
                failedFixtureAdmissions.Clear();
                failedFixtureDrains.Clear();
                failedAbsences.Clear();
                deniedPlans.Clear();
                failedPlans.Clear();
                failedCleanup.Clear();
                pendingIndependentPreparations.Clear();
                pendingCancellationPreparations.Clear();
                pendingIndependentFixtureAdmissions.Clear();
                pendingCancellationFixtureAdmissions.Clear();
                pendingIndependentFixtureDrains.Clear();
                pendingCancellationFixtureDrains.Clear();
                pendingIndependentAbsences.Clear();
                pendingCancellationAbsences.Clear();
                pendingIndependentPreparationRoots.Clear();
                pendingCancellationPreparationRoots.Clear();
                pendingIndependentPlans.Clear();
                pendingCancellationPlans.Clear();
                pendingPreparations.Clear();
                pendingPreparationRoots.Clear();
                pendingFixtureAdmissions.Clear();
                pendingFixtureDrains.Clear();
                pendingAbsences.Clear();
                pendingCallers.Clear();
                pendingPersistence.Clear();
                pendingLastPersistence.Clear();
                pendingReadyReads.Clear();
                pendingLifetimeChecks.Clear();
                unknownNotificationUpdateCancellationFixtureFacts.Clear();
                unknownNotificationUpdateCancellationAbsences.Clear();
                unknownNotificationUpdateCancellationPending.Clear();
                unknownNotificationUpdateCancellationPendingAbsence.Clear();
                unknownNotificationUpdateCancellationParentReads.Clear();
                unknownNotificationUpdateCancellationTokens.Clear();
                unknownNotificationUpdateIndependentFixtureFacts.Clear();
                unknownNotificationUpdateIndependentAbsences.Clear();
                unknownNotificationUpdateIndependentPending.Clear();
                unknownNotificationUpdateIndependentPendingAbsence.Clear();
                unknownNotificationUpdateIndependentParentReads.Clear();
                unknownNotificationUpdateIndependentTokens.Clear();

                deniedNotificationUpdateFixtureFacts.Clear();
                deniedNotificationUpdateAbsences.Clear();
                deniedNotificationUpdatePending.Clear();
                deniedNotificationUpdatePendingAbsence.Clear();
                deniedNotificationUpdateParentReads.Clear();
                deniedNotificationUpdateTokens.Clear();
                unknownNotificationUpdateFixtureFacts.Clear();
                unknownNotificationUpdateAbsences.Clear();
                unknownNotificationUpdatePending.Clear();
                unknownNotificationUpdatePendingAbsence.Clear();
                unknownNotificationUpdateParentReads.Clear();
                unknownNotificationUpdateTokens.Clear();
                privateUpdateIndependentFixtureFacts.Clear();
                privateUpdateIndependentAbsences.Clear();
                privateUpdateIndependentPending.Clear();
                privateUpdateIndependentPendingAbsence.Clear();
                privateUpdateIndependentParentReads.Clear();
                privateUpdateIndependentTokens.Clear();
                privateUpdateIndependentSetup.Clear();
                deniedPrivateDeleteFacts.Clear();
                deniedPrivateDeletePending.Clear();
                deniedPrivateDeleteAbsences.Clear();
                deniedPrivateDeleteReads.Clear();
                deniedPrivateDeleteLifetime.Clear();
                deniedPrivateDeleteTokens.Clear();
                deniedPrivateDeleteRoots.Clear();
                foreach (var plan in retained)
                    foreach (var child in plan.PolicyChildren) child.Clear();
                baselineConfiguration = null;
            }
            if (failure is not null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }
    private void Presence(Plan plan, string id)
    {
        var current = journal.Read(plan.Owner, plan.Selector);
        if (StatusDeniedVaultUpdateSelector(plan.Selector))
        {
            Require(!current.Resources.Single(r => r.Id == id).Absent);
            return;
        }
        if (StatusDeniedPrivateConnectionDeleteSelector(plan.Selector) &&
            !current.Resources.Single(r => r.Id == id).Absent) return;
        if (current.Closing && (!(NotificationFixtureProvisioner.StatusUnknownNotificationUpdateCancellationSelector(plan.Selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateIndependentSelector(plan.Selector) ||
            NotificationFixtureProvisioner.StatusDeniedNotificationUpdateSelector(plan.Selector) || NotificationFixtureProvisioner.StatusUnknownNotificationUpdateSelector(plan.Selector)) ||
            current.Resources.Single(r => r.Id == id).Absent))
        {
            journal.RecordPresence(plan.Owner, plan.Selector, id);
            if (id == plan.VaultId || id == plan.DeletedId)
                foreach (var child in plan.PolicyChildren)
                    journal.RecordPresence(plan.Owner, plan.Selector, plan.VaultId + "/secrets/" + child.Name);
        }
    }
    private Result Finish(State state, Plan plan) => new()
    {
        State = state,
        Journal = journal.Read(plan.Owner, plan.Selector),
        Receipts = plan.Receipts,
        CanarySha256 = plan.CanarySha256,
        CanaryVersion = plan.CanaryVersion
    };
    private bool BorrowedId(string id)
    {
        if (id is null || id.Length > 2048 || !id.StartsWith(SubscriptionId + "/", StringComparison.Ordinal) ||
            id.Contains("/secrets/", StringComparison.OrdinalIgnoreCase) ||
            id.Contains(NotificationPrefix, StringComparison.OrdinalIgnoreCase) ||
            id.Split('/').Skip(1).Any(part => !Segment(part, 256))) return false;
        if (id.Contains("/resourceGroups/", StringComparison.Ordinal))
            return id == GroupId || id.StartsWith(GroupId + "/", StringComparison.Ordinal);
        return id.StartsWith(SubscriptionId + "/providers/", StringComparison.Ordinal);
    }
    private static bool Segment(string? value, int maximum) => value is { Length: > 0 } &&
        value.Length <= maximum && value is not ("." or "..") &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');
    private static bool PolicyName(string? name) => name is { Length: > 0 and <= 127 } &&
        name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    private static bool NotificationName(string? name) => name is { Length: >= 3 and <= 64 } &&
        name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-');
    private static bool Same(string? left, string right) => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    private static bool Succeeded(KeyVaultData vault) => vault.Properties.ProvisioningState == KeyVaultProvisioningState.Succeeded;
    private static bool Terminal(KeyVaultData vault) => vault.Properties.ProvisioningState?.ToString() is "Succeeded" or "Failed" or "Canceled";
    private static State FailureState(Exception exception) => exception is RequestFailedException { Status: 401 or 403 } ? State.Denied : State.Uncertain;
    private static string Hash(string text)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(text);
        try { return Convert.ToHexString(SHA256.HashData(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static void Require([DoesNotReturnIf(false)] bool condition) { if (!condition) throw Failure(); }
    private static InvalidOperationException Failure() => new("vault-fixture-boundary");
    public override string ToString() => "[VaultFixtureProvisioner]";

    private static void VaultShape(JsonElement root)
    {
        Require(root.GetProperty("id").ValueKind == JsonValueKind.String &&
            root.GetProperty("location").ValueKind == JsonValueKind.String &&
            root.GetProperty("tags").ValueKind == JsonValueKind.Object);
        var properties = root.GetProperty("properties");
        foreach (string field in new[] { "enableRbacAuthorization", "enablePurgeProtection", "enableSoftDelete" })
            Require(properties.GetProperty(field).ValueKind is JsonValueKind.True or JsonValueKind.False);
        Require(properties.GetProperty("tenantId").TryGetGuid(out _) &&
            properties.GetProperty("softDeleteRetentionInDays").TryGetInt32(out _) &&
            properties.GetProperty("publicNetworkAccess").ValueKind == JsonValueKind.String &&
            properties.GetProperty("vaultUri").ValueKind == JsonValueKind.String &&
            properties.GetProperty("provisioningState").ValueKind == JsonValueKind.String &&
            properties.GetProperty("sku").GetProperty("family").ValueKind == JsonValueKind.String &&
            properties.GetProperty("sku").GetProperty("name").ValueKind == JsonValueKind.String &&
            properties.GetProperty("accessPolicies").ValueKind == JsonValueKind.Array);
        foreach (var policy in properties.GetProperty("accessPolicies").EnumerateArray())
        {
            Require(policy.GetProperty("tenantId").TryGetGuid(out _) && policy.GetProperty("objectId").TryGetGuid(out _));
            var permissions = policy.GetProperty("permissions");
            Require(permissions.GetProperty("secrets").ValueKind == JsonValueKind.Array);
            foreach (string other in new[] { "keys", "certificates", "storage" })
                Require(!permissions.TryGetProperty(other, out var values) ||
                    values.ValueKind == JsonValueKind.Array && values.GetArrayLength() == 0);
        }
    }
    private static void DeletedShape(JsonElement root)
    {
        Require(root.GetProperty("id").ValueKind == JsonValueKind.String);
        var properties = root.GetProperty("properties");
        Require(properties.GetProperty("vaultId").ValueKind == JsonValueKind.String &&
            properties.GetProperty("location").ValueKind == JsonValueKind.String &&
            properties.GetProperty("tags").ValueKind == JsonValueKind.Object &&
            properties.GetProperty("purgeProtectionEnabled").ValueKind is JsonValueKind.True or JsonValueKind.False &&
            properties.GetProperty("deletionDate").TryGetDateTimeOffset(out var deleted) &&
            properties.GetProperty("scheduledPurgeDate").TryGetDateTimeOffset(out var purge) && purge > deleted);
    }

    // Only source-generated typed SDK requests cross this final boundary.
    // Buffers are owned here and zeroed after actual SDK task completion, not
    // merely caller cancellation. Immutable SDK strings cannot be erased.
    // Host transports are never disposed.
    internal sealed class BoundaryTransport(HttpPipelineTransport inner, string origin, string path, string revision,
        RequestMethod method, int maximumBytes, bool secret, string subscription, string location,
        System.Action? beforeSend = null, System.Action<JsonElement>? shape = null, System.Action? present = null,
        string? ownedCanary = null, System.Action<HttpMessage>? authenticatedReadGuard = null,
        bool verifyReadIntegrity = false, bool strictSettings = false, bool strictDelete = false,
        bool parserCustody = false, bool statusVaultRecoverCancellationRead = false,
        bool statusVaultUpdateCancellationRead = false, bool statusSucceededCancellationMutation = false,
        bool notificationUpdateIndependentMutation = false, bool failedPurgeMutation = false)
        : HttpPipelineTransport, IDisposable
    {
        private readonly List<MemoryStream> buffers = [];
        private readonly List<IDisposable> settingsStorage = [];
        private readonly HashSet<string> statusUris = new(StringComparer.OrdinalIgnoreCase);
        private int sends, statusSends;
        private Request? originalReadRequest;
        private bool statusOnly;
        private readonly OwnedArmResponse.Storage parserStorage = new();
        private OwnedArmResponse.ParserCustody? custody;
        private bool fixtureDisposed, fixtureDisposalFailed;
        internal bool FixturePhysicalDrainComplete => statusSucceededCancellationMutation && fixtureDisposed && !fixtureDisposalFailed;
        internal bool FixtureDrainComplete => statusSucceededCancellationMutation && fixtureDisposed && !fixtureDisposalFailed && Valid &&
            (custody is { Complete: true, Invalid: false } || method != RequestMethod.Put && EmptyBody);
        internal bool ParserComplete => !parserCustody || custody is { Complete: true, Invalid: false };
        internal bool OwnsParserResponse(Response response) => !parserCustody || custody is not null && custody.Owns(response);
        internal int? Status { get; private set; }
        internal string? RequestId { get; private set; }
        internal bool Valid { get; private set; }
        internal bool HasAsync { get; private set; }
        internal bool EmptyBody { get; private set; }
        internal bool TerminalStatus { get; private set; }
        internal bool SucceededStatus { get; private set; }
        internal PolicyCredential? SecretCredential { get; set; }
        internal bool CanCheckStatus => !secret && statusUris.Count != 0;
        internal void BeginStatus()
        {
            Require(CanCheckStatus);
            statusOnly = true;
            statusSends = 0;
            // The SDK may complete from its already validated initial response
            // without a new send. An actual send invalidates Valid on entry.
            TerminalStatus = false;
            SucceededStatus = false;
        }
        public override Request CreateRequest()
        {
            if (!verifyReadIntegrity) return inner.CreateRequest();
            Require(originalReadRequest is null);
            return originalReadRequest = inner.CreateRequest();
        }
        public override void Process(HttpMessage message) => throw Failure();
        public override async ValueTask ProcessAsync(HttpMessage message)
        {
            message.CancellationToken.ThrowIfCancellationRequested();
            Uri uri = message.Request.Uri.ToUri();
            Require(Trusted(uri));
            if (statusOnly)
                Require(!failedPurgeMutation && message.Request.Method == RequestMethod.Get && message.Request.Content is null &&
                    statusUris.Contains(uri.AbsoluteUri) && ++statusSends <= (notificationUpdateIndependentMutation ? 1 : 2));
            else
                Require(message.Request.Method == method && Same(uri.AbsolutePath, path) &&
                    uri.Query == "?api-version=" + revision && ++sends <= 1);
            Valid = false;
            Status = null;
            RequestId = null;
            EmptyBody = false;
            if (message.Request.Content is { } content)
            {
                Require(content.TryComputeLength(out long length) && length >= 0 && length <= maximumBytes);
                var requestBuffer = new BoundedPolicyBuffer(maximumBytes);
                buffers.Add(requestBuffer);
                await content.WriteToAsync(requestBuffer, message.CancellationToken).ConfigureAwait(false);
                Require(requestBuffer.Length == length);
                if (secret)
                {
                    Require(method == RequestMethod.Put && ownedCanary is not null);
                    using var document = JsonDocument.Parse(requestBuffer.GetBuffer().AsMemory(0, (int)length));
                    Unique(document.RootElement);
                    Require(Hash(document.RootElement.GetProperty("value").GetString()!) == Hash(ownedCanary));
                }
                message.Request.Content = RequestContent.Create(requestBuffer.GetBuffer().AsMemory(0, (int)length));
                content.Dispose();
            }
            if (secret)
            {
                Require(SecretCredential is not null);
                var issued = SecretCredential.Issued ?? await SecretCredential.GetTokenAsync(
                    new TokenRequestContext(["https://vault.azure.net/.default"]), message.CancellationToken).ConfigureAwait(false);
                message.CancellationToken.ThrowIfCancellationRequested();
                message.Request.Headers.SetValue("Authorization", "Bearer " + issued.Token);
                if (method == RequestMethod.Put)
                {
                    Require(ownedCanary is not null);
                    var canonical = new MemoryStream();
                    buffers.Add(canonical);
                    using (var writer = new Utf8JsonWriter(canonical))
                    {
                        writer.WriteStartObject();
                        writer.WriteString("value", ownedCanary);
                        writer.WriteEndObject();
                    }
                    Require(canonical.Length <= maximumBytes);
                    message.Request.Content = RequestContent.Create(canonical.GetBuffer().AsMemory(0, (int)canonical.Length));
                    message.Request.Headers.SetValue("Content-Type", "application/json");
                }
            }
            if (!statusOnly)
            {
                if (verifyReadIntegrity) Require(ReferenceEquals(originalReadRequest, message.Request));
                authenticatedReadGuard?.Invoke(message);
                beforeSend?.Invoke();
            }
            var readHeaders = verifyReadIntegrity
                ? message.Request.Headers.Select(h => (h.Name, h.Value)).ToArray() : null;
            var fixtureRequest = statusSucceededCancellationMutation ? message.Request : null;
            var fixtureHeaders = statusSucceededCancellationMutation ? message.Request.Headers.ToArray() : null;
            var fixtureContent = statusSucceededCancellationMutation ? message.Request.Content : null;
            void CheckFixtureRequest()
            {
                if (!statusSucceededCancellationMutation) return;
                Require(ReferenceEquals(message.Request, fixtureRequest) && fixtureHeaders!.SequenceEqual(message.Request.Headers) &&
                    message.Request.Headers.TryGetValue("Authorization", out var auth) && auth.StartsWith("Bearer ", StringComparison.Ordinal) &&
                    auth.Length > 7 && (!statusOnly || notificationUpdateIndependentMutation) &&
                    message.Request.Method == (statusOnly ? RequestMethod.Get : method) &&
                    ReferenceEquals(message.Request.Content, fixtureContent) &&
                    message.Request.Uri.ToUri().AbsoluteUri == origin + path + "?api-version=" + revision);
                message.CancellationToken.ThrowIfCancellationRequested();
            }
            CheckFixtureRequest();
            message.BufferResponse = false;
            try { await inner.ProcessAsync(message).ConfigureAwait(false); }
            finally
            {
                if (statusSucceededCancellationMutation)
                {
                    if (message.HasResponse) parserStorage.Own(message.Response);
                }
                else if (strictSettings && message.HasResponse) settingsStorage.Add(message.Response);
            }
            CheckFixtureRequest();
            if (statusSucceededCancellationMutation && (method == RequestMethod.Put || statusOnly && notificationUpdateIndependentMutation))
            {
                var response = message.Response;
                var stream = response.ContentStream;
                var body = await OwnedArmResponse.CaptureAsync(message, maximumBytes, parserStorage).ConfigureAwait(false);
                CheckFixtureRequest();
                Require(ReferenceEquals(response.ContentStream, stream) && body.Response.Status == 200);
                using var json = JsonDocument.Parse(body.Bytes, new JsonDocumentOptions { MaxDepth = 32 });
                Unique(json.RootElement);
                shape?.Invoke(json.RootElement);
                Status = body.Response.Status;
                RequestId = body.NativeRequestId;
                statusUris.Add(origin + path + "?api-version=" + revision);
                custody = OwnedArmResponse.ParserCustody.Install(message, body.Response, body.Bytes, parserStorage,
                    requireRebuffer: false, requireDownstreamRead: true);
                Valid = true;
                return;
            }
            if (statusSucceededCancellationMutation)
            {
                var response = message.Response;
                int status = response.Status;
                string reason = response.ReasonPhrase, clientRequestId = response.ClientRequestId;
                var headers = response.Headers.Take(33).ToArray();
                string? Header(string name) => headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
                string? requestId = Header("x-ms-request-id");
                Require(status is 200 or 204 && reason.Length <= 256 && !reason.Any(char.IsControl) &&
                    clientRequestId.Length <= 1024 && !clientRequestId.Any(char.IsControl) && headers.Length <= 32 &&
                    headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                    headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                    headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                        h.Name.All(c => char.IsAsciiLetterOrDigit(c) || c == '-') && !h.Value.Any(char.IsControl)) &&
                    !new[] { "Location", "Azure-AsyncOperation", "Operation-Location", "Retry-After", "Content-Encoding",
                        "Transfer-Encoding", "Content-Range", "WWW-Authenticate" }.Any(n => Header(n) is not null) &&
                    requestId is not null && Segment(requestId, 256));
                long? declared = null;
                if (Header("Content-Length") is { } lengthText)
                {
                    Require(long.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
                        length >= 0 && length <= maximumBytes);
                    declared = length;
                }
                var stream = response.ContentStream;
                byte[] bytes = new byte[maximumBytes + 1];
                parserStorage.Own(bytes);
                int count = 0;
                if (stream is not null)
                {
                    parserStorage.Own(stream);
                    int read;
                    while ((read = await stream.ReadAsync(bytes.AsMemory(count), message.CancellationToken).ConfigureAwait(false)) != 0)
                    {
                        count += read;
                        Require(count <= maximumBytes);
                    }
                }
                Require((declared is null || declared == count) && (status != 204 || count == 0));
                CheckFixtureRequest();
                Require(ReferenceEquals(message.Response, response) && ReferenceEquals(response.ContentStream, stream) &&
                    response.Status == status && response.ReasonPhrase == reason && response.ClientRequestId == clientRequestId &&
                    headers.SequenceEqual(response.Headers));
                var ownedContent = new MemoryStream(bytes, 0, count, false, false);
                parserStorage.Own(ownedContent);
                var owned = new OwnedArmResponse(status, reason, clientRequestId, headers, ownedContent);
                message.Response = owned;
                if (count != 0)
                {
                    Require(Header("Content-Type") is { } type &&
                        type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase));
                    using var json = JsonDocument.Parse(bytes.AsMemory(0, count), new JsonDocumentOptions { MaxDepth = 32 });
                    Unique(json.RootElement);
                    if (failedPurgeMutation)
                        Require(json.RootElement.ValueKind == JsonValueKind.Object &&
                            json.RootElement.EnumerateObject().All(p => p.Name == "status") &&
                            json.RootElement.TryGetProperty("status", out var terminal) && terminal.ValueKind == JsonValueKind.String &&
                            terminal.GetString() == "Succeeded");
                    custody = OwnedArmResponse.ParserCustody.Install(message, owned, bytes.AsMemory(0, count), parserStorage,
                        requireRebuffer: false, requireDownstreamRead: true);
                }
                Require(!failedPurgeMutation || status == 200 && count > 0);
                Status = status;
                RequestId = requestId;
                EmptyBody = count == 0;
                statusUris.Add(origin + path + "?api-version=" + revision);
                Valid = true;
                return;
            }
            if (verifyReadIntegrity)
            {
                Require(ReferenceEquals(originalReadRequest, message.Request) &&
                    readHeaders!.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                authenticatedReadGuard!.Invoke(message);
            }
            Status = message.Response.Status;
            try
            {
                long? settingsLength = null;
                var settingsResponse = strictSettings ? message.Response : null;
                var settingsHeaders = strictSettings ? message.Response.Headers.ToArray() : null;
                string? settingsReason = strictSettings ? message.Response.ReasonPhrase : null;
                string? settingsRequestId = strictSettings ? message.Response.ClientRequestId : null;
                if (strictSettings)
                {
                    Require(Status is 200 or 404 && settingsReason is { Length: <= 256 } &&
                        !settingsReason.Any(char.IsControl) && settingsRequestId is { Length: <= 1024 } &&
                        !settingsRequestId.Any(char.IsControl));
                    var headers = settingsHeaders!;
                    string? Header(string name) => headers.FirstOrDefault(h =>
                        h.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
                    Require(headers.Length <= 32 && headers.Sum(h => h.Name.Length + h.Value.Length) <= 32768 &&
                        headers.Select(h => h.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() == headers.Length &&
                        headers.All(h => h.Name.Length is > 0 and <= 128 && h.Value.Length <= 16384 &&
                            !h.Name.Any(char.IsControl) && !h.Value.Any(char.IsControl)) &&
                        !new[] { "Azure-AsyncOperation", "Operation-Location", "Location", "Retry-After",
                            "Content-Encoding", "Transfer-Encoding" }.Any(n => Header(n) is not null) &&
                        Header("Content-Type") is { } type &&
                        type.Split(';')[0].Trim().Equals("application/json", StringComparison.OrdinalIgnoreCase) &&
                        Header("x-ms-request-id") is { } requestId && Segment(requestId, 256));
                    Require(!strictDelete || Header("Content-Range") is null && Header("WWW-Authenticate") is null);
                    if (Header("Content-Length") is { } lengthText)
                    {
                        Require(long.TryParse(lengthText, NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
                            length >= 0 && length <= maximumBytes);
                        settingsLength = length;
                    }
                }
                // A positive response invalidates stale absence even if its
                // body is partial, foreign or fails native deserialization.
                if (Status == 200) present?.Invoke();
                message.CancellationToken.ThrowIfCancellationRequested();
                Require(Status is >= 200 and < 300 or >= 400 and < 600);
                foreach (string header in new[] { "Azure-AsyncOperation", "Operation-Location", "Location" })
                {
                    if (!message.Response.Headers.TryGetValues(header, out var values)) continue;
                    string[] links = values.ToArray();
                    Require(links.Length == 1 && !secret);
                    HasAsync = true;
                    Require(Uri.TryCreate(links[0], UriKind.Absolute, out var next) && Trusted(next) &&
                        (next.Query.Length == 0 || next.Query == "?api-version=" + revision) &&
                        StatusPath(next.AbsolutePath));
                    statusUris.Add(next.Query.Length == 0 ? next.AbsoluteUri + "?api-version=" + revision : next.AbsoluteUri);
                }
                if (!secret && !statusOnly && Status is >= 200 and < 300)
                    statusUris.Add(origin + path + "?api-version=" + revision);
                if (message.Response.Headers.TryGetValues("x-ms-request-id", out var requestIds))
                {
                    string[] ids = requestIds.ToArray();
                    Require(ids.Length == 1 && Segment(ids[0], 256));
                    RequestId = ids[0];
                }
                if (message.Response.Headers.TryGetValues("Content-Length", out var sizes))
                {
                    string[] lengths = sizes.ToArray();
                    Require(lengths.Length == 1 &&
                        long.TryParse(lengths[0], NumberStyles.None, CultureInfo.InvariantCulture, out long length) &&
                        length >= 0 && length <= maximumBytes);
                }
                var buffer = new MemoryStream();
                buffers.Add(buffer);
                byte[] chunk = new byte[4096];
                Stream? updateInput = null;
                try
                {
                    Stream? input = message.Response.ContentStream;
                    if (statusVaultUpdateCancellationRead) updateInput = input;
                    if (strictSettings && input is not null) settingsStorage.Add(input);
                    if (input is not null)
                    {
                        try
                        {
                            int count;
                            while ((count = await input.ReadAsync(chunk, message.CancellationToken).ConfigureAwait(false)) != 0)
                            {
                                Require(buffer.Length + count <= maximumBytes);
                                buffer.Write(chunk, 0, count);
                            }
                        }
                        finally { if (!strictSettings) input.Dispose(); }
                    }
                }
                finally { CryptographicOperations.ZeroMemory(chunk); }
                EmptyBody = buffer.Length == 0;
                if (strictSettings)
                {
                    Require(!EmptyBody && (settingsLength is null || buffer.Length == settingsLength) &&
                        ReferenceEquals(message.Response, settingsResponse) && message.Response.Status == Status &&
                        settingsHeaders!.SequenceEqual(message.Response.Headers) &&
                        message.Response.ReasonPhrase == settingsReason &&
                        message.Response.ClientRequestId == settingsRequestId &&
                        readHeaders!.SequenceEqual(message.Request.Headers.Select(h => (h.Name, h.Value))));
                    Require(!(statusVaultRecoverCancellationRead || statusVaultUpdateCancellationRead) ||
                        ReferenceEquals(originalReadRequest, message.Request));
                    Require(!statusVaultUpdateCancellationRead ||
                        ReferenceEquals(message.Response.ContentStream, updateInput) &&
                        ReferenceEquals(message.Response, settingsResponse));
                    authenticatedReadGuard!.Invoke(message);
                }
                Require(Status != 204 || EmptyBody);
                buffer.Position = 0;
                if (!strictSettings) message.Response.ContentStream = buffer;
                if (!EmptyBody)
                {
                    using var document = JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length),
                        new JsonDocumentOptions { MaxDepth = 32 });
                    Unique(document.RootElement);
                    var root = document.RootElement;
                    Require(!strictDelete || root.ValueKind == JsonValueKind.Object &&
                        !new[] { "nextLink", "partial", "errors" }.Any(n => root.TryGetProperty(n, out _)) &&
                        (secret || !root.TryGetProperty("value", out _)));
                    if (strictSettings && Status == 404)
                        Require(root.GetProperty("error").GetProperty("code").GetString() is
                            "NotFound" or "ResourceNotFound" or "VaultNotFound");
                    if (statusVaultRecoverCancellationRead || statusVaultUpdateCancellationRead)
                    {
                        Require(strictSettings && strictDelete && parserCustody && verifyReadIntegrity);
                        if (Status == 404)
                        {
                            Require(root.EnumerateObject().Count() == 1);
                            RecoveryAbsence(root.GetProperty("error"));
                        }
                        else
                        {
                            Require(!root.TryGetProperty("error", out _) && !root.TryGetProperty("status", out _));
                            var properties = root.GetProperty("properties");
                            Require(!new[] { "error", "errors", "partial", "status" }
                                .Any(n => properties.TryGetProperty(n, out _)));
                        }
                    }
                    if (Status is >= 200 and < 300)
                    {
                        if (root.TryGetProperty("nextLink", out var next)) Require(next.ValueKind == JsonValueKind.Null);
                        if (!statusOnly && Status != 202) shape?.Invoke(root);
                        if (statusOnly)
                        {
                            string? state = root.TryGetProperty("status", out var value) && value.ValueKind == JsonValueKind.String
                                ? value.GetString() : root.TryGetProperty("properties", out var properties) &&
                                    properties.TryGetProperty("provisioningState", out value) && value.ValueKind == JsonValueKind.String
                                        ? value.GetString() : null;
                            TerminalStatus |= state is "Succeeded" or "Failed" or "Canceled" or "Cancelled";
                            SucceededStatus |= state == "Succeeded";
                        }
                    }
                }
                else if (Status == 200 && shape is not null && !statusOnly) throw Failure();
                // A host-owned response can ignore its ContentStream setter or
                // return different bytes on the next getter. Native parsing must
                // consume the exact buffer whose owned resource was validated.
                if (strictSettings)
                {
                    var owned = new OwnedArmResponse(Status!.Value, settingsReason!, settingsRequestId!, settingsHeaders!, buffer);
                    message.Response = owned;
                    if (parserCustody)
                        custody = OwnedArmResponse.ParserCustody.Install(message, owned,
                            buffer.GetBuffer().AsMemory(0, (int)buffer.Length), parserStorage, requireRebuffer: false);
                }
                Valid = true;
            }
            catch { message.Response.Dispose(); throw; }
        }
        private bool Trusted(Uri uri) => uri.Scheme == "https" && uri.IsDefaultPort &&
            uri.UserInfo.Length == 0 && uri.Fragment.Length == 0 && Same(uri.GetLeftPart(UriPartial.Authority), origin);
        private bool StatusPath(string candidate)
        {
            if (Same(candidate, path)) return true;
            string prefix = subscription + "/providers/Microsoft.KeyVault/locations/" + location + "/";
            if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
            string[] suffix = candidate[prefix.Length..].Split('/');
            return suffix.Length == 2 && suffix[0] is "operations" or "operationResults" &&
                Guid.TryParseExact(suffix[1], "D", out Guid id) && id != Guid.Empty;
        }
        internal static void Unique(JsonElement node)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in node.EnumerateObject()) { Require(names.Add(property.Name)); Unique(property.Value); }
            }
            else if (node.ValueKind == JsonValueKind.Array)
                foreach (var child in node.EnumerateArray()) Unique(child);
        }
        private static void RecoveryAbsence(JsonElement error)
        {
            Require(error.ValueKind == JsonValueKind.Object &&
                error.EnumerateObject().All(p => p.Name is "code" or "message" or "details") &&
                error.GetProperty("code").GetString() is "NotFound" or "ResourceNotFound" or "VaultNotFound");
            if (error.TryGetProperty("message", out var message)) Require(message.ValueKind == JsonValueKind.String);
            if (error.TryGetProperty("details", out var details))
            {
                Require(details.ValueKind == JsonValueKind.Array);
                foreach (var detail in details.EnumerateArray()) RecoveryAbsence(detail);
            }
        }
        public void Dispose()
        {
            bool failed = false;
            try { parserStorage.Dispose(); }
            catch (Exception) { failed = true; }
            foreach (var item in settingsStorage)
            {
                try { item.Dispose(); }
                catch (Exception) { failed = true; }
            }
            settingsStorage.Clear();
            foreach (var buffer in buffers)
                try
                {
                    if (buffer.TryGetBuffer(out var bytes)) CryptographicOperations.ZeroMemory(bytes.AsSpan());
                    buffer.Dispose();
                }
                catch (Exception) { failed = true; }
            buffers.Clear();
            if (statusSucceededCancellationMutation)
            {
                fixtureDisposalFailed |= failed;
                fixtureDisposed = true;
            }
            Require(!failed);
        }
    }
}
